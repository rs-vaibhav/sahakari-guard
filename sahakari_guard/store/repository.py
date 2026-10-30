"""SQLite persistence.

SQLite ships with Python, needs no server and works offline, which suits a
branch or a small bank's data centre. All access goes through ``Repository``;
a single re-entrant lock serialises writers so the API threads, the demo runner
and the outbox dispatcher can share one connection safely.

Timestamps: wall-clock times are stored as UTC ISO strings; event times (from
the bank's logs) are stored as IST ISO strings. Both sort correctly as text.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sahakari_guard.models import Alert
from sahakari_guard.timeutil import iso

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    label        TEXT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL,
    stats_json   TEXT
);

CREATE TABLE IF NOT EXISTS source_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    rows        INTEGER NOT NULL,
    parsed      INTEGER NOT NULL,
    rejected    INTEGER NOT NULL,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    run_id              TEXT,
    rule_id             TEXT NOT NULL,
    severity            TEXT NOT NULL,
    family              TEXT NOT NULL,
    key                 TEXT,
    rrn                 TEXT,
    account_token       TEXT,
    account_masked      TEXT,
    channel             TEXT,
    event_time          TEXT NOT NULL,
    detected_event_time TEXT NOT NULL,
    detected_at         TEXT NOT NULL,
    amount_paise        INTEGER NOT NULL DEFAULT 0,
    count               INTEGER NOT NULL DEFAULT 1,
    params_json         TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,
    status              TEXT NOT NULL,
    note                TEXT,
    incident_id         TEXT,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detected ON alerts(detected_event_time);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id      TEXT PRIMARY KEY,
    family           TEXT NOT NULL,
    severity         TEXT NOT NULL,
    status           TEXT NOT NULL,
    reportable       INTEGER NOT NULL,
    opened_at        TEXT NOT NULL,
    deadline_at      TEXT,
    first_event_at   TEXT NOT NULL,
    last_event_at    TEXT NOT NULL,
    detected_event_at TEXT NOT NULL,
    alert_count      INTEGER NOT NULL DEFAULT 0,
    open_alert_count INTEGER NOT NULL DEFAULT 0,
    amount_paise     INTEGER NOT NULL DEFAULT 0,
    accounts         INTEGER NOT NULL DEFAULT 0,
    channels         TEXT NOT NULL DEFAULT '',
    daksh_ref        TEXT,
    certin_ref       TEXT,
    dismissed_reason TEXT,
    officer          TEXT,
    updated_at       TEXT NOT NULL,
    closed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    at          TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_incident_events ON incident_events(incident_id);

CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT NOT NULL,
    channel         TEXT NOT NULL,
    incident_id     TEXT,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    status          TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    sent_at         TEXT,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status, next_attempt_at);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class Repository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
            )

    # ------------------------------------------------------------------ basics

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run several statements atomically (re-entrant: nested calls join the outer one)."""
        with self._lock:
            if self._conn.in_transaction:
                yield self._conn
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def query(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        with self._lock:
            return _row(self._conn.execute(sql, params).fetchone())

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.lastrowid or 0

    def reset(self) -> None:
        with self.transaction() as c:
            for table in ("alerts", "incidents", "incident_events", "outbox", "runs", "source_files", "kv"):
                c.execute(f"DELETE FROM {table}")

    # ------------------------------------------------------------------ kv

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM kv WHERE key = ?", (key,))
        if row is None:
            return default
        return json.loads(row["value"])

    def kv_set(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value, default=str)),
        )

    def next_sequence(self, name: str) -> int:
        with self.transaction():
            value = int(self.kv_get(f"seq:{name}", 0)) + 1
            self.kv_set(f"seq:{name}", value)
            return value

    # ------------------------------------------------------------------ runs

    def create_run(self, run_id: str, kind: str, label: str) -> None:
        self.execute(
            "INSERT INTO runs(run_id, kind, label, started_at, status) VALUES (?, ?, ?, ?, 'RUNNING')",
            (run_id, kind, label, utc_now_iso()),
        )

    def finish_run(self, run_id: str, status: str, stats: dict[str, Any]) -> None:
        self.execute(
            "UPDATE runs SET finished_at = ?, status = ?, stats_json = ? WHERE run_id = ?",
            (utc_now_iso(), status, json.dumps(stats, default=str), run_id),
        )

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["stats"] = json.loads(r.pop("stats_json") or "{}")
        return rows

    def add_source_file(self, run_id: str, summary: dict[str, Any]) -> None:
        self.execute(
            "INSERT INTO source_files(run_id, kind, name, sha256, rows, parsed, rejected, received_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, summary["kind"], summary["name"], summary["sha256"], summary["rows"],
                summary["parsed"], summary["rejected"], utc_now_iso(),
            ),
        )

    def source_files(self, run_ids: list[str] | None = None) -> list[dict[str, Any]]:
        if run_ids:
            marks = ",".join("?" * len(run_ids))
            return self.query(f"SELECT * FROM source_files WHERE run_id IN ({marks}) ORDER BY id", run_ids)
        return self.query("SELECT * FROM source_files ORDER BY id")

    # ------------------------------------------------------------------ alerts

    def insert_alerts(self, alerts: list[Alert], run_id: str | None, incident_ids: dict[str, str]) -> None:
        now = utc_now_iso()
        rows = [
            (
                a.alert_id, run_id, a.rule_id, a.severity.value, a.family, a.key, a.rrn, a.account_token,
                a.account_masked, a.channel, iso(a.event_time), iso(a.detected_event_time), now, a.amount,
                a.count, json.dumps(a.params, default=str), json.dumps(a.evidence, default=str), a.status,
                a.note, incident_ids.get(a.alert_id), now,
            )
            for a in alerts
        ]
        with self.transaction() as c:
            c.executemany(
                "INSERT INTO alerts(alert_id, run_id, rule_id, severity, family, key, rrn, account_token, "
                "account_masked, channel, event_time, detected_event_time, detected_at, amount_paise, count, "
                "params_json, evidence_json, status, note, incident_id, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )

    def apply_alert_update(
        self,
        alert_id: str,
        amount: int,
        count: int,
        params: dict[str, Any],
        detected_event_time: datetime,
        evidence_append: list[dict[str, Any]],
        evidence_limit: int,
    ) -> str | None:
        """Update an existing alert. Returns its incident id (or None if unknown)."""
        with self.transaction() as c:
            row = c.execute("SELECT evidence_json, incident_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            evidence = json.loads(row["evidence_json"])
            if evidence_append:
                evidence.extend(evidence_append[: max(0, evidence_limit - len(evidence))])
            c.execute(
                "UPDATE alerts SET amount_paise = ?, count = ?, params_json = ?, detected_event_time = "
                "MAX(detected_event_time, ?), evidence_json = ?, updated_at = ? WHERE alert_id = ?",
                (
                    amount, count, json.dumps(params, default=str), iso(detected_event_time),
                    json.dumps(evidence, default=str), utc_now_iso(), alert_id,
                ),
            )
            return row["incident_id"]

    def resolve_alert(self, alert_id: str, note: str) -> str | None:
        with self.transaction() as c:
            row = c.execute("SELECT incident_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            c.execute(
                "UPDATE alerts SET status = 'AUTO_RESOLVED', note = ?, updated_at = ? WHERE alert_id = ?",
                (note, utc_now_iso(), alert_id),
            )
            return row["incident_id"]

    @staticmethod
    def _decode_alert(row: dict[str, Any], with_evidence: bool = True) -> dict[str, Any]:
        row["params"] = json.loads(row.pop("params_json") or "{}")
        evidence = row.pop("evidence_json")
        if with_evidence:
            row["evidence"] = json.loads(evidence or "[]")
        return row

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.query_one("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        return self._decode_alert(row) if row else None

    def list_alerts(
        self,
        *,
        severity: str | None = None,
        rule_id: str | None = None,
        status: str | None = None,
        incident_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        with_evidence: bool = False,
    ) -> tuple[list[dict[str, Any]], int]:
        where, params = [], []
        for col, value in (("severity", severity), ("rule_id", rule_id), ("status", status), ("incident_id", incident_id)):
            if value:
                where.append(f"{col} = ?")
                params.append(value)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self.query_one(f"SELECT COUNT(*) AS n FROM alerts {clause}", params)["n"]
        rows = self.query(
            f"SELECT * FROM alerts {clause} ORDER BY detected_event_time DESC, alert_id LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        return [self._decode_alert(r, with_evidence) for r in rows], total

    def alert_counts(self) -> dict[str, Any]:
        by_rule = {r["rule_id"]: r["n"] for r in self.query(
            "SELECT rule_id, COUNT(*) AS n FROM alerts WHERE status = 'OPEN' GROUP BY rule_id")}
        by_sev = {r["severity"]: r["n"] for r in self.query(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'OPEN' GROUP BY severity")}
        total = self.query_one("SELECT COUNT(*) AS n FROM alerts")["n"]
        resolved = self.query_one("SELECT COUNT(*) AS n FROM alerts WHERE status = 'AUTO_RESOLVED'")["n"]
        hours = {r["h"]: r["n"] for r in self.query(
            "SELECT substr(detected_event_time, 1, 13) AS h, COUNT(*) AS n FROM alerts GROUP BY h")}
        return {"by_rule": by_rule, "by_severity": by_sev, "total": total, "auto_resolved": resolved, "by_hour": hours}

    # ------------------------------------------------------------------ incidents

    def insert_incident(self, inc: dict[str, Any]) -> None:
        cols = list(inc.keys())
        self.execute(
            f"INSERT INTO incidents({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            [inc[c] for c in cols],
        )

    def update_incident(self, incident_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.execute(f"UPDATE incidents SET {sets} WHERE incident_id = ?", list(fields.values()) + [incident_id])

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))

    def list_incidents(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if status:
            return self.query(
                "SELECT * FROM incidents WHERE status = ? ORDER BY opened_at DESC, incident_id DESC LIMIT ?",
                (status, limit),
            )
        return self.query("SELECT * FROM incidents ORDER BY opened_at DESC, incident_id DESC LIMIT ?", (limit,))

    def active_incidents(self, family: str) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM incidents WHERE family = ? AND status IN ('OPEN', 'CONFIRMED') ORDER BY last_event_at DESC",
            (family,),
        )

    def incident_aggregates(self, incident_id: str) -> dict[str, Any]:
        agg = self.query_one(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) AS open_count, "
            "COALESCE(SUM(CASE WHEN status = 'OPEN' AND rule_id != 'SG-R5' THEN amount_paise ELSE 0 END), 0) AS amount_txn, "
            "COALESCE(SUM(CASE WHEN status = 'OPEN' AND rule_id = 'SG-R5' THEN amount_paise ELSE 0 END), 0) AS amount_burst, "
            "COUNT(DISTINCT CASE WHEN status = 'OPEN' AND account_token != '' THEN account_token END) AS accounts, "
            "MIN(event_time) AS first_event, MAX(event_time) AS last_event, MIN(detected_event_time) AS detected "
            "FROM alerts WHERE incident_id = ?",
            (incident_id,),
        ) or {}
        sev = self.query(
            "SELECT DISTINCT severity FROM alerts WHERE incident_id = ? AND status = 'OPEN'", (incident_id,)
        )
        channels = self.query(
            "SELECT DISTINCT channel FROM alerts WHERE incident_id = ? AND channel != '' ORDER BY channel",
            (incident_id,),
        )
        # Burst alerts (SG-R5) describe the same money as the per-transaction alerts, so they only
        # count towards the amount at risk when no per-transaction alert exists.
        agg["amount"] = agg.get("amount_txn") or agg.get("amount_burst") or 0
        agg["severities"] = [r["severity"] for r in sev]
        agg["channels"] = [r["channel"] for r in channels]
        return agg

    def add_incident_event(self, incident_id: str, action: str, actor: str = "system", note: str = "") -> None:
        self.execute(
            "INSERT INTO incident_events(incident_id, at, action, actor, note) VALUES (?, ?, ?, ?, ?)",
            (incident_id, utc_now_iso(), action, actor, note),
        )

    def incident_events(self, incident_id: str) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY id", (incident_id,))

    # ------------------------------------------------------------------ outbox

    def enqueue_message(self, channel: str, incident_id: str | None, subject: str, body: str, payload: dict) -> int:
        now = utc_now_iso()
        return self.execute(
            "INSERT INTO outbox(created_at, channel, incident_id, subject, body, payload_json, status, attempts, "
            "next_attempt_at) VALUES (?, ?, ?, ?, ?, ?, 'QUEUED', 0, ?)",
            (now, channel, incident_id, subject, body, json.dumps(payload, default=str), now),
        )

    def due_messages(self, now_iso: str, limit: int = 20) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM outbox WHERE status = 'QUEUED' AND next_attempt_at <= ? ORDER BY id LIMIT ?",
            (now_iso, limit),
        )

    def mark_message(self, msg_id: int, status: str, *, error: str | None = None, next_attempt_at: str | None = None) -> None:
        now = utc_now_iso()
        if status == "SENT":
            self.execute(
                "UPDATE outbox SET status = 'SENT', sent_at = ?, attempts = attempts + 1, last_error = NULL WHERE id = ?",
                (now, msg_id),
            )
        else:
            self.execute(
                "UPDATE outbox SET status = ?, attempts = attempts + 1, last_error = ?, next_attempt_at = ? WHERE id = ?",
                (status, error, next_attempt_at or now, msg_id),
            )

    def list_outbox(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM outbox ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
        return rows

    def outbox_counts(self) -> dict[str, int]:
        return {r["status"]: r["n"] for r in self.query("SELECT status, COUNT(*) AS n FROM outbox GROUP BY status")}

    def release_queued_now(self) -> None:
        self.execute("UPDATE outbox SET next_attempt_at = ? WHERE status = 'QUEUED'", (utc_now_iso(),))
