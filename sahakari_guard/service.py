"""Application service: the one place where engine, storage, incidents,
notifications and reports meet.

The HTTP API, the CLI, the demo runner and the folder watcher all call this
class; none of them touch the database or the engine directly. That keeps
business rules in one place and makes every entry point behave the same.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from sahakari_guard import __version__
from sahakari_guard.config import SUPPORTED_LANGUAGES, Settings
from sahakari_guard.engine.reconciler import Reconciler
from sahakari_guard.engine.rules import RULES
from sahakari_guard.engine.runner import run_events
from sahakari_guard.i18n import normalise_lang, render_alert, t
from sahakari_guard.incidents.manager import ACTIVE_STATUSES, IncidentManager, NotFound, seconds_left
from sahakari_guard.ingest.parsers import IngestError, ParseResult, parse_bytes
from sahakari_guard.models import Alert, AlertResolved, AlertUpdate, EngineOutput, FeedEvent, event_sort_key
from sahakari_guard.money import format_inr, format_inr_short
from sahakari_guard.notify.outbox import NetworkState, Notifier, OutboxDispatcher
from sahakari_guard.privacy.masker import mask_csv_text, mask_text
from sahakari_guard.privacy.tokenizer import Tokenizer
from sahakari_guard.reports.builder import build_report, render_report_html
from sahakari_guard.simulator.scenarios import SCENARIOS
from sahakari_guard.store.repository import Repository
from sahakari_guard.timeutil import parse_ts

log = logging.getLogger(__name__)

_SUM_KEYS = (
    "events", "switch_events", "ledger_entries", "settlement_records", "profile_changes", "outward_payments", "ledger_unlinked",
    "duplicate_lines_ignored", "approvals", "rrns_tracked", "evaluations", "matched", "mismatched",
)


class Busy(RuntimeError):
    """Another run (demo, upload, benchmark) is in progress."""


def merge_stats(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any]:
    a, b = a or {}, b or {}
    out: dict[str, Any] = {k: int(a.get(k) or 0) + int(b.get(k) or 0) for k in _SUM_KEYS}
    hourly: dict[str, int] = dict(a.get("hourly_approvals") or {})
    for k, v in (b.get("hourly_approvals") or {}).items():
        hourly[k] = hourly.get(k, 0) + int(v)
    out["hourly_approvals"] = dict(sorted(hourly.items()))
    firsts = [x for x in (a.get("first_event"), b.get("first_event")) if x]
    lasts = [x for x in (a.get("last_event"), b.get("last_event")) if x]
    out["first_event"] = min(firsts) if firsts else None
    out["last_event"] = max(lasts) if lasts else None
    out["pending"] = int(b.get("pending") or 0) + int(a.get("pending") or 0)
    decided = out["matched"] + out["mismatched"]
    out["match_rate"] = round(out["matched"] / decided, 6) if decided else None
    return out


def new_run_id() -> str:
    return f"RUN-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:4].upper()}"


class GuardService:
    def __init__(self, settings: Settings, repo: Repository | None = None) -> None:
        self.settings = settings
        self.repo = repo or Repository(settings.db_path)
        self.tokenizer = Tokenizer(settings.token_secret)
        self.incidents = IncidentManager(self.repo, settings)
        self.network = NetworkState(self.repo)
        self.notifier = Notifier(self.repo, settings)
        self.dispatcher = OutboxDispatcher(self.repo, settings, self.network)
        self._run_lock = threading.Lock()
        self._live: dict[str, dict[str, Any]] = {}
        self._live_lock = threading.Lock()
        # Imported here to avoid an import cycle (demo -> service).
        from sahakari_guard.demo import DemoRunner, BenchmarkRunner

        self.demo = DemoRunner(self)
        self.bench = BenchmarkRunner(self)

    # ================================================================== lifecycle

    def start_background(self) -> None:
        self.dispatcher.start()

    def stop_background(self) -> None:
        self.demo.stop(wait=True)
        self.dispatcher.stop()

    @contextmanager
    def exclusive(self, what: str) -> Iterator[None]:
        if not self._run_lock.acquire(blocking=False):
            raise Busy(f"another run is in progress; wait for it to finish before starting {what}")
        try:
            yield
        finally:
            self._run_lock.release()

    @property
    def busy(self) -> bool:
        return self._run_lock.locked()

    def new_engine(self) -> Reconciler:
        return Reconciler(self.settings.engine, self.tokenizer)

    # ================================================================== stats

    def publish_live_stats(self, source: str, stats: dict[str, Any] | None) -> None:
        with self._live_lock:
            if stats is None:
                self._live.pop(source, None)
            else:
                self._live[source] = stats

    def add_base_stats(self, stats: dict[str, Any]) -> None:
        with self.repo.transaction():
            base = self.repo.kv_get("stats_base", {})
            self.repo.kv_set("stats_base", merge_stats(base, stats))

    def merged_stats(self) -> dict[str, Any]:
        stats = self.repo.kv_get("stats_base", {})
        with self._live_lock:
            live = list(self._live.values())
        merged = merge_stats(stats, None)
        for item in live:
            merged = merge_stats(merged, item)
        return merged

    # ================================================================== runs

    def begin_run(self, kind: str, label: str, sources: Iterable[ParseResult] = ()) -> str:
        run_id = new_run_id()
        self.repo.create_run(run_id, kind, label)
        for src in sources:
            self.repo.add_source_file(run_id, src.summary())
        return run_id

    def end_run(self, run_id: str, status: str, stats: dict[str, Any]) -> None:
        self.repo.finish_run(run_id, status, stats)

    def run_batch(
        self,
        events: list[FeedEvent],
        *,
        kind: str,
        label: str,
        sources: Iterable[ParseResult] = (),
        reset: bool = False,
    ) -> dict[str, Any]:
        """Check a complete batch of events (upload, CLI scan, instant scenario)."""
        with self.exclusive(kind):
            if reset:
                self.reset_data()
            run_id = self.begin_run(kind, label, sources)
            engine = self.new_engine()
            started = time.perf_counter()
            try:
                outputs = run_events(engine, sorted(events, key=event_sort_key), heartbeat_seconds=15)
                applied = self.apply_outputs(outputs, run_id)
            except Exception as exc:
                self.end_run(run_id, "FAILED", {"error": str(exc)})
                raise
            stats = engine.snapshot_stats()
            stats["seconds"] = round(time.perf_counter() - started, 3)
            self.add_base_stats(stats)
            self.end_run(run_id, "DONE", {**stats, **applied})
            return {"run_id": run_id, "stats": stats, **applied}

    def scan_uploads(self, uploads: list[tuple[str, bytes]]) -> dict[str, Any]:
        if not uploads:
            raise IngestError("no files were uploaded")
        parsed = [parse_bytes(data, name) for name, data in uploads]
        kinds = [p.kind for p in parsed]
        for kind in set(kinds):
            if kinds.count(kind) > 1:
                raise IngestError(f"more than one {kind} file was uploaded; upload one file per feed")
        if "switch" not in kinds or "ledger" not in kinds:
            raise IngestError("upload at least a switch log and a core-banking ledger file")
        self.repo.kv_set("simulation_savings", None)
        events: list[FeedEvent] = [r for p in parsed for r in p.records]
        result = self.run_batch(events, kind="upload", label=", ".join(p.name for p in parsed), sources=parsed)
        result["files"] = [p.summary() for p in parsed]
        return result

    def run_scenario_instant(self, scenario: str, seed: int = 42, transactions: int = 12_000, reset: bool = True) -> dict[str, Any]:
        from sahakari_guard.bench import compute_savings
        from sahakari_guard.simulator.scenarios import build_day

        day = build_day(scenario, seed=seed, transactions=transactions)
        result = self.run_batch(day.events(), kind="scenario", label=f"{scenario} (seed {seed})", reset=reset)
        if day.injection:
            alerts, _ = self.repo.list_alerts(limit=5000)
            savings = compute_savings(day.injection, alerts, tokenizer=self.tokenizer)
            if savings:
                self.repo.kv_set("simulation_savings", savings)
                result["savings"] = savings
        else:
            self.repo.kv_set("simulation_savings", None)
        return result

    # ================================================================== outputs -> storage

    def apply_outputs(self, outputs: list[EngineOutput], run_id: str | None) -> dict[str, Any]:
        """Persist engine outputs, group alerts into incidents and queue notifications."""
        if not outputs:
            return {"new_alerts": 0, "updated_alerts": 0, "resolved_alerts": 0, "new_incidents": []}
        limit = self.settings.engine.evidence_limit
        new_alerts: dict[str, Alert] = {}
        updates: dict[str, AlertUpdate] = {}
        resolved: dict[str, str] = {}
        for o in outputs:
            if isinstance(o, Alert):
                new_alerts[o.alert_id] = o
            elif isinstance(o, AlertUpdate):
                target = new_alerts.get(o.alert_id)
                if target is not None:
                    target.amount, target.count, target.params = o.amount, o.count, o.params
                    room = max(0, limit - len(target.evidence))
                    target.evidence.extend(o.evidence_append[:room])
                    continue
                prev = updates.get(o.alert_id)
                if prev is not None:
                    o.evidence_append = prev.evidence_append + o.evidence_append
                    if prev.detected_event_time > o.detected_event_time:
                        o.detected_event_time = prev.detected_event_time
                updates[o.alert_id] = o
            elif isinstance(o, AlertResolved):
                if o.alert_id in new_alerts:
                    new_alerts[o.alert_id].status = "AUTO_RESOLVED"
                    new_alerts[o.alert_id].note = o.note
                else:
                    resolved[o.alert_id] = o.note

        with self.repo.transaction():
            mapping, created = self.incidents.assign(list(new_alerts.values()))
            self.repo.insert_alerts(list(new_alerts.values()), run_id, mapping)
            touched: set[str] = set(mapping.values())
            for alert_id, u in updates.items():
                inc = self.repo.apply_alert_update(
                    alert_id, u.amount, u.count, u.params, u.detected_event_time, u.evidence_append, limit
                )
                if inc:
                    touched.add(inc)
            for alert_id, note in resolved.items():
                inc = self.repo.resolve_alert(alert_id, note)
                if inc:
                    touched.add(inc)
            changes = self.incidents.refresh(touched, created)
            for change in changes:
                self.notifier.incident_event(change.incident, change.kind)
        return {
            "new_alerts": len(new_alerts),
            "updated_alerts": len(updates),
            "resolved_alerts": len(resolved) + sum(1 for a in new_alerts.values() if a.status != "OPEN"),
            "new_incidents": created,
        }

    # ================================================================== reads

    def _render_alert(self, row: dict[str, Any], lang: str) -> dict[str, Any]:
        text = render_alert(lang, row["rule_id"], row.get("params") or {})
        delay = (parse_ts(row["detected_event_time"]) - parse_ts(row["event_time"])).total_seconds()
        return {
            **row,
            "name": text["name"],
            "message": text["message"],
            "amount": format_inr(int(row["amount_paise"])),
            "severity_label": t(lang, f"severity.{row['severity']}"),
            "status_label": t(lang, f"alert.status.{row['status']}"),
            "detected_after_seconds": max(0.0, delay),
        }

    def _render_incident(self, inc: dict[str, Any], lang: str) -> dict[str, Any]:
        return {
            **inc,
            "reportable": bool(inc["reportable"]),
            "family_label": t(lang, f"family.{inc['family']}"),
            "severity_label": t(lang, f"severity.{inc['severity']}"),
            "status_label": t(lang, f"incident.status.{inc['status']}"),
            "amount": format_inr(int(inc["amount_paise"])),
            "amount_short": format_inr_short(int(inc["amount_paise"])),
            "channels": [c for c in (inc.get("channels") or "").split(",") if c],
            "seconds_left": seconds_left(inc),
        }

    def summary(self, lang: str = "en") -> dict[str, Any]:
        lang = normalise_lang(lang)
        stats = self.merged_stats()
        incidents = self.repo.list_incidents()
        active = [i for i in incidents if i["status"] in ACTIVE_STATUSES]
        reportable_active = [i for i in active if i["reportable"]]
        counts = self.repo.alert_counts()
        if any(i["severity"] in ("CRITICAL", "HIGH") for i in reportable_active):
            status = "red"
        elif active:
            status = "amber"
        elif not stats.get("events") and not incidents:
            status = "empty"
        else:
            status = "green"
        deadlines = sorted(
            ((seconds_left(i), i["incident_id"]) for i in reportable_active if i.get("deadline_at")),
            key=lambda x: x[0],
        )
        latest, _ = self.repo.list_alerts(status="OPEN", limit=6)
        outbox = self.repo.outbox_counts()
        amount = sum(int(i["amount_paise"]) for i in active)
        return {
            "status": status,
            "stats": stats,
            "kpi": {
                "checked": stats["matched"] + stats["mismatched"],
                "match_rate": stats["match_rate"],
                "open_incidents": len(active),
                "amount_at_risk_paise": amount,
                "amount_at_risk": format_inr_short(amount),
                "next_deadline_seconds": deadlines[0][0] if deadlines else None,
                "next_deadline_incident": deadlines[0][1] if deadlines else None,
                "queued_messages": outbox.get("QUEUED", 0),
            },
            "top_incident": self._render_incident(self._pick_top(active), lang) if active else None,
            "alerts": counts,
            "latest_alerts": [self._render_alert(a, lang) for a in latest],
            "network_online": self.network.online,
            "outbox": outbox,
            "demo": self.demo.status(),
            "busy": self.busy,
            "server_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    @staticmethod
    def _pick_top(active: list[dict[str, Any]]) -> dict[str, Any]:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(active, key=lambda i: (-int(i["reportable"]), -order[i["severity"]], i["deadline_at"] or "~"))[0]

    def list_alerts(self, lang: str = "en", **filters: Any) -> dict[str, Any]:
        lang = normalise_lang(lang)
        rows, total = self.repo.list_alerts(**filters)
        return {"total": total, "items": [self._render_alert(r, lang) for r in rows]}

    def get_alert(self, alert_id: str, lang: str = "en") -> dict[str, Any]:
        row = self.repo.get_alert(alert_id)
        if row is None:
            raise NotFound(alert_id)
        return self._render_alert(row, normalise_lang(lang))

    def list_incidents(self, lang: str = "en", status: str | None = None) -> list[dict[str, Any]]:
        lang = normalise_lang(lang)
        return [self._render_incident(i, lang) for i in self.repo.list_incidents(status=status)]

    def get_incident(self, incident_id: str, lang: str = "en", alert_limit: int = 200) -> dict[str, Any]:
        lang = normalise_lang(lang)
        inc = self.repo.get_incident(incident_id)
        if inc is None:
            raise NotFound(incident_id)
        alerts, total = self.repo.list_alerts(incident_id=incident_id, limit=alert_limit)
        events = self.repo.incident_events(incident_id)
        data = {
            "incident": self._render_incident(inc, lang),
            "alerts": [self._render_alert(a, lang) for a in alerts],
            "alerts_total": total,
            "timeline": [{**e, "label": t(lang, f"timeline.{e['action']}")} for e in events],
            "actions": t(lang, f"actions.{inc['family']}"),
        }
        savings = self.repo.kv_get("simulation_savings")
        if savings:
            data["savings"] = savings
        return data

    def report(self, incident_id: str, lang: str = "en") -> dict[str, Any]:
        inc = self.repo.get_incident(incident_id)
        if inc is None:
            raise NotFound(incident_id)
        alerts, _ = self.repo.list_alerts(incident_id=incident_id, limit=1_000_000, with_evidence=True)
        run_ids = sorted({a["run_id"] for a in alerts if a.get("run_id")})
        files = self.repo.source_files(run_ids) if run_ids else []
        return build_report(inc, alerts, files, self.settings, lang)

    def report_html(self, incident_id: str, lang: str = "en") -> str:
        return render_report_html(self.report(incident_id, lang))

    def config(self) -> dict[str, Any]:
        e = self.settings.engine
        return {
            "version": __version__,
            "bank": {
                "name": self.settings.bank.name,
                "code": self.settings.bank.code,
                "location": self.settings.bank.location,
            },
            "languages": list(SUPPORTED_LANGUAGES),
            "default_language": self.settings.default_language,
            "engine": {
                "match_window_seconds": e.match_window_seconds,
                "velocity_window_seconds": e.velocity_window_seconds,
                "foreign_window_seconds": e.foreign_window_seconds,
                "reporting_deadline_hours": self.settings.incidents.reporting_deadline_hours,
            },
            "rules": [
                {"rule_id": r.rule_id, "code": r.code, "severity": r.severity.value, "family": r.family}
                for r in RULES.values()
            ],
            "scenarios": list(SCENARIOS),
            "notification_channel": self.notifier.channel,
        }

    # ================================================================== officer actions

    def confirm_incident(self, incident_id: str, officer: str, note: str = "") -> dict[str, Any]:
        return self.incidents.confirm(incident_id, officer, note)

    def dismiss_incident(self, incident_id: str, officer: str, reason: str) -> dict[str, Any]:
        return self.incidents.dismiss(incident_id, officer, reason)

    def mark_reported(self, incident_id: str, officer: str, daksh_ref: str, certin_ref: str = "") -> dict[str, Any]:
        return self.incidents.mark_reported(incident_id, officer, daksh_ref, certin_ref)

    # ================================================================== privacy

    def mask_text(self, text: str) -> dict[str, Any]:
        result = mask_text(text)
        return {"text": result.text, "counts": dict(result.counts), "total": result.total}

    def mask_csv(self, content: str) -> dict[str, Any]:
        masked, report = mask_csv_text(content, tokenizer=self.tokenizer)
        return {"csv": masked, "report": report.to_dict()}

    # ================================================================== network / outbox

    def set_network(self, online: bool) -> dict[str, Any]:
        self.network.set_online(online)
        if online:
            self.dispatcher.dispatch_once()
        return {"online": self.network.online, "outbox": self.repo.outbox_counts()}

    def flush_outbox(self) -> dict[str, Any]:
        self.repo.release_queued_now()
        result = self.dispatcher.dispatch_once()
        return {**result, "outbox": self.repo.outbox_counts()}

    def outbox(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.repo.list_outbox(limit)

    # ================================================================== maintenance

    def reset_data(self) -> None:
        """Delete alerts, incidents, runs and stats (benchmark results are kept)."""
        bench = self.repo.kv_get("benchmark")
        online = self.network.online
        self.repo.reset()
        if bench is not None:
            self.repo.kv_set("benchmark", bench)
        self.repo.kv_set("network_online", online)
        with self._live_lock:
            self._live.clear()

    def reset(self) -> None:
        if self.demo.running:
            raise Busy("stop the demo before clearing data")
        with self.exclusive("reset"):
            self.reset_data()
