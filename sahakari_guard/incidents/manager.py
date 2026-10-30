"""Incident lifecycle and the 6-hour reporting clock.

Alerts are evidence; incidents are what an officer acts on. Alerts of the same
family that happen close together (``group_window_seconds`` of event time)
belong to one incident, so a 400-transaction cash-out is one incident, not 400.

Lifecycle::

    OPEN ──confirm──> CONFIRMED ──report──> REPORTED
      │                   │
      └────dismiss────────┴──> DISMISSED
    OPEN ──(all alerts balanced by later postings)──> AUTO_CLOSED

The reporting deadline is ``opened_at + reporting_deadline_hours`` (wall clock),
because RBI and CERT-In count six hours from *detection*.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sahakari_guard.config import Settings
from sahakari_guard.engine.rules import is_reportable
from sahakari_guard.models import Alert, Severity
from sahakari_guard.store.repository import Repository, utc_now_iso
from sahakari_guard.timeutil import IST, iso, parse_ts

ACTIVE_STATUSES = ("OPEN", "CONFIRMED")


class InvalidTransition(ValueError):
    """The requested status change is not allowed from the current status."""


class NotFound(KeyError):
    pass


@dataclass
class RefreshChange:
    incident_id: str
    kind: str  # "OPENED" | "ESCALATED" | "AUTO_CLOSED"
    incident: dict[str, Any]


class IncidentManager:
    def __init__(self, repo: Repository, settings: Settings) -> None:
        self.repo = repo
        self.settings = settings
        self._group = timedelta(seconds=settings.incidents.group_window_seconds)
        self._deadline = timedelta(hours=settings.incidents.reporting_deadline_hours)

    # ------------------------------------------------------------------ assignment

    def assign(self, alerts: list[Alert]) -> tuple[dict[str, str], list[str]]:
        """Attach each OPEN alert to an active incident or create one.

        Returns ``(alert_id -> incident_id, new_incident_ids)``. Must be called
        inside a repository transaction together with the alert inserts.
        """
        mapping: dict[str, str] = {}
        created: list[str] = []
        cache: dict[str, list[dict[str, Any]]] = {}
        for alert in sorted(alerts, key=lambda a: (a.event_time, a.alert_id)):
            if alert.status != "OPEN":
                continue
            family = alert.family
            if family not in cache:
                cache[family] = [
                    {**row, "_first": parse_ts(row["first_event_at"]), "_last": parse_ts(row["last_event_at"])}
                    for row in self.repo.active_incidents(family)
                ]
            target = None
            for inc in cache[family]:
                if inc["_first"] - self._group <= alert.event_time <= inc["_last"] + self._group:
                    target = inc
                    break
            if target is None:
                target = self._create(alert)
                created.append(target["incident_id"])
                cache[family].insert(0, target)
            else:
                target["_first"] = min(target["_first"], alert.event_time)
                target["_last"] = max(target["_last"], alert.event_time)
            mapping[alert.alert_id] = target["incident_id"]
        return mapping, created

    def _create(self, alert: Alert) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        seq = self.repo.next_sequence(f"incident:{now.astimezone(IST):%Y%m%d}")
        incident_id = f"INC-{now.astimezone(IST):%Y%m%d}-{seq:04d}"
        reportable = is_reportable(alert.family)
        row = {
            "incident_id": incident_id,
            "family": alert.family,
            "severity": alert.severity.value,
            "status": "OPEN",
            "reportable": 1 if reportable else 0,
            "opened_at": now.isoformat(timespec="seconds"),
            "deadline_at": (now + self._deadline).isoformat(timespec="seconds") if reportable else None,
            "first_event_at": iso(alert.event_time),
            "last_event_at": iso(alert.event_time),
            "detected_event_at": iso(alert.detected_event_time),
            "alert_count": 0,
            "open_alert_count": 0,
            "amount_paise": 0,
            "accounts": 0,
            "channels": "",
            "updated_at": now.isoformat(timespec="seconds"),
        }
        self.repo.insert_incident(row)
        self.repo.add_incident_event(incident_id, "OPENED", "system", alert.rule_id)
        return {**row, "_first": alert.event_time, "_last": alert.event_time}

    # ------------------------------------------------------------------ aggregates

    def refresh(self, incident_ids: set[str], new_ids: list[str]) -> list[RefreshChange]:
        """Recompute totals from alerts; detect escalations and auto-closure."""
        changes: list[RefreshChange] = []
        for incident_id in sorted(i for i in incident_ids if i):
            inc = self.repo.get_incident(incident_id)
            if inc is None:
                continue
            agg = self.repo.incident_aggregates(incident_id)
            fields: dict[str, Any] = {
                "alert_count": agg.get("total") or 0,
                "open_alert_count": agg.get("open_count") or 0,
                "amount_paise": agg.get("amount") or 0,
                "accounts": agg.get("accounts") or 0,
                "channels": ",".join(agg.get("channels") or []),
            }
            if agg.get("first_event"):
                fields["first_event_at"] = agg["first_event"]
                fields["last_event_at"] = agg["last_event"]
            if agg.get("detected"):
                fields["detected_event_at"] = agg["detected"]
            old_sev = Severity(inc["severity"])
            new_sev = old_sev
            for sev in agg.get("severities") or []:
                new_sev = Severity.max(new_sev, Severity(sev))
            if new_sev is not old_sev:
                fields["severity"] = new_sev.value
            if inc["status"] == "OPEN" and fields["open_alert_count"] == 0 and fields["alert_count"] > 0:
                fields["status"] = "AUTO_CLOSED"
                fields["closed_at"] = utc_now_iso()
            self.repo.update_incident(incident_id, **fields)
            updated = {**inc, **fields}
            if incident_id in new_ids:
                changes.append(RefreshChange(incident_id, "OPENED", updated))
            elif new_sev is not old_sev:
                self.repo.add_incident_event(incident_id, "ESCALATED", "system", f"{old_sev.value} -> {new_sev.value}")
                changes.append(RefreshChange(incident_id, "ESCALATED", updated))
            if fields.get("status") == "AUTO_CLOSED":
                self.repo.add_incident_event(incident_id, "AUTO_CLOSED", "system", "")
                changes.append(RefreshChange(incident_id, "AUTO_CLOSED", updated))
        return changes

    # ------------------------------------------------------------------ officer actions

    def _get(self, incident_id: str) -> dict[str, Any]:
        inc = self.repo.get_incident(incident_id)
        if inc is None:
            raise NotFound(incident_id)
        return inc

    @staticmethod
    def _clean(value: str | None, field: str, *, required: bool, max_len: int = 200) -> str:
        text = (value or "").strip()
        if required and len(text) < 2:
            raise ValueError(f"{field} is required")
        if len(text) > max_len:
            raise ValueError(f"{field} is too long (max {max_len} characters)")
        return text

    def confirm(self, incident_id: str, officer: str, note: str = "") -> dict[str, Any]:
        with self.repo.transaction():
            inc = self._get(incident_id)
            if inc["status"] != "OPEN":
                raise InvalidTransition(f"only OPEN incidents can be confirmed (current: {inc['status']})")
            officer = self._clean(officer, "officer", required=True)
            self.repo.update_incident(incident_id, status="CONFIRMED", officer=officer)
            self.repo.add_incident_event(incident_id, "CONFIRMED", officer, self._clean(note, "note", required=False, max_len=500))
            return self._get(incident_id)

    def dismiss(self, incident_id: str, officer: str, reason: str) -> dict[str, Any]:
        with self.repo.transaction():
            inc = self._get(incident_id)
            if inc["status"] not in ACTIVE_STATUSES:
                raise InvalidTransition(f"only OPEN or CONFIRMED incidents can be dismissed (current: {inc['status']})")
            officer = self._clean(officer, "officer", required=True)
            reason = self._clean(reason, "reason", required=True, max_len=500)
            self.repo.update_incident(
                incident_id, status="DISMISSED", officer=officer, dismissed_reason=reason, closed_at=utc_now_iso()
            )
            self.repo.add_incident_event(incident_id, "DISMISSED", officer, reason)
            return self._get(incident_id)

    def mark_reported(self, incident_id: str, officer: str, daksh_ref: str, certin_ref: str = "") -> dict[str, Any]:
        with self.repo.transaction():
            inc = self._get(incident_id)
            if inc["status"] not in ACTIVE_STATUSES:
                raise InvalidTransition(f"only OPEN or CONFIRMED incidents can be reported (current: {inc['status']})")
            if not inc["reportable"]:
                raise InvalidTransition("this incident type is not a reportable cyber incident")
            officer = self._clean(officer, "officer", required=True)
            daksh_ref = self._clean(daksh_ref, "daksh_ref", required=True, max_len=80)
            certin_ref = self._clean(certin_ref, "certin_ref", required=False, max_len=80)
            self.repo.update_incident(
                incident_id, status="REPORTED", officer=officer, daksh_ref=daksh_ref,
                certin_ref=certin_ref or None, closed_at=utc_now_iso(),
            )
            self.repo.add_incident_event(incident_id, "REPORTED", officer, daksh_ref)
            return self._get(incident_id)


def seconds_left(incident: dict[str, Any], now: datetime | None = None) -> float | None:
    if not incident.get("deadline_at") or incident.get("status") not in ACTIVE_STATUSES:
        return None
    now = now or datetime.now(timezone.utc)
    return (parse_ts(incident["deadline_at"]) - now).total_seconds()
