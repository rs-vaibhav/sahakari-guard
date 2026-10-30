"""Pre-filled cyber-incident report (JSON + printable HTML).

The report gathers what an officer needs for the six-hour filing on RBI's
DAKSH portal and the CERT-In notification: who is reporting, what happened,
when it started, when it was detected, the impact, recommended actions and
evidence hashes. It is a *draft*: the officer verifies and files it.

Integrity: every source log file is listed with its SHA-256, and the report
payload itself is hashed, so any later change to the evidence is detectable.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from sahakari_guard import __version__
from sahakari_guard.config import Settings
from sahakari_guard.i18n import normalise_lang, render_alert, t
from sahakari_guard.incidents.manager import seconds_left
from sahakari_guard.money import format_inr
from sahakari_guard.timeutil import fmt_duration, fmt_ist, iso, parse_ts

HTML_ALERT_LIMIT = 60

_env = Environment(
    loader=PackageLoader("sahakari_guard.reports", "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _fmt(value: str | None) -> str:
    return fmt_ist(parse_ts(value)) if value else "-"


def _countries(alerts: list[dict[str, Any]], home: str) -> list[str]:
    found: set[str] = set()
    for a in alerts:
        for c in a.get("params", {}).get("country_list") or []:
            found.add(c)
        for ev in a.get("evidence") or []:
            c = ev.get("terminal_country")
            if c and c != home:
                found.add(c)
    return sorted(found)


def build_report(
    incident: dict[str, Any],
    alerts: list[dict[str, Any]],
    source_files: list[dict[str, Any]],
    settings: Settings,
    lang: str,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the report as a JSON-serialisable dict."""
    lang = normalise_lang(lang)
    generated_at = generated_at or datetime.now(timezone.utc)
    open_alerts = [a for a in alerts if a["status"] == "OPEN"] or alerts
    rule_counts = Counter(a["rule_id"] for a in open_alerts)
    txn_alerts = [a for a in open_alerts if a["rule_id"] != "SG-R5"]
    transactions = len({a["rrn"] for a in txn_alerts if a.get("rrn")}) or sum(a["count"] for a in open_alerts)
    rules_text = ", ".join(f"{rid} ({t(lang, f'rule.{rid}.name')})" for rid in sorted(rule_counts))
    amount = int(incident.get("amount_paise") or 0)
    first_detected = min((a["detected_event_time"] for a in open_alerts), default=None)

    detections = []
    for a in sorted(open_alerts, key=lambda x: (x["event_time"], x["alert_id"])):
        text = render_alert(lang, a["rule_id"], a.get("params", {}))
        detections.append({
            "alert_id": a["alert_id"],
            "rule_id": a["rule_id"],
            "rule_name": text["name"],
            "severity": a["severity"],
            "rrn": a.get("rrn") or "",
            "account": a.get("account_masked") or "",
            "channel": a.get("channel") or "",
            "amount_paise": int(a["amount_paise"]),
            "amount": format_inr(int(a["amount_paise"])),
            "event_time": a["event_time"],
            "detected_event_time": a["detected_event_time"],
            "detected_after": fmt_duration(
                (parse_ts(a["detected_event_time"]) - parse_ts(a["event_time"])).total_seconds()
            ),
            "message": text["message"],
        })

    files = [
        {"name": f["name"], "kind": f["kind"], "rows": f["rows"], "sha256": f["sha256"]}
        for f in source_files
    ]
    left = seconds_left(incident, generated_at)
    report: dict[str, Any] = {
        "schema": "sahakari-guard/incident-report/v1",
        "generator": f"Sahakari-Guard {__version__}",
        "language": lang,
        "notice": t(lang, "report.notice"),
        "entity": {
            "bank": settings.bank.name,
            "code": settings.bank.code,
            "location": settings.bank.location,
            "category": settings.bank.regulator_category,
            "officer": incident.get("officer") or settings.bank.reporting_officer,
            "email": settings.bank.officer_email,
            "phone": settings.bank.officer_phone,
        },
        "incident": {
            "reference": incident["incident_id"],
            "category_code": incident["family"],
            "category": t(lang, f"family.{incident['family']}"),
            "severity": incident["severity"],
            "severity_label": t(lang, f"severity.{incident['severity']}"),
            "status": incident["status"],
            "status_label": t(lang, f"incident.status.{incident['status']}"),
            "reportable": bool(incident["reportable"]),
            "daksh_ref": incident.get("daksh_ref"),
            "certin_ref": incident.get("certin_ref"),
        },
        "timing": {
            "first_event": incident["first_event_at"],
            "last_event": incident["last_event_at"],
            "first_alert_event_time": first_detected,
            "detected_at": incident["opened_at"],
            "deadline": incident.get("deadline_at"),
            "seconds_left": int(left) if left is not None else None,
            "generated": iso(generated_at),
        },
        "impact": {
            "transactions": transactions,
            "alerts": len(open_alerts),
            "amount_paise": amount,
            "amount": format_inr(amount),
            "accounts": int(incident.get("accounts") or 0),
            "channels": [c for c in (incident.get("channels") or "").split(",") if c],
            "countries": _countries(open_alerts, settings.engine.home_country),
        },
        "rules": [
            {"rule_id": rid, "name": t(lang, f"rule.{rid}.name"), "alerts": n} for rid, n in sorted(rule_counts.items())
        ],
        "description": t(
            lang, "report.description",
            count=transactions,
            rules=rules_text,
            amount=format_inr(amount),
            accounts=int(incident.get("accounts") or 0),
            first=_fmt(incident["first_event_at"]),
            detected=_fmt(first_detected),
        ),
        "actions": t(lang, f"actions.{incident['family']}"),
        "detections": detections,
        "evidence": {"source_files": files},
        "filing": [
            t(lang, "report.filing.daksh"),
            t(lang, "report.filing.certin"),
            t(lang, "report.filing.preserve"),
            t(lang, "report.filing.board"),
        ] if incident["reportable"] else [],
    }
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    report["evidence"]["payload_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report


def render_report_html(report: dict[str, Any]) -> str:
    lang = report["language"]

    def tr(key: str, **params: Any) -> Any:
        return t(lang, key, **params)

    template = _env.get_template("report.html")
    return template.render(
        r=report,
        tr=tr,
        fmt=_fmt,
        detections=report["detections"][:HTML_ALERT_LIMIT],
        more=max(0, len(report["detections"]) - HTML_ALERT_LIMIT),
    )
