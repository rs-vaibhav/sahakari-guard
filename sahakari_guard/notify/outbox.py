"""Store-and-forward notifications.

Detection must not depend on the internet. Messages for the branch manager are
written to a local outbox first; a dispatcher sends them when the line is up
and retries with exponential backoff when it is not. Nothing is lost if a
village branch goes offline for hours.

Channels:
* ``webhook`` - HTTP POST of a JSON payload to ``SG_WEBHOOK_URL`` (an SMS
  gateway, WhatsApp Business relay or chat webhook);
* ``sms-simulated`` - default for demos: "delivers" instantly when online.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from sahakari_guard.config import Settings
from sahakari_guard.i18n import t
from sahakari_guard.money import format_inr
from sahakari_guard.store.repository import Repository
from sahakari_guard.timeutil import fmt_ist, parse_ts

log = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 600


class DeliveryError(RuntimeError):
    pass


class NetworkState:
    """The simulated network switch used in demos (persisted in the database)."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    @property
    def online(self) -> bool:
        return bool(self.repo.kv_get("network_online", True))

    def set_online(self, online: bool) -> None:
        self.repo.kv_set("network_online", bool(online))
        if online:
            self.repo.release_queued_now()


class Notifier:
    """Builds messages for incident events and puts them in the outbox."""

    def __init__(self, repo: Repository, settings: Settings) -> None:
        self.repo = repo
        self.settings = settings

    @property
    def channel(self) -> str:
        return "webhook" if self.settings.webhook_url else "sms-simulated"

    def incident_event(self, incident: dict[str, Any], kind: str) -> int | None:
        if kind not in ("OPENED", "ESCALATED"):
            return None
        lang = self.settings.default_language
        deadline = fmt_ist(parse_ts(incident["deadline_at"])) if incident.get("deadline_at") else "-"
        subject = t(
            lang, "notify.title",
            severity=t(lang, f"severity.{incident['severity']}"),
            incident_id=incident["incident_id"],
        )
        body = t(
            lang, "notify.body",
            family=t(lang, f"family.{incident['family']}"),
            count=incident.get("open_alert_count") or incident.get("alert_count") or 0,
            amount=format_inr(int(incident.get("amount_paise") or 0)),
            deadline=deadline,
        )
        payload = {
            "event": f"incident.{kind.lower()}",
            "incident_id": incident["incident_id"],
            "severity": incident["severity"],
            "family": incident["family"],
            "amount_paise": int(incident.get("amount_paise") or 0),
            "deadline_at": incident.get("deadline_at"),
            "bank_code": self.settings.bank.code,
            "language": lang,
            "subject": subject,
            "body": body,
        }
        msg_id = self.repo.enqueue_message(self.channel, incident["incident_id"], subject, body, payload)
        self.repo.add_incident_event(incident["incident_id"], "NOTIFIED", "system", f"outbox #{msg_id}")
        return msg_id


class OutboxDispatcher:
    def __init__(self, repo: Repository, settings: Settings, network: NetworkState) -> None:
        self.repo = repo
        self.settings = settings
        self.network = network
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _deliver(self, msg: dict[str, Any]) -> None:
        if not self.network.online:
            raise DeliveryError("network offline (simulated)")
        if msg["channel"] == "webhook":
            if not self.settings.webhook_url:
                raise DeliveryError("webhook URL not configured")
            data = json.dumps(json.loads(msg["payload_json"])).encode("utf-8")
            req = urllib.request.Request(
                self.settings.webhook_url, data=data, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "sahakari-guard"},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 - URL comes from bank config
                    if not 200 <= resp.status < 300:
                        raise DeliveryError(f"HTTP {resp.status}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise DeliveryError(str(exc)) from exc

    def dispatch_once(self, now: datetime | None = None) -> dict[str, int]:
        now = now or datetime.now(timezone.utc)
        sent = failed = 0
        for msg in self.repo.due_messages(now.isoformat(timespec="seconds")):
            try:
                self._deliver(msg)
            except DeliveryError as exc:
                failed += 1
                delay = min(MAX_BACKOFF_SECONDS, 15 * (2 ** min(msg["attempts"], 6)))
                retry = (now + timedelta(seconds=delay)).isoformat(timespec="seconds")
                self.repo.mark_message(msg["id"], "QUEUED", error=str(exc), next_attempt_at=retry)
            else:
                sent += 1
                self.repo.mark_message(msg["id"], "SENT")
        return {"sent": sent, "deferred": failed}

    def start(self, interval: float = 3.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.dispatch_once()
                except Exception:  # pragma: no cover - keep the loop alive
                    log.exception("outbox dispatch failed")

        self._thread = threading.Thread(target=loop, name="outbox-dispatcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
