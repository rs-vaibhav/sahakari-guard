"""SG-R5 velocity rule: bursts of approvals.

Two patterns are watched with sliding windows:

* **per account** - one account approving far more transactions than normal
  within a few minutes (cloned card cash-out, or a script exploiting a credit bug);
* **bank-wide foreign spread** - many approvals at foreign terminals across many
  countries in a short window (the "ATM cash-out" pattern).

A burst is an *episode*: the first trigger raises one alert and later triggers
update it, until the burst has been quiet for ``velocity_cooldown_seconds``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from sahakari_guard.config import EngineSettings
from sahakari_guard.engine.evidence import EvidenceBuilder
from sahakari_guard.engine.rules import RULES
from sahakari_guard.models import Alert, AlertUpdate, Direction, EngineOutput, SwitchEvent
from sahakari_guard.privacy.masker import mask_keep_last
from sahakari_guard.privacy.tokenizer import Tokenizer

_CLEANUP_EVERY = 5000


@dataclass
class _Episode:
    alert_id: str
    last_ts: datetime
    count: int
    amount: int
    evidence_rows: int
    countries: set[str] = field(default_factory=set)


class VelocityMonitor:
    def __init__(
        self,
        cfg: EngineSettings,
        tokenizer: Tokenizer,
        evidence: EvidenceBuilder,
        new_id: Callable[[], str],
    ) -> None:
        self.cfg = cfg
        self.tokenizer = tokenizer
        self.evidence = evidence
        self.new_id = new_id
        self._window = timedelta(seconds=cfg.velocity_window_seconds)
        self._foreign_window = timedelta(seconds=cfg.foreign_window_seconds)
        self._cooldown = timedelta(seconds=cfg.velocity_cooldown_seconds)
        self._acct: dict[tuple[str, str], deque[tuple[datetime, int]]] = {}
        self._foreign: deque[tuple[datetime, str, int]] = deque()
        self._episodes: dict[str, _Episode] = {}
        self._observed = 0

    # ------------------------------------------------------------------ public

    def observe(self, ev: SwitchEvent) -> list[EngineOutput]:
        if not ev.approved:
            return []
        out: list[EngineOutput] = []
        self._observed += 1
        token = self.tokenizer.token(ev.account_no)

        threshold = (
            self.cfg.velocity_debit_threshold if ev.direction is Direction.DEBIT else self.cfg.velocity_credit_threshold
        )
        window = self._acct.setdefault((ev.direction.value, token), deque())
        window.append((ev.ts, ev.amount))
        cutoff = ev.ts - self._window
        while window and window[0][0] < cutoff:
            window.popleft()
        if len(window) > threshold:
            out.append(self._account_trigger(ev, token, window))

        if (
            ev.direction is Direction.DEBIT
            and ev.terminal_country
            and ev.terminal_country != self.cfg.home_country
        ):
            self._foreign.append((ev.ts, ev.terminal_country, ev.amount))
            fcut = ev.ts - self._foreign_window
            while self._foreign and self._foreign[0][0] < fcut:
                self._foreign.popleft()
            countries = {c for _, c, _ in self._foreign}
            if (
                len(self._foreign) >= self.cfg.foreign_count_threshold
                or len(countries) >= self.cfg.foreign_country_threshold
            ):
                out.append(self._foreign_trigger(ev, countries))

        if self._observed % _CLEANUP_EVERY == 0:
            self._cleanup(ev.ts)
        return out

    # ------------------------------------------------------------------ helpers

    def _live_episode(self, key: str, ts: datetime) -> _Episode | None:
        ep = self._episodes.get(key)
        if ep is not None and ts - ep.last_ts <= self._cooldown:
            return ep
        return None

    def _account_trigger(self, ev: SwitchEvent, token: str, window: deque) -> EngineOutput:
        key = f"acct:{ev.direction.value}:{token}"
        ep = self._live_episode(key, ev.ts)
        family = "UNAUTHORISED_DEBITS" if ev.direction is Direction.DEBIT else "ERRONEOUS_CREDITS"
        params = {
            "variant": "account",
            "account": mask_keep_last(ev.account_no),
            "direction": ev.direction.value,
            "window_count": len(window),
            "window_min": self.cfg.velocity_window_seconds // 60,
        }
        if ep is None:
            amount = sum(a for _, a in window)
            alert = self._new_alert(
                key, ev, family, amount, len(window), params, token,
                event_time=window[0][0],
            )
            self._episodes[key] = _Episode(alert.alert_id, ev.ts, len(window), amount, len(alert.evidence))
            return alert
        return self._update(ep, ev, params)

    def _foreign_trigger(self, ev: SwitchEvent, countries: set[str]) -> EngineOutput:
        key = "bank:foreign"
        ep = self._live_episode(key, ev.ts)
        params = {
            "variant": "foreign",
            "window_count": len(self._foreign),
            "countries": len(countries),
            "country_list": sorted(countries)[:12],
            "window_min": self.cfg.foreign_window_seconds // 60,
        }
        if ep is None:
            amount = sum(a for _, _, a in self._foreign)
            alert = self._new_alert(
                key, ev, "UNAUTHORISED_DEBITS", amount, len(self._foreign), params, "",
                event_time=self._foreign[0][0],
            )
            self._episodes[key] = _Episode(alert.alert_id, ev.ts, len(self._foreign), amount, len(alert.evidence), set(countries))
            return alert
        ep.countries |= countries
        params["countries"] = len(ep.countries)
        params["country_list"] = sorted(ep.countries)[:12]
        return self._update(ep, ev, params)

    def _update(self, ep: _Episode, ev: SwitchEvent, params: dict) -> AlertUpdate:
        ep.last_ts = ev.ts
        ep.count += 1
        ep.amount += ev.amount
        params = {**params, "episode_count": ep.count}
        evidence = []
        if ep.evidence_rows < self.cfg.evidence_limit:
            evidence.append(self.evidence.switch(ev))
            ep.evidence_rows += 1
        return AlertUpdate(
            alert_id=ep.alert_id,
            amount=ep.amount,
            count=ep.count,
            params=params,
            detected_event_time=ev.ts,
            evidence_append=evidence,
        )

    def _new_alert(
        self,
        key: str,
        ev: SwitchEvent,
        family: str,
        amount: int,
        count: int,
        params: dict,
        token: str,
        event_time: datetime,
    ) -> Alert:
        spec = RULES["SG-R5"]
        params = {**params, "episode_count": count}
        return Alert(
            alert_id=self.new_id(),
            rule_id=spec.rule_id,
            severity=spec.severity,
            family=family,
            key=key,
            event_time=event_time,
            detected_event_time=ev.ts,
            amount=amount,
            rrn=ev.rrn,
            account_token=token,
            account_masked=mask_keep_last(ev.account_no) if token else "",
            channel=ev.channel.value,
            count=count,
            params=params,
            evidence=[self.evidence.switch(ev)],
        )

    def _cleanup(self, now: datetime) -> None:
        cutoff = now - self._window
        for key in [k for k, dq in self._acct.items() if not dq or dq[-1][0] < cutoff]:
            del self._acct[key]
        for key in [k for k, ep in self._episodes.items() if now - ep.last_ts > self._cooldown]:
            del self._episodes[key]
