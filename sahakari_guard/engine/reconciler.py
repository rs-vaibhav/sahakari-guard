"""Match Watchdog: streaming three-way reconciliation per reference number (RRN).

How it works
------------
Events from the switch log, the CBS ledger and the network settlement file are
fed in (roughly) time order. For every RRN the engine keeps a small state:

* what the **switch** says moved   = approved amount - accepted reversals
* what the **ledger** says moved   = debits - credits (signed by direction)
* what the **network** settled

When nothing new has happened for an RRN for ``match_window_seconds`` (event
time), its *deadline* passes and the RRN is evaluated. Netting amounts instead
of pairing individual messages makes the logic robust to reversals, timeouts
and partial dispenses. A later posting re-opens the RRN; if it balances the
books, any alert raised earlier is automatically resolved.

Rules raised here: SG-R1, R2, R3, R4, R6, R7, R8 (SG-R5 lives in velocity.py).
The engine is pure: no I/O, no clock reads, no threads.
"""

from __future__ import annotations

import heapq
import itertools
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable

from sahakari_guard.config import EngineSettings
from sahakari_guard.engine.evidence import EvidenceBuilder
from sahakari_guard.engine.rules import RULES
from sahakari_guard.engine.velocity import VelocityMonitor
from sahakari_guard.models import (
    Alert,
    AlertResolved,
    AlertUpdate,
    Channel,
    Direction,
    EngineOutput,
    FeedEvent,
    LedgerEntry,
    SettlementRecord,
    SwitchEvent,
)
from sahakari_guard.privacy.masker import mask_keep_last
from sahakari_guard.privacy.tokenizer import Tokenizer
from sahakari_guard.timeutil import iso, to_ist

_STATE_EVIDENCE_LIMIT = 12


def default_id_factory() -> str:
    return "AL-" + uuid.uuid4().hex[:10].upper()


@dataclass(slots=True)
class RrnState:
    rrn: str
    first_ts: datetime
    last_ts: datetime
    direction: Direction | None = None
    channel: Channel | None = None
    account_no: str = ""
    sw_approved: int = 0
    sw_reversed: int = 0
    sw_auth_ok: int = 0
    ledger_dr: int = 0
    ledger_cr: int = 0
    nonrev: Counter = field(default_factory=Counter)
    journal_ids: set = field(default_factory=set)
    switch_ids: set = field(default_factory=set)
    settle_keys: set = field(default_factory=set)
    settled_debit: int = 0
    settled_credit: int = 0
    evidence: list = field(default_factory=list)
    deadline: datetime | None = None
    version: int = 0
    closed: bool = False
    outcome: str | None = None  # "matched" | "mismatch"
    open_alerts: dict = field(default_factory=dict)  # rule_id -> alert_id
    alert_amounts: dict = field(default_factory=dict)  # rule_id -> paise last reported

    @property
    def switch_net(self) -> int:
        return max(self.sw_approved - self.sw_reversed, 0)

    @property
    def ledger_net(self) -> int:
        if self.direction is Direction.CREDIT:
            return self.ledger_cr - self.ledger_dr
        return self.ledger_dr - self.ledger_cr

    def add_evidence(self, row: dict) -> None:
        if len(self.evidence) < _STATE_EVIDENCE_LIMIT:
            self.evidence.append(row)


@dataclass
class EngineStats:
    switch_events: int = 0
    ledger_entries: int = 0
    settlement_records: int = 0
    ledger_unlinked: int = 0
    duplicate_lines_ignored: int = 0
    approvals: int = 0
    rrns_tracked: int = 0
    evaluations: int = 0
    matched: int = 0
    mismatched: int = 0
    alerts_by_rule: Counter = field(default_factory=Counter)
    hourly_approvals: Counter = field(default_factory=Counter)
    first_event: datetime | None = None
    last_event: datetime | None = None

    @property
    def events(self) -> int:
        return self.switch_events + self.ledger_entries + self.settlement_records

    def to_dict(self) -> dict:
        decided = self.matched + self.mismatched
        return {
            "events": self.events,
            "switch_events": self.switch_events,
            "ledger_entries": self.ledger_entries,
            "settlement_records": self.settlement_records,
            "ledger_unlinked": self.ledger_unlinked,
            "duplicate_lines_ignored": self.duplicate_lines_ignored,
            "approvals": self.approvals,
            "rrns_tracked": self.rrns_tracked,
            "evaluations": self.evaluations,
            "matched": self.matched,
            "mismatched": self.mismatched,
            "match_rate": round(self.matched / decided, 6) if decided else None,
            "alerts_by_rule": dict(sorted(self.alerts_by_rule.items())),
            "hourly_approvals": dict(sorted(self.hourly_approvals.items())),
            "first_event": iso(self.first_event),
            "last_event": iso(self.last_event),
        }


class Reconciler:
    def __init__(
        self,
        cfg: EngineSettings,
        tokenizer: Tokenizer,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.tokenizer = tokenizer
        self.new_id = id_factory or default_id_factory
        self.evidence = EvidenceBuilder(tokenizer)
        self.velocity = VelocityMonitor(cfg, tokenizer, self.evidence, self.new_id)
        self.window = timedelta(seconds=cfg.match_window_seconds)
        self.retention = timedelta(seconds=cfg.retention_seconds)
        self.stats = EngineStats()
        self.watermark: datetime | None = None
        self._states: dict[str, RrnState] = {}
        self._heap: list[tuple[datetime, int, str, int]] = []
        self._purge_heap: list[tuple[datetime, int, str]] = []
        self._seq = itertools.count()

    # ================================================================== public API

    def process(self, event: FeedEvent) -> list[EngineOutput]:
        """Feed one event. Returns alerts raised, updated or resolved as a result."""
        out = self.advance(event.ts)
        if self.stats.first_event is None or event.ts < self.stats.first_event:
            self.stats.first_event = event.ts
        if self.stats.last_event is None or event.ts > self.stats.last_event:
            self.stats.last_event = event.ts
        if isinstance(event, SwitchEvent):
            out.extend(self._on_switch(event))
        elif isinstance(event, LedgerEntry):
            out.extend(self._on_ledger(event))
        elif isinstance(event, SettlementRecord):
            out.extend(self._on_settlement(event))
        else:  # pragma: no cover - defensive
            raise TypeError(f"unsupported event type {type(event).__name__}")
        return out

    def process_many(self, events: Iterable[FeedEvent]) -> list[EngineOutput]:
        out: list[EngineOutput] = []
        for ev in events:
            out.extend(self.process(ev))
        return out

    def advance(self, ts: datetime) -> list[EngineOutput]:
        """Move event time forward (also used as a heartbeat when feeds are quiet)."""
        if self.watermark is None or ts > self.watermark:
            self.watermark = ts
        out: list[EngineOutput] = []
        while self._heap and self._heap[0][0] <= self.watermark:
            _, _, rrn, version = heapq.heappop(self._heap)
            st = self._states.get(rrn)
            if st is None or st.closed or st.version != version:
                continue
            out.extend(self._evaluate(st, self.watermark))
        self._purge()
        return out

    def finalize(self) -> list[EngineOutput]:
        """End of a complete batch: evaluate every pending RRN at its own deadline."""
        out: list[EngineOutput] = []
        while self._heap:
            deadline, _, rrn, version = heapq.heappop(self._heap)
            st = self._states.get(rrn)
            if st is None or st.closed or st.version != version:
                continue
            out.extend(self._evaluate(st, deadline))
        return out

    @property
    def pending(self) -> int:
        return sum(1 for s in self._states.values() if not s.closed)

    def snapshot_stats(self) -> dict:
        data = self.stats.to_dict()
        data["pending"] = self.pending
        data["watermark"] = iso(self.watermark)
        return data

    # ================================================================== handlers

    def _state_for(self, rrn: str, ts: datetime) -> RrnState:
        st = self._states.get(rrn)
        if st is None:
            st = RrnState(rrn=rrn, first_ts=ts, last_ts=ts)
            self._states[rrn] = st
            self.stats.rrns_tracked += 1
        elif ts < st.first_ts:
            st.first_ts = ts
        return st

    def _touch(self, st: RrnState, ts: datetime) -> None:
        if ts > st.last_ts:
            st.last_ts = ts
        base = ts if self.watermark is None or ts > self.watermark else self.watermark
        st.deadline = base + self.window
        st.version += 1
        st.closed = False
        heapq.heappush(self._heap, (st.deadline, next(self._seq), st.rrn, st.version))

    def _on_switch(self, ev: SwitchEvent) -> list[EngineOutput]:
        st = self._state_for(ev.rrn, ev.ts)
        if ev.identity in st.switch_ids:
            self.stats.duplicate_lines_ignored += 1
            return []
        st.switch_ids.add(ev.identity)
        self.stats.switch_events += 1
        st.direction = ev.direction  # the switch is authoritative on direction
        st.channel = ev.channel
        if not st.account_no:
            st.account_no = ev.account_no
        out: list[EngineOutput] = []
        if ev.approved:
            st.sw_auth_ok += 1
            st.sw_approved += ev.amount
            self.stats.approvals += 1
            self.stats.hourly_approvals[to_ist(ev.ts).strftime("%Y-%m-%dT%H")] += 1
            if st.sw_auth_ok > 1:
                out.extend(self._duplicate(st, ev.ts, "switch", ev.amount, st.sw_auth_ok))
            for item in self.velocity.observe(ev):
                if isinstance(item, Alert):
                    self.stats.alerts_by_rule[item.rule_id] += 1
                out.append(item)
        elif ev.effective_reversal:
            st.sw_reversed += ev.amount
        st.add_evidence(self.evidence.switch(ev))
        self._touch(st, ev.ts)
        return out

    def _on_ledger(self, le: LedgerEntry) -> list[EngineOutput]:
        if not le.rrn:
            # Postings without a switch reference (cash deposits, interest...) are out of scope.
            self.stats.ledger_unlinked += 1
            return []
        st = self._state_for(le.rrn, le.ts)
        if le.journal_id in st.journal_ids:
            self.stats.duplicate_lines_ignored += 1
            return []
        st.journal_ids.add(le.journal_id)
        self.stats.ledger_entries += 1
        if st.direction is None:
            st.direction = le.drcr.opposite if le.is_reversal else le.drcr
        if st.channel is None:
            st.channel = le.channel
        if not st.account_no:
            st.account_no = le.account_no
        if le.drcr is Direction.DEBIT:
            st.ledger_dr += le.amount
        else:
            st.ledger_cr += le.amount
        out: list[EngineOutput] = []
        if not le.is_reversal:
            st.nonrev[le.drcr.value] += 1
            n = st.nonrev[le.drcr.value]
            if n > 1 and le.drcr is st.direction:
                out.extend(self._duplicate(st, le.ts, "ledger", le.amount, n))
        st.add_evidence(self.evidence.ledger(le))
        self._touch(st, le.ts)
        return out

    def _on_settlement(self, rec: SettlementRecord) -> list[EngineOutput]:
        st = self._state_for(rec.rrn, rec.txn_ts if rec.txn_ts and rec.txn_ts < rec.ts else rec.ts)
        key = (rec.cycle_id, rec.direction.value)
        if key in st.settle_keys:
            self.stats.duplicate_lines_ignored += 1
            return []
        st.settle_keys.add(key)
        self.stats.settlement_records += 1
        if rec.settled:
            if rec.direction is Direction.DEBIT:
                st.settled_debit += rec.amount
            else:
                st.settled_credit += rec.amount
        if st.direction is None:
            st.direction = rec.direction
        if st.channel is None:
            st.channel = rec.channel
        if not st.account_no and rec.account_no:
            st.account_no = rec.account_no
        st.add_evidence(self.evidence.settlement(rec))
        self._touch(st, rec.ts)
        return []

    # ================================================================== decisions

    def _classify(self, st: RrnState) -> dict[str, tuple[int, dict]]:
        """Return {rule_id: (amount_at_risk_paise, params)} for this RRN."""
        expected = st.switch_net
        actual = st.ledger_net
        base = {
            "rrn": st.rrn,
            "channel": st.channel.value if st.channel else "",
            "direction": st.direction.value if st.direction else "",
            "account": mask_keep_last(st.account_no),
            "switch_amount": expected,
            "ledger_amount": actual,
            "window": self.cfg.match_window_seconds,
        }
        findings: dict[str, tuple[int, dict]] = {}
        duplicate_open = "SG-R3" in st.open_alerts

        if st.direction is Direction.DEBIT and st.settled_debit > 0 and st.sw_approved == 0:
            findings["SG-R6"] = (st.settled_debit, {**base, "amount": st.settled_debit})
            return findings

        diff = actual - expected
        if diff == 0:
            return findings

        if st.direction is Direction.CREDIT:
            if diff > 0:
                if expected == 0:
                    findings["SG-R2"] = (actual, {**base, "amount": actual})
                elif not duplicate_open:
                    findings["SG-R4"] = (diff, {**base, "amount": diff})
            else:
                if actual <= 0:
                    findings["SG-R8"] = (expected, {**base, "amount": expected})
                elif not duplicate_open:
                    findings["SG-R4"] = (-diff, {**base, "amount": -diff})
        else:  # DEBIT (or unknown, treated as debit)
            if expected > 0 and actual <= 0:
                findings["SG-R1"] = (expected, {**base, "amount": expected})
            elif expected == 0 and actual > 0:
                findings["SG-R7"] = (actual, {**base, "amount": actual})
            elif not duplicate_open:
                findings["SG-R4"] = (abs(diff), {**base, "amount": abs(diff)})
        return findings

    def _evaluate(self, st: RrnState, detected: datetime) -> list[EngineOutput]:
        st.closed = True
        self.stats.evaluations += 1
        findings = self._classify(st)
        out: list[EngineOutput] = []

        for rule_id, alert_id in list(st.open_alerts.items()):
            if rule_id == "SG-R3":
                if st.ledger_net == st.switch_net and st.sw_auth_ok <= 1:
                    out.append(AlertResolved(alert_id, "Duplicate posting was reversed; books balance.", detected))
                    del st.open_alerts[rule_id]
                    st.alert_amounts.pop(rule_id, None)
                continue
            if rule_id not in findings:
                out.append(AlertResolved(alert_id, "A later posting balanced this transaction.", detected))
                del st.open_alerts[rule_id]
                st.alert_amounts.pop(rule_id, None)

        for rule_id, (amount, params) in findings.items():
            if rule_id in st.open_alerts:
                if st.alert_amounts.get(rule_id) != amount:
                    st.alert_amounts[rule_id] = amount
                    out.append(AlertUpdate(st.open_alerts[rule_id], amount, 1, params, detected))
                continue
            alert = self._make_alert(rule_id, st, amount, params, event_time=st.first_ts, detected=detected)
            st.open_alerts[rule_id] = alert.alert_id
            st.alert_amounts[rule_id] = amount
            out.append(alert)

        outcome = "mismatch" if st.open_alerts else "matched"
        if outcome != st.outcome:
            if st.outcome == "matched":
                self.stats.matched -= 1
            elif st.outcome == "mismatch":
                self.stats.mismatched -= 1
            if outcome == "matched":
                self.stats.matched += 1
            else:
                self.stats.mismatched += 1
            st.outcome = outcome

        heapq.heappush(self._purge_heap, (st.last_ts + self.retention, next(self._seq), st.rrn))
        return out

    def _duplicate(self, st: RrnState, ts: datetime, feed: str, amount: int, count: int) -> list[EngineOutput]:
        params = {
            "rrn": st.rrn,
            "feed": feed,
            "count": count,
            "amount": amount,
            "channel": st.channel.value if st.channel else "",
            "account": mask_keep_last(st.account_no),
        }
        if "SG-R3" in st.open_alerts:
            total = st.alert_amounts.get("SG-R3", 0) + amount
            st.alert_amounts["SG-R3"] = total
            return [AlertUpdate(st.open_alerts["SG-R3"], total, count, params, ts)]
        alert = self._make_alert("SG-R3", st, amount, params, event_time=ts, detected=ts)
        alert.count = count
        st.open_alerts["SG-R3"] = alert.alert_id
        st.alert_amounts["SG-R3"] = amount
        return [alert]

    def _make_alert(
        self,
        rule_id: str,
        st: RrnState,
        amount: int,
        params: dict,
        event_time: datetime,
        detected: datetime,
    ) -> Alert:
        spec = RULES[rule_id]
        self.stats.alerts_by_rule[rule_id] += 1
        return Alert(
            alert_id=self.new_id(),
            rule_id=rule_id,
            severity=spec.severity,
            family=spec.family,
            key=f"rrn:{st.rrn}:{rule_id}",
            event_time=event_time,
            detected_event_time=detected,
            amount=amount,
            rrn=st.rrn,
            account_token=self.tokenizer.token(st.account_no),
            account_masked=mask_keep_last(st.account_no),
            channel=st.channel.value if st.channel else "",
            params=params,
            evidence=list(st.evidence),
        )

    def _purge(self) -> None:
        if self.watermark is None:
            return
        while self._purge_heap and self._purge_heap[0][0] <= self.watermark:
            _, _, rrn = heapq.heappop(self._purge_heap)
            st = self._states.get(rrn)
            if st is not None and st.closed and st.last_ts + self.retention <= self.watermark:
                del self._states[rrn]
