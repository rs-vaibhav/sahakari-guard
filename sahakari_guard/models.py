"""Core data types shared by every layer.

Three input feeds are modelled, all read as *copies* of the bank's logs:

* ``SwitchEvent``      - one line from the ATM/UPI/IMPS switch log
* ``LedgerEntry``      - one posting from the core-banking (CBS) journal
* ``SettlementRecord`` - one line from the payment network's settlement file

Every amount is integer paise. Every timestamp is timezone-aware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Union


class Channel(str, Enum):
    ATM = "ATM"
    POS = "POS"
    UPI = "UPI"
    IMPS = "IMPS"
    BRANCH = "BRANCH"  # ledger-only postings (cash, interest, charges); never reconciled


class Direction(str, Enum):
    """Direction from the bank customer's point of view."""

    DEBIT = "DR"  # money leaves the customer's account (withdrawal, outward transfer)
    CREDIT = "CR"  # money enters the customer's account (inward transfer)

    @property
    def opposite(self) -> "Direction":
        return Direction.CREDIT if self is Direction.DEBIT else Direction.DEBIT


class MsgType(str, Enum):
    AUTH = "AUTH"
    REVERSAL = "REVERSAL"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]

    @classmethod
    def max(cls, a: "Severity", b: "Severity") -> "Severity":
        return a if a.rank >= b.rank else b


APPROVED_CODES = frozenset({"00"})


@dataclass(frozen=True, slots=True)
class SwitchEvent:
    ts: datetime
    rrn: str
    channel: Channel
    direction: Direction
    msg_type: MsgType
    response_code: str
    amount: int
    account_no: str
    card_no: str = ""
    terminal_id: str = ""
    terminal_country: str = ""
    counterparty: str = ""
    source_line: int = 0

    feed = "switch"

    @property
    def approved(self) -> bool:
        """A successful authorisation (money moved or was promised)."""
        return self.msg_type is MsgType.AUTH and self.response_code in APPROVED_CODES

    @property
    def effective_reversal(self) -> bool:
        """A reversal that the switch accepted."""
        return self.msg_type is MsgType.REVERSAL and self.response_code in APPROVED_CODES

    @property
    def identity(self) -> tuple:
        """Used to ignore byte-identical lines when a log is re-exported."""
        return (self.rrn, self.msg_type.value, self.ts.isoformat(), self.response_code, self.amount)


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    ts: datetime
    journal_id: str
    rrn: str
    channel: Channel
    account_no: str
    drcr: Direction
    amount: int
    is_reversal: bool = False
    narration: str = ""
    source_line: int = 0

    feed = "ledger"


@dataclass(frozen=True, slots=True)
class SettlementRecord:
    ts: datetime  # when the settlement file for this cycle was produced
    cycle_id: str
    rrn: str
    channel: Channel
    direction: Direction
    amount: int
    status: str = "SETTLED"
    txn_ts: datetime | None = None  # original transaction time, when the network file carries it
    account_no: str = ""  # issuer-side account/card reference, when available
    source_line: int = 0

    feed = "settlement"

    @property
    def settled(self) -> bool:
        return self.status.upper() == "SETTLED"


FeedEvent = Union[SwitchEvent, LedgerEntry, SettlementRecord]

FEED_ORDER = {"switch": 0, "ledger": 1, "settlement": 2}


def event_sort_key(event: FeedEvent) -> tuple:
    return (event.ts, FEED_ORDER[event.feed], event.source_line)


@dataclass(slots=True)
class Alert:
    """A single finding raised by the engine. Evidence is always masked."""

    alert_id: str
    rule_id: str
    severity: Severity
    family: str
    key: str
    event_time: datetime  # first offending event (event time)
    detected_event_time: datetime  # when the engine could conclude (event time)
    amount: int = 0  # paise at risk
    rrn: str = ""
    account_token: str = ""
    account_masked: str = ""
    channel: str = ""
    count: int = 1
    params: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    status: str = "OPEN"
    note: str = ""


@dataclass(slots=True)
class AlertUpdate:
    """An open alert grew (for example, a burst continued)."""

    alert_id: str
    amount: int
    count: int
    params: dict[str, Any]
    detected_event_time: datetime
    evidence_append: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class AlertResolved:
    """A late posting balanced the transaction, so the alert closes itself."""

    alert_id: str
    note: str
    resolved_event_time: datetime


EngineOutput = Union[Alert, AlertUpdate, AlertResolved]


@dataclass(frozen=True, slots=True)
class RowError:
    line: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"line": self.line, "message": self.message}
