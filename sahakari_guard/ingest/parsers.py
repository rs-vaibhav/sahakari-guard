"""Parsers for the three canonical CSV feeds.

Banks export logs in vendor-specific formats; a small adapter converts each
export into these canonical columns (documented in ``docs/DATA_FORMATS.md``).

Parsing is defensive: a bad row is reported with its line number and skipped,
it never stops the run. A file with missing required columns is rejected as a
whole with a clear message.
"""

from __future__ import annotations

import csv
import hashlib
import io
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Generic, Iterable, TypeVar

from sahakari_guard.models import (
    Channel,
    Direction,
    LedgerEntry,
    MsgType,
    OutwardPayment,
    ProfileChange,
    RowError,
    SettlementRecord,
    SwitchEvent,
)
from sahakari_guard.money import paise_to_str, parse_amount_to_paise
from sahakari_guard.timeutil import iso, parse_ts

T = TypeVar("T")

SWITCH_COLUMNS = (
    "ts", "rrn", "channel", "direction", "msg_type", "response_code", "amount",
    "account_no", "card_no", "terminal_id", "terminal_country", "counterparty",
)
SWITCH_REQUIRED = ("ts", "rrn", "channel", "direction", "msg_type", "response_code", "amount", "account_no")

LEDGER_COLUMNS = (
    "ts", "journal_id", "rrn", "channel", "account_no", "drcr", "amount", "is_reversal",
    "narration", "utr", "beneficiary_account_no", "beneficiary_ifsc",
)
LEDGER_REQUIRED = ("ts", "journal_id", "rrn", "channel", "account_no", "drcr", "amount")

SETTLEMENT_COLUMNS = ("cycle_id", "settled_at", "rrn", "channel", "direction", "amount", "status", "txn_ts", "account_no")
SETTLEMENT_REQUIRED = ("cycle_id", "settled_at", "rrn", "channel", "direction", "amount")

PROFILE_COLUMNS = ("ts", "account_no", "field", "old_value", "new_value", "changed_by", "channel")
PROFILE_REQUIRED = ("ts", "account_no", "field", "changed_by", "channel")

OUTWARD_COLUMNS = (
    "ts", "batch_id", "utr", "rail", "debit_account_no", "beneficiary_account_no",
    "beneficiary_ifsc", "beneficiary_name", "amount",
)
OUTWARD_REQUIRED = (
    "ts", "batch_id", "utr", "rail", "debit_account_no", "beneficiary_account_no",
    "beneficiary_ifsc", "amount",
)

MAX_ERRORS_KEPT = 500


class IngestError(ValueError):
    """The file as a whole cannot be used (wrong columns, wrong encoding...)."""


class RowParseError(ValueError):
    pass


@dataclass
class ParseResult(Generic[T]):
    kind: str
    name: str
    sha256: str
    records: list[T] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)
    error_count: int = 0
    rows: int = 0

    def summary(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "sha256": self.sha256,
            "rows": self.rows,
            "parsed": len(self.records),
            "rejected": self.error_count,
            "errors": [e.to_dict() for e in self.errors[:20]],
        }


# ------------------------------------------------------------------ field helpers

_DIRECTION_ALIASES = {
    "DR": Direction.DEBIT, "D": Direction.DEBIT, "DEBIT": Direction.DEBIT, "OUT": Direction.DEBIT, "OUTWARD": Direction.DEBIT,
    "CR": Direction.CREDIT, "C": Direction.CREDIT, "CREDIT": Direction.CREDIT, "IN": Direction.CREDIT, "INWARD": Direction.CREDIT,
}
_BOOL_TRUE = {"1", "true", "yes", "y", "t"}
_BOOL_FALSE = {"0", "false", "no", "n", "f", ""}


def _req(row: dict, key: str) -> str:
    value = (row.get(key) or "").strip()
    if not value:
        raise RowParseError(f"'{key}' is empty")
    return value


def _channel(value: str) -> Channel:
    try:
        return Channel(value.strip().upper())
    except ValueError as exc:
        raise RowParseError(f"unknown channel {value!r} (expected ATM, POS, UPI, IMPS, NEFT, RTGS or BRANCH)") from exc


def _direction(value: str) -> Direction:
    try:
        return _DIRECTION_ALIASES[value.strip().upper()]
    except KeyError as exc:
        raise RowParseError(f"unknown direction {value!r} (expected DR or CR)") from exc


def _msg_type(value: str) -> MsgType:
    v = value.strip().upper()
    if v in ("AUTH", "AUTHORISATION", "AUTHORIZATION", "0100", "0200", "0210"):
        return MsgType.AUTH
    if v in ("REVERSAL", "REV", "0400", "0420", "0430"):
        return MsgType.REVERSAL
    raise RowParseError(f"unknown msg_type {value!r} (expected AUTH or REVERSAL)")


def _bool(value: str | None) -> bool:
    v = (value or "").strip().lower()
    if v in _BOOL_TRUE:
        return True
    if v in _BOOL_FALSE:
        return False
    raise RowParseError(f"invalid boolean {value!r}")


def _ts(value: str):
    try:
        return parse_ts(value)
    except ValueError as exc:
        raise RowParseError(str(exc)) from exc


def _amount(value: str) -> int:
    try:
        return parse_amount_to_paise(value)
    except ValueError as exc:
        raise RowParseError(str(exc)) from exc


def _rrn(value: str) -> str:
    v = value.strip()
    if len(v) > 32 or not v.replace("-", "").isalnum():
        raise RowParseError(f"invalid reference number {value!r}")
    return v


# ------------------------------------------------------------------ row converters

def row_to_switch(row: dict, line: int = 0) -> SwitchEvent:
    return SwitchEvent(
        ts=_ts(_req(row, "ts")),
        rrn=_rrn(_req(row, "rrn")),
        channel=_channel(_req(row, "channel")),
        direction=_direction(_req(row, "direction")),
        msg_type=_msg_type(_req(row, "msg_type")),
        response_code=_req(row, "response_code").upper(),
        amount=_amount(_req(row, "amount")),
        account_no=_req(row, "account_no"),
        card_no=(row.get("card_no") or "").strip(),
        terminal_id=(row.get("terminal_id") or "").strip(),
        terminal_country=(row.get("terminal_country") or "").strip().upper(),
        counterparty=(row.get("counterparty") or "").strip(),
        source_line=line,
    )


def row_to_ledger(row: dict, line: int = 0) -> LedgerEntry:
    return LedgerEntry(
        ts=_ts(_req(row, "ts")),
        journal_id=_req(row, "journal_id"),
        rrn=_rrn(row["rrn"]) if (row.get("rrn") or "").strip() else "",
        channel=_channel(_req(row, "channel")),
        account_no=_req(row, "account_no"),
        drcr=_direction(_req(row, "drcr")),
        amount=_amount(_req(row, "amount")),
        is_reversal=_bool(row.get("is_reversal")),
        narration=(row.get("narration") or "").strip(),
        utr=(row.get("utr") or "").strip(),
        beneficiary_account_no=(row.get("beneficiary_account_no") or "").strip(),
        beneficiary_ifsc=(row.get("beneficiary_ifsc") or "").strip().upper(),
        source_line=line,
    )


def row_to_settlement(row: dict, line: int = 0) -> SettlementRecord:
    return SettlementRecord(
        ts=_ts(_req(row, "settled_at")),
        cycle_id=_req(row, "cycle_id"),
        rrn=_rrn(_req(row, "rrn")),
        channel=_channel(_req(row, "channel")),
        direction=_direction(_req(row, "direction")),
        amount=_amount(_req(row, "amount")),
        status=(row.get("status") or "SETTLED").strip().upper() or "SETTLED",
        txn_ts=_ts(row["txn_ts"]) if (row.get("txn_ts") or "").strip() else None,
        account_no=(row.get("account_no") or "").strip(),
        source_line=line,
    )


def row_to_profile(row: dict, line: int = 0) -> ProfileChange:
    field_val = _req(row, "field").strip().upper()
    return ProfileChange(
        ts=_ts(_req(row, "ts")),
        account_no=_req(row, "account_no"),
        field=field_val,
        old_value=(row.get("old_value") or "").strip(),
        new_value=(row.get("new_value") or "").strip(),
        changed_by=_req(row, "changed_by"),
        channel=(row.get("channel") or "").strip().upper(),
        source_line=line,
    )


def row_to_outward(row: dict, line: int = 0) -> OutwardPayment:
    return OutwardPayment(
        ts=_ts(_req(row, "ts")),
        batch_id=_req(row, "batch_id"),
        utr=_req(row, "utr"),
        rail=_req(row, "rail").strip().upper(),
        debit_account_no=_req(row, "debit_account_no"),
        beneficiary_account_no=_req(row, "beneficiary_account_no"),
        beneficiary_ifsc=_req(row, "beneficiary_ifsc").strip().upper(),
        beneficiary_name=(row.get("beneficiary_name") or "").strip(),
        amount=_amount(_req(row, "amount")),
        source_line=line,
    )


FEEDS: dict[str, tuple[tuple[str, ...], Callable[[dict, int], object]]] = {
    "switch": (SWITCH_REQUIRED, row_to_switch),
    "ledger": (LEDGER_REQUIRED, row_to_ledger),
    "settlement": (SETTLEMENT_REQUIRED, row_to_settlement),
    "profile": (PROFILE_REQUIRED, row_to_profile),
    "outward": (OUTWARD_REQUIRED, row_to_outward),
}


def detect_kind(header: Iterable[str]) -> str | None:
    """Guess which feed a CSV belongs to from its header."""
    cols = {h.strip().lower() for h in header if h}
    if set(OUTWARD_REQUIRED) <= cols:
        return "outward"
    if set(PROFILE_REQUIRED) <= cols:
        return "profile"
    if set(SWITCH_REQUIRED) <= cols:
        return "switch"
    if set(LEDGER_REQUIRED) <= cols:
        return "ledger"
    if set(SETTLEMENT_REQUIRED) <= cols:
        return "settlement"
    return None


def _decode(data: bytes, name: str) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError(f"{name}: file is not UTF-8 text") from exc


def parse_outward_xml(data: bytes, name: str) -> ParseResult[OutwardPayment]:
    data_lower = data.lower()
    if b"<!doctype" in data_lower or b"<!entity" in data_lower:
        raise IngestError(f"{name}: XML with DTD or entity declarations is rejected for safety")

    text = _decode(data, name)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise IngestError(f"{name}: invalid XML: {exc}") from exc

    result: ParseResult[OutwardPayment] = ParseResult(
        kind="outward", name=name, sha256=hashlib.sha256(data).hexdigest()
    )
    lines = text.splitlines()
    payment_lines: list[int] = [i + 1 for i, l in enumerate(lines) if "<payment" in l.lower()]

    payments = root.findall(".//Payment")
    if not payments and root.tag.lower() == "payment":
        payments = [root]

    for i, elem in enumerate(payments):
        line = payment_lines[i] if i < len(payment_lines) else (i + 1)
        result.rows += 1

        def get_f(tag: str) -> str:
            child = elem.find(tag)
            if child is not None and child.text:
                return child.text.strip()
            return (elem.attrib.get(tag) or "").strip()

        row_dict = {
            "ts": get_f("ts"),
            "batch_id": get_f("batch_id"),
            "utr": get_f("utr"),
            "rail": get_f("rail"),
            "debit_account_no": get_f("debit_account_no"),
            "beneficiary_account_no": get_f("beneficiary_account_no"),
            "beneficiary_ifsc": get_f("beneficiary_ifsc"),
            "beneficiary_name": get_f("beneficiary_name"),
            "amount": get_f("amount"),
        }
        try:
            result.records.append(row_to_outward(row_dict, line))
        except RowParseError as exc:
            result.error_count += 1
            if len(result.errors) < MAX_ERRORS_KEPT:
                result.errors.append(RowError(line, str(exc)))
    return result


def parse_bytes(data: bytes, name: str, kind: str | None = None) -> ParseResult:
    """Parse a feed from bytes. If XML, parses as outward payment feed. CSV kind is detected from the header if omitted."""
    stripped = data.strip()
    if stripped.startswith(b"<") or name.lower().endswith(".xml"):
        return parse_outward_xml(data, name)

    text = _decode(data, name)
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise IngestError(f"{name}: file is empty or has no header row")
    reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
    detected = detect_kind(reader.fieldnames)
    kind = kind or detected
    if kind not in FEEDS:
        raise IngestError(
            f"{name}: could not recognise the columns {reader.fieldnames}. "
            "Expected a switch log, CBS ledger, settlement, profile changes, or outward payments file (see docs/DATA_FORMATS.md)."
        )
    required, converter = FEEDS[kind]
    missing = [c for c in required if c not in reader.fieldnames]
    if missing:
        raise IngestError(f"{name}: missing required column(s) for {kind} feed: {', '.join(missing)}")

    result: ParseResult = ParseResult(kind=kind, name=name, sha256=hashlib.sha256(data).hexdigest())
    for row in reader:
        line = reader.line_num
        if not any((v or "").strip() for v in row.values() if isinstance(v, str)):
            continue  # skip blank lines
        result.rows += 1
        try:
            result.records.append(converter(row, line))
        except RowParseError as exc:
            result.error_count += 1
            if len(result.errors) < MAX_ERRORS_KEPT:
                result.errors.append(RowError(line, str(exc)))
    return result


def parse_file(path: str | Path, kind: str | None = None) -> ParseResult:
    p = Path(path)
    return parse_bytes(p.read_bytes(), p.name, kind)


# ------------------------------------------------------------------ writers (used by the simulator)

def _write(path: Path | None, header: tuple[str, ...], rows: Iterable[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(header), lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    text = buf.getvalue()
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    return text


def switch_to_row(e: SwitchEvent) -> dict:
    return {
        "ts": iso(e.ts), "rrn": e.rrn, "channel": e.channel.value, "direction": e.direction.value,
        "msg_type": e.msg_type.value, "response_code": e.response_code, "amount": paise_to_str(e.amount),
        "account_no": e.account_no, "card_no": e.card_no, "terminal_id": e.terminal_id,
        "terminal_country": e.terminal_country, "counterparty": e.counterparty,
    }


def ledger_to_row(e: LedgerEntry) -> dict:
    row = {
        "ts": iso(e.ts), "journal_id": e.journal_id, "rrn": e.rrn, "channel": e.channel.value,
        "account_no": e.account_no, "drcr": e.drcr.value, "amount": paise_to_str(e.amount),
        "is_reversal": "1" if e.is_reversal else "0", "narration": e.narration,
    }
    if e.utr or e.beneficiary_account_no or e.beneficiary_ifsc:
        row["utr"] = e.utr
        row["beneficiary_account_no"] = e.beneficiary_account_no
        row["beneficiary_ifsc"] = e.beneficiary_ifsc
    return row


def settlement_to_row(e: SettlementRecord) -> dict:
    return {
        "cycle_id": e.cycle_id, "settled_at": iso(e.ts), "rrn": e.rrn, "channel": e.channel.value,
        "direction": e.direction.value, "amount": paise_to_str(e.amount), "status": e.status,
        "txn_ts": iso(e.txn_ts) or "", "account_no": e.account_no,
    }


def profile_to_row(p: ProfileChange) -> dict:
    return {
        "ts": iso(p.ts),
        "account_no": p.account_no,
        "field": p.field,
        "old_value": p.old_value,
        "new_value": p.new_value,
        "changed_by": p.changed_by,
        "channel": str(p.channel.value if hasattr(p.channel, "value") else p.channel),
    }


def outward_to_row(o: OutwardPayment) -> dict:
    return {
        "ts": iso(o.ts),
        "batch_id": o.batch_id,
        "utr": o.utr,
        "rail": o.rail,
        "debit_account_no": o.debit_account_no,
        "beneficiary_account_no": o.beneficiary_account_no,
        "beneficiary_ifsc": o.beneficiary_ifsc,
        "beneficiary_name": o.beneficiary_name,
        "amount": paise_to_str(o.amount),
    }


def write_switch_csv(events: Iterable[SwitchEvent], path: Path | None = None) -> str:
    return _write(path, SWITCH_COLUMNS, (switch_to_row(e) for e in events))


def write_ledger_csv(entries: Iterable[LedgerEntry], path: Path | None = None) -> str:
    return _write(path, LEDGER_COLUMNS, (ledger_to_row(e) for e in entries))


def write_settlement_csv(records: Iterable[SettlementRecord], path: Path | None = None) -> str:
    return _write(path, SETTLEMENT_COLUMNS, (settlement_to_row(e) for e in records))


def write_profile_csv(events: Iterable[ProfileChange], path: Path | None = None) -> str:
    return _write(path, PROFILE_COLUMNS, (profile_to_row(e) for e in events))


def write_outward_csv(payments: Iterable[OutwardPayment], path: Path | None = None) -> str:
    return _write(path, OUTWARD_COLUMNS, (outward_to_row(e) for e in payments))
