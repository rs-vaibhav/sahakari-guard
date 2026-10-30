"""Privacy Shield: masks Indian personal identifiers before data leaves the bank.

Two complementary modes:

* **Structured masking** (``mask_value`` with a ``Policy``): used when the column
  is known, e.g. ``account_no`` keeps only the last four digits. Reference
  numbers such as RRN/UTR are deliberately *kept* because investigators need them.
* **Free-text scanning** (``mask_text``): used for narrations, remarks and any
  unknown column. Detectors use check digits (Verhoeff for Aadhaar, Luhn for
  cards) and context words to avoid masking ordinary numbers like amounts.

The design rule is "over-mask rather than leak": if a value is ambiguous in a
free-text field it is masked.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable

from sahakari_guard.privacy.checksums import luhn_valid, verhoeff_valid
from sahakari_guard.privacy.tokenizer import Tokenizer


class Policy(str, Enum):
    KEEP = "KEEP"  # reference numbers, amounts, timestamps
    LAST4 = "LAST4"  # account numbers
    CARD = "CARD"
    AADHAAR = "AADHAAR"
    PAN = "PAN"
    MOBILE = "MOBILE"
    EMAIL = "EMAIL"
    NAME = "NAME"
    TEXT = "TEXT"  # scan free text for identifiers
    DROP = "DROP"


# ---------------------------------------------------------------- formatters

def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def mask_keep_last(value: str, keep: int = 4) -> str:
    """``'001234567890' -> 'XXXXXXXX7890'`` (length preserved, digits only)."""
    digits = _digits(value)
    if not digits:
        return "X" * len(value or "") if value else ""
    if len(digits) <= keep:
        return "X" * len(digits)
    return "X" * (len(digits) - keep) + digits[-keep:]


def mask_card(value: str) -> str:
    digits = _digits(value)
    if len(digits) < 8:
        return "X" * len(digits)
    return "XXXX-XXXX-XXXX-" + digits[-4:]


def mask_aadhaar(value: str) -> str:
    digits = _digits(value)
    if len(digits) != 12:
        return mask_keep_last(value)
    return "XXXX-XXXX-" + digits[-4:]


def mask_pan(value: str) -> str:
    text = (value or "").strip().upper()
    if len(text) != 10:
        return "X" * len(text)
    return "XXXXXX" + text[6:]


def mask_mobile(value: str) -> str:
    digits = _digits(value)
    if len(digits) < 10:
        return "X" * len(digits)
    return "XXXXXX" + digits[-4:]


def mask_email(value: str) -> str:
    text = (value or "").strip()
    if "@" not in text:
        return "X" * len(text)
    local, _, domain = text.partition("@")
    return (local[:1] or "x") + "***@" + domain


def mask_name(value: str) -> str:
    parts = [p for p in re.split(r"\s+", (value or "").strip()) if p]
    return " ".join(p[0] + "***" for p in parts)


# ---------------------------------------------------------------- detectors

_EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# UPI virtual payment address, e.g. ramesh.kumar@oksbi (no dot after the handle)
_VPA_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._-]{3,})@([A-Za-z]{2,})(?![\w.])")
_CARD_RE = re.compile(r"(?<![\dX])(\d(?:[ -]?\d){12,18})(?![\d])")
_AADHAAR_SPACED_RE = re.compile(r"(?<![\dX])(\d{4})[ -](\d{4})[ -](\d{4})(?![\d])")
_AADHAAR_PLAIN_RE = re.compile(r"(?<![\dX])([2-9]\d{11})(?![\d])")
_AADHAAR_CONTEXT_RE = re.compile(r"(aadhaa?r|aadhar|\buid\b|ஆதார்|आधार)", re.IGNORECASE)
_REFERENCE_CONTEXT_RE = re.compile(r"(rrn|ref|utr|upi/|imps/|neft/|txn|stan|wdl|pos)\W{0,3}$", re.IGNORECASE)
_ACCOUNT_RE = re.compile(
    r"(?:(?<![A-Za-z])(?:a/?c|acct|account)|கணக்கு|खाता)(?:\s*(?:no\.?|number|num|#))?\s*[:\-]?\s*(\d{6,18})(?!\d)",
    re.IGNORECASE,
)
_PAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{3}[PCHFATBLJGpchfatbljg][A-Za-z]\d{4}[A-Za-z])(?![A-Za-z0-9])")
_MOBILE_RE = re.compile(r"(?<![\dX])(?:\+91[ -]?|91[ -]?|0)?([6-9]\d{4})[ -]?(\d{5})(?![\d])")
_CARD_GROUPED_RE = re.compile(r"\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}")
_CARD_CONTEXT_RE = re.compile(r"(card|debit|credit|அட்டை|कार्ड)", re.IGNORECASE)


@dataclass
class MaskResult:
    text: str
    counts: Counter = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _context_before(text: str, start: int, width: int = 24) -> str:
    return text[max(0, start - width):start]


def mask_text(text: str) -> MaskResult:
    """Scan free text and mask every identifier found."""
    if not text:
        return MaskResult(text or "")
    counts: Counter = Counter()

    def sub_email(m: re.Match) -> str:
        counts["email"] += 1
        return mask_email(m.group(0))

    def sub_vpa(m: re.Match) -> str:
        local = m.group(1)
        if local.isdigit() and len(local) >= 10:
            counts["mobile"] += 1
            return mask_mobile(local) + "@" + m.group(2)
        counts["vpa"] += 1
        return local[:1] + "***@" + m.group(2)

    def sub_card(m: re.Match) -> str:
        raw = m.group(1)
        digits = _digits(raw)
        if not 13 <= len(digits) <= 19:
            return raw
        # Luhn-valid, written in card groups (4-4-4-4), or next to the word "card": treat as a card number.
        if (
            luhn_valid(digits)
            or _CARD_GROUPED_RE.fullmatch(raw)
            or _CARD_CONTEXT_RE.search(_context_before(m.string, m.start()))
        ):
            counts["card"] += 1
            return mask_card(digits)
        return raw

    def sub_aadhaar_spaced(m: re.Match) -> str:
        # 4-4-4 grouping is the way Aadhaar numbers are printed and typed, so always mask it.
        counts["aadhaar"] += 1
        return mask_aadhaar("".join(m.groups()))

    def sub_aadhaar_plain(m: re.Match) -> str:
        digits = m.group(1)
        context = _context_before(m.string, m.start())
        if _AADHAAR_CONTEXT_RE.search(context):
            counts["aadhaar"] += 1
            return mask_aadhaar(digits)
        if verhoeff_valid(digits) and not _REFERENCE_CONTEXT_RE.search(context):
            counts["aadhaar"] += 1
            return mask_aadhaar(digits)
        return digits

    def sub_account(m: re.Match) -> str:
        counts["account"] += 1
        number = m.group(1)
        return m.group(0)[: m.start(1) - m.start(0)] + mask_keep_last(number)

    def sub_pan(m: re.Match) -> str:
        counts["pan"] += 1
        return mask_pan(m.group(1))

    def sub_mobile(m: re.Match) -> str:
        counts["mobile"] += 1
        return mask_mobile(m.group(1) + m.group(2))

    out = _EMAIL_RE.sub(sub_email, text)
    out = _VPA_RE.sub(sub_vpa, out)
    out = _CARD_RE.sub(sub_card, out)
    out = _AADHAAR_SPACED_RE.sub(sub_aadhaar_spaced, out)
    out = _AADHAAR_PLAIN_RE.sub(sub_aadhaar_plain, out)
    out = _ACCOUNT_RE.sub(sub_account, out)
    out = _PAN_RE.sub(sub_pan, out)
    out = _MOBILE_RE.sub(sub_mobile, out)
    return MaskResult(out, counts)


def find_pii(text: str) -> Counter:
    """Count identifiers still present in ``text`` (used to verify masking)."""
    return mask_text(text).counts


# ---------------------------------------------------------------- structured

def mask_value(value: str, policy: Policy) -> tuple[str, Counter]:
    """Mask one value according to a column policy."""
    value = "" if value is None else str(value)
    counts: Counter = Counter()
    if not value or policy is Policy.KEEP:
        return value, counts
    if policy is Policy.DROP:
        return "", Counter({"dropped": 1})
    if policy is Policy.LAST4:
        counts["account"] += 1
        return mask_keep_last(value), counts
    if policy is Policy.CARD:
        counts["card"] += 1
        return mask_card(value), counts
    if policy is Policy.AADHAAR:
        counts["aadhaar"] += 1
        return mask_aadhaar(value), counts
    if policy is Policy.PAN:
        digits = _digits(value)
        if len(digits) >= 13 and digits == value.replace(" ", "").replace("-", ""):
            # In card systems "PAN" means Primary Account Number (the card number).
            counts["card"] += 1
            return mask_card(value), counts
        counts["pan"] += 1
        return mask_pan(value), counts
    if policy is Policy.MOBILE:
        counts["mobile"] += 1
        return mask_mobile(value), counts
    if policy is Policy.EMAIL:
        counts["email"] += 1
        return mask_email(value), counts
    if policy is Policy.NAME:
        counts["name"] += 1
        return mask_name(value), counts
    result = mask_text(value)
    return result.text, result.counts


_KEEP_TOKENS = {
    "rrn", "utr", "stan", "ref", "reference", "journal", "cycle", "ts", "time", "timestamp", "date",
    "amount", "amt", "channel", "direction", "drcr", "status", "response", "code", "msg", "type",
    "terminal", "country", "settled", "reversal", "currency", "branch", "ifsc", "mcc", "at", "is",
}


def infer_policy(header: str) -> Policy:
    """Pick a masking policy from a column name. Unknown columns are scanned."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", (header or "").lower()) if t]
    joined = "".join(tokens)
    if any(t in ("aadhaar", "aadhar", "uid", "uidai") for t in tokens):
        return Policy.AADHAAR
    if "pan" in tokens or joined in ("panno", "pannumber", "pancard"):
        return Policy.PAN
    if "card" in tokens or "cardno" in joined:
        return Policy.CARD
    if "email" in tokens or "mail" in tokens:
        return Policy.EMAIL
    if any(t in ("mobile", "phone", "msisdn", "contact") for t in tokens):
        return Policy.MOBILE
    if "name" in tokens and not ({"file", "terminal", "bank", "branch"} & set(tokens)):
        return Policy.NAME
    if any(t in ("account", "acct", "acc", "ac") for t in tokens) or joined.startswith(("accountno", "acno", "acctno")):
        return Policy.LAST4
    if tokens and all(t in _KEEP_TOKENS or t in ("id", "no", "number") for t in tokens):
        return Policy.KEEP
    return Policy.TEXT


@dataclass
class CsvMaskReport:
    rows: int
    columns: dict[str, str]
    counts: dict[str, int]
    token_columns: list[str]
    residual: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "rows": self.rows,
            "columns": self.columns,
            "counts": self.counts,
            "token_columns": self.token_columns,
            "residual_identifiers": self.residual,
        }


def mask_csv_text(
    content: str,
    overrides: dict[str, Policy] | None = None,
    tokenizer: Tokenizer | None = None,
) -> tuple[str, CsvMaskReport]:
    """Mask a whole CSV document. Adds ``<col>_token`` columns for accounts if a tokenizer is given."""
    reader = csv.DictReader(io.StringIO(content.lstrip("﻿")))
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")
    header = [h for h in reader.fieldnames]
    policies = {h: (overrides or {}).get(h, infer_policy(h)) for h in header}
    token_cols = [h for h in header if policies[h] in (Policy.LAST4, Policy.CARD) and tokenizer is not None]
    out_header = header + [f"{h}_token" for h in token_cols]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=out_header, lineterminator="\n")
    writer.writeheader()
    totals: Counter = Counter()
    residual: Counter = Counter()
    rows = 0
    for row in reader:
        rows += 1
        out: dict[str, str] = {}
        for h in header:
            raw = row.get(h) or ""
            masked, counts = mask_value(raw, policies[h])
            totals.update(counts)
            out[h] = masked
            if policies[h] is not Policy.KEEP:
                residual.update(find_pii(masked))
        for h in token_cols:
            raw = (row.get(h) or "").strip()
            out[f"{h}_token"] = tokenizer.token(re.sub(r"\D", "", raw) or raw, "card" if policies[h] is Policy.CARD else "acct") if raw else ""
        writer.writerow(out)
    report = CsvMaskReport(
        rows=rows,
        columns={h: p.value for h, p in policies.items()},
        counts=dict(totals),
        token_columns=[f"{h}_token" for h in token_cols],
        residual=dict(residual),
    )
    return buf.getvalue(), report


def mask_csv_file(src: str | Path, dst: str | Path, tokenizer: Tokenizer | None = None) -> CsvMaskReport:
    content = Path(src).read_text(encoding="utf-8-sig")
    masked, report = mask_csv_text(content, tokenizer=tokenizer)
    Path(dst).write_text(masked, encoding="utf-8", newline="")
    return report


def mask_lines(lines: Iterable[str]) -> Iterable[str]:
    for line in lines:
        yield mask_text(line).text
