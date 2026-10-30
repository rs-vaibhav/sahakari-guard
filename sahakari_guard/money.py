"""Money helpers.

Amounts are stored as integer paise everywhere to avoid floating point error.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

MAX_AMOUNT_PAISE = 10**15  # ₹10 lakh crore; anything larger is a data error


def parse_amount_to_paise(value: str | int | float | Decimal) -> int:
    """Parse a rupee amount (``"1,234.50"``) into integer paise.

    Raises ``ValueError`` for blanks, non-numbers, negatives and absurd values.
    """
    if value is None:
        raise ValueError("amount is missing")
    text = str(value).strip().replace(",", "").replace("₹", "").replace("INR", "").strip()
    if not text:
        raise ValueError("amount is empty")
    try:
        amount = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError(f"invalid amount {value!r}") from exc
    if not amount.is_finite():
        raise ValueError(f"invalid amount {value!r}")
    if amount < 0:
        raise ValueError(f"negative amount {value!r}")
    paise = int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if paise > MAX_AMOUNT_PAISE:
        raise ValueError(f"amount {value!r} is implausibly large")
    return paise


def paise_to_str(paise: int) -> str:
    """Plain decimal string, e.g. ``123450 -> '1234.50'`` (used in CSV/JSON)."""
    sign = "-" if paise < 0 else ""
    rupees, p = divmod(abs(int(paise)), 100)
    return f"{sign}{rupees}.{p:02d}"


def _indian_grouping(n: int) -> str:
    s = str(n)
    if len(s) <= 3:
        return s
    head, tail = s[:-3], s[-3:]
    groups = []
    while len(head) > 2:
        groups.insert(0, head[-2:])
        head = head[:-2]
    if head:
        groups.insert(0, head)
    return ",".join(groups + [tail])


def format_inr(paise: int, symbol: bool = True, decimals: bool = True) -> str:
    """Indian-style formatting: ``123456789 -> '₹12,34,567.89'``."""
    paise = int(paise)
    sign = "-" if paise < 0 else ""
    rupees, p = divmod(abs(paise), 100)
    body = _indian_grouping(rupees)
    if decimals:
        body = f"{body}.{p:02d}"
    return f"{sign}{'₹' if symbol else ''}{body}"


def format_inr_short(paise: int) -> str:
    """Short form for dashboards: ₹4.2 Cr, ₹38.5 L, ₹12,400."""
    rupees = abs(int(paise)) / 100
    sign = "-" if paise < 0 else ""
    if rupees >= 1e7:
        return f"{sign}₹{rupees / 1e7:.2f} Cr"
    if rupees >= 1e5:
        return f"{sign}₹{rupees / 1e5:.2f} L"
    return sign + format_inr(abs(int(paise)), decimals=False)
