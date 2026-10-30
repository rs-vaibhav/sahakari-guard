"""Rule catalogue: what each detection rule means and how it is grouped.

Rule IDs are stable (SG-R1 ... SG-R8) so they can be referenced in reports,
tests and documentation. Human-readable text lives in ``sahakari_guard/i18n``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sahakari_guard.models import Severity


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    code: str
    severity: Severity
    family: str
    detects: str  # short English description for docs/CLI; UI uses i18n


@dataclass(frozen=True)
class FamilySpec:
    family: str
    reportable: bool  # counts as a cyber incident with the 6-hour clock


FAMILIES: dict[str, FamilySpec] = {
    "UNAUTHORISED_DEBITS": FamilySpec("UNAUTHORISED_DEBITS", True),
    "ERRONEOUS_CREDITS": FamilySpec("ERRONEOUS_CREDITS", True),
    "INTEGRITY": FamilySpec("INTEGRITY", True),
    "CUSTOMER_SERVICE": FamilySpec("CUSTOMER_SERVICE", False),
}

RULES: dict[str, RuleSpec] = {
    "SG-R1": RuleSpec(
        "SG-R1", "ORPHAN_APPROVAL", Severity.CRITICAL, "UNAUTHORISED_DEBITS",
        "Switch approved a debit but no matching debit reached the core-banking ledger (proxy switch / stand-in fraud).",
    ),
    "SG-R2": RuleSpec(
        "SG-R2", "UNFUNDED_CREDIT", Severity.CRITICAL, "ERRONEOUS_CREDITS",
        "Customer account credited although the network message failed or was reversed (credits without debits).",
    ),
    "SG-R3": RuleSpec(
        "SG-R3", "DUPLICATE_POSTING", Severity.HIGH, "INTEGRITY",
        "Same reference number approved or posted more than once (replayed / duplicated message).",
    ),
    "SG-R4": RuleSpec(
        "SG-R4", "AMOUNT_MISMATCH", Severity.HIGH, "INTEGRITY",
        "Switch and ledger disagree on the amount for the same reference number (tampering or interface bug).",
    ),
    "SG-R5": RuleSpec(
        "SG-R5", "VELOCITY_BURST", Severity.HIGH, "UNAUTHORISED_DEBITS",
        "Abnormal burst of approvals for one account, or foreign cash-out across many countries.",
    ),
    "SG-R6": RuleSpec(
        "SG-R6", "NETWORK_UNAUTHORISED", Severity.CRITICAL, "UNAUTHORISED_DEBITS",
        "Payment network settled a debit that the bank's own switch never approved.",
    ),
    "SG-R7": RuleSpec(
        "SG-R7", "UNAUTHORISED_LEDGER_DEBIT", Severity.MEDIUM, "UNAUTHORISED_DEBITS",
        "Ledger debited a customer for a payment the switch never approved.",
    ),
    "SG-R8": RuleSpec(
        "SG-R8", "MISSING_CREDIT", Severity.MEDIUM, "CUSTOMER_SERVICE",
        "Network confirmed an inward credit but the customer's account was not credited.",
    ),
}


def rule(rule_id: str) -> RuleSpec:
    try:
        return RULES[rule_id]
    except KeyError as exc:
        raise KeyError(f"unknown rule {rule_id}") from exc


def is_reportable(family: str) -> bool:
    spec = FAMILIES.get(family)
    return bool(spec and spec.reportable)
