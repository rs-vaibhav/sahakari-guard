"""Masked evidence records.

Every record that leaves the engine (alerts, reports, the dashboard) passes
through here, so raw account, card, Aadhaar or PAN numbers are never stored.
"""

from __future__ import annotations

from sahakari_guard.models import (
    LedgerEntry,
    OutwardPayment,
    ProfileChange,
    SettlementRecord,
    SwitchEvent,
)
from sahakari_guard.money import paise_to_str
from sahakari_guard.privacy.masker import (
    mask_card,
    mask_email,
    mask_keep_last,
    mask_mobile_last2,
    mask_name,
    mask_text,
)
from sahakari_guard.privacy.tokenizer import Tokenizer
from sahakari_guard.timeutil import iso


class EvidenceBuilder:
    def __init__(self, tokenizer: Tokenizer) -> None:
        self.tokenizer = tokenizer

    def switch(self, e: SwitchEvent) -> dict:
        return {
            "feed": "switch",
            "ts": iso(e.ts),
            "rrn": e.rrn,
            "channel": e.channel.value,
            "direction": e.direction.value,
            "msg_type": e.msg_type.value,
            "response_code": e.response_code,
            "amount": paise_to_str(e.amount),
            "account": mask_keep_last(e.account_no),
            "account_token": self.tokenizer.token(e.account_no),
            "card": mask_card(e.card_no) if e.card_no else "",
            "terminal_id": e.terminal_id,
            "terminal_country": e.terminal_country,
            "counterparty": mask_text(e.counterparty).text if e.counterparty else "",
            "line": e.source_line,
        }

    def ledger(self, e: LedgerEntry) -> dict:
        row = {
            "feed": "ledger",
            "ts": iso(e.ts),
            "rrn": e.rrn,
            "journal_id": e.journal_id,
            "channel": e.channel.value,
            "drcr": e.drcr.value,
            "amount": paise_to_str(e.amount),
            "is_reversal": e.is_reversal,
            "account": mask_keep_last(e.account_no),
            "account_token": self.tokenizer.token(e.account_no),
            "narration": mask_text(e.narration).text if e.narration else "",
            "line": e.source_line,
        }
        if e.utr:
            row["utr"] = e.utr
        if e.beneficiary_account_no:
            row["beneficiary_account"] = mask_keep_last(e.beneficiary_account_no)
        if e.beneficiary_ifsc:
            row["beneficiary_ifsc"] = e.beneficiary_ifsc
        return row

    def profile(self, e: ProfileChange) -> dict:
        old_val = e.old_value
        new_val = e.new_value
        if e.field.upper() == "MOBILE":
            old_val = mask_mobile_last2(old_val) if old_val else ""
            new_val = mask_mobile_last2(new_val) if new_val else ""
        elif e.field.upper() == "EMAIL":
            old_val = mask_email(old_val) if old_val else ""
            new_val = mask_email(new_val) if new_val else ""
        elif old_val or new_val:
            old_val = mask_text(old_val).text if old_val else ""
            new_val = mask_text(new_val).text if new_val else ""
        return {
            "feed": "profile",
            "ts": iso(e.ts),
            "account": mask_keep_last(e.account_no),
            "account_token": self.tokenizer.token(e.account_no),
            "field": e.field,
            "old_value": old_val,
            "new_value": new_val,
            "changed_by": e.changed_by,
            "channel": str(e.channel.value if hasattr(e.channel, "value") else e.channel),
            "line": e.source_line,
        }

    def outward(self, e: OutwardPayment) -> dict:
        return {
            "feed": "outward",
            "ts": iso(e.ts),
            "batch_id": e.batch_id,
            "utr": e.utr,
            "rail": e.rail,
            "account": mask_keep_last(e.debit_account_no),
            "account_token": self.tokenizer.token(e.debit_account_no),
            "beneficiary_account": mask_keep_last(e.beneficiary_account_no),
            "beneficiary_ifsc": e.beneficiary_ifsc,
            "beneficiary_name": mask_name(e.beneficiary_name) if e.beneficiary_name else "",
            "amount": paise_to_str(e.amount),
            "line": e.source_line,
        }

    def settlement(self, e: SettlementRecord) -> dict:
        return {
            "feed": "settlement",
            "ts": iso(e.ts),
            "rrn": e.rrn,
            "cycle_id": e.cycle_id,
            "channel": e.channel.value,
            "direction": e.direction.value,
            "amount": paise_to_str(e.amount),
            "status": e.status,
            "txn_ts": iso(e.txn_ts) if e.txn_ts else "",
            "account": mask_keep_last(e.account_no) if e.account_no else "",
            "line": e.source_line,
        }
