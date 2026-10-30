"""Masked evidence records.

Every record that leaves the engine (alerts, reports, the dashboard) passes
through here, so raw account, card, Aadhaar or PAN numbers are never stored.
"""

from __future__ import annotations

from sahakari_guard.models import LedgerEntry, SettlementRecord, SwitchEvent
from sahakari_guard.money import paise_to_str
from sahakari_guard.privacy.masker import mask_card, mask_keep_last, mask_text
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
        return {
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
