from __future__ import annotations

from datetime import timedelta

import pytest

from sahakari_guard.config import EngineSettings, load_settings
from sahakari_guard.models import Channel, Direction, LedgerEntry, MsgType, SettlementRecord, SwitchEvent
from sahakari_guard.timeutil import parse_ts

T0 = parse_ts("2026-11-01T10:00:00+05:30")
ACCOUNT = "00101100000042"
CARD = "6080011234567896"


def sw(sec: float, rrn: str, amount: int, *, direction=Direction.DEBIT, msg=MsgType.AUTH, rc="00",
       channel=Channel.ATM, account=ACCOUNT, country="IN") -> SwitchEvent:
    return SwitchEvent(
        ts=T0 + timedelta(seconds=sec), rrn=rrn, channel=channel, direction=direction, msg_type=msg,
        response_code=rc, amount=amount, account_no=account, card_no=CARD, terminal_id="ATM01",
        terminal_country=country,
    )


def le(sec: float, jid: str, rrn: str, amount: int, *, drcr=Direction.DEBIT, rev=False,
       channel=Channel.ATM, account=ACCOUNT, narration="ATM WDL") -> LedgerEntry:
    return LedgerEntry(
        ts=T0 + timedelta(seconds=sec), journal_id=jid, rrn=rrn, channel=channel, account_no=account,
        drcr=drcr, amount=amount, is_reversal=rev, narration=narration,
    )


def st(sec: float, rrn: str, amount: int, *, direction=Direction.DEBIT, txn_sec: float | None = None,
       cycle="C1", account=ACCOUNT) -> SettlementRecord:
    return SettlementRecord(
        ts=T0 + timedelta(seconds=sec), cycle_id=cycle, rrn=rrn, channel=Channel.ATM, direction=direction,
        amount=amount, txn_ts=T0 + timedelta(seconds=txn_sec) if txn_sec is not None else None, account_no=account,
    )


@pytest.fixture
def engine_settings() -> EngineSettings:
    return EngineSettings()


@pytest.fixture
def settings(tmp_path, monkeypatch):
    for var in ("SG_CONFIG", "SG_DATA_DIR", "SG_API_KEY", "SG_WEBHOOK_URL", "SG_TOKEN_SECRET", "SG_LANGUAGE"):
        monkeypatch.delenv(var, raising=False)
    return load_settings(data_dir=tmp_path / "data")


@pytest.fixture
def service(settings):
    from sahakari_guard.service import GuardService

    svc = GuardService(settings)
    yield svc
    svc.demo.stop(wait=True)
    svc.repo.close()


@pytest.fixture
def client(service):
    from fastapi.testclient import TestClient

    from sahakari_guard.api.app import create_app

    app = create_app(service.settings, service, background=False)
    with TestClient(app) as c:
        yield c
