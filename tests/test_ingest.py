from __future__ import annotations

import pytest

from sahakari_guard.ingest import FeedTailer, IngestError, parse_bytes
from sahakari_guard.ingest.parsers import write_ledger_csv, write_settlement_csv, write_switch_csv
from sahakari_guard.models import Direction, MsgType
from sahakari_guard.simulator import build_day

SWITCH_HEADER = "ts,rrn,channel,direction,msg_type,response_code,amount,account_no,card_no,terminal_id,terminal_country,counterparty\n"


def test_parse_switch_with_aliases_and_bom():
    data = ("﻿" + SWITCH_HEADER + "2026-11-01 10:00:00,630510000001,atm,DEBIT,0200,00,\"1,500.50\",0010,,,IN,\n").encode()
    result = parse_bytes(data, "switch.csv")
    assert result.kind == "switch" and result.error_count == 0
    (ev,) = result.records
    assert ev.amount == 150050 and ev.direction is Direction.DEBIT and ev.msg_type is MsgType.AUTH
    assert ev.ts.utcoffset().total_seconds() == 19800  # naive time treated as IST
    assert len(result.sha256) == 64


def test_bad_rows_are_reported_not_fatal():
    data = (
        SWITCH_HEADER
        + "2026-11-01T10:00:00+05:30,630510000001,ATM,DR,AUTH,00,100.00,0010,,,IN,\n"
        + "yesterday,630510000002,ATM,DR,AUTH,00,100.00,0010,,,IN,\n"
        + "2026-11-01T10:00:00+05:30,630510000003,BUS,DR,AUTH,00,100.00,0010,,,IN,\n"
        + "2026-11-01T10:00:00+05:30,630510000004,ATM,DR,AUTH,00,-5,0010,,,IN,\n"
        + "\n"
    ).encode()
    result = parse_bytes(data, "switch.csv")
    assert len(result.records) == 1
    assert result.error_count == 3
    assert [e.line for e in result.errors] == [3, 4, 5]


def test_missing_columns_rejected_with_clear_message():
    with pytest.raises(IngestError, match="could not recognise"):
        parse_bytes(b"foo,bar\n1,2\n", "x.csv")
    with pytest.raises(IngestError, match="missing required"):
        parse_bytes(b"ts,rrn\n", "x.csv", kind="switch")
    with pytest.raises(IngestError, match="UTF-8"):
        parse_bytes(b"\xff\xfe\x00bad", "x.csv")


def test_writers_round_trip():
    day = build_day("cosmos", seed=3, transactions=1000)
    for writer, records in (
        (write_switch_csv, day.switch), (write_ledger_csv, day.ledger), (write_settlement_csv, day.settlement)
    ):
        parsed = parse_bytes(writer(records).encode(), "f.csv")
        assert parsed.error_count == 0
        assert len(parsed.records) == len(records)
        assert sorted(r.amount for r in parsed.records) == sorted(r.amount for r in records)


def test_tailer_reads_only_complete_new_lines(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    log = inbox / "switch_log.csv"
    log.write_text(SWITCH_HEADER + "2026-11-01T10:00:00+05:30,630510000001,ATM,DR,AUTH,00,100.00,0010,,,IN,\n2026-11-01T10:00:0", encoding="utf-8")
    tailer = FeedTailer(inbox, tmp_path / "state.json")
    first = tailer.poll()
    assert len(first.events) == 1
    with log.open("a", encoding="utf-8") as fh:
        fh.write("5+05:30,630510000002,ATM,DR,AUTH,00,200.00,0010,,,IN,\n")
    second = tailer.poll()
    assert [e.rrn for e in second.events] == ["630510000002"]
    assert tailer.poll().events == []
    # A new tailer resumes from the saved offset.
    assert FeedTailer(inbox, tmp_path / "state.json").poll().events == []
