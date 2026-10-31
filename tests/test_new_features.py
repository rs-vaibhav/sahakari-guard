from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

from sahakari_guard.config import EngineSettings
from sahakari_guard.engine.baseline import (
    build_baseline_from_events,
    build_baseline_from_files,
    classify_day_type,
    is_second_or_fourth_saturday,
)
from sahakari_guard.engine.reconciler import Reconciler
from sahakari_guard.engine.runner import run_events
from sahakari_guard.ingest import IngestError, parse_bytes, parse_file
from sahakari_guard.ingest.parsers import (
    write_ledger_csv,
    write_outward_csv,
    write_profile_csv,
)
from sahakari_guard.models import (
    Alert,
    AlertResolved,
    AlertUpdate,
    Channel,
    Direction,
    LedgerEntry,
    MsgType,
    OutwardPayment,
    ProfileChange,
    Severity,
    SwitchEvent,
)
from sahakari_guard.privacy.masker import mask_mobile_last2
from sahakari_guard.privacy.tokenizer import Tokenizer
from sahakari_guard.simulator.scenarios import build_day
from sahakari_guard.timeutil import IST


# =====================================================================
# 1. PARSERS & FEEDS
# =====================================================================

def test_profile_changes_parser_happy_path():
    csv_text = (
        "ts,account_no,field,old_value,new_value,changed_by,channel\n"
        "2026-11-02T10:00:00+05:30,001010001,MOBILE,9876543210,9123456789,ADMIN1,BRANCH\n"
        "2026-11-02T10:05:00+05:30,001010002,EMAIL,old@bank.com,new@bank.com,ADMIN2,NETBANK\n"
    )
    result = parse_bytes(csv_text.encode("utf-8"), "profile_changes.csv")
    assert result.kind == "profile"
    assert result.error_count == 0
    assert len(result.records) == 2
    r1, r2 = result.records
    assert isinstance(r1, ProfileChange)
    assert r1.account_no == "001010001"
    assert r1.field == "MOBILE"
    assert r1.old_value == "9876543210"
    assert r1.new_value == "9123456789"
    assert r1.changed_by == "ADMIN1"


def test_profile_changes_bad_rows_reported():
    csv_text = (
        "ts,account_no,field,old_value,new_value,changed_by,channel\n"
        "not-a-ts,001010001,MOBILE,9876543210,9123456789,ADMIN1,BRANCH\n"
        "2026-11-02T10:00:00+05:30,,MOBILE,9876543210,9123456789,ADMIN1,BRANCH\n"
    )
    result = parse_bytes(csv_text.encode("utf-8"), "profile_changes.csv")
    assert result.error_count == 2
    assert [e.line for e in result.errors] == [2, 3]


def test_optional_ledger_columns():
    # Legacy ledger format without UTR / beneficiary columns
    legacy_csv = (
        "ts,journal_id,rrn,channel,account_no,drcr,amount,is_reversal,narration\n"
        "2026-11-02T10:00:00+05:30,J1,630510000001,UPI,001010001,DR,100000,false,UPI/TEST\n"
    )
    res_leg = parse_bytes(legacy_csv.encode("utf-8"), "ledger.csv")
    assert res_leg.kind == "ledger"
    assert len(res_leg.records) == 1
    assert res_leg.records[0].utr == ""

    # New ledger format with optional columns
    new_csv = (
        "ts,journal_id,rrn,channel,account_no,drcr,amount,is_reversal,narration,utr,beneficiary_account_no,beneficiary_ifsc\n"
        "2026-11-02T10:00:00+05:30,J2,UTR123,NEFT,001010001,DR,5000000,false,NEFT/TEST,UTR123,919876543210,SBIN0001234\n"
    )
    res_new = parse_bytes(new_csv.encode("utf-8"), "ledger.csv")
    assert res_new.kind == "ledger"
    assert len(res_new.records) == 1
    rec = res_new.records[0]
    assert rec.utr == "UTR123"
    assert rec.beneficiary_account_no == "919876543210"
    assert rec.beneficiary_ifsc == "SBIN0001234"


def test_outward_csv_parsing():
    csv_text = (
        "ts,batch_id,utr,rail,debit_account_no,beneficiary_account_no,beneficiary_ifsc,beneficiary_name,amount\n"
        "2026-11-02T11:00:00+05:30,B1,SBIN123,NEFT,001010001,919999999999,HDFC0001234,Ramesh,650000.00\n"
    )
    result = parse_bytes(csv_text.encode("utf-8"), "outward.csv")
    assert result.kind == "outward"
    assert len(result.records) == 1
    rec = result.records[0]
    assert isinstance(rec, OutwardPayment)
    assert rec.utr == "SBIN123"
    assert rec.amount == 65000000
    assert rec.beneficiary_name == "Ramesh"


def test_outward_xml_happy_path():
    xml_data = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<Payments>\n'
        b'  <Payment>\n'
        b'    <ts>2026-11-02T11:30:00+05:30</ts>\n'
        b'    <batch_id>BATCH01</batch_id>\n'
        b'    <utr>SBIN9990001</utr>\n'
        b'    <rail>RTGS</rail>\n'
        b'    <debit_account_no>001010001</debit_account_no>\n'
        b'    <beneficiary_account_no>881234567890</beneficiary_account_no>\n'
        b'    <beneficiary_ifsc>HDFC0009999</beneficiary_ifsc>\n'
        b'    <beneficiary_name>Deepa Kumar</beneficiary_name>\n'
        b'    <amount>750000.00</amount>\n'
        b'  </Payment>\n'
        b'</Payments>\n'
    )
    res = parse_bytes(xml_data, "outward.xml")
    assert res.kind == "outward"
    assert res.error_count == 0
    assert len(res.records) == 1
    rec = res.records[0]
    assert rec.utr == "SBIN9990001"
    assert rec.amount == 75000000
    assert rec.beneficiary_ifsc == "HDFC0009999"


def test_outward_xml_rejects_dtd_entities():
    malicious_dtd = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        b'<Payments><Payment><utr>&xxe;</utr></Payment></Payments>'
    )
    with pytest.raises(IngestError, match="DTD or entity declarations"):
        parse_bytes(malicious_dtd, "outward.xml")


def test_writers_round_trip_profile_and_outward():
    ts = datetime(2026, 11, 2, 10, 0, tzinfo=IST)
    profiles = [
        ProfileChange(ts=ts, account_no="001001", field="MOBILE", old_value="9876543210", new_value="9123456789", changed_by="STAFF1", channel="CBS")
    ]
    outwards = [
        OutwardPayment(ts=ts, batch_id="B1", utr="UTR01", rail="NEFT", debit_account_no="001001", beneficiary_account_no="88111", beneficiary_ifsc="SBIN01", beneficiary_name="Bob", amount=100000)
    ]
    p_csv = write_profile_csv(profiles)
    parsed_p = parse_bytes(p_csv.encode("utf-8"), "profiles.csv")
    assert len(parsed_p.records) == 1
    assert parsed_p.records[0].account_no == "001001"

    o_csv = write_outward_csv(outwards)
    parsed_o = parse_bytes(o_csv.encode("utf-8"), "outwards.csv")
    assert len(parsed_o.records) == 1
    assert parsed_o.records[0].utr == "UTR01"


# =====================================================================
# 2. RULE SG-R9 ("Contact changed, then money out")
# =====================================================================

def test_sg_r9_positive_single_large_debit():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    change = ProfileChange(
        ts=t0,
        account_no="001010001",
        field="MOBILE",
        old_value="9876543210",
        new_value="9999999999",
        changed_by="ADMIN1",
        channel="BRANCH",
    )
    outputs = reconciler.process(change)
    assert not outputs

    # Outward debit of Rs 1,50,000 (>= Rs 1,00,000) within 24 hours
    t1 = t0 + timedelta(hours=1)
    ev_switch = SwitchEvent(
        ts=t1,
        rrn="630511000001",
        channel=Channel.IMPS,
        direction=Direction.DEBIT,
        msg_type=MsgType.AUTH,
        response_code="00",
        amount=15000000,
        account_no="001010001",
    )
    outputs2 = reconciler.process(ev_switch)
    r9_alerts = [o for o in outputs2 if isinstance(o, Alert) and o.rule_id == "SG-R9"]
    assert len(r9_alerts) == 1
    a = r9_alerts[0]
    assert a.severity == Severity.CRITICAL
    assert a.amount == 15000000
    assert a.count == 1
    assert a.params["field"] == "MOBILE"
    # Mobile number masked: keeps last 2 digits
    assert mask_mobile_last2("9876543210") == "XXXXXXXX10"
    assert a.params["old_value"] == "XXXXXXXX10"
    assert a.params["new_value"] == "XXXXXXXX99"


def test_sg_r9_positive_count_threshold():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    change = ProfileChange(
        ts=t0, account_no="001010002", field="EMAIL", old_value="a@b.com", new_value="x@y.com", changed_by="STAFF"
    )
    reconciler.process(change)

    # 3 small debits of Rs 20,000 each (total Rs 60,000 < Rs 1,00,000, but count == 3)
    outputs = []
    for i in range(3):
        ev = SwitchEvent(
            ts=t0 + timedelta(minutes=10 * (i + 1)),
            rrn=f"63051100000{i+2}",
            channel=Channel.UPI,
            direction=Direction.DEBIT,
            msg_type=MsgType.AUTH,
            response_code="00",
            amount=2000000,
            account_no="001010002",
        )
        outputs.extend(reconciler.process(ev))

    r9_alerts = [o for o in outputs if isinstance(o, Alert) and o.rule_id == "SG-R9"]
    assert len(r9_alerts) == 1
    assert r9_alerts[0].count == 3
    assert r9_alerts[0].amount == 6000000


def test_sg_r9_below_threshold_negative():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    reconciler.process(ProfileChange(ts=t0, account_no="001010003", field="MOBILE", old_value="9876543210", new_value="9123456789", changed_by="STAFF"))

    # 1 debit of Rs 50,000 (< Rs 1,00,000 and count=1 < 3)
    ev = SwitchEvent(
        ts=t0 + timedelta(hours=2),
        rrn="630511000099",
        channel=Channel.UPI,
        direction=Direction.DEBIT,
        msg_type=MsgType.AUTH,
        response_code="00",
        amount=5000000,
        account_no="001010003",
    )
    outputs = reconciler.process(ev)
    assert not any(isinstance(o, Alert) and o.rule_id == "SG-R9" for o in outputs)


def test_sg_r9_older_than_window_negative():
    cfg = EngineSettings(contact_change_window_hours=24)
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    reconciler.process(ProfileChange(ts=t0, account_no="001010004", field="MOBILE", old_value="9876543210", new_value="9123456789", changed_by="STAFF"))

    # Debit 25 hours later (outside 24h window)
    ev = SwitchEvent(
        ts=t0 + timedelta(hours=25),
        rrn="630511000100",
        channel=Channel.IMPS,
        direction=Direction.DEBIT,
        msg_type=MsgType.AUTH,
        response_code="00",
        amount=20000000,
        account_no="001010004",
    )
    outputs = reconciler.process(ev)
    assert not any(isinstance(o, Alert) and o.rule_id == "SG-R9" for o in outputs)


def test_sg_r9_out_of_order_events():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t_change = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    t_debit = t_change + timedelta(minutes=30)

    # Debit arrives FIRST
    ev = SwitchEvent(
        ts=t_debit,
        rrn="630511000200",
        channel=Channel.IMPS,
        direction=Direction.DEBIT,
        msg_type=MsgType.AUTH,
        response_code="00",
        amount=15000000,
        account_no="001010005",
    )
    out1 = reconciler.process(ev)
    assert not any(isinstance(o, Alert) and o.rule_id == "SG-R9" for o in out1)

    # Profile change arrives LATER in the batch
    change = ProfileChange(
        ts=t_change,
        account_no="001010005",
        field="MOBILE",
        old_value="9876543210",
        new_value="9123456789",
        changed_by="STAFF",
    )
    out2 = reconciler.process(change)
    r9 = [o for o in out2 if isinstance(o, Alert) and o.rule_id == "SG-R9"]
    assert len(r9) == 1
    assert r9[0].amount == 15000000


def test_sg_r9_admin_multi_account_signal():
    cfg = EngineSettings(admin_account_change_threshold=3, admin_account_change_window_hours=1)
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 9, 0, tzinfo=IST)
    # Admin changes 3 different accounts within 30 minutes
    for i in range(3):
        reconciler.process(ProfileChange(
            ts=t0 + timedelta(minutes=i * 10),
            account_no=f"00101000{i+6}",
            field="MOBILE",
            old_value="9876543210",
            new_value="9123456789",
            changed_by="ROGUE_ADMIN",
        ))

    # Account 3 has money moved
    ev = SwitchEvent(
        ts=t0 + timedelta(minutes=40),
        rrn="630511000300",
        channel=Channel.IMPS,
        direction=Direction.DEBIT,
        msg_type=MsgType.AUTH,
        response_code="00",
        amount=20000000,
        account_no="001010008",
    )
    out = reconciler.process(ev)
    r9 = [o for o in out if isinstance(o, Alert) and o.rule_id == "SG-R9"]
    assert len(r9) == 1
    assert r9[0].params["admin_multi_account"] is True
    assert r9[0].params["admin_user"] == "ROGUE_ADMIN"


# =====================================================================
# 3. RULE SG-R10 ("Outgoing payment file mismatch")
# =====================================================================

def test_sg_r10_altered_beneficiary_account():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 11, 0, tzinfo=IST)
    utr = "SBIN26110200001"

    # Ledger entry with legitimate account
    ledger = LedgerEntry(
        ts=t0,
        journal_id="J101",
        rrn=utr,
        channel=Channel.NEFT,
        account_no="001010001",
        drcr=Direction.DEBIT,
        amount=50000000,
        utr=utr,
        beneficiary_account_no="911111111111",
        beneficiary_ifsc="SBIN0001234",
    )
    reconciler.process(ledger)

    # File row with altered account
    outward = OutwardPayment(
        ts=t0 + timedelta(seconds=10),
        batch_id="B01",
        utr=utr,
        rail="NEFT",
        debit_account_no="001010001",
        beneficiary_account_no="889999999999",  # altered!
        beneficiary_ifsc="SBIN0001234",
        beneficiary_name="Victim",
        amount=50000000,
    )
    outputs = reconciler.process(outward)
    r10 = [o for o in outputs if isinstance(o, Alert) and o.rule_id == "SG-R10"]
    assert len(r10) == 1
    assert r10[0].severity == Severity.CRITICAL
    assert "beneficiary_account_no" in r10[0].params["reason"]


def test_sg_r10_altered_beneficiary_ifsc():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 11, 0, tzinfo=IST)
    utr = "SBIN26110200002"

    ledger = LedgerEntry(
        ts=t0, journal_id="J102", rrn=utr, channel=Channel.RTGS, account_no="001010001",
        drcr=Direction.DEBIT, amount=60000000, utr=utr, beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234"
    )
    reconciler.process(ledger)

    outward = OutwardPayment(
        ts=t0 + timedelta(seconds=10), batch_id="B01", utr=utr, rail="RTGS", debit_account_no="001010001",
        beneficiary_account_no="911111111111", beneficiary_ifsc="HDFC0005678", beneficiary_name="Victim", amount=60000000
    )
    outputs = reconciler.process(outward)
    r10 = [o for o in outputs if isinstance(o, Alert) and o.rule_id == "SG-R10"]
    assert len(r10) == 1
    assert "beneficiary_ifsc" in r10[0].params["reason"]


def test_sg_r10_altered_amount():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 11, 0, tzinfo=IST)
    utr = "SBIN26110200003"

    ledger = LedgerEntry(
        ts=t0, journal_id="J103", rrn=utr, channel=Channel.NEFT, account_no="001010001",
        drcr=Direction.DEBIT, amount=50000000, utr=utr, beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234"
    )
    reconciler.process(ledger)

    outward = OutwardPayment(
        ts=t0 + timedelta(seconds=10), batch_id="B01", utr=utr, rail="NEFT", debit_account_no="001010001",
        beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234", beneficiary_name="Victim", amount=90000000  # altered amount!
    )
    outputs = reconciler.process(outward)
    r10 = [o for o in outputs if isinstance(o, Alert) and o.rule_id == "SG-R10"]
    assert len(r10) == 1
    assert "amount" in r10[0].params["reason"]


def test_sg_r10_file_row_without_ledger():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 11, 0, tzinfo=IST)
    outward = OutwardPayment(
        ts=t0, batch_id="B01", utr="ORPHAN_UTR", rail="NEFT", debit_account_no="001010001",
        beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234", beneficiary_name="Victim", amount=50000000
    )
    reconciler.process(outward)

    # After match window expires
    outputs = reconciler.advance(t0 + timedelta(seconds=cfg.match_window_seconds + 10))
    r10 = [o for o in outputs if isinstance(o, Alert) and o.rule_id == "SG-R10"]
    assert len(r10) == 1
    assert r10[0].severity == Severity.CRITICAL
    assert "no matching" in r10[0].params["reason"]


def test_sg_r10_ledger_without_file_is_medium_and_auto_resolves():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok)

    t0 = datetime(2026, 11, 2, 11, 0, tzinfo=IST)
    utr = "UNSENT_UTR"
    ledger = LedgerEntry(
        ts=t0, journal_id="J104", rrn=utr, channel=Channel.NEFT, account_no="001010001",
        drcr=Direction.DEBIT, amount=50000000, utr=utr, beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234"
    )
    reconciler.process(ledger)

    # Advance past window -> MEDIUM alert
    out_adv = reconciler.advance(t0 + timedelta(seconds=cfg.match_window_seconds + 10))
    r10 = [o for o in out_adv if isinstance(o, Alert) and o.rule_id == "SG-R10"]
    assert len(r10) == 1
    assert r10[0].severity == Severity.MEDIUM
    assert "not sent" in r10[0].params["reason"]

    # Late file arrival -> auto-resolves
    outward = OutwardPayment(
        ts=t0 + timedelta(seconds=cfg.match_window_seconds + 30), batch_id="B01", utr=utr, rail="NEFT", debit_account_no="001010001",
        beneficiary_account_no="911111111111", beneficiary_ifsc="SBIN0001234", beneficiary_name="Victim", amount=50000000
    )
    out_late = reconciler.process(outward)
    resolved = [o for o in out_late if isinstance(o, AlertResolved) and o.alert_id == r10[0].alert_id]
    assert len(resolved) == 1


# =====================================================================
# 4. RULE SG-R11 ("Unusual money-out for this kind of day")
# =====================================================================

def test_sg_r11_day_type_classification():
    # Sunday -> HOLIDAY
    assert classify_day_type(date(2026, 11, 1)) == "HOLIDAY"
    assert classify_day_type(date(2026, 11, 8)) == "HOLIDAY"
    # Monday -> WEEKDAY
    assert classify_day_type(date(2026, 11, 2)) == "WEEKDAY"
    # 1st Saturday (November 7, 2026) -> SATURDAY
    assert classify_day_type(date(2026, 11, 7)) == "SATURDAY"
    # 2nd Saturday (November 14, 2026) is bank HOLIDAY
    assert is_second_or_fourth_saturday(date(2026, 11, 14)) is True
    assert classify_day_type(date(2026, 11, 14)) == "HOLIDAY"
    # Config holiday
    assert classify_day_type(date(2026, 11, 4), holidays=("2026-11-04",)) == "HOLIDAY"


def test_sg_r11_fallback_limit_on_holiday():
    # Test fallback when baseline is empty/not provided
    cfg = EngineSettings(quiet_day_outward_limit=50_000_000)  # Rs 50 lakh limit
    tok = Tokenizer("test-secret")
    reconciler = Reconciler(cfg, tok, baseline={})

    # Sunday
    t0 = datetime(2026, 11, 8, 10, 0, tzinfo=IST)

    # Rs 40 lakh debit does not trigger
    ev1 = SwitchEvent(
        ts=t0, rrn="630511000401", channel=Channel.IMPS, direction=Direction.DEBIT,
        msg_type=MsgType.AUTH, response_code="00", amount=40_000_000, account_no="001"
    )
    outputs1 = reconciler.process(ev1)
    assert not any(isinstance(o, Alert) and o.rule_id == "SG-R11" for o in outputs1)

    # Another Rs 20 lakh debit (cumulative Rs 60 lakh > Rs 50 lakh) triggers SG-R11
    ev2 = SwitchEvent(
        ts=t0 + timedelta(minutes=15), rrn="630511000402", channel=Channel.IMPS, direction=Direction.DEBIT,
        msg_type=MsgType.AUTH, response_code="00", amount=20_000_000, account_no="002"
    )
    outputs2 = reconciler.process(ev2)
    r11 = [o for o in outputs2 if isinstance(o, Alert) and o.rule_id == "SG-R11"]
    assert len(r11) == 1
    assert r11[0].severity == Severity.HIGH
    assert r11[0].amount == 60_000_000


def test_sg_r11_normal_sunday_does_not_fire():
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    day = build_day("normal", day=date(2026, 11, 8), transactions=3000)
    engine = Reconciler(cfg, tok)
    outputs = run_events(engine, day.events())
    alerts = [o for o in outputs if isinstance(o, Alert)]
    assert not any(a.rule_id == "SG-R11" for a in alerts)


# =====================================================================
# 5. BENCHMARK & SCENARIOS VERIFICATION
# =====================================================================

def test_bhavnagar_scenario_detected_within_10_minutes():
    from sahakari_guard.bench import score_scenario, _final_alerts
    day = build_day("bhavnagar", seed=42, transactions=3000)
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    engine = Reconciler(cfg, tok)
    outputs = run_events(engine, day.events(), heartbeat_seconds=15)
    row = score_scenario("bhavnagar", day, _final_alerts(outputs), tok)

    assert row["detected"] is True
    assert row["recall"] == 1.0
    assert row["false_alerts"] == 0
    assert {"SG-R9", "SG-R5", "SG-R11"} <= set(row["rules_fired"])
    assert row["first_alert_seconds"] is not None
    # Detected within 10 minutes (600 seconds)
    assert row["first_alert_seconds"] <= 600
    # Savings estimate exists
    assert row["savings"] is not None
    assert row["savings"]["amount_saved_paise"] > 0


def test_ballari_scenario_detected():
    from sahakari_guard.bench import score_scenario, _final_alerts
    day = build_day("ballari", seed=42, transactions=3000)
    cfg = EngineSettings()
    tok = Tokenizer("test-secret")
    engine = Reconciler(cfg, tok)
    outputs = run_events(engine, day.events(), heartbeat_seconds=15)
    row = score_scenario("ballari", day, _final_alerts(outputs), tok)

    assert row["detected"] is True
    assert row["recall"] == 1.0
    assert row["false_alerts"] == 0
    assert "SG-R10" in row["rules_fired"]
    assert row["savings"] is not None
    assert row["savings"]["amount_saved_paise"] > 0
