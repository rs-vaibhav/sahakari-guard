from __future__ import annotations

from datetime import timedelta

from conftest import T0, le, st, sw
from sahakari_guard.config import EngineSettings
from sahakari_guard.engine import Reconciler
from sahakari_guard.engine.runner import run_events
from sahakari_guard.models import Alert, AlertResolved, AlertUpdate, Channel, Direction, MsgType, event_sort_key
from sahakari_guard.privacy import Tokenizer


def run(events, cfg=None, heartbeat=15):
    engine = Reconciler(cfg or EngineSettings(), Tokenizer("t"))
    out = run_events(engine, sorted(events, key=event_sort_key), heartbeat_seconds=heartbeat)
    alerts = {o.alert_id: o for o in out if isinstance(o, Alert)}
    for o in out:
        if isinstance(o, AlertResolved):
            alerts[o.alert_id].status = "AUTO_RESOLVED"
    return engine, out, alerts


def open_rules(alerts):
    return sorted(a.rule_id for a in alerts.values() if a.status == "OPEN")


def test_matched_debit_raises_nothing():
    engine, _, alerts = run([sw(0, "R1", 50000), le(2, "J1", "R1", 50000), st(600, "R1", 50000)])
    assert alerts == {}
    assert engine.stats.matched == 1 and engine.stats.mismatched == 0


def test_declined_and_reversed_transactions_are_quiet():
    events = [
        sw(0, "D1", 50000, rc="51"),  # declined, nothing posted
        sw(10, "T1", 50000), sw(60, "T1", 50000, msg=MsgType.REVERSAL),  # timeout before posting
        sw(20, "P1", 70000), le(22, "J1", "P1", 70000), sw(80, "P1", 70000, msg=MsgType.REVERSAL),
        le(85, "J2", "P1", 70000, drcr=Direction.CREDIT, rev=True),  # posted then reversed
    ]
    _, _, alerts = run(events)
    assert alerts == {}


def test_r1_orphan_approval_detected_after_window():
    _, _, alerts = run([sw(0, "R1", 200000), sw(400, "X", 1), le(401, "JX", "X", 1)])
    (alert,) = alerts.values()
    assert alert.rule_id == "SG-R1" and alert.amount == 200000 and alert.rrn == "R1"
    delay = (alert.detected_event_time - alert.event_time).total_seconds()
    assert 180 <= delay <= 180 + 15  # window + at most one heartbeat


def test_r2_unfunded_credit():
    events = [
        sw(0, "C1", 100000, direction=Direction.CREDIT, channel=Channel.IMPS),
        sw(5, "C1", 100000, direction=Direction.CREDIT, channel=Channel.IMPS, msg=MsgType.REVERSAL),
        le(3, "J1", "C1", 100000, drcr=Direction.CREDIT, channel=Channel.IMPS),
    ]
    _, _, alerts = run(events)
    assert open_rules(alerts) == ["SG-R2"]


def test_r3_duplicate_ledger_posting_raised_immediately():
    events = [sw(0, "D1", 300000), le(2, "J1", "D1", 300000), le(4, "J2", "D1", 300000)]
    _, out, alerts = run(events)
    assert open_rules(alerts) == ["SG-R3"]
    (alert,) = alerts.values()
    assert alert.detected_event_time == T0 + timedelta(seconds=4)
    assert not any(isinstance(o, Alert) and o.rule_id == "SG-R4" for o in out)


def test_r3_duplicate_resolves_when_reversed():
    events = [
        sw(0, "D1", 300000), le(2, "J1", "D1", 300000), le(4, "J2", "D1", 300000),
        le(30, "J3", "D1", 300000, drcr=Direction.CREDIT, rev=True),
    ]
    _, _, alerts = run(events)
    assert open_rules(alerts) == []


def test_identical_lines_are_ignored_not_flagged():
    line = le(2, "J1", "D1", 300000)
    engine, _, alerts = run([sw(0, "D1", 300000), line, line, sw(0, "D1", 300000)])
    assert alerts == {}
    assert engine.stats.duplicate_lines_ignored == 2


def test_r4_amount_mismatch():
    _, _, alerts = run([sw(0, "A1", 100000), le(2, "J1", "A1", 900000)])
    (alert,) = alerts.values()
    assert alert.rule_id == "SG-R4" and alert.amount == 800000


def test_r6_network_settled_without_switch_approval_uses_transaction_time():
    _, _, alerts = run([st(7200, "N1", 1000000, txn_sec=60)])
    (alert,) = alerts.values()
    assert alert.rule_id == "SG-R6"
    assert alert.event_time == T0 + timedelta(seconds=60)
    assert alert.account_masked.endswith("0042")


def test_r7_ledger_debit_without_approval():
    _, _, alerts = run([le(0, "J1", "G1", 250000, channel=Channel.UPI)])
    assert open_rules(alerts) == ["SG-R7"]


def test_r8_missing_customer_credit_is_not_cyber_family():
    _, _, alerts = run([sw(0, "M1", 400000, direction=Direction.CREDIT, channel=Channel.UPI)])
    (alert,) = alerts.values()
    assert alert.rule_id == "SG-R8" and alert.family == "CUSTOMER_SERVICE"


def test_late_posting_auto_resolves_alert():
    events = [sw(0, "L1", 300000), sw(300, "X", 1), le(301, "JX", "X", 1), le(520, "J1", "L1", 300000)]
    _, out, alerts = run(events)
    assert [a.rule_id for a in alerts.values()] == ["SG-R1"]
    assert any(isinstance(o, AlertResolved) for o in out)
    assert open_rules(alerts) == []


def test_ledger_without_rrn_is_out_of_scope():
    engine, _, alerts = run([le(0, "J1", "", 100000, channel=Channel.BRANCH)])
    assert alerts == {}
    assert engine.stats.ledger_unlinked == 1


def test_velocity_account_burst_updates_one_alert():
    cfg = EngineSettings(velocity_debit_threshold=3)
    events = []
    for i in range(8):
        rrn = f"V{i}"
        events += [sw(i * 20, rrn, 10000), le(i * 20 + 1, f"J{i}", rrn, 10000)]
    _, out, alerts = run(events, cfg)
    bursts = [a for a in alerts.values() if a.rule_id == "SG-R5"]
    assert len(bursts) == 1
    updates = [o for o in out if isinstance(o, AlertUpdate) and o.alert_id == bursts[0].alert_id]
    assert updates and updates[-1].count == 8


def test_velocity_foreign_spread():
    countries = ["US", "CA", "HK", "GB", "AE", "SG"]
    events = []
    for i, c in enumerate(countries):
        rrn = f"F{i}"
        events += [sw(i * 30, rrn, 1000000, country=c, account=f"0010110000{i:04d}"),
                   le(i * 30 + 1, f"J{i}", rrn, 1000000, account=f"0010110000{i:04d}")]
    _, _, alerts = run(events)
    foreign = [a for a in alerts.values() if a.rule_id == "SG-R5"]
    assert len(foreign) == 1 and foreign[0].key == "bank:foreign"
    assert foreign[0].params["countries"] >= 5


def test_evidence_is_masked():
    _, _, alerts = run([sw(0, "R1", 200000), le(1, "J1", "R1", 100, narration="mob 9876543210")])
    text = repr([a.evidence for a in alerts.values()])
    assert "00101100000042" not in text
    assert "6080011234567896" not in text
    assert "9876543210" not in text


def test_watermark_heartbeat_without_events():
    engine = Reconciler(EngineSettings(), Tokenizer("t"))
    assert engine.process(sw(0, "R1", 5000)) == []
    assert engine.advance(T0 + timedelta(seconds=179)) == []
    out = engine.advance(T0 + timedelta(seconds=181))
    assert [o.rule_id for o in out if isinstance(o, Alert)] == ["SG-R1"]
    assert engine.pending == 0
