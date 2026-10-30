from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from conftest import le, st, sw
from sahakari_guard.incidents import InvalidTransition, NotFound
from sahakari_guard.models import Channel, Direction
from sahakari_guard.reports import render_report_html


def test_cosmos_scenario_becomes_one_critical_incident(service):
    result = service.run_scenario_instant("cosmos", seed=11, transactions=2000)
    assert result["new_alerts"] > 0
    incidents = service.list_incidents()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["family"] == "UNAUTHORISED_DEBITS"
    assert inc["severity"] == "CRITICAL"
    assert inc["status"] == "OPEN"
    assert inc["reportable"] is True
    assert 5.9 * 3600 < inc["seconds_left"] <= 6 * 3600
    # Amount at risk counts each transaction once (burst alerts are context only).
    alerts, _ = service.repo.list_alerts(incident_id=inc["incident_id"], limit=10_000)
    txn_amount = sum(a["amount_paise"] for a in alerts if a["rule_id"] != "SG-R5")
    assert inc["amount_paise"] == txn_amount
    # A notification was queued for the branch manager.
    assert service.repo.outbox_counts().get("QUEUED", 0) >= 1


def test_normal_day_raises_nothing(service):
    service.run_scenario_instant("normal", seed=5, transactions=3000)
    summary = service.summary("en")
    assert summary["status"] == "green"
    assert summary["kpi"]["open_incidents"] == 0
    assert summary["kpi"]["checked"] > 2500
    assert summary["kpi"]["match_rate"] == 1.0


def test_slow_core_banking_closes_its_own_incident(service):
    engine = service.new_engine()
    run_id = service.begin_run("test", "slow")
    service.apply_outputs(engine.process_many([sw(0, "S1", 50000), sw(400, "X", 1), le(401, "JX", "X", 1)]), run_id)
    (inc,) = service.list_incidents()
    assert inc["status"] == "OPEN"
    service.apply_outputs(engine.process_many([le(500, "J1", "S1", 50000)]) + engine.advance(sw(900, "Y", 1).ts), run_id)
    (inc,) = service.list_incidents()
    assert inc["status"] == "AUTO_CLOSED"
    assert inc["open_alert_count"] == 0


def test_families_are_grouped_separately(service):
    events = [
        sw(0, "R1", 100000),  # SG-R1 -> unauthorised debits
        sw(10, "M1", 50000, direction=Direction.CREDIT, channel=Channel.UPI),  # SG-R8 -> customer service
        sw(20, "R2", 100000),  # SG-R1, joins the first incident
    ]
    service.run_batch(events, kind="test", label="families")
    incidents = {i["family"]: i for i in service.list_incidents()}
    assert set(incidents) == {"UNAUTHORISED_DEBITS", "CUSTOMER_SERVICE"}
    assert incidents["UNAUTHORISED_DEBITS"]["alert_count"] == 2
    assert incidents["CUSTOMER_SERVICE"]["reportable"] is False
    assert incidents["CUSTOMER_SERVICE"]["deadline_at"] is None


def test_incident_lifecycle(service):
    service.run_batch([sw(0, "R1", 100000)], kind="test", label="x")
    (inc,) = service.list_incidents()
    iid = inc["incident_id"]
    with pytest.raises(ValueError):
        service.confirm_incident(iid, "", "")
    assert service.confirm_incident(iid, "R. Kumar", "checked switch")["status"] == "CONFIRMED"
    with pytest.raises(InvalidTransition):
        service.confirm_incident(iid, "R. Kumar")
    reported = service.mark_reported(iid, "R. Kumar", "DAKSH-2026-0042", "CERTIN-77")
    assert reported["status"] == "REPORTED" and reported["daksh_ref"] == "DAKSH-2026-0042"
    with pytest.raises(InvalidTransition):
        service.dismiss_incident(iid, "R. Kumar", "late")
    actions = [e["action"] for e in service.repo.incident_events(iid)]
    assert actions[:1] == ["OPENED"] and "CONFIRMED" in actions and actions[-1] == "REPORTED"
    with pytest.raises(NotFound):
        service.get_incident("INC-NOPE")


def test_dismiss_requires_reason(service):
    service.run_batch([sw(0, "R1", 100000)], kind="test", label="x")
    (inc,) = service.list_incidents()
    with pytest.raises(ValueError):
        service.dismiss_incident(inc["incident_id"], "Officer", "")
    assert service.dismiss_incident(inc["incident_id"], "Officer", "test entry")["status"] == "DISMISSED"


def test_report_contents_and_integrity(service):
    service.run_scenario_instant("cosmos", seed=11, transactions=2000)
    (inc,) = service.list_incidents()
    report = service.report(inc["incident_id"], "en")
    assert report["schema"] == "sahakari-guard/incident-report/v1"
    assert report["impact"]["transactions"] == 420
    assert report["impact"]["countries"]
    assert report["timing"]["deadline"] and report["filing"]
    assert re.fullmatch(r"[0-9a-f]{64}", report["evidence"]["payload_sha256"])
    # Hash is stable for the same data and generation time.
    fixed = datetime(2026, 11, 1, tzinfo=timezone.utc)
    alerts, _ = service.repo.list_alerts(incident_id=inc["incident_id"], limit=10_000, with_evidence=True)
    from sahakari_guard.reports import build_report

    r1 = build_report(service.repo.get_incident(inc["incident_id"]), alerts, [], service.settings, "en", fixed)
    r2 = build_report(service.repo.get_incident(inc["incident_id"]), alerts, [], service.settings, "en", fixed)
    assert r1["evidence"]["payload_sha256"] == r2["evidence"]["payload_sha256"]
    alerts[0]["amount_paise"] += 1
    r3 = build_report(service.repo.get_incident(inc["incident_id"]), alerts, [], service.settings, "en", fixed)
    assert r3["evidence"]["payload_sha256"] != r1["evidence"]["payload_sha256"]


@pytest.mark.parametrize("lang", ["en", "ta", "hi"])
def test_report_html_renders_in_each_language_without_raw_identifiers(service, lang):
    from sahakari_guard.simulator import build_day

    day = build_day("cosmos", seed=11, transactions=2000)
    service.run_batch(day.events(), kind="test", label="cosmos")
    (inc,) = service.list_incidents()
    page = render_report_html(service.report(inc["incident_id"], lang))
    assert "<html" in page and inc["incident_id"] in page
    assert "{" not in re.sub(r"<style>.*?</style>", "", page, flags=re.S)  # no unfilled placeholders
    raw_accounts = {e.account_no for e in day.switch if e.rrn in day.injection.rrns}
    raw_cards = {e.card_no for e in day.switch if e.rrn in day.injection.rrns and e.card_no}
    for value in raw_accounts | raw_cards:
        assert value not in page
    report_json = json.dumps(service.report(inc["incident_id"], lang), ensure_ascii=False)
    for value in raw_accounts | raw_cards:
        assert value not in report_json


def test_outbox_queues_offline_and_sends_when_online(service):
    service.set_network(False)
    service.run_batch([sw(0, "R1", 100000)], kind="test", label="x")
    service.dispatcher.dispatch_once()
    counts = service.repo.outbox_counts()
    assert counts.get("QUEUED", 0) == 1 and counts.get("SENT", 0) == 0
    (msg,) = service.outbox()
    assert msg["attempts"] == 1 and "offline" in msg["last_error"]
    service.set_network(True)
    assert service.repo.outbox_counts().get("SENT", 0) == 1


def test_upload_requires_switch_and_ledger(service):
    from sahakari_guard.ingest import IngestError
    from sahakari_guard.ingest.parsers import write_switch_csv

    data = write_switch_csv([sw(0, "R1", 100)]).encode()
    with pytest.raises(IngestError, match="at least"):
        service.scan_uploads([("switch.csv", data)])
    with pytest.raises(IngestError, match="more than one"):
        service.scan_uploads([("a.csv", data), ("b.csv", data)])


def test_reset_keeps_benchmark(service):
    service.repo.kv_set("benchmark", {"x": 1})
    service.run_batch([sw(0, "R1", 100000)], kind="test", label="x")
    service.reset()
    assert service.list_incidents() == []
    assert service.repo.kv_get("benchmark") == {"x": 1}
    assert service.summary()["status"] == "empty"


def test_settlement_only_debit_raises_r6_via_service(service):
    service.run_batch([st(3600, "N1", 500000, txn_sec=30)], kind="test", label="r6")
    alerts = service.list_alerts("hi")["items"]
    assert [a["rule_id"] for a in alerts] == ["SG-R6"]
    assert "RRN N1" in alerts[0]["message"]
