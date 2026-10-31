from __future__ import annotations

import time

from sahakari_guard.ingest.parsers import write_ledger_csv, write_settlement_csv, write_switch_csv
from sahakari_guard.simulator import build_day


def _wait_demo(client, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get("/api/demo/status").json()
        if status["phase"] in ("done", "error", "stopped"):
            return status
        time.sleep(0.1)
    raise AssertionError("demo did not finish")


def test_health_config_and_pages(client):
    assert client.get("/api/health").json()["status"] == "ok"
    cfg = client.get("/api/config").json()
    assert cfg["languages"] == ["en", "ta", "hi"]
    assert {r["rule_id"] for r in cfg["rules"]} == {f"SG-R{i}" for i in range(1, 12)}
    page = client.get("/")
    assert page.status_code == 200 and "Sahakari-Guard" in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/api/i18n/ta").json()["lang.name"] == "தமிழ்"
    assert client.get("/api/i18n/xx").status_code == 404


def test_empty_summary(client):
    s = client.get("/api/summary").json()
    assert s["status"] == "empty"
    assert s["kpi"]["open_incidents"] == 0


def test_upload_flow_and_incident_actions(client):
    day = build_day("uco", seed=9, transactions=2000)
    files = [
        ("files", ("switch_log.csv", write_switch_csv(day.switch), "text/csv")),
        ("files", ("cbs_ledger.csv", write_ledger_csv(day.ledger), "text/csv")),
        ("files", ("settlement.csv", write_settlement_csv(day.settlement), "text/csv")),
    ]
    r = client.post("/api/upload", files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert {f["kind"] for f in body["files"]} == {"switch", "ledger", "settlement"}
    assert body["new_alerts"] > 0 and body["new_incidents"]

    summary = client.get("/api/summary?lang=ta").json()
    assert summary["status"] == "red"
    assert summary["latest_alerts"][0]["message"]

    alerts = client.get("/api/alerts", params={"rule": "SG-R2", "limit": 5}).json()
    assert alerts["total"] >= len(day.injection.rrns) and len(alerts["items"]) == 5
    one = client.get(f"/api/alerts/{alerts['items'][0]['alert_id']}?lang=hi").json()
    assert one["evidence"] and one["rule_id"] == "SG-R2"

    iid = body["new_incidents"][0]
    detail = client.get(f"/api/incidents/{iid}").json()
    assert detail["incident"]["family"] == "ERRONEOUS_CREDITS"
    assert detail["actions"] and detail["timeline"]

    html = client.get(f"/api/incidents/{iid}/report.html?lang=ta")
    assert html.status_code == 200 and "சைபர் சம்பவ அறிக்கை" in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"]
    js = client.get(f"/api/incidents/{iid}/report.json?download=true")
    assert "attachment" in js.headers["content-disposition"]

    assert client.post(f"/api/incidents/{iid}/confirm", json={"officer": "S. Meena"}).json()["status"] == "CONFIRMED"
    assert client.post(f"/api/incidents/{iid}/confirm", json={"officer": "S. Meena"}).status_code == 409
    assert client.post(f"/api/incidents/{iid}/reported", json={"officer": "S. Meena"}).status_code == 422
    done = client.post(f"/api/incidents/{iid}/reported", json={"officer": "S. Meena", "daksh_ref": "DK-1"})
    assert done.json()["status"] == "REPORTED"
    assert client.get("/api/incidents/INC-NOPE").status_code == 404


def test_upload_errors(client):
    bad = client.post("/api/upload", files=[("files", ("x.csv", "foo,bar\n1,2\n", "text/csv"))])
    assert bad.status_code == 400 and "could not recognise" in bad.json()["error"]
    many = client.post("/api/upload", files=[("files", (f"{i}.csv", "a\n", "text/csv")) for i in range(6)])
    assert many.status_code == 400


def test_samples_download(client):
    r = client.get("/api/samples/cosmos/switch.csv")
    assert r.status_code == 200 and r.text.startswith("ts,rrn,channel")
    assert client.get("/api/samples/nope/switch.csv").status_code == 404
    r_prof = client.get("/api/samples/bhavnagar/profile.csv")
    assert r_prof.status_code == 200 and "account_no" in r_prof.text
    r_out = client.get("/api/samples/ballari/outward.csv")
    assert r_out.status_code == 200 and "utr" in r_out.text


def test_demo_bhavnagar_and_savings_on_incident(client):
    r = client.post("/api/demo/start", json={"scenario": "bhavnagar", "instant": True, "transactions": 2000})
    assert r.status_code == 200
    status = _wait_demo(client)
    assert status["phase"] == "done", status
    assert status.get("savings") is not None
    assert status["savings"]["amount_saved_paise"] > 0

    incidents = client.get("/api/incidents").json()
    assert len(incidents) > 0
    iid = incidents[0]["incident_id"]
    detail = client.get(f"/api/incidents/{iid}").json()
    assert "savings" in detail
    assert detail["savings"]["simulated"] is True
    assert "total_attack_amount" in detail["savings"]


def test_privacy_endpoints(client):
    r = client.post("/api/privacy/mask-text", json={"text": "PAN ABCPE1234F mob 9876543210"}).json()
    assert r["text"] == "PAN XXXXXX234F mob XXXXXX3210" and r["total"] == 2
    csv_text = "account_no,narration\n001010001234567,Aadhaar 2345 6789 0124\n"
    r = client.post("/api/privacy/mask-csv", files={"file": ("cust.csv", csv_text, "text/csv")}).json()
    assert "001010001234567" not in r["csv"] and r["filename"] == "cust_masked.csv"
    assert r["report"]["columns"]["account_no"] == "LAST4"


def test_demo_instant_run_and_busy_guard(client):
    r = client.post("/api/demo/start", json={"scenario": "replay", "instant": True, "transactions": 2000})
    assert r.status_code == 200
    again = client.post("/api/demo/start", json={"scenario": "replay", "instant": True, "transactions": 2000})
    assert again.status_code in (200, 409)
    status = _wait_demo(client)
    assert status["phase"] == "done", status
    s = client.get("/api/summary").json()
    assert s["alerts"]["by_rule"].get("SG-R3") == 20
    assert client.post("/api/demo/start", json={"scenario": "nope"}).status_code == 400
    assert client.post("/api/demo/start", json={"scenario": "replay", "speed": 7}).status_code == 400


def test_network_toggle_and_flush(client):
    assert client.post("/api/network", json={"online": False}).json()["online"] is False
    assert client.get("/api/summary").json()["network_online"] is False
    assert client.post("/api/network", json={"online": True}).json()["online"] is True
    assert "sent" in client.post("/api/outbox/flush").json()


def test_api_key_enforced(settings, tmp_path):
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from sahakari_guard.api.app import create_app
    from sahakari_guard.service import GuardService

    secured = replace(settings, api_key="s3cret")
    svc = GuardService(secured)
    with TestClient(create_app(secured, svc, background=False)) as c:
        assert c.get("/api/health").status_code == 200
        assert c.get("/api/summary").status_code == 401
        assert c.get("/api/summary", headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.get("/api/summary", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert c.get("/api/summary?key=s3cret").status_code == 200
    svc.repo.close()
