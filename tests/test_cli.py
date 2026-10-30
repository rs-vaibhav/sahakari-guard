from __future__ import annotations

import json

from sahakari_guard.cli import main


def test_simulate_scan_report_mask(tmp_path, capsys, monkeypatch):
    for var in ("SG_CONFIG", "SG_DATA_DIR", "SG_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    data_dir = tmp_path / "data"
    out = tmp_path / "logs"
    assert main(["--data-dir", str(data_dir), "simulate", "--scenario", "ghost", "--transactions", "1500", "--out", str(out)]) == 0
    truth = json.loads((out / "ground_truth.json").read_text())
    assert truth["expected_rules"] == ["SG-R7"]

    code = main([
        "--data-dir", str(data_dir), "scan", "--switch", str(out / "switch_log.csv"),
        "--ledger", str(out / "cbs_ledger.csv"), "--settlement", str(out / "settlement.csv"), "--fail-on-alert",
    ])
    text = capsys.readouterr().out
    assert code == 1  # alerts are open
    assert "SG-R7" in text and "Incident INC-" in text
    incident_id = next(w for w in text.split() if w.startswith("INC-"))

    report_file = tmp_path / "report.html"
    assert main(["--data-dir", str(data_dir), "report", incident_id, "--lang", "hi", "--out", str(report_file)]) == 0
    assert "साइबर घटना रिपोर्ट" in report_file.read_text(encoding="utf-8")

    masked = tmp_path / "masked.csv"
    assert main(["--data-dir", str(data_dir), "mask", str(out / "cbs_ledger.csv"), "--out", str(masked)]) == 0
    content = masked.read_text(encoding="utf-8")
    assert "account_no_token" in content
    assert "KYC UPDATE" not in content or "AADHAAR XXXX-XXXX-" in content

    assert main(["--data-dir", str(data_dir), "report", "INC-NOPE"]) == 2
