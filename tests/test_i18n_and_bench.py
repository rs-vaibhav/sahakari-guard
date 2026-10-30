from __future__ import annotations

import re

import pytest

from sahakari_guard.bench import run_benchmark, to_markdown
from sahakari_guard.engine.rules import RULES
from sahakari_guard.i18n import catalog, render_alert, t
from sahakari_guard.money import format_inr, format_inr_short, parse_amount_to_paise
from sahakari_guard.simulator import SCENARIOS

LANGS = ("en", "ta", "hi")


def test_all_languages_have_the_same_keys_and_placeholders():
    en = catalog("en")
    for lang in ("ta", "hi"):
        other = catalog(lang)
        assert set(other) == set(en), f"{lang} keys differ"
        for key, value in en.items():
            if isinstance(value, str):
                assert set(re.findall(r"\{(\w+)\}", value)) == set(re.findall(r"\{(\w+)\}", other[key])), key
            else:
                assert isinstance(other[key], list) and len(other[key]) == len(value), key


@pytest.mark.parametrize("lang", LANGS)
@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_renders_without_leftover_placeholders(lang, rule_id):
    params = {
        "rrn": "630511004211", "channel": "ATM", "direction": "DR", "account": "XXXX0042", "switch_amount": 100000,
        "ledger_amount": 0, "window": 180, "amount": 100000, "count": 2, "feed": "ledger", "variant": "account",
        "window_count": 9, "window_min": 10, "episode_count": 12, "countries": 6,
    }
    text = render_alert(lang, rule_id, params)
    assert text["name"] and text["message"]
    assert "{" not in text["message"], text["message"]
    if rule_id == "SG-R5":
        foreign = render_alert(lang, rule_id, {**params, "variant": "foreign"})
        assert "{" not in foreign["message"]


@pytest.mark.parametrize("lang", LANGS)
def test_every_scenario_and_family_is_translated(lang):
    for key in SCENARIOS:
        assert t(lang, f"scenario.{key}.name") != f"scenario.{key}.name"
    for rule in RULES.values():
        assert isinstance(t(lang, f"actions.{rule.family}"), list)


def test_money_helpers():
    assert parse_amount_to_paise("1,234.505") == 123451
    assert parse_amount_to_paise("₹ 10") == 1000
    for bad in ("", "abc", "-1", "NaN", "1e20"):
        with pytest.raises(ValueError):
            parse_amount_to_paise(bad)
    assert format_inr(123456789) == "₹12,34,567.89"
    assert format_inr(5) == "₹0.05"
    assert format_inr_short(104250000) == "₹10.43 L"
    assert format_inr_short(1042500000) == "₹1.04 Cr"


def test_benchmark_detects_every_attack_with_no_false_alerts():
    result = run_benchmark(seed=101, transactions=3000)
    by_name = {r["scenario"]: r for r in result["results"]}
    assert set(by_name) == set(SCENARIOS)
    for name, row in by_name.items():
        assert row["false_alerts"] == 0, name
        if name in ("normal", "slowcbs"):
            assert row["detected"] is None
        else:
            assert row["detected"] is True, name
            assert row["recall"] == 1.0, name
            assert set(row["expected_rules"]) <= set(row["rules_fired"]), name
    assert by_name["slowcbs"]["transient_alerts"] > 0  # raised, then closed by the late postings
    md = to_markdown(result)
    assert md.startswith("# Benchmark results") and "| cosmos |" in md
