"""Benchmark: inject each scenario into a synthetic day and score detection.

Metrics per scenario
--------------------
* **detected** - at least one alert attributable to the injected attack.
* **recall** - share of injected transactions (RRNs) flagged by a transaction-level rule.
* **false alerts** - alerts still open at the end that are not attributable to the attack.
* **transient alerts** - alerts raised and then auto-resolved by a late posting (noise the officer never has to handle).
* **first alert** - event-time delay from attack start to the first attributable alert.
* **median time to detect** - per injected transaction, delay from the transaction to its first alert.
* **next-morning reconciliation** - an *assumed* baseline where reconciliation runs at 10:00 the next day.

Times are measured in *event time* (the bank's clock in the logs), with a 15-second
heartbeat that mimics a live deployment. Everything runs on synthetic data.
"""

from __future__ import annotations

import statistics
import time
from datetime import datetime, time as dtime, timedelta, timezone
from typing import Any

from sahakari_guard import __version__
from sahakari_guard.config import EngineSettings
from sahakari_guard.engine.reconciler import Reconciler
from sahakari_guard.engine.runner import run_events
from sahakari_guard.models import Alert, AlertResolved, AlertUpdate
from sahakari_guard.money import format_inr, format_inr_short
from sahakari_guard.privacy.tokenizer import Tokenizer
from sahakari_guard.simulator.generator import Injection
from sahakari_guard.simulator.scenarios import SCENARIOS, build_day
from sahakari_guard.timeutil import IST, fmt_duration, iso, parse_ts

BENCH_ORDER = ["normal", "slowcbs", "cosmos", "uco", "replay", "tamper", "ghost", "missing", "bhavnagar", "ballari"]
ATTRIBUTION_SLACK = timedelta(minutes=30)


def compute_savings(
    inj: Injection | None,
    alerts: Iterable[Any],
    assumed_response_minutes: int = 15,
    tokenizer: Tokenizer | None = None,
) -> dict[str, Any] | None:
    if inj is None or not inj.rrn_amounts:
        return None
    total_attack_amount = sum(inj.rrn_amounts.values())
    if not total_attack_amount:
        return None

    attack_rrns = inj.rrns
    attack_tokens = {tokenizer.token(a) for a in inj.accounts} if (tokenizer and inj.accounts) else set()

    hits = []
    for a in alerts:
        rid = getattr(a, "rule_id", None) or (a.get("rule_id") if isinstance(a, dict) else "")
        r_rrn = getattr(a, "rrn", None) or (a.get("rrn") if isinstance(a, dict) else "")
        tok = getattr(a, "account_token", None) or (a.get("account_token") if isinstance(a, dict) else "")
        raw_det = getattr(a, "detected_event_time", None) or (a.get("detected_event_time") if isinstance(a, dict) else None)
        det_ts = raw_det if isinstance(raw_det, datetime) else (parse_ts(raw_det) if raw_det else None)
        if not det_ts:
            continue

        is_attr = False
        if rid == "SG-R5":
            key = getattr(a, "key", "") or (a.get("key", "") if isinstance(a, dict) else "")
            if key == "bank:foreign":
                is_attr = inj.start - ATTRIBUTION_SLACK <= det_ts <= inj.end + ATTRIBUTION_SLACK
            elif attack_tokens:
                is_attr = tok in attack_tokens
            else:
                is_attr = True
        elif rid == "SG-R9":
            is_attr = (tok in attack_tokens) if attack_tokens else True
        elif rid == "SG-R11":
            is_attr = inj.start - ATTRIBUTION_SLACK <= det_ts <= inj.end + ATTRIBUTION_SLACK
        elif r_rrn in attack_rrns:
            is_attr = True

        if is_attr:
            hits.append(det_ts)

    if hits:
        first_alert_ts = min(hits)
        block_ts = first_alert_ts + timedelta(minutes=assumed_response_minutes)
        amount_before_first_alert = sum(
            amt for rrn, amt in inj.rrn_amounts.items() if inj.rrn_times.get(rrn, inj.start) <= first_alert_ts
        )
        amount_before_block = sum(
            amt for rrn, amt in inj.rrn_amounts.items() if inj.rrn_times.get(rrn, inj.start) <= block_ts
        )
        amount_saved = max(0, total_attack_amount - amount_before_block)
        delay_seconds = round((first_alert_ts - inj.start).total_seconds(), 1)
    else:
        first_alert_ts = None
        amount_before_first_alert = total_attack_amount
        amount_saved = 0
        delay_seconds = None

    return {
        "simulated": True,
        "label": "Estimate, simulated data",
        "assumed_response_minutes": assumed_response_minutes,
        "total_attack_amount_paise": total_attack_amount,
        "total_attack_amount": format_inr(total_attack_amount),
        "total_attack_amount_short": format_inr_short(total_attack_amount),
        "amount_moved_before_alert_paise": amount_before_first_alert,
        "amount_moved_before_alert": format_inr(amount_before_first_alert),
        "amount_saved_paise": amount_saved,
        "amount_saved": format_inr(amount_saved),
        "amount_saved_short": format_inr_short(amount_saved),
        "next_morning_loss_paise": total_attack_amount,
        "next_morning_loss": format_inr(total_attack_amount),
        "first_alert_delay_seconds": delay_seconds,
    }


def _final_alerts(outputs: list) -> dict[str, Alert]:
    alerts: dict[str, Alert] = {}
    for o in outputs:
        if isinstance(o, Alert):
            alerts[o.alert_id] = o
        elif isinstance(o, AlertUpdate) and o.alert_id in alerts:
            a = alerts[o.alert_id]
            a.amount, a.count = o.amount, o.count
        elif isinstance(o, AlertResolved) and o.alert_id in alerts:
            alerts[o.alert_id].status = "AUTO_RESOLVED"
    return alerts


def score_scenario(scenario: str, day, alerts: dict[str, Alert], tokenizer: Tokenizer) -> dict[str, Any]:
    inj = day.injection
    attack_rrns = inj.rrns if inj else set()
    attack_tokens = {tokenizer.token(a) for a in inj.accounts} if inj else set()

    def attributable(a: Alert) -> bool:
        if inj is None:
            return False
        if a.rule_id == "SG-R5":
            if a.key == "bank:foreign":
                return inj.start - ATTRIBUTION_SLACK <= a.detected_event_time <= inj.end + ATTRIBUTION_SLACK
            return a.account_token in attack_tokens
        if a.rule_id == "SG-R9":
            return a.account_token in attack_tokens
        if a.rule_id == "SG-R11":
            return inj.start - ATTRIBUTION_SLACK <= a.detected_event_time <= inj.end + ATTRIBUTION_SLACK
        return a.rrn in attack_rrns

    open_alerts = [a for a in alerts.values() if a.status == "OPEN"]
    false_alerts = [a for a in open_alerts if not attributable(a)]
    transient = [a for a in alerts.values() if a.status == "AUTO_RESOLVED"]
    hits = [a for a in alerts.values() if attributable(a)]

    first_detect: dict[str, datetime] = {}
    for a in hits:
        if a.rule_id in ("SG-R5", "SG-R11"):
            continue
        if a.rule_id == "SG-R9":
            for rrn, acct in inj.rrn_accounts.items():
                if tokenizer.token(acct) == a.account_token:
                    t_detect = max(a.detected_event_time, inj.rrn_times.get(rrn, a.detected_event_time))
                    if rrn not in first_detect or t_detect < first_detect[rrn]:
                        first_detect[rrn] = t_detect
            continue
        if a.rrn not in attack_rrns:
            continue
        current = first_detect.get(a.rrn)
        if current is None or a.detected_event_time < current:
            first_detect[a.rrn] = a.detected_event_time

    result: dict[str, Any] = {
        "scenario": scenario,
        "attack_transactions": len(attack_rrns),
        "expected_rules": sorted(inj.expected_rules) if inj else [],
        "rules_fired": sorted({a.rule_id for a in open_alerts}),
        "open_alerts": len(open_alerts),
        "false_alerts": len(false_alerts),
        "transient_alerts": len(transient),
        "detected": bool(hits) if inj else None,
        "recall": round(len(first_detect) / len(attack_rrns), 4) if attack_rrns else None,
        "first_alert_seconds": None,
        "median_ttd_seconds": None,
        "p95_ttd_seconds": None,
        "eod_baseline_seconds": None,
        "attack_start": iso(inj.start) if inj else None,
        "savings": compute_savings(inj, hits),
    }
    if inj and hits:
        first = min(a.detected_event_time for a in hits)
        result["first_alert_seconds"] = round((first - inj.start).total_seconds(), 1)
    if first_detect and inj:
        delays = sorted((first_detect[r] - inj.rrn_times[r]).total_seconds() for r in first_detect)
        result["median_ttd_seconds"] = round(statistics.median(delays), 1)
        result["p95_ttd_seconds"] = round(delays[min(len(delays) - 1, int(0.95 * len(delays)))], 1)
    if inj:
        next_morning = datetime.combine(inj.start.astimezone(IST).date() + timedelta(days=1), dtime(10, 0), tzinfo=IST)
        result["eod_baseline_seconds"] = round((next_morning - inj.start).total_seconds(), 1)
    return result


def run_benchmark(
    seed: int = 42,
    transactions: int = 12_000,
    engine_settings: EngineSettings | None = None,
    scenarios: list[str] | None = None,
) -> dict[str, Any]:
    cfg = engine_settings or EngineSettings()
    tokenizer = Tokenizer("benchmark-secret")
    rows = []
    total_events = 0
    total_seconds = 0.0
    for i, scenario in enumerate(scenarios or BENCH_ORDER):
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario}")
        day = build_day(scenario, seed=seed + i, transactions=transactions)
        events = day.events()
        engine = Reconciler(cfg, tokenizer)
        t0 = time.perf_counter()
        outputs = run_events(engine, events, heartbeat_seconds=15)
        elapsed = time.perf_counter() - t0
        total_events += len(events)
        total_seconds += elapsed
        row = score_scenario(scenario, day, _final_alerts(outputs), tokenizer)
        row["events"] = len(events)
        row["engine_seconds"] = round(elapsed, 3)
        rows.append(row)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "version": __version__,
        "seed": seed,
        "transactions_per_day": transactions,
        "match_window_seconds": cfg.match_window_seconds,
        "throughput_events_per_second": round(total_events / total_seconds) if total_seconds else None,
        "results": rows,
    }


def _d(seconds: float | None) -> str:
    return fmt_duration(seconds) if seconds is not None else "-"


def to_markdown(bench: dict[str, Any]) -> str:
    lines = [
        "# Benchmark results",
        "",
        f"Generated {bench['generated_at']} by Sahakari-Guard {bench['version']} "
        f"(seed {bench['seed']}, {bench['transactions_per_day']:,} normal transactions per synthetic day, "
        f"match window {bench['match_window_seconds']} s).",
        "",
        "All data is synthetic. Times are event time with a 15-second heartbeat (as in live operation). "
        "The last column assumes the usual practice of reconciling the switch with the ledger at 10:00 the next morning.",
        "",
        "| Scenario | Attack txns | Detected | Flagged | False alerts | Auto-resolved | First alert | Median time to detect | 95th percentile | Next-morning reconciliation |",
        "|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in bench["results"]:
        detected = "-" if r["detected"] is None else ("yes" if r["detected"] else "**no**")
        recall = "-" if r["recall"] is None else f"{r['recall'] * 100:.1f}%"
        lines.append(
            f"| {r['scenario']} | {r['attack_transactions']} | {detected} | {recall} | {r['false_alerts']} | "
            f"{r['transient_alerts']} | {_d(r['first_alert_seconds'])} | {_d(r['median_ttd_seconds'])} | "
            f"{_d(r['p95_ttd_seconds'])} | {_d(r['eod_baseline_seconds'])} |"
        )
    lines += [
        "",
        "`normal` and `slowcbs` contain no attack: `slowcbs` delays core-banking postings by 4-8 minutes for 20 minutes, "
        "so alerts are raised and must close themselves when the late postings arrive (shown as auto-resolved). "
        "In `cosmos`, a quarter of the withdrawals bypass the bank's switch log entirely and can only be caught "
        "from the network settlement file, which arrives every two hours; that is why its 95th percentile is longer. "
        "In `bhavnagar`, registered mobile numbers are changed on a Sunday followed by rapid outward transfers. "
        "In `ballari`, beneficiary account and IFSC details in the outward payment file are altered vs the core ledger.",
        "",
        f"Engine throughput: **{bench['throughput_events_per_second']:,} events per second** on one CPU core "
        "(switch, ledger and settlement lines combined).",
        "",
        "Rules fired per scenario:",
        "",
    ]
    for r in bench["results"]:
        lines.append(f"* `{r['scenario']}`: {', '.join(r['rules_fired']) or 'none'} "
                     f"(expected: {', '.join(r['expected_rules']) or 'none'})")
    lines.append("")
    lines.append("Reproduce with `python -m sahakari_guard bench`.")
    return "\n".join(lines) + "\n"
