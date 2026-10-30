"""Attack and fault scenarios injected on top of a normal day.

Each scenario returns an ``Injection`` with the ground truth (which RRNs are
part of the attack, when it started) so the benchmark can score detection.
The patterns are modelled on public reporting of real incidents; amounts and
volumes are scaled down to a small bank.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, time, timedelta
from typing import Callable

from sahakari_guard.models import Channel, Direction, MsgType
from sahakari_guard.simulator.generator import (
    Injection,
    SimConfig,
    SimDay,
    TrafficBuilder,
    generate_normal_day,
)
from sahakari_guard.timeutil import IST

CASHOUT_COUNTRIES = [
    "US", "CA", "HK", "GB", "AE", "SG", "TH", "TR", "RU", "DE", "FR",
    "IT", "ES", "PL", "UA", "BR", "MX", "ZA", "EG", "MY", "ID", "PH",
]


def _at(b: TrafficBuilder, hour: int, minute: int = 0) -> datetime:
    return datetime.combine(b.cfg.day, time(hour, minute), tzinfo=IST)


def inject_cosmos(b: TrafficBuilder) -> Injection:
    """Proxy-switch ATM cash-out (modelled on the 2018 Cosmos Bank attack).

    Malware on the switch answers cloned-card withdrawals itself, so approvals
    never reach core banking. Most approvals still appear in the bank's switch
    log; some are answered entirely outside it and only show up in the
    network settlement file.
    """
    rng = b.rng
    start = _at(b, 2, 0)
    duration = timedelta(minutes=150)
    cards = rng.sample(b.retail, 110)
    inj = Injection("cosmos", start, start + duration, expected_rules={"SG-R1", "SG-R5", "SG-R6"})
    offsets = sorted(rng.uniform(0, duration.total_seconds()) for _ in range(420))
    for off in offsets:
        ts = start + timedelta(seconds=off)
        cust = rng.choice(cards)
        country = rng.choice(CASHOUT_COUNTRIES)
        amount = rng.choice([8000, 10000, 12000, 15000, 18000, 20000]) * 100
        rrn = b.rrn(ts)
        if rng.random() < 0.75:
            b.add_switch(ts, rrn, Channel.ATM, Direction.DEBIT, MsgType.AUTH, "00", amount, cust,
                         country=country, terminal_id=b.terminal(Channel.ATM, country))
        b.add_settlement(ts, rrn, Channel.ATM, Direction.DEBIT, amount, cust)
        inj.add(rrn, ts, cust.account_no)
    return inj


def inject_uco(b: TrafficBuilder) -> Injection:
    """Credits without debits (modelled on the 2023 UCO Bank IMPS incident).

    Inward IMPS credits keep being posted to beneficiaries even though the
    network reversed the remitter's leg. A few account holders notice and
    trigger many transfers in quick succession.
    """
    rng = b.rng
    start = _at(b, 20, 30)
    window = timedelta(hours=3)
    exploiters = rng.sample(b.retail, 45)
    inj = Injection("uco", start, start + window, expected_rules={"SG-R2", "SG-R5"})
    for cust in exploiters:
        ts = start + timedelta(seconds=rng.uniform(0, window.total_seconds() * 0.6))
        for _ in range(rng.randint(20, 60)):
            ts += timedelta(seconds=rng.uniform(5, 20))  # scripted, faster than any human
            if ts > inj.end:
                break
            amount = rng.choice([5000, 10000, 25000, 49999]) * 100
            rrn = b.rrn(ts)
            b.add_switch(ts, rrn, Channel.IMPS, Direction.CREDIT, MsgType.AUTH, "00", amount, cust,
                         counterparty=b.counterparty_vpa())
            b.add_ledger(ts + timedelta(seconds=rng.uniform(1, 4)), rrn, Channel.IMPS, cust, Direction.CREDIT,
                         amount, narration=f"IMPS/{rrn}/INWARD")
            # Network reverses the remitter leg, but the faulty interface never reverses the credit.
            b.add_switch(ts + timedelta(seconds=rng.uniform(5, 12)), rrn, Channel.IMPS, Direction.CREDIT,
                         MsgType.REVERSAL, "00", amount, cust)
            inj.add(rrn, ts, cust.account_no)
    inj.start = min((e.ts for e in b.day.switch if e.rrn in inj.rrns), default=start)
    return inj


def inject_replay(b: TrafficBuilder) -> Injection:
    rng = b.rng
    start, end = _at(b, 11), _at(b, 16)
    inj = Injection("replay", start, end, expected_rules={"SG-R3"})
    for _ in range(20):
        ts = start + timedelta(seconds=rng.uniform(0, (end - start).total_seconds()))
        cust = rng.choice(b.retail)
        channel = rng.choice([Channel.UPI, Channel.IMPS])
        amount = b.amount_for(channel, Direction.DEBIT)
        rrn = b.rrn(ts)
        b.add_switch(ts, rrn, channel, Direction.DEBIT, MsgType.AUTH, "00", amount, cust,
                     counterparty=b.counterparty_vpa())
        first = ts + timedelta(seconds=rng.uniform(1, 5))
        b.add_ledger(first, rrn, channel, cust, Direction.DEBIT, amount, narration=f"{channel.value}/{rrn}")
        b.add_ledger(first + timedelta(seconds=rng.uniform(2, 40)), rrn, channel, cust, Direction.DEBIT, amount,
                     narration=f"{channel.value}/{rrn}")
        b.add_settlement(ts, rrn, channel, Direction.DEBIT, amount, cust)
        inj.add(rrn, ts, cust.account_no)
    inj.start = min(e.ts for e in b.day.switch if e.rrn in inj.rrns)
    return inj


def inject_tamper(b: TrafficBuilder) -> Injection:
    rng = b.rng
    start, end = _at(b, 14), _at(b, 15, 30)
    inj = Injection("tamper", start, end, expected_rules={"SG-R4"})
    for i in range(15):
        ts = start + timedelta(seconds=rng.uniform(0, (end - start).total_seconds()))
        cust = rng.choice(b.retail)
        rrn = b.rrn(ts)
        if i % 3:
            # Inward credit inflated tenfold between switch and ledger.
            amount = rng.choice([1000, 2000, 5000]) * 100
            b.add_switch(ts, rrn, Channel.UPI, Direction.CREDIT, MsgType.AUTH, "00", amount, cust,
                         counterparty=b.counterparty_vpa())
            b.add_ledger(ts + timedelta(seconds=2), rrn, Channel.UPI, cust, Direction.CREDIT, amount * 10,
                         narration=f"UPI/{rrn}")
            b.add_settlement(ts, rrn, Channel.UPI, Direction.CREDIT, amount, cust)
        else:
            # Outward debit where the customer is charged a token amount only.
            amount = rng.choice([20000, 40000, 75000]) * 100
            b.add_switch(ts, rrn, Channel.IMPS, Direction.DEBIT, MsgType.AUTH, "00", amount, cust,
                         counterparty=b.counterparty_vpa())
            b.add_ledger(ts + timedelta(seconds=2), rrn, Channel.IMPS, cust, Direction.DEBIT, 100,
                         narration=f"IMPS/{rrn}")
            b.add_settlement(ts, rrn, Channel.IMPS, Direction.DEBIT, amount, cust)
        inj.add(rrn, ts, cust.account_no)
    inj.start = min(e.ts for e in b.day.switch if e.rrn in inj.rrns)
    return inj


def inject_ghost(b: TrafficBuilder) -> Injection:
    rng = b.rng
    start = _at(b, 13, 5)
    inj = Injection("ghost", start, start + timedelta(minutes=50), expected_rules={"SG-R7"})
    for _ in range(12):
        ts = start + timedelta(seconds=rng.uniform(0, 3000))
        cust = rng.choice(b.retail)
        channel = rng.choice([Channel.UPI, Channel.IMPS])
        amount = rng.randint(20_000, 90_000) * 100
        rrn = b.rrn(ts)
        b.add_ledger(ts, rrn, channel, cust, Direction.DEBIT, amount, narration=f"{channel.value}/{rrn}/TRANSFER")
        inj.add(rrn, ts, cust.account_no)
    inj.start = min(e.ts for e in b.day.ledger if e.rrn in inj.rrns)
    return inj


def inject_missing(b: TrafficBuilder) -> Injection:
    rng = b.rng
    start, end = _at(b, 10), _at(b, 12)
    inj = Injection("missing", start, end, expected_rules={"SG-R8"})
    for _ in range(18):
        ts = start + timedelta(seconds=rng.uniform(0, (end - start).total_seconds()))
        cust = rng.choice(b.retail)
        amount = b.amount_for(Channel.UPI, Direction.CREDIT)
        rrn = b.rrn(ts)
        b.add_switch(ts, rrn, Channel.UPI, Direction.CREDIT, MsgType.AUTH, "00", amount, cust,
                     counterparty=b.counterparty_vpa())
        b.add_settlement(ts, rrn, Channel.UPI, Direction.CREDIT, amount, cust)
        inj.add(rrn, ts, cust.account_no)
    inj.start = min(e.ts for e in b.day.switch if e.rrn in inj.rrns)
    return inj


def inject_slow_cbs(b: TrafficBuilder) -> None:
    """Legitimate noise: core banking runs slow for 20 minutes.

    Ledger postings arrive 4-8 minutes late, beyond the 3-minute match window.
    The engine raises alerts and must then close them by itself when the
    postings arrive. Nothing here is an attack, so no alert should stay open.
    """
    rng = b.rng
    start, end = _at(b, 15, 0), _at(b, 15, 20)
    switch_ts = {e.rrn: e.ts for e in b.day.switch if e.msg_type is MsgType.AUTH}
    for i, entry in enumerate(b.day.ledger):
        origin = switch_ts.get(entry.rrn)
        if entry.rrn and origin is not None and start <= origin < end:
            b.day.ledger[i] = replace(entry, ts=entry.ts + timedelta(seconds=rng.uniform(240, 480)))
    return None


@dataclass(frozen=True)
class Scenario:
    key: str
    inject: Callable[[TrafficBuilder], Injection | None] | None
    live_window: tuple[int, int]  # default playback window (hour, minute) when there is no injection


SCENARIOS: dict[str, Scenario] = {
    "normal": Scenario("normal", None, (10, 0)),
    "cosmos": Scenario("cosmos", inject_cosmos, (2, 0)),
    "uco": Scenario("uco", inject_uco, (20, 30)),
    "replay": Scenario("replay", inject_replay, (11, 0)),
    "tamper": Scenario("tamper", inject_tamper, (14, 0)),
    "ghost": Scenario("ghost", inject_ghost, (13, 0)),
    "missing": Scenario("missing", inject_missing, (10, 0)),
    "slowcbs": Scenario("slowcbs", inject_slow_cbs, (14, 55)),
}


def build_day(scenario: str = "normal", seed: int = 42, transactions: int = 12_000, **overrides) -> SimDay:
    """A full synthetic day with the chosen scenario injected."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
    cfg = SimConfig(seed=seed, transactions=transactions, **overrides)
    builder = generate_normal_day(cfg)
    spec = SCENARIOS[scenario]
    if spec.inject is not None:
        builder.day.injection = spec.inject(builder)
    return builder.day


def playback_window(day: SimDay, scenario: str) -> tuple[datetime, datetime]:
    """Event-time window to play slowly in the live demo."""
    if day.injection is not None:
        start = day.injection.start - timedelta(minutes=10)
        end = day.injection.end + timedelta(minutes=25)
    else:
        hour, minute = SCENARIOS[scenario].live_window
        start = datetime.combine(day.config.day, time(hour, minute), tzinfo=IST)
        end = start + timedelta(minutes=60)
    return max(start, day.day_start), end
