"""Attack and fault scenarios injected on top of a normal day.

Each scenario returns an ``Injection`` with the ground truth (which RRNs are
part of the attack, when it started) so the benchmark can score detection.
The patterns are modelled on public reporting of real incidents; amounts and
volumes are scaled down to a small bank.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta
from typing import Callable

from sahakari_guard.models import Channel, Direction, MsgType
from sahakari_guard.simulator.generator import (
    FIRST_NAMES,
    LAST_NAMES,
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
        inj.add(rrn, ts, cust.account_no, amount=amount)
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
            inj.add(rrn, ts, cust.account_no, amount=amount)
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
        inj.add(rrn, ts, cust.account_no, amount=amount)
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
        inj.add(rrn, ts, cust.account_no, amount=amount)
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
        inj.add(rrn, ts, cust.account_no, amount=amount)
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
        inj.add(rrn, ts, cust.account_no, amount=amount)
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


def inject_bhavnagar(b: TrafficBuilder) -> Injection:
    """Sunday mobile number hijack followed by massive outward transfers.

    Modelled on Bhavnagar District Co-op Bank, March 2026.
    At 09:00-09:20 an admin ID changes registered mobile numbers on 4 accounts.
    From 10:00, rapid IMPS/UPI outward transfers (each <= Rs 5 lakh) move ~Rs 7.34 crore
    to ~135 different beneficiaries. Ledger posts normally (so SG-R1 stays silent).
    Expected to fire: SG-R9 (contact changed then money out), SG-R5 (velocity), SG-R11 (unusual money-out for holiday).
    """
    rng = b.rng
    victims = rng.sample(b.retail, 4)
    admin_id = "EMP1042"

    # 09:00 - 09:20: mobile number changes on 4 accounts
    for i, cust in enumerate(victims):
        change_ts = _at(b, 9, 0) + timedelta(minutes=i * 5, seconds=rng.uniform(10, 50))
        old_mob = cust.mobile
        new_mob = "98" + b._digits(8)
        cust.mobile = new_mob
        b.add_profile_change(
            ts=change_ts,
            account_no=cust.account_no,
            field="MOBILE",
            old_value=old_mob,
            new_value=new_mob,
            changed_by=admin_id,
            channel="CBS_BRANCH",
        )

    start = _at(b, 10, 0)
    end = _at(b, 10, 35)
    inj = Injection("bhavnagar", start, end, expected_rules={"SG-R9", "SG-R5", "SG-R11"})

    beneficiaries = [f"mule{i:03d}@{rng.choice(['okaxis', 'okhdfcbank', 'paytm', 'ybl'])}" for i in range(135)]
    total_transfers = 150
    duration_secs = (end - start).total_seconds()

    for i in range(total_transfers):
        offset = (i / total_transfers) * duration_secs + rng.uniform(-10, 10)
        ts = start + timedelta(seconds=max(0, offset))
        cust = victims[i % 4]
        ben = beneficiaries[i % len(beneficiaries)]
        channel = rng.choice([Channel.IMPS, Channel.UPI])
        amount = rng.randint(480_000, 495_000) * 100  # <= Rs 5 lakh
        rrn = b.rrn(ts)

        b.add_switch(ts, rrn, channel, Direction.DEBIT, MsgType.AUTH, "00", amount, cust, counterparty=ben)
        narration = b.narration(channel, Direction.DEBIT, rrn, cust, ben, "")
        b.add_ledger(
            ts + timedelta(seconds=rng.uniform(1, 3)),
            rrn,
            channel,
            cust,
            Direction.DEBIT,
            amount,
            narration=narration,
        )
        b.add_settlement(ts, rrn, channel, Direction.DEBIT, amount, cust)
        inj.add(rrn, ts, cust.account_no, amount=amount)

    inj.start = min(inj.rrn_times.values())
    inj.end = max(inj.rrn_times.values())
    return inj


def inject_ballari(b: TrafficBuilder) -> Injection:
    """NEFT/RTGS outward payment file tampering.

    Modelled on Ballari DCC Bank, Karnataka, January 2025.
    25 file rows (amount > Rs 5 lakh) have beneficiary account number and IFSC altered
    compared to the CBS ledger instruction, totaling ~Rs 2.34 crore.
    Expected to fire: SG-R10 (file mismatch vs ledger).
    """
    rng = b.rng
    start = _at(b, 11, 30)
    end = _at(b, 12, 15)
    inj = Injection("ballari", start, end, expected_rules={"SG-R10"})

    batch_id = f"BATCH-{b.cfg.day:%Y%m%d}-01"

    # 25 altered transfers totaling ~Rs 2.34 crore
    amounts = [rng.randint(650_000, 1_250_000) * 100 for _ in range(24)]
    current_total = sum(amounts)
    target_total = 23_400_000 * 100
    rem = target_total - current_total
    if rem < 500_000 * 100:
        rem = 936_000 * 100
    amounts.append(rem)

    for i, amount in enumerate(amounts):
        ts = start + timedelta(seconds=i * 90 + rng.uniform(1, 5))
        cust = rng.choice(b.retail)
        rail = rng.choice(["NEFT", "RTGS"])
        channel = Channel.NEFT if rail == "NEFT" else Channel.RTGS
        utr = f"SBIN{b.cfg.day:%y%m%d}{b._digits(8)}"

        true_ben_acct = "91" + b._digits(12)
        true_ben_ifsc = f"SBIN000{b._digits(4)}"
        ben_name = f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"

        b.add_ledger(
            ts,
            rrn=utr,
            channel=channel,
            cust=cust,
            drcr=Direction.DEBIT,
            amount=amount,
            narration=f"{rail}/{utr}/{ben_name}",
            utr=utr,
            beneficiary_account_no=true_ben_acct,
            beneficiary_ifsc=true_ben_ifsc,
        )

        tampered_acct = "88" + b._digits(12)
        tampered_ifsc = f"HDFC000{b._digits(4)}"
        file_ts = ts + timedelta(seconds=rng.uniform(10, 30))

        b.add_outward(
            ts=file_ts,
            batch_id=batch_id,
            utr=utr,
            rail=rail,
            debit_account_no=cust.account_no,
            beneficiary_account_no=tampered_acct,
            beneficiary_ifsc=tampered_ifsc,
            beneficiary_name=ben_name,
            amount=amount,
        )
        inj.add(utr, file_ts, cust.account_no, amount=amount)

    inj.start = min(inj.rrn_times.values())
    inj.end = max(inj.rrn_times.values())
    return inj


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
    "bhavnagar": Scenario("bhavnagar", inject_bhavnagar, (10, 0)),
    "ballari": Scenario("ballari", inject_ballari, (11, 30)),
}


def build_day(scenario: str = "normal", seed: int = 42, transactions: int = 12_000, **overrides) -> SimDay:
    """A full synthetic day with the chosen scenario injected."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
    if "day" not in overrides:
        if scenario == "bhavnagar":
            overrides["day"] = date(2026, 11, 8)  # Sunday
        else:
            overrides["day"] = date(2026, 11, 2)  # Monday
    cfg = SimConfig(seed=seed, transactions=transactions, **overrides)
    builder = generate_normal_day(cfg)
    spec = SCENARIOS[scenario]
    if spec.inject is not None:
        builder.day.injection = spec.inject(builder)
    return builder.day


def playback_window(day: SimDay, scenario: str) -> tuple[datetime, datetime]:
    """Event-time window to play slowly in the live demo."""
    if scenario == "bhavnagar":
        start = datetime.combine(day.config.day, time(9, 0), tzinfo=IST)
        end = datetime.combine(day.config.day, time(10, 30), tzinfo=IST)
        return start, end
    if day.injection is not None:
        start = day.injection.start - timedelta(minutes=10)
        end = day.injection.end + timedelta(minutes=25)
    else:
        hour, minute = SCENARIOS[scenario].live_window
        start = datetime.combine(day.config.day, time(hour, minute), tzinfo=IST)
        end = start + timedelta(minutes=60)
    return max(start, day.day_start), end
