"""Synthetic traffic for a small co-operative bank.

Produces one day of switch, ledger and settlement records that look like a
real small bank's logs, including the *legitimate* oddities a watchdog must not
flag: declines, timeouts with reversals, late postings, failed inward credits,
the odd foreign withdrawal and busy merchant accounts.

Everything here is synthetic. Aadhaar, PAN, card and mobile numbers are
randomly generated (with valid check digits so the Privacy Shield can be
tested) and do not belong to anyone.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from pathlib import Path

from sahakari_guard.ingest.parsers import write_ledger_csv, write_settlement_csv, write_switch_csv
from sahakari_guard.models import (
    Channel,
    Direction,
    FeedEvent,
    LedgerEntry,
    MsgType,
    SettlementRecord,
    SwitchEvent,
    event_sort_key,
)
from sahakari_guard.privacy.checksums import luhn_check_digit, verhoeff_check_digit
from sahakari_guard.timeutil import IST

FIRST_NAMES = [
    "Arun", "Kavitha", "Murugan", "Lakshmi", "Senthil", "Priya", "Karthik", "Meena", "Rajesh", "Anitha",
    "Suresh", "Divya", "Ganesh", "Revathi", "Vijay", "Saranya", "Ramesh", "Deepa", "Balaji", "Gayathri",
    "Mohan", "Selvi", "Prakash", "Nandhini", "Ravi", "Sangeetha", "Venkatesh", "Malathi", "Ashok", "Uma",
]
LAST_NAMES = [
    "Kumar", "Raman", "Subramanian", "Pillai", "Natarajan", "Krishnan", "Iyer", "Shanmugam", "Rajan",
    "Velu", "Sundaram", "Arumugam", "Gopal", "Chandran", "Perumal", "Sharma", "Reddy", "Nair",
]
VPA_HANDLES = ["oksbi", "okaxis", "okhdfcbank", "ybl", "paytm", "ibl"]
MERCHANTS = [
    "Sri Murugan Stores", "Anna Medicals", "Kanchi Silks", "Velan Hardware", "Amman Rice Mandi",
    "Chengai Fertilisers", "Lakshmi Bakery", "Thendral Mobiles", "Kaveri Agro Inputs", "Selvam Textiles",
    "Ganapathy Fuels", "Arul Dairy",
]
HOUR_WEIGHTS = [
    0.30, 0.20, 0.15, 0.10, 0.10, 0.30, 0.80, 1.50, 2.50, 3.50, 4.20, 4.50,
    4.30, 4.00, 3.80, 3.90, 4.10, 4.40, 4.60, 4.50, 3.80, 2.80, 1.60, 0.80,
]
CHANNEL_MIX = [
    ((Channel.ATM, Direction.DEBIT), 0.28),
    ((Channel.POS, Direction.DEBIT), 0.12),
    ((Channel.UPI, Direction.DEBIT), 0.32),
    ((Channel.IMPS, Direction.DEBIT), 0.05),
    ((Channel.UPI, Direction.CREDIT), 0.18),
    ((Channel.IMPS, Direction.CREDIT), 0.05),
]
ATM_AMOUNTS = [500, 1000, 1500, 2000, 2000, 2500, 3000, 3000, 4000, 5000, 5000, 6000, 8000, 10000]
DECLINE_CODES = ["51", "55", "05", "91", "61"]
INWARD_FAIL_CODES = ["91", "M1", "M3"]
NRI_COUNTRIES = ["AE", "SG", "QA", "SA", "US", "GB"]


@dataclass
class SimConfig:
    day: date = date(2026, 11, 1)
    transactions: int = 12_000
    accounts: int = 4_000
    merchant_accounts: int = 12
    seed: int = 42
    decline_rate: float = 0.03
    reversal_rate: float = 0.01
    inward_fail_rate: float = 0.02
    inward_reversal_rate: float = 0.003
    foreign_rate: float = 0.0015
    late_posting_rate: float = 0.003
    non_switch_ledger_rate: float = 0.05
    pii_narration_rate: float = 0.02
    settlement_cycle_minutes: int = 120
    settlement_delay_minutes: int = 20
    bank_code: str = "608001"  # synthetic card BIN for the demo bank


@dataclass
class Customer:
    account_no: str
    card_no: str
    name: str
    mobile: str
    aadhaar: str
    pan: str
    vpa: str
    is_merchant: bool = False
    merchant_name: str = ""
    nri: bool = False


@dataclass
class Injection:
    """Ground truth for an injected scenario (used by the benchmark)."""

    scenario: str
    start: datetime
    end: datetime
    rrns: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    expected_rules: set[str] = field(default_factory=set)
    rrn_times: dict[str, datetime] = field(default_factory=dict)

    def add(self, rrn: str, ts: datetime, account_no: str) -> None:
        self.rrns.add(rrn)
        self.accounts.add(account_no)
        self.rrn_times[rrn] = ts


@dataclass
class SimDay:
    config: SimConfig
    switch: list[SwitchEvent] = field(default_factory=list)
    ledger: list[LedgerEntry] = field(default_factory=list)
    settlement: list[SettlementRecord] = field(default_factory=list)
    injection: Injection | None = None

    def events(self) -> list[FeedEvent]:
        merged: list[FeedEvent] = [*self.switch, *self.ledger, *self.settlement]
        merged.sort(key=event_sort_key)
        return merged

    @property
    def day_start(self) -> datetime:
        return datetime.combine(self.config.day, time(0, 0), tzinfo=IST)

    def write_csvs(self, out_dir: str | Path) -> dict[str, Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = {
            "switch": out / "switch_log.csv",
            "ledger": out / "cbs_ledger.csv",
            "settlement": out / "settlement.csv",
        }
        write_switch_csv(sorted(self.switch, key=event_sort_key), paths["switch"])
        write_ledger_csv(sorted(self.ledger, key=event_sort_key), paths["ledger"])
        write_settlement_csv(sorted(self.settlement, key=event_sort_key), paths["settlement"])
        return paths


class TrafficBuilder:
    """Low-level helpers shared by the normal-traffic generator and the scenarios."""

    def __init__(self, cfg: SimConfig) -> None:
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.day = SimDay(config=cfg)
        self._rrn_seq = 0
        self._journal_seq = 0
        self._terminal_seq = 0
        self.customers = self._make_customers()
        self.retail = [c for c in self.customers if not c.is_merchant]
        self.merchants = [c for c in self.customers if c.is_merchant]

    # ------------------------------------------------------------------ identities

    def _digits(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789") for _ in range(n))

    def _aadhaar(self) -> str:
        body = self.rng.choice("23456789") + self._digits(10)
        return body + verhoeff_check_digit(body)

    def _card(self) -> str:
        body = self.cfg.bank_code + self._digits(9)
        return body + luhn_check_digit(body)

    def _pan(self) -> str:
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return (
            "".join(self.rng.choice(letters) for _ in range(3)) + "P" + self.rng.choice(letters)
            + self._digits(4) + self.rng.choice(letters)
        )

    def _make_customers(self) -> list[Customer]:
        customers = []
        for i in range(self.cfg.accounts):
            first, last = self.rng.choice(FIRST_NAMES), self.rng.choice(LAST_NAMES)
            mobile = self.rng.choice("6789") + self._digits(9)
            handle = self.rng.choice(VPA_HANDLES)
            vpa = f"{mobile}@{handle}" if self.rng.random() < 0.4 else f"{first.lower()}.{last.lower()}{i % 97}@{handle}"
            customers.append(
                Customer(
                    account_no=f"00{101 + i % 7:03d}{100000000 + i:09d}",
                    card_no=self._card(),
                    name=f"{first} {last}",
                    mobile=mobile,
                    aadhaar=self._aadhaar(),
                    pan=self._pan(),
                    vpa=vpa,
                    nri=self.rng.random() < 0.01,
                )
            )
        for i, c in enumerate(customers[: self.cfg.merchant_accounts]):
            c.is_merchant = True
            c.merchant_name = MERCHANTS[i % len(MERCHANTS)]
        return customers

    def rrn(self, ts: datetime) -> str:
        """12-digit RRN in the common YDDDHHnnnnnn layout (year digit, day of year, hour, sequence)."""
        self._rrn_seq += 1
        local = ts.astimezone(IST)
        return f"{local.year % 10}{local.timetuple().tm_yday:03d}{local.hour:02d}{self._rrn_seq:06d}"

    def journal_id(self) -> str:
        self._journal_seq += 1
        return f"JNL{self.cfg.day:%y%m%d}{self._journal_seq:08d}"

    def terminal(self, channel: Channel, country: str = "IN") -> str:
        self._terminal_seq = (self._terminal_seq % 40) + 1
        if channel is Channel.ATM:
            return f"{'ATMCGL' if country == 'IN' else 'ATMX' + country}{self._terminal_seq:03d}"
        if channel is Channel.POS:
            return f"POS{self._terminal_seq:05d}"
        return ""

    # ------------------------------------------------------------------ record helpers

    def add_switch(
        self, ts: datetime, rrn: str, channel: Channel, direction: Direction, msg_type: MsgType, rc: str,
        amount: int, cust: Customer, *, country: str = "", terminal_id: str = "", counterparty: str = "",
    ) -> None:
        self.day.switch.append(
            SwitchEvent(
                ts=ts, rrn=rrn, channel=channel, direction=direction, msg_type=msg_type, response_code=rc,
                amount=amount, account_no=cust.account_no,
                card_no=cust.card_no if channel in (Channel.ATM, Channel.POS) else "",
                terminal_id=terminal_id, terminal_country=country, counterparty=counterparty,
            )
        )

    def add_ledger(
        self, ts: datetime, rrn: str, channel: Channel, cust: Customer, drcr: Direction, amount: int,
        *, is_reversal: bool = False, narration: str = "",
    ) -> None:
        self.day.ledger.append(
            LedgerEntry(
                ts=ts, journal_id=self.journal_id(), rrn=rrn, channel=channel, account_no=cust.account_no,
                drcr=drcr, amount=amount, is_reversal=is_reversal, narration=narration,
            )
        )

    def add_settlement(
        self, txn_ts: datetime, rrn: str, channel: Channel, direction: Direction, amount: int, cust: Customer | None = None,
    ) -> None:
        start = self.day.day_start
        minutes = max(0, int((txn_ts - start).total_seconds() // 60))
        idx = minutes // self.cfg.settlement_cycle_minutes
        cycle_end = start + timedelta(minutes=(idx + 1) * self.cfg.settlement_cycle_minutes)
        self.day.settlement.append(
            SettlementRecord(
                ts=cycle_end + timedelta(minutes=self.cfg.settlement_delay_minutes),
                cycle_id=f"{self.cfg.day:%Y%m%d}-C{idx + 1:02d}",
                rrn=rrn, channel=channel, direction=direction, amount=amount, status="SETTLED",
                txn_ts=txn_ts, account_no=cust.account_no if cust else "",
            )
        )

    # ------------------------------------------------------------------ sampling

    def random_ts(self, start_hour: float = 0.0, end_hour: float = 24.0) -> datetime:
        hours = [h for h in range(24) if start_hour <= h < end_hour] or [int(start_hour)]
        weights = [HOUR_WEIGHTS[h] for h in hours]
        hour = self.rng.choices(hours, weights=weights)[0]
        lo = max(hour * 3600, int(start_hour * 3600))
        hi = min((hour + 1) * 3600, int(end_hour * 3600))
        second = self.rng.randrange(lo, max(lo + 1, hi))
        return self.day.day_start + timedelta(seconds=second)

    def ledger_lag(self) -> timedelta:
        if self.rng.random() < self.cfg.late_posting_rate:
            return timedelta(seconds=self.rng.uniform(60, 150))
        return timedelta(seconds=min(45.0, self.rng.lognormvariate(math.log(2.0), 0.8)))

    def amount_for(self, channel: Channel, direction: Direction) -> int:
        r = self.rng
        if channel is Channel.ATM:
            rupees = r.choice(ATM_AMOUNTS)
        elif channel is Channel.POS:
            rupees = min(50_000.0, max(20.0, r.lognormvariate(math.log(800), 1.0)))
        elif channel is Channel.IMPS:
            rupees = min(200_000.0, max(100.0, r.lognormvariate(math.log(5_000), 1.0)))
        else:
            rupees = min(100_000.0, max(1.0, r.lognormvariate(math.log(300), 1.2)))
        return int(round(rupees * 100))

    def counterparty_vpa(self) -> str:
        first, last = self.rng.choice(FIRST_NAMES).lower(), self.rng.choice(LAST_NAMES).lower()
        return f"{first}.{last}@{self.rng.choice(VPA_HANDLES)}"

    def narration(self, channel: Channel, direction: Direction, rrn: str, cust: Customer, counterparty: str, terminal: str) -> str:
        if channel is Channel.ATM:
            return f"ATM WDL {terminal} {rrn}"
        if channel is Channel.POS:
            return f"POS {self.rng.choice(MERCHANTS).upper()} {rrn}"
        if self.rng.random() < self.cfg.pii_narration_rate:
            # Some core-banking systems copy customer identifiers into the narration.
            return f"{channel.value}/{rrn}/{cust.name.upper()}/MOB {cust.mobile}"
        tag = "Payment" if direction is Direction.DEBIT else "Received"
        return f"{channel.value}/{rrn}/{counterparty}/{tag}"


def _normal_outward(b: TrafficBuilder, ts: datetime, cust: Customer, channel: Channel) -> None:
    rng, cfg = b.rng, b.cfg
    direction = Direction.DEBIT
    amount = b.amount_for(channel, direction)
    rrn = b.rrn(ts)
    country = "IN"
    if channel is Channel.ATM and cust.nri and rng.random() < 0.5:
        country = rng.choice(NRI_COUNTRIES)
    elif channel is Channel.ATM and rng.random() < cfg.foreign_rate:
        country = rng.choice(NRI_COUNTRIES)
    terminal = b.terminal(channel, country)
    counterparty = b.counterparty_vpa() if channel in (Channel.UPI, Channel.IMPS) else ""
    if rng.random() < cfg.decline_rate:
        b.add_switch(ts, rrn, channel, direction, MsgType.AUTH, rng.choice(DECLINE_CODES), amount, cust,
                     country=country, terminal_id=terminal, counterparty=counterparty)
        return
    b.add_switch(ts, rrn, channel, direction, MsgType.AUTH, "00", amount, cust,
                 country=country, terminal_id=terminal, counterparty=counterparty)
    narration = b.narration(channel, direction, rrn, cust, counterparty, terminal)
    if rng.random() < cfg.reversal_rate:
        rev_ts = ts + timedelta(seconds=rng.uniform(20, 90))
        if rng.random() < 0.5:
            # Timeout before the core banking posted anything: only the switch sees both legs.
            b.add_switch(rev_ts, rrn, channel, direction, MsgType.REVERSAL, "00", amount, cust,
                         country=country, terminal_id=terminal)
        else:
            # Posted, then reversed (e.g. cash not dispensed): ledger shows debit and reversal.
            b.add_ledger(ts + b.ledger_lag(), rrn, channel, cust, Direction.DEBIT, amount, narration=narration)
            b.add_switch(rev_ts, rrn, channel, direction, MsgType.REVERSAL, "00", amount, cust,
                         country=country, terminal_id=terminal)
            b.add_ledger(rev_ts + timedelta(seconds=rng.uniform(1, 10)), rrn, channel, cust, Direction.CREDIT,
                         amount, is_reversal=True, narration=f"REV {narration}")
        return
    b.add_ledger(ts + b.ledger_lag(), rrn, channel, cust, Direction.DEBIT, amount, narration=narration)
    b.add_settlement(ts, rrn, channel, direction, amount, cust)


def _normal_inward(b: TrafficBuilder, ts: datetime, cust: Customer, channel: Channel) -> None:
    rng, cfg = b.rng, b.cfg
    direction = Direction.CREDIT
    amount = b.amount_for(channel, direction)
    rrn = b.rrn(ts)
    counterparty = b.counterparty_vpa()
    if rng.random() < cfg.inward_fail_rate:
        b.add_switch(ts, rrn, channel, direction, MsgType.AUTH, rng.choice(INWARD_FAIL_CODES), amount, cust,
                     counterparty=counterparty)
        return
    b.add_switch(ts, rrn, channel, direction, MsgType.AUTH, "00", amount, cust, counterparty=counterparty)
    narration = b.narration(channel, direction, rrn, cust, counterparty, "")
    post_ts = ts + b.ledger_lag()
    b.add_ledger(post_ts, rrn, channel, cust, Direction.CREDIT, amount, narration=narration)
    if rng.random() < cfg.inward_reversal_rate:
        # Remitter side timed out: the network reverses and the bank correctly reverses the credit.
        rev_ts = max(post_ts, ts) + timedelta(seconds=rng.uniform(20, 60))
        b.add_switch(rev_ts, rrn, channel, direction, MsgType.REVERSAL, "00", amount, cust)
        b.add_ledger(rev_ts + timedelta(seconds=rng.uniform(1, 8)), rrn, channel, cust, Direction.DEBIT, amount,
                     is_reversal=True, narration=f"REV {narration}")
        return
    b.add_settlement(ts, rrn, channel, direction, amount, cust)


def _non_switch_postings(b: TrafficBuilder, count: int) -> None:
    """Cash deposits, interest and KYC notes: postings with no RRN (out of the watchdog's scope)."""
    for _ in range(count):
        cust = b.rng.choice(b.retail)
        ts = b.random_ts(9.5, 17.5)
        kind = b.rng.random()
        if kind < 0.6:
            b.add_ledger(ts, "", Channel.BRANCH, cust, Direction.CREDIT,
                         b.rng.choice([100000, 250000, 500000, 1000000]), narration="CASH DEP BRANCH COUNTER")
        elif kind < 0.9:
            b.add_ledger(ts, "", Channel.BRANCH, cust, Direction.CREDIT, b.rng.randint(1000, 90000),
                         narration="SB INTEREST CREDIT")
        else:
            spaced = f"{cust.aadhaar[:4]} {cust.aadhaar[4:8]} {cust.aadhaar[8:]}"
            b.add_ledger(ts, "", Channel.BRANCH, cust, Direction.DEBIT, 5900,
                         narration=f"KYC UPDATE CHG AADHAAR {spaced} PAN {cust.pan} MOB {cust.mobile}")


def generate_normal_day(cfg: SimConfig) -> TrafficBuilder:
    """Generate a full day of legitimate traffic. Returns the builder so scenarios can add to it."""
    b = TrafficBuilder(cfg)
    kinds = [k for k, _ in CHANNEL_MIX]
    weights = [w for _, w in CHANNEL_MIX]
    for _ in range(cfg.transactions):
        channel, direction = b.rng.choices(kinds, weights=weights)[0]
        ts = b.random_ts()
        if direction is Direction.CREDIT:
            if channel is Channel.UPI and b.merchants and b.rng.random() < 0.3:
                cust = b.rng.choice(b.merchants)
            else:
                cust = b.rng.choice(b.retail)
            _normal_inward(b, ts, cust, channel)
        else:
            _normal_outward(b, ts, b.rng.choice(b.retail), channel)
    _non_switch_postings(b, int(cfg.transactions * cfg.non_switch_ledger_rate))
    return b
