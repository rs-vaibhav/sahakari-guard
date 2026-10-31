"""Day type classification and historical volume baseline for SG-R11.

Day types:
* WEEKDAY  - Monday through Friday (excluding declared holidays)
* SATURDAY - 1st, 3rd, and 5th Saturdays
* HOLIDAY  - Sundays, 2nd and 4th Saturdays, and declared holidays

Baseline tracks cumulative approved outward debits by hour-of-day per day type.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from sahakari_guard.ingest.parsers import parse_file
from sahakari_guard.models import Channel, Direction, LedgerEntry, SwitchEvent
from sahakari_guard.timeutil import to_ist

log = logging.getLogger(__name__)

DAY_TYPES = ("WEEKDAY", "SATURDAY", "HOLIDAY")


def is_second_or_fourth_saturday(d: date) -> bool:
    """In Indian banking, the 2nd and 4th Saturdays of every month are holidays."""
    if d.weekday() != 5:  # Saturday is weekday 5
        return False
    return (8 <= d.day <= 14) or (22 <= d.day <= 28)


def classify_day_type(d: date, holidays: Iterable[str] = ()) -> str:
    """Classify a date as WEEKDAY, SATURDAY, or HOLIDAY."""
    iso_date = d.isoformat()
    if iso_date in holidays or d.strftime("%Y-%m-%d") in holidays:
        return "HOLIDAY"
    if d.weekday() == 6:  # Sunday
        return "HOLIDAY"
    if d.weekday() == 5:  # Saturday
        if is_second_or_fourth_saturday(d):
            return "HOLIDAY"
        return "SATURDAY"
    return "WEEKDAY"


def _p95(values: list[int]) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return values[0]
    sorted_vals = sorted(values)
    idx = int(0.95 * len(sorted_vals))
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def build_baseline_from_events(
    events: Iterable[tuple[datetime, int]],
    holidays: tuple[str, ...] = ("2026-11-08",),
) -> tuple[dict[str, Any], list[str]]:
    """Build baseline metrics from a collection of (IST timestamp, amount_paise) tuples."""
    # Group amounts by date and hour
    # daily_hours[d][hour] = sum of amounts in that hour
    daily_hours: dict[date, dict[int, int]] = {}
    for ts, amount in events:
        ist_dt = to_ist(ts)
        d = ist_dt.date()
        h = ist_dt.hour
        daily = daily_hours.setdefault(d, {i: 0 for i in range(24)})
        daily[h] += amount

    # Group days by day_type
    days_by_type: dict[str, list[date]] = {dt: [] for dt in DAY_TYPES}
    for d in daily_hours:
        dtype = classify_day_type(d, holidays)
        days_by_type[dtype].append(d)

    warnings: list[str] = []
    for dtype, days in days_by_type.items():
        if len(days) < 4:
            warn_msg = f"baseline warning: day type '{dtype}' has only {len(days)} day(s); needs >= 4 for a reliable baseline"
            warnings.append(warn_msg)
            log.warning(warn_msg)

    baseline: dict[str, Any] = {
        "day_counts": {dt: len(days) for dt, days in days_by_type.items()},
        "by_day_type": {},
    }

    for dtype in DAY_TYPES:
        baseline["by_day_type"][dtype] = {}
        days = days_by_type[dtype]
        for h in range(24):
            cumulatives: list[int] = []
            for d in days:
                cum = sum(daily_hours[d][i] for i in range(h + 1))
                cumulatives.append(cum)
            if cumulatives:
                mean_val = round(sum(cumulatives) / len(cumulatives))
                p95_val = _p95(cumulatives)
            else:
                mean_val = 0
                p95_val = 0
            baseline["by_day_type"][dtype][str(h)] = {
                "mean": mean_val,
                "p95": p95_val,
            }

    return baseline, warnings


def build_baseline_from_files(
    paths: list[Path | str],
    holidays: tuple[str, ...] = ("2026-11-08",),
) -> tuple[dict[str, Any], list[str]]:
    """Parse switch logs and ledger files to extract outward debit events, then compute baseline."""
    events: list[tuple[datetime, int]] = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"file not found: {p}")
        result = parse_file(p)
        for rec in result.records:
            if isinstance(rec, SwitchEvent):
                if rec.approved and rec.direction is Direction.DEBIT:
                    events.append((rec.ts, rec.amount))
            elif isinstance(rec, LedgerEntry):
                if rec.drcr is Direction.DEBIT and not rec.is_reversal and rec.channel != Channel.BRANCH:
                    events.append((rec.ts, rec.amount))
    return build_baseline_from_events(events, holidays)


def save_baseline(baseline: dict[str, Any], path: Path | str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load_baseline(path: Path | str | None = None) -> dict[str, Any] | None:
    """Load baseline from the given path, data/baseline.json, or package resources."""
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.append(Path("data/baseline.json"))
    try:
        pkg_file = Path(str(resources.files("sahakari_guard").joinpath("baseline.json")))
        candidates.append(pkg_file)
    except Exception:  # pragma: no cover
        pass

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if "by_day_type" in data:
                    return data
            except Exception as exc:
                log.warning("could not load baseline from %s: %s", candidate, exc)
    return None


def generate_synthetic_baseline(weeks: int = 8, seed: int = 42) -> dict[str, Any]:
    """Generate a realistic baseline for a small co-operative bank over 8 weeks.

    Typical small bank outward debit volume:
    * HOLIDAY (Sundays, 2nd/4th Saturdays): ~Rs 70-80 lakh total per day
    * SATURDAY (working Saturdays): ~Rs 1.5 - 2.0 crore total per day
    * WEEKDAY (Monday-Friday): ~Rs 2.5 - 3.2 crore total per day
    """
    import random
    from sahakari_guard.simulator.generator import HOUR_WEIGHTS

    rng = random.Random(seed)
    total_weights = sum(HOUR_WEIGHTS)
    norm_weights = [w / total_weights for w in HOUR_WEIGHTS]

    # Target daily totals in paise
    # Holiday: 75 lakh mean
    # Saturday: 1.8 crore mean
    # Weekday: 2.8 crore mean
    targets = {
        "HOLIDAY": (75_00_000 * 100, 5_00_000 * 100),
        "SATURDAY": (180_00_000 * 100, 15_00_000 * 100),
        "WEEKDAY": (280_00_000 * 100, 20_00_000 * 100),
    }

    # Simulate days for 8 weeks
    num_days = {
        "HOLIDAY": weeks * 1 + weeks // 2,  # 8 Sundays + 4 alternate Saturdays = 12
        "SATURDAY": weeks // 2,  # 4 working Saturdays
        "WEEKDAY": weeks * 5,  # 40 weekdays
    }

    baseline: dict[str, Any] = {
        "day_counts": num_days,
        "by_day_type": {},
    }

    for dtype, n_days in num_days.items():
        mean_tot, std_tot = targets[dtype]
        day_cumulatives: list[list[int]] = []
        for _ in range(n_days):
            day_total = max(int(mean_tot * 0.7), int(rng.gauss(mean_tot, std_tot)))
            hourly = [int(day_total * w) for w in norm_weights]
            cum = []
            running = 0
            for val in hourly:
                running += val
                cum.append(running)
            day_cumulatives.append(cum)

        baseline["by_day_type"][dtype] = {}
        for h in range(24):
            vals = [day_cumulatives[d][h] for d in range(n_days)]
            mean_val = round(sum(vals) / len(vals))
            p95_val = _p95(vals)
            baseline["by_day_type"][dtype][str(h)] = {
                "mean": mean_val,
                "p95": p95_val,
            }

    return baseline

