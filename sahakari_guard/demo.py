"""Background runners: the live demo playback and the benchmark.

The demo replays a synthetic day: hours without the attack are fast-forwarded,
and the attack window is played at an accelerated but watchable speed with a
heartbeat, so alerts appear on the dashboard as the simulated clock passes the
moment the engine can conclude something is wrong.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import date, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sahakari_guard.bench import compute_savings, run_benchmark, to_markdown
from sahakari_guard.simulator.scenarios import SCENARIOS, build_day, playback_window
from sahakari_guard.timeutil import IST, iso

if TYPE_CHECKING:  # pragma: no cover
    from sahakari_guard.service import GuardService

log = logging.getLogger(__name__)

ALLOWED_SPEEDS = (30, 60, 120, 300, 600)
FAST_FORWARD_CHUNK = 3000
TICK_SECONDS = 0.25


class DemoRunner:
    def __init__(self, service: "GuardService") -> None:
        self.service = service
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._state: dict[str, Any] = {"phase": "idle"}

    # ------------------------------------------------------------------ control

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            st = dict(self._state)
            if "savings" not in st or st["savings"] is None:
                st["savings"] = self.service.repo.kv_get("simulation_savings")
            return st

    def _set(self, **fields: Any) -> None:
        with self._lock:
            self._state.update(fields)

    def start(self, scenario: str, speed: int = 120, seed: int = 42, transactions: int = 12_000, instant: bool = False) -> dict[str, Any]:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}")
        if speed not in ALLOWED_SPEEDS:
            raise ValueError(f"speed must be one of {ALLOWED_SPEEDS}")
        if not 1000 <= transactions <= 200_000:
            raise ValueError("transactions must be between 1,000 and 200,000")
        if self.running:
            from sahakari_guard.service import Busy

            raise Busy("a demo is already running")
        if not self.service._run_lock.acquire(blocking=False):  # noqa: SLF001 - shared run lock
            from sahakari_guard.service import Busy

            raise Busy("another run is in progress")
        self._stop.clear()
        with self._lock:
            self._state = {
                "phase": "preparing",
                "scenario": scenario,
                "speed": speed,
                "seed": seed,
                "instant": instant,
                "progress": 0.0,
                "events_total": 0,
                "events_done": 0,
                "sim_clock": None,
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "new_alerts": 0,
                "error": None,
                "savings": None,
            }
        self._thread = threading.Thread(
            target=self._run_guarded, args=(scenario, speed, seed, transactions, instant), name="demo-runner", daemon=True
        )
        self._thread.start()
        return self.status()

    def stop(self, wait: bool = False) -> dict[str, Any]:
        self._stop.set()
        if wait and self._thread is not None:
            self._thread.join(timeout=10)
        return self.status()

    # ------------------------------------------------------------------ worker

    def _run_guarded(self, scenario: str, speed: int, seed: int, transactions: int, instant: bool) -> None:
        try:
            self._run(scenario, speed, seed, transactions, instant)
        except Exception as exc:  # keep the server alive and report the failure
            log.exception("demo failed")
            self._set(phase="error", error=str(exc))
        finally:
            self.service.publish_live_stats("demo", None)
            self.service._run_lock.release()  # noqa: SLF001

    def _apply(self, engine, outputs, run_id: str, inj=None) -> None:
        if outputs:
            result = self.service.apply_outputs(outputs, run_id)
            with self._lock:
                self._state["new_alerts"] = self._state.get("new_alerts", 0) + result["new_alerts"]
            if inj:
                alerts, _ = self.service.repo.list_alerts(limit=5000)
                savings = compute_savings(inj, alerts, tokenizer=self.service.tokenizer)
                if savings:
                    self.service.repo.kv_set("simulation_savings", savings)
                    with self._lock:
                        self._state["savings"] = savings
        self.service.publish_live_stats("demo", engine.snapshot_stats())

    def _run(self, scenario: str, speed: int, seed: int, transactions: int, instant: bool) -> None:
        svc = self.service
        sim_date = datetime.now(IST).date()
        if scenario == "bhavnagar" and sim_date.weekday() != 6:
            sim_date = date(2026, 11, 8)
        elif scenario != "bhavnagar" and sim_date.weekday() in (5, 6):
            sim_date = date(2026, 11, 2)
        day = build_day(scenario, seed=seed, transactions=transactions, day=sim_date)
        events = day.events()
        svc.reset_data()
        run_id = svc.begin_run("demo", f"{scenario} (seed {seed}, x{speed})")
        engine = svc.new_engine()
        total = len(events)
        self._set(events_total=total, run_id=run_id)
        live_start, live_end = playback_window(day, scenario)
        if instant:
            live_start = live_end = events[-1].ts + timedelta(seconds=1)

        idx = 0
        step = timedelta(seconds=15)

        def feed_until(limit: datetime | None, chunk: int | None = None) -> list:
            nonlocal idx
            out = []
            fed = 0
            prev = engine.watermark
            while idx < total and (limit is None or events[idx].ts < limit):
                ev = events[idx]
                if prev is not None and ev.ts - prev > step:
                    t = prev + step
                    while t < ev.ts:
                        out.extend(engine.advance(t))
                        t += step
                out.extend(engine.process(ev))
                if prev is None or ev.ts > prev:
                    prev = ev.ts
                idx += 1
                fed += 1
                if chunk and fed >= chunk:
                    break
            return out

        # Phase 1: fast-forward normal traffic before the interesting window.
        self._set(phase="fast_forward")
        while idx < total and events[idx].ts < live_start and not self._stop.is_set():
            outputs = feed_until(live_start, FAST_FORWARD_CHUNK)
            self._apply(engine, outputs, run_id, day.injection)
            self._set(events_done=idx, progress=round(idx / total, 4), sim_clock=iso(engine.watermark))

        # Phase 2: play the attack window at the chosen speed with a heartbeat.
        if not self._stop.is_set() and not instant:
            self._set(phase="live")
            sim = live_start
            last = time.monotonic()
            while sim < live_end and not self._stop.is_set():
                time.sleep(TICK_SECONDS)
                now = time.monotonic()
                sim = min(live_end, sim + timedelta(seconds=(now - last) * speed))
                last = now
                outputs = feed_until(sim)
                outputs.extend(engine.advance(sim))
                self._apply(engine, outputs, run_id, day.injection)
                self._set(events_done=idx, progress=round(idx / total, 4), sim_clock=iso(sim))

        if self._stop.is_set():
            stats = engine.snapshot_stats()
            svc.add_base_stats(stats)
            svc.end_run(run_id, "STOPPED", stats)
            self._set(phase="stopped")
            return

        # Phase 3: the rest of the day, then close out pending transactions.
        self._set(phase="finishing")
        while idx < total and not self._stop.is_set():
            outputs = feed_until(None, FAST_FORWARD_CHUNK)
            self._apply(engine, outputs, run_id, day.injection)
            self._set(events_done=idx, progress=round(idx / total, 4), sim_clock=iso(engine.watermark))
        self._apply(engine, engine.finalize(), run_id, day.injection)
        stats = engine.snapshot_stats()
        svc.publish_live_stats("demo", None)
        svc.add_base_stats(stats)
        svc.end_run(run_id, "DONE", stats)
        if day.injection:
            alerts, _ = svc.repo.list_alerts(limit=5000)
            savings = compute_savings(day.injection, alerts, tokenizer=svc.tokenizer)
            if savings:
                svc.repo.kv_set("simulation_savings", savings)
                self._set(savings=savings)
        self._set(phase="done", progress=1.0, events_done=total, sim_clock=iso(engine.watermark),
                  finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))


class BenchmarkRunner:
    """Runs the benchmark in the background and stores the result."""

    def __init__(self, service: "GuardService") -> None:
        self.service = service
        self._thread: threading.Thread | None = None
        self._state: dict[str, Any] = {"phase": "idle"}
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
        state["result"] = self.service.repo.kv_get("benchmark")
        return state

    def start(self, seed: int = 42, transactions: int = 12_000) -> dict[str, Any]:
        if self.running:
            from sahakari_guard.service import Busy

            raise Busy("the benchmark is already running")
        if not 1000 <= transactions <= 100_000:
            raise ValueError("transactions must be between 1,000 and 100,000")
        with self._lock:
            self._state = {"phase": "running", "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}

        def work() -> None:
            try:
                result = run_benchmark(seed=seed, transactions=transactions, engine_settings=self.service.settings.engine)
                result["markdown"] = to_markdown(result)
                self.service.repo.kv_set("benchmark", result)
                with self._lock:
                    self._state = {"phase": "done"}
            except Exception as exc:  # pragma: no cover - defensive
                log.exception("benchmark failed")
                with self._lock:
                    self._state = {"phase": "error", "error": str(exc)}

        self._thread = threading.Thread(target=work, name="benchmark", daemon=True)
        self._thread.start()
        return self.status()
