"""Helpers to drive the engine over a batch of events.

In live operation the watermark is moved by the wall clock even when the logs
are quiet (night hours). For batches we reproduce that with a *heartbeat*: if
two consecutive events are far apart, the engine is advanced in small steps in
between, so detection times match what a live deployment would see.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from sahakari_guard.engine.reconciler import Reconciler
from sahakari_guard.models import EngineOutput, FeedEvent


def run_events(
    engine: Reconciler,
    events: Iterable[FeedEvent],
    heartbeat_seconds: int = 15,
    finalize: bool = True,
) -> list[EngineOutput]:
    step = timedelta(seconds=heartbeat_seconds) if heartbeat_seconds > 0 else None
    out: list[EngineOutput] = []
    previous = engine.watermark
    for event in events:
        if step is not None and previous is not None and event.ts - previous > step:
            t = previous + step
            while t < event.ts:
                out.extend(engine.advance(t))
                t += step
        out.extend(engine.process(event))
        if previous is None or event.ts > previous:
            previous = event.ts
    if finalize:
        out.extend(engine.finalize())
    return out
