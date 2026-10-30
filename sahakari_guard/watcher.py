"""Folder watcher for pilots: near-real-time checking of log exports.

A scheduled job at the bank copies (or appends to) the switch, ledger and
settlement exports in an *inbox* folder. The watcher polls that folder, reads
only new lines, and keeps one long-lived engine so pending transactions carry
over between polls.

Clock modes:
* ``event`` (default) - time moves only with the timestamps in the logs. Safe
  for batch exports that arrive late.
* ``wall`` - time also moves with the computer's clock (minus ``lag``), so a
  missing ledger posting is flagged even when the logs go quiet. Use this when
  the exports are written continuously.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sahakari_guard.ingest.tailer import FeedTailer

if TYPE_CHECKING:  # pragma: no cover
    from sahakari_guard.service import GuardService

log = logging.getLogger(__name__)


class FolderWatcher:
    def __init__(
        self,
        service: "GuardService",
        inbox: str | Path,
        interval: float = 5.0,
        clock: str = "event",
        lag_seconds: int = 60,
    ) -> None:
        if clock not in ("event", "wall"):
            raise ValueError("clock must be 'event' or 'wall'")
        self.service = service
        self.inbox = Path(inbox)
        self.interval = interval
        self.clock = clock
        self.lag = timedelta(seconds=lag_seconds)
        self.tailer = FeedTailer(self.inbox, service.settings.data_dir / "watch_state.json")
        self.engine = service.new_engine()
        self.run_id = service.begin_run("watch", str(self.inbox))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self.errors: list[dict] = []

    def poll_once(self) -> dict[str, Any]:
        result = self.tailer.poll()
        outputs = []
        for ev in result.events:
            outputs.extend(self.engine.process(ev))
        if self.clock == "wall":
            outputs.extend(self.engine.advance(datetime.now(timezone.utc) - self.lag))
        applied = self.service.apply_outputs(outputs, self.run_id)
        self.service.publish_live_stats("watch", self.engine.snapshot_stats())
        if result.errors:
            self.errors = (self.errors + result.errors)[-200:]
            for err in result.errors[:5]:
                log.warning("rejected line %s:%s - %s", err["file"], err["line"], err["message"])
        return {"events": len(result.events), "files": result.files, "rejected": len(result.errors), **applied}

    def run_forever(self) -> None:
        log.info("watching %s every %.1fs (clock=%s)", self.inbox, self.interval, self.clock)
        try:
            while not self._stop.is_set():
                try:
                    summary = self.poll_once()
                    if summary["events"]:
                        log.info("processed %s new lines, %s new alerts", summary["events"], summary["new_alerts"])
                except Exception:  # keep watching even if one poll fails
                    log.exception("watch poll failed")
                self._stop.wait(self.interval)
        finally:
            self.close()

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run_forever, name="folder-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        stats = self.engine.snapshot_stats()
        self.service.publish_live_stats("watch", None)
        self.service.add_base_stats(stats)
        self.service.end_run(self.run_id, "STOPPED", stats)
