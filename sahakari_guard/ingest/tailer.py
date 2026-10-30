"""Incremental reader for append-only CSV logs (``watch`` mode).

The bank's systems keep appending to their log exports; a scheduled job copies
them into an *inbox* folder. ``FeedTailer.poll()`` reads only the new complete
lines since the previous poll, so detection runs within seconds of a line
being written. Offsets are saved to disk, so a restart does not re-read old
lines (and the engine ignores exact duplicates anyway).
"""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from sahakari_guard.ingest.parsers import FEEDS, RowParseError, detect_kind
from sahakari_guard.models import FeedEvent, RowError, event_sort_key

log = logging.getLogger(__name__)

NAME_HINTS = {
    "switch": ("switch",),
    "ledger": ("ledger", "cbs", "journal"),
    "settlement": ("settlement", "ntsl", "network"),
}


@dataclass
class PollResult:
    events: list[FeedEvent] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    files: dict[str, int] = field(default_factory=dict)


class FeedTailer:
    def __init__(self, inbox: Path, state_file: Path) -> None:
        self.inbox = Path(inbox)
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.state_file = Path(state_file)
        self._state: dict[str, dict] = self._load_state()

    def _load_state(self) -> dict[str, dict]:
        if self.state_file.exists():
            try:
                return json.loads(self.state_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                log.warning("tailer state file unreadable; starting from the beginning of each file")
        return {}

    def _save_state(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._state, indent=2), encoding="utf-8")
        tmp.replace(self.state_file)

    @staticmethod
    def _kind_from_name(name: str) -> str | None:
        lower = name.lower()
        for kind, hints in NAME_HINTS.items():
            if any(h in lower for h in hints):
                return kind
        return None

    def poll(self) -> PollResult:
        result = PollResult()
        for path in sorted(self.inbox.glob("*.csv")):
            try:
                self._read_new_lines(path, result)
            except OSError as exc:  # file locked or removed mid-read: try next poll
                log.warning("could not read %s: %s", path.name, exc)
        if result.files:
            self._save_state()
        result.events.sort(key=event_sort_key)
        return result

    def _read_new_lines(self, path: Path, result: PollResult) -> None:
        key = path.name
        st = self._state.get(key, {"offset": 0, "header": None, "kind": None, "line": 0})
        size = path.stat().st_size
        if size < st["offset"]:  # truncated or rotated: start again
            st = {"offset": 0, "header": None, "kind": None, "line": 0}
        if size == st["offset"]:
            return
        with path.open("rb") as fh:
            fh.seek(st["offset"])
            chunk = fh.read(size - st["offset"])
        last_nl = chunk.rfind(b"\n")
        if last_nl < 0:
            return  # no complete line yet
        complete = chunk[: last_nl + 1]
        text = complete.decode("utf-8-sig" if st["offset"] == 0 else "utf-8", errors="replace")
        lines = text.splitlines()
        if st["header"] is None:
            if not lines:
                return
            header = [h.strip().lower() for h in next(csv.reader([lines[0]]))]
            kind = detect_kind(header) or self._kind_from_name(key)
            if kind is None:
                log.warning("skipping %s: unrecognised columns", key)
                st.update(offset=size, header=header, kind="unknown")
                self._state[key] = st
                return
            st["header"], st["kind"] = header, kind
            st["line"] = 1
            lines = lines[1:]
        st["offset"] += len(complete)
        self._state[key] = st
        if st["kind"] not in FEEDS:
            return
        _, converter = FEEDS[st["kind"]]
        parsed = 0
        for row in csv.reader(io.StringIO("\n".join(lines))):
            st["line"] += 1
            if not any(cell.strip() for cell in row):
                continue
            record = dict(zip(st["header"], row))
            try:
                result.events.append(converter(record, st["line"]))
                parsed += 1
            except RowParseError as exc:
                result.errors.append({"file": key, **RowError(st["line"], str(exc)).to_dict()})
        result.files[key] = parsed
