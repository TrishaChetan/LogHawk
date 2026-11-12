"""Live mode: follow log files as they grow and raise alerts in real time.

    python -m loghawk.cli watch /var/log/auth.log /var/log/nginx/access.log
    python -m loghawk.cli watch auth.log --from-start --min-severity high --jsonl alerts.jsonl

Works like `tail -F`: starts at the end of each file (or the beginning with
--from-start), survives log rotation (file replaced) and truncation (file
shrinks), and waits for files that don't exist yet. Every new line is parsed
and pushed through the same streaming RuleEngine used by `analyze`, so
threshold and sequence rules keep their state across lines and files.
Partial lines (writer hasn't finished the line yet) are held until complete.
Standard library only — no inotify dependency.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .parsers import parse_line
from .rules import SEVERITY_WEIGHT, Alert, RuleEngine, load_rules


@dataclass
class _Tail:
    path: str
    from_start: bool = False
    fh: object = None
    inode: int | None = None
    buf: str = ""
    head: bytes = b""               # first bytes of the file, to spot truncate-and-rewrite
    opened_once: bool = field(default=False)

    HEAD_LEN = 64

    def _head(self) -> bytes:
        try:
            return os.pread(self.fh.fileno(), self.HEAD_LEN, 0)
        except (OSError, AttributeError):  # pread missing on Windows
            return b""

    def _rewritten(self, size: int) -> bool:
        """True if the file was truncated (possibly refilled since the last poll)."""
        if size < self.fh.tell():
            return True
        if self.head and self._head()[: len(self.head)] != self.head:
            return True
        return False

    def _open(self) -> bool:
        try:
            fh = open(self.path, encoding="utf-8", errors="replace")
        except OSError:
            return False
        st = os.fstat(fh.fileno())
        # first open: honour --from-start; reopen after rotation: read new file from its start
        if self.opened_once or self.from_start:
            fh.seek(0)
        else:
            fh.seek(0, os.SEEK_END)
        self.fh, self.inode, self.buf, self.opened_once = fh, st.st_ino, "", True
        self.head = self._head()
        return True

    def read_lines(self) -> list[str]:
        if self.fh is None and not self._open():
            return []
        try:
            st = os.stat(self.path)
        except OSError:
            return self._drain()               # file moved away; keep draining old handle
        if st.st_ino != self.inode:            # rotated: finish old file, switch to new one
            lines = self._drain()
            self.fh.close()
            self.fh = None
            if self._open():
                lines += self._drain()
            return lines
        if self._rewritten(st.st_size):        # truncated in place (copytruncate)
            self.fh.seek(0)
            self.buf = ""
            self.head = self._head()
        elif len(self.head) < self.HEAD_LEN:   # file was short/empty: grow the fingerprint
            self.head = self._head()
        return self._drain()

    def _drain(self) -> list[str]:
        data = self.fh.read()
        if not data:
            return []
        data = self.buf + data
        *complete, self.buf = data.split("\n")  # keep an unfinished last line for later
        return complete


def follow(paths: list[str], from_start: bool = False, interval: float = 0.5,
           stop: Callable[[], bool] = lambda: False) -> Iterator[str]:
    """Yield new lines from all files until stop() returns True."""
    tails = [_Tail(p, from_start) for p in paths]
    while not stop():
        got = False
        for t in tails:
            for line in t.read_lines():
                got = True
                yield line
        if not got:
            time.sleep(interval)


def watch(paths: list[str], on_alert: Callable[[Alert], None], *, from_start: bool = False,
          min_severity: str = "low", interval: float = 0.5, stop: Callable[[], bool] = lambda: False,
          engine: RuleEngine | None = None) -> dict:
    """Run the rule engine over followed lines. Returns counters when stopped."""
    engine = engine or RuleEngine(load_rules())
    floor = SEVERITY_WEIGHT.get(min_severity, 0)
    stats = {"lines": 0, "events": 0, "alerts": 0}
    for line in follow(paths, from_start, interval, stop):
        stats["lines"] += 1
        try:
            ev = parse_line(line)
        except Exception:  # a malformed line must never stop the watcher
            ev = None
        if not ev:
            continue
        stats["events"] += 1
        for a in engine.process(ev):
            if SEVERITY_WEIGHT.get(a.severity, 0) >= floor:
                stats["alerts"] += 1
                on_alert(a)
    return stats


def alert_jsonl(a: Alert) -> str:
    d = a.to_dict()
    d.pop("evidence", None)
    return json.dumps(d, default=str)
