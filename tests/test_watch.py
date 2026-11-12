import os
import threading
import time
from pathlib import Path

from loghawk.watch import _Tail, watch

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "scenario" / "auth.log"


def test_tail_starts_at_end_and_holds_partial_lines(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("old line\n")
    t = _Tail(str(f))
    assert t.read_lines() == []                 # existing content skipped (like tail -f)
    with open(f, "a") as fh:
        fh.write("new 1\nnew 2 (partial")
    assert t.read_lines() == ["new 1"]          # unfinished line held back
    with open(f, "a") as fh:
        fh.write(" now done)\n")
    assert t.read_lines() == ["new 2 (partial now done)"]


def test_tail_from_start_rotation_and_truncation(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("one\ntwo\n")
    t = _Tail(str(f), from_start=True)
    assert t.read_lines() == ["one", "two"]
    os.rename(f, tmp_path / "a.log.1")          # logrotate: move + create new file
    f.write_text("fresh\n")
    assert t.read_lines() == ["fresh"]
    f.write_text("")                            # truncate in place
    with open(f, "a") as fh:
        fh.write("after truncate\n")
    assert t.read_lines() == ["after truncate"]


def test_waits_for_missing_file(tmp_path):
    t = _Tail(str(tmp_path / "later.log"))
    assert t.read_lines() == []
    (tmp_path / "later.log").write_text("x\n")
    t.read_lines()                              # opens at end
    with open(tmp_path / "later.log", "a") as fh:
        fh.write("y\n")
    assert t.read_lines() == ["y"]


def test_watch_raises_alerts_as_lines_arrive(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    alerts, done = [], threading.Event()
    result = {}

    def run():
        result["stats"] = watch([str(log)], alerts.append, interval=0.05, stop=done.is_set)

    th = threading.Thread(target=run)
    th.start()
    time.sleep(0.2)
    with open(log, "a") as fh:                  # stream the attack scenario in chunks
        lines = SAMPLE.read_text().splitlines(keepends=True)
        for i in range(0, len(lines), 200):
            fh.writelines(lines[i:i + 200])
            fh.flush()
            time.sleep(0.02)
    deadline = time.time() + 10
    while time.time() < deadline and result.get("stats") is None and not alerts:
        time.sleep(0.1)
    time.sleep(0.5)
    done.set()
    th.join(5)
    assert alerts, "expected alerts from the attack scenario"
    assert result["stats"]["events"] > 0
    assert {a.rule_id for a in alerts} & {"LH-L01", "LH-L02", "LH-L03"}
