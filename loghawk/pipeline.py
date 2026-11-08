"""End-to-end analysis pipeline: files -> events -> rules + UEBA -> incidents."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from .correlate import Incident, correlate
from .parsers import Event, parse_file, parse_lines
from .rules import Alert, RuleEngine, load_rules
from .ueba import UEBA

UEBA_PATH = Path(__file__).resolve().parent.parent / "models" / "ueba.joblib"


@dataclass
class Result:
    events: list[Event]
    alerts: list[Alert]
    incidents: list[Incident]
    stats: dict = field(default_factory=dict)


def analyse_events(events: list[Event], ueba: UEBA | None = None, rules_dir: str | None = None,
                   ueba_from: float | None = None) -> Result:
    t = time.time()
    events = sorted(events, key=lambda e: e.ts)
    engine = RuleEngine(load_rules(rules_dir) if rules_dir else None)
    alerts: list[Alert] = []
    for e in events:
        alerts += engine.process(e)
    if ueba is not None and ueba.trained:
        scope = [e for e in events if ueba_from is None or e.ts >= ueba_from]
        alerts += ueba.score(scope)
    alerts.sort(key=lambda a: a.ts)
    incidents = correlate(alerts)
    by_source: dict[str, int] = {}
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
    return Result(events, alerts, incidents, {
        "events": len(events), "alerts": len(alerts), "incidents": len(incidents),
        "events_by_source": by_source, "rules_loaded": len(engine.rules),
        "seconds": round(time.time() - t, 3),
        "events_per_second": round(len(events) / max(time.time() - t, 1e-6)),
    })


def analyse_files(paths: list[str], ueba: UEBA | None = None, **kw) -> Result:
    events: list[Event] = []
    for p in paths:
        events += parse_file(p)
    return analyse_events(events, ueba, **kw)


def analyse_text(text: str, ueba: UEBA | None = None) -> Result:
    return analyse_events(list(parse_lines(text.splitlines())), ueba)


def train_ueba(events: list[Event], until: float | None = None, tz_offset_h: float = 0.0) -> UEBA:
    base = [e for e in events if until is None or e.ts < until]
    u = UEBA(tz_offset_h=tz_offset_h).fit(base)
    UEBA_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(u, UEBA_PATH)
    return u


def load_ueba() -> UEBA | None:
    return joblib.load(UEBA_PATH) if UEBA_PATH.exists() else None
