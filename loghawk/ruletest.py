"""Try a single detection rule against real logs.

`lint-rules` tells you a rule is well-formed; `test-rule` tells you whether it
actually fires on your data, and why or why not:

    python -m loghawk.cli test-rule LH-001 samples/scenario/auth.log
    python -m loghawk.cli test-rule my_rule.yml /var/log/auth.log --show 10

The report shows how many events each condition (or each sequence step)
matched, then runs the rule through the real streaming engine to list the
alerts it would raise. A rule whose conditions match but never fires usually
has a threshold, window or group_by that is too strict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .parsers import Event, parse_file
from .rules import Alert, Rule, RuleEngine, load_rules


@dataclass
class RuleTestReport:
    rule: Rule
    events: int
    step_hits: list[int]                  # matches per condition / sequence step
    samples: list[Event] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.alerts:
            return f"FIRES — {len(self.alerts)} alert(s)"
        if not any(self.step_hits):
            return "NO MATCH — no event satisfies the match conditions"
        if self.rule.type == "sequence" and 0 in self.step_hits:
            first_missing = self.step_hits.index(0) + 1
            return f"PARTIAL — step {first_missing} never matched"
        return ("MATCHES BUT DOESN'T FIRE — conditions match, but the "
                f"{'threshold/window' if self.rule.type == 'threshold' else 'sequence order/window'} isn't met")


def resolve_rule(spec: str) -> Rule:
    """A rule id from the bundled rules, or a path to a .yml file (first rule in it)."""
    path = Path(spec)
    if path.suffix in (".yml", ".yaml") and path.exists():
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        if not docs:
            raise ValueError(f"{spec}: no rule found")
        return Rule.from_dict(docs[0])
    for r in load_rules():
        if r.id.lower() == spec.lower():
            return r
    raise ValueError(f"unknown rule '{spec}' (see `loghawk rules`)")


def test_rule(rule: Rule, events: list[Event], samples: int = 5) -> RuleTestReport:
    events = sorted(events, key=lambda e: e.ts)
    matchers = [rule.match] if rule.type in ("single", "threshold") else [m for m, _ in rule.steps]
    hits = [0] * len(matchers)
    shown: list[Event] = []
    for e in events:
        for i, m in enumerate(matchers):
            if m(e):
                hits[i] += 1
                if len(shown) < samples:
                    shown.append(e)
    engine = RuleEngine([rule])
    alerts = [a for e in events for a in engine.process(e)]
    return RuleTestReport(rule, len(events), hits, shown, alerts)


test_rule.__test__ = False  # not a pytest test, despite the name


def test_rule_on_files(spec: str, files: list[str], samples: int = 5) -> RuleTestReport:
    events = [e for f in files for e in parse_file(f)]
    return test_rule(resolve_rule(spec), events, samples)


test_rule_on_files.__test__ = False


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def format_report(rep: RuleTestReport) -> str:
    r = rep.rule
    lines = [f"Rule {r.id}: {r.title}  [{r.type}, {r.severity}]",
             f"Events parsed: {rep.events}"]
    if r.type == "sequence":
        for i, n in enumerate(rep.step_hits, 1):
            lines.append(f"  step {i}: {n} matching event(s)")
    else:
        lines.append(f"  match conditions: {rep.step_hits[0]} matching event(s)")
        if r.type == "threshold":
            per = f" distinct {r.distinct}" if r.distinct else " events"
            lines.append(f"  needs {r.threshold}{per} within {int(r.window)}s"
                         + (f" per {', '.join(r.group_by)}" if r.group_by else ""))
    if rep.samples:
        lines.append("Sample matching events:")
        for e in rep.samples:
            who = " ".join(f"{k}={v}" for k, v in (("user", e.user), ("src_ip", e.src_ip), ("host", e.host)) if v)
            lines.append(f"  {_when(e.ts)}  {e.source}/{e.action} {e.outcome}  {who}".rstrip())
    for a in rep.alerts:
        ents = " ".join(f"{k}={v}" for k, v in a.entities.items())
        lines.append(f"ALERT {_when(a.ts)}  count={a.count}  {ents}")
    lines.append(f"Result: {rep.verdict}")
    return "\n".join(lines)
