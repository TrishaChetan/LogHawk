"""Sigma-inspired detection rules.

Rules are YAML files in rules/. Three rule types:

single     — one event matches the conditions
threshold  — >= N matching events (or N distinct values of a field) per group within a window
sequence   — ordered steps per group within a window (e.g. many failures THEN a success)

Condition syntax (all keys AND-ed, list values OR-ed), Sigma-style modifiers:

    match:
      source: linux_auth                 # equals (case-insensitive)
      action: [ssh_login, ssh_invalid_user]
      command|contains: ["/etc/shadow", "/etc/sudoers"]
      url_decoded|re: "(?i)union\\s+select"
      status|gte: 400
      user|not: [root]
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .parsers import Event

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SEVERITY_WEIGHT = {"informational": 1, "low": 3, "medium": 10, "high": 25, "critical": 50}


def _to_list(v) -> list:
    return v if isinstance(v, list) else [v]


def compile_condition(key: str, value: Any) -> Callable[[Event], bool]:
    fieldname, _, mod = key.partition("|")
    vals = _to_list(value)

    def get(e: Event):
        v = e.get(fieldname, "")
        return "" if v is None else v

    if mod == "" or mod == "eq":
        lowered = {str(v).lower() for v in vals}
        return lambda e: str(get(e)).lower() in lowered
    if mod == "contains":
        needles = [str(v).lower() for v in vals]
        return lambda e: any(n in str(get(e)).lower() for n in needles)
    if mod == "startswith":
        needles = tuple(str(v).lower() for v in vals)
        return lambda e: str(get(e)).lower().startswith(needles)
    if mod == "endswith":
        needles = tuple(str(v).lower() for v in vals)
        return lambda e: str(get(e)).lower().endswith(needles)
    if mod == "re":
        pats = [re.compile(v) for v in vals]
        return lambda e: any(p.search(str(get(e))) for p in pats)
    if mod in ("gt", "gte", "lt", "lte"):
        num = float(vals[0])
        op = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[mod]
        return lambda e: _num(get(e)) is not None and op(_num(get(e)), num)
    if mod == "not":
        lowered = {str(v).lower() for v in vals}
        return lambda e: str(get(e)).lower() not in lowered
    if mod == "exists":
        want = bool(vals[0])
        return lambda e: bool(get(e)) == want
    raise ValueError(f"unknown modifier '{mod}' in '{key}'")


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def compile_match(match: dict) -> Callable[[Event], bool]:
    conds = [compile_condition(k, v) for k, v in (match or {}).items()]
    return lambda e: all(c(e) for c in conds)


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    ts: float
    tactic: str
    technique: str
    technique_name: str
    entities: dict
    count: int
    description: str
    evidence: list = field(default_factory=list)  # list of event dicts (sample)

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class Rule:
    id: str
    title: str
    type: str
    severity: str
    description: str
    mitre: dict
    match: Callable[[Event], bool] | None = None
    group_by: list = field(default_factory=list)
    threshold: int = 1
    window: float = 300.0
    distinct: str | None = None
    steps: list = field(default_factory=list)   # [(matcher, min_count)]
    enabled: bool = True
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        r = cls(id=d["id"], title=d["title"], type=d.get("type", "single"), severity=d.get("severity", "medium"),
                description=d.get("description", ""), mitre=d.get("mitre", {}), group_by=_to_list(d.get("group_by", [])),
                threshold=int(d.get("threshold", 1)), window=float(d.get("window", 300)), distinct=d.get("distinct"),
                enabled=d.get("enabled", True), raw=d)
        if r.severity not in SEVERITY_WEIGHT:
            raise ValueError(f"{r.id}: bad severity {r.severity}")
        if r.type in ("single", "threshold"):
            r.match = compile_match(d["match"])
        elif r.type == "sequence":
            r.steps = [(compile_match(s["match"]), int(s.get("min_count", 1))) for s in d["steps"]]
        else:
            raise ValueError(f"{r.id}: unknown type {r.type}")
        return r

    def key(self, e: Event) -> tuple:
        return tuple(str(e.get(g, "")) for g in self.group_by)


def load_rules(directory: Path | str = RULES_DIR) -> list[Rule]:
    rules = []
    for p in sorted(Path(directory).glob("*.yml")):
        docs = [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if d]
        for d in docs:
            rules.append(Rule.from_dict(d))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate rule ids: {dupes}")
    return [r for r in rules if r.enabled]


class RuleEngine:
    """Streaming evaluation; feed events in time order."""

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else load_rules()
        self.state: dict[str, dict] = {r.id: defaultdict(deque) for r in self.rules}
        self.seq: dict[str, dict] = {r.id: {} for r in self.rules if r.type == "sequence"}
        self.cooldown: dict[tuple, float] = {}

    def _alert(self, r: Rule, e: Event, count: int, evidence: list[Event], extra: str = "") -> Alert | None:
        k = (r.id, r.key(e))
        if e.ts - self.cooldown.get(k, -1e18) < max(r.window, 60):
            return None
        self.cooldown[k] = e.ts
        if r.type == "threshold":
            # only entities shared by ALL evidence events — the 42 usernames guessed in a
            # brute force are not "the user" of the alert, the source IP is
            ents = {f: e.get(f) for f in ("src_ip", "user", "host")
                    if e.get(f) and all(x.get(f) == e.get(f) for x in evidence)}
        else:
            # single event, or the final step of a sequence (e.g. the account that got in)
            ents = {f: e.get(f) for f in ("src_ip", "user", "host") if e.get(f)}
        desc = r.description.strip() + (f" — {extra}" if extra else "")
        return Alert(r.id, r.title, r.severity, e.ts, r.mitre.get("tactic", ""), r.mitre.get("technique", ""),
                     r.mitre.get("name", ""), ents, count, desc, [x.to_dict() for x in evidence[-5:]])

    def process(self, e: Event) -> list[Alert]:
        out = []
        for r in self.rules:
            if r.type == "single":
                if r.match(e):
                    a = self._alert(r, e, 1, [e])
                    if a:
                        out.append(a)
            elif r.type == "threshold":
                if not r.match(e):
                    continue
                dq = self.state[r.id][r.key(e)]
                dq.append(e)
                while dq and e.ts - dq[0].ts > r.window:
                    dq.popleft()
                n = len({str(x.get(r.distinct)) for x in dq}) if r.distinct else len(dq)
                if n >= r.threshold:
                    extra = f"{n} {'distinct ' + r.distinct + ' values' if r.distinct else 'events'} in {int(r.window)}s"
                    a = self._alert(r, e, n, list(dq), extra)
                    if a:
                        out.append(a)
            else:  # sequence
                k = r.key(e)
                st = self.seq[r.id].get(k)
                if st and e.ts - st["start"] > r.window:
                    st = None
                    self.seq[r.id].pop(k, None)
                step_idx = st["step"] if st else 0
                matcher, need = r.steps[step_idx]
                if matcher(e):
                    if st is None:
                        st = {"start": e.ts, "step": 0, "count": 0, "events": []}
                        self.seq[r.id][k] = st
                    st["count"] += 1
                    st["events"].append(e)
                    if st["count"] >= need:
                        st["step"] += 1
                        st["count"] = 0
                        if st["step"] == len(r.steps):
                            a = self._alert(r, e, len(st["events"]), st["events"], f"{len(r.steps)}-step sequence completed")
                            self.seq[r.id].pop(k, None)
                            if a:
                                out.append(a)
        return out
