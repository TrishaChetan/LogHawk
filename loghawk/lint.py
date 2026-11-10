"""Rule linter — catch mistakes in custom YAML rules before they silently fail.

`load_rules()` stops at the first hard error, and some mistakes are not errors
at all: a typo such as `src_iP: 1.2.3.4` compiles fine but can never match,
because no event has that field. The linter checks every rule in every file
and reports all problems at once, with file and rule id.

    python -m loghawk.cli lint-rules            # lint the bundled rules/
    python -m loghawk.cli lint-rules my_rules/  # lint your own directory
"""
from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

import yaml

from .parsers import Event
from .rules import RULES_DIR, SEVERITY_WEIGHT, Rule

# Fields parsers put in Event.extra (see parsers.py)
EXTRA_FIELDS = {
    "proto", "src_port", "auth_method", "target_user", "url_decoded", "referrer",
    "logon_type", "subject_user", "parent_process",
}
EVENT_FIELDS = {f.name for f in fields(Event)} - {"extra"} | EXTRA_FIELDS
SOURCES = {"linux_auth", "web_access", "windows", "firewall"}
MODIFIERS = {"", "eq", "contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "not", "exists"}
TYPES = {"single", "threshold", "sequence"}
KNOWN_KEYS = {"id", "title", "description", "type", "severity", "mitre", "match", "group_by", "threshold",
              "window", "distinct", "steps", "enabled", "tags", "references", "author", "falsepositives"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class Problem:
    file: str
    rule_id: str
    level: str      # "error" | "warning"
    message: str

    def __str__(self):
        return f"{self.level.upper():<7} {self.file} [{self.rule_id}] {self.message}"


def _check_match(match, where: str, add) -> None:
    if not isinstance(match, dict) or not match:
        add("error", f"{where}: 'match' must be a non-empty mapping")
        return
    for key, value in match.items():
        name, _, mod = str(key).partition("|")
        if mod not in MODIFIERS:
            add("error", f"{where}: unknown modifier '|{mod}' in '{key}' "
                         f"(valid: {', '.join(sorted(m for m in MODIFIERS if m))})")
        if name not in EVENT_FIELDS:
            close = [f for f in EVENT_FIELDS if f.lower() == name.lower()]
            hint = f" — did you mean '{close[0]}'?" if close else ""
            add("warning", f"{where}: field '{name}' is never set by any parser, so this condition can't match{hint}")
        if name == "source":
            for v in value if isinstance(value, list) else [value]:
                if str(v).lower() not in SOURCES:
                    add("warning", f"{where}: unknown source '{v}' (known: {', '.join(sorted(SOURCES))})")
        if mod == "re":
            for v in value if isinstance(value, list) else [value]:
                try:
                    re.compile(v)
                except (re.error, TypeError) as e:
                    add("error", f"{where}: invalid regex {v!r}: {e}")
        if mod in ("gt", "gte", "lt", "lte"):
            try:
                float(value[0] if isinstance(value, list) else value)
            except (TypeError, ValueError):
                add("error", f"{where}: '{key}' needs a number, got {value!r}")


def lint_rule(d: dict, file: str) -> list[Problem]:
    rid = str(d.get("id", "?"))
    out: list[Problem] = []

    def add(level, msg):
        out.append(Problem(file, rid, level, msg))

    for k in ("id", "title"):
        if not d.get(k):
            add("error", f"missing required field '{k}'")
    for k in d:
        if k not in KNOWN_KEYS:
            add("warning", f"unknown top-level key '{k}' (ignored by the engine)")

    rtype = d.get("type", "single")
    if rtype not in TYPES:
        add("error", f"unknown type '{rtype}' (valid: {', '.join(sorted(TYPES))})")
    sev = d.get("severity", "medium")
    if sev not in SEVERITY_WEIGHT:
        add("error", f"bad severity '{sev}' (valid: {', '.join(SEVERITY_WEIGHT)})")
    if not d.get("description"):
        add("warning", "no description — analysts won't know why this fired")

    mitre = d.get("mitre") or {}
    if not mitre:
        add("warning", "no MITRE ATT&CK mapping; it won't appear in the kill chain")
    elif mitre.get("technique") and not TECHNIQUE_RE.match(str(mitre["technique"])):
        add("warning", f"technique '{mitre['technique']}' doesn't look like T1234 or T1234.001")

    if rtype in ("single", "threshold"):
        _check_match(d.get("match"), "match", add)
    if rtype == "threshold":
        if int(d.get("threshold", 1)) < 2:
            add("warning", "threshold rule with threshold < 2 behaves like a single rule")
        if not d.get("group_by"):
            add("warning", "threshold rule without group_by counts all events together")
    if rtype == "sequence":
        steps = d.get("steps") or []
        if len(steps) < 2:
            add("error", "sequence rule needs at least 2 steps")
        for i, s in enumerate(steps, 1):
            _check_match((s or {}).get("match"), f"steps[{i}].match", add)
        if not d.get("group_by"):
            add("warning", "sequence rule without group_by can chain unrelated events")
    if d.get("distinct") and d["distinct"] not in EVENT_FIELDS:
        add("warning", f"distinct field '{d['distinct']}' is never set by any parser")
    for g in (d.get("group_by") or []) if isinstance(d.get("group_by"), list) else [d.get("group_by")]:
        if g and g not in EVENT_FIELDS:
            add("warning", f"group_by field '{g}' is never set by any parser")
    try:
        float(d.get("window", 300))
    except (TypeError, ValueError):
        add("error", f"window must be a number of seconds, got {d.get('window')!r}")

    # Finally make sure the engine itself accepts it
    if not any(p.level == "error" for p in out):
        try:
            Rule.from_dict(d)
        except Exception as e:  # noqa: BLE001 — report anything the engine rejects
            add("error", f"engine rejected rule: {e}")
    return out


def lint_directory(directory: Path | str = RULES_DIR) -> tuple[int, list[Problem]]:
    """Return (number_of_rules, problems) for every *.yml / *.yaml file."""
    directory = Path(directory)
    problems: list[Problem] = []
    seen: dict[str, str] = {}
    count = 0
    files = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))
    if not files:
        problems.append(Problem(str(directory), "-", "error", "no .yml/.yaml rule files found"))
    for p in files:
        try:
            docs = [d for d in yaml.safe_load_all(p.read_text(encoding="utf-8")) if d]
        except yaml.YAMLError as e:
            problems.append(Problem(p.name, "-", "error", f"YAML syntax error: {e}"))
            continue
        for d in docs:
            if not isinstance(d, dict):
                problems.append(Problem(p.name, "-", "error", "rule document is not a mapping"))
                continue
            count += 1
            problems += lint_rule(d, p.name)
            rid = d.get("id")
            if rid in seen:
                problems.append(Problem(p.name, str(rid), "error", f"duplicate id (also in {seen[rid]})"))
            elif rid:
                seen[rid] = p.name
    return count, problems
