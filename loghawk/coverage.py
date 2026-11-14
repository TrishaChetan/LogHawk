"""MITRE ATT&CK coverage of the loaded detection rules.

    python -m loghawk.cli coverage                      # table + gaps
    python -m loghawk.cli coverage --navigator layer.json

The --navigator file is an ATT&CK Navigator layer (format 4.5). Open
https://mitre-attack.github.io/attack-navigator/ → "Open Existing Layer" →
"Upload from local" to see every covered technique highlighted, with darker
cells for techniques covered by more rules.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .rules import Rule, load_rules

# Enterprise ATT&CK tactics in kill-chain order (name, Navigator short name)
TACTICS = [
    ("Reconnaissance", "reconnaissance"),
    ("Resource Development", "resource-development"),
    ("Initial Access", "initial-access"),
    ("Execution", "execution"),
    ("Persistence", "persistence"),
    ("Privilege Escalation", "privilege-escalation"),
    ("Defense Evasion", "defense-evasion"),
    ("Credential Access", "credential-access"),
    ("Discovery", "discovery"),
    ("Lateral Movement", "lateral-movement"),
    ("Collection", "collection"),
    ("Command and Control", "command-and-control"),
    ("Exfiltration", "exfiltration"),
    ("Impact", "impact"),
]
SHORT = {name.lower(): short for name, short in TACTICS}
# Resource Development happens on the attacker's side, so log-based tools can't see it
NOT_LOG_VISIBLE = {"Resource Development"}


def compute(rules: list[Rule] | None = None) -> dict:
    rules = rules if rules is not None else load_rules()
    by_tactic: dict[str, list[Rule]] = defaultdict(list)
    techniques: dict[tuple, dict] = {}
    unmapped = []
    for r in rules:
        tactic = (r.mitre or {}).get("tactic", "").strip()
        tech = (r.mitre or {}).get("technique", "").strip()
        if not tactic:
            unmapped.append(r.id)
            continue
        by_tactic[tactic.lower()].append(r)
        if tech:
            t = techniques.setdefault((tech, tactic.lower()), {
                "technique": tech, "name": (r.mitre or {}).get("name", ""), "tactic": tactic, "rules": []})
            t["rules"].append(r.id)

    rows = []
    for name, _ in TACTICS:
        rs = by_tactic.get(name.lower(), [])
        techs = sorted({(r.mitre or {}).get("technique", "") for r in rs} - {""})
        rows.append({"tactic": name, "rules": [r.id for r in rs], "techniques": techs,
                     "visible_in_logs": name not in NOT_LOG_VISIBLE})
    covered = [r for r in rows if r["rules"]]
    gaps = [r["tactic"] for r in rows if not r["rules"] and r["visible_in_logs"]]
    return {
        "rules": len(rules),
        "tactics_covered": len(covered),
        "tactics_total": len(TACTICS),
        "techniques_covered": len({t["technique"] for t in techniques.values()}),
        "tactics": rows,
        "techniques": sorted(techniques.values(), key=lambda t: (t["technique"], t["tactic"])),
        "gaps": gaps,
        "unmapped_rules": unmapped,
    }


def format_coverage(c: dict) -> str:
    out = [f"{c['rules']} rules · {c['tactics_covered']}/{c['tactics_total']} ATT&CK tactics · "
           f"{c['techniques_covered']} techniques", ""]
    width = max(len(r["tactic"]) for r in c["tactics"])
    for r in c["tactics"]:
        n = len(r["rules"])
        bar = "█" * n if n else ("·" if r["visible_in_logs"] else " ")
        note = ", ".join(r["techniques"]) if n else ("GAP" if r["visible_in_logs"] else "n/a (attacker-side)")
        out.append(f"  {r['tactic']:<{width}}  {n:>2}  {bar:<8} {note}")
    if c["gaps"]:
        out += ["", "Gaps — no rule detects: " + ", ".join(c["gaps"])]
    if c["unmapped_rules"]:
        out.append("Rules without a MITRE mapping: " + ", ".join(c["unmapped_rules"]))
    return "\n".join(out)


def navigator_layer(c: dict, name: str = "LogHawk detection coverage") -> dict:
    max_rules = max((len(t["rules"]) for t in c["techniques"]), default=1)
    return {
        "name": name,
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{c['rules']} LogHawk rules covering {c['techniques_covered']} techniques",
        "techniques": [
            {
                "techniqueID": t["technique"],
                "tactic": SHORT.get(t["tactic"].lower(), t["tactic"].lower().replace(" ", "-")),
                "score": len(t["rules"]),
                "comment": "Rules: " + ", ".join(t["rules"]),
                "enabled": True,
            }
            for t in c["techniques"]
        ],
        "gradient": {"colors": ["#c6e5ff", "#0b5394"], "minValue": 0, "maxValue": max_rules},
        "legendItems": [],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": False,
    }


def write_navigator(c: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(navigator_layer(c), indent=2), encoding="utf-8")
