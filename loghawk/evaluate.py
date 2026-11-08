"""Reproducible evaluation for the project report.

    python -m loghawk.evaluate --seeds 5

For each random seed a fresh 8-day dataset is generated (7 benign days + attack night).
  * UEBA is trained on days 1-5 only.
  * Days 6-7 are held-out benign data  -> false-positive measurement (rules + UEBA).
  * Night 8 contains the attack         -> detection per stage, per rule, and incident quality.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from .generator import LogGen
from .parsers import parse_file
from .pipeline import analyse_events
from .rules import load_rules
from .ueba import UEBA

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
FILES = ["auth.log", "ufw.log", "access.log", "windows_security.jsonl"]


def run_seed(seed: int) -> dict:
    with tempfile.TemporaryDirectory() as d:
        LogGen(seed=seed).write(d)
        gt = json.loads((Path(d) / "ground_truth.json").read_text())
        events = [e for f in FILES for e in parse_file(str(Path(d) / f))]
    attack_start = gt["attack_start"]
    holdout_start = attack_start - 2 * 86400
    ueba = UEBA(tz_offset_h=5.5).fit([e for e in events if e.ts < holdout_start])
    res = analyse_events(events, ueba, ueba_from=holdout_start)

    fp = [a for a in res.alerts if a.ts < attack_start]
    fp_holdout = [a for a in fp if a.ts >= holdout_start]
    attack_alerts = [a for a in res.alerts if a.ts >= attack_start]
    fired = {a.rule_id for a in attack_alerts}
    stages = []
    for s in gt["stages"]:
        in_window = {a.rule_id for a in attack_alerts if s["start"] - 1 <= a.ts <= s["end"] + 600}
        exp = s["expected_rules"]
        stages.append({"stage": s["stage"], "detected": bool(in_window & set(exp)),
                       "rules_fired": sorted(set(exp) & in_window), "rules_missed": sorted(set(exp) - fired),
                       "first_alert_delay_s": min((a.ts - s["start"] for a in attack_alerts
                                                   if a.rule_id in exp and a.ts >= s["start"] - 1), default=None)})
    expected = {r for s in gt["stages"] for r in s["expected_rules"]}
    attack_incidents = [i for i in res.incidents if i.start >= attack_start]
    return {
        "seed": seed, "events": res.stats["events"], "events_per_second": res.stats["events_per_second"],
        "alerts_total": len(res.alerts), "attack_alerts": len(attack_alerts),
        "false_positives_7_days": len(fp), "false_positives_holdout_2_days": len(fp_holdout),
        "fp_rules": dict(Counter(a.rule_id for a in fp)),
        "expected_rules": len(expected), "expected_rules_fired": len(expected & fired),
        "unexpected_rules_in_attack": sorted(fired - expected),
        "stages": stages,
        "attack_incidents": [{"risk": i.risk, "severity": i.severity, "alerts": len(i.alerts),
                              "tactics": i.tactics, "src_ip": i.entities["src_ip"], "user": i.entities["user"]}
                             for i in attack_incidents],
        "alert_reduction": round(1 - len(attack_incidents) / max(1, len(attack_alerts)), 3),
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    args = ap.parse_args(argv)
    runs = [run_seed(s) for s in range(1, args.seeds + 1)]
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "evaluation.json").write_text(json.dumps(runs, indent=2))

    n = len(runs)
    stage_hits = defaultdict(int)
    delays = defaultdict(list)
    for r in runs:
        for s in r["stages"]:
            stage_hits[s["stage"]] += s["detected"]
            if s["first_alert_delay_s"] is not None:
                delays[s["stage"]].append(s["first_alert_delay_s"])
    rule_cov = sum(r["expected_rules_fired"] for r in runs) / sum(r["expected_rules"] for r in runs)
    md = [f"# LogHawk evaluation ({n} independent synthetic datasets)\n",
          f"Rules loaded: {len(load_rules())} + UEBA model\n",
          "## Attack-stage detection\n", "| Stage | Detected | Median time to first alert |", "|---|---|---|"]
    for st, hits in stage_hits.items():
        d = sorted(delays[st]); med = d[len(d) // 2] if d else None
        md.append(f"| {st} | {hits}/{n} | {'%.0f s' % med if med is not None else '—'} |")
    md += ["", "## Summary", "",
           f"- Expected rule firings: **{rule_cov:.1%}** ({sum(r['expected_rules_fired'] for r in runs)}/{sum(r['expected_rules'] for r in runs)})",
           f"- False positives on 7 benign days (rules + UEBA): **{sum(r['false_positives_7_days'] for r in runs)}** total across {n} datasets "
           f"({sum(r['false_positives_holdout_2_days'] for r in runs)} on UEBA hold-out days)",
           f"- Alerts → incidents: {sum(r['attack_alerts'] for r in runs) / n:.0f} alerts collapse into "
           f"{sum(len(r['attack_incidents']) for r in runs) / n:.1f} incidents per attack "
           f"(**{sum(r['alert_reduction'] for r in runs) / n:.0%} fewer items** for the analyst)",
           f"- Throughput: ~{sum(r['events_per_second'] for r in runs) // n:,} events/s (single Python process)",
           "", "## Incidents (seed 1)", "", "| Risk | Severity | Alerts | Source IPs | Users | ATT&CK tactics |", "|---|---|---|---|---|---|"]
    for i in runs[0]["attack_incidents"]:
        md.append(f"| {i['risk']} | {i['severity']} | {i['alerts']} | {', '.join(i['src_ip'])} | {', '.join(i['user'])} | {' → '.join(i['tactics'])} |")
    fp_rules = Counter()
    for r in runs:
        fp_rules.update(r["fp_rules"])
    if fp_rules:
        md += ["", "False-positive rules: " + ", ".join(f"{k} ×{v}" for k, v in fp_rules.most_common())]
    (REPORTS / "metrics.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
