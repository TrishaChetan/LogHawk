"""LogHawk command line.

    python -m loghawk.cli generate samples/scenario
    python -m loghawk.cli analyze /var/log/auth.log access.log --json report.json
    python -m loghawk.cli train-ueba baseline/*.log --tz 5.5
    python -m loghawk.cli search auth.log 'action:ssh_login outcome:success user:root'
    python -m loghawk.cli rules
    python -m loghawk.cli lint-rules [rules_dir] [--strict]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from .generator import LogGen
from .lint import lint_directory
from .parsers import parse_file
from .pipeline import analyse_files, load_ueba, train_ueba
from .rules import load_rules
from .search import search

C = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "informational": "\033[90m"}
R = "\033[0m"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="loghawk")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate"); g.add_argument("out"); g.add_argument("--seed", type=int, default=1)
    a = sub.add_parser("analyze"); a.add_argument("files", nargs="+"); a.add_argument("--json"); a.add_argument("--no-ueba", action="store_true")
    t = sub.add_parser("train-ueba"); t.add_argument("files", nargs="+"); t.add_argument("--tz", type=float, default=0.0, help="UTC offset of working hours, e.g. 5.5 for IST")
    s = sub.add_parser("search"); s.add_argument("file"); s.add_argument("query")
    sub.add_parser("rules")
    lr = sub.add_parser("lint-rules", help="check rule files for mistakes")
    lr.add_argument("directory", nargs="?", help="rules directory (default: bundled rules/)")
    lr.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    if args.cmd == "generate":
        print("wrote", LogGen(seed=args.seed).write(args.out))
    elif args.cmd == "train-ueba":
        events = [e for f in args.files for e in parse_file(f)]
        u = train_ueba(events, tz_offset_h=args.tz)
        print(f"UEBA trained on {len(events)} events, {len(u.user_mean)} users")
    elif args.cmd == "lint-rules":
        n, problems = lint_directory(args.directory) if args.directory else lint_directory()
        for p in problems:
            color = "\033[91m" if p.level == "error" else "\033[93m"
            print(f"{color}{p}{R}")
        errors = sum(p.level == "error" for p in problems)
        warnings = len(problems) - errors
        print(f"{n} rules checked · {errors} error(s) · {warnings} warning(s)")
        if errors or (args.strict and warnings):
            sys.exit(1)
    elif args.cmd == "rules":
        for r in load_rules():
            print(f"{r.id:<8} {r.severity:<9} {r.type:<10} {r.mitre.get('technique', ''):<11} {r.title}")
    elif args.cmd == "search":
        total, hits = search(parse_file(args.file), args.query, 50)
        for e in hits:
            print(datetime.fromtimestamp(e.ts).isoformat(), e.source, e.action, e.outcome, e.message or f"{e.src_ip} {e.url} {e.status}")
        print(f"{total} matches")
    else:
        res = analyse_files(args.files, None if args.no_ueba else load_ueba())
        print(f"{res.stats['events']} events · {res.stats['alerts']} alerts · {res.stats['incidents']} incidents\n")
        for i in res.incidents:
            print(f"{C[i.severity]}■ INCIDENT #{i.id} [{i.severity.upper()} risk {i.risk}]{R} {i.title}")
            print(f"  entities: ips={i.entities['src_ip']} users={i.entities['user']} hosts={i.entities['host']}")
            print(f"  kill chain: {' → '.join(i.tactics)}")
            for al in i.alerts:
                print(f"    {datetime.fromtimestamp(al['ts']).strftime('%m-%d %H:%M:%S')} {C[al['severity']]}{al['severity']:<8}{R} "
                      f"{al['rule_id']:<8} {al['title']}  [{al['technique']}]")
            print()
        if args.json:
            json.dump({"stats": res.stats, "incidents": [i.to_dict() for i in res.incidents]}, open(args.json, "w"), indent=2, default=str)


if __name__ == "__main__":
    main()
