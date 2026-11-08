"""Tiny search language for events (inspired by Splunk/KQL).

    src_ip:45.33.12.7 action:ssh_login outcome:failure
    user:bob* NOT action:cron
    status>=400 source:web_access
    "etc/shadow"                       # free text over message/url/command
Terms are AND-ed; NOT negates the next term; * is a wildcard.
"""
from __future__ import annotations

import fnmatch
import re
import shlex

from .parsers import Event

TEXT_FIELDS = ("message", "url", "command", "user_agent")
TERM = re.compile(r"^(?P<f>[\w.]+)(?P<op>:|>=|<=|>|<|=)(?P<v>.*)$")


def compile_query(q: str):
    try:
        tokens = shlex.split(q)
    except ValueError:
        tokens = q.split()
    preds, negate = [], False
    for tok in tokens:
        if tok.upper() == "NOT":
            negate = True
            continue
        if tok.upper() == "AND":
            continue
        m = TERM.match(tok)
        if m and m["op"] == ":" or (m and m["op"] == "="):
            f, v = m["f"], m["v"].lower()
            pred = (lambda f, v: lambda e: fnmatch.fnmatchcase(str(e.get(f, "")).lower(), v))(f, v)
        elif m:
            f, op, v = m["f"], m["op"], float(m["v"])
            cmp = {">": float.__gt__, "<": float.__lt__, ">=": float.__ge__, "<=": float.__le__}[op]
            pred = (lambda f, v, cmp: lambda e: _num(e.get(f)) is not None and cmp(_num(e.get(f)), v))(f, v, cmp)
        else:
            needle = tok.lower()
            pred = (lambda n: lambda e: any(n in str(e.get(x, "")).lower() for x in TEXT_FIELDS))(needle)
        preds.append((lambda p, neg: (lambda e: not p(e)) if neg else p)(pred, negate))
        negate = False
    return lambda e: all(p(e) for p in preds)


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def search(events: list[Event], q: str, limit: int = 200) -> tuple[int, list[Event]]:
    pred = compile_query(q) if q.strip() else (lambda e: True)
    hits = [e for e in events if pred(e)]
    return len(hits), hits[-limit:][::-1]
