"""Alert -> incident correlation.

Individual alerts are noisy; analysts work on incidents. Alerts are linked when
they share an entity (source IP or user) within a time window — using
union-find, so a chain like

    IP 45.33.12.7 brute-forces SSH  ->  logs in as bob  ->  bob runs sudo  ->  bob creates 'backdoor'

becomes ONE incident even though no single alert contains every entity.
Generic shared accounts (root, Administrator…) are not used for linking,
otherwise every root alert would merge into one giant incident. Hosts link
only within a short window (30 min) for the same reason.

Risk score = sum of severity weights x (1 + 0.25 per extra ATT&CK tactic),
so multi-stage attacks rank above many alerts of a single kind.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .rules import SEVERITY_WEIGHT, Alert

TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact"]
NO_LINK_USERS = {"root", "administrator", "admin", "system", "guest", ""}


@dataclass
class Incident:
    id: int
    start: float
    end: float
    risk: float
    severity: str
    title: str
    entities: dict
    tactics: list
    alerts: list = field(default_factory=list)

    def to_dict(self):
        return self.__dict__.copy()


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def _keys(a: Alert) -> list[str]:
    ks = []
    if a.entities.get("src_ip"):
        ks.append("ip:" + a.entities["src_ip"])
    u = str(a.entities.get("user", "")).lower()
    if u and u not in NO_LINK_USERS:
        ks.append("user:" + u)
    if a.entities.get("host"):
        ks.append("host:" + str(a.entities["host"]).lower())
    return ks or [f"alert:{id(a)}"]


def correlate(alerts: list[Alert], window: float = 6 * 3600, host_window: float = 1800) -> list[Incident]:
    """IPs and users link alerts up to `window` apart; a host links only within
    `host_window` (busy servers would otherwise glue unrelated activity together)."""
    alerts = sorted(alerts, key=lambda a: a.ts)
    uf = _UF()
    # entity key -> (current node id, last time seen). An entity that has been quiet
    # for longer than `window` starts a new node, so unrelated activity days apart
    # by the same IP/user does not merge into one incident.
    active: dict[str, tuple[str, float]] = {}
    counter = 0
    node_of: list[str] = []
    for a in alerts:
        nodes = []
        for k in _keys(a):
            cur = active.get(k)
            w = host_window if k.startswith("host:") else window
            if cur is None or a.ts - cur[1] > w:
                counter += 1
                cur = (f"{k}#{counter}", a.ts)
            active[k] = (cur[0], a.ts)
            nodes.append(cur[0])
        for n in nodes[1:]:
            uf.union(nodes[0], n)
        node_of.append(nodes[0])
    # re-resolve after all unions
    groups: dict[str, list[Alert]] = {}
    for a, n in zip(alerts, node_of):
        groups.setdefault(uf.find(n), []).append(a)

    incidents = []
    for i, (_, al) in enumerate(sorted(groups.items(), key=lambda kv: kv[1][0].ts), 1):
        tactics = sorted({a.tactic for a in al if a.tactic}, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        base = sum(SEVERITY_WEIGHT[a.severity] for a in al)
        risk = round(base * (1 + 0.25 * max(0, len(tactics) - 1)), 1)
        sev = "critical" if risk >= 150 else "high" if risk >= 60 else "medium" if risk >= 20 else "low"
        ents = {"src_ip": sorted({a.entities["src_ip"] for a in al if a.entities.get("src_ip")}),
                "user": sorted({a.entities["user"] for a in al if a.entities.get("user")}),
                "host": sorted({a.entities["host"] for a in al if a.entities.get("host")})}
        top = max(al, key=lambda a: SEVERITY_WEIGHT[a.severity])
        title = top.title if len(al) == 1 else f"{top.title} (+{len(al) - 1} related alerts, {len(tactics)} tactics)"
        incidents.append(Incident(i, al[0].ts, al[-1].ts, risk, sev, title, ents, tactics, [a.to_dict() for a in al]))
    return sorted(incidents, key=lambda x: -x.risk)
