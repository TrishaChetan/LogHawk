"""User & Entity Behaviour Analytics (UEBA) — the ML layer.

Rules catch known-bad patterns. UEBA catches *unusual* behaviour for a specific
user even when every single event looks innocent: a developer logging in at
03:00 from an address they've never used, then running sudo for the first time.

Per user, events are bucketed into 1-hour windows and described by 10 features.
An Isolation Forest learns the population of normal user-hours from a baseline
period. At detection time each user-hour gets an anomaly score, and the
explanation lists which features deviate most from *that user's* own history
(z-scores), so analysts see "why", not just a number.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest

from .parsers import Event
from .rules import Alert

FEATURES = ["logins_ok", "logins_fail", "distinct_ips", "new_ips", "sudo_cmds", "priv_actions",
            "hour_sin", "hour_cos", "off_hours", "distinct_hosts"]
LOGIN_ACTIONS = {"ssh_login", "logon"}
PRIV_ACTIONS = {"user_created", "group_member_added", "service_installed", "audit_log_cleared", "scheduled_task_created"}
IGNORE_USERS = {"", "-", "system", "local service", "network service", "anonymous logon"}


def _bucket(ts: float, tz_offset_h: float = 0.0) -> int:
    """Hour bucket in LOCAL time, so 'working hours' means the organisation's hours."""
    return int((ts + tz_offset_h * 3600) // 3600)


def _user_of(e: Event) -> str:
    u = (e.user or "").lower()
    return "" if u in IGNORE_USERS or u.endswith("$") else u


SUCCESS_ACTIONS = LOGIN_ACTIONS | PRIV_ACTIONS | {"sudo", "process_created", "su", "explicit_credential_logon"}


@dataclass
class UserHour:
    user: str
    hour: int
    ok: int = 0
    fail: int = 0
    ips: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    sudo: int = 0
    priv: int = 0
    events: list = field(default_factory=list)
    acted: bool = False   # did the account itself DO anything successfully this hour?
    acted_ips: dict = field(default_factory=dict)    # ip -> count of successful actions
    acted_hosts: dict = field(default_factory=dict)  # host -> count of successful actions


def aggregate(events: list[Event], tz_offset_h: float = 0.0) -> dict[tuple, UserHour]:
    agg: dict[tuple, UserHour] = {}
    for e in events:
        u = _user_of(e)
        if not u or e.source == "web_access":
            continue
        k = (u, _bucket(e.ts, tz_offset_h))
        uh = agg.setdefault(k, UserHour(u, k[1]))
        if e.action in LOGIN_ACTIONS:
            if e.outcome == "success":
                uh.ok += 1
            elif e.outcome == "failure":
                uh.fail += 1
        if e.src_ip:
            uh.ips.add(e.src_ip)
        if e.host:
            uh.hosts.add(e.host)
        if e.action == "sudo" and e.outcome == "success":
            uh.sudo += 1
        if e.action in PRIV_ACTIONS:
            uh.priv += 1
        if e.action in SUCCESS_ACTIONS and e.outcome == "success":
            uh.acted = True
            if e.src_ip:
                uh.acted_ips[e.src_ip] = uh.acted_ips.get(e.src_ip, 0) + 1
            if e.host:
                uh.acted_hosts[e.host] = uh.acted_hosts.get(e.host, 0) + 1
        uh.events.append(e)
    return agg


class UEBA:
    def __init__(self, contamination: float = 0.01, min_score: float = 0.62, tz_offset_h: float = 0.0):
        self.tz = tz_offset_h
        self.iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=5)
        self.known_ips: dict[str, set] = defaultdict(set)
        self.user_mean: dict[str, np.ndarray] = {}
        self.user_std: dict[str, np.ndarray] = {}
        self.global_mean = self.global_std = None
        self.min_score = min_score
        self.trained = False

    def _vector(self, uh: UserHour, learn: bool) -> list[float]:
        new = len(uh.ips - self.known_ips[uh.user])
        if learn:
            self.known_ips[uh.user] |= uh.ips
        hod = uh.hour % 24
        return [uh.ok, uh.fail, len(uh.ips), new, uh.sudo, uh.priv,
                math.sin(2 * math.pi * hod / 24), math.cos(2 * math.pi * hod / 24),
                float(hod < 7 or hod >= 21), len(uh.hosts)]

    def fit(self, events: list[Event]) -> "UEBA":
        rows, users = [], []
        for (u, h), uh in sorted(aggregate(events, self.tz).items(), key=lambda kv: kv[0][1]):
            rows.append(self._vector(uh, learn=True)); users.append(u)
        X = np.array(rows, dtype=float)
        if len(X) < 20:
            raise ValueError("not enough baseline activity to train UEBA (need ≥20 user-hours)")
        self.iso.fit(X)
        self.global_mean, self.global_std = X.mean(0), X.std(0) + 1e-6
        for u in set(users):
            Xu = X[[i for i, x in enumerate(users) if x == u]]
            self.user_mean[u] = Xu.mean(0)
            self.user_std[u] = np.maximum(Xu.std(0), self.global_std * 0.25)
        self.trained = True
        return self

    def explain(self, user: str, v: np.ndarray) -> list[str]:
        mu = self.user_mean.get(user, self.global_mean)
        sd = self.user_std.get(user, self.global_std)
        z = (v - mu) / sd
        names = {"logins_ok": "successful logins", "logins_fail": "failed logins", "distinct_ips": "distinct source IPs",
                 "new_ips": "never-seen source IPs", "sudo_cmds": "sudo commands", "priv_actions": "privileged actions",
                 "off_hours": "activity outside working hours", "distinct_hosts": "distinct hosts"}
        out = []
        for i in np.argsort(-np.abs(z)):
            f = FEATURES[i]
            if f in names and z[i] > 2.0:
                out.append(f"{names[f]}: {v[i]:g} (usual ≈ {mu[i]:.1f})")
            if len(out) == 3:
                break
        if user not in self.user_mean:
            out.insert(0, "user has no baseline history")
        return out

    def score(self, events: list[Event]) -> list[Alert]:
        if not self.trained:
            return []
        alerts = []
        for (u, h), uh in sorted(aggregate(events, self.tz).items(), key=lambda kv: kv[0][1]):
            # An account that only *received* failed logins is a victim of guessing,
            # already covered by brute-force/spray rules. UEBA judges what the
            # account holder (or whoever holds its credentials) actually did.
            if not uh.acted:
                continue
            v = np.array(self._vector(uh, learn=False), dtype=float)
            s = float(-self.iso.score_samples(v.reshape(1, -1))[0])
            if s < self.min_score:
                continue
            reasons = self.explain(u, v)
            if not reasons:
                continue
            sev = "high" if s >= self.min_score + 0.08 else "medium"
            first = min(uh.events, key=lambda e: e.ts)
            # attribute the alert to where the account actually acted, not where it was merely targeted
            ents = {"user": u}
            if uh.acted_ips:
                ents["src_ip"] = max(uh.acted_ips, key=uh.acted_ips.get)
            if uh.acted_hosts:
                ents["host"] = max(uh.acted_hosts, key=uh.acted_hosts.get)
            alerts.append(Alert("LH-U01", "Anomalous user behaviour (UEBA)", sev, first.ts, "Defense Evasion",
                                "T1078", "Valid Accounts (behavioural anomaly)", ents, len(uh.events),
                                f"Anomaly score {s:.2f}. " + "; ".join(reasons),
                                [e.to_dict() for e in uh.events[:5]]))
        return alerts
