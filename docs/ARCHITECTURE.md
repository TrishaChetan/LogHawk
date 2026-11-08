# LogHawk — Architecture

## Data flow

1. **Parsing** (`parsers.py`) — each line is auto-detected (JSON → Windows, combined-log regex → web, syslog regex → Linux/firewall) and mapped onto one `Event` schema loosely following Elastic Common Schema. Malformed lines are skipped, never fatal. URLs are double-URL-decoded into `extra.url_decoded` so encoded payloads (`%2527`) are visible to rules.
2. **Rule engine** (`rules.py`) — YAML rules compile to Python closures once at load time. Events stream through in time order:
   * *single*: match → alert
   * *threshold*: per-group deque trimmed to the window; count events or distinct values
   * *sequence*: per-group state machine with step counters; resets when the window expires
   * every rule/group pair has a cooldown (≥ the rule window) to prevent alert storms
3. **UEBA** (`ueba.py`) — see below.
4. **Correlation** (`correlate.py`) — union-find over entity keys (`ip:`, `user:`, `host:`). An entity links alerts only while it stays active (6 h for IPs/users, 30 min for hosts). Generic accounts (root, Administrator) never link.
5. **Risk** — Σ severity weight (low 3, medium 10, high 25, critical 50) × (1 + 0.25 × (tactics − 1)).

## UEBA model

| Feature | Why |
|---|---|
| successful / failed logins per hour | credential misuse, guessing |
| distinct IPs, never-seen IPs | access from new locations |
| sudo commands, privileged actions | privilege abuse |
| hour of day (sin/cos), off-hours flag | unusual working time |
| distinct hosts | lateral movement |

* Isolation Forest (200 trees) on all user-hours of the baseline period.
* Only hours where the account *acted successfully* are scored — victims of password guessing are already covered by rules.
* Explanations: z-score of each feature against **that user's** own mean/std (std floored at 25% of the population std so that perfectly regular users don't produce infinite z-scores).
* Severity: `high` if score ≥ 0.70, otherwise `medium`.

## Why both rules and ML?

| | Rules | UEBA |
|---|---|---|
| Known attack patterns (SQLi, LSASS dump) | ✅ precise, explainable | ❌ |
| Legitimate credentials used abnormally | ❌ every event looks valid | ✅ |
| Tuning effort | thresholds per rule | needs baseline history |
| False positives | very low | a few per month (weekend edge cases) |

In the evaluation, UEBA independently flagged both compromised accounts (bob: off-hours, new IP, 6 sudo commands; svc_backup: privileged actions it never performed before), giving a second, rule-independent signal.

## Security of the console

* Upload limit 100 MB per file; parsing errors are contained per line.
* All log-derived text is HTML-escaped in the UI (log lines are attacker-controlled — a `<script>` in a URL must not execute in the analyst's browser).
* YAML loaded with `safe_load` only.
