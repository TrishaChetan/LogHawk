# 🦅 LogHawk — SIEM-lite with Detection Rules, UEBA and Incident Correlation

LogHawk ingests logs from Linux servers, web servers, firewalls and Windows, normalises them into one schema,
runs **29 Sigma-style detection rules** plus a **machine-learning behaviour model (UEBA)**, and correlates the
resulting alerts into **incidents** ranked by risk and mapped to the **MITRE ATT&CK** kill chain.

![tests](https://github.com/TrishaChetan/LogHawk/actions/workflows/tests.yml/badge.svg)

> Final-year cybersecurity project · Python · scikit-learn · FastAPI · YAML rules

## What it does

```
 auth.log ─┐                                  ┌─ 29 YAML rules (single / threshold / sequence) ─┐
 access.log┼─► parsers ─► normalised events ──┤                                                  ├─► correlation ─► incidents
 ufw.log   │   (ECS-like)                      └─ UEBA: Isolation Forest per user-hour ───────────┘   (union-find)    risk + kill chain
 win.jsonl ┘
```

| Capability | Details |
|---|---|
| **Log sources** | Linux auth (`auth.log`/`secure`, classic and ISO syslog), Nginx/Apache combined, UFW/iptables, Windows Security & System events as JSON |
| **Rule engine** | Sigma-inspired YAML with `field\|contains`, `\|re`, `\|startswith`, `\|gte`, `\|not` modifiers; *single*, *threshold* (count or distinct count per group in a window) and *sequence* (ordered multi-step) rules; per-rule cooldowns |
| **UEBA (ML)** | Isolation Forest on per-user hourly behaviour (logins, failures, new IPs, sudo, privileged actions, time of day); explains *why* using z-scores against that user's own baseline |
| **Correlation** | Union-find over IPs, users and hosts with time windows → turns ~28 alerts into 2 incidents |
| **Risk scoring** | Σ severity weights × (1 + 0.25 per extra ATT&CK tactic) — multi-stage attacks rank first |
| **Search** | Mini query language: `src_ip:45.33.12.7 action:ssh_login NOT outcome:success`, `status>=400`, wildcards |
| **Interfaces** | SOC web console, REST API, CLI |

## Rule coverage (29 rules)

| Area | Rules | ATT&CK examples |
|---|---|---|
| Linux | SSH brute force, username enumeration, **brute force → success** (sequence), root login, `/etc/shadow` via sudo, new user, privileged group add, **new user → sudo group** (sequence), download-and-execute / cron persistence, sudo failures | T1110.001, T1078, T1003.008, T1136.001, T1098, T1059.004 |
| Web | SQL injection, XSS, path traversal/LFI, attack-tool user agents, content discovery (404 bursts), web shell / command injection, exposed `.env`/`.git`/backups | T1190, T1505.003, T1595, T1552.001 |
| Windows | logon brute force, **password spraying** (distinct users), **spray → success** (sequence), encoded PowerShell, privileged group add, audit log cleared, suspicious service, LOLBins (certutil, mshta, regsvr32), LSASS dumping, new account | T1110.003, T1059.001, T1218, T1003.001, T1070.001, T1543.003 |
| Firewall | port scan (distinct ports), remote-admin port probing | T1046, T1021 |
| UEBA | anomalous user behaviour | T1078 |

Write your own: drop a `.yml` file in `rules/` — see [docs/RULES.md](docs/RULES.md). Try it on real logs with `python -m loghawk.cli test-rule <id-or-file> <logfile>`, which shows what matched and why it did or didn't fire. Check it with `python -m loghawk.cli lint-rules`, which catches typos in field names that would otherwise make a rule silently never match.

## Quick start

```bash
git clone https://github.com/TrishaChetan/LogHawk.git && cd LogHawk
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

uvicorn loghawk.api:app --reload      # open http://127.0.0.1:8000 → "Load demo scenario"
```

The demo generates 8 days of logs for a small company (≈14,700 events) — a week of normal work followed by a night-time intrusion —
trains UEBA on the normal week and runs every detection.

### CLI

```bash
python -m loghawk.cli generate samples/scenario                         # regenerate the sample dataset
python -m loghawk.cli train-ueba baseline/auth.log baseline/win.jsonl --tz 5.5
python -m loghawk.cli analyze samples/scenario/*.log samples/scenario/windows_security.jsonl
python -m loghawk.cli search samples/scenario/auth.log 'action:sudo command:*shadow*'
python -m loghawk.cli rules
python -m loghawk.cli coverage --navigator layer.json
python -m loghawk.cli watch /var/log/auth.log /var/log/nginx/access.log --min-severity high --jsonl alerts.jsonl
```

**ATT&CK coverage** — `coverage` shows which MITRE ATT&CK tactics and techniques the rules detect, how many rules
cover each, and the gaps (currently Collection, Command and Control, Exfiltration and Impact). `--navigator` writes an
ATT&CK Navigator layer you can upload at https://mitre-attack.github.io/attack-navigator/ to see a heat map; the same
data is at `GET /api/coverage` and `GET /api/coverage/navigator`.

**Live mode** — `watch` follows log files like `tail -F` (survives logrotate and copytruncate, waits for files
that don't exist yet) and pushes every new line through the streaming rule engine, printing alerts the moment
they fire. `--from-start` replays existing content first; `--jsonl` appends alerts for a SIEM or script.

Docker: `docker build -t loghawk . && docker run -p 8000:8000 loghawk`

### Sample output

```
■ INCIDENT #1 [CRITICAL risk 907.5] Web shell or command injection (+15 related alerts, 7 tactics)
  entities: ips=['45.33.12.7'] users=['backdoor', 'bob'] hosts=['gw01', 'web', 'web01']
  kill chain: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Credential Access → Discovery
    medium   LH-W04   Known attack tool user agent           [T1595.002]
    high     LH-W01   SQL injection attempt                  [T1190]
    medium   LH-F01   Port scan blocked by firewall          [T1046]
    medium   LH-L01   SSH brute force                        [T1110.001]
    critical LH-L03   SSH brute force followed by successful login  [T1078]
    high     LH-L05   Sensitive file accessed with sudo      [T1003.008]
    critical LH-L10   New account then added to privileged group    [T1136.001]
    high     LH-L08   Download-and-execute or persistence command   [T1059.004]
    ...
■ INCIDENT #2 [CRITICAL risk 626.0] Spray success — failures then logon from same source (+9 related alerts, 5 tactics)
  entities: ips=['10.10.9.99'] users=['helpdesk2', 'svc_backup'] hosts=['DC01']
```

## Evaluation

`python -m loghawk.evaluate --seeds 5` generates 5 independent datasets. UEBA trains on days 1–5; days 6–7 are a held-out benign
period for false-positive measurement; night 8 contains the attack.

| Stage | Detected | Median time to first alert |
|---|---|---|
| Web reconnaissance & exploitation attempts | 5/5 | 0 s |
| Network port scan | 5/5 | 16 s |
| SSH brute force and account compromise | 5/5 | 15 s |
| Privilege escalation & persistence on Linux | 5/5 | 44 s |
| Windows spray → credential dumping → persistence → log wiping | 5/5 | 35 s |

- **100%** of expected rule firings (135/135)
- **4 false positives** over 35 benign days (all medium-severity UEBA alerts on weekends — e.g. a developer logging in twice on a Saturday)
- **93% fewer items** to triage: ~28 alerts per attack collapse into 2 incidents
- ~25,000 events/s in a single Python process

Full results: `reports/metrics.md`, `reports/evaluation.json`.

### Design decisions found through testing

- **Threshold-alert entities** — a brute-force alert first carried the *last guessed username*, which wrongly linked unrelated attacks. Alerts now only carry entities shared by all their evidence events.
- **UEBA scope** — UEBA first flagged every *victim* of the password spray. It now only scores hours where the account itself did something successful, and attributes alerts to where the account acted.
- **Local time** — "working hours" must be the organisation's time zone, otherwise a nightly 01:00 IST backup job looks like 19:30 UTC daytime activity.

## Tests

```bash
pytest -q    # 20 tests: every parser, rule types and modifiers, cooldowns, correlation, search language,
             # two full attack scenarios end-to-end, REST API
```

## Project structure

```
loghawk/
  parsers.py     4 log formats → normalised Event
  rules.py       YAML rule compiler + streaming engine (single / threshold / sequence)
  ueba.py        per-user behavioural ML (Isolation Forest + explanations)
  correlate.py   alerts → incidents, risk score, kill chain
  pipeline.py    end-to-end analysis
  search.py      query language
  generator.py   realistic multi-source logs with ground truth
  evaluate.py    multi-seed evaluation for the report
  api.py         FastAPI          templates/index.html   SOC console
  cli.py         command line
rules/           linux.yml  web.yml  windows.yml  firewall.yml
samples/scenario 8 days of sample logs + ground_truth.json
docs/            architecture, rule-writing guide, report outline
```

## Limitations & future work

- In-memory storage — fine for files up to a few million events; a production build would index into OpenSearch/ClickHouse.
- No GeoIP enrichment (impossible-travel detection) or threat-intel feeds yet.
- UEBA needs at least a few days of history per user; brand-new accounts are judged against the population baseline.
- Sigma compatibility is partial (no `condition:` boolean expressions across selections).

## License

MIT
