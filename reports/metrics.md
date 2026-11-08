# LogHawk evaluation (5 independent synthetic datasets)

Rules loaded: 29 + UEBA model

## Attack-stage detection

| Stage | Detected | Median time to first alert |
|---|---|---|
| Web reconnaissance & exploitation attempts | 5/5 | 0 s |
| Network port scan | 5/5 | 16 s |
| SSH brute force and account compromise | 5/5 | 15 s |
| Privilege escalation & persistence on Linux | 5/5 | 44 s |
| Windows password spray → credential dumping → persistence → log wiping | 5/5 | 35 s |

## Summary

- Expected rule firings: **100.0%** (135/135)
- False positives on 7 benign days (rules + UEBA): **4** total across 5 datasets (4 on UEBA hold-out days)
- Alerts → incidents: 28 alerts collapse into 2.0 incidents per attack (**93% fewer items** for the analyst)
- Throughput: ~25,593 events/s (single Python process)

## Incidents (seed 1)

| Risk | Severity | Alerts | Source IPs | Users | ATT&CK tactics |
|---|---|---|---|---|---|
| 1067.0 | critical | 17 | 45.33.12.7 | backdoor, bob | Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery |
| 676.0 | critical | 11 | 10.10.9.99 | helpdesk2, svc_backup | Initial Access → Execution → Persistence → Defense Evasion → Credential Access |

False-positive rules: LH-U01 ×4
