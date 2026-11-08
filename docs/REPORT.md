# Project Report Outline — LogHawk

## Abstract
Security teams receive far more alerts than they can investigate, while attackers using valid credentials evade signature
rules altogether. LogHawk is a lightweight SIEM that combines 29 Sigma-style detection rules with a per-user behavioural
anomaly model (UEBA) and correlates alerts into risk-ranked incidents mapped to MITRE ATT&CK. Across five independent
synthetic datasets it detected every stage of a multi-stage intrusion, fired 100% of expected rules, produced 4 false
positives in 35 benign days, and reduced analyst workload by 93% (≈28 alerts → 2 incidents per attack).

## 1. Introduction
- Role of SIEM in a SOC; alert fatigue statistics
- Objectives: multi-source ingestion, extensible rules, ML for credential misuse, incident-level output
## 2. Literature survey
- Commercial/open SIEMs: Splunk, Elastic Security, Wazuh, Microsoft Sentinel
- Sigma rule format; MITRE ATT&CK as a common language
- UEBA research: Isolation Forest, autoencoders, peer-group analysis
- Alert correlation approaches: rule-based chaining, graph-based, attack-graph methods
## 3. System design
- Architecture and event schema
- Rule language design (single / threshold / sequence)
- UEBA feature engineering
- Correlation algorithm (union-find with time-bounded entity links) and risk formula
## 4. Implementation
- Python, scikit-learn, FastAPI, YAML; parsers for 4 log formats
- Test-driven fixes (entity extraction, UEBA scope, time zones) — see README "Design decisions"
## 5. Results
- Detection table per stage, time-to-detect
- False positives and their analysis
- Alert → incident reduction
- Throughput
- Screenshots: overview, incident timeline, search
## 6. Conclusion & future work
- GeoIP/impossible travel, threat-intel enrichment, full Sigma conversion, persistent storage, SOAR playbooks (auto-block IP)
## References
