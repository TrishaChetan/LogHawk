from loghawk.correlate import correlate
from loghawk.parsers import parse_line
from loghawk.rules import Rule, RuleEngine, load_rules


def run(lines, rules=None):
    eng = RuleEngine(rules)
    out = []
    for l in lines:
        e = parse_line(l)
        if e:
            out += eng.process(e)
    return out


def ssh(i, user, ok=False, ip="45.33.12.7"):
    word = "Accepted password" if ok else "Failed password"
    return f"2026-11-03T02:{10 + i // 60:02d}:{i % 60:02d}+05:30 web01 sshd[1]: {word} for {user} from {ip} port 4000 ssh2"


def test_all_rules_load_and_are_valid():
    rules = load_rules()
    assert len(rules) >= 25
    assert all(r.mitre.get("technique") for r in rules)


def test_threshold_and_sequence():
    lines = [ssh(i, f"user{i % 7}") for i in range(12)] + [ssh(20, "bob", ok=True)]
    ids = {a.rule_id for a in run(lines)}
    assert {"LH-L01", "LH-L02", "LH-L03"} <= ids


def test_threshold_entities_exclude_varying_user():
    a = [x for x in run([ssh(i, f"user{i}") for i in range(12)]) if x.rule_id == "LH-L01"][0]
    assert a.entities.get("src_ip") == "45.33.12.7" and "user" not in a.entities


def test_below_threshold_is_quiet():
    assert run([ssh(i, "alice", ip="10.10.1.21") for i in range(3)]) == []


def test_cooldown_prevents_alert_storm():
    alerts = [a for a in run([ssh(i, "root") for i in range(50)]) if a.rule_id == "LH-L01"]
    assert len(alerts) == 1


def test_custom_rule_modifiers():
    r = Rule.from_dict({"id": "T1", "title": "t", "severity": "low", "type": "single",
                        "match": {"source": "web_access", "status|gte": 500, "user_agent|contains": "sqlmap"}})
    line = '1.2.3.4 - - [03/Nov/2026:02:10:00 +0530] "GET / HTTP/1.1" 503 1 "-" "sqlmap/1.8"'
    assert run([line], [r])[0].rule_id == "T1"


def test_web_rules():
    base = '45.33.12.7 - - [03/Nov/2026:02:10:{s:02d} +0530] "GET {u} HTTP/1.1" {st} 1 "-" "Mozilla/5.0"'
    lines = [base.format(s=1, u="/p?id=1%20UNION%20SELECT%20a,b%20FROM%20users", st=500),
             base.format(s=2, u="/f?file=../../../../etc/passwd", st=400),
             base.format(s=3, u="/s?q=%3Cscript%3Ealert(1)%3C/script%3E", st=200),
             base.format(s=4, u="/.env", st=200)]
    assert {"LH-W01", "LH-W03", "LH-W02", "LH-W07"} <= {a.rule_id for a in run(lines)}


def test_correlation_links_chain_via_entities():
    lines = [ssh(i, "root") for i in range(12)] + [ssh(20, "bob", ok=True)] + [
        "2026-11-03T02:12:00+05:30 web01 sudo[9]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        # unrelated activity on another host, hours later
        "2026-11-03T09:00:00+05:30 db01 sshd[1]: Accepted password for root from 10.9.9.9 port 1 ssh2"]
    inc = correlate(run(lines))
    big = max(inc, key=lambda i: len(i.alerts))
    assert {"LH-L01", "LH-L03", "LH-L05"} <= {a["rule_id"] for a in big.alerts}
    assert len(inc) == 2  # the root login on db01 is a separate incident
    assert big.risk > inc[-1].risk
