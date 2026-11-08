import pytest
from fastapi.testclient import TestClient

from loghawk import api
from loghawk.evaluate import run_seed
from loghawk.search import search
from loghawk.parsers import parse_line


@pytest.mark.parametrize("seed", [11, 12])
def test_full_scenario_detected_without_false_positives(seed):
    r = run_seed(seed)
    assert all(s["detected"] for s in r["stages"]), r["stages"]
    assert r["expected_rules_fired"] == r["expected_rules"]
    assert r["false_positives_7_days"] <= 2
    assert len(r["attack_incidents"]) == 2
    assert r["attack_incidents"][0]["severity"] == "critical"


def test_search_language():
    ev = [parse_line(l) for l in [
        "2026-11-03T02:10:00+05:30 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        "2026-11-03T02:11:00+05:30 web01 sshd[1]: Accepted password for bob from 1.2.3.4 port 1 ssh2",
        '1.2.3.4 - - [03/Nov/2026:02:10:00 +0530] "GET /x HTTP/1.1" 404 1 "-" "curl"']]
    assert search(ev, "src_ip:1.2.3.4")[0] == 3
    assert search(ev, "action:ssh_login NOT outcome:failure")[1][0].user == "bob"
    assert search(ev, "status>=400")[0] == 1
    assert search(ev, "user:b*")[0] == 1


def test_api_demo_flow():
    c = TestClient(api.app)
    assert "LogHawk" in c.get("/").text
    s = c.post("/api/demo").json()
    assert s["events"] > 10000 and s["incidents"] >= 2
    inc = c.get("/api/incidents").json()
    detail = c.get(f"/api/incidents/{inc[0]['id']}").json()
    assert detail["alerts"] and detail["tactics"]
    assert c.get("/api/search", params={"q": "action:sudo command:*shadow*"}).json()["total"] >= 1
    assert len(c.get("/api/rules").json()) >= 25
    up = c.post("/api/ingest", files=[("files", ("auth.log", b"Nov  3 02:11:09 web01 sshd[1]: Failed password for root from 9.9.9.9 port 1 ssh2\n"))]).json()
    assert up["events"] == 1
