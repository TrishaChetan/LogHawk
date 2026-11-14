import json

from fastapi.testclient import TestClient

from loghawk import api
from loghawk.cli import main
from loghawk.coverage import TACTICS, compute, format_coverage, navigator_layer
from loghawk.rules import Rule


def test_bundled_rules_coverage():
    c = compute()
    assert c["rules"] >= 29
    assert c["tactics_total"] == len(TACTICS) == 14
    assert "Resource Development" not in c["gaps"]          # attacker-side, never a gap
    covered = {r["tactic"] for r in c["tactics"] if r["rules"]}
    assert {"Credential Access", "Persistence"} <= covered
    assert not covered & set(c["gaps"])


def test_gaps_and_unmapped():
    rules = [
        Rule.from_dict({"id": "A", "title": "a", "match": {"source": "windows"},
                        "mitre": {"tactic": "Execution", "technique": "T1059.001", "name": "PowerShell"}}),
        Rule.from_dict({"id": "B", "title": "b", "match": {"source": "windows"},
                        "mitre": {"tactic": "Execution", "technique": "T1059.001"}}),
        Rule.from_dict({"id": "C", "title": "c", "match": {"source": "windows"}}),
    ]
    c = compute(rules)
    assert c["tactics_covered"] == 1 and c["techniques_covered"] == 1
    assert c["unmapped_rules"] == ["C"]
    assert "Impact" in c["gaps"] and "Execution" not in c["gaps"]
    assert "GAP" in format_coverage(c)
    layer = navigator_layer(c)
    t = layer["techniques"][0]
    assert (t["techniqueID"], t["tactic"], t["score"]) == ("T1059.001", "execution", 2)
    assert layer["domain"] == "enterprise-attack" and layer["gradient"]["maxValue"] == 2


def test_cli_writes_navigator(tmp_path, capsys):
    out = tmp_path / "layer.json"
    main(["coverage", "--navigator", str(out)])
    layer = json.loads(out.read_text())
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) >= 20
    assert "ATT&CK tactics" in capsys.readouterr().out


def test_api_endpoints():
    c = TestClient(api.app)
    assert c.get("/api/coverage").json()["tactics_total"] == 14
    assert c.get("/api/coverage/navigator").json()["domain"] == "enterprise-attack"
