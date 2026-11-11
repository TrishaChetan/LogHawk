from pathlib import Path

import pytest

from loghawk import ruletest
from loghawk.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "scenario"
AUTH = str(SAMPLES / "auth.log")


def test_sequence_rule_fires_on_scenario():
    rep = ruletest.test_rule_on_files("LH-L03", [AUTH])
    assert rep.alerts
    assert rep.verdict.startswith("FIRES")
    assert len(rep.step_hits) == 2 and all(rep.step_hits)


def test_rule_id_is_case_insensitive_and_no_match_is_explained():
    rep = ruletest.test_rule_on_files("lh-w01", [AUTH])
    assert rep.step_hits == [0]
    assert rep.verdict.startswith("NO MATCH")


def test_threshold_too_strict_is_explained(tmp_path):
    rule = tmp_path / "strict.yml"
    rule.write_text(
        "id: X-1\ntitle: strict\ntype: threshold\nseverity: high\n"
        "match: {source: linux_auth, action: ssh_login, outcome: failure}\n"
        "group_by: src_ip\nthreshold: 5000\nwindow: 60\n"
    )
    rep = ruletest.test_rule_on_files(str(rule), [AUTH])
    assert rep.step_hits[0] > 0 and not rep.alerts
    assert "DOESN'T FIRE" in rep.verdict
    assert "needs 5000 events within 60s per src_ip" in ruletest.format_report(rep)


def test_cli_exit_codes(capsys):
    with pytest.raises(SystemExit) as e:
        main(["test-rule", "LH-L03", AUTH])
    assert e.value.code == 0
    with pytest.raises(SystemExit) as e:
        main(["test-rule", "LH-W01", AUTH])
    assert e.value.code == 2
    assert "Result:" in capsys.readouterr().out
