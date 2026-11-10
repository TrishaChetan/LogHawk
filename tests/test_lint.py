from pathlib import Path

from loghawk.cli import main
from loghawk.lint import lint_directory, lint_rule

GOOD = {
    "id": "T-1", "title": "t", "description": "d", "type": "single", "severity": "high",
    "mitre": {"tactic": "Execution", "technique": "T1059.001"},
    "match": {"source": "windows", "command|re": "(?i)-enc"},
}


def test_bundled_rules_have_no_errors():
    n, problems = lint_directory()
    assert n >= 29
    assert [p for p in problems if p.level == "error"] == []


def test_good_rule_is_clean():
    assert lint_rule(GOOD, "x.yml") == []


def test_field_typo_is_flagged_with_hint():
    bad = {**GOOD, "match": {"Src_IP": "1.2.3.4"}}
    msgs = [p.message for p in lint_rule(bad, "x.yml")]
    assert any("did you mean 'src_ip'" in m for m in msgs)


def test_errors_detected():
    bad = {**GOOD, "severity": "urgent", "match": {"command|regex": "x", "url|re": "("}}
    errors = [p.message for p in lint_rule(bad, "x.yml") if p.level == "error"]
    assert any("bad severity" in m for m in errors)
    assert any("unknown modifier" in m for m in errors)
    assert any("invalid regex" in m for m in errors)


def test_sequence_needs_two_steps():
    seq = {**GOOD, "type": "sequence", "group_by": "src_ip", "steps": [{"match": {"source": "windows"}}]}
    seq.pop("match")
    assert any("at least 2 steps" in p.message for p in lint_rule(seq, "x.yml"))


def test_duplicate_ids_and_exit_code(tmp_path: Path, capsys):
    (tmp_path / "a.yml").write_text("id: D-1\ntitle: a\nmatch: {source: windows}\n")
    (tmp_path / "b.yml").write_text("id: D-1\ntitle: b\nmatch: {source: windows}\n")
    _, problems = lint_directory(tmp_path)
    assert any("duplicate id" in p.message for p in problems)
    try:
        main(["lint-rules", str(tmp_path)])
    except SystemExit as e:
        assert e.code == 1
    else:
        raise AssertionError("expected non-zero exit")
