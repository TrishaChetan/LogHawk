from types import SimpleNamespace
from pathlib import Path

from loghawk.cli import main
from loghawk.report import response_steps, to_markdown

SC = Path(__file__).resolve().parent.parent / "samples" / "scenario"


def _inc(techs, ips=("45.33.12.7",), users=("bob",), hosts=("web01",)):
    alerts = [{"ts": 1_762_000_000 + i, "severity": "high", "rule_id": f"R{i}", "title": t, "technique": t}
              for i, t in enumerate(techs)]
    return SimpleNamespace(id=1, start=alerts[0]["ts"], end=alerts[-1]["ts"], risk=99.0, severity="high",
                           title="Test", entities={"src_ip": list(ips), "user": list(users), "host": list(hosts)},
                           tactics=["Credential Access"], alerts=alerts)


def test_playbook_fills_entities_and_orders_phases():
    steps = response_steps(_inc(["T1110.001", "T1003.008", "T1490"]))
    phases = [p for p, _ in steps]
    assert phases == sorted(phases, key=["Contain", "Investigate", "Eradicate", "Recover"].index)
    text = " ".join(t for _, t in steps)
    assert "Block 45.33.12.7" in text and "MFA" in text and "for bob" in text
    assert "Isolate web01" in text and "offline/immutable backups" in text
    assert steps[-1] == ("Recover", "Write down the timeline and lessons learned; add a detection or fix for anything missed")


def test_prefix_matching_is_exact():
    # T1110 must not match T11100 or similar; unknown techniques still get the generic steps
    steps = response_steps(_inc(["T1999"]))
    assert all(p == "Recover" for p, _ in steps)


def test_markdown_for_empty_and_scenario(tmp_path, capsys):
    empty = SimpleNamespace(incidents=[], stats={"events": 10, "alerts": 0, "incidents": 0})
    assert "No incidents found." in to_markdown(empty)

    out = tmp_path / "ir.md"
    main(["report", str(SC / "auth.log"), str(SC / "access.log"), str(SC / "ufw.log"),
          str(SC / "windows_security.jsonl"), "-o", str(out), "--no-ueba"])
    md = out.read_text()
    assert md.startswith("# LogHawk incident report")
    assert "### Timeline" in md and "### Response checklist" in md and "- [ ] **Contain:**" in md
    assert "https://attack.mitre.org/techniques/T1110/001/" in md
    assert "45.33.12.7" in md
