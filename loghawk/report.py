"""Incident report: what happened, in what order, and what to do about it.

    python -m loghawk.cli report samples/scenario/*.log samples/scenario/*.jsonl -o incident-report.md

The report is plain Markdown (renders on GitHub, pastes into a ticket or a
doc). For every incident it gives the kill chain, the entities involved, a
timeline of alerts and a response checklist built from the ATT&CK techniques
that were seen: contain first, then eradicate, then recover.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime

# technique prefix -> (phase, action). Prefix match, so "T1110" covers T1110.001/.003.
# {ip} {user} {host} are filled in from the incident's entities.
PLAYBOOK: dict[str, list[tuple[str, str]]] = {
    "T1110": [("Contain", "Block {ip} at the firewall / fail2ban"),
              ("Eradicate", "Enforce MFA or key-only login for {user}; disable password SSH/RDP where possible")],
    "T1078": [("Contain", "Disable or force a password reset for {user} and end their active sessions"),
              ("Investigate", "Review everything {user} did after the suspicious login")],
    "T1021": [("Contain", "Restrict SSH/RDP/WinRM on {host} to an admin VPN or jump host")],
    "T1046": [("Contain", "Block {ip}; scanning usually comes right before an attack")],
    "T1595": [("Contain", "Rate-limit or block {ip} at the WAF / reverse proxy")],
    "T1589": [("Eradicate", "Return the same error for wrong usernames and wrong passwords (stop user enumeration)")],
    "T1190": [("Contain", "Block {ip} at the WAF and take the vulnerable endpoint offline if it can't be patched now"),
              ("Eradicate", "Patch or fix the injected parameter; check the database for changed or extracted data")],
    "T1505.003": [("Contain", "Isolate {host}; delete the web shell only after copying it for evidence"),
                  ("Eradicate", "Find how it was uploaded, and rotate any credentials stored on the web server")],
    "T1552": [("Eradicate", "Remove exposed .env/.git/backups from the web root and rotate every secret they contained")],
    "T1059": [("Investigate", "Pull the full command line and parent process for the commands run on {host}")],
    "T1218": [("Investigate", "Check what the signed binary on {host} downloaded or ran; block it with AppLocker/WDAC")],
    "T1003": [("Contain", "Isolate {host} — credentials were dumped"),
              ("Eradicate", "Reset passwords for every account that logged in to {host}; rotate service account secrets")],
    "T1136": [("Eradicate", "Delete the account created by the attacker and check for its SSH keys / group memberships")],
    "T1098": [("Eradicate", "Remove unexpected SSH keys or group memberships added for {user}")],
    "T1543": [("Eradicate", "Remove the malicious service on {host} and check other autostart locations")],
    "T1548": [("Eradicate", "Review sudoers / admin rights of {user}; remove anything not needed")],
    "T1070": [("Investigate", "Logs were cleared on {host} — pull copies from your SIEM or log forwarder")],
    "T1083": [("Investigate", "List which directories and files {user} browsed")],
    "T1560": [("Investigate", "Find the archive created on {host} and whether it left the network")],
    "T1105": [("Contain", "Block the download source at the proxy/firewall"),
              ("Eradicate", "Find and remove the downloaded tool on {host}; check its hash on VirusTotal")],
    "T1571": [("Contain", "Block outbound traffic from {ip} to the C2 port and isolate the host if it's internal")],
    "T1048": [("Contain", "Block the destination and isolate {host}"),
              ("Investigate", "Work out what data left and whether it must be reported (DPDP Act / GDPR breach rules)")],
    "T1485": [("Contain", "Isolate {host} immediately to stop further destruction"),
              ("Recover", "Restore the deleted data from offline backups")],
    "T1490": [("Contain", "Isolate {host} now — deleting shadow copies is a ransomware precursor"),
              ("Recover", "Check offline/immutable backups are intact before anything else")],
    "T1531": [("Recover", "Restore the deleted accounts and check who issued the deletions")],
}
ALWAYS = [("Recover", "Keep the original logs as evidence (copy, hash, store read-only)"),
          ("Recover", "Write down the timeline and lessons learned; add a detection or fix for anything missed")]
PHASES = ["Contain", "Investigate", "Eradicate", "Recover"]


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _duration(a: float, b: float) -> str:
    s = int(b - a)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60} min"
    return f"{s // 3600} h {s % 3600 // 60} min"


def response_steps(incident) -> list[tuple[str, str]]:
    """Deduplicated (phase, action) list for an incident, ordered by phase."""
    ents = incident.entities
    fill = {"ip": ", ".join(ents.get("src_ip") or []) or "the source IP",
            "user": ", ".join(ents.get("user") or []) or "the affected account",
            "host": ", ".join(ents.get("host") or []) or "the affected host"}
    steps: list[tuple[str, str]] = []
    for al in incident.alerts:
        tech = al.get("technique") or ""
        for prefix, actions in PLAYBOOK.items():
            if tech == prefix or tech.startswith(prefix + "."):
                for phase, text in actions:
                    step = (phase, text.format(**fill))
                    if step not in steps:
                        steps.append(step)
    steps += [s for s in ALWAYS if s not in steps]
    return sorted(steps, key=lambda s: PHASES.index(s[0]))


def to_markdown(result, sources: list[str] | None = None) -> str:
    incs = result.incidents
    stats = result.stats
    sev = Counter(i.severity for i in incs)
    out = ["# LogHawk incident report", "",
           f"_Generated {datetime.now():%Y-%m-%d %H:%M}"
           + (f" from {len(sources)} log file(s): {', '.join(f'`{s}`' for s in sources)}" if sources else "") + "_", "",
           "## Summary", "",
           f"- **{stats['events']:,}** events analysed → **{stats['alerts']}** alerts → **{stats['incidents']}** incidents",
           "- Incidents by severity: " + (", ".join(f"{n} {s}" for s, n in sorted(
               sev.items(), key=lambda kv: ["critical", "high", "medium", "low"].index(kv[0]))) or "none")]
    if incs:
        top = incs[0]
        out.append(f"- Highest risk: **#{top.id} {top.title}** (risk {top.risk}, {len(top.tactics)} ATT&CK tactic(s))")
    else:
        out += ["", "No incidents found."]
        return "\n".join(out) + "\n"

    out += ["", "| # | Severity | Risk | Incident | Started | Duration | Kill chain |", "|---|---|---|---|---|---|---|"]
    for i in incs:
        out.append(f"| {i.id} | {i.severity} | {i.risk} | {i.title} | {_fmt_ts(i.start)} | "
                   f"{_duration(i.start, i.end)} | {' → '.join(i.tactics)} |")

    for i in incs:
        e = i.entities
        out += ["", f"## Incident #{i.id} — {i.title}", "",
                f"**Severity:** {i.severity} · **Risk:** {i.risk} · **When:** {_fmt_ts(i.start)} → "
                f"{_fmt_ts(i.end)} ({_duration(i.start, i.end)})", "",
                f"**Kill chain:** {' → '.join(i.tactics) or '—'}", "",
                "**Involved:** " + " · ".join(f"{label}: {', '.join(f'`{v}`' for v in vals)}"
                                              for label, vals in (("IPs", e["src_ip"]), ("users", e["user"]),
                                                                  ("hosts", e["host"])) if vals), "",
                "### Timeline", "", "| Time | Severity | Rule | What happened | ATT&CK |", "|---|---|---|---|---|"]
        for al in i.alerts:
            tech = al.get("technique") or ""
            link = f"[{tech}](https://attack.mitre.org/techniques/{tech.replace('.', '/')}/)" if tech else ""
            out.append(f"| {_fmt_ts(al['ts'])} | {al['severity']} | {al['rule_id']} | {al['title']} | {link} |")
        out += ["", "### Response checklist", ""]
        for phase, text in response_steps(i):
            out.append(f"- [ ] **{phase}:** {text}")
    return "\n".join(out) + "\n"
