"""Log parsers -> one normalised event schema (loosely based on Elastic ECS).

Supported sources (auto-detected per line):
  * linux_auth   — /var/log/auth.log, /var/log/secure (sshd, sudo, useradd, usermod, su)
  * web_access   — Apache / Nginx combined log format
  * windows      — Windows Security events exported as JSON lines (Winlogbeat / Get-WinEvent | ConvertTo-Json)
  * firewall     — iptables / UFW kernel log lines
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

DEFAULT_YEAR = datetime.now().year


@dataclass
class Event:
    ts: float
    source: str                  # linux_auth | web_access | windows | firewall
    host: str = ""
    action: str = ""             # normalised action, e.g. ssh_login, sudo, user_created, http_request
    outcome: str = ""            # success | failure | ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    process: str = ""
    command: str = ""
    url: str = ""
    method: str = ""
    status: int = 0
    user_agent: str = ""
    bytes: int = 0
    event_id: int = 0
    group: str = ""
    message: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def get(self, name: str, default=None):
        if hasattr(self, name):
            return getattr(self, name)
        return self.extra.get(name, default)


# ---------------------------------------------------------------- linux auth
SYSLOG = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
ISO_SYSLOG = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?) (?P<host>\S+) (?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
SSH_OK = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.a-fA-F:]+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:.*?; )?TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+) : (?:\d+ )?incorrect password attempts?")
USERADD = re.compile(r"new user: name=(?P<user>[^,]+)")
GROUPADD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
SU = re.compile(r"(?:Successful su|session opened) for user (?P<target>\S+) by (?P<user>\S*)")
FW = re.compile(r"\[UFW (?P<act>BLOCK|ALLOW|AUDIT)\]|IPTABLES|kernel:.*SRC=")
KV = re.compile(r"(\w+)=(\S*)")


def _syslog_ts(m) -> float:
    if m.groupdict().get("iso"):
        s = m["iso"].replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    dt = datetime.strptime(f"{DEFAULT_YEAR} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def parse_syslog(line: str) -> Event | None:
    m = SYSLOG.match(line) or ISO_SYSLOG.match(line)
    if not m:
        return None
    ts, host, proc, msg = _syslog_ts(m), m["host"], m["proc"], m["msg"]
    if FW.search(line):
        kv = dict(KV.findall(msg))
        act = re.search(r"\[UFW (\w+)\]", msg)
        return Event(ts, "firewall", host, "firewall", "failure" if (act and act.group(1) == "BLOCK") or "DROP" in msg else "success",
                     src_ip=kv.get("SRC", ""), dst_ip=kv.get("DST", ""), dst_port=int(kv.get("DPT", 0) or 0),
                     message=msg, extra={"proto": kv.get("PROTO", "")})
    e = Event(ts, "linux_auth", host, process=proc, message=msg)
    if proc.startswith("sshd"):
        if (x := SSH_FAIL.search(msg)):
            e.action, e.outcome, e.user, e.src_ip, e.extra = "ssh_login", "failure", x["user"], x["ip"], {"src_port": int(x["port"])}
        elif (x := SSH_OK.search(msg)):
            e.action, e.outcome, e.user, e.src_ip, e.extra = "ssh_login", "success", x["user"], x["ip"], {"auth_method": x["method"]}
        elif (x := SSH_INVALID.search(msg)):
            e.action, e.outcome, e.user, e.src_ip = "ssh_invalid_user", "failure", x["user"], x["ip"]
        else:
            e.action = "ssh_other"
    elif proc == "sudo":
        if (x := SUDO.match(msg)):
            e.action, e.outcome, e.user, e.command, e.extra = "sudo", "success", x["user"], x["cmd"].strip(), {"target_user": x["target"]}
        elif (x := SUDO_FAIL.match(msg)):
            e.action, e.outcome, e.user = "sudo", "failure", x["user"]
        else:
            e.action = "sudo_other"
    elif proc in ("useradd", "adduser"):
        x = USERADD.search(msg)
        e.action, e.outcome, e.user = "user_created", "success", (x["user"] if x else "")
    elif proc in ("usermod", "gpasswd") or "to group" in msg:
        x = GROUPADD.search(msg)
        e.action, e.outcome = "group_member_added", "success"
        if x:
            e.user, e.group = x["user"], x["group"]
    elif proc == "su":
        x = SU.search(msg)
        e.action, e.outcome = "su", ("failure" if "FAILED" in msg else "success")
        if x:
            e.user, e.extra = x["user"], {"target_user": x["target"]}
    elif proc in ("CRON", "cron"):
        e.action = "cron"
        cmd = re.search(r"CMD \((.*)\)", msg)
        e.command = cmd.group(1) if cmd else ""
    else:
        e.action = "syslog"
    return e


# ---------------------------------------------------------------- web access
COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


def parse_web(line: str, host: str = "web") -> Event | None:
    m = COMBINED.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    url = m["url"]
    return Event(ts, "web_access", host, "http_request", "success" if int(m["status"]) < 400 else "failure",
                 user="" if m["user"] == "-" else m["user"], src_ip=m["ip"], url=url, method=m["method"],
                 status=int(m["status"]), bytes=0 if m["bytes"] == "-" else int(m["bytes"]),
                 user_agent=m["ua"] or "", extra={"url_decoded": unquote_plus(unquote_plus(url)), "referrer": m["ref"] or ""})


# ---------------------------------------------------------------- windows
WIN_ACTIONS = {
    4624: ("logon", "success"), 4625: ("logon", "failure"), 4634: ("logoff", "success"),
    4648: ("explicit_credential_logon", "success"), 4672: ("special_privileges_logon", "success"),
    4688: ("process_created", "success"), 4697: ("service_installed", "success"),
    4698: ("scheduled_task_created", "success"), 4720: ("user_created", "success"),
    4726: ("user_deleted", "success"), 4728: ("group_member_added", "success"),
    4732: ("group_member_added", "success"), 4740: ("account_locked", "success"),
    4756: ("group_member_added", "success"), 1102: ("audit_log_cleared", "success"),
    7045: ("service_installed", "success"),
}


def parse_windows(line: str) -> Event | None:
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict) or not ({"EventID", "event_id", "winlog"} & set(d)):
        return None
    w = d.get("winlog", {})
    data = {**w.get("event_data", {}), **d.get("EventData", {})}
    eid = int(d.get("EventID") or d.get("event_id") or w.get("event_id") or 0)
    ts_raw = d.get("@timestamp") or d.get("TimeCreated") or d.get("timestamp")
    ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")).timestamp() if ts_raw else 0.0
    action, outcome = WIN_ACTIONS.get(eid, (f"event_{eid}", ""))
    user = data.get("TargetUserName") or data.get("SubjectUserName") or ""
    if eid in (4728, 4732, 4756):
        user = data.get("MemberName", "").split(",")[0].replace("CN=", "") or data.get("MemberSid", "") or user
    return Event(ts, "windows", d.get("Computer") or w.get("computer_name") or d.get("host", ""), action, outcome,
                 user=user, src_ip=data.get("IpAddress", "") if data.get("IpAddress") not in ("-", None) else "",
                 process=data.get("NewProcessName", "") or data.get("ServiceFileName", ""),
                 command=data.get("CommandLine", "") or data.get("ServiceFileName", "") or data.get("TaskContent", ""),
                 event_id=eid, group=data.get("TargetUserName", "") if eid in (4728, 4732, 4756) else "",
                 extra={"logon_type": str(data.get("LogonType", "")), "subject_user": data.get("SubjectUserName", ""),
                        "parent_process": data.get("ParentProcessName", "")})


# ---------------------------------------------------------------- dispatcher
def parse_line(line: str) -> Event | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    if line.lstrip().startswith("{"):
        return parse_windows(line)
    return parse_web(line) or parse_syslog(line)


def parse_lines(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        try:
            e = parse_line(line)
        except Exception:  # a malformed line must never stop ingestion
            e = None
        if e:
            yield e


def parse_file(path: str) -> list[Event]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sorted(parse_lines(fh), key=lambda e: e.ts)
