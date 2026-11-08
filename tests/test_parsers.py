from loghawk.parsers import parse_line


def test_ssh_failed_classic_syslog():
    e = parse_line("Nov  3 02:11:09 web01 sshd[2211]: Failed password for invalid user admin from 45.33.12.7 port 51234 ssh2")
    assert (e.source, e.action, e.outcome, e.user, e.src_ip) == ("linux_auth", "ssh_login", "failure", "admin", "45.33.12.7")


def test_ssh_accepted_iso():
    e = parse_line("2026-11-03T02:15:00+05:30 web01 sshd[1]: Accepted password for bob from 45.33.12.7 port 4444 ssh2")
    assert e.outcome == "success" and e.user == "bob" and e.extra["auth_method"] == "password"


def test_sudo():
    e = parse_line("2026-11-03T02:16:00+05:30 web01 sudo[9]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    assert e.action == "sudo" and e.user == "bob" and e.command == "/usr/bin/cat /etc/shadow"


def test_group_add():
    e = parse_line("2026-11-03T02:17:00+05:30 web01 usermod[9]: add 'backdoor' to group 'sudo'")
    assert e.action == "group_member_added" and e.user == "backdoor" and e.group == "sudo"


def test_nginx_combined_and_double_decoding():
    e = parse_line('45.33.12.7 - - [03/Nov/2026:02:10:00 +0530] "GET /p?id=1%2527%2520OR%25201%253D1 HTTP/1.1" 500 12 "-" "sqlmap/1.8"')
    assert e.source == "web_access" and e.status == 500 and "' OR 1=1" in e.extra["url_decoded"]


def test_ufw():
    e = parse_line("2026-11-03T02:12:00+05:30 gw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.12.7 DST=203.0.113.10 PROTO=TCP SPT=5555 DPT=3389 SYN")
    assert e.source == "firewall" and e.outcome == "failure" and e.dst_port == 3389


def test_windows_json():
    e = parse_line('{"@timestamp":"2026-11-02T21:00:00Z","EventID":4732,"Computer":"DC01","EventData":{"MemberName":"CN=helpdesk2,CN=Users,DC=corp","TargetUserName":"Administrators"}}')
    assert e.source == "windows" and e.user == "helpdesk2" and e.group == "Administrators"


def test_garbage_is_ignored():
    assert parse_line("") is None
    assert parse_line("this is not a log line") is None
    assert parse_line("{not json") is None
