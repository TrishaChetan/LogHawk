# Writing LogHawk rules

Rules live in `rules/*.yml`. Several rules can share a file, separated by `---`.

## Common fields

| Field | Required | Meaning |
|---|---|---|
| `id` | ✓ | unique, e.g. `LH-L01` |
| `title` | ✓ | shown in alerts |
| `type` | | `single` (default), `threshold`, `sequence` |
| `severity` | | `informational`, `low`, `medium` (default), `high`, `critical` |
| `mitre` | | `{tactic, technique, name}` |
| `description` | | why it matters |
| `enabled` | | `false` to disable |

## Conditions (`match`)

All keys are AND-ed. A list value means OR.

| Syntax | Meaning |
|---|---|
| `action: ssh_login` | equals (case-insensitive) |
| `action: [ssh_login, logon]` | equals any |
| `command\|contains: ["/etc/shadow"]` | substring |
| `url_decoded\|re: "(?i)union\\s+select"` | regular expression |
| `command\|startswith` / `\|endswith` | prefix / suffix |
| `status\|gte: 500` | numeric `gt` `gte` `lt` `lte` |
| `user\|not: [root, admin]` | not equal to any |
| `src_ip\|exists: true` | field present |

Event fields: `source, host, action, outcome, user, src_ip, dst_ip, dst_port, process, command, url, method, status,
user_agent, bytes, event_id, group, message` and anything in `extra` (`url_decoded`, `auth_method`, `logon_type`, `parent_process`…).

## Single

```yaml
id: MY-001
title: Login from a decommissioned admin account
severity: high
match: {action: [ssh_login, logon], outcome: success, user: [olduser, contractor1]}
```

## Threshold

```yaml
id: MY-002
title: Many 5xx errors from one client
type: threshold
severity: low
match: {source: web_access, status|gte: 500}
group_by: src_ip
threshold: 50          # events …
window: 60             # … within 60 s
# distinct: url        # optional: count distinct values instead of events
```

## Sequence

Steps must happen in order, for the same `group_by` value, within `window` seconds.

```yaml
id: MY-003
title: Exposed .env downloaded then admin login
type: sequence
severity: critical
group_by: src_ip
window: 3600
steps:
  - match: {source: web_access, url|endswith: "/.env", status: 200}
  - match: {source: web_access, url|startswith: "/admin", method: POST, status: 302}
```

Restart the API (or re-run the CLI) to load new rules.

## Testing a rule against real logs

```bash
python -m loghawk.cli test-rule LH-L03 samples/scenario/auth.log
python -m loghawk.cli test-rule my_rule.yml /var/log/auth.log --show 10
```

`test-rule` runs one rule (by id or from a `.yml` file) through the real streaming engine and explains the outcome:
how many events each condition or sequence step matched, a few sample matching events, the alerts it would raise,
and a verdict — **FIRES**, **NO MATCH** (conditions never match — check field values), **PARTIAL** (a sequence step
never matched) or **MATCHES BUT DOESN'T FIRE** (threshold, window or group_by too strict). It exits 0 when the rule
fires and 2 when it doesn't, so it can be used in CI against a sample log.

## Linting your rules

```bash
python -m loghawk.cli lint-rules              # bundled rules/
python -m loghawk.cli lint-rules my_rules/    # your own directory
python -m loghawk.cli lint-rules --strict     # fail on warnings too (good for CI)
```

The linter reports every problem at once instead of stopping at the first: unknown modifiers, invalid regexes,
bad severities, duplicate ids, sequence rules with fewer than two steps — and, most importantly, **field names no
parser ever sets** (e.g. `Src_IP` instead of `src_ip`). Those compile fine but can never match, so without the
linter they fail silently.
