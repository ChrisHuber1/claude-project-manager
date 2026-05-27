# Skip-Permissions Guardrails Specification

Version: 1.0
Last updated: 2026-05-01
Applies to: All projects managed by ClaudeProjectManager

This document defines the safety framework for running Claude Code with
`--dangerously-skip-permissions`. Every autonomous session MUST comply with
these rules. The machine-readable config is `guardrails/config.json`.

---

## 1. Backup & Recovery

### Safety Checkpoints
- Before any autonomous session, create branch `safety/pre-session-<YYYYMMDD-HHMMSS>`.
- Stage and commit all current state: `[SAFETY] checkpoint before autonomous session`.
- Push the safety branch to the project's private GitHub remote under `YOUR_GITHUB_USER`.
- If the push fails, halt. No backup = no autonomous session.

### GitHub Remote Setup
- If the project has no GitHub remote, create one via `gh repo create YOUR_GITHUB_USER/<project> --private` and add it as origin.
- All repos must be **private**.

### On-Range Backups
- Maintain bare git backups at `~/backups/<project>.git` on linux-host.
- These are accessible without internet for disaster recovery.

### Cleanup
- Auto-delete safety branches older than 30 days (local and remote).

---

## 2. Forbidden Operations

### Hard-Blocked Commands (NEVER execute)

#### Filesystem Destruction
- `rm -rf` on anything at or above the project root (`../`, `/`, `~`)
- `rm -rf /` or any variation targeting system directories

#### Git History Destruction
- `git push --force` to `main` or `master`
- `git reset --hard` on shared/protected branches
- `git rebase -i` on shared/protected branches

#### Database Destruction
- `DROP DATABASE` without explicit human approval
- `DROP TABLE` without explicit human approval
- `TRUNCATE` on production tables

#### Credential Files (no write/delete)
- `~/.ssh/*`
- `*.env` files
- `*credentials*`, `*secret*`, `*.pem`, `*.key`
- Any file matching patterns in the secrets blocklist

#### System Commands
- `shutdown`, `reboot`, `halt`, `poweroff`
- `systemctl stop` on non-project services
- `kill -9` on non-project PIDs
- `chmod 777`, `chown` (privilege escalation)

#### Network Infrastructure
- `iptables`, `nft`, `pfctl` -- firewall rule modifications
- `ip link set down`, `ifconfig down` -- interface state changes
- `netplan apply` -- network reconfigurations
- `/etc/resolv.conf` modifications -- DNS changes
- Pi-hole configuration modifications
- DHCP server/scope changes
- `wg-quick down` -- VPN/WireGuard tunnel teardowns
- WireGuard config file modifications
- `ip route del` -- routing table changes
- Default gateway modifications
- OPNsense API calls that modify firewall/routing rules

#### Data Exfiltration
- `curl`/`wget` POSTing file contents to unknown endpoints
- Any command piping sensitive data to external hosts

### Allowed Operations
- `rm` on individual files within the project root (normal cleanup)
- `git push --force` on feature branches only
- `pip install`, `npm install` from standard registries
- `sudo systemctl restart` for project-specific services (with logging)

---

## 3. Scope Containment

### Write Confinement
All file writes MUST be within the project directory, with these exceptions:
- `C:\Users\YOUR_USER\ClaudeProjectManager\state\` (manager state/logs)
- `C:\Users\YOUR_USER\ClaudeProjectManager\guardrails\` (guardrail configs)
- `~/backups/` on linux-host (safety checkpoints)
- `~/recovery/` on linux-host (recovery scripts)
- `C:\Users\YOUR_USER\ClaudeProjectManager\recovery\` (local recovery scripts)

### Read-Only Paths (within projects)
- `.env`, `.env.*` files
- `LICENSE` files
- `.git/` internals (use git commands, never hand-edit)

### Cross-Project Writes
If working on Project A and needing to modify Project B, treat it as a
separate operation with its own safety checkpoint first.

---

## 4. Network & External Actions

| Action | Policy |
|---|---|
| `git push` | Feature branches only (`pm/*`, `safety/*`, `dev/*`). `main`/`master` requires approval. |
| `git pull` / `git fetch` | Always allowed |
| Package installs | Standard registries only (PyPI, npm, apt official). Log every install. |
| HTTP to range hosts | Allowed (subject to Section 2 network protections) |
| HTTP external (GET) | Allowed |
| HTTP external (POST/PUT/DELETE) | Requires approval, except GitHub via `gh` CLI |
| SSH to range hosts | Allowed |
| SSH outside range | Blocked |
| Download + execute binaries | Blocked, requires approval |

---

## 5. Audit Trail

### Session Logs
- Format: JSON Lines (`.jsonl`)
- Location: `C:\Users\YOUR_USER\ClaudeProjectManager\state\sessions\session-<timestamp>.jsonl`
- Mirror: `~/audit/` on linux-host

### Entry Types
```jsonl
{"ts":"<ISO8601>","type":"command","project":"<name>","cmd":"<command>","exit_code":<int>,"model":"<model>"}
{"ts":"<ISO8601>","type":"file_modify","project":"<name>","path":"<path>","lines_added":<int>,"lines_removed":<int>,"model":"<model>"}
{"ts":"<ISO8601>","type":"file_delete","project":"<name>","path":"<path>","model":"<model>"}
{"ts":"<ISO8601>","type":"git_op","project":"<name>","op":"<push|commit|branch>","detail":"<info>","model":"<model>"}
{"ts":"<ISO8601>","type":"guardrail_block","project":"<name>","cmd":"<command>","rule":"<rule_name>","model":"<model>"}
{"ts":"<ISO8601>","type":"package_install","project":"<name>","package":"<name@version>","registry":"<source>","model":"<model>"}
{"ts":"<ISO8601>","type":"ssh_connect","host":"<host>","user":"<user>","model":"<model>"}
```

### End-of-Session Summary
```jsonl
{"ts":"<ISO8601>","type":"session_summary","project":"<name>","duration_min":<int>,"commands_run":<int>,"files_changed":<int>,"lines_added":<int>,"lines_removed":<int>,"deps_added":["<pkg>"],"safety_branch":"<branch>","checkpoint_pushed":<bool>}
```

### Retention
- 90 days local, then auto-delete.
- GitHub safety branches serve as permanent archive.

---

## 6. Kill Switch / Limits

| Limit | Threshold | Behavior |
|---|---|---|
| File deletions per session | 10 | Halt, verbal alert, wait for approval |
| Lines changed in single file | 500 | Pause, ask confirmation |
| Total files modified per session | 50 | Halt, verbal alert, wait for approval |
| Consecutive failures on same task | 2 | Stop, verbal alert, wait for input |
| Session time (autonomous) | 2 hours | Verbal alert "Master, claude needs you", continue read-only |
| Connectivity loss to linux-host | 60 seconds | Pause remote ops, run connectivity recovery check |

All limits are **soft** -- they halt and ask, not hard-abort. Chris can say
"continue" to resume.

After verbal alert, suppress further audible alerts for 60 seconds.

---

## 7. Pre-flight Checklist

Every `--dangerously-skip-permissions` session MUST pass all checks:

| # | Check | Pass Condition | On Fail |
|---|---|---|---|
| 1 | Git repository | Project is a git repo | Refuse skip-permissions |
| 2 | Clean git state | No uncommitted changes | Auto-stash with `pre-session-stash-<timestamp>` |
| 3 | GitHub remote | Origin points to private `YOUR_GITHUB_USER` repo | Create via `gh repo create --private`, add remote |
| 4 | Safety checkpoint | `safety/pre-session-<ts>` branch created and pushed | Halt if push fails |
| 5 | Connectivity | Can reach linux-host gateway + external host | linux-host unreachable = halt. Internet only = warn, proceed |
| 6 | Recovery scripts | Scripts exist on linux-host and MainPC | Halt |
| 7 | Disk space | >= 1GB free on linux-host and MainPC | Halt |
| 8 | Audit log writable | Can append to session log | Halt |

---

## 8. Per-Project Overrides

### Global Defaults
Live in `guardrails/config.json`. Apply to every project.

### Project Overrides
Place `.claude-guardrails.json` at the project root.

#### Tightening (always allowed)
```json
{
  "overrides": {
    "limits.max_file_deletions": 5,
    "limits.max_lines_changed_single_file": 200
  }
}
```

#### Loosening (requires reason)
```json
{
  "overrides": {
    "limits.max_lines_changed_single_file": 2000,
    "reason": "Project has auto-generated API client files that routinely exceed 500 lines"
  }
}
```

### Immutable Rules (cannot be overridden)
- Network protection rules (Section 2 network layer)
- Credential file protections
- Safety checkpoint requirement
- Audit logging requirement
- Recovery script requirement
