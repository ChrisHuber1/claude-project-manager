"""
Guardrail enforcement hook for Claude Code PreToolUse events.

Reads the tool invocation from stdin, checks it against forbidden patterns
in config.json, and returns a JSON decision to block or allow.

Used as a PreToolUse hook in .claude/settings.local.json.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

GUARDRAILS_DIR = Path(__file__).parent
CONFIG_PATH = GUARDRAILS_DIR / "config.json"
SESSION_DIR = GUARDRAILS_DIR.parent / "state" / "sessions"
SESSION_STATE_PATH = GUARDRAILS_DIR.parent / "state" / "guardrail_session.json"

_config = None

SSH_PATTERN = re.compile(r"^\s*ssh\s+", re.IGNORECASE)

FILES_EXEMPT_FROM_COUNTER = [
    "scratchpad.md",
    "guardrail_session.json",
    "activity.log",
    "audit.log",
]

DIRS_EXEMPT_FROM_COUNTER = [
    os.path.join(".claude", "projects").replace("\\", "/").lower(),
    "state/sessions",
    "state/agent_active",
    "state/agent_results",
]


def _load_session_state():
    try:
        with open(SESSION_STATE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        state = {
            "file_deletions": 0,
            "files_modified": 0,
            "session_start": datetime.now(timezone.utc).isoformat(),
        }
        _save_session_state(state)
        return state


def _save_session_state(state):
    SESSION_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SESSION_STATE_PATH, "w") as f:
        json.dump(state, f)


def load_config():
    global _config
    if _config is None:
        with open(CONFIG_PATH) as f:
            _config = json.load(f)
    return _config


def log_block(project, cmd, rule):
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    sessions = sorted(SESSION_DIR.glob("session-*.jsonl"), reverse=True)
    if sessions:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "guardrail_block",
            "project": project or "unknown",
            "cmd": cmd[:500],
            "rule": rule
        }
        with open(sessions[0], "a") as f:
            f.write(json.dumps(entry) + "\n")


def _is_exempt_from_file_counter(file_path):
    if not file_path:
        return False
    normalized = file_path.replace("\\", "/").lower()
    basename = normalized.rsplit("/", 1)[-1]
    if basename in FILES_EXEMPT_FROM_COUNTER:
        return True
    for exempt_dir in DIRS_EXEMPT_FROM_COUNTER:
        if exempt_dir in normalized:
            return True
    return False


def check_forbidden_command(cmd, config):
    cmd_lower = cmd.lower().strip()
    forbidden = config["forbidden_commands"]

    for category, rules in forbidden.items():
        patterns = rules.get("patterns", [])
        for pattern in patterns:
            try:
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    return category, pattern
            except re.error:
                if pattern.lower() in cmd_lower:
                    return category, pattern

    return None, None


def check_file_write_blocked(file_path, config):
    if not file_path:
        return None, None

    path_lower = file_path.lower().replace("\\", "/")

    cred_patterns = config["forbidden_commands"]["credential_files"]["write_blocked_patterns"]
    for pattern in cred_patterns:
        pattern_clean = pattern.replace("**/", "").replace("*", "")
        if pattern_clean and pattern_clean.lower() in path_lower:
            return "credential_files", pattern

    net_files = config["forbidden_commands"]["network_infrastructure"].get("file_write_blocked", [])
    for blocked_path in net_files:
        blocked_clean = blocked_path.replace("*", "").lower()
        if blocked_clean and blocked_clean in path_lower:
            return "network_infrastructure", blocked_path

    return None, None


def check_scope_containment(file_path, config):
    if not file_path:
        return True

    project_root = os.environ.get(
        "CLAUDE_PROJECT_DIR",
        r"C:\Users\YOUR_USER\ClaudeProjectManager",
    ).replace("\\", "/").lower().rstrip("/")

    path_normalized = file_path.replace("\\", "/").lower()

    if path_normalized.startswith(project_root):
        return True

    allowed_outside = config["scope_containment"]["write_allowed_outside_project"]
    for allowed in allowed_outside:
        allowed_normalized = allowed.replace("\\", "/").lower().rstrip("/")
        if path_normalized.startswith(allowed_normalized):
            return True

    return False


def _is_ssh_command(cmd):
    return bool(SSH_PATTERN.match(cmd))


def check_limits(tool_name, cmd, config):
    limits = config["limits"]

    if tool_name in ("Bash", "PowerShell"):
        if _is_ssh_command(cmd):
            return None, None

        state = _load_session_state()
        start = datetime.fromisoformat(state["session_start"])
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() / 60
        if elapsed >= limits["max_autonomous_minutes"]:
            return "session_time_limit", f"Session has exceeded {limits['max_autonomous_minutes']} minute limit. Reset with: ! echo '{{\"file_deletions\":0,\"files_modified\":0,\"session_start\":\"'$(date -u +%%Y-%%m-%%dT%%H:%%M:%%S+00:00)'\"}}' > /c/Users/Chris/ClaudeProjectManager/state/guardrail_session.json"

    return None, None


def check_network_api(cmd, config):
    api_blocked = config["forbidden_commands"]["network_infrastructure"].get("api_blocked_patterns", [])
    for pattern in api_blocked:
        pattern_clean = pattern.replace("*", ".*")
        if re.search(pattern_clean, cmd, re.IGNORECASE):
            return "network_infrastructure_api", pattern
    return None, None


def evaluate(tool_use):
    config = load_config()
    tool_name = tool_use.get("tool_name", "")
    tool_input = tool_use.get("tool_input", {})

    if tool_name in ("Bash", "PowerShell"):
        cmd = tool_input.get("command", "")
        if not cmd:
            return {"decision": "allow"}

        category, pattern = check_forbidden_command(cmd, config)
        if category:
            log_block(None, cmd, category)
            return {
                "decision": "block",
                "reason": f"GUARDRAIL BLOCK [{category}]: Command matches forbidden pattern '{pattern}'. This operation requires explicit human approval."
            }

        category, pattern = check_network_api(cmd, config)
        if category:
            log_block(None, cmd, category)
            return {
                "decision": "block",
                "reason": f"GUARDRAIL BLOCK [{category}]: Command targets network infrastructure API '{pattern}'. This could take down the network. Requires explicit human approval."
            }

        rm_patterns = [r'\brm\s+', r'Remove-Item', r'del\s+', r'rmdir']
        for rp in rm_patterns:
            if re.search(rp, cmd, re.IGNORECASE):
                state = _load_session_state()
                state["file_deletions"] = state.get("file_deletions", 0) + 1
                _save_session_state(state)
                if state["file_deletions"] > config["limits"]["max_file_deletions_per_session"]:
                    log_block(None, cmd, "file_deletion_limit")
                    return {
                        "decision": "block",
                        "reason": f"GUARDRAIL BLOCK [file_deletion_limit]: Session has exceeded {config['limits']['max_file_deletions_per_session']} file deletions. Halting for approval."
                    }
                break

        limit_cat, limit_msg = check_limits(tool_name, cmd, config)
        if limit_cat:
            log_block(None, cmd, limit_cat)
            return {
                "decision": "block",
                "reason": f"GUARDRAIL BLOCK [{limit_cat}]: {limit_msg}"
            }

    elif tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")

        category, pattern = check_file_write_blocked(file_path, config)
        if category:
            log_block(None, f"write:{file_path}", category)
            return {
                "decision": "block",
                "reason": f"GUARDRAIL BLOCK [{category}]: Writing to '{file_path}' is forbidden (matches '{pattern}'). Credential and secret files are protected."
            }

        read_only = config["scope_containment"]["read_only_within_project"]
        for ro_pattern in read_only:
            if file_path and ro_pattern.lower() in file_path.lower():
                log_block(None, f"write:{file_path}", "read_only_path")
                return {
                    "decision": "block",
                    "reason": f"GUARDRAIL BLOCK [read_only_path]: '{file_path}' is marked read-only within projects."
                }

        if not check_scope_containment(file_path, config):
            log_block(None, f"write:{file_path}", "scope_containment")
            return {
                "decision": "block",
                "reason": f"GUARDRAIL BLOCK [scope_containment]: Writing to '{file_path}' is outside the project root and not in the allowed-outside list."
            }

        if not _is_exempt_from_file_counter(file_path):
            state = _load_session_state()
            state["files_modified"] = state.get("files_modified", 0) + 1
            _save_session_state(state)
            if state["files_modified"] > config["limits"]["max_files_modified_per_session"]:
                log_block(None, f"write:{file_path}", "files_modified_limit")
                return {
                    "decision": "block",
                    "reason": f"GUARDRAIL BLOCK [files_modified_limit]: Session has modified {config['limits']['max_files_modified_per_session']} files. Halting for approval."
                }

    return {"decision": "allow"}


def main():
    try:
        input_data = json.loads(sys.stdin.read())
        result = evaluate(input_data)
        print(json.dumps(result))
    except json.JSONDecodeError:
        print(json.dumps({"decision": "allow"}))
    except Exception as e:
        print(json.dumps({
            "decision": "block",
            "reason": f"Guardrail enforcement error: {e}. Blocking by default for safety."
        }))


if __name__ == "__main__":
    main()
