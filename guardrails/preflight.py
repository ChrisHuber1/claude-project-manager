"""
Pre-flight checklist for --dangerously-skip-permissions sessions.

Runs all Section 7 checks before an autonomous session can begin.
Exit code 0 = all checks passed. Non-zero = session must not proceed.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

GUARDRAILS_DIR = Path(__file__).parent
CONFIG_PATH = GUARDRAILS_DIR / "config.json"
STATE_DIR = GUARDRAILS_DIR.parent / "state"
SESSION_DIR = STATE_DIR / "sessions"
RECOVERY_LOCAL = GUARDRAILS_DIR.parent / "recovery" / "restore-network.ps1"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def log(status, check, message):
    icon = "PASS" if status else "FAIL"
    print(f"[{icon}] {check}: {message}")
    return status


def run(cmd, cwd=None, timeout=30):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd,
            timeout=timeout, shell=isinstance(cmd, str)
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def check_git_repo(project_path):
    code, out, _ = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=project_path)
    return log(code == 0 and out == "true", "Git Repo", f"{project_path} is a git repository" if code == 0 else "Not a git repository - refusing skip-permissions")


def check_clean_state(project_path, config):
    code, out, _ = run(["git", "status", "--porcelain"], cwd=project_path)
    if code != 0:
        return log(False, "Clean State", "Failed to check git status")
    if not out:
        return log(True, "Clean State", "Working tree is clean")
    if config["preflight"]["auto_stash_on_dirty"]:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        stash_msg = f"{config['backup']['stash_prefix']}{ts}"
        code, _, err = run(["git", "stash", "push", "-m", stash_msg], cwd=project_path)
        if code == 0:
            return log(True, "Clean State", f"Dirty tree auto-stashed as '{stash_msg}'")
        return log(False, "Clean State", f"Auto-stash failed: {err}")
    return log(False, "Clean State", "Uncommitted changes present and auto_stash disabled")


def check_github_remote(project_path, config):
    github_user = config["github_user"]
    code, out, _ = run(["git", "remote", "get-url", "origin"], cwd=project_path)
    if code == 0 and github_user.lower() in out.lower():
        return log(True, "GitHub Remote", f"Origin: {out}")

    project_name = Path(project_path).name
    print(f"[INFO] GitHub Remote: No origin found for {github_user}. Creating private repo...")
    code, out, err = run(
        ["gh", "repo", "create", f"{github_user}/{project_name}", "--private", "--source", ".", "--remote", "origin"],
        cwd=project_path
    )
    if code == 0:
        return log(True, "GitHub Remote", f"Created private repo {github_user}/{project_name}")
    return log(False, "GitHub Remote", f"Failed to create repo: {err}")


def check_safety_checkpoint(project_path, config):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"{config['backup']['safety_branch_prefix']}{ts}"

    code, _, err = run(["git", "checkout", "-b", branch], cwd=project_path)
    if code != 0:
        return log(False, "Safety Checkpoint", f"Failed to create branch {branch}: {err}")

    code, _, err = run(["git", "add", "-A"], cwd=project_path)
    if code != 0:
        run(["git", "checkout", "-"], cwd=project_path)
        return log(False, "Safety Checkpoint", f"Failed to stage files: {err}")

    code, out, _ = run(["git", "status", "--porcelain"], cwd=project_path)
    if out:
        code, _, err = run(
            ["git", "commit", "-m", "[SAFETY] checkpoint before autonomous session"],
            cwd=project_path
        )
        if code != 0:
            run(["git", "checkout", "-"], cwd=project_path)
            return log(False, "Safety Checkpoint", f"Commit failed: {err}")

    code, _, err = run(["git", "push", "origin", branch], cwd=project_path, timeout=60)
    run(["git", "checkout", "-"], cwd=project_path)

    if code != 0:
        return log(False, "Safety Checkpoint", f"Push failed - no backup, halting: {err}")
    return log(True, "Safety Checkpoint", f"Branch {branch} pushed to GitHub")


def check_connectivity(config):
    linux-host = config["linux-host"]
    ext_target = config["preflight"]["connectivity_targets"]["external"]

    code_gw, _, _ = run(["ping", "-n", "1", "-w", "3000", linux-host["host"]])
    ops1_ok = code_gw == 0

    code_ext, _, _ = run(["ping", "-n", "1", "-w", "3000", ext_target])
    ext_ok = code_ext == 0

    if not ops1_ok:
        return log(False, "Connectivity", f"Cannot reach linux-host ({linux-host['host']}) - halting")
    if not ext_ok:
        print(f"[WARN] Connectivity: Internet unreachable ({ext_target}) - proceeding with warning")
        return log(True, "Connectivity", f"linux-host reachable, internet down - proceeding with caution")
    return log(True, "Connectivity", f"linux-host ({linux-host['host']}) and internet ({ext_target}) reachable")


def check_recovery_scripts(config):
    linux-host = config["linux-host"]
    local_exists = RECOVERY_LOCAL.exists()

    code, out, _ = run([
        "ssh", f"{linux-host['user']}@{linux-host['host']}",
        f"test -f {linux-host['recovery_path']}/restore-network.sh && echo exists"
    ], timeout=15)
    remote_exists = "exists" in out

    if local_exists and remote_exists:
        return log(True, "Recovery Scripts", "Present on MainPC and linux-host")
    missing = []
    if not local_exists:
        missing.append(f"MainPC ({RECOVERY_LOCAL})")
    if not remote_exists:
        missing.append(f"linux-host ({linux-host['recovery_path']}/restore-network.sh)")
    return log(False, "Recovery Scripts", f"Missing: {', '.join(missing)}")


def check_disk_space(config):
    min_gb = config["preflight"]["require_min_disk_gb"]
    local_free = shutil.disk_usage("C:\\").free / (1024 ** 3)
    local_ok = local_free >= min_gb

    linux-host = config["linux-host"]
    code, out, _ = run([
        "ssh", f"{linux-host['user']}@{linux-host['host']}",
        "df -BG --output=avail / | tail -1"
    ], timeout=15)
    remote_ok = False
    remote_free = 0
    if code == 0:
        try:
            remote_free = int(out.strip().replace("G", ""))
            remote_ok = remote_free >= min_gb
        except ValueError:
            pass

    if local_ok and remote_ok:
        return log(True, "Disk Space", f"MainPC: {local_free:.1f}GB free, linux-host: {remote_free}GB free")
    problems = []
    if not local_ok:
        problems.append(f"MainPC: {local_free:.1f}GB < {min_gb}GB")
    if not remote_ok:
        problems.append(f"linux-host: {remote_free}GB < {min_gb}GB")
    return log(False, "Disk Space", f"Insufficient: {', '.join(problems)}")


def check_audit_log_writable():
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    test_file = SESSION_DIR / ".write_test"
    try:
        test_file.write_text("test")
        test_file.unlink()
        return log(True, "Audit Log", f"Session log directory writable: {SESSION_DIR}")
    except Exception as e:
        return log(False, "Audit Log", f"Cannot write to {SESSION_DIR}: {e}")


def init_session_log(config):
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    log_file = SESSION_DIR / f"session-{ts}.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "session_start",
        "preflight": "passed",
        "config_version": config["version"]
    }
    log_file.write_text(json.dumps(entry) + "\n")
    print(f"\n[SESSION] Log initialized: {log_file}")
    return log_file


def run_preflight(project_path):
    print("=" * 60)
    print("  GUARDRAILS PRE-FLIGHT CHECK")
    print(f"  Project: {project_path}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)
    print()

    config = load_config()
    checks = []

    checks.append(check_git_repo(project_path))
    if not checks[-1]:
        print("\n[ABORT] Project must be a git repo for skip-permissions mode.")
        return False

    checks.append(check_clean_state(project_path, config))
    checks.append(check_github_remote(project_path, config))

    if not checks[-1]:
        print("\n[ABORT] GitHub remote required for safety checkpoints.")
        return False

    checks.append(check_safety_checkpoint(project_path, config))
    if not checks[-1]:
        print("\n[ABORT] Safety checkpoint must be pushed before autonomous session.")
        return False

    checks.append(check_connectivity(config))
    if not checks[-1]:
        print("\n[ABORT] linux-host must be reachable.")
        return False

    checks.append(check_recovery_scripts(config))
    if not checks[-1]:
        print("\n[ABORT] Recovery scripts must exist on both machines.")
        return False

    checks.append(check_disk_space(config))
    if not checks[-1]:
        print("\n[ABORT] Insufficient disk space.")
        return False

    checks.append(check_audit_log_writable())
    if not checks[-1]:
        print("\n[ABORT] Audit log must be writable.")
        return False

    passed = all(checks)
    print()
    print("=" * 60)
    if passed:
        print("  ALL CHECKS PASSED - autonomous session authorized")
        session_log = init_session_log(config)
        print(f"  Session log: {session_log}")
    else:
        print("  PRE-FLIGHT FAILED - session NOT authorized")
    print("=" * 60)
    return passed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python preflight.py <project_path>")
        sys.exit(1)
    project_path = sys.argv[1]
    if not Path(project_path).is_dir():
        print(f"Error: {project_path} is not a directory")
        sys.exit(1)
    success = run_preflight(project_path)
    sys.exit(0 if success else 1)
