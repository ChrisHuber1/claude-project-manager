import base64
import json
import time
from datetime import datetime
from pathlib import Path
from config import run_ssh, STATE_DIR


SCAN_SCRIPT = r'''
import os, json, subprocess, glob
from datetime import datetime

home = os.path.expanduser("~")
skip = {".ssh", ".cache", ".local", ".config", ".gnupg", ".bash_history",
        ".bashrc", ".profile", ".bash_logout", ".viminfo", "snap", ".nano",
        ".claude", ".pm-state", "environment"}

projects = []
for entry in sorted(os.listdir(home)):
    full = os.path.join(home, entry)
    if not os.path.isdir(full) or entry.startswith(".") or entry in skip:
        continue
    p = {"name": entry, "host": "linux-host", "path": full}

    # git state
    git_dir = os.path.join(full, ".git")
    p["is_git"] = os.path.isdir(git_dir)
    if p["is_git"]:
        try:
            branch = subprocess.check_output(
                ["git", "-C", full, "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL, text=True).strip()
            p["branch"] = branch
        except Exception:
            p["branch"] = "unknown"
        try:
            status = subprocess.check_output(
                ["git", "-C", full, "status", "--porcelain"],
                stderr=subprocess.DEVNULL, text=True).strip()
            p["git_dirty"] = len(status) > 0
        except Exception:
            p["git_dirty"] = False
        try:
            log = subprocess.check_output(
                ["git", "-C", full, "log", "-1", "--format=%aI"],
                stderr=subprocess.DEVNULL, text=True).strip()
            p["last_commit"] = log
        except Exception:
            p["last_commit"] = None
    else:
        p["branch"] = None
        p["git_dirty"] = False
        p["last_commit"] = None

    # docs
    for doc in ["README.md", "TODO.md", "STATUS.md", "CHANGELOG.md", "CLAUDE.md", "SESSION_NOTES.md"]:
        p["has_" + doc.replace(".", "_").lower()] = os.path.isfile(os.path.join(full, doc))

    # TODO parsing
    todos_total = 0
    todos_done = 0
    todo_file = os.path.join(full, "TODO.md")
    if os.path.isfile(todo_file):
        try:
            with open(todo_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("- [ ]"):
                        todos_total += 1
                    elif line.startswith("- [x]") or line.startswith("- [X]"):
                        todos_total += 1
                        todos_done += 1
        except Exception:
            pass
    p["todos_total"] = todos_total
    p["todos_done"] = todos_done

    # running processes (check common ports/pidfiles)
    p["running"] = False

    # error detection in logs
    p["has_errors"] = False
    log_patterns = glob.glob(os.path.join(full, "*.log")) + glob.glob(os.path.join(full, "logs", "*.log"))
    for lf in log_patterns[:5]:
        try:
            with open(lf) as f:
                lines = f.readlines()[-200:]
                for line in lines:
                    if any(kw in line for kw in ["ERROR", "FATAL", "Traceback"]):
                        p["has_errors"] = True
                        break
        except Exception:
            pass
        if p["has_errors"]:
            break

    # file activity
    newest_mtime = 0
    src_exts = {".py", ".js", ".ts", ".sh", ".go", ".rs", ".c", ".html",
                ".css", ".yml", ".yaml", ".json", ".conf", ".md"}
    for root, dirs, files in os.walk(full):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for fn in files:
            if os.path.splitext(fn)[1] in src_exts:
                try:
                    mt = os.path.getmtime(os.path.join(root, fn))
                    if mt > newest_mtime:
                        newest_mtime = mt
                except Exception:
                    pass
    if newest_mtime > 0:
        age_days = (datetime.now().timestamp() - newest_mtime) / 86400
        p["last_activity_days"] = round(age_days, 1)
        p["last_activity_ts"] = datetime.fromtimestamp(newest_mtime).isoformat()
    else:
        p["last_activity_days"] = None
        p["last_activity_ts"] = None

    # file count
    file_count = 0
    for root, dirs, files in os.walk(full):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        file_count += len(files)
    p["file_count"] = file_count

    # pm status
    for sf in [".pm-status.json", ".pm-status.yaml"]:
        if os.path.isfile(os.path.join(full, sf)):
            p["has_pm_status"] = True
            break
    else:
        p["has_pm_status"] = False

    # priority detection from docs
    p["priority"] = None
    for doc_name in ["TODO.md", "README.md", "CLAUDE.md"]:
        doc_path = os.path.join(full, doc_name)
        if os.path.isfile(doc_path):
            try:
                with open(doc_path) as f:
                    content = f.read(4096).lower()
                    if "[p0]" in content or "priority: critical" in content:
                        p["priority"] = "P0"
                    elif "[p1]" in content or "priority: high" in content:
                        p["priority"] = "P1"
                    elif "[p2]" in content or "priority: medium" in content:
                        p["priority"] = "P2"
            except Exception:
                pass
        if p["priority"]:
            break

    projects.append(p)

print(json.dumps(projects))
'''


def scan_projects():
    encoded = base64.b64encode(SCAN_SCRIPT.encode()).decode()
    stdout, stderr, rc = run_ssh(
        f'echo {encoded} | base64 -d | python3',
        timeout=30
    )
    if rc != 0:
        return None, f"Scan failed: {stderr[:200]}"
    try:
        projects = json.loads(stdout.strip())
        scan_time = datetime.now().isoformat()
        state = {"scan_time": scan_time, "projects": projects}
        state_file = STATE_DIR / "projects.json"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state, indent=2))
        try:
            from obsidian_sync import publish_to_vault
            publish_to_vault(projects, scan_time)
        except Exception:
            pass
        return projects, None
    except json.JSONDecodeError as e:
        return None, f"JSON parse error: {e}"


def load_cached_projects():
    state_file = STATE_DIR / "projects.json"
    if state_file.exists():
        try:
            data = json.loads(state_file.read_text())
            return data.get("projects", []), data.get("scan_time")
        except Exception:
            pass
    return [], None


def check_host_reachable(host=None):
    from config import OPS1_HOST
    h = host or OPS1_HOST
    stdout, stderr, rc = run_ssh("echo ok", host=h, timeout=5)
    return rc == 0
