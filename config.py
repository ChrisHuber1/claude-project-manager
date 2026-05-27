import os
import subprocess
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent
BOOTSTRAP_PATH = BASE_DIR / "bootstrap.env"
STATE_DIR = BASE_DIR / "state"
LOGS_DIR = BASE_DIR / "logs"


def load_bootstrap():
    env = {}
    if BOOTSTRAP_PATH.exists():
        for line in BOOTSTRAP_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


REQUIRED_BOOTSTRAP = ["OPS1_HOST", "OPS1_USER", "OPS1_SSH_KEY"]

_bootstrap = load_bootstrap()
OPS1_HOST = _bootstrap.get("OPS1_HOST", "YOUR_HOST_IP")
OPS1_USER = _bootstrap.get("OPS1_USER", "YOUR_SSH_USER")
OPS1_SSH_KEY = _bootstrap.get("OPS1_SSH_KEY", "")
ANTHROPIC_API_KEY = _bootstrap.get("ANTHROPIC_API_KEY", "")
OBSIDIAN_VAULT_PATH = _bootstrap.get("OBSIDIAN_VAULT_PATH", r"C:\Users\YOUR_USER\obsidian-vault")

_remote_env = {}
_remote_env_lock = threading.Lock()
_last_env_refresh = 0


def ssh_cmd(host=None, user=None, key=None):
    h = host or OPS1_HOST
    u = user or OPS1_USER
    k = key or OPS1_SSH_KEY
    return [
        "ssh",
        "-i", k,
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        f"{u}@{h}",
    ]


def run_ssh(command, host=None, user=None, key=None, timeout=15):
    target_host = host or OPS1_HOST

    if os.environ.get("AGENT_LOCAL_MODE") and target_host == OPS1_HOST:
        try:
            result = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", 1
        except Exception as e:
            return "", str(e), 1

    if os.environ.get("AGENT_LOCAL_MODE"):
        u = user or OPS1_USER
        cmd = [
            "ssh",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            f"{u}@{target_host}",
            command,
        ]
    else:
        cmd = ssh_cmd(host, user, key) + [command]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH timeout", 1
    except Exception as e:
        return "", str(e), 1


def refresh_remote_env():
    global _last_env_refresh
    env = {}
    stdout, stderr, rc = run_ssh(
        "cat ~/credentials/credentials.env ~/credentials/devices.env "
        "~/credentials/firewall.env ~/credentials/network.env 2>/dev/null"
    )
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    with _remote_env_lock:
        _remote_env.clear()
        _remote_env.update(env)
        _last_env_refresh = time.time()
    return len(env) > 0


def get_remote_env():
    with _remote_env_lock:
        return dict(_remote_env)


def get_env_key_names():
    with _remote_env_lock:
        return list(_remote_env.keys())


def check_bootstrap():
    missing = []
    for k in REQUIRED_BOOTSTRAP:
        if not _bootstrap.get(k):
            missing.append(k)
    if not ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY (optional but recommended)")
    return missing
