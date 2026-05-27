"""Base agent framework -- common SSH, detection, reporting, audit, alerting."""

import json
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from config import run_ssh, STATE_DIR, OPS1_HOST, OPS1_USER, OPS1_SSH_KEY


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    severity: Severity
    source: str
    message: str
    details: str = ""
    host: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AgentResult:
    agent_name: str
    success: bool
    findings: list = field(default_factory=list)
    summary: str = ""
    run_time: str = field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [f if isinstance(f, dict) else f.to_dict()
                         for f in self.findings]
        return d

    @property
    def critical_count(self):
        return sum(1 for f in self.findings
                   if (f.severity if isinstance(f, Finding) else f.get("severity")) == Severity.CRITICAL)

    @property
    def high_count(self):
        return sum(1 for f in self.findings
                   if (f.severity if isinstance(f, Finding) else f.get("severity")) == Severity.HIGH)

    def has_actionable(self):
        return self.critical_count > 0 or self.high_count > 0


RESULTS_DIR = STATE_DIR / "agent_results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


class BaseAgent:
    name = "base"
    description = "Base agent"
    default_interval = 300
    tier = "base"

    def __init__(self, app=None):
        self._app = app
        self._running = False
        self._thread = None
        self._last_result = None
        self._run_count = 0

    def run(self) -> AgentResult:
        start = time.time()
        self._run_count += 1
        try:
            result = self.check()
            result.duration_seconds = round(time.time() - start, 2)
            self._last_result = result
            self._save_result(result)
            self._audit_run(result)
            if result.has_actionable():
                self._alert(result)
            return result
        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                error=str(e),
                duration_seconds=round(time.time() - start, 2),
            )
            self._last_result = result
            self._save_result(result)
            self._audit_run(result)
            return result

    def check(self) -> AgentResult:
        raise NotImplementedError

    def start_loop(self, interval=None):
        if self._running:
            return
        self._running = True
        iv = interval or self.default_interval
        self._thread = threading.Thread(
            target=self._loop, args=(iv,), daemon=True
        )
        self._thread.start()

    def stop_loop(self):
        self._running = False

    def _loop(self, interval):
        while self._running:
            self.run()
            if self._app:
                self._notify_tui()
            time.sleep(interval)

    def _notify_tui(self):
        if not self._app or not self._last_result:
            return
        r = self._last_result
        if r.success:
            c = r.critical_count
            h = r.high_count
            if c > 0:
                msg = f"[red][{self.name}] {c} CRITICAL findings[/]"
            elif h > 0:
                msg = f"[yellow][{self.name}] {h} HIGH findings[/]"
            else:
                msg = f"[green][{self.name}] OK -- {r.summary}[/]"
        else:
            msg = f"[red][{self.name}] ERROR: {r.error[:100]}[/]"
        try:
            self._app.call_from_thread(self._app.log_activity, msg)
        except Exception:
            pass

    def _save_result(self, result: AgentResult):
        path = RESULTS_DIR / f"{self.name}.json"
        try:
            path.write_text(json.dumps(result.to_dict(), indent=2))
        except Exception:
            pass

    def _audit_run(self, result: AgentResult):
        entry = {
            "ts": datetime.now().isoformat(),
            "agent": self.name,
            "success": result.success,
            "findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "duration": result.duration_seconds,
        }
        if result.error:
            entry["error"] = result.error[:200]
        try:
            audit = STATE_DIR / "audit.log"
            with open(audit, "a") as f:
                f.write(f"[{entry['ts']}] agent_run: {json.dumps(entry)}\n")
        except Exception:
            pass

    def _alert(self, result: AgentResult):
        if result.critical_count > 0:
            try:
                from alerts import alert_input_needed
                alert_input_needed()
            except Exception:
                pass

    # --- Utility methods for subclasses ---

    def ssh(self, command, host=None, timeout=15):
        return run_ssh(command, host=host, timeout=timeout)

    def ssh_check(self, host, port=22, timeout=5):
        stdout, stderr, rc = run_ssh("echo ok", host=host, timeout=timeout)
        return rc == 0

    def ssh_json(self, command, host=None, timeout=15):
        stdout, stderr, rc = self.ssh(command, host=host, timeout=timeout)
        if rc != 0:
            return None, stderr
        try:
            return json.loads(stdout.strip()), None
        except json.JSONDecodeError as e:
            return None, str(e)

    def detect_stack(self, project_path, host=None):
        cmd = f"ls {project_path}/ 2>/dev/null"
        stdout, stderr, rc = self.ssh(cmd, host=host, timeout=10)
        if rc != 0:
            return {"type": "unknown"}

        files = set(stdout.strip().split("\n"))
        stack = {"type": "unknown", "languages": [], "frameworks": [], "tools": []}

        if "requirements.txt" in files or "setup.py" in files or "pyproject.toml" in files:
            stack["languages"].append("python")
        if "package.json" in files:
            stack["languages"].append("javascript")
        if "tsconfig.json" in files:
            stack["languages"].append("typescript")
        if "Cargo.toml" in files:
            stack["languages"].append("rust")
        if "go.mod" in files:
            stack["languages"].append("go")
        if "project.godot" in files:
            stack["type"] = "game"
            stack["frameworks"].append("godot")
        if "Gemfile" in files:
            stack["languages"].append("ruby")

        if "next.config.js" in files or "next.config.mjs" in files or "next.config.ts" in files:
            stack["type"] = "fullstack"
            stack["frameworks"].append("nextjs")
        elif "manage.py" in files:
            stack["type"] = "fullstack"
            stack["frameworks"].append("django")
        elif "app.py" in files or "main.py" in files:
            if "python" in stack["languages"]:
                stack["type"] = "api" if "fastapi" not in str(files) else "api"

        if "Dockerfile" in files or "docker-compose.yml" in files or "docker-compose.yaml" in files:
            stack["tools"].append("docker")
        if "Makefile" in files:
            stack["tools"].append("make")
        if ".github" in files:
            stack["tools"].append("github-actions")
        if "ansible.cfg" in files or "playbooks" in files:
            stack["type"] = "ansible"
            stack["tools"].append("ansible")

        if stack["type"] == "unknown" and stack["languages"]:
            stack["type"] = stack["languages"][0]

        return stack

    @property
    def last_result(self):
        return self._last_result

    @property
    def is_running(self):
        return self._running
