"""Lightweight HTTP API serving agent status for the web pixel office.

Run on linux-host: python3 ~/ClaudeProjectManager/scripts/agent_api.py
Listens on port 8801. Returns JSON at /api/agents, accepts POST at /api/hooks.
"""

import json
import os
import re
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent
STATE_DIR = PROJECT_DIR / "state"
RESULTS_DIR = STATE_DIR / "agent_results"
ACTIVE_DIR = STATE_DIR / "agent_active"
REGISTRY_FILE = STATE_DIR / "range_registry.json"
SESSIONS_DIR = Path.home() / "chatbot-sessions"
PORT = 8801
STALE_SECONDS = 300

PROJECT_AGENT_MAP = {
    "ClaudeProjectManager": "project_tracker",
    "MyProject": "build_validator",
    "trading-bot": "code_quality",
    "chatbot": "test_runner",
    "siem": "siem_watchdog",
    "SecurityAuditProject": "security_scanner",
    "FirewallManager": "security_monitor",
    "VPN": "backup_guardian",
    "ms-security-training": "daily_briefing",
    "linux-tools": "scaffold_agent",
    "scpinbox": "dependency_checker",
    "network-schema": "risk_drift",
    "siem-triage": "cross_project_intel",
    "obsidian-vault": "session_historian",
}

FALLBACK_AGENTS = [
    "session_historian", "scaffold_agent", "dependency_checker", "risk_drift",
]


def _project_from_cwd(cwd):
    if not cwd:
        return None
    name = cwd.replace("\\", "/").rstrip("/").split("/")[-1]
    return name


def _agent_for_project(project_name):
    if not project_name:
        return FALLBACK_AGENTS[0]
    for key, agent in PROJECT_AGENT_MAP.items():
        if key.lower() in project_name.lower():
            return agent
    idx = hash(project_name) % len(FALLBACK_AGENTS)
    return FALLBACK_AGENTS[idx]


class AgentAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/agents":
            self._serve_agents()
        elif self.path == "/api/range":
            self._serve_range()
        elif self.path in ("/api/transcripts", "/api/transcripts/sessions"):
            self._serve_transcript_index()
        elif self.path.startswith("/api/transcripts/sessions/"):
            self._serve_transcript_detail()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/hooks":
            self._handle_hook()
        else:
            self.send_error(404)

    def _handle_hook(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            event = json.loads(body)
        except Exception:
            self._json_response({"error": "bad request"}, 400)
            return

        hook_event = event.get("hook_event_name", "")
        session_id = event.get("session_id", "unknown")
        cwd = event.get("cwd", "")
        project = _project_from_cwd(cwd)
        agent_name = _agent_for_project(project)

        ACTIVE_DIR.mkdir(parents=True, exist_ok=True)
        marker_path = ACTIVE_DIR / f"{agent_name}.json"
        now = datetime.now().isoformat()

        if hook_event in ("Stop", "SessionEnd"):
            if marker_path.exists():
                try:
                    data = json.loads(marker_path.read_text())
                    if data.get("session_id") == session_id:
                        data["finished"] = now
                        marker_path.write_text(json.dumps(data))
                except Exception:
                    pass
        else:
            existing = {}
            if marker_path.exists():
                try:
                    existing = json.loads(marker_path.read_text())
                except Exception:
                    pass

            if existing.get("session_id") == session_id:
                existing["last_seen"] = now
                tool = event.get("tool_name", "")
                if tool:
                    existing["task"] = f"{project}: {tool}"
                marker_path.write_text(json.dumps(existing))
            else:
                task = f"{project or 'session'}: starting"
                if event.get("tool_name"):
                    task = f"{project}: {event['tool_name']}"
                marker = {
                    "agent": agent_name,
                    "session_id": session_id,
                    "project": project,
                    "started": now,
                    "last_seen": now,
                    "finished": "",
                    "task": task,
                }
                marker_path.write_text(json.dumps(marker))

        self._json_response({"ok": True, "agent": agent_name})

    def _serve_agents(self):
        results = {}
        if RESULTS_DIR.exists():
            for f in RESULTS_DIR.glob("*.json"):
                try:
                    results[f.stem] = json.loads(f.read_text())
                except Exception:
                    pass

        active = {}
        now = datetime.now()
        if ACTIVE_DIR.exists():
            for f in ACTIVE_DIR.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    last_seen_str = data.get("last_seen") or data.get("started", "")
                    last_seen = datetime.fromisoformat(last_seen_str)
                    age_from_last = (now - last_seen).total_seconds()
                    started = datetime.fromisoformat(data.get("started", last_seen_str))
                    age_from_start = (now - started).total_seconds()
                    if age_from_last < STALE_SECONDS:
                        data["_age"] = round(age_from_start, 1)
                        finished_str = data.get("finished", "")
                        if finished_str:
                            data["_since_finish"] = round(
                                (now - datetime.fromisoformat(finished_str)).total_seconds(), 1
                            )
                        else:
                            data["_since_finish"] = -1
                        active[f.stem] = data
                    else:
                        f.unlink(missing_ok=True)
                except Exception:
                    pass

        payload = {"results": results, "active": active, "timestamp": now.isoformat()}
        self._json_response(payload)

    def _serve_range(self):
        if REGISTRY_FILE.exists():
            try:
                data = json.loads(REGISTRY_FILE.read_text())
                self._json_response(data)
                return
            except Exception:
                pass
        self._json_response({"error": "no registry"})

    def _serve_transcript_index(self):
        sessions = []
        if SESSIONS_DIR.is_dir():
            for month_dir in sorted(os.listdir(SESSIONS_DIR), reverse=True):
                month_path = SESSIONS_DIR / month_dir
                if not month_path.is_dir():
                    continue
                for fname in sorted(os.listdir(month_path), reverse=True):
                    if not fname.endswith(".json"):
                        continue
                    fpath = month_path / fname
                    try:
                        data = json.loads(fpath.read_text())
                        sessions.append({
                            "session_name": fname[:-5],
                            "date": data.get("date", ""),
                            "time_start": data.get("time_start", ""),
                            "time_end": data.get("time_end", ""),
                            "topic": data.get("topic", ""),
                            "type": data.get("type", "class"),
                            "questions_detected": data.get("questions_detected", 0),
                            "duration_minutes": data.get("duration_minutes", 0),
                            "due_outs_count": len(data.get("due_outs", [])),
                            "month": month_dir,
                        })
                    except Exception:
                        pass
        self._json_response(sessions)

    def _serve_transcript_detail(self):
        parts = self.path.rstrip("/").split("/")
        if len(parts) < 5:
            self.send_error(404)
            return
        session_name = parts[4]
        is_transcript = len(parts) >= 6 and parts[5] == "transcript"

        m = re.match(r"session_(\d{8})_(\d{4})", session_name)
        if not m:
            self._json_response({"error": "invalid session name"}, 404)
            return
        month_dir = f"{m.group(1)[:4]}-{m.group(1)[4:6]}"

        if is_transcript:
            jsonl_path = SESSIONS_DIR / month_dir / f"{session_name}_transcript.jsonl"
            if not jsonl_path.exists():
                self._json_response([])
                return
            entries = []
            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
            self._json_response(entries)
            return

        json_path = SESSIONS_DIR / month_dir / f"{session_name}.json"
        if json_path.exists():
            try:
                self._json_response(json.loads(json_path.read_text()))
                return
            except Exception:
                pass

        md_path = SESSIONS_DIR / month_dir / f"{session_name}.md"
        md_content = ""
        if md_path.exists():
            md_content = md_path.read_text(encoding="utf-8")
        self._json_response({
            "session_name": session_name,
            "date": f"{m.group(1)[:4]}-{m.group(1)[4:6]}-{m.group(1)[6:8]}",
            "time_start": f"{m.group(2)[:2]}:{m.group(2)[2:4]}",
            "summary": md_content,
            "due_outs": [],
            "incorrect_answers": [],
            "questions": [],
        })

    def _json_response(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def main():
    server = HTTPServer(("0.0.0.0", PORT), AgentAPIHandler)
    print(f"Agent API listening on port {PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
