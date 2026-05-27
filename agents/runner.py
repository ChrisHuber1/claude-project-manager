"""Agent runner -- start, stop, and query all agents from one place."""

import json
from datetime import datetime
from pathlib import Path

from agents.base_agent import RESULTS_DIR


_registry = {}


def register(agent_class):
    _registry[agent_class.name] = agent_class
    return agent_class


def get_agent_class(name):
    return _registry.get(name)


def list_agents():
    return list(_registry.keys())


def get_agent_info():
    info = []
    for name, cls in _registry.items():
        info.append({
            "name": name,
            "description": cls.description,
            "tier": cls.tier,
            "interval": cls.default_interval,
        })
    return info


class AgentManager:
    def __init__(self, app=None):
        self._app = app
        self._agents = {}

    def start(self, name, interval=None):
        if name in self._agents and self._agents[name].is_running:
            return False, f"{name} already running"
        cls = get_agent_class(name)
        if not cls:
            return False, f"Unknown agent: {name}"
        agent = cls(app=self._app)
        self._agents[name] = agent
        agent.start_loop(interval)
        return True, f"{name} started (interval={interval or agent.default_interval}s)"

    def stop(self, name):
        if name not in self._agents:
            return False, f"{name} not active"
        self._agents[name].stop_loop()
        return True, f"{name} stopped"

    def run_once(self, name):
        cls = get_agent_class(name)
        if not cls:
            return None, f"Unknown agent: {name}"
        agent = cls(app=self._app)
        self._agents[name] = agent
        result = agent.run()
        return result, None

    def stop_all(self):
        for name, agent in self._agents.items():
            agent.stop_loop()
        return True

    def status(self):
        rows = []
        for name in _registry:
            agent = self._agents.get(name)
            running = agent.is_running if agent else False
            last = agent.last_result if agent else None
            result_file = RESULTS_DIR / f"{name}.json"
            if not last and result_file.exists():
                try:
                    last_data = json.loads(result_file.read_text())
                    last_time = last_data.get("run_time", "?")
                    last_ok = last_data.get("success", False)
                    findings = len(last_data.get("findings", []))
                except Exception:
                    last_time, last_ok, findings = "?", False, 0
            elif last:
                last_time = last.run_time
                last_ok = last.success
                findings = len(last.findings)
            else:
                last_time, last_ok, findings = "never", None, 0

            rows.append({
                "name": name,
                "running": running,
                "last_run": last_time,
                "last_ok": last_ok,
                "findings": findings,
                "tier": _registry[name].tier,
            })
        return rows

    def start_tier(self, tier):
        started = []
        for name, cls in _registry.items():
            if cls.tier == tier:
                ok, msg = self.start(name)
                if ok:
                    started.append(name)
        return started

    def start_all(self):
        started = []
        for name in _registry:
            ok, msg = self.start(name)
            if ok:
                started.append(name)
        return started
