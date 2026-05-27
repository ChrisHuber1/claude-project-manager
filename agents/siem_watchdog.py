"""Agent 3: SIEM Watchdog -- Wazuh services, triage bot health, critical alert forwarding."""

import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity, STATE_DIR
from agents.runner import register


SIEM_SSH_KEY = Path.home() / "MyProject" / ".secrets" / "ssh" / "id_your_key"
RESTART_STATE_FILE = STATE_DIR / "siem_restart_count.json"
MAX_RESTARTS_PER_DAY = 2


@register
class SIEMWatchdogAgent(BaseAgent):
    name = "siem_watchdog"
    description = "Wazuh services health, triage bot output, CRITICAL alert forwarding"
    default_interval = 1800
    tier = "infrastructure"

    SIEM_HOST = "YOUR_SIEM_IP"
    SIEM_USER = "YOUR_SSH_USER"
    WAZUH_SERVICES = ["wazuh-manager", "wazuh-indexer", "wazuh-dashboard"]

    def check(self) -> AgentResult:
        findings = []

        findings.extend(self._check_wazuh_services())
        findings.extend(self._check_triage_bot())
        findings.extend(self._check_recent_alerts())

        summary_parts = []
        svc_ok = sum(1 for f in findings if f.source == "wazuh_services" and f.severity == Severity.INFO)
        summary_parts.append(f"{svc_ok}/{len(self.WAZUH_SERVICES)} services up")

        if svc_ok == len(self.WAZUH_SERVICES):
            self._clear_ntfy_cooldown()
            self._reset_restart_counts()

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=", ".join(summary_parts),
        )

    def _siem_ssh(self, command, timeout=15):
        """SSH to siem-host as YOUR_SSH_USER (has sudo) using the id_your_key key."""
        import os
        if os.environ.get("AGENT_LOCAL_MODE"):
            cmd = [
                "ssh",
                "-i", str(SIEM_SSH_KEY),
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={timeout}",
                f"{self.SIEM_USER}@{self.SIEM_HOST}",
                command,
            ]
        else:
            from config import OPS1_HOST, OPS1_USER, OPS1_SSH_KEY
            cmd = [
                "ssh", "-i", OPS1_SSH_KEY,
                "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                f"{OPS1_USER}@{OPS1_HOST}",
                f"ssh -i {SIEM_SSH_KEY} -o StrictHostKeyChecking=accept-new "
                f"-o BatchMode=yes -o ConnectTimeout={timeout} "
                f"{self.SIEM_USER}@{self.SIEM_HOST} '{command}'",
            ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
            return r.stdout, r.stderr, r.returncode
        except Exception as e:
            return "", str(e), 1

    def _get_restart_counts(self):
        try:
            if RESTART_STATE_FILE.exists():
                return json.loads(RESTART_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save_restart_counts(self, counts):
        try:
            RESTART_STATE_FILE.write_text(json.dumps(counts, indent=2))
        except OSError:
            pass

    def _reset_restart_counts(self):
        try:
            RESTART_STATE_FILE.unlink(missing_ok=True)
        except OSError:
            pass

    def _can_restart(self, service):
        counts = self._get_restart_counts()
        entry = counts.get(service, {})
        count = entry.get("count", 0)
        first = entry.get("first_attempt", "")
        if count >= MAX_RESTARTS_PER_DAY and first:
            try:
                first_dt = datetime.fromisoformat(first)
                if (datetime.now() - first_dt).total_seconds() < 86400:
                    return False
            except ValueError:
                pass
        return True

    def _record_restart(self, service):
        counts = self._get_restart_counts()
        entry = counts.get(service, {"count": 0, "first_attempt": ""})
        if entry["count"] == 0 or not entry.get("first_attempt"):
            entry["first_attempt"] = datetime.now().isoformat()
        entry["count"] = entry.get("count", 0) + 1
        entry["last_attempt"] = datetime.now().isoformat()
        counts[service] = entry
        self._save_restart_counts(counts)

    def _attempt_restart(self, service):
        """Clear stale PIDs and restart a Wazuh service. Returns (success, new_status)."""
        if not self._can_restart(service):
            return False, "restart limit reached (2/day)"

        self._record_restart(service)

        if service == "wazuh-manager":
            self._siem_ssh("sudo rm -f /var/ossec/var/run/*.pid", timeout=10)

        self._siem_ssh(f"sudo systemctl restart {service}", timeout=30)
        time.sleep(5)

        stdout, _, rc = self._siem_ssh(f"systemctl is-active {service}", timeout=10)
        new_status = stdout.strip()
        return new_status == "active", new_status

    def _check_wazuh_services(self):
        findings = []
        for svc in self.WAZUH_SERVICES:
            stdout, stderr, rc = self._siem_ssh(
                f"systemctl is-active {svc} 2>/dev/null", timeout=10,
            )
            status = stdout.strip()

            if rc != 0 and not status:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    source="siem_watchdog",
                    message=f"Cannot reach siem-host to check {svc}",
                    details=stderr[:200],
                    host="siem-host",
                ))
                continue

            if status == "active":
                findings.append(Finding(
                    severity=Severity.INFO,
                    source="wazuh_services",
                    message=f"{svc}: active",
                    host="siem-host",
                ))
                continue

            restarted, new_status = self._attempt_restart(svc)
            if restarted:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source="siem_watchdog",
                    message=f"{svc} was DOWN ({status}), auto-restarted successfully",
                    host="siem-host",
                ))
            else:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    source="siem_watchdog",
                    message=f"Wazuh service DOWN: {svc} ({status}). "
                            f"Auto-restart failed: {new_status}",
                    host="siem-host",
                ))
        return findings

    def _check_triage_bot(self):
        findings = []
        today = datetime.now().strftime("%Y-%m-%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        stdout, stderr, rc = self.ssh(
            f"ls ~/siem-logs/{today}.html ~/siem-logs/{yesterday}.html 2>/dev/null | wc -l",
            timeout=10,
        )
        try:
            count = int(stdout.strip())
        except ValueError:
            count = 0

        if count == 0:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="siem_watchdog",
                message="Triage bot: no reports for today or yesterday",
                host="linux-host",
            ))
        elif count == 1:
            findings.append(Finding(
                severity=Severity.INFO,
                source="siem_watchdog",
                message="Triage bot: report found for recent day",
                host="linux-host",
            ))

        stdout2, stderr2, rc2 = self.ssh(
            "systemctl is-active siem-triage.timer 2>/dev/null",
            timeout=10,
        )
        timer_status = stdout2.strip()
        if timer_status != "active":
            findings.append(Finding(
                severity=Severity.HIGH,
                source="siem_watchdog",
                message=f"siem-triage.timer is {timer_status or 'not found'}",
                host="linux-host",
            ))

        return findings

    def _check_recent_alerts(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "tail -100 /var/ossec/logs/alerts/alerts.log 2>/dev/null "
            "| grep -c 'level.*1[0-5]' || echo 0",
            host=self.SIEM_HOST, timeout=10,
        )
        try:
            high_alerts = int(stdout.strip())
        except ValueError:
            high_alerts = 0

        if high_alerts > 20:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="siem_watchdog",
                message=f"Wazuh: {high_alerts} high-severity alerts in recent log tail",
                host="siem-host",
            ))
        elif high_alerts > 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="siem_watchdog",
                message=f"Wazuh: {high_alerts} high-severity alerts (normal range)",
                host="siem-host",
            ))

        return findings
