"""Agent 12: Risk & Drift Detector -- stale projects, TODO inflation, repeated failures, scope creep."""

import json
from datetime import datetime

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class RiskDriftAgent(BaseAgent):
    name = "risk_drift"
    description = "Flags stale projects, climbing TODOs, repeated failures, scope creep, estimate drift"
    default_interval = 86400
    tier = "management"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    TODO_GROWTH_THRESHOLD = 5
    STALE_DAYS_WARN = 14
    STALE_DAYS_CRIT = 30

    def check(self) -> AgentResult:
        findings = []

        for proj in self.PROJECTS:
            findings.extend(self._check_staleness(proj))
            findings.extend(self._check_todo_trajectory(proj))
            findings.extend(self._check_scope_creep(proj))
            findings.extend(self._check_error_patterns(proj))

        risks = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{risks} risks detected across {len(self.PROJECTS)} projects",
        )

    def _check_staleness(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, stderr, rc = self.ssh(
            f"cd {path} && git log -1 --format=%aI 2>/dev/null",
            timeout=10,
        )
        if rc != 0 or not stdout.strip():
            return findings

        try:
            last = datetime.fromisoformat(stdout.strip().replace("Z", "+00:00"))
            age = (datetime.now(last.tzinfo) - last).days
        except Exception:
            return findings

        stdout2, _, _ = self.ssh(
            f"grep -c '\\- \\[ \\]' {path}/TODO.md 2>/dev/null || echo 0",
            timeout=10,
        )
        try:
            open_todos = int(stdout2.strip())
        except ValueError:
            open_todos = 0

        if age >= self.STALE_DAYS_CRIT and open_todos > 0:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="risk_drift",
                message=f"{proj}: {age} days stale with {open_todos} open TODOs -- at risk of abandonment",
                host="linux-host",
            ))
        elif age >= self.STALE_DAYS_WARN and open_todos > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="risk_drift",
                message=f"{proj}: {age} days since last commit, {open_todos} TODOs remaining",
                host="linux-host",
            ))
        elif age >= self.STALE_DAYS_CRIT and open_todos == 0:
            findings.append(Finding(
                severity=Severity.LOW,
                source="risk_drift",
                message=f"{proj}: inactive {age} days but no open TODOs -- may be complete",
                host="linux-host",
            ))

        return findings

    def _check_todo_trajectory(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, stderr, rc = self.ssh(
            f"cd {path} && git log --all --oneline --diff-filter=M -- TODO.md 2>/dev/null | wc -l",
            timeout=10,
        )
        try:
            edit_count = int(stdout.strip())
        except ValueError:
            return findings

        if edit_count < 2:
            return findings

        stdout2, _, rc2 = self.ssh(
            f"cd {path} && git log -1 --format=%H -- TODO.md 2>/dev/null",
            timeout=10,
        )
        if rc2 != 0 or not stdout2.strip():
            return findings

        latest_hash = stdout2.strip()
        stdout3, _, _ = self.ssh(
            f"cd {path} && git show {latest_hash}:TODO.md 2>/dev/null | grep -c '\\- \\[ \\]' || echo 0",
            timeout=10,
        )
        stdout4, _, _ = self.ssh(
            f"cd {path} && git log --reverse --format=%H -- TODO.md 2>/dev/null | head -1",
            timeout=10,
        )
        if stdout4.strip():
            first_hash = stdout4.strip()
            stdout5, _, _ = self.ssh(
                f"cd {path} && git show {first_hash}:TODO.md 2>/dev/null | grep -c '\\- \\[ \\]' || echo 0",
                timeout=10,
            )
            try:
                current_open = int(stdout3.strip())
                original_open = int(stdout5.strip())
                growth = current_open - original_open
                if growth > self.TODO_GROWTH_THRESHOLD:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        source="risk_drift",
                        message=f"{proj}: TODO count grew by {growth} (scope creep signal)",
                        details=f"Started with {original_open} open, now {current_open}",
                        host="linux-host",
                    ))
            except ValueError:
                pass

        return findings

    def _check_scope_creep(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, _, rc = self.ssh(
            f"cd {path} && git log --since='30 days ago' --oneline 2>/dev/null | wc -l",
            timeout=10,
        )
        try:
            recent_commits = int(stdout.strip())
        except ValueError:
            return findings

        stdout2, _, _ = self.ssh(
            f"cd {path} && git log --since='30 days ago' --numstat 2>/dev/null "
            f"| awk '/^[0-9]/ {{added+=$1; deleted+=$2}} END {{print added, deleted}}'",
            timeout=10,
        )
        parts = stdout2.strip().split()
        if len(parts) >= 2:
            try:
                added = int(parts[0])
                deleted = int(parts[1])
                if recent_commits > 0 and added > 0:
                    churn_ratio = deleted / added if added > 0 else 0
                    if churn_ratio > 0.8 and added > 200:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            source="risk_drift",
                            message=f"{proj}: high churn -- {added} lines added, {deleted} deleted in 30d",
                            details="High delete/add ratio suggests rework or thrashing",
                            host="linux-host",
                        ))
            except ValueError:
                pass

        return findings

    def _check_error_patterns(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, _, rc = self.ssh(
            f"cd {path} && git log --since='7 days ago' --oneline 2>/dev/null "
            f"| grep -ic 'fix\\|bug\\|revert\\|broken\\|hotfix' || echo 0",
            timeout=10,
        )
        try:
            fix_count = int(stdout.strip())
        except ValueError:
            return findings

        if fix_count >= 3:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="risk_drift",
                message=f"{proj}: {fix_count} fix/revert commits in 7 days -- stability concern",
                host="linux-host",
            ))

        return findings
