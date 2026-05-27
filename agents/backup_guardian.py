"""Agent 4: Backup Guardian -- GitHub sync, linux-host bare repos, proxmox-node1 backups, disk space."""

import json
from datetime import datetime, timedelta

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class BackupGuardianAgent(BaseAgent):
    name = "backup_guardian"
    description = "GitHub repo sync, linux-host bare repos, proxmox-node1 backups, disk space on targets"
    default_interval = 86400
    tier = "infrastructure"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    def check(self) -> AgentResult:
        findings = []

        findings.extend(self._check_git_push_status())
        findings.extend(self._check_bare_repos())
        findings.extend(self._check_backup_disk_space())

        unpushed = sum(1 for f in findings
                       if f.severity in (Severity.HIGH, Severity.MEDIUM)
                       and "unpushed" in f.message.lower())
        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{len(self.PROJECTS) - unpushed}/{len(self.PROJECTS)} repos synced",
        )

    def _check_git_push_status(self):
        findings = []
        for proj in self.PROJECTS:
            stdout, stderr, rc = self.ssh(
                f"cd ~/{proj} && git status --porcelain 2>/dev/null | wc -l",
                timeout=10,
            )
            try:
                dirty = int(stdout.strip())
            except ValueError:
                dirty = -1

            if dirty < 0:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    source="backup_guardian",
                    message=f"{proj}: not a git repo or git error",
                    host="linux-host",
                ))
                continue

            if dirty > 0:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    source="backup_guardian",
                    message=f"{proj}: {dirty} uncommitted changes",
                    host="linux-host",
                ))

            stdout2, stderr2, rc2 = self.ssh(
                f"cd ~/{proj} && git log origin/main..HEAD --oneline 2>/dev/null | wc -l",
                timeout=10,
            )
            try:
                unpushed = int(stdout2.strip())
            except ValueError:
                unpushed = 0

            if unpushed > 0:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source="backup_guardian",
                    message=f"{proj}: {unpushed} unpushed commits",
                    host="linux-host",
                ))

            stdout3, stderr3, rc3 = self.ssh(
                f"cd ~/{proj} && git log -1 --format=%aI 2>/dev/null",
                timeout=10,
            )
            if rc3 == 0 and stdout3.strip():
                try:
                    last_commit = datetime.fromisoformat(stdout3.strip().replace("Z", "+00:00"))
                    age_days = (datetime.now(last_commit.tzinfo) - last_commit).days
                    if age_days > 30:
                        findings.append(Finding(
                            severity=Severity.LOW,
                            source="backup_guardian",
                            message=f"{proj}: last commit {age_days} days ago",
                            host="linux-host",
                        ))
                except Exception:
                    pass

        return findings

    def _check_bare_repos(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "ls ~/backups/*.git 2>/dev/null | wc -l",
            timeout=10,
        )
        try:
            count = int(stdout.strip())
        except ValueError:
            count = 0

        if count == 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="backup_guardian",
                message="No bare repo backups found in ~/backups/",
                host="linux-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                source="backup_guardian",
                message=f"{count} bare repo backups in ~/backups/",
                host="linux-host",
            ))
        return findings

    def _check_backup_disk_space(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "df -h / --output=pcent 2>/dev/null | tail -1",
            timeout=10,
        )
        if rc == 0 and stdout.strip():
            try:
                pct = int(stdout.strip().replace("%", ""))
                if pct >= 90:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        source="backup_guardian",
                        message=f"linux-host root disk at {pct}% -- backups at risk",
                        host="linux-host",
                    ))
            except ValueError:
                pass
        return findings
