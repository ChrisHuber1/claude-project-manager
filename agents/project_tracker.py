"""Agent 9: Project Tracker -- git hygiene, TODO progress, stale branches, recommendations."""

import json
from datetime import datetime

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class ProjectTrackerAgent(BaseAgent):
    name = "project_tracker"
    description = "Git hygiene, TODO progress, stale branches, dependency freshness, recommendations"
    default_interval = 86400
    tier = "management"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    def check(self) -> AgentResult:
        findings = []

        for proj in self.PROJECTS:
            findings.extend(self._check_git_hygiene(proj))
            findings.extend(self._check_todo_progress(proj))
            findings.extend(self._check_stale_branches(proj))

        dirty = sum(1 for f in findings if "uncommitted" in f.message.lower())
        stale = sum(1 for f in findings if "stale" in f.message.lower())

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{dirty} dirty, {stale} stale across {len(self.PROJECTS)} projects",
        )

    def _check_git_hygiene(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, stderr, rc = self.ssh(
            f"cd {path} && git status --porcelain 2>/dev/null",
            timeout=10,
        )
        if rc != 0:
            return findings

        if stdout.strip():
            lines = stdout.strip().split("\n")
            untracked = sum(1 for l in lines if l.startswith("??"))
            modified = sum(1 for l in lines if l.startswith(" M") or l.startswith("M "))
            parts = []
            if modified:
                parts.append(f"{modified} modified")
            if untracked:
                parts.append(f"{untracked} untracked")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="project_tracker",
                message=f"{proj}: uncommitted changes ({', '.join(parts)})",
                host="linux-host",
            ))

        stdout2, stderr2, rc2 = self.ssh(
            f"cd {path} && git log -1 --format=%aI 2>/dev/null",
            timeout=10,
        )
        if rc2 == 0 and stdout2.strip():
            try:
                last = datetime.fromisoformat(stdout2.strip().replace("Z", "+00:00"))
                age = (datetime.now(last.tzinfo) - last).days
                if age > 14:
                    findings.append(Finding(
                        severity=Severity.LOW if age < 30 else Severity.MEDIUM,
                        source="project_tracker",
                        message=f"{proj}: stale -- last commit {age} days ago",
                        host="linux-host",
                    ))
            except Exception:
                pass

        return findings

    def _check_todo_progress(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, stderr, rc = self.ssh(
            f"cat {path}/TODO.md 2>/dev/null",
            timeout=10,
        )
        if rc != 0 or not stdout.strip():
            return findings

        total = 0
        done = 0
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("- [ ]"):
                total += 1
            elif line.startswith("- [x]") or line.startswith("- [X]"):
                total += 1
                done += 1

        if total == 0:
            return findings

        pct = done / total * 100
        if pct >= 90:
            findings.append(Finding(
                severity=Severity.INFO,
                source="project_tracker",
                message=f"{proj}: nearly done -- {done}/{total} TODOs ({pct:.0f}%)",
                host="linux-host",
            ))
        elif pct >= 50:
            findings.append(Finding(
                severity=Severity.INFO,
                source="project_tracker",
                message=f"{proj}: {done}/{total} TODOs ({pct:.0f}%)",
                host="linux-host",
            ))
        else:
            remaining = total - done
            findings.append(Finding(
                severity=Severity.LOW,
                source="project_tracker",
                message=f"{proj}: {remaining} TODOs remaining ({pct:.0f}% done)",
                host="linux-host",
            ))

        return findings

    def _check_stale_branches(self, proj):
        findings = []
        path = f"~/{proj}"

        stdout, stderr, rc = self.ssh(
            f"cd {path} && git branch --list 2>/dev/null | wc -l",
            timeout=10,
        )
        try:
            branch_count = int(stdout.strip())
        except ValueError:
            return findings

        if branch_count > 5:
            findings.append(Finding(
                severity=Severity.LOW,
                source="project_tracker",
                message=f"{proj}: {branch_count} branches -- consider cleanup",
                host="linux-host",
            ))

        return findings
