"""Agent 11: Cross-Project Intelligence -- dependency graph, shared patterns, unblock chains."""

import json
from collections import defaultdict

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


KNOWN_DEPENDENCIES = {
    "FirewallManager": ["SecurityAuditProject"],
    "siem-triage": ["siem"],
    "network-schema": ["MyProject"],
}

KNOWN_SHARED_INFRA = {
    "environment_files": ["MyProject", "siem", "VPNProject", "FirewallManager"],
    "inventory_yml": ["MyProject", "siem", "FirewallManager"],
    "wireguard": ["VPNProject", "siem"],
    "opnsense_api": ["FirewallManager", "VPNProject", "MyProject"],
    "dns-host": ["VPNProject", "siem"],
}


@register
class CrossProjectIntelAgent(BaseAgent):
    name = "cross_project_intel"
    description = "Dependency graph, shared patterns, duplicate work, unblock chain analysis"
    default_interval = 86400
    tier = "management"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    def check(self) -> AgentResult:
        findings = []

        findings.extend(self._check_dependency_health())
        findings.extend(self._check_shared_file_drift())
        findings.extend(self._check_cross_references())
        findings.extend(self._build_recommendation())

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{len(findings)} cross-project insights",
        )

    def _check_dependency_health(self):
        findings = []
        for proj, deps in KNOWN_DEPENDENCIES.items():
            for dep in deps:
                stdout, stderr, rc = self.ssh(
                    f"cd ~/{dep} && git log -1 --format=%aI 2>/dev/null",
                    timeout=10,
                )
                dep_stdout, _, dep_rc = self.ssh(
                    f"cd ~/{proj} && git log -1 --format=%aI 2>/dev/null",
                    timeout=10,
                )

                if rc == 0 and dep_rc == 0 and stdout.strip() and dep_stdout.strip():
                    from datetime import datetime
                    try:
                        dep_time = datetime.fromisoformat(stdout.strip().replace("Z", "+00:00"))
                        proj_time = datetime.fromisoformat(dep_stdout.strip().replace("Z", "+00:00"))
                        if dep_time > proj_time:
                            diff = (dep_time - proj_time).days
                            if diff > 3:
                                findings.append(Finding(
                                    severity=Severity.MEDIUM,
                                    source="cross_project_intel",
                                    message=f"{dep} updated {diff}d after {proj} -- may have unsynced changes",
                                    host="linux-host",
                                ))
                    except Exception:
                        pass

                stdout2, stderr2, rc2 = self.ssh(
                    f"test -d ~/{dep} && echo exists || echo missing",
                    timeout=5,
                )
                if "missing" in stdout2:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        source="cross_project_intel",
                        message=f"{proj} depends on {dep} but {dep} directory is missing",
                        host="linux-host",
                    ))
        return findings

    def _check_shared_file_drift(self):
        findings = []
        for resource, projects in KNOWN_SHARED_INFRA.items():
            if resource == "environment_files":
                stdout, _, rc = self.ssh(
                    "ls -la ~/credentials/ 2>/dev/null | wc -l",
                    timeout=5,
                )
                try:
                    count = int(stdout.strip())
                except ValueError:
                    count = 0
                if count < 2:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        source="cross_project_intel",
                        message=f"Shared environment files missing -- affects {len(projects)} projects",
                        host="linux-host",
                    ))
        return findings

    def _check_cross_references(self):
        findings = []
        blockers = defaultdict(list)

        for proj in self.PROJECTS:
            stdout, stderr, rc = self.ssh(
                f"grep -rh 'blocker\\|blocked by\\|depends on\\|waiting for' "
                f"~/{proj}/TODO.md ~/{proj}/SESSION_NOTES.md 2>/dev/null | head -5",
                timeout=10,
            )
            if rc == 0 and stdout.strip():
                for line in stdout.strip().split("\n"):
                    line = line.strip().lower()
                    for other in self.PROJECTS:
                        if other.lower() in line and other != proj:
                            blockers[proj].append(other)

        for proj, blocked_by in blockers.items():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="cross_project_intel",
                message=f"{proj} references {', '.join(blocked_by)} as dependency/blocker",
                host="linux-host",
            ))

        return findings

    def _build_recommendation(self):
        findings = []
        unblock_scores = defaultdict(int)

        for proj, deps in KNOWN_DEPENDENCIES.items():
            for dep in deps:
                unblock_scores[dep] += 1

        if unblock_scores:
            top = max(unblock_scores, key=unblock_scores.get)
            count = unblock_scores[top]
            if count > 0:
                findings.append(Finding(
                    severity=Severity.INFO,
                    source="cross_project_intel",
                    message=f"Completing {top} would unblock {count} other project(s)",
                    host="linux-host",
                ))

        return findings
