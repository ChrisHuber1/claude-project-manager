"""Agent 14: Daily Briefing -- pre-session briefing with overnight changes, alerts, recommendations."""

import json
from datetime import datetime, timedelta

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity, RESULTS_DIR
from agents.runner import register


@register
class DailyBriefingAgent(BaseAgent):
    name = "daily_briefing"
    description = "Pre-session briefing: overnight changes, alerts, cron results, recommended focus"
    default_interval = 86400
    tier = "session"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    def check(self) -> AgentResult:
        findings = []
        sections = {}

        sections["overnight_changes"] = self._check_overnight_changes()
        sections["agent_alerts"] = self._check_agent_results()
        sections["cron_health"] = self._check_cron_health()
        sections["recommendation"] = self._build_recommendation()

        for section_name, section_findings in sections.items():
            findings.extend(section_findings)

        briefing = self._format_briefing(sections)

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=briefing[:200],
        )

    def _check_overnight_changes(self):
        findings = []
        for proj in self.PROJECTS:
            stdout, stderr, rc = self.ssh(
                f"cd ~/{proj} && git log --since='24 hours ago' --oneline 2>/dev/null",
                timeout=10,
            )
            if rc == 0 and stdout.strip():
                commits = stdout.strip().split("\n")
                findings.append(Finding(
                    severity=Severity.INFO,
                    source="daily_briefing",
                    message=f"{proj}: {len(commits)} new commits in 24h",
                    details="\n".join(commits[:5]),
                    host="linux-host",
                ))
        return findings

    def _check_agent_results(self):
        findings = []
        agent_names = [
            "range_health", "security_monitor", "siem_watchdog",
            "backup_guardian", "security_scanner",
        ]
        for name in agent_names:
            result_file = RESULTS_DIR / f"{name}.json"
            if not result_file.exists():
                continue
            try:
                data = json.loads(result_file.read_text())
                critical = sum(1 for f in data.get("findings", [])
                               if f.get("severity") == "CRITICAL")
                high = sum(1 for f in data.get("findings", [])
                           if f.get("severity") == "HIGH")
                if critical > 0:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        source="daily_briefing",
                        message=f"Agent {name}: {critical} CRITICAL findings outstanding",
                        host="linux-host",
                    ))
                elif high > 0:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        source="daily_briefing",
                        message=f"Agent {name}: {high} HIGH findings outstanding",
                        host="linux-host",
                    ))
            except Exception:
                pass
        return findings

    def _check_cron_health(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "journalctl --since '24 hours ago' -u cron --no-pager 2>/dev/null "
            "| grep -c 'FAILED\\|error\\|Error' || echo 0",
            timeout=10,
        )
        try:
            failures = int(stdout.strip())
        except ValueError:
            failures = 0

        if failures > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="daily_briefing",
                message=f"{failures} cron failures in last 24h",
                host="linux-host",
            ))

        today = datetime.now().strftime("%Y-%m-%d")
        stdout2, _, rc2 = self.ssh(
            f"test -f ~/siem-logs/{today}.html && echo ok || echo missing",
            timeout=5,
        )
        if "missing" in stdout2:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="daily_briefing",
                message="Today's SIEM triage report not yet generated",
                host="linux-host",
            ))

        return findings

    def _build_recommendation(self):
        findings = []
        project_scores = {}

        for proj in self.PROJECTS:
            score = 0
            reasons = []

            stdout, _, rc = self.ssh(
                f"cd ~/{proj} && git log -1 --format=%aI 2>/dev/null",
                timeout=10,
            )
            if rc == 0 and stdout.strip():
                try:
                    last = datetime.fromisoformat(stdout.strip().replace("Z", "+00:00"))
                    age = (datetime.now(last.tzinfo) - last).days
                    if age < 3:
                        score += 20
                        reasons.append("active momentum")
                    elif age > 14:
                        score -= 10
                except Exception:
                    pass

            stdout2, _, _ = self.ssh(
                f"grep -c '\\- \\[ \\]' ~/{proj}/TODO.md 2>/dev/null || echo 0",
                timeout=10,
            )
            stdout3, _, _ = self.ssh(
                f"grep -c '\\- \\[x\\]\\|\\- \\[X\\]' ~/{proj}/TODO.md 2>/dev/null || echo 0",
                timeout=10,
            )
            try:
                open_t = int(stdout2.strip())
                done_t = int(stdout3.strip())
                total = open_t + done_t
                if total > 0:
                    pct = done_t / total
                    if pct >= 0.7:
                        score += 30
                        reasons.append(f"{pct:.0%} complete -- close to finish")
            except ValueError:
                pass

            project_scores[proj] = (score, reasons)

        if project_scores:
            top_proj = max(project_scores, key=lambda k: project_scores[k][0])
            score, reasons = project_scores[top_proj]
            if score > 0:
                findings.append(Finding(
                    severity=Severity.INFO,
                    source="daily_briefing",
                    message=f"Recommended focus: {top_proj} ({'; '.join(reasons)})",
                    host="linux-host",
                ))

        return findings

    def _format_briefing(self, sections):
        parts = []
        overnight = sections.get("overnight_changes", [])
        if overnight:
            changed = [f.message for f in overnight]
            parts.append(f"Overnight: {len(changed)} projects with changes")
        else:
            parts.append("Overnight: no changes")

        alerts = sections.get("agent_alerts", [])
        critical = sum(1 for f in alerts if f.severity == Severity.CRITICAL)
        high = sum(1 for f in alerts if f.severity == Severity.HIGH)
        if critical or high:
            parts.append(f"Alerts: {critical} critical, {high} high")
        else:
            parts.append("Alerts: all clear")

        rec = sections.get("recommendation", [])
        if rec:
            parts.append(rec[0].message)

        return " | ".join(parts)
