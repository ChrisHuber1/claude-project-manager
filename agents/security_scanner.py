"""Agent 7: Security Scanner -- SAST, dependency CVEs, secrets detection, OWASP."""

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class SecurityScannerAgent(BaseAgent):
    name = "security_scanner"
    description = "SAST, dependency CVEs, secrets detection, OWASP checks"
    default_interval = 86400
    tier = "development"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    SECRET_PATTERNS = [
        r"AKIA[0-9A-Z]{16}",
        r"sk-ant-[a-zA-Z0-9_-]{20,}",
        r"ghp_[a-zA-Z0-9]{36}",
        r"-----BEGIN.*PRIVATE KEY-----",
        r"password\s*=\s*['\"][^'\"]{8,}",
        r"api_key\s*=\s*['\"][^'\"]{8,}",
        r"secret\s*=\s*['\"][^'\"]{8,}",
    ]

    def check(self, project=None) -> AgentResult:
        findings = []
        projects = [project] if project else self.PROJECTS

        for proj in projects:
            proj_path = f"~/{proj}"
            stack = self.detect_stack(proj_path)
            findings.extend(self._scan_secrets(proj, proj_path))
            findings.extend(self._scan_dependencies(proj, proj_path, stack))
            findings.extend(self._scan_sast(proj, proj_path, stack))

        vulns = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{vulns} vulnerabilities across {len(projects)} projects",
        )

    def _scan_secrets(self, proj, path):
        findings = []
        for pattern in self.SECRET_PATTERNS:
            stdout, stderr, rc = self.ssh(
                f"grep -rnl --include='*.py' --include='*.js' --include='*.ts' "
                f"--include='*.yaml' --include='*.yml' --include='*.json' "
                f"--include='*.sh' --include='*.env' "
                f"-E '{pattern}' {path}/ 2>/dev/null "
                f"| grep -v node_modules | grep -v venv | grep -v .git | head -5",
                timeout=15,
            )
            if rc == 0 and stdout.strip():
                files = stdout.strip().split("\n")
                for f in files:
                    rel = f.replace(path + "/", "")
                    if ".env.example" in rel or "test" in rel.lower():
                        continue
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        source="security_scanner",
                        message=f"{proj}: potential secret in {rel}",
                        details=f"Pattern matched: {pattern[:30]}...",
                        host="linux-host",
                    ))
        return findings

    def _scan_dependencies(self, proj, path, stack):
        findings = []
        langs = stack.get("languages", [])

        if "python" in langs:
            stdout, stderr, rc = self.ssh(
                f"cd {path} && pip-audit -r requirements.txt --format=json 2>/dev/null",
                timeout=30,
            )
            if rc is not None and stdout.strip():
                try:
                    import json
                    data = json.loads(stdout.strip())
                    vulns = data.get("dependencies", [])
                    for dep in vulns:
                        dep_name = dep.get("name", "?")
                        for vuln in dep.get("vulns", []):
                            vuln_id = vuln.get("id", "?")
                            fix = vuln.get("fix_versions", [])
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                source="security_scanner",
                                message=f"{proj}: {dep_name} -- {vuln_id}",
                                details=f"Fix: {', '.join(fix)}" if fix else "",
                                host="linux-host",
                            ))
                except Exception:
                    pass

            if not findings:
                stdout2, stderr2, rc2 = self.ssh(
                    f"cd {path} && pip-audit -r requirements.txt 2>/dev/null | tail -5",
                    timeout=30,
                )
                if rc2 != 0 and "found" in (stdout2 + stderr2).lower():
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        source="security_scanner",
                        message=f"{proj}: pip-audit found vulnerabilities",
                        details=(stdout2 + stderr2).strip()[:300],
                        host="linux-host",
                    ))

        if "javascript" in langs or "typescript" in langs:
            stdout, stderr, rc = self.ssh(
                f"cd {path} && npm audit --json 2>/dev/null | head -100",
                timeout=30,
            )
            if rc != 0 and stdout.strip():
                try:
                    import json
                    data = json.loads(stdout.strip())
                    summary = data.get("metadata", {}).get("vulnerabilities", {})
                    critical = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    if critical > 0:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            source="security_scanner",
                            message=f"{proj}: {critical} critical npm vulnerabilities",
                            host="linux-host",
                        ))
                    if high > 0:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            source="security_scanner",
                            message=f"{proj}: {high} high npm vulnerabilities",
                            host="linux-host",
                        ))
                except Exception:
                    pass

        return findings

    def _scan_sast(self, proj, path, stack):
        findings = []

        if "python" in stack.get("languages", []):
            stdout, stderr, rc = self.ssh(
                f"which bandit >/dev/null 2>&1 && "
                f"bandit -r {path} -ll --format json -x {path}/venv,{path}/.venv 2>/dev/null | "
                f"python3 -c \"import sys,json; d=json.load(sys.stdin); "
                f"print(len(d.get('results',[])))\" 2>/dev/null",
                timeout=30,
            )
            try:
                issues = int(stdout.strip())
            except ValueError:
                issues = 0

            if issues > 0:
                findings.append(Finding(
                    severity=Severity.HIGH if issues > 5 else Severity.MEDIUM,
                    source="security_scanner",
                    message=f"{proj}: {issues} bandit security issues",
                    host="linux-host",
                ))

        stdout, stderr, rc = self.ssh(
            f"which gitleaks >/dev/null 2>&1 && "
            f"gitleaks detect --source={path} --no-git --quiet 2>/dev/null; echo $?",
            timeout=30,
        )
        if stdout.strip().endswith("1"):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source="security_scanner",
                message=f"{proj}: gitleaks detected secrets in source",
                host="linux-host",
            ))

        return findings
