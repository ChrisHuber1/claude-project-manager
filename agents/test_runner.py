"""Agent 6: Test Runner -- run test suites, track coverage, flag regressions."""

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class TestRunnerAgent(BaseAgent):
    name = "test_runner"
    description = "Run test suites, track coverage, flag regressions"
    default_interval = 0
    tier = "development"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    def check(self, project=None) -> AgentResult:
        findings = []
        projects = [project] if project else self.PROJECTS

        for proj in projects:
            proj_path = f"~/{proj}"
            stack = self.detect_stack(proj_path)
            proj_findings = self._run_tests(proj, proj_path, stack)
            findings.extend(proj_findings)

        passed = sum(1 for f in findings if f.severity == Severity.INFO and "passed" in f.message.lower())
        failed = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{passed} passed, {failed} failed across {len(projects)} projects",
        )

    def _run_tests(self, proj, path, stack):
        findings = []
        langs = stack.get("languages", [])

        if "python" in langs:
            findings.extend(self._run_pytest(proj, path))
        if "javascript" in langs or "typescript" in langs:
            findings.extend(self._run_jest(proj, path))
        if "rust" in langs:
            findings.extend(self._run_cargo_test(proj, path))
        if "go" in langs:
            findings.extend(self._run_go_test(proj, path))

        if not findings:
            has_tests, _ = self._has_test_files(proj, path)
            if not has_tests:
                findings.append(Finding(
                    severity=Severity.LOW,
                    source="test_runner",
                    message=f"{proj}: no test files found",
                    host="linux-host",
                ))

        return findings

    def _has_test_files(self, proj, path):
        stdout, stderr, rc = self.ssh(
            f"find {path} -name 'test_*' -o -name '*_test.*' -o -name '*.test.*' "
            f"-o -name 'tests.py' -o -name 'spec_*' 2>/dev/null "
            f"| grep -v node_modules | grep -v venv | head -5",
            timeout=10,
        )
        files = [l for l in stdout.strip().split("\n") if l.strip()] if stdout.strip() else []
        return len(files) > 0, files

    def _run_pytest(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && python3 -m pytest --tb=short --no-header -q 2>/dev/null | tail -15",
            timeout=60,
        )
        if rc is None:
            return findings

        output = stdout.strip() + stderr.strip()
        if "no tests ran" in output.lower() or not output:
            return findings

        if rc == 0:
            last_line = output.strip().split("\n")[-1] if output.strip() else ""
            findings.append(Finding(
                severity=Severity.INFO,
                source="test_runner",
                message=f"{proj}: pytest passed -- {last_line}",
                host="linux-host",
            ))
        else:
            fail_lines = [l for l in output.split("\n") if "FAILED" in l or "ERROR" in l]
            findings.append(Finding(
                severity=Severity.HIGH,
                source="test_runner",
                message=f"{proj}: pytest FAILED ({len(fail_lines)} failures)",
                details="\n".join(fail_lines[:10]),
                host="linux-host",
            ))

        stdout2, stderr2, rc2 = self.ssh(
            f"cd {path} && python3 -m pytest --cov={path} --cov-report=term-missing -q 2>/dev/null "
            f"| grep 'TOTAL' | tail -1",
            timeout=60,
        )
        if rc2 == 0 and "TOTAL" in stdout2:
            findings.append(Finding(
                severity=Severity.INFO,
                source="test_runner",
                message=f"{proj}: coverage -- {stdout2.strip()}",
                host="linux-host",
            ))

        return findings

    def _run_jest(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && test -f node_modules/.bin/jest && "
            f"npx jest --no-coverage --silent 2>/dev/null | tail -10",
            timeout=60,
        )
        if rc is None or not stdout.strip():
            return findings

        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="test_runner",
                message=f"{proj}: jest passed",
                host="linux-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="test_runner",
                message=f"{proj}: jest FAILED",
                details=stdout.strip()[:300],
                host="linux-host",
            ))
        return findings

    def _run_cargo_test(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && cargo test --no-fail-fast 2>&1 | tail -10",
            timeout=120,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="test_runner",
                message=f"{proj}: cargo test passed",
                host="linux-host",
            ))
        elif stdout.strip():
            findings.append(Finding(
                severity=Severity.HIGH,
                source="test_runner",
                message=f"{proj}: cargo test FAILED",
                details=stdout.strip()[:300],
                host="linux-host",
            ))
        return findings

    def _run_go_test(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && go test ./... 2>&1 | tail -10",
            timeout=60,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="test_runner",
                message=f"{proj}: go test passed",
                host="linux-host",
            ))
        elif stdout.strip():
            findings.append(Finding(
                severity=Severity.HIGH,
                source="test_runner",
                message=f"{proj}: go test FAILED",
                details=stdout.strip()[:300],
                host="linux-host",
            ))
        return findings
