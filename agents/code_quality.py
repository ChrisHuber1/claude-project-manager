"""Agent 5: Code Quality -- auto-detect stack, run linters/type checkers/formatters."""

import os

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class CodeQualityAgent(BaseAgent):
    name = "code_quality"
    description = "Auto-detect stack, run linters/type checkers/formatters per project"
    default_interval = 0
    tier = "development"

    PROJECTS = [
        "MyProject", "SecurityAuditProject",
        "FirewallManager", "VPNProject", "siem", "network-schema",
        "linux-tools", "chatbot", "siem-triage",
    ]

    PYTHON_LINTERS = {
        "ruff": "ruff check --quiet {path} 2>/dev/null | head -30",
        "flake8": "flake8 --max-line-length=120 --count --statistics {path} 2>/dev/null | tail -10",
        "pylint": "pylint --errors-only {path}/*.py 2>/dev/null | head -20",
    }

    JS_LINTERS = {
        "eslint": "cd {path} && npx eslint . --format compact 2>/dev/null | tail -20",
    }

    def check(self, project=None) -> AgentResult:
        findings = []
        projects = [project] if project else self.PROJECTS

        for proj in projects:
            proj_path = f"~/{proj}"
            stack = self.detect_stack(proj_path)
            proj_findings = []

            if "python" in stack.get("languages", []):
                proj_findings.extend(self._check_python(proj, proj_path))

            if "javascript" in stack.get("languages", []) or "typescript" in stack.get("languages", []):
                proj_findings.extend(self._check_js(proj, proj_path))

            if "rust" in stack.get("languages", []):
                proj_findings.extend(self._check_rust(proj, proj_path))

            if "go" in stack.get("languages", []):
                proj_findings.extend(self._check_go(proj, proj_path))

            if stack.get("type") == "game" and "godot" in stack.get("frameworks", []):
                proj_findings.extend(self._check_godot(proj, proj_path))

            if not proj_findings:
                findings.append(Finding(
                    severity=Severity.INFO,
                    source="code_quality",
                    message=f"{proj}: clean (stack: {stack.get('type', 'unknown')})",
                    host="linux-host",
                ))
            else:
                findings.extend(proj_findings)

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"Checked {len(projects)} projects",
        )

    def _check_python(self, proj, path):
        findings = []
        available_linter = None
        for linter in ["ruff", "flake8", "pylint"]:
            stdout, stderr, rc = self.ssh(f"which {linter} 2>/dev/null", timeout=5)
            if rc == 0:
                available_linter = linter
                break

        if not available_linter:
            py_count_out, _, _ = self.ssh(f"find {path} -name '*.py' -not -path '*/venv/*' | wc -l", timeout=10)
            try:
                py_count = int(py_count_out.strip())
            except ValueError:
                py_count = 0
            if py_count > 0:
                findings.append(Finding(
                    severity=Severity.LOW,
                    source="code_quality",
                    message=f"{proj}: no Python linter installed (ruff/flake8/pylint)",
                    host="linux-host",
                ))
            return findings

        cmd = self.PYTHON_LINTERS[available_linter].format(path=path)
        stdout, stderr, rc = self.ssh(cmd, timeout=30)

        if rc != 0 and stdout.strip():
            issues = stdout.strip().split("\n")
            error_count = len([l for l in issues if l.strip()])
            if error_count > 0:
                findings.append(Finding(
                    severity=Severity.MEDIUM if error_count < 10 else Severity.HIGH,
                    source="code_quality",
                    message=f"{proj}: {error_count} {available_linter} issues",
                    details="\n".join(issues[:10]),
                    host="linux-host",
                ))

        mypy_out, _, mypy_rc = self.ssh(f"which mypy 2>/dev/null", timeout=5)
        if mypy_rc == 0:
            stdout2, stderr2, rc2 = self.ssh(
                f"mypy --ignore-missing-imports --no-error-summary {path}/*.py 2>/dev/null | head -20",
                timeout=30,
            )
            if rc2 != 0 and stdout2.strip():
                type_errors = [l for l in stdout2.strip().split("\n") if "error:" in l]
                if type_errors:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        source="code_quality",
                        message=f"{proj}: {len(type_errors)} mypy type errors",
                        details="\n".join(type_errors[:5]),
                        host="linux-host",
                    ))

        return findings

    def _check_js(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && test -f node_modules/.bin/eslint && "
            f"npx eslint . --format compact --quiet 2>/dev/null | wc -l",
            timeout=30,
        )
        try:
            issues = int(stdout.strip())
        except ValueError:
            issues = 0

        if issues > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM if issues < 20 else Severity.HIGH,
                source="code_quality",
                message=f"{proj}: {issues} ESLint issues",
                host="linux-host",
            ))

        stdout2, stderr2, rc2 = self.ssh(
            f"cd {path} && test -f tsconfig.json && npx tsc --noEmit 2>/dev/null | tail -5",
            timeout=30,
        )
        if rc2 != 0 and stdout2.strip():
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="code_quality",
                message=f"{proj}: TypeScript compilation errors",
                details=stdout2.strip()[:300],
                host="linux-host",
            ))

        return findings

    def _check_rust(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && cargo clippy --message-format=short 2>/dev/null | grep 'warning\\|error' | wc -l",
            timeout=60,
        )
        try:
            issues = int(stdout.strip())
        except ValueError:
            issues = 0
        if issues > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="code_quality",
                message=f"{proj}: {issues} clippy warnings/errors",
                host="linux-host",
            ))
        return findings

    def _check_go(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && go vet ./... 2>&1 | wc -l",
            timeout=30,
        )
        try:
            issues = int(stdout.strip())
        except ValueError:
            issues = 0
        if issues > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source="code_quality",
                message=f"{proj}: {issues} go vet issues",
                host="linux-host",
            ))
        return findings

    def _check_godot(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"find {path} -name '*.gd' -exec grep -l 'var.*=' {{}} \\; 2>/dev/null | wc -l",
            timeout=15,
        )
        findings.append(Finding(
            severity=Severity.INFO,
            source="code_quality",
            message=f"{proj}: Godot project detected (GDScript files present)",
            host="linux-host",
        ))
        return findings
