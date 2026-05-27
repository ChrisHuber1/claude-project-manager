"""Agent 8: Build Validator -- compile/build checks, Docker builds, asset pipelines."""

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class BuildValidatorAgent(BaseAgent):
    name = "build_validator"
    description = "Compile/build checks, Docker builds, asset pipelines per project type"
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
            findings.extend(self._validate(proj, proj_path, stack))

        passed = sum(1 for f in findings if f.severity == Severity.INFO)
        failed = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{passed} passed, {failed} failed",
        )

    def _validate(self, proj, path, stack):
        findings = []
        langs = stack.get("languages", [])
        tools = stack.get("tools", [])
        frameworks = stack.get("frameworks", [])

        if "python" in langs:
            findings.extend(self._check_python_imports(proj, path))

        if "typescript" in langs:
            findings.extend(self._check_tsc(proj, path))

        if "rust" in langs:
            findings.extend(self._check_cargo_build(proj, path))

        if "go" in langs:
            findings.extend(self._check_go_build(proj, path))

        if "nextjs" in frameworks:
            findings.extend(self._check_next_build(proj, path))

        if "django" in frameworks:
            findings.extend(self._check_django(proj, path))

        if "docker" in tools:
            findings.extend(self._check_docker(proj, path))

        if "godot" in frameworks:
            findings.extend(self._check_godot(proj, path))

        return findings

    def _check_python_imports(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && python3 -c \""
            f"import ast, sys, os; "
            f"files = [f for f in os.listdir('.') if f.endswith('.py')]; "
            f"errors = []; "
            f"[errors.append(f) for f in files "
            f"if not (lambda fn: (lambda: (ast.parse(open(fn).read()), True)[-1])() "
            f"if os.path.isfile(fn) else True)(f)]; "
            f"print(len(errors))\" 2>/dev/null || "
            f"python3 -c \"import py_compile, os, sys; "
            f"files = [f for f in os.listdir('.') if f.endswith('.py')]; "
            f"bad = 0; "
            f"[exec('try:\\n py_compile.compile(f, doraise=True)\\nexcept: bad += 1') for f in files]; "
            f"print(bad)\" 2>/dev/null",
            timeout=15,
        )
        stdout2, stderr2, rc2 = self.ssh(
            f"cd {path} && python3 -m py_compile *.py 2>&1 | head -10",
            timeout=15,
        )
        if rc2 != 0 and stderr2.strip():
            findings.append(Finding(
                severity=Severity.HIGH,
                source="build_validator",
                message=f"{proj}: Python syntax errors",
                details=stderr2.strip()[:300],
                host="linux-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Python files compile OK",
                host="linux-host",
            ))
        return findings

    def _check_tsc(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && npx tsc --noEmit 2>&1 | tail -5",
            timeout=60,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: TypeScript compiles clean",
                host="linux-host",
            ))
        else:
            error_count_out, _, _ = self.ssh(
                f"cd {path} && npx tsc --noEmit 2>&1 | grep -c 'error TS'",
                timeout=60,
            )
            try:
                errors = int(error_count_out.strip())
            except ValueError:
                errors = 0
            findings.append(Finding(
                severity=Severity.HIGH,
                source="build_validator",
                message=f"{proj}: {errors} TypeScript errors",
                details=stdout.strip()[:300] if stdout else "",
                host="linux-host",
            ))
        return findings

    def _check_cargo_build(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && cargo check 2>&1 | tail -5",
            timeout=120,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Rust compiles clean",
                host="linux-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="build_validator",
                message=f"{proj}: Rust build errors",
                details=(stdout + stderr).strip()[:300],
                host="linux-host",
            ))
        return findings

    def _check_go_build(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && go build ./... 2>&1 | tail -5",
            timeout=60,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Go builds clean",
                host="linux-host",
            ))
        else:
            findings.append(Finding(
                severity=Severity.HIGH,
                source="build_validator",
                message=f"{proj}: Go build errors",
                details=(stdout + stderr).strip()[:300],
                host="linux-host",
            ))
        return findings

    def _check_next_build(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && npx next lint 2>&1 | tail -5",
            timeout=60,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Next.js lint passed",
                host="linux-host",
            ))
        return findings

    def _check_django(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && python3 manage.py check 2>&1 | tail -5",
            timeout=30,
        )
        if rc == 0:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Django system check passed",
                host="linux-host",
            ))
        elif stdout.strip():
            findings.append(Finding(
                severity=Severity.HIGH,
                source="build_validator",
                message=f"{proj}: Django check failed",
                details=stdout.strip()[:300],
                host="linux-host",
            ))
        return findings

    def _check_docker(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"cd {path} && test -f Dockerfile && "
            f"docker build --dry-run . 2>&1 | tail -3 || echo 'no-docker-or-no-dry-run'",
            timeout=30,
        )
        if "no-docker-or-no-dry-run" not in stdout:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Dockerfile present",
                host="linux-host",
            ))
        return findings

    def _check_godot(self, proj, path):
        findings = []
        stdout, stderr, rc = self.ssh(
            f"test -f {path}/project.godot && echo found || echo missing",
            timeout=5,
        )
        if "found" in stdout:
            findings.append(Finding(
                severity=Severity.INFO,
                source="build_validator",
                message=f"{proj}: Godot project.godot present",
                host="linux-host",
            ))
        return findings
