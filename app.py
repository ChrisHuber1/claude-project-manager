import json
import threading
import time
from datetime import datetime
from pathlib import Path

from textual.app import App
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from config import (
    STATE_DIR,
    check_bootstrap,
    refresh_remote_env,
    get_env_key_names,
    run_ssh,
    OPS1_HOST,
)
from scanner import scan_projects, load_cached_projects, check_host_reachable
from recommender import compute_recommendation
from alerts import alert_input_needed

import agents.range_health
import agents.security_monitor
import agents.siem_watchdog
import agents.backup_guardian
import agents.code_quality
import agents.test_runner
import agents.security_scanner
import agents.build_validator
import agents.project_tracker
import agents.scaffold_agent
import agents.cross_project_intel
import agents.risk_drift
import agents.session_historian
import agents.daily_briefing
import agents.range_manager

from agents.runner import AgentManager, get_agent_info


SCAN_INTERVAL = 300
HEARTBEAT_INTERVAL = 30
AGENT_REFRESH_INTERVAL = 60

DASHBOARD_GROUPS = [
    ("Admin", "Admin"),
    ("Network", "Network"),
    ("Compute", "Compute"),
    ("Services", "Services"),
    ("Security", "Security"),
    ("Projects", "Projects"),
]

DASHBOARD_ICONS = [
    ("code", "\U0001f4bb"),
    ("robot", "\U0001f916"),
    ("shield", "\U0001f6e1"),
    ("gear", "⚙"),
    ("book", "\U0001f4d6"),
    ("rocket", "\U0001f680"),
    ("wrench", "\U0001f527"),
    ("chart", "\U0001f4ca"),
    ("lock", "\U0001f512"),
    ("globe", "\U0001f310"),
]


class NewProjectScreen(Screen):
    CSS = """
    NewProjectScreen {
        background: $background;
    }
    #np-container {
        padding: 1 2;
    }
    .dialog-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
        height: 1;
        margin-bottom: 1;
    }
    .field-label {
        margin-top: 1;
        margin-bottom: 0;
        padding: 0 2;
    }
    #np-container Input {
        margin: 0 2;
        width: 60;
    }
    .options-text {
        padding: 0 2;
        color: $text-muted;
    }
    #np-error {
        color: $error;
        height: 1;
        margin: 1 2;
    }
    """

    BINDINGS = [("escape", "cancel", "Back")]

    _GROUP_OPTIONS = ["Admin", "Network", "Compute", "Services", "Security", "Projects"]
    _ICON_OPTIONS = [
        ("\U0001f4bb", "code"),
        ("\U0001f916", "robot"),
        ("\U0001f6e1", "shield"),
        ("⚙", "gear"),
        ("\U0001f4d6", "book"),
        ("\U0001f680", "rocket"),
        ("\U0001f527", "wrench"),
        ("\U0001f4ca", "chart"),
        ("\U0001f512", "lock"),
        ("\U0001f310", "globe"),
    ]

    def compose(self):
        yield Header()
        with VerticalScroll(id="np-container"):
            yield Label("NEW PROJECT", classes="dialog-title")

            yield Label("Project Name (PascalCase, e.g. MyNewProject):", classes="field-label")
            yield Input(id="inp-name", placeholder="MyNewProject")

            yield Label("Description:", classes="field-label")
            yield Input(id="inp-desc", placeholder="Short description of the project")

            group_opts = "  ".join(f"{i+1}={g}" for i, g in enumerate(self._GROUP_OPTIONS))
            yield Label(f"Dashboard Group ({group_opts}):", classes="field-label")
            yield Input(id="inp-group", placeholder="6", value="6")

            icon_opts = "  ".join(f"{i+1}={ic}" for i, (ic, _) in enumerate(self._ICON_OPTIONS))
            yield Label(f"Icon ({icon_opts}):", classes="field-label")
            yield Input(id="inp-icon", placeholder="1", value="1")

            yield Label("Tags (comma-separated):", classes="field-label")
            yield Input(id="inp-tags", placeholder="python, automation, security")

            yield Label("Init git repo? (y/n):", classes="field-label")
            yield Input(id="inp-git", placeholder="y", value="y")

            yield Label("", id="np-error")
            yield Label("[dim]Fill fields with Tab, then press Enter on any field to create. Esc to cancel.[/]", classes="options-text")
        yield Footer()

    def on_mount(self):
        self.query_one("#inp-name", Input).focus()

    def on_input_submitted(self, event):
        self._do_create()

    def action_cancel(self):
        self.app.pop_screen()

    def _do_create(self):
        name = self.query_one("#inp-name", Input).value.strip()
        desc = self.query_one("#inp-desc", Input).value.strip()
        group_val = self.query_one("#inp-group", Input).value.strip()
        icon_val = self.query_one("#inp-icon", Input).value.strip()
        tags_raw = self.query_one("#inp-tags", Input).value.strip()
        git_val = self.query_one("#inp-git", Input).value.strip().lower()

        err = self.query_one("#np-error", Label)

        if not name:
            err.update("[red]Project name is required[/]")
            self.query_one("#inp-name", Input).focus()
            return
        if " " in name:
            err.update("[red]No spaces -- use PascalCase[/]")
            self.query_one("#inp-name", Input).focus()
            return
        if not desc:
            err.update("[red]Description is required[/]")
            self.query_one("#inp-desc", Input).focus()
            return

        try:
            group_idx = int(group_val) - 1
            group = self._GROUP_OPTIONS[group_idx]
        except (ValueError, IndexError):
            err.update(f"[red]Group: enter 1-{len(self._GROUP_OPTIONS)}[/]")
            return

        try:
            icon_idx = int(icon_val) - 1
            icon = self._ICON_OPTIONS[icon_idx][0]
        except (ValueError, IndexError):
            err.update(f"[red]Icon: enter 1-{len(self._ICON_OPTIONS)}[/]")
            return

        tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
        init_git = git_val in ("y", "yes", "1", "true")

        result = {
            "name": name,
            "description": desc,
            "group": group,
            "icon": icon,
            "tags": tags,
            "init_git": init_git,
        }
        self.app.pop_screen()
        self.app.handle_new_project(result)


class WorkOnProjectScreen(Screen):
    CSS = """
    WorkOnProjectScreen {
        background: $background;
    }
    #work-container {
        padding: 1 2;
    }
    .dialog-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
        height: 1;
        margin-bottom: 1;
    }
    #project-list {
        height: auto;
        padding: 0 2;
        margin-bottom: 1;
    }
    #choice-input {
        margin: 0 2;
        width: 50;
    }
    #work-error {
        color: $error;
        height: 1;
        margin: 0 2;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Back"),
    ]

    def __init__(self, projects, recommendation):
        super().__init__()
        self._projects = projects or []
        self._recommendation = recommendation
        self._choices = []

    def compose(self):
        yield Header()
        with Vertical(id="work-container"):
            yield Label("SELECT PROJECT TO WORK ON", classes="dialog-title")
            yield Static(id="project-list", markup=True)
            yield Label("Type a number and press Enter (or 0 to cancel):")
            yield Input(id="choice-input", placeholder="Enter number...")
            yield Label("", id="work-error")
        yield Footer()

    def on_mount(self):
        rec_name = ""
        if self._recommendation and self._recommendation.get("recommendation"):
            rec_name = self._recommendation["recommendation"]

        lines = []
        idx = 1
        for p in sorted(self._projects, key=lambda x: x.get("last_activity_days") or 999):
            if p.get("file_count", 0) < 2:
                continue

            age = p.get("last_activity_days")
            age_str = f"{age:.0f}d ago" if age is not None else "---"
            pri = p.get("priority") or ""
            marker = " [bold cyan]<<< RECOMMENDED[/]" if p["name"] == rec_name else ""

            info_parts = [f"{p.get('file_count', 0)} files", age_str]
            if pri:
                info_parts.append(pri)
            if p.get("has_errors"):
                info_parts.append("[red]ERRORS[/]")
            if p.get("is_git"):
                info_parts.append("git")

            info = "  ".join(info_parts)
            lines.append(f"  [bold]{idx}.[/]  {p['name']:30s}  {info}{marker}")
            self._choices.append(p["name"])
            idx += 1

        lines.append("")
        lines.append("  [dim]0.  Cancel[/]")

        self.query_one("#project-list", Static).update("\n".join(lines))
        self.query_one("#choice-input", Input).focus()

    def on_input_submitted(self, event):
        val = event.value.strip()
        err = self.query_one("#work-error", Label)

        if not val:
            return

        try:
            num = int(val)
        except ValueError:
            err.update(f"[red]Enter a number 0-{len(self._choices)}[/]")
            return

        if num == 0:
            self.app.pop_screen()
            return

        if num < 1 or num > len(self._choices):
            err.update(f"[red]Enter a number 0-{len(self._choices)}[/]")
            return

        project_name = self._choices[num - 1]
        self.app.pop_screen()
        self.app.handle_work_selection(project_name)

    def action_cancel(self):
        self.app.pop_screen()


class ProjectDetailScreen(Screen):
    CSS = """
    ProjectDetailScreen {
        background: $background;
        layout: grid;
        grid-size: 1 3;
        grid-rows: auto auto 1fr;
    }
    .dialog-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
        height: 1;
        margin-bottom: 1;
    }
    #detail-info {
        padding: 0 2;
        height: auto;
    }
    #detail-actions {
        padding: 0 2;
        height: auto;
    }
    #detail-input {
        margin: 0 2;
        width: 50;
    }
    #detail-error {
        color: $error;
        height: 1;
        margin: 0 2;
    }
    #detail-result-scroll {
        border: solid $primary;
        margin: 0 1;
        height: 100%;
    }
    """

    BINDINGS = [("escape", "close", "Back")]

    def __init__(self, project_data):
        super().__init__()
        self._project = project_data
        self._path = project_data.get("path", "~/" + project_data["name"])
        self._pending_session = False

    def compose(self):
        p = self._project
        yield Header()
        with Vertical(id="detail-top"):
            yield Label(f"PROJECT: {p['name']}", classes="dialog-title")
            yield Static(id="detail-info", markup=True)
            yield Static(id="detail-actions", markup=True)
            yield Input(id="detail-input", placeholder="Enter action number...")
            yield Label("", id="detail-error")
        with VerticalScroll(id="detail-result-scroll"):
            yield Static(id="detail-result", markup=True)
        yield Footer()

    def on_mount(self):
        self._show_info()
        self._show_actions()
        self.query_one("#detail-input", Input).focus()

    def _show_info(self):
        p = self._project
        age = p.get("last_activity_days")
        age_str = f"{age:.1f}d ago" if age is not None else "?"
        git_info = ""
        if p.get("is_git"):
            dirty = " [red]DIRTY[/]" if p.get("git_dirty") else ""
            git_info = f"  [bold]Git:[/] {p.get('branch', '?')}{dirty}"
        todos = ""
        if p.get("todos_total", 0) > 0:
            pct = p["todos_done"] / p["todos_total"] * 100
            todos = f"  [bold]TODOs:[/] {p['todos_done']}/{p['todos_total']} ({pct:.0f}%)"
        docs = []
        for key in ["has_readme_md", "has_todo_md", "has_status_md",
                     "has_changelog_md", "has_claude_md", "has_session_notes_md"]:
            if p.get(key):
                docs.append(key.replace("has_", "").replace("_md", "").upper())
        err = "  [bold red]ERRORS[/]" if p.get("has_errors") else ""

        info = (
            f"[bold]Path:[/] {self._path}  [bold]Files:[/] {p.get('file_count', 0)}  "
            f"[bold]Activity:[/] {age_str}{git_info}{todos}{err}\n"
            f"[bold]Docs:[/] {', '.join(docs) if docs else 'none'}"
        )
        self.query_one("#detail-info", Static).update(info)

    def _show_actions(self):
        lines = [
            "",
            "[bold]Actions:[/]",
            "  [bold]1.[/] Git status          [bold]6.[/] Build validation",
            "  [bold]2.[/] Recent commits       [bold]7.[/] View logs",
            "  [bold]3.[/] View TODO.md         [bold]8.[/] Open SSH terminal",
            "  [bold]4.[/] Code quality check    [bold]9.[/] Record session",
            "  [bold]5.[/] Run tests            [bold]0.[/] Back",
        ]
        self.query_one("#detail-actions", Static).update("\n".join(lines))

    def on_input_submitted(self, event):
        val = event.value.strip()
        err = self.query_one("#detail-error", Label)
        err.update("")
        event.input.value = ""

        if not val:
            return

        if self._pending_session:
            self.on_input_submitted_session(val)
            return

        try:
            num = int(val)
        except ValueError:
            err.update("[red]Enter a number 0-9[/]")
            return

        actions = {
            0: self._action_back,
            1: self._action_git_status,
            2: self._action_recent_commits,
            3: self._action_view_todo,
            4: self._action_code_quality,
            5: self._action_run_tests,
            6: self._action_build_check,
            7: self._action_view_logs,
            8: self._action_ssh_terminal,
            9: self._action_session_notes,
        }
        action = actions.get(num)
        if action:
            action()
        else:
            err.update("[red]Enter 0-9[/]")

    def _set_result(self, text):
        try:
            self.query_one("#detail-result", Static).update(text)
        except Exception:
            pass

    def _run_ssh_action(self, label, command, timeout=30):
        self._set_result(f"[yellow]{label}...[/]")
        threading.Thread(
            target=self._ssh_thread, args=(label, command, timeout), daemon=True
        ).start()

    def _ssh_thread(self, label, command, timeout):
        try:
            stdout, stderr, rc = run_ssh(command, timeout=timeout)
            output = stdout.strip() if rc == 0 else f"Error (rc={rc}):\n{stderr.strip()}"
            if not output:
                output = "(no output)"
            header = f"[bold cyan]── {label} ──[/]\n\n"
            self.app.call_from_thread(self._set_result, header + output)
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"[red]Thread error: {e}[/]")

    def _action_back(self):
        self.app.pop_screen()

    def _action_git_status(self):
        self._run_ssh_action(
            "Git Status",
            f"cd {self._path} && git status && echo '---' && git stash list 2>/dev/null",
        )

    def _action_recent_commits(self):
        self._run_ssh_action(
            "Recent Commits",
            f"cd {self._path} && git log --oneline --graph -20 2>/dev/null || echo 'Not a git repo'",
        )

    def _action_view_todo(self):
        self._run_ssh_action(
            "TODO.md",
            f"cat {self._path}/TODO.md 2>/dev/null || echo 'No TODO.md found'",
            timeout=10,
        )

    def _action_code_quality(self):
        name = self._project["name"]
        self._set_result(f"[yellow]Running code quality checks on {name}...[/]")
        threading.Thread(target=self._quality_thread, daemon=True).start()

    def _quality_thread(self):
        try:
            self._quality_thread_inner()
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"[red]Quality check error: {e}[/]")

    def _quality_thread_inner(self):
        path = self._path
        lines = []
        stdout, _, rc = run_ssh(f"ls {path}/ 2>/dev/null", timeout=10)
        files = set(stdout.strip().split("\n")) if rc == 0 else set()

        if "requirements.txt" in files or "pyproject.toml" in files or "setup.py" in files:
            lines.append("[bold]Python linting:[/]")
            for tool in ["ruff check .", "flake8 --max-line-length=120 .", "python3 -m py_compile"]:
                if "py_compile" in tool:
                    cmd = f"cd {path} && find . -name '*.py' -exec python3 -m py_compile {{}} + 2>&1 | head -20"
                else:
                    cmd = f"cd {path} && {tool} 2>&1 | head -30"
                out, _, _ = run_ssh(cmd, timeout=30)
                if out.strip():
                    lines.append(out.strip())
                else:
                    lines.append(f"  {tool.split()[0]}: [green]clean[/]")
                lines.append("")

        if "package.json" in files:
            lines.append("[bold]JS/TS linting:[/]")
            out, _, _ = run_ssh(f"cd {path} && npx eslint . 2>&1 | head -30", timeout=30)
            lines.append(out.strip() if out.strip() else "  eslint: [green]clean[/]")
            lines.append("")

        if "Cargo.toml" in files:
            lines.append("[bold]Rust clippy:[/]")
            out, _, _ = run_ssh(f"cd {path} && cargo clippy 2>&1 | head -30", timeout=60)
            lines.append(out.strip() if out.strip() else "  clippy: [green]clean[/]")
            lines.append("")

        if "go.mod" in files:
            lines.append("[bold]Go vet:[/]")
            out, _, _ = run_ssh(f"cd {path} && go vet ./... 2>&1 | head -30", timeout=30)
            lines.append(out.strip() if out.strip() else "  go vet: [green]clean[/]")
            lines.append("")

        if not lines:
            lines.append("No recognized language detected for quality checks.")

        header = f"[bold cyan]── Code Quality: {self._project['name']} ──[/]\n\n"
        self.app.call_from_thread(self._set_result, header + "\n".join(lines))

    def _action_run_tests(self):
        name = self._project["name"]
        self._set_result(f"[yellow]Running tests on {name}...[/]")
        threading.Thread(target=self._test_thread, daemon=True).start()

    def _test_thread(self):
        try:
            self._test_thread_inner()
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"[red]Test runner error: {e}[/]")

    def _test_thread_inner(self):
        path = self._path
        stdout, _, rc = run_ssh(f"ls {path}/ 2>/dev/null", timeout=10)
        files = set(stdout.strip().split("\n")) if rc == 0 else set()
        lines = []

        if "requirements.txt" in files or "pyproject.toml" in files:
            out, _, _ = run_ssh(
                f"cd {path} && python3 -m pytest -v --tb=short 2>&1 | tail -40", timeout=120
            )
            lines.append("[bold]pytest:[/]")
            lines.append(out.strip() if out.strip() else "  No tests found or pytest not installed")

        elif "package.json" in files:
            out, _, _ = run_ssh(
                f"cd {path} && npm test 2>&1 | tail -40", timeout=120
            )
            lines.append("[bold]npm test:[/]")
            lines.append(out.strip() if out.strip() else "  No test script defined")

        elif "Cargo.toml" in files:
            out, _, _ = run_ssh(f"cd {path} && cargo test 2>&1 | tail -40", timeout=120)
            lines.append("[bold]cargo test:[/]")
            lines.append(out.strip())

        elif "go.mod" in files:
            out, _, _ = run_ssh(f"cd {path} && go test ./... -v 2>&1 | tail -40", timeout=120)
            lines.append("[bold]go test:[/]")
            lines.append(out.strip())

        else:
            lines.append("No recognized test framework detected.")

        header = f"[bold cyan]── Tests: {self._project['name']} ──[/]\n\n"
        self.app.call_from_thread(self._set_result, header + "\n".join(lines))

    def _action_build_check(self):
        name = self._project["name"]
        self._set_result(f"[yellow]Running build validation on {name}...[/]")
        threading.Thread(target=self._build_thread, daemon=True).start()

    def _build_thread(self):
        try:
            self._build_thread_inner()
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"[red]Build check error: {e}[/]")

    def _build_thread_inner(self):
        path = self._path
        stdout, _, rc = run_ssh(f"ls {path}/ 2>/dev/null", timeout=10)
        files = set(stdout.strip().split("\n")) if rc == 0 else set()
        lines = []

        if "requirements.txt" in files or "pyproject.toml" in files:
            out, _, _ = run_ssh(
                f"cd {path} && find . -name '*.py' | head -50 | xargs python3 -m py_compile 2>&1",
                timeout=30,
            )
            lines.append("[bold]Python syntax check:[/]")
            lines.append(out.strip() if out.strip() else "  [green]All files compile OK[/]")

        if "tsconfig.json" in files:
            out, _, _ = run_ssh(f"cd {path} && npx tsc --noEmit 2>&1 | tail -20", timeout=60)
            lines.append("[bold]TypeScript compilation:[/]")
            lines.append(out.strip() if out.strip() else "  [green]No type errors[/]")

        if "Cargo.toml" in files:
            out, _, _ = run_ssh(f"cd {path} && cargo check 2>&1 | tail -20", timeout=60)
            lines.append("[bold]Cargo check:[/]")
            lines.append(out.strip() if out.strip() else "  [green]Build OK[/]")

        if "go.mod" in files:
            out, _, _ = run_ssh(f"cd {path} && go build ./... 2>&1 | tail -20", timeout=60)
            lines.append("[bold]Go build:[/]")
            lines.append(out.strip() if out.strip() else "  [green]Build OK[/]")

        if "Dockerfile" in files:
            lines.append("[bold]Dockerfile:[/] present")

        if not lines:
            lines.append("No recognized build system detected.")

        header = f"[bold cyan]── Build Validation: {self._project['name']} ──[/]\n\n"
        self.app.call_from_thread(self._set_result, header + "\n".join(lines))

    def _action_view_logs(self):
        path = self._path
        cmd = (
            f"find {path} -maxdepth 2 \\( -name '*.log' -o -path '*/logs/*' \\) -type f 2>/dev/null"
            f" | head -5 | while read f; do echo '=== '$f' ==='; tail -30 \"$f\"; echo; done"
        )
        fallback = f"echo 'No log files found'; ls -la {path}/*.log {path}/logs/ 2>/dev/null || true"
        self._run_ssh_action("Logs", f"({cmd}) 2>/dev/null || {fallback}", timeout=15)

    def _action_ssh_terminal(self):
        import subprocess as sp
        name = self._project["name"]
        ssh_cmd_str = f"ssh YOUR_SSH_USER@YOUR_HOST_IP -t \"cd ~/{name} && exec bash --login\""
        try:
            sp.Popen(
                ["cmd", "/c", "start", "cmd", "/k", ssh_cmd_str],
                creationflags=0x00000008,
            )
            self._set_result(f"[green]Opened SSH terminal to ~/{name}/ on linux-host[/]")
            self.app.log_activity(f"Opened SSH terminal: {name}")
        except Exception as e:
            self._set_result(f"[red]Failed to open terminal: {e}[/]\n\nManual command:\n  {ssh_cmd_str}")

    def _action_session_notes(self):
        self._set_result(
            "[bold cyan]── Session Notes ──[/]\n\n"
            "Enter a session summary at the prompt below.\n"
            "Format: brief description of what was done.\n\n"
            "[dim]Type your summary and press Enter to record, or 0 to cancel.[/]"
        )
        self._pending_session = True

    def on_input_submitted_session(self, val):
        if val == "0":
            self._pending_session = False
            self._set_result("")
            return
        name = self._project["name"]
        self._set_result(f"[yellow]Recording session for {name}...[/]")
        self._pending_session = False
        threading.Thread(
            target=self._session_thread, args=(name, val), daemon=True
        ).start()

    def _session_thread(self, name, summary):
        try:
            from agents.session_historian import SessionHistorianAgent
            agent = SessionHistorianAgent()
            result = agent.record_session(name, summary)
            lines = [f"[bold cyan]── Session Recorded ──[/]\n"]
            for f in result.findings:
                lines.append(f"  {f.message}")
            self.app.call_from_thread(self._set_result, "\n".join(lines))
            self.app.call_from_thread(
                self.app.log_activity,
                f"Session recorded for [bold]{name}[/]: {summary[:60]}"
            )
        except Exception as e:
            self.app.call_from_thread(self._set_result, f"[red]Session error: {e}[/]")

    def action_close(self):
        self.app.pop_screen()


class AgentControlScreen(Screen):
    CSS = """
    AgentControlScreen {
        background: $background;
    }
    #agent-container {
        padding: 1 2;
    }
    .dialog-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
        height: 1;
        margin-bottom: 1;
    }
    #agent-list-view {
        height: auto;
        padding: 0 2;
        margin-bottom: 1;
    }
    #agent-input {
        margin: 0 2;
        width: 50;
    }
    #agent-error {
        color: $error;
        height: 1;
        margin: 0 2;
    }
    #agent-result-view {
        padding: 0 2;
        height: auto;
    }
    """

    BINDINGS = [("escape", "cancel", "Back")]

    def __init__(self, agent_manager):
        super().__init__()
        self._mgr = agent_manager
        self._mode = "menu"
        self._agent_names = []

    def compose(self):
        yield Header()
        with VerticalScroll(id="agent-container"):
            yield Label("AGENT CONTROL", classes="dialog-title")
            yield Static(id="agent-list-view", markup=True)
            yield Label("Type a number and press Enter:")
            yield Input(id="agent-input", placeholder="Enter number...")
            yield Label("", id="agent-error")
            yield Static(id="agent-result-view", markup=True)
        yield Footer()

    def on_mount(self):
        self._show_menu()
        self.query_one("#agent-input", Input).focus()

    def _show_menu(self):
        self._mode = "menu"
        status = self._mgr.status()
        lines = ["[bold]Agent Status:[/]\n"]
        lines.append(f"  {'Name':<25} {'Tier':<12} {'Running':<9} {'Last Run':<20} {'Findings'}")
        lines.append(f"  {'-'*78}")
        for s in status:
            running = "[green]YES[/]" if s["running"] else "[dim]no[/]"
            last = s["last_run"][:19] if len(str(s["last_run"])) > 19 else str(s["last_run"])
            lines.append(f"  {s['name']:<25} {s['tier']:<12} {running:<9} {last:<20} {s['findings']}")

        lines.append("")
        lines.append("[bold]Actions:[/]")
        lines.append("  [bold]1.[/]  Run agent once")
        lines.append("  [bold]2.[/]  Start agent loop")
        lines.append("  [bold]3.[/]  Stop agent")
        lines.append("  [bold]4.[/]  Start all infrastructure agents")
        lines.append("  [bold]5.[/]  Stop all agents")
        lines.append("  [bold]6.[/]  Run daily briefing")
        lines.append("  [bold]0.[/]  Back")

        self.query_one("#agent-list-view", Static).update("\n".join(lines))

    def _show_agent_select(self, mode_label):
        info = get_agent_info()
        self._agent_names = [i["name"] for i in info]
        lines = [f"[bold]Select agent to {mode_label}:[/]\n"]
        for idx, i in enumerate(info, 1):
            iv = f"{i['interval']}s" if i['interval'] > 0 else "manual"
            lines.append(f"  [bold]{idx}.[/]  {i['name']:<25} ({i['tier']}, {iv})")
        lines.append(f"\n  [bold]0.[/]  Cancel")
        self.query_one("#agent-list-view", Static).update("\n".join(lines))

    def on_input_submitted(self, event):
        val = event.value.strip()
        err = self.query_one("#agent-error", Label)
        err.update("")
        event.input.value = ""

        if not val:
            return

        try:
            num = int(val)
        except ValueError:
            err.update("[red]Enter a number[/]")
            return

        if self._mode == "menu":
            self._handle_menu(num)
        elif self._mode in ("select_run", "select_start", "select_stop"):
            self._handle_agent_select(num, self._mode.split("_")[1])

    def _handle_menu(self, num):
        if num == 0:
            self.app.pop_screen()
        elif num == 1:
            self._mode = "select_run"
            self._show_agent_select("run once")
        elif num == 2:
            self._mode = "select_start"
            self._show_agent_select("start")
        elif num == 3:
            self._mode = "select_stop"
            self._show_agent_select("stop")
        elif num == 4:
            started = self._mgr.start_tier("infrastructure")
            result = self.query_one("#agent-result-view", Static)
            if started:
                result.update(f"[green]Started: {', '.join(started)}[/]")
                self.app.log_activity(f"[green]Started infra agents: {', '.join(started)}[/]")
            else:
                result.update("[yellow]No infrastructure agents to start (may already be running)[/]")
            self._show_menu()
        elif num == 5:
            self._mgr.stop_all()
            self.query_one("#agent-result-view", Static).update("[yellow]All agents stopped[/]")
            self.app.log_activity("[yellow]All agents stopped[/]")
            self._show_menu()
        elif num == 6:
            self._run_briefing()

    def _handle_agent_select(self, num, action):
        if num == 0:
            self._show_menu()
            return
        if num < 1 or num > len(self._agent_names):
            self.query_one("#agent-error", Label).update(f"[red]Enter 0-{len(self._agent_names)}[/]")
            return

        name = self._agent_names[num - 1]
        result_widget = self.query_one("#agent-result-view", Static)

        if action == "run":
            result_widget.update(f"[yellow]Running {name}...[/]")
            threading.Thread(target=self._run_agent_thread, args=(name,), daemon=True).start()
        elif action == "start":
            ok, msg = self._mgr.start(name)
            result_widget.update(f"[green]{msg}[/]" if ok else f"[red]{msg}[/]")
            if ok:
                self.app.log_activity(f"[green]{msg}[/]")
            self._show_menu()
        elif action == "stop":
            ok, msg = self._mgr.stop(name)
            result_widget.update(f"[green]{msg}[/]" if ok else f"[red]{msg}[/]")
            if ok:
                self.app.log_activity(f"[yellow]{msg}[/]")
            self._show_menu()

    def _run_agent_thread(self, name):
        self.app.call_from_thread(self.app.log_activity, f"Running agent [bold]{name}[/]...")
        result, err = self._mgr.run_once(name)
        if err:
            self.call_from_thread(self._show_run_result, name, None, err)
        else:
            self.call_from_thread(self._show_run_result, name, result, None)

    def _show_run_result(self, name, result, error):
        widget = self.query_one("#agent-result-view", Static)
        if error:
            widget.update(f"[red]Error running {name}: {error}[/]")
            self.app.log_activity(f"[red]Agent {name} error: {error}[/]")
        else:
            lines = [f"[bold]Agent: {name}[/]"]
            lines.append(f"Status: {'[green]OK[/]' if result.success else '[red]FAILED[/]'}")
            lines.append(f"Duration: {result.duration_seconds}s")
            lines.append(f"Summary: {result.summary}")
            if result.findings:
                lines.append(f"\n[bold]Findings ({len(result.findings)}):[/]")
                for f in result.findings[:15]:
                    sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}.get(sev, "white")
                    lines.append(f"  [{color}][{sev}][/{color}] {f.message}")
            widget.update("\n".join(lines))
            self.app.log_activity(
                f"Agent [bold]{name}[/]: {'OK' if result.success else 'FAILED'} "
                f"({len(result.findings)} findings, {result.duration_seconds}s)"
            )
        self.app._refresh_agent_table()
        self._show_menu()

    def _run_briefing(self):
        self.query_one("#agent-result-view", Static).update("[yellow]Running daily briefing...[/]")
        threading.Thread(target=self._briefing_thread, daemon=True).start()

    def _briefing_thread(self):
        self.app.call_from_thread(self.app.log_activity, "Running daily briefing...")
        result, err = self._mgr.run_once("daily_briefing")
        if err:
            self.call_from_thread(self._show_briefing_result, None, err)
        else:
            self.call_from_thread(self._show_briefing_result, result, None)

    def _show_briefing_result(self, result, error):
        widget = self.query_one("#agent-result-view", Static)
        if error:
            widget.update(f"[red]Briefing error: {error}[/]")
        else:
            lines = ["[bold cyan]═══ DAILY BRIEFING ═══[/]", ""]
            lines.append(result.summary)
            if result.findings:
                lines.append("")
                icons = {"CRITICAL": "[red]!!![/]", "HIGH": "[red]!![/]", "MEDIUM": "[yellow]![/]", "LOW": "[cyan]~[/]", "INFO": "[dim].[/]"}
                for f in result.findings:
                    sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    icon = icons.get(sev, ".")
                    lines.append(f"  {icon} [{sev}] {f.message}")
            widget.update("\n".join(lines))
            self.app.log_activity(
                f"[cyan]Briefing: {result.summary[:80]}[/]"
            )
        self.app._refresh_agent_table()
        self._show_menu()

    def action_cancel(self):
        self.app.pop_screen()


class ProjectManagerApp(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-columns: 3fr 1fr;
        grid-rows: 5fr 3fr 2fr;
    }
    #project-panel {
        border: solid green;
        height: 100%;
    }
    #recommendation-panel {
        border: solid cyan;
        row-span: 2;
        height: 100%;
    }
    #agent-panel {
        border: solid $secondary;
        height: 100%;
    }
    #activity-panel {
        border: solid yellow;
        column-span: 2;
        height: 100%;
    }
    #model-label {
        dock: bottom;
        height: 1;
        background: $surface;
        color: $text;
        text-align: right;
        padding: 0 1;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
    }
    DataTable {
        height: 100%;
    }
    RichLog {
        height: 100%;
    }
    .panel-title {
        text-style: bold;
        color: $accent;
        padding: 0 1;
        height: 1;
    }
    """

    TITLE = "ClaudeProjectManager"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("s", "scan", "Full Scan"),
        ("n", "new_project", "New Project"),
        ("w", "work_on", "Work On..."),
        ("d", "detail", "Detail"),
        ("a", "agents", "Agents"),
        ("b", "briefing", "Briefing"),
        ("v", "pixel_office", "Pixel Office"),
    ]

    def __init__(self):
        super().__init__()
        self._projects = []
        self._recommendation = None
        self._scan_thread = None
        self._ops1_reachable = True
        self._current_model = "Haiku"
        self._last_scan = None
        self._agent_mgr = AgentManager(app=self)

    def compose(self):
        yield Header()
        with Vertical(id="project-panel"):
            yield Label("PROJECTS", classes="panel-title")
            yield DataTable(id="project-table")
        with Vertical(id="recommendation-panel"):
            yield Label("RECOMMENDATION", classes="panel-title")
            yield Static(id="rec-content", markup=True)
            yield Label("", id="model-label")
        with Vertical(id="agent-panel"):
            yield Label("AGENTS", classes="panel-title")
            yield DataTable(id="agent-table")
        with Vertical(id="activity-panel"):
            yield Label("ACTIVITY LOG", classes="panel-title")
            yield RichLog(id="activity-log", highlight=True, markup=True)
        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self):
        table = self.query_one("#project-table", DataTable)
        table.add_columns(
            "Project", "Activity", "Files", "Git", "Dirty",
            "TODOs", "Priority", "Errors"
        )
        table.cursor_type = "row"

        agent_table = self.query_one("#agent-table", DataTable)
        agent_table.add_columns("Agent", "Tier", "Status", "Last Run", "Findings")
        agent_table.cursor_type = "row"
        self._refresh_agent_table()

        self.log_activity("ClaudeProjectManager starting up...")
        self.log_activity("Press [bold]a[/]=Agents  [bold]b[/]=Briefing  [bold]n[/]=New project")
        self._check_bootstrap()
        self.set_timer(0.5, self._initial_scan)
        self.set_interval(SCAN_INTERVAL, self._background_scan)
        self.set_interval(HEARTBEAT_INTERVAL, self._write_heartbeat)
        self.set_interval(AGENT_REFRESH_INTERVAL, self._refresh_agent_table)

    def _check_bootstrap(self):
        missing = check_bootstrap()
        if missing:
            for k in missing:
                self.log_activity(f"[yellow]WARNING: {k} not set in bootstrap.env[/]")
        else:
            self.log_activity("[green]Bootstrap config OK[/]")

    def _initial_scan(self):
        self.log_activity("Connecting to linux-host...")
        self.update_model("Haiku", "startup scan")
        self._load_remote_env()

        cached, scan_time = load_cached_projects()
        if cached:
            self._projects = cached
            self._refresh_table()
            self.log_activity(f"Loaded {len(cached)} cached projects (from {scan_time})")

        self._background_scan()

    def _load_remote_env(self):
        try:
            ok = refresh_remote_env()
            if ok:
                keys = get_env_key_names()
                self.log_activity(f"[green]Remote env loaded: {len(keys)} keys[/]")
            else:
                self.log_activity("[yellow]Remote env: no keys found[/]")
        except Exception as e:
            self.log_activity(f"[red]Remote env error: {e}[/]")

    def _background_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._scan_thread = threading.Thread(target=self._do_scan, daemon=True)
        self._scan_thread.start()

    def _do_scan(self):
        self.call_from_thread(self._update_status, "Scanning linux-host...")
        reachable = check_host_reachable()
        if not reachable:
            self._ops1_reachable = False
            self.call_from_thread(
                self.log_activity, "[red]linux-host UNREACHABLE[/]"
            )
            self.call_from_thread(
                self._update_status, "linux-host unreachable -- retrying next cycle"
            )
            return

        self._ops1_reachable = True
        projects, err = scan_projects()
        if err:
            self.call_from_thread(
                self.log_activity, f"[red]Scan error: {err}[/]"
            )
            return

        self._projects = projects or []
        self._last_scan = datetime.now()
        self.call_from_thread(self._refresh_table)
        self.call_from_thread(self._update_recommendation)
        self.call_from_thread(
            self.log_activity,
            f"[green]Scan complete: {len(self._projects)} projects[/]"
        )
        self.call_from_thread(
            self._update_status,
            f"Last scan: {self._last_scan.strftime('%H:%M:%S')} -- {len(self._projects)} projects"
        )

    def _refresh_table(self):
        table = self.query_one("#project-table", DataTable)
        table.clear()
        for p in sorted(self._projects, key=lambda x: x.get("last_activity_days") or 999):
            age = p.get("last_activity_days")
            age_str = f"{age:.0f}d" if age is not None else "--"
            todos = ""
            if p.get("todos_total", 0) > 0:
                todos = f"{p['todos_done']}/{p['todos_total']}"
            table.add_row(
                p["name"],
                age_str,
                str(p.get("file_count", 0)),
                "Y" if p.get("is_git") else "N",
                "Y" if p.get("git_dirty") else "",
                todos,
                p.get("priority") or "",
                "ERR" if p.get("has_errors") else "",
            )

    def _update_recommendation(self):
        rec = compute_recommendation(self._projects)
        self._recommendation = rec
        content = self.query_one("#rec-content", Static)
        if not rec or not rec.get("recommendation"):
            content.update("No recommendation at this time.")
            return

        lines = [
            f"[bold cyan]RECOMMENDATION: {rec['recommendation']}[/]",
            f"[white]Why:[/] {rec['reason']}",
        ]
        if rec.get("runner_up"):
            lines.append(f"\n[bold]Runner-up:[/] {rec['runner_up']}")
            lines.append(f"  {rec.get('runner_up_reason', '')}")
        if rec.get("also_consider"):
            lines.append(f"\n[bold]Also consider:[/] {rec['also_consider']}")
            lines.append(f"  {rec.get('also_consider_reason', '')}")
        content.update("\n".join(lines))

    def _update_status(self, text):
        bar = self.query_one("#status-bar", Static)
        bar.update(text)

    def _write_heartbeat(self):
        hb = STATE_DIR / "heartbeat"
        try:
            hb.write_text(datetime.now().isoformat())
        except Exception:
            pass

    def update_model(self, model, reason=""):
        self._current_model = model
        label = self.query_one("#model-label", Label)
        label.update(f"Model: {model}")
        if reason:
            self.log_activity(f"Model -> {model}: {reason}")
            self._audit(f"model_switch: {model} reason={reason}")

    def log_activity(self, message):
        try:
            log = self.query_one("#activity-log", RichLog)
            ts = datetime.now().strftime("%H:%M:%S")
            log.write(f"[{ts}] {message}")
        except Exception:
            pass

        try:
            activity_file = STATE_DIR / "activity.log"
            with open(activity_file, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] {message}\n")
        except Exception:
            pass

    def _audit(self, entry):
        try:
            audit_file = STATE_DIR / "audit.log"
            with open(audit_file, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] {entry}\n")
        except Exception:
            pass

    def _refresh_agent_table(self):
        try:
            agent_table = self.query_one("#agent-table", DataTable)
        except Exception:
            return
        agent_table.clear()
        status_rows = self._agent_mgr.status()
        for s in status_rows:
            running = "RUN" if s["running"] else ""
            if s["last_ok"] is True:
                ok_str = "OK"
            elif s["last_ok"] is False:
                ok_str = "FAIL"
            else:
                ok_str = "-"
            last = str(s["last_run"])[:19] if len(str(s["last_run"])) > 19 else str(s["last_run"])
            agent_table.add_row(
                s["name"],
                s["tier"],
                f"{running} {ok_str}".strip(),
                last,
                str(s["findings"]),
            )
        self._write_pixel_office_status()

    def action_agents(self):
        self.push_screen(AgentControlScreen(self._agent_mgr))

    def action_pixel_office(self):
        self.log_activity("Launching Pixel Office window...")
        self._write_pixel_office_status()
        import subprocess as _sp
        import sys as _sys
        _sp.Popen(
            [_sys.executable, "-m", "pixel_office.office"],
            cwd=str(STATE_DIR.parent),
        )

    def _write_pixel_office_status(self):
        from pixel_office.bridge import write_live_status
        status = {}
        for s in self._agent_mgr.status():
            status[s["name"]] = {
                "running": s["running"],
                "task": "",
            }
        write_live_status(status)

    def action_briefing(self):
        self.log_activity("Running daily briefing...")
        threading.Thread(target=self._run_briefing_bg, daemon=True).start()

    def _run_briefing_bg(self):
        self.call_from_thread(self.update_model, "Sonnet", "daily briefing")
        result, err = self._agent_mgr.run_once("daily_briefing")
        if err:
            self.call_from_thread(self.log_activity, f"[red]Briefing error: {err}[/]")
        else:
            self.call_from_thread(
                self.log_activity,
                f"[cyan]Briefing: {result.summary}[/]"
            )
            if result.findings:
                for f in result.findings[:10]:
                    sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    icons = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "INFO": "."}
                    self.call_from_thread(
                        self.log_activity,
                        f"  {icons.get(sev, '.')} [{sev}] {f.message}"
                    )
        self.call_from_thread(self._refresh_agent_table)
        self.call_from_thread(self.update_model, "Haiku", "briefing complete")

    def action_refresh(self):
        self._refresh_table()
        self._update_recommendation()
        self._refresh_agent_table()

    def action_scan(self):
        self.log_activity("Manual scan triggered...")
        self._background_scan()

    def action_new_project(self):
        self.push_screen(NewProjectScreen())

    def handle_new_project(self, result):
        self.log_activity(f"Creating project [bold]{result['name']}[/]...")
        thread = threading.Thread(
            target=self._create_project_remote, args=(result,), daemon=True
        )
        thread.start()

    def _create_project_remote(self, spec):
        name = spec["name"]
        desc = spec["description"]
        group = spec["group"]
        icon = spec["icon"]
        tags = spec["tags"]
        init_git = spec["init_git"]
        today = datetime.now().strftime("%Y-%m-%d")

        # 1. Create directory and scaffold on linux-host
        readme_content = f"# {name}\\n\\n{desc}\\n"
        changelog_content = f"# CHANGELOG\\n\\n## {today}\\n\\n- Project created by ClaudeProjectManager\\n"
        todo_content = f"# TODO -- {name}\\n\\n- [ ] Define project scope and requirements\\n- [ ] Set up development environment\\n- [ ] Implement core functionality\\n"
        claude_content = f"# {name}\\n\\n## Purpose\\n\\n{desc}\\n\\n## Project Host\\n\\nThis project lives on linux-host (YOUR_HOST_IP) at `~/{name}/`.\\n"

        scaffold_cmds = [
            f"mkdir -p ~/{name}",
            f"echo -e '{readme_content}' > ~/{name}/README.md",
            f"echo -e '{changelog_content}' > ~/{name}/CHANGELOG.md",
            f"echo -e '{todo_content}' > ~/{name}/TODO.md",
            f"echo -e '{claude_content}' > ~/{name}/CLAUDE.md",
        ]

        if init_git:
            scaffold_cmds.extend([
                f"cd ~/{name} && git init",
                f"cd ~/{name} && git add -A",
                f'cd ~/{name} && git commit -m "[PM] Initial project scaffold"',
            ])

        cmd = " && ".join(scaffold_cmds)
        stdout, stderr, rc = run_ssh(cmd, timeout=15)
        if rc != 0:
            self.call_from_thread(
                self.log_activity,
                f"[red]Failed to scaffold {name}: {stderr[:200]}[/]"
            )
            return

        self.call_from_thread(
            self.log_activity,
            f"[green]Scaffolded {name} on linux-host[/]"
        )
        self.call_from_thread(self._audit, f"project_created: {name} on linux-host")

        # 2. Add to web-host dashboard services.json
        self.call_from_thread(
            self.log_activity, f"Adding {name} to web-host dashboard..."
        )

        proj_id = name.lower().replace(" ", "-")
        new_entry = {
            "id": proj_id,
            "name": name,
            "description": desc,
            "group": group,
            "icon": icon,
            "hostname": "linux-host.web-host.com",
            "ip": "YOUR_HOST_IP",
            "tags": tags + ["project", "linux-host"],
            "links": [
                {
                    "label": "SSH to linux-host",
                    "url": "/guac/",
                    "icon": "↗",
                }
            ],
            "note": f"Project dir: ~/{name}",
        }

        add_script = (
            "python3 -c \""
            "import json, sys; "
            f"entry = {json.dumps(new_entry)}; "
            "f = '/var/www/dashboard/data/services.json'; "
            "data = json.loads(open(f).read()); "
            f"ids = [s['id'] for s in data]; "
            f"id_val = '{proj_id}'; "
            "already = id_val in ids; "
            "exec('data.append(entry)') if not already else None; "
            "open(f, 'w').write(json.dumps(data, indent=2)); "
            "print('added' if not already else 'exists')"
            "\""
        )

        stdout2, stderr2, rc2 = run_ssh(
            f"ssh web-host {add_script}",
            timeout=15,
        )
        if rc2 != 0:
            self.call_from_thread(
                self.log_activity,
                f"[yellow]Dashboard update failed: {stderr2[:200]}. "
                f"You can add manually later.[/]"
            )
        else:
            result_text = stdout2.strip()
            if result_text == "added":
                self.call_from_thread(
                    self.log_activity,
                    f"[green]Added {name} to web-host dashboard[/]"
                )
            else:
                self.call_from_thread(
                    self.log_activity,
                    f"[yellow]{name} already on dashboard[/]"
                )

        # 3. Rescan to pick up the new project
        self.call_from_thread(
            self.log_activity, "Rescanning projects..."
        )
        self._do_scan()

    def action_work_on(self):
        self.push_screen(
            WorkOnProjectScreen(self._projects, self._recommendation),
        )

    def handle_work_selection(self, project_name):
        if not project_name:
            return
        self.log_activity(f"[bold cyan]Working on: {project_name}[/]")
        self._audit(f"work_selected: {project_name}")
        self._update_status(f"ACTIVE: {project_name}")

        thread = threading.Thread(
            target=self._load_project_context, args=(project_name,), daemon=True
        )
        thread.start()

    def _load_project_context(self, name):
        self.call_from_thread(
            self.log_activity, f"Loading context for {name}..."
        )

        docs_to_read = ["CLAUDE.md", "README.md", "TODO.md", "SESSION_NOTES.md", "STATUS.md"]
        for doc in docs_to_read:
            stdout, stderr, rc = run_ssh(
                f"head -50 ~/{name}/{doc} 2>/dev/null", timeout=10
            )
            if rc == 0 and stdout.strip():
                lines = stdout.strip().split("\n")
                preview = lines[0] if lines else ""
                line_count = len(lines)
                self.call_from_thread(
                    self.log_activity,
                    f"  {doc}: {line_count} lines -- {preview[:60]}"
                )

        stdout, stderr, rc = run_ssh(
            f"ls ~/{name}/ 2>/dev/null | head -20", timeout=10
        )
        if rc == 0 and stdout.strip():
            files = stdout.strip().split("\n")
            self.call_from_thread(
                self.log_activity,
                f"  Files: {', '.join(files[:10])}"
                + (f" (+{len(files)-10} more)" if len(files) > 10 else "")
            )

        self.call_from_thread(
            self.log_activity,
            f"[bold green]Ready to work on {name}. "
            f"SSH: YOUR_SSH_USER@YOUR_HOST_IP ~/{name}/[/]"
        )

    def action_detail(self):
        table = self.query_one("#project-table", DataTable)
        if table.cursor_row is None:
            return
        row = table.get_row_at(table.cursor_row)
        project_name = row[0]
        project_data = None
        for p in self._projects:
            if p["name"] == project_name:
                project_data = p
                break
        if project_data:
            self.push_screen(ProjectDetailScreen(project_data))

    def _get_selected_project_name(self):
        table = self.query_one("#project-table", DataTable)
        if table.cursor_row is not None:
            row = table.get_row_at(table.cursor_row)
            return row[0]
        return None


def run_tui():
    app = ProjectManagerApp()
    app.run()
