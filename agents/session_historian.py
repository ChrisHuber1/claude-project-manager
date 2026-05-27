"""Agent 13: Session Historian -- end-of-session summaries, SESSION_NOTES updates, wiki narrative."""

import json
from datetime import datetime

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class SessionHistorianAgent(BaseAgent):
    name = "session_historian"
    description = "End-of-session summaries, SESSION_NOTES.md updates, wiki cross-session narrative"
    default_interval = 0
    tier = "session"

    def check(self) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=[],
            summary="Session historian ready -- use record_session() at end of session",
        )

    def record_session(self, project, summary, decisions=None, files_changed=None,
                       blockers=None, next_steps=None):
        findings = []
        today = datetime.now().strftime("%Y-%m-%d")
        now = datetime.now().strftime("%H:%M")
        decisions = decisions or []
        files_changed = files_changed or []
        blockers = blockers or []
        next_steps = next_steps or []

        session_entry = f"\n## Session {today} {now}\n\n"
        session_entry += f"**Summary:** {summary}\n\n"

        if decisions:
            session_entry += "**Decisions:**\n"
            for d in decisions:
                session_entry += f"- {d}\n"
            session_entry += "\n"

        if files_changed:
            session_entry += "**Files changed:**\n"
            for f in files_changed[:20]:
                session_entry += f"- `{f}`\n"
            session_entry += "\n"

        if blockers:
            session_entry += "**Blockers:**\n"
            for b in blockers:
                session_entry += f"- {b}\n"
            session_entry += "\n"

        if next_steps:
            session_entry += "**Next steps:**\n"
            for n in next_steps:
                session_entry += f"- {n}\n"
            session_entry += "\n"

        path = f"~/{project}"
        stdout, stderr, rc = self.ssh(
            f"test -f {path}/SESSION_NOTES.md && echo exists || echo missing",
            timeout=5,
        )

        if "missing" in stdout:
            header = f"# Session Notes -- {project}\n\n"
            self.ssh(
                f"cat > {path}/SESSION_NOTES.md << 'SEOF'\n{header}\nSEOF",
                timeout=5,
            )
            findings.append(Finding(
                severity=Severity.INFO,
                source="session_historian",
                message=f"Created SESSION_NOTES.md for {project}",
                host="linux-host",
            ))

        escaped_entry = session_entry.replace("'", "'\\''")
        self.ssh(
            f"echo '{escaped_entry}' >> {path}/SESSION_NOTES.md",
            timeout=10,
        )

        self.ssh(
            f"cd {path} && git add SESSION_NOTES.md && "
            f"git commit -m '[PM] Session notes {today}' 2>/dev/null",
            timeout=15,
        )

        findings.append(Finding(
            severity=Severity.INFO,
            source="session_historian",
            message=f"Session recorded for {project}: {summary[:80]}",
            host="linux-host",
        ))

        wiki_entry = f"## {project} -- {today} {now}\n\n{summary}\n\n"
        if decisions:
            wiki_entry += "Decisions: " + "; ".join(decisions) + "\n\n"
        if blockers:
            wiki_entry += "Blockers: " + "; ".join(blockers) + "\n\n"

        self.ssh(
            f"echo '{wiki_entry.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' "
            f">> ~/obsidian-vault/.raw/projects/{project}/session-log.md",
            timeout=10,
        )

        findings.append(Finding(
            severity=Severity.INFO,
            source="session_historian",
            message=f"Wiki session log updated for {project}",
            host="linux-host",
        ))

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"Session recorded for {project}",
        )

    def get_last_session(self, project):
        path = f"~/{project}"
        stdout, stderr, rc = self.ssh(
            f"tail -30 {path}/SESSION_NOTES.md 2>/dev/null",
            timeout=10,
        )
        return stdout.strip() if rc == 0 else None

    def get_session_history(self, project, count=5):
        path = f"~/{project}"
        stdout, stderr, rc = self.ssh(
            f"cd {path} && git log --oneline -- SESSION_NOTES.md 2>/dev/null | head -{count}",
            timeout=10,
        )
        return stdout.strip() if rc == 0 else None
