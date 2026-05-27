# ClaudeProjectManager

An autonomous AI agent that manages 12+ software projects across a multi-host cyber range. It scans project state, commits code on feature branches, monitors infrastructure health, and coordinates work across machines ;  with safety guardrails that prevent it from doing anything destructive without human approval.

I manage a home lab with 8+ hosts running everything from SIEM to trading bots to a VPN gateway. Keeping 12 projects moving across that many systems meant I was spending more time on context-switching than building. So I built an AI project manager that maintains the context for me.

## What It Actually Does

- **Project scanning:** SSHs into hosts, reads project state, tracks status across the portfolio
- **Autonomous commits:** Works on feature branches (`pm/YYYY-MM-DD-slug`), never touches main directly
- **Agent framework:** Specialized agents for SIEM health, trading bot monitoring, range diagnostics
- **Obsidian sync:** Dual-writes project state to a local JSON registry and an Obsidian vault for cross-project knowledge
- **Relay system:** Dead-drop file coordination between multiple machines running Claude Code sessions
- **Phone alerting:** Pushes ntfy notifications on critical findings; audible alerts via Windows SAPI when human input is needed

## Safety Guardrails

This is the part that matters most. An AI agent with SSH access to your infrastructure needs hard limits, not suggestions.

| Guardrail | What It Does |
|---|---|
| Scope containment | Blocks writes outside the project directory and a short allowlist |
| Session time limit | Kills the session after 2 hours to prevent runaway execution |
| File deletion tracking | Counts deletions per session; alerts if threshold exceeded |
| Forbidden operations | Hard block on `rm -rf`, `DROP TABLE`, force-push, and other destructive commands |
| Network protection | Prevents outbound connections to unlisted destinations |
| Kill switch | File-based halt that stops all agent activity immediately |
| Audit log | Append-only log of all operations ;  key names only, never values |

The guardrail system runs as a pre-check on every tool call. It's not advisory ;  it blocks the operation and logs it.

**Lesson learned the hard way:** Editing the guardrail's own source code mid-session can deadlock all write operations if an intermediate state breaks the evaluator. The enforcer is always rewritten as a complete file, never patched incrementally.

## Skills System

Packaged workflows for common operations:

- **range-health** ;  SSH into all hosts, check services, report what's down
- **trading-bot-check** ;  Pull trade logs, check bot status, report PnL
- **ms-security-status** ;  Track progress on Microsoft security training plan
- **onboard-employee** ;  Step-by-step device onboarding for remote employees
- **llm-council** ;  Multi-model review of proposed changes (experimental)

## Architecture

```
Windows (MainPC)
+--------------------------------+
| ClaudeProjectManager           |
| ├── agents/        (agent framework, scoring, base class)
| ├── guardrails/    (enforce.py, config.json)
| ├── scripts/       (SSH helpers, cron runners, API)
| ├── state/         (projects.json, agent results, audit log)
| ├── relay/         (dead-drop coordination)
| └── .claude/skills/ (packaged workflows)
+---------------+----------------+
                |
          SSH   |
                v
+--------------------------------+
| ops1 (Linux)                   |
| ├── 12 managed projects        |
| ├── environment (secrets)      |
| └── agent_api.py (port 8801)   |
+--------------------------------+
                |
          SSH   |
                v
+--------------------------------+
| Range hosts (pve1, pve2,       |
|   siem01, huberhouse, etc.)    |
+--------------------------------+
```

## Decisions and Tradeoffs

**File-based state over a database:** The state directory uses JSON files and flat text. A database would be cleaner for querying, but this system needs to survive session restarts, context compaction, and the AI equivalent of "I forgot what I was doing." Files are debuggable, diffable, and I can fix state by editing a JSON file.

**Obsidian as shared knowledge layer:** I tried using the AI's context window as the knowledge layer. It works until the context gets compacted and the AI loses critical project context. Writing to Obsidian means the knowledge survives even if the conversation doesn't. The vault is version-controlled and searchable independently.

**Dead-drop relay over message queues:** Two machines might be running Claude Code sessions that need to coordinate. A message queue would be the "right" answer, but a relay system using files on a shared SSH target is simpler, has zero dependencies, and fails in ways I can debug by reading a text file.

**Guardrails as enforcement, not guidance:** Early versions used the AI's instructions to "be careful." That works until it doesn't. The guardrail system is a Python pre-check that returns BLOCK or ALLOW before any tool execution. The AI can't reason its way around a hard block.

## What I'd Do Differently

- The polling loop should run as a separate process writing to state files, not inside a Claude Code conversation. Long-running conversations accumulate context, trigger compaction, and lose state. I'm solving a process management problem with a conversation tool.
- The relay system works but is fragile. If I rebuild it, I'd use a lightweight message broker or even just a shared SQLite file over NFS.

## Current State

In daily use managing all projects in my portfolio. The agent framework, guardrails, skills, and Obsidian sync are all functional. The relay system works but is lightly used. Phone alerting fires on critical findings.

This repo is the meta-project ;  the tool I use to manage everything else I've built.
