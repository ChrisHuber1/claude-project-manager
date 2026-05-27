"""CLI entry point for running agents standalone."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

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

from agents.runner import AgentManager, list_agents, get_agent_info


def main():
    parser = argparse.ArgumentParser(description="ClaudeProjectManager Agent CLI")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List all available agents")
    sub.add_parser("status", help="Show last run status for all agents")

    run_p = sub.add_parser("run", help="Run an agent once")
    run_p.add_argument("agent", help="Agent name")
    run_p.add_argument("--json", action="store_true", help="JSON output")

    start_p = sub.add_parser("start", help="Start an agent loop")
    start_p.add_argument("agent", help="Agent name or 'all' or tier name")
    start_p.add_argument("--interval", type=int, help="Override interval in seconds")

    brief_p = sub.add_parser("briefing", help="Run daily briefing")
    brief_p.add_argument("--json", action="store_true", help="JSON output")

    scaffold_p = sub.add_parser("scaffold", help="Create a new project")
    scaffold_p.add_argument("name", help="Project name")
    scaffold_p.add_argument("type", help="Project type (python-cli, python-api, fullstack-next, game-godot, etc.)")
    scaffold_p.add_argument("--description", default="", help="Project description")

    session_p = sub.add_parser("session", help="Record session notes")
    session_p.add_argument("project", help="Project name")
    session_p.add_argument("summary", help="Session summary")

    args = parser.parse_args()
    mgr = AgentManager()

    if args.command == "list":
        print(f"{'Name':<25} {'Tier':<15} {'Interval':<10} Description")
        print("-" * 90)
        for info in get_agent_info():
            iv = f"{info['interval']}s" if info['interval'] > 0 else "manual"
            print(f"{info['name']:<25} {info['tier']:<15} {iv:<10} {info['description']}")

    elif args.command == "status":
        rows = mgr.status()
        print(f"{'Agent':<25} {'Running':<10} {'Last Run':<22} {'OK':<5} {'Findings'}")
        print("-" * 80)
        for r in rows:
            ok = "Y" if r["last_ok"] else ("N" if r["last_ok"] is not None else "-")
            running = "YES" if r["running"] else ""
            last = r["last_run"][:19] if len(r["last_run"]) > 19 else r["last_run"]
            print(f"{r['name']:<25} {running:<10} {last:<22} {ok:<5} {r['findings']}")

    elif args.command == "run":
        result, err = mgr.run_once(args.agent)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        if hasattr(args, 'json') and args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"Agent: {result.agent_name}")
            print(f"Status: {'OK' if result.success else 'FAILED'}")
            print(f"Duration: {result.duration_seconds}s")
            print(f"Summary: {result.summary}")
            if result.error:
                print(f"Error: {result.error}")
            if result.findings:
                print(f"\nFindings ({len(result.findings)}):")
                for f in result.findings:
                    sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    print(f"  [{sev}] {f.message}")
                    if f.details:
                        for line in f.details.split("\n")[:3]:
                            print(f"         {line}")

    elif args.command == "briefing":
        result, err = mgr.run_once("daily_briefing")
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        if hasattr(args, 'json') and args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print("=" * 60)
            print(f"  DAILY BRIEFING -- {result.run_time[:10]}")
            print("=" * 60)
            print(f"\n{result.summary}\n")
            if result.findings:
                for f in result.findings:
                    sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
                    icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~", "INFO": "."}
                    print(f"  {icon.get(sev, '.')} [{sev}] {f.message}")

    elif args.command == "scaffold":
        from agents.scaffold_agent import ScaffoldAgent
        agent = ScaffoldAgent()
        result = agent.scaffold_project(args.name, args.type, args.description)
        if result.success:
            print(f"Created {args.name} ({args.type})")
            for f in result.findings:
                print(f"  {f.message}")
        else:
            print(f"Failed: {result.error}")
            sys.exit(1)

    elif args.command == "session":
        from agents.session_historian import SessionHistorianAgent
        agent = SessionHistorianAgent()
        result = agent.record_session(args.project, args.summary)
        for f in result.findings:
            print(f"  {f.message}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
