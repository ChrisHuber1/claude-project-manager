#!/usr/bin/env bash
# Agent cron runner for linux-host — runs agents locally without SSH overhead.
# Usage: agent-cron.sh <agent_name> [--json]
#   e.g. agent-cron.sh range_health
#        agent-cron.sh daily_briefing --json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"

mkdir -p "$LOG_DIR"

AGENT="${1:?Usage: agent-cron.sh <agent_name>}"
shift
EXTRA_ARGS="$*"

export AGENT_LOCAL_MODE=1
export PYTHONPATH="$PROJECT_DIR"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

{
    echo "[$TIMESTAMP] Running agent: $AGENT"
    cd "$PROJECT_DIR"
    python3 -m agents.cli run "$AGENT" $EXTRA_ARGS 2>&1
    echo "[$TIMESTAMP] Agent $AGENT finished (exit=$?)"
} >> "$LOG_DIR/agent-cron.log" 2>&1
