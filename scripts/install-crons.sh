#!/usr/bin/env bash
# Install agent cron schedules on linux-host.
# Run once after cloning the repo: bash ~/ClaudeProjectManager/scripts/install-crons.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUNNER="$PROJECT_DIR/scripts/agent-cron.sh"

chmod +x "$RUNNER"

mkdir -p "$PROJECT_DIR/state/agent_results"
mkdir -p "$PROJECT_DIR/logs"

CRON_BLOCK="# --- ClaudeProjectManager agents (managed) ---
*/10 * * * * $RUNNER range_health
*/15 * * * * $RUNNER range_manager
*/30 * * * * $RUNNER security_monitor
0 * * * *    $RUNNER siem_watchdog
0 4 * * *    $RUNNER risk_drift
30 4 * * *   $RUNNER project_tracker
0 5 * * *    $RUNNER cross_project_intel
30 5 * * *   $RUNNER backup_guardian
0 6 * * *    $RUNNER security_scanner
30 6 * * *   $RUNNER daily_briefing
# --- end ClaudeProjectManager agents ---"

EXISTING=$(crontab -l 2>/dev/null || true)

if echo "$EXISTING" | grep -q "ClaudeProjectManager agents"; then
    echo "Replacing existing agent cron block..."
    CLEANED=$(echo "$EXISTING" | sed '/# --- ClaudeProjectManager agents/,/# --- end ClaudeProjectManager agents/d')
    echo "$CLEANED
$CRON_BLOCK" | crontab -
else
    echo "Adding agent cron block..."
    echo "$EXISTING
$CRON_BLOCK" | crontab -
fi

echo "Cron schedules installed:"
echo ""
echo "  Every 10 min:  range_health"
echo "  Every 15 min:  range_manager"
echo "  Every 30 min:  security_monitor"
echo "  Hourly:        siem_watchdog"
echo "  04:00 daily:   risk_drift"
echo "  04:30 daily:   project_tracker"
echo "  05:00 daily:   cross_project_intel"
echo "  05:30 daily:   backup_guardian"
echo "  06:00 daily:   security_scanner"
echo "  06:30 daily:   daily_briefing"
echo ""
echo "Logs: $PROJECT_DIR/logs/agent-cron.log"
echo "Results: $PROJECT_DIR/state/agent_results/"
