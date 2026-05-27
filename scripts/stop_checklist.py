"""Stop hook checklist -- runs after every assistant response.

Command-type hook (not prompt-type) to avoid the infinite loop issue.
Always exits 0 -- outputs reminders only, never blocks.
See memory: feedback_stop_hook_loop.md for why this must be command-type.
"""

import os
import subprocess
import sys

PROJECT_DIR = os.environ.get(
    "CLAUDE_PROJECT_DIR",
    r"C:\Users\YOUR_USER\ClaudeProjectManager",
)

reminders = []

scratchpad = os.path.join(PROJECT_DIR, "SCRATCHPAD.md")
if os.path.isfile(scratchpad):
    try:
        with open(scratchpad, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if content:
            reminders.append(
                "SCRATCHPAD.md has active task state -- consider updating "
                "memory and clearing it if this task is complete."
            )
    except OSError:
        pass

try:
    result = subprocess.run(
        ["git", "diff", "--stat", "--cached"],
        capture_output=True,
        text=True,
        cwd=PROJECT_DIR,
        timeout=5,
    )
    if result.stdout.strip():
        reminders.append(
            "Staged git changes detected -- consider committing if work is complete."
        )
except (subprocess.TimeoutExpired, FileNotFoundError):
    pass

if reminders:
    print("TASK CHECKLIST: " + " | ".join(reminders))

sys.exit(0)
