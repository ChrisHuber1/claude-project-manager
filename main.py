#!/usr/bin/env python3
"""ClaudeProjectManager -- autonomous AI project manager TUI."""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(exist_ok=True)

from app import run_tui

if __name__ == "__main__":
    run_tui()
