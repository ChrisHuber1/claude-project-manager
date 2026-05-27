"""Obsidian vault sync for project registry.

Writes scanner output to .raw/projects/registry.md in the Obsidian vault
so both MainPC and Laptop sessions share project state.
"""

import json
import re
from datetime import datetime
from pathlib import Path


def _vault_path():
    from config import OBSIDIAN_VAULT_PATH
    p = Path(OBSIDIAN_VAULT_PATH)
    return p if p.is_dir() else None


def format_registry_note(projects, scan_time):
    ts = scan_time if isinstance(scan_time, str) else datetime.now().isoformat()
    ts_short = ts[:16].replace("T", " ")

    header = f"""---
type: machine-registry
title: Project Registry
updated: {ts}
scan_source: linux-host
project_count: {len(projects)}
tags:
  - machine-data
  - projects
  - registry
---

# Project Registry

Last scanned: {ts_short} from linux-host

| Project | Activity | Files | Branch | Dirty | Errors | Priority |
|---------|----------|-------|--------|-------|--------|----------|
"""
    rows = []
    for p in projects:
        activity = p.get("last_activity_days")
        activity_str = f"{activity}d" if activity is not None else "-"
        rows.append(
            f"| {p['name']} "
            f"| {activity_str} "
            f"| {p.get('file_count', '-')} "
            f"| {p.get('branch') or '-'} "
            f"| {'Yes' if p.get('git_dirty') else 'No'} "
            f"| {'Yes' if p.get('has_errors') else 'No'} "
            f"| {p.get('priority') or '-'} |"
        )

    table = "\n".join(rows)
    json_block = json.dumps(projects, indent=2)

    return f"""{header}{table}

<!-- MACHINE DATA -->
```json
{json_block}
```
<!-- END MACHINE DATA -->
"""


def parse_registry_note(content):
    scan_time = None
    for line in content.splitlines():
        if line.startswith("updated:"):
            scan_time = line.split(":", 1)[1].strip()
            break

    match = re.search(
        r"<!-- MACHINE DATA -->\s*```json\s*\n(.*?)\n```\s*<!-- END MACHINE DATA -->",
        content,
        re.DOTALL,
    )
    if not match:
        return [], scan_time
    try:
        projects = json.loads(match.group(1))
        return projects, scan_time
    except json.JSONDecodeError:
        return [], scan_time


def publish_to_vault(projects, scan_time):
    vault = _vault_path()
    if vault is None:
        return False
    registry = vault / ".raw" / "projects" / "registry.md"
    registry.parent.mkdir(parents=True, exist_ok=True)
    content = format_registry_note(projects, scan_time)
    registry.write_text(content, encoding="utf-8")
    return True


def load_from_vault_file():
    vault = _vault_path()
    if vault is None:
        return None
    registry = vault / ".raw" / "projects" / "registry.md"
    if not registry.exists():
        return None
    content = registry.read_text(encoding="utf-8")
    projects, scan_time = parse_registry_note(content)
    if not projects:
        return None
    return projects, scan_time
