"""Agent 10: Scaffold Agent -- bootstrap new projects by type with full wiring."""

import json
from datetime import datetime

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


TEMPLATES = {
    "python-cli": {
        "files": {
            "main.py": '#!/usr/bin/env python3\n"""{{name}} -- {{description}}"""\n\n\ndef main():\n    pass\n\n\nif __name__ == "__main__":\n    main()\n',
            "requirements.txt": "",
            "Makefile": 'lint:\n\truff check .\n\ntest:\n\tpython3 -m pytest -v\n\nformat:\n\truff format .\n',
        },
        "gitignore_extra": "",
    },
    "python-api": {
        "files": {
            "main.py": '#!/usr/bin/env python3\n"""{{name}} API"""\n\nfrom fastapi import FastAPI\n\napp = FastAPI(title="{{name}}")\n\n\n@app.get("/health")\ndef health():\n    return {"status": "ok"}\n',
            "requirements.txt": "fastapi\nuvicorn\n",
            "Makefile": 'run:\n\tuvicorn main:app --reload\n\nlint:\n\truff check .\n\ntest:\n\tpython3 -m pytest -v\n',
        },
        "gitignore_extra": "",
    },
    "fullstack-next": {
        "files": {},
        "init_cmd": "npx create-next-app@latest {{name}} --typescript --eslint --tailwind --app --src-dir --no-import-alias",
        "gitignore_extra": ".next/\nnode_modules/\n",
    },
    "fullstack-django": {
        "files": {},
        "init_cmd": "django-admin startproject {{name}} .",
        "gitignore_extra": "db.sqlite3\nmedia/\nstatic_collected/\n",
    },
    "game-godot": {
        "files": {},
        "gitignore_extra": ".godot/\n*.import\nexport_presets.cfg\n",
    },
    "game-pygame": {
        "files": {
            "main.py": '#!/usr/bin/env python3\n"""{{name}} -- {{description}}"""\n\nimport pygame\n\n\ndef main():\n    pygame.init()\n    screen = pygame.display.set_mode((800, 600))\n    pygame.display.set_caption("{{name}}")\n    clock = pygame.time.Clock()\n    running = True\n\n    while running:\n        for event in pygame.event.get():\n            if event.type == pygame.QUIT:\n                running = False\n\n        screen.fill((0, 0, 0))\n        pygame.display.flip()\n        clock.tick(60)\n\n    pygame.quit()\n\n\nif __name__ == "__main__":\n    main()\n',
            "requirements.txt": "pygame\n",
        },
        "gitignore_extra": "",
    },
    "ansible": {
        "files": {
            "ansible.cfg": "[defaults]\ninventory = inventory.yml\nhost_key_checking = False\n",
            "inventory.yml": "all:\n  hosts:\n",
            "playbooks/main.yml": "---\n- name: {{name}}\n  hosts: all\n  tasks: []\n",
        },
        "gitignore_extra": "*.retry\n",
    },
}


@register
class ScaffoldAgent(BaseAgent):
    name = "scaffold"
    description = "Bootstrap new projects by type with linting, tests, CI, GitHub, wiki wiring"
    default_interval = 0
    tier = "management"

    def check(self) -> AgentResult:
        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=[],
            summary="Scaffold agent ready -- use scaffold_project() to create",
        )

    def scaffold_project(self, name, project_type, description="", tags=None, group="Projects"):
        findings = []
        tags = tags or []
        today = datetime.now().strftime("%Y-%m-%d")

        template = TEMPLATES.get(project_type)
        if not template:
            return AgentResult(
                agent_name=self.name, success=False,
                error=f"Unknown type: {project_type}. Available: {', '.join(TEMPLATES.keys())}",
            )

        path = f"~/{name}"
        self.ssh(f"mkdir -p {path}", timeout=5)

        gitignore_base = (
            "# Secrets\n.secrets/\n*.env\n!*.env.example\n*.pem\n*.key\n\n"
            "# Python\n__pycache__/\n*.pyc\nvenv/\n.venv/\n\n"
            "# OS\n.DS_Store\nThumbs.db\n\n"
            "# IDE\n.vscode/\n.idea/\n\n"
            "# Logs\n*.log\n\n"
            "# Node\nnode_modules/\n"
        )
        gitignore = gitignore_base + template.get("gitignore_extra", "")
        self.ssh(f"cat > {path}/.gitignore << 'GEOF'\n{gitignore}\nGEOF", timeout=5)

        for filename, content in template.get("files", {}).items():
            content = content.replace("{{name}}", name).replace("{{description}}", description)
            dir_part = "/".join(filename.split("/")[:-1])
            if dir_part:
                self.ssh(f"mkdir -p {path}/{dir_part}", timeout=5)
            self.ssh(f"cat > {path}/{filename} << 'FEOF'\n{content}\nFEOF", timeout=5)

        init_cmd = template.get("init_cmd", "")
        if init_cmd:
            init_cmd = init_cmd.replace("{{name}}", name)
            stdout, stderr, rc = self.ssh(f"cd {path} && {init_cmd}", timeout=120)
            if rc != 0:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source="scaffold",
                    message=f"Init command failed: {init_cmd}",
                    details=stderr[:300],
                    host="linux-host",
                ))

        readme = f"# {name}\n\n{description}\n"
        todo = f"# TODO -- {name}\n\n- [ ] Define scope and requirements\n- [ ] Set up development environment\n- [ ] Implement core functionality\n"
        claude_md = (
            f"# CLAUDE.md -- {name}\n\n"
            f"## Purpose\n\n{description}\n\n"
            f"## Project Host\n\nThis project lives on linux-host (YOUR_HOST_IP) at `~/{name}/`.\n\n"
            f"---\n\n"
            f"## Cross-Project Knowledge Base\n\n"
            f"A shared wiki vault lives at ~/obsidian-vault/ on this host.\n\n"
            f"When you need context not already in this project:\n"
            f"1. Read ~/obsidian-vault/wiki/concepts/_index.md for topic overview\n"
            f"2. Check ~/obsidian-vault/.raw/projects/ for raw project docs\n"
            f"3. Drill into specific wiki pages under ~/obsidian-vault/wiki/ as needed\n"
        )
        changelog = f"# CHANGELOG\n\n## {today}\n\n- Project created by ClaudeProjectManager (type: {project_type})\n"

        for fname, content in [("README.md", readme), ("TODO.md", todo),
                                ("CLAUDE.md", claude_md), ("CHANGELOG.md", changelog)]:
            self.ssh(f"cat > {path}/{fname} << 'DEOF'\n{content}\nDEOF", timeout=5)

        cmds = [
            f"cd {path} && git init",
            f"cd {path} && git add -A",
            f"cd {path} && git commit -m '[PM] Initial scaffold ({project_type})'",
            f"cd {path} && git branch -M main",
        ]
        for cmd in cmds:
            self.ssh(cmd, timeout=15)

        findings.append(Finding(
            severity=Severity.INFO,
            source="scaffold",
            message=f"Scaffolded {name} as {project_type} on linux-host",
            host="linux-host",
        ))

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"Created {name} ({project_type})",
        )
