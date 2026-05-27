"""Agent: Range Manager -- Proxmox cluster inventory, resource monitoring, VM/CT registry."""

import json
import time
from datetime import datetime
from pathlib import Path

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity, STATE_DIR
from agents.runner import register
from config import run_ssh

REGISTRY_FILE = STATE_DIR / "range_registry.json"
PROXMOX_ENV = "~/MyProject/.secrets/proxmox_api.env"


def _gb(b):
    return round(b / 1073741824, 1)


def _pct(used, total):
    if total == 0:
        return 0
    return round(used * 100 / total, 1)


@register
class RangeManagerAgent(BaseAgent):
    name = "range_manager"
    description = "Proxmox cluster inventory, resource monitoring, VM/CT change detection"
    default_interval = 300
    tier = "infrastructure"

    RAM_WARN_PCT = 85
    RAM_CRIT_PCT = 95
    DISK_WARN_PCT = 85
    DISK_CRIT_PCT = 95
    CPU_WARN_PCT = 80

    def check(self) -> AgentResult:
        findings = []

        cluster_data, err = self._api_call("/cluster/resources")
        if err:
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=f"Proxmox API error: {err}",
            )

        nodes = []
        vms = []
        cts = []
        storages = []

        for item in cluster_data:
            t = item.get("type")
            if t == "node":
                nodes.append(item)
            elif t == "qemu":
                vms.append(item)
            elif t == "lxc":
                cts.append(item)
            elif t == "storage":
                storages.append(item)

        for node in nodes:
            findings.extend(self._check_node_resources(node))

        for s in storages:
            findings.extend(self._check_storage(s))

        for vm in vms:
            findings.extend(self._check_guest(vm, "VM"))

        for ct in cts:
            findings.extend(self._check_guest(ct, "CT"))

        changes = self._detect_changes(vms, cts)
        findings.extend(changes)

        registry = self._build_registry(nodes, vms, cts, storages)
        self._save_registry(registry)

        running_guests = sum(1 for g in vms + cts if g.get("status") == "running")
        total_guests = len(vms) + len(cts)
        node_names = ", ".join(n.get("node", "?") for n in nodes)

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{len(nodes)} nodes ({node_names}), {running_guests}/{total_guests} guests running",
        )

    def _api_call(self, endpoint):
        cmd = (
            f"set -a && source {PROXMOX_ENV} && set +a && "
            f'curl -sk --max-time 10 '
            f'-H "Authorization: PVEAPIToken=${{PVE1_TOKEN_ID}}=${{PVE1_TOKEN_SECRET}}" '
            f'"https://${{PVE1_API_HOST}}:${{PVE1_API_PORT}}/api2/json{endpoint}"'
        )
        stdout, stderr, rc = self.ssh(cmd, timeout=20)
        if rc != 0 or not stdout.strip():
            return None, stderr or "empty response"
        try:
            data = json.loads(stdout.strip())
            return data.get("data", []), None
        except json.JSONDecodeError as e:
            return None, f"JSON parse error: {e}"

    def _check_node_resources(self, node):
        findings = []
        name = node.get("node", "unknown")
        status = node.get("status", "unknown")

        if status != "online":
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source=self.name,
                message=f"Node {name} is {status}",
                host=name,
            ))
            return findings

        mem = node.get("mem", 0)
        maxmem = node.get("maxmem", 1)
        cpu = node.get("cpu", 0)
        ram_pct = _pct(mem, maxmem)

        if ram_pct >= self.RAM_CRIT_PCT:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source=self.name,
                message=f"{name} RAM critical: {_gb(mem)}G/{_gb(maxmem)}G ({ram_pct}%)",
                host=name,
            ))
        elif ram_pct >= self.RAM_WARN_PCT:
            findings.append(Finding(
                severity=Severity.HIGH,
                source=self.name,
                message=f"{name} RAM high: {_gb(mem)}G/{_gb(maxmem)}G ({ram_pct}%)",
                host=name,
            ))

        cpu_pct = round(cpu * 100, 1)
        if cpu_pct >= self.CPU_WARN_PCT:
            findings.append(Finding(
                severity=Severity.HIGH,
                source=self.name,
                message=f"{name} CPU high: {cpu_pct}% ({node.get('maxcpu', '?')} cores)",
                host=name,
            ))

        return findings

    def _check_storage(self, s):
        findings = []
        name = f"{s.get('node', '?')}/{s.get('storage', '?')}"
        disk = s.get("disk", 0)
        maxdisk = s.get("maxdisk", 1)
        pct = _pct(disk, maxdisk)

        if pct >= self.DISK_CRIT_PCT:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source=self.name,
                message=f"Storage {name} critical: {_gb(disk)}G/{_gb(maxdisk)}G ({pct}%)",
                host=s.get("node", "?"),
            ))
        elif pct >= self.DISK_WARN_PCT:
            findings.append(Finding(
                severity=Severity.HIGH,
                source=self.name,
                message=f"Storage {name} high: {_gb(disk)}G/{_gb(maxdisk)}G ({pct}%)",
                host=s.get("node", "?"),
            ))

        return findings

    def _check_guest(self, guest, gtype):
        findings = []
        name = guest.get("name", f"vmid-{guest.get('vmid', '?')}")
        status = guest.get("status", "unknown")
        node = guest.get("node", "?")

        if status == "stopped":
            findings.append(Finding(
                severity=Severity.INFO,
                source=self.name,
                message=f"{gtype} {name} (VMID {guest.get('vmid')}) stopped on {node}",
                host=node,
            ))

        if status == "running":
            mem = guest.get("mem", 0)
            maxmem = guest.get("maxmem", 1)
            ram_pct = _pct(mem, maxmem)
            if ram_pct >= 95:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source=self.name,
                    message=f"{gtype} {name} RAM critical: {_gb(mem)}G/{_gb(maxmem)}G ({ram_pct}%)",
                    host=node,
                    details=f"vmid={guest.get('vmid')} node={node}",
                ))

            lock = guest.get("lock")
            if lock:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    source=self.name,
                    message=f"{gtype} {name} is locked: {lock}",
                    host=node,
                ))

        return findings

    def _detect_changes(self, vms, cts):
        findings = []
        current_ids = set()
        current_map = {}
        for g in vms + cts:
            gid = g.get("id", "")
            current_ids.add(gid)
            current_map[gid] = g

        previous = {}
        if REGISTRY_FILE.exists():
            try:
                prev_data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
                for g in prev_data.get("guests", []):
                    previous[g.get("id", "")] = g
            except Exception:
                pass

        prev_ids = set(previous.keys())

        for gid in current_ids - prev_ids:
            g = current_map[gid]
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source=self.name,
                message=f"NEW: {g.get('type', '?').upper()} {g.get('name', '?')} (VMID {g.get('vmid')}) on {g.get('node')}",
                host=g.get("node", "?"),
            ))

        for gid in prev_ids - current_ids:
            g = previous[gid]
            findings.append(Finding(
                severity=Severity.MEDIUM,
                source=self.name,
                message=f"REMOVED: {g.get('type', '?').upper()} {g.get('name', '?')} (VMID {g.get('vmid')}) from {g.get('node')}",
                host=g.get("node", "?"),
            ))

        for gid in current_ids & prev_ids:
            cur = current_map[gid]
            prev = previous[gid]
            if cur.get("status") != prev.get("status"):
                findings.append(Finding(
                    severity=Severity.INFO,
                    source=self.name,
                    message=f"{cur.get('name', '?')} status changed: {prev.get('status')} -> {cur.get('status')}",
                    host=cur.get("node", "?"),
                ))
            if cur.get("node") != prev.get("node"):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    source=self.name,
                    message=f"{cur.get('name', '?')} migrated: {prev.get('node')} -> {cur.get('node')}",
                    host=cur.get("node", "?"),
                ))

        return findings

    def _build_registry(self, nodes, vms, cts, storages):
        registry = {
            "updated": datetime.now().isoformat(),
            "nodes": [],
            "guests": [],
            "storage": [],
        }

        for n in nodes:
            mem = n.get("mem", 0)
            maxmem = n.get("maxmem", 1)
            registry["nodes"].append({
                "node": n.get("node"),
                "status": n.get("status"),
                "cpu_pct": round(n.get("cpu", 0) * 100, 1),
                "cores": n.get("maxcpu"),
                "ram_used_gb": _gb(mem),
                "ram_total_gb": _gb(maxmem),
                "ram_pct": _pct(mem, maxmem),
                "uptime_days": round(n.get("uptime", 0) / 86400, 1),
            })

        for g in vms + cts:
            mem = g.get("mem", 0)
            maxmem = g.get("maxmem", 1)
            registry["guests"].append({
                "id": g.get("id"),
                "vmid": g.get("vmid"),
                "name": g.get("name"),
                "type": g.get("type"),
                "node": g.get("node"),
                "status": g.get("status"),
                "cpu_pct": round(g.get("cpu", 0) * 100, 1),
                "cores": g.get("maxcpu"),
                "ram_used_gb": _gb(mem),
                "ram_total_gb": _gb(maxmem),
                "ram_pct": _pct(mem, maxmem),
                "disk_gb": _gb(g.get("maxdisk", 0)),
                "uptime_days": round(g.get("uptime", 0) / 86400, 1),
                "tags": g.get("tags", ""),
                "lock": g.get("lock", ""),
            })

        for s in storages:
            disk = s.get("disk", 0)
            maxdisk = s.get("maxdisk", 1)
            registry["storage"].append({
                "node": s.get("node"),
                "storage": s.get("storage"),
                "type": s.get("plugintype"),
                "used_gb": _gb(disk),
                "total_gb": _gb(maxdisk),
                "pct": _pct(disk, maxdisk),
                "content": s.get("content", ""),
            })

        return registry

    def _save_registry(self, registry):
        try:
            REGISTRY_FILE.write_text(json.dumps(registry, indent=2), encoding="utf-8")
        except Exception:
            pass

    @staticmethod
    def get_registry():
        if not REGISTRY_FILE.exists():
            return None
        try:
            return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def get_node_summary(node_name=None):
        reg = RangeManagerAgent.get_registry()
        if not reg:
            return "No registry data -- run range_manager first."
        lines = []
        for n in reg.get("nodes", []):
            if node_name and n["node"] != node_name:
                continue
            lines.append(f"=== {n['node']} ({n['status']}) ===")
            lines.append(f"  CPU: {n['cpu_pct']}% ({n['cores']} cores)")
            lines.append(f"  RAM: {n['ram_used_gb']}G / {n['ram_total_gb']}G ({n['ram_pct']}%)")
            lines.append(f"  Uptime: {n['uptime_days']} days")

            guests = [g for g in reg.get("guests", []) if g["node"] == n["node"]]
            if guests:
                guests.sort(key=lambda g: g.get("ram_used_gb", 0), reverse=True)
                lines.append(f"  Guests ({len(guests)}):")
                for g in guests:
                    status = g["status"]
                    icon = "R" if status == "running" else "S"
                    lock = f" [LOCK:{g['lock']}]" if g.get("lock") else ""
                    lines.append(
                        f"    [{icon}] {g['name']:20s} "
                        f"RAM {g['ram_used_gb']:5.1f}G/{g['ram_total_gb']:4.1f}G "
                        f"CPU {g['cpu_pct']:5.1f}% "
                        f"Disk {g['disk_gb']:5.0f}G"
                        f"{lock}"
                    )

        for s in reg.get("storage", []):
            if node_name and s["node"] != node_name:
                continue
            lines.append(f"  Storage {s['storage']}: {s['used_gb']}G/{s['total_gb']}G ({s['pct']}%) [{s['type']}]")

        return "\n".join(lines) if lines else f"Node '{node_name}' not found."
