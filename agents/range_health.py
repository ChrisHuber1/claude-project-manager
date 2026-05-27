"""Agent 1: Range Health -- host availability, VM states, service ports, disk space."""

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class RangeHealthAgent(BaseAgent):
    name = "range_health"
    description = "Host pings, Proxmox API, VM states, service ports, disk space"
    default_interval = 300
    tier = "infrastructure"

    HOSTS = {
        "linux-host": {"ip": "YOUR_HOST_IP", "ports": [22]},
        "web-host": {"ip": "YOUR_WEB_HOST_IP", "ports": [22, 80, 443]},
        "proxmox-node1": {"ip": "YOUR_PVE1_IP", "ports": [22, 8006]},
        "proxmox-node2": {"ip": "YOUR_PVE2_IP", "ports": [22, 8006]},
        "firewall-host": {"ip": "YOUR_GATEWAY_IP", "ports": [443]},
        "dns-host": {"ip": "YOUR_DNS_HOST_IP", "ports": [22, 53, 80]},
        "vpn-host": {"ip": "YOUR_VPN_HOST_IP", "ports": [22]},
        "siem-host": {"ip": "YOUR_SIEM_IP", "ports": [22, 443]},
    }

    DISK_WARN_PCT = 85
    DISK_CRIT_PCT = 95

    def check(self) -> AgentResult:
        findings = []
        reachable = 0
        total = len(self.HOSTS)

        for name, info in self.HOSTS.items():
            ip = info["ip"]
            alive = self._ping(ip)
            if not alive:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    source="range_health",
                    message=f"{name} ({ip}) is UNREACHABLE",
                    host=name,
                ))
                continue

            reachable += 1

            for port in info["ports"]:
                if not self._port_open(ip, port):
                    sev = Severity.HIGH if port in (22, 443, 8006) else Severity.MEDIUM
                    findings.append(Finding(
                        severity=sev,
                        source="range_health",
                        message=f"{name}:{port} not responding",
                        host=name,
                    ))

        disk_findings = self._check_disk_space()
        findings.extend(disk_findings)

        vm_findings = self._check_vm_states()
        findings.extend(vm_findings)

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{reachable}/{total} hosts up",
        )

    def _ping(self, ip):
        stdout, stderr, rc = self.ssh(
            f"ping -c 1 -W 2 {ip} >/dev/null 2>&1 && echo ok || echo fail",
            timeout=8,
        )
        return "ok" in stdout

    def _port_open(self, ip, port):
        stdout, stderr, rc = self.ssh(
            f"timeout 3 bash -c 'echo > /dev/tcp/{ip}/{port}' 2>/dev/null && echo open || echo closed",
            timeout=8,
        )
        return "open" in stdout

    def _check_disk_space(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "df -h --output=pcent,target / /home /var /tmp 2>/dev/null | tail -n +2",
            timeout=10,
        )
        if rc != 0:
            return findings

        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pct = int(parts[0].replace("%", ""))
                    mount = parts[1]
                    if pct >= self.DISK_CRIT_PCT:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            source="range_health",
                            message=f"linux-host disk {mount} at {pct}%",
                            host="linux-host",
                        ))
                    elif pct >= self.DISK_WARN_PCT:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            source="range_health",
                            message=f"linux-host disk {mount} at {pct}%",
                            host="linux-host",
                        ))
                except ValueError:
                    pass
        return findings

    def _check_vm_states(self):
        findings = []
        for pve in ["YOUR_PVE1_IP", "YOUR_PVE2_IP"]:
            pve_name = "proxmox-node1" if "10" in pve else "proxmox-node2"
            stdout, stderr, rc = self.ssh(
                "qm list 2>/dev/null | tail -n +2",
                host=pve, timeout=10,
            )
            if rc != 0:
                continue

            for line in stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    vmid = parts[0]
                    vm_name = parts[1]
                    status = parts[2]
                    if status == "stopped":
                        findings.append(Finding(
                            severity=Severity.INFO,
                            source="range_health",
                            message=f"VM {vm_name} (VMID {vmid}) stopped on {pve_name}",
                            host=pve_name,
                        ))
        return findings
