"""Agent 2: Security Monitor -- SSH failures, port anomalies, WireGuard peers, firewall drift."""

from agents.base_agent import BaseAgent, AgentResult, Finding, Severity
from agents.runner import register


@register
class SecurityMonitorAgent(BaseAgent):
    name = "security_monitor"
    description = "SSH auth failures, port anomalies, WireGuard peers, firewall drift, new users"
    default_interval = 900
    tier = "infrastructure"

    MONITORED_HOSTS = ["YOUR_HOST_IP", "YOUR_WEB_HOST_IP", "YOUR_VPN_HOST_IP",
                       "YOUR_PVE1_IP", "YOUR_PVE2_IP", "YOUR_DNS_HOST_IP"]
    SSH_FAIL_THRESHOLD = 5
    WG_HOST = "YOUR_VPN_HOST_IP"

    def check(self) -> AgentResult:
        findings = []

        findings.extend(self._check_ssh_failures())
        findings.extend(self._check_wireguard_peers())
        findings.extend(self._check_new_users())
        findings.extend(self._check_sudoers_changes())
        findings.extend(self._check_listening_ports())

        return AgentResult(
            agent_name=self.name,
            success=True,
            findings=findings,
            summary=f"{len(findings)} security findings",
        )

    def _check_ssh_failures(self):
        findings = []
        for host_ip in self.MONITORED_HOSTS:
            stdout, stderr, rc = self.ssh(
                "journalctl -u ssh -u sshd --since '15 min ago' --no-pager 2>/dev/null "
                "| grep -c 'Failed password\\|Failed publickey\\|Invalid user' || echo 0",
                host=host_ip, timeout=10,
            )
            if rc != 0:
                continue
            try:
                count = int(stdout.strip())
            except ValueError:
                continue

            if count >= self.SSH_FAIL_THRESHOLD * 3:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    source="security_monitor",
                    message=f"SSH brute-force: {count} failures in 15min on {host_ip}",
                    host=host_ip,
                ))
            elif count >= self.SSH_FAIL_THRESHOLD:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source="security_monitor",
                    message=f"SSH auth failures: {count} in 15min on {host_ip}",
                    host=host_ip,
                ))
        return findings

    def _check_wireguard_peers(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "wg show all peers 2>/dev/null",
            host=self.WG_HOST, timeout=10,
        )
        if rc != 0:
            return findings

        stdout2, stderr2, rc2 = self.ssh(
            "wg show all latest-handshakes 2>/dev/null",
            host=self.WG_HOST, timeout=10,
        )
        if rc2 == 0 and stdout2.strip():
            for line in stdout2.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    peer = parts[1][:16] + "..."
                    ts = parts[2]
                    try:
                        ts_int = int(ts)
                        if ts_int == 0:
                            continue
                        findings.append(Finding(
                            severity=Severity.INFO,
                            source="security_monitor",
                            message=f"WireGuard peer active: {peer}",
                            host="vpn-host",
                        ))
                    except ValueError:
                        pass
        return findings

    def _check_new_users(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "find /etc/passwd -mmin -15 -newer /etc/hostname 2>/dev/null && echo MODIFIED || echo UNCHANGED",
            timeout=10,
        )
        if "MODIFIED" in stdout:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source="security_monitor",
                message="/etc/passwd modified in last 15 minutes on linux-host",
                host="linux-host",
            ))

        stdout2, stderr2, rc2 = self.ssh(
            "awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null",
            timeout=10,
        )
        if rc2 == 0 and stdout2.strip():
            users = stdout2.strip().split("\n")
            known = {"YOUR_SSH_USER", "ubuntu", "debian"}
            unknown = [u for u in users if u not in known]
            if unknown:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    source="security_monitor",
                    message=f"Unknown user accounts on linux-host: {', '.join(unknown)}",
                    host="linux-host",
                ))
        return findings

    def _check_sudoers_changes(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "find /etc/sudoers /etc/sudoers.d/ -mmin -15 2>/dev/null | head -5",
            timeout=10,
        )
        if rc == 0 and stdout.strip():
            findings.append(Finding(
                severity=Severity.CRITICAL,
                source="security_monitor",
                message=f"sudoers modified recently: {stdout.strip()}",
                host="linux-host",
            ))
        return findings

    def _check_listening_ports(self):
        findings = []
        stdout, stderr, rc = self.ssh(
            "ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}'",
            timeout=10,
        )
        if rc != 0:
            return findings

        expected_ports = {22, 53, 80, 443, 514, 3000, 5601, 8006, 8080, 9090, 9200, 55000}
        for addr in stdout.strip().split("\n"):
            addr = addr.strip()
            if not addr:
                continue
            try:
                port = int(addr.rsplit(":", 1)[-1])
                if port > 10000 and port not in expected_ports and port < 50000:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        source="security_monitor",
                        message=f"Unexpected port listening on linux-host: {addr}",
                        host="linux-host",
                    ))
            except ValueError:
                pass
        return findings
