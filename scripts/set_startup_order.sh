#!/bin/bash
# Set Proxmox VM/CT startup order for power-loss recovery
# Run on linux-host (YOUR_HOST_IP)

set -a; source ~/MyProject/.secrets/proxmox_api.env; set +a
BASE="https://${PVE1_API_HOST}:${PVE1_API_PORT}/api2/json"
AUTH="Authorization: PVEAPIToken=${PVE1_TOKEN_ID}=${PVE1_TOKEN_SECRET}"

set_startup() {
    local node=$1 type=$2 vmid=$3 order=$4 up=$5 down=$6 name=$7
    local startup="order=${order},up=${up},down=${down}"
    local url="${BASE}/nodes/${node}/${type}/${vmid}/config"
    local http_code
    http_code=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "$AUTH" -d "startup=${startup}" "$url" 2>/dev/null)
    if [ "$http_code" = "200" ]; then
        echo "  OK: ${name} VMID=${vmid} -> startup=${startup}"
    else
        echo "  FAIL: ${name} VMID=${vmid} HTTP=${http_code}"
    fi
}

echo "Setting startup order on all guests..."
echo

# Order 1: WireGuard gateway - foundational network, boots first
set_startup proxmox-node1 lxc  210 1 15 120 vpn-host

# Order 2: Data store - other services may depend on it
set_startup proxmox-node1 qemu 101 2 15 120 data-host

# Order 3: Ops management VM - Claude/Ansible hub
set_startup proxmox-node2 qemu 200 3 30 90 linux-host

# Order 4: SIEM - monitoring, needs time to initialize Wazuh
set_startup proxmox-node2 qemu 215 4 30 90 siem-host

# Order 5: web-host web frontend
set_startup proxmox-node2 qemu 130 5 15 60 web-host

# Order 6: Trading data store (before trading bot)
set_startup proxmox-node1 lxc  104 6 10 60 trading-data

# Order 7: Trading bot (depends on trading-data)
set_startup proxmox-node2 lxc  103 7 10 60 trading-bot

# Order 8: Media server - lowest priority
set_startup proxmox-node1 qemu 100 8 0 30 media-host

echo
echo "Done. Verifying..."
echo

# Verify by reading back
for entry in "proxmox-node1 lxc 210 vpn-host" "proxmox-node1 qemu 101 data-host" "proxmox-node2 qemu 200 linux-host" "proxmox-node2 qemu 215 siem-host" "proxmox-node2 qemu 130 web-host" "proxmox-node1 lxc 104 trading-data" "proxmox-node2 lxc 103 trading-bot" "proxmox-node1 qemu 100 media-host"; do
    read -r node type vmid name <<< "$entry"
    startup=$(curl -sk -H "$AUTH" "${BASE}/nodes/${node}/${type}/${vmid}/config" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('startup','UNSET'))" 2>/dev/null)
    echo "  ${name} VMID=${vmid}: startup=${startup}"
done
