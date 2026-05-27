#!/bin/bash
# pve-postboot-verify.sh — Verify all onboot=1 guests started after boot, retry failures
# Deployed to /usr/local/bin/ on each Proxmox host

LOG="/var/log/pve-postboot-verify.log"
RETRIES=3
RETRY_DELAY=30

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG"; }

log "=== Post-boot verification starting ==="

check_and_start() {
    local type=$1  # qemu or lxc
    local confdir=$2
    local start_cmd=$3
    local status_cmd=$4

    for conf in "$confdir"/*.conf; do
        [ -f "$conf" ] || continue
        vmid=$(basename "$conf" .conf)

        if ! grep -q '^onboot: 1' "$conf"; then
            continue
        fi

        name=$(grep -m1 -oP '^(name|hostname): \K.*' "$conf" 2>/dev/null || echo "vmid-$vmid")
        status=$($status_cmd "$vmid" 2>/dev/null | grep -oP 'status: \K\w+')

        if [ "$status" = "running" ]; then
            log "OK: $type $vmid ($name) is running"
        else
            log "WARN: $type $vmid ($name) is $status — attempting start"
            for attempt in $(seq 1 $RETRIES); do
                $start_cmd "$vmid" 2>>"$LOG"
                sleep $RETRY_DELAY
                status=$($status_cmd "$vmid" 2>/dev/null | grep -oP 'status: \K\w+')
                if [ "$status" = "running" ]; then
                    log "OK: $type $vmid ($name) started on attempt $attempt"
                    break
                fi
                log "RETRY: $type $vmid ($name) still $status (attempt $attempt/$RETRIES)"
            done
            if [ "$status" != "running" ]; then
                log "FAIL: $type $vmid ($name) could not be started after $RETRIES attempts"
            fi
        fi
    done
}

check_and_start "VM"  "/etc/pve/qemu-server" "qm start" "qm status"
check_and_start "CT"  "/etc/pve/lxc"         "pct start" "pct status"

log "=== Post-boot verification complete ==="
