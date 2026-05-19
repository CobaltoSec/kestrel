#!/usr/bin/env bash
# Idempotent setup of msfrpcd on Kali VM for Kestrel MCP integration.
#
# Run via SSH from your control host:
#     ssh -i ~/.ssh/kali-pentest kali@<kali-ip> bash < scripts/kali-setup-msfrpc.sh
#
# Or copy first, then run with sudo:
#     scp scripts/kali-setup-msfrpc.sh kali@<kali-ip>:/tmp/
#     ssh kali@<kali-ip> sudo bash /tmp/kali-setup-msfrpc.sh
#
# Idempotent: safe to re-run. Writes ~/.kestrel/msfrpc.secret on the Kali side
# AND prints it to stdout so the control host can mirror it locally.
#
# Exit codes:
#   0 — msfrpcd is up and responding
#   1 — generic failure
#   2 — metasploit-framework not installed and apt-get not available

set -euo pipefail

readonly SECRET_FILE="${HOME}/.kestrel/msfrpc.secret"
readonly MSFRPC_HOST="${MSFRPC_HOST:-127.0.0.1}"
readonly MSFRPC_PORT="${MSFRPC_PORT:-55553}"
readonly MSFRPC_USER="${MSFRPC_USER:-msf}"
readonly SYSTEMD_UNIT="/etc/systemd/system/msfrpcd.service"

log() {
    printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

ensure_msf_installed() {
    if command -v msfrpcd >/dev/null 2>&1; then
        log "msfrpcd already installed"
        return 0
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        log "ERROR: msfrpcd not found and apt-get not available"
        return 2
    fi
    log "Installing metasploit-framework..."
    sudo apt-get update -qq
    sudo apt-get install -y metasploit-framework
}

ensure_secret() {
    mkdir -p "$(dirname "$SECRET_FILE")"
    if [ ! -f "$SECRET_FILE" ]; then
        log "Generating new msfrpc secret at $SECRET_FILE"
        # 32 hex chars
        head -c 32 /dev/urandom | xxd -p -c 32 > "$SECRET_FILE"
        chmod 600 "$SECRET_FILE"
    fi
    cat "$SECRET_FILE"
}

write_systemd_unit() {
    local secret="$1"
    log "Writing $SYSTEMD_UNIT"
    sudo tee "$SYSTEMD_UNIT" >/dev/null <<EOF
[Unit]
Description=Metasploit RPC daemon for Kestrel MCP
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$(id -un)
ExecStart=/usr/bin/msfrpcd -P ${secret} -S -U ${MSFRPC_USER} -a ${MSFRPC_HOST} -p ${MSFRPC_PORT} -f
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable msfrpcd.service
    sudo systemctl restart msfrpcd.service
}

verify_rpc_up() {
    local secret="$1"
    log "Verifying RPC at ${MSFRPC_HOST}:${MSFRPC_PORT}..."
    # Wait up to 20s for startup
    for _ in $(seq 1 20); do
        if curl -ks "https://${MSFRPC_HOST}:${MSFRPC_PORT}/api/" -X POST -d "" >/dev/null 2>&1; then
            log "msfrpcd is responding"
            return 0
        fi
        sleep 1
    done
    log "ERROR: msfrpcd did not respond within 20s"
    return 1
}

main() {
    ensure_msf_installed
    local secret
    secret=$(ensure_secret)
    if [ ! -f "$SYSTEMD_UNIT" ] || ! systemctl is-active --quiet msfrpcd.service; then
        write_systemd_unit "$secret"
    else
        log "msfrpcd.service already running; restarting to pick up any secret changes"
        sudo systemctl restart msfrpcd.service
    fi
    verify_rpc_up "$secret"
    log "Setup complete. Mirror this secret to your control host at ~/.kestrel/msfrpc.secret:"
    echo "===SECRET==="
    echo "$secret"
    echo "===END==="
}

main "$@"
