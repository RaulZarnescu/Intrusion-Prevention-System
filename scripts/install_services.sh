#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_USER="$(stat -c '%U' "$REPO_DIR")"

echo "Installing systemd services using repository path: $REPO_DIR"
echo "Services will run as user: $REPO_USER (for non-root tasks)"

SERVICES=(
    "ips-loader.service"
    "ips-threat-intel-update.service"
    "ips-threat-intel-update.timer"
    "ips-sni-blocklist-update.service"
    "ips-sni-blocklist-update.timer"
)

for svc in "${SERVICES[@]}"; do
    if [ -f "$SCRIPT_DIR/$svc.example" ]; then
        SRC_FILE="$SCRIPT_DIR/$svc.example"
    elif [ -f "$SCRIPT_DIR/$svc" ]; then
        SRC_FILE="$SCRIPT_DIR/$svc"
    else
        echo "[!] Cannot find $svc in $SCRIPT_DIR"
        exit 1
    fi
    
    DEST_FILE="/etc/systemd/system/$svc"
    echo "[+] Installing $svc..."
    
    # 1. Replace hardcoded raul paths and placeholder paths with $REPO_DIR
    # 2. Replace User=raul with User=$REPO_USER
    sed -e "s|/home/raul/CLionProjects/Intrusion-Prevention-System|$REPO_DIR|g" \
        -e "s|/path/to/Intrusion-Prevention-System|$REPO_DIR|g" \
        -e "s|^User=raul|User=$REPO_USER|g" \
        "$SRC_FILE" > "$DEST_FILE"
        
    chmod 644 "$DEST_FILE"
done

echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo "[*] Enabling ips-loader.service (which also enables the timers)..."
systemctl enable ips-loader.service

echo ""
echo "[+] Installation complete!"
echo "Note: The bridge setup will now persist across reboots."
echo "The threat intelligence feed will update automatically via ips-threat-intel-update.timer."
echo ""
echo "To start the IPS now, run:"
echo "  sudo systemctl start ips-loader.service"
