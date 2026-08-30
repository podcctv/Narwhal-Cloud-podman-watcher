#!/usr/bin/env bash
set -euo pipefail

SIDE="${1:-}"
REPO_DIR="${2:-}"
BASE_DIR="/opt/narwhal-monitor"
UPDATER="$BASE_DIR/auto-update.sh"
CONFIG_FILE="$BASE_DIR/${SIDE}-auto-update.env"
SERVICE_NAME="narwhal-monitor-${SIDE}-update.service"
TIMER_NAME="narwhal-monitor-${SIDE}-update.timer"

if [[ "$SIDE" != "server" && "$SIDE" != "client" ]]; then
  echo "usage: $0 server|client /absolute/repository/path" >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "setup-auto-update.sh must run as root" >&2
  exit 1
fi
if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "[WARN] $REPO_DIR is not a Git checkout; automatic $SIDE updates were not enabled."
  exit 0
fi

mkdir -p "$BASE_DIR"
install -m 0755 "$REPO_DIR/scripts/auto-update.sh" "$UPDATER"
existing_enabled="$(awk -F= '$1=="AUTO_UPDATE_ENABLED"{print $2;exit}' "$CONFIG_FILE" 2>/dev/null || true)"
existing_enabled="${existing_enabled:-true}"
{
  echo "AUTO_UPDATE_ENABLED=$existing_enabled"
  printf 'AUTO_UPDATE_REPO_DIR=%q\n' "$REPO_DIR"
  echo "AUTO_UPDATE_BRANCH=main"
} >"$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"

cat >"/etc/systemd/system/$SERVICE_NAME" <<EOF_SERVICE
[Unit]
Description=Narwhal Monitor $SIDE automatic update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATER $SIDE
# Server/Caddy are launched into narwhal-monitor.slice by install-server.sh,
# outside this short-lived updater cgroup.  Therefore a timeout may safely stop
# every updater subprocess without touching the running containers.
KillMode=control-group
# install-server launches Podman through a unique transient scope inside
# narwhal-monitor.slice; delegation permits that nested cgroup operation.
Delegate=yes
TimeoutStartSec=30min
TimeoutStopSec=2min
EOF_SERVICE

cat >"/etc/systemd/system/$TIMER_NAME" <<EOF_TIMER
[Unit]
Description=Check Narwhal Monitor $SIDE updates every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=2min
Persistent=true
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF_TIMER

current_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
printf '%s\n' "$current_commit" >"$BASE_DIR/${SIDE}-auto-update.version"
chmod 0600 "$BASE_DIR/${SIDE}-auto-update.version"
systemctl daemon-reload
systemctl enable --now "$TIMER_NAME" >/dev/null
echo "[INFO] Automatic $SIDE updates enabled: $TIMER_NAME (origin/main, every 15 minutes)"
