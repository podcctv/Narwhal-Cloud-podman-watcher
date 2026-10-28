#!/usr/bin/env bash
set -euo pipefail

SIDE="${1:-}"
REPO_DIR="${2:-}"
BASE_DIR="/opt/narwhal-monitor"
UPDATER="$BASE_DIR/auto-update.sh"
CONFIG_FILE="$BASE_DIR/${SIDE}-auto-update.env"
SERVICE_NAME="narwhal-monitor-${SIDE}-update.service"
TIMER_NAME="narwhal-monitor-${SIDE}-update.timer"
TRUSTED_REPO="https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"
UPDATE_MODE="git"

if [[ "$SIDE" != "server" && "$SIDE" != "client" ]]; then
  echo "usage: $0 server|client /absolute/repository/path" >&2
  exit 2
fi
SOURCE_DIR="$REPO_DIR"
existing_mode="$(awk -F= '$1=="AUTO_UPDATE_MODE"{print $2;exit}' "$CONFIG_FILE" 2>/dev/null || true)"
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "setup-auto-update.sh must run as root" >&2
  exit 1
fi
bootstrap_update_checkout() {
  local fallback="$BASE_DIR/${SIDE}-update-repo"
  local staging="" resolved_base="" resolved_staging="" current_origin=""

  if [[ -L "$fallback" ]]; then
    echo "[WARN] $fallback is a symbolic link; preserving it and falling back to fixed-origin archives."
    return 1
  fi
  if [[ -d "$fallback/.git" ]]; then
    current_origin="$(git -C "$fallback" remote get-url origin 2>/dev/null || true)"
    if [[ "$current_origin" != "$TRUSTED_REPO" ]]; then
      echo "[WARN] Existing $fallback checkout has an unexpected origin; preserving it and falling back to fixed-origin archives."
      return 1
    fi
    if [[ -n "$(git -C "$fallback" status --porcelain 2>/dev/null || true)" ]]; then
      echo "[WARN] Existing $fallback checkout has local changes; preserving it and falling back to fixed-origin archives."
      return 1
    fi
    REPO_DIR="$fallback"
    return 0
  fi
  if [[ -e "$fallback" ]]; then
    echo "[WARN] $fallback exists but is not a Git checkout; preserving it and falling back to fixed-origin archives."
    return 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    echo "[WARN] Git is unavailable; using the fixed-origin archive updater."
    return 1
  fi

  mkdir -p "$BASE_DIR"
  staging="$(mktemp -d "$BASE_DIR/${SIDE}-update-bootstrap.XXXXXX")"
  if ! git clone --single-branch --branch main "$TRUSTED_REPO" "$staging/repo"; then
    echo "[WARN] Could not bootstrap the trusted update checkout; automatic $SIDE updates were not enabled."
    resolved_base="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
    resolved_staging="$(realpath -e "$staging" 2>/dev/null || true)"
    if [[ -n "$resolved_base" && "$resolved_staging" == "$resolved_base/${SIDE}-update-bootstrap."* ]]; then
      rm -rf -- "$resolved_staging"
    fi
    return 1
  fi
  current_origin="$(git -C "$staging/repo" remote get-url origin 2>/dev/null || true)"
  if [[ "$current_origin" != "$TRUSTED_REPO" || -n "$(git -C "$staging/repo" status --porcelain --untracked-files=no)" ]]; then
    echo "[WARN] Bootstrapped update checkout failed origin/cleanliness verification; automatic $SIDE updates were not enabled."
    resolved_base="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
    resolved_staging="$(realpath -e "$staging" 2>/dev/null || true)"
    if [[ -n "$resolved_base" && "$resolved_staging" == "$resolved_base/${SIDE}-update-bootstrap."* ]]; then
      rm -rf -- "$resolved_staging"
    fi
    return 1
  fi
  if [[ -e "$fallback" ]]; then
    echo "[WARN] $fallback appeared during checkout bootstrap; preserving it and leaving automatic $SIDE updates disabled."
    resolved_base="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
    resolved_staging="$(realpath -e "$staging" 2>/dev/null || true)"
    if [[ -n "$resolved_base" && "$resolved_staging" == "$resolved_base/${SIDE}-update-bootstrap."* ]]; then
      rm -rf -- "$resolved_staging"
    fi
    return 1
  fi
  if ! mv -T -- "$staging/repo" "$fallback"; then
    echo "[WARN] Could not install the bootstrapped checkout at $fallback; preserving existing files."
    resolved_base="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
    resolved_staging="$(realpath -e "$staging" 2>/dev/null || true)"
    if [[ -n "$resolved_base" && "$resolved_staging" == "$resolved_base/${SIDE}-update-bootstrap."* ]]; then
      rm -rf -- "$resolved_staging"
    fi
    return 1
  fi
  resolved_base="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
  resolved_staging="$(realpath -e "$staging" 2>/dev/null || true)"
  if [[ -n "$resolved_base" && "$resolved_staging" == "$resolved_base/${SIDE}-update-bootstrap."* ]]; then
    rm -rf -- "$resolved_staging"
  fi
  REPO_DIR="$fallback"
  echo "[INFO] Bootstrapped a clean, trusted update checkout at $REPO_DIR."
}

if [[ ! -d "$REPO_DIR/.git" ]]; then
  if [[ "$existing_mode" == "archive" ]]; then
    UPDATE_MODE="archive"
  elif bootstrap_update_checkout; then
    UPDATE_MODE="git"
  else
    # Some supported hosts cannot use GitHub's smart-HTTP endpoint or do not
    # have Git installed. Keep the updater pinned to this project's public
    # GitHub archive endpoint instead of silently disabling future updates.
    UPDATE_MODE="archive"
    echo "[INFO] Enabling fixed-origin archive updates for $SIDE (no usable Git checkout)."
  fi
fi
if [[ "$UPDATE_MODE" == "git" ]]; then
  current_origin="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
  current_changes="$(git -C "$REPO_DIR" status --porcelain 2>/dev/null || true)"
  if [[ "$current_origin" != "$TRUSTED_REPO" || -n "$current_changes" ]]; then
    echo "[WARN] Update checkout origin or working tree is not trusted; preserving it and using fixed-origin archives."
    UPDATE_MODE="archive"
  fi
fi

mkdir -p "$BASE_DIR"
if [[ "$UPDATE_MODE" == "git" ]]; then
  REPO_DIR="${REPO_DIR:-$BASE_DIR/${SIDE}-update-repo}"
  install -m 0755 "$REPO_DIR/scripts/auto-update.sh" "$UPDATER"
  install -m 0755 "$REPO_DIR/scripts/update_archive.py" "$BASE_DIR/update_archive.py"
else
  if [[ ! -f "$REPO_DIR/scripts/auto-update.sh" || ! -f "$REPO_DIR/scripts/update_archive.py" ]]; then
    echo "[WARN] Installer source is missing the fixed-origin archive updater; automatic $SIDE updates were not enabled."
    exit 0
  fi
  install -m 0755 "$REPO_DIR/scripts/auto-update.sh" "$UPDATER"
  install -m 0755 "$REPO_DIR/scripts/update_archive.py" "$BASE_DIR/update_archive.py"
  REPO_DIR=""
fi

mkdir -p "$BASE_DIR"
existing_enabled="$(awk -F= '$1=="AUTO_UPDATE_ENABLED"{print $2;exit}' "$CONFIG_FILE" 2>/dev/null || true)"
existing_enabled="${existing_enabled:-true}"
{
  echo "AUTO_UPDATE_ENABLED=$existing_enabled"
  echo "AUTO_UPDATE_MODE=$UPDATE_MODE"
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
OnCalendar=*:0/15
RandomizedDelaySec=2min
AccuracySec=1min
Persistent=true
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF_TIMER

if [[ "$UPDATE_MODE" == "git" ]]; then
  current_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
  printf '%s\n' "$current_commit" >"$BASE_DIR/${SIDE}-auto-update.version"
else
  current_version="$(tr -d '[:space:]' <"$SOURCE_DIR/VERSION" 2>/dev/null || true)"
  [[ "$current_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || current_version="unknown"
  printf 'version:%s\n' "$current_version" >"$BASE_DIR/${SIDE}-auto-update.version"
fi
chmod 0600 "$BASE_DIR/${SIDE}-auto-update.version"
systemctl daemon-reload
systemctl enable "$TIMER_NAME" >/dev/null
# A timer rewritten by its own updater can otherwise remain active(elapsed)
# forever with no NextElapse timestamp on some systemd releases.
systemctl restart "$TIMER_NAME"
echo "[INFO] Automatic $SIDE updates enabled: $TIMER_NAME (fixed GitHub main, mode=$UPDATE_MODE, every 15 minutes)"
