#!/usr/bin/env bash
set -euo pipefail

SIDE="${1:-}"
BASE_DIR="/opt/narwhal-monitor"
CONFIG_FILE="$BASE_DIR/${SIDE}-auto-update.env"
STATE_FILE="$BASE_DIR/${SIDE}-auto-update.version"
LOG_FILE="$BASE_DIR/${SIDE}-auto-update.log"
LOCK_FILE="/run/narwhal-monitor-${SIDE}-auto-update.lock"

installed_version() {
  if [[ "$SIDE" == "server" ]]; then
    podman inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
      narwhal-monitor-server 2>/dev/null \
      | awk -F= '$1=="NARWHAL_VERSION"{print substr($0,index($0,"=")+1);exit}'
  else
    awk -F= '$1=="NARWHAL_VERSION"{print substr($0,index($0,"=")+1);exit}' \
      "$BASE_DIR/client.env" 2>/dev/null || true
  fi
}

log() {
  local line
  line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$SIDE] $*"
  echo "$line"
  echo "$line" >>"$LOG_FILE"
}

cleanup_stage() {
  local resolved base_resolved
  [[ -n "${STAGE_DIR:-}" && -d "$STAGE_DIR" ]] || return 0
  resolved="$(realpath -e "$STAGE_DIR" 2>/dev/null || true)"
  base_resolved="$(realpath -e "$BASE_DIR" 2>/dev/null || true)"
  [[ -n "$resolved" && -n "$base_resolved" && "$resolved" == "$base_resolved/update-stage."* && "$resolved" != "$base_resolved" ]] || return 0
  rm -rf -- "$resolved"
}

if [[ "$SIDE" != "server" && "$SIDE" != "client" ]]; then
  echo "usage: $0 server|client" >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "auto updater must run as root" >&2
  exit 1
fi
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "missing auto-update config: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"
if [[ "${AUTO_UPDATE_ENABLED:-true}" != "true" ]]; then
  exit 0
fi
UPDATE_MODE="${AUTO_UPDATE_MODE:-git}"
REPO_DIR="${AUTO_UPDATE_REPO_DIR:-}"
BRANCH="${AUTO_UPDATE_BRANCH:-main}"
if [[ "$UPDATE_MODE" != "git" && "$UPDATE_MODE" != "archive" ]]; then
  log "ERROR invalid update mode: $UPDATE_MODE"
  exit 1
fi
if [[ "$UPDATE_MODE" == "git" && ( -z "$REPO_DIR" || ! -d "$REPO_DIR/.git" ) ]]; then
  log "ERROR repository is unavailable: ${REPO_DIR:-unset}"
  exit 1
fi
if [[ "$UPDATE_MODE" == "archive" && ! -f "$BASE_DIR/update_archive.py" ]]; then
  log "ERROR fixed-origin archive updater is missing"
  exit 1
fi

if [[ "${NARWHAL_UPDATE_LOCKED:-0}" != "1" ]]; then
  set +e
  flock --exclusive --nonblock --close --conflict-exit-code 75 "$LOCK_FILE" \
    env NARWHAL_UPDATE_LOCKED=1 bash "$0" "$SIDE"
  lock_result=$?
  set -e
  if [[ "$lock_result" -eq 75 ]]; then
    log "another update is already running"
    exit 0
  fi
  exit "$lock_result"
fi

if [[ "$UPDATE_MODE" == "git" ]]; then
  remote_commit="$(git -C "$REPO_DIR" ls-remote origin "refs/heads/$BRANCH" | awk 'NR==1{print $1}')"
  if [[ ! "$remote_commit" =~ ^[0-9a-f]{40}$ ]]; then
    log "ERROR cannot resolve origin/$BRANCH"
    exit 1
  fi
  deployed_commit="$(tr -d '[:space:]' <"$STATE_FILE" 2>/dev/null || true)"
  local_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
  local_version=""
  if [[ "$local_commit" == "$remote_commit" && -f "$REPO_DIR/VERSION" ]]; then
    local_version="$(tr -d '[:space:]' <"$REPO_DIR/VERSION")"
  fi
  runtime_version="$(installed_version || true)"
  if [[ "$remote_commit" == "$deployed_commit" \
    && "$local_commit" == "$remote_commit" \
    && -n "$local_version" \
    && "$runtime_version" == "$local_version" ]]; then
    exit 0
  fi
  if [[ "$remote_commit" == "$deployed_commit" ]]; then
    log "deployment drift detected: state=$deployed_commit repository=$local_commit runtime_version=${runtime_version:-unknown} expected_version=${local_version:-unknown}"
  fi
  if [[ -n "$(git -C "$REPO_DIR" status --porcelain --untracked-files=no)" ]]; then
    log "ERROR tracked local changes detected in $REPO_DIR; refusing automatic update to preserve operator changes"
    exit 1
  fi

  log "update found: ${deployed_commit:-unknown} -> $remote_commit"
  git -C "$REPO_DIR" fetch --prune origin "$BRANCH"
  local_commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
  if ! git -C "$REPO_DIR" merge-base --is-ancestor "$local_commit" "$remote_commit"; then
    log "ERROR local branch cannot be fast-forwarded to origin/$BRANCH"
    exit 1
  fi
  git -C "$REPO_DIR" merge --ff-only "$remote_commit"
  SOURCE_DIR="$REPO_DIR"
else
  command -v python3 >/dev/null 2>&1 || { log "ERROR Python 3 is required for archive updates"; exit 1; }
  remote_commit="$(python3 "$BASE_DIR/update_archive.py" resolve)" || { log "ERROR cannot resolve fixed GitHub main revision"; exit 1; }
  if [[ ! "$remote_commit" =~ ^[0-9a-f]{40}$ ]]; then
    log "ERROR fixed GitHub main revision was invalid"
    exit 1
  fi
  remote_version="$(python3 "$BASE_DIR/update_archive.py" version)" || { log "ERROR cannot read fixed GitHub main version"; exit 1; }
  if [[ ! "$remote_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log "ERROR fixed GitHub main version was invalid"
    exit 1
  fi
  deployed_commit="$(tr -d '[:space:]' <"$STATE_FILE" 2>/dev/null || true)"
  runtime_version="$(installed_version || true)"
  if [[ "$remote_commit" == "$deployed_commit" && "$runtime_version" == "$remote_version" ]]; then
    exit 0
  fi
  if [[ "$remote_commit" == "$deployed_commit" ]]; then
    log "deployment drift detected: state=$deployed_commit runtime_version=${runtime_version:-unknown} expected_version=$remote_version"
  fi
  log "archive update found: ${deployed_commit:-unknown} -> $remote_commit (version $remote_version)"
  STAGE_DIR="$(mktemp -d "$BASE_DIR/update-stage.XXXXXX")"
  trap cleanup_stage EXIT
  python3 "$BASE_DIR/update_archive.py" download "$remote_commit" "$STAGE_DIR"
  archive_version="$(tr -d '[:space:]' <"$STAGE_DIR/VERSION")"
  if [[ "$archive_version" != "$remote_version" ]]; then
    log "ERROR GitHub main changed during archive download; will retry next cycle"
    exit 1
  fi
  SOURCE_DIR="$STAGE_DIR"
fi

if [[ "$SIDE" == "server" ]]; then
  install_env="$BASE_DIR/server-install.env"
  image_source="$(awk -F= '$1=="IMAGE_SOURCE"{print substr($0,index($0,"=")+1);exit}' "$install_env" 2>/dev/null || true)"
  github_image="$(awk -F= '$1=="GITHUB_IMAGE"{print substr($0,index($0,"=" )+1);exit}' "$install_env" 2>/dev/null || true)"
  if [[ "$image_source" == "github" && -n "$github_image" ]]; then
    image_ready="false"
    for _ in $(seq 1 30); do
      if podman pull "$github_image" >/dev/null 2>&1; then
        image_revision="$(podman image inspect --format '{{ index .Labels "org.opencontainers.image.revision" }}' "$github_image" 2>/dev/null || true)"
        if [[ "$image_revision" == "$remote_commit" ]]; then
          image_ready="true"
          break
        fi
      fi
      sleep 30
    done
    if [[ "$image_ready" != "true" ]]; then
      log "ERROR GHCR image for $remote_commit was not ready; will retry"
      exit 1
    fi
  fi
  NARWHAL_AUTO_UPDATE=1 bash "$SOURCE_DIR/scripts/install-server.sh" update
else
  set +e
  NARWHAL_AUTO_UPDATE=1 bash "$SOURCE_DIR/scripts/install-client.sh" update
  client_update_result=$?
  set -e
  if [[ "$client_update_result" -eq 75 ]]; then
    log "update deferred: waiting for Server to run the target version"
    exit 0
  elif [[ "$client_update_result" -ne 0 ]]; then
    log "ERROR Client installer failed with exit code $client_update_result"
    exit "$client_update_result"
  fi
fi

expected_version="$(tr -d '[:space:]' <"$SOURCE_DIR/VERSION")"
runtime_version="$(installed_version || true)"
if [[ "$runtime_version" != "$expected_version" ]]; then
  log "ERROR deployment verification failed: runtime_version=${runtime_version:-unknown} expected_version=$expected_version"
  exit 1
fi

printf '%s\n' "$remote_commit" >"$STATE_FILE.tmp"
chmod 0600 "$STATE_FILE.tmp"
mv -f "$STATE_FILE.tmp" "$STATE_FILE"
log "update completed: $remote_commit (version $expected_version)"
