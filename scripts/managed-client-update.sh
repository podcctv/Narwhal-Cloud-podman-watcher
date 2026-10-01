#!/usr/bin/env bash
# Independent systemd unit survives restarting the Agent. No remote shell input.
set -euo pipefail
base=/opt/narwhal-monitor
mode=${1:-}
action_id=${4:-${2:-0}}
[[ "$action_id" =~ ^[0-9]+$ ]] || exit 2
snapshot="$base/client-previous"
app_dir="$base/client-agent"
exec 9>"$base/managed-client-update.lock"
flock -n 9 || { echo 'another managed upgrade is running'; exit 1; }
exec 8>/run/narwhal-monitor-client-auto-update.lock
flock -n 8 || { echo 'automatic updater is already running; retry later'; exit 1; }
snapshot_ready=0
deployment_started=0
write_result() {
  local installed_version
  installed_version=$(awk -F= '$1=="NARWHAL_VERSION"{print $2;exit}' "$base/client.env" 2>/dev/null || true)
  [[ "$installed_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || installed_version=unknown
  umask 077
  printf '{"action_id":%s,"status":"%s","version":"%s","mode":"%s"}\n' "$action_id" "$1" "$installed_version" "$mode" >"$base/managed-update-result.json.tmp"
  mv -f "$base/managed-update-result.json.tmp" "$base/managed-update-result.json"
}
restore() {
  [[ -f "$snapshot/agent.py" && -f "$snapshot/client.env" ]] || return 1
  systemctl stop narwhal-monitor-client.service || return 1
  install -m 0644 "$snapshot/agent.py" "$app_dir/agent.py" || return 1
  if [[ -f "$snapshot/operations.py" ]]; then
    install -m 0644 "$snapshot/operations.py" "$app_dir/operations.py" || return 1
  fi
  if [[ -f "$snapshot/security_banner.py" ]]; then
    install -m 0644 "$snapshot/security_banner.py" "$app_dir/security_banner.py" || return 1
  fi
  install -m 0600 "$snapshot/client.env" "$base/client.env" || return 1
  install -m 0644 "$snapshot/requirements.txt" "$app_dir/requirements.txt" || return 1
  "$app_dir/.venv/bin/pip" install -r "$app_dir/requirements.txt" || return 1
  systemctl restart narwhal-monitor-client.service || return 1
  systemctl is-active --quiet narwhal-monitor-client.service
}
on_error() {
  local result=$?
  trap - ERR
  if [[ "$deployment_started" == 1 && "$snapshot_ready" == 1 ]]; then
    restore || echo 'automatic rollback failed; inspect the retained snapshot'
  fi
  write_result failed || true
  exit "$result"
}
trap on_error ERR
if [[ "$mode" == rollback ]]; then
  systemctl stop narwhal-monitor-client-update.timer
  systemctl disable narwhal-monitor-client-update.timer
  restore
  write_result installed
  exit
fi
[[ "$mode" == upgrade && "${2:-}" =~ ^[0-9a-f]{40}$ && "${3:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
revision=$2
version=$3
config="$base/client-auto-update.env"
[[ -f "$config" ]] || { echo 'no checkout configured'; exit 1; }
# Locally installed root-owned configuration, never a network-provided script.
source "$config"
repo=${AUTO_UPDATE_REPO_DIR:-}
[[ -n "$repo" && "$repo" == /* && -d "$repo/.git" ]] || exit 1
origin=$(git -C "$repo" remote get-url origin)
[[ "$origin" == https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git ]] || { echo 'untrusted origin'; exit 1; }
[[ -z $(git -C "$repo" status --porcelain) ]] || { echo 'preserving local changes; refusing upgrade'; exit 1; }
git -C "$repo" fetch origin main
[[ $(git -C "$repo" rev-parse origin/main) == "$revision" ]] || { echo 'main changed; create a new campaign'; exit 1; }
git -C "$repo" merge-base --is-ancestor HEAD "$revision" || { echo 'checkout diverged; preserving local commits'; exit 1; }
[[ $(git -C "$repo" show "$revision:VERSION" | tr -d '[:space:]') == "$version" ]] || exit 1
stage=$(mktemp -d "$base/managed-stage.XXXXXX")
cleanup_stage() {
  local resolved
  resolved=$(realpath -e "$stage") || return
  [[ "$resolved" == /opt/narwhal-monitor/managed-stage.* && "$resolved" != "$base" ]] || return
  rm -rf -- "$resolved"
}
trap cleanup_stage EXIT
git -C "$repo" archive "$revision" | tar -x -C "$stage"
"$app_dir/.venv/bin/python" -m py_compile "$stage/client/agent.py" "$stage/client/operations.py" "$stage/client/security_banner.py"
mkdir -p "$snapshot"
chmod 0700 "$snapshot"
install -m 0644 "$app_dir/agent.py" "$snapshot/agent.py"
[[ ! -f "$app_dir/operations.py" ]] || install -m 0644 "$app_dir/operations.py" "$snapshot/operations.py"
[[ ! -f "$app_dir/security_banner.py" ]] || install -m 0644 "$app_dir/security_banner.py" "$snapshot/security_banner.py"
install -m 0644 "$app_dir/requirements.txt" "$snapshot/requirements.txt"
install -m 0600 "$base/client.env" "$snapshot/client.env"
git -C "$repo" rev-parse HEAD >"$snapshot/revision"
snapshot_ready=1
# Explicit managed rollout takes over from the unconditional 15-minute timer.
systemctl stop narwhal-monitor-client-update.timer
systemctl disable narwhal-monitor-client-update.timer
deployment_started=1
if NARWHAL_MANAGED_UPDATE=1 NARWHAL_AUTO_UPDATE=1 bash "$stage/scripts/install-client.sh" update && systemctl is-active --quiet narwhal-monitor-client.service; then
  # Keep the checkout and deployment marker aligned without discarding edits.
  git -C "$repo" merge --ff-only "$revision"
  printf '%s\n' "$revision" >"$base/client-auto-update.version"
  chmod 0600 "$base/client-auto-update.version"
  write_result installed
  echo "installed $version at $revision; wait for signed version report"
else
  echo 'upgrade failed; restoring previous agent'
  restore
  deployment_started=0
  write_result failed
  exit 1
fi
