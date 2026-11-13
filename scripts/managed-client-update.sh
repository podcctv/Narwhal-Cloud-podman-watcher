#!/usr/bin/env bash
# Independent systemd unit survives restarting the Agent. No remote shell input.
set -euo pipefail
base=/opt/narwhal-monitor
mode=${1:-}
action_id=${4:-${2:-0}}
[[ "$action_id" =~ ^[0-9]+$ ]] || exit 2
snapshot="$base/client-previous"
app_dir="$base/client-agent"
systemd_unit="${NARWHAL_SYSTEMD_SERVICE_FILE:-/etc/systemd/system/narwhal-monitor-client.service}"
exec 9>"$base/managed-client-update.lock"
flock -n 9 || { echo 'another managed upgrade is running'; exit 1; }
exec 8>/run/narwhal-monitor-client-auto-update.lock
flock -n 8 || { echo 'automatic updater is already running; retry later'; exit 1; }
snapshot_ready=0
deployment_started=0
failure_message=""
write_result() {
  local installed_version
  installed_version=$(awk -F= '$1=="NARWHAL_VERSION"{print $2;exit}' "$base/client.env" 2>/dev/null || true)
  [[ "$installed_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || installed_version=unknown
  umask 077
  # Dynamic source diagnostics are reduced to one line and JSON-escaped before use.
  printf '{"action_id":%s,"status":"%s","version":"%s","mode":"%s","message":"%s"}\n' \
    "$action_id" "$1" "$installed_version" "$mode" "$failure_message" >"$base/managed-update-result.json.tmp"
  mv -f "$base/managed-update-result.json.tmp" "$base/managed-update-result.json"
}
fail_preflight() {
  failure_message="$1"
  echo "$failure_message" >&2
  write_result failed || true
  exit 1
}
wait_for_client_stable() {
  local timeout_seconds=45 stable_seconds=15 started_at=$SECONDS stable_since=0
  local status active_state sub_state main_pid restart_count signature previous_signature=""
  while (( SECONDS - started_at < timeout_seconds )); do
    status=$(systemctl show --no-pager --property=ActiveState,SubState,MainPID,NRestarts narwhal-monitor-client.service 2>/dev/null || true)
    active_state="$(sed -n 's/^ActiveState=//p' <<<"$status")"
    sub_state="$(sed -n 's/^SubState=//p' <<<"$status")"
    main_pid="$(sed -n 's/^MainPID=//p' <<<"$status")"
    restart_count="$(sed -n 's/^NRestarts=//p' <<<"$status")"
    if [[ "$active_state" == active && "$sub_state" == running && "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
      signature="$main_pid/$restart_count"
      if [[ "$signature" != "$previous_signature" ]]; then
        previous_signature="$signature"
        stable_since=$SECONDS
      elif (( SECONDS - stable_since >= stable_seconds )); then
        return 0
      fi
    else
      previous_signature=""
      stable_since=0
    fi
    sleep 2
  done
  echo 'client service did not remain active with a stable process for 15 seconds' >&2
  return 1
}
restore() {
  local snapshot_client_dir="$snapshot/client"
  if [[ ! -d "$snapshot_client_dir" ]]; then
    snapshot_client_dir="$snapshot"
  fi
  [[ -f "$snapshot_client_dir/agent.py" && -f "$snapshot/client.env" ]] || return 1
  systemctl stop narwhal-monitor-client.service || return 1
  if [[ -f "$app_dir/admission_guard.py" ]]; then
    "$app_dir/.venv/bin/python" "$app_dir/admission_guard.py" --release-all || return 1
  fi
  shopt -s nullglob
  local cur_py cur_name snap_py cur_bin bin_name snap_bin
  for cur_py in "$app_dir"/*.py; do
    cur_name=$(basename "$cur_py")
    if [[ ! -f "$snapshot_client_dir/$cur_name" ]]; then
      rm -f "$cur_py" || return 1
    fi
  done
  if [[ -f "$snapshot/staged-files.manifest" ]]; then
    while IFS= read -r staged_rel; do
      [[ -n "$staged_rel" ]] || continue
      if [[ ! -f "$snapshot_client_dir/$staged_rel" ]]; then
        rm -f "$app_dir/$staged_rel" || return 1
      fi
    done <"$snapshot/staged-files.manifest"
  fi
  if [[ -d "$app_dir/bin" ]]; then
    for cur_bin in "$app_dir/bin"/*; do
      [[ -f "$cur_bin" ]] || continue
      bin_name=$(basename "$cur_bin")
      if [[ ! -f "$snapshot_client_dir/bin/$bin_name" ]]; then
        rm -f "$cur_bin" || return 1
      fi
    done
    if [[ ! -d "$snapshot_client_dir/bin" ]]; then
      rmdir "$app_dir/bin" 2>/dev/null || true
    fi
  fi
  for snap_py in "$snapshot_client_dir"/*.py; do
    install -m 0644 "$snap_py" "$app_dir/$(basename "$snap_py")" || return 1
  done
  if [[ -d "$snapshot_client_dir/bin" ]]; then
    mkdir -p "$app_dir/bin" || return 1
    for snap_bin in "$snapshot_client_dir/bin"/*; do
      [[ -f "$snap_bin" ]] || continue
      install -m 0755 "$snap_bin" "$app_dir/bin/$(basename "$snap_bin")" || return 1
    done
  fi
  shopt -u nullglob
  install -m 0600 "$snapshot/client.env" "$base/client.env" || return 1
  install -m 0644 "$snapshot/requirements.txt" "$app_dir/requirements.txt" || return 1
  "$app_dir/.venv/bin/pip" install -r "$app_dir/requirements.txt" || return 1
  if [[ -f "$snapshot/managed-client-update.sh" ]]; then
    install -m 0755 "$snapshot/managed-client-update.sh" "$base/managed-client-update.sh" || return 1
  fi
  if [[ -f "$snapshot/update_archive.py" ]]; then
    install -m 0755 "$snapshot/update_archive.py" "$base/update_archive.py" || return 1
  fi
  if [[ -f "$snapshot/narwhal-monitor-client.service" ]]; then
    install -m 0644 "$snapshot/narwhal-monitor-client.service" "$systemd_unit" || return 1
    systemctl daemon-reload || return 1
  fi
  systemctl restart narwhal-monitor-client.service || return 1
  wait_for_client_stable
}
on_error() {
  local result=$?
  trap - ERR
  if [[ -z "$failure_message" ]]; then
    failure_message="update command failed with exit code $result"
  fi
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
[[ "$mode" == upgrade && "${2:-}" =~ ^[0-9a-f]{40}$ && "${3:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail_preflight 'invalid immutable upgrade target'
revision=$2
version=$3
config="$base/client-auto-update.env"
[[ -f "$config" ]] || fail_preflight 'no checkout configured; run the installer update setup before retrying'
# Locally installed root-owned configuration, never a network-provided script.
source "$config"
repo=${AUTO_UPDATE_REPO_DIR:-}
update_mode=${AUTO_UPDATE_MODE:-git}
stage=$(mktemp -d "$base/managed-stage.XXXXXX")
cleanup_stage() {
  local resolved
  resolved=$(realpath -e "$stage") || return
  [[ "$resolved" == /opt/narwhal-monitor/managed-stage.* && "$resolved" != "$base" ]] || return
  rm -rf -- "$resolved"
}
trap cleanup_stage EXIT
if [[ "$update_mode" == git ]]; then
  [[ -n "$repo" && "$repo" == /* && -d "$repo/.git" ]] || fail_preflight 'configured update checkout is missing or invalid'
  origin=$(git -C "$repo" remote get-url origin) || fail_preflight 'could not read update checkout origin'
  [[ "$origin" == https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git ]] || fail_preflight 'untrusted update checkout origin'
  [[ -z $(git -C "$repo" status --porcelain) ]] || fail_preflight 'preserving local changes; refusing upgrade'
  git -C "$repo" fetch origin main
  [[ $(git -C "$repo" rev-parse origin/main) == "$revision" ]] || fail_preflight 'main changed; create a new campaign'
  git -C "$repo" merge-base --is-ancestor HEAD "$revision" || fail_preflight 'checkout diverged; preserving local commits'
  [[ $(git -C "$repo" show "$revision:VERSION" | tr -d '[:space:]') == "$version" ]] || fail_preflight 'target VERSION does not match the release'
  git -C "$repo" archive "$revision" | tar -x -C "$stage"
elif [[ "$update_mode" == archive ]]; then
  helper="$base/update_archive.py"
  [[ -f "$helper" && -x "$helper" ]] || fail_preflight 'fixed-origin archive updater is missing'
  command -v python3 >/dev/null 2>&1 || fail_preflight 'Python 3 is unavailable for archive upgrade'
  current_main=$(python3 "$helper" resolve) || fail_preflight 'could not verify current GitHub main revision'
  [[ "$current_main" == "$revision" ]] || fail_preflight 'main changed; create a new campaign'
  # Older installed Agents only know the original codeload `download` command.
  # Use the pinned-file fallback only after the helper has been upgraded to advertise it.
  helper_commands=$(python3 "$helper" --help 2>&1 || true)
  download_command=download
  if grep -q 'download-client' <<<"$helper_commands"; then
    download_command=download-client
  fi
  if ! bundle_error=$(python3 "$helper" "$download_command" "$revision" "$stage" 2>&1); then
    bundle_error=${bundle_error//$'\r'/ }
    bundle_error=${bundle_error//$'\n'/ }
    bundle_error=${bundle_error//\\/\\\\}
    bundle_error=${bundle_error//\"/\\\"}
    bundle_error=${bundle_error:0:300}
    fail_preflight "could not download immutable Agent update bundle: ${bundle_error:-unknown source error}"
  fi
  [[ $(tr -d '[:space:]' <"$stage/VERSION") == "$version" ]] || fail_preflight 'target VERSION does not match the release'
else
  fail_preflight 'invalid automatic update mode'
fi
shopt -s nullglob
stage_py_files=("$stage/client"/*.py)
shopt -u nullglob
[[ ${#stage_py_files[@]} -gt 0 && -f "$stage/client/agent.py" ]] || fail_preflight 'staged client bundle is missing Python modules'
"$app_dir/.venv/bin/python" -m py_compile "${stage_py_files[@]}"
rm -rf "$snapshot"
mkdir -p "$snapshot/client"
chmod 0700 "$snapshot" "$snapshot/client"
: >"$snapshot/installed-files.manifest"
: >"$snapshot/staged-files.manifest"
shopt -s nullglob
for stage_py in "$stage/client"/*.py; do
  printf '%s\n' "$(basename "$stage_py")" >>"$snapshot/staged-files.manifest"
done
if [[ -d "$stage/client/bin" ]]; then
  for stage_bin in "$stage/client/bin"/*; do
    [[ -f "$stage_bin" ]] || continue
    printf 'bin/%s\n' "$(basename "$stage_bin")" >>"$snapshot/staged-files.manifest"
  done
fi
for app_py in "$app_dir"/*.py; do
  app_py_name=$(basename "$app_py")
  install -m 0644 "$app_py" "$snapshot/client/$app_py_name"
  printf '%s\n' "$app_py_name" >>"$snapshot/installed-files.manifest"
done
if [[ -d "$app_dir/bin" ]]; then
  mkdir -p "$snapshot/client/bin"
  chmod 0755 "$snapshot/client/bin"
  for app_bin in "$app_dir/bin"/*; do
    [[ -f "$app_bin" ]] || continue
    app_bin_name=$(basename "$app_bin")
    install -m 0755 "$app_bin" "$snapshot/client/bin/$app_bin_name"
    printf 'bin/%s\n' "$app_bin_name" >>"$snapshot/installed-files.manifest"
  done
fi
shopt -u nullglob
install -m 0644 "$app_dir/requirements.txt" "$snapshot/requirements.txt"
install -m 0600 "$base/client.env" "$snapshot/client.env"
if [[ -f "$systemd_unit" ]]; then
  install -m 0644 "$systemd_unit" "$snapshot/narwhal-monitor-client.service"
fi
if [[ -f "$base/managed-client-update.sh" ]]; then
  install -m 0755 "$base/managed-client-update.sh" "$snapshot/managed-client-update.sh"
fi
if [[ -f "$base/update_archive.py" ]]; then
  install -m 0755 "$base/update_archive.py" "$snapshot/update_archive.py"
fi
if [[ "$update_mode" == git ]]; then
  git -C "$repo" rev-parse HEAD >"$snapshot/revision"
else
  tr -d '[:space:]' <"$base/client-auto-update.version" >"$snapshot/revision" 2>/dev/null || true
fi
snapshot_ready=1
# Explicit managed rollout takes over from the unconditional 15-minute timer.
systemctl stop narwhal-monitor-client-update.timer
systemctl disable narwhal-monitor-client-update.timer
deployment_started=1
if NARWHAL_MANAGED_UPDATE=1 NARWHAL_AUTO_UPDATE=1 bash "$stage/scripts/install-client.sh" update && wait_for_client_stable; then
  # Keep the checkout and deployment marker aligned without discarding edits.
  if [[ "$update_mode" == git ]]; then
    git -C "$repo" merge --ff-only "$revision"
  fi
  printf '%s\n' "$revision" >"$base/client-auto-update.version"
  chmod 0600 "$base/client-auto-update.version"
  write_result installed
  echo "installed $version at $revision; wait for signed version report"
else
  echo 'upgrade failed; restoring previous agent'
  if ! restore; then
    echo 'automatic rollback failed; inspect the retained snapshot' >&2
  fi
  deployment_started=0
  write_result failed
  exit 1
fi
