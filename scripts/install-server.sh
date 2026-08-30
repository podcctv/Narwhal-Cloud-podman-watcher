#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
SERVER_ENV_FILE="/opt/narwhal-monitor/server.env"
SERVER_INSTALL_ENV_FILE="/opt/narwhal-monitor/server-install.env"
SERVER_DATA_DIR="/opt/narwhal-monitor/server-data"
TLS_DIR="/opt/narwhal-monitor/caddy"
TLS_CA_EXPORT_DIR="/opt/narwhal-monitor/tls-ca"
CONTAINER_NAME="narwhal-monitor-server"
TLS_CONTAINER_NAME="narwhal-monitor-caddy"
DEPLOY_LOCK_FILE="/run/narwhal-monitor-server-deploy-v2.lock"
# 专用网络：避免使用 Podman 默认 10.88.0.0/16，规避与宿主机已有私网网卡冲突。
NARWHAL_NETWORK_NAME="narwhal-monitor-net"
# Long-running Server/Caddy processes must not remain in the short-lived
# automatic updater's cgroup.  The concrete arguments are selected after
# Podman is available (see configure_container_cgroup_args).
PODMAN_CGROUP_ARGS=( --cgroups=split )
PODMAN_RUN_IN_SCOPE="no"
# shellcheck source=scripts/lib/interactive.sh
source "$ROOT_DIR/scripts/lib/interactive.sh"

MODE="${1:-install}"
RESET_DATA_ARG="${2:-}"
if [[ "$MODE" != "install" && "$MODE" != "update" && "$MODE" != "reset-password" ]]; then
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update|reset-password] [--reset-data]"
  exit 1
fi
if [[ -n "$RESET_DATA_ARG" && "$RESET_DATA_ARG" != "--reset-data" ]]; then
  echo "[ERROR] 未知参数: $RESET_DATA_ARG"
  echo "[ERROR] 用法: bash scripts/install-server.sh [install|update|reset-password] [--reset-data]"
  exit 1
fi
if [[ "$MODE" == "reset-password" && -n "$RESET_DATA_ARG" ]]; then
  echo "[ERROR] reset-password 不接受 --reset-data"
  exit 1
fi

detect_ghcr_owner() {
  local owner="narwhal-cloud"
  if command -v git >/dev/null 2>&1; then
    local remote_url
    remote_url="$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || true)"
    if [[ -n "$remote_url" ]]; then
      if [[ "$remote_url" =~ github\.com[:/]([^/]+)/[^/]+(\.git)?$ ]]; then
        owner="${BASH_REMATCH[1]}"
      fi
    fi
  fi
  echo "$owner"
}

generate_secret() {
  tr -d '-' </proc/sys/kernel/random/uuid | cut -c 1-25
}

generate_dashboard_username() {
  echo "narwhal-$(generate_secret | cut -c 1-10)"
}

generate_dashboard_password() {
  printf '%s%s' "$(generate_secret)" "$(generate_secret)"
}

pick_random_port() {
  local fallback=49152
  if ! command -v ss >/dev/null 2>&1; then
    echo "$fallback"
    return
  fi

  local candidate
  for _ in $(seq 1 120); do
    candidate="$(shuf -i 40000-65000 -n 1)"
    if ! ss -ltnH "( sport = :${candidate} )" | grep -q .; then
      echo "$candidate"
      return
    fi
  done

  echo "$fallback"
}

# 将 IPv4 地址转换为整数，便于做子网归属判断。
ip_to_int() {
  local ip="$1"
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# 判断给定的子网是否与宿主机已有网卡/路由冲突。
# 冲突判定：
#   1) 宿主机任一非 loopback 网卡已配置该子网内的地址；
#   2) 已存在指向该子网的路由（如其它私网 bridge）。
# 注意：更新流程会先通过 `podman network exists` 复用同名网络并提前返回，
# 因此这里无需跳过本项目网桥——否则会漏判与其它 Podman 网络（如默认 podman 网桥）
# 的子网重叠，导致新建网络失败并错误回退到默认网络。
subnet_conflicts() {
  local subnet="$1"
  local net="${subnet%/*}"
  local prefix="${subnet#*/}"
  local net_int mask_int
  net_int="$(ip_to_int "$net")"
  mask_int="$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))"

  local iface addr addr_int
  while read -r iface addr; do
    [[ "$iface" == "lo" ]] && continue
    addr="${addr%%/*}"
    case "$addr" in
      *:*) continue ;;  # 跳过 IPv6
    esac
    addr_int="$(ip_to_int "$addr")"
    if (( (addr_int & mask_int) == (net_int & mask_int) )); then
      return 0
    fi
  done < <(ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}')

  # 已有指向该子网的路由（排除默认路由 0.0.0.0/0）。
  if ip route show to "$subnet" 2>/dev/null \
      | grep -v -E '^default' \
      | grep -q .; then
    return 0
  fi

  return 1
}

# 确保存在专用的 Podman 网络，且子网不与宿主机已有私网冲突。
# 通过 NARWHAL_NETWORK_NAME 返回网络名称（全局），并打印最终使用的子网。
ensure_narwhal_network() {
  if ! command -v podman >/dev/null 2>&1; then
    echo "[WARN] 未检测到 podman，跳过专用网络创建，Server 将使用默认网络。"
    NARWHAL_NETWORK_NAME=""
    return 0
  fi

  # 已存在则直接复用，不再做冲突检测。
  # 原因：subnet_conflicts 会把本网络自身的路由（如 10.233.0.0/16 dev narwhal-monitor0）
  # 误判为“与宿主机冲突”，导致更新时反复销毁重建网络、使正在运行的 Server 断网。
  # 冲突退避仅发生在“首次新建”网络时（见下方候选子网逻辑）。
  if podman network exists "$NARWHAL_NETWORK_NAME" >/dev/null 2>&1; then
    local existing_subnet=""
    existing_subnet="$(podman network inspect "$NARWHAL_NETWORK_NAME" \
      --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null || true)"
    echo "[INFO] 复用已存在的专用网络 $NARWHAL_NETWORK_NAME (subnet=${existing_subnet:-未知})。"
    return 0
  fi

  # 候选子网，按顺序尝试：先排除与宿主机冲突的子网，再实际创建；
  # 若某个子网创建失败（例如与其它 Podman 网络子网重叠），继续尝试下一个，
  # 而不是直接回退到默认网络，以保证专用网络能尽可能被创建出来。
  local -a candidates=(
    "10.233.0.0/16"
    "10.99.0.0/16"
    "10.135.0.0/16"
    "10.155.0.0/16"
    "10.199.0.0/16"
    "10.209.0.0/16"
    "172.20.0.0/16"
    "172.28.0.0/16"
  )
  local candidate=""
  local create_err=""
  for candidate in "${candidates[@]}"; do
    if subnet_conflicts "$candidate"; then
      echo "[INFO] 候选子网 $candidate 与宿主机冲突，退避到下一个。"
      continue
    fi
    if ! create_err="$(podman network create --subnet "$candidate" "$NARWHAL_NETWORK_NAME" 2>&1)"; then
      echo "[WARN] 候选子网 $candidate 创建失败：$create_err（尝试下一个）。"
      continue
    fi
    echo "[INFO] 已创建专用网络 $NARWHAL_NETWORK_NAME (subnet=$candidate)，规避与宿主机已有私网网卡冲突。"
    return 0
  done

  echo "[WARN] 所有候选子网均无法创建专用网络，回退到 Podman 默认网络（可能存在私网冲突风险）。"
  NARWHAL_NETWORK_NAME=""
  return 0
}

ask_with_default() {
  local prompt="$1"
  local current="$2"
  local answer=""
  if [[ "$MODE" == "update" ]]; then
    echo "$current"
    return
  fi
  read -rp "$prompt [$current]: " answer
  echo "${answer:-$current}"
}

load_kv_from_file() {
  local f="$1"
  local key="$2"
  [[ -f "$f" ]] || return 1
  awk -v k="$key" '
    {
      gsub(/\r/, "")
      pos = index($0, "=")
      if (pos > 0) {
        current_key = substr($0, 1, pos - 1)
        if (current_key == k) {
          print substr($0, pos + 1)
          found = 1
          exit
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$f"
}

load_non_empty_or_default() {
  local f="$1"
  local key="$2"
  local fallback="$3"
  local value=""

  value="$(load_kv_from_file "$f" "$key" || true)"
  if [[ -n "$value" ]]; then
    echo "$value"
  else
    echo "$fallback"
  fi
}

is_truthy() {
  local value="${1:-}"
  value="$(echo "$value" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "y" ]]
}

wipe_server_data() {
  if [[ -d "$SERVER_DATA_DIR" ]]; then
    rm -rf "${SERVER_DATA_DIR:?}/"* "${SERVER_DATA_DIR:?}"/.[!.]* "${SERVER_DATA_DIR:?}"/..?* 2>/dev/null || true
  fi
  mkdir -p "$SERVER_DATA_DIR"
}

ensure_root_and_deps() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Please run as root: sudo bash scripts/install-server.sh ${MODE}"
    exit 1
  fi

  if ! command -v podman >/dev/null 2>&1; then
    echo "Installing podman..."
    apt-get update
    apt-get install -y podman
  fi
}

ask_choice_with_default() {
  local prompt="$1"
  local current="$2"
  shift 2
  if [[ "$MODE" == "update" ]]; then
    echo "$current"
    return
  fi
  narwhal_choose "$prompt" "$current" "$@"
}

acquire_deploy_lock() {
  if [[ "${NARWHAL_SERVER_DEPLOY_LOCKED:-0}" == "1" ]]; then
    if (( ${NARWHAL_SERVER_DEPLOY_WAITED:-0} > 0 )); then
      echo "[OK] 已等待 ${NARWHAL_SERVER_DEPLOY_WAITED} 秒，部署锁现已释放，继续当前流程。"
    fi
    return
  fi
  local -a locked_command=(
    env NARWHAL_SERVER_DEPLOY_LOCKED=1
    NARWHAL_SERVER_DEPLOY_WAITED=0
    bash "$ROOT_DIR/scripts/install-server.sh" "$MODE"
  )
  if [[ -n "$RESET_DATA_ARG" ]]; then
    locked_command+=( "$RESET_DATA_ARG" )
  fi

  local waited_seconds=0
  local lock_result=0
  while true; do
    locked_command[2]="NARWHAL_SERVER_DEPLOY_WAITED=$waited_seconds"
    set +e
    flock --exclusive --nonblock --close --conflict-exit-code 75 \
      "$DEPLOY_LOCK_FILE" "${locked_command[@]}"
    lock_result=$?
    set -e
    if [[ "$lock_result" -ne 75 ]]; then
      exit "$lock_result"
    fi
    if (( waited_seconds == 0 )); then
      echo "[INFO] 检测到另一个 Server 安装或自动更新正在执行，等待其释放部署锁（最长 5 分钟）..."
      if command -v systemctl >/dev/null 2>&1 \
        && systemctl is-active --quiet narwhal-monitor-server-update.service; then
        echo "[INFO] 后台自动更新服务当前为 active；可在另一终端查看："
        echo "       journalctl -fu narwhal-monitor-server-update.service"
      fi
    fi
    if (( waited_seconds >= 300 )); then
      break
    fi
    sleep 5
    waited_seconds=$((waited_seconds + 5))
    if (( waited_seconds % 30 == 0 )); then
      echo "[INFO] 仍在等待其他部署完成：${waited_seconds}/300 秒..."
    fi
  done
  echo "[ERROR] 等待 Server 部署锁超过 5 分钟，可能已有安装或自动更新仍在运行。"
  echo "[INFO] 可检查: systemctl status narwhal-monitor-server-update.service --no-pager"
  exit 1
}

remove_container_for_replace() {
  local container_name="$1"
  local display_name="$2"
  local existing_id=""
  existing_id="$(podman container inspect --format '{{.Id}}' "$container_name" 2>/dev/null || true)"
  if [[ -n "$existing_id" ]]; then
    echo "[INFO] 正在替换现有 $display_name 容器: ${existing_id:0:12}"
    if ! podman rm -f --time 10 "$container_name"; then
      echo "[WARN] 首次删除旧 $display_name 容器失败，尝试强制停止后再次删除..."
      podman stop --time 5 "$container_name" >/dev/null 2>&1 || true
      podman rm -f --time 0 "$container_name" || true
    fi
  fi
  if podman container inspect "$container_name" >/dev/null 2>&1; then
    echo "[ERROR] 旧 $display_name 容器仍占用名称 '$container_name'，拒绝继续以免产生半更新状态。"
    podman container inspect --format 'ID={{.Id}} Status={{.State.Status}} Error={{.State.Error}}' \
      "$container_name" 2>/dev/null || true
    exit 1
  fi
}

# 等待指定主机端口不再被监听（netavark 端口回收存在竞态，释放需要一点时间）。
wait_for_port_free() {
  local port="$1"
  local waited=0
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  while (( waited < 15 )); do
    if ! ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "[WARN] 端口 $port 在 15 秒内仍被占用。" >&2
  return 0
}

wait_for_backend_http() {
  local host_port="$1"
  local attempt=""
  local status=""
  if ! command -v curl >/dev/null 2>&1; then
    echo "[WARN] curl 不可用，跳过 Server 后端 HTTP 健康检查。"
    return 0
  fi
  for attempt in $(seq 1 30); do
    status="$(curl --noproxy '*' --max-time 2 -sS -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${host_port}/" 2>/dev/null || true)"
    if [[ "$status" =~ ^[1-4][0-9][0-9]$ ]]; then
      echo "[OK] Server 后端 HTTP 可达（127.0.0.1:${host_port}，状态码 $status）。"
      return 0
    fi
    sleep 1
  done
  echo "[ERROR] Server 容器虽显示运行，但后端端口 127.0.0.1:${host_port} 未返回 HTTP。"
  return 1
}

wait_for_tls_http() {
  local host="$1"
  local attempt=""
  local status=""
  local -a target_args=()
  if ! command -v curl >/dev/null 2>&1; then
    echo "[WARN] curl 不可用，跳过 TLS Proxy HTTP 健康检查。"
    return 0
  fi
  # curl --resolve 的 IPv6 目标语法差异较大；Caddy 配置校验仍会覆盖该场景。
  if [[ "$host" == *:* ]]; then
    echo "[WARN] TLS host 为 IPv6，跳过本机 --resolve HTTP 检查。"
    return 0
  fi
  if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    # curl 对 IP 字面量不发送 SNI；将 IP --resolve 到 127.0.0.1 会导致
    # Caddy 无法选择 IP 证书并返回 TLS internal error，因此直接访问公网 IP。
    target_args=( "https://${host}/" )
  else
    target_args=( --resolve "${host}:443:127.0.0.1" "https://${host}/" )
  fi
  for attempt in $(seq 1 30); do
    status="$(curl --noproxy '*' --max-time 3 -k -sS -o /dev/null -w '%{http_code}' \
      "${target_args[@]}" 2>/dev/null || true)"
    if [[ "$status" =~ ^[1-4][0-9][0-9]$ ]]; then
      echo "[OK] TLS Proxy HTTP 可达（https://${host}/，状态码 $status）。"
      return 0
    fi
    sleep 1
  done
  echo "[ERROR] TLS Proxy 虽显示运行，但 https://${host}/ 未返回有效 HTTP。"
  return 1
}

stage_container_replacement() {
  local container_name="$1"
  local display_name="$2"
  local backup_name="${container_name}-rollback"

  if podman container inspect "$backup_name" >/dev/null 2>&1; then
    if ! podman container inspect "$container_name" >/dev/null 2>&1; then
      echo "[WARN] 发现上次未完成的 $display_name 回滚容器，先恢复服务。"
      podman rename "$backup_name" "$container_name"
      podman start "$container_name" >/dev/null
    else
      podman rm -f "$backup_name" >/dev/null 2>&1 || true
    fi
  fi

  if ! podman container inspect "$container_name" >/dev/null 2>&1; then
    return 0
  fi
  echo "[INFO] 暂存现有 $display_name 容器用于失败回滚。"
  if ! podman stop --time 10 "$container_name" >/dev/null; then
    # A previously misconfigured updater may have killed conmon while leaving
    # the OCI payload alive.  Podman can then stop the payload successfully but
    # still return an internal error because no exit file was written.  Only
    # clean up when Podman now proves the payload is stopped and conmon is gone.
    local stopped=""
    local payload_pid=""
    local conmon_file=""
    local conmon_pid=""
    stopped="$(podman inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null || true)"
    payload_pid="$(podman inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null || true)"
    conmon_file="$(podman inspect -f '{{.ConmonPidFile}}' "$container_name" 2>/dev/null || true)"
    if [[ -n "$conmon_file" ]]; then
      conmon_pid="$(cat "$conmon_file" 2>/dev/null || true)"
    fi
    if [[ "$stopped" == "false" && "${payload_pid:-0}" == "0" \
      && ( -z "$conmon_pid" || ! -d "/proc/$conmon_pid" ) ]]; then
      echo "[WARN] $display_name 已停止但 conmon 未写入退出状态；清理孤儿元数据后继续重建。"
      podman container cleanup --rm "$container_name" >/dev/null 2>&1 \
        || podman rm -f --time 0 "$container_name" >/dev/null 2>&1 \
        || true
      if ! podman container inspect "$container_name" >/dev/null 2>&1; then
        return 0
      fi
    fi
    echo "[ERROR] 无法停止现有 $display_name 容器，保留原服务并中止更新。"
    return 1
  fi
  if ! podman rename "$container_name" "$backup_name"; then
    echo "[ERROR] 无法暂存现有 $display_name 容器，正在恢复原服务。"
    podman start "$container_name" >/dev/null 2>&1 || true
    return 1
  fi
}

configure_container_cgroup_args() {
  local cgroup_manager=""
  cgroup_manager="$(podman info --format '{{.Host.CgroupManager}}' 2>/dev/null || true)"
  if [[ "$cgroup_manager" == "systemd" ]]; then
    # --cgroups=split alone still nests conmon and the payload underneath the
    # invoking oneshot service.  That leaves the updater cgroup populated and
    # systemd refuses the next start with "Device or resource busy".  An
    # explicit slice makes both processes siblings of the updater instead.
    PODMAN_CGROUP_ARGS=( --cgroups=enabled --cgroup-parent=narwhal-monitor.slice )
    if command -v systemd-run >/dev/null 2>&1; then
      PODMAN_RUN_IN_SCOPE="yes"
      echo "[INFO] Server/Caddy 将通过独立 transient scope 运行在 narwhal-monitor.slice。"
    else
      PODMAN_RUN_IN_SCOPE="no"
      echo "[WARN] systemd-run 不可用；Server/Caddy 使用独立 cgroup parent，但无法创建 launch scope。"
    fi
  else
    # Preserve compatibility with cgroupfs-based Podman hosts.
    PODMAN_CGROUP_ARGS=( --cgroups=split )
    PODMAN_RUN_IN_SCOPE="no"
    echo "[INFO] Podman cgroup manager=${cgroup_manager:-unknown}，使用 split 模式。"
  fi
}

podman_run_detached() {
  local scope_label="$1"
  shift
  local -a command=( podman run -d "${PODMAN_CGROUP_ARGS[@]}" "$@" )
  if [[ "$PODMAN_RUN_IN_SCOPE" == "yes" ]]; then
    # Even with --cgroup-parent, conmon inherits the invoking systemd service's
    # cgroup.  A unique transient scope makes that long-lived monitor a sibling
    # of the updater.  --collect removes the scope after the container exits.
    local scope_unit="narwhal-${scope_label}-launch-$(date +%s%N)-${BASHPID}"
    systemd-run --scope --quiet --collect --slice=narwhal-monitor.slice \
      --unit="$scope_unit" "${command[@]}"
  else
    "${command[@]}"
  fi
}

rollback_container_replacement() {
  local container_name="$1"
  local display_name="$2"
  local backup_name="${container_name}-rollback"
  podman rm -f "$container_name" >/dev/null 2>&1 || true
  if podman container inspect "$backup_name" >/dev/null 2>&1; then
    echo "[WARN] $display_name 更新失败，正在自动恢复上一版本容器。"
    if podman rename "$backup_name" "$container_name" \
      && podman start "$container_name" >/dev/null; then
      echo "[OK] 已恢复上一版本 $display_name 容器。"
      return 0
    fi
    echo "[ERROR] 上一版本 $display_name 容器自动恢复失败，请检查 Podman 状态。"
  fi
  return 1
}

commit_container_replacement() {
  local container_name="$1"
  local backup_name="${container_name}-rollback"
  podman rm -f "$backup_name" >/dev/null 2>&1 || true
}

restore_caddy_config() {
  local caddyfile="$TLS_DIR/Caddyfile"
  local backup="$TLS_DIR/Caddyfile.rollback"
  rm -f "$TLS_DIR/Caddyfile.new"
  if [[ -f "$backup" ]]; then
    mv -f "$backup" "$caddyfile"
  elif [[ -f "$TLS_DIR/Caddyfile.rollback.absent" ]]; then
    rm -f "$caddyfile"
  fi
  rm -f "$TLS_DIR/Caddyfile.rollback.absent"
}

commit_caddy_config() {
  rm -f "$TLS_DIR/Caddyfile.new" "$TLS_DIR/Caddyfile.rollback" \
    "$TLS_DIR/Caddyfile.rollback.absent"
}

# 只接受合法 TCP 端口；旧配置若混入日志文本则重新选择随机端口，绝不拼接其中的数字。
sanitize_server_port() {
  local desired="$1"
  if [[ "$desired" =~ ^[0-9]{1,5}$ ]] \
    && (( 10#$desired >= 1024 && 10#$desired <= 65535 )); then
    echo "$((10#$desired))"
    return
  fi
  echo "[WARN] Server 后端端口配置无效，改用新的随机空闲端口。" >&2
  pick_random_port
}

verify_server_image_version() {
  local image_name="$1"
  local image_version=""
  # metadata-action 会把 OCI version 标签写成 latest，因此读取镜像实际运行环境。
  image_version="$(podman image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
    "$image_name" 2>/dev/null \
    | awk -F= '$1=="NARWHAL_VERSION"{print substr($0,index($0,"=")+1);exit}')"
  if [[ "$image_version" != "$PROJECT_VERSION" ]]; then
    echo "[ERROR] Server 镜像版本不匹配: image=${image_version:-未知}, expected=$PROJECT_VERSION"
    echo "[INFO] 保留当前 Server 容器；请等待 GHCR 对应版本构建完成后重试。"
    exit 1
  fi
}

replace_server_container() {
  local image_name="$1"
  local port_binding="$2"
  local network_name="${3:-}"
  RESOLVED_SERVER_PORT=""
  RESOLVED_SERVER_BINDING="$port_binding"
  local -a net_args=()
  if [[ -n "$network_name" ]]; then
    net_args=( --network "$network_name" )
  fi

  # 提取发布端口，兼容 61912:8080 与 127.0.0.1:61912:8080。
  local bind_host=""
  local host_port=""
  local container_port=""
  local -a binding_parts=()
  IFS=':' read -r -a binding_parts <<<"$port_binding"
  if (( ${#binding_parts[@]} == 2 )); then
    host_port="${binding_parts[0]}"
    container_port="${binding_parts[1]}"
  elif (( ${#binding_parts[@]} == 3 )); then
    bind_host="${binding_parts[0]}"
    host_port="${binding_parts[1]}"
    container_port="${binding_parts[2]}"
  else
    echo "[ERROR] 无效的 Server 端口绑定: $port_binding"
    exit 1
  fi

  if ! stage_container_replacement "$CONTAINER_NAME" "Server"; then
    exit 1
  fi
  wait_for_port_free "$host_port"
  if command -v ss >/dev/null 2>&1 \
    && ss -ltnH "sport = :$host_port" 2>/dev/null | grep -q .; then
    local replacement_port=""
    replacement_port="$(pick_random_port)"
    echo "[WARN] 旧 Server 删除后端口 $host_port 仍被占用；不会终止宿主机进程，改用端口 $replacement_port。"
    host_port="$replacement_port"
    if [[ -n "$bind_host" ]]; then
      port_binding="${bind_host}:${host_port}:${container_port}"
    else
      port_binding="${host_port}:${container_port}"
    fi
  fi
  RESOLVED_SERVER_PORT="$host_port"
  RESOLVED_SERVER_BINDING="$port_binding"

  local new_id=""
  local attempt=""
  local tried_default_net="no"
  for attempt in 1 2 3 4 5; do
    # 注意：不要写成 `... && break`，否则 podman run 失败时 set -e 会静默中止整个脚本。
    new_id="$(podman_run_detached server --name "$CONTAINER_NAME" \
      --restart=always \
      "${net_args[@]}" \
      -p "$port_binding" \
      --env-file "$SERVER_ENV_FILE" \
      -v "$SERVER_DATA_DIR:/data" \
      -v "$TLS_CA_EXPORT_DIR:/tls-ca:ro" \
      "$image_name" 2>&1)" || true
    new_id="$(printf '%s' "$new_id" | tr -d '[:space:]')"
    if [[ "$new_id" == *"address already in use"* ]]; then
      local retry_port=""
      retry_port="$(pick_random_port)"
      echo "[WARN] 端口 $host_port 出现并发占用（尝试 $attempt/5）；不会清理宿主机进程，改用端口 $retry_port。"
      podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
      host_port="$retry_port"
      if [[ -n "$bind_host" ]]; then
        port_binding="${bind_host}:${host_port}:${container_port}"
      else
        port_binding="${host_port}:${container_port}"
      fi
      RESOLVED_SERVER_PORT="$host_port"
      RESOLVED_SERVER_BINDING="$port_binding"
      new_id=""
      sleep 3
      continue
    fi
    # 若使用专用网络创建容器失败，回退到默认网络再试一次。
    # Caddy 以 --network host 反代 127.0.0.1:<host_port>，因此网络选择不影响后端可达性。
    if [[ -n "$network_name" && "$tried_default_net" != "yes" && ! "$new_id" =~ ^[0-9a-fA-F]{12,}$ ]]; then
      echo "[WARN] 使用专用网络 $network_name 创建 Server 容器失败（${new_id}），回退到默认网络重试。"
      net_args=()
      tried_default_net="yes"
      podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
      continue
    fi
    if [[ ! "$new_id" =~ ^[0-9a-fA-F]{12,}$ ]]; then
      echo "[ERROR] 新 Server 容器创建失败: $new_id"
      rollback_container_replacement "$CONTAINER_NAME" "Server" || true
      exit 1
    fi
    break
  done
  if [[ ! "$new_id" =~ ^[0-9a-fA-F]{12,}$ ]]; then
    echo "[ERROR] 新 Server 容器创建失败（端口 $host_port 持续被占用）。"
    rollback_container_replacement "$CONTAINER_NAME" "Server" || true
    exit 1
  fi
  echo "$new_id"

  local running="false"
  local runtime_version=""
  local attempt=""
  for attempt in $(seq 1 30); do
    running="$(podman container inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || true)"
    runtime_version="$(
      podman container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
        "$CONTAINER_NAME" 2>/dev/null \
        | awk -F= '$1=="NARWHAL_VERSION"{print substr($0,index($0,"=")+1);exit}'
    )"
    if [[ "$running" == "true" ]]; then
      if [[ "$runtime_version" != "$PROJECT_VERSION" ]]; then
        echo "[ERROR] Server 运行版本不匹配: runtime=${runtime_version:-未知}, expected=$PROJECT_VERSION"
        podman logs --tail 120 "$CONTAINER_NAME" 2>&1 || true
        rollback_container_replacement "$CONTAINER_NAME" "Server" || true
        exit 1
      fi
      if ! wait_for_backend_http "$host_port"; then
        podman logs --tail 120 "$CONTAINER_NAME" 2>&1 || true
        rollback_container_replacement "$CONTAINER_NAME" "Server" || true
        exit 1
      fi
      echo "[OK] Server 容器已运行，版本 v$runtime_version。"
      return
    fi
    sleep 1
  done
  echo "[ERROR] Server 容器启动失败: running=${running:-unknown}。"
  podman logs --tail 120 "$CONTAINER_NAME" 2>&1 || true
  rollback_container_replacement "$CONTAINER_NAME" "Server" || true
  exit 1
}

setup_tls_proxy() {
  local host="$1"
  local upstream_port="$2"
  local enable_tls="$3"
  local tls_email="$4"
  local tls_cert_mode="$5"
  local cloudflare_api_token="$6"
  local caddy_image="$7"

  mkdir -p "$TLS_CA_EXPORT_DIR"

  if [[ "$enable_tls" != "yes" ]]; then
    remove_container_for_replace "$TLS_CONTAINER_NAME" "TLS Proxy"
    commit_caddy_config
    rm -f "$TLS_CA_EXPORT_DIR/root.crt"
    return
  fi

  mkdir -p "$TLS_DIR/config" "$TLS_DIR/data"

  local host_is_ip="no"
  if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$host" =~ : ]]; then
    host_is_ip="yes"
  fi

  local caddyfile="$TLS_DIR/Caddyfile.new"
  rm -f "$caddyfile"
  if [[ "$tls_cert_mode" == "internal" || "$host_is_ip" == "yes" ]]; then
    cat >"$caddyfile" <<CADDY
https://$host {
  tls internal
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
  else
    if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
      if [[ -z "$cloudflare_api_token" ]]; then
        echo "[ERROR] TLS cert mode 'cloudflare_dns' requires Cloudflare API token."
        rm -f "$caddyfile"
        return 1
      fi
      cat >"$caddyfile" <<CADDY
{
$( [[ -n "$tls_email" ]] && echo "  email $tls_email" )
}
https://$host {
  tls {
    dns cloudflare {\$CLOUDFLARE_API_TOKEN}
  }
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
    else
      if [[ -n "$tls_email" ]]; then
        cat >"$caddyfile" <<CADDY
{
  email $tls_email
}
https://$host {
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
      else
        cat >"$caddyfile" <<CADDY
https://$host {
  reverse_proxy 127.0.0.1:${upstream_port}
}
CADDY
      fi
    fi
  fi

  if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
    if [[ "$caddy_image" =~ ^docker\.io/caddy-dns/cloudflare(:.*)?$ ]]; then
      local normalized_tag="${BASH_REMATCH[1]}"
      [[ -z "$normalized_tag" ]] && normalized_tag=":latest"
      caddy_image="ghcr.io/caddy-dns/cloudflare${normalized_tag}"
      echo "[INFO] Remapped docker.io/caddy-dns/cloudflare to $caddy_image"
    fi
    local -a cf_caddy_candidates=(
      "$caddy_image"
      "ghcr.io/caddy-dns/cloudflare:latest"
      "ghcr.io/caddy-dns/cloudflare:2"
    )
    local selected_image=""
    local img=""
    for img in "${cf_caddy_candidates[@]}"; do
      [[ -z "$img" ]] && continue
      if podman pull "$img" >/dev/null 2>&1; then
        selected_image="$img"
        break
      fi
    done
    if [[ -z "$selected_image" ]]; then
      echo "[ERROR] Unable to pull Cloudflare DNS Caddy image."
      echo "        Tried: ${cf_caddy_candidates[*]}"
      echo "        Please verify network access / registry reachability, or set tls_cert_mode=auto/internal."
      rm -f "$caddyfile"
      return 1
    fi
    caddy_image="$selected_image"
  fi

  # 优先复用配置镜像；若不可达，则尝试多个候选引用（docker.io 被限流/屏蔽时仍可部署）。
  local -a caddy_candidates=( "$caddy_image" "docker.io/library/caddy:2" "caddy:2" "ghcr.io/caddyserver/caddy:2" )
  local chosen_caddy=""
  local cimg=""
  for cimg in "${caddy_candidates[@]}"; do
    [[ -z "$cimg" ]] && continue
    if podman image exists "$cimg" >/dev/null 2>&1; then
      chosen_caddy="$cimg"
      echo "[INFO] 使用已缓存 Caddy 镜像: $chosen_caddy"
      break
    fi
    if timeout 90 podman pull "$cimg" >/dev/null 2>&1; then
      chosen_caddy="$cimg"
      echo "[INFO] 已拉取 Caddy 镜像: $chosen_caddy"
      break
    fi
    echo "[WARN] Caddy 镜像 $cimg 不可用（拉取失败或本地不存在），尝试下一个候选。"
  done
  if [[ -z "$chosen_caddy" ]]; then
    echo "[ERROR] 无法获取任何 Caddy 镜像（docker.io 可能不可达且本地无缓存）。"
    echo "[ERROR] 请检查 registry 可达性，或配置 podman 镜像加速器（如 docker.m.daocloud.io）后重试。"
    echo "[ERROR] 调试：尝试手动拉取 -> podman pull docker.io/library/caddy:2"
    rm -f "$caddyfile"
    return 1
  fi
  caddy_image="$chosen_caddy"

  if [[ -f "$TLS_DIR/Caddyfile" ]]; then
    cp -p "$TLS_DIR/Caddyfile" "$TLS_DIR/Caddyfile.rollback"
    rm -f "$TLS_DIR/Caddyfile.rollback.absent"
  else
    rm -f "$TLS_DIR/Caddyfile.rollback"
    : >"$TLS_DIR/Caddyfile.rollback.absent"
  fi
  mv -f "$caddyfile" "$TLS_DIR/Caddyfile"
  if ! stage_container_replacement "$TLS_CONTAINER_NAME" "TLS Proxy"; then
    restore_caddy_config
    return 1
  fi

  local -a podman_args=(
    --name "$TLS_CONTAINER_NAME"
    --restart=always
    --network host
    -v "$TLS_DIR/Caddyfile:/etc/caddy/Caddyfile:ro"
    -v "$TLS_DIR/data:/data"
    -v "$TLS_DIR/config:/config"
  )
  if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
    podman_args+=( -e "CLOUDFLARE_API_TOKEN=$cloudflare_api_token" )
  fi
  podman_args+=( "$caddy_image" )

  local tls_container_id=""
  if ! tls_container_id="$(podman_run_detached caddy "${podman_args[@]}" 2>&1)"; then
    echo "[ERROR] TLS Proxy 容器创建失败: ${tls_container_id}"
    echo "[ERROR] 调试：请手动运行上述等价命令查看完整报错，或执行 podman logs $TLS_CONTAINER_NAME 查看 Caddy 启动日志。"
    restore_caddy_config
    rollback_container_replacement "$TLS_CONTAINER_NAME" "TLS Proxy" || true
    return 1
  fi
  echo "$tls_container_id"

  local tls_running="false"
  local tls_attempt=""
  for tls_attempt in $(seq 1 30); do
    tls_running="$(podman container inspect --format '{{.State.Running}}' "$TLS_CONTAINER_NAME" 2>/dev/null || true)"
    if [[ "$tls_running" == "true" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "$tls_running" != "true" ]]; then
    echo "[ERROR] TLS Proxy 容器未能进入运行状态。"
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
    restore_caddy_config
    rollback_container_replacement "$TLS_CONTAINER_NAME" "TLS Proxy" || true
    return 1
  fi
  if ! podman exec "$TLS_CONTAINER_NAME" caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    echo "[WARN] TLS Proxy 配置校验未通过（若容器已在运行通常不影响实际服务）；日志如下："
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
  fi
  if ! wait_for_tls_http "$host"; then
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
    restore_caddy_config
    rollback_container_replacement "$TLS_CONTAINER_NAME" "TLS Proxy" || true
    return 1
  fi
  echo "[OK] TLS Proxy 容器已运行。"

  if [[ "$tls_cert_mode" == "internal" || "$host_is_ip" == "yes" ]]; then
    local generated_root="$TLS_DIR/data/caddy/pki/authorities/local/root.crt"
    local attempt=""
    for attempt in $(seq 1 30); do
      if [[ -s "$generated_root" ]]; then
        install -m 0644 "$generated_root" "$TLS_CA_EXPORT_DIR/root.crt.tmp"
        mv -f "$TLS_CA_EXPORT_DIR/root.crt.tmp" "$TLS_CA_EXPORT_DIR/root.crt"
        echo "[OK] Internal TLS CA exported for authenticated Client bootstrap."
        commit_container_replacement "$TLS_CONTAINER_NAME"
        commit_caddy_config
        return
      fi
      sleep 1
    done
    echo "[ERROR] Caddy internal CA was not generated within 30 seconds."
    podman logs --tail 100 "$TLS_CONTAINER_NAME" 2>&1 || true
    restore_caddy_config
    rollback_container_replacement "$TLS_CONTAINER_NAME" "TLS Proxy" || true
    return 1
  fi
  rm -f "$TLS_CA_EXPORT_DIR/root.crt"
  commit_container_replacement "$TLS_CONTAINER_NAME"
  commit_caddy_config
}

replace_kv_in_file() {
  local file="$1"
  local key="$2"
  local value="$3"
  local temp_file
  temp_file="$(mktemp "${file}.tmp.XXXXXX")"
  awk -v k="$key" -v v="$value" '
    BEGIN { replaced = 0 }
    {
      pos = index($0, "=")
      current_key = pos > 0 ? substr($0, 1, pos - 1) : ""
      if (current_key == k) {
        if (!replaced) print k "=" v
        replaced = 1
      } else {
        print
      }
    }
    END { if (!replaced) print k "=" v }
  ' "$file" >"$temp_file"
  chmod 0600 "$temp_file"
  mv -f "$temp_file" "$file"
}

reset_server_password() {
  if [[ ! -f "$SERVER_ENV_FILE" ]]; then
    echo "[ERROR] Server 尚未安装，找不到 $SERVER_ENV_FILE"
    exit 1
  fi
  local dashboard_username dashboard_password
  dashboard_username="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME || true)"
  dashboard_username="${dashboard_username:-$(generate_dashboard_username)}"
  dashboard_password="$(generate_dashboard_password)"
  replace_kv_in_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME "$dashboard_username"
  replace_kv_in_file "$SERVER_ENV_FILE" DASHBOARD_PASSWORD "$dashboard_password"
  echo "[INFO] 已生成新的 Server Dashboard 随机密码，正在重建 Server 容器使其生效..."
  bash "$ROOT_DIR/scripts/install-server.sh" update
}

print_https_guide() {
  cat <<'EOF_HTTPS_GUIDE'

===== HTTPS 配置指引 =====
三种方式都会由 Caddy 自动续期证书。域名使用公网 CA，IP 使用内部 CA。

方式 A：域名直连（ACME HTTP-01，最简单）
适用：你使用 Cloudflare 托管 DNS，但可将该记录设置为 DNS only（灰云）。
  1) 在 Cloudflare DNS 中新增 A/AAAA 记录（例如 monitor.example.com）指向服务器公网 IP。
  2) 将该记录设置为 DNS only（灰云），不要走 Cloudflare 代理。
  3) 服务器放通 80/443 端口。
  4) 脚本填写建议：
     - Enable HTTPS reverse proxy: yes
     - TLS host: monitor.example.com
     - TLS cert mode: auto
     - TLS email: 建议填写
  5) Client 端 SERVER_URL 使用：https://monitor.example.com

方式 B：Cloudflare DNS Challenge（可橙云）
适用：你希望保留 Cloudflare 代理（橙云）或不便开放 80 端口。
  1) 在 Cloudflare 创建 API Token，权限至少包含：
     - Zone:DNS:Edit
     - Zone:Zone:Read
  2) 脚本填写建议：
     - Enable HTTPS reverse proxy: yes
     - TLS host: monitor.example.com
     - TLS cert mode: cloudflare_dns
     - Cloudflare API token: 填入上一步 token
  3) 脚本会自动使用带 Cloudflare DNS 模块的 Caddy 镜像并注入 token。
  4) Client 端 SERVER_URL 使用：https://monitor.example.com

方式 C：直接使用 IP（内部 CA）
  1) TLS host 填写 Server 公网 IP，TLS cert mode 选择 auto 或 internal。
  2) Client 端 SERVER_URL 使用 https://SERVER_IP，不要追加随机 Backend Port。
  3) Client 安装器会通过共享密钥认证接口自动获取、验证并保存公开根证书。
  4) 不会传输 CA 私钥，也不会降级为跳过 TLS 验证。
==============================================

EOF_HTTPS_GUIDE
}

main() {
  ensure_root_and_deps
  configure_container_cgroup_args
  acquire_deploy_lock
  if [[ "$MODE" == "reset-password" ]]; then
    reset_server_password
    return
  fi
  local reset_data="no"
  if [[ "$RESET_DATA_ARG" == "--reset-data" ]] || is_truthy "${RESET_SERVER_DATA:-}"; then
    reset_data="yes"
  fi

  local default_image_source="github"
  local default_github_image="ghcr.io/$(detect_ghcr_owner)/podman-watcher-server:latest"
  local default_port="$(pick_random_port)"
  local default_secret="$(generate_secret)"
  local default_th="80"
  local default_tls_enable="yes"
  local default_tls_host="$(hostname -I | awk '{print $1}')"
  local default_tls_email=""
  local default_tls_cert_mode="auto"
  local default_cloudflare_api_token=""
  local default_alert_webhook_url=""
  local default_alert_webhook_min_severity="warning"
  local default_conn_warning_threshold="500"
  local default_conn_critical_threshold="1000"
  local default_connection_stop_threshold="1500"
  local default_connection_stop_duration_seconds="900"
  local default_connection_stop_max_gap_seconds="600"
  local default_offline_host_purge_seconds="86400"
  local default_dashboard_username
  local default_dashboard_password
  default_dashboard_username="$(generate_dashboard_username)"
  default_dashboard_password="$(generate_dashboard_password)"

  default_image_source="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" IMAGE_SOURCE "$default_image_source")"
  default_github_image="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" GITHUB_IMAGE "$default_github_image")"
  default_port="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" PORT "$default_port")"
  default_tls_enable="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_ENABLE "$default_tls_enable")"
  default_tls_host="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_HOST "$default_tls_host")"
  default_tls_email="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_EMAIL "$default_tls_email")"
  default_tls_cert_mode="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" TLS_CERT_MODE "$default_tls_cert_mode")"
  default_cloudflare_api_token="$(load_non_empty_or_default "$SERVER_INSTALL_ENV_FILE" CLOUDFLARE_API_TOKEN "$default_cloudflare_api_token")"

  local env_secret env_th env_alert_webhook_url env_alert_webhook_min_severity env_dashboard_username env_dashboard_password
  local env_conn_warning_threshold env_conn_critical_threshold env_connection_stop_threshold env_connection_stop_duration_seconds env_connection_stop_max_gap_seconds env_offline_host_purge_seconds
  env_secret="$(load_kv_from_file "$SERVER_ENV_FILE" SHARED_SECRET || true)"
  env_th="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_DISK_THRESHOLD_PERCENT || true)"
  env_alert_webhook_url="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_URL || true)"
  env_alert_webhook_min_severity="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_WEBHOOK_MIN_SEVERITY || true)"
  env_dashboard_username="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_USERNAME || true)"
  env_dashboard_password="$(load_kv_from_file "$SERVER_ENV_FILE" DASHBOARD_PASSWORD || true)"
  env_conn_warning_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_CONN_WARNING_THRESHOLD || true)"
  env_conn_critical_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" ALERT_CONN_CRITICAL_THRESHOLD || true)"
  env_connection_stop_threshold="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_THRESHOLD || true)"
  env_connection_stop_duration_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_DURATION_SECONDS || true)"
  env_connection_stop_max_gap_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" CONNECTION_STOP_MAX_GAP_SECONDS || true)"
  env_offline_host_purge_seconds="$(load_kv_from_file "$SERVER_ENV_FILE" OFFLINE_HOST_PURGE_SECONDS || true)"
  default_secret="${env_secret:-$default_secret}"
  default_th="${env_th:-$default_th}"
  default_alert_webhook_url="${env_alert_webhook_url:-$default_alert_webhook_url}"
  default_alert_webhook_min_severity="${env_alert_webhook_min_severity:-$default_alert_webhook_min_severity}"
  default_dashboard_username="${env_dashboard_username:-$default_dashboard_username}"
  default_dashboard_password="${env_dashboard_password:-$default_dashboard_password}"
  default_conn_warning_threshold="${env_conn_warning_threshold:-$default_conn_warning_threshold}"
  default_conn_critical_threshold="${env_conn_critical_threshold:-$default_conn_critical_threshold}"
  default_connection_stop_threshold="${env_connection_stop_threshold:-$default_connection_stop_threshold}"
  default_connection_stop_duration_seconds="${env_connection_stop_duration_seconds:-$default_connection_stop_duration_seconds}"
  default_connection_stop_max_gap_seconds="${env_connection_stop_max_gap_seconds:-$default_connection_stop_max_gap_seconds}"
  default_offline_host_purge_seconds="${env_offline_host_purge_seconds:-$default_offline_host_purge_seconds}"

  local image_source github_image port secret th tls_enable tls_host tls_email tls_cert_mode cloudflare_api_token caddy_image alert_webhook_url alert_webhook_min_severity

  image_source="$(ask_choice_with_default "请选择 Server 镜像来源" "$default_image_source" \
    "github|GitHub Container Registry（推荐）" \
    "local|本机源码构建")"
  image_source=$(echo "$image_source" | tr '[:upper:]' '[:lower:]')
  github_image="$(ask_with_default "GitHub image (for github source)" "$default_github_image")"
  port="$(ask_with_default "Server listen port" "$default_port")"
  port="$(sanitize_server_port "$port")"
  secret="$(ask_with_default "Shared secret (for client auth)" "$default_secret")"
  th="$(ask_with_default "Disk alert threshold percent" "$default_th")"
  if [[ "$MODE" == "update" ]]; then
    alert_webhook_url="$default_alert_webhook_url"
    alert_webhook_min_severity="$default_alert_webhook_min_severity"
  else
    alert_webhook_url="$(ask_with_default "Security alert webhook URL (empty to disable)" "$default_alert_webhook_url")"
    alert_webhook_min_severity="$(ask_choice_with_default "请选择 Webhook 最低告警级别" "$default_alert_webhook_min_severity" \
      "warning|warning 及以上" \
      "critical|仅 critical")"
  fi
  tls_enable="$(ask_choice_with_default "是否启用 HTTPS 反向代理" "$default_tls_enable" \
    "yes|启用（推荐）" \
    "no|不启用")"
  tls_enable=$(echo "$tls_enable" | tr '[:upper:]' '[:lower:]')

  if [[ "$tls_enable" == "yes" ]]; then
    print_https_guide
    tls_host="$(ask_with_default "TLS host (domain or IP)" "$default_tls_host")"
    tls_email="$(ask_with_default "TLS email (domain cert optional)" "$default_tls_email")"
    tls_cert_mode="$(ask_choice_with_default "请选择 TLS 证书模式" "$default_tls_cert_mode" \
      "auto|自动：域名使用公网 CA，IP 自动切换内部 CA" \
      "internal|内部 CA：适合直接使用 IP" \
      "cloudflare_dns|Cloudflare DNS Challenge")"
    tls_cert_mode=$(echo "$tls_cert_mode" | tr '[:upper:]' '[:lower:]')
    case "$tls_cert_mode" in
      auto|internal|cloudflare_dns) ;;
      *)
        echo "[WARN] Unknown TLS cert mode '$tls_cert_mode', fallback to auto."
        tls_cert_mode="auto"
        ;;
    esac

    if [[ "$tls_cert_mode" == "auto" ]]; then
      if [[ "$tls_host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$tls_host" =~ : ]]; then
        echo "[INFO] TLS host 看起来是 IP，auto 将自动切换为 internal（自签证书）。"
        tls_cert_mode="internal"
      fi
    elif [[ "$tls_cert_mode" == "internal" ]]; then
      true
    fi

    if [[ "$tls_cert_mode" == "cloudflare_dns" ]]; then
      cloudflare_api_token="$(ask_with_default "Cloudflare API token (Zone DNS Edit)" "$default_cloudflare_api_token")"
      caddy_image="ghcr.io/caddy-dns/cloudflare:latest"
    else
      cloudflare_api_token=""
      caddy_image="docker.io/library/caddy:2"
    fi
  else
    tls_host=""
    tls_email=""
    tls_cert_mode=""
    cloudflare_api_token=""
    caddy_image=""
  fi

  mkdir -p "$SERVER_DATA_DIR" "$TLS_CA_EXPORT_DIR"
  cat >"$SERVER_ENV_FILE" <<ENV
NARWHAL_VERSION=$PROJECT_VERSION
SHARED_SECRET=$secret
ALERT_DISK_THRESHOLD_PERCENT=$th
ALERT_CONN_WARNING_THRESHOLD=$default_conn_warning_threshold
ALERT_CONN_CRITICAL_THRESHOLD=$default_conn_critical_threshold
CONNECTION_STOP_THRESHOLD=$default_connection_stop_threshold
CONNECTION_STOP_DURATION_SECONDS=$default_connection_stop_duration_seconds
CONNECTION_STOP_MAX_GAP_SECONDS=$default_connection_stop_max_gap_seconds
OFFLINE_HOST_PURGE_SECONDS=$default_offline_host_purge_seconds
ALERT_WEBHOOK_URL=$alert_webhook_url
ALERT_WEBHOOK_MIN_SEVERITY=$alert_webhook_min_severity
DB_PATH=/data/monitor.db
TLS_CA_CERT_PATH=/tls-ca/root.crt
DASHBOARD_USERNAME=$default_dashboard_username
DASHBOARD_PASSWORD=$default_dashboard_password
ENV

  cat >"$SERVER_INSTALL_ENV_FILE" <<ENV
IMAGE_SOURCE=$image_source
GITHUB_IMAGE=$github_image
PORT=$port
TLS_ENABLE=$tls_enable
TLS_HOST=$tls_host
TLS_EMAIL=$tls_email
TLS_CERT_MODE=$tls_cert_mode
CLOUDFLARE_API_TOKEN=$cloudflare_api_token
ENV
  chmod 0600 "$SERVER_ENV_FILE" "$SERVER_INSTALL_ENV_FILE"

  if [[ "$reset_data" == "yes" ]]; then
    echo "[INFO] 检测到 reset-data，请求清空历史采集数据（初始化数据库）..."
    wipe_server_data
  fi

  local image_name="narwhal-monitor-server:latest"
  case "$image_source" in
    local)
      podman build --build-arg "APP_VERSION=$PROJECT_VERSION" -t "$image_name" -f server/Dockerfile server
      ;;
    github)
      echo "Trying to pull $github_image..."
      if podman pull "$github_image"; then
        image_name="$github_image"
      else
        echo "[WARN] Pull github image failed. Falling back to local build (this avoids GHCR 403/private image issues)."
        podman build --build-arg "APP_VERSION=$PROJECT_VERSION" -t "$image_name" -f server/Dockerfile server
      fi
      ;;
    *)
      echo "Unsupported image source: $image_source"
      echo "Please choose 'local' or 'github'."
      exit 1
      ;;
  esac

  local port_binding="${port}:8080"
  if [[ "$tls_enable" == "yes" ]]; then
    port_binding="127.0.0.1:${port}:8080"
  fi

  # 创建专用网络并规避与宿主机已有私网（如 10.88.0.0/16）的冲突。
  ensure_narwhal_network

  # 镜像版本必须与安装脚本一致；校验发生在删除当前 Server 之前。
  verify_server_image_version "$image_name"

  # Keep the current Server available until the replacement image is ready, then
  # perform one serialized, verified and idempotent container replacement.
  replace_server_container "$image_name" "$port_binding" "$NARWHAL_NETWORK_NAME"
  local resolved_port_changed="no"
  if [[ "$RESOLVED_SERVER_PORT" != "$port" ]]; then
    port="$RESOLVED_SERVER_PORT"
    port_binding="$RESOLVED_SERVER_BINDING"
    resolved_port_changed="yes"
  fi

  if ! setup_tls_proxy "$tls_host" "$port" "$tls_enable" "$tls_email" "$tls_cert_mode" "$cloudflare_api_token" "$caddy_image"; then
    rollback_container_replacement "$CONTAINER_NAME" "Server" || true
    echo "[ERROR] TLS Proxy 部署失败，Server 已回滚到上一版本。"
    exit 1
  fi
  if [[ "$resolved_port_changed" == "yes" ]]; then
    replace_kv_in_file "$SERVER_INSTALL_ENV_FILE" PORT "$port"
  fi
  commit_container_replacement "$CONTAINER_NAME"
  bash "$ROOT_DIR/scripts/setup-auto-update.sh" server "$ROOT_DIR"

  if [[ "$tls_enable" == "yes" ]]; then
    echo "Server started: https://${tls_host}"
  else
    echo "Server started: http://$(hostname -I | awk '{print $1}'):${port}"
  fi

  cat <<EOF_SUM

===== Server Install Summary =====
Mode: $MODE
Version: $PROJECT_VERSION
Container Name: $CONTAINER_NAME
Backend Port: $port
Backend Binding: $port_binding
Shared Secret: $(if [[ "$MODE" == "install" && "${NARWHAL_AUTO_UPDATE:-0}" != "1" ]]; then echo "$secret"; else echo "preserved (see $SERVER_ENV_FILE)"; fi)
Dashboard Username: $(if [[ "${NARWHAL_AUTO_UPDATE:-0}" == "1" ]]; then echo "preserved (see $SERVER_ENV_FILE)"; else echo "$default_dashboard_username"; fi)
Dashboard Password: $(if [[ "${NARWHAL_AUTO_UPDATE:-0}" == "1" ]]; then echo "preserved (see $SERVER_ENV_FILE)"; else echo "$default_dashboard_password"; fi)
Security Webhook: ${alert_webhook_url:-disabled}
Webhook Minimum Severity: $alert_webhook_min_severity
Disk Alert Threshold: $th%
Image Source: $image_source
Env File: $SERVER_ENV_FILE
Install Config: $SERVER_INSTALL_ENV_FILE
Data Dir: $SERVER_DATA_DIR
Data Reset: $reset_data
Container Image: $image_name
HTTPS Enabled: $tls_enable
HTTPS Host: ${tls_host:-N/A}
TLS Proxy Container: $TLS_CONTAINER_NAME
TLS Cert Mode: ${tls_cert_mode:-N/A}
Client Server URL: $(if [[ "$tls_enable" == "yes" ]]; then echo "https://${tls_host}"; else echo "http://$(hostname -I | awk '{print $1}'):${port}"; fi)
TLS CA Bootstrap: $(if [[ "$tls_cert_mode" == "internal" ]]; then echo "HMAC-authenticated /api/v1/tls/ca"; else echo "system/public trust"; fi)
Caddy Image: ${caddy_image:-N/A}
Automatic Updates: enabled (origin/main every 15 minutes)
==================================
EOF_SUM
}

main "$@"
