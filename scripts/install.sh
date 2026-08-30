#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_BASE_DIR="/opt/narwhal-monitor"
UNINSTALL_IMAGES_TO_REMOVE=()
# shellcheck source=scripts/lib/interactive.sh
source "$ROOT_DIR/scripts/lib/interactive.sh"

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "[ERROR] 请使用 root 运行：sudo bash scripts/install.sh"
    exit 1
  fi
}

ensure_cmd() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[INFO] 安装依赖: $pkg"
    apt-get update
    apt-get install -y "$pkg"
  fi
}

install_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] 仅支持 Debian/Ubuntu (apt-get) 自动安装依赖，请手动安装 git/curl 和所需容器运行时后重试。"
    exit 1
  fi

  ensure_cmd git git
  ensure_cmd curl curl
}

update_repo_self() {
  if [[ ! -d "$ROOT_DIR/.git" ]]; then
    echo "[WARN] 当前目录不是 git 仓库，跳过脚本自更新。"
    return
  fi

  # 不自动丢弃运维人员的本地修改；明确报错并要求人工审查。
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=no)" ]]; then
    echo "[ERROR] 检测到仓库存在已跟踪的本地改动，拒绝自动覆盖。"
    echo "[INFO] 请先执行 git -C '$ROOT_DIR' status 并人工提交、暂存或还原后重试。"
    exit 1
  fi

  echo "[INFO] 更新安装脚本与仓库代码（git pull --ff-only）..."
  git -C "$ROOT_DIR" fetch --all --prune
  git -C "$ROOT_DIR" pull --ff-only
}

cleanup_after_update() {
  if [[ "${SKIP_CLEANUP_ON_UPDATE:-0}" == "1" ]]; then
    echo "[INFO] 检测到 SKIP_CLEANUP_ON_UPDATE=1，跳过更新后清理。"
    return
  fi

  echo "[INFO] 更新完成，开始清理无用文件与旧镜像..."

  if command -v podman >/dev/null 2>&1; then
    podman container prune -f >/dev/null 2>&1 || true
    podman image prune -af >/dev/null 2>&1 || true
    podman volume prune -f >/dev/null 2>&1 || true
    podman network prune -f >/dev/null 2>&1 || true
    echo "[INFO] Podman 无用资源清理完成。"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true
    echo "[INFO] apt 缓存与无用依赖清理完成。"
  fi
}

run_installer() {
  local target="$1"
  local mode="$2"
  local reset_server_data="${3:-no}"
  local -a server_extra_args=()
  if [[ "$reset_server_data" == "yes" ]]; then
    server_extra_args+=(--reset-data)
  fi
  case "$target" in
    server)
      bash "$ROOT_DIR/scripts/install-server.sh" "$mode" "${server_extra_args[@]}"
      ;;
    client)
      bash "$ROOT_DIR/scripts/install-client.sh" "$mode"
      ;;
    both)
      echo "[INFO] 先处理 Server，再处理 Client。"
      bash "$ROOT_DIR/scripts/install-server.sh" "$mode" "${server_extra_args[@]}"
      # The Client installer reads the just-created local Server config when
      # this marker is present. This keeps both installs on one shared URL and
      # secret without exposing the secret in argv or the process environment.
      NARWHAL_INSTALL_BOTH=1 bash "$ROOT_DIR/scripts/install-client.sh" "$mode"
      ;;
    *)
      echo "[ERROR] 不支持的安装目标: $target"
      exit 1
      ;;
  esac
}

remove_container_if_exists() {
  local name="$1"
  if podman container exists "$name" >/dev/null 2>&1; then
    echo "[INFO] 删除容器: $name"
    podman rm -f "$name" >/dev/null 2>&1 || true
  fi
}

remove_systemd_service_if_exists() {
  local service_name="$1"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | awk '{print $1}' | grep -Fxq "$service_name"; then
      echo "[INFO] 停止并禁用 systemd 服务: $service_name"
      systemctl disable --now "$service_name" >/dev/null 2>&1 || true
    fi
  fi
}

remove_image_if_exists() {
  local image="$1"
  if podman image exists "$image" >/dev/null 2>&1; then
    echo "[INFO] 删除镜像: $image"
    podman rmi -f "$image" >/dev/null 2>&1 || true
  fi
}

detect_ghcr_owner() {
  local owner="narwhal-cloud"
  if command -v git >/dev/null 2>&1; then
    local remote_url=""
    remote_url="$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || true)"
    if [[ -n "$remote_url" && "$remote_url" =~ github\.com[:/]([^/]+)/[^/]+(\.git)?$ ]]; then
      owner="${BASH_REMATCH[1]}"
    fi
  fi
  echo "$owner"
}

append_unique_image() {
  local image="$1"
  [[ -n "$image" ]] || return 0
  case "$image" in
    IMAGE_SOURCE=*|GITHUB_IMAGE=*|PORT=*|TLS_ENABLE=*|TLS_HOST=*|TLS_EMAIL=*|TLS_CERT_MODE=*|CLOUDFLARE_API_TOKEN=*|*=*)
      return 0
      ;;
  esac

  local existing=""
  for existing in "${UNINSTALL_IMAGES_TO_REMOVE[@]-}"; do
    if [[ "$existing" == "$image" ]]; then
      return 0
    fi
  done
  UNINSTALL_IMAGES_TO_REMOVE+=("$image")
}

collect_images_from_saved_configs() {
  local client_install_env="$INSTALL_BASE_DIR/client-install.env"
  local server_install_env="$INSTALL_BASE_DIR/server-install.env"

  if [[ -f "$client_install_env" ]]; then
    local client_image=""
    client_image="$(awk -F= '$1=="GITHUB_IMAGE"{print substr($0, index($0, "=") + 1); exit}' "$client_install_env" 2>/dev/null || true)"
    append_unique_image "$client_image"
  fi

  if [[ -f "$server_install_env" ]]; then
    local server_image=""
    server_image="$(awk -F= '$1=="GITHUB_IMAGE"{print substr($0, index($0, "=") + 1); exit}' "$server_install_env" 2>/dev/null || true)"
    append_unique_image "$server_image"
  fi
}

remove_images_by_repository_pattern() {
  local pattern="$1"
  [[ -n "$pattern" ]] || return 0

  local image_id=""
  while IFS= read -r image_id; do
    [[ -z "$image_id" ]] && continue
    echo "[INFO] 删除镜像ID: $image_id (匹配: $pattern)"
    podman rmi -f "$image_id" >/dev/null 2>&1 || true
  done < <(podman images --format '{{.ID}} {{.Repository}}:{{.Tag}}' | awk -v p="$pattern" '$2 ~ p {print $1}')
}

uninstall_narwhal_related() {
  echo "[INFO] 开始卸载 Narwhal-Cloud-podman-watcher 相关 Podman 资源..."
  echo "[INFO] 仅清理本项目相关资源，不会删除其他已有 Podman 容器。"

  if command -v podman >/dev/null 2>&1; then
    local owner=""
    owner="$(detect_ghcr_owner)"

    remove_container_if_exists "narwhal-monitor-client"
    remove_container_if_exists "narwhal-monitor-server"
    remove_container_if_exists "narwhal-monitor-caddy"

    # 清理 Server 专用网络（忽略不存在/被其它容器占用的情况）。
    podman network rm -f "narwhal-monitor-net" >/dev/null 2>&1 || true

    UNINSTALL_IMAGES_TO_REMOVE=(
      "narwhal-monitor-server:latest"
      "ghcr.io/narwhal-cloud/podman-watcher-server:latest"
      "ghcr.io/${owner}/podman-watcher-server:latest"
      "docker.io/library/caddy:2"
      "ghcr.io/caddy-dns/cloudflare:latest"
      "ghcr.io/caddy-dns/cloudflare:2"
    )

    collect_images_from_saved_configs

    local image=""
    for image in "${UNINSTALL_IMAGES_TO_REMOVE[@]}"; do
      remove_image_if_exists "$image"
    done

    # 清理同仓库下可能存在的非 latest 标签镜像（例如手动指定了版本标签）。
    remove_images_by_repository_pattern '^ghcr[.]io/(narwhal-cloud|'"$owner"')/podman-watcher-server$'
    remove_images_by_repository_pattern '^ghcr[.]io/caddy-dns/cloudflare$'
  else
    echo "[WARN] 未检测到 podman，跳过容器/镜像删除，仅清理本项目配置目录。"
  fi

  remove_systemd_service_if_exists "narwhal-monitor-client.service"
  remove_systemd_service_if_exists "narwhal-monitor-client-update.timer"
  remove_systemd_service_if_exists "narwhal-monitor-server-update.timer"
  remove_systemd_service_if_exists "narwhal-monitor-client-update.service"
  remove_systemd_service_if_exists "narwhal-monitor-server-update.service"
  if [[ -f "/etc/systemd/system/narwhal-monitor-client.service" ]]; then
    echo "[INFO] 删除 systemd 服务文件: /etc/systemd/system/narwhal-monitor-client.service"
    rm -f /etc/systemd/system/narwhal-monitor-client.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f \
    /etc/systemd/system/narwhal-monitor-client-update.timer \
    /etc/systemd/system/narwhal-monitor-server-update.timer \
    /etc/systemd/system/narwhal-monitor-client-update.service \
    /etc/systemd/system/narwhal-monitor-server-update.service
  systemctl daemon-reload >/dev/null 2>&1 || true

  if [[ -d "$INSTALL_BASE_DIR" ]]; then
    echo "[INFO] 删除配置与数据目录: $INSTALL_BASE_DIR"
    rm -rf "$INSTALL_BASE_DIR"
  fi

  echo "[OK] 卸载完成：Narwhal-Cloud-podman-watcher 相关资源已清理。"
}

main() {
  require_root

  echo "=== Narwhal Monitor 一键安装/更新器 ==="
  echo "该脚本会自动补齐依赖，并启动交互式安装或无感更新。"

  local action
  local reset_server_data="no"
  action="$(narwhal_choose "请选择操作" "install" \
    "install|安装" \
    "update|更新" \
    "diagnose-server|诊断 Server（只读）" \
    "reset-server-password|重置 Server 登录密码" \
    "uninstall|卸载")"

  case "$action" in
    install)
      install_deps
      local mode
      mode="$(narwhal_choose "请选择安装目标" "client" \
        "client|Client" \
        "server|Server" \
        "both|Server 和 Client")"
      if [[ "$mode" == "server" || "$mode" == "both" ]]; then
        local reset_confirm=""
        reset_confirm="$(narwhal_choose "是否删除 Server 已有全部采集数据（初始化数据库）" "no" \
          "no|否，保留现有数据库（推荐）" \
          "yes|是，永久清空全部采集数据")"
        if [[ "$reset_confirm" == "yes" ]]; then
          reset_server_data="yes"
        fi
      fi
      run_installer "$mode" install "$reset_server_data"
      ;;
    update)
      install_deps
      local mode
      mode="$(narwhal_choose "请选择更新目标" "client" \
        "client|Client" \
        "server|Server" \
        "both|Server 和 Client")"
      if [[ "$mode" == "server" || "$mode" == "both" ]]; then
        local reset_confirm=""
        reset_confirm="$(narwhal_choose "是否删除 Server 已有全部采集数据（初始化数据库）" "no" \
          "no|否，保留现有数据库（推荐）" \
          "yes|是，永久清空全部采集数据")"
        if [[ "$reset_confirm" == "yes" ]]; then
          reset_server_data="yes"
        fi
      fi
      update_repo_self
      run_installer "$mode" update "$reset_server_data"
      cleanup_after_update
      ;;
    reset-server-password|reset-password)
      install_deps
      bash "$ROOT_DIR/scripts/install-server.sh" reset-password
      ;;
    diagnose-server|diagnose)
      bash "$ROOT_DIR/scripts/diagnose-server.sh"
      ;;
    uninstall)
      uninstall_narwhal_related
      ;;
    *)
      echo "[ERROR] 不支持的操作: $action"
      exit 1
      ;;
  esac

  echo "[OK] $action 流程执行完成。"
}

main "$@"
