#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
CLIENT_ENV_FILE="/opt/narwhal-monitor/client.env"
CLIENT_INSTALL_ENV_FILE="/opt/narwhal-monitor/client-install.env"
CLIENT_APP_DIR="/opt/narwhal-monitor/client-agent"
CLIENT_VENV_DIR="$CLIENT_APP_DIR/.venv"
CLIENT_CA_FILE="/opt/narwhal-monitor/server-ca.crt"
LOCAL_SERVER_ENV_FILE="/opt/narwhal-monitor/server.env"
LOCAL_SERVER_INSTALL_ENV_FILE="/opt/narwhal-monitor/server-install.env"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/narwhal-monitor-client.service"
MODE="${1:-install}"
# shellcheck source=scripts/lib/interactive.sh
source "$ROOT_DIR/scripts/lib/interactive.sh"

if [[ "$MODE" != "install" && "$MODE" != "update" ]]; then
  echo "[ERROR] 用法: bash scripts/install-client.sh [install|update]"
  exit 1
fi

generate_secret() {
  tr -d '-' </proc/sys/kernel/random/uuid | cut -c 1-25
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

is_truthy() {
  local value="${1:-}"
  value="$(echo "$value" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "y" ]]
}

derive_local_server_url() {
  local tls_enable tls_host port
  tls_enable="$(load_kv_from_file "$LOCAL_SERVER_INSTALL_ENV_FILE" TLS_ENABLE || true)"
  tls_host="$(load_kv_from_file "$LOCAL_SERVER_INSTALL_ENV_FILE" TLS_HOST || true)"
  port="$(load_kv_from_file "$LOCAL_SERVER_INSTALL_ENV_FILE" PORT || true)"
  if is_truthy "$tls_enable" && [[ -n "$tls_host" ]]; then
    printf 'https://%s\n' "$tls_host"
  elif [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 )); then
    printf 'http://127.0.0.1:%s\n' "$port"
  fi
}

runtime_selection_includes_incus() {
  local value
  value="$(printf '%s' "${1:-auto}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ -z "$value" || ",$value," == *,auto,* || ",$value," == *,incus,* ]]
}

check_incus_visibility() {
  local runtimes_value="$1"
  local project_value="$2"
  project_value="$(printf '%s' "$project_value" | tr '[:upper:]' '[:lower:]')"
  runtime_selection_includes_incus "$runtimes_value" || return 0

  if ! command -v incus >/dev/null 2>&1; then
    if [[ "$(printf '%s' "$runtimes_value" | tr '[:upper:]' '[:lower:]')" == *incus* ]]; then
      echo "[WARN] 已显式启用 Incus，但宿主机 PATH 中没有 incus 命令。"
    else
      echo "[INFO] 未检测到 Incus CLI，跳过 Incus 可见性检查。"
    fi
    return 0
  fi

  local -a list_cmd=(incus list type=container status=running --format=csv -c n)
  if [[ "$project_value" == "all" || "$project_value" == "*" || -z "$project_value" ]]; then
    list_cmd=(incus list --all-projects type=container status=running --format=csv -c n)
  else
    list_cmd=(incus --project "$project_value" list type=container status=running --format=csv -c n)
  fi

  local output=""
  if ! output="$(timeout 30s "${list_cmd[@]}" 2>&1)"; then
    echo "[WARN] Incus 可见性检查失败，Client 可能无法采集 Incus 容器。"
    echo "[WARN] 请确认 root 可执行: ${list_cmd[*]}"
    echo "[WARN] Incus 返回: $(printf '%s' "$output" | head -n 1)"
    return 0
  fi

  local visible_count=0
  visible_count="$(printf '%s\n' "$output" | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]')"
  if (( visible_count > 0 )); then
    echo "[OK] Incus 可见性检查通过：项目范围 ${project_value:-all}，运行中容器 $visible_count 个。"
    return 0
  fi

  if [[ "$project_value" != "all" && "$project_value" != "*" && -n "$project_value" ]]; then
    local all_output="" all_count=0
    all_output="$(timeout 30s incus list --all-projects type=container status=running --format=csv -c n 2>/dev/null || true)"
    all_count="$(printf '%s\n' "$all_output" | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]')"
    if (( all_count > 0 )); then
      echo "[WARN] Incus 项目 '$project_value' 没有运行中容器，但其他项目共有 $all_count 个。"
      echo "[WARN] 将 $CLIENT_ENV_FILE 中 INCUS_PROJECT 改为 all 后重启 Client，可采集全部项目。"
      return 0
    fi
  fi
  echo "[INFO] Incus CLI 可访问，但当前项目范围没有运行中的容器。"
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/install-client.sh ${MODE}"
  exit 1
fi

if ! command -v podman >/dev/null 2>&1 \
  && ! command -v podman-remote >/dev/null 2>&1 \
  && ! command -v docker >/dev/null 2>&1 \
  && ! command -v incus >/dev/null 2>&1; then
  echo "No supported runtime found; installing podman as the default runtime..."
  apt-get update
  apt-get install -y podman
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Installing python3..."
  apt-get update
  apt-get install -y python3 python3-venv
fi

if ! python3 -m venv -h >/dev/null 2>&1; then
  echo "Installing python3-venv..."
  apt-get update
  apt-get install -y python3-venv
fi

ensure_python_venv_ready() {
  local tmp_venv
  tmp_venv="$(mktemp -d /tmp/narwhal-venv-check-XXXXXX)"

  if python3 -m venv "$tmp_venv" >/dev/null 2>&1; then
    rm -rf "$tmp_venv"
    return 0
  fi

  rm -rf "$tmp_venv"
  local py_minor
  py_minor="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

  echo "Detected missing ensurepip for python${py_minor}, installing venv packages..."
  apt-get update
  apt-get install -y "python${py_minor}-venv" python3-venv
}

ensure_python_venv_ready

ensure_client_venv() {
  if [[ -d "$CLIENT_VENV_DIR" && -x "$CLIENT_VENV_DIR/bin/python" && -x "$CLIENT_VENV_DIR/bin/pip" ]]; then
    return 0
  fi

  if [[ -d "$CLIENT_VENV_DIR" ]]; then
    echo "Existing virtualenv is incomplete, recreating: $CLIENT_VENV_DIR"
    rm -rf "$CLIENT_VENV_DIR"
  fi

  python3 -m venv "$CLIENT_VENV_DIR"
}

both_server_url=""
both_server_secret=""
if is_truthy "${NARWHAL_INSTALL_BOTH:-0}"; then
  both_server_url="$(derive_local_server_url)"
  both_server_secret="$(load_kv_from_file "$LOCAL_SERVER_ENV_FILE" SHARED_SECRET || true)"
  if [[ -z "$both_server_url" || -z "$both_server_secret" ]]; then
    echo "[ERROR] both 安装未能读取本机 Server URL 或共享密钥，拒绝生成无法上报的 Client 配置。"
    exit 1
  fi
  echo "[INFO] both 安装已自动复用本机 Server URL 与共享密钥。"
fi
default_server_url="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SERVER_URL "${both_server_url:-http://127.0.0.1:8080}")"
default_secret="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SHARED_SECRET "${both_server_secret:-$(generate_secret)}")"
default_tls_ca_file="$(load_kv_from_file "$CLIENT_ENV_FILE" SERVER_TLS_CA_FILE || true)"
default_host_id="$(load_non_empty_or_default "$CLIENT_ENV_FILE" HOST_ID "$(hostname)")"
default_interval="$(load_non_empty_or_default "$CLIENT_ENV_FILE" REPORT_INTERVAL "300")"
default_action_poll_interval="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ACTION_POLL_INTERVAL "10")"
runtime_command_timeout="$(load_non_empty_or_default "$CLIENT_ENV_FILE" RUNTIME_COMMAND_TIMEOUT_SECONDS "30")"
default_runtimes="$(load_non_empty_or_default "$CLIENT_ENV_FILE" CONTAINER_RUNTIMES "auto")"
default_docker_monitor_mode="$(load_non_empty_or_default "$CLIENT_ENV_FILE" DOCKER_MONITOR_MODE "notice")"
default_monitored_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" MONITORED_IMAGE_PATTERNS "*")"
default_monitored_incus_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" MONITORED_INCUS_PATTERNS "*")"
default_incus_project="$(load_non_empty_or_default "$CLIENT_ENV_FILE" INCUS_PROJECT "all")"
default_security_enabled="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_MONITOR_ENABLED "true")"
default_access_log_paths="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_ACCESS_LOG_PATHS "/var/log/nginx/access.log,/var/log/caddy/access.log")"
default_container_access_log_paths="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_CONTAINER_ACCESS_LOG_PATHS "/var/log/nginx/access.log,/var/log/caddy/access.log")"
ddos_rx_bps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_DDOS_RX_BPS "100000000")"
ddos_rx_pps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_DDOS_RX_PPS "50000")"
ddos_syn_recv="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_DDOS_SYN_RECV "200")"
conn_warning_threshold="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CONN_WARNING_THRESHOLD "500")"
conn_critical_threshold="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CONN_CRITICAL_THRESHOLD "1000")"
inbound_unique_ips="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_INBOUND_UNIQUE_IPS "10")"
cc_total_rps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CC_TOTAL_RPS "100")"
cc_ip_rps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CC_IP_RPS "30")"
cc_4xx_rate="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CC_4XX_RATE "0.5")"
cc_min_requests="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_CC_MIN_REQUESTS "50")"
scan_unique_ports="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_SCAN_UNIQUE_PORTS "20")"
abuse_unique_ips="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_OUTBOUND_UNIQUE_IPS "200")"
abuse_suspicious="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_SUSPICIOUS_CONNECTIONS "20")"
abuse_tx_bps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_TX_BPS "100000000")"
abuse_tx_pps="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_TX_PPS "50000")"
abuse_tcp_opens="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_TCP_OPENS_PER_SEC "200")"
abuse_tcp_fails="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_TCP_FAILS_PER_SEC "50")"
abuse_udp_out="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_UDP_OUT_PER_SEC "10000")"
abuse_process_count="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_ABUSE_PROCESS_COUNT "500")"
config_audit_enabled="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_CONFIG_AUDIT_ENABLED "true")"
suspicious_ports="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_SUSPICIOUS_OUTBOUND_PORTS "25,465,587,23,445,6667")"
access_log_max_bytes="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_ACCESS_LOG_MAX_BYTES "1048576")"
socket_snapshot_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_SOCKET_SNAPSHOT_MAX "500")"
communication_detail_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_COMMUNICATION_DETAIL_MAX "100")"
conntrack_snapshot_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_CONNTRACK_SNAPSHOT_MAX "5000")"
host_proxy_socket_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_HOST_PROXY_SOCKET_MAX "5000")"
panel_env_scan_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_ENV_SCAN_MAX_PROCESSES "32")"
panel_env_max_bytes="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_ENV_MAX_BYTES "16384")"
geoip_mmdb_path="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_MMDB_PATH "/usr/share/GeoIP/GeoLite2-Country.mmdb")"
geoip_https_enabled="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_HTTPS_ENABLED "true")"
geoip_https_endpoint="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_HTTPS_ENDPOINT "https://api.country.is/")"
geoip_cache_max="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_CACHE_MAX_ENTRIES "4096")"
geoip_cache_ttl="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_CACHE_TTL_SECONDS "86400")"
geoip_negative_cache_ttl="$(load_non_empty_or_default "$CLIENT_ENV_FILE" GEOIP_NEGATIVE_CACHE_TTL_SECONDS "900")"
web_scan_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_WEB_SCAN_PATTERNS ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1")"
web_scan_requests="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_WEB_SCAN_REQUESTS "10")"
auth_failures_per_ip="$(load_non_empty_or_default "$CLIENT_ENV_FILE" ALERT_AUTH_FAILURES_PER_IP "20")"
suspicious_process_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_SUSPICIOUS_PROCESS_PATTERNS "xmrig,kinsing,kdevtmpfsi,watchbog,cryptonight,minerd,pwnrig,teamtnt,stratum+tcp,stratum+ssl,/dev/tcp/,nc -e,ncat -e,socat exec:,mkfifo /tmp")"
auto_remediate_xmrig="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_AUTO_REMEDIATE_XMRIG "true")"
auto_remediate_xrayr="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_AUTO_REMEDIATE_XRAYR "true")"
panel_detection_enabled="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_PAIRING_DETECTION_ENABLED "true")"
default_allowed_panel_domains="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_ALLOWED_PANEL_DOMAINS "")"
panel_process_patterns="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_PROCESS_PATTERNS "xboard-node,xrayr,v2bx,soga,sspanel-uim-node")"
panel_config_paths="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_CONFIG_PATHS "/etc/XrayR/config.yml,/etc/V2bX/config.json,/etc/V2bX/config.json.bak,/usr/local/V2bX/config.json,/usr/local/V2bX/config.json.bak,/etc/xboard-node/config.yml,/etc/xboard-node/config.yaml,/usr/local/etc/bby-agent.yml,/opt/xboard-node/config.yml,/app/config/config.yml,/etc/soga/soga.conf,/etc/soga/config.yml")"
socks_config_paths="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_SOCKS_CONFIG_PATHS "/etc/danted.conf,/etc/sockd.conf,/etc/3proxy/3proxy.cfg,/etc/3proxy.cfg,/etc/xray/config.json,/usr/local/etc/xray/config.json,/etc/v2ray/config.json,/usr/local/etc/v2ray/config.json,/etc/sing-box/config.json,/etc/sing-box.json,/etc/gost/config.yaml,/etc/gost/config.json")"
socks_auth_enforcement_file="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE "/opt/narwhal-monitor/socks-auth-enforcement.json")"
for required_panel_path in /etc/V2bX/config.json.bak /usr/local/V2bX/config.json /usr/local/V2bX/config.json.bak /usr/local/etc/bby-agent.yml; do
  if [[ ",${panel_config_paths}," != *",${required_panel_path},"* ]]; then
    panel_config_paths="${panel_config_paths},${required_panel_path}"
  fi
done
panel_allowlist_file="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_ALLOWLIST_FILE "/opt/narwhal-monitor/panel-allowlist.json")"
panel_auto_remediate_file="$(load_non_empty_or_default "$CLIENT_ENV_FILE" SECURITY_PANEL_AUTO_REMEDIATE_FILE "/opt/narwhal-monitor/panel-auto-remediate.json")"

server_url="$(ask_with_default "Server URL (e.g. https://server.example.com or https://1.2.3.4)" "$default_server_url")"
secret="$(ask_with_default "Shared secret" "$default_secret")"
host_id="$(ask_with_default "Host ID" "$default_host_id")"
interval="$(ask_with_default "Collect interval seconds" "$default_interval")"
runtimes="$(ask_with_default "Container runtimes (auto or comma-separated podman,docker,incus)" "$default_runtimes")"
docker_monitor_mode="$(ask_choice_with_default "请选择 Docker 处理方式" "$default_docker_monitor_mode" \
  "notice|仅发现并提醒（推荐）" \
  "full|完整监测" \
  "off|关闭 Docker 发现")"
monitored_patterns="$(ask_with_default "Podman/Docker image patterns (comma-separated substring match)" "$default_monitored_patterns")"
monitored_incus_patterns="$(ask_with_default "Incus name/image patterns (* for all)" "$default_monitored_incus_patterns")"
incus_project="$(ask_with_default "Incus project (all or exact project name)" "$default_incus_project")"
security_enabled="$(ask_choice_with_default "是否启用 DDoS/CC/滥用/扫描监测" "$default_security_enabled" \
  "true|启用（推荐）" \
  "false|禁用")"
access_log_paths="$(ask_with_default "Nginx/Caddy access log paths (comma-separated)" "$default_access_log_paths")"
container_access_log_paths="$(ask_with_default "Access log paths inside every container (comma-separated)" "$default_container_access_log_paths")"
allowed_panel_domains="$(ask_with_default "Allowed airport panel domains (comma-separated; empty means none)" "$default_allowed_panel_domains")"

mkdir -p /opt/narwhal-monitor
tls_ca_output="${default_tls_ca_file:-$CLIENT_CA_FILE}"
tls_ca_file=""
if [[ "$server_url" == https://* || "$server_url" != *://* ]]; then
  echo "[INFO] Validating Server TLS and bootstrapping an internal CA when required..."
  tls_ca_file="$(printf '%s' "$secret" | python3 "$ROOT_DIR/scripts/bootstrap-client-ca.py" \
    --server-url "$server_url" \
    --secret-stdin \
    --output "$tls_ca_output")"
fi

if ! is_truthy "${NARWHAL_SKIP_SERVER_VERSION_GATE:-0}"; then
  echo "[INFO] Checking that Server v$PROJECT_VERSION is running before Client update..."
  set +e
  version_gate_output="$(printf '%s' "$secret" | python3 "$ROOT_DIR/scripts/check-server-version.py" \
    --server-url "$server_url" \
    --expected-version "$PROJECT_VERSION" \
    --ca-file "$tls_ca_file" \
    --secret-stdin 2>&1)"
  version_gate_result=$?
  set -e
  if [[ -n "$version_gate_output" ]]; then
    echo "$version_gate_output"
  fi
  if [[ "$version_gate_result" -eq 10 ]]; then
    if [[ "$MODE" == "install" && "${NARWHAL_AUTO_UPDATE:-0}" != "1" ]]; then
      echo "[WARN] Server 尚未运行 v$PROJECT_VERSION；继续首次人工安装。"
      echo "[WARN] Client 可能短暂领先，Server 自动升级完成后版本会恢复一致。"
    else
      echo "[WAIT] Client 保持当前版本；Server 升级到 v$PROJECT_VERSION 后将自动重试。"
      exit 75
    fi
  elif [[ "$version_gate_result" -ne 0 ]]; then
    echo "[ERROR] Server 版本校验失败，拒绝升级 Client。"
    exit 1
  fi
fi

if [[ ! -r /proc/net/nf_conntrack && ! -r /proc/net/ip_conntrack ]] \
  && ! command -v conntrack >/dev/null 2>&1; then
  echo "Installing conntrack for NAT-aware inbound source telemetry..."
  if command -v apt-get >/dev/null 2>&1; then
    if ! apt-get update || ! apt-get install -y conntrack; then
      echo "[WARN] conntrack install failed; inbound IP telemetry will use container socket fallback."
    fi
  else
    echo "[WARN] conntrack is unavailable; install conntrack-tools to restore public source IPs behind NAT."
  fi
fi

cat >"$CLIENT_ENV_FILE" <<ENV
NARWHAL_VERSION=$PROJECT_VERSION
SERVER_URL=$server_url
SHARED_SECRET=$secret
SERVER_TLS_CA_FILE=$tls_ca_file
HOST_ID=$host_id
REPORT_INTERVAL=$interval
ACTION_POLL_INTERVAL=$default_action_poll_interval
RUNTIME_COMMAND_TIMEOUT_SECONDS=$runtime_command_timeout
WATCH_DISK_FILE=/xfs_disk.img
CONTAINER_RUNTIMES=$runtimes
DOCKER_MONITOR_MODE=$docker_monitor_mode
MONITORED_IMAGE_PATTERNS=$monitored_patterns
MONITORED_INCUS_PATTERNS=$monitored_incus_patterns
INCUS_PROJECT=$incus_project
SECURITY_MONITOR_ENABLED=$security_enabled
SECURITY_ACCESS_LOG_PATHS=$access_log_paths
SECURITY_CONTAINER_ACCESS_LOG_PATHS=$container_access_log_paths
ALERT_DDOS_RX_BPS=$ddos_rx_bps
ALERT_DDOS_RX_PPS=$ddos_rx_pps
ALERT_DDOS_SYN_RECV=$ddos_syn_recv
ALERT_CONN_WARNING_THRESHOLD=$conn_warning_threshold
ALERT_CONN_CRITICAL_THRESHOLD=$conn_critical_threshold
ALERT_INBOUND_UNIQUE_IPS=$inbound_unique_ips
ALERT_CC_TOTAL_RPS=$cc_total_rps
ALERT_CC_IP_RPS=$cc_ip_rps
ALERT_CC_4XX_RATE=$cc_4xx_rate
ALERT_CC_MIN_REQUESTS=$cc_min_requests
ALERT_SCAN_UNIQUE_PORTS=$scan_unique_ports
ALERT_ABUSE_OUTBOUND_UNIQUE_IPS=$abuse_unique_ips
ALERT_ABUSE_SUSPICIOUS_CONNECTIONS=$abuse_suspicious
ALERT_ABUSE_TX_BPS=$abuse_tx_bps
ALERT_ABUSE_TX_PPS=$abuse_tx_pps
ALERT_ABUSE_TCP_OPENS_PER_SEC=$abuse_tcp_opens
ALERT_ABUSE_TCP_FAILS_PER_SEC=$abuse_tcp_fails
ALERT_ABUSE_UDP_OUT_PER_SEC=$abuse_udp_out
ALERT_ABUSE_PROCESS_COUNT=$abuse_process_count
SECURITY_CONFIG_AUDIT_ENABLED=$config_audit_enabled
SECURITY_SUSPICIOUS_OUTBOUND_PORTS=$suspicious_ports
SECURITY_ACCESS_LOG_MAX_BYTES=$access_log_max_bytes
SECURITY_SOCKET_SNAPSHOT_MAX=$socket_snapshot_max
SECURITY_COMMUNICATION_DETAIL_MAX=$communication_detail_max
SECURITY_CONNTRACK_SNAPSHOT_MAX=$conntrack_snapshot_max
SECURITY_HOST_PROXY_SOCKET_MAX=$host_proxy_socket_max
SECURITY_PANEL_ENV_SCAN_MAX_PROCESSES=$panel_env_scan_max
SECURITY_PANEL_ENV_MAX_BYTES=$panel_env_max_bytes
GEOIP_MMDB_PATH=$geoip_mmdb_path
GEOIP_HTTPS_ENABLED=$geoip_https_enabled
GEOIP_HTTPS_ENDPOINT=$geoip_https_endpoint
GEOIP_CACHE_MAX_ENTRIES=$geoip_cache_max
GEOIP_CACHE_TTL_SECONDS=$geoip_cache_ttl
GEOIP_NEGATIVE_CACHE_TTL_SECONDS=$geoip_negative_cache_ttl
SECURITY_WEB_SCAN_PATTERNS=$web_scan_patterns
ALERT_WEB_SCAN_REQUESTS=$web_scan_requests
ALERT_AUTH_FAILURES_PER_IP=$auth_failures_per_ip
SECURITY_SUSPICIOUS_PROCESS_PATTERNS=$suspicious_process_patterns
SECURITY_AUTO_REMEDIATE_XMRIG=$auto_remediate_xmrig
SECURITY_AUTO_REMEDIATE_XRAYR=$auto_remediate_xrayr
SECURITY_PANEL_PAIRING_DETECTION_ENABLED=$panel_detection_enabled
SECURITY_ALLOWED_PANEL_DOMAINS=$allowed_panel_domains
SECURITY_PANEL_ALLOWLIST_FILE=$panel_allowlist_file
SECURITY_PANEL_AUTO_REMEDIATE_FILE=$panel_auto_remediate_file
SECURITY_PANEL_PROCESS_PATTERNS=$panel_process_patterns
SECURITY_PANEL_CONFIG_PATHS=$panel_config_paths
SECURITY_SOCKS_CONFIG_PATHS=$socks_config_paths
SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE=$socks_auth_enforcement_file
ENV

cat >"$CLIENT_INSTALL_ENV_FILE" <<ENV
RUNTIME=host-agent
AGENT_DIR=$CLIENT_APP_DIR
ENV
chmod 0600 "$CLIENT_ENV_FILE" "$CLIENT_INSTALL_ENV_FILE"

# 为兼容旧版本，先尝试删除原容器化 client。
podman rm -f narwhal-monitor-client >/dev/null 2>&1 || true
docker rm -f narwhal-monitor-client >/dev/null 2>&1 || true

mkdir -p "$CLIENT_APP_DIR"
cp "$ROOT_DIR/client/agent.py" "$CLIENT_APP_DIR/agent.py"
cp "$ROOT_DIR/client/requirements.txt" "$CLIENT_APP_DIR/requirements.txt"

ensure_client_venv

"$CLIENT_VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$CLIENT_VENV_DIR/bin/pip" install -r "$CLIENT_APP_DIR/requirements.txt"

cat >"$SYSTEMD_SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Narwhal Monitor Host Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CLIENT_APP_DIR
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=$CLIENT_ENV_FILE
ExecStart=$CLIENT_VENV_DIR/bin/python $CLIENT_APP_DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl enable narwhal-monitor-client.service >/dev/null
systemctl restart narwhal-monitor-client.service
bash "$ROOT_DIR/scripts/setup-auto-update.sh" client "$ROOT_DIR"
check_incus_visibility "$runtimes" "$incus_project"

cat <<EOF_SUM

===== Client Install Summary =====
Mode: $MODE
Version: $PROJECT_VERSION
Runtime: host agent (systemd)
Service Name: narwhal-monitor-client.service
Server URL: $server_url
Server TLS CA: ${tls_ca_file:-system trust}
Shared Secret: $(if [[ "$MODE" == "install" ]]; then echo "$secret"; else echo "preserved (see $CLIENT_ENV_FILE)"; fi)
Host ID: $host_id
Report Interval: $interval s
Watch Disk File: /xfs_disk.img
Monitored Image Patterns: $monitored_patterns
Monitored Incus Patterns: $monitored_incus_patterns
Container Runtimes: $runtimes
Docker Handling: $docker_monitor_mode
Incus Project: $incus_project
Runtime Access: host CLI/socket (auto-detected by agent)
Security Monitoring: $security_enabled
Access Logs: $access_log_paths
Container Access Logs: $container_access_log_paths
Env File: $CLIENT_ENV_FILE
Install Config: $CLIENT_INSTALL_ENV_FILE
Agent Directory: $CLIENT_APP_DIR
Venv Directory: $CLIENT_VENV_DIR
Automatic Updates: enabled (origin/main every 15 minutes)
==================================
EOF_SUM
