#!/usr/bin/env bash
# Launched by the Client after it has acknowledged a server-authorised deletion.
# It must outlive the systemd service, so keep it deliberately dependency-light.
set -u
ACTION_ID="${1:-0}"
sleep 3
ENV_FILE="/opt/narwhal-monitor/client.env"
value() { sed -n "s/^$1=//p" "$ENV_FILE" 2>/dev/null | head -n 1; }
SERVER_URL="$(value SERVER_URL)"
SHARED_SECRET="$(value SHARED_SECRET)"
HOST_ID="$(value HOST_ID)"
NODE_ID="$(value NODE_ID)"
CA_FILE="$(value SERVER_TLS_CA_FILE)"
systemctl disable --now narwhal-monitor-client.service narwhal-monitor-client-update.timer >/dev/null 2>&1 || true
rm -f /etc/systemd/system/narwhal-monitor-client.service \
  /etc/systemd/system/narwhal-monitor-client-update.service \
  /etc/systemd/system/narwhal-monitor-client-update.timer
systemctl daemon-reload >/dev/null 2>&1 || true
# Only the Client-owned values are used below. A signed completion callback keeps
# the Server record until this script has actually disabled its systemd units.
if [[ -n "$SERVER_URL" && -n "$SHARED_SECRET" && -n "$HOST_ID" && -n "$NODE_ID" ]] && command -v curl >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
  BODY="$(ACTION_ID="$ACTION_ID" HOST_ID="$HOST_ID" NODE_ID="$NODE_ID" python3 -c 'import json, os; print(json.dumps({"action_id":int(os.environ["ACTION_ID"]),"host_id":os.environ["HOST_ID"],"node_id":os.environ["NODE_ID"],"status":"succeeded","message":"client_cleanup_complete"}, separators=(",", ":")))')"
  TS="$(date +%s)"
  SIG="$(printf '%s' "$BODY$TS" | openssl dgst -sha256 -hmac "$SHARED_SECRET" -hex | awk '{print $NF}')"
  CURL_ARGS=(-fsS --connect-timeout 10 --max-time 20 -H 'Content-Type: application/json' -H "X-Timestamp: $TS" -H "X-Signature: $SIG" --data "$BODY")
  if [[ -n "$CA_FILE" && -r "$CA_FILE" ]]; then CURL_ARGS+=(--cacert "$CA_FILE"); fi
  for _ in 1 2 3 4 5; do
    curl "${CURL_ARGS[@]}" "$SERVER_URL/api/v1/actions/result" && break
    sleep 3
  done
fi
rm -rf /opt/narwhal-monitor/client-agent
rm -f /opt/narwhal-monitor/client.env /opt/narwhal-monitor/client-install.env \
  /opt/narwhal-monitor/client-auto-update.env /opt/narwhal-monitor/client-auto-update.log \
  /opt/narwhal-monitor/server-ca.crt /opt/narwhal-monitor/client-self-uninstall.sh
# Keep /var/lib/narwhal-monitor/node-id: reinstalling this same machine must merge
# into its previous identity rather than create a duplicate due to a renamed label.
exit 0
