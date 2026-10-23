import { SecurityAlert } from '../../api/types';

/**
 * Network and traffic observations are protection signals, not proof of user
 * misconduct. The server-provided classification is authoritative. When
 * talking to an older server that omits it, fail closed for known signal types
 * rather than trusting client/node-supplied attribution flags.
 */
const PROTECTION_ONLY_ALERT_TYPES = new Set([
  'container_connection_count', 'inbound_ip_fanout', 'socks_inbound_fanout',
  'inbound_source_blocked', 'tcp_concurrency_limited', 'admission_unverified',
  'vmess_port_blocked', 'vmess_block_unverified',
  'ddos_bandwidth', 'ddos_packets', 'ddos_syn', 'cc_total_rps', 'cc_single_ip',
  'cc_4xx_ratio', 'http_5xx_ratio', 'http_abuse', 'web_scan', 'port_scan',
  'outbound_fanout', 'outbound_sensitive_ports', 'outbound_bandwidth_abuse',
  'outbound_packet_abuse', 'outbound_connection_churn', 'outbound_connection_failures',
  'udp_outbound_flood', 'hy2_high_concurrency', 'hy2_abnormal_throttle',
  'traffic_imbalance', 'ops_policy_signal', 'ops_bandwidth_saturation',
  'ops_baseline_anomaly', 'ops_connection_guard',
]);

export const isProtectionOnlySignal = (alert: SecurityAlert): boolean =>
  typeof alert.protection_only === 'boolean'
    ? alert.protection_only
    : PROTECTION_ONLY_ALERT_TYPES.has(alert.type);
