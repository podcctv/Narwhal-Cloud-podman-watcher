export interface ContainerItem {
  host_id: string;
  runtime: 'incus' | 'podman' | 'docker' | string;
  project?: string;
  container_name: string;
  container_id?: string;
  user_email?: string;
  user_note?: string;
  status?: string;
  cpu_percent?: number;
  mem_percent?: number;
  mem_bytes?: number;
  mem_limit_bytes?: number;
  net_rx_bps?: number;
  net_tx_bps?: number;
  tcp_rx_bps?: number;
  tcp_tx_bps?: number;
  udp_rx_bps?: number;
  udp_tx_bps?: number;
  conn_count?: number;
  host_last_seen?: number;
  host_last_seen_iso_utc8?: string;
  host_offline_seconds?: number;
  timestamp?: number;
  timestamp_iso_utc8?: string;
  offline_seconds?: number;
  offline_hours?: number;
  agent_version?: string;
  cpu_effective_cpus?: number;
  container_disk_rw_bytes?: number;
  disk_root_used_percent?: number | null;
  disk_used_percent?: number;
  disk_root_total_bytes?: number;
  disk_root_avail_bytes?: number;
  disk_data_total_bytes?: number;
  disk_data_avail_bytes?: number;
  disk_data_mountpoint?: string;
  container_fs_root_total_bytes?: number;
  container_fs_root_avail_bytes?: number;
  top_cpu_process_command?: string;
  top_cpu_process_cpu_percent?: number;
  top_cpu_process_pid?: number;
  tcp_country_stats?: { country: string; connections: number }[];
  udp_country_stats?: { country: string; connections: number }[];
  alerts?: {
    stale?: boolean;
    host_stale?: boolean;
    cpu?: boolean;
    memory?: boolean;
    disk?: boolean;
    conn?: boolean;
    traffic_imbalance?: boolean;
    traffic_imbalance_ratio?: number;
    traffic_imbalance_direction?: 'outbound_heavy' | 'inbound_heavy' | string;
    hy2_detected?: boolean;
    hy2_concurrency?: number;
    hy2_confidence?: 'confirmed' | 'suspected' | string;
    udp_throttled?: boolean;
    udp_throttle_rate_mbps?: number;
    udp_throttle_remaining_seconds?: number;
    udp_throttle_violation_count?: number;
    [key: string]: any;
  };
  security?: ContainerSecurity;
}

export interface ContainerSecurity {
  admission?: {
    state: 'enforced' | 'unverified' | 'unavailable';
    observed_at?: number;
    error?: string;
    source_limit?: number;
    source_limit_enforced?: boolean;
    source_policy?: 'first_five_enforced' | 'observe_only';
    sources?: { ip: string; first_seen: number }[];
    blocked?: Record<string, { first_seen: number; last_seen: number; packets: number }>;
    limited?: boolean;
    tcp_connections?: number;
    review_at?: number;
    extensions?: number;
    blocked_packets?: number;
    tcp_denied?: number;
  };
  process_count?: number;
  top_cpu_process_command?: string;
  top_cpu_process_cpu_percent?: number;
  top_cpu_process_pid?: number;
  suspicious_processes?: { pid?: number; command?: string; pattern?: string }[];
  listening_ports?: string[];
  udp_listening_ports?: number[];
  network_exposure?: { listen: string; target: string }[];
  inbound_unique_ips?: number;
  inbound_unique_ip_threshold?: number;
  inbound_ip_observation?: string;
  inbound_top_ips?: { ip: string; connections: number }[];
  incoming_established?: number;
  outbound_established?: number;
  net_rx_pps?: number;
  syn_recv_count?: number;
  panel_pairing?: {
    detected: boolean;
    approved: boolean;
    [key: string]: any;
  };
  socks_proxy?: {
    detected: boolean;
    auth_mode: 'no_auth' | 'weak_password' | 'configured' | 'unknown' | string;
    public_exposure: boolean;
    [key: string]: any;
  };
  hy2_protocol?: {
    detected: boolean;
    confidence: 'confirmed' | 'suspected' | 'none' | string;
    process?: string;
    pid?: number;
    listening_udp_ports?: number[];
    udp_concurrency?: number;
    unique_remote_ips?: number;
    evidence?: string[];
  };
  udp_throttle?: {
    throttled: boolean;
    rate_mbps: number;
    remaining_seconds: number;
    violation_count: number;
    reason?: string;
  };
  configuration_risks?: { message?: string; code?: string }[];
  communication_detail_available?: boolean;
  service_inventory_state?: 'complete' | 'partial' | 'unavailable' | string;
  service_listeners?: {
    process?: string;
    pid?: number;
    proto?: 'tcp' | 'udp' | string;
    local?: string;
    port?: number;
    source?: 'ss_process_owner' | 'container_proc_net' | string;
    process_attribution?: 'attributed' | 'unavailable' | string;
    application_protocols?: string[];
    application_protocol_evidence?: 'config_matches_live_pid_and_port' | string;
    vmess_block_state?: 'blocked' | 'unverified' | string;
    vmess_block_message?: string;
  }[];
  communication_processes?: {
    process?: string;
    pid?: number;
    inbound_connections?: number;
    outbound_connections?: number;
    unique_remote_ips?: number;
    original_inbound_unique_ips?: number;
    original_inbound_top_ips?: string[];
  }[];
  communication_sockets?: {
    process?: string;
    pid?: number;
    proto?: string;
    direction?: 'inbound' | 'outbound' | string;
    origin?: 'remote_peer' | 'local_process' | 'unknown' | string;
    origin_confidence?: 'confirmed' | 'probable' | 'unknown' | string;
    direction_evidence?: string;
    process_role?: 'acceptor' | 'initiator' | 'unknown' | string;
    process_attribution?: 'attributed' | 'unavailable' | string;
    process_attribution_source?: string;
    conntrack_match?: 'original_tuple' | 'reply_tuple' | string;
    local?: string;
    remote?: string;
    state?: string;
    original_remote_ips?: string[];
  }[];
  connection_attribution?: {
    captured_sockets?: number;
    confirmed_local_initiated?: number;
    probable_local_initiated?: number;
    confirmed_remote_initiated?: number;
    probable_remote_initiated?: number;
    unknown_direction?: number;
    process_attributed_sockets?: number;
    conntrack_confirmed_sockets?: number;
    conntrack_available?: boolean;
    conntrack_entries_examined?: number;
    conntrack_snapshot_truncated?: boolean;
    socket_snapshot_truncated?: boolean;
    process_attribution_available?: boolean;
  };
  host_conntrack_snapshot_count?: number;
  host_conntrack_snapshot_truncated?: boolean;
  communication_snapshot_count?: number;
  communication_snapshot_truncated?: boolean;
  [key: string]: any;
}

export interface LatestResponse {
  server_version: string;
  timestamp?: string;
  items: ContainerItem[];
}

export interface SecurityAlert {
  id: number;
  host_id: string;
  runtime: string;
  project?: string;
  container_name?: string;
  type: string;
  /** Server-side evidence classification; protection signals are not buyer/user misconduct. */
  protection_only?: boolean;
  severity: 'critical' | 'warning' | 'info' | string;
  status: 'active' | 'suppressed' | 'dismissed' | 'remediated' | 'resolved' | string;
  title?: string;
  message: string;
  value?: any;
  threshold?: any;
  details?: any;
  deep_evidence?: {
    captured_at_utc8?: string;
    inbound_unique_ips?: number;
    outbound_unique_ips?: number;
    inbound_process_count?: number;
    outbound_process_count?: number;
    connection_count?: number;
    socket_snapshot_count?: number;
    socket_snapshot_truncated?: boolean;
    inbound_country_stats?: { country?: string; connections?: number; ip_count?: number }[];
    outbound_country_stats?: { country?: string; connections?: number; ip_count?: number }[];
    inbound_ips?: DeepEvidenceIp[];
    outbound_ips?: DeepEvidenceIp[];
    connection_ips?: DeepEvidenceIp[];
    connection_attribution?: {
      captured_sockets?: number;
      confirmed_local_initiated?: number;
      probable_local_initiated?: number;
      confirmed_remote_initiated?: number;
      probable_remote_initiated?: number;
      unknown_direction?: number;
      process_attributed_sockets?: number;
      conntrack_confirmed_sockets?: number;
      conntrack_available?: boolean;
      conntrack_snapshot_truncated?: boolean;
      socket_snapshot_truncated?: boolean;
    };
    errors?: string[];
  } | null;
  occurrence_count?: number;
  first_seen_utc8?: string;
  last_seen_utc8?: string;
  recovery?: {
    state: string;
    verified: boolean;
    recovered_at_utc8?: string | null;
    duration_seconds?: number | null;
    closed_at_utc8?: string | null;
    closed_duration_seconds?: number | null;
  };
  latest_action?: {
    id?: number;
    action_type?: string;
    status?: string;
    result_message?: string;
    updated_at_utc8?: string;
    params?: { max_connections?: number; lease_expires_at?: number; [key: string]: any };
  };
  latest_decision?: {
    decision?: string;
    requested_by?: string;
    created_at_utc8?: string;
  };
}

export interface SecurityStatusItem {
  enabled?: boolean;
  stale?: boolean;
  interval_seconds?: number;
  thresholds?: Record<string, number>;
  sample_alerts?: Partial<SecurityAlert>[];
  host_audit?: {
    enabled?: boolean;
    scope?: 'host' | 'agent_container' | string;
    os?: { id?: string; version_id?: string };
    rescan_requested_at?: number;
    snapshot_status?: 'ready' | 'partial' | 'unavailable' | string;
    snapshot_at?: number;
    baseline_at?: number;
    baseline_pending?: boolean;
    snapshot_files?: number;
    user_accounts?: number;
    ssh_key_count?: number;
    ssh_log_status?: 'available' | 'partial' | 'unavailable' | string;
    ssh_events_last_period?: number;
    new_ssh_login_events?: number;
    country_lookup?: string;
    recent_events?: Array<{ type?: string; title?: string; message?: string; severity?: string }>;
    vulnerability_scan?: {
      status?: string;
      coverage?: string;
      checked_at?: number;
      last_attempt_at?: number;
      packages_checked?: number;
      finding_count?: number;
      critical_count?: number;
      error?: string;
    };
    security_indicator_scan?: {
      status?: string;
      coverage?: string;
      checked_at?: number;
      last_attempt_at?: number;
      finding_count?: number;
      critical_count?: number;
      python_site_roots?: number;
      python_packages_checked?: number;
      config_files_checked?: number;
      ca_certificates_checked?: number;
      runtime_inventory?: { status?: string; engines?: string[]; images_checked?: number };
      error?: string;
    };
    recent_findings?: Array<{
      id?: string;
      cve?: string;
      package?: string;
      version?: string;
      ecosystem?: string;
      source?: string;
      severity?: string;
      summary?: string;
    }>;
    recent_indicators?: Array<{
      id?: string;
      rule?: string;
      severity?: string;
      component?: string;
      title?: string;
      evidence?: string[];
      guidance?: string;
      reference?: string;
      finding_ids?: string[];
      instance_count?: number;
    }>;
  };
  access_sources?: AccessSource[];
  today_peak_container_conn_count?: number;
  host_id: string;
  node_id?: string;
  host_config?: Record<string, any>;
  rx_bps: number;
  tx_bps: number;
  rx_mbps: number;
  tx_mbps: number;
  rx_pps: number;
  tx_pps: number;
  syn_recv: number;
  http_rps: number;
  top_ip_rps: number;
  http_4xx_rate: number;
  http_5xx_rate: number;
  access_requests: number;
  access_unique_ips: number;
  active_alerts: number;
  timestamp_iso_utc8?: string;
  today_peak_rx_bps: number;
  today_peak_tx_bps: number;
  today_peak_rx_mbps: number;
  today_peak_tx_mbps: number;
  today_peak_conn_count: number;
  today_peak_inbound_ips: number;
  today_peak_outbound_ips: number;
}

export interface HostFirewallRule {
  key: string;
  priority: number;
  direction: 'in' | 'out';
  protocol: 'all' | 'tcp' | 'udp' | 'http' | 'tls' | 'socks' | 'ssh' | 'fet' | 'wireguard' | 'openvpn' | 'quic' | 'mtproto';
  action: 'block' | 'pass';
  enabled: boolean;
  port_start: number;
  port_end?: number;
  ip_type: 'any' | 'cidr' | 'geoip';
  ip?: string;
  countries?: string[];
}

export interface HostFirewallAbusePolicy {
  speedtest: boolean;
  mining: boolean;
  bt: boolean;
  interfaces: string[];
  /** Fleet templates use logical runtimes and resolve real interfaces per host. */
  runtimes?: Array<'incus' | 'podman'>;
}

export interface HostFirewallRuntimeStatus {
  control_api: 'ready' | 'unsupported' | 'unavailable' | 'unknown';
  control_api_reason?: string;
  control_api_http_status?: number | null;
  observed_at: number;
  stale?: boolean;
}

export interface HostFirewallInterface {
  name: string;
  kind: string;
  kernel_kind?: string;
  state: string;
  mtu: number | null;
  addresses: string[];
  is_default_route: boolean;
  runtimes: Array<'incus' | 'podman'>;
  network_names: string[];
  firewall_eligible: boolean;
}

export interface HostFirewallInterfaceInventory {
  status: 'ready' | 'unavailable' | 'unknown';
  observed_at: number;
  stale: boolean;
  interfaces: HostFirewallInterface[];
}

export interface ManualBandwidthLimit {
  scope: 'host' | 'container';
  interface?: string;
  runtime?: 'incus' | 'podman';
  project?: string;
  container_name?: string;
  container_id?: string;
  upload_mbps: number;
  download_mbps: number;
}

export interface ManualBandwidthLimitResponse {
  host_id: string;
  expected_node_id: string;
  host_online: boolean;
  sample_at: number;
  interfaces: Array<{
    name: string; kind: string; state: string; is_default_route: boolean;
    runtimes?: Array<'incus' | 'podman'>; network_names?: string[];
  }>;
  containers: Array<{ runtime: 'incus' | 'podman'; project: string; container_name: string; container_id: string }>;
  policy: {
    schema: 1; revision: number; limits: ManualBandwidthLimit[];
    auto_throttle: {
      enabled: boolean; threshold_percent: number; trigger_seconds: number;
      tier_percentages: number[]; minimum_mbps: number;
      recovery_percent: number; recovery_seconds: number;
    };
  };
  reported: {
    revision?: number; state?: string; items?: Array<Record<string, unknown>>; message?: string;
    updated_at?: number;
    active_limits?: Array<{
      scope: 'host' | 'container'; target: string; interface?: string;
      runtime?: 'incus' | 'podman'; project?: string; container_name?: string;
      container_id?: string; upload_mbps: number; download_mbps: number;
      last_confirmed_at?: number;
    }>;
    auto_throttle?: {
      enabled?: boolean; state?: string; interface?: string; items?: Array<Record<string, unknown>>; message?: string;
      mapped_containers?: number; unmapped_containers?: number; unavailable_samples?: number;
      threshold_percent?: number; trigger_seconds?: number; tier_percentages?: number[];
      minimum_mbps?: number; recovery_percent?: number; recovery_seconds?: number;
    };
  };
}

export interface HostFirewallLiveRule {
  id: number;
  priority: number;
  direction: 'in' | 'out';
  protocol: HostFirewallRule['protocol'];
  action: 'block' | 'pass';
  enabled: boolean;
  port_start: number;
  port_end: number;
  ip_type: HostFirewallRule['ip_type'];
  ip?: string;
  countries?: string[];
  origin: 'platform' | 'manual';
  managed_key?: string;
  sync_state: 'manual' | 'in_sync' | 'drifted' | 'orphaned';
}

export interface HostFirewallLiveReadback {
  status: 'ready' | 'unavailable' | 'unsupported' | 'unknown';
  observed_at: number;
  last_success_at: number;
  age_seconds?: number | null;
  stale: boolean;
  sync_status?: 'in_sync' | 'drifted' | 'unknown';
  rule_count?: number;
  managed_rule_count?: number;
  drift_count?: number;
  missing_count?: number;
  rfw_api_version?: string;
  capabilities_known?: boolean;
  supported_protocols?: string[];
  protocol_capabilities?: Record<string, 'supported' | 'unsupported' | 'unknown'>;
  mtproto_support?: 'supported' | 'unsupported' | 'unknown';
  snapshot: null | {
    status: 'in_sync' | 'drifted';
    observed_at: number;
    policy_revision: number;
    rule_count: number;
    managed_rule_count: number;
    drift_count: number;
    missing_count: number;
    rfw_api_version?: string;
    capabilities_known?: boolean;
    supported_protocols?: string[];
    rules: HostFirewallLiveRule[];
    expected_rules: Array<{ key: string; id?: number; sync_state: 'in_sync' | 'drifted' | 'missing' }>;
  };
}

export interface HostFirewallPolicyResponse {
  host_id: string;
  agent_ready: boolean;
  revision: number;
  source_fleet_revision: number;
  policy: { rules: HostFirewallRule[]; abuse: HostFirewallAbusePolicy };
  runtime_status: HostFirewallRuntimeStatus;
  interface_inventory?: HostFirewallInterfaceInventory;
  live_readback: HostFirewallLiveReadback;
  updated_by: string;
  updated_at_utc8: string;
  latest_action: null | {
    id: number;
    status: string;
    message: string;
    updated_at_utc8: string;
  };
  policy_history?: Array<{
    revision: number;
    policy: { rules: HostFirewallRule[]; abuse: HostFirewallAbusePolicy };
    updated_by: string;
    updated_at_utc8: string;
    source_fleet_revision: number;
  }>;
}

export interface ConnectionEvidenceResponse {
  host_id: string;
  runtime: string;
  project: string;
  container_name: string;
  window_minutes: number;
  sample_count: number;
  timeline: Array<{
    ts: number;
    connection_count: number;
    process_attribution: {
      captured: number;
      attributed: number;
      confirmed_local: number;
      confirmed_remote: number;
      unknown_direction: number;
      conntrack_available: boolean;
    };
    access_log: Record<string, number>;
    ips: Array<{
      ip: string;
      inbound: number;
      processes: unknown[];
      origin_confidence: string;
      network_evidence: Record<string, unknown>;
      assessment: Record<string, any>;
      abuseipdb: Record<string, any>;
    }>;
  }>;
  source_assessment: Record<string, any>;
  interpretation: string;
}

export interface FleetFirewallHostStatus {
  host_id: string;
  registered: boolean;
  online: boolean;
  agent_version: string;
  control_api: HostFirewallRuntimeStatus['control_api'];
  control_api_reason?: string;
  control_api_http_status?: number | null;
  control_api_stale?: boolean;
  observed_at: number;
  local_revision: number;
  fleet_revision: number;
  state: 'unregistered' | 'offline' | 'awaiting_capability' | 'awaiting_rfw_capability' | 'firewall_status_stale' | 'awaiting_interfaces' | 'interfaces_not_found' | 'rfw_protocol_update_required' | 'runman_update_required' | 'runman_unavailable' | 'queued' | 'apply_failed' | 'drifted' | 'last_apply_succeeded' | 'not_synced' | 'ready';
  required_protocols: string[];
  unsupported_protocols: string[];
  unknown_protocols: string[];
  container_interfaces: {
    status: HostFirewallInterfaceInventory['status'];
    observed_at: number;
    stale: boolean;
    by_runtime: Record<'incus' | 'podman', string[]>;
  };
  live_readback: Omit<HostFirewallLiveReadback, 'snapshot'>;
  last_action: null | { id: number; status: string; message: string; updated_at_utc8: string };
}

export interface FleetFirewallPolicyResponse {
  revision: number;
  policy: { rules: HostFirewallRule[]; abuse: HostFirewallAbusePolicy };
  updated_by: string;
  updated_at_utc8: string;
  hosts: FleetFirewallHostStatus[];
  counts: { total: number; registered: number; online: number; control_ready: number; last_apply_succeeded: number; deferred: number; network_deferred: number; live_readback_current: number; drifted_hosts: number; readback_unavailable: number; mtproto_supported_hosts: number; mtproto_unsupported_hosts: number; mtproto_capability_unknown_hosts: number; required_protocols_supported_hosts: number; required_protocols_unsupported_hosts: number; required_protocols_unknown_hosts: number };
  live_rule_readback_supported: boolean;
}

export interface HistoryPoint {
  timestamp_iso_utc8: string;
  cpu_percent: number;
  mem_percent: number;
  net_rx_bps: number;
  net_tx_bps: number;
  tcp_rx_bps?: number;
  tcp_tx_bps?: number;
  udp_rx_bps?: number;
  udp_tx_bps?: number;
  conn_count: number;
  agent_version?: string;
}

export interface DeepEvidenceIp {
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  connections?: number;
  inbound?: number;
  outbound?: number;
  unknown?: number;
  processes?: string[];
  inbound_origin?: 'remote_peer' | 'local_process' | 'unknown' | string;
  inbound_origin_confidence?: 'confirmed' | 'probable' | 'mixed' | 'unknown' | string;
  inbound_direction_evidence?: string[];
  inbound_processes?: { process?: string; pid?: number }[];
  outbound_origin?: 'remote_peer' | 'local_process' | 'unknown' | string;
  outbound_origin_confidence?: 'confirmed' | 'probable' | 'mixed' | 'unknown' | string;
  outbound_direction_evidence?: string[];
  outbound_processes?: { process?: string; pid?: number }[];
  source_observation?: string;
  network_evidence?: {
    flow_count?: number;
    tcp_established_flows?: number;
    tcp_unreplied_flows?: number;
    tcp_handshake_pending_flows?: number;
    source_packets?: number;
    reply_packets?: number;
    public_ports?: number[];
    container_ports?: number[];
    protocols?: string[];
    evidence_sources?: string[];
    classification?: string;
    scope?: string;
  };
}

export interface InboundPortEvidence {
  container_port?: number;
  source_ips?: string[];
  source_ip_count?: number;
  connections?: number;
  process_listeners?: { process?: string; pid?: number }[];
  correlation_scope?: 'container_port_aggregate' | string;
  confidence?: 'port_correlated' | string;
  exact_socket_match?: boolean;
}

export interface IPReputationSettings {
  provider: 'AbuseIPDB' | string;
  configured: boolean;
  updated_at: number;
  last_check?: {
    status: 'checked' | 'error' | string;
    checked_at: number;
    provider_status?: number;
    retry_after_seconds?: number;
    message?: string;
  } | null;
}

export interface IPReputationResult {
  status: 'checked' | 'error' | 'not_configured' | 'local_limit' | string;
  provider?: string;
  ip: string;
  classification?: 'many_recent_reports' | 'reported' | 'few_reports' | 'reports_low_confidence' | 'no_recent_reports' | string;
  abuse_confidence_score?: number;
  total_reports?: number;
  distinct_reporters?: number;
  last_reported_at?: string;
  usage_type?: string;
  isp?: string;
  country_code?: string;
  is_whitelisted?: boolean | null;
  checked_at?: number;
  cached?: boolean;
  message?: string;
  provider_status?: number;
  retry_after_seconds?: number;
  retryable?: boolean;
}

export interface AccessSource {
  label?: string;
  enabled?: boolean;
  readable_files?: number;
  container_readable_files?: number;
  missing_files?: number;
  unreadable_files?: number;
  parse_errors?: number;
  requests?: number;
  requests_per_second?: number;
  top_ip_requests_per_second?: number;
  unique_ips?: number;
  status_4xx?: number;
  status_5xx?: number;
}

export interface DiagnosticData {
  action?: {
    id: number;
    status: 'queued' | 'dispatched' | 'succeeded' | 'failed' | string;
    action_type: string;
    result_message?: string;
    updated_at_utc8?: string;
  } | null;
  sample?: {
    report_timestamp_utc8?: string;
    report_timestamp?: number;
    sampled_at?: number;
    network_rates?: {
      rx_bps?: number;
      tx_bps?: number;
      rx_pps?: number;
      tx_pps?: number;
      sample_seconds?: number;
    };
    process_count?: number;
    processes?: {
      items?: {
        process?: string;
        pid?: number;
        user?: string;
        cpu_percent?: number;
        rss_bytes?: number;
        state?: string;
        command?: string;
      }[];
    };
    unique_connection_ips?: number;
    inbound_ips?: DeepEvidenceIp[];
    outbound_ips?: DeepEvidenceIp[];
    unclassified_ips?: DeepEvidenceIp[];
    connection_ips?: DeepEvidenceIp[];
    inbound_port_evidence?: InboundPortEvidence[];
    inbound_source_history?: {
      status?: 'available' | 'insufficient_history' | string;
      lookback_seconds?: number;
      report_sample_count?: number;
      conntrack_sample_count?: number;
      conntrack_sample_span_seconds?: number;
      first_sampled_at?: number;
      last_sampled_at?: number;
      reference_sample_at?: number;
      minimum_repeat_samples?: number;
      minimum_repeat_span_seconds?: number;
      identity_confirmed?: boolean;
      customer_attribution_status?: 'not_verified' | string;
      customer_notice_allowed?: boolean;
      requires_application_auth_logs?: boolean;
      assessments?: {
        ip: string;
        classification?: string;
        confidence?: 'low' | 'moderate' | string;
        sample_count?: number;
        sample_span_seconds?: number;
        listener_transport_samples?: number;
        service_activity_samples?: number;
        probe_clue_samples?: number;
        service_ports?: number[];
        non_listener_ports?: number[];
        max_established_flows?: number;
        max_incomplete_flows?: number;
        identity_confirmed?: boolean;
      }[];
    };
    connection_count?: number;
    communication_sockets?: {
      process?: string;
      pid?: number;
      proto?: string;
      direction?: string;
      origin?: string;
      origin_confidence?: string;
      direction_evidence?: string;
      process_role?: string;
      process_attribution?: string;
      process_attribution_source?: string;
      conntrack_match?: string;
      local?: string;
      remote?: string;
      state?: string;
      original_remote_ips?: string[];
    }[];
    connection_attribution?: {
      captured_sockets?: number;
      confirmed_local_initiated?: number;
      probable_local_initiated?: number;
      confirmed_remote_initiated?: number;
      probable_remote_initiated?: number;
      unknown_direction?: number;
      process_attributed_sockets?: number;
      conntrack_confirmed_sockets?: number;
      conntrack_available?: boolean;
      conntrack_entries_examined?: number;
      conntrack_snapshot_truncated?: boolean;
      socket_snapshot_truncated?: boolean;
      process_attribution_available?: boolean;
    };
    errors?: string[];
  } | null;
}

export interface StatsResponse {
  server_version?: string;
  containers_count: number;
  samples_count: number;
  sample_interval_seconds: number;
  window_minutes: number;
  cpu_top: any[];
  conn_top: any[];
  traffic_top: any[];
  all_containers: any[];
  host_summary: any[];
}

export interface ContainerIdentity {
  host_id: string;
  runtime: string;
  project?: string;
  container_name: string;
  container_id?: string;
  /** Explicit security alert selected for a targeted disposition. */
  alert_id?: number;
}

export interface ContainerUserNoteResponse {
  ok: boolean;
  found: boolean;
  host_id: string;
  runtime: string;
  project: string;
  container_name: string;
  container_id: string;
  user_email: string;
  user_note: string;
  updated_at: number;
}

export interface NotificationBot {
  id: number;
  name: string;
  kind: 'telegram' | string;
  target: string;
  min_severity: 'info' | 'warning' | 'critical' | string;
  enabled: boolean;
  token_configured: boolean;
  created_at_utc8?: string;
  updated_at_utc8?: string;
  last_delivery_status?: 'never' | 'succeeded' | 'failed' | string;
  last_delivery_error?: string;
  last_sent_at_utc8?: string;
}

export interface PushSettingsResponse {
  narwhal_api_url: string;
  narwhal_api_key_configured: boolean;
  narwhal_api_key_masked: string;
  narwhal_machine_id: string;
  narwhal_node_name: string;
  buyer_notify_enabled: boolean;
  buyer_min_severity?: 'warning' | 'critical';
  buyer_recovery_enabled?: boolean;
  buyer_sender?: string;
  telegram_bots_count: number;
  callback_ready: boolean;
  proxy_configured?: boolean;
  proxy_scheme?: string;
}

export interface PushSettingsPayload {
  narwhal_api_url?: string;
  narwhal_api_key?: string;
  narwhal_machine_id?: string;
  narwhal_node_name?: string;
  buyer_notify_enabled?: boolean;
  buyer_min_severity?: 'warning' | 'critical';
  buyer_recovery_enabled?: boolean;
  user_id?: string;
  scope?: 'user' | 'machine';
  send?: boolean;
  confirm_audience?: string;
  confirm_broadcast?: boolean;
}

export interface InvestigationReceipt { kind: string; target: string; status: 'ok' | 'failed'; }
export interface InvestigationEvidence {
  auth_mode?: string;
  service_listeners?: { process: string; local: string; pid: string }[];
  automatic_remediation?: { attempted: boolean; succeeded: boolean; items: InvestigationReceipt[] };
}
export interface InvestigationAction { id?: number; action_type?: string; status?: string; updated_at?: number; items?: InvestigationReceipt[]; }
export interface InvestigationIncident {
  id: number; identity_key: string; host_id: string; runtime: string; project: string; container_name: string;
  user_id: string; title: string; alert_type: string; category: string; severity: string; status: string; state: string;
  first_seen: number; last_anomaly: number; recorded_from: number; legacy: number;
  value: number | null; threshold: number | null; initial_value: number | null; initial_threshold: number | null;
  evidence: InvestigationEvidence; action: InvestigationAction;
  transitions: { ts: number; state: string; status: string; severity: string; value: number | null; threshold: number | null; evidence: InvestigationEvidence; action: InvestigationAction }[];
}
export interface InvestigationResponse {
  concentration: { user_id: string; observed: number; affected: number; share: number | null } | null;
  hosts: { host_id: string; first_sample: number; last_sample: number }[];
  users: { user_id: string; observed: number; affected: number; unassessed: number; episodes: number; pending: number; rate: number | null; share: number | null; legacy: number; security: number; signals: number; protection_signals: number }[];
  items: InvestigationIncident[]; total: number; offset: number;
  public_items: InvestigationIncident[]; public_total: number;
  summary: { observed: number; affected: number; protection_signals: number; users: number; unknown: number; attributed: number; legacy: number };
  coverage: { from: number | null; retention_days: number; complete_window: boolean; note: string };
  window: { start: number; end: number }; host_id: string; days: number;
}
