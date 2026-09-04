export interface ContainerItem {
  host_id: string;
  runtime: 'incus' | 'podman' | 'docker' | string;
  project?: string;
  container_name: string;
  container_id?: string;
  status?: string;
  cpu_percent?: number;
  mem_percent?: number;
  mem_bytes?: number;
  mem_limit_bytes?: number;
  net_rx_bps?: number;
  net_tx_bps?: number;
  conn_count?: number;
  timestamp_iso_utc8?: string;
  agent_version?: string;
  cpu_effective_cpus?: number;
  container_disk_rw_bytes?: number;
  container_fs_root_total_bytes?: number;
  container_fs_root_avail_bytes?: number;
  top_cpu_process_command?: string;
  top_cpu_process_cpu_percent?: number;
  top_cpu_process_pid?: number;
  tcp_country_stats?: { country: string; connections: number }[];
  udp_country_stats?: { country: string; connections: number }[];
  alerts?: {
    stale?: boolean;
    cpu?: boolean;
    memory?: boolean;
    disk?: boolean;
    conn?: boolean;
    [key: string]: any;
  };
  security?: ContainerSecurity;
}

export interface ContainerSecurity {
  process_count?: number;
  top_cpu_process_command?: string;
  top_cpu_process_cpu_percent?: number;
  top_cpu_process_pid?: number;
  suspicious_processes?: { pid?: number; command?: string; pattern?: string }[];
  listening_ports?: string[];
  network_exposure?: { listen: string; target: string }[];
  inbound_unique_ips?: number;
  inbound_unique_ip_threshold?: number;
  inbound_ip_observation?: string;
  inbound_top_ips?: { ip: string; connections: number }[];
  incoming_established?: number;
  outbound_unique_ips?: number;
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
  configuration_risks?: { message?: string; code?: string }[];
  communication_detail_available?: boolean;
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
    local?: string;
    remote?: string;
    state?: string;
    original_remote_ips?: string[];
  }[];
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
  severity: 'critical' | 'warning' | 'info' | string;
  status: 'active' | 'suppressed' | 'dismissed' | 'remediated' | 'resolved' | string;
  title?: string;
  message: string;
  value?: any;
  threshold?: any;
  details?: any;
  occurrence_count?: number;
  first_seen_utc8?: string;
  last_seen_utc8?: string;
  latest_action?: {
    id?: number;
    action_type?: string;
    status?: string;
    result_message?: string;
    updated_at_utc8?: string;
  };
  latest_decision?: {
    decision?: string;
    requested_by?: string;
    created_at_utc8?: string;
  };
}

export interface SecurityStatusItem {
  host_id: string;
  rx_bps: number;
  tx_bps: number;
  rx_mbps: number;
  tx_mbps: number;
  rx_pps: number;
  syn_recv: number;
  http_rps: number;
  top_ip_rps: number;
  access_log?: string;
  timestamp_iso_utc8?: string;
  today_peak_rx_bps: number;
  today_peak_tx_bps: number;
  today_peak_rx_mbps: number;
  today_peak_tx_mbps: number;
  today_peak_conn_count: number;
  today_peak_inbound_ips: number;
  today_peak_outbound_ips: number;
}

export interface HistoryPoint {
  timestamp_iso_utc8: string;
  cpu_percent: number;
  mem_percent: number;
  net_rx_bps: number;
  net_tx_bps: number;
  conn_count: number;
  agent_version?: string;
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
    connection_ips?: {
      ip?: string;
      connections?: number;
      inbound?: number;
      outbound?: number;
      processes?: string[];
    }[];
    connection_count?: number;
    communication_sockets?: {
      process?: string;
      pid?: number;
      proto?: string;
      direction?: string;
      local?: string;
      remote?: string;
    }[];
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
}
