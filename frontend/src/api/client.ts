import {
  LatestResponse,
  SecurityAlert,
  SecurityStatusItem,
  HistoryPoint,
  DiagnosticData,
  StatsResponse,
  ContainerIdentity,
} from './types';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (res.status === 401) {
    throw new ApiError('Dashboard 认证失败或已过期 (HTTP 401)', 401);
  }

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const json = await res.json();
      if (json.detail) detail = json.detail;
    } catch {
      // ignore
    }
    throw new ApiError(detail, res.status);
  }

  return res.json() as Promise<T>;
}

export const api = {
  getLatest: (includeStale = true) =>
    request<LatestResponse>(`/api/v1/latest?include_stale=${includeStale}`),

  getActiveAlerts: () =>
    request<{ items?: SecurityAlert[]; alerts?: SecurityAlert[]; active_count?: number }>('/api/v1/security/alerts'),

  getSecurityStatus: async () => {
    const raw = await request<{ items: any[] }>('/api/v1/security/status');
    const items: SecurityStatusItem[] = (raw.items || []).map((item) => {
      const access = item.access_log || {};
      const source = String(access.source || '');
      const containerLogs = Number(access.container_readable_files || 0);
      let logState = '未配置';
      if (access.enabled) {
        if (source === 'host') logState = '宿主机正常';
        else if (source === 'container') logState = `容器日志正常 (${containerLogs})`;
        else if (source === 'permission_denied') logState = '权限不足';
        else if (source === 'not_found') logState = '未发现日志文件';
        else logState = '待采集';
      }

      const rxBps = Number(item.total_rx_bps || 0);
      const txBps = Number(item.total_tx_bps || 0);
      const peakRxBps = Number(item.today_peak_rx_bps || 0);
      const peakTxBps = Number(item.today_peak_tx_bps || 0);

      return {
        host_id: String(item.host_id || ''),
        rx_bps: rxBps,
        tx_bps: txBps,
        rx_mbps: (rxBps * 8) / 1000000,
        tx_mbps: (txBps * 8) / 1000000,
        rx_pps: Number(item.total_rx_pps || 0),
        syn_recv: Number(item.syn_recv_count || 0),
        http_rps: Number(access.requests_per_second || 0),
        top_ip_rps: Number(access.top_ip_requests_per_second || 0),
        access_log: logState,
        timestamp_iso_utc8: item.timestamp_utc8 || '-',
        today_peak_rx_bps: peakRxBps,
        today_peak_tx_bps: peakTxBps,
        today_peak_rx_mbps: (peakRxBps * 8) / 1000000,
        today_peak_tx_mbps: (peakTxBps * 8) / 1000000,
        today_peak_conn_count: Number(item.today_peak_conn_count || 0),
        today_peak_inbound_ips: Number(item.today_peak_inbound_ips || 0),
        today_peak_outbound_ips: Number(item.today_peak_outbound_ips || 0),
      };
    });
    return { items };
  },

  getAlertHistory: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<{
      items: SecurityAlert[];
      total: number;
      counts: Record<string, number>;
      alert_types: string[];
      hosts: string[];
    }>(`/api/v1/security/history?${qs}`);
  },

  dispositionAlert: (alertId: number, decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'reopen') =>
    request<{ queued?: boolean; detail?: string }>(`/api/v1/security/alerts/${alertId}/disposition`, {
      method: 'POST',
      body: JSON.stringify({ decision }),
    }),

  getContainerHistory: (identity: ContainerIdentity, minutes = 1440) => {
    const qs = new URLSearchParams({
      host_id: identity.host_id,
      runtime: identity.runtime,
      project: identity.project || '',
      container_name: identity.container_name,
      minutes: String(minutes),
    }).toString();
    return request<{ items: HistoryPoint[] }>(`/api/v1/history?${qs}`);
  },

  getContainerDiagnostic: (identity: ContainerIdentity) => {
    const qs = new URLSearchParams({
      host_id: identity.host_id,
      runtime: identity.runtime,
      project: identity.project || '',
      container_name: identity.container_name,
    }).toString();
    return request<DiagnosticData>(`/api/v1/containers/diagnostics?${qs}`);
  },

  requestContainerDiagnostic: (identity: ContainerIdentity) =>
    request<{ action: any }>('/api/v1/containers/diagnostics', {
      method: 'POST',
      body: JSON.stringify(identity),
    }),

  getStats: async (minutes = 720) => {
    const raw = await request<any>(`/api/v1/stats?minutes=${minutes}`);
    const ranks = raw.ranks || {};
    const cpu_top = (ranks.avg_cpu_top10 || []).map((x: any) => ({
      host_id: x.host_id,
      runtime: x.project ? `${x.runtime}/${x.project}` : x.runtime,
      project: x.project,
      container_name: x.container_name,
      avg_cpu: Number(x.avg?.cpu_percent ?? x.avg_cpu ?? 0),
      max_cpu: Number(x.max?.cpu_percent ?? x.max_cpu ?? 0),
    }));

    const traffic_top = (ranks.traffic_top10 || []).map((x: any) => ({
      host_id: x.host_id,
      runtime: x.project ? `${x.runtime}/${x.project}` : x.runtime,
      project: x.project,
      container_name: x.container_name,
      total_rx_bytes: Number(x.traffic_bytes?.rx ?? x.total_rx_bytes ?? 0),
      total_tx_bytes: Number(x.traffic_bytes?.tx ?? x.total_tx_bytes ?? 0),
      total_bytes: Number(x.traffic_bytes?.total ?? x.total_bytes ?? 0),
    }));

    return {
      server_version: raw.server_version,
      containers_count: Number(raw.container_count || 0),
      samples_count: Number(raw.samples || 0),
      sample_interval_seconds: Number(raw.recommendation?.suggested_interval_seconds || 60),
      window_minutes: Number(raw.window_minutes || minutes),
      cpu_top,
      conn_top: ranks.avg_conn_top10 || [],
      traffic_top,
      all_containers: raw.containers || [],
      host_summary: raw.hosts || [],
    } as StatsResponse;
  },
};

// Utilities for visual formatting
export function fmtBytes(bytes: number | undefined | null): string {
  const n = Number(bytes || 0);
  if (n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtMbps(bps: number | undefined | null, digits = 2): string {
  const val = (Number(bps || 0) * 8) / 1000 / 1000;
  if (!Number.isFinite(val) || val <= 0) return '0.00';
  if (val < 0.01) return '<0.01';
  return val.toFixed(digits);
}

export function fmtNumber(v: number | undefined | null, digits = 1): string {
  const n = Number(v || 0);
  return Number.isFinite(n) ? n.toFixed(digits) : '0';
}

export function fmtNetSpeed(bps: number | undefined | null): { mbps: string; bytesPerSec: string } {
  const n = Number(bps || 0);
  const mbpsVal = (n * 8) / 1000 / 1000;
  return {
    mbps: `${mbpsVal < 0.01 && mbpsVal > 0 ? '<0.01' : mbpsVal.toFixed(2)} Mbps`,
    bytesPerSec: `${fmtBytes(n)}/s`,
  };
}
