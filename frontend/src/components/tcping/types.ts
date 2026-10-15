export type Scope = 'province' | 'city' | 'all';
export interface ProbeResult {
  ip: string; samples_ms: (number | null)[]; error: string;
  median_ms: number | null; min_ms: number | null; max_ms: number | null;
  success: number; attempts: number; status: string;
}
export interface Target {
  id: string; kind: 'province' | 'city'; province: string; city: string;
  carrier: string; host: string; port: number; result?: ProbeResult | null;
}
export interface Directory {
  generation: string; updated_at: string; fetched_at: number; stale: boolean;
  nodes: Target[]; counts: { province_groups: number; province_nodes: number; city_nodes: number; total: number; extra_nodes?: number; province_targets?: number };
}
export interface Source {
  id: string; name: string; region: string; purchase_url: string; status: string;
  cooldown_until: number; latest_job: { id: string; status: string; scope: Scope; finished_at: number } | null;
  product?: { product_id: string; product_name: string; virtualization_type: string;
    sale_status: 'available' | 'sold_out' | 'unavailable' | 'unknown'; remaining: number | null;
    purchase_url: string; catalog_updated_at: number; catalog_stale: boolean;
    mapping_state?: 'verified' | 'unverified' | 'mismatch' } | null;
}
export interface Job {
  id: string; source_id: string; generation: string; scope: Scope; samples: number;
  status: string; created_at: number; deadline_at: number; started_at: number; finished_at: number;
  message: string; nodes: Target[]; completed: number;
}
export const carriers: Record<string, string> = { telecom: '电信', unicom: '联通', mobile: '移动', custom: '指定目标' };
const virtualizationNames: Record<string, string> = { incus: 'Incus', podman: 'Podman', docker: 'Docker', kvm: 'KVM', lxc: 'LXC', openvz: 'OpenVZ', vmware: 'VMware', xen: 'Xen' };
export const virtualizationLabel = (value: string) => virtualizationNames[value.toLowerCase()] || value || '待识别';
export const sourceStatus: Record<string, string> = { ready: '在线 · 可测试', offline: '离线', needs_upgrade: '待升级', identity_changed: '来源已变更' };
export const jobStatus: Record<string, string> = { queued: '等待 Agent 接收', running: '测试进行中', completed: '已完成', partial: '部分完成', expired: '执行超时', cancelled: '已取消', failed: '执行失败' };
export const scopes: Record<Scope, string> = { province: '省级运营商', city: '市级节点', all: '全部节点' };
export const active = (job?: Job | null) => !!job && ['queued', 'running'].includes(job.status);
export function median(values: number[]) {
  const v = [...values].sort((a, b) => a - b), n = v.length;
  return n ? (v[Math.floor(n / 2)] + v[Math.floor((n - 1) / 2)]) / 2 : null;
}
export const latencyColor = (v: number | null) => v === null ? '#334155' : v < 50 ? '#34d399' : v < 100 ? '#a3e635' : v < 200 ? '#facc15' : v < 250 ? '#fb923c' : '#f87171';
export const utc = (seconds: number) => seconds ? new Date(seconds * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '尚无记录';
export class PublicError extends Error {
  constructor(message: string, public latest?: string, public retry = 0) { super(message); }
}
// Deliberately separate from the authenticated dashboard client: never redirect
// to login and never request private host/commerce APIs on this public page.
export async function publicRequest<T>(path: string, payload?: unknown): Promise<T> {
  const controller = new AbortController(), timer = window.setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch('/api/public/tcping/' + path, {
      method: payload === undefined ? 'GET' : 'POST', credentials: 'omit', signal: controller.signal,
      headers: payload === undefined ? {} : { 'Content-Type': 'application/json' },
      body: payload === undefined ? undefined : JSON.stringify(payload), cache: 'no-store',
    });
    const data = await response.json();
    if (!response.ok) {
      const detail = data.detail;
      throw new PublicError(typeof detail === 'string' ? detail : detail?.message || '请求失败，请稍后重试', detail?.latest_job_id, Number(detail?.retry_after || response.headers.get('Retry-After') || 0));
    }
    return data;
  } catch (error) {
    if (error instanceof PublicError) throw error;
    throw new PublicError('网络请求未完成，请检查连接后重试');
  } finally { window.clearTimeout(timer); }
}
