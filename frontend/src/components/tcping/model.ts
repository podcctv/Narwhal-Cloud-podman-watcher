import type { Target } from './types';

export interface Filters { province: string; carrier: string; status: string }

export function filterTargets(nodes: Target[], filters: Filters): Target[] {
  return nodes.filter(n => (!filters.province || n.province === filters.province)
    && (!filters.carrier || n.carrier === filters.carrier)
    && (!filters.status || (filters.status === 'ok' ? !!n.result?.success
      : filters.status === 'pending' ? !n.result : !!n.result && !n.result.success)));
}

export function middle(values: number[]): number | null {
  const v = [...values].sort((a, b) => a - b), n = v.length;
  return n ? (v[Math.floor(n / 2)] + v[Math.floor((n - 1) / 2)]) / 2 : null;
}

export function provinceSummary(nodes: Target[], province: string, filters: Filters) {
  const original = nodes.filter(n => n.province === province);
  const rows = filterTargets(original, filters);
  const good = rows.filter(n => n.result?.median_ms != null);
  return { rows, total: rows.length, completed: rows.filter(n => n.result).length,
    good: good.length, value: middle(good.map(n => n.result!.median_ms!)),
    filteredOut: !!original.length && !rows.length };
}

export const mainCarriers = ['telecom', 'unicom', 'mobile'] as const;
export function connectionSummary(rows: Target[]) {
  const returned = rows.filter(n => n.result);
  const valid = returned.filter(n => n.result!.success > 0 && n.result!.median_ms != null && Number.isFinite(n.result!.median_ms));
  const success = returned.reduce((sum, n) => sum + n.result!.success, 0);
  const attempts = returned.reduce((sum, n) => sum + n.result!.attempts, 0);
  const failed = returned.filter(n => !n.result!.success).length;
  const partial = returned.filter(n => n.result!.success > 0 && n.result!.success < n.result!.attempts).length;
  const pending = rows.length - returned.length;
  const errors = [...new Set(returned.filter(n => !n.result!.success).map(n => n.result!.error || n.result!.status))];
  return { total: rows.length, completed: returned.length, pending, success, attempts, failed, partial, errors,
    value: middle(valid.map(n => n.result!.median_ms!)) };
}
export type ConnectionSummary = ReturnType<typeof connectionSummary>;
export const probeErrorLabel = (error: string) => ({ timeout: '连接超时', refused: '连接被拒', network_error: '网络错误', dns_error: 'DNS 失败', blocked_dns: '地址不安全', deadline: '执行超时', worker_error: '执行错误', cancelled: '已取消' }[error] || '无有效连接');
export function summaryState(s: ConnectionSummary): string {
  if (!s.total) return '无目标';
  if (!s.completed) return '未返回';
  const labels = [s.failed ? `${s.failed} 目标失败（${s.errors.map(probeErrorLabel).join('、')}）` : '',
    s.partial ? `${s.partial} 目标部分成功` : '', s.pending ? `${s.pending} 未返回` : ''].filter(Boolean);
  return labels.join(' · ') || '全部连接成功';
}
export function carrierComparison(nodes: Target[]) {
  return [...new Set(nodes.filter(n => mainCarriers.includes(n.carrier as typeof mainCarriers[number])).map(n => n.province))].map(province => ({
    province, cells: mainCarriers.map(carrier => connectionSummary(nodes.filter(n => n.province === province && n.carrier === carrier))),
  }));
}
export function compareProvinces(a: ReturnType<typeof carrierComparison>[number], b: ReturnType<typeof carrierComparison>[number], sort: string) {
  const worst = (row: typeof a) => Math.max(-1, ...row.cells.map(s => s.value ?? -1));
  const failures = (row: typeof a) => row.cells.reduce((n, s) => n + s.failed + s.partial, 0);
  return (sort === 'issues' ? failures(b) - failures(a) || worst(b) - worst(a)
    : sort === 'latency' ? worst(b) - worst(a) : 0) || a.province.localeCompare(b.province, 'zh');
}
