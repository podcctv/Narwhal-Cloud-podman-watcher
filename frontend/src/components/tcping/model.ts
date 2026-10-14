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
