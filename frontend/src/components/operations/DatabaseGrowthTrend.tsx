type Sample = { ts: number; database_bytes: number; wal_bytes: number; total_bytes: number };
type Growth = {
  status?: string;
  sampled_at?: number;
  baseline_at?: number;
  baseline_bytes?: number;
  total_bytes?: number;
  growth_bytes?: number | null;
  growth_percent?: number | null;
  history?: Sample[];
  warning_threshold_bytes?: number;
  warning_threshold_percent?: number;
  critical_threshold_bytes?: number;
  critical_threshold_percent?: number;
  retention_days?: number;
  sample_interval_seconds?: number;
};

const bytes = (value?: number | null) => {
  if (value == null) return '—';
  const absolute = Math.abs(value);
  const formatted = absolute >= 1024 ** 3 ? `${(absolute / 1024 ** 3).toFixed(2)} GiB`
    : absolute >= 1024 ** 2 ? `${(absolute / 1024 ** 2).toFixed(1)} MiB`
      : `${Math.round(absolute / 1024)} KiB`;
  return formatted;
};
const date = (value?: number) => value
  ? new Date(value * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })
  : '—';

const statusLabels: Record<string, string> = {
  healthy: '增长正常', warning: '增长偏快', critical: '增长过快', warming_up: '积累中',
};
const statusStyle: Record<string, string> = {
  healthy: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  warning: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  critical: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
  warming_up: 'border-slate-700 bg-slate-800 text-slate-300',
};

export function DatabaseGrowthTrend({ growth = {} }: { growth?: Growth }) {
  const history = growth.history || [];
  const max = Math.max(1, ...history.map(sample => sample.total_bytes));
  const status = growth.status || 'warming_up';
  const growthValue = growth.growth_bytes;
  const description = status === 'warming_up'
    ? '历史基线尚未覆盖约 24 小时；采样每小时一次，期间不判定增长风险。'
    : `最近约 24 小时 ${growthValue == null ? '—' : `${growthValue >= 0 ? '+' : '−'}${bytes(growthValue)}`}（${growth.growth_percent ?? 0}%）`;

  return <section aria-label="数据库增长趋势" className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <h3 className="text-sm font-semibold text-slate-200">数据库增长趋势</h3>
        <p className="mt-1 text-xs text-slate-400">数据库文件 + WAL · 每小时采样 · 保留 {growth.retention_days ?? 45} 天</p>
      </div>
      <span className={`inline-flex rounded-md border px-2 py-1 text-xs ${statusStyle[status] || statusStyle.warming_up}`}>{statusLabels[status] || statusLabels.warming_up}</span>
    </div>
    <div className="mt-4 grid gap-3 sm:grid-cols-3">
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"><p className="text-xs text-slate-500">当前占用</p><p className="mt-1 font-mono text-lg text-sky-200">{bytes(growth.total_bytes)}</p></div>
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"><p className="text-xs text-slate-500">24 小时变化</p><p className="mt-1 font-mono text-lg text-slate-100">{growthValue == null ? '—' : `${growthValue >= 0 ? '+' : '−'}${bytes(growthValue)}`}</p></div>
      <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"><p className="text-xs text-slate-500">最近采样</p><p className="mt-1 text-sm text-slate-200">{date(growth.sampled_at)}</p></div>
    </div>
    <p className="mt-3 text-sm text-slate-300">{description}</p>
    <p className="mt-1 text-xs leading-5 text-slate-500">仅用于运维中心提示，不向客户推送，也不会自动清理数据。警告需同时达到 {bytes(growth.warning_threshold_bytes)} 和 {growth.warning_threshold_percent ?? 10}%；危险需同时达到 {bytes(growth.critical_threshold_bytes)} 和 {growth.critical_threshold_percent ?? 25}%。</p>
    {history.length > 1 ? <>
      <div role="img" aria-label={`最近 ${history.length} 次每小时数据库与 WAL 总占用趋势`} className="mt-4 flex h-24 items-end gap-1 rounded-lg border border-slate-800 bg-slate-950/50 px-2 pt-2">
        {history.map(sample => <div key={sample.ts} title={`${date(sample.ts)} · ${bytes(sample.total_bytes)}`} className="min-w-0 flex-1 rounded-t-sm bg-sky-500/70 hover:bg-sky-300" style={{ height: `${Math.max(4, sample.total_bytes / max * 100)}%` }} />)}
      </div>
      <div className="mt-1 flex justify-between text-[11px] text-slate-500"><span>{date(history[0].ts)}</span><span>{date(history[history.length - 1].ts)}</span></div>
    </> : <p className="mt-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400">采样历史建立中；后台每小时保存一次，不影响容器流量数据。</p>}
  </section>;
}
