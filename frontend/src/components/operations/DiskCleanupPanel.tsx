import { useCallback, useEffect, useState } from 'react';
import { HardDrive, RefreshCw, ScanSearch, Trash2, ShieldCheck, LoaderCircle } from 'lucide-react';
import { fmtBytes, request } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { ToastMessage } from '../common/Toast';

type Policy = { enabled: boolean; include_containers: boolean; retention_days: number; interval_hours: number };
type Item = { runtime: string; name: string; status: string; candidate_files?: number; candidate_bytes?: number; deleted_files?: number; unlinked_bytes?: number; freed_bytes?: number; skipped?: number; errors?: number; bounded?: boolean; before?: { used_percent: number }; after?: { used_percent: number }; reason?: string };
type Run = { run_id: string; node_id: string; host_id: string; mode: string; status: string; automatic: boolean; started_at: number; finished_at?: number; items: Item[] };
type Host = { host_id: string; node_id: string; available: boolean; stale: boolean; running: boolean; disk: { used_percent?: number; available_bytes?: number }; policy: Policy };
type Data = { hosts: Host[]; runs: Run[]; actions: { id: number; host_id: string; status: string; result_message: string; updated_at: number }[] };
const defaults: Policy = { enabled: false, include_containers: true, retention_days: 14, interval_hours: 24 };
const field = 'w-full min-w-0 rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400';
const button = 'inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm text-sky-200 hover:bg-sky-500/20 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-50';
const labels: Record<string, string> = { running: '执行中', scanned: '扫描完成 · 未删除', succeeded: '清理完成', partial: '部分完成 / 有跳过项', failed: '失败', interrupted: '中断 · 未自动重试', skipped: '已跳过', queued: '已排队', dispatched: '已下发' };
const date = (n: number) => new Date(n * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });

export function DiskCleanupPanel({ admin, paused, onToast }: { admin: boolean; paused: boolean; onToast: (type: ToastMessage['type'], message: string) => void }) {
  const [data, setData] = useState<Data>({ hosts: [], runs: [], actions: [] });
  const [selected, setSelected] = useState('');
  const [draft, setDraft] = useState<Policy>(defaults);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [confirm, setConfirm] = useState<{ title: string; description: string; execute: () => Promise<unknown> } | null>(null);
  const load = useCallback(async () => {
    const next = await request<Data>('/api/v1/ops/disk-cleanup');
    setData(next); setLoaded(true); setError('');
  }, []);
  useEffect(() => {
    let alive = true;
    const refresh = () => { void load().catch(e => { if (alive) setError(e instanceof Error ? e.message : String(e)); }); };
    refresh();
    const timer = setInterval(() => { if (!paused && !document.hidden) refresh(); }, 10000);
    return () => { alive = false; clearInterval(timer); };
  }, [load, paused]);
  const host = data.hosts.find(h => h.node_id === selected);
  const runs = data.runs.filter(r => r.node_id === selected);
  const plan = runs.find(r => r.mode === 'scan' && ['scanned', 'partial'].includes(r.status) && r.items.some(i => i.status === 'scanned') && Date.now() / 1000 - r.started_at <= 900);
  const pending = host && data.actions.some(a => a.host_id === host.host_id && ['queued', 'dispatched', 'running'].includes(a.status) && Date.now() / 1000 - a.updated_at < 900);
  const unavailable = !admin || !host || host.stale || !host.available || busy;
  const post = (operation: string, payload: Record<string, unknown> = {}) => request(`/api/v1/ops/disk-cleanup/${operation}`, { method: 'POST', body: JSON.stringify({ host_id: host?.host_id, node_id: host?.node_id, ...payload }) });
  const act = async (operation: () => Promise<unknown>, message: string) => {
    setBusy(true);
    try { await operation(); onToast('success', message); await load(); setConfirm(null); }
    catch (e) { onToast('error', e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };
  return <section aria-label="安全磁盘清理" className="space-y-4 rounded-xl border border-slate-700 bg-slate-900/80 p-4 tabular-nums sm:p-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="flex items-center gap-2 font-semibold text-slate-100"><HardDrive className="h-5 w-5 text-sky-400" />宿主机与容器 · 安全磁盘清理</h3><button type="button" className={button} disabled={busy} onClick={() => void act(load, '清理状态已刷新')}><RefreshCw className="h-4 w-4" />刷新状态</button></div>
    <p className="flex items-start gap-2 text-sm leading-relaxed text-slate-300"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /><span>默认关闭自动删除。仅清理下载包缓存、过期归档日志和崩溃文件；不截断活动日志，不删除容器、镜像、卷、数据库、备份、独立认证/审计日志或取证记录。journal 归档也按日志保留期限处理。不可恢复删除前请检查保留期限。</span></p>
    {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
    {!loaded && !error && <p role="status" className="text-sm text-slate-300">正在读取磁盘清理状态…</p>}
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{data.hosts.map(h => <button type="button" key={h.node_id || h.host_id} onClick={() => { setSelected(h.node_id); setDraft({ ...defaults, ...h.policy }); }} className={`min-h-20 min-w-0 rounded-lg border p-3 text-left focus:outline-none focus:ring-2 focus:ring-sky-400 ${selected === h.node_id ? 'border-sky-400 bg-sky-950/30' : 'border-slate-700 bg-slate-950/50'}`} aria-pressed={selected === h.node_id}>
      <span className="block break-words text-sm font-semibold text-slate-100">{h.host_id}</span>
      <span className={`mt-2 block text-xs ${h.stale ? 'text-slate-300' : (h.disk.used_percent || 0) >= 90 ? 'text-amber-200' : 'text-slate-300'}`}>{h.stale ? '节点采样过期' : h.disk.used_percent == null ? '磁盘尚未上报' : `磁盘 ${h.disk.used_percent.toFixed(1)}% · 可用 ${fmtBytes(h.disk.available_bytes || 0)}`}{!h.stale && (h.disk.used_percent || 0) >= 90 && ' · 空间不足'}</span>
      <span className="mt-2 block text-xs text-slate-300">{h.available ? h.policy.enabled ? '自动清理已配置' : '自动清理关闭' : '需要新版原生宿主机 Agent'}{h.running && ' · 节点执行中'}</span>
    </button>)}</div>
    {loaded && !data.hosts.length && <p className="text-sm text-slate-300">暂无宿主机报告。</p>}
    {!admin && <p className="text-sm text-amber-200">当前账号仅可查看，清理和自动策略需管理员操作。</p>}
    {host && <div className="space-y-4 border-t border-slate-700 pt-4">
      <h4 className="break-words text-sm font-semibold">配置目标：{host.host_id}</h4>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="flex min-h-11 items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={draft.enabled} disabled={unavailable} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />启用自动清理</label>
        <label className="flex min-h-11 items-center gap-2 text-sm text-slate-200"><input type="checkbox" checked={draft.include_containers} disabled={unavailable} onChange={e => setDraft({ ...draft, include_containers: e.target.checked })} />包含 Incus / Podman 容器</label>
        <label className="text-sm text-slate-300">归档日志保留天数<input type="number" min="14" max="90" className={`${field} mt-1`} disabled={unavailable} value={draft.retention_days} onChange={e => setDraft({ ...draft, retention_days: Number(e.target.value) })} /></label>
        <label className="text-sm text-slate-300">每个目标的清理间隔（小时）<input type="number" min="6" max="168" className={`${field} mt-1`} disabled={unavailable} value={draft.interval_hours} onChange={e => setDraft({ ...draft, interval_hours: Number(e.target.value) })} /></label>
      </div>
      <p className="text-xs leading-relaxed text-slate-300">自动清理分批轮转本机及所有受监测的 Incus / Podman 容器，新容器自动纳入。每轮最多 5 个目标、1,000 个文件、512 MiB；包缓存至少保留 1 天。绑定挂载、活动文件和隔离取证中的容器跳过，Docker 不自动处理。配置需等节点下一次轮询确认；本页时间均为北京时间。</p>
      <div className="flex flex-wrap gap-3">
        <button type="button" className={button} disabled={unavailable} onClick={() => setConfirm({ title: draft.enabled ? '启用自动磁盘清理' : '保存磁盘清理策略', description: `${host.host_id}：${draft.enabled ? `自动删除超过保留期限的允许清理文件；归档日志保留 ${draft.retention_days} 天，每个目标间隔 ${draft.interval_hours} 小时。删除不可恢复。` : '关闭自动删除，不会立即清理任何文件。'} ${draft.include_containers ? '包含 Incus / Podman 容器。' : '仅宿主机。'}`, execute: () => post('policy', { policy: { enabled: draft.enabled, include_containers: draft.include_containers, retention_days: draft.retention_days, interval_hours: draft.interval_hours }, confirmed: true }) })}>保存策略</button>
        <button type="button" className={button} disabled={unavailable || !!pending || host.running} onClick={() => void act(() => post('scan'), '只读扫描已排队，请等待 Agent 扫描结果')}><ScanSearch className="h-4 w-4" />扫描预览（不删除）</button>
        <button type="button" className={`${button} border-rose-500/50 text-rose-200`} disabled={unavailable || !!pending || host.running || !plan} onClick={() => plan && setConfirm({ title: '执行已预览的安全清理', description: `${host.host_id}：扫描 ${plan.run_id} 中可安全处理的目标，预计可移除文件占用 ${fmtBytes(plan.items.filter(i => i.status === 'scanned').reduce((n, i) => n + (i.candidate_bytes || 0), 0))}。仅处理安全完成扫描的目标，其他目标跳过。执行时会重新检查实例及文件身份；删除不可恢复。`, execute: () => post('execute', { plan_id: plan.run_id, confirmed: true }) })}><Trash2 className="h-4 w-4" />确认清理本次扫描</button>
        {pending && <span role="status" className="inline-flex items-center gap-2 text-sm text-sky-200"><LoaderCircle className="h-4 w-4 animate-spin motion-reduce:animate-none" />任务排队或执行中，不代表已释放空间</span>}
      </div>
      {!plan && <p className="text-xs text-slate-300">手动清理需先完成 15 分钟内的扫描。手动扫描每轮为宿主机及最多 4 个容器；自动模式会轮转所有容器。</p>}
      {runs.slice(0, 20).map(r => <div key={r.run_id} className="space-y-2 rounded-lg border border-slate-700 bg-slate-950/50 p-3">
        <div className="flex flex-wrap justify-between gap-2 text-sm"><span>{r.automatic ? '自动' : '手动'}{r.mode === 'scan' ? '扫描' : '清理'} · {date(r.started_at)}</span><span className={['failed', 'interrupted', 'partial'].includes(r.status) ? 'text-amber-200' : 'text-sky-200'}>{labels[r.status] || r.status}</span></div>
        {r.items.map((i, n) => <div key={`${i.runtime}/${i.name}/${n}`} className="border-t border-slate-800 pt-2 text-xs text-slate-300"><p className="break-words">{i.runtime === 'host' ? '宿主机' : `${i.runtime} / ${i.name}`} · {labels[i.status] || i.status}</p><p className="mt-1">候选 {i.candidate_files || 0} 文件 / {fmtBytes(i.candidate_bytes || 0)} · 已删除 {i.deleted_files || 0} 文件 / {fmtBytes(i.unlinked_bytes || 0)} · 跳过 {i.skipped || 0} · 错误 {i.errors || 0}</p>{i.after && <p className={`mt-1 ${i.after.used_percent >= 90 ? 'text-amber-200' : ''}`}>{r.mode === 'scan' ? `当前磁盘 ${i.after.used_percent.toFixed(1)}% · 只读扫描，未删除文件` : `磁盘 ${i.before?.used_percent.toFixed(1)}% → ${i.after.used_percent.toFixed(1)}%；可用空间增加 ${fmtBytes(i.freed_bytes || 0)}（含同期业务写入变化）`}{i.after.used_percent >= 90 && ` · ${r.mode === 'clean' ? '清理后仍' : '当前仍'}达到 90%，请人工检查业务占用`}</p>}{i.status === 'skipped' && <p className="mt-1 text-amber-200">身份、挂载、证据保留或文件系统检查不可用，未清理此目标。</p>}{i.bounded && <p className="mt-1 text-amber-200">已达到本轮预算；未扩大删除范围，后续轮次继续检查。</p>}</div>)}
      </div>)}
      {!runs.length && <p className="text-sm text-slate-300">暂无清理记录。先执行只读扫描，查看可处理范围。</p>}
      {data.actions.filter(a => a.host_id === host.host_id && a.status === 'failed').slice(0, 3).map(a => <p key={a.id} role="status" className="break-words text-xs text-amber-200">任务 #{a.id} 失败：{a.result_message || '等待详细结果'}</p>)}
    </div>}
    <ConfirmDialog open={!!confirm} title={confirm?.title || ''} description={confirm?.description || ''} confirmLabel="确认" isSubmitting={busy} onCancel={() => !busy && setConfirm(null)} onConfirm={() => confirm && void act(confirm.execute, '已提交，请等待节点确认与实际结果')} />
  </section>;
}
