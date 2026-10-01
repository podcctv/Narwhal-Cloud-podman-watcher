import { useCallback, useEffect, useState } from 'react';
import { BellRing, RefreshCw, Save, Send } from 'lucide-react';
import { api, request } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { ToastMessage } from '../common/Toast';

type Target = { host_id: string; runtime: string; project: string; container_name: string; machine_id: string; user_id: string; node_name: string; scope: 'user' | 'machine'; enabled: boolean | number };
type RecordItem = Target & { id: number; state: string; status: string; subject: string; message: string; last_error: string; attempts: number; due_at: number; machine_next_at: number; created_at: number; http_status: number };
type Data = { items: RecordItem[]; counts: Record<string, number>; targets: Target[]; hosts: Target[] };
const EMPTY: Target = { host_id: '', runtime: '', project: '', container_name: '', machine_id: '', user_id: '', node_name: '', scope: 'user', enabled: true };
const LABELS: Record<string, string> = { blocked: '缺收件映射', queued: '待发送', retrying: '等待重试', sending: '发送中', succeeded: '成功', failed: '失败', uncertain: '结果不确定', cancelled: '状态变化已取消', expired: '已过期' };
const stamp = (t: number) => t ? new Date(t * 1000).toLocaleString('zh-CN') : '—';
const identity = (t: Target) => JSON.stringify([t.host_id, t.runtime, t.project, t.container_name]);
const field = 'min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 p-2 text-sm text-slate-100';

export function BuyerNotificationsView({ onToast }: { onToast: (type: ToastMessage['type'], message: string) => void }) {
  const [data, setData] = useState<Data>({ items: [], counts: {}, targets: [], hosts: [] });
  const [form, setForm] = useState<Target>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{ subject?: string; body?: string; audience?: string } | null>(null);
  const [confirmation, setConfirmation] = useState<'target' | 'test' | RecordItem | null>(null);
  const load = useCallback(async () => {
    try { setData(await request<Data>('/api/v1/buyer/records')); setError(''); }
    catch (e: any) { setError(e.message); }
  }, []);
  useEffect(() => { void load(); const timer = setInterval(() => { if (!document.hidden) void load(); }, 10000); return () => clearInterval(timer); }, [load]);
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    try { await work(); await load(); }
    catch (e: any) { onToast('error', e.message); }
    finally { setBusy(false); setConfirmation(null); }
  };
  const save = () => run(async () => {
    await request('/api/v1/buyer/targets', { method: 'POST', body: JSON.stringify({ ...form, enabled: Boolean(form.enabled), confirm_broadcast: form.scope === 'machine' }) });
    onToast('success', '精确收件映射已保存；不会发送测试通知');
  });
  const testPayload = () => ({ narwhal_machine_id: form.machine_id, narwhal_node_name: form.node_name, user_id: form.user_id, scope: form.scope });
  const makePreview = () => run(async () => { const p = await api.testPushSettings(testPayload()); setPreview(p); });
  const accept = () => {
    if (confirmation === 'target') return save();
    if (confirmation === 'test') return run(async () => {
      const r = await api.testPushSettings({ ...testPayload(), send: true, confirm_audience: preview?.audience, confirm_broadcast: form.scope === 'machine' });
      onToast(r.ok ? 'success' : 'error', r.message);
      setPreview(null);
    });
    if (confirmation) { const row = confirmation; return run(async () => { await request(`/api/v1/buyer/records/${row.id}/retry`, { method: 'POST', body: JSON.stringify({ confirm_duplicate_risk: true }) }); onToast('success', '已排队；不会绕过机器冷却期'); }); }
  };
  const change = (value: Partial<Target>) => { setForm(old => ({ ...old, ...value })); setPreview(null); };
  return <section className="min-w-0 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="flex items-center gap-2 font-semibold text-slate-100"><BellRing className="h-5 w-5 text-sky-400" />买家推送记录与收件范围</h3><p className="mt-1 text-xs text-slate-400">仅服务端发送；持久队列、机器级冷却、七天投递期限、九十天记录保留。</p></div><button onClick={load} className="min-h-11 rounded-lg border border-slate-700 px-3"><RefreshCw className="h-4 w-4" /></button></div>
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
    <div className="flex flex-wrap gap-2">{Object.entries(data.counts).map(([status, count]) => <span key={status} className="rounded-lg bg-slate-950 px-3 py-2 text-xs text-slate-300 tabular-nums">{LABELS[status] || status} {count}</span>)}</div>
    <form onSubmit={e => { e.preventDefault(); form.scope === 'machine' ? setConfirmation('target') : void save(); }} className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      <label className="text-xs text-slate-300">精确容器身份<select required value={identity(form)} onChange={e => { const t = data.hosts.find(t => identity(t) === e.target.value); if (t) { const saved = data.targets.find(s => identity(s) === identity(t)); setForm(saved ? { ...saved, enabled: Boolean(saved.enabled) } : { ...EMPTY, ...t }); setPreview(null); } }} className={field}><option value={identity(EMPTY)}>选择主机 / 运行时 / 项目 / 容器</option>{data.hosts.map(t => <option key={identity(t)} value={identity(t)}>{t.host_id} / {t.runtime} / {t.project} / {t.container_name}</option>)}</select></label>
      <label className="text-xs text-slate-300">托管机器 UUID<input required value={form.machine_id} onChange={e => change({ machine_id: e.target.value })} className={field} /></label>
      <label className="text-xs text-slate-300">通知范围<select value={form.scope} onChange={e => change({ scope: e.target.value as Target['scope'] })} className={field}><option value="user">仅指定买家（推荐）</option><option value="machine">整机全部买家（广播）</option></select></label>
      <label className="text-xs text-slate-300">买家 user_id<input required={form.scope === 'user'} disabled={form.scope !== 'user'} value={form.user_id} onChange={e => change({ user_id: e.target.value })} className={field} /></label>
      <label className="text-xs text-slate-300">节点显示名称<input value={form.node_name} onChange={e => change({ node_name: e.target.value })} className={field} /></label>
      <label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={Boolean(form.enabled)} onChange={e => change({ enabled: e.target.checked })} />启用此映射</label>
      <div className="flex flex-wrap gap-2 md:col-span-2 xl:col-span-3"><button disabled={busy || !form.host_id} className="min-h-11 rounded-lg bg-sky-500 px-4 text-slate-950 flex items-center gap-2 disabled:opacity-50"><Save className="h-4 w-4" />保存映射</button><button type="button" disabled={busy} onClick={makePreview} className="min-h-11 rounded-lg border border-slate-700 px-4 disabled:opacity-50">预览测试（不发送）</button></div>
    </form>
    {preview && <div className="rounded-xl border border-amber-700 bg-amber-950/30 p-4 text-sm break-words"><p className="text-amber-200">{preview.audience}</p><p className="mt-2 text-slate-200">{preview.subject}</p><p className="text-slate-300">{preview.body}</p><button disabled={busy} onClick={() => setConfirmation('test')} className="mt-3 min-h-11 rounded-lg border border-amber-600 px-3 text-amber-200 flex items-center gap-2"><Send className="h-4 w-4" />确认范围后真实测试</button></div>}
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">{data.items.map(r => <article key={r.id} className="min-w-0 rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-300 break-words">
      <div className="flex flex-wrap justify-between gap-2"><strong className="text-sm text-slate-100">{r.subject}</strong><span className={r.status === 'succeeded' ? 'text-emerald-300' : ['failed', 'uncertain'].includes(r.status) ? 'text-red-300' : 'text-amber-300'}>{LABELS[r.status] || r.status}</span></div>
      <p className="mt-2">#{r.id} · {r.host_id} / {r.runtime} / {r.project} / {r.container_name}</p><p>收件：{r.machine_id || '未映射'} / {r.scope === 'machine' ? '整机全部买家' : r.user_id || '未映射'}</p>
      <p className="tabular-nums">创建 {stamp(r.created_at)} · 尝试 {r.attempts} 次 · HTTP {r.http_status || '—'}</p>{['queued', 'retrying', 'blocked'].includes(r.status) && <p>最早下次尝试 {stamp(Math.max(r.due_at, r.machine_next_at))}</p>}
      {r.last_error && <p className="mt-2 text-red-300">{r.last_error}</p>}<details className="mt-2"><summary className="min-h-8 cursor-pointer text-sky-300">查看通知内容</summary><p className="whitespace-pre-wrap">{r.message}</p></details>
      {['failed', 'uncertain', 'blocked'].includes(r.status) && r.state !== 'test' && <button disabled={busy} onClick={() => setConfirmation(r)} className="mt-2 min-h-11 rounded-lg border border-slate-700 px-3">受控补发</button>}
    </article>)}</div>
    {!data.items.length && <p className="text-sm text-slate-400">尚无投递记录。不会补发升级前的历史恢复消息。</p>}
    <ConfirmDialog open={Boolean(confirmation)} title={confirmation === 'target' ? '确认整机买家广播' : confirmation === 'test' ? '发送真实测试通知' : '确认补发风险'} description={confirmation === 'target' ? `该容器事件将发送给机器 ${form.machine_id} 的全部买家。` : confirmation === 'test' ? `${preview?.audience}。将发送真实通知并占用机器冷却额度。` : '网络失败可能发生在上游已接收之后；补发可能重复。请先核对上游记录。'} confirmLabel="确认" isSubmitting={busy} onCancel={() => setConfirmation(null)} onConfirm={accept} />
  </section>;
}
