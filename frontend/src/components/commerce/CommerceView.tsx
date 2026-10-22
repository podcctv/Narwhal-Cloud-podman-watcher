import { useEffect, useMemo, useRef, useState } from 'react';
import * as echarts from 'echarts';
import { KeyRound, RefreshCw, Server, ShoppingBag, Receipt, AlertTriangle, Trash2, Pencil } from 'lucide-react';
import { request } from '../../api/client';

type Money = string | null;
type Settings = { configured: boolean; updated_at: number; synced_at: number; last_error: string; api_url: string; syncing: boolean };
type Machine = { id: string; name: string; region: string; status: string; sold_current: number; self_current: number; observed_vms: number; vm_count: number | null; buyer_count: number; est_revenue: Money; earned_revenue: Money; locked_value: Money };
type Overview = { available: boolean; synced_at: number; stale: boolean; last_error: string; machines: Machine[]; profile: { available_balance: Money; escrow_balance: Money; escrow_locked_value: Money; escrow_available_balance?: Money; commission_rate: Money } | null; documentation: string };
type RecordRow = { id: string; vm_id?: string; machine_id?: string; machine_name?: string; status?: string; type: string; amount: Money; discount_amount?: Money; balance_type?: string; balance_after?: Money; created_at: number };
type History = { items: RecordRow[]; total: number; totals: { type: string; balance_type: string; count: number; amount: Money; uncompleted: number }[]; trend: { day: string; type: string; count: number }[]; unmapped: number | null };
const labels: Record<string, string> = { purchase: '购买', refund: '退款', renewal: '续费', renew: '续费扣款', push: '转移', escrow_in: '卖家托管入账', escrow_renew: '卖家续费入账', escrow_deduct: '托管扣减', topup: '充值', market_sell: '市场卖出', market_buy: '市场买入', withdrawal: '提现', ip_rent: 'IP 租用', ip_renew: 'IP 续租', compensation: '补偿' };
const label = (kind: string) => labels[kind] || kind;
const kindColors: Record<string, string> = { purchase: '#38bdf8', refund: '#fb7185', renew: '#34d399', renewal: '#34d399', escrow_in: '#a78bfa', escrow_renew: '#c4b5fd', escrow_deduct: '#fbbf24', topup: '#2dd4bf' };
const usd = (value: Money | undefined) => value == null ? '未提供' : new Intl.NumberFormat('zh-CN', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(Number(value));
const date = (value: number) => new Date(value * 1000).toLocaleString('zh-CN', { timeZone: 'UTC', hour12: false });
const panel = 'rounded-2xl border border-slate-800 bg-slate-900/60 p-4 sm:p-6';
const input = 'min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400';
const button = 'min-h-11 rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-sky-400 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50 disabled:cursor-not-allowed';

function Trend({ rows }: { rows: History['trend'] }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || !rows.length) return;
    const chart = echarts.init(target.current);
    const days = [...new Set(rows.map(r => r.day))].sort();
    const kinds = [...new Set(rows.map(r => r.type))];
    const counts = new Map(rows.map(r => [r.day + ':' + r.type, r.count]));
    chart.setOption({ animation: false, backgroundColor: 'transparent', color: ['#38bdf8', '#fb7185', '#34d399', '#fbbf24', '#a78bfa'],
      aria: { enabled: true, label: { description: `UTC 每日记录笔数，共 ${rows.reduce((n, r) => n + r.count, 0)} 笔。${kinds.map(k => `${label(k)} ${rows.filter(r => r.type === k).reduce((n, r) => n + r.count, 0)} 笔`).join('；')}。仅显示有记录日期，详细记录见下方表格。` } }, tooltip: { trigger: 'axis', renderMode: 'richText' },
      legend: { type: 'scroll', textStyle: { color: '#cbd5e1' }, top: 0 },
      grid: { left: 40, right: 15, top: 50, bottom: 35, containLabel: true },
      xAxis: { type: 'category', data: days, axisLabel: { color: '#94a3b8' } },
      yAxis: { type: 'value', min: 0, minInterval: 1, axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#1e293b' } } },
      series: kinds.map(kind => ({ name: label(kind), type: 'bar', stack: 'records', barMaxWidth: 40, itemStyle: { color: kindColors[kind] || '#94a3b8' }, data: days.map(day => counts.get(day + ':' + kind) ?? 0) })),
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(target.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [rows]);
  if (!rows.length) return <p className="py-12 text-center text-sm text-slate-400">当前筛选没有历史记录</p>;
  return <div ref={target} className="h-72 w-full" role="img" aria-label="按 UTC 日期分组的记录笔数；只展示有记录的日期，精确数量见下方类型汇总" />;
}

export function CommerceView() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [editingKey, setEditingKey] = useState(false);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [historyError, setHistoryError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const [ledger, setLedger] = useState(false);
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [machine, setMachine] = useState('');
  const [kind, setKind] = useState('');
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    request<Settings>('/api/v1/commerce/settings', { signal: controller.signal })
      .then(setSettings).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    request<Overview>('/api/v1/commerce/overview', { signal: controller.signal })
      .then(setOverview).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!settings?.syncing || busy) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const state = await request<Settings>('/api/v1/commerce/settings', { signal: controller.signal });
        if (controller.signal.aborted) return;
        setSettings(state);
        if (state.syncing) timer = setTimeout(poll, 2000);
        else { setError(state.last_error); setRevision(r => r + 1); }
      } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : '同步状态读取失败'); }
    };
    timer = setTimeout(poll, 2000);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [settings?.syncing, busy]);

  useEffect(() => {
    setHistory(null); setHistoryError('');
    if (!overview?.available) return;
    if (start && end && start > end) { setHistoryError('开始日期不能晚于结束日期'); return; }
    const controller = new AbortController();
    const query = new URLSearchParams({ ledger: String(ledger), machine, kind, offset: String(offset), limit: '50' });
    if (start) query.set('start', String(Date.parse(start + 'T00:00:00Z') / 1000));
    if (end) query.set('end', String(Date.parse(end + 'T23:59:59Z') / 1000));
    request<History>('/api/v1/commerce/history?' + query, { signal: controller.signal })
      .then(setHistory).catch(e => { if (!controller.signal.aborted) setHistoryError(e.message); });
    return () => controller.abort();
  }, [overview, ledger, start, end, machine, kind, offset]);

  async function act(action: 'save' | 'sync' | 'delete') {
    if (busy) return;
    if (action === 'delete' && !window.confirm('删除当前账号的个人 API Key 和经营数据缓存？不会影响上游资源或全局买家通知。')) return;
    setBusy(action); setError(''); setNotice('');
    let saved = false;
    try {
      if (action === 'save') {
        await request('/api/v1/commerce/settings', { method: 'POST', body: JSON.stringify({ api_key: apiKey.trim() }) });
        saved = true;
        setSettings({ configured: true, updated_at: Math.floor(Date.now()/1000), synced_at: 0, last_error: '', api_url: settings?.api_url || '', syncing: false });
        setEditingKey(false); setApiKey(''); setOverview(null); setHistory(null);
        setNotice('密钥已加密保存，正在同步数据…');
        await synchronize();
        setNotice('个人 API Key 已配置，经营数据已同步');
      } else if (action === 'sync') {
        await synchronize();
        setNotice('已完成同步');
      } else {
        await request('/api/v1/commerce/settings', { method: 'DELETE' });
        setSettings({ configured: false, updated_at: 0, synced_at: 0, last_error: '', api_url: settings?.api_url || '', syncing: false });
        setEditingKey(false); setApiKey(''); setOverview(null); setHistory(null); setNotice('个人密钥和缓存已删除');
      }
    } catch (e) { setNotice(saved ? 'API Key 已保存；数据同步未完成，可直接重试同步，无需重新输入密钥。' : ''); setError(e instanceof Error ? e.message : '操作失败'); }
    finally { setBusy(''); setOffset(0); setRevision(r => r + 1); }
  }

  async function synchronize() {
    await request('/api/v1/commerce/sync', { method: 'POST' });
    for (let n = 0; n < 125; n++) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const state = await request<Settings>('/api/v1/commerce/settings');
      if (!state.syncing) {
        if (state.last_error) throw new Error(state.last_error);
        if (!state.configured || !state.synced_at) throw new Error('同步未完成或密钥已变化，请重试');
        return;
      }
    }
    throw new Error('同步等待超时，请刷新页面检查状态');
  }

  const machines = overview?.machines || [];
  const names = useMemo(() => Object.fromEntries(machines.map(m => [m.id, m.name])), [machines]);
  const totalSold = machines.reduce((n, m) => n + m.sold_current, 0);
  const largest = Math.max(1, ...machines.map(m => m.observed_vms));
  const reset = () => { setStart(''); setEnd(''); setMachine(''); setKind(''); setOffset(0); };

  return <div className="space-y-6 text-slate-200 [&_button]:min-h-11 [&_button]:cursor-pointer">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="text-xl font-bold">经营分析</h2><p className="mt-1 text-sm text-slate-400">个人 Narwhal 账号 · 母鸡出售现状与购买、退款历史</p></div>
      <button className={button + ' flex items-center gap-2'} disabled={!settings?.configured || !!busy || settings.syncing} onClick={() => act('sync')}><RefreshCw className={'h-4 w-4 ' + (busy || settings?.syncing ? 'motion-safe:animate-spin' : '')} />{busy || settings?.syncing ? '正在处理…' : '同步经营数据'}</button>
    </div>
    {error && <p role="alert" className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-4 text-sm text-rose-200">{error}</p>}
    {notice && <p role="status" className="text-sm text-emerald-300">{notice}</p>}
    {settings?.syncing && !busy && <p role="status" className="text-sm text-sky-300">后台同步进行中，完成后自动刷新；离开页面不会取消任务。</p>}
    <section className={panel} aria-labelledby="personal-key-heading">
      <div className="mb-4 flex flex-wrap items-center gap-2"><KeyRound className="h-5 w-5 text-sky-400" /><h3 id="personal-key-heading" className="font-semibold">个人 API Key</h3><span className={settings?.configured ? 'rounded-full border border-emerald-500/40 bg-emerald-950/40 px-2 py-1 text-xs text-emerald-300' : 'text-xs text-slate-400'}>{settings ? settings.configured ? '已保存 · 已加密' : '未配置' : '加载中…'}</span></div>
      {settings?.configured && <div className="mb-4 rounded-xl border border-slate-700 bg-slate-950/60 p-4">
        <label className="block text-sm text-slate-300">已保存的个人 API Key<input className={input + ' mt-2 cursor-default text-slate-400'} type="text" value="••••••••（已安全保存，不显示原文）" readOnly autoComplete="off" /></label>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          {!editingKey && <button type="button" className={button + ' flex items-center gap-2'} disabled={!!busy || settings.syncing} onClick={() => { setApiKey(''); setEditingKey(true); }}><Pencil className="h-4 w-4" />更换 API Key</button>}
          <button type="button" className={button + ' flex items-center gap-2 border-rose-500/60 text-rose-300 hover:border-rose-300'} disabled={!!busy || settings.syncing} onClick={() => act('delete')}><Trash2 className="h-4 w-4" />删除 API Key</button>
          {settings.updated_at > 0 && <span className="text-xs text-slate-400">保存时间：{date(settings.updated_at)} UTC</span>}
        </div>
        <p className="mt-3 text-xs leading-5 text-slate-400">密钥已生效，无需重复输入。仅点击“更换 API Key”时输入新密钥；删除会同时清除当前用户的经营缓存。</p>
      </div>}
      {settings && (!settings.configured || editingKey) && <form onSubmit={e => { e.preventDefault(); act('save'); }} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="min-w-0 flex-1 text-sm text-slate-300" htmlFor="commerce-key">{settings.configured ? '新的个人 API Key' : '配置个人 API Key'}<input id="commerce-key" type="password" autoComplete="off" autoFocus={editingKey} spellCheck={false} maxLength={512} value={apiKey} onChange={e => setApiKey(e.target.value)} className={input + ' mt-2'} placeholder="输入 Narwhal 平台个人 API Key" aria-describedby="key-help" /></label>
        <button type="submit" className={button + ' bg-sky-500 text-slate-950 hover:bg-sky-400'} disabled={!!busy || !apiKey.trim()}>{busy === 'save' ? '校验并保存…' : settings.configured ? '保存新密钥并同步' : '保存并同步'}</button>
        {editingKey && <button type="button" className={button} disabled={!!busy} onClick={() => { setApiKey(''); setEditingKey(false); }}>取消更换</button>}
      </form>}
      <p id="key-help" className="mt-3 text-xs leading-6 text-slate-400">仅用于当前登录用户的数据查询，加密保存在服务端；不修改全局买家通知配置，不执行购买或退款操作。<a className="ml-2 text-sky-300 underline" href="https://api.fuckip.me/openapi.yaml" target="_blank" rel="noreferrer">接口文档</a></p>
    </section>
    {!overview ? <p role="status" className="text-sm text-slate-400">正在加载个人经营数据…</p> : !overview.available ? <div className={panel}><ShoppingBag className="mb-3 h-8 w-8 text-slate-500" /><h3 className="font-semibold">还没有个人经营数据</h3><p className="mt-2 text-sm text-slate-400">{settings?.configured ? '点击“同步经营数据”获取上游数据。' : '配置个人 API Key 后，即可查看母鸡出售现状和账号交易历史。'}</p></div> : <>
      <div className="flex flex-wrap gap-2 text-xs text-slate-400"><span>上次成功同步：{date(overview.synced_at)} UTC</span><span>· 上游快照，非实时财务报表 · USD</span></div>
      {overview.stale && <p role="status" className="flex gap-2 rounded-xl border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-200"><AlertTriangle className="h-5 w-5 shrink-0" />{overview.last_error || '数据已超过 15 分钟，请手动同步获取最新情况。'} 当前仍展示上次成功快照。</p>}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5" aria-label="当前账号快照，不受下方历史筛选影响">
        {[['母鸡 / 当前售出小鸡', `${machines.length} / ${totalSold}`, '售出指当前归属其他用户的小鸡；不是累计销量'], ['可用余额（不可提现）', usd(overview.profile?.available_balance), '用于平台消费，不属于可提现的托管资金'], ['托管总余额', usd(overview.profile?.escrow_balance), '托管可用与冻结金额之和，不等于净利润'], ['托管可用余额', usd(overview.profile?.escrow_available_balance), '托管总余额减去冻结金额；提现以平台规则为准'], ['托管冻结金额', usd(overview.profile?.escrow_locked_value), '尚未解冻，暂不可提现']].map(([title, value, hint]) => <div key={title} role="group" aria-label={title} className={panel}><p className="text-sm text-slate-400">{title}</p><p className="mt-2 wrap-break-word font-mono tabular-nums text-2xl font-semibold text-slate-100">{value}</p><p className="mt-2 text-xs leading-5 text-slate-400">{hint}</p></div>)}
      </section>
      <section className={panel} aria-labelledby="machine-sales-heading">
        <h3 id="machine-sales-heading" className="mb-2 flex items-center gap-2 font-semibold"><Server className="h-5 w-5 text-sky-400" />各母鸡出售现状</h3>
        <p className="mb-4 text-xs leading-6 text-slate-400">当前售出与自用分开计算。收益、冻结值由平台直接提供；已结算收益不含退款、补偿及进行中的冻结值，不与历史订单重复相加。</p>
        {!machines.length ? <p className="py-8 text-center text-sm text-slate-400">当前账号没有母鸡；仍可在下方查看个人购买与退款历史。</p> : <div className="overflow-x-auto"><table className="w-full min-w-[780px] text-left text-sm"><thead className="text-xs text-slate-400"><tr>{['母鸡', '当前小鸡（售出 / 自用）', '买家数', '预估收益 USD', '已结算收益 USD', '冻结值 USD'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr></thead><tbody>{machines.map(m => <tr key={m.id} className="border-t border-slate-800 hover:bg-slate-800/40">
          <td className="max-w-56 px-3 py-4"><button className="text-left text-sky-300 underline decoration-slate-600 underline-offset-4 focus-visible:ring-2 focus-visible:ring-sky-400" onClick={() => { setLedger(false); setMachine(m.id); setOffset(0); }} title={m.id}>{m.name || m.id}</button><p className="mt-1 text-xs text-slate-400">{m.region} · {m.status === 'online' ? '在线' : m.status === 'offline' ? '离线' : m.status}</p></td>
          <td className="min-w-44 px-3 py-4"><p>{m.sold_current} / {m.self_current}</p><div className="mt-2 flex h-2 overflow-hidden rounded-sm bg-slate-800" aria-hidden="true"><span className="bg-sky-400" style={{ width: `${m.sold_current / largest * 100}%` }} /><span className="bg-slate-500" style={{ width: `${m.self_current / largest * 100}%` }} /></div>{m.vm_count != null && m.vm_count !== m.observed_vms && <p className="mt-2 text-xs text-amber-300">平台总数 {m.vm_count}，明细 {m.observed_vms}，可能同步期间有变化</p>}</td>
          <td className="px-3 py-4 font-mono">{m.buyer_count}</td><td className="px-3 py-4 font-mono">{usd(m.est_revenue)}</td><td className="px-3 py-4 font-mono text-emerald-300">{usd(m.earned_revenue)}</td><td className="px-3 py-4 font-mono">{usd(m.locked_value)}</td>
        </tr>)}</tbody></table></div>}
      </section>
      <section className={panel} aria-labelledby="billing-heading">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3"><h3 id="billing-heading" className="flex items-center gap-2 font-semibold"><Receipt className="h-5 w-5 text-sky-400" />购买、退款与账单分析</h3><div className="flex gap-2">{[false, true].map(value => <button key={String(value)} className={button + (ledger === value ? ' border-sky-400 bg-sky-950' : '')} aria-pressed={ledger === value} onClick={() => { setLedger(value); setMachine(''); setKind(''); setOffset(0); }}>{value ? '账单流水' : '订单历史'}</button>)}</div></div>
        <p className="mb-4 text-xs leading-6 text-slate-400">{ledger ? '当前账号账单；金额保留上游正负号，不将不同余额账户混为净利润。有历史母鸡 ID 的流水可按母鸡筛选，其余标为归属未知。' : '当前账号的订单，不等于所有买家的历史订单。优先使用订单中的历史母鸡 ID，否则按小鸡 ID 关联；无法可靠关联时标为归属未知。'}</p>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <label className="text-xs text-slate-400">开始日期（UTC）<input type="date" value={start} onChange={e => { setStart(e.target.value); setOffset(0); }} className={input + ' mt-2'} /></label>
          <label className="text-xs text-slate-400">结束日期（UTC）<input type="date" value={end} onChange={e => { setEnd(e.target.value); setOffset(0); }} className={input + ' mt-2'} /></label>
          <label className="text-xs text-slate-400">订单归属母鸡<select value={machine} onChange={e => { setMachine(e.target.value); setOffset(0); }} className={input + ' mt-2 disabled:opacity-40'}><option value="">全部归属</option><option value="unknown">归属未知</option>{machines.map(m => <option key={m.id} value={m.id}>{m.name || m.id}</option>)}</select></label>
          <label className="text-xs text-slate-400">记录类型<select value={kind} onChange={e => { setKind(e.target.value); setOffset(0); }} className={input + ' mt-2'}><option value="">全部类型</option>{Object.keys(labels).map(k => <option key={k} value={k}>{label(k)}</option>)}</select></label>
          <button className={button + ' self-end'} onClick={reset}>重置历史筛选</button>
        </div>
        {historyError ? <p role="alert" className="mt-4 text-sm text-rose-300">{historyError}</p> : !history ? <p role="status" className="py-12 text-center text-slate-400">正在加载历史记录…</p> : <>
          <div className="my-5 flex flex-wrap gap-3 text-sm"><span>筛选内共 {history.total} 笔</span>{history.unmapped != null && <span className="text-slate-400">· {history.unmapped} 笔归属未知</span>}</div>
          <h4 className="mb-3 text-sm font-medium">每日记录笔数（UTC，仅显示有记录日期）</h4><Trend rows={history.trend} />
          <div className="my-4 flex flex-wrap gap-3">{history.totals.map(t => <div key={t.type + t.balance_type} className="rounded-xl border border-slate-800 px-4 py-3 text-sm"><span className="text-slate-300">{label(t.type)}{t.balance_type ? ` / ${t.balance_type === 'escrow' ? '托管' : t.balance_type === 'available' ? '可用' : t.balance_type}` : ''} · {t.count} 笔</span><p className="mt-1 font-mono">{usd(t.amount)}</p>{t.uncompleted > 0 && <p className="mt-1 text-xs text-amber-300">{t.uncompleted} 笔未完成或状态未知，未计入金额</p>}</div>)}</div>
          <p className="mb-3 text-xs text-slate-400">以上金额按记录类型和余额账户独立求和；订单仅累计 completed 状态；不合算为收入或净利润。缺失金额显示“未提供”，不按零处理。</p>
          <div className="overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="text-xs text-slate-400"><tr>{['时间 UTC', '类型', '金额 USD', ledger ? '余额账户 / 变动后余额' : '母鸡归属', '记录 / 小鸡 ID'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr></thead><tbody>{history.items.map(r => <tr key={r.id} className="border-t border-slate-800 hover:bg-slate-800/40"><td className="whitespace-nowrap px-3 py-3">{date(r.created_at)}</td><td className="px-3 py-3">{label(r.type)}{r.status && <p className="mt-1 text-xs text-slate-400">{r.status === 'completed' ? '已完成' : r.status}</p>}</td><td className="whitespace-nowrap px-3 py-3 font-mono">{usd(r.amount)}</td><td className="max-w-56 wrap-break-word px-3 py-3">{ledger ? `${r.balance_type === 'escrow' ? '托管' : r.balance_type === 'available' ? '可用' : r.balance_type} / ${usd(r.balance_after)}` : r.machine_id ? r.machine_name || names[r.machine_id] || r.machine_id : '归属未知'}{ledger && <p className="mt-1 text-xs text-slate-400">{r.machine_name || (r.machine_id ? names[r.machine_id] || r.machine_id : '归属未知')}</p>}</td><td className="px-3 py-3 font-mono text-xs"><p>{r.id}</p>{r.vm_id && <p className="mt-1 text-slate-400">VM {r.vm_id}</p>}</td></tr>)}</tbody></table>{!history.total && <p className="py-8 text-center text-sm text-slate-400">当前筛选没有记录</p>}</div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-slate-400"><span>{history.total ? `${offset + 1}–${Math.min(offset + 50, history.total)} / ${history.total}` : '0 条记录'}</span><div className="flex gap-3"><button className={button} disabled={!offset} onClick={() => setOffset(n => Math.max(0, n - 50))}>上一页</button><button className={button} disabled={offset + 50 >= history.total} onClick={() => setOffset(n => n + 50)}>下一页</button></div></div>
        </>}
      </section>
    </>}
  </div>;
}
