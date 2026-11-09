import { useEffect, useMemo, useRef, useState } from 'react';
import * as echarts from 'echarts/core';
import { BarChart, LineChart } from 'echarts/charts';
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import {
  KeyRound, RefreshCw, Server, ShoppingBag, Receipt, AlertTriangle, Trash2, Pencil,
  Calendar, ShieldAlert, Award, Ban, Bell, CheckCircle2, Gift,
  DollarSign, Users, X, Send
} from 'lucide-react';
import { request } from '../../api/client';
import type {
  CommerceAutoSyncSettings, DailyAnalyticsResponse, MonthlyAnalyticsItem,
  RiskAnalysisResponse, LoyaltyUserItem, BlockedUserItem, BlockedUsersResponse
} from '../../api/types';

echarts.use([BarChart, LineChart, AriaComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

type Money = string | null;
type Settings = { configured: boolean; updated_at: number; synced_at: number; last_error: string; api_url: string; syncing: boolean };
type Machine = { id: string; name: string; region: string; status: string; sold_current: number; self_current: number; observed_vms: number; vm_count: number | null; buyer_count: number; est_revenue: Money; earned_revenue: Money; locked_value: Money };
type Overview = { available: boolean; synced_at: number; stale: boolean; last_error: string; machines: Machine[]; profile: { available_balance: Money; escrow_balance: Money; escrow_locked_value: Money; escrow_available_balance?: Money; commission_rate: Money } | null; documentation: string };
type RecordRow = { id: string; vm_id?: string; machine_id?: string; machine_name?: string; status?: string; type: string; amount: Money; discount_amount?: Money; balance_type?: string; balance_after?: Money; created_at: number };
type History = { items: RecordRow[]; total: number; totals: { type: string; balance_type: string; count: number; amount: Money; uncompleted: number }[]; trend: { day: string; type: string; count: number }[]; unmapped: number | null };

const labels: Record<string, string> = { purchase: '购买', refund: '退款', renewal: '续费', renew: '续费扣款', push: '转移', escrow_in: '卖家托管入账', escrow_renew: '卖家续费入账', escrow_deduct: '托管扣减', topup: '充值', market_sell: '市场卖出', market_buy: '市场买入', withdrawal: '提现', ip_rent: 'IP 租用', ip_renew: 'IP 续租', compensation: '补偿' };
const label = (kind: string) => labels[kind] || kind;
const kindColors: Record<string, string> = { purchase: '#38bdf8', refund: '#fb7185', renew: '#34d399', renewal: '#34d399', escrow_in: '#a78bfa', escrow_renew: '#c4b5fd', escrow_deduct: '#fbbf24', topup: '#2dd4bf' };
const usd = (value: Money | number | undefined) => value == null ? '未提供' : new Intl.NumberFormat('zh-CN', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(Number(value));
const date = (value: number) => new Date(value * 1000).toLocaleString('zh-CN', { timeZone: 'UTC', hour12: false });
const panel = 'ui-surface-card p-4 sm:p-6';
const input = 'ui-input';
const button = 'min-h-11 rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-sky-400/70 hover:bg-slate-800 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50 disabled:cursor-not-allowed';

function Trend({ rows }: { rows: History['trend'] }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || !rows.length) return;
    const chart = echarts.init(target.current);
    const days = [...new Set(rows.map(r => r.day))].sort();
    const kinds = [...new Set(rows.map(r => r.type))];
    const counts = new Map(rows.map(r => [r.day + ':' + r.type, r.count]));
    chart.setOption({
      animation: false, backgroundColor: 'transparent', color: ['#38bdf8', '#fb7185', '#34d399', '#fbbf24', '#a78bfa'],
      aria: { enabled: true, label: { description: `UTC 每日记录笔数，共 ${rows.reduce((n, r) => n + r.count, 0)} 笔。` } },
      tooltip: { trigger: 'axis', renderMode: 'richText' },
      legend: { type: 'scroll', textStyle: { color: '#cbd5e1' }, top: 0 },
      grid: { left: 40, right: 15, top: 50, bottom: 35, containLabel: true },
      xAxis: { type: 'category', data: days, axisLabel: { color: '#94a3b8' } },
      yAxis: { type: 'value', min: 0, minInterval: 1, axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#1e293b' } } },
      series: kinds.map(kind => ({
        name: label(kind), type: 'bar', stack: 'records', barMaxWidth: 40,
        itemStyle: { color: kindColors[kind] || '#94a3b8' },
        data: days.map(day => counts.get(day + ':' + kind) ?? 0)
      })),
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(target.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [rows]);
  if (!rows.length) return <p className="py-12 text-center text-sm text-slate-400">当前筛选没有历史记录</p>;
  return <div ref={target} className="h-72 w-full overflow-hidden" role="img" aria-label="按 UTC 日期分组的记录笔数" />;
}

function DailyRevenueChart({ items }: { items: DailyAnalyticsResponse['daily'] }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || !items.length) return;
    const chart = echarts.init(target.current);
    const sorted = [...items].reverse();
    const dates = sorted.map(i => i.date);
    const gmvs = sorted.map(i => Number(i.orders_amount));
    const refunds = sorted.map(i => Number(i.refunds_amount));
    const nets = sorted.map(i => Number(i.net_revenue));

    chart.setOption({
      animation: false, backgroundColor: 'transparent',
      tooltip: { trigger: 'axis', renderMode: 'richText' },
      legend: { textStyle: { color: '#cbd5e1' }, top: 0, data: ['总销售额(GMV)', '退款支出', '净收益'] },
      grid: { left: 50, right: 20, top: 45, bottom: 35, containLabel: true },
      xAxis: { type: 'category', data: dates, axisLabel: { color: '#94a3b8', rotate: dates.length > 10 ? 30 : 0 } },
      yAxis: { type: 'value', axisLabel: { color: '#94a3b8' }, splitLine: { lineStyle: { color: '#1e293b' } } },
      series: [
        { name: '总销售额(GMV)', type: 'bar', data: gmvs, itemStyle: { color: '#38bdf8' }, barMaxWidth: 24 },
        { name: '退款支出', type: 'bar', data: refunds, itemStyle: { color: '#fb7185' }, barMaxWidth: 24 },
        { name: '净收益', type: 'line', data: nets, itemStyle: { color: '#34d399' }, lineStyle: { width: 3 } }
      ]
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(target.current);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [items]);
  if (!items.length) return <p className="py-12 text-center text-sm text-slate-400">暂无日度统计数据</p>;
  return <div ref={target} className="h-72 w-full overflow-hidden" />;
}

export function CommerceView() {
  const [tab, setTab] = useState<'overview' | 'analytics' | 'risk' | 'loyalty' | 'blocklist' | 'settings'>('overview');
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

  // New modules state
  const [dailyData, setDailyData] = useState<DailyAnalyticsResponse | null>(null);
  const [monthlyData, setMonthlyData] = useState<MonthlyAnalyticsItem[] | null>(null);
  const [riskData, setRiskData] = useState<RiskAnalysisResponse | null>(null);
  const [loyaltyData, setLoyaltyData] = useState<LoyaltyUserItem[] | null>(null);
  const [blockedUsers, setBlockedUsers] = useState<BlockedUserItem[]>([]);
  const [autoSyncSettings, setAutoSyncSettings] = useState<CommerceAutoSyncSettings | null>(null);

  // Modals state
  const [compensateModal, setCompensateModal] = useState<{
    open: boolean; vm_id: string; user_name: string; machine_name: string; price_monthly: string | null; days: number; busy: boolean; error: string; success: string;
  }>({ open: false, vm_id: '', user_name: '', machine_name: '', price_monthly: null, days: 3, busy: false, error: '', success: '' });

  const [blockModal, setBlockModal] = useState<{
    open: boolean; vm_id: string; user_name: string; reason: string; busy: boolean; error: string; success: string;
  }>({ open: false, vm_id: '', user_name: '', reason: '频繁买退 / 恶意占用资源', busy: false, error: '', success: '' });

  useEffect(() => {
    const controller = new AbortController();
    request<Settings>('/api/v1/commerce/settings', { signal: controller.signal })
      .then(setSettings).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    request<Overview>('/api/v1/commerce/overview', { signal: controller.signal })
      .then(setOverview).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    request<CommerceAutoSyncSettings>('/api/v1/commerce/notification-settings', { signal: controller.signal })
      .then(setAutoSyncSettings).catch(() => {});
    return () => controller.abort();
  }, [revision]);

  // Load module data when switching tabs
  useEffect(() => {
    if (!overview?.available) return;
    const controller = new AbortController();
    if (tab === 'analytics') {
      request<DailyAnalyticsResponse>('/api/v1/commerce/daily-analytics?days=30', { signal: controller.signal })
        .then(setDailyData).catch(() => {});
      request<MonthlyAnalyticsItem[]>('/api/v1/commerce/monthly-analytics?months=12', { signal: controller.signal })
        .then(setMonthlyData).catch(() => {});
    } else if (tab === 'risk') {
      request<RiskAnalysisResponse>('/api/v1/commerce/risk-analysis', { signal: controller.signal })
        .then(setRiskData).catch(() => {});
    } else if (tab === 'loyalty') {
      request<LoyaltyUserItem[]>('/api/v1/commerce/loyalty-users', { signal: controller.signal })
        .then(setLoyaltyData).catch(() => {});
    } else if (tab === 'blocklist') {
      request<BlockedUsersResponse>('/api/v1/commerce/blocked-users', { signal: controller.signal })
        .then(res => setBlockedUsers(res.items || [])).catch(() => {});
    }
    return () => controller.abort();
  }, [tab, overview, revision]);

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

  // Periodic check to silently update UI when background auto-sync completes
  useEffect(() => {
    if (!settings?.configured || busy) return;
    const interval = setInterval(async () => {
      try {
        const state = await request<Settings>('/api/v1/commerce/settings');
        if (state.synced_at && state.synced_at !== settings.synced_at) {
          setRevision(r => r + 1);
        }
      } catch {}
    }, 30000);
    return () => clearInterval(interval);
  }, [settings?.configured, settings?.synced_at, busy]);

  // Auto-sync on page entry if snapshot is stale or older than 5 minutes
  const entrySyncTriggered = useRef(false);
  useEffect(() => {
    if (!overview || entrySyncTriggered.current) return;
    if (!settings?.configured || settings?.syncing || busy) return;
    const age = Math.floor(Date.now() / 1000) - (overview.synced_at || 0);
    if (overview.stale || age >= 300 || !overview.available) {
      entrySyncTriggered.current = true;
      request<{ ok: boolean; syncing: boolean }>('/api/v1/commerce/sync', { method: 'POST' })
        .then(() => {
          setSettings(prev => prev ? { ...prev, syncing: true } : prev);
        })
        .catch(() => {
          // If a sync is already running in background, that's fine
        });
    }
  }, [overview, settings?.configured, settings?.syncing, busy]);

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

  async function executeCompensate() {
    if (compensateModal.busy) return;
    setCompensateModal(m => ({ ...m, busy: true, error: '', success: '' }));
    try {
      await request('/api/v1/commerce/compensate', {
        method: 'POST',
        body: JSON.stringify({ vm_id: compensateModal.vm_id, days: compensateModal.days })
      });
      setCompensateModal(m => ({ ...m, busy: false, success: `已成功为小鸡赠送 ${m.days} 天可用时长！上游已自动延长 expires_at。` }));
      setTimeout(() => {
        setCompensateModal(m => ({ ...m, open: false }));
        setRevision(r => r + 1);
      }, 1500);
    } catch (e) {
      setCompensateModal(m => ({ ...m, busy: false, error: e instanceof Error ? e.message : '赠送时长失败' }));
    }
  }

  async function executeBlockUser() {
    if (blockModal.busy) return;
    setBlockModal(m => ({ ...m, busy: true, error: '', success: '' }));
    try {
      await request('/api/v1/commerce/block-user', {
        method: 'POST',
        body: JSON.stringify({ vm_id: blockModal.vm_id, reason: blockModal.reason })
      });
      setBlockModal(m => ({ ...m, busy: false, success: '买家已被成功列入黑名单！其在您名下所有母鸡上的自动续费已被关停，且无法再次购买或接收实例。' }));
      setTimeout(() => {
        setBlockModal(m => ({ ...m, open: false }));
        setRevision(r => r + 1);
      }, 1500);
    } catch (e) {
      setBlockModal(m => ({ ...m, busy: false, error: e instanceof Error ? e.message : '拉黑操作失败' }));
    }
  }

  async function executeUnblockUser(userId: string) {
    if (!window.confirm('确认将此买家从黑名单中移除，恢复其在您母鸡上的购买资格？')) return;
    try {
      await request(`/api/v1/commerce/blocked-users/${userId}`, { method: 'DELETE' });
      setNotice('买家已成功从黑名单移除');
      setRevision(r => r + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : '解除拉黑失败');
    }
  }

  async function saveAutoSync(updated: Partial<CommerceAutoSyncSettings>) {
    if (!autoSyncSettings) return;
    const next = { ...autoSyncSettings, ...updated };
    setAutoSyncSettings(next);
    try {
      await request('/api/v1/commerce/notification-settings', {
        method: 'POST',
        body: JSON.stringify(next)
      });
      setNotice('自动同步与 Telegram 推送设置已保存');
    } catch (e) {
      setError(e instanceof Error ? e.message : '保存设置失败');
    }
  }

  async function testTelegramPush() {
    try {
      setNotice('正在向 Telegram 发送测试卡片…');
      const res = await request<{ ok: boolean; sent_count: number }>('/api/v1/commerce/test-telegram', { method: 'POST' });
      setNotice(`✅ 测试卡片已成功推送到 ${res.sent_count} 个 Telegram 机器人通道！`);
    } catch (e) {
      setError(e instanceof Error ? e.message : '发送测试失败');
    }
  }

  const machines = overview?.machines || [];
  const names = useMemo(() => Object.fromEntries(machines.map(m => [m.id, m.name])), [machines]);
  const totalSold = machines.reduce((n, m) => n + m.sold_current, 0);
  const largest = Math.max(1, ...machines.map(m => m.observed_vms));
  const reset = () => { setStart(''); setEnd(''); setMachine(''); setKind(''); setOffset(0); };

  const abnormalCount = (riskData?.watchlist?.length || 0) + (riskData?.abnormal_machines?.filter(m => m.is_abnormal)?.length || 0);

  return (
    <div className="space-y-6 text-slate-200 [&_button]:min-h-11 [&_button]:cursor-pointer">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold">经营分析与运营中台</h2>
          <p className="mt-1 text-sm text-slate-400">母鸡出租现状 · 智能买退风控 · 用户忠诚度评估 · 实时 Telegram 经营通知</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {settings?.configured && autoSyncSettings && (
            autoSyncSettings.auto_sync ? (
              <span className="hidden sm:inline-flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-950/60 border border-emerald-500/40 px-2.5 py-1.5 rounded-lg">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                后台自动定时同步中 ({Math.round(autoSyncSettings.interval_seconds / 60)} 分钟/次)
              </span>
            ) : (
              <span className="hidden sm:inline-flex text-xs text-slate-400 bg-slate-800/40 border border-slate-700/50 px-2.5 py-1.5 rounded-lg">
                后台自动同步未开启
              </span>
            )
          )}
          <button className={button + ' flex items-center gap-2'} disabled={!settings?.configured || !!busy || settings.syncing} onClick={() => act('sync')}>
            <RefreshCw className={'h-4 w-4 ' + (busy || settings?.syncing ? 'motion-safe:animate-spin' : '')} />
            {busy || settings?.syncing ? '正在处理…' : '立即手动同步'}
          </button>
        </div>
      </div>

      {error && <p role="alert" className="rounded-xl border border-rose-500/40 bg-rose-950/40 p-4 text-sm text-rose-200">{error}</p>}
      {notice && <p role="status" className="rounded-xl border border-emerald-500/40 bg-emerald-950/40 p-4 text-sm text-emerald-300">{notice}</p>}
      {settings?.syncing && !busy && <p role="status" className="text-sm text-sky-300">后台同步进行中，完成后自动刷新；离开页面不会取消任务。</p>}

      {/* If API key is not configured, show the Personal Key configuration section immediately */}
      {(!settings?.configured || editingKey) && (
        <section className={panel} aria-labelledby="personal-key-heading">
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <KeyRound className="h-5 w-5 text-sky-400" />
            <h3 id="personal-key-heading" className="font-semibold">个人 API Key</h3>
            <span className={settings?.configured ? 'rounded-full border border-emerald-500/40 bg-emerald-950/40 px-2 py-1 text-xs text-emerald-300' : 'text-xs text-slate-400'}>
              {settings ? settings.configured ? '已保存 · 已加密' : '未配置' : '加载中…'}
            </span>
          </div>
          <form onSubmit={e => { e.preventDefault(); act('save'); }} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <label className="min-w-0 flex-1 text-sm text-slate-300" htmlFor="commerce-key">
              {settings?.configured ? '新的个人 API Key' : '配置个人 API Key'}
              <input id="commerce-key" type="password" autoComplete="off" autoFocus={editingKey} spellCheck={false} maxLength={512} value={apiKey} onChange={e => setApiKey(e.target.value)} className={input + ' mt-2'} placeholder="输入 Narwhal 平台个人 API Key" aria-describedby="key-help" />
            </label>
            <button type="submit" className={button + ' bg-sky-500 text-slate-950 hover:bg-sky-400'} disabled={!!busy || !apiKey.trim()}>
              {busy === 'save' ? '校验并保存…' : settings?.configured ? '保存新密钥并同步' : '保存并同步'}
            </button>
            {editingKey && <button type="button" className={button} disabled={!!busy} onClick={() => { setApiKey(''); setEditingKey(false); }}>取消更换</button>}
          </form>
          <p id="key-help" className="mt-3 text-xs leading-6 text-slate-400">仅用于当前登录用户的数据查询，加密保存在服务端；不修改全局买家通知配置，不执行购买或退款操作。<a className="ml-2 text-sky-300 underline" href="https://api.fuckip.me/openapi.yaml" target="_blank" rel="noreferrer">接口文档</a></p>
        </section>
      )}

      {/* Tabs Bar */}
      <div className="flex overflow-x-auto border-b border-slate-800 gap-2 pb-1 text-sm">
        {[
          { key: 'overview', label: '📊 概览与走势', badge: null },
          { key: 'analytics', label: '📅 日度与月度经营', badge: null },
          { key: 'risk', label: '🚨 异常退款与重点关注', badge: abnormalCount > 0 ? abnormalCount : null },
          { key: 'loyalty', label: '👑 用户忠诚与奖励', badge: null },
          { key: 'blocklist', label: '🚫 黑名单管理', badge: blockedUsers.length > 0 ? blockedUsers.length : null },
          { key: 'settings', label: '⚙️ 同步与推送设置', badge: null },
        ].map(t => (
          <button
            key={t.key}
            type="button"
            className={`whitespace-nowrap px-4 py-2 font-medium transition-colors border-b-2 -mb-[2px] flex items-center gap-2 ${
              tab === t.key
                ? 'border-sky-400 text-sky-300 bg-sky-950/30 rounded-t-lg'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
            onClick={() => setTab(t.key as any)}
          >
            {t.label}
            {t.badge != null && (
              <span className="rounded-full bg-rose-500/30 border border-rose-500/50 px-1.5 py-0.2 text-[11px] font-mono text-rose-300">
                {t.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW */}
      {tab === 'overview' && (
        <div className="space-y-6">
          {!overview ? (
            <p role="status" className="text-sm text-slate-400">正在加载个人经营数据…</p>
          ) : !overview.available ? (
            <div className={panel}>
              <ShoppingBag className="mb-3 h-8 w-8 text-slate-500" />
              <h3 className="font-semibold">还没有个人经营数据</h3>
              <p className="mt-2 text-sm text-slate-400">
                {settings?.configured ? '点击“同步经营数据”获取上游数据。' : '在“同步与推送设置”中配置个人 API Key 后即可查看。'}
              </p>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                <span>上次成功同步：{date(overview.synced_at)} UTC</span>
                <span>· 上游快照，非实时财务报表 · USD</span>
                {autoSyncSettings?.auto_sync && (
                  <span className="text-emerald-400 text-[11px] bg-emerald-950/50 border border-emerald-500/30 px-1.5 py-0.5 rounded">
                    ● 后台按每 {Math.round(autoSyncSettings.interval_seconds / 60)} 分钟自动同步并静默刷新
                  </span>
                )}
              </div>
              {overview.stale && (
                <p role="status" className="flex gap-2 rounded-xl border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-200">
                  <AlertTriangle className="h-5 w-5 shrink-0" />
                  {overview.last_error || (autoSyncSettings?.auto_sync ? '快照数据超过 15 分钟未刷新，后台正在等待下个轮询周期自动重试，也可点击上方“立即手动同步”。' : '数据已超过 15 分钟，请手动同步获取最新情况或至“同步与推送设置”开启自动定时同步。')} 当前仍展示上次成功快照。
                </p>
              )}
              <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5" aria-label="当前账号快照">
                {[
                  ['母鸡 / 当前售出小鸡', `${machines.length} / ${totalSold}`, '售出指当前归属其他用户的小鸡；不是累计销量'],
                  ['可用余额（不可提现）', usd(overview.profile?.available_balance), '用于平台消费，不属于可提现的托管资金'],
                  ['托管总余额', usd(overview.profile?.escrow_balance), '托管可用与冻结金额之和，不等于净利润'],
                  ['托管可用余额', usd(overview.profile?.escrow_available_balance), '托管总余额减去冻结金额；提现以平台规则为准'],
                  ['托管冻结金额', usd(overview.profile?.escrow_locked_value), '尚未解冻，暂不可提现']
                ].map(([title, value, hint]) => (
                  <div key={title} role="group" aria-label={title} className={panel}>
                    <p className="text-sm text-slate-400">{title}</p>
                    <p className="mt-2 wrap-break-word font-mono tabular-nums text-2xl font-semibold text-slate-100">{value}</p>
                    <p className="mt-2 text-xs leading-5 text-slate-400">{hint}</p>
                  </div>
                ))}
              </section>

              <section className={panel} aria-labelledby="machine-sales-heading">
                <h3 id="machine-sales-heading" className="mb-2 flex items-center gap-2 font-semibold">
                  <Server className="h-5 w-5 text-sky-400" />各母鸡出售现状
                </h3>
                <p className="mb-4 text-xs leading-6 text-slate-400">当前售出与自用分开计算。收益、冻结值由平台直接提供；已结算收益不含退款、补偿及进行中的冻结值。</p>
                {!machines.length ? (
                  <p className="py-8 text-center text-sm text-slate-400">当前账号没有母鸡；仍可在下方查看个人购买与退款历史。</p>
                ) : (
                  <div tabIndex={0} role="region" aria-label="各母鸡出售现状表格" className="ui-table-wrap">
                    <table className="w-full min-w-[780px] text-left text-sm">
                      <thead className="text-xs text-slate-400">
                        <tr>
                          {['母鸡', '当前小鸡（售出 / 自用）', '买家数', '预估收益 USD', '已结算收益 USD', '冻结值 USD'].map(h => (
                            <th key={h} className="px-3 py-3 font-medium">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {machines.map(m => (
                          <tr key={m.id} className="border-t border-slate-800 hover:bg-slate-800/40">
                            <td className="max-w-56 px-3 py-4">
                              <button className="text-left text-sky-300 underline decoration-slate-600 underline-offset-4 focus-visible:ring-2 focus-visible:ring-sky-400" onClick={() => { setLedger(false); setMachine(m.id); setOffset(0); }} title={m.id}>
                                {m.name || m.id}
                              </button>
                              <p className="mt-1 text-xs text-slate-400">{m.region} · {m.status === 'online' ? '在线' : m.status === 'offline' ? '离线' : m.status}</p>
                            </td>
                            <td className="min-w-44 px-3 py-4">
                              <p>{m.sold_current} / {m.self_current}</p>
                              <div className="mt-2 flex h-2 overflow-hidden rounded-sm bg-slate-800" aria-hidden="true">
                                <span className="bg-sky-400" style={{ width: `${(m.sold_current / largest) * 100}%` }} />
                                <span className="bg-slate-500" style={{ width: `${(m.self_current / largest) * 100}%` }} />
                              </div>
                            </td>
                            <td className="px-3 py-4 font-mono">{m.buyer_count}</td>
                            <td className="px-3 py-4 font-mono">{usd(m.est_revenue)}</td>
                            <td className="px-3 py-4 font-mono text-emerald-300">{usd(m.earned_revenue)}</td>
                            <td className="px-3 py-4 font-mono">{usd(m.locked_value)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {/* History Section */}
              <section className={panel} aria-labelledby="billing-heading">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <h3 id="billing-heading" className="flex items-center gap-2 font-semibold">
                    <Receipt className="h-5 w-5 text-sky-400" />购买、退款与账单明细
                  </h3>
                  <div className="flex gap-2">
                    {[false, true].map(value => (
                      <button key={String(value)} className={button + (ledger === value ? ' border-sky-400 bg-sky-950' : '')} aria-pressed={ledger === value} onClick={() => { setLedger(value); setMachine(''); setKind(''); setOffset(0); }}>
                        {value ? '账单流水' : '订单历史'}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                  <label className="text-xs text-slate-400">开始日期（UTC）<input type="date" value={start} onChange={e => { setStart(e.target.value); setOffset(0); }} className={input + ' mt-2'} /></label>
                  <label className="text-xs text-slate-400">结束日期（UTC）<input type="date" value={end} onChange={e => { setEnd(e.target.value); setOffset(0); }} className={input + ' mt-2'} /></label>
                  <label className="text-xs text-slate-400">订单归属母鸡<select value={machine} onChange={e => { setMachine(e.target.value); setOffset(0); }} className="ui-select mt-2"><option value="">全部归属</option><option value="unknown">归属未知</option>{machines.map(m => <option key={m.id} value={m.id}>{m.name || m.id}</option>)}</select></label>
                  <label className="text-xs text-slate-400">记录类型<select value={kind} onChange={e => { setKind(e.target.value); setOffset(0); }} className="ui-select mt-2"><option value="">全部类型</option>{Object.keys(labels).map(k => <option key={k} value={k}>{label(k)}</option>)}</select></label>
                  <button className={button + ' self-end'} onClick={reset}>重置历史筛选</button>
                </div>
                {historyError ? (
                  <p role="alert" className="mt-4 text-sm text-rose-300">{historyError}</p>
                ) : !history ? (
                  <p role="status" className="py-12 text-center text-slate-400">正在加载历史记录…</p>
                ) : (
                  <>
                    <div className="my-5 flex flex-wrap gap-3 text-sm">
                      <span>筛选内共 {history.total} 笔</span>
                      {history.unmapped != null && <span className="text-slate-400">· {history.unmapped} 笔归属未知</span>}
                    </div>
                    <h4 className="mb-3 text-sm font-medium">每日记录笔数（UTC）</h4>
                    <Trend rows={history.trend} />
                    <div className="my-4 flex flex-wrap gap-3">
                      {history.totals.map(t => (
                        <div key={t.type + t.balance_type} className="rounded-xl border border-slate-800 bg-slate-950/60 px-4 py-3 text-sm">
                          <span className="text-slate-300">{label(t.type)}{t.balance_type ? ` / ${t.balance_type === 'escrow' ? '托管' : '可用'}` : ''} · {t.count} 笔</span>
                          <p className="mt-1 font-mono">{usd(t.amount)}</p>
                        </div>
                      ))}
                    </div>
                    <div tabIndex={0} role="region" aria-label="订单与账单流水表格" className="ui-table-wrap">
                      <table className="w-full min-w-[760px] text-left text-sm">
                        <thead className="text-xs text-slate-400">
                          <tr>{['时间 UTC', '类型', '金额 USD', ledger ? '余额账户 / 变动后余额' : '母鸡归属', '记录 / 小鸡 ID'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr>
                        </thead>
                        <tbody>
                          {history.items.map(r => (
                            <tr key={r.id} className="border-t border-slate-800 hover:bg-slate-800/40">
                              <td className="whitespace-nowrap px-3 py-3">{date(r.created_at)}</td>
                              <td className="px-3 py-3">{label(r.type)}{r.status && <p className="mt-1 text-xs text-slate-400">{r.status === 'completed' ? '已完成' : r.status}</p>}</td>
                              <td className="whitespace-nowrap px-3 py-3 font-mono">{usd(r.amount)}</td>
                              <td className="max-w-56 wrap-break-word px-3 py-3">{ledger ? `${r.balance_type === 'escrow' ? '托管' : '可用'} / ${usd(r.balance_after)}` : r.machine_id ? r.machine_name || names[r.machine_id] || r.machine_id : '归属未知'}</td>
                              <td className="px-3 py-3 font-mono text-xs"><p>{r.id}</p>{r.vm_id && <p className="mt-1 text-slate-400">VM {r.vm_id}</p>}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </section>
            </>
          )}
        </div>
      )}

      {/* TAB 2: DAILY & MONTHLY ANALYTICS */}
      {tab === 'analytics' && (
        <div className="space-y-6">
          {dailyData?.today_summary && (
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="今日经营指标">
              <div className={panel}>
                <p className="text-sm text-slate-400">今日总销售额 (GMV)</p>
                <p className="mt-2 font-mono text-2xl font-bold text-sky-400">{usd(dailyData.today_summary.gmv)}</p>
                <p className="mt-1 text-xs text-slate-400">共 {dailyData.today_summary.orders_count} 笔订单 · 昨日 {usd(dailyData.today_summary.yesterday_gmv)}</p>
              </div>
              <div className={panel}>
                <p className="text-sm text-slate-400">今日退款支出</p>
                <p className="mt-2 font-mono text-2xl font-bold text-rose-400">-{usd(dailyData.today_summary.refunds_amount)}</p>
                <p className="mt-1 text-xs text-slate-400">{dailyData.today_summary.refunds_count} 笔退款</p>
              </div>
              <div className={panel}>
                <p className="text-sm text-slate-400">今日净收益</p>
                <p className="mt-2 font-mono text-2xl font-bold text-emerald-400">{usd(dailyData.today_summary.net_revenue)}</p>
                <p className="mt-1 text-xs text-slate-400">昨日净收益 {usd(dailyData.today_summary.yesterday_net)}</p>
              </div>
              <div className={panel}>
                <p className="text-sm text-slate-400">今日退款率</p>
                <p className="mt-2 font-mono text-2xl font-bold text-slate-200">
                  {dailyData.today_summary.orders_count + dailyData.today_summary.refunds_count > 0
                    ? ((dailyData.today_summary.refunds_count / (dailyData.today_summary.orders_count + dailyData.today_summary.refunds_count)) * 100).toFixed(1)
                    : 0}%
                </p>
                <p className="mt-1 text-xs text-slate-400">退款笔数 / (总订单+退款)</p>
              </div>
            </section>
          )}

          <section className={panel}>
            <h3 className="mb-2 flex items-center gap-2 font-semibold">
              <Calendar className="h-5 w-5 text-sky-400" />近 30 日收支走势分析 (UTC)
            </h3>
            <p className="mb-4 text-xs text-slate-400">直观展示每日新增销售额、退款支出与实际净收入趋势。</p>
            {dailyData?.daily ? <DailyRevenueChart items={dailyData.daily} /> : <p className="py-8 text-center text-sm text-slate-400">正在生成日度走势…</p>}
          </section>

          <section className={panel}>
            <h3 className="mb-2 flex items-center gap-2 font-semibold">
              <DollarSign className="h-5 w-5 text-emerald-400" />每月经营汇总月报 (近 12 个月)
            </h3>
            <p className="mb-4 text-xs text-slate-400">按自然月聚合销售额、退款总额、退款率及各月热销母鸡。</p>
            {!monthlyData?.length ? (
              <p className="py-8 text-center text-sm text-slate-400">暂无月度数据</p>
            ) : (
              <div tabIndex={0} role="region" aria-label="月度经营表格" className="ui-table-wrap">
                <table className="w-full min-w-[700px] text-left text-sm">
                  <thead className="text-xs text-slate-400">
                    <tr>
                      {['月份', '新买入 / 续费', '销售额 (GMV)', '退款笔数 / 金额', '月度净收入', '退款率', '热销母鸡 Top 3'].map(h => (
                        <th key={h} className="px-3 py-3 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {monthlyData.map(m => (
                      <tr key={m.month} className="border-t border-slate-800 hover:bg-slate-800/40">
                        <td className="whitespace-nowrap px-3 py-3 font-medium text-sky-300">{m.month}</td>
                        <td className="px-3 py-3">{m.purchases_count} 购 / {m.renewals_count} 续</td>
                        <td className="px-3 py-3 font-mono font-medium">{usd(m.orders_amount)}</td>
                        <td className="px-3 py-3 font-mono text-rose-300">{m.refunds_count} 笔 / -{usd(m.refunds_amount)}</td>
                        <td className="px-3 py-3 font-mono font-bold text-emerald-300">{usd(m.net_revenue)}</td>
                        <td className="px-3 py-3 font-mono">
                          <span className={m.refund_rate >= 15 ? 'text-rose-400 font-bold' : 'text-slate-300'}>{m.refund_rate}%</span>
                        </td>
                        <td className="px-3 py-3 text-xs text-slate-400">
                          {m.top_machines.length ? (
                            m.top_machines.map(tm => (
                              <span key={tm.machine_id} className="inline-block mr-2 rounded bg-slate-800 px-1.5 py-0.5">
                                {tm.machine_name}: ${tm.amount}
                              </span>
                            ))
                          ) : '无'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {/* TAB 3: RISK & WATCHLIST */}
      {tab === 'risk' && (
        <div className="space-y-6">
          <section className={panel}>
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h3 className="flex items-center gap-2 font-semibold text-rose-300">
                  <ShieldAlert className="h-5 w-5 text-rose-400" />异常退款服务器分析（母鸡维度）
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  识别哪些母鸡退款率畸高。注意：节点退款率偏高通常由机房网络抽风、IP 被墙或线路断流引起，建议优先排查节点网络，非买家单方面责任。
                </p>
              </div>
            </div>
            {!riskData?.abnormal_machines?.length ? (
              <p className="py-8 text-center text-sm text-slate-400">正在分析各母鸡退款率…</p>
            ) : (
              <div tabIndex={0} role="region" aria-label="母鸡退款率表格" className="ui-table-wrap">
                <table className="w-full min-w-[700px] text-left text-sm">
                  <thead className="text-xs text-slate-400">
                    <tr>{['母鸡名称', '地区', '订单数 / 退款数', '退款总额', '退款率', '诊断与排查建议'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {riskData.abnormal_machines.map(m => (
                      <tr key={m.machine_id} className={`border-t border-slate-800 ${m.is_abnormal ? 'bg-rose-950/20' : 'hover:bg-slate-800/40'}`}>
                        <td className="px-3 py-3 font-medium">
                          {m.machine_name}
                          {m.is_abnormal && <span className="ml-2 rounded-full border border-rose-500/50 bg-rose-950/60 px-2 py-0.5 text-xs text-rose-300">⚠️ 退款率高危</span>}
                        </td>
                        <td className="px-3 py-3 text-slate-400">{m.region || '未知'}</td>
                        <td className="px-3 py-3 font-mono">{m.orders_count} 单 / {m.refunds_count} 退</td>
                        <td className="px-3 py-3 font-mono text-rose-300">-{usd(m.refund_amount)}</td>
                        <td className="px-3 py-3 font-mono">
                          <span className={m.is_abnormal ? 'text-rose-400 font-bold' : 'text-slate-300'}>{m.refund_rate}%</span>
                        </td>
                        <td className="px-3 py-3 text-xs text-slate-300">{m.suggestion}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className={panel}>
            <div className="mb-4">
              <h3 className="flex items-center gap-2 font-semibold text-amber-300">
                <Users className="h-5 w-5 text-amber-400" />重点关注买家清单（频繁买退 / 试用羊毛党）
              </h3>
              <p className="mt-1 text-xs text-slate-400">
                自动归集多次购买并极速退款（&lt;24小时内）、退款率高、或频繁买退的买家。可在右侧直接一键拉黑，禁止其再次下单。
              </p>
            </div>
            {!riskData?.watchlist?.length ? (
              <div className="py-8 text-center text-sm text-slate-400">
                <CheckCircle2 className="mx-auto mb-2 h-6 w-6 text-emerald-400" />
                当前未发现恶意频繁买退买家，经营风控状态良好。
              </div>
            ) : (
              <div tabIndex={0} role="region" aria-label="重点关注买家表格" className="ui-table-wrap">
                <table className="w-full min-w-[750px] text-left text-sm">
                  <thead className="text-xs text-slate-400">
                    <tr>{['买家标识 / 邮箱', '买入 / 退款', '退款率', '极速退款(&lt;24h)', '净消费额', '风险特征标签', '操作'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {riskData.watchlist.map(u => (
                      <tr key={u.user_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                        <td className="px-3 py-3">
                          <p className="font-medium text-slate-200">{u.user_name}</p>
                          <p className="text-xs text-slate-400 font-mono">{u.user_email}</p>
                        </td>
                        <td className="px-3 py-3 font-mono">{u.total_purchases} 购 / {u.total_refunds} 退</td>
                        <td className="px-3 py-3 font-mono font-bold text-rose-400">{u.refund_rate}%</td>
                        <td className="px-3 py-3 font-mono text-amber-300">{u.quick_refunds} 次</td>
                        <td className="px-3 py-3 font-mono">{usd(Number(u.total_spent) - Number(u.total_refunded))}</td>
                        <td className="px-3 py-3">
                          <div className="flex flex-wrap gap-1">
                            {u.risk_tags.map(tag => (
                              <span key={tag} className="rounded bg-rose-950/60 border border-rose-500/40 px-1.5 py-0.5 text-xs text-rose-300">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-3 py-3">
                          {u.sample_vm_id ? (
                            <button
                              type="button"
                              className="rounded-lg border border-rose-500/60 bg-rose-950/40 px-2.5 py-1 text-xs font-medium text-rose-300 hover:bg-rose-900/50 flex items-center gap-1"
                              onClick={() => setBlockModal({ open: true, vm_id: u.sample_vm_id, user_name: u.user_name, reason: '频繁买退 / 试用羊毛', busy: false, error: '', success: '' })}
                            >
                              <Ban className="h-3.5 w-3.5" />拉黑买家
                            </button>
                          ) : (
                            <span className="text-xs text-slate-500">无活跃VM关联</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {/* TAB 4: USER LOYALTY & REWARDS */}
      {tab === 'loyalty' && (
        <div className="space-y-6">
          <section className={panel}>
            <div className="mb-4">
              <h3 className="flex items-center gap-2 font-semibold text-amber-300">
                <Award className="h-5 w-5 text-amber-400" />买家忠诚度评估与时长奖励中台
              </h3>
              <p className="mt-1 text-xs text-slate-400">
                依据买家持续在期天数、续费频次及历史履约状态自动评估忠诚度等级。可直接为忠诚老客或受故障影响的实例一键「赠送可用时长」，从您的托管余额自扣补偿。
              </p>
            </div>
            {!loyaltyData?.length ? (
              <p className="py-8 text-center text-sm text-slate-400">正在评估买家忠诚度…</p>
            ) : (
              <div tabIndex={0} role="region" aria-label="买家忠诚度表格" className="ui-table-wrap">
                <table className="w-full min-w-[780px] text-left text-sm">
                  <thead className="text-xs text-slate-400">
                    <tr>{['买家标识 / 邮箱', '忠诚等级徽章', '在期小鸡数', '累计在期天数', '续费次数', '累计消费 USD', '活跃小鸡明细与一键奖励'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {loyaltyData.map(u => (
                      <tr key={u.user_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                        <td className="px-3 py-3">
                          <p className="font-medium text-slate-200">{u.user_name}</p>
                          <p className="text-xs text-slate-400 font-mono">{u.user_email}</p>
                        </td>
                        <td className="px-3 py-3">
                          {u.loyalty_tier === 'diamond' && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-sky-400/50 bg-sky-950/60 px-2.5 py-0.5 text-xs font-semibold text-sky-300">
                              💎 钻石老客
                            </span>
                          )}
                          {u.loyalty_tier === 'gold' && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/50 bg-amber-950/60 px-2.5 py-0.5 text-xs font-semibold text-amber-300">
                              🥇 黄金老客
                            </span>
                          )}
                          {u.loyalty_tier === 'silver' && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-slate-600 bg-slate-800/60 px-2.5 py-0.5 text-xs text-slate-300">
                              🥈 常规履约
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-3 font-mono">{u.active_vms_count} 台</td>
                        <td className="px-3 py-3 font-mono text-sky-300">{u.estimated_tenure_days} 天</td>
                        <td className="px-3 py-3 font-mono text-emerald-300">{u.renewal_count} 次</td>
                        <td className="px-3 py-3 font-mono">{usd(u.total_spent)}</td>
                        <td className="px-3 py-3">
                          <div className="space-y-1">
                            {u.vms.map(vm => (
                              <div key={vm.id} className="flex items-center justify-between gap-2 rounded bg-slate-950/60 border border-slate-800 px-2 py-1 text-xs">
                                <span className="font-mono text-slate-300" title={vm.id}>
                                  {vm.machine_name} (余 {vm.days_remaining} 天)
                                </span>
                                <button
                                  type="button"
                                  className="rounded bg-sky-500/20 border border-sky-400/40 px-2 py-0.5 text-[11px] font-medium text-sky-300 hover:bg-sky-500/30 flex items-center gap-1"
                                  onClick={() => setCompensateModal({
                                    open: true, vm_id: vm.id, user_name: u.user_name, machine_name: vm.machine_name, price_monthly: vm.price_monthly, days: 3, busy: false, error: '', success: ''
                                  })}
                                >
                                  <Gift className="h-3 w-3" />赠送时长
                                </button>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {/* TAB 5: BLOCKLIST */}
      {tab === 'blocklist' && (
        <div className="space-y-6">
          <section className={panel}>
            <div className="mb-4">
              <h3 className="flex items-center gap-2 font-semibold text-rose-300">
                <Ban className="h-5 w-5 text-rose-400" />上游黑名单管理
              </h3>
              <p className="mt-1 text-xs text-slate-400">
                当前被您列入黑名单的买家。被拉黑的用户无法在您拥有的任何母鸡上下单、续费或转鸡，现有实例到期后自动停止。
              </p>
            </div>
            {!blockedUsers.length ? (
              <div className="py-12 text-center text-sm text-slate-400">
                <CheckCircle2 className="mx-auto mb-2 h-7 w-7 text-emerald-400" />
                当前黑名单为空，没有被封禁的买家。
              </div>
            ) : (
              <div tabIndex={0} role="region" aria-label="黑名单表格" className="ui-table-wrap">
                <table className="w-full min-w-[700px] text-left text-sm">
                  <thead className="text-xs text-slate-400">
                    <tr>{['买家标识 / 用户名', '拉黑原因', '触发拉黑的实例 (VM ID)', '拉黑时间 (UTC)', '操作'].map(h => <th key={h} className="px-3 py-3 font-medium">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {blockedUsers.map(b => (
                      <tr key={b.id || b.user_id} className="border-t border-slate-800 hover:bg-slate-800/40">
                        <td className="px-3 py-3 font-medium text-slate-200">{b.user_name || b.user_id}</td>
                        <td className="px-3 py-3 text-xs text-rose-300">{b.reason || '未填写原因'}</td>
                        <td className="px-3 py-3 font-mono text-xs text-slate-400">{b.vm_id || '无'}</td>
                        <td className="px-3 py-3 text-xs text-slate-400">{date(b.created_at)}</td>
                        <td className="px-3 py-3">
                          <button
                            type="button"
                            className="rounded-lg border border-slate-600 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-200 hover:border-sky-400 hover:text-sky-300"
                            onClick={() => executeUnblockUser(b.user_id)}
                          >
                            解除拉黑
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {/* TAB 6: SETTINGS & PUSH */}
      {tab === 'settings' && (
        <div className="space-y-6">
          <section className={panel} aria-labelledby="personal-key-heading">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <KeyRound className="h-5 w-5 text-sky-400" />
              <h3 id="personal-key-heading" className="font-semibold">个人 API Key</h3>
              <span className={settings?.configured ? 'rounded-full border border-emerald-500/40 bg-emerald-950/40 px-2 py-1 text-xs text-emerald-300' : 'text-xs text-slate-400'}>
                {settings ? settings.configured ? '已保存 · 已加密' : '未配置' : '加载中…'}
              </span>
            </div>
            {settings?.configured && (
              <div className="mb-4 rounded-xl border border-slate-700 bg-slate-950/60 p-4">
                <label className="block text-sm text-slate-300">
                  已保存的个人 API Key
                  <input className={input + ' mt-2 cursor-default text-slate-400'} type="text" value="••••••••（已安全保存，不显示原文）" readOnly autoComplete="off" />
                </label>
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  {!editingKey && (
                    <button type="button" className={button + ' flex items-center gap-2'} disabled={!!busy || settings.syncing} onClick={() => { setApiKey(''); setEditingKey(true); }}>
                      <Pencil className="h-4 w-4" />更换 API Key
                    </button>
                  )}
                  <button type="button" className={button + ' flex items-center gap-2 border-rose-500/60 text-rose-300 hover:border-rose-300'} disabled={!!busy || settings.syncing} onClick={() => act('delete')}>
                    <Trash2 className="h-4 w-4" />删除 API Key
                  </button>
                  {settings.updated_at > 0 && <span className="text-xs text-slate-400">保存时间：{date(settings.updated_at)} UTC</span>}
                </div>
              </div>
            )}
            {settings && (!settings.configured || editingKey) && (
              <form onSubmit={e => { e.preventDefault(); act('save'); }} className="flex flex-col gap-3 sm:flex-row sm:items-end">
                <label className="min-w-0 flex-1 text-sm text-slate-300" htmlFor="commerce-key">
                  {settings.configured ? '新的个人 API Key' : '配置个人 API Key'}
                  <input id="commerce-key" type="password" autoComplete="off" autoFocus={editingKey} spellCheck={false} maxLength={512} value={apiKey} onChange={e => setApiKey(e.target.value)} className={input + ' mt-2'} placeholder="输入 Narwhal 平台个人 API Key" />
                </label>
                <button type="submit" className={button + ' bg-sky-500 text-slate-950 hover:bg-sky-400'} disabled={!!busy || !apiKey.trim()}>
                  {busy === 'save' ? '校验并保存…' : settings.configured ? '保存新密钥并同步' : '保存并同步'}
                </button>
                {editingKey && <button type="button" className={button} disabled={!!busy} onClick={() => { setApiKey(''); setEditingKey(false); }}>取消更换</button>}
              </form>
            )}
          </section>

          {autoSyncSettings && (
            <section className={panel}>
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h3 className="flex items-center gap-2 font-semibold">
                    <Bell className="h-5 w-5 text-sky-400" />自动定时同步与 Telegram 经营推送配置
                  </h3>
                  <p className="mt-1 text-xs text-slate-400">
                    后台自动按周期同步 Narwhal API，在新订单买入或退款时秒级推送到绑定的 Telegram 机器人，并生成日度/月度简报。
                  </p>
                </div>
                <button type="button" className={button + ' flex items-center gap-1.5 text-xs'} onClick={testTelegramPush}>
                  <Send className="h-3.5 w-3.5 text-sky-300" />测试发送 TG 经营卡片
                </button>
              </div>

              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <label className="flex items-center justify-between cursor-pointer">
                    <span className="text-sm font-medium">后台自动定时同步</span>
                    <input
                      type="checkbox"
                      checked={autoSyncSettings.auto_sync}
                      onChange={e => saveAutoSync({ auto_sync: e.target.checked })}
                      className="h-5 w-5 rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-sky-400"
                    />
                  </label>
                  <p className="mt-2 text-xs text-slate-400">自动拉取上游订单、流水与小鸡数据更新快照</p>
                  <div className="mt-3">
                    <label className="text-xs text-slate-400">同步轮询间隔</label>
                    <select
                      value={autoSyncSettings.interval_seconds}
                      onChange={e => saveAutoSync({ interval_seconds: Number(e.target.value) })}
                      className="ui-select mt-1 w-full"
                    >
                      <option value={180}>每 3 分钟 (高频刷新)</option>
                      <option value={300}>每 5 分钟 (推荐)</option>
                      <option value={600}>每 10 分钟</option>
                      <option value={900}>每 15 分钟</option>
                      <option value={1800}>每 30 分钟</option>
                    </select>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                  <span className="text-sm font-medium block">Telegram 实时动态提醒</span>
                  <label className="flex items-center justify-between cursor-pointer">
                    <span className="text-xs text-slate-300">🛒 新买入 / 续费订单提醒</span>
                    <input
                      type="checkbox"
                      checked={autoSyncSettings.tg_notify_orders}
                      onChange={e => saveAutoSync({ tg_notify_orders: e.target.checked })}
                      className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-sky-500"
                    />
                  </label>
                  <label className="flex items-center justify-between cursor-pointer">
                    <span className="text-xs text-slate-300">⚠️ 退款 / 托管扣减提醒</span>
                    <input
                      type="checkbox"
                      checked={autoSyncSettings.tg_notify_refunds}
                      onChange={e => saveAutoSync({ tg_notify_refunds: e.target.checked })}
                      className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-sky-500"
                    />
                  </label>
                  <p className="text-[11px] text-slate-500 leading-4">产生新事件时，机器人将在 60 秒内将美观卡片推送至您的 Telegram 群组</p>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                  <span className="text-sm font-medium block">定期经营简报播报</span>
                  <label className="flex items-center justify-between cursor-pointer">
                    <span className="text-xs text-slate-300">📊 每日经营简报推送</span>
                    <input
                      type="checkbox"
                      checked={autoSyncSettings.tg_daily_digest}
                      onChange={e => saveAutoSync({ tg_daily_digest: e.target.checked })}
                      className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-sky-500"
                    />
                  </label>
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>每日推送时间 (UTC+8)</span>
                    <select
                      value={autoSyncSettings.digest_hour}
                      onChange={e => saveAutoSync({ digest_hour: Number(e.target.value) })}
                      className="ui-select py-1 text-xs"
                    >
                      {[0, 6, 8, 9, 10, 12, 18, 20, 22].map(h => (
                        <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>
                      ))}
                    </select>
                  </div>
                  <label className="flex items-center justify-between cursor-pointer pt-1 border-t border-slate-800">
                    <span className="text-xs text-slate-300">🗓️ 每月 1 日经营月报推送</span>
                    <input
                      type="checkbox"
                      checked={autoSyncSettings.tg_monthly_digest}
                      onChange={e => saveAutoSync({ tg_monthly_digest: e.target.checked })}
                      className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-sky-500"
                    />
                  </label>
                </div>
              </div>
            </section>
          )}
        </div>
      )}

      {/* COMPENSATE / REWARD MODAL */}
      {compensateModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="flex items-center gap-2 font-bold text-slate-100">
                <Gift className="h-5 w-5 text-sky-400" />赠送 / 奖励小鸡可用时长
              </h3>
              <button
                type="button"
                className="text-slate-400 hover:text-slate-200"
                onClick={() => setCompensateModal(m => ({ ...m, open: false }))}
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="mt-4 space-y-3 text-sm">
              <div>
                <span className="text-xs text-slate-400">买家标识：</span>
                <span className="font-medium text-slate-200 ml-1">{compensateModal.user_name}</span>
              </div>
              <div>
                <span className="text-xs text-slate-400">所属母鸡：</span>
                <span className="font-medium text-slate-200 ml-1">{compensateModal.machine_name}</span>
              </div>
              <div>
                <span className="text-xs text-slate-400">目标小鸡 ID：</span>
                <span className="font-mono text-xs text-slate-300 ml-1">{compensateModal.vm_id}</span>
              </div>
              <div className="pt-2">
                <label className="text-xs text-slate-300 font-medium">赠送可用时长 (天数)</label>
                <div className="grid grid-cols-5 gap-2 mt-2">
                  {[1, 3, 7, 14, 30].map(d => (
                    <button
                      key={d}
                      type="button"
                      className={`py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                        compensateModal.days === d
                          ? 'border-sky-400 bg-sky-950/60 text-sky-300'
                          : 'border-slate-700 bg-slate-800/60 text-slate-300 hover:border-slate-500'
                      }`}
                      onClick={() => setCompensateModal(m => ({ ...m, days: d }))}
                    >
                      +{d} 天
                    </button>
                  ))}
                </div>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={compensateModal.days}
                  onChange={e => setCompensateModal(m => ({ ...m, days: Math.max(1, Math.min(365, Number(e.target.value) || 1)) }))}
                  className={input + ' mt-2 w-full font-mono text-sm'}
                  placeholder="自定义天数 (1~365)"
                />
              </div>

              {compensateModal.price_monthly && (
                <div className="rounded-xl border border-sky-500/30 bg-sky-950/30 p-3 text-xs leading-5 text-sky-200">
                  <p>💡 预估成本：约 <b>${((Number(compensateModal.price_monthly) * compensateModal.days) / 31).toFixed(2)} USD</b></p>
                  <p className="text-[11px] text-sky-300/80">此费用将从您的托管可用余额中扣除，小鸡到期时间将即时顺延。</p>
                </div>
              )}

              {compensateModal.error && <p className="text-xs text-rose-300 font-medium">{compensateModal.error}</p>}
              {compensateModal.success && <p className="text-xs text-emerald-300 font-medium">{compensateModal.success}</p>}
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                className={button}
                disabled={compensateModal.busy}
                onClick={() => setCompensateModal(m => ({ ...m, open: false }))}
              >
                取消
              </button>
              <button
                type="button"
                className={button + ' bg-sky-500 text-slate-950 hover:bg-sky-400 font-semibold'}
                disabled={compensateModal.busy || !compensateModal.days}
                onClick={executeCompensate}
              >
                {compensateModal.busy ? '正在扣减并延期…' : `确认赠送 ${compensateModal.days} 天`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* BLOCK USER MODAL */}
      {blockModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl border border-rose-500/40 bg-slate-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="flex items-center gap-2 font-bold text-rose-300">
                <Ban className="h-5 w-5 text-rose-400" />拉黑买家确认
              </h3>
              <button
                type="button"
                className="text-slate-400 hover:text-slate-200"
                onClick={() => setBlockModal(m => ({ ...m, open: false }))}
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="mt-4 space-y-3 text-sm">
              <div className="rounded-xl border border-rose-500/30 bg-rose-950/30 p-3 text-xs leading-5 text-rose-200">
                <p className="font-semibold">⚠️ 封禁后生效规则：</p>
                <p>1. 该用户在您拥有的<b>所有母鸡</b>上均无法再新购、续费、在集市买鸡或接收 push 转移；</p>
                <p>2. 系统将自动关停该用户在您名下所有小鸡的<b>自动续费</b>；现有运行中的实例允许运行至自然到期。</p>
              </div>

              <div>
                <span className="text-xs text-slate-400">目标买家：</span>
                <span className="font-medium text-slate-200 ml-1">{blockModal.user_name}</span>
              </div>

              <div>
                <label className="text-xs text-slate-300 font-medium">拉黑原因 (上游可展示给买家)</label>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {['频繁买退 / 试用羊毛', '端口扫描 / 恶意攻击', '严重超时占用带宽', '违反服务条款'].map(r => (
                    <button
                      key={r}
                      type="button"
                      className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs text-slate-300 hover:border-sky-400"
                      onClick={() => setBlockModal(m => ({ ...m, reason: r }))}
                    >
                      {r}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  maxLength={500}
                  value={blockModal.reason}
                  onChange={e => setBlockModal(m => ({ ...m, reason: e.target.value }))}
                  className={input + ' mt-2 w-full text-sm'}
                  placeholder="填写拉黑原因说明"
                />
              </div>

              {blockModal.error && <p className="text-xs text-rose-300 font-medium">{blockModal.error}</p>}
              {blockModal.success && <p className="text-xs text-emerald-300 font-medium">{blockModal.success}</p>}
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                className={button}
                disabled={blockModal.busy}
                onClick={() => setBlockModal(m => ({ ...m, open: false }))}
              >
                取消
              </button>
              <button
                type="button"
                className={button + ' border-rose-500 bg-rose-600 text-white hover:bg-rose-500 font-semibold'}
                disabled={blockModal.busy}
                onClick={executeBlockUser}
              >
                {blockModal.busy ? '正在拉黑…' : '确认列入黑名单'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
