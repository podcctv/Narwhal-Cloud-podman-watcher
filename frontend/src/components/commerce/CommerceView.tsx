import { useEffect, useMemo, useRef, useState } from 'react';
import * as echarts from 'echarts/core';
import { BarChart, LineChart } from 'echarts/charts';
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import {
  KeyRound,
  RefreshCw,
  Server,
  ShoppingBag,
  Receipt,
  AlertTriangle,
  Trash2,
  Pencil,
  Calendar,
  ShieldAlert,
  Award,
  Ban,
  Bell,
  CheckCircle2,
  Gift,
  DollarSign,
  Users,
  X,
  Send,
  BarChart3,
  Settings as SettingsIcon,
  Gem,
  Medal,
  ShoppingCart,
  Eye,
  EyeOff,
  Lightbulb,
} from 'lucide-react';
import { request } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';
import type {
  CommerceAutoSyncSettings,
  DailyAnalyticsResponse,
  MonthlyAnalyticsItem,
  RiskAnalysisResponse,
  LoyaltyUserItem,
  BlockedUserItem,
  BlockedUsersResponse,
} from '../../api/types';

echarts.use([BarChart, LineChart, AriaComponent, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

type Money = string | null;
type Settings = {
  configured: boolean;
  updated_at: number;
  synced_at: number;
  last_error: string;
  api_url: string;
  syncing: boolean;
};
type Machine = {
  id: string;
  name: string;
  region: string;
  status: string;
  sold_current: number;
  self_current: number;
  observed_vms: number;
  vm_count: number | null;
  buyer_count: number;
  est_revenue: Money;
  earned_revenue: Money;
  locked_value: Money;
};
type Overview = {
  available: boolean;
  synced_at: number;
  stale: boolean;
  last_error: string;
  machines: Machine[];
  profile: {
    available_balance: Money;
    escrow_balance: Money;
    escrow_locked_value: Money;
    escrow_available_balance?: Money;
    commission_rate: Money;
  } | null;
  documentation: string;
};
type RecordRow = {
  id: string;
  vm_id?: string;
  machine_id?: string;
  machine_name?: string;
  status?: string;
  type: string;
  amount: Money;
  discount_amount?: Money;
  balance_type?: string;
  balance_after?: Money;
  created_at: number;
};
type History = {
  items: RecordRow[];
  total: number;
  totals: { type: string; balance_type: string; count: number; amount: Money; uncompleted: number }[];
  trend: { day: string; type: string; count: number }[];
  unmapped: number | null;
};

const labels: Record<string, string> = {
  purchase: '购买',
  refund: '退款',
  renewal: '续费',
  renew: '续费扣款',
  push: '转移',
  escrow_in: '卖家托管入账',
  escrow_renew: '卖家续费入账',
  escrow_deduct: '托管扣减',
  topup: '充值',
  market_sell: '市场卖出',
  market_buy: '市场买入',
  withdrawal: '提现',
  ip_rent: 'IP 租用',
  ip_renew: 'IP 续租',
  compensation: '补偿',
};
const label = (kind: string) => labels[kind] || kind;
const kindColors: Record<string, string> = {
  purchase: '#087bff',
  refund: '#dc2626',
  renew: '#147468',
  renewal: '#147468',
  escrow_in: '#7c3aed',
  escrow_renew: '#00b6ec',
  escrow_deduct: '#d97706',
  topup: '#0d9488',
};
const usd = (value: Money | number | undefined) =>
  value == null ? '未提供' : new Intl.NumberFormat('zh-CN', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(Number(value));
const date = (value: number) => new Date(value * 1000).toLocaleString('zh-CN', { timeZone: 'UTC', hour12: false });

function Trend({ rows }: { rows: History['trend'] }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || !rows.length) return;
    const chart = echarts.init(target.current);
    const days = [...new Set(rows.map((r) => r.day))].sort();
    const kinds = [...new Set(rows.map((r) => r.type))];
    const counts = new Map(rows.map((r) => [r.day + ':' + r.type, r.count]));
    chart.setOption({
      animation: false,
      backgroundColor: '#ffffff',
      color: ['#087bff', '#dc2626', '#147468', '#d97706', '#7c3aed'],
      aria: {
        enabled: true,
        label: { description: `UTC 每日记录笔数，共 ${rows.reduce((n, r) => n + r.count, 0)} 笔。` },
      },
      tooltip: {
        trigger: 'axis',
        renderMode: 'richText',
        backgroundColor: '#ffffff',
        borderColor: '#cedae7',
        borderWidth: 1,
        textStyle: { color: '#0b1636', fontSize: 12 },
      },
      legend: { type: 'scroll', textStyle: { color: '#31485e' }, top: 4 },
      grid: { left: 40, right: 15, top: 48, bottom: 35, containLabel: true },
      xAxis: {
        type: 'category',
        data: days,
        axisLabel: { color: '#475569' },
        axisLine: { lineStyle: { color: '#cedae7' } },
      },
      yAxis: {
        type: 'value',
        min: 0,
        minInterval: 1,
        axisLabel: { color: '#475569' },
        splitLine: { lineStyle: { color: '#e1ebf4' } },
      },
      series: kinds.map((kind) => ({
        name: label(kind),
        type: 'bar',
        stack: 'records',
        barMaxWidth: 40,
        itemStyle: { color: kindColors[kind] || '#64748b' },
        data: days.map((day) => counts.get(day + ':' + kind) ?? 0),
      })),
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(target.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [rows]);
  if (!rows.length) return <p className="py-12 text-center text-sm text-[#506483]">当前筛选没有历史记录</p>;
  return <div ref={target} className="h-72 w-full overflow-hidden rounded-xl border border-[#dce5ef] bg-white p-2" role="img" aria-label="按 UTC 日期分组的记录笔数" />;
}

function DailyRevenueChart({ items }: { items: DailyAnalyticsResponse['daily'] }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!target.current || !items.length) return;
    const chart = echarts.init(target.current);
    const sorted = [...items].reverse();
    const dates = sorted.map((i) => i.date);
    const gmvs = sorted.map((i) => Number(i.orders_amount));
    const refunds = sorted.map((i) => Number(i.refunds_amount));
    const nets = sorted.map((i) => Number(i.net_revenue));

    chart.setOption({
      animation: false,
      backgroundColor: '#ffffff',
      tooltip: {
        trigger: 'axis',
        renderMode: 'richText',
        backgroundColor: '#ffffff',
        borderColor: '#cedae7',
        borderWidth: 1,
        textStyle: { color: '#0b1636', fontSize: 12 },
      },
      legend: {
        textStyle: { color: '#31485e' },
        top: 4,
        data: ['总销售额(GMV)', '退款支出', '净收益'],
      },
      grid: { left: 50, right: 20, top: 48, bottom: 35, containLabel: true },
      xAxis: {
        type: 'category',
        data: dates,
        axisLabel: { color: '#475569', rotate: dates.length > 10 ? 30 : 0 },
        axisLine: { lineStyle: { color: '#cedae7' } },
      },
      yAxis: {
        type: 'value',
        axisLabel: { color: '#475569' },
        splitLine: { lineStyle: { color: '#e1ebf4' } },
      },
      series: [
        { name: '总销售额(GMV)', type: 'bar', data: gmvs, itemStyle: { color: '#087bff' }, barMaxWidth: 24 },
        { name: '退款支出', type: 'bar', data: refunds, itemStyle: { color: '#dc2626' }, barMaxWidth: 24 },
        { name: '净收益', type: 'line', data: nets, itemStyle: { color: '#147468' }, lineStyle: { width: 3 } },
      ],
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(target.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [items]);
  if (!items.length) return <p className="py-12 text-center text-sm text-[#506483]">暂无日度统计数据</p>;
  return <div ref={target} className="h-72 w-full overflow-hidden rounded-xl border border-[#dce5ef] bg-white p-2" />;
}

export function CommerceView() {
  const [tab, setTab] = useState<'overview' | 'analytics' | 'risk' | 'loyalty' | 'blocklist' | 'settings'>('overview');
  const [settings, setSettings] = useState<Settings | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [apiKey, setApiKey] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
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

  const [dailyData, setDailyData] = useState<DailyAnalyticsResponse | null>(null);
  const [monthlyData, setMonthlyData] = useState<MonthlyAnalyticsItem[] | null>(null);
  const [riskData, setRiskData] = useState<RiskAnalysisResponse | null>(null);
  const [loyaltyData, setLoyaltyData] = useState<LoyaltyUserItem[] | null>(null);
  const [blockedUsers, setBlockedUsers] = useState<BlockedUserItem[]>([]);
  const [autoSyncSettings, setAutoSyncSettings] = useState<CommerceAutoSyncSettings | null>(null);

  const [confirmDeleteKey, setConfirmDeleteKey] = useState(false);
  const [confirmUnblockUserId, setConfirmUnblockUserId] = useState<string | null>(null);

  const [compensateModal, setCompensateModal] = useState<{
    open: boolean;
    vm_id: string;
    user_name: string;
    machine_name: string;
    price_monthly: string | null;
    days: number;
    busy: boolean;
    error: string;
    success: string;
  }>({ open: false, vm_id: '', user_name: '', machine_name: '', price_monthly: null, days: 3, busy: false, error: '', success: '' });

  const [blockModal, setBlockModal] = useState<{
    open: boolean;
    vm_id: string;
    user_name: string;
    reason: string;
    busy: boolean;
    error: string;
    success: string;
  }>({ open: false, vm_id: '', user_name: '', reason: '频繁买退 / 恶意占用资源', busy: false, error: '', success: '' });

  useEffect(() => {
    const controller = new AbortController();
    request<Settings>('/api/v1/commerce/settings', { signal: controller.signal })
      .then(setSettings)
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      });
    request<Overview>('/api/v1/commerce/overview', { signal: controller.signal })
      .then(setOverview)
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      });
    request<CommerceAutoSyncSettings>('/api/v1/commerce/notification-settings', { signal: controller.signal })
      .then(setAutoSyncSettings)
      .catch(() => {});
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    if (!overview?.available) return;
    const controller = new AbortController();
    if (tab === 'analytics') {
      request<DailyAnalyticsResponse>('/api/v1/commerce/daily-analytics?days=30', { signal: controller.signal })
        .then(setDailyData)
        .catch(() => {});
      request<MonthlyAnalyticsItem[]>('/api/v1/commerce/monthly-analytics?months=12', { signal: controller.signal })
        .then(setMonthlyData)
        .catch(() => {});
    } else if (tab === 'risk') {
      request<RiskAnalysisResponse>('/api/v1/commerce/risk-analysis', { signal: controller.signal })
        .then(setRiskData)
        .catch(() => {});
    } else if (tab === 'loyalty') {
      request<LoyaltyUserItem[]>('/api/v1/commerce/loyalty-users', { signal: controller.signal })
        .then(setLoyaltyData)
        .catch(() => {});
    } else if (tab === 'blocklist') {
      request<BlockedUsersResponse>('/api/v1/commerce/blocked-users', { signal: controller.signal })
        .then((res) => setBlockedUsers(res.items || []))
        .catch(() => {});
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
        else {
          setError(state.last_error);
          setRevision((r) => r + 1);
        }
      } catch (e) {
        if (!controller.signal.aborted) setError(e instanceof Error ? e.message : '同步状态读取失败');
      }
    };
    timer = setTimeout(poll, 2000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [settings?.syncing, busy]);

  useEffect(() => {
    if (!settings?.configured || busy) return;
    const interval = setInterval(async () => {
      try {
        const state = await request<Settings>('/api/v1/commerce/settings');
        if (state.synced_at && state.synced_at !== settings.synced_at) {
          setRevision((r) => r + 1);
        }
      } catch {}
    }, 30000);
    return () => clearInterval(interval);
  }, [settings?.configured, settings?.synced_at, busy]);

  const entrySyncTriggered = useRef(false);
  useEffect(() => {
    if (!overview || entrySyncTriggered.current) return;
    if (!settings?.configured || settings?.syncing || busy) return;
    const age = Math.floor(Date.now() / 1000) - (overview.synced_at || 0);
    if (overview.stale || age >= 300 || !overview.available) {
      entrySyncTriggered.current = true;
      request<{ ok: boolean; syncing: boolean }>('/api/v1/commerce/sync', { method: 'POST' })
        .then(() => {
          setSettings((prev) => (prev ? { ...prev, syncing: true } : prev));
        })
        .catch(() => {});
    }
  }, [overview, settings?.configured, settings?.syncing, busy]);

  useEffect(() => {
    setHistory(null);
    setHistoryError('');
    if (!overview?.available) return;
    if (start && end && start > end) {
      setHistoryError('开始日期不能晚于结束日期');
      return;
    }
    const controller = new AbortController();
    const query = new URLSearchParams({
      ledger: String(ledger),
      machine,
      kind,
      offset: String(offset),
      limit: '50',
    });
    if (start) query.set('start', String(Date.parse(start + 'T00:00:00Z') / 1000));
    if (end) query.set('end', String(Date.parse(end + 'T23:59:59Z') / 1000));
    request<History>('/api/v1/commerce/history?' + query, { signal: controller.signal })
      .then(setHistory)
      .catch((e) => {
        if (!controller.signal.aborted) setHistoryError(e.message);
      });
    return () => controller.abort();
  }, [overview, ledger, start, end, machine, kind, offset]);

  async function act(action: 'save' | 'sync' | 'delete') {
    if (busy) return;
    setBusy(action);
    setError('');
    setNotice('');
    let saved = false;
    try {
      if (action === 'save') {
        await request('/api/v1/commerce/settings', {
          method: 'POST',
          body: JSON.stringify({ api_key: apiKey.trim() }),
        });
        saved = true;
        setSettings({
          configured: true,
          updated_at: Math.floor(Date.now() / 1000),
          synced_at: 0,
          last_error: '',
          api_url: settings?.api_url || '',
          syncing: false,
        });
        setEditingKey(false);
        setApiKey('');
        setOverview(null);
        setHistory(null);
        setNotice('密钥已加密保存，正在同步数据…');
        await synchronize();
        setNotice('个人 API Key 已配置，经营数据已同步');
      } else if (action === 'sync') {
        await synchronize();
        setNotice('已完成同步');
      } else {
        await request('/api/v1/commerce/settings', { method: 'DELETE' });
        setSettings({
          configured: false,
          updated_at: 0,
          synced_at: 0,
          last_error: '',
          api_url: settings?.api_url || '',
          syncing: false,
        });
        setEditingKey(false);
        setApiKey('');
        setOverview(null);
        setHistory(null);
        setNotice('个人密钥和缓存已删除');
      }
    } catch (e) {
      setNotice(saved ? 'API Key 已保存；数据同步未完成，可直接重试同步，无需重新输入密钥。' : '');
      setError(e instanceof Error ? e.message : '操作失败');
    } finally {
      setBusy('');
      setOffset(0);
      setRevision((r) => r + 1);
      setConfirmDeleteKey(false);
    }
  }

  async function synchronize() {
    await request('/api/v1/commerce/sync', { method: 'POST' });
    for (let n = 0; n < 125; n++) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
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
    setCompensateModal((m) => ({ ...m, busy: true, error: '', success: '' }));
    try {
      await request('/api/v1/commerce/compensate', {
        method: 'POST',
        body: JSON.stringify({ vm_id: compensateModal.vm_id, days: compensateModal.days }),
      });
      setCompensateModal((m) => ({
        ...m,
        busy: false,
        success: `已成功为小鸡赠送 ${m.days} 天可用时长！上游已自动延长 expires_at。`,
      }));
      setTimeout(() => {
        setCompensateModal((m) => ({ ...m, open: false }));
        setRevision((r) => r + 1);
      }, 1500);
    } catch (e) {
      setCompensateModal((m) => ({
        ...m,
        busy: false,
        error: e instanceof Error ? e.message : '赠送时长失败',
      }));
    }
  }

  async function executeBlockUser() {
    if (blockModal.busy) return;
    setBlockModal((m) => ({ ...m, busy: true, error: '', success: '' }));
    try {
      await request('/api/v1/commerce/block-user', {
        method: 'POST',
        body: JSON.stringify({ vm_id: blockModal.vm_id, reason: blockModal.reason }),
      });
      setBlockModal((m) => ({
        ...m,
        busy: false,
        success: '买家已被成功列入黑名单！其在您名下所有母鸡上的自动续费已被关停，且无法再次购买或接收实例。',
      }));
      setTimeout(() => {
        setBlockModal((m) => ({ ...m, open: false }));
        setRevision((r) => r + 1);
      }, 1500);
    } catch (e) {
      setBlockModal((m) => ({
        ...m,
        busy: false,
        error: e instanceof Error ? e.message : '拉黑操作失败',
      }));
    }
  }

  async function executeUnblockUser(userId: string) {
    try {
      await request(`/api/v1/commerce/blocked-users/${userId}`, { method: 'DELETE' });
      setNotice('买家已成功从黑名单移除');
      setRevision((r) => r + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : '解除拉黑失败');
    } finally {
      setConfirmUnblockUserId(null);
    }
  }

  async function saveAutoSync(updated: Partial<CommerceAutoSyncSettings>) {
    if (!autoSyncSettings) return;
    const next = { ...autoSyncSettings, ...updated };
    setAutoSyncSettings(next);
    try {
      await request('/api/v1/commerce/notification-settings', {
        method: 'POST',
        body: JSON.stringify(next),
      });
      setNotice('自动同步与 Telegram 推送设置已保存');
    } catch (e) {
      setError(e instanceof Error ? e.message : '保存设置失败');
    }
  }

  async function testTelegramPush() {
    try {
      setNotice('正在向 Telegram 发送测试卡片…');
      const res = await request<{ ok: boolean; sent_count: number }>('/api/v1/commerce/test-telegram', {
        method: 'POST',
      });
      setNotice(`测试卡片已成功推送到 ${res.sent_count} 个 Telegram 机器人通道！`);
    } catch (e) {
      setError(e instanceof Error ? e.message : '发送测试失败');
    }
  }

  const machines = overview?.machines || [];
  const names = useMemo(() => Object.fromEntries(machines.map((m) => [m.id, m.name])), [machines]);
  const totalSold = machines.reduce((n, m) => n + m.sold_current, 0);
  const largest = Math.max(1, ...machines.map((m) => m.observed_vms));
  const reset = () => {
    setStart('');
    setEnd('');
    setMachine('');
    setKind('');
    setOffset(0);
  };

  const abnormalCount =
    (riskData?.watchlist?.length || 0) +
    (riskData?.abnormal_machines?.filter((m) => m.is_abnormal)?.length || 0);

  return (
    <div className="space-y-6 text-[#0b1636] [&_button]:cursor-pointer">
      {/* Header Card */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="min-w-0">
            <span className="rn2-eyebrow block">COMMERCE &amp; REVENUE · OPERATIONS HUB</span>
            <h2 className="mt-0.5 text-lg font-bold text-white sm:text-xl">经营分析与运营中台</h2>
            <p className="mt-0.5 text-xs text-[#b9d3ee]">
              母鸡出租现状 · 智能买退风控 · 用户忠诚度评估 · 实时 Telegram 经营通知
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {settings?.configured && autoSyncSettings && (
              autoSyncSettings.auto_sync ? (
                <span className="rn2-pill rn2-pill-teal hidden sm:inline-flex">
                  <span className="h-2 w-2 rounded-full bg-[#147468]" aria-hidden="true" />
                  后台自动定时同步中 ({Math.round(autoSyncSettings.interval_seconds / 60)} 分钟/次)
                </span>
              ) : (
                <span className="rn2-pill rn2-pill-slate hidden sm:inline-flex">后台自动同步未开启</span>
              )
            )}
            <button
              type="button"
              className="rn2-btn rn2-btn-orange rn2-btn-sm"
              disabled={!settings?.configured || !!busy || settings.syncing}
              onClick={() => act('sync')}
            >
              <RefreshCw
                className={'h-4 w-4 ' + (busy || settings?.syncing ? 'motion-safe:animate-spin' : '')}
                aria-hidden="true"
              />
              {busy || settings?.syncing ? '正在处理…' : '立即手动同步'}
            </button>
          </div>
        </div>
      </section>

      {error && (
        <p role="alert" className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 text-sm font-medium text-[#b41835]">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="rounded-xl border border-[#9de2d8] bg-[#e6f7f4] p-4 text-sm font-medium text-[#147468]">
          {notice}
        </p>
      )}
      {settings?.syncing && !busy && (
        <p role="status" className="rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] px-4 py-3 text-sm font-medium text-[#0657b8]">
          后台同步进行中，完成后自动刷新；离开页面不会取消任务。
        </p>
      )}

      {/* Personal Key Configuration Card (shown immediately if not configured or editing) */}
      {(!settings?.configured || editingKey) && (
        <section className="rn2-card overflow-hidden" aria-labelledby="personal-key-heading">
          <div className="rn2-card-head">
            <div className="flex items-center gap-2.5">
              <KeyRound className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
              <div>
                <span className="rn2-eyebrow block">PERSONAL API CREDENTIAL</span>
                <h3 id="personal-key-heading" className="text-base font-bold text-white">
                  个人 API Key
                </h3>
              </div>
            </div>
            <span className={`rn2-pill ${settings?.configured ? 'rn2-pill-teal' : 'rn2-pill-amber'}`}>
              {settings ? (settings.configured ? '已保存 · 已加密' : '未配置') : '加载中…'}
            </span>
          </div>

          <div className="p-5 sm:p-6">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                act('save');
              }}
              className="flex flex-col gap-3 sm:flex-row sm:items-end"
            >
              <div className="min-w-0 flex-1">
                <label className="block text-sm font-semibold text-[#0b1636]" htmlFor="commerce-key">
                  {settings?.configured ? '新的个人 API Key' : '配置个人 API Key'}
                </label>
                <div className="relative mt-2">
                  <input
                    id="commerce-key"
                    type={showApiKey ? 'text' : 'password'}
                    autoComplete="off"
                    autoFocus={editingKey}
                    spellCheck={false}
                    maxLength={512}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="rn2-input pr-12 font-mono"
                    placeholder="输入 Narwhal 平台个人 API Key"
                    aria-describedby="key-help"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey((v) => !v)}
                    aria-label={showApiKey ? '隐藏个人 API Key' : '显示个人 API Key'}
                    aria-pressed={showApiKey}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#506483] hover:text-[#087bff]"
                  >
                    {showApiKey ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  </button>
                </div>
              </div>
              <button
                type="submit"
                className="rn2-btn rn2-btn-orange shrink-0"
                disabled={!!busy || !apiKey.trim()}
              >
                {busy === 'save' ? '校验并保存…' : settings?.configured ? '保存新密钥并同步' : '保存并同步'}
              </button>
              {editingKey && (
                <button
                  type="button"
                  className="rn2-btn rn2-btn-ghost shrink-0"
                  disabled={!!busy}
                  onClick={() => {
                    setApiKey('');
                    setEditingKey(false);
                  }}
                >
                  取消更换
                </button>
              )}
            </form>
            <p id="key-help" className="mt-3 text-xs leading-6 text-[#506483]">
              仅用于当前登录用户的数据查询，加密保存在服务端；不修改全局买家通知配置，不执行购买或退款操作。
              <a
                className="ml-2 font-semibold text-[#087bff] underline hover:text-[#0657b8]"
                href="https://api.fuckip.me/openapi.yaml"
                target="_blank"
                rel="noreferrer"
              >
                接口文档
              </a>
            </p>
          </div>
        </section>
      )}

      {/* Light-Ice Tabs Bar */}
      <div className="flex gap-1.5 overflow-x-auto rounded-xl border border-[#cedae7] bg-white p-1.5 shadow-xs text-sm">
        {[
          { key: 'overview', label: '概览与走势', Icon: BarChart3, badge: null },
          { key: 'analytics', label: '日度与月度经营', Icon: Calendar, badge: null },
          { key: 'risk', label: '异常退款与重点关注', Icon: ShieldAlert, badge: abnormalCount > 0 ? abnormalCount : null },
          { key: 'loyalty', label: '用户忠诚与奖励', Icon: Award, badge: null },
          { key: 'blocklist', label: '黑名单管理', Icon: Ban, badge: blockedUsers.length > 0 ? blockedUsers.length : null },
          { key: 'settings', label: '同步与推送设置', Icon: SettingsIcon, badge: null },
        ].map(({ key, label: tabLabel, Icon, badge }) => (
          <button
            key={key}
            type="button"
            className={`flex min-h-11 items-center gap-2 whitespace-nowrap rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors sm:text-sm ${
              tab === key
                ? 'bg-[#087bff] text-white shadow-xs'
                : 'text-[#31485e] hover:bg-[#f4f8fd] hover:text-[#087bff]'
            }`}
            onClick={() => setTab(key as typeof tab)}
          >
            <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{tabLabel}</span>
            {badge != null && (
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[11px] font-bold ${
                  tab === key ? 'bg-white/20 text-white' : 'border border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]'
                }`}
              >
                {badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW */}
      {tab === 'overview' && (
        <div className="space-y-6">
          {!overview ? (
            <p role="status" className="rounded-xl border border-[#cedae7] bg-white p-6 text-sm text-[#506483]">
              正在加载个人经营数据…
            </p>
          ) : !overview.available ? (
            <div className="rn2-card p-6">
              <ShoppingBag className="mb-3 h-8 w-8 text-[#087bff]" aria-hidden="true" />
              <h3 className="font-bold text-[#0b1636]">还没有个人经营数据</h3>
              <p className="mt-2 text-sm text-[#506483]">
                {settings?.configured
                  ? '点击“同步经营数据”获取上游数据。'
                  : '在“同步与推送设置”中配置个人 API Key 后即可查看。'}
              </p>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2 text-xs text-[#506483]">
                <span className="font-mono font-semibold text-[#31485e]">
                  上次成功同步：{date(overview.synced_at)} UTC
                </span>
                <span>· 上游快照，非实时财务报表 · USD</span>
                {autoSyncSettings?.auto_sync && (
                  <span className="rn2-pill rn2-pill-teal rn2-pill-sm">
                    后台按每 {Math.round(autoSyncSettings.interval_seconds / 60)} 分钟自动同步并静默刷新
                  </span>
                )}
              </div>

              {overview.stale && (
                <p
                  role="status"
                  className="flex gap-2.5 rounded-xl border border-[#f7d58b] bg-[#fef6e4] p-3.5 text-sm font-medium text-[#9a5b00]"
                >
                  <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden="true" />
                  <span>
                    {overview.last_error ||
                      (autoSyncSettings?.auto_sync
                        ? '快照数据超过 15 分钟未刷新，后台正在等待下个轮询周期自动重试，也可点击上方“立即手动同步”。'
                        : '数据已超过 15 分钟，请手动同步获取最新情况或至“同步与推送设置”开启自动定时同步。')}{' '}
                    当前仍展示上次成功快照。
                  </span>
                </p>
              )}

              {/* Account Snapshot 5-col Spec Strip */}
              <section className="rn2-card overflow-hidden" aria-label="当前账号快照">
                <div className="rn2-card-head">
                  <div>
                    <span className="rn2-eyebrow block">ACCOUNT SNAPSHOT · USD</span>
                    <h3 className="mt-0.5 text-base font-bold text-white">当前账号余额与售出快照</h3>
                  </div>
                  <span className="font-mono text-xs text-[#cde8ff]">
                    {machines.length} 台母鸡 · {totalSold} 台售出
                  </span>
                </div>
                <div className="rn2-spec-strip grid-cols-1 divide-y divide-[#d2dfec] sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-3 xl:grid-cols-5">
                  {[
                    [
                      '母鸡 / 当前售出小鸡',
                      `${machines.length} / ${totalSold}`,
                      '售出指当前归属其他用户的小鸡；不是累计销量',
                      'text-[#087bff]',
                    ],
                    [
                      '可用余额（不可提现）',
                      usd(overview.profile?.available_balance),
                      '用于平台消费，不属于可提现的托管资金',
                      'text-[#0b1636]',
                    ],
                    [
                      '托管总余额',
                      usd(overview.profile?.escrow_balance),
                      '托管可用与冻结金额之和，不等于净利润',
                      'text-[#0b1636]',
                    ],
                    [
                      '托管可用余额',
                      usd(overview.profile?.escrow_available_balance),
                      '托管总余额减去冻结金额；提现以平台规则为准',
                      'text-[#147468]',
                    ],
                    [
                      '托管冻结金额',
                      usd(overview.profile?.escrow_locked_value),
                      '尚未解冻，暂不可提现',
                      'text-[#9a5b00]',
                    ],
                  ].map(([title, value, hint, toneClass]) => (
                    <div key={title} role="group" aria-label={title} className="rn2-spec-cell p-4 sm:p-5">
                      <p className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">{title}</p>
                      <p className={`mt-2 wrap-break-word font-mono text-2xl font-bold tabular-nums ${toneClass}`}>
                        {value}
                      </p>
                      <p className="mt-2 text-xs leading-5 text-[#506483]">{hint}</p>
                    </div>
                  ))}
                </div>
              </section>

              {/* Machine Sales Table */}
              <section className="rn2-card overflow-hidden" aria-labelledby="machine-sales-heading">
                <div className="rn2-card-head">
                  <div className="flex items-center gap-2.5">
                    <Server className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                    <div>
                      <span className="rn2-eyebrow block">HOST PROFITABILITY</span>
                      <h3 id="machine-sales-heading" className="text-base font-bold text-white">
                        各母鸡出售现状
                      </h3>
                    </div>
                  </div>
                </div>
                <div className="p-5 sm:p-6">
                  <p className="mb-4 text-xs leading-6 text-[#506483]">
                    当前售出与自用分开计算。收益、冻结值由平台直接提供；已结算收益不含退款、补偿及进行中的冻结值。
                  </p>
                  {!machines.length ? (
                    <p className="py-8 text-center text-sm text-[#506483]">
                      当前账号没有母鸡；仍可在下方查看个人购买与退款历史。
                    </p>
                  ) : (
                    <div tabIndex={0} role="region" aria-label="各母鸡出售现状表格" className="rn2-table-wrap">
                      <table className="w-full min-w-[780px] text-left text-sm">
                        <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                          <tr>
                            {['母鸡', '当前小鸡（售出 / 自用）', '买家数', '预估收益 USD', '已结算收益 USD', '冻结值 USD'].map(
                              (h) => (
                                <th key={h} className="px-3.5 py-3">
                                  {h}
                                </th>
                              )
                            )}
                          </tr>
                        </thead>
                        <tbody>
                          {machines.map((m) => (
                            <tr key={m.id}>
                              <td className="max-w-56 px-3.5 py-4">
                                <button
                                  type="button"
                                  className="text-left font-bold text-[#087bff] underline decoration-[#087bff]/40 underline-offset-4 hover:text-[#0657b8]"
                                  onClick={() => {
                                    setLedger(false);
                                    setMachine(m.id);
                                    setOffset(0);
                                  }}
                                  title={m.id}
                                >
                                  {m.name || m.id}
                                </button>
                                <p className="mt-1 text-xs text-[#506483]">
                                  {m.region} · {m.status === 'online' ? '在线' : m.status === 'offline' ? '离线' : m.status}
                                </p>
                              </td>
                              <td className="min-w-44 px-3.5 py-4">
                                <p className="font-mono font-semibold text-[#0b1636] tabular-nums">
                                  {m.sold_current} / {m.self_current}
                                </p>
                                <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-[#e8f1fb]" aria-hidden="true">
                                  <span
                                    className="bg-[#087bff]"
                                    style={{ width: `${(m.sold_current / largest) * 100}%` }}
                                  />
                                  <span
                                    className="bg-[#94a3b8]"
                                    style={{ width: `${(m.self_current / largest) * 100}%` }}
                                  />
                                </div>
                              </td>
                              <td className="px-3.5 py-4 font-mono tabular-nums">{m.buyer_count}</td>
                              <td className="px-3.5 py-4 font-mono tabular-nums">{usd(m.est_revenue)}</td>
                              <td className="px-3.5 py-4 font-mono font-bold text-[#147468] tabular-nums">
                                {usd(m.earned_revenue)}
                              </td>
                              <td className="px-3.5 py-4 font-mono tabular-nums">{usd(m.locked_value)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </section>

              {/* History Section */}
              <section className="rn2-card overflow-hidden" aria-labelledby="billing-heading">
                <div className="rn2-card-head">
                  <div className="flex items-center gap-2.5">
                    <Receipt className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                    <div>
                      <span className="rn2-eyebrow block">ORDERS &amp; LEDGER</span>
                      <h3 id="billing-heading" className="text-base font-bold text-white">
                        购买、退款与账单明细
                      </h3>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {[false, true].map((value) => (
                      <button
                        key={String(value)}
                        type="button"
                        className={`rn2-btn rn2-btn-sm ${ledger === value ? 'rn2-btn-blue' : 'rn2-btn-ghost'}`}
                        aria-pressed={ledger === value}
                        onClick={() => {
                          setLedger(value);
                          setMachine('');
                          setKind('');
                          setOffset(0);
                        }}
                      >
                        {value ? '账单流水' : '订单历史'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-5 p-5 sm:p-6">
                  <div className="grid gap-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4 sm:grid-cols-2 lg:grid-cols-5">
                    <label className="text-xs font-semibold text-[#31485e]">
                      开始日期（UTC）
                      <input
                        type="date"
                        value={start}
                        onChange={(e) => {
                          setStart(e.target.value);
                          setOffset(0);
                        }}
                        className="rn2-input mt-1.5"
                      />
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      结束日期（UTC）
                      <input
                        type="date"
                        value={end}
                        onChange={(e) => {
                          setEnd(e.target.value);
                          setOffset(0);
                        }}
                        className="rn2-input mt-1.5"
                      />
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      订单归属母鸡
                      <select
                        value={machine}
                        onChange={(e) => {
                          setMachine(e.target.value);
                          setOffset(0);
                        }}
                        className="rn2-select mt-1.5"
                      >
                        <option value="">全部归属</option>
                        <option value="unknown">归属未知</option>
                        {machines.map((m) => (
                          <option key={m.id} value={m.id}>
                            {m.name || m.id}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      记录类型
                      <select
                        value={kind}
                        onChange={(e) => {
                          setKind(e.target.value);
                          setOffset(0);
                        }}
                        className="rn2-select mt-1.5"
                      >
                        <option value="">全部类型</option>
                        {Object.keys(labels).map((k) => (
                          <option key={k} value={k}>
                            {label(k)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="button" className="rn2-btn rn2-btn-ghost self-end" onClick={reset}>
                      重置历史筛选
                    </button>
                  </div>

                  {historyError ? (
                    <p role="alert" className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-3 text-sm text-[#b41835]">
                      {historyError}
                    </p>
                  ) : !history ? (
                    <p role="status" className="py-12 text-center text-[#506483]">
                      正在加载历史记录…
                    </p>
                  ) : (
                    <>
                      <div className="flex flex-wrap gap-3 text-sm font-semibold text-[#0b1636]">
                        <span>筛选内共 {history.total} 笔</span>
                        {history.unmapped != null && (
                          <span className="font-normal text-[#506483]">· {history.unmapped} 笔归属未知</span>
                        )}
                      </div>
                      <h4 className="text-sm font-bold text-[#0b1636]">每日记录笔数（UTC）</h4>
                      <Trend rows={history.trend} />

                      <div className="flex flex-wrap gap-3">
                        {history.totals.map((t) => (
                          <div
                            key={t.type + t.balance_type}
                            className="rounded-xl border border-[#cedae7] bg-[#f4f8fd] px-4 py-3 text-sm"
                          >
                            <span className="text-xs font-semibold text-[#506483]">
                              {label(t.type)}
                              {t.balance_type ? ` / ${t.balance_type === 'escrow' ? '托管' : '可用'}` : ''} · {t.count} 笔
                            </span>
                            <p className="mt-1 font-mono font-bold text-[#0b1636] tabular-nums">{usd(t.amount)}</p>
                          </div>
                        ))}
                      </div>

                      <div tabIndex={0} role="region" aria-label="订单与账单流水表格" className="rn2-table-wrap">
                        <table className="w-full min-w-[760px] text-left text-sm">
                          <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                            <tr>
                              {['时间 UTC', '类型', '金额 USD', ledger ? '余额账户 / 变动后余额' : '母鸡归属', '记录 / 小鸡 ID'].map(
                                (h) => (
                                  <th key={h} className="px-3.5 py-3">
                                    {h}
                                  </th>
                                )
                              )}
                            </tr>
                          </thead>
                          <tbody>
                            {history.items.map((r) => (
                              <tr key={r.id}>
                                <td className="whitespace-nowrap px-3.5 py-3 font-mono text-xs text-[#31485e]">
                                  {date(r.created_at)}
                                </td>
                                <td className="px-3.5 py-3 font-medium">
                                  {label(r.type)}
                                  {r.status && (
                                    <p className="mt-1 text-xs text-[#506483]">
                                      {r.status === 'completed' ? '已完成' : r.status}
                                    </p>
                                  )}
                                </td>
                                <td className="whitespace-nowrap px-3.5 py-3 font-mono font-semibold tabular-nums">
                                  {usd(r.amount)}
                                </td>
                                <td className="max-w-56 wrap-break-word px-3.5 py-3 text-[#31485e]">
                                  {ledger
                                    ? `${r.balance_type === 'escrow' ? '托管' : '可用'} / ${usd(r.balance_after)}`
                                    : r.machine_id
                                      ? r.machine_name || names[r.machine_id] || r.machine_id
                                      : '归属未知'}
                                </td>
                                <td className="px-3.5 py-3 font-mono text-xs text-[#31485e]">
                                  <p>{r.id}</p>
                                  {r.vm_id && <p className="mt-1 text-[#506483]">VM {r.vm_id}</p>}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </section>
            </>
          )}
        </div>
      )}

      {/* TAB 2: DAILY & MONTHLY ANALYTICS */}
      {tab === 'analytics' && (
        <div className="space-y-6">
          {dailyData?.today_summary && (
            <section className="rn2-card overflow-hidden" aria-label="今日经营指标">
              <div className="rn2-card-head">
                <div>
                  <span className="rn2-eyebrow block">TODAY METRICS · UTC</span>
                  <h3 className="mt-0.5 text-base font-bold text-white">今日经营关键指标</h3>
                </div>
              </div>
              <div className="rn2-spec-strip grid-cols-1 divide-y divide-[#d2dfec] sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4">
                <div className="rn2-spec-cell p-4 sm:p-5">
                  <p className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">今日总销售额 (GMV)</p>
                  <p className="mt-2 font-mono text-2xl font-bold text-[#087bff] tabular-nums">
                    {usd(dailyData.today_summary.gmv)}
                  </p>
                  <p className="mt-1 font-mono text-xs text-[#506483] tabular-nums">
                    共 {dailyData.today_summary.orders_count} 笔订单 · 昨日 {usd(dailyData.today_summary.yesterday_gmv)}
                  </p>
                </div>
                <div className="rn2-spec-cell p-4 sm:p-5">
                  <p className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">今日退款支出</p>
                  <p className="mt-2 font-mono text-2xl font-bold text-[#b41835] tabular-nums">
                    -{usd(dailyData.today_summary.refunds_amount)}
                  </p>
                  <p className="mt-1 font-mono text-xs text-[#506483] tabular-nums">
                    {dailyData.today_summary.refunds_count} 笔退款
                  </p>
                </div>
                <div className="rn2-spec-cell p-4 sm:p-5">
                  <p className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">今日净收益</p>
                  <p className="mt-2 font-mono text-2xl font-bold text-[#147468] tabular-nums">
                    {usd(dailyData.today_summary.net_revenue)}
                  </p>
                  <p className="mt-1 font-mono text-xs text-[#506483] tabular-nums">
                    昨日净收益 {usd(dailyData.today_summary.yesterday_net)}
                  </p>
                </div>
                <div className="rn2-spec-cell p-4 sm:p-5">
                  <p className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">今日退款率</p>
                  <p className="mt-2 font-mono text-2xl font-bold text-[#0b1636] tabular-nums">
                    {dailyData.today_summary.orders_count + dailyData.today_summary.refunds_count > 0
                      ? (
                          (dailyData.today_summary.refunds_count /
                            (dailyData.today_summary.orders_count + dailyData.today_summary.refunds_count)) *
                          100
                        ).toFixed(1)
                      : 0}
                    %
                  </p>
                  <p className="mt-1 text-xs text-[#506483]">退款笔数 / (总订单+退款)</p>
                </div>
              </div>
            </section>
          )}

          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <Calendar className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">30-DAY REVENUE TREND</span>
                  <h3 className="text-base font-bold text-white">近 30 日收支走势分析 (UTC)</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">直观展示每日新增销售额、退款支出与实际净收入趋势。</p>
              {dailyData?.daily ? (
                <DailyRevenueChart items={dailyData.daily} />
              ) : (
                <p className="py-8 text-center text-sm text-[#506483]">正在生成日度走势…</p>
              )}
            </div>
          </section>

          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <DollarSign className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">12-MONTH LEDGER SUMMARY</span>
                  <h3 className="text-base font-bold text-white">每月经营汇总月报 (近 12 个月)</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">按自然月聚合销售额、退款总额、退款率及各月热销母鸡。</p>
              {!monthlyData?.length ? (
                <p className="py-8 text-center text-sm text-[#506483]">暂无月度数据</p>
              ) : (
                <div tabIndex={0} role="region" aria-label="月度经营表格" className="rn2-table-wrap">
                  <table className="w-full min-w-[700px] text-left text-sm">
                    <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                      <tr>
                        {['月份', '新买入 / 续费', '销售额 (GMV)', '退款笔数 / 金额', '月度净收入', '退款率', '热销母鸡 Top 3'].map(
                          (h) => (
                            <th key={h} className="px-3.5 py-3">
                              {h}
                            </th>
                          )
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {monthlyData.map((m) => (
                        <tr key={m.month}>
                          <td className="whitespace-nowrap px-3.5 py-3 font-bold text-[#087bff]">{m.month}</td>
                          <td className="px-3.5 py-3 tabular-nums">
                            {m.purchases_count} 购 / {m.renewals_count} 续
                          </td>
                          <td className="px-3.5 py-3 font-mono font-semibold tabular-nums">{usd(m.orders_amount)}</td>
                          <td className="px-3.5 py-3 font-mono font-semibold text-[#b41835] tabular-nums">
                            {m.refunds_count} 笔 / -{usd(m.refunds_amount)}
                          </td>
                          <td className="px-3.5 py-3 font-mono font-bold text-[#147468] tabular-nums">
                            {usd(m.net_revenue)}
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">
                            <span className={m.refund_rate >= 15 ? 'font-bold text-[#b41835]' : 'text-[#31485e]'}>
                              {m.refund_rate}%
                            </span>
                          </td>
                          <td className="px-3.5 py-3 text-xs text-[#31485e]">
                            {m.top_machines.length
                              ? m.top_machines.map((tm) => (
                                  <span
                                    key={tm.machine_id}
                                    className="mr-2 mb-1 inline-block rounded border border-[#cedae7] bg-[#f4f8fd] px-2 py-0.5 font-mono"
                                  >
                                    {tm.machine_name}: ${tm.amount}
                                  </span>
                                ))
                              : '无'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      {/* TAB 3: RISK & WATCHLIST */}
      {tab === 'risk' && (
        <div className="space-y-6">
          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="h-5 w-5 text-[#fda4af]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">HOST REFUND RISK</span>
                  <h3 className="text-base font-bold text-white">异常退款服务器分析（母鸡维度）</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">
                识别哪些母鸡退款率畸高。注意：节点退款率偏高通常由机房网络抽风、IP 被墙或线路断流引起，建议优先排查节点网络，非买家单方面责任。
              </p>
              {!riskData?.abnormal_machines?.length ? (
                <p className="py-8 text-center text-sm text-[#506483]">正在分析各母鸡退款率…</p>
              ) : (
                <div tabIndex={0} role="region" aria-label="母鸡退款率表格" className="rn2-table-wrap">
                  <table className="w-full min-w-[700px] text-left text-sm">
                    <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                      <tr>
                        {['母鸡名称', '地区', '订单数 / 退款数', '退款总额', '退款率', '诊断与排查建议'].map((h) => (
                          <th key={h} className="px-3.5 py-3">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {riskData.abnormal_machines.map((m) => (
                        <tr key={m.machine_id} className={m.is_abnormal ? 'bg-[#ffeef1]/60' : ''}>
                          <td className="px-3.5 py-3 font-bold text-[#0b1636]">
                            <span>{m.machine_name}</span>
                            {m.is_abnormal && (
                              <span className="rn2-pill rn2-pill-crimson rn2-pill-sm ml-2">退款率高危</span>
                            )}
                          </td>
                          <td className="px-3.5 py-3 text-[#506483]">{m.region || '未知'}</td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">
                            {m.orders_count} 单 / {m.refunds_count} 退
                          </td>
                          <td className="px-3.5 py-3 font-mono font-semibold text-[#b41835] tabular-nums">
                            -{usd(m.refund_amount)}
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">
                            <span className={m.is_abnormal ? 'font-bold text-[#b41835]' : 'text-[#31485e]'}>
                              {m.refund_rate}%
                            </span>
                          </td>
                          <td className="px-3.5 py-3 text-xs text-[#31485e]">{m.suggestion}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>

          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <Users className="h-5 w-5 text-[#fcd34d]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">ABUSE WATCHLIST</span>
                  <h3 className="text-base font-bold text-white">重点关注买家清单（频繁买退 / 试用羊毛党）</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">
                自动归集多次购买并极速退款（&lt;24小时内）、退款率高、或频繁买退的买家。可在右侧直接一键拉黑，禁止其再次下单。
              </p>
              {!riskData?.watchlist?.length ? (
                <div className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] py-8 text-center text-sm text-[#506483]">
                  <CheckCircle2 className="mx-auto mb-2 h-6 w-6 text-[#147468]" aria-hidden="true" />
                  当前未发现恶意频繁买退买家，经营风控状态良好。
                </div>
              ) : (
                <div tabIndex={0} role="region" aria-label="重点关注买家表格" className="rn2-table-wrap">
                  <table className="w-full min-w-[750px] text-left text-sm">
                    <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                      <tr>
                        {[
                          '买家标识 / 邮箱',
                          '买入 / 退款',
                          '退款率',
                          '极速退款(<24h)',
                          '净消费额',
                          '风险特征标签',
                          '操作',
                        ].map((h) => (
                          <th key={h} className="px-3.5 py-3">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {riskData.watchlist.map((u) => (
                        <tr key={u.user_id}>
                          <td className="px-3.5 py-3">
                            <p className="font-bold text-[#0b1636]">{u.user_name}</p>
                            <p className="font-mono text-xs text-[#506483]">{u.user_email}</p>
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">
                            {u.total_purchases} 购 / {u.total_refunds} 退
                          </td>
                          <td className="px-3.5 py-3 font-mono font-bold text-[#b41835] tabular-nums">
                            {u.refund_rate}%
                          </td>
                          <td className="px-3.5 py-3 font-mono font-semibold text-[#9a5b00] tabular-nums">
                            {u.quick_refunds} 次
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">
                            {usd(Number(u.total_spent) - Number(u.total_refunded))}
                          </td>
                          <td className="px-3.5 py-3">
                            <div className="flex flex-wrap gap-1">
                              {u.risk_tags.map((tag) => (
                                <span key={tag} className="rn2-pill rn2-pill-crimson rn2-pill-sm">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-3.5 py-3">
                            {u.sample_vm_id ? (
                              <button
                                type="button"
                                className="rn2-btn rn2-btn-danger rn2-btn-sm"
                                onClick={() =>
                                  setBlockModal({
                                    open: true,
                                    vm_id: u.sample_vm_id,
                                    user_name: u.user_name,
                                    reason: '频繁买退 / 试用羊毛',
                                    busy: false,
                                    error: '',
                                    success: '',
                                  })
                                }
                              >
                                <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                                拉黑买家
                              </button>
                            ) : (
                              <span className="text-xs text-[#697b9c]">无活跃VM关联</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      {/* TAB 4: USER LOYALTY & REWARDS */}
      {tab === 'loyalty' && (
        <div className="space-y-6">
          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <Award className="h-5 w-5 text-[#fcd34d]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">LOYALTY &amp; REWARDS</span>
                  <h3 className="text-base font-bold text-white">买家忠诚度评估与时长奖励中台</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">
                依据买家持续在期天数、续费频次及历史履约状态自动评估忠诚度等级。可直接为忠诚老客或受故障影响的实例一键「赠送可用时长」，从您的托管余额自扣补偿。
              </p>
              {!loyaltyData?.length ? (
                <p className="py-8 text-center text-sm text-[#506483]">正在评估买家忠诚度…</p>
              ) : (
                <div tabIndex={0} role="region" aria-label="买家忠诚度表格" className="rn2-table-wrap">
                  <table className="w-full min-w-[780px] text-left text-sm">
                    <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                      <tr>
                        {[
                          '买家标识 / 邮箱',
                          '忠诚等级徽章',
                          '在期小鸡数',
                          '累计在期天数',
                          '续费次数',
                          '累计消费 USD',
                          '活跃小鸡明细与一键奖励',
                        ].map((h) => (
                          <th key={h} className="px-3.5 py-3">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {loyaltyData.map((u) => (
                        <tr key={u.user_id}>
                          <td className="px-3.5 py-3">
                            <p className="font-bold text-[#0b1636]">{u.user_name}</p>
                            <p className="font-mono text-xs text-[#506483]">{u.user_email}</p>
                          </td>
                          <td className="px-3.5 py-3">
                            {u.loyalty_tier === 'diamond' && (
                              <span className="rn2-pill rn2-pill-blue">
                                <Gem className="h-3.5 w-3.5" aria-hidden="true" />
                                钻石老客
                              </span>
                            )}
                            {u.loyalty_tier === 'gold' && (
                              <span className="rn2-pill rn2-pill-amber">
                                <Medal className="h-3.5 w-3.5" aria-hidden="true" />
                                黄金老客
                              </span>
                            )}
                            {u.loyalty_tier === 'silver' && (
                              <span className="rn2-pill rn2-pill-slate">
                                <Award className="h-3.5 w-3.5" aria-hidden="true" />
                                常规履约
                              </span>
                            )}
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">{u.active_vms_count} 台</td>
                          <td className="px-3.5 py-3 font-mono font-semibold text-[#087bff] tabular-nums">
                            {u.estimated_tenure_days} 天
                          </td>
                          <td className="px-3.5 py-3 font-mono font-semibold text-[#147468] tabular-nums">
                            {u.renewal_count} 次
                          </td>
                          <td className="px-3.5 py-3 font-mono tabular-nums">{usd(u.total_spent)}</td>
                          <td className="px-3.5 py-3">
                            <div className="space-y-1.5">
                              {u.vms.map((vm) => (
                                <div
                                  key={vm.id}
                                  className="flex items-center justify-between gap-2 rounded-lg border border-[#dce5ef] bg-[#f4f8fd] px-2.5 py-1.5 text-xs"
                                >
                                  <span className="font-mono text-[#0b1636]" title={vm.id}>
                                    {vm.machine_name} (余 {vm.days_remaining} 天)
                                  </span>
                                  <button
                                    type="button"
                                    className="rn2-btn rn2-btn-blue rn2-btn-sm"
                                    onClick={() =>
                                      setCompensateModal({
                                        open: true,
                                        vm_id: vm.id,
                                        user_name: u.user_name,
                                        machine_name: vm.machine_name,
                                        price_monthly: vm.price_monthly,
                                        days: 3,
                                        busy: false,
                                        error: '',
                                        success: '',
                                      })
                                    }
                                  >
                                    <Gift className="h-3.5 w-3.5" aria-hidden="true" />
                                    赠送时长
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
            </div>
          </section>
        </div>
      )}

      {/* TAB 5: BLOCKLIST */}
      {tab === 'blocklist' && (
        <div className="space-y-6">
          <section className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <Ban className="h-5 w-5 text-[#fda4af]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">UPSTREAM BLOCKLIST</span>
                  <h3 className="text-base font-bold text-white">上游黑名单管理</h3>
                </div>
              </div>
            </div>
            <div className="p-5 sm:p-6">
              <p className="mb-4 text-xs text-[#506483]">
                当前被您列入黑名单的买家。被拉黑的用户无法在您拥有的任何母鸡上下单、续费或转鸡，现有实例到期后自动停止。
              </p>
              {!blockedUsers.length ? (
                <div className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] py-12 text-center text-sm text-[#506483]">
                  <CheckCircle2 className="mx-auto mb-2 h-7 w-7 text-[#147468]" aria-hidden="true" />
                  当前黑名单为空，没有被封禁的买家。
                </div>
              ) : (
                <div tabIndex={0} role="region" aria-label="黑名单表格" className="rn2-table-wrap">
                  <table className="w-full min-w-[700px] text-left text-sm">
                    <thead className="bg-[#edf5fc] text-xs font-bold text-[#31485e]">
                      <tr>
                        {['买家标识 / 用户名', '拉黑原因', '触发拉黑的实例 (VM ID)', '拉黑时间 (UTC)', '操作'].map((h) => (
                          <th key={h} className="px-3.5 py-3">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {blockedUsers.map((b) => (
                        <tr key={b.id || b.user_id}>
                          <td className="px-3.5 py-3 font-bold text-[#0b1636]">{b.user_name || b.user_id}</td>
                          <td className="px-3.5 py-3 text-xs font-medium text-[#b41835]">{b.reason || '未填写原因'}</td>
                          <td className="px-3.5 py-3 font-mono text-xs text-[#506483]">{b.vm_id || '无'}</td>
                          <td className="px-3.5 py-3 font-mono text-xs text-[#506483]">{date(b.created_at)}</td>
                          <td className="px-3.5 py-3">
                            <button
                              type="button"
                              className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                              onClick={() => setConfirmUnblockUserId(b.user_id)}
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
            </div>
          </section>
        </div>
      )}

      {/* TAB 6: SETTINGS & PUSH */}
      {tab === 'settings' && (
        <div className="space-y-6">
          <section className="rn2-card overflow-hidden" aria-labelledby="personal-key-tab-heading">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2.5">
                <KeyRound className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                <div>
                  <span className="rn2-eyebrow block">PERSONAL API KEY</span>
                  <h3 id="personal-key-tab-heading" className="text-base font-bold text-white">
                    个人 API Key
                  </h3>
                </div>
              </div>
              <span className={`rn2-pill ${settings?.configured ? 'rn2-pill-teal' : 'rn2-pill-amber'}`}>
                {settings ? (settings.configured ? '已保存 · 已加密' : '未配置') : '加载中…'}
              </span>
            </div>

            <div className="p-5 sm:p-6 space-y-4">
              {settings?.configured && (
                <div className="rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4">
                  <label className="block text-sm font-semibold text-[#0b1636]">
                    已保存的个人 API Key
                    <input
                      className="rn2-input mt-2 cursor-default font-mono text-[#506483]"
                      type="text"
                      value="••••••••（已安全保存，不显示原文）"
                      readOnly
                      autoComplete="off"
                    />
                  </label>
                  <div className="mt-3 flex flex-wrap items-center gap-3">
                    {!editingKey && (
                      <button
                        type="button"
                        className="rn2-btn rn2-btn-ghost"
                        disabled={!!busy || settings.syncing}
                        onClick={() => {
                          setApiKey('');
                          setEditingKey(true);
                        }}
                      >
                        <Pencil className="h-4 w-4" aria-hidden="true" />
                        更换 API Key
                      </button>
                    )}
                    <button
                      type="button"
                      className="rn2-btn rn2-btn-danger"
                      disabled={!!busy || settings.syncing}
                      onClick={() => setConfirmDeleteKey(true)}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                      删除 API Key
                    </button>
                    {settings.updated_at > 0 && (
                      <span className="font-mono text-xs text-[#506483]">保存时间：{date(settings.updated_at)} UTC</span>
                    )}
                  </div>
                </div>
              )}

              {settings && (!settings.configured || editingKey) && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    act('save');
                  }}
                  className="flex flex-col gap-3 sm:flex-row sm:items-end"
                >
                  <div className="min-w-0 flex-1">
                    <label className="block text-sm font-semibold text-[#0b1636]" htmlFor="commerce-key">
                      {settings.configured ? '新的个人 API Key' : '配置个人 API Key'}
                    </label>
                    <div className="relative mt-2">
                      <input
                        id="commerce-key"
                        type={showApiKey ? 'text' : 'password'}
                        autoComplete="off"
                        autoFocus={editingKey}
                        spellCheck={false}
                        maxLength={512}
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        className="rn2-input pr-12 font-mono"
                        placeholder="输入 Narwhal 平台个人 API Key"
                      />
                      <button
                        type="button"
                        onClick={() => setShowApiKey((v) => !v)}
                        aria-label={showApiKey ? '隐藏个人 API Key' : '显示个人 API Key'}
                        aria-pressed={showApiKey}
                        className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#506483] hover:text-[#087bff]"
                      >
                        {showApiKey ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                      </button>
                    </div>
                  </div>
                  <button
                    type="submit"
                    className="rn2-btn rn2-btn-orange shrink-0"
                    disabled={!!busy || !apiKey.trim()}
                  >
                    {busy === 'save' ? '校验并保存…' : settings.configured ? '保存新密钥并同步' : '保存并同步'}
                  </button>
                  {editingKey && (
                    <button
                      type="button"
                      className="rn2-btn rn2-btn-ghost shrink-0"
                      disabled={!!busy}
                      onClick={() => {
                        setApiKey('');
                        setEditingKey(false);
                      }}
                    >
                      取消更换
                    </button>
                  )}
                </form>
              )}
            </div>
          </section>

          {autoSyncSettings && (
            <section className="rn2-card overflow-hidden">
              <div className="rn2-card-head">
                <div className="flex items-center gap-2.5">
                  <Bell className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                  <div>
                    <span className="rn2-eyebrow block">AUTO SYNC &amp; DIGEST</span>
                    <h3 className="text-base font-bold text-white">自动定时同步与 Telegram 经营推送配置</h3>
                  </div>
                </div>
                <button type="button" className="rn2-btn rn2-btn-ghost rn2-btn-sm" onClick={testTelegramPush}>
                  <Send className="h-3.5 w-3.5" aria-hidden="true" />
                  测试发送 TG 经营卡片
                </button>
              </div>

              <div className="space-y-4 p-5 sm:p-6">
                <p className="text-xs text-[#506483]">
                  后台自动按周期同步 Narwhal API，在新订单买入或退款时秒级推送到绑定的 Telegram 机器人，并生成日度/月度简报。
                </p>

                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <div className="rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4">
                    <label className="flex min-h-11 cursor-pointer items-center justify-between">
                      <span className="text-sm font-bold text-[#0b1636]">后台自动定时同步</span>
                      <input
                        type="checkbox"
                        checked={autoSyncSettings.auto_sync}
                        onChange={(e) => saveAutoSync({ auto_sync: e.target.checked })}
                        className="h-5 w-5 accent-[#087bff]"
                      />
                    </label>
                    <p className="mt-1.5 text-xs text-[#506483]">自动拉取上游订单、流水与小鸡数据更新快照</p>
                    <div className="mt-3">
                      <label htmlFor="commerce-sync-interval" className="text-xs font-semibold text-[#31485e]">
                        同步轮询间隔
                      </label>
                      <select
                        id="commerce-sync-interval"
                        value={autoSyncSettings.interval_seconds}
                        onChange={(e) => saveAutoSync({ interval_seconds: Number(e.target.value) })}
                        className="rn2-select mt-1.5"
                      >
                        <option value={180}>每 3 分钟 (高频刷新)</option>
                        <option value={300}>每 5 分钟 (推荐)</option>
                        <option value={600}>每 10 分钟</option>
                        <option value={900}>每 15 分钟</option>
                        <option value={1800}>每 30 分钟</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4">
                    <span className="block text-sm font-bold text-[#0b1636]">Telegram 实时动态提醒</span>
                    <label className="flex min-h-11 cursor-pointer items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-[#31485e]">
                        <ShoppingCart className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                        新买入 / 续费订单提醒
                      </span>
                      <input
                        type="checkbox"
                        checked={autoSyncSettings.tg_notify_orders}
                        onChange={(e) => saveAutoSync({ tg_notify_orders: e.target.checked })}
                        className="h-4 w-4 accent-[#087bff]"
                      />
                    </label>
                    <label className="flex min-h-11 cursor-pointer items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-[#31485e]">
                        <AlertTriangle className="h-3.5 w-3.5 text-[#d97706]" aria-hidden="true" />
                        退款 / 托管扣减提醒
                      </span>
                      <input
                        type="checkbox"
                        checked={autoSyncSettings.tg_notify_refunds}
                        onChange={(e) => saveAutoSync({ tg_notify_refunds: e.target.checked })}
                        className="h-4 w-4 accent-[#087bff]"
                      />
                    </label>
                    <p className="text-[11px] leading-4 text-[#506483]">
                      产生新事件时，机器人将在 60 秒内将美观卡片推送至您的 Telegram 群组
                    </p>
                  </div>

                  <div className="space-y-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4">
                    <span className="block text-sm font-bold text-[#0b1636]">定期经营简报播报</span>
                    <label className="flex min-h-11 cursor-pointer items-center justify-between">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-[#31485e]">
                        <BarChart3 className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                        每日经营简报推送
                      </span>
                      <input
                        type="checkbox"
                        checked={autoSyncSettings.tg_daily_digest}
                        onChange={(e) => saveAutoSync({ tg_daily_digest: e.target.checked })}
                        className="h-4 w-4 accent-[#087bff]"
                      />
                    </label>
                    <div className="flex items-center justify-between gap-2 text-xs text-[#31485e]">
                      <span className="font-medium">每日推送时间 (UTC+8)</span>
                      <select
                        aria-label="每日推送时间"
                        value={autoSyncSettings.digest_hour}
                        onChange={(e) => saveAutoSync({ digest_hour: Number(e.target.value) })}
                        className="rn2-select-sm w-28 font-mono"
                      >
                        {[0, 6, 8, 9, 10, 12, 18, 20, 22].map((h) => (
                          <option key={h} value={h}>
                            {String(h).padStart(2, '0')}:00
                          </option>
                        ))}
                      </select>
                    </div>
                    <label className="flex min-h-11 cursor-pointer items-center justify-between border-t border-[#d2dfec] pt-2">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-[#31485e]">
                        <Calendar className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                        每月 1 日经营月报推送
                      </span>
                      <input
                        type="checkbox"
                        checked={autoSyncSettings.tg_monthly_digest}
                        onChange={(e) => saveAutoSync({ tg_monthly_digest: e.target.checked })}
                        className="h-4 w-4 accent-[#087bff]"
                      />
                    </label>
                  </div>
                </div>
              </div>
            </section>
          )}
        </div>
      )}

      {/* COMPENSATE / REWARD MODAL */}
      {compensateModal.open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#02182f]/70 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          aria-label="赠送或奖励小鸡可用时长"
        >
          <div className="rn2-card w-full max-w-md overflow-hidden shadow-2xl">
            <div className="rn2-card-head">
              <h3 className="flex items-center gap-2 font-bold text-white">
                <Gift className="h-5 w-5 text-[#54c7ff]" aria-hidden="true" />
                赠送 / 奖励小鸡可用时长
              </h3>
              <button
                type="button"
                aria-label="关闭弹窗"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-[#cde8ff] hover:bg-white/10 hover:text-white"
                onClick={() => setCompensateModal((m) => ({ ...m, open: false }))}
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
            <div className="space-y-3 p-5 text-sm sm:p-6">
              <div>
                <span className="text-xs text-[#506483]">买家标识：</span>
                <span className="ml-1 font-bold text-[#0b1636]">{compensateModal.user_name}</span>
              </div>
              <div>
                <span className="text-xs text-[#506483]">所属母鸡：</span>
                <span className="ml-1 font-bold text-[#0b1636]">{compensateModal.machine_name}</span>
              </div>
              <div>
                <span className="text-xs text-[#506483]">目标小鸡 ID：</span>
                <span className="ml-1 font-mono text-xs text-[#31485e]">{compensateModal.vm_id}</span>
              </div>

              <div className="pt-2">
                <label className="text-xs font-bold text-[#31485e]">赠送可用时长 (天数)</label>
                <div className="mt-2 grid grid-cols-5 gap-2">
                  {[1, 3, 7, 14, 30].map((d) => (
                    <button
                      key={d}
                      type="button"
                      className={`min-h-10 rounded-lg border text-xs font-bold transition-colors ${
                        compensateModal.days === d
                          ? 'border-[#087bff] bg-[#e8f3ff] text-[#0657b8]'
                          : 'border-[#cedae7] bg-white text-[#31485e] hover:border-[#087bff]'
                      }`}
                      onClick={() => setCompensateModal((m) => ({ ...m, days: d }))}
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
                  onChange={(e) =>
                    setCompensateModal((m) => ({
                      ...m,
                      days: Math.max(1, Math.min(365, Number(e.target.value) || 1)),
                    }))
                  }
                  className="rn2-input mt-2 font-mono text-sm"
                  placeholder="自定义天数 (1~365)"
                />
              </div>

              {compensateModal.price_monthly && (
                <div className="rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] p-3 text-xs leading-5 text-[#0657b8]">
                  <p className="flex items-center gap-1.5 font-semibold">
                    <Lightbulb className="h-4 w-4 shrink-0" aria-hidden="true" />
                    预估成本：约 <b>${((Number(compensateModal.price_monthly) * compensateModal.days) / 31).toFixed(2)} USD</b>
                  </p>
                  <p className="mt-0.5 text-[11px] text-[#31485e]">
                    此费用将从您的托管可用余额中扣除，小鸡到期时间将即时顺延。
                  </p>
                </div>
              )}

              {compensateModal.error && (
                <p className="text-xs font-semibold text-[#b41835]">{compensateModal.error}</p>
              )}
              {compensateModal.success && (
                <p className="text-xs font-semibold text-[#147468]">{compensateModal.success}</p>
              )}

              <div className="flex justify-end gap-3 border-t border-[#dce5ef] pt-4">
                <button
                  type="button"
                  className="rn2-btn rn2-btn-ghost"
                  disabled={compensateModal.busy}
                  onClick={() => setCompensateModal((m) => ({ ...m, open: false }))}
                >
                  取消
                </button>
                <button
                  type="button"
                  className="rn2-btn rn2-btn-orange"
                  disabled={compensateModal.busy || !compensateModal.days}
                  onClick={executeCompensate}
                >
                  {compensateModal.busy ? '正在扣减并延期…' : `确认赠送 ${compensateModal.days} 天`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* BLOCK USER MODAL */}
      {blockModal.open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#02182f]/70 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          aria-label="拉黑买家确认"
        >
          <div className="rn2-card w-full max-w-md overflow-hidden shadow-2xl">
            <div className="rn2-card-head">
              <h3 className="flex items-center gap-2 font-bold text-white">
                <Ban className="h-5 w-5 text-[#fda4af]" aria-hidden="true" />
                拉黑买家确认
              </h3>
              <button
                type="button"
                aria-label="关闭弹窗"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-[#cde8ff] hover:bg-white/10 hover:text-white"
                onClick={() => setBlockModal((m) => ({ ...m, open: false }))}
              >
                <X className="h-5 w-5" aria-hidden="true" />
              </button>
            </div>
            <div className="space-y-3 p-5 text-sm sm:p-6">
              <div className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-3 text-xs leading-5 text-[#b41835]">
                <p className="font-bold">封禁后生效规则：</p>
                <p>1. 该用户在您拥有的<b>所有母鸡</b>上均无法再新购、续费、在集市买鸡或接收 push 转移；</p>
                <p>2. 系统将自动关停该用户在您名下所有小鸡的<b>自动续费</b>；现有运行中的实例允许运行至自然到期。</p>
              </div>

              <div>
                <span className="text-xs text-[#506483]">目标买家：</span>
                <span className="ml-1 font-bold text-[#0b1636]">{blockModal.user_name}</span>
              </div>

              <div>
                <label className="text-xs font-bold text-[#31485e]">拉黑原因 (上游可展示给买家)</label>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {['频繁买退 / 试用羊毛', '端口扫描 / 恶意攻击', '严重超时占用带宽', '违反服务条款'].map((r) => (
                    <button
                      key={r}
                      type="button"
                      className="rounded-lg border border-[#cedae7] bg-[#f4f8fd] px-2.5 py-1 text-xs font-medium text-[#31485e] hover:border-[#087bff] hover:text-[#087bff]"
                      onClick={() => setBlockModal((m) => ({ ...m, reason: r }))}
                    >
                      {r}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  maxLength={500}
                  value={blockModal.reason}
                  onChange={(e) => setBlockModal((m) => ({ ...m, reason: e.target.value }))}
                  className="rn2-input mt-2 text-sm"
                  placeholder="填写拉黑原因说明"
                />
              </div>

              {blockModal.error && <p className="text-xs font-semibold text-[#b41835]">{blockModal.error}</p>}
              {blockModal.success && <p className="text-xs font-semibold text-[#147468]">{blockModal.success}</p>}

              <div className="flex justify-end gap-3 border-t border-[#dce5ef] pt-4">
                <button
                  type="button"
                  className="rn2-btn rn2-btn-ghost"
                  disabled={blockModal.busy}
                  onClick={() => setBlockModal((m) => ({ ...m, open: false }))}
                >
                  取消
                </button>
                <button
                  type="button"
                  className="rn2-btn rn2-btn-danger font-bold"
                  disabled={blockModal.busy}
                  onClick={executeBlockUser}
                >
                  {blockModal.busy ? '正在拉黑…' : '确认列入黑名单'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={confirmDeleteKey}
        title="确认删除个人 API Key？"
        description="删除当前账号的个人 API Key 和经营数据缓存？不会影响上游资源或全局买家通知。"
        confirmLabel="确认删除"
        tone="danger"
        isSubmitting={busy === 'delete'}
        onCancel={() => setConfirmDeleteKey(false)}
        onConfirm={() => void act('delete')}
      />

      <ConfirmDialog
        open={Boolean(confirmUnblockUserId)}
        title="确认解除黑名单？"
        description="确认将此买家从黑名单中移除，恢复其在您母鸡上的购买资格？"
        confirmLabel="确认解除"
        tone="primary"
        onCancel={() => setConfirmUnblockUserId(null)}
        onConfirm={() => {
          if (confirmUnblockUserId) void executeUnblockUser(confirmUnblockUserId);
        }}
      />
    </div>
  );
}
