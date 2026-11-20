import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  FileText,
  GitBranch,
  HardDrive,
  type LucideIcon,
  RefreshCw,
  Search,
  Server,
  Shield,
  Users,
  X,
} from 'lucide-react';
import { request } from '../../api/client';
import { SpecStrip } from '../../v2/components/Primitives';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { ToastMessage } from '../common/Toast';
import { AlertReplayPanel } from './AlertReplayPanel';
import { DatabaseGrowthTrend } from './DatabaseGrowthTrend';
import { DiskCleanupPanel } from './DiskCleanupPanel';

type RecordData = Record<string, any>;

const sections = [
  ['health', '1 采集健康'],
  ['rechecks', '2 处置复查'],
  ['storage', '3 存储管理'],
  ['traffic', '4 流量账本'],
  ['policies', '5 业务策略'],
  ['baseline', '6 动态基线'],
  ['incidents', '7 事件时间线'],
  ['logs', '8 日志接入'],
  ['upgrades', '9 节点升级'],
  ['services', '10 服务可用性'],
  ['inventory', '11 服务清单'],
  ['backups', '12 备份'],
  ['users', '13 权限与审计'],
  ['replay', '14 告警复盘'],
] as const;

type Section = (typeof sections)[number][0];

interface SectionGroup {
  id: string;
  title: string;
  subtitle: string;
  icon: LucideIcon;
  items: Array<{ key: Section; label: string; keywords: string }>;
}

const sectionGroups: SectionGroup[] = [
  {
    id: 'inspect',
    title: '巡检与健康',
    subtitle: '节点采集、处置复查与服务监测',
    icon: Activity,
    items: [
      { key: 'health', label: '1 采集健康', keywords: 'health rescan 采集 健康 复扫 安全审计' },
      { key: 'rechecks', label: '2 处置复查', keywords: 'rechecks action 处置 复查 动作 回执' },
      { key: 'incidents', label: '7 事件时间线', keywords: 'incidents timeline 事件 时间线 异常 恢复' },
      { key: 'services', label: '10 服务可用性', keywords: 'services probe http tcp tls 服务 可用性 探测' },
      { key: 'inventory', label: '11 服务清单', keywords: 'inventory listener port 服务 清单 监听 端口' },
    ],
  },
  {
    id: 'storage-traffic',
    title: '存储与流量',
    subtitle: '安全磁盘清理、SQLite 容量与账本',
    icon: HardDrive,
    items: [
      { key: 'storage', label: '3 存储管理', keywords: 'storage disk cleanup wal sqlite database 存储 磁盘 清理 数据库' },
      { key: 'traffic', label: '4 流量账本', keywords: 'traffic ledger rx tx 流量 账本 汇总' },
    ],
  },
  {
    id: 'policy-release',
    title: '策略与发布',
    subtitle: '带宽策略、动态基线、日志与灰度',
    icon: GitBranch,
    items: [
      { key: 'policies', label: '5 业务策略', keywords: 'policies bandwidth profile 业务 策略 带宽 静默' },
      { key: 'baseline', label: '6 动态基线', keywords: 'baseline anomaly 动态 基线 异常 告警' },
      { key: 'logs', label: '8 日志接入', keywords: 'logs nginx caddy apache access 日志 接入 发现' },
      { key: 'upgrades', label: '9 节点升级', keywords: 'upgrades canary rollout rollback 节点 升级 灰度 回滚' },
    ],
  },
  {
    id: 'audit-system',
    title: '审计与系统',
    subtitle: '一致性备份、RBAC 权限与复盘',
    icon: Shield,
    items: [
      { key: 'backups', label: '12 备份', keywords: 'backups drill sqlite 备份 恢复 演练' },
      { key: 'users', label: '13 权限与审计', keywords: 'users rbac audit 权限 用户 角色 审计' },
      { key: 'replay', label: '14 告警复盘', keywords: 'replay conntrack 告警 复盘 回放' },
    ],
  },
];

const validSectionIds = new Set<string>(sections.map(([key]) => key));

const resolveSection = (value?: string): Section | null => {
  if (!value) return null;
  if (validSectionIds.has(value)) return value as Section;
  if (value === 'cleanup') return 'storage';
  if (value === 'policy') return 'policies';
  return null;
};

const labels: Record<string, string> = {
  healthy: '正常',
  idle: '零活动',
  stale: '采集过期',
  unavailable: '未采集',
  partial: '采集不完整',
  complete: '完整',
  high: '高',
  medium: '中',
  low: '低',
  disabled: '未启用',
  permission_denied: '权限不足',
  parse_error: '解析失败',
  missing: '文件缺失',
  not_configured: '未接入',
  failed: '失败',
  warning: '警告',
  critical: '危险',
  warming_up: '积累中',
  queued: '排队',
  dispatched: '已下发',
  running: '执行中',
  succeeded: '执行成功',
  awaiting_report: '等待复查',
  retrying: '复发重试',
  recurring: '风险持续',
  verified: '已验证',
  unverified: '无法确认',
  open: '进行中',
  resolved: '已恢复',
  pending: '待处理',
  canary: '灰度中',
  rollout: '分批发布',
  paused: '已暂停',
  superseded: '已被新版本取代',
  rollback_queued: '等待回滚',
  rolled_back: '已回滚',
};

function Status({ value }: { value: string }) {
  const good = ['healthy', 'idle', 'verified', 'resolved', 'succeeded', 'complete', 'high'].includes(value);
  const bad = ['failed', 'critical', 'recurring', 'permission_denied', 'parse_error'].includes(value);
  const unknown = ['stale', 'unavailable', 'disabled', 'unverified', 'not_configured', 'low', 'warming_up'].includes(value);
  const toneClass = good
    ? 'rn2-pill-teal'
    : bad
      ? 'rn2-pill-crimson'
      : unknown
        ? 'rn2-pill-slate'
        : 'rn2-pill-amber';
  return <span className={`rn2-pill rn2-pill-sm ${toneClass}`}>{labels[value] || value}</span>;
}

const bytes = (n: number = 0) =>
  n >= 1073741824
    ? `${(n / 1073741824).toFixed(2)} GiB`
    : n >= 1048576
      ? `${(n / 1048576).toFixed(1)} MiB`
      : `${Math.round(n / 1024)} KiB`;

const date = (ts?: number) =>
  ts ? new Date(ts * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '尚无报告';

const primaryCta = 'rn2-btn rn2-btn-orange';
const secondaryCta = 'rn2-btn rn2-btn-blue';
const neutralBtn = 'rn2-btn rn2-btn-ghost';
const dangerBtn = 'rn2-btn rn2-btn-danger';

function Card({
  title,
  eyebrow,
  badge,
  children,
}: {
  title: string;
  eyebrow?: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rn2-card min-w-0 overflow-hidden">
      <div className="rn2-card-head">
        <div className="min-w-0 flex-1">
          {eyebrow && <span className="rn2-eyebrow block text-[#54c7ff]">{eyebrow}</span>}
          <h3 className="mt-0.5 wrap-break-word text-sm font-bold text-white sm:text-base">{title}</h3>
        </div>
        {badge && <div className="min-w-0 max-w-full shrink-0">{badge}</div>}
      </div>
      <div className="min-w-0 p-4 text-[#0b1636] sm:p-5">{children}</div>
    </section>
  );
}

function Empty({ text = '尚无数据。更新 Client 后等待一次采集报告。' }: { text?: string }) {
  return (
    <p className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] px-4 py-6 text-center text-sm text-[#697b9c]">
      {text}
    </p>
  );
}

export interface OperationsViewProps {
  onToast: (type: ToastMessage['type'], message: string) => void;
  isPaused?: boolean;
  initialSection?: string;
  initialHostId?: string;
}

export function OperationsView({ onToast, isPaused = false, initialSection, initialHostId }: OperationsViewProps) {
  const [section, setSection] = useState<Section>(() => resolveSection(initialSection) ?? 'health');
  const [moduleQuery, setModuleQuery] = useState('');
  const [session, setSession] = useState<RecordData>({ role: 'viewer' });
  const [overview, setOverview] = useState<RecordData>({ hosts: [], incidents: [], rechecks: [], actions: [] });
  const [data, setData] = useState<RecordData>({});
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState<RecordData>({
    profile: 'general',
    bandwidth_mbps: '',
    bandwidth_minutes: 10,
    interval_hours: 24,
    retention: 7,
    drill_enabled: true,
    role: 'viewer',
    kind: 'http',
    host_id: initialHostId || '',
  });
  const [preview, setPreview] = useState<RecordData | null>(null);
  const [timeline, setTimeline] = useState<RecordData | null>(null);
  const [historyEntity, setHistoryEntity] = useState('');
  const [historyPeriod, setHistoryPeriod] = useState('day');
  const [historyDays, setHistoryDays] = useState(31);
  const [confirm, setConfirm] = useState<{ title: string; message: string; run: () => Promise<unknown> } | null>(null);
  const sequence = useRef(0);
  const loadedSection = useRef(section);
  const backupSettingsDirty = useRef(false);
  const admin = session.role === 'admin';

  useEffect(() => {
    const resolved = resolveSection(initialSection);
    if (resolved) setSection(resolved);
  }, [initialSection]);

  useEffect(() => {
    if (!initialHostId) return;
    setForm((prev) => ({ ...prev, host_id: initialHostId }));
  }, [initialHostId]);

  const change = (key: string, value: any) => {
    if (['interval_hours', 'retention', 'drill_enabled'].includes(key)) backupSettingsDirty.current = true;
    setForm((f) => ({ ...f, [key]: value }));
    setPreview(null);
  };

  const post = (path: string, payload: RecordData = {}) =>
    request<RecordData>(`/api/v1/ops/${path}`, { method: 'POST', body: JSON.stringify(payload) });

  const saveBackupSettings = (enabled: boolean) =>
    post('backups/settings', {
      enabled,
      interval_hours: form.interval_hours,
      retention: form.retention,
      drill_enabled: !!form.drill_enabled,
    }).then((result) => {
      backupSettingsDirty.current = false;
      return result;
    });

  const load = useCallback(async () => {
    const current = ++sequence.current;
    const me = await request<RecordData>('/api/v1/ops/session');
    const summary = await request<RecordData>('/api/v1/ops/overview');
    let info: RecordData = {};
    const endpoint = section === 'baseline' ? 'traffic' : section === 'users' ? 'users' : section;
    if (section === 'replay' && ['admin', 'operator'].includes(me.role)) {
      const [inventory, replays] = await Promise.all([
        request<RecordData>('/api/v1/ops/service-inventory?limit=500'),
        request<RecordData>('/api/v1/ops/alerts/replays'),
      ]);
      info = {
        inventory: inventory.items || [],
        replays: replays.items || [],
        feedback_categories: replays.feedback_categories || [],
      };
    }
    if (['storage', 'traffic', 'baseline', 'policies', 'upgrades', 'services', 'inventory', 'backups', 'users'].includes(section)) {
      if (!['backups', 'users'].includes(section) || me.role === 'admin') {
        const suffix =
          section === 'traffic'
            ? `?period=${historyPeriod}&days=${historyDays}&entity=${encodeURIComponent(historyEntity)}`
            : '';
        const route = section === 'inventory' ? 'service-inventory' : endpoint;
        info = await request<RecordData>(`/api/v1/ops/${route}${suffix}`);
        if (section === 'users') info.audit = (await request<RecordData>('/api/v1/ops/audit')).items;
        if (section === 'policies') info.entities = (await request<RecordData>('/api/v1/ops/traffic')).items;
      }
    }
    if (current === sequence.current) {
      setSession(me);
      setOverview(summary);
      setData(info);
    }
  }, [section, historyEntity, historyPeriod, historyDays]);

  useEffect(() => {
    let alive = true;
    const sectionChanged = loadedSection.current !== section;
    loadedSection.current = section;
    setLoading(true);
    if (sectionChanged) setError('');
    setPreview(null);
    setTimeline(null);
    const refresh = async () => {
      try {
        await load();
        if (alive) setError('');
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (alive) setLoading(false);
      }
    };
    void refresh();
    const timer = setInterval(() => {
      if (!isPaused && !document.hidden) void refresh();
    }, 10000);
    return () => {
      alive = false;
      sequence.current++;
      clearInterval(timer);
    };
  }, [load, isPaused]);

  useEffect(() => {
    if (section === 'backups' && data.settings && !backupSettingsDirty.current) {
      setForm((current) => ({
        ...current,
        interval_hours: data.settings.interval_hours ?? 24,
        retention: data.settings.retention ?? 7,
        drill_enabled: data.settings.drill_enabled !== false,
      }));
    }
  }, [section, data.settings]);

  const act = async (fn: () => Promise<unknown>, message = '操作已完成') => {
    const isRefresh = fn === load;
    setBusy(true);
    if (isRefresh) setLoading(true);
    try {
      await fn();
      if (isRefresh) {
        setError('');
        onToast('success', message);
        return;
      }
      try {
        await load();
        setError('');
        onToast('success', message);
      } catch (refreshError) {
        const refreshMessage = refreshError instanceof Error ? refreshError.message : String(refreshError);
        setError(refreshMessage);
        onToast('error', `操作已完成，但数据刷新失败：${refreshMessage}`);
      }
    } catch (e) {
      const actionError = e instanceof Error ? e.message : String(e);
      setError(actionError);
      onToast('error', actionError);
    } finally {
      setBusy(false);
      if (isRefresh) setLoading(false);
      setConfirm(null);
    }
  };

  const filteredGroups = useMemo(() => {
    const q = moduleQuery.trim().toLocaleLowerCase();
    if (!q) return sectionGroups;
    return sectionGroups
      .map((group) => {
        const groupMatch = group.title.toLocaleLowerCase().includes(q) || group.subtitle.toLocaleLowerCase().includes(q);
        const items = groupMatch
          ? group.items
          : group.items.filter(
              (item) => item.label.toLocaleLowerCase().includes(q) || item.keywords.toLocaleLowerCase().includes(q)
            );
        return { ...group, items };
      })
      .filter((group) => group.items.length > 0);
  }, [moduleQuery]);

  const currentSectionLabel = sections.find(([k]) => k === section)?.[1] || section;
  const openIncidentsCount = (overview.incidents || []).filter((i: RecordData) => i.status === 'open').length;

  const hostSelect = (
    <label className="block text-xs font-semibold text-[#31485e]">
      目标节点
      <select className="rn2-select mt-1.5" value={form.host_id || ''} onChange={(e) => change('host_id', e.target.value)}>
        <option value="">请选择节点</option>
        {overview.hosts.map((h: RecordData) => (
          <option key={h.node} value={h.host_id}>
            {h.host_id}
          </option>
        ))}
      </select>
    </label>
  );

  const items: RecordData[] = data.items || [];
  const selectedEntity = form.entity || '';
  const policyPayload = () => ({
    entity: selectedEntity,
    profile: form.profile,
    rules: {
      bandwidth_mbps: Number(form.bandwidth_mbps || 0),
      bandwidth_ratio: 0.9,
      bandwidth_duration_seconds: Number(form.bandwidth_minutes || 10) * 60,
      silent_until: Number(form.silent_hours || 0) > 0 ? Math.floor(Date.now() / 1000 + Number(form.silent_hours) * 3600) : 0,
      ...(form.connections ? { connections: Number(form.connections) } : {}),
      ...(form.rx_mbps ? { rx_bps: (Number(form.rx_mbps) * 1e6) / 8 } : {}),
      ...(form.http_rps ? { http_rps: Number(form.http_rps) } : {}),
    },
  });

  return (
    <div className="mt-4 space-y-5 text-[#0b1636] tabular-nums">
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="min-w-0 flex-1">
            <span className="rn2-eyebrow block text-[#54c7ff]">OPERATIONS HUB · 14 MODULES</span>
            <h2 className="mt-0.5 flex items-center gap-2 text-lg font-extrabold text-white sm:text-xl">
              <Activity className="h-5 w-5 shrink-0 text-[#54c7ff]" aria-hidden="true" />
              <span>运维中心</span>
            </h2>
            <p className="mt-1 text-xs text-[#b9d3ee]">
              采集 → 判断 → 执行 → 复查 · {session.username || '用户'} / {session.role}
            </p>
          </div>
          <button
            type="button"
            className="rn2-btn rn2-btn-ghost rn2-btn-sm min-h-11 shrink-0"
            disabled={busy}
            onClick={() => void act(load, '数据已刷新')}
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            刷新
          </button>
        </div>

        <SpecStrip
          columnsClassName="grid-cols-2 sm:grid-cols-4"
          items={[
            { label: '纳管节点', value: (overview.hosts || []).length, tone: 'blue' },
            { label: '进行中事件', value: openIncidentsCount, tone: openIncidentsCount > 0 ? 'amber' : 'teal' },
            { label: '处置复查', value: (overview.rechecks || []).length },
            { label: '当前模块', value: currentSectionLabel, mono: false },
          ]}
        />
      </section>

      <section className="rn2-card overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-[#dce5ef] bg-[#f4f8fd] px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <div className="min-w-0">
            <h3 className="text-sm font-bold text-[#0b1636]">功能模块导航</h3>
            <p className="mt-0.5 text-xs text-[#697b9c]">按运维域分为 4 组，或输入编号/关键词快速定位。</p>
          </div>
          <div className="flex w-full items-center gap-2 sm:max-w-sm">
            <div className="relative min-w-0 flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#697b9c]" aria-hidden="true" />
              <label htmlFor="ops-module-search" className="sr-only">
                筛选运维模块
              </label>
              <input
                id="ops-module-search"
                type="search"
                value={moduleQuery}
                onChange={(e) => setModuleQuery(e.target.value)}
                placeholder="筛选模块（如：清理、升级、备份、审计）…"
                className="rn2-input pl-9"
              />
            </div>
            {moduleQuery.trim() && (
              <button
                type="button"
                onClick={() => setModuleQuery('')}
                className="rn2-btn rn2-btn-ghost min-h-11 shrink-0 px-3 text-xs"
                aria-label="清空模块筛选"
              >
                <X className="h-4 w-4" aria-hidden="true" />
                清空
              </button>
            )}
          </div>
        </div>

        <nav aria-label="运维功能" className="p-4 sm:p-5">
          {filteredGroups.length ? (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              {filteredGroups.map((group) => {
                const GroupIcon = group.icon;
                return (
                  <div
                    key={group.id}
                    className="flex min-w-0 flex-col rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3"
                  >
                    <div className="mb-2.5 flex items-start gap-2 border-b border-[#dce5ef] pb-2">
                      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] text-[#087bff]">
                        <GroupIcon className="h-4 w-4" aria-hidden={true} />
                      </span>
                      <div className="min-w-0">
                        <h4 className="text-xs font-extrabold tracking-wide text-[#0b1636]">{group.title}</h4>
                        <p className="mt-0.5 truncate text-[11px] text-[#697b9c]" title={group.subtitle}>
                          {group.subtitle}
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-1.5">
                      {group.items.map((item) => {
                        const active = section === item.key;
                        return (
                          <button
                            key={item.key}
                            type="button"
                            onClick={() => setSection(item.key)}
                            aria-current={active ? 'page' : undefined}
                            className={`flex min-h-11 w-full min-w-0 items-center justify-start rounded-xl border px-3 py-2 text-left text-sm font-semibold transition-all focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] ${
                              active
                                ? 'border-[#087bff] bg-linear-to-r from-[#087bff] to-[#0967bb] text-white shadow-[0_4px_12px_rgba(8,123,255,0.26)]'
                                : 'border-[#cedae7] bg-white text-[#0b1636] hover:border-[#087bff] hover:bg-[#e8f3ff] hover:text-[#08458c]'
                            }`}
                          >
                            {item.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] px-4 py-6 text-center">
              <p className="text-sm font-medium text-[#31485e]">没有匹配 “{moduleQuery.trim()}” 的运维模块。</p>
              <button type="button" onClick={() => setModuleQuery('')} className={neutralBtn}>
                查看全部 14 个模块
              </button>
            </div>
          )}
        </nav>
      </section>

      {error && (
        <div
          role="alert"
          className="flex flex-col gap-3 rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <p className="min-w-0 wrap-break-word text-sm font-medium text-[#b41835]">{error}</p>
          <button
            type="button"
            disabled={busy}
            onClick={() => void act(load, '数据已刷新')}
            className="rn2-btn rn2-btn-danger min-h-11 shrink-0"
          >
            {busy ? '正在重试…' : '重试'}
          </button>
        </div>
      )}

      {section === 'storage' && (
        <DiskCleanupPanel
          admin={session.role === 'admin'}
          paused={isPaused}
          onToast={onToast}
          initialHostId={initialHostId}
        />
      )}
      {section === 'storage' && <DatabaseGrowthTrend growth={data.growth} />}

      {loading ? (
        <p aria-live="polite" className="rounded-xl border border-[#cedae7] bg-white px-4 py-8 text-center text-sm text-[#31485e]">
          正在读取运维数据…
        </p>
      ) : (
        <>
          {section === 'health' && (
            <div className="grid gap-4 lg:grid-cols-2">
              {!overview.hosts.length && !error && <Empty />}
              {overview.hosts.map((h: RecordData) => (
                <Card
                  key={h.node}
                  eyebrow="HOST COLLECTION HEALTH"
                  title={h.host_id}
                  badge={<Status value={h.status} />}
                >
                  <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-[#697b9c]">
                    <span>{date(h.ts)}</span>
                    <span>·</span>
                    <span className="font-mono font-semibold text-[#31485e]">{h.data.architecture || '架构未知'}</span>
                  </div>
                  {(h.data.health || []).map((s: RecordData) => (
                    <div key={s.source} className="space-y-1 border-t border-[#dce5ef] py-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-sm font-semibold text-[#0b1636]">{s.source}</span>
                        <Status value={h.stale ? 'stale' : s.status} />
                      </div>
                      <p className="wrap-break-word text-xs text-[#31485e]">
                        {Object.entries(s.details || {})
                          .map(([k, v]) => `${k}: ${v}`)
                          .join(' · ')}
                      </p>
                      <p className="text-xs text-[#697b9c]">{s.guidance}</p>
                    </div>
                  ))}
                  {!h.data.health && <Empty text="旧版 Client 未上报健康诊断，请先升级；不能据此判定数据为真实 0。" />}
                  <button
                    type="button"
                    className={`${secondaryCta} mt-3`}
                    disabled={!admin || busy || h.stale}
                    title={h.stale ? '节点最近上报已过期' : '重新执行只读主机安全审计'}
                    onClick={() =>
                      setConfirm({
                        title: '请求主机安全复扫',
                        message: `向 ${h.host_id} 请求一次只读扫描。扫描可能短暂增加 CPU 与网络查询；不会自动安装更新或修改配置。`,
                        run: () => post('security/rescan', { host_id: h.host_id }),
                      })
                    }
                  >
                    请求只读复扫
                  </button>
                </Card>
              ))}
            </div>
          )}

          {section === 'rechecks' && (
            <div className="space-y-4">
              <Card eyebrow="POST-REMEDIATION VERIFICATION" title="风险执行后的复查">
                <p className="mb-4 text-xs leading-5 text-[#31485e]">
                  执行成功后等待两次新安全报告。风险复发最多重试两次；未采集、禁用安全或离线不会被标记为验证成功。
                </p>
                {!overview.rechecks.length && (
                  <Empty text="暂无处置复查记录。新执行的弱认证、恶意进程、面板处置会在这里跟踪。" />
                )}
                {overview.rechecks.map((r: RecordData) => (
                  <div key={r.action_id} className="flex flex-wrap items-start justify-between gap-3 border-t border-[#dce5ef] py-3">
                    <div className="min-w-0 wrap-break-word">
                      <p className="text-sm font-semibold text-[#0b1636]">
                        {r.host_id} / {r.container_name} · #{r.action_id}
                      </p>
                      <p className="mt-1 text-xs text-[#31485e]">
                        {r.alert_type} · 重试 {r.attempts}/2 · 干净采样 {r.clean_samples}/2
                      </p>
                      <p className="mt-1 text-xs text-[#697b9c]">
                        {r.message} · {r.result_message}
                      </p>
                    </div>
                    <Status value={r.status} />
                  </div>
                ))}
              </Card>
              <Card eyebrow="ACTION RECEIPTS" title="最近动作与失败原因">
                {!overview.actions.length && <Empty text="暂无最近动作记录。" />}
                {overview.actions.map((a: RecordData) => (
                  <div key={a.id} className="border-t border-[#dce5ef] py-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-[#0b1636]">
                        #{a.id} {a.host_id} / {a.container_name} · {a.action_type}
                      </span>
                      <Status value={a.status} />
                    </div>
                    <p className="mt-1 wrap-break-word text-xs text-[#697b9c]">
                      {a.result_message || '等待 Client 回执'} · {date(a.updated_at)}
                    </p>
                  </div>
                ))}
              </Card>
            </div>
          )}

          {section === 'storage' && (
            <>
              <div className="grid gap-4 sm:grid-cols-3">
                {[
                  ['数据库', data.database_bytes, 'DATABASE SIZE'],
                  ['WAL', data.wal_bytes, 'WRITE-AHEAD LOG'],
                  ['可复用空间', data.reusable_bytes, 'FREELIST PAGES'],
                ].map(([label, n, eyebrow]) => (
                  <Card key={String(label)} eyebrow={String(eyebrow)} title={String(label)}>
                    <p className="font-mono text-2xl font-extrabold text-[#087bff]">{bytes(Number(n))}</p>
                  </Card>
                ))}
              </div>
              <Card eyebrow="RETENTION & PRUNING" title="保留策略与清理状态">
                <p className="text-sm leading-6 text-[#31485e]">
                  原始 {Math.round(data.raw_retention_seconds / 86400)} 天 · 小时汇总 30 天 · 日汇总 400 天。按表统计可能不含共享索引；已清理的页可复用，不会立即缩小文件。
                </p>
                <p className="my-3 wrap-break-word rounded-xl border border-[#dce5ef] bg-[#f4f8fd] px-3.5 py-2.5 text-sm font-medium text-[#0b1636]">
                  上次清理：{date(data.cleanup?.last_success)} · {data.cleanup?.error || '无错误'} · 移除{' '}
                  {data.cleanup?.removed_rows || 0} 行
                </p>
                <button
                  type="button"
                  className={primaryCta}
                  disabled={!admin || busy}
                  onClick={() =>
                    void act(
                      () => post('storage/cleanup'),
                      '已执行一轮有界清理；大积压会由后台继续处理'
                    )
                  }
                >
                  <Database className="h-4 w-4" aria-hidden="true" />
                  执行有界清理
                </button>
              </Card>
              <Card eyebrow="SQLITE TABLES" title="数据库表统计">
                {!(data.tables || []).length ? (
                  <Empty text="暂无表级统计。" />
                ) : (
                  <div className="rn2-table-wrap">
                    <table className="min-w-[460px] text-left text-xs">
                      <thead>
                        <tr>
                          <th className="px-4 py-2.5 font-semibold">表名</th>
                          <th className="px-4 py-2.5 font-semibold">行数</th>
                          <th className="px-4 py-2.5 font-semibold">估算大小</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(data.tables || []).map((t: RecordData) => (
                          <tr key={t.name}>
                            <td className="px-4 py-2.5 font-mono font-semibold text-[#0b1636]">{t.name}</td>
                            <td className="px-4 py-2.5 font-mono text-[#31485e]">
                              {t.rows == null ? '计数超时' : `${t.rows.toLocaleString()} 行`}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[#08458c]">
                              {t.bytes == null ? 'dbstat 不可用' : bytes(t.bytes)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </>
          )}

          {(section === 'traffic' || section === 'baseline') && (
            <div className="grid gap-4 lg:grid-cols-2">
              {!items.length && <Empty />}
              {items.map((i) => (
                <Card
                  key={i.entity}
                  eyebrow={section === 'traffic' ? 'TRAFFIC COUNTER' : 'DYNAMIC BASELINE'}
                  title={`${i.host_id} / ${i.name}`}
                  badge={
                    section === 'baseline' ? (
                      <Status value={!i.data.baseline_ready ? 'unavailable' : i.data.anomaly ? 'critical' : 'healthy'} />
                    ) : undefined
                  }
                >
                  <p className="mb-3 text-xs text-[#697b9c]">
                    {i.runtime} · {i.project || '默认项目'} · {date(i.ts)}
                  </p>
                  {section === 'traffic' ? (
                    <>
                      <div className="grid grid-cols-2 gap-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3">
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#697b9c]">今日 RX / TX</p>
                          <p className="mt-1 font-mono text-sm font-bold text-[#087bff]">
                            {bytes(i.today.rx)} / {bytes(i.today.tx)}
                          </p>
                        </div>
                        <div>
                          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#697b9c]">本月 RX / TX</p>
                          <p className="mt-1 font-mono text-sm font-bold text-[#0b1636]">
                            {bytes(i.month.rx)} / {bytes(i.month.tx)}
                          </p>
                        </div>
                      </div>
                      <p className="mt-3 text-xs text-[#31485e]">
                        覆盖 {Math.round((i.month.covered / 3600) * 10) / 10} 小时 · 间断/重置 {i.month.gaps} ·{' '}
                        {i.month.estimated ? '含速率估算，不作为精确计费' : '累计计数器差值'}
                      </p>
                      {i.policy.monthly_quota_bytes > 0 && (
                        <div className="mt-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3">
                          <span className="text-xs text-[#697b9c]">仅统计，不提醒流量额度</span>
                          <p className="mt-1 text-sm font-semibold text-[#0b1636]">
                            参考额度 {bytes(i.policy.monthly_quota_bytes)} · 使用{' '}
                            {Math.round(((i.month.rx + i.month.tx) / i.policy.monthly_quota_bytes) * 100)}%
                          </p>
                        </div>
                      )}
                    </>
                  ) : (
                    <>
                      <p className="text-sm font-semibold text-[#0b1636]">
                        基线入站 {bytes(i.data.medians?.[0])}/s · 连接 {Math.round(i.data.medians?.[1] || 0)}
                      </p>
                      <p className="mt-2 text-xs leading-5 text-[#697b9c]">
                        至少 24 个、跨度一小时的近期样本；流量与连接同时超过 {i.policy.baseline_factor} 倍基线及策略底线，持续三次才告警。不据此自动停业务。
                      </p>
                    </>
                  )}
                </Card>
              ))}
            </div>
          )}

          {section === 'policies' && (
            <>
              <Card eyebrow="BANDWIDTH & THRESHOLD POLICY" title="策略覆盖 / 持续带宽提醒">
                <p className="mb-4 text-xs leading-5 text-[#31485e]">
                  连接等主机策略可继承，容器覆盖优先。实例带宽不继承主机带宽：自动读取托管实例带宽，或在容器策略中手工填写。达到 90% 且有效采样持续至少 10 分钟时提醒，不因此自动停机；流量额度仅统计、不提醒。预设是起步值，不是适用于所有业务的统一安全标准。静默只影响运维信号，不解除弱认证/恶意进程防护。
                </p>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  <label className="text-xs font-semibold text-[#31485e]">
                    策略身份
                    <select className="rn2-select mt-1.5" value={selectedEntity} onChange={(e) => change('entity', e.target.value)}>
                      <option value="">请选择节点或容器</option>
                      {overview.hosts.map((h: RecordData) => (
                        <option key={h.node} value={JSON.stringify([h.node, 'host', '', '__host__'])}>
                          {h.host_id} / 整个节点
                        </option>
                      ))}
                      {(data.entities || []).map((i: RecordData) => (
                        <option key={i.entity} value={i.entity}>
                          {i.host_id} / {i.runtime} / {i.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs font-semibold text-[#31485e]">
                    业务类型
                    <select className="rn2-select mt-1.5" value={form.profile} onChange={(e) => change('profile', e.target.value)}>
                      {['general', 'web', 'socks', 'hy2'].map((p) => (
                        <option key={p}>{p}</option>
                      ))}
                    </select>
                  </label>
                  {[
                    ['bandwidth_mbps', '实例带宽 Mbps（0 自动读取）'],
                    ['bandwidth_minutes', '持续提醒分钟（至少 10）'],
                    ['connections', '连接警告（可选）'],
                    ['rx_mbps', '入站 Mbps（可选）'],
                    ['http_rps', 'HTTP RPS（可选）'],
                    ['silent_hours', '临时静默小时（0-24）'],
                  ].map(([k, label]) => (
                    <label key={k} className="text-xs font-semibold text-[#31485e]">
                      {label}
                      <input
                        type="number"
                        min="0"
                        className="rn2-input mt-1.5"
                        value={form[k] || ''}
                        onChange={(e) => change(k, e.target.value)}
                      />
                    </label>
                  ))}
                </div>
                <div className="mt-4 flex flex-wrap gap-3">
                  <button
                    type="button"
                    className={secondaryCta}
                    disabled={!admin || busy || !selectedEntity}
                    onClick={() => void act(async () => setPreview(await post('policies/preview', policyPayload())), '预览已生成')}
                  >
                    预览影响
                  </button>
                  <button
                    type="button"
                    className={primaryCta}
                    disabled={!admin || busy || !preview || preview.entity !== selectedEntity}
                    onClick={() => void act(() => post('policies', policyPayload()), '策略已保存')}
                  >
                    保存策略
                  </button>
                </div>
                {preview && (
                  <p className="mt-4 wrap-break-word rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] p-3 text-sm font-medium text-[#08458c]">
                    连接 {preview.before.connections} → {preview.after.connections}；入站 {bytes(preview.before.rx_bps)}/s →{' '}
                    {bytes(preview.after.rx_bps)}/s；{preview.scope}
                  </p>
                )}
              </Card>
              <div className="grid gap-3 sm:grid-cols-2">
                {items.map((i) => (
                  <Card key={i.entity} eyebrow="ACTIVE OVERRIDE" title={`${i.profile} 策略`}>
                    <p className="wrap-break-word font-mono text-sm font-semibold text-[#0b1636]">{JSON.parse(i.entity).join(' / ')}</p>
                    <p className="mt-2 text-xs text-[#697b9c]">
                      实例带宽 {i.data.bandwidth_mbps || '自动读取'} Mbps · 持续提醒{' '}
                      {Math.round((i.data.bandwidth_duration_seconds || 600) / 60)} 分钟 · 更新时间 {date(i.updated_at)}
                    </p>
                  </Card>
                ))}
              </div>
            </>
          )}

          {section === 'traffic' && (
            <Card eyebrow="LONG-TERM ROLLUPS" title="长期小时 / 日汇总">
              <div className="mb-4 grid gap-3 sm:grid-cols-3">
                <label className="text-xs font-semibold text-[#31485e]">
                  身份
                  <select className="rn2-select mt-1.5" value={historyEntity} onChange={(e) => setHistoryEntity(e.target.value)}>
                    <option value="">所有身份（最近最多 2000 桶）</option>
                    {items.map((i) => (
                      <option key={i.entity} value={i.entity}>
                        {i.host_id} / {i.runtime} / {i.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs font-semibold text-[#31485e]">
                  汇总粒度
                  <select className="rn2-select mt-1.5" value={historyPeriod} onChange={(e) => setHistoryPeriod(e.target.value)}>
                    <option value="day">每天</option>
                    <option value="hour">每小时（保留 30 天）</option>
                  </select>
                </label>
                <label className="text-xs font-semibold text-[#31485e]">
                  时间范围
                  <select
                    className="rn2-select mt-1.5"
                    value={historyDays}
                    onChange={(e) => setHistoryDays(Number(e.target.value))}
                  >
                    {[7, 31, 180, 400].map((d) => (
                      <option key={d} value={d}>
                        最近 {d} 天
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              {!(data.buckets || []).length && <Empty text="所选时间范围尚无汇总；部署后开始积累，不补算清理过的历史。" />}
              {!!(data.buckets || []).length && (
                <div className="rn2-table-wrap">
                  <table className="min-w-[680px] text-left text-xs">
                    <thead>
                      <tr>
                        <th className="px-4 py-2.5 font-semibold">时间桶</th>
                        <th className="px-4 py-2.5 font-semibold">身份</th>
                        <th className="px-4 py-2.5 font-semibold">↓ 入站 / ↑ 出站</th>
                        <th className="px-4 py-2.5 font-semibold">CPU / 内存 / 连接峰值</th>
                        <th className="px-4 py-2.5 font-semibold">采样质量</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(data.buckets || []).slice(0, 60).map((r: RecordData) => (
                        <tr key={`${r.entity}/${r.bucket}`}>
                          <td className="px-4 py-2.5 whitespace-nowrap text-[#31485e]">{date(r.bucket)}</td>
                          <td className="px-4 py-2.5 wrap-break-word font-mono font-medium text-[#0b1636]">
                            {JSON.parse(r.entity).join(' / ')}
                          </td>
                          <td className="px-4 py-2.5 whitespace-nowrap font-mono font-bold text-[#087bff]">
                            ↓ {bytes(r.rx)} · ↑ {bytes(r.tx)}
                          </td>
                          <td className="px-4 py-2.5 whitespace-nowrap font-mono text-[#31485e]">
                            CPU {r.cpu_avg.toFixed(1)}% · 内存 {r.mem_avg.toFixed(1)}% · 峰值 {r.peak_connections}
                          </td>
                          <td className="px-4 py-2.5 text-[#697b9c]">
                            覆盖 {Math.round(r.covered / 60)} 分钟 · 间断 {r.gaps} · {r.estimated ? '含估算' : '计数器差值'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {(data.buckets || []).length > 60 && (
                <p className="mt-3 text-xs text-[#697b9c]">
                  显示最近 60 桶；缩短时间范围或选择单个身份查看，完整汇总可通过已认证 API 获取。
                </p>
              )}
            </Card>
          )}

          {section === 'incidents' && (
            <>
              <Card eyebrow="INCIDENT CORRELATION" title="聚合事件">
                <p className="mb-4 text-xs leading-5 text-[#31485e]">
                  同一节点/运行时/项目/容器内关联异常、处置与恢复。持续样本每五分钟留一次摘要，避免日志无限增长。
                </p>
                {!overview.incidents.length && <Empty text="暂无运维事件。" />}
                <div className="divide-y divide-[#dce5ef]">
                  {overview.incidents.map((i: RecordData) => (
                    <button
                      type="button"
                      key={i.id}
                      className="flex min-h-11 w-full flex-wrap items-center justify-between gap-2 rounded-lg px-2 py-3 text-left transition-colors hover:bg-[#f4f8fd]"
                      onClick={() =>
                        void act(
                          async () => setTimeline(await request<RecordData>(`/api/v1/ops/incidents/${i.id}`)),
                          '时间线已打开'
                        )
                      }
                    >
                      <span className="min-w-0 wrap-break-word text-sm font-semibold text-[#0b1636]">
                        #{i.id} {i.kind} · {JSON.parse(i.entity).join(' / ')}
                        <span className="mt-1 block text-xs font-normal text-[#697b9c]">
                          {date(i.opened_at)} → {date(i.last_seen)}
                        </span>
                      </span>
                      <span className="flex flex-wrap gap-2">
                        <Status value={i.status} />
                        {i.status === 'open' && i.data.severity && <Status value={i.data.severity} />}
                      </span>
                    </button>
                  ))}
                </div>
              </Card>
              {timeline && (
                <Card eyebrow="INCIDENT TIMELINE" title={`事件 #${timeline.incident.id} 时间线`}>
                  {timeline.events.map((e: RecordData) => (
                    <div key={e.id} className="border-l-2 border-[#087bff] py-3 pl-4">
                      <p className="text-xs font-medium text-[#697b9c]">
                        {date(e.ts)} · {e.kind}
                      </p>
                      <p className="mt-1 wrap-break-word text-sm text-[#0b1636]">
                        {e.data.message || e.data.status || e.data.error || JSON.stringify(e.data)}
                      </p>
                    </div>
                  ))}
                </Card>
              )}
            </>
          )}

          {section === 'inventory' && (
            <>
              <Card eyebrow="LISTENER INVENTORY" title="容器服务清单">
                <p className="mb-3 text-xs leading-5 text-[#31485e]">
                  只在完整采样之间比较监听变化；部分/不可用采样不会推断服务消失。变化是运维核对提示，不是违规判定。PID 用于证据展示，不参与稳定身份判断；记录保留 90 天，最多 20,000 条。
                </p>
                {!items.length && <Empty text="还没有完整服务清单；升级 Agent 并等待至少一次完整采样。" />}
                {items.map((item: RecordData) => (
                  <div key={item.entity} className="border-t border-[#dce5ef] py-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <strong className="wrap-break-word text-sm font-bold text-[#0b1636]">
                        {item.host_id} / {item.runtime}
                        {item.project ? `/${item.project}` : ''} / {item.container_name}
                      </strong>
                      <div className="flex flex-wrap items-center gap-2">
                        <Status value={item.coverage} />
                        <span className="text-xs text-[#697b9c]">最近完整 {date(item.complete_at)}</span>
                      </div>
                    </div>
                    <p className="mt-1 break-all text-xs text-[#31485e]">
                      容器 ID：{item.container_id || '未知'} · 用户邮箱：{item.owner?.user_email || '未备注'}
                      {item.owner?.user_note ? ` · ${item.owner.user_note}` : ''}
                    </p>
                    <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                      {(item.listeners || []).map((listener: RecordData, index: number) => (
                        <div
                          key={`${listener.proto}-${listener.port}-${listener.local}-${listener.process}-${index}`}
                          className="min-w-0 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-2.5 text-xs"
                        >
                          <strong className="text-[#0b1636]">
                            {listener.process || '进程未归属'} · {listener.proto}/{listener.port}
                          </strong>
                          <p className="mt-1 break-all text-[#31485e]">
                            地址 {listener.local || '未知'} · PID {listener.pid || '未知'} ·{' '}
                            {listener.process_attribution === 'attributed' ? '进程已归属' : '未归属'}
                          </p>
                          <p className="mt-1 text-[#697b9c]">
                            协议标签 {(listener.application_protocols || []).join(', ') || '未识别'} · 来源{' '}
                            {listener.source || '未知'}
                          </p>
                        </div>
                      ))}
                      {!(item.listeners || []).length && <p className="text-xs text-[#697b9c]">完整采样未发现监听服务。</p>}
                    </div>
                  </div>
                ))}
              </Card>
              <Card eyebrow="LISTENER DIFFS" title="最近变化">
                <p className="mb-3 text-xs text-[#697b9c]">
                  新增监听、移除监听或同一监听地址的进程归属变化。低置信度表示 Agent 未能把端口关联到具体进程。
                </p>
                {!data.changes?.length && <Empty text="还没有服务变化记录。首次完整采样仅建立基线，不会报警。" />}
                {(data.changes || []).map((changeItem: RecordData) => (
                  <div
                    key={changeItem.id}
                    className="flex flex-wrap items-start justify-between gap-3 border-t border-[#dce5ef] py-3"
                  >
                    <div className="min-w-0">
                      <p className="wrap-break-word text-sm font-semibold text-[#0b1636]">
                        {changeItem.change_type === 'listener_added'
                          ? '新增监听'
                          : changeItem.change_type === 'listener_removed'
                            ? '监听已移除'
                            : '进程归属变化'}{' '}
                        · {changeItem.host_id} / {changeItem.runtime}
                        {changeItem.project ? `/${changeItem.project}` : ''}/{changeItem.container_name}
                      </p>
                      <p className="mt-1 text-xs text-[#31485e]">
                        {changeItem.data.process || '未知进程'} · {changeItem.data.proto}/{changeItem.data.port} ·{' '}
                        {changeItem.data.local || '地址未知'}
                        {changeItem.data.application_protocols?.length
                          ? ` · ${changeItem.data.application_protocols.join(', ')}`
                          : ''}
                      </p>
                      <p className="mt-1 text-xs text-[#697b9c]">
                        证据：{changeItem.data.evidence} · PID {changeItem.data.pid || '未知'}
                        {changeItem.data.previous_process ? ` · 先前进程 ${changeItem.data.previous_process}` : ''}
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center gap-2">
                      <Status value={changeItem.confidence} />
                      <span className="text-xs text-[#697b9c]">{date(changeItem.ts)}</span>
                    </div>
                  </div>
                ))}
              </Card>
            </>
          )}

          {section === 'logs' && (
            <>
              <Card eyebrow="ACCESS LOG DISCOVERY" title="HTTP/CC 日志接入向导">
                <p className="mb-4 text-xs leading-5 text-[#31485e]">
                  先在节点发现 nginx/caddy/apache 的日志，再选择可解析文件接入。仅上传格式、方法、状态码统计，不上传原始 URL/IP 或敏感日志内容。容器日志仍由已有容器采集器负责。
                </p>
                <div className="max-w-lg space-y-3">
                  {hostSelect}
                  <button
                    type="button"
                    className={secondaryCta}
                    disabled={session.role === 'viewer' || busy || !form.host_id}
                    onClick={() =>
                      void act(
                        () => post('logs/discover', { host_id: form.host_id }),
                        '发现任务已排队；请等待 Client 执行和新报告'
                      )
                    }
                  >
                    发现并预览格式
                  </button>
                </div>
              </Card>
              {overview.hosts
                .filter((h: RecordData) => !form.host_id || h.host_id === form.host_id)
                .map((h: RecordData) => (
                  <Card key={h.node} eyebrow="DISCOVERED LOG SOURCES" title={h.host_id}>
                    {!(h.data.log_discovery || []).length && <Empty text="未发现或尚未执行；确认日志已开启且路径可读。" />}
                    {(h.data.log_discovery || []).map((l: RecordData) => (
                      <div key={l.path} className="space-y-2 border-t border-[#dce5ef] py-3">
                        <p className="break-all font-mono text-xs font-semibold text-[#0b1636]">{l.path}</p>
                        <Status value={l.status} />
                        <p className="text-xs text-[#31485e]">
                          解析 {l.parsed}/{l.samples} · 格式 {l.formats.join(', ') || '未知'} · 方法 {l.methods.join(', ')} · 最近修改{' '}
                          {date(l.modified_at)}
                        </p>
                        <button
                          type="button"
                          className={secondaryCta}
                          disabled={!admin || busy || !['healthy', 'idle'].includes(l.status)}
                          onClick={() =>
                            setConfirm({
                              title: '接入访问日志',
                              message: `将 ${h.host_id} 的宿主机日志采集路径设为 ${l.path}；Client 将重启。`,
                              run: () => post('logs/connect', { host_id: h.host_id, paths: [l.path] }),
                            })
                          }
                        >
                          接入此文件
                        </button>
                      </div>
                    ))}
                  </Card>
                ))}
            </>
          )}

          {section === 'replay' &&
            (['admin', 'operator'].includes(session.role) ? (
              <AlertReplayPanel inventory={data.inventory || []} initialReplays={data.replays || []} onToast={onToast} />
            ) : (
              <Empty text="仅管理员或运维人员可查看连接来源复盘。" />
            ))}

          {section === 'upgrades' &&
            (() => {
              const releases: RecordData[] =
                Array.isArray(data.available_releases) && data.available_releases.length
                  ? data.available_releases
                  : data.server_version
                    ? [
                        {
                          version: data.server_version,
                          revision: data.server_revision || '',
                          label: `v${data.server_version}${
                            data.server_revision ? `（当前主控 · ${String(data.server_revision).slice(0, 7)}）` : '（当前主控）'
                          }`,
                          current: true,
                        },
                      ]
                    : [];
              const selectedRelease =
                releases.find(
                  (r: RecordData) => r.version === form.version && (!form.revision || r.revision === form.revision)
                ) || releases[0];
              const targetVersion = String(selectedRelease?.version || form.version || data.server_version || '');
              const targetRevision = String(selectedRelease?.revision || form.revision || data.server_revision || '');
              const allNodes: RecordData[] = data.nodes || [];
              const selectedHosts: string[] = Array.isArray(form.hosts) ? form.hosts : [];
              const outdatedHostIds = allNodes
                .filter((n: RecordData) => n.agent_version !== targetVersion)
                .map((n: RecordData) => String(n.host_id));
              const allHostIds = allNodes.map((n: RecordData) => String(n.host_id));

              return (
                <>
                  <Card eyebrow="AUTOMATIC FLEET FOLLOW" title="节点自动跟随升级">
                    <p className="mb-3 text-sm leading-6 text-[#31485e]">
                      主控发布成功后自动灰度；健康版本上报并观察至少 2 分钟后，每次最多 3 台。健康检查失败立即暂停；安装失败最多 3 次后暂停，需管理员人工重试或回滚。
                    </p>
                    <p className="mb-3 text-sm font-semibold text-[#0b1636]">
                      {data.automatic?.enabled ? '自动跟随已开启' : '自动跟随已暂停'} · 最近检查 {date(data.automatic?.last_checked)}
                    </p>
                    {data.automatic?.error && (
                      <p role="status" className="mb-3 rounded-xl border border-[#f7d58b] bg-[#fef6e4] px-3 py-2 text-sm text-[#9a5b00]">
                        {data.automatic.error}
                      </p>
                    )}
                    <button
                      type="button"
                      className={data.automatic?.enabled ? neutralBtn : secondaryCta}
                      disabled={!admin || busy}
                      onClick={() =>
                        setConfirm({
                          title: data.automatic?.enabled ? '暂停自动跟随' : '开启自动跟随',
                          message: '仅影响后续下发，已执行的升级不回滚。',
                          run: () => post('upgrades/automatic', { enabled: !data.automatic?.enabled }),
                        })
                      }
                    >
                      {data.automatic?.enabled ? '暂停自动跟随' : '开启自动跟随'}
                    </button>
                    {(data.automatic?.holds || []).map((host: string) => (
                      <div key={host} className="mt-3 flex flex-wrap items-center gap-2 text-sm text-[#0b1636]">
                        <span className="min-w-0 break-all font-medium">{host} · 人工回滚保护</span>
                        <button
                          type="button"
                          className={secondaryCta}
                          disabled={!admin || busy}
                          onClick={() =>
                            setConfirm({
                              title: '恢复节点自动升级',
                              message: '允许该节点跟随当前主控版本。',
                              run: () =>
                                post('upgrades/automatic', {
                                  enabled: !!data.automatic?.enabled,
                                  resume_host: host,
                                }),
                            })
                          }
                        >
                          恢复自动跟随
                        </button>
                      </div>
                    ))}
                  </Card>

                  <Card eyebrow="NODE VERSIONS & RECEIPTS" title="全节点版本与最近上报">
                    <p className="mb-3 text-xs text-[#697b9c]">
                      失败原因来自节点执行回执；“最近上报”过期代表当前状态无法确认。
                    </p>
                    {!allNodes.length ? (
                      <Empty text="暂无注册节点。" />
                    ) : (
                      <div className="rn2-table-wrap">
                        <table className="min-w-[680px] text-left text-xs">
                          <thead>
                            <tr>
                              <th className="px-4 py-2.5 font-semibold">节点</th>
                              <th className="px-4 py-2.5 font-semibold">状态</th>
                              <th className="px-4 py-2.5 font-semibold">Client 版本</th>
                              <th className="px-4 py-2.5 font-semibold">最近上报</th>
                              <th className="px-4 py-2.5 font-semibold">受管升级 & 最近操作</th>
                            </tr>
                          </thead>
                          <tbody>
                            {allNodes.map((n: RecordData) => (
                              <tr key={n.host_id}>
                                <td className="px-4 py-2.5 font-semibold text-[#0b1636]">
                                  <span className="inline-flex items-center gap-1.5">
                                    <Server className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                                    {n.host_id}
                                  </span>
                                </td>
                                <td className="px-4 py-2.5">
                                  <Status value={n.report_stale ? 'stale' : 'healthy'} />
                                </td>
                                <td className="px-4 py-2.5 font-mono font-semibold text-[#08458c]">{n.agent_version}</td>
                                <td className="px-4 py-2.5 whitespace-nowrap text-[#31485e]">{date(n.last_seen)}</td>
                                <td className="px-4 py-2.5 text-[#31485e]">
                                  {n.managed_upgrade ? '支持受管升级' : '需更新 Agent 才支持受管升级'}
                                  {n.latest_update
                                    ? ` · 最近操作 ${n.latest_update.action_type === 'managed_rollback' ? '回滚' : '升级'} ${
                                        labels[n.latest_update.status] || n.latest_update.status
                                      }：${n.latest_update.result_message || '无错误详情'}`
                                    : ' · 尚无升级操作'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </Card>

                  <Card eyebrow="CANARY ROLLOUT" title="选择版本与节点灰度升级">
                    <p className="mb-4 text-xs leading-5 text-[#31485e]">
                      从下拉菜单选择已发布版本并勾选节点（首台将作为灰度节点，上报目标版本并健康观察通过后可推广其余节点）。托管发布会暂停节点无条件自动更新定时器，并保留上一版以供回滚。
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="text-xs font-semibold text-[#31485e]">
                        选择升级版本
                        <select
                          className="rn2-select mt-1.5"
                          disabled={!admin || busy || !releases.length}
                          value={selectedRelease ? `${selectedRelease.version}:${selectedRelease.revision}` : ''}
                          onChange={(e) => {
                            const picked = releases.find((r: RecordData) => `${r.version}:${r.revision}` === e.target.value);
                            if (picked) {
                              setForm((current) => ({ ...current, version: picked.version, revision: picked.revision }));
                            }
                          }}
                        >
                          {releases.map((r: RecordData) => (
                            <option key={`${r.version}:${r.revision}`} value={`${r.version}:${r.revision}`}>
                              {r.label}
                            </option>
                          ))}
                          {!releases.length && <option value="">暂无可用发布版本</option>}
                        </select>
                      </label>
                      <div className="flex flex-col justify-end text-xs font-semibold text-[#31485e]">
                        <span>绑定 main 提交（自动匹配）</span>
                        <code className="mt-1.5 block truncate rounded-xl border border-[#cedae7] bg-[#f4f8fd] px-3 py-2.5 font-mono text-xs text-[#0b1636]">
                          {targetRevision || '将由主控自动校验 origin/main'}
                        </code>
                      </div>
                    </div>
                    <div className="mt-4 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] px-3 py-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          className={`${secondaryCta} rn2-btn-sm min-h-11`}
                          disabled={!admin || busy || !outdatedHostIds.length}
                          onClick={() => change('hosts', outdatedHostIds)}
                        >
                          全选待升级 ({outdatedHostIds.length})
                        </button>
                        <button
                          type="button"
                          className={`${neutralBtn} rn2-btn-sm min-h-11`}
                          disabled={!admin || busy || !allHostIds.length}
                          onClick={() => change('hosts', allHostIds)}
                        >
                          全选全部 ({allHostIds.length})
                        </button>
                        <button
                          type="button"
                          className={`${neutralBtn} rn2-btn-sm min-h-11`}
                          disabled={!admin || busy || !selectedHosts.length}
                          onClick={() => change('hosts', [])}
                        >
                          清空选择
                        </button>
                      </div>
                      <span className="text-xs font-semibold tabular-nums text-[#31485e]">
                        已选 {selectedHosts.length} / {allHostIds.length} 台
                      </span>
                    </div>
                    <div className="my-3 grid gap-2 sm:grid-cols-2">
                      {allNodes.map((n: RecordData) => {
                        const checked = selectedHosts.includes(n.host_id);
                        return (
                          <label
                            key={n.host_id}
                            className={`flex min-h-11 cursor-pointer items-center gap-2.5 rounded-xl border px-3 py-2 text-sm transition-colors ${
                              checked
                                ? 'border-[#087bff] bg-[#e8f3ff] text-[#0b1636]'
                                : 'border-[#cedae7] bg-[#f4f8fd] text-[#0b1636] hover:border-[#087bff]'
                            }`}
                          >
                            <input
                              type="checkbox"
                              className="h-4 w-4 shrink-0 accent-[#087bff]"
                              disabled={!admin || busy}
                              checked={checked}
                              onChange={(e) =>
                                change(
                                  'hosts',
                                  e.target.checked
                                    ? [...selectedHosts, n.host_id]
                                    : selectedHosts.filter((x: string) => x !== n.host_id)
                                )
                              }
                            />
                            <span className="min-w-0 flex-1 wrap-break-word font-medium">
                              {n.host_id} ·{' '}
                              <span
                                className={
                                  n.agent_version === targetVersion ? 'font-mono font-bold text-[#147468]' : 'font-mono font-bold text-[#9a5b00]'
                                }
                              >
                                {n.agent_version}
                              </span>{' '}
                              · <span className="text-xs text-[#697b9c]">{date(n.last_seen)}</span>
                            </span>
                          </label>
                        );
                      })}
                    </div>
                    <button
                      type="button"
                      className={primaryCta}
                      disabled={!admin || busy || !selectedHosts.length || !targetVersion}
                      onClick={() =>
                        setConfirm({
                          title: '创建灰度发布',
                          message: `目标版本 v${targetVersion}${targetRevision ? ` (${targetRevision.slice(0, 7)})` : ''}；先升级 ${
                            selectedHosts[0]
                          }，其余 ${Math.max(0, selectedHosts.length - 1)} 台等待灰度通过。`,
                          run: () => post('upgrades', { hosts: selectedHosts, revision: targetRevision, version: targetVersion }),
                        })
                      }
                    >
                      <GitBranch className="h-4 w-4" aria-hidden="true" />
                      创建灰度升级 ({selectedHosts.length})
                    </button>
                  </Card>

                  {(data.campaigns || []).map((c: RecordData) => (
                    <Card
                      key={c.id}
                      eyebrow="RELEASE CAMPAIGN"
                      title={`发布 #${c.id} / ${c.version}`}
                      badge={<Status value={c.status} />}
                    >
                      {c.status === 'paused' && c.data?.paused_reason && (
                        <p role="status" className="mb-2 rounded-xl border border-[#f7d58b] bg-[#fef6e4] p-3 text-sm text-[#78350f]">
                          暂停原因：{c.data.paused_reason} · 节点 {c.data.paused_host}
                        </p>
                      )}
                      <p className="mb-3 break-all font-mono text-xs text-[#697b9c]">{c.revision}</p>
                      {(data.progress || [])
                        .filter((n: RecordData) => n.campaign === c.id)
                        .map((n: RecordData) => (
                          <div key={n.host_id} className="border-t border-[#dce5ef] py-3">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="min-w-0 wrap-break-word text-sm font-semibold text-[#0b1636]">
                                {n.host_id} · 目标 {n.target_version} · 当前 {n.actual_version}
                              </span>
                              <div className="flex flex-wrap items-center gap-2">
                                <span
                                  className={`rn2-pill rn2-pill-sm ${n.node_online ? 'rn2-pill-teal' : 'rn2-pill-slate'}`}
                                >
                                  {n.node_online ? '在线' : '离线 / 心跳过期'}
                                </span>
                                <Status value={n.status} />
                              </div>
                            </div>
                            <p className="mt-1 text-xs text-[#31485e]">
                              最近心跳：{date(n.node_last_seen)} ·{' '}
                              {n.version_matches_target
                                ? n.verified_by_observation
                                  ? '目标版本已通过连续健康观察确认'
                                  : n.status === 'verified'
                                    ? '目标版本与升级动作回执、健康检查已确认'
                                    : n.version_observation_since
                                      ? `目标版本已上报，健康观察 ${n.version_observation_elapsed_seconds || 0} / 120 秒`
                                      : '目标版本已上报，等待连续健康观察'
                                : '目标版本尚未上报'}
                            </p>
                            {n.action?.result_message && (
                              <p
                                className={`mt-1 wrap-break-word text-xs font-medium ${
                                  n.verified_by_observation ? 'text-[#9a5b00]' : 'text-[#b41835]'
                                }`}
                              >
                                {n.verified_by_observation ? '历史升级动作回执' : '失败/执行信息'}：{n.action.result_message}
                                {n.verified_by_observation ? '；当前版本已由稳定健康上报确认' : ''}
                              </p>
                            )}
                            {n.status === 'failed' &&
                              n.action?.action_type !== 'managed_rollback' &&
                              (!c.data?.automatic || c.status === 'paused') && (
                                <button
                                  type="button"
                                  className={`${secondaryCta} mt-2`}
                                  disabled={!admin || busy || n.manual_attempts >= 3}
                                  onClick={() =>
                                    setConfirm({
                                      title: '重试失败节点升级',
                                      message: `只对 ${n.host_id} 重试固定提交 ${c.revision}。要求节点在线且提交仍是 main；最多 3 次。`,
                                      run: () => post(`upgrades/${c.id}/${encodeURIComponent(n.host_id)}/retry`),
                                    })
                                  }
                                >
                                  {n.manual_attempts >= 3 ? '已达重试上限' : '重试此节点'}
                                </button>
                              )}
                          </div>
                        ))}
                      <div className="mt-3 flex flex-wrap gap-2">
                        {c.status === 'paused' && (
                          <button
                            type="button"
                            className={secondaryCta}
                            disabled={!admin || busy}
                            onClick={() =>
                              setConfirm({
                                title: '恢复暂停的发布',
                                message: '仅在灰度节点最新健康审计通过、没有失败节点时恢复协调器；不会跳过灰度观察。',
                                run: () => post(`upgrades/${c.id}/resume`),
                              })
                            }
                          >
                            健康复核通过，恢复发布
                          </button>
                        )}
                        <button
                          type="button"
                          className={primaryCta}
                          disabled={
                            !admin ||
                            busy ||
                            c.status !== 'canary' ||
                            !(data.progress || []).some((n: RecordData) => n.campaign === c.id && n.status === 'verified')
                          }
                          onClick={() =>
                            setConfirm({
                              title: '推广灰度版本',
                              message: '将目标固定版本下发给本批次其余节点。',
                              run: () => post(`upgrades/${c.id}/promote`),
                            })
                          }
                        >
                          灰度通过，推广其余节点
                        </button>
                      </div>
                    </Card>
                  ))}

                  <Card eyebrow="MANAGED ROLLBACK" title="回滚到节点保留的上一版">
                    <div className="max-w-md space-y-3">
                      {hostSelect}
                      <button
                        type="button"
                        className={dangerBtn}
                        disabled={!admin || busy || !form.host_id}
                        onClick={() =>
                          setConfirm({
                            title: '回滚 Client',
                            message: `恢复 ${form.host_id} 本地保留的上一版 Client 与配置，期间会重启服务。不存在备份时会失败，不会下载未知版本。`,
                            run: () => post('upgrades/rollback', { host_id: form.host_id }),
                          })
                        }
                      >
                        回滚所选节点
                      </button>
                    </div>
                  </Card>
                </>
              );
            })()}

          {section === 'services' && (
            <>
              <Card eyebrow="SYNTHETIC SERVICE PROBES" title="新增节点侧服务探测">
                <p className="mb-4 text-xs leading-5 text-[#31485e]">
                  HTTP/TCP 由所选 Agent 发起，HTTP 不跟随重定向。TLS 严格验证，提前 14 天提醒过期。存活容器不等于服务正常。
                </p>
                <div className="grid gap-3 sm:grid-cols-2">
                  {hostSelect}
                  <label className="text-xs font-semibold text-[#31485e]">
                    协议
                    <select className="rn2-select mt-1.5" value={form.kind} onChange={(e) => change('kind', e.target.value)}>
                      <option value="http">HTTP / HTTPS</option>
                      <option value="tcp">TCP</option>
                    </select>
                  </label>
                  <label className="text-xs font-semibold text-[#31485e]">
                    名称
                    <input className="rn2-input mt-1.5" value={form.name || ''} onChange={(e) => change('name', e.target.value)} />
                  </label>
                  <label className="text-xs font-semibold text-[#31485e]">
                    地址（无凭据）
                    <input
                      className="rn2-input mt-1.5"
                      placeholder="https://example.com/health 或 tcp://127.0.0.1:443"
                      value={form.target || ''}
                      onChange={(e) => change('target', e.target.value)}
                    />
                  </label>
                </div>
                <button
                  type="button"
                  className={`${primaryCta} mt-4`}
                  disabled={!admin || busy || !form.host_id || !form.target}
                  onClick={() =>
                    void act(
                      () => post('services', { host_id: form.host_id, name: form.name, target: form.target, kind: form.kind }),
                      '探测已配置；等待节点下次报告'
                    )
                  }
                >
                  添加探测
                </button>
              </Card>
              <div className="grid gap-4 sm:grid-cols-2">
                {items.map((i) => {
                  const r = (data.results || []).find((x: RecordData) => x.service_id === i.id);
                  const stale = !r || Date.now() / 1000 - r.ts > 900;
                  return (
                    <Card
                      key={i.id}
                      eyebrow="PROBE TARGET"
                      title={`${i.host_id} / ${i.name}`}
                      badge={<Status value={stale ? 'stale' : r.data.status} />}
                    >
                      <p className="mb-2 break-all font-mono text-xs text-[#697b9c]">{i.data.target}</p>
                      <p className="my-2 text-sm font-medium text-[#0b1636]">
                        延迟 {r?.data.latency_ms ?? '—'} ms · HTTP {r?.data.http_status ?? '—'} · TLS 剩余{' '}
                        {r?.data.tls_days_remaining ?? '—'} 天
                      </p>
                      {r?.data.error && <p className="mb-3 text-xs font-medium text-[#b41835]">{r.data.error}</p>}
                      <button
                        type="button"
                        className={dangerBtn}
                        disabled={!admin || busy}
                        onClick={() =>
                          setConfirm({
                            title: '移除服务探测',
                            message: `移除 ${i.name} 的探测，不会停止实际服务。`,
                            run: () => request(`/api/v1/ops/services/${i.id}`, { method: 'DELETE' }),
                          })
                        }
                      >
                        移除探测
                      </button>
                    </Card>
                  );
                })}
              </div>
            </>
          )}

          {section === 'backups' &&
            (admin ? (
              <>
                <Card eyebrow="SQLITE BACKUP & DRILL" title="一致性备份与每周恢复演练">
                  <p className="mb-4 text-xs leading-5 text-[#31485e]">
                    SQLite online backup 会执行 integrity_check。恢复演练只复制到隔离临时目录，验证可重开、核心表和外键，不覆盖线上数据库。演练需要额外临时磁盘空间；可选择每周自动演练最近备份。
                  </p>
                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <label className="text-xs font-semibold text-[#31485e]">
                      间隔（小时）
                      <input
                        type="number"
                        min="1"
                        max="168"
                        className="rn2-input mt-1.5"
                        value={form.interval_hours}
                        onChange={(e) => change('interval_hours', Number(e.target.value))}
                      />
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      保留份数
                      <input
                        type="number"
                        min="1"
                        max="30"
                        className="rn2-input mt-1.5"
                        value={form.retention}
                        onChange={(e) => change('retention', Number(e.target.value))}
                      />
                    </label>
                    <label className="flex min-h-11 cursor-pointer items-center gap-2 self-end rounded-xl border border-[#cedae7] bg-[#f4f8fd] px-3 text-sm font-medium text-[#0b1636]">
                      <input
                        type="checkbox"
                        className="h-4 w-4 shrink-0 accent-[#087bff]"
                        checked={!!form.drill_enabled}
                        onChange={(e) => change('drill_enabled', e.target.checked)}
                      />
                      每周自动恢复演练
                    </label>
                    <button
                      type="button"
                      className={`${primaryCta} self-end`}
                      disabled={busy}
                      onClick={() => void act(() => saveBackupSettings(true), '定时备份设置已保存')}
                    >
                      启用 / 更新
                    </button>
                  </div>
                  <div className="my-4 flex flex-wrap gap-3">
                    <button
                      type="button"
                      className={secondaryCta}
                      disabled={busy}
                      onClick={() => void act(() => post('backups'), '备份已创建并通过完整性检查')}
                    >
                      立即备份
                    </button>
                    <button
                      type="button"
                      className={neutralBtn}
                      disabled={busy}
                      onClick={() => void act(() => saveBackupSettings(false), '定时备份已关闭')}
                    >
                      关闭定时备份
                    </button>
                  </div>
                  <p className="text-sm font-medium text-[#31485e]">
                    定时备份 {data.settings?.enabled ? '已启用' : '未启用'} · 自动演练{' '}
                    {data.settings?.drill_enabled ? '每周' : '未启用'} · 最近备份 {date(data.settings?.last_success)} ·{' '}
                    {data.settings?.error || '无备份错误'}
                  </p>
                  {data.drill_health && (
                    <p
                      role={
                        ['failed', 'overdue', 'never_tested'].includes(data.drill_health.state) &&
                        data.settings?.enabled &&
                        data.settings?.drill_enabled
                          ? 'alert'
                          : undefined
                      }
                      className={`mt-2 rounded-xl border px-3.5 py-2.5 text-xs ${
                        data.drill_health.state === 'healthy'
                          ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#0f5b52]'
                          : data.drill_health.state === 'disabled'
                            ? 'border-[#dce5ef] bg-[#f4f8fd] text-[#697b9c]'
                            : 'border-[#f7d58b] bg-[#fef6e4] text-[#78350f]'
                      }`}
                    >
                      隔离恢复演练：{data.drill_health.message}
                      {data.drill_health.last_success_at ? ` · 最近成功 ${date(data.drill_health.last_success_at)}` : ''}
                      {data.drill_health.due_at ? ` · 下次到期 ${date(data.drill_health.due_at)}` : ''}
                    </p>
                  )}
                  {data.settings?.last_drill && (
                    <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-[#31485e]">
                      <span>最近演练：</span>
                      <Status value={data.settings.last_drill.status} />
                      <span>
                        {data.settings.last_drill.backup_name} · {date(data.settings.last_drill.finished_at)} ·{' '}
                        {(data.settings.last_drill.duration_ms / 1000).toFixed(1)} 秒 · {data.settings.last_drill.message}
                      </span>
                    </p>
                  )}
                </Card>

                <Card eyebrow="SNAPSHOTS & RECOVERY" title="备份清单 / 隔离恢复演练">
                  {!items.length && <Empty text="尚未创建备份。" />}
                  {items.map((i) => (
                    <div key={i.name} className="flex flex-wrap items-center justify-between gap-3 border-t border-[#dce5ef] py-3">
                      <div className="min-w-0">
                        <p className="break-all font-mono text-xs font-semibold text-[#0b1636]">{i.name}</p>
                        <p className="mt-1 text-xs text-[#697b9c]">
                          {bytes(i.bytes)} · {date(i.ts)}
                        </p>
                        {i.last_drill && (
                          <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-[#31485e]">
                            <span>最近演练：</span>
                            <Status value={i.last_drill.status} />
                            <span>
                              {date(i.last_drill.finished_at)} · {(i.last_drill.duration_ms / 1000).toFixed(1)} 秒 ·{' '}
                              {i.last_drill.message}
                            </span>
                          </p>
                        )}
                      </div>
                      <button
                        type="button"
                        className={secondaryCta}
                        disabled={busy}
                        onClick={() =>
                          void act(async () => {
                            const result = await post(`backups/${encodeURIComponent(i.name)}/drill`);
                            if (result.status === 'failed') throw new Error(result.message || '隔离恢复演练失败');
                            return result;
                          }, '隔离恢复演练成功')
                        }
                      >
                        执行恢复演练
                      </button>
                    </div>
                  ))}
                  <p className="mt-4 text-xs leading-5 text-[#697b9c]">
                    备份前会估算 SQLite 快照大小并检查磁盘空间，至少保留 512 MiB 余量；隔离恢复演练在备份所在数据盘创建临时副本，同样预留空间，不足时会记录失败原因并跳过复制。验证后删除临时副本，不会覆盖线上 monitor.db。备份包含密钥，服务端文件权限 0600。
                  </p>
                </Card>

                {!!data.drills?.length && (
                  <Card eyebrow="DRILL LOG" title="最近演练记录">
                    {data.drills.slice(0, 10).map((drill: RecordData) => (
                      <div key={drill.id} className="flex flex-wrap items-center justify-between gap-2 border-t border-[#dce5ef] py-2.5 text-xs">
                        <span className="min-w-0 break-all font-medium text-[#0b1636]">
                          {drill.backup_name} · {drill.message}
                        </span>
                        <span className="flex items-center gap-2 text-[#697b9c]">
                          <Status value={drill.status} />
                          {(drill.duration_ms / 1000).toFixed(1)} 秒 · {date(drill.finished_at)}
                        </span>
                      </div>
                    ))}
                  </Card>
                )}
              </>
            ) : (
              <Empty text="仅管理员可管理或查看含密钥备份。" />
            ))}

          {section === 'users' &&
            (admin ? (
              <>
                <Card eyebrow="RBAC ACCESS CONTROL" title="用户与角色">
                  <p className="mb-4 text-xs leading-5 text-[#31485e]">
                    admin 管理全部；operator 可诊断/处置；viewer 只读且不能读取通知配置。原有环境管理员保留，数据库不保存明文密码。
                  </p>
                  <div className="grid gap-3 sm:grid-cols-3">
                    <label className="text-xs font-semibold text-[#31485e]">
                      用户名
                      <input
                        className="rn2-input mt-1.5"
                        value={form.username || ''}
                        onChange={(e) => change('username', e.target.value)}
                        autoComplete="off"
                      />
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      密码（至少 12 位）
                      <input
                        type="password"
                        className="rn2-input mt-1.5"
                        value={form.password || ''}
                        onChange={(e) => change('password', e.target.value)}
                        autoComplete="new-password"
                      />
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      角色
                      <select className="rn2-select mt-1.5" value={form.role} onChange={(e) => change('role', e.target.value)}>
                        {['viewer', 'operator', 'admin'].map((r) => (
                          <option key={r}>{r}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <button
                    type="button"
                    className={`${primaryCta} mt-4`}
                    disabled={busy || !form.username || (form.password || '').length < 12}
                    onClick={() =>
                      void act(async () => {
                        await post('users', { username: form.username, password: form.password, role: form.role });
                        change('password', '');
                      }, '用户已保存')
                    }
                  >
                    <Users className="h-4 w-4" aria-hidden="true" />
                    创建 / 更新账号
                  </button>
                  <p className="mt-4 text-xs font-medium text-[#697b9c]">环境管理员：{data.environment_admin}</p>
                  <div className="mt-2 divide-y divide-[#dce5ef]">
                    {items.map((i) => (
                      <div key={i.username} className="flex flex-wrap items-center justify-between gap-2 py-2.5">
                        <span className="font-mono text-sm font-semibold text-[#0b1636]">
                          {i.username} <span className="text-[#697b9c]">/ {i.role}</span>
                        </span>
                        <button
                          type="button"
                          className={dangerBtn}
                          disabled={busy || i.username === session.username}
                          onClick={() =>
                            setConfirm({
                              title: '删除账号',
                              message: `撤销 ${i.username} 的面板访问权限。`,
                              run: () => request(`/api/v1/ops/users/${encodeURIComponent(i.username)}`, { method: 'DELETE' }),
                            })
                          }
                        >
                          撤销
                        </button>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card eyebrow="AUDIT TRAIL" title="变更审计（最近 100 条）">
                  {!(data.audit || []).length ? (
                    <Empty text="暂无变更审计记录。" />
                  ) : (
                    <div className="rn2-table-wrap">
                      <table className="min-w-[600px] text-left text-xs">
                        <thead>
                          <tr>
                            <th className="px-4 py-2.5 font-semibold">操作者</th>
                            <th className="px-4 py-2.5 font-semibold">请求</th>
                            <th className="px-4 py-2.5 font-semibold">HTTP 状态</th>
                            <th className="px-4 py-2.5 font-semibold">时间（北京时间）</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(data.audit || []).map((a: RecordData) => (
                            <tr key={a.id}>
                              <td className="px-4 py-2.5 font-semibold text-[#0b1636]">{a.username}</td>
                              <td className="px-4 py-2.5 break-all font-mono text-[#31485e]">
                                {a.method} {a.path}
                              </td>
                              <td className="px-4 py-2.5">
                                <span
                                  className={`rn2-pill rn2-pill-sm font-mono ${
                                    Number(a.status) >= 400 ? 'rn2-pill-crimson' : 'rn2-pill-teal'
                                  }`}
                                >
                                  HTTP {a.status}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 whitespace-nowrap text-[#697b9c]">{date(a.ts)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>
              </>
            ) : (
              <Empty text="仅管理员可管理用户和审计记录。" />
            ))}
        </>
      )}

      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#dce5ef] bg-white px-4 py-3 text-xs text-[#697b9c]">
        <Shield className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
        <span>管理 API 均经过认证与角色校验；数据时间为北京时间。</span>
        <span className="inline-flex items-center gap-1 font-medium text-[#147468]">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          正常
        </span>
        <span className="inline-flex items-center gap-1 font-medium text-[#9a5b00]">
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          警告
        </span>
        <span className="inline-flex items-center gap-1 font-medium text-[#b41835]">
          <FileText className="h-4 w-4" aria-hidden="true" />
          危险
        </span>
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title || ''}
        description={confirm?.message || ''}
        confirmLabel={busy ? '正在执行…' : '确认执行'}
        onConfirm={() => {
          if (confirm) void act(confirm.run);
        }}
        onCancel={() => {
          if (!busy) setConfirm(null);
        }}
        isSubmitting={busy}
      />
    </div>
  );
}
