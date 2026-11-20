import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Box,
  BriefcaseBusiness,
  LayoutDashboard,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Users,
  Wrench,
  X,
} from 'lucide-react';
import { ContainerIdentity, ContainerItem } from '../../api/types';

export type ConsoleTab =
  | 'dashboard'
  | 'alerts'
  | 'investigation'
  | 'stats'
  | 'settings'
  | 'notifications'
  | 'operations'
  | 'commerce'
  | 'firewall';

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  containers: ContainerItem[];
  onSelectContainer: (id: ContainerIdentity) => void;
  onSelectTab: (tab: ConsoleTab) => void;
  onOpenOpsModule?: (opsSubTab: string) => void;
  onSelectHost?: (hostId: string) => void;
}

const MAIN_VIEWS = [
  {
    id: 'dashboard' as const,
    label: '总览看板',
    hint: 'Overview',
    keywords: '总览 看板 主机 容器 实时 状态 kpi dashboard overview',
    icon: LayoutDashboard,
    accent: 'text-[#087bff]',
  },
  {
    id: 'alerts' as const,
    label: '安全告警历史',
    hint: 'Security Alerts',
    keywords: '安全 告警 历史 隔离 复核 alerts security',
    icon: AlertTriangle,
    accent: 'text-[#ff6b00]',
  },
  {
    id: 'investigation' as const,
    label: '用户与容器排查',
    hint: 'User Investigation',
    keywords: '用户 排查 邮箱 关联 investigation user',
    icon: Users,
    accent: 'text-[#08458c]',
  },
  {
    id: 'stats' as const,
    label: '数据统计与排行榜',
    hint: 'Telemetry & Stats',
    keywords: '数据 统计 排行 流量 cpu ip stats analytics',
    icon: BarChart3,
    accent: 'text-[#147468]',
  },
  {
    id: 'commerce' as const,
    label: '经营分析与账本',
    hint: 'Commerce & Ledger',
    keywords: '经营 分析 账本 余额 收益 commerce ledger',
    icon: BriefcaseBusiness,
    accent: 'text-[#087bff]',
  },
  {
    id: 'operations' as const,
    label: '运维中心',
    hint: 'Operations Hub',
    keywords: '运维 中心 模块 巡检 升级 备份 operations ops',
    icon: Wrench,
    accent: 'text-[#08458c]',
  },
  {
    id: 'firewall' as const,
    label: '母机防火墙策略',
    hint: 'Host Firewall',
    keywords: '母机 防火墙 策略 rfw 规则 firewall',
    icon: ShieldCheck,
    accent: 'text-[#ff6b00]',
  },
  {
    id: 'settings' as const,
    label: '系统设置与推送配置',
    hint: 'Settings & Push',
    keywords: '系统 设置 推送 通知 tg 白名单 安全策略 settings',
    icon: Settings,
    accent: 'text-[#147468]',
  },
] as const;

const OPS_MODULES = [
  { id: 'health', code: '01', label: '1 采集健康', hint: 'Collection Health', keywords: '采集 健康 复扫 rescan health' },
  { id: 'rechecks', code: '02', label: '2 处置复查', hint: 'Action Rechecks', keywords: '处置 复查 验证 动作 rechecks' },
  { id: 'storage', code: '03', label: '3 存储管理', hint: 'Storage & Cleanup', keywords: '存储 磁盘 清理 数据库 wal sqlite storage cleanup' },
  { id: 'traffic', code: '04', label: '4 流量账本', hint: 'Traffic Ledger', keywords: '流量 账本 汇总 rx tx traffic' },
  { id: 'policies', code: '05', label: '5 业务策略', hint: 'Business Policies', keywords: '业务 策略 带宽 静默 policies' },
  { id: 'baseline', code: '06', label: '6 动态基线', hint: 'Dynamic Baseline', keywords: '动态 基线 异常 baseline' },
  { id: 'incidents', code: '07', label: '7 事件时间线', hint: 'Incident Timeline', keywords: '事件 时间线 incidents' },
  { id: 'logs', code: '08', label: '8 日志接入', hint: 'Log Discovery', keywords: '日志 接入 nginx caddy apache access logs' },
  { id: 'upgrades', code: '09', label: '9 节点升级', hint: 'Fleet Upgrades', keywords: '节点 升级 灰度 回滚 agent upgrades rollback' },
  { id: 'services', code: '10', label: '10 服务可用性', hint: 'Service Availability', keywords: '服务 可用性 探测 http tcp services' },
  { id: 'inventory', code: '11', label: '11 服务清单', hint: 'Service Inventory', keywords: '服务 清单 监听 端口 inventory' },
  { id: 'backups', code: '12', label: '12 备份', hint: 'Backups & Drills', keywords: '备份 恢复 演练 backups' },
  { id: 'users', code: '13', label: '13 权限与审计', hint: 'RBAC & Audit', keywords: '权限 用户 审计 rbac users audit' },
  { id: 'replay', code: '14', label: '14 告警复盘', hint: 'Alert Replay', keywords: '告警 复盘 连接 来源 replay' },
] as const;

interface HostSummary {
  hostId: string;
  containerCount: number;
  runtimes: string[];
  alertCount: number;
}

type PaletteEntry =
  | { key: string; kind: 'view'; item: (typeof MAIN_VIEWS)[number] }
  | { key: string; kind: 'ops'; item: (typeof OPS_MODULES)[number] }
  | { key: string; kind: 'host'; item: HostSummary }
  | { key: string; kind: 'container'; item: ContainerItem };

export const CommandPaletteV2: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  containers,
  onSelectContainer,
  onSelectTab,
  onOpenOpsModule,
  onSelectHost,
}) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    if (!isOpen) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    setQuery('');
    setActiveIndex(0);

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = dialogRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href]',
      );
      if (!focusable?.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (
        event.shiftKey &&
        (document.activeElement === first || !dialogRef.current?.contains(document.activeElement))
      ) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey &&
        (document.activeElement === last || !dialogRef.current?.contains(document.activeElement))
      ) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [isOpen, onClose]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  const q = query.trim().toLowerCase();

  const hosts = useMemo<HostSummary[]>(() => {
    const byHost = new Map<string, { count: number; runtimes: Set<string>; alerts: number }>();
    for (const c of containers) {
      const entry = byHost.get(c.host_id) ?? { count: 0, runtimes: new Set<string>(), alerts: 0 };
      entry.count += 1;
      if (c.runtime) entry.runtimes.add(c.runtime);
      if (c.alerts && (c.alerts.cpu || c.alerts.memory || c.alerts.disk || c.alerts.conn || c.alerts.hy2_detected)) {
        entry.alerts += 1;
      }
      byHost.set(c.host_id, entry);
    }
    return Array.from(byHost.entries())
      .map(([hostId, info]) => ({
        hostId,
        containerCount: info.count,
        runtimes: Array.from(info.runtimes),
        alertCount: info.alerts,
      }))
      .sort((a, b) => a.hostId.localeCompare(b.hostId));
  }, [containers]);

  const filteredViews = useMemo(
    () =>
      MAIN_VIEWS.filter((view) => {
        if (!q) return true;
        return (
          view.label.toLowerCase().includes(q) ||
          view.hint.toLowerCase().includes(q) ||
          view.keywords.toLowerCase().includes(q) ||
          view.id.toLowerCase().includes(q)
        );
      }),
    [q],
  );

  const filteredOps = useMemo(
    () =>
      OPS_MODULES.filter((mod) => {
        if (!q) return true;
        return (
          mod.label.toLowerCase().includes(q) ||
          mod.hint.toLowerCase().includes(q) ||
          mod.keywords.toLowerCase().includes(q) ||
          mod.id.toLowerCase().includes(q)
        );
      }),
    [q],
  );

  const filteredHosts = useMemo(
    () =>
      hosts
        .filter((host) => {
          if (!q) return true;
          return (
            host.hostId.toLowerCase().includes(q) ||
            host.runtimes.some((rt) => rt.toLowerCase().includes(q))
          );
        })
        .slice(0, q ? 12 : 6),
    [hosts, q],
  );

  const filteredContainers = useMemo(
    () =>
      containers
        .filter((c) => {
          if (!q) return true;
          return (
            c.container_name.toLowerCase().includes(q) ||
            c.host_id.toLowerCase().includes(q) ||
            (c.user_email || '').toLowerCase().includes(q) ||
            (c.user_note || '').toLowerCase().includes(q) ||
            (c.project && c.project.toLowerCase().includes(q)) ||
            c.runtime.toLowerCase().includes(q)
          );
        })
        .slice(0, q ? 20 : 15),
    [containers, q],
  );

  const entries = useMemo<PaletteEntry[]>(() => {
    const list: PaletteEntry[] = [];
    for (const item of filteredViews) list.push({ key: `view:${item.id}`, kind: 'view', item });
    for (const item of filteredOps) list.push({ key: `ops:${item.id}`, kind: 'ops', item });
    for (const item of filteredHosts) list.push({ key: `host:${item.hostId}`, kind: 'host', item });
    for (const item of filteredContainers) {
      list.push({
        key: `container:${item.host_id}-${item.runtime}-${item.project || ''}-${item.container_name}`,
        kind: 'container',
        item,
      });
    }
    return list;
  }, [filteredViews, filteredOps, filteredHosts, filteredContainers]);

  const safeActiveIndex = entries.length ? Math.min(activeIndex, entries.length - 1) : 0;

  useEffect(() => {
    if (!isOpen) return;
    itemRefs.current[safeActiveIndex]?.scrollIntoView({ block: 'nearest' });
  }, [isOpen, safeActiveIndex]);

  if (!isOpen) return null;

  const indexOfKey = new Map<string, number>();
  entries.forEach((entry, idx) => indexOfKey.set(entry.key, idx));

  const activate = (index: number) => {
    const entry = entries[index];
    if (!entry) return;

    if (entry.kind === 'view') {
      onSelectTab(entry.item.id);
      onClose();
      return;
    }

    if (entry.kind === 'ops') {
      if (onOpenOpsModule) {
        onOpenOpsModule(entry.item.id);
      } else {
        onSelectTab('operations');
      }
      onClose();
      return;
    }

    if (entry.kind === 'host') {
      if (onSelectHost) {
        onSelectHost(entry.item.hostId);
        onClose();
        return;
      }
      if (q !== entry.item.hostId.toLowerCase()) {
        setQuery(entry.item.hostId);
        inputRef.current?.focus();
        return;
      }
      onSelectTab('dashboard');
      onClose();
      return;
    }

    const c = entry.item;
    onSelectContainer({
      host_id: c.host_id,
      runtime: c.runtime,
      project: c.project,
      container_name: c.container_name,
      container_id: c.container_id,
    });
    onClose();
  };

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      return;
    }
    if (!entries.length) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((value) => (value + 1) % entries.length);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((value) => (value - 1 + entries.length) % entries.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      activate(safeActiveIndex);
    }
  };

  return (
    <div
      ref={dialogRef}
      role="dialog"
      aria-modal="true"
      aria-label="全局检索"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      className="fixed inset-0 z-50 flex items-start justify-center bg-[#02182f]/75 px-4 pt-14 pb-6 backdrop-blur-xs sm:pt-20"
    >
      <div className="relative w-full max-w-2xl overflow-hidden rounded-[14px] border border-[#cedae7] bg-white text-[#0b1636] shadow-[0_24px_60px_rgba(2,24,47,0.48)]">
        {/* Midnight Header Bar */}
        <div className="flex items-center justify-between gap-3 border-b border-[#0f3459] bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] px-4 py-2.5 text-[#e6f4ff]">
          <span className="font-mono text-[11px] font-bold tracking-[0.14em] uppercase text-[#54c7ff]">
            QUICK COMMAND · 2.0
          </span>
          <span className="font-mono text-[11px] font-semibold tabular-nums text-[#cde8ff]">
            {entries.length} 项匹配
          </span>
        </div>

        {/* Search Input Header */}
        <div className="flex items-center gap-3 border-b border-[#cedae7] bg-[#f4f8fd] px-4 py-3">
          <Search className="h-5 w-5 shrink-0 text-[#087bff]" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            aria-label="搜索节点、容器或用户邮箱"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            placeholder="搜索视图、14 项运维工具、节点、容器或用户邮箱… (Esc 退出)"
            className="min-w-0 flex-1 bg-transparent text-sm font-medium text-[#0b1636] placeholder:text-[#697b9c] focus:outline-hidden"
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                inputRef.current?.focus();
              }}
              aria-label="清空搜索"
              className="rounded-md border border-[#d2dfec] bg-white px-2 py-1 text-xs font-medium text-[#506483] transition-colors hover:border-[#087bff] hover:text-[#0b1636]"
            >
              清空
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭全局检索"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#cedae7] bg-white text-[#506483] transition-colors hover:border-[#087bff] hover:text-[#0b1636] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff]"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        {/* Results Body */}
        <div className="max-h-[64dvh] overflow-y-auto bg-white p-2.5 sm:max-h-[28rem]">
          {entries.length === 0 ? (
            <div className="px-4 py-10 text-center">
              <p className="text-sm font-semibold text-[#0b1636]">未找到匹配的视图、运维工具、节点或容器</p>
              <p className="mt-1 text-xs text-[#697b9c]">尝试搜索节点名、容器名、邮箱、或模块关键字（如：升级、备份、防火墙）</p>
            </div>
          ) : (
            <div className="space-y-3">
              {/* 8 Main Console Views */}
              {filteredViews.length > 0 && (
                <div>
                  <div className="px-2.5 py-1 font-mono text-[11px] font-bold tracking-[0.12em] uppercase text-[#506483]">
                    主控制台视图 ({filteredViews.length})
                  </div>
                  <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                    {filteredViews.map((view) => {
                      const idx = indexOfKey.get(`view:${view.id}`) ?? 0;
                      const isActive = safeActiveIndex === idx;
                      const Icon = view.icon;
                      return (
                        <button
                          key={view.id}
                          ref={(el) => {
                            itemRefs.current[idx] = el;
                          }}
                          type="button"
                          onMouseEnter={() => setActiveIndex(idx)}
                          onClick={() => activate(idx)}
                          className={`flex min-h-10 w-full items-center justify-between gap-2 rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                            isActive
                              ? 'border-[#087bff] bg-[#eef5ff] text-[#08458c] shadow-xs'
                              : 'border-transparent bg-white text-[#0b1636] hover:border-[#d2dfec] hover:bg-[#f4f8fd]'
                          }`}
                        >
                          <div className="flex min-w-0 items-center gap-2.5">
                            <Icon className={`h-4 w-4 shrink-0 ${view.accent}`} aria-hidden="true" />
                            <span className="truncate font-semibold">
                              {view.label}{' '}
                              <span className="text-xs font-normal text-[#697b9c]">({view.hint})</span>
                            </span>
                          </div>
                          <ArrowRight
                            className={`h-3.5 w-3.5 shrink-0 ${isActive ? 'text-[#087bff]' : 'text-[#697b9c]'}`}
                            aria-hidden="true"
                          />
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* All 14 Ops Hub Tools */}
              {filteredOps.length > 0 && (
                <div>
                  <div className="px-2.5 py-1 font-mono text-[11px] font-bold tracking-[0.12em] uppercase text-[#506483]">
                    运维中心工具 ({filteredOps.length})
                  </div>
                  <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                    {filteredOps.map((mod) => {
                      const idx = indexOfKey.get(`ops:${mod.id}`) ?? 0;
                      const isActive = safeActiveIndex === idx;
                      return (
                        <button
                          key={mod.id}
                          ref={(el) => {
                            itemRefs.current[idx] = el;
                          }}
                          type="button"
                          onMouseEnter={() => setActiveIndex(idx)}
                          onClick={() => activate(idx)}
                          className={`flex min-h-10 w-full items-center justify-between gap-2 rounded-xl border px-3 py-1.5 text-left text-sm transition-colors ${
                            isActive
                              ? 'border-[#087bff] bg-[#eef5ff] text-[#08458c] shadow-xs'
                              : 'border-transparent bg-white text-[#0b1636] hover:border-[#d2dfec] hover:bg-[#f4f8fd]'
                          }`}
                        >
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="inline-flex h-5 min-w-6 shrink-0 items-center justify-center rounded border border-[#d2dfec] bg-[#f4f8fd] px-1 font-mono text-[10px] font-bold text-[#08458c]">
                              {mod.code}
                            </span>
                            <span className="truncate font-medium">
                              {mod.label}{' '}
                              <span className="text-xs font-normal text-[#697b9c]">· {mod.hint}</span>
                            </span>
                          </div>
                          <ArrowRight
                            className={`h-3.5 w-3.5 shrink-0 ${isActive ? 'text-[#087bff]' : 'text-[#697b9c]'}`}
                            aria-hidden="true"
                          />
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Hosts Section */}
              {filteredHosts.length > 0 && (
                <div>
                  <div className="px-2.5 py-1 font-mono text-[11px] font-bold tracking-[0.12em] uppercase text-[#506483]">
                    节点主机 ({filteredHosts.length})
                  </div>
                  <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                    {filteredHosts.map((host) => {
                      const idx = indexOfKey.get(`host:${host.hostId}`) ?? 0;
                      const isActive = safeActiveIndex === idx;
                      return (
                        <button
                          key={host.hostId}
                          ref={(el) => {
                            itemRefs.current[idx] = el;
                          }}
                          type="button"
                          onMouseEnter={() => setActiveIndex(idx)}
                          onClick={() => activate(idx)}
                          className={`flex min-h-10 w-full items-center justify-between gap-2 rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                            isActive
                              ? 'border-[#087bff] bg-[#eef5ff] text-[#08458c] shadow-xs'
                              : 'border-transparent bg-white text-[#0b1636] hover:border-[#d2dfec] hover:bg-[#f4f8fd]'
                          }`}
                        >
                          <div className="flex min-w-0 items-center gap-2.5">
                            <Server className="h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />
                            <div className="min-w-0">
                              <p className="truncate font-semibold">{host.hostId}</p>
                              <p className="truncate font-mono text-[11px] text-[#506483]">
                                {host.containerCount} 容器 · {host.runtimes.join('/') || 'unknown'}
                                {host.alertCount > 0 ? ` · ${host.alertCount} 告警` : ''}
                              </p>
                            </div>
                          </div>
                          <span className="shrink-0 font-mono text-[10px] font-semibold text-[#697b9c]">
                            {onSelectHost || q === host.hostId.toLowerCase() ? '跳转' : '筛选'}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Containers Section */}
              {filteredContainers.length > 0 && (
                <div>
                  <div className="px-2.5 py-1 font-mono text-[11px] font-bold tracking-[0.12em] uppercase text-[#506483]">
                    在线容器 ({filteredContainers.length})
                  </div>
                  <div className="space-y-1">
                    {filteredContainers.map((c) => {
                      const entryKey = `container:${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`;
                      const idx = indexOfKey.get(entryKey) ?? 0;
                      const isActive = safeActiveIndex === idx;
                      return (
                        <button
                          key={entryKey}
                          ref={(el) => {
                            itemRefs.current[idx] = el;
                          }}
                          type="button"
                          onMouseEnter={() => setActiveIndex(idx)}
                          onClick={() => activate(idx)}
                          className={`group flex min-h-10 w-full items-center justify-between gap-2 rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                            isActive
                              ? 'border-[#087bff] bg-[#eef5ff] text-[#08458c] shadow-xs'
                              : 'border-transparent bg-white text-[#0b1636] hover:border-[#d2dfec] hover:bg-[#f4f8fd]'
                          }`}
                        >
                          <div className="flex min-w-0 items-center gap-2.5">
                            <Box className="h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />
                            <span className="truncate font-semibold">{c.container_name}</span>
                            <span className="truncate text-xs text-[#506483]">
                              {c.user_email ? `${c.user_email} · ` : ''}
                              {c.user_note ? `${c.user_note} · ` : ''}
                              {c.host_id} · {c.project ? `${c.runtime}/${c.project}` : c.runtime}
                            </span>
                          </div>
                          <div className="flex shrink-0 items-center gap-2 text-xs text-[#506483]">
                            <span className="font-mono font-semibold tabular-nums text-[#0b1636]">
                              CPU {(c.cpu_percent || 0).toFixed(1)}%
                            </span>
                            <ArrowRight
                              className={`h-3.5 w-3.5 ${isActive ? 'text-[#087bff]' : 'text-[#697b9c]'}`}
                              aria-hidden="true"
                            />
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#d2dfec] bg-[#f4f8fd] px-4 py-2.5 text-[11px] text-[#506483]">
          <span>
            按{' '}
            <kbd className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#0b1636]">
              ↑
            </kbd>{' '}
            <kbd className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#0b1636]">
              ↓
            </kbd>{' '}
            导航，
            <kbd className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#0b1636]">
              Enter
            </kbd>{' '}
            跳转，
            <kbd className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#0b1636]">
              Esc
            </kbd>{' '}
            关闭
          </span>
          <span>
            快捷键：
            <kbd className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#0b1636]">
              Ctrl+K
            </kbd>
          </span>
        </div>
      </div>
    </div>
  );
};
