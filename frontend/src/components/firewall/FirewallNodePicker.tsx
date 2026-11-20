import React, { useEffect, useMemo, useState } from 'react';
import { Check, ChevronLeft, ChevronRight, Search, Server } from 'lucide-react';
import { FleetFirewallHostStatus } from '../../api/types';

export interface FirewallNodeOption {
  host_id: string;
  node_id: string;
  stale: boolean;
}

export type FirewallNodeFilter = 'all' | 'attention' | 'online' | 'offline';

interface FirewallNodePickerProps {
  hosts: FirewallNodeOption[];
  fleetHosts: FleetFirewallHostStatus[];
  selectedHostId: string;
  search: string;
  filter: FirewallNodeFilter;
  onSearchChange: (value: string) => void;
  onFilterChange: (value: FirewallNodeFilter) => void;
  onSelect: (hostId: string) => void;
}

const healthyStates = new Set(['ready', 'last_apply_succeeded']);
const errorStates = new Set(['apply_failed', 'drifted', 'runman_update_required', 'rfw_protocol_update_required']);
const PAGE_SIZE = 6;
const stateLabels: Record<string, string> = {
  unregistered: '未登记',
  offline: '离线',
  awaiting_capability: '等待能力上报',
  awaiting_rfw_capability: '等待 RFW 核验',
  rfw_protocol_update_required: '需升级 RFW',
  runman_update_required: '需更新 Runman',
  runman_unavailable: 'Runman 不可用',
  queued: '策略处理中',
  awaiting_interfaces: '等待网卡清单',
  interfaces_not_found: '未发现目标网桥',
  apply_failed: '应用失败',
  drifted: '规则有偏差',
  last_apply_succeeded: '最近已应用',
  not_synced: '待同步',
  ready: '已就绪',
};

export const FirewallNodePicker: React.FC<FirewallNodePickerProps> = ({
  hosts,
  fleetHosts,
  selectedHostId,
  search,
  filter,
  onSearchChange,
  onFilterChange,
  onSelect,
}) => {
  const [page, setPage] = useState(0);
  const statusByHost = useMemo(() => new Map(fleetHosts.map((host) => [host.host_id, host])), [fleetHosts]);
  const selectedHost = hosts.find((host) => host.host_id === selectedHostId);
  const selectedStatus = selectedHost ? statusByHost.get(selectedHost.host_id) : undefined;
  const getOnline = (host: FirewallNodeOption) => statusByHost.get(host.host_id)?.online ?? !host.stale;
  const needsAttention = (host: FirewallNodeOption) => {
    const status = statusByHost.get(host.host_id);
    return host.stale || Boolean(status && !healthyStates.has(status.state));
  };
  const counts = {
    all: hosts.length,
    attention: hosts.filter(needsAttention).length,
    online: hosts.filter(getOnline).length,
    offline: hosts.filter((host) => !getOnline(host)).length,
  };
  const filteredHosts = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return hosts
      .filter((host) => {
        const searchable = `${host.host_id} ${host.node_id}`.toLocaleLowerCase();
        if (query && !searchable.includes(query)) return false;
        if (filter === 'attention' && !needsAttention(host)) return false;
        if (filter === 'online' && !getOnline(host)) return false;
        if (filter === 'offline' && getOnline(host)) return false;
        return true;
      })
      .sort(
        (a, b) =>
          Number(needsAttention(b)) - Number(needsAttention(a)) ||
          Number(getOnline(b)) - Number(getOnline(a)) ||
          a.host_id.localeCompare(b.host_id)
      );
  }, [filter, fleetHosts, hosts, search, statusByHost]);

  const pageCount = Math.max(1, Math.ceil(filteredHosts.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleHosts = filteredHosts.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);

  useEffect(() => setPage(0), [filter, search]);
  useEffect(() => setPage((current) => Math.min(current, pageCount - 1)), [pageCount]);

  return (
    <section aria-label="选择防火墙节点" className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-bold text-[#0b1636]">选择母机</h3>
          <p className="mt-0.5 text-[11px] text-[#697b9c]">先定位节点，再查看或修改它的策略。</p>
        </div>
        <span className="rn2-pill rn2-pill-sm shrink-0 font-mono tabular-nums">{hosts.length} 台</span>
      </div>

      {selectedHost && (
        <div
          role="status"
          aria-live="polite"
          className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] px-3 py-2 text-[11px]"
        >
          <span className="font-semibold text-[#0657b8]">当前策略对象</span>
          <strong className="max-w-full break-all font-bold text-[#0b1636]">{selectedHost.host_id}</strong>
          <span className="text-[#697b9c]">·</span>
          <span
            className={
              selectedStatus && errorStates.has(selectedStatus.state)
                ? 'font-semibold text-[#b41835]'
                : selectedStatus && healthyStates.has(selectedStatus.state)
                  ? 'font-semibold text-[#147468]'
                  : 'font-semibold text-[#9a5b00]'
            }
          >
            {selectedStatus
              ? stateLabels[selectedStatus.state] || selectedStatus.state
              : selectedHost.stale
                ? '心跳过期'
                : '等待节点状态'}
          </span>
        </div>
      )}

      <label htmlFor="firewall-host-search" className="sr-only">
        搜索母机名称或节点 ID
      </label>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#697b9c]" aria-hidden="true" />
        <input
          id="firewall-host-search"
          type="search"
          value={search}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="搜索母机名称或节点 ID…"
          className="rn2-input pl-9"
        />
      </div>

      <div className="flex flex-wrap gap-1.5" role="group" aria-label="筛选母机状态">
        {([
          ['all', '全部'],
          ['attention', '需关注'],
          ['online', '在线'],
          ['offline', '离线'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => onFilterChange(key)}
            aria-pressed={filter === key}
            className={`min-h-9 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] ${
              filter === key
                ? 'border-[#087bff] bg-[#087bff] text-white shadow-[0_2px_8px_rgba(8,123,255,0.25)]'
                : 'border-[#cedae7] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff] hover:bg-[#e8f3ff] hover:text-[#08458c]'
            }`}
          >
            {label} <span className="ml-1 font-mono tabular-nums">{counts[key]}</span>
          </button>
        ))}
      </div>

      {filteredHosts.length ? (
        <>
          <div className="space-y-2" aria-label="母机列表">
            {visibleHosts.map((host) => {
              const status = statusByHost.get(host.host_id);
              const selected = host.host_id === selectedHostId;
              const online = getOnline(host);
              const attention = needsAttention(host);
              const tone = errorStates.has(status?.state || '')
                ? 'rn2-pill-crimson'
                : !online || attention
                  ? 'rn2-pill-amber'
                  : 'rn2-pill-teal';
              const stateLabel = status ? stateLabels[status.state] || status.state : online ? '在线 · 等待状态' : '心跳过期';
              const interfaceStatus = status?.container_interfaces;
              const networks =
                interfaceStatus?.stale || interfaceStatus?.status !== 'ready'
                  ? '网卡清单待刷新'
                  : [
                      interfaceStatus.by_runtime.incus.length ? `Incus ${interfaceStatus.by_runtime.incus.length}` : '',
                      interfaceStatus.by_runtime.podman.length ? `Podman ${interfaceStatus.by_runtime.podman.length}` : '',
                      interfaceStatus.by_runtime.runman.length ? `Runman ${interfaceStatus.by_runtime.runman.length}` : '',
                    ]
                      .filter(Boolean)
                      .join(' · ') || '未发现容器网桥';

              return (
                <button
                  key={host.host_id}
                  type="button"
                  onClick={() => onSelect(host.host_id)}
                  aria-pressed={selected}
                  className={`flex min-h-16 w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] ${
                    selected
                      ? 'border-[#087bff] bg-[#e8f3ff] shadow-[0_0_0_1px_#087bff]'
                      : 'border-[#cedae7] bg-[#f4f8fd] hover:border-[#087bff] hover:bg-white'
                  }`}
                >
                  <span
                    className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${
                      selected
                        ? 'border-[#087bff] bg-[#087bff] text-white'
                        : 'border-[#cedae7] bg-white text-[#31485e]'
                    }`}
                  >
                    <Server className="h-4 w-4" aria-hidden="true" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-bold text-[#0b1636]" title={host.host_id}>
                      {host.host_id}
                    </span>
                    <span className="mt-1 block truncate text-[11px] text-[#697b9c]">
                      {networks}
                      {status?.agent_version ? ` · Agent ${status.agent_version}` : ''}
                    </span>
                  </span>
                  <span className={`rn2-pill rn2-pill-sm shrink-0 ${tone}`}>{stateLabel}</span>
                  {selected && <Check className="h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />}
                </button>
              );
            })}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1" aria-label="母机列表分页">
            <span className="text-[11px] text-[#697b9c]">
              显示 {currentPage * PAGE_SIZE + 1}–{Math.min((currentPage + 1) * PAGE_SIZE, filteredHosts.length)} / {filteredHosts.length} 台
            </span>
            <div className="flex gap-1.5">
              <button
                type="button"
                onClick={() => setPage(Math.max(0, currentPage - 1))}
                disabled={currentPage === 0}
                aria-label="上一页母机"
                className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-[#cedae7] bg-white px-2.5 text-xs font-medium text-[#0b1636] hover:border-[#087bff] hover:bg-[#f4f8fd] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] disabled:cursor-not-allowed disabled:opacity-45"
              >
                <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
                上一页
              </button>
              <span className="inline-flex min-h-9 min-w-12 items-center justify-center rounded-lg border border-[#dce5ef] bg-[#f4f8fd] px-2 font-mono text-xs font-semibold tabular-nums text-[#31485e]">
                {currentPage + 1} / {pageCount}
              </span>
              <button
                type="button"
                onClick={() => setPage(Math.min(pageCount - 1, currentPage + 1))}
                disabled={currentPage >= pageCount - 1}
                aria-label="下一页母机"
                className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-[#cedae7] bg-white px-2.5 text-xs font-medium text-[#0b1636] hover:border-[#087bff] hover:bg-[#f4f8fd] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] disabled:cursor-not-allowed disabled:opacity-45"
              >
                下一页
                <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>
        </>
      ) : (
        <div className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] px-3 py-6 text-center text-xs text-[#697b9c]">
          没有符合条件的母机。可以切换状态筛选或清空搜索。
        </div>
      )}
    </section>
  );
};
