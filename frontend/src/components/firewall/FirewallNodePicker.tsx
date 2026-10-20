import React, { useMemo } from 'react';
import { Check, Search, Server } from 'lucide-react';
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
const stateLabels: Record<string, string> = {
  unregistered: '未登记', offline: '离线', awaiting_capability: '等待能力上报',
  awaiting_rfw_capability: '等待 RFW 核验', rfw_protocol_update_required: '需升级 RFW',
  runman_update_required: '需更新 Runman', runman_unavailable: 'Runman 不可用',
  queued: '策略处理中', awaiting_interfaces: '等待网卡清单', interfaces_not_found: '未发现目标网桥',
  apply_failed: '应用失败', drifted: '规则有偏差', last_apply_succeeded: '最近已应用',
  not_synced: '待同步', ready: '已就绪',
};

export const FirewallNodePicker: React.FC<FirewallNodePickerProps> = ({
  hosts, fleetHosts, selectedHostId, search, filter, onSearchChange, onFilterChange, onSelect,
}) => {
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
    return hosts.filter((host) => {
      const searchable = `${host.host_id} ${host.node_id}`.toLocaleLowerCase();
      if (query && !searchable.includes(query)) return false;
      if (filter === 'attention' && !needsAttention(host)) return false;
      if (filter === 'online' && !getOnline(host)) return false;
      if (filter === 'offline' && getOnline(host)) return false;
      return true;
    }).sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a))
      || Number(getOnline(b)) - Number(getOnline(a))
      || a.host_id.localeCompare(b.host_id));
  }, [filter, fleetHosts, hosts, search, statusByHost]);

  return <section aria-label="选择防火墙节点" className="space-y-3">
    <div className="flex items-center justify-between gap-3">
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-slate-200">选择母机</h3>
        <p className="mt-0.5 text-[11px] text-slate-500">先定位节点，再查看或修改它的策略。</p>
      </div>
      <span className="shrink-0 rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-[10px] text-slate-400">{hosts.length} 台</span>
    </div>

    {selectedHost && <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg border border-sky-900/70 bg-sky-950/30 px-3 py-2 text-[10px]">
      <span className="text-sky-300">当前策略对象</span>
      <strong className="max-w-full break-all text-slate-100">{selectedHost.host_id}</strong>
      <span className="text-slate-500">·</span>
      <span className={selectedStatus && errorStates.has(selectedStatus.state) ? 'text-rose-300' : selectedStatus && healthyStates.has(selectedStatus.state) ? 'text-emerald-300' : 'text-amber-300'}>
        {selectedStatus ? stateLabels[selectedStatus.state] || selectedStatus.state : selectedHost.stale ? '心跳过期' : '等待节点状态'}
      </span>
    </div>}

    <label htmlFor="firewall-host-search" className="sr-only">搜索母机名称或节点 ID</label>
    <div className="relative">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" aria-hidden="true" />
      <input id="firewall-host-search" type="search" value={search} onChange={(event) => onSearchChange(event.target.value)} placeholder="搜索母机名称或节点 ID…" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-400" />
    </div>

    <div className="flex flex-wrap gap-1.5" role="group" aria-label="筛选母机状态">
      {([
        ['all', '全部'], ['attention', '需关注'], ['online', '在线'], ['offline', '离线'],
      ] as const).map(([key, label]) => <button key={key} type="button" onClick={() => onFilterChange(key)} aria-pressed={filter === key} className={`min-h-9 rounded-lg border px-2.5 text-[10px] transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 ${filter === key ? 'border-sky-700 bg-sky-950/60 text-sky-100' : 'border-slate-700 bg-slate-950/70 text-slate-400 hover:bg-slate-800'}`}>
        {label} <span className="ml-1 font-mono tabular-nums">{counts[key]}</span>
      </button>)}
    </div>

    {filteredHosts.length ? <div className="max-h-72 space-y-1.5 overflow-y-auto pr-1" aria-label="母机列表">
      {filteredHosts.map((host) => {
        const status = statusByHost.get(host.host_id);
        const selected = host.host_id === selectedHostId;
        const online = getOnline(host);
        const attention = needsAttention(host);
        const tone = errorStates.has(status?.state || '')
          ? 'border-rose-800 bg-rose-950/40 text-rose-200'
          : !online || attention
            ? 'border-amber-800 bg-amber-950/40 text-amber-200'
            : 'border-emerald-800 bg-emerald-950/40 text-emerald-200';
        const stateLabel = status ? stateLabels[status.state] || status.state : online ? '在线 · 等待状态' : '心跳过期';
        const interfaceStatus = status?.container_interfaces;
        const networks = interfaceStatus?.stale || interfaceStatus?.status !== 'ready'
          ? '网卡清单待刷新'
          : [
            interfaceStatus.by_runtime.incus.length ? `Incus ${interfaceStatus.by_runtime.incus.length}` : '',
            interfaceStatus.by_runtime.podman.length ? `Podman ${interfaceStatus.by_runtime.podman.length}` : '',
          ].filter(Boolean).join(' · ') || '未发现容器网桥';

        return <button key={host.host_id} type="button" onClick={() => onSelect(host.host_id)} aria-pressed={selected} className={`flex min-h-16 w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 ${selected ? 'border-sky-600 bg-sky-950/50' : 'border-slate-800 bg-slate-950/50 hover:border-slate-600 hover:bg-slate-900'}`}>
          <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${selected ? 'border-sky-700/70 bg-sky-950 text-sky-300' : 'border-slate-700 bg-slate-900 text-slate-400'}`}><Server className="h-4 w-4" aria-hidden="true" /></span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-xs font-semibold text-slate-100" title={host.host_id}>{host.host_id}</span>
            <span className="mt-1 block truncate text-[10px] text-slate-500">{networks}{status?.agent_version ? ` · Agent ${status.agent_version}` : ''}</span>
          </span>
          <span className={`shrink-0 rounded-full border px-2 py-1 text-[9px] ${tone}`}>{stateLabel}</span>
          {selected && <Check className="h-4 w-4 shrink-0 text-sky-300" aria-hidden="true" />}
        </button>;
      })}
    </div> : <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-6 text-center text-xs text-slate-500">
      没有符合条件的母机。可以切换状态筛选或清空搜索。
    </div>}
  </section>;
};
