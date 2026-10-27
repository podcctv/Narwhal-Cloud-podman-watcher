import React, { useEffect, useMemo, useState } from 'react';
import { Gauge, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../../api/client';
import { ContainerItem, ManualBandwidthLimit, ManualBandwidthLimitResponse } from '../../api/types';

interface HostBandwidthPanelProps {
  hostId: string;
  containers: ContainerItem[];
  onToast?: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh?: () => void;
  onClose: () => void;
}

const fieldClass = 'min-h-9 w-full rounded-lg border border-slate-700 bg-slate-950 px-2.5 text-sm text-slate-100 focus:border-sky-500 focus:outline-hidden focus:ring-2 focus:ring-sky-500/30';
const rateValue = (value: string) => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : 0;
};
const reportedLabel: Record<string, string> = {
  applied: '节点已应用并读回', failed: '节点应用失败', rejected: '节点拒绝策略', unconfigured: '未配置限速',
};

export const HostBandwidthPanel: React.FC<HostBandwidthPanelProps> = ({ hostId, containers, onToast, onRefresh, onClose }) => {
  const [context, setContext] = useState<ManualBandwidthLimitResponse | null>(null);
  const [hostLimit, setHostLimit] = useState<ManualBandwidthLimit | null>(null);
  const [containerLimits, setContainerLimits] = useState<ManualBandwidthLimit[]>([]);
  const [newTarget, setNewTarget] = useState('');
  const [newUpload, setNewUpload] = useState('0');
  const [newDownload, setNewDownload] = useState('0');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState('');

  const refresh = async () => {
    setLoading(true);
    setLoadError('');
    try {
      const result = await api.getManualBandwidthLimits(hostId);
      setContext(result);
      setHostLimit(result.policy.limits.find((item) => item.scope === 'host') || null);
      setContainerLimits(result.policy.limits.filter((item) => item.scope === 'container'));
    } catch (error: any) {
      setLoadError(error?.message || '无法读取母机网卡与容器清单');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, [hostId]);

  const candidates = useMemo(() => containers.filter((item) =>
    (item.runtime === 'incus' || item.runtime === 'podman') && item.container_id
  ), [containers]);
  const targetKey = (item: Pick<ManualBandwidthLimit, 'runtime' | 'project' | 'container_name' | 'container_id'>) =>
    [item.runtime, item.project || '', item.container_name, item.container_id].join('\0');
  const configured = new Set(containerLimits.map(targetKey));
  const availableCandidates = candidates.filter((item) => !configured.has(targetKey({
    runtime: item.runtime as 'incus' | 'podman', project: item.project || '',
    container_name: item.container_name, container_id: item.container_id || '',
  })));
  const selectedCandidate = availableCandidates.find((item) => targetKey({
    runtime: item.runtime as 'incus' | 'podman', project: item.project || '',
    container_name: item.container_name, container_id: item.container_id || '',
  }) === newTarget);

  const updateContainer = (index: number, changes: Partial<ManualBandwidthLimit>) => {
    setContainerLimits((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, ...changes } : item));
  };

  const addContainer = () => {
    if (!selectedCandidate?.container_id) return;
    setContainerLimits((current) => [...current, {
      scope: 'container', runtime: selectedCandidate.runtime as 'incus' | 'podman',
      project: selectedCandidate.project || '', container_name: selectedCandidate.container_name,
      container_id: selectedCandidate.container_id || '',
      upload_mbps: rateValue(newUpload), download_mbps: rateValue(newDownload),
    }]);
    setNewTarget('');
    setNewUpload('0');
    setNewDownload('0');
  };

  const save = async () => {
    if (!context?.host_online) {
      onToast?.('error', '母机当前离线，无法确认策略目标与网卡');
      return;
    }
    const limits = [...(hostLimit ? [hostLimit] : []), ...containerLimits];
    if (limits.some((item) => item.upload_mbps < 0 || item.download_mbps < 0 || (!item.upload_mbps && !item.download_mbps))) {
      onToast?.('error', '每条限速至少要填写一个大于 0 的方向');
      return;
    }
    setSaving(true);
    try {
      const result = await api.updateManualBandwidthLimits(hostId, limits);
      onToast?.('success', `限速策略已保存（修订 ${result.revision}）；节点下次动作轮询时生效`);
      await refresh();
      onRefresh?.();
    } catch (error: any) {
      onToast?.('error', `保存失败：${error?.message || error}`);
    } finally {
      setSaving(false);
    }
  };

  const removeContainer = (index: number) => setContainerLimits((current) => current.filter((_, i) => i !== index));

  return <section className="rounded-xl border border-sky-800/70 bg-slate-950/70 p-4" aria-label={`${hostId} 带宽限速配置`}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-2.5">
        <Gauge className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100">母机与容器带宽限速</h3>
          <p className="mt-1 text-xs leading-5 text-slate-400">上行是发出流量，下行是接收流量。超额流量会被丢弃；这是 policer，不是平滑排队整形。</p>
        </div>
      </div>
      <div className="flex shrink-0 gap-2">
        <button type="button" onClick={() => void refresh()} disabled={loading || saving} className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-slate-700 px-3 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50" aria-label="刷新网卡和容器清单"><RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />刷新</button>
        <button type="button" onClick={onClose} className="min-h-9 rounded-lg border border-slate-700 px-3 text-xs text-slate-300 hover:bg-slate-800">收起</button>
      </div>
    </div>

    <div className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100/90">
      母机限速会作用于所选网卡上的母机及经过它的容器流量；容器限速只作用于所选 Incus / Podman 容器的默认网卡。不会改写已有 root qdisc 或 RFW 规则。修改策略后最多等待一个 Agent 动作轮询周期。
    </div>

    {context?.reported && <p className={`mt-3 text-xs ${context.reported.state === 'applied' ? 'text-emerald-300' : context.reported.state === 'failed' || context.reported.state === 'rejected' ? 'text-rose-300' : 'text-slate-400'}`} role="status">
      节点状态：{reportedLabel[context.reported.state || ''] || '等待节点回报'}{context.reported.revision ? ` · 修订 ${context.reported.revision}` : ''}
      {context.reported.message ? ` · ${context.reported.message}` : ''}
    </p>}

    {loading ? <p className="mt-4 text-sm text-slate-400">正在读取在线清单…</p> : loadError ? <p className="mt-4 rounded-lg border border-rose-900/60 p-3 text-sm text-rose-200">{loadError}</p> : <>
      {!context?.host_online && <p className="mt-3 text-sm text-amber-200">母机离线或身份未注册，当前只读，不能保存新策略。</p>}

      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-200">母机总带宽</h4>
          {!hostLimit && <button type="button" disabled={!context?.interfaces.some((item) => item.state === 'up')} onClick={() => setHostLimit({ scope: 'host', interface: context?.interfaces.find((item) => item.state === 'up')?.name || '', upload_mbps: 20, download_mbps: 20 })} className="inline-flex min-h-8 items-center gap-1 rounded-lg border border-sky-800 px-2.5 text-xs text-sky-200 hover:bg-sky-950/50 disabled:opacity-40"><Plus className="h-3.5 w-3.5" />添加母机限速</button>}
        </div>
        {hostLimit ? <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(180px,1.2fr)_1fr_1fr_auto] sm:items-end">
          <label className="block text-xs text-slate-400">采集到的网卡<select className={`${fieldClass} mt-1`} value={hostLimit.interface || ''} onChange={(event) => setHostLimit({ ...hostLimit, interface: event.target.value })}>
            <option value="">选择网卡</option>{context?.interfaces.filter((item) => item.state === 'up').map((item) => <option key={item.name} value={item.name}>{item.name}{item.is_default_route ? ' · 默认路由' : ''}{item.kind ? ` · ${item.kind}` : ''}</option>)}
          </select></label>
          <label className="block text-xs text-slate-400">上行 Mbps<input aria-label="母机上行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={hostLimit.upload_mbps} onChange={(event) => setHostLimit({ ...hostLimit, upload_mbps: rateValue(event.target.value) })} /></label>
          <label className="block text-xs text-slate-400">下行 Mbps<input aria-label="母机下行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={hostLimit.download_mbps} onChange={(event) => setHostLimit({ ...hostLimit, download_mbps: rateValue(event.target.value) })} /></label>
          <button type="button" onClick={() => setHostLimit(null)} className="min-h-9 rounded-lg border border-rose-900/70 px-3 text-xs text-rose-200 hover:bg-rose-950/40">移除</button>
        </div> : <p className="mt-2 text-xs text-slate-500">未配置母机总限速。</p>}
        {!context?.interfaces.some((item) => item.state === 'up') && <p className="mt-2 text-xs text-amber-300">没有已确认的在线网卡清单；请先更新 Agent 并等待上报。</p>}
      </div>

      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2"><h4 className="text-xs font-semibold uppercase tracking-wide text-slate-200">单容器限速</h4><span className="text-[11px] text-slate-500">仅 Incus / Podman · {containerLimits.length} 条</span></div>
        {containerLimits.length > 0 && <div className="mt-3 space-y-2">
          {containerLimits.map((item, index) => <div key={targetKey(item)} className="grid gap-2 rounded-lg border border-slate-800 p-2.5 sm:grid-cols-[minmax(180px,1.3fr)_1fr_1fr_auto] sm:items-center">
            <div className="min-w-0"><p className="truncate text-xs font-semibold text-slate-100" title={item.container_name}>{item.container_name}</p><p className="truncate font-mono text-[10px] text-slate-500">{item.runtime}{item.project ? `/${item.project}` : ''} · {item.container_id}</p></div>
            <label className="text-[11px] text-slate-400">上行 Mbps<input aria-label={`${item.container_name} 上行限速 Mbps`} className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={item.upload_mbps} onChange={(event) => updateContainer(index, { upload_mbps: rateValue(event.target.value) })} /></label>
            <label className="text-[11px] text-slate-400">下行 Mbps<input aria-label={`${item.container_name} 下行限速 Mbps`} className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={item.download_mbps} onChange={(event) => updateContainer(index, { download_mbps: rateValue(event.target.value) })} /></label>
            <button type="button" onClick={() => removeContainer(index)} className="inline-flex min-h-9 items-center justify-center gap-1 rounded-lg border border-rose-900/70 px-3 text-xs text-rose-200 hover:bg-rose-950/40"><Trash2 className="h-3.5 w-3.5" />移除</button>
          </div>)}
        </div>}
        <div className="mt-3 grid gap-2 sm:grid-cols-[minmax(200px,1.4fr)_1fr_1fr_auto] sm:items-end">
          <label className="block text-xs text-slate-400">在线容器<select className={`${fieldClass} mt-1`} value={newTarget} onChange={(event) => setNewTarget(event.target.value)}>
            <option value="">选择容器</option>{availableCandidates.map((item) => <option key={targetKey({ runtime: item.runtime as 'incus' | 'podman', project: item.project || '', container_name: item.container_name, container_id: item.container_id || '' })} value={targetKey({ runtime: item.runtime as 'incus' | 'podman', project: item.project || '', container_name: item.container_name, container_id: item.container_id || '' })}>{item.runtime}/{item.project ? `${item.project}/` : ''}{item.container_name}</option>)}
          </select></label>
          <label className="block text-xs text-slate-400">上行 Mbps<input aria-label="新容器上行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={newUpload} onChange={(event) => setNewUpload(event.target.value)} /></label>
          <label className="block text-xs text-slate-400">下行 Mbps<input aria-label="新容器下行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={newDownload} onChange={(event) => setNewDownload(event.target.value)} /></label>
          <button type="button" onClick={addContainer} disabled={!selectedCandidate || (!rateValue(newUpload) && !rateValue(newDownload))} className="inline-flex min-h-9 items-center justify-center gap-1 rounded-lg border border-sky-800 px-3 text-xs text-sky-200 hover:bg-sky-950/50 disabled:opacity-40"><Plus className="h-3.5 w-3.5" />添加</button>
        </div>
        {!candidates.length && <p className="mt-2 text-xs text-amber-300">最新采样中没有可限速的 Incus / Podman 容器；容器身份或 Agent 采集未就绪。</p>}
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-[11px] leading-5 text-slate-500">清空所有条目并保存，可撤销主机和容器限速。策略按当前节点身份保存。</p>
        <button type="button" onClick={() => void save()} disabled={saving || !context?.host_online} className="min-h-10 rounded-lg border border-sky-700 bg-sky-950/70 px-4 text-xs font-semibold text-sky-100 hover:bg-sky-900/70 disabled:opacity-50">{saving ? '保存中…' : '保存并应用'}</button>
      </div>
    </>}
  </section>;
};
