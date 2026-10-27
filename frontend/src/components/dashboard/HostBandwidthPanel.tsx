import React, { useEffect, useMemo, useState } from 'react';
import { Gauge, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
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
const directionLabel: Record<string, string> = { upload: '上行', download: '下行' };
const bandwidthPriorityFixIsAvailable = (value: string) => {
  const match = value.match(/(?:^|[^0-9])v?(\d+)\.(\d+)\.(\d+)/i);
  if (!match) return null;
  const actual = match.slice(1).map(Number);
  const minimum = [1, 7, 98];
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual[index] !== minimum[index]) return actual[index] > minimum[index];
  }
  return true;
};
const formatBandwidthFailure = (message: string, agentVersion: string) => {
  if (!/RTNETLINK answers: File exists/i.test(message)) return message;
  const hasPriorityRetry = bandwidthPriorityFixIsAvailable(agentVersion);
  if (hasPriorityRetry === false) {
    return `${message}。当前 Agent ${agentVersion} 早于 1.7.98，尚无 tc 优先级冲突重试；升级到 1.7.98 或更新版本后重新保存。`;
  }
  return `${message}。该方向尚未确认限速生效；请查看 tc 过滤器优先级冲突。Agent 只会选择空闲优先级，不会覆盖已有过滤器。`;
};

export const HostBandwidthPanel: React.FC<HostBandwidthPanelProps> = ({ hostId, containers, onToast, onRefresh, onClose }) => {
  const [context, setContext] = useState<ManualBandwidthLimitResponse | null>(null);
  const [hostLimit, setHostLimit] = useState<ManualBandwidthLimit | null>(null);
  const [autoThrottleEnabled, setAutoThrottleEnabled] = useState(true);
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
      const loadedHostLimit = result.policy.limits.find((item) => item.scope === 'host') || null;
      setHostLimit(loadedHostLimit);
      setAutoThrottleEnabled(result.policy.auto_throttle?.enabled ?? Boolean(loadedHostLimit));
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
  const selectedInterface = context?.interfaces.find((item) => item.name === hostLimit?.interface);
  const reportedAuto = context?.reported?.auto_throttle;
  const reportedItems = context?.reported?.items || [];
  const reportedFailures = reportedItems.filter((item) => item.state === 'failed' || item.state === 'cleanup_failed');
  const savedRevision = Number(context?.policy?.revision || 0);
  const reportedRevision = Number(context?.reported?.revision || 0);
  const waitingForApply = Boolean(context?.host_online && savedRevision > reportedRevision);
  const reportMatchesCurrentRevision = savedRevision === reportedRevision;
  const activeLimits = useMemo(() => {
    if (Array.isArray(context?.reported?.active_limits)) return context.reported.active_limits;
    const grouped = new Map<string, {
      scope: 'host' | 'container'; target: string; interface: string;
      runtime: 'incus' | 'podman' | ''; project: string; container_name: string;
      container_id: string; upload_mbps: number; download_mbps: number; last_confirmed_at: number;
    }>();
    for (const item of reportedItems) {
      if (item.state !== 'applied' || (item.scope !== 'host' && item.scope !== 'container')) continue;
      const scope = item.scope;
      const target = String(item.target || item.container_name || item.interface || '');
      if (!target) continue;
      const runtime = item.runtime === 'incus' || item.runtime === 'podman' ? item.runtime : '';
      const project = String(item.project || '');
      const containerId = String(item.container_id || '');
      const iface = String(item.interface || '');
      const key = [scope, runtime, project, containerId || target, iface].join('\0');
      const current = grouped.get(key) || {
        scope, target, interface: iface, runtime, project,
        container_name: String(item.container_name || ''), container_id: containerId,
        upload_mbps: 0, download_mbps: 0, last_confirmed_at: 0,
      };
      if (item.direction === 'upload' || item.direction === 'download') {
        current[`${item.direction}_mbps`] = Number(item.rate_mbps || 0);
      } else {
        current.upload_mbps = Number(item.upload_mbps || 0);
        current.download_mbps = Number(item.download_mbps || 0);
      }
      grouped.set(key, current);
    }
    return Array.from(grouped.values()).filter((item) => item.upload_mbps > 0 || item.download_mbps > 0);
  }, [context?.reported?.active_limits, reportedItems]);
  const activeContainerLimits = activeLimits.filter((item) => item.scope === 'container');
  const activeHostLimits = activeLimits.filter((item) => item.scope === 'host');
  const autoActiveItems = (reportedAuto?.items || []).filter((item) => item.state === 'limited'
    || Number(item.upload_high_seconds || 0) > 0 || Number(item.download_high_seconds || 0) > 0
    || Number(item.upload_low_seconds || 0) > 0 || Number(item.download_low_seconds || 0) > 0);
  const autoStateLabel: Record<string, string> = {
    limited: '已触发阶梯限速', monitoring: '监测中，当前未限速',
    no_mapped_containers: '未发现可安全映射的容器', disabled: '自动保护已关闭',
    verification_unavailable: '网卡或网络命名空间无法核实，暂不自动限速',
    sampling_unavailable: '容器流量采样不可用，暂不推进限速阶梯',
  };

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
      const result = await api.updateManualBandwidthLimits(hostId, limits, { enabled: autoThrottleEnabled && Boolean(hostLimit) });
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

    {(context?.reported || waitingForApply) && <p className={`mt-3 text-xs ${waitingForApply ? 'text-amber-200' : context?.reported?.state === 'applied' ? 'text-emerald-300' : context?.reported?.state === 'failed' || context?.reported?.state === 'rejected' ? 'text-rose-300' : 'text-slate-400'}`} role="status">
      节点状态：{waitingForApply ? '策略已保存，等待 Agent 应用并读回' : reportedLabel[context?.reported?.state || ''] || '等待节点回报'}{context?.reported?.revision ? ` · 最近确认修订 ${context.reported.revision}` : ''}
      {waitingForApply ? ` · 当前策略修订 ${savedRevision}` : ''}
      {context?.sample_at ? ` · 最近上报 ${new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', dateStyle: 'short', timeStyle: 'medium' }).format(context.sample_at * 1000)}` : ''}
      {context?.reported?.message ? ` · ${context.reported.message}` : ''}
    </p>}
    {reportedFailures.length > 0 && <div className="mt-3 rounded-lg border border-rose-900/70 bg-rose-950/25 p-3" role="alert">
      <h4 className="text-xs font-semibold text-rose-200">{reportMatchesCurrentRevision ? '限速未确认成功的项目' : '上一修订失败记录（当前修订尚未全部确认）'}</h4>
      <div className="mt-2 space-y-2">
        {reportedFailures.map((item, index) => {
          const target = String(item.target || item.container_name || item.interface || '目标');
          const direction = directionLabel[String(item.direction || '')] || '目标';
          const message = formatBandwidthFailure(String(item.message || 'Agent 未提供详细错误'), context?.agent_version || '');
          return <div key={`${target}-${String(item.direction || '')}-${index}`} className="break-words text-xs leading-5 text-rose-100/90">
            <span className="font-semibold">{target}{item.interface ? ` · ${String(item.interface)}` : ''} · {direction}：</span>{message}
          </div>;
        })}
      </div>
    </div>}

    {loading ? <p className="mt-4 text-sm text-slate-400">正在读取在线清单…</p> : loadError ? <p className="mt-4 rounded-lg border border-rose-900/60 p-3 text-sm text-rose-200">{loadError}</p> : <>
      {!context?.host_online && <p className="mt-3 text-sm text-amber-200">母机离线或身份未注册，当前只读，不能保存新策略。</p>}

      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-200">母机总带宽</h4>
          {!hostLimit && <button type="button" disabled={!context?.interfaces.some((item) => item.state === 'up')} onClick={() => { setHostLimit({ scope: 'host', interface: context?.interfaces.find((item) => item.state === 'up')?.name || '', upload_mbps: 20, download_mbps: 20 }); setAutoThrottleEnabled(true); }} className="inline-flex min-h-8 items-center gap-1 rounded-lg border border-sky-800 px-2.5 text-xs text-sky-200 hover:bg-sky-950/50 disabled:opacity-40"><Plus className="h-3.5 w-3.5" />添加母机限速</button>}
        </div>
        {hostLimit ? <div className="mt-3 grid gap-3 sm:grid-cols-[minmax(180px,1.2fr)_1fr_1fr_auto] sm:items-end">
          <label className="block text-xs text-slate-400">采集到的网卡<select className={`${fieldClass} mt-1`} value={hostLimit.interface || ''} onChange={(event) => setHostLimit({ ...hostLimit, interface: event.target.value })}>
            <option value="">选择网卡</option>{context?.interfaces.filter((item) => item.state === 'up').map((item) => <option key={item.name} value={item.name}>{item.name}{item.is_default_route ? ' · 默认路由' : ''}{item.kind ? ` · ${item.kind}` : ''}</option>)}
          </select></label>
          <label className="block text-xs text-slate-400">上行 Mbps<input aria-label="母机上行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={hostLimit.upload_mbps} onChange={(event) => setHostLimit({ ...hostLimit, upload_mbps: rateValue(event.target.value) })} /></label>
          <label className="block text-xs text-slate-400">下行 Mbps<input aria-label="母机下行限速 Mbps" className={`${fieldClass} mt-1`} type="number" min="0" max="100000" step="1" value={hostLimit.download_mbps} onChange={(event) => setHostLimit({ ...hostLimit, download_mbps: rateValue(event.target.value) })} /></label>
          <button type="button" onClick={() => { setHostLimit(null); setAutoThrottleEnabled(false); }} className="min-h-9 rounded-lg border border-rose-900/70 px-3 text-xs text-rose-200 hover:bg-rose-950/40">移除</button>
        </div> : <p className="mt-2 text-xs text-slate-500">未配置母机总限速。</p>}
        {!context?.interfaces.some((item) => item.state === 'up') && <p className="mt-2 text-xs text-amber-300">没有已确认的在线网卡清单；请先更新 Agent 并等待上报。</p>}
      </div>

      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 gap-2.5">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
            <div className="min-w-0">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-200">容器自动阶梯限速</h4>
              <p className="mt-1 text-xs leading-5 text-slate-400">上下行分开累计有效采样窗口：平均速率达到当前限额的 80% 累计 5 分钟，先降到母机基准的 50%；之后仍达到当前容器限额的 80%，再累计 5 分钟降到 25%、5%，最低 1 Mbps。低于当前容器限额的 50% 累计 10 分钟，恢复一级。</p>
            </div>
          </div>
          <label className="inline-flex min-h-9 shrink-0 items-center gap-2 rounded-lg border border-slate-700 px-3 text-xs text-slate-200">
            <input type="checkbox" checked={autoThrottleEnabled} disabled={!hostLimit || !context?.host_online} onChange={(event) => setAutoThrottleEnabled(event.target.checked)} className="h-4 w-4 accent-emerald-500" />
            启用自动保护
          </label>
        </div>
        <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 p-2.5 text-[11px] leading-5 text-slate-400">
          以当前所选网卡的带宽为基准；例如 20 Mbps 的方向，平均速率达到 16 Mbps 并累计覆盖 5 分钟有效采样后触发，随后依次为 10 → 5 → 1 Mbps。之后每级按当前容器限额的 80% 继续判断；低于当前限额的一半并累计 10 分钟后，每次恢复一级。只处理能由 Agent 确认网络归属的 Incus / Podman 容器；共享网络命名空间、网卡路径或采样无法确认时，不启动新的自动限速。超出 policer 的数据包会被丢弃。
        </div>
        {selectedInterface && autoThrottleEnabled && <p className="mt-2 text-[11px] leading-5 text-sky-200/80">
          当前网络范围：{selectedInterface.kind === 'bridge' ? `直接接入 ${selectedInterface.name} 的运行时 bridge 容器` : selectedInterface.is_default_route ? `挂接到运行时 bridge、经默认路由 ${selectedInterface.name} 转发的容器` : `Agent 验证默认网络确实经过 ${selectedInterface.name} 的容器`}。未能确认路径的容器会跳过保护。
        </p>}
        {reportedAuto && <div className="mt-3 border-t border-slate-800 pt-2 text-xs" role="status">
          <p className={reportedAuto.state === 'limited' || reportedAuto.state === 'verification_unavailable' || reportedAuto.state === 'sampling_unavailable' ? 'text-amber-300' : reportedAuto.state === 'no_mapped_containers' ? 'text-slate-400' : 'text-emerald-300'}>
            节点状态：{autoStateLabel[reportedAuto.state || ''] || '等待 Agent 上报'}{reportedAuto.interface ? ` · 网卡 ${reportedAuto.interface}` : ''}
          </p>
          <p className="mt-1 text-[11px] text-slate-500">已映射 {Number(reportedAuto.mapped_containers || 0)} 个 · 路径不匹配 {Number(reportedAuto.unmapped_containers || 0)} 个 · 流量采样不可用 {Number(reportedAuto.unavailable_samples || 0)} 个</p>
          {reportedAuto.message && <p className="mt-1 text-[11px] text-amber-200">{reportedAuto.message}</p>}
          {autoActiveItems.length > 0 && <div className="mt-2 space-y-2 text-slate-300">
            {autoActiveItems.slice(0, 6).map((item, index) => {
              const uploadHigh = Number(item.upload_high_seconds || 0);
              const downloadHigh = Number(item.download_high_seconds || 0);
              const uploadLow = Number(item.upload_low_seconds || 0);
              const downloadLow = Number(item.download_low_seconds || 0);
              const progress = [
                uploadHigh > 0 ? `上行高占用 ${uploadHigh}/300 秒` : '',
                downloadHigh > 0 ? `下行高占用 ${downloadHigh}/300 秒` : '',
                uploadLow > 0 ? `上行恢复观察 ${uploadLow}/600 秒` : '',
                downloadLow > 0 ? `下行恢复观察 ${downloadLow}/600 秒` : '',
              ].filter(Boolean).join(' · ');
              return <div key={`${String(item.container_id || item.container_name)}-${index}`} className="break-all">
                <p>{String(item.runtime || '')}/{String(item.container_name || '')} · 上行 {Number(item.upload_current_mbps || 0).toFixed(2)}/{Number(item.upload_baseline_mbps || 0)} Mbps{Number(item.upload_mbps || 0) ? `（限 ${Number(item.upload_mbps)}）` : ''} · 下行 {Number(item.download_current_mbps || 0).toFixed(2)}/{Number(item.download_baseline_mbps || 0)} Mbps{Number(item.download_mbps || 0) ? `（限 ${Number(item.download_mbps)}）` : ''}</p>
                {progress && <p className="mt-0.5 text-[11px] text-sky-200/80">{progress}</p>}
              </div>;
            })}
            {autoActiveItems.length > 6 && <p className="text-slate-500">另有 {autoActiveItems.length - 6} 个容器处于保护或阶梯观察中</p>}
          </div>}
        </div>}
      </div>

      <div className="mt-3 rounded-lg border border-sky-900/60 bg-sky-950/15 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-100">当前已确认生效的限速</h4>
          <span className="text-[11px] text-slate-500">按 Agent 最近一次内核读回记录 · {activeContainerLimits.length} 个容器</span>
        </div>
        {activeContainerLimits.length > 0 ? <div className="mt-2 space-y-2">
          {activeContainerLimits.map((item) => <div key={`${item.runtime}/${item.project}/${item.container_id || item.target}`} className="grid gap-1 rounded-lg border border-slate-800 bg-slate-950/50 p-2.5 sm:grid-cols-[minmax(180px,1fr)_minmax(220px,auto)] sm:items-center">
            <div className="min-w-0">
              <p className="break-words text-xs font-semibold text-slate-100">{item.runtime}/{item.project ? `${item.project}/` : ''}{item.container_name || item.target}</p>
              <p className="break-all font-mono text-[10px] text-slate-500">{item.container_id}{item.interface ? ` · ${item.interface}` : ''}</p>
            </div>
            <p className="tabular-nums text-xs text-sky-100">上行 {item.upload_mbps > 0 ? `${item.upload_mbps} Mbps` : '未限'} · 下行 {item.download_mbps > 0 ? `${item.download_mbps} Mbps` : '未限'}</p>
          </div>)}
        </div> : <p className="mt-2 text-xs text-slate-400">当前没有已确认生效的容器限速。策略配置值不代表节点已经应用成功。</p>}
        {activeHostLimits.length > 0 && <div className="mt-3 border-t border-slate-800 pt-2">
          <p className="text-[11px] font-semibold text-slate-300">母机网卡限速</p>
          {activeHostLimits.map((item) => <p key={`${item.interface}-${item.target}`} className="mt-1 tabular-nums text-xs text-sky-100">{item.interface || item.target} · 上行 {item.upload_mbps > 0 ? `${item.upload_mbps} Mbps` : '未限'} · 下行 {item.download_mbps > 0 ? `${item.download_mbps} Mbps` : '未限'}</p>)}
        </div>}
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
