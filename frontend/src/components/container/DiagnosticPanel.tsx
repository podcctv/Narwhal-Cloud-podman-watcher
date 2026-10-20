import React, { useCallback, useMemo, useRef, useState } from 'react';
import { Sparkles, Terminal, Globe, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import { DiagnosticData, ContainerIdentity, IPReputationResult } from '../../api/types';
import { api, fmtBytes, fmtMbps, fmtNumber } from '../../api/client';

interface DiagnosticPanelProps {
  identity: ContainerIdentity;
  diagnostic: DiagnosticData | null;
  isStale?: boolean;
  onRefresh: () => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const DiagnosticPanel: React.FC<DiagnosticPanelProps> = ({
  identity,
  diagnostic,
  isStale = false,
  onRefresh,
  onToast,
}) => {
  const [submitting, setSubmitting] = useState(false);
  const [reputationConfigured, setReputationConfigured] = useState(false);
  const [reputationSettingsLoaded, setReputationSettingsLoaded] = useState(false);
  const [checkingReputation, setCheckingReputation] = useState<string | null>(null);
  const [reputationByIp, setReputationByIp] = useState<Record<string, IPReputationResult>>({});
  const reputationLookupInFlight = useRef(new Set<string>());
  const reputationLookupsStarted = useRef(new Set<string>());

  const action = diagnostic?.action;
  const sample = diagnostic?.sample;
  const isQueuedOrDispatched =
    action && (action.status === 'queued' || action.status === 'dispatched');

  // Automatically poll every 2.5 seconds while waiting for the node to return diagnostic report
  React.useEffect(() => {
    if (!isQueuedOrDispatched) return;
    const pollTimer = setInterval(() => {
      onRefresh();
    }, 2500);
    return () => clearInterval(pollTimer);
  }, [isQueuedOrDispatched, onRefresh]);

  React.useEffect(() => {
    let active = true;
    api.getIPReputationSettings()
      .then(result => {
        if (!active) return;
        setReputationConfigured(Boolean(result.configured));
        setReputationSettingsLoaded(true);
      })
      .catch(() => {
        if (!active) return;
        setReputationConfigured(false);
        setReputationSettingsLoaded(true);
      });
    return () => { active = false; };
  }, []);

  const checkReputation = useCallback(async (ip: string) => {
    if (!ip || reputationLookupInFlight.current.has(ip)) return null;
    reputationLookupInFlight.current.add(ip);
    setCheckingReputation(ip);
    try {
      const result = await api.checkIPReputation(ip);
      setReputationByIp(current => ({ ...current, [ip]: result }));
      return result;
    } catch (err: any) {
      const result: IPReputationResult = {
        status: 'error',
        ip,
        message: err?.message || '查询失败',
      };
      setReputationByIp(current => ({
        ...current,
        [ip]: result,
      }));
      return result;
    } finally {
      reputationLookupInFlight.current.delete(ip);
      setCheckingReputation(current => current === ip ? null : current);
    }
  }, []);

  const handleRequest = async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await api.requestContainerDiagnostic(identity);
      onToast('success', '已触发一次性深度采样请求');
      onRefresh();
    } catch (err: any) {
      onToast('error', `请求失败：${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const isSupportedRuntime = ['incus', 'podman'].includes(identity.runtime);
  const inboundIps = sample?.inbound_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.inbound || 0) > 0);
  const outboundIps = sample?.outbound_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.outbound || 0) > 0);
  const unclassifiedIps = sample?.unclassified_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.unknown || 0) > 0);
  const automaticReputationCandidates = useMemo(() => {
    const candidates = sample?.inbound_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.inbound || 0) > 0);
    const seen = new Set<string>();
    return [...candidates]
      .filter((ip) => Boolean(ip.ip) && Number(ip.inbound || 0) > 0)
      .sort((a, b) => Number(b.inbound || 0) - Number(a.inbound || 0))
      .filter((ip) => {
        const address = ip.ip || '';
        if (seen.has(address)) return false;
        seen.add(address);
        return true;
      })
      .slice(0, 5)
      .map((ip) => ip.ip as string);
  }, [sample?.inbound_ips, sample?.connection_ips]);
  const highlyReportedInboundIps = inboundIps.filter((ip) => {
    const result = reputationByIp[ip.ip || ''];
    return result?.status === 'checked' && Number(result.abuse_confidence_score || 0) >= 75;
  });
  const diagnosticSnapshotId = action?.id ?? sample?.report_timestamp_utc8 ?? '';
  const reputationLookupScope = [
    identity.host_id,
    identity.runtime,
    identity.project || '',
    identity.container_name,
    diagnosticSnapshotId,
  ].join(':');

  React.useEffect(() => {
    if (!reputationConfigured || isStale || action?.status !== 'succeeded' || !sample || !diagnosticSnapshotId) return;
    let active = true;
    const checkTopInboundIps = async () => {
      for (const ip of automaticReputationCandidates) {
        const lookupKey = `${reputationLookupScope}:${ip}`;
        if (reputationLookupsStarted.current.has(lookupKey)) continue;
        reputationLookupsStarted.current.add(lookupKey);
        await checkReputation(ip);
        if (!active) return;
      }
    };
    void checkTopInboundIps();
    return () => { active = false; };
  }, [action?.status, automaticReputationCandidates, checkReputation, diagnosticSnapshotId, isStale, reputationConfigured, reputationLookupScope, sample]);
  const attribution = sample?.connection_attribution;
  const connectionSockets = sample?.communication_sockets || [];
  const inboundPortEvidence = sample?.inbound_port_evidence || [];
  const originEvidenceLabels: Record<string, string> = {
    confirmed_syn_recv: 'TCP SYN-RECV：远端发起握手',
    confirmed_syn_sent: 'TCP SYN-SENT：本地发起握手',
    probable_local_listener_match: '本地监听端口匹配（推定）',
    confirmed_conntrack_original_initiator: 'conntrack 原始五元组：本地发起',
    confirmed_conntrack_reply_acceptor: 'conntrack 回包五元组：外部发起',
    confirmed_host_conntrack_original_tuple: '宿主机 conntrack 原始方向 / NAT 还原',
    ambiguous_conntrack_tuple_match: 'conntrack 方向证据冲突',
    probable_established_non_listener: '已建立且本地端口非监听端口（推定）',
    probable_connected_udp_listener_match: 'UDP 本地监听端口匹配（推定）',
    probable_connected_udp_non_listener: 'UDP 本地端口非监听端口（推定）',
    host_conntrack_original_tuple: '宿主机 conntrack 原始方向：外部远端发起',
    socket_direction_snapshot: '节点 socket 快照',
  };

  const getConnectionOrigin = (socket: NonNullable<typeof connectionSockets>[number]) => {
    const confidence = socket.origin_confidence || 'unknown';
    if (confidence === 'mixed') return { label: '方向证据冲突', className: 'border-rose-500/30 bg-rose-950/30 text-rose-200' };
    if (socket.direction === 'outbound') {
      return confidence === 'confirmed'
        ? { label: '本地进程发起 · 已确认', className: 'border-sky-500/30 bg-sky-950/30 text-sky-200' }
        : confidence === 'probable'
          ? { label: '本地进程发起 · 推定', className: 'border-amber-500/30 bg-amber-950/30 text-amber-200' }
          : { label: '本机出站 · 发起方待核实', className: 'border-slate-700 bg-slate-900 text-slate-300' };
    }
    if (socket.direction === 'inbound') {
      return confidence === 'confirmed'
        ? { label: '外部发起 · 已确认', className: 'border-emerald-500/30 bg-emerald-950/30 text-emerald-200' }
        : confidence === 'probable'
          ? { label: '外部发起 · 推定', className: 'border-amber-500/30 bg-amber-950/30 text-amber-200' }
          : { label: '外部入站 · 发起方待核实', className: 'border-slate-700 bg-slate-900 text-slate-300' };
    }
    return { label: '发起方未知', className: 'border-slate-700 bg-slate-900 text-slate-300' };
  };

  const renderIpGroup = (title: string, description: string, ips: typeof inboundIps, direction: 'inbound' | 'outbound' | 'unknown') => (
    <div>
      <h4 className="text-xs font-bold text-slate-200 mb-1 flex items-center gap-1.5">
        <Globe className={`h-3.5 w-3.5 ${direction === 'inbound' ? 'text-emerald-400' : direction === 'outbound' ? 'text-sky-400' : 'text-amber-400'}`} />
        <span>{title} ({ips.length})</span>
      </h4>
      <p className="mb-2 text-[11px] text-slate-500">{description}</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto font-mono text-xs">
        {ips.map((ip, idx) => {
          const evidence = direction === 'inbound' ? ip.network_evidence : undefined;
          const reputation = direction === 'inbound' ? reputationByIp[ip.ip || ''] : undefined;
          const originConfidence = direction === 'inbound'
            ? ip.inbound_origin_confidence
            : direction === 'outbound' ? ip.outbound_origin_confidence : 'unknown';
          const directionEvidence = direction === 'inbound'
            ? ip.inbound_direction_evidence
            : direction === 'outbound' ? ip.outbound_direction_evidence : [];
          const directionalProcesses = direction === 'inbound'
            ? ip.inbound_processes
            : direction === 'outbound' ? ip.outbound_processes : [];
          const originJudgment = direction === 'inbound'
            ? originConfidence === 'confirmed'
              ? '已确认是外部远端发起、容器服务接受。下方进程是服务端接受进程，不是访问该 IP 的发起进程。'
              : originConfidence === 'mixed'
                ? '方向证据不一致，暂不归因；请以单条连接详情和下一次采样复核。'
                : originConfidence === 'probable'
                ? '更像是外部远端连接到容器服务；但监听端口/已建立状态不能单独证明原始发起方，请优先参考 conntrack 五元组。'
                : '这是入站连接；旧版或不完整快照未保存足够的方向证据，请重新采样核实。'
            : direction === 'outbound'
              ? originConfidence === 'confirmed'
                ? '已确认由容器内本地进程发起（TCP 握手或 conntrack 五元组确认本端是原始发起方）。'
                : originConfidence === 'mixed'
                  ? '方向证据不一致，暂不归因；请以单条连接详情和下一次采样复核。'
                  : originConfidence === 'probable'
                  ? '较可能由容器内本地进程发起。已建立连接的快照看不到最初握手；这是方向推定，不是绝对证明。'
                  : '当前快照无法确认连接发起方。'
              : '采样没有足够证据确定连接方向；不要据此归因给客户或自动判定恶意。';
          const originTone = originConfidence === 'confirmed'
            ? direction === 'inbound' ? 'border-emerald-500/30 bg-emerald-950/30 text-emerald-200' : 'border-sky-500/30 bg-sky-950/30 text-sky-200'
            : originConfidence === 'mixed'
              ? 'border-rose-500/30 bg-rose-950/30 text-rose-200'
            : 'border-amber-500/30 bg-amber-950/30 text-amber-200';
          const evidenceLabels: Record<string, { label: string; className: string; detail: string }> = {
            possible_multiport_probe: { label: '疑似多端口探测线索', className: 'border-amber-500/30 bg-amber-950/30 text-amber-200', detail: '同一来源访问多个端口，且未完成或未见回包的 TCP 流较多；这是单次快照线索，不等于确认攻击。' },
            bidirectional_tcp_observed: { label: '观察到 TCP 双向通信', className: 'border-emerald-500/30 bg-emerald-950/30 text-emerald-200', detail: '服务端也观察到回包，说明连接有双向通信；不能据此确认用户身份或请求目的。' },
            mixed_connection_evidence: { label: '双向连接与未回复请求并存', className: 'border-sky-500/30 bg-sky-950/30 text-sky-200', detail: '同一来源既有双向通信，也有未见回包的流；可能包含正常访问和失败/探测请求。' },
            unreplied_tcp_observed: { label: '存在未完成的 TCP 连接', className: 'border-amber-500/30 bg-amber-950/30 text-amber-200', detail: '可能是扫描、被拒绝的连接或网络丢包；单凭此项无法判定恶意。' },
            insufficient_transport_evidence: { label: '传输层证据不足', className: 'border-slate-700 bg-slate-900 text-slate-300', detail: '当前快照不能区分正常访问与探测。' },
          };
          const evidenceView = evidenceLabels[evidence?.classification || ''];
          const repLabel = reputation?.status === 'checked'
            ? reputation.classification === 'many_recent_reports' ? `近期公开举报较多 · ${reputation.abuse_confidence_score}/100`
              : reputation.classification === 'reported' ? `有近期公开举报 · ${reputation.abuse_confidence_score}/100`
                : reputation.classification === 'few_reports' ? `少量近期公开举报 · ${reputation.abuse_confidence_score}/100`
                  : '过去 90 天无公开举报（不代表安全）'
            : reputation?.message;
          const repTone = reputation?.status !== 'checked'
            ? 'border-slate-700 bg-slate-900 text-slate-300'
            : (reputation.abuse_confidence_score || 0) >= 75
              ? 'border-rose-500/30 bg-rose-950/30 text-rose-200'
              : (reputation.abuse_confidence_score || 0) > 0
                ? 'border-amber-500/30 bg-amber-950/30 text-amber-200'
                : 'border-slate-700 bg-slate-900 text-slate-300';
          return (
          <div key={`${direction}-${ip.ip}-${idx}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
            <div className="flex items-center justify-between gap-2 font-bold text-slate-200">
              <span className="break-all">{ip.ip}</span>
              <span className="shrink-0 text-slate-400">{direction === 'inbound' ? ip.inbound : direction === 'outbound' ? ip.outbound : ip.unknown} conns</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {[ip.country || 'UN', ip.region, ip.city].filter(Boolean).join(' · ')}
            </div>
            <div className="mt-0.5 break-words text-[11px] text-slate-500">
              运营商：{ip.isp || '暂未识别'}{ip.asn ? ` · AS${ip.asn}` : ''}
            </div>
            <div className={`mt-2 rounded-md border px-2 py-1.5 text-[11px] ${originTone}`}>
              <strong>{direction === 'inbound' ? originConfidence === 'mixed' ? '发起方：证据冲突' : '发起方：外部远端' : direction === 'outbound' ? originConfidence === 'confirmed' ? '发起方：本地进程（已确认）' : originConfidence === 'mixed' ? '发起方：证据冲突' : originConfidence === 'probable' ? '发起方：较可能是本地进程' : '发起方：方向证据不足' : '发起方：待确认'}</strong>
              <p className="mt-0.5 leading-4 opacity-90">{originJudgment}</p>
              {directionEvidence && directionEvidence.length > 0 && <p className="mt-1 leading-4 opacity-80">证据：{directionEvidence.map((value) => originEvidenceLabels[value] || value).join('；')}</p>}
              {directionalProcesses && directionalProcesses.length > 0 && <p className="mt-1 leading-4 opacity-80">进程归属：{directionalProcesses.map((item) => `${item.process || 'unknown'}${item.pid ? ` (PID ${item.pid})` : ''}`).join('、')}</p>}
            </div>
            {direction !== 'unknown' && <div className="mt-1 break-words text-[11px] text-slate-400">
              <strong>{direction === 'inbound' ? '服务端接受进程：' : '本地发起进程：'}</strong>
              {directionalProcesses && directionalProcesses.length > 0
                ? directionalProcesses.map((item) => `${item.process || 'unknown'}${item.pid ? ` (PID ${item.pid})` : ''}`).join('、')
                : ip.processes?.length
                  ? `旧版快照仅有关联列表，未按方向区分：${ip.processes.join('、')}`
                  : '进程 / PID 归属本次未取得'}
            </div>}
            {direction === 'inbound' && <div className="mt-2 space-y-1.5 border-t border-slate-800 pt-2">
              {evidenceView ? <div className={`rounded-md border px-2 py-1.5 text-[11px] ${evidenceView.className}`}>
                <strong>{evidenceView.label}</strong>
                <p className="mt-0.5 leading-4 opacity-90">{evidenceView.detail}</p>
                <p className="mt-1 text-[10px] opacity-80">TCP 已建立 {evidence?.tcp_established_flows || 0} 条 · 未见回包 {evidence?.tcp_unreplied_flows || 0} 条 · 握手待完成 {evidence?.tcp_handshake_pending_flows || 0} 条 · 回包 {evidence?.reply_packets || 0} · 目标端口 {(evidence?.public_ports || []).join(', ') || '未识别'}</p>
                <p className="mt-1 text-[10px] opacity-80">证据：{(evidence?.evidence_sources || []).join('、') || 'conntrack 状态快照'} · 范围：{evidence?.scope || '单次快照'}</p>
              </div> : <p className="text-[11px] text-slate-500">没有关联到 conntrack 状态快照；来源 IP 数量本身不能证明扫描或客户操作。</p>}
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" disabled={!reputationConfigured || checkingReputation !== null} onClick={() => checkReputation(ip.ip || '')} className="min-h-11 rounded-md border border-sky-700/60 bg-sky-950/30 px-3 py-2 text-[11px] font-semibold text-sky-200 hover:bg-sky-900/50 disabled:cursor-not-allowed disabled:opacity-50">
                  {checkingReputation === ip.ip ? '查询中…' : reputationConfigured ? '查询 AbuseIPDB' : '先配置 AbuseIPDB Key'}
                </button>
                {reputation && <span className="text-[10px] text-slate-500">{reputation.cached ? '缓存结果' : reputation.checked_at ? new Date(reputation.checked_at * 1000).toLocaleString('zh-CN', { hour12: false }) : ''}</span>}
              </div>
              {reputation && <div className={`rounded-md border px-2 py-1.5 text-[11px] ${repTone}`}>
                <strong>{repLabel}</strong>
                {reputation.status === 'checked' && <p className="mt-0.5 leading-4 opacity-90">公开举报 {reputation.total_reports || 0} 次 · 最近举报 {reputation.last_reported_at || '无'}{reputation.usage_type ? ` · 网络类型 ${reputation.usage_type}` : ''}</p>}
                <p className="mt-0.5 leading-4 opacity-80">{reputation.status === 'checked' ? reputation.message : '查询失败、未配置或额度不足均不代表该 IP 安全或恶意。'}</p>
              </div>}
            </div>}
          </div>
          );
        })}
        {ips.length === 0 && <div className="text-[11px] text-slate-500">采样瞬间未发现可见的公网 IP。</div>}
      </div>
    </div>
  );

  return (
    <div className="rounded-xl border border-sky-500/30 bg-gradient-to-br from-slate-900 via-slate-900/90 to-sky-950/30 p-4 shadow-sm">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-sky-400" />
            <h3 className="text-sm font-bold text-slate-100">按需深度快照分析</h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            一次性有界快照（不持续抓包、不全盘扫描）；配置 AbuseIPDB 后，完成时自动查询入站连接数最多的 5 个公网 IP。
          </p>
        </div>

        <button
          type="button"
          disabled={submitting || isQueuedOrDispatched || !isSupportedRuntime || isStale}
          onClick={handleRequest}
          className="flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 transition-all disabled:opacity-50 shadow-sm shrink-0"
        >
          <Sparkles className="h-3.5 w-3.5" />
          <span>
            {submitting
              ? '提交中...'
              : isQueuedOrDispatched
              ? '等待上报中'
              : isStale
              ? '采样已过期'
              : '请求深度上报'}
          </span>
        </button>
      </div>

      {/* State Status Banner */}
      <div className="my-3">
        {!isSupportedRuntime ? (
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/40 p-2.5 text-xs text-amber-300">
            Docker 默认仅提醒，当前节点不支持深度快照采集。
          </div>
        ) : isStale ? (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-950/40 p-2.5 text-xs text-amber-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>该容器的监控采样已过期，无法向 Agent 下发任务。请确认容器仍在运行并恢复监控后重试。</span>
          </div>
        ) : action?.status === 'queued' ? (
          <div className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-950/40 p-2.5 text-xs text-sky-300">
            <Clock className="h-4 w-4 animate-spin text-sky-400" />
            <span>任务 #{action.id} 已排队，等待节点守护进程领取（通常 10 秒内）...</span>
          </div>
        ) : action?.status === 'dispatched' ? (
          <div className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-950/40 p-2.5 text-xs text-sky-300">
            <Clock className="h-4 w-4 animate-spin text-sky-400" />
            <span>任务 #{action.id} 已由节点领取，正在等待指标返回...</span>
          </div>
        ) : action?.status === 'succeeded' ? (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/40 p-2.5 text-xs text-emerald-300">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span>深度采样完成 · {action.updated_at_utc8 || '最新'}</span>
          </div>
        ) : action?.status === 'failed' ? (
          <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-950/40 p-2.5 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 text-rose-400" />
            <span>采样失败：{action.result_message || '节点未返回报告'}</span>
          </div>
        ) : (
          <div className="text-xs text-slate-500">尚未请求深度上报快照。</div>
        )}
      </div>

      {/* Snapshot Data View */}
      {sample && (
        <div className="space-y-4 pt-2">
          {reputationSettingsLoaded && <div aria-live="polite" className={`rounded-lg border p-2.5 text-xs leading-5 ${reputationConfigured ? 'border-sky-500/25 bg-sky-950/20 text-sky-200' : 'border-amber-500/30 bg-amber-950/30 text-amber-200'}`}>
            {reputationConfigured
              ? `AbuseIPDB 已启用：自动查询最多 5 个入站公网 IP，结果缓存 24 小时；每日查询保护上限 900 次。信誉分只作提醒，不会自动封禁。${checkingReputation ? ` 正在查询 ${checkingReputation}…` : ''}`
              : 'AbuseIPDB 尚未配置 API Key；请到“系统设置 → 入站 IP 信誉查询”加密保存后，深度快照才会自动检查前 5 个入站公网 IP。'}
          </div>}
          {highlyReportedInboundIps.length > 0 && <div role="alert" className="rounded-lg border border-red-500/40 bg-red-950/30 p-3 text-xs leading-5 text-red-200">
            <strong>AbuseIPDB 高举报信号：{highlyReportedInboundIps.length} 个来源</strong>
            <span className="ml-1 inline-flex flex-wrap gap-1.5">
              {highlyReportedInboundIps.map((ip) => <span key={ip.ip} className="inline-flex items-center gap-1 rounded border border-red-500/30 bg-red-950/50 px-1.5 py-0.5">
                <span className="font-mono">{ip.ip}</span>
                <span className="tabular-nums">{reputationByIp[ip.ip || '']?.abuse_confidence_score || 0}/100</span>
              </span>)}
            </span>
            <p className="mt-1 text-red-200/80">这是第三方社区举报信誉，不足以证明本次连接是攻击或归责客户；请结合本页连接方向、进程和 conntrack 证据人工判断。</p>
          </div>}
          {/* Rate Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">瞬时 RX 带宽</span>
              <span className="text-emerald-400 font-bold text-sm">
                {fmtMbps(sample.network_rates?.rx_bps)} Mbps
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">瞬时 TX 带宽</span>
              <span className="text-sky-400 font-bold text-sm">
                {fmtMbps(sample.network_rates?.tx_bps)} Mbps
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">连接 IP 数</span>
              <span className="text-slate-200 font-bold text-sm">
                {sample.unique_connection_ips || 0} IPs
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">进程数量</span>
              <span className="text-slate-200 font-bold text-sm">
                {sample.process_count || 0} Procs
              </span>
            </div>
          </div>

          {attribution && (
            <div className="rounded-lg border border-sky-500/25 bg-sky-950/20 p-3 text-xs">
              <div className="font-semibold text-sky-200">连接发起方深度核验</div>
              <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4 tabular-nums">
                <div className="rounded-md bg-slate-950/60 p-2"><span className="block text-[10px] text-slate-500">本地发起 · 已确认</span><strong className="text-sky-300">{attribution.confirmed_local_initiated || 0}</strong></div>
                <div className="rounded-md bg-slate-950/60 p-2"><span className="block text-[10px] text-slate-500">本地发起 · 推定</span><strong className="text-amber-300">{attribution.probable_local_initiated || 0}</strong></div>
                <div className="rounded-md bg-slate-950/60 p-2"><span className="block text-[10px] text-slate-500">外部发起 · 已确认</span><strong className="text-emerald-300">{attribution.confirmed_remote_initiated || 0}</strong></div>
                <div className="rounded-md bg-slate-950/60 p-2"><span className="block text-[10px] text-slate-500">方向未知</span><strong className="text-slate-300">{attribution.unknown_direction || 0}</strong></div>
              </div>
              <p className="mt-2 leading-4 text-slate-400">
                已归属进程/PID {attribution.process_attributed_sockets || 0}/{attribution.captured_sockets || 0} 条；conntrack 五元组确认 {attribution.conntrack_confirmed_sockets || 0} 条。
                {!attribution.conntrack_available && ' 当前节点未提供 conntrack，已确认数可能较少。'}
                {(attribution.conntrack_snapshot_truncated || attribution.socket_snapshot_truncated) && ' 快照达到采集上限，结果不是全量。'}
              </p>
            </div>
          )}

          {connectionSockets.length > 0 && (
            <details className="overflow-hidden rounded-lg border border-slate-700 bg-slate-950/50">
              <summary className="cursor-pointer list-none px-3 py-2.5 text-xs font-semibold text-slate-200 hover:bg-slate-900/70">
                逐条连接证据（{connectionSockets.length} 条{connectionSockets.length > 100 ? '，最多展示前 100 条' : ''}）
                <span className="ml-2 font-normal text-slate-500">展开核对端点、状态、进程与发起方向</span>
              </summary>
              <div className="max-h-96 space-y-2 overflow-y-auto border-t border-slate-800 p-2">
                {connectionSockets.slice(0, 100).map((socket, index) => {
                  const origin = getConnectionOrigin(socket);
                  const evidence = socket.direction_evidence
                    ? originEvidenceLabels[socket.direction_evidence] || socket.direction_evidence
                    : '没有方向证据';
                  return (
                    <article key={`${socket.proto || 'unknown'}-${socket.local || ''}-${socket.remote || ''}-${index}`} className="min-w-0 rounded-md border border-slate-800 bg-slate-900/70 p-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${origin.className}`}>{origin.label}</span>
                        <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300">{String(socket.proto || 'unknown').toUpperCase()}</span>
                        <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">{socket.state || '状态未知'}</span>
                      </div>
                      <div className="mt-1.5 break-all font-mono text-[11px] text-slate-200">{socket.local || '-'} → {socket.remote || '-'}</div>
                      <div className="mt-1 break-words text-[11px] text-slate-400">
                        进程：{socket.process || 'unknown'}{Number(socket.pid || 0) > 0 ? ` · PID ${socket.pid}` : ' · PID 未取得'}
                        {socket.process_role === 'initiator' ? ' · 角色：发起方' : socket.process_role === 'acceptor' ? ' · 角色：接受连接的服务端' : ''}
                      </div>
                      <div className="mt-1 break-words text-[10px] text-slate-500">判定依据：{evidence}</div>
                      {Array.isArray(socket.original_remote_ips) && socket.original_remote_ips.length > 0 && (
                        <div className="mt-1 break-all text-[10px] text-emerald-300">conntrack 五元组还原来源：{socket.original_remote_ips.join(', ')}</div>
                      )}
                    </article>
                  );
                })}
              </div>
              <p className="border-t border-slate-800 px-3 py-2 text-[10px] leading-4 text-slate-500">
                “PID/进程归属”只说明哪个进程持有该 socket；发起方向以握手状态或 conntrack 五元组为准。没有这些强证据时只标推定/未知，不据此判定恶意。
              </p>
            </details>
          )}

          {/* Detailed Processes Table */}
          {sample.processes?.items && sample.processes.items.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-sky-400" />
                <span>快照进程列表 ({sample.processes.items.length})</span>
              </h4>
              <div className="max-h-48 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/60 divide-y divide-slate-800/60 font-mono text-xs">
                {sample.processes.items.map((p, idx) => (
                  <div key={idx} className="p-2.5 hover:bg-slate-900/60 transition-colors">
                    <div className="flex items-center justify-between text-slate-200 font-semibold">
                      <span>{p.process || 'unknown'} · PID {p.pid}</span>
                      <span className="text-sky-400">
                        CPU {fmtNumber(p.cpu_percent)}% · RSS {fmtBytes(p.rss_bytes)}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-1">
                      {p.command || '-'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {renderIpGroup('接入容器的公网来源', '展示远端来源及本地接受进程；服务端进程不等于连接发起方。', inboundIps, 'inbound')}
          {inboundPortEvidence.length > 0 && (
            <section className="rounded-lg border border-slate-700 bg-slate-950/50 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-xs font-bold text-slate-200">NAT / 代理端口级来源关联 ({inboundPortEvidence.length})</h4>
                <span className="rounded border border-amber-500/30 bg-amber-950/30 px-2 py-1 text-[10px] text-amber-200">聚合推定 · 非逐连接确认</span>
              </div>
              <p className="mt-1 text-[11px] leading-4 text-slate-400">
                当 NAT 或用户态代理隐藏了公网来源时，主控按容器目标端口汇总来源 IP 和监听进程。端口上有进程只能说明服务在接收连接，不能把每个 IP 精确绑定到某个已建立 socket，也不能据此判断客户有责。
              </p>
              <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {inboundPortEvidence.slice(0, 20).map((item, index) => (
                  <article key={`${item.container_port || 0}-${index}`} className="min-w-0 rounded-md border border-slate-800 bg-slate-900/70 p-2.5 text-[11px]">
                    <div className="font-semibold text-slate-200">容器端口 {item.container_port || '-'} · {item.connections || 0} 条聚合连接</div>
                    <div className="mt-1 break-all text-slate-400">来源 IP ({item.source_ip_count || 0})：{(item.source_ips || []).join('、') || '-'}</div>
                    <div className="mt-1 break-words text-slate-500">监听进程：{(item.process_listeners || []).map(listener => `${listener.process || 'unknown'}${listener.pid ? ` (PID ${listener.pid})` : ''}`).join('、') || '未取得'}</div>
                  </article>
                ))}
              </div>
            </section>
          )}
          {renderIpGroup('容器访问的公网目标', '展示本地进程与连接方向证据；仅看到已建立连接时会标为“较可能”，不会冒充握手级确认。', outboundIps, 'outbound')}
          {unclassifiedIps.length > 0 && renderIpGroup('方向待确认的公网连接', '采样证据不足以判断哪一端先发起；保留单独展示，避免误归因。', unclassifiedIps, 'unknown')}
        </div>
      )}
    </div>
  );
};
