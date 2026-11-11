import React, { useState } from 'react';
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ChevronRight,
  Copy,
  Check,
  Gauge,
  Network,
  ShieldAlert,
  Terminal,
} from 'lucide-react';
import {
  SocketAbuseAssessment,
  SocketAbuseDimension,
  SocketAbuseIpDetail,
  SocketAbuseInvestigation,
  SocketAbuseProcessCommand,
  SocketAbuseScenario,
} from '../../api/types';

interface SocketAbuseEvidenceProps {
  alert?: Record<string, any> | null;
  assessment?: SocketAbuseAssessment | null;
  compact?: boolean;
}

export const extractSocketAbuseAssessment = (
  alert?: Record<string, any> | null,
  direct?: SocketAbuseAssessment | null,
): SocketAbuseAssessment | null => {
  const candidate =
    direct ||
    alert?.socket_abuse ||
    alert?.details?.socket_abuse ||
    alert?.observation?.socket_abuse ||
    alert?.details?.observation?.socket_abuse;
  if (!candidate || typeof candidate !== 'object') return null;
  if (!Array.isArray(candidate.dimensions) || candidate.dimensions.length === 0) return null;
  return candidate as SocketAbuseAssessment;
};

const riskBadgeMeta = (risk?: string) => {
  if (risk === 'high') {
    return {
      label: '高风险线索',
      badge: 'border-rose-500/40 bg-rose-950/70 text-rose-200',
      box: 'border-rose-500/30 bg-rose-950/20',
      header: 'text-rose-300',
      bar: 'bg-rose-500',
    };
  }
  if (risk === 'medium') {
    return {
      label: '重点核实',
      badge: 'border-amber-500/40 bg-amber-950/70 text-amber-200',
      box: 'border-amber-500/30 bg-amber-950/15',
      header: 'text-amber-300',
      bar: 'bg-amber-400',
    };
  }
  return {
    label: '正常特征',
    badge: 'border-emerald-500/35 bg-emerald-950/60 text-emerald-200',
    box: 'border-slate-800/90 bg-slate-900/65',
    header: 'text-emerald-300',
    bar: 'bg-emerald-500',
  };
};

const scenarioMeta = (likelihood?: string) => {
  if (likelihood === 'high') {
    return {
      label: '高可能',
      fullLabel: '高可能性',
      badge: 'border-amber-500/45 bg-amber-950/70 text-amber-200',
      pill: 'border-amber-500/40 bg-amber-950/45 text-amber-100',
      dot: 'bg-amber-400',
      bar: 'bg-amber-400',
    };
  }
  if (likelihood === 'medium') {
    return {
      label: '中等',
      fullLabel: '中等可能',
      badge: 'border-sky-500/40 bg-sky-950/70 text-sky-200',
      pill: 'border-sky-500/35 bg-sky-950/40 text-sky-100',
      dot: 'bg-sky-400',
      bar: 'bg-sky-400',
    };
  }
  return {
    label: '较低',
    fullLabel: '可能性较低',
    badge: 'border-slate-700/80 bg-slate-900/80 text-slate-400',
    pill: 'border-slate-800 bg-slate-900/60 text-slate-400',
    dot: 'bg-slate-600',
    bar: 'bg-slate-600',
  };
};

const shortDimTitle = (key?: string, fallback?: string) => {
  if (key === 'state_breakdown') return '1. 连接状态拆解';
  if (key === 'inbound_fanout') return '2. 入站并发业务源';
  if (key === 'outbound_profile') return '3. 出站目标与进程';
  if (key === 'traffic_profile') return '4. 包速率与带宽';
  return fallback || '维度指标';
};

export const SocketAbuseEvidence: React.FC<SocketAbuseEvidenceProps> = ({
  alert,
  assessment,
  compact = false,
}) => {
  const [copiedPid, setCopiedPid] = useState<number | null>(null);

  const data = extractSocketAbuseAssessment(alert, assessment);
  if (!data) return null;

  const isSuspected = Boolean(data.suspected || data.verdict === 'suspected_abuse');
  const isBenignHigh = data.verdict === 'benign_high_sockets';
  const categories = Array.isArray(data.categories) ? data.categories : [];
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const inv: SocketAbuseInvestigation | undefined = data.investigation;

  const headerStyle = isSuspected
    ? 'border-amber-500/35 bg-slate-950/75'
    : isBenignHigh
    ? 'border-emerald-500/30 bg-slate-950/75'
    : 'border-slate-800 bg-slate-950/75';

  const verdictBadgeStyle = isSuspected
    ? 'border-rose-500/50 bg-rose-950/80 text-rose-200'
    : isBenignHigh
    ? 'border-emerald-500/40 bg-emerald-950/80 text-emerald-200'
    : 'border-cyan-500/40 bg-cyan-950/70 text-cyan-200';

  const dimMap: Record<string, SocketAbuseDimension> = {};
  for (const d of dimensions) {
    if (d?.key) dimMap[d.key] = d;
  }

  // 前端兼容回退合成：即使节点 Agent 仍在 v1.8.15 尚未生成 investigation，也根据已有维度指标即时合成场景评估
  const effectiveInv: SocketAbuseInvestigation = inv || (() => {
    const d2m = dimMap['inbound_fanout']?.metrics || {};
    const d3m = dimMap['outbound_profile']?.metrics || {};
    const inEstablished = Number(d2m.incoming_established || 0);
    const outEstablished = Number(d3m.outbound_established || 0);
    const inIps = Number(d2m.inbound_established_unique_ips || 0);
    const outIps = Number(d3m.outbound_unique_ips || 0);
    const socksDetected = Boolean(d2m.socks_detected);
    const socksAuth = String(d2m.socks_auth_mode || 'unknown');
    const details: SocketAbuseIpDetail[] = Array.isArray(d2m.top_ip_details) ? d2m.top_ip_details : [];

    let relayCount = 0;
    const netGroups: Record<string, { label: string; ips: number; conns: number }> = {};
    for (const item of details) {
      const isp = String(item.isp || '').toLowerCase();
      const ip = String(item.ip || '');
      const isRelay = item.network_kind === 'relay' || ip.startsWith('104.28.') || isp.includes('cloudflare');
      if (isRelay) relayCount++;
      const groupKey = isRelay ? 'Cloudflare WARP / 中继网络' : (item.network_label || item.isp || item.country_name || '其他网络');
      const g = netGroups[groupKey] || { label: groupKey, ips: 0, conns: 0 };
      g.ips += 1;
      g.conns += Number(item.established_connections || 0);
      netGroups[groupKey] = g;
    }
    const estimatedSources = Math.max(1, Object.keys(netGroups).length);
    const relayShare = details.length > 0 ? relayCount / details.length : 0;
    const pairMax = Math.max(inEstablished, outEstablished, 1);
    const proxySymmetry = (inEstablished > 0 && outEstablished > 0) ? Math.min(inEstablished, outEstablished) / pairMax : 0;
    const proxyLike = socksDetected || (inEstablished >= 10 && outEstablished >= 10 && proxySymmetry >= 0.6);

    const scenarios: SocketAbuseScenario[] = [
      {
        key: 'personal_relay_proxy',
        label: '个人自用代理（含 WARP/中继二级代理）',
        likelihood: (proxyLike && (relayShare >= 0.5 || estimatedSources <= 2)) ? 'high' : 'medium',
        basis: `${relayCount}/${details.length || inIps} 个来源 IP 属中继网络，估算独立网络约 ${estimatedSources} 个，出站以 HTTPS 访问为主。`,
      },
      {
        key: 'multi_device_sharing',
        label: '多设备共用 / 小规模共享',
        likelihood: (estimatedSources >= 4 || (inIps >= 6 && relayShare < 0.5)) ? 'medium' : 'low',
        basis: `已建连来源 ${inIps} 个 IP、估算独立网络 ${estimatedSources} 个，入站活跃 ${inEstablished} 条。`,
      },
      {
        key: 'commercial_proxy_exit',
        label: '商业共享 / 机场出口',
        likelihood: (estimatedSources >= 8 && inEstablished >= 120) ? 'high' : (estimatedSources >= 5 && inEstablished >= 60) ? 'medium' : 'low',
        basis: `独立网络 ${estimatedSources} 个，入站活跃 ${inEstablished} 条，未达大规模商业机场量级。`,
      },
      {
        key: 'automation_relay',
        label: '自动化程序 / 爬虫中转',
        likelihood: (outIps >= 80 && estimatedSources <= 2) ? 'medium' : 'low',
        basis: `出站外部目标 ${outIps} 个 IP，当前未见明显扫描或异常爬虫特征。`,
      },
    ];

    const notes = [
      relayCount > 0 ? `${relayCount} 个公网来源属于 Cloudflare/中继网络；同一用户经 WARP 多出口重连会产生多个 IP，不能直接认定为多人共用。` : '',
      proxyLike && proxySymmetry > 0 ? `入站 ${inEstablished} 条与出站 ${outEstablished} 条高度对称 (对称度 ${Math.round(proxySymmetry * 100)}%)，符合典型代理转发特征。` : '',
      socksDetected && socksAuth === 'unknown' ? 'SOCKS5 认证模式显示为 unknown 表示尚未读取配置或使用非标认证，不能当成无密码开放代理。' : '',
      '连接特征仅作为运维观察参考，未通过应用日志还原，不作为处罚依据。',
    ].filter(Boolean);

    return {
      proxy_like: proxyLike,
      proxy_symmetry: proxySymmetry,
      relay_ips: relayCount,
      estimated_independent_sources: { low: estimatedSources, high: inIps },
      source_networks: Object.values(netGroups).map((g) => ({
        label: g.label,
        kind: 'relay',
        ips: g.ips,
        established_connections: g.conns,
      })),
      scenarios,
      notes,
    };
  })();

  const dim1 = dimMap['state_breakdown'];
  const dim2 = dimMap['inbound_fanout'];
  const dim3 = dimMap['outbound_profile'];
  const dim4 = dimMap['traffic_profile'];

  const m1 = dim1?.metrics || {};
  const m2 = dim2?.metrics || {};
  const m3 = dim3?.metrics || {};
  const m4 = dim4?.metrics || {};

  const totalSockets = Number(m1.total || 0);
  const established = Number(m1.tcp_established || 0);
  const timeWait = Number(m1.tcp_time_wait || 0);
  const synSent = Number(m1.tcp_syn_sent || 0);
  const synRecv = Number(m1.tcp_syn_recv || 0);
  const udpSockets = Number(m1.udp_sockets || 0);
  const incomingEst = Number(m2.incoming_established || 0);
  const outboundEst = Number(m3.outbound_established || 0);
  const inIpsCount = Number(m2.inbound_established_unique_ips || 0);
  const outIpsCount = Number(m3.outbound_unique_ips || 0);
  const outPortsCount = Number(m3.outbound_unique_ports || 0);
  const suspiciousOut = Number(m3.suspicious_outbound_connections || 0);
  const txPps = Math.round(Number(m4.tx_pps || 0));
  const rxPps = Math.round(Number(m4.rx_pps || 0));
  const avgPkt = Math.round(Number(m4.avg_tx_packet_size || 0));

  const denom = Math.max(totalSockets, established + timeWait + synSent + synRecv + udpSockets, 1);
  const estPct = Math.round((established / denom) * 100);
  const twPct = Math.round((timeWait / denom) * 100);
  const synSentPct = Math.round((synSent / denom) * 100);
  const otherPct = Math.max(0, 100 - estPct - twPct - synSentPct);

  const inboundIpDetails: SocketAbuseIpDetail[] = Array.isArray(m2.top_ip_details) ? m2.top_ip_details : [];
  const outboundIpDetails: SocketAbuseIpDetail[] = Array.isArray(m3.top_ip_details) ? m3.top_ip_details : [];
  const topProcesses: Array<{ process: string; pid: number; inbound_connections?: number; outbound_connections?: number }> =
    Array.isArray(m3.top_processes) ? m3.top_processes : [];
  const primaryProc = topProcesses[0];

  // 对 source_networks 按 label 进行去重聚合，避免同一分类（如“接入网 (家宽 / 移动)”）因不同 ASN 重复渲染多遍
  const aggregatedSourceNetworks = (() => {
    const raw = Array.isArray(effectiveInv?.source_networks) ? effectiveInv.source_networks : [];
    const map = new Map<string, { label: string; ips: number; conns: number; asns: string[] }>();
    for (const item of raw) {
      const key = item.label || item.isp || item.asn || '未知网络';
      const existing = map.get(key) || { label: key, ips: 0, conns: 0, asns: [] };
      existing.ips += Number(item.ips || 0);
      existing.conns += Number(item.established_connections || 0);
      if (item.asn && !existing.asns.includes(item.asn) && existing.asns.length < 3) {
        existing.asns.push(item.asn);
      }
      map.set(key, existing);
    }
    return Array.from(map.values()).sort((a, b) => b.ips - a.ips || b.conns - a.conns);
  })();

  const scenarios: SocketAbuseScenario[] = Array.isArray(effectiveInv?.scenarios) ? effectiveInv.scenarios : [];
  const topScenario = scenarios.find((s) => s.likelihood === 'high') || scenarios.find((s) => s.likelihood === 'medium') || scenarios[0];

  const handleCopyCmd = (cmd: string, pid: number) => {
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(cmd);
        setCopiedPid(pid);
        setTimeout(() => setCopiedPid(null), 2000);
      }
    } catch {
      // ignore
    }
  };

  return (
    <div
      data-testid="socket-abuse-evidence"
      className={`mt-2.5 rounded-xl border p-3 text-xs leading-snug ${headerStyle}`}
    >
      {/* 1. 紧凑头部与结论条 */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 font-semibold text-slate-100">
            <Network className="h-3.5 w-3.5 shrink-0 text-sky-400" aria-hidden="true" />
            <span>Socket / 代理连接四维判断依据</span>
          </span>
          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${verdictBadgeStyle}`}>
            {data.verdict_label || (isSuspected ? '疑似滥用 · 待人工复核' : '倾向非滥用')}
          </span>
          {effectiveInv?.proxy_like && (
            <span className="rounded border border-sky-500/35 bg-sky-950/60 px-1.5 py-0.5 font-mono text-[10px] text-sky-200 tabular-nums">
              TCP 代理对称度 {Math.round(Number(effectiveInv.proxy_symmetry || 0) * 100)}%
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
          <span className="rounded border border-slate-800 bg-slate-900/90 px-2 py-0.5 text-slate-300">
            人工复核 · 未自动停机
          </span>
        </div>
      </div>

      {/* 结论与命中规则（单行紧凑展示） */}
      {(data.conclusion || categories.length > 0) && (
        <div className="mt-1.5 space-y-1">
          {data.conclusion && (
            <p className="text-[11px] text-slate-300 tabular-nums">{data.conclusion}</p>
          )}
          {categories.map((cat) => (
            <div
              key={cat.code}
              className="flex items-center gap-1.5 rounded border border-rose-500/35 bg-rose-950/40 px-2.5 py-1 text-[11px] text-rose-100"
            >
              <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-rose-400" aria-hidden="true" />
              <span className="min-w-0 break-words">
                <strong className="font-semibold text-rose-200">命中规则 · {cat.title}：</strong>
                {cat.reason}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* 2. 四维核心指标水平紧凑条（消除垂直堆叠与空白黑洞） */}
      <div className={`mt-2.5 grid gap-2 ${compact ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4'}`}>
        {/* 维度 1：连接状态拆解 */}
        {dim1 && (
          <div className={`flex min-w-0 flex-col justify-between rounded-lg border p-2.5 ${riskBadgeMeta(dim1.risk).box}`}>
            <div className="flex items-center justify-between gap-1.5">
              <span className="truncate text-[11px] font-semibold text-slate-100" title={dim1.title}>
                {shortDimTitle(dim1.key, dim1.title)}
              </span>
              <span className={`shrink-0 rounded border px-1.5 py-0.2 text-[9px] font-medium ${riskBadgeMeta(dim1.risk).badge}`}>
                {riskBadgeMeta(dim1.risk).label}
              </span>
            </div>

            <div className="my-1.5">
              <div className="flex items-baseline justify-between gap-1 font-mono text-[11px] tabular-nums">
                <span className="text-slate-200">
                  总计 <strong className="text-white">{totalSockets}</strong>
                </span>
                <span className="text-[10px] text-cyan-300">
                  EST {established} ({estPct}%) · TW {timeWait} ({twPct}%)
                </span>
              </div>
              <div className="mt-1 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                <div style={{ width: `${estPct}%` }} className="bg-cyan-500" title={`ESTABLISHED ${established} (${estPct}%)`} />
                <div style={{ width: `${twPct}%` }} className="bg-emerald-500" title={`TIME_WAIT ${timeWait} (${twPct}%)`} />
                {synSent > 0 && <div style={{ width: `${synSentPct}%` }} className="bg-rose-500" title={`SYN_SENT ${synSent}`} />}
                {otherPct > 0 && <div style={{ width: `${otherPct}%` }} className="bg-slate-700" title="其他状态" />}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-1 border-t border-slate-800/70 pt-1.5 font-mono text-[10px] text-slate-400 tabular-nums">
              <span>SYN_SENT {synSent} · RECV {synRecv} · UDP {udpSockets}</span>
              <span className="text-sky-300">入{incomingEst}⇄出{outboundEst}</span>
            </div>
          </div>
        )}

        {/* 维度 2：入站并发业务源 */}
        {dim2 && (
          <div className={`flex min-w-0 flex-col justify-between rounded-lg border p-2.5 ${riskBadgeMeta(dim2.risk).box}`}>
            <div className="flex items-center justify-between gap-1.5">
              <span className="truncate text-[11px] font-semibold text-slate-100" title={dim2.title}>
                {shortDimTitle(dim2.key, dim2.title)}
              </span>
              <span className={`shrink-0 rounded border px-1.5 py-0.2 text-[9px] font-medium ${riskBadgeMeta(dim2.risk).badge}`}>
                {riskBadgeMeta(dim2.risk).label}
              </span>
            </div>

            <div className="my-1.5">
              <div className="flex items-baseline justify-between gap-1 font-mono text-[11px] tabular-nums">
                <span className={inIpsCount >= 10 ? 'text-amber-200' : 'text-slate-200'}>
                  真实来源 <strong className={inIpsCount >= 10 ? 'text-amber-300' : 'text-cyan-300'}>{inIpsCount}</strong> IP
                </span>
                <span className="text-[10px] text-slate-300">
                  入站活跃 {incomingEst} 条
                </span>
              </div>
              <div className="mt-1 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                <div
                  style={{ width: `${Math.min(100, Math.max(6, Math.round((inIpsCount / 15) * 100)))}%` }}
                  className={inIpsCount >= 10 ? 'bg-amber-400' : 'bg-cyan-500'}
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-1 border-t border-slate-800/70 pt-1.5 font-mono text-[10px] text-slate-400 tabular-nums">
              <span>未建连探测 {m2.inbound_syn_recv_unique_ips ?? 0} IP</span>
              {effectiveInv?.relay_ips ? (
                <span className="text-amber-300">中继 {effectiveInv.relay_ips} IP</span>
              ) : m2.socks_detected ? (
                <span className="text-rose-300">SOCKS5({m2.socks_auth_mode || 'unknown'})</span>
              ) : (
                <span className="text-slate-300">独立网络 ~{effectiveInv?.estimated_independent_sources?.low ?? 1} 个</span>
              )}
            </div>
          </div>
        )}

        {/* 维度 3：出站目标与进程画像 */}
        {dim3 && (
          <div className={`flex min-w-0 flex-col justify-between rounded-lg border p-2.5 ${riskBadgeMeta(dim3.risk).box}`}>
            <div className="flex items-center justify-between gap-1.5">
              <span className="truncate text-[11px] font-semibold text-slate-100" title={dim3.title}>
                {shortDimTitle(dim3.key, dim3.title)}
              </span>
              <span className={`shrink-0 rounded border px-1.5 py-0.2 text-[9px] font-medium ${riskBadgeMeta(dim3.risk).badge}`}>
                {riskBadgeMeta(dim3.risk).label}
              </span>
            </div>

            <div className="my-1.5">
              <div className="flex items-baseline justify-between gap-1 font-mono text-[11px] tabular-nums">
                <span className="text-slate-200">
                  出站活跃 <strong className="text-white">{outboundEst}</strong>
                </span>
                <span className="text-[10px] text-slate-300">
                  目标 {outIpsCount} IP / {outPortsCount} 端口
                </span>
              </div>
              <div className="mt-1 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                <div
                  style={{ width: `${suspiciousOut > 0 ? Math.min(100, suspiciousOut * 15) : Math.min(100, Math.max(5, Math.round((outIpsCount / 60) * 100)))}%` }}
                  className={suspiciousOut >= 5 ? 'bg-rose-500' : 'bg-emerald-500'}
                />
              </div>
            </div>

            <div className="flex items-center justify-between gap-1 border-t border-slate-800/70 pt-1.5 font-mono text-[10px] text-slate-400 tabular-nums">
              <span className={suspiciousOut >= 5 ? 'text-rose-300 font-semibold' : ''}>
                敏感端口 {suspiciousOut}
              </span>
              {primaryProc ? (
                <span className="min-w-0 truncate text-cyan-300" title={`${primaryProc.process}(PID ${primaryProc.pid}, 入${primaryProc.inbound_connections ?? 0}/出${primaryProc.outbound_connections ?? 0})`}>
                  {primaryProc.process} (PID {primaryProc.pid})
                </span>
              ) : (
                <span>无主进程样本</span>
              )}
            </div>
          </div>
        )}

        {/* 维度 4：包速率与带宽特征 */}
        {dim4 && (
          <div className={`flex min-w-0 flex-col justify-between rounded-lg border p-2.5 ${riskBadgeMeta(dim4.risk).box}`}>
            <div className="flex items-center justify-between gap-1.5">
              <span className="truncate text-[11px] font-semibold text-slate-100" title={dim4.title}>
                {shortDimTitle(dim4.key, dim4.title)}
              </span>
              <span className={`shrink-0 rounded border px-1.5 py-0.2 text-[9px] font-medium ${riskBadgeMeta(dim4.risk).badge}`}>
                {riskBadgeMeta(dim4.risk).label}
              </span>
            </div>

            <div className="my-1.5">
              <div className="flex items-baseline justify-between gap-1 font-mono text-[11px] tabular-nums">
                <span className="text-slate-200">
                  TX <strong className="text-white">{txPps}</strong> · RX <strong className="text-white">{rxPps}</strong> pps
                </span>
                <span className="text-[10px] text-slate-300">
                  均包 {avgPkt} B
                </span>
              </div>
              <div className="mt-1 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-950">
                <div
                  style={{ width: `${Math.min(100, Math.max(6, Math.round((Math.max(txPps, rxPps) / 1500) * 100)))}%` }}
                  className={txPps >= 1500 && avgPkt <= 160 ? 'bg-rose-500' : 'bg-emerald-500'}
                />
              </div>
            </div>

            <div className="flex items-center justify-between gap-1 border-t border-slate-800/70 pt-1.5 font-mono text-[10px] text-slate-400 tabular-nums">
              <span className="truncate text-emerald-300">
                {avgPkt >= 500
                  ? '大包吞吐 (Web/传输)'
                  : txPps >= 1500 && avgPkt <= 160
                  ? '高频小包泛洪特征'
                  : '均衡中等包长 (交互/代理)'}
              </span>
              <span className="shrink-0">
                对称比 {rxPps > 0 ? (txPps / rxPps).toFixed(2) : '0'}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* 3. 运营场景内联评估条（单行药丸化，替代高大四卡片） */}
      {scenarios.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800/90 bg-slate-900/55 px-2.5 py-1.5">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            <span className="shrink-0 text-[10px] font-semibold text-slate-300">
              场景评估：
            </span>
            {scenarios.map((sc) => {
              const meta = scenarioMeta(sc.likelihood);
              return (
                <span
                  key={sc.key}
                  title={`${sc.label}（${meta.fullLabel}）：${sc.basis}`}
                  className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] ${meta.pill}`}
                >
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} aria-hidden="true" />
                  <span className="truncate max-w-[11rem]">{sc.label.replace(/（.*?）/g, '')}</span>
                  <span className="font-mono text-[9px] opacity-85">{meta.label}</span>
                </span>
              );
            })}
          </div>
          {topScenario && (
            <span className="min-w-0 truncate text-[10px] text-slate-400 tabular-nums" title={topScenario.basis}>
              首要倾向：{topScenario.basis}
            </span>
          )}
        </div>
      )}

      {/* 4. 按需折叠明细区（采用原生 <details> 保持 Find-in-page 可检索与键盘无障碍，双列网格消除留白） */}
      <details className="group mt-2 rounded-lg border border-slate-800/80 bg-slate-900/40">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-[11px] select-none transition-colors hover:bg-slate-800/50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-300 [&::-webkit-details-marker]:hidden">
          <span className="inline-flex items-center gap-1.5 font-medium text-sky-300">
            <ChevronRight className="h-3.5 w-3.5 shrink-0 transition-transform duration-150 group-open:rotate-90" aria-hidden="true" />
            <span className="group-open:hidden">展开 IP 与诊断明细</span>
            <span className="hidden group-open:inline">收起明细</span>
          </span>
          <span className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-slate-400 tabular-nums">
            <span>入站样本 {inboundIpDetails.length} IP</span>
            {outboundIpDetails.length > 0 && <span>· 出站样本 {outboundIpDetails.length} IP</span>}
            {aggregatedSourceNetworks.length > 0 && (
              <span className="hidden sm:inline text-slate-300">
                · 网络聚类：{aggregatedSourceNetworks.slice(0, 2).map((g) => `${g.label}(${g.ips}IP)`).join(' / ')}
              </span>
            )}
          </span>
        </summary>

        <div className="space-y-2.5 border-t border-slate-800/80 p-2.5">
          {/* 来源网络去重聚合条 */}
          {aggregatedSourceNetworks.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 rounded border border-slate-800/90 bg-slate-950/70 px-2.5 py-1.5 text-[10px] text-slate-300 tabular-nums">
              <span className="font-semibold text-slate-200">来源网络去重透视：</span>
              {aggregatedSourceNetworks.map((net, i) => (
                <span
                  key={`${net.label}-${i}`}
                  className="rounded border border-slate-800 bg-slate-900/90 px-1.5 py-0.5 font-mono text-slate-200"
                >
                  {net.label} ({net.ips} IP · {net.conns} 活跃{net.asns.length > 0 ? ` · ${net.asns.join('/')}` : ''})
                </span>
              ))}
            </div>
          )}

          {/* 入站并发来源 IP 双列紧凑网格 */}
          {inboundIpDetails.length > 0 && (
            <div>
              <div className="mb-1.5 flex items-center justify-between text-[10px] text-slate-400">
                <span className="inline-flex items-center gap-1 font-semibold text-slate-200">
                  <ArrowDownLeft className="h-3 w-3 text-cyan-400" aria-hidden="true" />
                  <span>入站已建连公网来源明细 (Top {Math.min(inboundIpDetails.length, 8)})</span>
                </span>
                <span className="font-mono tabular-nums">已排除仅 SYN 探测未建连 IP</span>
              </div>
              <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2 font-mono text-[11px] tabular-nums">
                {inboundIpDetails.slice(0, 8).map((item: SocketAbuseIpDetail) => {
                  const fallbackGeo = [
                    item.country_name || (item.country && item.country !== 'UN' ? item.country : ''),
                    item.region || item.city,
                    item.isp,
                    item.asn,
                  ]
                    .filter(Boolean)
                    .join(' · ');
                  const geoText = item.geo_label || fallbackGeo;
                  const portsText = Array.isArray(item.local_ports) && item.local_ports.length > 0
                    ? `→ :${item.local_ports.join('/')}`
                    : '';
                  const isRelay = item.network_kind === 'relay' || (item.isp || '').toLowerCase().includes('cloudflare');
                  return (
                    <div
                      key={item.ip}
                      className="flex min-w-0 items-center justify-between gap-2 rounded border border-slate-800/90 bg-slate-950/85 px-2.5 py-1.5"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-semibold text-sky-300">{item.ip}</span>
                          {item.network_label && (
                            <span
                              className={`rounded px-1 py-0.2 text-[9px] font-sans ${
                                isRelay
                                  ? 'border border-amber-700/50 bg-amber-950/70 text-amber-200'
                                  : 'bg-indigo-950/65 text-indigo-200'
                              }`}
                            >
                              {item.network_label}
                            </span>
                          )}
                        </div>
                        {geoText && (
                          <div className="mt-0.5 truncate font-sans text-[10px] text-slate-400" title={geoText}>
                            {geoText}
                          </div>
                        )}
                      </div>
                      <div className="shrink-0 text-right text-[10px] text-slate-300">
                        <div>已建连 {item.established_connections ?? 0} / 总 {item.connections ?? 0}</div>
                        {portsText && <div className="text-sky-300">{portsText}</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* 出站目标 IP 双列紧凑网格 */}
          {outboundIpDetails.length > 0 && (
            <div>
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-1 text-[10px] text-slate-400">
                <span className="inline-flex items-center gap-1 font-semibold text-slate-200">
                  <ArrowUpRight className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                  <span>出站访问目标公网明细 (Top {Math.min(outboundIpDetails.length, 6)})</span>
                </span>
                {inv?.outbound_orgs && inv.outbound_orgs.length > 0 && (
                  <span className="font-mono text-slate-300">
                    目标归属：{inv.outbound_orgs.slice(0, 4).map((o) => `${o.org}(${o.connections})`).join(' · ')}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2 font-mono text-[11px] tabular-nums">
                {outboundIpDetails.slice(0, 6).map((item: SocketAbuseIpDetail) => {
                  const fallbackGeo = [
                    item.country_name || (item.country && item.country !== 'UN' ? item.country : ''),
                    item.region || item.city,
                    item.isp,
                    item.asn,
                  ]
                    .filter(Boolean)
                    .join(' · ');
                  const geoText = item.geo_label || fallbackGeo;
                  const portsText = Array.isArray(item.ports) && item.ports.length > 0
                    ? `端口 ${item.ports.slice(0, 3).join('/')}`
                    : '';
                  return (
                    <div
                      key={item.ip}
                      className="flex min-w-0 items-center justify-between gap-2 rounded border border-slate-800/90 bg-slate-950/85 px-2.5 py-1.5"
                    >
                      <div className="min-w-0 flex-1">
                        <span className="font-semibold text-sky-300">{item.ip}</span>
                        {geoText && (
                          <div className="mt-0.5 truncate font-sans text-[10px] text-emerald-200/90" title={geoText}>
                            {geoText}
                          </div>
                        )}
                      </div>
                      <div className="shrink-0 text-right text-[10px] text-slate-300">
                        <div>活跃 {item.established_connections ?? 0} / 总 {item.connections ?? 0}</div>
                        {portsText && <div className="text-slate-400">{portsText}</div>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* 捕获到的代理进程启动参数（含脱敏与一键复制排查命令） */}
          {Array.isArray(effectiveInv?.proxy_processes) && effectiveInv.proxy_processes.length > 0 && (
            <div className="rounded border border-slate-800 bg-slate-950/80 p-2">
              <div className="flex items-center justify-between text-[10px]">
                <span className="inline-flex items-center gap-1 font-semibold text-sky-200">
                  <Terminal className="h-3 w-3 text-sky-400" aria-hidden="true" />
                  <span>检测到活跃代理进程与启动命令 (密码/密钥已自动脱敏)</span>
                </span>
              </div>
              <div className="mt-1.5 space-y-1.5 font-mono text-[11px]">
                {effectiveInv.proxy_processes.map((proc: SocketAbuseProcessCommand) => (
                  <div
                    key={proc.pid}
                    className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-800 bg-slate-900/90 px-2.5 py-1.5"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2 text-[10px]">
                        <span className="rounded bg-sky-950 px-1.5 py-0.5 text-sky-300">
                          {proc.process} (PID {proc.pid})
                        </span>
                        {Array.isArray(proc.listeners) && proc.listeners.length > 0 && (
                          <span className="text-emerald-400">监听: {proc.listeners.join(', ')}</span>
                        )}
                        {Array.isArray(proc.forwards) && proc.forwards.length > 0 && (
                          <span className="text-amber-400">转发: {proc.forwards.join(', ')}</span>
                        )}
                      </div>
                      <div className="mt-0.5 break-all text-[10px] text-slate-300">{proc.command}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopyCmd(proc.command, proc.pid)}
                      className="inline-flex shrink-0 items-center gap-1 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[10px] text-slate-200 hover:bg-slate-700 focus-visible:outline-2 focus-visible:outline-sky-300"
                    >
                      {copiedPid === proc.pid ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedPid === proc.pid ? '已复制' : '复制命令'}</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 四维文字详述与场景完整依据双列面板 */}
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 text-[10px] text-slate-400">
            <div className="space-y-1 rounded border border-slate-800/80 bg-slate-950/60 p-2">
              <div className="flex items-center gap-1 font-semibold text-slate-300">
                <Activity className="h-3 w-3 text-sky-400" aria-hidden="true" />
                <span>四维指标诊断说明</span>
              </div>
              {dimensions.map((d) => (
                <div key={d.key} className="leading-relaxed">
                  <span className="font-medium text-slate-200">{shortDimTitle(d.key, d.title)}：</span>
                  <span>{d.summary}</span>
                </div>
              ))}
            </div>

            {effectiveInv && (
              <div className="space-y-1 rounded border border-slate-800/80 bg-slate-950/60 p-2">
                <div className="flex items-center gap-1 font-semibold text-slate-300">
                  <Gauge className="h-3 w-3 text-amber-400" aria-hidden="true" />
                  <span>场景评估依据与排查边界</span>
                </div>
                {scenarios.map((sc) => (
                  <div key={sc.key} className="leading-relaxed">
                    <span className="font-medium text-slate-200">{sc.label} ({scenarioMeta(sc.likelihood).fullLabel})：</span>
                    <span>{sc.basis}</span>
                  </div>
                ))}
                {Array.isArray(effectiveInv.notes) && effectiveInv.notes.map((note, idx) => (
                  <div key={idx} className="flex items-start gap-1 text-slate-400">
                    <span className="text-sky-400">•</span>
                    <span>{note}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </details>
    </div>
  );
};
