import React, { useState } from 'react';
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
    };
  }
  if (risk === 'medium') {
    return {
      label: '重点核实',
      badge: 'border-amber-500/40 bg-amber-950/70 text-amber-200',
      box: 'border-amber-500/30 bg-amber-950/20',
      header: 'text-amber-300',
    };
  }
  return {
    label: '正常特征',
    badge: 'border-emerald-500/35 bg-emerald-950/60 text-emerald-200',
    box: 'border-slate-800 bg-slate-900/60',
    header: 'text-emerald-300',
  };
};

const scenarioMeta = (likelihood?: string) => {
  if (likelihood === 'high') {
    return {
      label: '高可能性',
      badge: 'border-amber-500/40 bg-amber-950/70 text-amber-200',
      bar: 'bg-amber-400',
    };
  }
  if (likelihood === 'medium') {
    return {
      label: '中等可能',
      badge: 'border-sky-500/40 bg-sky-950/70 text-sky-200',
      bar: 'bg-sky-400',
    };
  }
  return {
    label: '可能性较低',
    badge: 'border-slate-700/80 bg-slate-900/80 text-slate-300',
    bar: 'bg-slate-600',
  };
};

export const SocketAbuseEvidence: React.FC<SocketAbuseEvidenceProps> = ({
  alert,
  assessment,
  compact = false,
}) => {
  const [copiedPid, setCopiedPid] = useState<number | null>(null);
  const [showAllNotes, setShowAllNotes] = useState(false);

  const data = extractSocketAbuseAssessment(alert, assessment);
  if (!data) return null;

  const isSuspected = Boolean(data.suspected || data.verdict === 'suspected_abuse');
  const isBenignHigh = data.verdict === 'benign_high_sockets';
  const categories = Array.isArray(data.categories) ? data.categories : [];
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const inv: SocketAbuseInvestigation | undefined = data.investigation;

  const headerStyle = isSuspected
    ? 'border-amber-500/40 bg-amber-950/20'
    : isBenignHigh
    ? 'border-emerald-500/30 bg-emerald-950/15'
    : 'border-slate-800 bg-slate-950/60';

  const verdictBadgeStyle = isSuspected
    ? 'border-rose-500/50 bg-rose-950/80 text-rose-200'
    : isBenignHigh
    ? 'border-emerald-500/40 bg-emerald-950/80 text-emerald-200'
    : 'border-cyan-500/40 bg-cyan-950/70 text-cyan-200';

  const dimMap: Record<string, SocketAbuseDimension> = {};
  for (const d of dimensions) {
    if (d?.key) dimMap[d.key] = d;
  }

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

  const denom = Math.max(totalSockets, established + timeWait + synSent + synRecv + udpSockets, 1);
  const estPct = Math.round((established / denom) * 100);
  const twPct = Math.round((timeWait / denom) * 100);
  const synSentPct = Math.round((synSent / denom) * 100);
  const otherPct = Math.max(0, 100 - estPct - twPct - synSentPct);

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
      className={`mt-3 rounded-lg border p-3.5 text-xs leading-relaxed ${headerStyle}`}
    >
      {/* 头部结论条 */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-slate-100">
            Socket / 代理连接四维判断依据与深度诊断
          </span>
          <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${verdictBadgeStyle}`}>
            {data.verdict_label || (isSuspected ? '疑似滥用 · 待人工复核' : '倾向非滥用')}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {inv?.proxy_like && (
            <span className="rounded border border-sky-500/35 bg-sky-950/60 px-2 py-0.5 text-[11px] font-mono text-sky-200">
              TCP 代理转发对称度 {Math.round(Number(inv.proxy_symmetry || 0) * 100)}%
            </span>
          )}
          <span className="rounded border border-slate-700/80 bg-slate-900/80 px-2 py-0.5 text-[11px] text-slate-300">
            人工复核模式 · 未自动停机/封禁
          </span>
        </div>
      </div>

      {data.conclusion && (
        <p className="mt-2.5 text-slate-200">{data.conclusion}</p>
      )}

      {categories.length > 0 && (
        <div className="mt-2.5 space-y-1.5">
          {categories.map((cat) => (
            <div
              key={cat.code}
              className="rounded border border-rose-500/35 bg-rose-950/40 px-3 py-1.5 text-rose-100"
            >
              <span className="font-semibold text-rose-200">命中规则 · {cat.title}：</span>
              <span>{cat.reason}</span>
            </div>
          ))}
        </div>
      )}

      {/* 四大维度网格 —— 填补留白、信息均衡 */}
      <div className={`mt-3 grid gap-3 ${compact ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-2'}`}>
        {/* 维度 1：连接状态拆解 */}
        {dim1 && (
          <div className={`flex flex-col justify-between rounded-md border p-3 ${riskBadgeMeta(dim1.risk).box}`}>
            <div>
              <div className="flex items-center justify-between gap-2 border-b border-slate-800/60 pb-1.5">
                <span className="font-semibold text-slate-100">{dim1.title}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${riskBadgeMeta(dim1.risk).badge}`}>
                  {riskBadgeMeta(dim1.risk).label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] text-slate-300">{dim1.summary}</p>

              {/* 连接状态占比进度条（填补空隙，直观表现短连接堆积 vs 活跃） */}
              <div className="mt-2.5">
                <div className="flex justify-between text-[10px] font-mono text-slate-400">
                  <span>状态分布占比</span>
                  <span>EST {estPct}% / TIME_WAIT {twPct}%</span>
                </div>
                <div className="mt-1 flex h-2 w-full overflow-hidden rounded bg-slate-950">
                  <div
                    style={{ width: `${estPct}%` }}
                    className="bg-cyan-500"
                    title={`ESTABLISHED ${established} (${estPct}%)`}
                  />
                  <div
                    style={{ width: `${twPct}%` }}
                    className="bg-emerald-500"
                    title={`TIME_WAIT ${timeWait} (${twPct}%)`}
                  />
                  {synSent > 0 && (
                    <div
                      style={{ width: `${synSentPct}%` }}
                      className="bg-rose-500"
                      title={`SYN_SENT ${synSent} (${synSentPct}%)`}
                    />
                  )}
                  {otherPct > 0 && (
                    <div
                      style={{ width: `${otherPct}%` }}
                      className="bg-slate-700"
                      title="其他状态"
                    />
                  )}
                </div>
              </div>

              {/* 细化指标药丸 */}
              <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[11px]">
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-200">
                  总计 {totalSockets}
                </span>
                <span className="rounded border border-cyan-500/35 bg-cyan-950/50 px-2 py-0.5 text-cyan-200">
                  ESTABLISHED {established} ({estPct}%)
                </span>
                <span className="rounded border border-emerald-500/35 bg-emerald-950/45 px-2 py-0.5 text-emerald-200">
                  TIME_WAIT {timeWait} ({twPct}%)
                </span>
                <span
                  className={`rounded border px-2 py-0.5 ${
                    synSent >= 20
                      ? 'border-rose-500/50 bg-rose-950/60 text-rose-200'
                      : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
                  }`}
                >
                  SYN_SENT {synSent}
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-300">
                  SYN_RECV {synRecv}
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-300">
                  UDP {udpSockets}
                </span>
              </div>
            </div>

            {/* 底部代理一进一出配对观察 */}
            <div className="mt-3 rounded border border-slate-800/80 bg-slate-950/60 p-2 text-[11px]">
              <div className="flex items-center justify-between text-slate-300">
                <span className="text-slate-400">双向并发对称性：</span>
                <span className="font-mono text-sky-300">
                  入站活跃 {incomingEst} 条 ⇄ 出站活跃 {outboundEst} 条
                  {incomingEst > 0 && outboundEst > 0 && (
                    <span className="ml-1.5 text-slate-400">
                      (比率 {(Math.min(incomingEst, outboundEst) / Math.max(incomingEst, outboundEst, 1)).toFixed(2)})
                    </span>
                  )}
                </span>
              </div>
              <p className="mt-1 text-[10px] text-slate-400">
                {Math.abs(incomingEst - outboundEst) <= 5 && incomingEst >= 10
                  ? '入站与出站连接数高度一致，呈典型一进一出网络代理中转模式。'
                  : '连接数略有偏差，可能包含长连接保活、短连接或非代理服务。'}
              </p>
            </div>
          </div>
        )}

        {/* 维度 2：入站并发业务源 */}
        {dim2 && (
          <div className={`flex flex-col justify-between rounded-md border p-3 ${riskBadgeMeta(dim2.risk).box}`}>
            <div>
              <div className="flex items-center justify-between gap-2 border-b border-slate-800/60 pb-1.5">
                <span className="font-semibold text-slate-100">{dim2.title}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${riskBadgeMeta(dim2.risk).badge}`}>
                  {riskBadgeMeta(dim2.risk).label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] text-slate-300">{dim2.summary}</p>

              {/* 核心指标药丸 */}
              <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[11px]">
                <span
                  className={`rounded border px-2 py-0.5 ${
                    Number(m2.inbound_established_unique_ips || 0) >= 10
                      ? 'border-amber-500/50 bg-amber-950/60 text-amber-200'
                      : 'border-cyan-500/35 bg-cyan-950/50 text-cyan-200'
                  }`}
                >
                  已建连真实来源 IP: {m2.inbound_established_unique_ips ?? 0}
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-300">
                  入站活跃连接: {m2.incoming_established ?? 0}
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-400">
                  仅探测未建连 IP: {m2.inbound_syn_recv_unique_ips ?? 0}
                </span>
                {m2.socks_detected && (
                  <span className="rounded border border-rose-500/40 bg-rose-950/60 px-2 py-0.5 text-rose-200">
                    SOCKS5 ({m2.socks_auth_mode || 'unknown'})
                  </span>
                )}
                {inv?.relay_ips ? (
                  <span className="rounded border border-amber-500/40 bg-amber-950/60 px-2 py-0.5 text-amber-200">
                    WARP/中继 IP: {inv.relay_ips} 个 (估算真实网络 {inv.estimated_independent_sources?.low ?? 1} 个)
                  </span>
                ) : null}
              </div>

              {/* 入站来源明细列表 */}
              {Array.isArray(m2.top_ip_details) && m2.top_ip_details.length > 0 && (
                <div className="mt-2.5 space-y-1 font-mono text-[11px]">
                  {m2.top_ip_details.slice(0, 6).map((item: SocketAbuseIpDetail) => {
                    const fallbackGeo = [
                      item.country_name || (item.country && item.country !== 'UN' ? item.country : ''),
                      item.region || item.city,
                      item.isp,
                      item.asn,
                    ]
                      .filter(Boolean)
                      .join('·');
                    const geoText = item.geo_label || fallbackGeo;
                    const portsText = Array.isArray(item.local_ports) && item.local_ports.length > 0
                      ? ` → 端口 ${item.local_ports.join('/')}`
                      : '';
                    const isRelay = item.network_kind === 'relay' || (item.isp || '').toLowerCase().includes('cloudflare');
                    return (
                      <div
                        key={item.ip}
                        className="flex flex-wrap items-center justify-between gap-1 rounded border border-slate-800 bg-slate-950/80 px-2 py-1"
                      >
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-semibold text-sky-300">{item.ip}</span>
                          {geoText && (
                            <span
                              className={`rounded px-1.5 py-0.2 text-[10px] ${
                                isRelay ? 'bg-amber-950/70 text-amber-200 border border-amber-700/50' : 'bg-slate-900 text-slate-300'
                              }`}
                            >
                              {geoText}
                            </span>
                          )}
                          {item.network_label && (
                            <span className="rounded bg-indigo-950/60 px-1 py-0.2 text-[9px] text-indigo-300">
                              {item.network_label}
                            </span>
                          )}
                        </div>
                        <div className="text-slate-400">
                          已建连 {item.established_connections ?? 0} / 总 {item.connections ?? 0}
                          {portsText && <span className="text-slate-300">{portsText}</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* 来源网络聚合说明 */}
            {inv?.source_networks && inv.source_networks.length > 0 && (
              <div className="mt-3 rounded border border-slate-800/80 bg-slate-950/60 p-2 text-[10px] text-slate-300">
                <span className="font-semibold text-slate-200">来源网络去重透视：</span>
                {inv.source_networks.map((net, i) => (
                  <span key={i} className="mr-2">
                    {net.label} ({net.ips} IP · {net.established_connections} 活跃)
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 维度 3：出站目标与进程画像 */}
        {dim3 && (
          <div className={`flex flex-col justify-between rounded-md border p-3 ${riskBadgeMeta(dim3.risk).box}`}>
            <div>
              <div className="flex items-center justify-between gap-2 border-b border-slate-800/60 pb-1.5">
                <span className="font-semibold text-slate-100">{dim3.title}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${riskBadgeMeta(dim3.risk).badge}`}>
                  {riskBadgeMeta(dim3.risk).label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] text-slate-300">{dim3.summary}</p>

              {/* 核心指标药丸 */}
              <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[11px]">
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-200">
                  出站活跃: {m3.outbound_established ?? 0}
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-300">
                  外部目标 IP: {m3.outbound_unique_ips ?? 0} / 端口: {m3.outbound_unique_ports ?? 0}
                </span>
                <span
                  className={`rounded border px-2 py-0.5 ${
                    Number(m3.suspicious_outbound_connections || 0) >= 5
                      ? 'border-rose-500/50 bg-rose-950/60 text-rose-200'
                      : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
                  }`}
                >
                  敏感端口连接: {m3.suspicious_outbound_connections ?? 0}
                </span>
                {Array.isArray(m3.top_processes) &&
                  m3.top_processes.map((proc: any) => (
                    <span
                      key={`${proc.process}-${proc.pid}`}
                      className="rounded border border-cyan-500/35 bg-cyan-950/45 px-2 py-0.5 text-cyan-200"
                    >
                      {proc.process}(PID {proc.pid}, 入{proc.inbound_connections}/出{proc.outbound_connections})
                    </span>
                  ))}
              </div>

              {/* 出站目标明细列表 */}
              {Array.isArray(m3.top_ip_details) && m3.top_ip_details.length > 0 && (
                <div className="mt-2.5 space-y-1 font-mono text-[11px]">
                  {m3.top_ip_details.slice(0, 5).map((item: SocketAbuseIpDetail) => {
                    const fallbackGeo = [
                      item.country_name || (item.country && item.country !== 'UN' ? item.country : ''),
                      item.region || item.city,
                      item.isp,
                      item.asn,
                    ]
                      .filter(Boolean)
                      .join('·');
                    const geoText = item.geo_label || fallbackGeo;
                    const portsText = Array.isArray(item.ports) && item.ports.length > 0
                      ? `·端口 ${item.ports.slice(0, 3).join('/')}`
                      : '';
                    return (
                      <div
                        key={item.ip}
                        className="flex flex-wrap items-center justify-between gap-1 rounded border border-slate-800 bg-slate-950/80 px-2 py-1"
                      >
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-semibold text-sky-300">{item.ip}</span>
                          {geoText && (
                            <span className="rounded bg-emerald-950/60 px-1.5 py-0.2 text-[10px] text-emerald-200 border border-emerald-800/40">
                              {geoText}
                            </span>
                          )}
                        </div>
                        <div className="text-slate-400">
                          活跃 {item.established_connections ?? 0} / 总 {item.connections ?? 0}
                          {portsText && <span className="text-slate-300">{portsText}</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* 出站目标组织与端口分布 */}
            {inv?.outbound_orgs && inv.outbound_orgs.length > 0 && (
              <div className="mt-3 rounded border border-slate-800/80 bg-slate-950/60 p-2 text-[10px] text-slate-300">
                <span className="font-semibold text-slate-200">目标归属聚合：</span>
                {inv.outbound_orgs.slice(0, 4).map((org, i) => (
                  <span key={i} className="mr-2 text-slate-300">
                    {org.org} ({org.connections} 条)
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 维度 4：包速率与带宽特征 */}
        {dim4 && (
          <div className={`flex flex-col justify-between rounded-md border p-3 ${riskBadgeMeta(dim4.risk).box}`}>
            <div>
              <div className="flex items-center justify-between gap-2 border-b border-slate-800/60 pb-1.5">
                <span className="font-semibold text-slate-100">{dim4.title}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${riskBadgeMeta(dim4.risk).badge}`}>
                  {riskBadgeMeta(dim4.risk).label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] text-slate-300">{dim4.summary}</p>

              {/* 速率药丸 */}
              <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[11px]">
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-200">
                  出站 PPS: {Math.round(Number(m4.tx_pps || 0))} pps
                </span>
                <span className="rounded border border-slate-700/80 bg-slate-950/70 px-2 py-0.5 text-slate-300">
                  入站 PPS: {Math.round(Number(m4.rx_pps || 0))} pps
                </span>
                {Number(m4.avg_tx_packet_size || 0) > 0 && (
                  <span
                    className={`rounded border px-2 py-0.5 ${
                      Number(m4.tx_pps || 0) >= 1500 && Number(m4.avg_tx_packet_size || 0) <= 160
                        ? 'border-rose-500/50 bg-rose-950/60 text-rose-200'
                        : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
                    }`}
                  >
                    出站均包长: {Math.round(Number(m4.avg_tx_packet_size || 0))} B
                  </span>
                )}
              </div>

              {/* 流量与包长特征健康分析卡片（填补空白，直观分析流媒体 vs 小包泛洪） */}
              <div className="mt-2.5 rounded border border-slate-800 bg-slate-950/70 p-2.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">网络流量形态分析：</span>
                  <span className="font-mono text-emerald-300">
                    {Number(m4.avg_tx_packet_size || 0) >= 500
                      ? '大包吞吐 (正常 Web / 传输)'
                      : Number(m4.tx_pps || 0) >= 1500 && Number(m4.avg_tx_packet_size || 0) <= 160
                      ? '高频小包泛洪特征'
                      : '均衡中等包长 (交互/代理会话)'}
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-2 gap-2 text-[10px] font-mono">
                  <div className="rounded bg-slate-900/90 p-1.5">
                    <span className="text-slate-400">PPS 对称比：</span>
                    <span className="ml-1 text-slate-200">
                      {Number(m4.rx_pps || 0) > 0
                        ? (Number(m4.tx_pps || 0) / Number(m4.rx_pps || 1)).toFixed(2)
                        : '0'}
                    </span>
                  </div>
                  <div className="rounded bg-slate-900/90 p-1.5">
                    <span className="text-slate-400">单包开销：</span>
                    <span className="ml-1 text-slate-200">
                      {Math.round(Number(m4.avg_tx_packet_size || 0))} 字节/包
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* 流量状态评定 */}
            <div className="mt-3 rounded border border-slate-800/80 bg-slate-950/60 p-2 text-[10px] text-slate-400">
              {Number(m4.tx_pps || 0) <= 200 && Number(m4.rx_pps || 0) <= 200
                ? '双向包速率均低于 200 pps，未见 UDP Flood、ICMP Flood 或 SYN Flood 等高频发包攻击。'
                : '包速率处于中高水平，持续监测是否有异常突增。'}
            </div>
          </div>
        )}
      </div>

      {/* 运维专家业务场景推断与排查面板 —— 彻底充实内容，解决“留白过多” */}
      {inv && (
        <div className="mt-3 rounded-md border border-slate-800 bg-slate-950/80 p-3">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <span className="font-semibold text-slate-200">
              运营分析 · 业务场景可能性评估
            </span>
            <span className="text-[10px] text-slate-400">
              基于入站网络、双向对称度与端口散度自动推断，不作为处罚依据
            </span>
          </div>

          {/* 场景评估四卡片 */}
          {Array.isArray(inv.scenarios) && inv.scenarios.length > 0 && (
            <div className="mt-2.5 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {inv.scenarios.map((sc: SocketAbuseScenario) => {
                const meta = scenarioMeta(sc.likelihood);
                return (
                  <div
                    key={sc.key}
                    className="flex flex-col justify-between rounded border border-slate-800/90 bg-slate-900/70 p-2"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1">
                        <span className="font-medium text-slate-200">{sc.label}</span>
                        <span className={`rounded border px-1.5 py-0.2 text-[9px] font-semibold ${meta.badge}`}>
                          {meta.label}
                        </span>
                      </div>
                      <p className="mt-1 text-[10px] text-slate-400 leading-snug">{sc.basis}</p>
                    </div>
                    <div className="mt-2 h-1 w-full overflow-hidden rounded bg-slate-950">
                      <div
                        className={`h-full ${meta.bar}`}
                        style={{
                          width: sc.likelihood === 'high' ? '85%' : sc.likelihood === 'medium' ? '50%' : '20%',
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* 捕获到的代理进程启动参数（含脱敏与一键复制排查命令） */}
          {Array.isArray(inv.proxy_processes) && inv.proxy_processes.length > 0 && (
            <div className="mt-3 rounded border border-slate-800 bg-slate-900/80 p-2.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="font-semibold text-sky-200">
                  检测到活跃代理进程与启动命令 (自动脱敏)
                </span>
                <span className="text-[10px] text-slate-400">密码与密钥已自动掩码处理</span>
              </div>
              <div className="mt-2 space-y-2 font-mono text-[11px]">
                {inv.proxy_processes.map((proc: SocketAbuseProcessCommand) => (
                  <div
                    key={proc.pid}
                    className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-950 p-2 border border-slate-800"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-sky-950 px-1.5 py-0.5 text-sky-300">
                          {proc.process} (PID {proc.pid})
                        </span>
                        {Array.isArray(proc.listeners) && proc.listeners.length > 0 && (
                          <span className="text-emerald-400">
                            监听: {proc.listeners.join(', ')}
                          </span>
                        )}
                        {Array.isArray(proc.forwards) && proc.forwards.length > 0 && (
                          <span className="text-amber-400">
                            转发: {proc.forwards.join(', ')}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 break-all text-[10px] text-slate-300">
                        {proc.command}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleCopyCmd(proc.command, proc.pid)}
                      className="shrink-0 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[10px] text-slate-200 hover:bg-slate-700"
                    >
                      {copiedPid === proc.pid ? '已复制' : '复制命令'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 运维排查指导与免责边界 */}
          {Array.isArray(inv.notes) && inv.notes.length > 0 && (
            <div className="mt-2.5 text-[11px] text-slate-400 space-y-1">
              {(showAllNotes ? inv.notes : inv.notes.slice(0, 3)).map((note: string, idx: number) => (
                <div key={idx} className="flex items-start gap-1.5">
                  <span className="text-sky-400">•</span>
                  <span>{note}</span>
                </div>
              ))}
              {inv.notes.length > 3 && (
                <button
                  type="button"
                  onClick={() => setShowAllNotes(!showAllNotes)}
                  className="mt-1 text-[10px] text-sky-400 hover:underline"
                >
                  {showAllNotes ? '收起排查建议' : `展开全部 ${inv.notes.length} 条排查建议`}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
