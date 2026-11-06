import React from 'react';
import { SocketAbuseAssessment, SocketAbuseDimension } from '../../api/types';

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
      badge: 'border-rose-500/35 bg-rose-950/60 text-rose-200',
      box: 'border-rose-500/25 bg-rose-950/20',
    };
  }
  if (risk === 'medium') {
    return {
      label: '重点核实',
      badge: 'border-amber-500/35 bg-amber-950/60 text-amber-200',
      box: 'border-amber-500/25 bg-amber-950/15',
    };
  }
  return {
    label: '正常特征',
    badge: 'border-emerald-500/30 bg-emerald-950/45 text-emerald-200',
    box: 'border-slate-800 bg-slate-900/55',
  };
};

const renderDimensionMetrics = (dim: SocketAbuseDimension) => {
  const m = dim.metrics || {};
  if (dim.key === 'state_breakdown') {
    return (
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] font-mono">
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-200">
          总计 {m.total ?? 0}
        </span>
        <span className="rounded border border-cyan-500/30 bg-cyan-950/40 px-1.5 py-0.5 text-cyan-200">
          ESTABLISHED {m.tcp_established ?? 0} ({Math.round(Number(m.established_ratio || 0) * 100)}%)
        </span>
        <span className="rounded border border-emerald-500/30 bg-emerald-950/35 px-1.5 py-0.5 text-emerald-200">
          TIME_WAIT {m.tcp_time_wait ?? 0} ({Math.round(Number(m.time_wait_ratio || 0) * 100)}%)
        </span>
        <span
          className={`rounded border px-1.5 py-0.5 ${
            Number(m.tcp_syn_sent || 0) >= 20
              ? 'border-rose-500/40 bg-rose-950/50 text-rose-200'
              : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
          }`}
        >
          SYN_SENT {m.tcp_syn_sent ?? 0}
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-300">
          SYN_RECV {m.tcp_syn_recv ?? 0}
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-300">
          UDP {m.udp_sockets ?? 0}
        </span>
      </div>
    );
  }
  if (dim.key === 'inbound_fanout') {
    const topIps = Array.isArray(m.top_ips) ? m.top_ips.slice(0, 4) : [];
    return (
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] font-mono">
        <span
          className={`rounded border px-1.5 py-0.5 ${
            Number(m.inbound_established_unique_ips || 0) >= 10
              ? 'border-amber-500/40 bg-amber-950/50 text-amber-200'
              : 'border-cyan-500/30 bg-cyan-950/40 text-cyan-200'
          }`}
        >
          已建连真实来源 IP: {m.inbound_established_unique_ips ?? 0}
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-300">
          入站活跃连接: {m.incoming_established ?? 0}
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-400">
          仅探测未建连 IP: {m.inbound_syn_recv_unique_ips ?? 0}
        </span>
        {m.socks_detected && (
          <span className="rounded border border-rose-500/35 bg-rose-950/50 px-1.5 py-0.5 text-rose-200">
            SOCKS5 ({m.socks_auth_mode || 'unknown'})
          </span>
        )}
        {topIps.map((item: string) => (
          <span
            key={item}
            className="rounded border border-slate-800 bg-slate-950/80 px-1.5 py-0.5 text-slate-300"
          >
            {item}
          </span>
        ))}
      </div>
    );
  }
  if (dim.key === 'outbound_profile') {
    const sensitivePorts = Array.isArray(m.sensitive_ports) ? m.sensitive_ports.slice(0, 4) : [];
    const topProcs = Array.isArray(m.top_processes) ? m.top_processes.slice(0, 2) : [];
    return (
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] font-mono">
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-200">
          出站活跃: {m.outbound_established ?? 0}
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-300">
          外部目标 IP: {m.outbound_unique_ips ?? 0} / 端口: {m.outbound_unique_ports ?? 0}
        </span>
        <span
          className={`rounded border px-1.5 py-0.5 ${
            Number(m.suspicious_outbound_connections || 0) >= 5 || sensitivePorts.length > 0
              ? 'border-rose-500/40 bg-rose-950/50 text-rose-200'
              : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
          }`}
        >
          敏感端口连接: {m.suspicious_outbound_connections ?? 0}
        </span>
        {sensitivePorts.map((sp: any) => (
          <span
            key={`${sp.port}-${sp.service}`}
            className="rounded border border-rose-500/35 bg-rose-950/50 px-1.5 py-0.5 text-rose-200"
          >
            {sp.port}/{sp.service} ({sp.connections}条·{sp.unique_ips}IP)
          </span>
        ))}
        {topProcs.map((proc: any) => (
          <span
            key={`${proc.process}-${proc.pid}`}
            className="rounded border border-cyan-500/25 bg-cyan-950/35 px-1.5 py-0.5 text-cyan-200"
          >
            {proc.process}(PID {proc.pid})
          </span>
        ))}
      </div>
    );
  }
  if (dim.key === 'traffic_profile') {
    return (
      <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] font-mono">
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-200">
          出站 PPS: {Math.round(Number(m.tx_pps || 0))} pps
        </span>
        <span className="rounded border border-slate-700/80 bg-slate-950/70 px-1.5 py-0.5 text-slate-300">
          入站 PPS: {Math.round(Number(m.rx_pps || 0))} pps
        </span>
        {Number(m.avg_tx_packet_size || 0) > 0 && (
          <span
            className={`rounded border px-1.5 py-0.5 ${
              Number(m.tx_pps || 0) >= 1500 && Number(m.avg_tx_packet_size || 0) <= 160
                ? 'border-rose-500/40 bg-rose-950/50 text-rose-200'
                : 'border-slate-700/80 bg-slate-950/70 text-slate-300'
            }`}
          >
            出站均包长: {Math.round(Number(m.avg_tx_packet_size || 0))} B
          </span>
        )}
      </div>
    );
  }
  return null;
};

export const SocketAbuseEvidence: React.FC<SocketAbuseEvidenceProps> = ({
  alert,
  assessment,
  compact = false,
}) => {
  const data = extractSocketAbuseAssessment(alert, assessment);
  if (!data) return null;

  const isSuspected = Boolean(data.suspected || data.verdict === 'suspected_abuse');
  const isBenignHigh = data.verdict === 'benign_high_sockets';
  const categories = Array.isArray(data.categories) ? data.categories : [];
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];

  const headerStyle = isSuspected
    ? 'border-amber-500/35 bg-amber-950/25'
    : isBenignHigh
    ? 'border-emerald-500/30 bg-emerald-950/15'
    : 'border-slate-800 bg-slate-950/60';

  const verdictBadgeStyle = isSuspected
    ? 'border-rose-500/40 bg-rose-950/70 text-rose-200'
    : isBenignHigh
    ? 'border-emerald-500/35 bg-emerald-950/60 text-emerald-200'
    : 'border-cyan-500/30 bg-cyan-950/50 text-cyan-200';

  return (
    <div
      data-testid="socket-abuse-evidence"
      className={`mt-3 rounded-lg border p-3 text-xs leading-relaxed ${headerStyle}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-semibold text-slate-100">
            Socket / 代理连接四维判断依据
          </span>
          <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${verdictBadgeStyle}`}>
            {data.verdict_label || (isSuspected ? '疑似滥用 · 待人工复核' : '倾向非滥用')}
          </span>
        </div>
        <span className="rounded border border-slate-700/80 bg-slate-900/80 px-2 py-0.5 text-[11px] text-slate-300">
          人工复核模式 · 未自动停机/封禁
        </span>
      </div>

      {data.conclusion && (
        <p className="mt-2 text-slate-200">{data.conclusion}</p>
      )}

      {categories.length > 0 && (
        <div className="mt-2.5 space-y-1.5">
          {categories.map((cat) => (
            <div
              key={cat.code}
              className="rounded border border-rose-500/30 bg-rose-950/35 px-2.5 py-1.5 text-rose-100"
            >
              <span className="font-semibold text-rose-200">命中规则 · {cat.title}：</span>
              <span>{cat.reason}</span>
            </div>
          ))}
        </div>
      )}

      <div className={`mt-2.5 grid gap-2 ${compact ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-2'}`}>
        {dimensions.map((dim) => {
          const meta = riskBadgeMeta(dim.risk);
          return (
            <div
              key={dim.key}
              className={`rounded-md border p-2.5 ${meta.box}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-slate-100">{dim.title}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${meta.badge}`}>
                  {meta.label}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-slate-300">{dim.summary}</p>
              {renderDimensionMetrics(dim)}
            </div>
          );
        })}
      </div>
    </div>
  );
};

