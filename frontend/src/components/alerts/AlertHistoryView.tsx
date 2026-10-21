import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Filter,
  RotateCcw,
  Search,
  Ban,
  Clock,
  ArrowRight,
  Network,
  ShieldCheck,
} from 'lucide-react';
import { SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { SocksPasswordReview } from './SocksPasswordReview';
import { UserNoticeAction } from './UserNoticeAction';
import { isProtectionOnlySignal } from './protectionSignals';

const elapsed = (seconds: number): string => {
  const units: [number, string][] = [[86400, '天'], [3600, '小时'], [60, '分钟'], [1, '秒']];
  let remaining = Math.max(0, Math.floor(seconds));
  const parts = units.flatMap(([size, label]) => {
    const count = Math.floor(remaining / size);
    remaining %= size;
    return count ? [`${count} ${label}`] : [];
  });
  return parts.join(' ') || '0 秒';
};

const recoveryLabel = (alert: SecurityAlert): string => {
  if (alert.recovery?.verified) return '已确认恢复';
  if (alert.recovery?.state === 'manual_closed') return '人工关闭 · 未验证恢复';
  if (alert.recovery?.state === 'legacy_verified') return '已恢复 · 历史时间未留存';
  return alert.status === 'resolved' ? '已关闭 · 待验证恢复' : '';
};

const evidenceConfidenceLabel = (value?: string): string => ({
  confirmed: '已确认',
  probable: '推定',
  mixed: '证据冲突',
  unknown: '未知',
} as Record<string, string>)[value || 'unknown'] || '未知';

const inboundSignalLabel = (value?: string): string => ({
  possible_multiport_probe: '多端口探测迹象',
  bidirectional_tcp_observed: '已观察到双向 TCP 通信',
  mixed_connection_evidence: '已建连与未应答连接并存',
  unreplied_tcp_observed: '存在未应答 TCP 连接',
  insufficient_transport_evidence: '传输层证据不足',
} as Record<string, string>)[value || ''] || '行为线索不足';

const hasActionEvidence = (alert: SecurityAlert): boolean => {
  if (alert.runtime !== 'incus' && alert.runtime !== 'podman') return false;
  const details = alert.details || {};
  if (alert.type === 'unauthorized_panel_pairing') {
    return (details.process_patterns || []).length > 0 || (details.config_files || []).length > 0;
  }
  if (alert.type === 'socks_weak_auth') {
    return ['no_auth', 'weak_password'].includes(details.socks_auth_mode) && (details.socks_processes || []).length > 0;
  }
  if (alert.type === 'malicious_process') {
    return (details.malicious_processes || []).some((item: any) => item?.process === 'xmrig');
  }
  return false;
};

interface AlertHistoryViewProps {
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onBackToDashboard: () => void;
}

export const AlertHistoryView: React.FC<AlertHistoryViewProps> = ({
  onToast,
  onBackToDashboard,
}) => {
  const [statusTab, setStatusTab] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [alertType, setAlertType] = useState('all');
  const [hostId, setHostId] = useState('');
  const [query, setQuery] = useState('');

  const [items, setItems] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [typeOptions, setTypeOptions] = useState<string[]>([]);
  const [hostOptions, setHostOptions] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [offset, setOffset] = useState(0);
  const limit = 30;

  const loadData = async (reset = false) => {
    if (loading) return;
    setLoading(true);
    const newOffset = reset ? 0 : offset;
    try {
      const res = await api.getAlertHistory({
        status: statusTab,
        severity,
        alert_type: alertType,
        host_id: hostId,
        query,
        limit: String(limit),
        offset: String(newOffset),
      });

      if (reset) {
        setItems(res.items || []);
        setOffset(res.items.length);
      } else {
        setItems((prev) => [...prev, ...(res.items || [])]);
        setOffset((prev) => prev + (res.items || []).length);
      }

      setTotal(res.total || 0);
      setCounts(res.counts || {});
      if (res.alert_types) setTypeOptions(res.alert_types);
      if (res.hosts) setHostOptions(res.hosts);
    } catch (err: any) {
      onToast('error', `加载告警记录失败：${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, [statusTab, severity, alertType, hostId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadData(true);
  };

  const handleReset = () => {
    setStatusTab('all');
    setSeverity('all');
    setAlertType('all');
    setHostId('');
    setQuery('');
  };

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'reopen'
  ) => {
    try {
      const res = await api.dispositionAlert(alertId, decision);
      onToast('success', res.queued ? '操作已排队等待节点执行' : '安全状态已更新');
      loadData(true);
    } catch (err: any) {
      onToast('error', `处置操作失败：${err.message || err}`);
    }
  };

  const statusLabels: Record<string, string> = {
    all: '全部',
    active: '活动',
    suppressed: '已放行',
    dismissed: '本次忽略',
    remediated: '已处理',
    resolved: '已恢复 / 已关闭',
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-amber-950/80 p-2.5 text-amber-400 border border-amber-500/30">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">
              安全告警与处置审计历史
            </h2>
            <p className="text-xs text-slate-400">
              保留活动、已忽略、已处理及恢复事件；可一键重新执行定向清理或解除策略。
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onBackToDashboard}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-700 transition-colors shrink-0"
        >
          <span>返回总览看板</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Filter Panel */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Filter className="h-4 w-4 text-sky-400" />
            <span>维度筛选与检索</span>
          </div>
          <button
            type="button"
            onClick={handleReset}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RotateCcw className="h-3 w-3" />
            <span>重置筛选</span>
          </button>
        </div>

        {/* Form Controls */}
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">告警级别</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
            >
              <option value="all">全部级别</option>
              <option value="critical">Critical (高危)</option>
              <option value="warning">Warning (告警)</option>
              <option value="info">Info (提示)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">告警类型</label>
            <select
              value={alertType}
              onChange={(e) => setAlertType(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
            >
              <option value="all">全部类型</option>
              {typeOptions.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">所属主机</label>
            <select
              value={hostId}
              onChange={(e) => setHostId(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
            >
              <option value="">全部主机</option>
              {hostOptions.map((h) => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">关键词搜索</label>
            <div className="relative">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="容器、说明、进程特征..."
                className="w-full rounded-lg border border-slate-800 bg-slate-950 pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent"
              />
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            </div>
          </div>
        </form>

        {/* Status Tabs */}
        <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 overflow-x-auto">
          {['all', 'active', 'suppressed', 'dismissed', 'remediated', 'resolved'].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setStatusTab(s)}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold transition-all shrink-0 focus:outline-none focus:ring-2 focus:ring-sky-400 ${
                statusTab === s
                  ? 'border-sky-500 bg-sky-950/80 text-sky-300'
                  : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <span>{statusLabels[s] || s}</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px]">
                {counts[s] || 0}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Alert Card List */}
      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-800 p-12 text-center text-slate-500 text-xs">
            没有符合筛选条件的告警记录
          </div>
        ) : (
          items.map((alert) => {
            const isHistorical = alert.status !== 'active';
            const protectionOnly = isProtectionOnlySignal(alert);
            const canRemediate = hasActionEvidence(alert);
            const attribution = alert.deep_evidence?.connection_attribution;
            const inboundEvidence = alert.deep_evidence?.inbound_ips ||
              (alert.deep_evidence?.connection_ips || []).filter((entry) => Number(entry.inbound || 0) > 0);

            return (
              <div
                key={alert.id}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 shadow-sm hover:border-slate-700 transition-colors space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusBadge status={alert.severity} size="sm" />
                      <span className="font-bold text-sm text-slate-100">
                        {alert.title || alert.type}
                      </span>
                      {protectionOnly && (
                        <span className="inline-flex items-center gap-1 rounded-full border border-sky-500/40 bg-sky-950/50 px-2 py-0.5 text-[10px] font-semibold text-sky-200">
                          <ShieldCheck className="h-3 w-3" />
                          保护类 · 不计用户滥用
                        </span>
                      )}
                      <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                        {alert.host_id}
                      </span>
                      <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                        {alert.project ? `${alert.runtime}/${alert.project}` : alert.runtime}
                      </span>
                      {alert.container_name && (
                        <span className="rounded-md bg-sky-950/60 border border-sky-500/30 px-2 py-0.5 font-mono text-xs text-sky-300">
                          {alert.container_name}
                        </span>
                      )}
                      <span className="rounded-full bg-slate-800 px-2 py-0.2 text-[10px] text-slate-400 font-mono">
                        {recoveryLabel(alert) || statusLabels[alert.status] || alert.status}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {alert.message}
                    </p>
                    {protectionOnly && (
                      <div className="rounded-lg border border-sky-800/70 bg-sky-950/25 px-3 py-2 text-[11px] leading-relaxed text-slate-300">
                        <div className="flex items-center gap-1.5 font-semibold text-sky-200">
                          <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                          仅作为网络保护记录
                        </div>
                        <p className="mt-1">
                          连接、来源 IP 或流量特征不能单独证明用户身份或违规意图；此记录不计入用户异常统计，也不作为滥用指控或处罚依据。若达到独立保护阈值，系统可能限制新连接或停止目标容器，并只发送说明保护动作的通知。
                        </p>
                      </div>
                    )}
                    <SocksPasswordReview alert={alert} onRefresh={() => loadData(true)} onToast={onToast} />
                    {!protectionOnly && <UserNoticeAction alertId={alert.id} onToast={onToast} />}
                  </div>

                  <span className="text-xs text-slate-500 tabular-nums shrink-0">
                    出现 {alert.occurrence_count || 1} 次
                  </span>
                </div>

                {alert.deep_evidence && (
                  <details className="rounded-xl border border-sky-900/70 bg-sky-950/20 p-3">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold text-sky-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 rounded-md">
                      <span className="flex items-center gap-2">
                        <Network className="h-4 w-4 text-sky-400" />
                        自动深度取证 · {alert.deep_evidence.captured_at_utc8 || '已采集'}
                      </span>
                      <span className="font-mono text-[11px] text-slate-400">
                        入站 {alert.deep_evidence.inbound_unique_ips || 0} IP / {alert.deep_evidence.inbound_process_count || 0} 进程　
                        出站 {alert.deep_evidence.outbound_unique_ips || 0} IP / {alert.deep_evidence.outbound_process_count || 0} 进程
                      </span>
                    </summary>
                    <div className="mt-3 border-t border-sky-900/50 pt-3">
                      {attribution && (
                        <section className="mb-3 rounded-lg border border-sky-900/70 bg-slate-950/60 p-3">
                          <h4 className="text-xs font-semibold text-sky-200">连接发起方核验</h4>
                          <div className="mt-2 grid grid-cols-2 gap-2 text-[11px] tabular-nums sm:grid-cols-4">
                            <div className="rounded-md bg-slate-900 p-2"><span className="block text-slate-500">本机进程发起 · 已确认</span><strong className="text-sky-300">{attribution.confirmed_local_initiated || 0}</strong></div>
                            <div className="rounded-md bg-slate-900 p-2"><span className="block text-slate-500">本机进程发起 · 推定</span><strong className="text-amber-300">{attribution.probable_local_initiated || 0}</strong></div>
                            <div className="rounded-md bg-slate-900 p-2"><span className="block text-slate-500">外部远端发起 · 已确认</span><strong className="text-emerald-300">{attribution.confirmed_remote_initiated || 0}</strong></div>
                            <div className="rounded-md bg-slate-900 p-2"><span className="block text-slate-500">方向未知</span><strong className="text-slate-300">{attribution.unknown_direction || 0}</strong></div>
                          </div>
                          <p className="mt-2 text-[10px] leading-4 text-slate-500">
                            PID/进程归属 {attribution.process_attributed_sockets || 0}/{attribution.captured_sockets || 0} 条 · conntrack 五元组确认 {attribution.conntrack_confirmed_sockets || 0} 条。
                            {!attribution.conntrack_available && ' conntrack 不可用，部分方向只能推定。'}
                            {(attribution.conntrack_snapshot_truncated || attribution.socket_snapshot_truncated) && ' 快照达到采集上限，结果非全量。'}
                            {' '}方向和进程只能说明连接路径，不能单独判断客户意图。
                          </p>
                        </section>
                      )}
                      <h4 className="mb-2 text-xs font-semibold text-slate-200">接入容器的公网客户端</h4>
                      <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                      {inboundEvidence.slice(0, 100).map((entry, index) => (
                        <div key={`${entry.ip}-${index}`} className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 text-[11px] text-slate-300">
                          <div className="flex items-center justify-between gap-2">
                            <code className="text-sky-300 break-all">{entry.ip || '-'}</code>
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-slate-400">{entry.country || 'UN'}</span>
                          </div>
                          <div className="mt-1 text-slate-400 tabular-nums">
                            接入连接 {entry.inbound || 0}
                          </div>
                          <div className="mt-1 break-words text-slate-400">
                            发起方向：外部远端 · {evidenceConfidenceLabel(entry.inbound_origin_confidence)}
                          </div>
                          {entry.network_evidence && (
                            <div className="mt-1 break-words text-amber-200/90">
                              {inboundSignalLabel(entry.network_evidence.classification)} · 已建连 {entry.network_evidence.tcp_established_flows || 0} / 未应答 {entry.network_evidence.tcp_unreplied_flows || 0} / 握手待完成 {entry.network_evidence.tcp_handshake_pending_flows || 0} · 回包 {entry.network_evidence.reply_packets || 0}
                            </div>
                          )}
                          <div className="mt-1 break-words text-slate-500">
                            归属：{[entry.region, entry.city].filter(Boolean).join(' · ') || '暂未识别'} · 运营商：{entry.isp || '暂未识别'}{entry.asn ? ` · AS${entry.asn}` : ''}
                          </div>
                          <div className="mt-1 break-words text-slate-500">
                            接入端进程：{(entry.inbound_processes || []).map((item) => item.process).filter(Boolean).join('、') || (entry.processes || []).join('、') || '未归属'}
                          </div>
                        </div>
                      ))}
                      {inboundEvidence.length === 0 && (
                        <div className="text-xs text-slate-500">采样瞬间未发现可见的公网连接 IP。</div>
                      )}
                      </div>
                    </div>
                    <div className="mt-3 border-t border-sky-900/50 pt-3">
                      <h4 className="mb-2 text-xs font-semibold text-slate-200">容器主动访问的公网目标</h4>
                      <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                      {(alert.deep_evidence.outbound_ips || (alert.deep_evidence.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0)).slice(0, 100).map((entry, index) => (
                        <div key={`${entry.ip}-${index}`} className="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5 text-[11px] text-slate-300">
                          <div className="flex items-center justify-between gap-2">
                            <code className="text-sky-300 break-all">{entry.ip || '-'}</code>
                            <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-slate-400">{entry.country || 'UN'}</span>
                          </div>
                          <div className="mt-1 text-slate-400 tabular-nums">出站连接 {entry.outbound || 0}</div>
                          <div className="mt-1 break-words text-slate-500">
                            归属：{[entry.region, entry.city].filter(Boolean).join(' · ') || '暂未识别'} · 运营商：{entry.isp || '暂未识别'}{entry.asn ? ` · AS${entry.asn}` : ''}
                          </div>
                          <div className="mt-1 break-words text-slate-400">发起方向：本机进程 · {evidenceConfidenceLabel(entry.outbound_origin_confidence)}</div>
                          <div className="mt-1 break-words text-slate-500">发起进程：{(entry.outbound_processes || []).map((item) => item.process).filter(Boolean).join('、') || (entry.processes || []).join('、') || '未归属'}</div>
                        </div>
                      ))}
                      {(alert.deep_evidence.outbound_ips || (alert.deep_evidence.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0)).length === 0 && (
                        <div className="text-xs text-slate-500">采样瞬间未发现容器主动访问的公网 IP。</div>
                      )}
                      </div>
                    </div>
                    <p className="mt-2 text-[10px] leading-4 text-slate-500">
                      多端口探测或未应答只代表单次采样中的传输层迹象，可能由扫描、丢包或服务拒绝造成；不能仅凭这些数据判定恶意，需结合应用访问日志和连续样本。
                    </p>
                    {(alert.deep_evidence.errors || []).length > 0 && (
                      <p className="mt-2 text-[11px] text-amber-300">
                        部分证据不可用：{alert.deep_evidence.errors?.join('；')}
                      </p>
                    )}
                  </details>
                )}

                {/* Footnotes & Actions */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80 pt-3 text-xs">
                  <div className="min-w-0 break-words text-slate-500 text-[11px] font-mono">
                    <div>首次 {alert.first_seen_utc8} · 最近 {alert.last_seen_utc8}</div>
                    {alert.recovery?.verified && alert.recovery.duration_seconds != null && (
                      <div className="mt-1 text-emerald-300">告警持续 {elapsed(alert.recovery.duration_seconds)} 后确认恢复 · 恢复 {alert.recovery.recovered_at_utc8}</div>
                    )}
                    {!alert.recovery?.verified && alert.recovery?.closed_duration_seconds != null && (
                      <div className="mt-1 text-amber-300">关闭前持续 {elapsed(alert.recovery.closed_duration_seconds)} · 关闭 {alert.recovery.closed_at_utc8} · {alert.recovery.state === 'legacy_verified' ? '历史恢复时刻未留存，不能计算准确恢复时长' : '不代表已确认恢复'}</div>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {canRemediate && <button
                      type="button"
                      onClick={() => handleDecision(alert.id, 'deny')}
                      className="flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-950/60 px-2.5 py-1 text-xs font-semibold text-rose-200 hover:bg-rose-900/80 transition-colors"
                    >
                      <Ban className="h-3 w-3" />
                      <span>{isHistorical ? '重新定向处置' : '定向处置'}</span>
                    </button>}

                    {(alert.status === 'suppressed' || alert.status === 'dismissed') && (
                      <button
                        type="button"
                        onClick={() => handleDecision(alert.id, 'reopen')}
                        className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
                      >
                        <Clock className="h-3 w-3" />
                        <span>恢复提醒</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}

        {/* Load More Button */}
        {offset < total && (
          <div className="text-center pt-2">
            <button
              type="button"
              onClick={() => loadData(false)}
              disabled={loading}
              className="rounded-xl border border-slate-800 bg-slate-900 px-6 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              {loading ? '加载中...' : `加载更多 (${offset} / ${total})`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
