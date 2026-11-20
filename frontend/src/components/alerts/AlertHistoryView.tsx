import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  Filter,
  RotateCcw,
  Search,
  Ban,
  Check,
  EyeOff,
  Clock,
  ArrowRight,
  Network,
  ShieldCheck,
  LoaderCircle,
} from 'lucide-react';
import { SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { SocksPasswordReview } from './SocksPasswordReview';
import { UserNoticeAction } from './UserNoticeAction';
import { isProtectionOnlySignal } from './protectionSignals';
import {
  connectionAttributionUnavailable,
  formatConnectionEvidenceCount,
  formatConnectionEvidenceRatio,
} from './connectionEvidence';
import { ProtocolGuardEvidence } from './ProtocolGuardEvidence';
import { SocketAbuseEvidence, extractSocketAbuseAssessment } from './SocketAbuseEvidence';
import { hasRemediationEvidence } from './remediationEvidence';
import { ConfirmDialog } from '../common/ConfirmDialog';

const elapsed = (seconds: number): string => {
  const units: [number, string][] = [
    [86400, '天'],
    [3600, '小时'],
    [60, '分钟'],
    [1, '秒'],
  ];
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

const evidenceConfidenceLabel = (value?: string): string =>
  (
    {
      confirmed: '已确认',
      probable: '推定',
      mixed: '证据冲突',
      unknown: '未知',
    } as Record<string, string>
  )[value || 'unknown'] || '未知';

const inboundSignalLabel = (value?: string): string =>
  (
    {
      possible_multiport_probe: '多端口探测迹象',
      bidirectional_tcp_observed: '已观察到双向 TCP 通信',
      mixed_connection_evidence: '已建连与未应答连接并存',
      unreplied_tcp_observed: '存在未应答 TCP 连接',
      insufficient_transport_evidence: '传输层证据不足',
    } as Record<string, string>
  )[value || ''] || '行为线索不足';

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
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [searchVersion, setSearchVersion] = useState(0);

  const [items, setItems] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [typeOptions, setTypeOptions] = useState<string[]>([]);
  const [hostOptions, setHostOptions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [pendingRemediation, setPendingRemediation] = useState<SecurityAlert | null>(null);
  const [submittingAlertId, setSubmittingAlertId] = useState<number | null>(null);
  const loadRequestId = useRef(0);
  const loadController = useRef<AbortController | null>(null);
  const filtersRef = useRef({ statusTab, severity, alertType, hostId, submittedQuery, offset });
  filtersRef.current = { statusTab, severity, alertType, hostId, submittedQuery, offset };
  const limit = 30;

  const loadData = async (reset = false) => {
    loadController.current?.abort();
    const controller = new AbortController();
    loadController.current = controller;
    const requestId = ++loadRequestId.current;
    const filters = filtersRef.current;
    const newOffset = reset ? 0 : filters.offset;
    setLoading(true);
    setLoadError(null);
    if (reset) {
      setItems([]);
      setOffset(0);
      setTotal(0);
      setCounts({});
    }
    try {
      const res = await api.getAlertHistory(
        {
          status: filters.statusTab,
          severity: filters.severity,
          alert_type: filters.alertType,
          host_id: filters.hostId,
          query: filters.submittedQuery,
          limit: String(limit),
          offset: String(newOffset),
        },
        controller.signal
      );

      if (requestId !== loadRequestId.current || controller.signal.aborted) return;

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
      if (!controller.signal.aborted && requestId === loadRequestId.current) {
        const message = err?.message || String(err);
        setLoadError(message);
        onToast('error', `加载告警记录失败：${message}`);
      }
    } finally {
      if (!controller.signal.aborted && requestId === loadRequestId.current) setLoading(false);
    }
  };

  useEffect(() => {
    void loadData(true);
  }, [statusTab, severity, alertType, hostId, submittedQuery, searchVersion]);

  useEffect(
    () => () => {
      loadRequestId.current += 1;
      loadController.current?.abort();
    },
    []
  );

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittedQuery(query.trim());
    setOffset(0);
    setSearchVersion((version) => version + 1);
  };

  const handleReset = () => {
    setStatusTab('all');
    setSeverity('all');
    setAlertType('all');
    setHostId('');
    setQuery('');
    setSubmittedQuery('');
    setOffset(0);
    setSearchVersion((version) => version + 1);
  };

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'reopen' | 'freeze_container'
  ) => {
    if (submittingAlertId !== null) return;
    setSubmittingAlertId(alertId);
    try {
      const res = await api.dispositionAlert(alertId, decision);
      onToast(
        'success',
        decision === 'freeze_container'
          ? '容器封禁冻结指令已排队，等待节点执行'
          : res.queued
            ? '操作已排队等待节点执行'
            : '安全状态已更新'
      );
      await loadData(true);
    } catch (err: any) {
      onToast('error', `处置操作失败：${err.message || err}`);
    } finally {
      setSubmittingAlertId(null);
      setPendingRemediation(null);
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
    <div className="space-y-6 text-[#0b1636]">
      {/* Top Banner */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#f7d58b]/40 bg-[#ff6b00]/20 text-[#fcd34d]">
              <ShieldAlert className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block">SECURITY AUDIT · ALERT HISTORY</span>
              <h2 className="mt-0.5 text-base font-bold text-white sm:text-lg">安全告警与处置审计历史</h2>
              <p className="mt-0.5 text-xs text-[#b9d3ee]">
                保留活动、已忽略、已处理及恢复事件；可一键重新执行定向清理或解除策略。
              </p>
            </div>
          </div>

          <button type="button" onClick={onBackToDashboard} className="rn2-btn rn2-btn-ghost rn2-btn-sm shrink-0">
            <span>返回总览看板</span>
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>

        {/* Filter Panel */}
        <div className="space-y-4 p-4 sm:p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-bold text-[#0b1636]">
              <Filter className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
              <span>维度筛选与检索</span>
            </div>
            <button type="button" onClick={handleReset} className="rn2-btn rn2-btn-ghost rn2-btn-sm">
              <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
              <span>重置筛选</span>
            </button>
          </div>

          {/* Form Controls */}
          <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 md:grid-cols-5">
            <div>
              <label htmlFor="alert-history-severity" className="mb-1 block font-semibold text-[#31485e]">
                告警级别
              </label>
              <select
                id="alert-history-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="rn2-select-sm w-full"
              >
                <option value="all">全部级别</option>
                <option value="critical">Critical (高危)</option>
                <option value="warning">Warning (告警)</option>
                <option value="info">Info (提示)</option>
              </select>
            </div>

            <div>
              <label htmlFor="alert-history-type" className="mb-1 block font-semibold text-[#31485e]">
                告警类型
              </label>
              <select
                id="alert-history-type"
                value={alertType}
                onChange={(e) => setAlertType(e.target.value)}
                className="rn2-select-sm w-full"
              >
                <option value="all">全部类型</option>
                {typeOptions.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="alert-history-host" className="mb-1 block font-semibold text-[#31485e]">
                所属主机
              </label>
              <select
                id="alert-history-host"
                value={hostId}
                onChange={(e) => setHostId(e.target.value)}
                className="rn2-select-sm w-full"
              >
                <option value="">全部主机</option>
                {hostOptions.map((h) => (
                  <option key={h} value={h}>
                    {h}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="alert-history-query" className="mb-1 block font-semibold text-[#31485e]">
                关键词搜索
              </label>
              <div className="relative">
                <input
                  id="alert-history-query"
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="容器、说明、进程特征..."
                  className="rn2-input-sm w-full pl-8 pr-3"
                />
                <Search aria-hidden="true" className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#697b9c]" />
              </div>
            </div>

            <button type="submit" className="rn2-btn rn2-btn-orange self-end">
              <Search aria-hidden="true" className="h-4 w-4" />
              搜索
            </button>
          </form>

          {/* Status Tabs */}
          <div className="flex flex-wrap items-center gap-2 border-t border-[#dce5ef] pt-3">
            {['all', 'active', 'suppressed', 'dismissed', 'remediated', 'resolved'].map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setStatusTab(s)}
                aria-pressed={statusTab === s}
                className={`flex min-h-9 shrink-0 items-center gap-1.5 rounded-full border px-3.5 py-1 text-xs font-semibold transition-all focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] ${
                  statusTab === s
                    ? 'border-[#0867d6] bg-[#087bff] text-white shadow-xs'
                    : 'border-[#cedae7] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff] hover:text-[#087bff]'
                }`}
              >
                <span>{statusLabels[s] || s}</span>
                <span
                  className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] font-bold tabular-nums ${
                    statusTab === s ? 'bg-white/20 text-white' : 'bg-white text-[#0b1636]'
                  }`}
                >
                  {counts[s] || 0}
                </span>
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Alert Card List */}
      <div className="space-y-3">
        {loadError && (
          <div
            role="alert"
            className="flex flex-col gap-3 rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 sm:flex-row sm:items-center sm:justify-between"
          >
            <p className="min-w-0 break-words text-sm font-medium text-[#b41835]">告警历史未能更新：{loadError}</p>
            <button type="button" onClick={() => void loadData(true)} className="rn2-btn rn2-btn-danger rn2-btn-sm shrink-0">
              重试
            </button>
          </div>
        )}

        {loading && items.length === 0 ? (
          <p
            role="status"
            aria-live="polite"
            className="rounded-xl border border-[#cedae7] bg-white p-8 text-center text-sm font-medium text-[#31485e]"
          >
            正在读取告警记录…
          </p>
        ) : !loadError && items.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-[#cedae7] bg-white p-12 text-center text-xs font-medium text-[#506483]">
            没有符合筛选条件的告警记录
          </div>
        ) : (
          items.map((alert) => {
            const isHistorical = alert.status !== 'active';
            const isSubmitting = submittingAlertId === alert.id;
            const protectionOnly = isProtectionOnlySignal(alert);
            const canRemediate = hasRemediationEvidence(alert);
            const attribution = alert.deep_evidence?.connection_attribution;
            const attributionUnavailable = connectionAttributionUnavailable(
              attribution,
              alert.deep_evidence?.connection_count
            );
            const inboundEvidence =
              alert.deep_evidence?.inbound_ips ||
              (alert.deep_evidence?.connection_ips || []).filter((entry) => Number(entry.inbound || 0) > 0);
            const outboundEvidence =
              alert.deep_evidence?.outbound_ips ||
              (alert.deep_evidence?.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0);

            return (
              <div
                key={alert.id}
                className="rounded-[14px] border border-[#cedae7] bg-white p-4 text-[#0b1636] shadow-[0_5px_16px_rgba(12,37,65,0.06)] transition-colors hover:border-[#087bff]/50 space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge status={alert.severity} size="sm" />
                      <span className="text-sm font-bold text-[#0b1636]">{alert.title || alert.type}</span>
                      {protectionOnly && (
                        <span className="rn2-pill rn2-pill-blue rn2-pill-sm">
                          <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                          保护类 · 不计用户滥用
                        </span>
                      )}
                      <span className="rounded-md border border-[#cedae7] bg-[#f4f8fd] px-2 py-0.5 font-mono text-xs text-[#31485e]">
                        {alert.host_id}
                      </span>
                      <span className="rounded-md border border-[#cedae7] bg-[#f4f8fd] px-2 py-0.5 font-mono text-xs text-[#31485e]">
                        {alert.project ? `${alert.runtime}/${alert.project}` : alert.runtime}
                      </span>
                      {alert.container_name && (
                        <span className="rounded-md border border-[#a9d1ff] bg-[#e8f3ff] px-2 py-0.5 font-mono text-xs font-semibold text-[#0657b8]">
                          {alert.container_name}
                        </span>
                      )}
                      <span
                        className={`rn2-pill rn2-pill-sm font-mono ${
                          alert.recovery?.verified ? 'rn2-pill-teal' : 'rn2-pill-slate'
                        }`}
                      >
                        {recoveryLabel(alert) || statusLabels[alert.status] || alert.status}
                      </span>
                    </div>

                    <p className="text-xs leading-relaxed text-[#31485e]">{alert.message}</p>
                    <SocketAbuseEvidence alert={alert} />
                    <ProtocolGuardEvidence alert={alert} />
                    {protectionOnly &&
                      (extractSocketAbuseAssessment(alert) ? (
                        <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] px-3 py-1.5 text-[11px] text-[#31485e]">
                          <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-[#087bff]" aria-hidden="true" />
                          <span className="font-semibold text-[#0657b8]">仅作为网络保护记录：</span>
                          <span>连接、来源 IP 或流量特征不单独证明用户违规意图，不计入用户异常统计。</span>
                        </div>
                      ) : (
                        <div className="rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] px-3 py-2 text-[11px] leading-relaxed text-[#31485e]">
                          <div className="flex items-center gap-1.5 font-semibold text-[#0657b8]">
                            <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                            仅作为网络保护记录
                          </div>
                          <p className="mt-1">
                            连接、来源 IP 或流量特征不能单独证明用户身份或违规意图；此记录不计入用户异常统计，也不作为滥用指控或处罚依据。若达到独立保护阈值，系统可能限制新连接或停止目标容器，并只发送说明保护动作的通知。
                          </p>
                        </div>
                      ))}
                    <SocksPasswordReview alert={alert} onRefresh={() => loadData(true)} onToast={onToast} />
                    {!protectionOnly && <UserNoticeAction alertId={alert.id} onToast={onToast} />}
                  </div>

                  <span className="shrink-0 font-mono text-xs font-semibold text-[#506483] tabular-nums">
                    出现 {alert.occurrence_count || 1} 次
                  </span>
                </div>

                {alert.deep_evidence && (
                  <details className="rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3">
                    <summary className="flex cursor-pointer list-none items-center justify-between gap-3 rounded-md text-xs font-bold text-[#0b1636] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff]">
                      <span className="flex items-center gap-2">
                        <Network className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                        自动深度取证 · {alert.deep_evidence.captured_at_utc8 || '已采集'}
                      </span>
                      <span className="font-mono text-[11px] font-semibold text-[#506483] tabular-nums">
                        入站{' '}
                        {formatConnectionEvidenceCount(
                          alert.deep_evidence.inbound_unique_ips,
                          attributionUnavailable && inboundEvidence.length === 0
                        )}{' '}
                        IP /{' '}
                        {formatConnectionEvidenceCount(
                          alert.deep_evidence.inbound_process_count,
                          attributionUnavailable
                        )}{' '}
                        进程　 出站{' '}
                        {formatConnectionEvidenceCount(
                          alert.deep_evidence.outbound_unique_ips,
                          attributionUnavailable && outboundEvidence.length === 0
                        )}{' '}
                        IP /{' '}
                        {formatConnectionEvidenceCount(
                          alert.deep_evidence.outbound_process_count,
                          attributionUnavailable
                        )}{' '}
                        进程
                      </span>
                    </summary>

                    <div className="mt-3 border-t border-[#d2dfec] pt-3">
                      {attribution && (
                        <section className="mb-3 rounded-xl border border-[#cedae7] bg-white p-3">
                          <h4 className="text-xs font-bold text-[#0657b8]">连接发起方核验</h4>
                          <div className="mt-2 grid grid-cols-2 divide-y divide-[#d2dfec] overflow-hidden rounded-lg border border-[#d2dfec] bg-[#f4f8fd] text-[11px] tabular-nums sm:grid-cols-4 sm:divide-x sm:divide-y-0">
                            <div className="p-2.5">
                              <span className="block text-[#506483]">本机进程发起 · 已确认</span>
                              <strong className="font-mono text-sm text-[#087bff]">
                                {formatConnectionEvidenceCount(
                                  attribution.confirmed_local_initiated,
                                  attributionUnavailable
                                )}
                              </strong>
                            </div>
                            <div className="p-2.5">
                              <span className="block text-[#506483]">本机进程发起 · 推定</span>
                              <strong className="font-mono text-sm text-[#9a5b00]">
                                {formatConnectionEvidenceCount(
                                  attribution.probable_local_initiated,
                                  attributionUnavailable
                                )}
                              </strong>
                            </div>
                            <div className="p-2.5">
                              <span className="block text-[#506483]">外部远端发起 · 已确认</span>
                              <strong className="font-mono text-sm text-[#147468]">
                                {formatConnectionEvidenceCount(
                                  attribution.confirmed_remote_initiated,
                                  attributionUnavailable
                                )}
                              </strong>
                            </div>
                            <div className="p-2.5">
                              <span className="block text-[#506483]">方向未知</span>
                              <strong className="font-mono text-sm text-[#31485e]">
                                {formatConnectionEvidenceCount(
                                  attribution.unknown_direction,
                                  attributionUnavailable
                                )}
                              </strong>
                            </div>
                          </div>
                          <p className="mt-2 text-[10px] leading-4 text-[#506483]">
                            {attributionUnavailable
                              ? `触发时连接总数 ${formatConnectionEvidenceCount(alert.deep_evidence.connection_count, false)} 条，但没有可用的逐连接快照；方向与 PID 归属未知，不能把缺失样本当作 0。`
                              : `PID/进程归属 ${formatConnectionEvidenceRatio(attribution.process_attributed_sockets, attribution.captured_sockets, false)} 条 · conntrack 五元组确认 ${formatConnectionEvidenceCount(attribution.conntrack_confirmed_sockets, false)} 条。`}
                            {!attribution.conntrack_available &&
                              !attributionUnavailable &&
                              ' conntrack 不可用；其它方向依据 socket 状态证据判定。'}
                            {(attribution.conntrack_snapshot_truncated || attribution.socket_snapshot_truncated) &&
                              ' 快照达到采集上限，结果非全量。'}
                            {' '}
                            方向和进程只能说明连接路径，不能单独判断客户意图。
                          </p>
                        </section>
                      )}

                      {!attribution && (
                        <p className="mb-3 rounded-lg border border-[#f7d58b] bg-[#fef6e4] p-3 text-[11px] leading-5 text-[#9a5b00]">
                          该历史记录没有发起方向/PID 归属数据；这表示证据未留存，不代表对应计数为 0。
                        </p>
                      )}

                      <h4 className="mb-2 text-xs font-bold text-[#0b1636]">接入容器的公网客户端</h4>
                      <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                        {inboundEvidence.slice(0, 100).map((entry, index) => (
                          <div
                            key={`${entry.ip}-${index}`}
                            className="rounded-lg border border-[#dce5ef] bg-white p-2.5 text-[11px] text-[#31485e]"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <code className="break-all font-mono font-bold text-[#0657b8]">{entry.ip || '-'}</code>
                              <span className="rounded bg-[#eef3f9] px-1.5 py-0.5 font-mono text-[#31485e]">
                                {entry.country || 'UN'}
                              </span>
                            </div>
                            <div className="mt-1 text-[#31485e] tabular-nums">接入连接 {entry.inbound || 0}</div>
                            <div className="mt-1 wrap-break-word text-[#506483]">
                              发起方向：外部远端 · {evidenceConfidenceLabel(entry.inbound_origin_confidence)}
                            </div>
                            {entry.network_evidence && (
                              <div className="mt-1 wrap-break-word font-medium text-[#9a5b00]">
                                {inboundSignalLabel(entry.network_evidence.classification)} · 已建连{' '}
                                {entry.network_evidence.tcp_established_flows || 0} / 未应答{' '}
                                {entry.network_evidence.tcp_unreplied_flows || 0} / 握手待完成{' '}
                                {entry.network_evidence.tcp_handshake_pending_flows || 0} · 回包{' '}
                                {entry.network_evidence.reply_packets || 0}
                              </div>
                            )}
                            <div className="mt-1 wrap-break-word text-[#506483]">
                              归属：{[entry.region, entry.city].filter(Boolean).join(' · ') || '暂未识别'} · 运营商：
                              {entry.isp || '暂未识别'}
                              {entry.asn ? ` · AS${entry.asn}` : ''}
                            </div>
                            <div className="mt-1 wrap-break-word text-[#506483]">
                              接入端进程：
                              {(entry.inbound_processes || []).map((item) => item.process).filter(Boolean).join('、') ||
                                (entry.processes || []).join('、') ||
                                '未归属'}
                            </div>
                          </div>
                        ))}
                        {inboundEvidence.length === 0 && (
                          <div className="text-xs text-[#506483]">采样瞬间未发现可见的公网连接 IP。</div>
                        )}
                      </div>
                    </div>

                    <div className="mt-3 border-t border-[#d2dfec] pt-3">
                      <h4 className="mb-2 text-xs font-bold text-[#0b1636]">容器主动访问的公网目标</h4>
                      <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
                        {(
                          alert.deep_evidence.outbound_ips ||
                          (alert.deep_evidence.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0)
                        )
                          .slice(0, 100)
                          .map((entry, index) => (
                            <div
                              key={`${entry.ip}-${index}`}
                              className="rounded-lg border border-[#dce5ef] bg-white p-2.5 text-[11px] text-[#31485e]"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <code className="break-all font-mono font-bold text-[#0657b8]">{entry.ip || '-'}</code>
                                <span className="rounded bg-[#eef3f9] px-1.5 py-0.5 font-mono text-[#31485e]">
                                  {entry.country || 'UN'}
                                </span>
                              </div>
                              <div className="mt-1 text-[#31485e] tabular-nums">出站连接 {entry.outbound || 0}</div>
                              <div className="mt-1 wrap-break-word text-[#506483]">
                                归属：{[entry.region, entry.city].filter(Boolean).join(' · ') || '暂未识别'} · 运营商：
                                {entry.isp || '暂未识别'}
                                {entry.asn ? ` · AS${entry.asn}` : ''}
                              </div>
                              <div className="mt-1 wrap-break-word text-[#506483]">
                                发起方向：本机进程 · {evidenceConfidenceLabel(entry.outbound_origin_confidence)}
                              </div>
                              <div className="mt-1 wrap-break-word text-[#506483]">
                                发起进程：
                                {(entry.outbound_processes || []).map((item) => item.process).filter(Boolean).join('、') ||
                                  (entry.processes || []).join('、') ||
                                  '未归属'}
                              </div>
                            </div>
                          ))}
                        {(
                          alert.deep_evidence.outbound_ips ||
                          (alert.deep_evidence.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0)
                        ).length === 0 && (
                          <div className="text-xs text-[#506483]">采样瞬间未发现容器主动访问的公网 IP。</div>
                        )}
                      </div>
                    </div>

                    <p className="mt-2 text-[10px] leading-4 text-[#506483]">
                      多端口探测或未应答只代表单次采样中的传输层迹象，可能由扫描、丢包或服务拒绝造成；不能仅凭这些数据判定恶意，需结合应用访问日志和连续样本。
                    </p>
                    {(alert.deep_evidence.errors || []).length > 0 && (
                      <p className="mt-2 text-[11px] font-medium text-[#9a5b00]">
                        部分证据不可用：{alert.deep_evidence.errors?.join('；')}
                      </p>
                    )}
                  </details>
                )}

                {/* Footnotes & Actions */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#dce5ef] pt-3 text-xs">
                  <div className="min-w-0 wrap-break-word font-mono text-[11px] text-[#506483]">
                    <div>
                      首次 {alert.first_seen_utc8} · 最近 {alert.last_seen_utc8}
                    </div>
                    {alert.recovery?.verified && alert.recovery.duration_seconds != null && (
                      <div className="mt-1 font-semibold text-[#147468]">
                        告警持续 {elapsed(alert.recovery.duration_seconds)} 后确认恢复 · 恢复 {alert.recovery.recovered_at_utc8}
                      </div>
                    )}
                    {!alert.recovery?.verified && alert.recovery?.closed_duration_seconds != null && (
                      <div className="mt-1 font-semibold text-[#9a5b00]">
                        关闭前持续 {elapsed(alert.recovery.closed_duration_seconds)} · 关闭 {alert.recovery.closed_at_utc8} ·{' '}
                        {alert.recovery.state === 'legacy_verified'
                          ? '历史恢复时刻未留存，不能计算准确恢复时长'
                          : '不代表已确认恢复'}
                      </div>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {alert.type === 'socket_abuse_suspected' && alert.status === 'active' && (
                      <>
                        {alert.container_name && ['incus', 'podman', 'runman'].includes(alert.runtime) && (
                          <button
                            type="button"
                            onClick={() => void handleDecision(alert.id, 'freeze_container')}
                            disabled={submittingAlertId !== null}
                            className="rn2-btn rn2-btn-danger rn2-btn-sm"
                            title="挂起冻结该容器实例，立即阻断异常连接并标记告警已处理"
                          >
                            <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>封禁</span>
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => void handleDecision(alert.id, 'allow_silent')}
                          disabled={submittingAlertId !== null}
                          className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                          title="忽略该容器的此类 Socket 异常提醒（可在告警历史中恢复）"
                        >
                          <Check className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" />
                          <span>忽略</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDecision(alert.id, 'dismiss_once')}
                          disabled={submittingAlertId !== null}
                          className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                          title="跳过本次告警提醒，后续状态变化时仍会再次提醒"
                        >
                          <EyeOff className="h-3.5 w-3.5 text-[#506483]" aria-hidden="true" />
                          <span>跳过本次</span>
                        </button>
                      </>
                    )}

                    {canRemediate && (
                      <button
                        type="button"
                        onClick={() => setPendingRemediation(alert)}
                        disabled={submittingAlertId !== null}
                        className="rn2-btn rn2-btn-danger rn2-btn-sm"
                      >
                        <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>{isHistorical ? '重新定向处置' : '定向处置'}</span>
                      </button>
                    )}

                    {(alert.status === 'suppressed' || alert.status === 'dismissed') && (
                      <button
                        type="button"
                        onClick={() => void handleDecision(alert.id, 'reopen')}
                        disabled={submittingAlertId !== null}
                        className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                      >
                        {isSubmitting ? (
                          <LoaderCircle className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" aria-hidden="true" />
                        ) : (
                          <Clock className="h-3.5 w-3.5" aria-hidden="true" />
                        )}
                        <span>{isSubmitting ? '正在提交…' : '恢复提醒'}</span>
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
          <div className="pt-2 text-center">
            <button type="button" onClick={() => void loadData(false)} disabled={loading} className="rn2-btn rn2-btn-ghost">
              {loading ? '加载中...' : `加载更多 (${offset} / ${total})`}
            </button>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={pendingRemediation !== null}
        title="确认定向处置？"
        description={
          pendingRemediation
            ? `将向 ${pendingRemediation.host_id} 的 ${pendingRemediation.runtime}${pendingRemediation.project ? ` / ${pendingRemediation.project}` : ''} 容器 ${pendingRemediation.container_name || '目标实例'} 提交已核验证据对应的定向处置。历史告警会在执行前重新核对目标；此操作不会停止整个容器。`
            : ''
        }
        confirmLabel="确认定向处置"
        tone="danger"
        isSubmitting={pendingRemediation !== null && submittingAlertId === pendingRemediation.id}
        onConfirm={() => {
          if (pendingRemediation) void handleDecision(pendingRemediation.id, 'deny');
        }}
        onCancel={() => {
          if (submittingAlertId === null) setPendingRemediation(null);
        }}
      />
    </div>
  );
};
