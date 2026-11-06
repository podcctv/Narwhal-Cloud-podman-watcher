import React, { useState } from 'react';
import {
  ShieldAlert,
  Ban,
  Check,
  EyeOff,
  ExternalLink,
  ArrowUpRight,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { ContainerIdentity, SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { SocksPasswordReview } from '../alerts/SocksPasswordReview';
import { UserNoticeAction } from '../alerts/UserNoticeAction';
import { isProtectionOnlySignal } from '../alerts/protectionSignals';
import { connectionAttributionUnavailable, formatConnectionEvidenceCount, formatConnectionEvidenceRatio } from '../alerts/connectionEvidence';
import { ProtocolGuardEvidence } from '../alerts/ProtocolGuardEvidence';
import { SocketAbuseEvidence } from '../alerts/SocketAbuseEvidence';
import { hasRemediationEvidence } from '../alerts/remediationEvidence';

interface SecurityAlertSectionProps {
  alerts: SecurityAlert[];
  onRefresh: () => void;
  onViewAllHistory: () => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onSelectContainer: (identity: ContainerIdentity) => void;
}

export const SecurityAlertSection: React.FC<SecurityAlertSectionProps> = ({
  alerts,
  onRefresh,
  onViewAllHistory,
  onToast,
  onSelectContainer,
}) => {
  const [submittingId, setSubmittingId] = useState<number | null>(null);
  const protectionOnlyCount = alerts.filter(isProtectionOnlySignal).length;
  const [pendingDecision, setPendingDecision] = useState<{
    id: number;
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'resolve' | 'apply_container_connlimit' | 'release_container_connlimit' | 'freeze_container';
  } | null>(null);

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'resolve' | 'apply_container_connlimit' | 'release_container_connlimit' | 'freeze_container'
  ) => {
    setSubmittingId(alertId);
    try {
      const res = await api.dispositionAlert(
        alertId,
        decision,
        decision === 'apply_container_connlimit' ? { max_connections: 500, duration_seconds: 1800 } : {},
      );
      onToast(
        'success',
        decision === 'resolve'
          ? '告警已标记为已解决'
          : decision === 'freeze_container'
          ? '容器封禁冻结指令已排队，等待节点执行'
          : res.queued
          ? '处置指令已排队，等待节点执行'
          : '安全策略已更新'
      );
      onRefresh();
    } catch (err: any) {
      onToast('error', `操作失败：${err.message || err}`);
    } finally {
      setSubmittingId(null);
    }
  };

  const openQuarantineReview = () => {
    const panel = document.getElementById('quarantine-review');
    if (!panel) {
      onToast('error', '当前页面未加载到隔离复核记录；刷新后重试。');
      return;
    }
    panel.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    panel.focus({ preventScroll: true });
  };

  const confirmationCopy = pendingDecision?.decision === 'deny'
    ? { title: '确认执行定向处置？', description: '仅处理本告警已识别的进程、服务或配置；不会停止整个容器。节点将在下一轮上报时执行并回传结果。', confirmLabel: '确认定向处置', tone: 'danger' as const }
    : pendingDecision?.decision === 'freeze_container'
    ? { title: '确认封禁该容器实例？', description: '将向节点下发容器挂起冻结指令，立即定格容器内所有进程并阻断异常连接，同时将本条告警标记为已处理。可在容器详情抽屉中随时解除冻结。', confirmLabel: '确认封禁', tone: 'danger' as const }
    : pendingDecision?.decision === 'apply_container_connlimit'
    ? { title: '确认临时限制 TCP 新连接？', description: '仅对已核验的 Incus 或 Runman 实例生效：入站和出站方向各限制为最多 500 条并发 TCP 连接，持续 30 分钟；达到上限后拒绝新的 TCP SYN。已有会话不会被断开，UDP 不受影响。可能影响合法高并发业务；规则可手动撤销并会自动过期。', confirmLabel: '应用 30 分钟限额', tone: 'danger' as const }
    : pendingDecision?.decision === 'release_container_connlimit'
    ? { title: '解除临时 TCP 限额？', description: '只删除本系统为该 Incus 或 Runman 实例创建并带有专属标记的连接限制规则，不改动其他防火墙规则。', confirmLabel: '解除限额', tone: 'primary' as const }
    : pendingDecision?.decision === 'allow_silent'
    ? { title: '确认忽略并建立放行策略？', description: '该告警对象将被持续忽略放行且不再提醒。你可在告警历史中随时恢复提醒。', confirmLabel: '确认忽略', tone: 'primary' as const }
    : pendingDecision?.decision === 'resolve'
    ? { title: '确认标记为已解决？', description: '该告警将从活动列表移入历史记录；后续再次检测到同类风险时仍会重新告警。', confirmLabel: '标记已解决', tone: 'primary' as const }
    : { title: '确认跳过本次告警？', description: '仅隐藏当前这一轮活动告警。风险仍会被持续采集，并在后续异常状态变化时再次提示。', confirmLabel: '确认跳过本次', tone: 'primary' as const };

  if (alerts.length === 0) {
    return (
      <section className="mb-6 rounded-2xl border border-emerald-500/25 bg-emerald-950/20 p-4 backdrop-blur-xs sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-emerald-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-emerald-300">
                当前没有新的活动安全告警
              </h2>
              <p className="mt-0.5 text-xs text-emerald-400/80">
                已隔离事件仍需单独复核；没有告警不代表已覆盖所有加密业务行为。
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onViewAllHistory}
            className="flex min-h-9 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800 hover:text-white"
          >
            <span>查看处置历史</span>
            <ExternalLink className="h-3 w-3" />
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="mb-6 overflow-hidden rounded-2xl border border-rose-500/35 bg-slate-900/92 shadow-xl backdrop-blur-xs">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-900/75 px-4 py-3.5 sm:px-5">
        <div className="flex min-w-0 flex-wrap items-center gap-2.5">
          <div className="rounded-lg border border-rose-500/40 bg-rose-950/80 p-1.5 text-rose-400">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <h2 className="flex flex-wrap items-center gap-2 text-sm font-bold text-slate-100">
            <span>安全告警中心</span>
            <span className="rounded-full border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 font-mono text-[11px] font-bold text-rose-300 tabular-nums">
              {alerts.length} 项安全提醒
            </span>
            {protectionOnlyCount > 0 && (
              <span className="rounded-full border border-sky-500/35 bg-sky-950/55 px-2 py-0.5 text-[10px] font-medium text-sky-200 tabular-nums">
                {protectionOnlyCount} 项仅保护 · 不计用户滥用
              </span>
            )}
          </h2>
        </div>

        <button
          type="button"
          onClick={onViewAllHistory}
          className="flex min-h-9 items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-950/35 px-3 py-1.5 text-xs font-semibold text-sky-300 transition-colors hover:border-sky-400/50 hover:bg-sky-950/60 hover:text-sky-200"
        >
          <span>查看全部告警记录</span>
          <ExternalLink className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Alert List */}
      <div className="divide-y divide-slate-800/80">
        {alerts.map((alert) => {
          const isProcessing = submittingId === alert.id;
          const protectionOnly = isProtectionOnlySignal(alert);
          const prohibitedActivity = alert.type === 'prohibited_activity';
          const admissionUnverified = alert.type === 'admission_unverified';
          const deepEvidence = alert.deep_evidence;
          const attribution = deepEvidence?.connection_attribution;
          const attributionUnavailable = connectionAttributionUnavailable(attribution, deepEvidence?.connection_count);
          const inboundEvidence = deepEvidence?.inbound_ips ||
            (deepEvidence?.connection_ips || []).filter((entry) => Number(entry.inbound || 0) > 0);
          const outboundEvidence = deepEvidence?.outbound_ips ||
            (deepEvidence?.connection_ips || []).filter((entry) => Number(entry.outbound || 0) > 0);
          const inboundEvidenceUnavailable = attributionUnavailable && inboundEvidence.length === 0;
          const outboundEvidenceUnavailable = attributionUnavailable && outboundEvidence.length === 0;
          const probeIpCount = new Set(inboundEvidence
            .filter((item) => item.network_evidence?.classification === 'possible_multiport_probe')
            .map((item) => item.ip)
            .filter(Boolean)).size;
          const runtimeText = alert.project
            ? `${alert.runtime}/${alert.project}`
            : alert.runtime;
          const isActionFailed = alert.latest_action?.status === 'failed';
          const canRemediate = hasRemediationEvidence(alert);
          const connlimitAction = alert.latest_action;
          const connlimitExpiresAt = Number(connlimitAction?.params?.lease_expires_at || 0);
          const connlimitActive = connlimitAction?.action_type === 'apply_container_connlimit'
            && connlimitAction.status === 'succeeded' && connlimitExpiresAt > Math.floor(Date.now() / 1000);
          const connlimitPending = ['apply_container_connlimit', 'release_container_connlimit'].includes(connlimitAction?.action_type || '')
            && ['queued', 'dispatched', 'running'].includes(connlimitAction?.status || '');
          const canUseConnlimit = alert.type === 'container_connection_count'
            && (alert.runtime === 'incus' || alert.runtime === 'runman') && (alert.project || '') === 'default';
          const isSocketAbuseReview = alert.type === 'socket_abuse_suspected';
          const canFreezeContainer = isSocketAbuseReview
            && Boolean(alert.container_name)
            && ['incus', 'podman', 'runman'].includes(alert.runtime);
          const freezePending = connlimitAction?.action_type === 'freeze_container'
            && ['queued', 'dispatched', 'running'].includes(connlimitAction?.status || '');

          return (
            <div
              key={alert.id}
              className="p-5 hover:bg-slate-800/25 transition-colors flex flex-col lg:flex-row lg:items-start justify-between gap-4"
            >
              {/* Alert Content */}
              <div className="min-w-0 flex-1 space-y-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={alert.severity} size="sm" />
                  {protectionOnly && (
                    <span className="inline-flex items-center gap-1 rounded-full border border-sky-500/40 bg-sky-950/50 px-2 py-0.5 text-[10px] font-semibold text-sky-200">
                      <ShieldCheck className="h-3 w-3" />
                      保护类 · 用户归因未确认
                    </span>
                  )}
                  <span className="text-sm font-semibold text-slate-100">
                    {alert.title || alert.type}
                  </span>
                  <span className="rounded-md border border-slate-700/70 bg-slate-800/90 px-2 py-0.5 font-mono text-xs text-slate-300">
                    {alert.host_id}
                  </span>
                  <span className="rounded-md border border-slate-700/70 bg-slate-800/90 px-2 py-0.5 font-mono text-xs text-slate-300">
                    {runtimeText}
                  </span>
                  {alert.container_name && (
                    <span className="rounded-md border border-sky-500/35 bg-sky-950/60 px-2 py-0.5 font-mono text-xs text-sky-300">
                      {alert.container_name}
                    </span>
                  )}
                  <span className="text-xs text-slate-400 tabular-nums">
                    出现 {alert.occurrence_count || 1} 次 · 最近 {alert.last_seen_utc8 || '-'}
                  </span>
                </div>

                <p className="text-xs leading-relaxed text-slate-200">
                  {alert.message}
                </p>
                <SocketAbuseEvidence alert={alert} />
                <ProtocolGuardEvidence alert={alert} />
                {protectionOnly && (
                  <div className="rounded-xl border border-sky-800/70 bg-sky-950/25 px-3.5 py-2.5 text-[11px] leading-relaxed text-slate-300">
                    <div className="flex items-center gap-1.5 font-semibold text-sky-200">
                      <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                      {admissionUnverified ? '保护状态待核实' : '仅作为主机保护信号'}
                    </div>
                    <p className="mt-1">
                      {admissionUnverified
                        ? '采样或规则校验未通过，当前不能确认防护是否生效；这不代表已确认攻击，也不归因为用户行为。'
                        : '当前数据只反映连接、流量或访问特征，尚未通过应用/代理认证日志关联到具体用户；不作为用户滥用指控或处罚依据。若达到独立保护阈值，系统可能限制新连接或停止目标容器，并只发送说明保护动作的通知。'}
                    </p>
                    {deepEvidence ? (
                      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 border-t border-sky-900/70 pt-2 text-slate-300 tabular-nums">
                        <span>深度快照：{deepEvidence.captured_at_utc8 || '时间未上报'}</span>
                        <span>入站：{formatConnectionEvidenceCount(deepEvidence.inbound_unique_ips, inboundEvidenceUnavailable)} IP / {formatConnectionEvidenceCount(deepEvidence.inbound_process_count, attributionUnavailable)} 进程</span>
                        <span>出站：{formatConnectionEvidenceCount(deepEvidence.outbound_unique_ips, outboundEvidenceUnavailable)} IP / {formatConnectionEvidenceCount(deepEvidence.outbound_process_count, attributionUnavailable)} 进程</span>
                        {attribution && <span>
                          发起方向：本机进程已确认 {formatConnectionEvidenceCount(attribution.confirmed_local_initiated, attributionUnavailable)} / 远端发起已确认 {formatConnectionEvidenceCount(attribution.confirmed_remote_initiated, attributionUnavailable)} / 未知 {formatConnectionEvidenceCount(attribution.unknown_direction, attributionUnavailable)}
                        </span>}
                        {probeIpCount > 0 && <span className="text-amber-200">多端口探测线索 {probeIpCount} IP（非攻击定论）</span>}
                        {attribution && (attributionUnavailable
                          ? <span className="text-amber-200">连接明细未采集，发起方向与进程归属未知，不能按 0 条判断</span>
                          : <span>进程/PID 归属 {formatConnectionEvidenceRatio(attribution.process_attributed_sockets, attribution.captured_sockets, false)} 条</span>)}
                        {attribution?.conntrack_available === false && !attributionUnavailable && <span className="text-amber-200">conntrack 不可用；其余方向只按 socket 状态证据判定</span>}
                      </div>
                    ) : (
                      <p className="mt-2 border-t border-sky-900/70 pt-2 text-slate-400">
                        尚无深度连接快照；目前不能判断连接来源、发起方向或对应进程。
                      </p>
                    )}
                    <p className="mt-1 text-slate-400">连接方向或进程归属不等于用户身份；需要认证日志才能把行为关联到用户。</p>
                  </div>
                )}
                <SocksPasswordReview alert={alert} onRefresh={onRefresh} onToast={onToast} />

                {/* Remediation Failure Explanation Banner */}
                {isActionFailed && (
                  <div className="mt-2 flex items-start gap-2 rounded-xl border border-rose-500/40 bg-rose-950/40 p-3 text-xs">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
                    <div className="min-w-0 flex-1">
                      <div className="font-semibold text-rose-300">
                        {prohibitedActivity ? '隔离恢复未验证：' : '前次定向处置未成功：'}
                      </div>
                      <div className="mt-0.5 break-all font-mono text-[11px] text-slate-300">
                        {alert.latest_action?.result_message || '节点未返回具体失败原因'}
                      </div>
                      <div className="mt-1 text-[11px] text-slate-400">
                        {prohibitedActivity
                          ? '请到上方隔离复核区选择恢复原实例网络，或在容器已重装时核验旧实例身份。此类告警不能通过放行、忽略或普通标记解决。'
                          : '请根据回执检查节点版本、权限及残留守护进程后重试。标记已解决只归档告警，不会清理程序；风险仍存在时会再次告警。'}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                {alert.container_name && (
                  <button
                    type="button"
                    onClick={() => onSelectContainer({
                      host_id: alert.host_id,
                      runtime: alert.runtime,
                      project: alert.project || '',
                      container_name: alert.container_name || '',
                    })}
                    className="flex min-h-10 items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-950/60 px-3 py-1.5 text-xs font-semibold text-sky-200 transition-colors hover:bg-sky-900/70"
                    title="打开该告警对应的容器详情"
                  >
                    <ArrowUpRight className="h-3.5 w-3.5" />
                    <span>查看容器</span>
                  </button>
                )}
                {prohibitedActivity && (
                  <button
                    type="button"
                    onClick={openQuarantineReview}
                    className="flex min-h-11 items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/50 px-3 py-1.5 text-xs font-semibold text-amber-100 hover:bg-amber-900/70 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-amber-400"
                    aria-controls="quarantine-review"
                    title="前往管理员隔离复核流程"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
                    <span>前往隔离复核</span>
                  </button>
                )}
                {!protectionOnly && <UserNoticeAction alertId={alert.id} onToast={onToast} />}
                {canUseConnlimit && !prohibitedActivity && (connlimitActive ? (
                  <button
                    type="button"
                    disabled={isProcessing || connlimitPending}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'release_container_connlimit' })}
                    className="flex min-h-10 items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/50 px-3 py-1.5 text-xs font-semibold text-amber-200 transition-all hover:bg-amber-900/70 disabled:opacity-50"
                    title="移除本系统创建的临时 TCP 限额"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
                    <span>解除 TCP 限额</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    disabled={isProcessing || connlimitPending}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'apply_container_connlimit' })}
                    className="flex min-h-10 items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/50 px-3 py-1.5 text-xs font-semibold text-amber-200 transition-all hover:bg-amber-900/70 disabled:opacity-50"
                    title="每方向临时限制并发 TCP 新连接；不影响 UDP 和既有连接"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
                    <span>{connlimitPending ? 'TCP 限额处理中...' : '临时 TCP 限额'}</span>
                  </button>
                ))}
                {canRemediate && !prohibitedActivity && <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'deny' })}
                  className="flex min-h-10 items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-950/80 px-3 py-1.5 text-xs font-semibold text-rose-200 transition-all hover:bg-rose-900/90 disabled:opacity-50"
                  title="定向清理恶意进程或停止非合规服务（不停止整个容器）"
                >
                  <Ban className="h-3.5 w-3.5" />
                  <span>
                    {isProcessing
                      ? '处理中...'
                      : isActionFailed
                      ? '重试定向处置'
                      : '定向处置'}
                  </span>
                </button>}

                {canFreezeContainer && !prohibitedActivity && (
                  <button
                    type="button"
                    disabled={isProcessing || freezePending}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'freeze_container' })}
                    className="flex min-h-10 items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-950/80 px-3 py-1.5 text-xs font-semibold text-rose-200 transition-all hover:bg-rose-900/90 disabled:opacity-50"
                    title="挂起冻结该容器实例，立即阻断异常连接并标记告警已处理"
                  >
                    <Ban className="h-3.5 w-3.5" />
                    <span>{freezePending ? '封禁执行中...' : '封禁'}</span>
                  </button>
                )}

                {(!protectionOnly || isSocketAbuseReview) && !prohibitedActivity && <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'allow_silent' })}
                  className="flex min-h-10 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/85 px-2.5 py-1.5 text-xs font-medium text-slate-200 transition-all hover:bg-slate-700 disabled:opacity-50"
                  title={isSocketAbuseReview ? '忽略该容器的此类 Socket 异常提醒（可在告警历史中恢复）' : '放行并永久不再提醒此项告警'}
                >
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span>{isSocketAbuseReview ? '忽略' : '放行策略'}</span>
                </button>}

                {isActionFailed && !prohibitedActivity && (
                  <button
                    type="button"
                    disabled={isProcessing}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'resolve' })}
                    className="flex min-h-10 items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-2.5 py-1.5 text-xs font-semibold text-emerald-300 transition-all hover:bg-emerald-900/60 disabled:opacity-50"
                    title="手动确认问题已处理，直接消除此告警"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    <span>标记已解决</span>
                  </button>
                )}

                {(!protectionOnly || isSocketAbuseReview) && !prohibitedActivity && <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'dismiss_once' })}
                  className="flex min-h-10 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/85 px-2.5 py-1.5 text-xs font-medium text-slate-300 transition-all hover:bg-slate-700 disabled:opacity-50"
                  title={isSocketAbuseReview ? '跳过本次告警提醒，后续状态变化时仍会再次提醒' : '本次临时忽略'}
                >
                  <EyeOff className="h-3.5 w-3.5 text-slate-400" />
                  <span>{isSocketAbuseReview ? '跳过本次' : '本次忽略'}</span>
                </button>}
              </div>
            </div>
          );
        })}
      </div>
      <ConfirmDialog
        open={Boolean(pendingDecision)}
        {...confirmationCopy}
        isSubmitting={pendingDecision ? submittingId === pendingDecision.id : false}
        onCancel={() => setPendingDecision(null)}
        onConfirm={async () => {
          if (!pendingDecision) return;
          const decision = pendingDecision;
          await handleDecision(decision.id, decision.decision);
          setPendingDecision(null);
        }}
      />
    </section>
  );
};
