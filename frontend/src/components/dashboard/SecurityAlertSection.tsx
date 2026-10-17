import React, { useState } from 'react';
import {
  ShieldAlert,
  Ban,
  Check,
  EyeOff,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { SocksPasswordReview } from '../alerts/SocksPasswordReview';
import { UserNoticeAction } from '../alerts/UserNoticeAction';

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

interface SecurityAlertSectionProps {
  alerts: SecurityAlert[];
  onRefresh: () => void;
  onViewAllHistory: () => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const SecurityAlertSection: React.FC<SecurityAlertSectionProps> = ({
  alerts,
  onRefresh,
  onViewAllHistory,
  onToast,
}) => {
  const [submittingId, setSubmittingId] = useState<number | null>(null);
  const [pendingDecision, setPendingDecision] = useState<{
    id: number;
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'resolve' | 'apply_container_connlimit' | 'release_container_connlimit';
  } | null>(null);

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'resolve' | 'apply_container_connlimit' | 'release_container_connlimit'
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

  const confirmationCopy = pendingDecision?.decision === 'deny'
    ? { title: '确认执行定向处置？', description: '仅处理本告警已识别的进程、服务或配置；不会停止整个容器。节点将在下一轮上报时执行并回传结果。', confirmLabel: '确认定向处置', tone: 'danger' as const }
    : pendingDecision?.decision === 'apply_container_connlimit'
    ? { title: '确认临时限制 TCP 新连接？', description: '仅对已核验的 Runman 托管 Incus 实例生效：入站和出站方向各限制为最多 500 条并发 TCP 连接，持续 30 分钟；达到上限后拒绝新的 TCP SYN。已有会话不会被断开，UDP 不受影响。可能影响合法高并发业务；规则可手动撤销并会自动过期。', confirmLabel: '应用 30 分钟限额', tone: 'danger' as const }
    : pendingDecision?.decision === 'release_container_connlimit'
    ? { title: '解除临时 TCP 限额？', description: '只删除本系统为该 Incus 实例创建并带有专属标记的连接限制规则，不改动其他防火墙规则。', confirmLabel: '解除限额', tone: 'primary' as const }
    : pendingDecision?.decision === 'allow_silent'
    ? { title: '确认建立放行策略？', description: '该告警对象将被持续放行且不再提醒。你可在告警历史中随时撤销该策略。', confirmLabel: '确认放行', tone: 'primary' as const }
    : pendingDecision?.decision === 'resolve'
    ? { title: '确认标记为已解决？', description: '该告警将从活动列表移入历史记录；后续再次检测到同类风险时仍会重新告警。', confirmLabel: '标记已解决', tone: 'primary' as const }
    : { title: '确认本次忽略？', description: '仅隐藏当前活动告警。风险仍会被持续采集，并在状态变化后再次提示。', confirmLabel: '本次忽略', tone: 'primary' as const };

  if (alerts.length === 0) {
    return (
      <section className="mb-6 rounded-2xl border border-emerald-500/20 bg-emerald-950/20 p-5 backdrop-blur-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-emerald-500/10 p-2.5 text-emerald-400 border border-emerald-500/30">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-emerald-300">
                当前没有新的活动安全告警
              </h2>
              <p className="text-xs text-emerald-400/80">
                已隔离事件仍需单独复核；没有告警不代表已覆盖所有加密业务行为。
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onViewAllHistory}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <span>查看处置历史</span>
            <ExternalLink className="h-3 w-3" />
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="mb-6 rounded-2xl border border-rose-500/30 bg-slate-900/90 shadow-xl overflow-hidden backdrop-blur-sm">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/60 px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <div className="rounded-lg bg-rose-950/80 p-1.5 text-rose-400 border border-rose-500/40">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <span>安全告警中心</span>
            <span className="rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/40 px-2 py-0.2 text-[11px] font-mono font-bold">
              {alerts.length} 项需处理
            </span>
          </h2>
        </div>

        <button
          type="button"
          onClick={onViewAllHistory}
          className="flex items-center gap-1.5 text-xs font-medium text-sky-400 hover:text-sky-300 transition-colors"
        >
          <span>查看全部告警记录</span>
          <ExternalLink className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Alert List */}
      <div className="divide-y divide-slate-800/80">
        {alerts.map((alert) => {
          const isProcessing = submittingId === alert.id;
          const runtimeText = alert.project
            ? `${alert.runtime}/${alert.project}`
            : alert.runtime;
          const isActionFailed = alert.latest_action?.status === 'failed';
          const canRemediate = hasActionEvidence(alert);
          const connlimitAction = alert.latest_action;
          const connlimitExpiresAt = Number(connlimitAction?.params?.lease_expires_at || 0);
          const connlimitActive = connlimitAction?.action_type === 'apply_container_connlimit'
            && connlimitAction.status === 'succeeded' && connlimitExpiresAt > Math.floor(Date.now() / 1000);
          const connlimitPending = ['apply_container_connlimit', 'release_container_connlimit'].includes(connlimitAction?.action_type || '')
            && ['queued', 'dispatched', 'running'].includes(connlimitAction?.status || '');
          const canUseConnlimit = alert.type === 'container_connection_count'
            && alert.runtime === 'incus' && (alert.project || '') === 'default';

          return (
            <div
              key={alert.id}
              className="p-5 hover:bg-slate-800/30 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              {/* Alert Content */}
              <div className="space-y-2 min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <StatusBadge status={alert.severity} size="sm" />
                  <span className="font-semibold text-sm text-slate-100">
                    {alert.title || alert.type}
                  </span>
                  <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                    {alert.host_id}
                  </span>
                  <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                    {runtimeText}
                  </span>
                  {alert.container_name && (
                    <span className="rounded-md bg-sky-950/60 border border-sky-500/30 px-2 py-0.5 font-mono text-xs text-sky-300">
                      {alert.container_name}
                    </span>
                  )}
                  <span className="text-xs text-slate-500 tabular-nums">
                    出现 {alert.occurrence_count || 1} 次 · 最近 {alert.last_seen_utc8 || '-'}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {alert.message}
                </p>
                <SocksPasswordReview alert={alert} onRefresh={onRefresh} onToast={onToast} />

                {/* Remediation Failure Explanation Banner */}
                {isActionFailed && (
                  <div className="mt-2 rounded-lg border border-rose-500/40 bg-rose-950/40 p-2.5 text-xs flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="font-semibold text-rose-300">
                        前次定向处置未成功：
                      </div>
                      <div className="text-slate-300 font-mono text-[11px] mt-0.5 break-all">
                        {alert.latest_action?.result_message || '节点未返回具体失败原因'}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        请根据回执检查节点版本、权限及残留守护进程后重试。标记已解决只归档告警，不会清理程序；风险仍存在时会再次告警。
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                <UserNoticeAction alertId={alert.id} onToast={onToast} />
                {canUseConnlimit && (connlimitActive ? (
                  <button
                    type="button"
                    disabled={isProcessing || connlimitPending}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'release_container_connlimit' })}
                    className="flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/50 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-900/70 transition-all disabled:opacity-50"
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
                    className="flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-950/50 px-3 py-1.5 text-xs font-semibold text-amber-200 hover:bg-amber-900/70 transition-all disabled:opacity-50"
                    title="每方向临时限制并发 TCP 新连接；不影响 UDP 和既有连接"
                  >
                    <ShieldAlert className="h-3.5 w-3.5" />
                    <span>{connlimitPending ? 'TCP 限额处理中...' : '临时 TCP 限额'}</span>
                  </button>
                ))}
                {canRemediate && <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'deny' })}
                  className="flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-950/80 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-900/90 transition-all disabled:opacity-50"
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

                <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'allow_silent' })}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-all disabled:opacity-50"
                  title="放行并永久不再提醒此项告警"
                >
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span>放行策略</span>
                </button>

                {isActionFailed && (
                  <button
                    type="button"
                    disabled={isProcessing}
                    onClick={() => setPendingDecision({ id: alert.id, decision: 'resolve' })}
                    className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-2.5 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-900/60 transition-all disabled:opacity-50"
                    title="手动确认问题已处理，直接消除此告警"
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    <span>标记已解决</span>
                  </button>
                )}

                <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => setPendingDecision({ id: alert.id, decision: 'dismiss_once' })}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-all disabled:opacity-50"
                  title="本次临时忽略"
                >
                  <EyeOff className="h-3.5 w-3.5 text-slate-400" />
                  <span>本次忽略</span>
                </button>
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
