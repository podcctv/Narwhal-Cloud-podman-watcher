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

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'resolve'
  ) => {
    setSubmittingId(alertId);
    try {
      const res = await api.dispositionAlert(alertId, decision);
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
                系统当前安全状态良好
              </h2>
              <p className="text-xs text-emerald-400/80">
                未检测到恶意挖矿、非法面板对接或弱口令/无认证 SOCKS 代理行为。
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

                {/* Remediation Failure Explanation Banner */}
                {isActionFailed && (
                  <div className="mt-2 rounded-lg border border-rose-500/40 bg-rose-950/40 p-2.5 text-xs flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="font-semibold text-rose-300">
                        前次定向处置未成功（节点报告无变更）：
                      </div>
                      <div className="text-slate-300 font-mono text-[11px] mt-0.5 break-all">
                        {alert.latest_action?.result_message || '未匹配到可清理的进程或服务'}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        已优化深度查杀机制。可直接点击“重试定向处置”强制杀灭，或点击“标记已解决”消除告警。
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 shrink-0 flex-wrap">
                <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => handleDecision(alert.id, 'deny')}
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
                </button>

                <button
                  type="button"
                  disabled={isProcessing}
                  onClick={() => handleDecision(alert.id, 'allow_silent')}
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
                    onClick={() => handleDecision(alert.id, 'resolve')}
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
                  onClick={() => handleDecision(alert.id, 'dismiss_once')}
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
    </section>
  );
};
