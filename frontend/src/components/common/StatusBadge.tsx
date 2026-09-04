import React from 'react';
import { CheckCircle2, AlertTriangle, AlertOctagon, HelpCircle, PowerOff } from 'lucide-react';

export type BadgeStatus = 'healthy' | 'warning' | 'critical' | 'info' | 'offline' | 'stale';

interface StatusBadgeProps {
  status: BadgeStatus | string;
  label?: string;
  size?: 'sm' | 'md';
  pulse?: boolean;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  label,
  size = 'md',
  pulse = false,
}) => {
  const norm = (status || '').toLowerCase();

  let colors = 'border-slate-700 bg-slate-800/80 text-slate-300';
  let Icon = HelpCircle;
  let defaultLabel = status;

  if (norm === 'healthy' || norm === 'ok' || norm === 'running' || norm === 'active') {
    colors = 'border-emerald-500/30 bg-emerald-950/50 text-emerald-400';
    Icon = CheckCircle2;
    defaultLabel = '正常运行';
  } else if (norm === 'warning' || norm === 'warn' || norm === 'suppressed' || norm === 'dismissed') {
    colors = 'border-amber-500/30 bg-amber-950/50 text-amber-400';
    Icon = AlertTriangle;
    defaultLabel = '注意/告警';
  } else if (norm === 'critical' || norm === 'danger' || norm === 'error' || norm === 'bad') {
    colors = 'border-rose-500/30 bg-rose-950/50 text-rose-400';
    Icon = AlertOctagon;
    defaultLabel = '高危告警';
  } else if (norm === 'offline' || norm === 'stale') {
    colors = 'border-slate-700 bg-slate-900/60 text-slate-400';
    Icon = PowerOff;
    defaultLabel = norm === 'stale' ? '采样过期' : '已离线';
  }

  const isSmall = size === 'sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 font-medium transition-colors ${
        isSmall ? 'py-0.5 text-xs' : 'py-1 text-xs'
      } ${colors}`}
    >
      {pulse && (norm === 'healthy' || norm === 'ok' || norm === 'running') ? (
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
        </span>
      ) : (
        <Icon className={isSmall ? 'h-3 w-3' : 'h-3.5 w-3.5'} />
      )}
      <span>{label || defaultLabel}</span>
    </span>
  );
};
