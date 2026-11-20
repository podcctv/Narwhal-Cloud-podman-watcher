import React from 'react';
import { CheckCircle2, AlertTriangle, AlertOctagon, HelpCircle, PowerOff, Info } from 'lucide-react';

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

  let colors = 'border-[#cbd7e6] bg-[#eef3f9] text-[#4a607a]';
  let Icon = HelpCircle;
  let defaultLabel = status;

  if (norm === 'healthy' || norm === 'ok' || norm === 'running' || norm === 'active') {
    colors = 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]';
    Icon = CheckCircle2;
    defaultLabel = '正常运行';
  } else if (norm === 'warning' || norm === 'warn' || norm === 'suppressed' || norm === 'dismissed') {
    colors = 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]';
    Icon = AlertTriangle;
    defaultLabel = '注意/告警';
  } else if (norm === 'critical' || norm === 'danger' || norm === 'error' || norm === 'bad') {
    colors = 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]';
    Icon = AlertOctagon;
    defaultLabel = '高危告警';
  } else if (norm === 'info') {
    colors = 'border-[#a9d1ff] bg-[#e8f3ff] text-[#0657b8]';
    Icon = Info;
    defaultLabel = '管控状态';
  } else if (norm === 'offline' || norm === 'stale') {
    colors = 'border-[#cbd7e6] bg-[#eef3f9] text-[#4a607a]';
    Icon = PowerOff;
    defaultLabel = norm === 'stale' ? '采样过期' : '已离线';
  }

  const isSmall = size === 'sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 font-semibold whitespace-nowrap transition-colors ${
        isSmall ? 'py-0.5 text-xs' : 'py-1 text-xs'
      } ${colors}`}
    >
      {pulse && (norm === 'healthy' || norm === 'ok' || norm === 'running') ? (
        <span className="relative flex h-2 w-2 shrink-0" aria-hidden="true">
          <span className="absolute inline-flex h-full w-full animate-ping-slow rounded-full bg-[#147468] opacity-75"></span>
          <span className="relative inline-flex h-2 w-2 rounded-full bg-[#147468]"></span>
        </span>
      ) : (
        <Icon className={isSmall ? 'h-3 w-3 shrink-0' : 'h-3.5 w-3.5 shrink-0'} aria-hidden="true" />
      )}
      <span>{label || defaultLabel}</span>
    </span>
  );
};
