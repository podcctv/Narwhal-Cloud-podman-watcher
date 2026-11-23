import React from 'react';
import { Play, Pause, RotateCw } from 'lucide-react';

interface CountdownTimerProps {
  countdown: number;
  totalSeconds?: number;
  isPaused: boolean;
  onTogglePause: () => void;
  onRefreshNow: () => void;
  isRefreshing: boolean;
  lastRefreshTime?: string;
}

export const CountdownTimer: React.FC<CountdownTimerProps> = ({
  countdown,
  totalSeconds = 10,
  isPaused,
  onTogglePause,
  onRefreshNow,
  isRefreshing,
  lastRefreshTime,
}) => {
  const radius = 10;
  const circumference = 2 * Math.PI * radius;
  const progress = isPaused ? 1 : Math.max(0, countdown / totalSeconds);
  const strokeDashoffset = circumference - progress * circumference;

  return (
    <div
      className="flex h-11 shrink-0 items-center gap-2 rounded-xl border border-[#e2e8f0] bg-[#f8fafc] px-2.5 text-[#0f172a] shadow-2xs"
      role="group"
      aria-label="自动刷新控制"
    >
      {/* Circular Countdown Indicator */}
      <div className="relative flex h-6 w-6 shrink-0 items-center justify-center">
        <svg className="h-6 w-6 -rotate-90 transform" viewBox="0 0 24 24" aria-hidden="true">
          <circle
            cx="12"
            cy="12"
            r={radius}
            className="stroke-[#e2e8f0]"
            strokeWidth="2.5"
            fill="transparent"
          />
          <circle
            cx="12"
            cy="12"
            r={radius}
            className={`transition-all duration-300 ${
              isPaused ? 'stroke-amber-500' : 'stroke-[#4f46e5]'
            }`}
            strokeWidth="2.5"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        <span className="absolute font-mono text-[10px] font-bold tabular-nums text-[#0f172a]">
          {isPaused ? 'P' : Math.ceil(countdown)}
        </span>
      </div>

      <div className="hidden flex-col sm:flex">
        <span className="text-[11px] font-semibold text-[#0f172a]">
          {isPaused ? '自动刷新已暂停' : `实时轮询 (${Math.ceil(countdown)}s)`}
        </span>
        {lastRefreshTime && (
          <span className="font-mono text-[10px] text-[#64748b] tabular-nums">
            {lastRefreshTime}
          </span>
        )}
      </div>

      {/* Control buttons */}
      <div className="flex items-center gap-0.5 border-l border-[#e2e8f0] pl-1">
        <button
          type="button"
          onClick={onTogglePause}
          title={isPaused ? '恢复自动刷新' : '暂停自动刷新'}
          aria-label={isPaused ? '恢复自动刷新' : '暂停自动刷新'}
          className="flex h-9 w-9 items-center justify-center rounded-lg text-[#475569] transition-colors hover:bg-[#eef2ff] hover:text-[#4f46e5] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#4f46e5]"
        >
          {isPaused ? <Play className="h-3.5 w-3.5" aria-hidden="true" /> : <Pause className="h-3.5 w-3.5" aria-hidden="true" />}
        </button>
        <button
          type="button"
          onClick={onRefreshNow}
          disabled={isRefreshing}
          title="立即手动刷新"
          aria-label="立即手动刷新"
          className="flex h-9 w-9 items-center justify-center rounded-lg text-[#475569] transition-colors hover:bg-[#eef2ff] hover:text-[#4f46e5] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#4f46e5] disabled:opacity-50"
        >
          <RotateCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-[#4f46e5]' : ''}`} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
};
