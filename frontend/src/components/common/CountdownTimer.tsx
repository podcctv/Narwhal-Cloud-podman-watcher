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
    <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/90 px-2.5 py-1.5 shadow-sm">
      {/* Circular Countdown Indicator */}
      <div className="relative flex h-6 w-6 items-center justify-center">
        <svg className="h-6 w-6 -rotate-90 transform" viewBox="0 0 24 24">
          <circle
            cx="12"
            cy="12"
            r={radius}
            className="stroke-slate-800"
            strokeWidth="2.5"
            fill="transparent"
          />
          <circle
            cx="12"
            cy="12"
            r={radius}
            className={`transition-all duration-300 ${
              isPaused ? 'stroke-amber-400' : 'stroke-sky-400'
            }`}
            strokeWidth="2.5"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>
        <span className="absolute font-mono text-[10px] font-bold tabular-nums text-slate-300">
          {isPaused ? 'P' : Math.ceil(countdown)}
        </span>
      </div>

      <div className="hidden flex-col sm:flex">
        <span className="text-[11px] font-medium text-slate-300">
          {isPaused ? '自动刷新已暂停' : `自动轮询 (${Math.ceil(countdown)}s)`}
        </span>
        {lastRefreshTime && (
          <span className="text-[10px] text-slate-500 tabular-nums">
            {lastRefreshTime}
          </span>
        )}
      </div>

      {/* Control buttons */}
      <div className="flex items-center gap-1 border-l border-slate-800 pl-2">
        <button
          type="button"
          onClick={onTogglePause}
          title={isPaused ? '恢复自动刷新' : '暂停自动刷新'}
          className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors focus:outline-none focus:ring-1 focus:ring-sky-400"
        >
          {isPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
        </button>
        <button
          type="button"
          onClick={onRefreshNow}
          disabled={isRefreshing}
          title="立即手动刷新"
          className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-sky-300 transition-colors focus:outline-none focus:ring-1 focus:ring-sky-400 disabled:opacity-50"
        >
          <RotateCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
        </button>
      </div>
    </div>
  );
};
