import React, { useState, useEffect, useRef, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { Globe, X, ChevronDown } from 'lucide-react';
import { ReachCheckSummary } from '../../utils/reachCheck';
import { ReachCheckPanel } from '../tcping/ReachCheckPanel';
import { api } from '../../api/client';

interface HostReachabilityBadgeProps {
  hostId: string;
  ip?: string;
  className?: string;
}

function formatAgo(timestampSec: number): string {
  if (!timestampSec) return '暂未巡检';
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - timestampSec);
  if (diff < 60) return '刚刚巡检';
  if (diff < 3600) return `${Math.floor(diff / 60)}分钟前巡检`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}小时前巡检`;
  return `${Math.floor(diff / 86400)}天前巡检`;
}

function getCarrierLatencyColor(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || ms <= 0) return 'text-slate-400';
  if (ms < 80) return 'text-emerald-400';
  if (ms < 180) return 'text-emerald-300';
  if (ms < 280) return 'text-amber-300';
  return 'text-rose-400';
}

function getVerdictTextColor(verdict: string): string {
  if (verdict === 'ok') return 'text-emerald-400';
  if (verdict === 'gfw_blocked') return 'text-rose-400';
  if (verdict === 'partial') return 'text-amber-300';
  return 'text-slate-300';
}

export const HostReachabilityBadge: React.FC<HostReachabilityBadgeProps> = ({
  hostId,
  ip,
  className = '',
}) => {
  const [summary, setSummary] = useState<ReachCheckSummary | null>(null);
  const [testedPort, setTestedPort] = useState<number>(443);
  const [isDualStack, setIsDualStack] = useState<boolean>(false);
  const [statsV6, setStatsV6] = useState<any>(null);
  const [rawItem, setRawItem] = useState<any>(null);

  // Popover state & Portal positioning
  const [popoverOpen, setPopoverOpen] = useState<boolean>(false);
  const [popoverCoords, setPopoverCoords] = useState<{ top: number; left: number; showAbove: boolean } | null>(null);
  const [activeStack, setActiveStack] = useState<'v4' | 'v6'>('v4');

  // Full detailed ReachCheckPanel modal (also Portal mounted to avoid contain:layout clipping)
  const [fullModalOpen, setFullModalOpen] = useState<boolean>(false);

  const triggerRef = useRef<HTMLSpanElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  const target = ip || hostId;

  // 1. Check sessionStorage
  useEffect(() => {
    try {
      for (const p of [testedPort, 443, 80, 22]) {
        const cached = sessionStorage.getItem(`reach:${target}:${p}`);
        if (cached) {
          const parsed = JSON.parse(cached);
          setSummary(parsed);
          setTestedPort(p);
          return;
        }
      }
    } catch { }

    // 2. Fetch latest automated check result from server
    let active = true;
    api.getReachabilityHost(hostId)
      .then((res: any) => {
        const item = res?.item || res;
        if (!active || !item || !item.target) return;
        setRawItem(item);
        setTestedPort(item.port || 0);
        setIsDualStack(Boolean(item.is_dual_stack));
        setStatsV6(item.stats_v6 || null);
        setSummary({
          target: item.target,
          port: item.port || 0,
          protocol: item.protocol || 'TCP',
          verdict: item.verdict,
          verdictLabel: item.verdict_label,
          verdictDescription: item.verdict_desc || item.verdict_description || '',
          stats: {
            total: item.stats?.total || 18,
            success: item.stats?.success ?? item.stats?.ok ?? 0,
            failed: item.stats?.failed ?? ((item.stats?.total || 18) - (item.stats?.success ?? item.stats?.ok ?? 0)),
            cnSuccess: item.stats?.cn_success ?? item.stats?.cnSuccess ?? 0,
            cnTotal: item.stats?.cn_total ?? item.stats?.cnTotal ?? 3,
            cnAverageMs: item.stats?.cnAverageMs ?? item.stats?.cn_avg_ms ?? null,
            globalAverageMs: item.stats?.globalAverageMs ?? item.stats?.global_avg_ms ?? null,
            minLatencyMs: item.stats?.min_ms ?? null,
            maxLatencyMs: item.stats?.max_ms ?? null,
            cnTelecomMs: item.stats?.cnTelecomMs ?? item.stats?.cn_telecom_ms ?? null,
            cnUnicomMs: item.stats?.cnUnicomMs ?? item.stats?.cn_unicom_ms ?? null,
            cnMobileMs: item.stats?.cnMobileMs ?? item.stats?.cn_mobile_ms ?? null,
          },
          advice: [],
          results: item.results || [],
          checkedAt: (item.checked_at || 0) * 1000,
        });
      })
      .catch(() => { });

    return () => {
      active = false;
    };
  }, [hostId, target]);

  // Dynamic positioning for Popover
  const updatePosition = useCallback(() => {
    if (!triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const popoverWidth = Math.min(350, window.innerWidth - 16);
    const popoverHeight = 360;
    const spaceBelow = window.innerHeight - rect.bottom;
    const showAbove = spaceBelow < popoverHeight && rect.top > popoverHeight;

    const top = showAbove
      ? Math.max(8, rect.top - popoverHeight - 8)
      : Math.min(window.innerHeight - 8, rect.bottom + 8);
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - popoverWidth - 8));

    setPopoverCoords({ top, left, showAbove });
  }, []);

  useEffect(() => {
    if (!popoverOpen) return;
    updatePosition();

    const handlePointerDown = (e: MouseEvent | TouchEvent) => {
      const targetEl = e.target as Node;
      if (popoverRef.current && popoverRef.current.contains(targetEl)) return;
      if (triggerRef.current && triggerRef.current.contains(targetEl)) return;
      setPopoverOpen(false);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setPopoverOpen(false);
      }
    };

    const handleScrollOrResize = () => {
      updatePosition();
    };

    window.addEventListener('pointerdown', handlePointerDown, { passive: true });
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('scroll', handleScrollOrResize, { passive: true, capture: true });
    window.addEventListener('resize', handleScrollOrResize, { passive: true });

    return () => {
      window.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('scroll', handleScrollOrResize, true);
      window.removeEventListener('resize', handleScrollOrResize);
    };
  }, [popoverOpen, updatePosition]);

  // Badge visual theme tokens (Option A - Aurora Pulse Capsule)
  const isPing = summary?.protocol === 'PING' || testedPort <= 0;
  const portLabel = isPing ? 'ICMP' : `:${testedPort}`;

  const v4Latency = summary?.stats?.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : '';
  const v6Latency = (statsV6?.cnAverageMs ?? statsV6?.cn_avg_ms) ? `${statsV6.cnAverageMs ?? statsV6.cn_avg_ms}ms` : '';

  let badgeStyle = 'border-slate-700 bg-slate-900/80 text-slate-300 hover:border-slate-600';
  let pulseColor = 'bg-slate-400';
  let dotColor = 'bg-slate-500';

  if (summary) {
    if (summary.verdict === 'ok') {
      badgeStyle =
        'border-emerald-500/40 bg-gradient-to-r from-emerald-950/70 via-slate-900/80 to-emerald-950/70 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.15)] hover:border-emerald-400 hover:shadow-[0_0_16px_rgba(16,185,129,0.3)]';
      pulseColor = 'bg-emerald-400';
      dotColor = 'bg-emerald-500';
    } else if (summary.verdict === 'gfw_blocked') {
      badgeStyle =
        'border-rose-500/50 bg-gradient-to-r from-rose-950/80 via-slate-900/80 to-rose-950/80 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.2)] hover:border-rose-400 animate-pulse';
      pulseColor = 'bg-rose-400';
      dotColor = 'bg-rose-500';
    } else {
      badgeStyle =
        'border-amber-500/40 bg-gradient-to-r from-amber-950/70 via-slate-900/80 to-amber-950/70 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.15)] hover:border-amber-400';
      pulseColor = 'bg-amber-400';
      dotColor = 'bg-amber-500';
    }
  }

  const badgeText = !summary
    ? '可达性检测'
    : isDualStack && v4Latency && v6Latency
      ? `三网双栈 (V4: ${v4Latency} | V6: ${v6Latency})`
      : summary.verdict === 'ok'
          ? `三网可达 ${v4Latency}`
          : summary.verdict === 'gfw_blocked'
              ? '国内受阻'
              : summary.verdict === 'partial'
    ?`部分受阻 ${v4Latency}`
    : '连接异常';

// Active stack data for Popover
const currentStats = activeStack === 'v6' && statsV6 ? statsV6 : summary?.stats;
const displayTelecomMs = currentStats?.cnTelecomMs ?? currentStats?.cn_telecom_ms ?? null;
const displayUnicomMs = currentStats?.cnUnicomMs ?? currentStats?.cn_unicom_ms ?? null;
const displayMobileMs = currentStats?.cnMobileMs ?? currentStats?.cn_mobile_ms ?? null;
const displayGlobalAvg = currentStats?.globalAverageMs ?? currentStats?.global_avg_ms ?? null;
const displayMinMs = currentStats?.minLatencyMs ?? currentStats?.min_ms ?? null;

const displayVerdict = (activeStack === 'v6' ? rawItem?.verdict_v6 : summary?.verdict) || summary?.verdict || 'ok';
const displayVerdictLabel = (activeStack === 'v6' ? rawItem?.verdict_label_v6 : summary?.verdictLabel) || summary?.verdictLabel || '三网通畅';
const displayVerdictDesc = (activeStack === 'v6' ? rawItem?.verdict_desc_v6 : summary?.verdictDescription) || summary?.verdictDescription || '';

const checkedEpochSec = rawItem?.checked_at || (summary?.checkedAt ? Math.floor(summary.checkedAt / 1000) : 0);
const timeAgoText = formatAgo(checkedEpochSec);

const statusBadgeStyle =
  displayVerdict === 'ok'
    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60'
    : displayVerdict === 'gfw_blocked'
      ? 'bg-rose-950/80 text-rose-300 border-rose-800/60'
      : 'bg-amber-950/80 text-amber-300 border-amber-800/60';

return (
  <>
      {/* 
        Badge Trigger: 
        Uses <span role="button" tabIndex={0}> to eliminate button-in-button nesting 
        inside host accordion bar and prevent event bubbling.
      */}
      <span
      ref={triggerRef}
      role="button"
      tabIndex={0}
      onClick={(e) => {
        e.stopPropagation();
        setPopoverOpen((prev) => !prev);
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          e.stopPropagation();
          setPopoverOpen((prev) => !prev);
        }
      }}
      className={`group relative inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition-all duration-200 cursor-pointer select-none ${badgeStyle} ${className}`}
      title={`全球与三网实时可达性 (端口: ${portLabel}) - 点击查看三网微详情`}
      aria-haspopup="dialog"
      aria-expanded={popoverOpen}
    >
      {/* Breathing Dual Pulse Dots */}
      <span className="relative flex h-2 w-2 shrink-0">
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${pulseColor}`} />
        <span className={`relative inline-flex rounded-full h-2 w-2 ${dotColor}`} />
      </span>

      <Globe className="h-3 w-3 shrink-0" />
    <span className="font-semibold text-white tracking-tight">{badgeText}</span>
    <span className="font-mono text-[10px] opacity-80 bg-black/20 px-1 py-0.2 rounded border border-white/10">
      {portLabel}
    </span>

      <ChevronDown
        className={`h-3 w-3 shrink-0 transition-transform duration-200 opacity-70 group-hover:opacity-100 ${popoverOpen ? 'rotate-180 text-white' : ''
          }`}
      />
      </span >

{/* 
        POPOVER (小浮窗) - Option A: Aurora Bento Capsule
        Mounted via ReactDOM.createPortal directly to document.body,
        completely escaping any ancestor contain:layout or overflow:hidden constraints!
      */}
{
  popoverOpen && popoverCoords && createPortal(
    <div
      ref={popoverRef}
      role="dialog"
      aria-label="三网实时时延浮窗"
      style={{
        position: 'fixed',
        top: `${popoverCoords.top}px`,
        left: `${popoverCoords.left}px`,
        width: '344px',
        maxWidth: 'calc(100vw - 16px)',
      }}
      className="z-[9999] rounded-2xl border border-slate-700/80 bg-slate-900/96 p-4 shadow-2xl backdrop-blur-xl ring-1 ring-white/10 text-slate-100 animate-fade-in"
      onClick={(e) => e.stopPropagation()}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 pb-2.5 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className={`h-2 w-2 rounded-full shrink-0 ${dotColor}`} />
            <span className="text-xs font-bold text-white tracking-tight">全球与三网实时可达性</span>
            <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-medium border ${statusBadgeStyle}`}>
              {displayVerdictLabel}
            </span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate max-w-[250px]" title={hostId}>
            {hostId} · {isPing ? '智能 ICMP' : `TCP :${testedPort}`}
          </div>
        </div>
        <button
          type="button"
          onClick={() => setPopoverOpen(false)}
          className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition cursor-pointer shrink-0"
          aria-label="关闭浮窗"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Dual Stack Switcher (if dual stack is present) */}
      {isDualStack && (
        <div className="flex items-center gap-1 mt-2.5 bg-slate-950/70 p-1 rounded-lg border border-slate-800 text-[11px]">
          <span className="text-slate-500 text-[10px] px-1.5 font-medium">协议栈:</span>
          <button
            type="button"
            onClick={() => setActiveStack('v4')}
            className={`flex-1 py-0.5 rounded text-center font-mono font-medium transition cursor-pointer ${activeStack === 'v4'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200'
              }`}
          >
            IPv4 {v4Latency ? `(${v4Latency})` : ''}
          </button>
          <button
            type="button"
            onClick={() => setActiveStack('v6')}
            className={`flex-1 py-0.5 rounded text-center font-mono font-medium transition cursor-pointer ${activeStack === 'v6'
                ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30 font-bold'
                : 'text-slate-400 hover:text-slate-200'
              }`}
          >
            IPv6 {v6Latency ? `(${v6Latency})` : ''}
          </button>
        </div>
      )}

      {/* 3-Carrier Bento Cards (China Telecom / Unicom / Mobile) */}
      <div className="grid grid-cols-3 gap-2 my-3">
        {/* China Telecom */}
        <div className="bg-gradient-to-b from-slate-950 to-slate-900/90 border border-slate-800/80 rounded-xl p-2.5 text-center relative overflow-hidden group hover:border-blue-500/40 transition">
          <div className="text-[10px] font-medium text-slate-400 flex items-center justify-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0" />
            <span>中国电信</span>
          </div>
          <div className={`text-sm font-bold font-mono tabular-nums mt-1 ${getCarrierLatencyColor(displayTelecomMs)}`}>
            {displayTelecomMs !== null && displayTelecomMs !== undefined && displayTelecomMs > 0 ? (
              <>{displayTelecomMs}<span className="text-[10px] text-slate-400 ml-0.5">ms</span></>
            ) : (
              <span className="text-xs text-slate-500">未采</span>
            )}
          </div>
          <div className="text-[9px] text-emerald-400/90 mt-0.5 font-mono">
            {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
          </div>
        </div>

        {/* China Unicom */}
        <div className="bg-gradient-to-b from-slate-950 to-slate-900/90 border border-slate-800/80 rounded-xl p-2.5 text-center relative overflow-hidden group hover:border-sky-500/40 transition">
          <div className="text-[10px] font-medium text-slate-400 flex items-center justify-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shrink-0" />
            <span>中国联通</span>
          </div>
          <div className={`text-sm font-bold font-mono tabular-nums mt-1 ${getCarrierLatencyColor(displayUnicomMs)}`}>
            {displayUnicomMs !== null && displayUnicomMs !== undefined && displayUnicomMs > 0 ? (
              <>{displayUnicomMs}<span className="text-[10px] text-slate-400 ml-0.5">ms</span></>
            ) : (
              <span className="text-xs text-slate-500">未采</span>
            )}
          </div>
          <div className="text-[9px] text-emerald-400/90 mt-0.5 font-mono">
            {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
          </div>
        </div>

        {/* China Mobile */}
        <div className="bg-gradient-to-b from-slate-950 to-slate-900/90 border border-slate-800/80 rounded-xl p-2.5 text-center relative overflow-hidden group hover:border-violet-500/40 transition">
          <div className="text-[10px] font-medium text-slate-400 flex items-center justify-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400 shrink-0" />
            <span>中国移动</span>
          </div>
          <div className={`text-sm font-bold font-mono tabular-nums mt-1 ${getCarrierLatencyColor(displayMobileMs)}`}>
            {displayMobileMs !== null && displayMobileMs !== undefined && displayMobileMs > 0 ? (
              <>{displayMobileMs}<span className="text-[10px] text-slate-400 ml-0.5">ms</span></>
            ) : (
              <span className="text-xs text-slate-500">未采</span>
            )}
          </div>
          <div className="text-[9px] text-emerald-400/90 mt-0.5 font-mono">
            {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
          </div>
        </div>
      </div>

      {/* Metric Details Strip */}
      <div className="bg-slate-950/70 rounded-xl p-2.5 border border-slate-800/80 text-[11px] space-y-1.5">
        <div className="flex items-center justify-between text-slate-400">
          <span>全球 18 节点均延</span>
          <span className="font-mono text-slate-200 font-bold tabular-nums">
            {displayGlobalAvg !== null ? `${displayGlobalAvg} ms` : '未测'}
            {displayMinMs !== null && ` (最优 ${displayMinMs}ms)`}
          </span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>GFW 阻断状态</span>
          <span className={`font-medium flex items-center gap-1 ${getVerdictTextColor(displayVerdict)}`}>
            {displayVerdictDesc || displayVerdictLabel || '正常可达'}
          </span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span>双栈网络</span>
          <span className="text-sky-300 font-mono text-[10px]">
            {isDualStack ? 'IPv4 + IPv6 双栈已通' : '单栈 IPv4'}
          </span>
        </div>
      </div>

      {/* Footer Actions */}
      <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-slate-800/80 text-[11px]">
        <span className="text-slate-500 font-mono">{timeAgoText}</span>
        <div className="flex items-center gap-3">
          <a
            href="/tcping"
            className="text-slate-400 hover:text-slate-200 transition"
          >
            TCP 测速
          </a>
          <button
            type="button"
            onClick={() => {
              setPopoverOpen(false);
              setFullModalOpen(true);
            }}
            className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-medium transition cursor-pointer"
          >
            <span>全网拓扑 →</span>
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}

{/* 
        Full ReachCheckPanel Modal
        Also mounted via createPortal to document.body!
      */}
{
  fullModalOpen && createPortal(
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-[10000] flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in"
      onClick={() => setFullModalOpen(false)}
    >
      <div
        className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={() => setFullModalOpen(false)}
          className="absolute top-4 right-4 rounded-lg p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition cursor-pointer"
          aria-label="关闭"
        >
          <X className="h-5 w-5" />
        </button>

        <ReachCheckPanel
          initialTarget={summary?.target || target}
          initialPort={testedPort}
          availableHosts={[{ id: hostId, name: hostId, ip }]}
          isLoggedIn={true}
        />
      </div>
        </div >,
    document.body
  )
}
    </>
  );
};
