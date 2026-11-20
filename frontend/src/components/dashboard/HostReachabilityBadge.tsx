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
  surface?: 'midnight' | 'light';
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
  if (ms === null || ms === undefined || ms <= 0) return 'text-[#697b9c]';
  if (ms < 80) return 'text-[#147468]';
  if (ms < 180) return 'text-[#0657b8]';
  if (ms < 280) return 'text-[#9a5b00]';
  return 'text-[#b41835]';
}

function getVerdictTextColor(verdict: string): string {
  if (verdict === 'ok') return 'text-[#147468]';
  if (verdict === 'gfw_blocked') return 'text-[#b41835]';
  if (verdict === 'partial') return 'text-[#9a5b00]';
  return 'text-[#31485e]';
}

export const HostReachabilityBadge: React.FC<HostReachabilityBadgeProps> = ({
  hostId,
  ip,
  className = '',
  surface = 'midnight',
}) => {
  const [summary, setSummary] = useState<ReachCheckSummary | null>(null);
  const [testedPort, setTestedPort] = useState<number>(443);
  const [isDualStack, setIsDualStack] = useState<boolean>(false);
  const [statsV6, setStatsV6] = useState<any>(null);
  const [rawItem, setRawItem] = useState<any>(null);

  const [popoverOpen, setPopoverOpen] = useState<boolean>(false);
  const [popoverCoords, setPopoverCoords] = useState<{ top: number; left: number; showAbove: boolean } | null>(null);
  const [activeStack, setActiveStack] = useState<'v4' | 'v6'>('v4');
  const [fullModalOpen, setFullModalOpen] = useState<boolean>(false);

  const triggerRef = useRef<HTMLSpanElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  const target = ip || hostId;

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

  const isPing = summary?.protocol === 'PING' || testedPort <= 0;
  const portLabel = isPing ? 'ICMP' : `:${testedPort}`;

  const v4Latency = summary?.stats?.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : '';
  const v6Latency = (statsV6?.cnAverageMs ?? statsV6?.cn_avg_ms) ? `${statsV6.cnAverageMs ?? statsV6.cn_avg_ms}ms` : '';

  const isLightSurface = surface === 'light';
  let badgeStyle = isLightSurface
    ? 'border-[#cedae7] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff]'
    : 'border-[#54c7ff]/35 bg-[#02182f]/80 text-[#e6f4ff] hover:border-[#54c7ff]';
  let dotColor = 'bg-[#697b9c]';

  if (summary) {
    if (summary.verdict === 'ok') {
      badgeStyle = isLightSurface
        ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468] hover:border-[#147468]'
        : 'border-emerald-400/55 bg-emerald-500/20 text-emerald-100 hover:border-emerald-300';
      dotColor = 'bg-emerald-400';
    } else if (summary.verdict === 'gfw_blocked') {
      badgeStyle = isLightSurface
        ? 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835] hover:border-[#dc2626]'
        : 'border-rose-400/65 bg-rose-500/25 text-rose-100 hover:border-rose-300';
      dotColor = 'bg-rose-400';
    } else {
      badgeStyle = isLightSurface
        ? 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00] hover:border-[#d97706]'
        : 'border-amber-400/55 bg-amber-500/20 text-amber-100 hover:border-amber-300';
      dotColor = 'bg-amber-400';
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
    ? `部分受阻 ${v4Latency}`
    : '连接异常';

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
      ? 'border-emerald-400/50 bg-emerald-500/25 text-emerald-100'
      : displayVerdict === 'gfw_blocked'
        ? 'border-rose-400/50 bg-rose-500/25 text-rose-100'
        : 'border-amber-400/50 bg-amber-500/25 text-amber-100';

  return (
    <>
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
        className={`group relative inline-flex cursor-pointer select-none items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold transition-colors ${badgeStyle} ${className}`}
        title={`全球与三网实时可达性 (端口: ${portLabel}) - 点击查看三网微详情`}
        aria-haspopup="dialog"
        aria-expanded={popoverOpen}
      >
        <span className={`relative inline-flex h-2 w-2 shrink-0 rounded-full ${dotColor}`} aria-hidden="true" />
        <Globe className="h-3 w-3 shrink-0" aria-hidden="true" />
        <span className="tracking-tight">{badgeText}</span>
        <span
          className={`rounded border px-1 py-0.2 font-mono text-[10px] ${
            isLightSurface
              ? 'border-[#cedae7] bg-white text-[#4a607a]'
              : 'border-white/20 bg-black/25 text-[#cde8ff]'
          }`}
        >
          {portLabel}
        </span>
        <ChevronDown
          className={`h-3 w-3 shrink-0 opacity-75 transition-transform duration-200 group-hover:opacity-100 ${popoverOpen ? 'rotate-180' : ''}`}
          aria-hidden="true"
        />
      </span>

      {popoverOpen && popoverCoords && createPortal(
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
          className="rn2-card z-[9999] overflow-hidden shadow-[0_22px_54px_rgba(3,24,46,0.34)]"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Midnight Popover Header */}
          <div className="flex items-start justify-between gap-2 bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] px-4 py-3 text-[#e6f4ff]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className={`h-2 w-2 shrink-0 rounded-full ${dotColor}`} />
                <span className="text-xs font-bold tracking-tight text-white">全球与三网实时可达性</span>
                <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none ${statusBadgeStyle}`}>
                  {displayVerdictLabel}
                </span>
              </div>
              <div className="mt-0.5 max-w-[250px] truncate font-mono text-[11px] text-[#b9d3ee]" title={hostId}>
                {hostId} · {isPing ? '智能 ICMP' : `TCP :${testedPort}`}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setPopoverOpen(false)}
              className="shrink-0 rounded-lg border border-white/15 bg-white/10 p-1 text-[#cde8ff] transition-colors hover:bg-white/20 hover:text-white"
              aria-label="关闭浮窗"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>

          <div className="bg-white p-3.5 text-[#0b1636]">
            {isDualStack && (
              <div className="mb-3 flex items-center gap-1 rounded-lg border border-[#cedae7] bg-[#f4f8fd] p-1 text-[11px]">
                <span className="px-1.5 text-[10px] font-semibold text-[#697b9c]">协议栈:</span>
                <button
                  type="button"
                  onClick={() => setActiveStack('v4')}
                  className={`flex-1 rounded py-1 text-center font-mono font-semibold transition ${
                    activeStack === 'v4'
                      ? 'bg-[#087bff] text-white shadow-xs'
                      : 'text-[#4a607a] hover:text-[#0b1636]'
                  }`}
                >
                  IPv4 {v4Latency ? `(${v4Latency})` : ''}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveStack('v6')}
                  className={`flex-1 rounded py-1 text-center font-mono font-semibold transition ${
                    activeStack === 'v6'
                      ? 'bg-[#087bff] text-white shadow-xs'
                      : 'text-[#4a607a] hover:text-[#0b1636]'
                  }`}
                >
                  IPv6 {v6Latency ? `(${v6Latency})` : ''}
                </button>
              </div>
            )}

            {/* 3-Carrier Cards */}
            <div className="grid grid-cols-3 gap-2">
              <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-center">
                <div className="flex items-center justify-center gap-1 text-[10px] font-semibold text-[#4a607a]">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#087bff]" />
                  <span>中国电信</span>
                </div>
                <div className={`mt-1 font-mono text-sm font-extrabold tabular-nums ${getCarrierLatencyColor(displayTelecomMs)}`}>
                  {displayTelecomMs !== null && displayTelecomMs !== undefined && displayTelecomMs > 0 ? (
                    <>{displayTelecomMs}<span className="ml-0.5 text-[10px] font-normal text-[#697b9c]">ms</span></>
                  ) : (
                    <span className="text-xs text-[#697b9c]">未采</span>
                  )}
                </div>
                <div className="mt-0.5 font-mono text-[9px] font-semibold text-[#147468]">
                  {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
                </div>
              </div>

              <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-center">
                <div className="flex items-center justify-center gap-1 text-[10px] font-semibold text-[#4a607a]">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#00b6ec]" />
                  <span>中国联通</span>
                </div>
                <div className={`mt-1 font-mono text-sm font-extrabold tabular-nums ${getCarrierLatencyColor(displayUnicomMs)}`}>
                  {displayUnicomMs !== null && displayUnicomMs !== undefined && displayUnicomMs > 0 ? (
                    <>{displayUnicomMs}<span className="ml-0.5 text-[10px] font-normal text-[#697b9c]">ms</span></>
                  ) : (
                    <span className="text-xs text-[#697b9c]">未采</span>
                  )}
                </div>
                <div className="mt-0.5 font-mono text-[9px] font-semibold text-[#147468]">
                  {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
                </div>
              </div>

              <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-center">
                <div className="flex items-center justify-center gap-1 text-[10px] font-semibold text-[#4a607a]">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-violet-500" />
                  <span>中国移动</span>
                </div>
                <div className={`mt-1 font-mono text-sm font-extrabold tabular-nums ${getCarrierLatencyColor(displayMobileMs)}`}>
                  {displayMobileMs !== null && displayMobileMs !== undefined && displayMobileMs > 0 ? (
                    <>{displayMobileMs}<span className="ml-0.5 text-[10px] font-normal text-[#697b9c]">ms</span></>
                  ) : (
                    <span className="text-xs text-[#697b9c]">未采</span>
                  )}
                </div>
                <div className="mt-0.5 font-mono text-[9px] font-semibold text-[#147468]">
                  {displayVerdict === 'gfw_blocked' ? '受阻' : '0% 丢包'}
                </div>
              </div>
            </div>

            {/* Metric Details Strip */}
            <div className="mt-3 space-y-1.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-2.5 text-[11px]">
              <div className="flex items-center justify-between text-[#4a607a]">
                <span>全球 18 节点均延</span>
                <span className="font-mono font-bold text-[#0b1636] tabular-nums">
                  {displayGlobalAvg !== null ? `${displayGlobalAvg} ms` : '未测'}
                  {displayMinMs !== null && ` (最优 ${displayMinMs}ms)`}
                </span>
              </div>
              <div className="flex items-center justify-between text-[#4a607a]">
                <span>GFW 阻断状态</span>
                <span className={`font-semibold ${getVerdictTextColor(displayVerdict)}`}>
                  {displayVerdictDesc || displayVerdictLabel || '正常可达'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[#4a607a]">
                <span>双栈网络</span>
                <span className="font-mono text-[10px] font-semibold text-[#0657b8]">
                  {isDualStack ? 'IPv4 + IPv6 双栈已通' : '单栈 IPv4'}
                </span>
              </div>
            </div>

            {/* Footer Actions */}
            <div className="mt-3 flex items-center justify-between border-t border-[#dce5ef] pt-2.5 text-[11px]">
              <span className="font-mono text-[#697b9c]">{timeAgoText}</span>
              <div className="flex items-center gap-3">
                <a href="/tcping" className="font-medium text-[#4a607a] hover:text-[#087bff]">
                  TCP 测速
                </a>
                <button
                  type="button"
                  onClick={() => {
                    setPopoverOpen(false);
                    setFullModalOpen(true);
                  }}
                  className="inline-flex cursor-pointer items-center gap-1 font-bold text-[#087bff] hover:text-[#0657b8]"
                >
                  <span>全网拓扑 →</span>
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {/* Full ReachCheckPanel Modal (ReachCheckPanel keeps dark internal palette, so wrap in dark shell for legible contrast) */}
      {fullModalOpen && createPortal(
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-[10000] flex items-center justify-center bg-[#02182f]/75 p-4 backdrop-blur-sm"
          onClick={() => setFullModalOpen(false)}
        >
          <div
            className="rn2-dark-zone relative max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-2xl border border-[#54c7ff]/30 bg-[#02182f] p-6 text-slate-100 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => setFullModalOpen(false)}
              className="absolute right-4 top-4 cursor-pointer rounded-lg p-1.5 text-slate-300 transition hover:bg-white/10 hover:text-white"
              aria-label="关闭"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>

            <ReachCheckPanel
              initialTarget={summary?.target || target}
              initialPort={testedPort}
              availableHosts={[{ id: hostId, name: hostId, ip }]}
              isLoggedIn={true}
            />
          </div>
        </div>,
        document.body
      )}
    </>
  );
};
