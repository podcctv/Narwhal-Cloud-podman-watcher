import React, { useState, useEffect } from 'react';
import { Globe, X } from 'lucide-react';
import { ReachCheckSummary } from '../../utils/reachCheck';
import { ReachCheckPanel } from '../tcping/ReachCheckPanel';

interface HostReachabilityBadgeProps {
  hostId: string;
  ip?: string;
  className?: string;
}

export const HostReachabilityBadge: React.FC<HostReachabilityBadgeProps> = ({
  hostId,
  ip,
  className = '',
}) => {
  const [summary, setSummary] = useState<ReachCheckSummary | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const target = ip || hostId;

  // Check sessionStorage for cached reachability results
  useEffect(() => {
    try {
      // Check port 443 then port 22 or other common ports
      for (const p of [443, 80, 22]) {
        const cached = sessionStorage.getItem(`reach:${target}:${p}`);
        if (cached) {
          setSummary(JSON.parse(cached));
          break;
        }
      }
    } catch {}
  }, [target]);

  const badgeStyle = !summary
    ? 'border-slate-700 bg-slate-800/80 text-slate-300 hover:border-slate-600'
    : summary.verdict === 'ok'
    ? 'border-emerald-500/40 bg-emerald-950/60 text-emerald-300 hover:border-emerald-400'
    : summary.verdict === 'gfw_blocked'
    ? 'border-rose-500/50 bg-rose-950/70 text-rose-300 hover:border-rose-400 animate-pulse'
    : 'border-amber-500/40 bg-amber-950/60 text-amber-300 hover:border-amber-400';

  const badgeText = !summary
    ? '可达性检测'
    : summary.verdict === 'ok'
    ? `三网可达 ${summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : ''}`
    : summary.verdict === 'gfw_blocked'
    ? '国内受阻'
    : summary.verdict === 'partial'
    ? '部分受阻'
    : '连接异常';

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setModalOpen(true);
        }}
        className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium transition cursor-pointer ${badgeStyle} ${className}`}
        title="点击查看全球 18 区域与国内三网可达性"
      >
        <Globe className="h-3 w-3 shrink-0" />
        <span>{badgeText}</span>
      </button>

      {/* Modal Dialog */}
      {modalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in"
          onClick={() => setModalOpen(false)}
        >
          <div
            className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="absolute top-4 right-4 rounded-lg p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
              aria-label="关闭"
            >
              <X className="h-5 w-5" />
            </button>

            <ReachCheckPanel
              initialTarget={target}
              initialPort={443}
              availableHosts={[{ id: hostId, name: hostId, ip }]}
            />
          </div>
        </div>
      )}
    </>
  );
};
