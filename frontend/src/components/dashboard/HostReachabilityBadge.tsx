import React, { useState, useEffect } from 'react';
import { Globe, X } from 'lucide-react';
import { ReachCheckSummary } from '../../utils/reachCheck';
import { ReachCheckPanel } from '../tcping/ReachCheckPanel';
import { api } from '../../api/client';

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
  const [testedPort, setTestedPort] = useState<number>(443);
  const [modalOpen, setModalOpen] = useState(false);

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
    } catch {}

    // 2. Fetch latest automated check result from server
    let active = true;
    api.getReachabilityHost(hostId)
      .then((res: any) => {
        const item = res?.item || res;
        if (!active || !item || !item.target) return;
        setTestedPort(item.port || 0);
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
          },
          advice: [],
          results: item.results || [],
          checkedAt: (item.checked_at || 0) * 1000,
        });
      })
      .catch(() => {});

    return () => {
      active = false;
    };
  }, [hostId, target]);

  const badgeStyle = !summary
    ? 'border-slate-700 bg-slate-800/80 text-slate-300 hover:border-slate-600'
    : summary.verdict === 'ok'
    ? 'border-emerald-500/40 bg-emerald-950/60 text-emerald-300 hover:border-emerald-400'
    : summary.verdict === 'gfw_blocked'
    ? 'border-rose-500/50 bg-rose-950/70 text-rose-300 hover:border-rose-400 animate-pulse'
    : 'border-amber-500/40 bg-amber-950/60 text-amber-300 hover:border-amber-400';

  const isPing = summary?.protocol === 'PING' || testedPort <= 0;
  const portLabel = isPing ? 'ICMP' : `:${testedPort}`;

  const badgeText = !summary
    ? '可达性检测'
    : summary.verdict === 'ok'
    ? `三网可达 ${summary.stats?.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : ''} (${portLabel})`
    : summary.verdict === 'gfw_blocked'
    ? `国内受阻 (${portLabel})`
    : summary.verdict === 'partial'
    ? `部分受阻 (${portLabel})`
    : `连接异常 (${portLabel})`;

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          setModalOpen(true);
        }}
        className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium transition cursor-pointer ${badgeStyle} ${className}`}
        title={`全球与三网可达性 (随机端口: ${testedPort}) - 点击查看详情`}
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
              initialTarget={summary?.target || target}
              initialPort={testedPort}
              availableHosts={[{ id: hostId, name: hostId, ip }]}
              isLoggedIn={true}
            />
          </div>
        </div>
      )}
    </>
  );
};
