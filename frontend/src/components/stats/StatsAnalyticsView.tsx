import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  RefreshCw,
  Cpu,
  Network,
  ArrowRight,
} from 'lucide-react';
import { StatsResponse, ContainerIdentity } from '../../api/types';
import { api, fmtBytes, fmtNumber } from '../../api/client';

interface StatsAnalyticsViewProps {
  onSelectContainer: (id: ContainerIdentity) => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onBackToDashboard: () => void;
}

export const StatsAnalyticsView: React.FC<StatsAnalyticsViewProps> = ({
  onSelectContainer,
  onToast,
  onBackToDashboard,
}) => {
  const [minutes, setMinutes] = useState(720);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    if (loading) return;
    setLoading(true);
    try {
      const data = await api.getStats(minutes);
      setStats(data);
    } catch (err: any) {
      onToast('error', `加载统计数据失败：${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-sky-950/80 p-2.5 text-sky-400 border border-sky-500/30">
            <BarChart3 className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">
              数据统计与综合排行分析
            </h2>
            <p className="text-xs text-slate-400">
              资源消耗、峰值连接与全网累计流量聚合洞察。
            </p>
          </div>
        </div>

        {/* Time window selector & buttons */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-xs">
            <label className="text-slate-400">统计窗口(分钟):</label>
            <input
              type="number"
              min="5"
              max="10080"
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
              className="w-24 rounded-lg border border-slate-800 bg-slate-950 px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-sky-500"
            />
          </div>

          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
            <span>刷新</span>
          </button>

          <button
            type="button"
            onClick={onBackToDashboard}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
          >
            <span>返回总览</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-slate-400 block text-[11px]">统计容器数</span>
          <span className="text-xl font-extrabold text-slate-100 mt-1 block tabular-nums">
            {stats?.containers_count || 0}
          </span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-slate-400 block text-[11px]">累计样本数</span>
          <span className="text-xl font-extrabold text-slate-100 mt-1 block tabular-nums">
            {stats?.samples_count || 0}
          </span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-slate-400 block text-[11px]">建议采样间隔</span>
          <span className="text-xl font-extrabold text-sky-400 mt-1 block tabular-nums">
            {stats?.sample_interval_seconds ? `${stats.sample_interval_seconds}s` : '--'}
          </span>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-slate-400 block text-[11px]">有效统计窗口</span>
          <span className="text-xl font-extrabold text-emerald-400 mt-1 block tabular-nums">
            {stats?.window_minutes ? `${stats.window_minutes}m` : '--'}
          </span>
        </div>
      </div>

      {/* Top 10 CPU Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
        <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900/80 px-5 py-3">
          <Cpu className="h-4 w-4 text-sky-400" />
          <h3 className="text-sm font-bold text-slate-100">Top 10：平均 CPU 消耗</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th className="px-5 py-2.5">主机</th>
                <th className="px-5 py-2.5">运行时</th>
                <th className="px-5 py-2.5">容器</th>
                <th className="px-5 py-2.5 text-right">平均 CPU%</th>
                <th className="px-5 py-2.5 text-right">峰值 CPU%</th>
                <th className="px-5 py-2.5 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(stats?.cpu_top || []).map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-5 py-2.5 text-slate-400">{row.host_id}</td>
                  <td className="px-5 py-2.5 text-slate-400">{row.runtime}</td>
                  <td className="px-5 py-2.5 font-semibold text-slate-100">{row.container_name}</td>
                  <td className="px-5 py-2.5 text-right text-sky-400 font-bold tabular-nums">
                    {fmtNumber(row.avg_cpu)}%
                  </td>
                  <td className="px-5 py-2.5 text-right text-slate-300 tabular-nums">
                    {fmtNumber(row.max_cpu)}%
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <button
                      type="button"
                      onClick={() =>
                        onSelectContainer({
                          host_id: row.host_id,
                          runtime: row.runtime,
                          project: row.project,
                          container_name: row.container_name,
                        })
                      }
                      className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] text-sky-400 hover:text-sky-300 hover:border-sky-500 transition-colors"
                    >
                      排查
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top 10 Traffic Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
        <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900/80 px-5 py-3">
          <Network className="h-4 w-4 text-emerald-400" />
          <h3 className="text-sm font-bold text-slate-100">Top 10：累计流量消耗</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th className="px-5 py-2.5">主机</th>
                <th className="px-5 py-2.5">运行时</th>
                <th className="px-5 py-2.5">容器</th>
                <th className="px-5 py-2.5 text-right">累计 RX</th>
                <th className="px-5 py-2.5 text-right">累计 TX</th>
                <th className="px-5 py-2.5 text-right">累计总流量</th>
                <th className="px-5 py-2.5 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(stats?.traffic_top || []).map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-5 py-2.5 text-slate-400">{row.host_id}</td>
                  <td className="px-5 py-2.5 text-slate-400">{row.runtime}</td>
                  <td className="px-5 py-2.5 font-semibold text-slate-100">{row.container_name}</td>
                  <td className="px-5 py-2.5 text-right text-emerald-400 tabular-nums">
                    {fmtBytes(row.total_rx_bytes)}
                  </td>
                  <td className="px-5 py-2.5 text-right text-sky-400 tabular-nums">
                    {fmtBytes(row.total_tx_bytes)}
                  </td>
                  <td className="px-5 py-2.5 text-right font-bold text-slate-100 tabular-nums">
                    {fmtBytes(row.total_bytes)}
                  </td>
                  <td className="px-5 py-2.5 text-right">
                    <button
                      type="button"
                      onClick={() =>
                        onSelectContainer({
                          host_id: row.host_id,
                          runtime: row.runtime,
                          project: row.project,
                          container_name: row.container_name,
                        })
                      }
                      className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] text-sky-400 hover:text-sky-300 hover:border-sky-500 transition-colors"
                    >
                      排查
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
