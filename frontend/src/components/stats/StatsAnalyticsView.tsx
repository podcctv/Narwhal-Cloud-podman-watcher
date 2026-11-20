import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  RefreshCw,
  AlertTriangle,
  LoaderCircle,
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getStats(minutes);
      setStats(data);
    } catch (err: any) {
      const message = err?.message || String(err);
      setError(message);
      onToast('error', `加载统计数据失败：${message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const presets = [
    { label: '1h', value: 60 },
    { label: '6h', value: 360 },
    { label: '12h', value: 720 },
    { label: '24h', value: 1440 },
    { label: '7d', value: 10080 },
  ];

  const loadWithMinutes = async (targetMinutes: number) => {
    setMinutes(targetMinutes);
    setLoading(true);
    setError(null);
    try {
      const data = await api.getStats(targetMinutes);
      setStats(data);
    } catch (err: any) {
      const message = err?.message || String(err);
      setError(message);
      onToast('error', `加载统计数据失败：${message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 text-[#0b1636]">
      {/* Header & Controls */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
              <BarChart3 className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block">TELEMETRY ANALYTICS · TOP CONSUMERS</span>
              <h2 className="mt-0.5 text-base font-bold text-white sm:text-lg">数据统计与综合排行分析</h2>
              <p className="mt-0.5 text-xs text-[#b9d3ee]">资源消耗、峰值连接与全网累计流量聚合洞察。</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={loadData}
              disabled={loading}
              className="rn2-btn rn2-btn-blue rn2-btn-sm"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
              <span>刷新</span>
            </button>
            <button
              type="button"
              onClick={onBackToDashboard}
              className="rn2-btn rn2-btn-ghost rn2-btn-sm"
            >
              <span>返回总览</span>
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Light-Ice Time Window Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#dce5ef] bg-white px-5 py-3.5">
          <div
            className="flex flex-wrap items-center gap-1 rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-1"
            role="group"
            aria-label="快捷时间窗口"
          >
            {presets.map((preset) => (
              <button
                key={preset.value}
                type="button"
                onClick={() => void loadWithMinutes(preset.value)}
                disabled={loading}
                aria-pressed={minutes === preset.value}
                className={`min-h-9 rounded-lg px-3 font-mono text-xs font-bold tabular-nums transition-colors ${
                  minutes === preset.value
                    ? 'bg-[#087bff] text-white shadow-xs'
                    : 'text-[#31485e] hover:bg-white hover:text-[#087bff]'
                }`}
              >
                {preset.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs">
            <label htmlFor="stats-minutes-input" className="font-semibold text-[#31485e]">
              统计窗口(分钟):
            </label>
            <input
              id="stats-minutes-input"
              type="number"
              min="5"
              max="10080"
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
              className="rn2-input-sm w-24 font-mono text-xs font-semibold tabular-nums"
            />
          </div>
        </div>

        {/* Light-Ice KPI Spec Strip */}
        <div className="rn2-spec-strip grid-cols-2 bg-[#f4f8fd] divide-x divide-[#d2dfec] sm:grid-cols-4">
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">统计容器数</span>
            <span className="mt-1 block font-mono text-xl font-extrabold text-[#0b1636] tabular-nums sm:text-2xl">
              {stats ? stats.containers_count : '—'}
            </span>
          </div>
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">累计样本数</span>
            <span className="mt-1 block font-mono text-xl font-extrabold text-[#0b1636] tabular-nums sm:text-2xl">
              {stats ? stats.samples_count : '—'}
            </span>
          </div>
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">建议采样间隔</span>
            <span className="mt-1 block font-mono text-xl font-extrabold text-[#087bff] tabular-nums sm:text-2xl">
              {stats?.sample_interval_seconds ? `${stats.sample_interval_seconds}s` : '--'}
            </span>
          </div>
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">有效统计窗口</span>
            <span className="mt-1 block font-mono text-xl font-extrabold text-[#147468] tabular-nums sm:text-2xl">
              {stats?.window_minutes ? `${stats.window_minutes}m` : '--'}
            </span>
          </div>
        </div>
      </section>

      {error && (
        <section
          role="alert"
          aria-live="assertive"
          className="flex flex-col gap-3 rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex min-w-0 items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-[#b41835]" aria-hidden="true" />
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-[#0b1636]">统计数据未能更新</h3>
              <p className="mt-1 break-words text-xs text-[#b41835]">
                {stats ? '仍显示上次成功读取的数据。' : '当前统计结果未知，不能按零值判断。'} {error}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void loadData()}
            disabled={loading}
            className="rn2-btn rn2-btn-danger rn2-btn-sm shrink-0"
          >
            {loading ? '正在重试…' : '重试'}
          </button>
        </section>
      )}

      {loading && !stats && (
        <p
          role="status"
          aria-live="polite"
          className="rounded-xl border border-[#cedae7] bg-white p-6 text-sm font-medium text-[#31485e]"
        >
          <LoaderCircle className="mr-2 inline h-4 w-4 animate-spin text-[#087bff] motion-reduce:animate-none" aria-hidden="true" />
          正在读取统计数据…
        </p>
      )}

      {/* Top 10 CPU Table */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex items-center gap-2.5">
            <Cpu className="h-4.5 w-4.5 text-[#54c7ff]" aria-hidden="true" />
            <div>
              <span className="rn2-eyebrow block">COMPUTE CONSUMPTION</span>
              <h3 className="text-sm font-bold text-white sm:text-base">Top 10：平均 CPU 消耗</h3>
            </div>
          </div>
        </div>

        <div
          tabIndex={0}
          role="region"
          aria-label="Top 10 平均 CPU 消耗表格"
          className="rn2-table-wrap hidden rounded-none border-0 md:block"
        >
          <table className="w-full text-left text-xs">
            <thead className="bg-[#edf5fc] text-[11px] font-bold uppercase tracking-wider text-[#31485e]">
              <tr>
                <th className="px-5 py-3">主机</th>
                <th className="px-5 py-3">运行时</th>
                <th className="px-5 py-3">容器</th>
                <th className="px-5 py-3 text-right">平均 CPU%</th>
                <th className="px-5 py-3 text-right">峰值 CPU%</th>
                <th className="px-5 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {(stats?.cpu_top || []).map((row, idx) => (
                <tr key={idx}>
                  <td className="px-5 py-3 text-[#31485e]">{row.host_id}</td>
                  <td className="px-5 py-3 text-[#506483]">{row.runtime}</td>
                  <td className="px-5 py-3 font-bold text-[#0b1636]">{row.container_name}</td>
                  <td className="px-5 py-3 text-right font-bold text-[#087bff] tabular-nums">
                    {fmtNumber(row.avg_cpu)}%
                  </td>
                  <td className="px-5 py-3 text-right text-[#31485e] tabular-nums">
                    {fmtNumber(row.max_cpu)}%
                  </td>
                  <td className="px-5 py-3 text-right">
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
                      className="rn2-btn rn2-btn-blue rn2-btn-sm"
                    >
                      查看
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="space-y-2.5 p-3.5 md:hidden">
          {(stats?.cpu_top || []).map((row, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() =>
                onSelectContainer({
                  host_id: row.host_id,
                  runtime: row.runtime,
                  project: row.project,
                  container_name: row.container_name,
                })
              }
              className="w-full rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3.5 text-left transition-colors hover:border-[#087bff]"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-mono text-xs text-[#506483]">
                    {row.host_id} · {row.runtime}
                  </p>
                  <p className="mt-1 truncate text-sm font-bold text-[#0b1636]">{row.container_name}</p>
                </div>
                <span className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[#087bff] px-2.5 py-1 text-xs font-semibold text-white">
                  查看
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </span>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-xs tabular-nums">
                <span className="rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] p-2 text-[#0657b8]">
                  平均 <b>{fmtNumber(row.avg_cpu)}%</b>
                </span>
                <span className="rounded-lg border border-[#cedae7] bg-white p-2 text-[#0b1636]">
                  峰值 <b>{fmtNumber(row.max_cpu)}%</b>
                </span>
              </div>
            </button>
          ))}
        </div>
      </section>

      {/* Top 10 Traffic Table */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex items-center gap-2.5">
            <Network className="h-4.5 w-4.5 text-[#54c7ff]" aria-hidden="true" />
            <div>
              <span className="rn2-eyebrow block">NETWORK THROUGHPUT</span>
              <h3 className="text-sm font-bold text-white sm:text-base">Top 10：累计流量消耗</h3>
            </div>
          </div>
        </div>

        <div
          tabIndex={0}
          role="region"
          aria-label="Top 10 累计流量消耗表格"
          className="rn2-table-wrap hidden rounded-none border-0 md:block"
        >
          <table className="w-full text-left text-xs">
            <thead className="bg-[#edf5fc] text-[11px] font-bold uppercase tracking-wider text-[#31485e]">
              <tr>
                <th className="px-5 py-3">主机</th>
                <th className="px-5 py-3">运行时</th>
                <th className="px-5 py-3">容器</th>
                <th className="px-5 py-3 text-right">累计 RX</th>
                <th className="px-5 py-3 text-right">累计 TX</th>
                <th className="px-5 py-3 text-right">累计总流量</th>
                <th className="px-5 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {(stats?.traffic_top || []).map((row, idx) => (
                <tr key={idx}>
                  <td className="px-5 py-3 text-[#31485e]">{row.host_id}</td>
                  <td className="px-5 py-3 text-[#506483]">{row.runtime}</td>
                  <td className="px-5 py-3 font-bold text-[#0b1636]">{row.container_name}</td>
                  <td className="px-5 py-3 text-right font-semibold text-[#147468] tabular-nums">
                    {fmtBytes(row.total_rx_bytes)}
                  </td>
                  <td className="px-5 py-3 text-right font-semibold text-[#087bff] tabular-nums">
                    {fmtBytes(row.total_tx_bytes)}
                  </td>
                  <td className="px-5 py-3 text-right font-bold text-[#0b1636] tabular-nums">
                    {fmtBytes(row.total_bytes)}
                  </td>
                  <td className="px-5 py-3 text-right">
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
                      className="rn2-btn rn2-btn-blue rn2-btn-sm"
                    >
                      查看
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="space-y-2.5 p-3.5 md:hidden">
          {(stats?.traffic_top || []).map((row, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() =>
                onSelectContainer({
                  host_id: row.host_id,
                  runtime: row.runtime,
                  project: row.project,
                  container_name: row.container_name,
                })
              }
              className="w-full rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3.5 text-left transition-colors hover:border-[#087bff]"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate font-mono text-xs text-[#506483]">
                    {row.host_id} · {row.runtime}
                  </p>
                  <p className="mt-1 truncate text-sm font-bold text-[#0b1636]">{row.container_name}</p>
                </div>
                <span className="inline-flex shrink-0 items-center gap-1 rounded-lg bg-[#087bff] px-2.5 py-1 text-xs font-semibold text-white">
                  查看
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </span>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 font-mono text-[11px] tabular-nums">
                <span className="rounded-lg border border-[#9de2d8] bg-[#e6f7f4] p-2 text-[#147468]">
                  RX
                  <br />
                  <b>{fmtBytes(row.total_rx_bytes)}</b>
                </span>
                <span className="rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] p-2 text-[#0657b8]">
                  TX
                  <br />
                  <b>{fmtBytes(row.total_tx_bytes)}</b>
                </span>
                <span className="rounded-lg border border-[#cedae7] bg-white p-2 text-[#0b1636]">
                  合计
                  <br />
                  <b>{fmtBytes(row.total_bytes)}</b>
                </span>
              </div>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
};
