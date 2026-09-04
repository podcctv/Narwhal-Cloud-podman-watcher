import React from 'react';
import { Activity, ArrowDown, ArrowUp } from 'lucide-react';
import { SecurityStatusItem } from '../../api/types';
import { fmtBytes, fmtNetSpeed, fmtNumber } from '../../api/client';

interface TelemetrySectionProps {
  telemetry: SecurityStatusItem[];
}

export const TelemetrySection: React.FC<TelemetrySectionProps> = ({ telemetry }) => {
  if (!telemetry || telemetry.length === 0) return null;

  return (
    <section className="mb-6 rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/80 px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <div className="rounded-lg bg-sky-950/60 p-1.5 text-sky-400 border border-sky-500/30">
            <Activity className="h-4 w-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">主机网络与安全遥测</h2>
            <p className="text-[11px] text-slate-400">
              实时监控主机下行/上行网络速率与当天峰值连接数、独立入站/出站 IP 统计
            </p>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="border-b border-slate-800 bg-slate-950/70 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            <tr>
              <th className="px-5 py-3.5 whitespace-nowrap">主机</th>
              <th className="px-4 py-3.5 text-right whitespace-nowrap">实时速率 (下行 / 上行)</th>
              <th className="px-4 py-3.5 text-right whitespace-nowrap">当天最高下载</th>
              <th className="px-4 py-3.5 text-right whitespace-nowrap">当天最高上传</th>
              <th className="px-4 py-3.5 text-center whitespace-nowrap">当天最高连接</th>
              <th className="px-4 py-3.5 text-center whitespace-nowrap">最高入站 IP</th>
              <th className="px-4 py-3.5 text-center whitespace-nowrap">最高出站 IP</th>
              <th className="px-4 py-3.5 text-center whitespace-nowrap">访问日志</th>
              <th className="px-5 py-3.5 text-right whitespace-nowrap">采样时间</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {telemetry.map((t) => {
              const curRx = fmtNetSpeed(t.rx_bps);
              const curTx = fmtNetSpeed(t.tx_bps);
              const peakRx = fmtNetSpeed(t.today_peak_rx_bps);
              const peakTx = fmtNetSpeed(t.today_peak_tx_bps);
              const synAlert = t.syn_recv > 50;

              return (
                <tr key={t.host_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-5 py-3 whitespace-nowrap font-medium text-slate-200">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-100">{t.host_id}</span>
                      {synAlert && (
                        <span className="rounded bg-rose-950/80 border border-rose-500/40 px-1.5 py-0.5 text-[10px] font-bold text-rose-300 animate-pulse whitespace-nowrap">
                          SYN {t.syn_recv}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums whitespace-nowrap">
                    <div className="flex flex-col items-end gap-0.5">
                      <div className="flex items-center gap-1.5 font-mono text-xs font-bold">
                        <span className="text-emerald-400 flex items-center">
                          <ArrowDown className="h-3 w-3 inline mr-0.5 text-emerald-400/80" />
                          {curRx.mbps}
                        </span>
                        <span className="text-slate-600 font-normal">/</span>
                        <span className="text-sky-400 flex items-center">
                          <ArrowUp className="h-3 w-3 inline mr-0.5 text-sky-400/80" />
                          {curTx.mbps}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono tracking-tight">
                        ↓ {fmtBytes(t.rx_bps)}/s · ↑ {fmtBytes(t.tx_bps)}/s
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums whitespace-nowrap">
                    <div className="flex flex-col items-end gap-0.5">
                      <span className="font-mono text-xs font-bold text-emerald-400">
                        {peakRx.mbps}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono tracking-tight">
                        {peakRx.bytesPerSec}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums whitespace-nowrap">
                    <div className="flex flex-col items-end gap-0.5">
                      <span className="font-mono text-xs font-bold text-sky-400">
                        {peakTx.mbps}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono tracking-tight">
                        {peakTx.bytesPerSec}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center tabular-nums whitespace-nowrap">
                    <span className="inline-flex min-w-[56px] justify-center items-center rounded-md bg-amber-500/10 border border-amber-500/30 px-2.5 py-1 text-xs font-bold text-amber-300 font-mono shadow-sm">
                      {fmtNumber(t.today_peak_conn_count, 0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center tabular-nums whitespace-nowrap">
                    <span className="inline-flex min-w-[48px] justify-center items-center rounded-md bg-rose-500/10 border border-rose-500/30 px-2.5 py-1 text-xs font-bold text-rose-300 font-mono shadow-sm">
                      {fmtNumber(t.today_peak_inbound_ips, 0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center tabular-nums whitespace-nowrap">
                    <span className="inline-flex min-w-[48px] justify-center items-center rounded-md bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-1 text-xs font-bold text-cyan-300 font-mono shadow-sm">
                      {fmtNumber(t.today_peak_outbound_ips, 0)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center whitespace-nowrap">
                    {(() => {
                      const logText = typeof t.access_log === 'string' ? t.access_log : '正常';
                      const isOk = logText.includes('正常');
                      const isWarn = logText === '未配置' || logText === '待采集';
                      return (
                        <span
                          className={`inline-flex items-center px-2.5 py-1 rounded-md border text-[11px] font-medium whitespace-nowrap ${
                            isOk
                              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                              : isWarn
                              ? 'border-slate-700 bg-slate-800/80 text-slate-400'
                              : 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                          }`}
                        >
                          {logText}
                        </span>
                      );
                    })()}
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {t.timestamp_iso_utc8 || '-'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};

