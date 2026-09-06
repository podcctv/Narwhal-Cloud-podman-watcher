import React, { useState } from 'react';
import { Activity, ArrowDown, ArrowUp } from 'lucide-react';
import { SecurityStatusItem } from '../../api/types';
import { fmtBytes, fmtNetSpeed, fmtNumber } from '../../api/client';
import { api } from '../../api/client';

interface TelemetrySectionProps {
  telemetry: SecurityStatusItem[];
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh: () => void;
}

export const TelemetrySection: React.FC<TelemetrySectionProps> = ({ telemetry, onToast, onRefresh }) => {
  const [editing, setEditing] = useState<SecurityStatusItem | null>(null);
  const [deleting, setDeleting] = useState<SecurityStatusItem | null>(null);
  const [busy, setBusy] = useState(false);
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

      <div className="w-full">
        <table className="w-full table-fixed text-left text-xs text-slate-300">
          <thead className="border-b border-slate-800 bg-slate-950/70 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            <tr>
              <th className="px-5 py-3.5 whitespace-nowrap">主机</th>
              <th className="px-4 py-3.5 text-right whitespace-nowrap">实时速率 (下行 / 上行)</th>
              <th className="hidden 2xl:table-cell px-4 py-3.5 text-right whitespace-nowrap">当天最高下载</th>
              <th className="hidden 2xl:table-cell px-4 py-3.5 text-right whitespace-nowrap">当天最高上传</th>
              <th className="hidden xl:table-cell px-4 py-3.5 text-center whitespace-nowrap">当天最高连接</th>
              <th className="hidden xl:table-cell px-4 py-3.5 text-center whitespace-nowrap">最高入站 IP</th>
              <th className="hidden 2xl:table-cell px-4 py-3.5 text-center whitespace-nowrap">最高出站 IP</th>
              <th className="px-4 py-3.5 text-center whitespace-nowrap">访问日志</th>
              <th className="hidden lg:table-cell px-5 py-3.5 text-right whitespace-nowrap">采样时间</th>
              <th className="px-5 py-3.5 text-right whitespace-nowrap">操作</th>
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
                  <td className="hidden 2xl:table-cell px-4 py-3 text-right tabular-nums whitespace-nowrap">
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
                  <td className="hidden 2xl:table-cell px-4 py-3 text-right tabular-nums whitespace-nowrap">
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
                  <td className="hidden xl:table-cell px-4 py-3 text-center tabular-nums whitespace-nowrap">
                    <span className="inline-flex min-w-[56px] justify-center items-center rounded-md bg-amber-500/10 border border-amber-500/30 px-2.5 py-1 text-xs font-bold text-amber-300 font-mono shadow-sm">
                      {fmtNumber(t.today_peak_conn_count, 0)}
                    </span>
                  </td>
                  <td className="hidden xl:table-cell px-4 py-3 text-center tabular-nums whitespace-nowrap">
                    <span className="inline-flex min-w-[48px] justify-center items-center rounded-md bg-rose-500/10 border border-rose-500/30 px-2.5 py-1 text-xs font-bold text-rose-300 font-mono shadow-sm">
                      {fmtNumber(t.today_peak_inbound_ips, 0)}
                    </span>
                  </td>
                  <td className="hidden 2xl:table-cell px-4 py-3 text-center tabular-nums whitespace-nowrap">
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
                  <td className="hidden lg:table-cell px-5 py-3 text-right tabular-nums text-slate-400 font-mono text-[11px] whitespace-nowrap">
                    {t.timestamp_iso_utc8 || '-'}
                  </td>
                  <td className="px-5 py-3 text-right whitespace-nowrap">
                    <button onClick={() => setEditing(t)} className="mr-2 rounded-md border border-sky-500/30 bg-sky-500/10 px-2.5 py-1.5 text-[11px] font-medium text-sky-300 hover:bg-sky-500/20">配置</button>
                    <button onClick={() => setDeleting(t)} className="rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20">删除</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {editing && <HostConfigDialog host={editing} busy={busy} onClose={() => setEditing(null)} onSave={async (config) => {
        setBusy(true); try { await api.updateHostConfig(editing.host_id, config); onToast('success', '配置已下发，将在节点下次轮询时生效。'); setEditing(null); onRefresh(); } catch (e: any) { onToast('error', e.message || '配置下发失败'); } finally { setBusy(false); }
      }} />}
      {deleting && <HostDeleteDialog host={deleting} busy={busy} onClose={() => setDeleting(null)} onDelete={async (mode) => {
        setBusy(true); try { await api.deleteHost(deleting.host_id, mode); onToast('success', mode === 'uninstall' ? '已下发远程自卸载，节点确认后将从面板移除。' : '主机记录已删除。'); setDeleting(null); onRefresh(); } catch (e: any) { onToast('error', e.message || '删除失败'); } finally { setBusy(false); }
      }} />}
    </section>
  );
};

const HostConfigDialog: React.FC<{host: SecurityStatusItem; busy: boolean; onClose: () => void; onSave: (v: Record<string, any>) => void}> = ({ host, busy, onClose, onSave }) => {
  const c = host.host_config || {};
  const [name, setName] = useState(host.host_id);
  const [interval, setIntervalValue] = useState(String(c.report_interval || 300));
  const [runtimes, setRuntimes] = useState(String(c.container_runtimes || 'auto'));
  const [docker, setDocker] = useState(String(c.docker_monitor_mode || 'notice'));
  return <div role="dialog" aria-modal="true" className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4"><form onSubmit={(e) => { e.preventDefault(); onSave({host_id:name, report_interval:Number(interval), container_runtimes:runtimes, docker_monitor_mode:docker}); }} className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"><h3 className="text-base font-bold">修改主机配置</h3><p className="mt-1 text-xs text-slate-400">改名不会产生新主机：系统以稳定 NODE_ID 合并历史数据。</p><label className="mt-4 block text-xs text-slate-300">显示名称<input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" required /></label><label className="mt-3 block text-xs text-slate-300">上报间隔（秒）<input type="number" min="60" max="3600" value={interval} onChange={(e) => setIntervalValue(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" required /></label><label className="mt-3 block text-xs text-slate-300">运行时<input value={runtimes} onChange={(e) => setRuntimes(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" /></label><label className="mt-3 block text-xs text-slate-300">Docker 模式<select value={docker} onChange={(e) => setDocker(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"><option value="notice">仅提示</option><option value="full">完整采集</option><option value="off">关闭</option></select></label><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onClose} className="rounded border border-slate-700 px-3 py-2 text-sm">取消</button><button disabled={busy} className="rounded bg-sky-600 px-3 py-2 text-sm font-semibold">{busy ? '下发中…' : '保存并下发'}</button></div></form></div>;
};

const HostDeleteDialog: React.FC<{host: SecurityStatusItem; busy: boolean; onClose: () => void; onDelete: (m: 'uninstall' | 'records_only') => void}> = ({ host, busy, onClose, onDelete }) => {
  const [confirm, setConfirm] = useState(''); const [mode, setMode] = useState<'uninstall' | 'records_only'>('uninstall');
  return <div role="dialog" aria-modal="true" className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4"><div className="w-full max-w-md rounded-2xl border border-rose-900/70 bg-slate-900 p-5 shadow-2xl"><h3 className="text-base font-bold text-rose-200">删除主机</h3><p className="mt-2 text-xs leading-5 text-slate-300">“远程卸载”会让节点停止并删除 Narwhal Client、配置和自动更新单元；不会修改容器或业务服务。仅删记录会保留节点 Agent，下一次上报会重新出现。</p><label className="mt-4 flex gap-2 text-sm"><input type="radio" checked={mode==='uninstall'} onChange={() => setMode('uninstall')} />远程卸载 Client（推荐）</label><label className="mt-2 flex gap-2 text-sm"><input type="radio" checked={mode==='records_only'} onChange={() => setMode('records_only')} />只删除面板记录</label><label className="mt-4 block text-xs">输入完整主机名确认：<b>{host.host_id}</b><input value={confirm} onChange={(e) => setConfirm(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" /></label><div className="mt-5 flex justify-end gap-2"><button onClick={onClose} className="rounded border border-slate-700 px-3 py-2 text-sm">取消</button><button disabled={busy || confirm !== host.host_id} onClick={() => onDelete(mode)} className="rounded bg-rose-700 px-3 py-2 text-sm font-semibold disabled:opacity-50">{busy ? '处理中…' : '确认删除'}</button></div></div></div>;
};

