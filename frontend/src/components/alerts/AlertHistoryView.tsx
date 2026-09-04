import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Filter,
  RotateCcw,
  Search,
  Ban,
  Clock,
  ArrowRight,
} from 'lucide-react';
import { SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';

interface AlertHistoryViewProps {
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onBackToDashboard: () => void;
}

export const AlertHistoryView: React.FC<AlertHistoryViewProps> = ({
  onToast,
  onBackToDashboard,
}) => {
  const [statusTab, setStatusTab] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [alertType, setAlertType] = useState('all');
  const [hostId, setHostId] = useState('');
  const [query, setQuery] = useState('');

  const [items, setItems] = useState<SecurityAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [typeOptions, setTypeOptions] = useState<string[]>([]);
  const [hostOptions, setHostOptions] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [offset, setOffset] = useState(0);
  const limit = 30;

  const loadData = async (reset = false) => {
    if (loading) return;
    setLoading(true);
    const newOffset = reset ? 0 : offset;
    try {
      const res = await api.getAlertHistory({
        status: statusTab,
        severity,
        alert_type: alertType,
        host_id: hostId,
        query,
        limit: String(limit),
        offset: String(newOffset),
      });

      if (reset) {
        setItems(res.items || []);
        setOffset(res.items.length);
      } else {
        setItems((prev) => [...prev, ...(res.items || [])]);
        setOffset((prev) => prev + (res.items || []).length);
      }

      setTotal(res.total || 0);
      setCounts(res.counts || {});
      if (res.alert_types) setTypeOptions(res.alert_types);
      if (res.hosts) setHostOptions(res.hosts);
    } catch (err: any) {
      onToast('error', `加载告警记录失败：${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, [statusTab, severity, alertType, hostId]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadData(true);
  };

  const handleReset = () => {
    setStatusTab('all');
    setSeverity('all');
    setAlertType('all');
    setHostId('');
    setQuery('');
  };

  const handleDecision = async (
    alertId: number,
    decision: 'deny' | 'allow_silent' | 'dismiss_once' | 'reopen'
  ) => {
    try {
      const res = await api.dispositionAlert(alertId, decision);
      onToast('success', res.queued ? '操作已排队等待节点执行' : '安全状态已更新');
      loadData(true);
    } catch (err: any) {
      onToast('error', `处置操作失败：${err.message || err}`);
    }
  };

  const statusLabels: Record<string, string> = {
    all: '全部',
    active: '活动',
    suppressed: '已放行',
    dismissed: '本次忽略',
    remediated: '已处理',
    resolved: '已恢复',
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-amber-950/80 p-2.5 text-amber-400 border border-amber-500/30">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">
              安全告警与处置审计历史
            </h2>
            <p className="text-xs text-slate-400">
              保留活动、已忽略、已处理及恢复事件；可一键重新执行定向清理或解除策略。
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onBackToDashboard}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-700 transition-colors shrink-0"
        >
          <span>返回总览看板</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Filter Panel */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-300">
            <Filter className="h-4 w-4 text-sky-400" />
            <span>维度筛选与检索</span>
          </div>
          <button
            type="button"
            onClick={handleReset}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RotateCcw className="h-3 w-3" />
            <span>重置筛选</span>
          </button>
        </div>

        {/* Form Controls */}
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">告警级别</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="all">全部级别</option>
              <option value="critical">Critical (高危)</option>
              <option value="warning">Warning (告警)</option>
              <option value="info">Info (提示)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">告警类型</label>
            <select
              value={alertType}
              onChange={(e) => setAlertType(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="all">全部类型</option>
              {typeOptions.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">所属主机</label>
            <select
              value={hostId}
              onChange={(e) => setHostId(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-slate-200 focus:outline-none focus:border-sky-500"
            >
              <option value="">全部主机</option>
              {hostOptions.map((h) => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">关键词搜索</label>
            <div className="relative">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="容器、说明、进程特征..."
                className="w-full rounded-lg border border-slate-800 bg-slate-950 pl-8 pr-3 py-2 text-slate-200 focus:outline-none focus:border-sky-500"
              />
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            </div>
          </div>
        </form>

        {/* Status Tabs */}
        <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80 overflow-x-auto">
          {['all', 'active', 'suppressed', 'dismissed', 'remediated', 'resolved'].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setStatusTab(s)}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold transition-all shrink-0 ${
                statusTab === s
                  ? 'border-sky-500 bg-sky-950/80 text-sky-300'
                  : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <span>{statusLabels[s] || s}</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px]">
                {counts[s] || 0}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Alert Card List */}
      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-800 p-12 text-center text-slate-500 text-xs">
            没有符合筛选条件的告警记录
          </div>
        ) : (
          items.map((alert) => {
            const isHistorical = alert.status !== 'active';

            return (
              <div
                key={alert.id}
                className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 shadow-sm hover:border-slate-700 transition-colors space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusBadge status={alert.severity} size="sm" />
                      <span className="font-bold text-sm text-slate-100">
                        {alert.title || alert.type}
                      </span>
                      <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                        {alert.host_id}
                      </span>
                      <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-400">
                        {alert.project ? `${alert.runtime}/${alert.project}` : alert.runtime}
                      </span>
                      {alert.container_name && (
                        <span className="rounded-md bg-sky-950/60 border border-sky-500/30 px-2 py-0.5 font-mono text-xs text-sky-300">
                          {alert.container_name}
                        </span>
                      )}
                      <span className="rounded-full bg-slate-800 px-2 py-0.2 text-[10px] text-slate-400 font-mono">
                        {statusLabels[alert.status] || alert.status}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">
                      {alert.message}
                    </p>
                  </div>

                  <span className="text-xs text-slate-500 tabular-nums shrink-0">
                    出现 {alert.occurrence_count || 1} 次
                  </span>
                </div>

                {/* Footnotes & Actions */}
                <div className="flex items-center justify-between border-t border-slate-800/80 pt-3 text-xs">
                  <div className="text-slate-500 text-[11px] font-mono">
                    首次 {alert.first_seen_utc8} · 最近 {alert.last_seen_utc8}
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleDecision(alert.id, 'deny')}
                      className="flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-950/60 px-2.5 py-1 text-xs font-semibold text-rose-200 hover:bg-rose-900/80 transition-colors"
                    >
                      <Ban className="h-3 w-3" />
                      <span>{isHistorical ? '重新定向处置' : '定向处置'}</span>
                    </button>

                    {(alert.status === 'suppressed' || alert.status === 'dismissed') && (
                      <button
                        type="button"
                        onClick={() => handleDecision(alert.id, 'reopen')}
                        className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-300 hover:bg-slate-700 transition-colors"
                      >
                        <Clock className="h-3 w-3" />
                        <span>恢复提醒</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}

        {/* Load More Button */}
        {offset < total && (
          <div className="text-center pt-2">
            <button
              type="button"
              onClick={() => loadData(false)}
              disabled={loading}
              className="rounded-xl border border-slate-800 bg-slate-900 px-6 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              {loading ? '加载中...' : `加载更多 (${offset} / ${total})`}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
