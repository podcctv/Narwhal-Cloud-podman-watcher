import React, { useCallback, useEffect, useState } from 'react';
import { Loader2, Radio, RefreshCw } from 'lucide-react';
import { request } from '../../api/client';

type ProbeRole = 'disabled' | 'mainland' | 'overseas';
interface Candidate { host_id: string; node_id: string; agent_version: string; last_seen: number; role: ProbeRole }
interface ManageData { minimum_mainland: number; minimum_overseas: number; coverage: { mainland: number; overseas: number }; candidates: Candidate[] }

const roleLabel: Record<ProbeRole, string> = { disabled: '不参与', mainland: '国内探测点', overseas: '海外探测点' };

export const GfwProbeManage: React.FC = () => {
  const [data, setData] = useState<ManageData>();
  const [busyNode, setBusyNode] = useState('');
  const [error, setError] = useState('');
  const load = useCallback(async () => setData(await request<ManageData>('/api/v1/gfw-probes/manage')), []);
  useEffect(() => { load().catch(e => setError((e as Error).message)); }, [load]);

  const save = async (candidate: Candidate, role: ProbeRole) => {
    setBusyNode(candidate.node_id); setError('');
    try {
      await request('/api/v1/gfw-probes/role', { method: 'POST', body: JSON.stringify({ host_id: candidate.host_id, node_id: candidate.node_id, role }) });
      await load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusyNode(''); }
  };

  const coverageReady = !!data && data.coverage.mainland >= data.minimum_mainland && data.coverage.overseas >= data.minimum_overseas;
  return <section className="mt-5 rounded-xl border border-slate-700 bg-slate-950/40 p-4" aria-busy={!!busyNode}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-3">
        <span className="rounded-lg border border-sky-800 bg-sky-950/50 p-2 text-sky-300"><Radio size={18} /></span>
        <div><h2 className="font-semibold text-slate-100">国内连通性探测节点</h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-300">明确指定探测点位置。同一公网端口至少 2 个国内点失败、海外点成功，连续 3 轮后记录为 GFW Blocked；原端点连续 2 轮恢复后结束周期。探测只连接已发现的公网 Incus / Podman TCP 映射。它是连通性证据，不单独证明具体封锁来源。</p>
        </div>
      </div>
      <button type="button" className="tcp-text" onClick={() => load().catch(e => setError((e as Error).message))} disabled={!data || !!busyNode} aria-label="刷新探测节点"><RefreshCw size={15} /></button>
    </div>
    <div className={`mt-3 rounded-lg border p-3 text-xs ${coverageReady ? 'border-emerald-800 bg-emerald-950/20 text-emerald-200' : 'border-amber-800 bg-amber-950/20 text-amber-200'}`}>
      已就绪：国内 {data?.coverage.mainland || 0}/{data?.minimum_mainland || 2} · 海外 {data?.coverage.overseas || 0}/{data?.minimum_overseas || 1}。{coverageReady ? '探测任务会按约 5 分钟周期运行。' : '先选择在线、Agent 已更新的节点；未达到数量时所有主机保持“待评估”。'}
    </div>
    {error && <p className="mt-3 rounded-lg border border-rose-800 bg-rose-950/30 p-2 text-xs text-rose-200" role="alert">{error}</p>}
    <div className="mt-3 grid min-w-0 gap-2 md:grid-cols-2">
      {data?.candidates.map(candidate => <div key={candidate.node_id} className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-slate-100" title={candidate.host_id}>{candidate.host_id}</p>
          <p className="mt-1 text-[11px] text-slate-400">Agent {candidate.agent_version || '未知'} · 最近上报 {candidate.last_seen ? new Date(candidate.last_seen * 1000).toLocaleString('zh-CN', { hour12: false }) : '未知'}</p>
        </div>
        <label className="flex shrink-0 items-center gap-2 text-xs text-slate-300">
          <span className="sr-only">{candidate.host_id} 的探测区域</span>
          {busyNode === candidate.node_id && <Loader2 size={14} className="animate-spin" />}
          <select className="max-w-40 rounded-md border border-slate-700 bg-slate-950 px-2 py-1.5 text-slate-100" value={candidate.role} disabled={!!busyNode} onChange={event => save(candidate, event.target.value as ProbeRole)}>
            {(Object.keys(roleLabel) as ProbeRole[]).map(role => <option key={role} value={role}>{roleLabel[role]}</option>)}
          </select>
        </label>
      </div>)}
    </div>
    {data && data.candidates.length === 0 && <p className="mt-3 text-xs text-slate-400">当前没有已注册的 Agent 节点。</p>}
  </section>;
};
