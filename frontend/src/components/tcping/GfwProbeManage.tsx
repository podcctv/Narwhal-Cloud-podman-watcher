import React, { useCallback, useEffect, useState } from 'react';
import { Loader2, Radio, RefreshCw } from 'lucide-react';
import { request } from '../../api/client';

type ProbeRole = 'disabled' | 'mainland' | 'overseas';
interface Candidate { host_id: string; node_id: string; agent_version: string; last_seen: number; role: ProbeRole; region?: string; carrier?: string; network_id?: string; network_identity_updated_at?: number; probe_online?: boolean; last_seen_age_seconds?: number | null }
interface ProbeEndpointResult { ip: string; port: number; success: boolean | null; latency_ms: number | null; error: string; attempts: number }
interface LatestRoleResult { status: string; created_at: number; finished_at: number; source_host_id: string; source_region: string; source_carrier: string; source_network_id?: string; target_host_id: string; target_node_id: string; error: string; endpoints: ProbeEndpointResult[] }
interface ManageData {
  minimum_mainland: number;
  minimum_overseas: number;
  coverage: { mainland: number; overseas: number };
  target_coverage?: {
    online_hosts: number;
    hosts_with_targets: number;
    hosts_with_independent_probes?: number;
    hosts_ready_for_probe?: number;
    target_endpoints: number;
    discovery?: Record<string, number>;
    eligible_endpoints?: number;
    eligible_containers?: number;
    sampled_containers?: number;
    sample_limit_per_host?: number;
    sample_date_utc?: string;
    missing_reasons: Array<{ reason: string; hosts: number }>;
    probe_missing_reasons?: Array<{ reason: string; hosts: number }>;
  };
  probe_health?: {
    window_seconds: number;
    jobs: Record<string, number>;
    last_finished_at: number;
    last_attempt?: { status?: string; created_at?: number; finished_at?: number; error?: string };
    roles?: Record<'mainland' | 'overseas', {
      configured: number; online: number; offline: number; missing_region: number; missing_carrier: number;
      online_missing_region?: number; online_missing_carrier?: number; distinct_regions: number; distinct_carriers: number;
      distinct_networks?: number; online_missing_network_identity?: number;
    }>;
    latest_role_results?: Partial<Record<'mainland' | 'overseas', LatestRoleResult | null>>;
    recommendations?: string[];
  };
  candidates: Candidate[];
}

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
      await request('/api/v1/gfw-probes/role', { method: 'POST', body: JSON.stringify({ host_id: candidate.host_id, node_id: candidate.node_id, role, region: candidate.region || '', carrier: candidate.carrier || '' }) });
      await load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusyNode(''); }
  };

  const updateCandidate = (nodeId: string, field: 'region' | 'carrier', value: string) => {
    setData(current => current ? {
      ...current,
      candidates: current.candidates.map(candidate => candidate.node_id === nodeId ? { ...candidate, [field]: value } : candidate),
    } : current);
  };

  const mainlandNetworks = data?.probe_health?.roles?.mainland?.distinct_networks || 0;
  const overseasNetworks = data?.probe_health?.roles?.overseas?.distinct_networks || 0;
  const coverageReady = !!data && data.coverage.mainland >= data.minimum_mainland && data.coverage.overseas >= data.minimum_overseas
    && mainlandNetworks >= data.minimum_mainland && overseasNetworks >= data.minimum_overseas;
  return <section className="mt-5 rounded-xl border border-slate-700 bg-slate-950/40 p-4" aria-busy={!!busyNode}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="flex min-w-0 items-start gap-3">
        <span className="rounded-lg border border-sky-800 bg-sky-950/50 p-2 text-sky-300"><Radio size={18} /></span>
        <div><h2 className="font-semibold text-slate-100">国内连通性探测节点</h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-300">此处只配置“从哪里探测”。同一公网 TCP 端点需由至少 2 个不同已识别公网网段的国内探针连续超时，同时海外探针连接成功，连续 3 轮后记录为“疑似 GFW Blocked”。这是大陆与海外的连通性差异，不能单独证明具体封锁机制；拒绝连接和探针网络错误只记为未知。原端点连续 2 轮恢复后结束周期。端口由 Agent 自动发现，不需要手填；ICMP ping 不作为阻断证据。</p>
        </div>
      </div>
      <button type="button" className="tcp-text" onClick={() => load().catch(e => setError((e as Error).message))} disabled={!data || !!busyNode} aria-label="刷新探测节点"><RefreshCw size={15} /></button>
    </div>
    <div className={`mt-3 rounded-lg border p-3 text-xs ${coverageReady ? 'border-emerald-800 bg-emerald-950/20 text-emerald-200' : 'border-amber-800 bg-amber-950/20 text-amber-200'}`}>
      在线节点：国内 {data?.coverage.mainland || 0}/{data?.minimum_mainland || 2} · 海外 {data?.coverage.overseas || 0}/{data?.minimum_overseas || 1}；已识别不同公网网段：国内 {mainlandNetworks}/{data?.minimum_mainland || 2} · 海外 {overseasNetworks}/{data?.minimum_overseas || 1}。{coverageReady ? '探测任务会按约 5 分钟周期运行。' : 'Agent 会自动登记 API 观察到的公网来源网段；网段身份未核实或来源不足时继续采集，但不确认 GFW 阻断。'}
    </div>
    <div className="mt-2 rounded-lg border border-slate-700 bg-slate-900/60 p-3 text-xs text-slate-200">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <strong>被测主机与有效探测覆盖</strong>
        <span className="tabular-nums">可发现端点 {data?.target_coverage?.hosts_with_targets || 0}/{data?.target_coverage?.online_hosts || 0} 台 · 当前可实际探测 {data?.target_coverage?.hosts_ready_for_probe || 0} 台 · 今日抽测 {data?.target_coverage?.sampled_containers || 0}/{data?.target_coverage?.eligible_containers || 0} 个容器</span>
      </div>
      <p className="mt-1 text-slate-300">“可发现端点”表示找到了明确的公网 IP:TCP 端口；“可实际探测”还要求排除目标主机自身后，国内与海外探针数量仍满足判定门槛。探针不会自测，所以总探针数量达标不代表每台探针主机都可被评估。</p>
      <p className="mt-1 leading-5 text-slate-300">自动采集 Incus 代理 / 网络转发、Podman 已发布 TCP 端口、宿主机明确的 TCP DNAT 规则，以及容器直接持有的公网 IPv4/IPv6 + 实际监听端口。每天按稳定轮换抽取每台母鸡最多 2 个不同容器，通常每个容器抽测一个已存在的公网 TCP 端口；已确认受阻的端口优先复测以确认恢复。当天继续按约 5 分钟周期复测样本，累积证据。不会创建端口映射；未抽中的容器或端口仍是未验证状态。上游 NAT 若未在宿主机配置中留下明确端口转发，系统不会把出口 IP 猜成入站公网 IP。</p>
      <p className="mt-1 text-slate-400">今日 UTC {data?.target_coverage?.sample_date_utc || '—'} · 抽测端点 {data?.target_coverage?.target_endpoints || 0} 个 · 有明确映射的端点共 {data?.target_coverage?.eligible_endpoints || 0} 个</p>
      {data?.target_coverage?.discovery && <p className="mt-1 text-slate-300">来源清单：直连公网 {data.target_coverage.discovery.direct_public_listener || 0} · Podman 发布 {data.target_coverage.discovery.podman_publish || 0} · Incus Proxy/Forward {Number(data.target_coverage.discovery.incus_proxy || 0) + Number(data.target_coverage.discovery.incus_forward || 0)} · 宿主机 DNAT {data.target_coverage.discovery.host_dnat || 0}；目标无监听 {data.target_coverage.discovery.mapping_target_not_listening || 0} · 监听地址待核实 {Number(data.target_coverage.discovery.direct_listener_address_unverified || 0) + Number(data.target_coverage.discovery.mapping_listener_address_unverified || 0)} · 公网地址未匹配 {data.target_coverage.discovery.mapping_without_host_public_ip || 0} · 归属冲突 {data.target_coverage.discovery.ambiguous_sockets || 0}</p>}
      {!!data?.target_coverage?.missing_reasons?.length && <div className="mt-2 space-y-1 text-amber-200">
        {data.target_coverage.missing_reasons.map(item => <p key={item.reason} className="break-words">{item.hosts} 台：{item.reason}</p>)}
      </div>}
      {!!data?.target_coverage?.probe_missing_reasons?.length && <div className="mt-2 space-y-1 text-amber-200">
        {data.target_coverage.probe_missing_reasons.map(item => <p key={item.reason} className="break-words">{item.hosts} 台：{item.reason}</p>)}
      </div>}
      {data?.probe_health && <p className="mt-2 border-t border-slate-800 pt-2 text-slate-300">
        最近 24 小时探针任务：回传完成 {data.probe_health.jobs.complete || 0} · 失败 {data.probe_health.jobs.failed || 0} · 超时 {data.probe_health.jobs.expired || 0} · 排队/运行 {data.probe_health.jobs.queued || 0}/{data.probe_health.jobs.running || 0}；最近完成 {data.probe_health.last_finished_at ? new Date(data.probe_health.last_finished_at * 1000).toLocaleString('zh-CN', { hour12: false }) : '最近 24 小时暂无完成任务'}。任务完成代表探针已回传，不代表端口可达。
      </p>}
      {data?.probe_health?.roles && <div className="mt-2 grid gap-2 border-t border-slate-800 pt-2 text-xs sm:grid-cols-2">
        {(['mainland', 'overseas'] as const).map(role => {
          const stats = data.probe_health?.roles?.[role];
          if (!stats) return null;
          return <div key={role} className="rounded-md border border-slate-700/70 bg-slate-950/30 p-2">
            <p className="font-semibold text-slate-200">{role === 'mainland' ? '国内探针' : '海外探针'}：在线 {stats.online}/{role === 'mainland' ? data.minimum_mainland : data.minimum_overseas} · 已配置 {stats.configured} · 离线 {stats.offline}</p>
            <p className="mt-1 text-slate-300">已识别公网网段 {stats.distinct_networks || 0} · 地区 {stats.distinct_regions} 个 · 运营商 {stats.distinct_carriers} 个 · 来源待识别 {stats.online_missing_network_identity || 0}</p>
            {(() => {
              const latest = data.probe_health?.latest_role_results?.[role];
              return latest ? <div className="mt-2 rounded border border-slate-700/70 bg-slate-950/40 p-2">
                <p className="font-medium text-slate-200">最近实际端口结果 · {latest.finished_at ? new Date(latest.finished_at * 1000).toLocaleString('zh-CN', { hour12: false }) : latest.status}</p>
                <p className="mt-1 break-all text-slate-400">目标：{latest.target_host_id || '未知'} · 来源：{latest.source_region || latest.source_host_id || '未知'}{latest.source_carrier ? ` / ${latest.source_carrier}` : ''} · 网段 {latest.source_network_id || '待识别'}</p>
                {latest.endpoints.length ? <div className="mt-1 space-y-1">{latest.endpoints.map((endpoint, index) => <p key={`${endpoint.ip}:${endpoint.port}:${index}`} className={endpoint.success === true ? 'text-emerald-300' : endpoint.success === false ? 'text-amber-200' : 'text-slate-400'}>
                  <span className="font-mono">{endpoint.ip}:{endpoint.port}</span> · {endpoint.success === true ? `可连接${endpoint.latency_ms != null ? ` · ${endpoint.latency_ms.toFixed(1)} ms` : ''}` : endpoint.success === false ? `连接失败${endpoint.error ? ` · ${endpoint.error}` : ''}` : `无端口结果${endpoint.error ? ` · ${endpoint.error}` : ''}`}
                </p>)}</div> : <p className="mt-1 text-amber-200">任务 {latest.status}，没有端口结果{latest.error ? ` · ${latest.error}` : ''}</p>}
              </div> : <p className="mt-2 text-slate-400">该角色尚无已完成探测结果。</p>;
            })()}
          </div>;
        })}
      </div>}
      {!!data?.probe_health?.recommendations?.length && <div className="mt-2 space-y-1 rounded-md border border-amber-900/70 bg-amber-950/20 p-2 text-xs text-amber-200">
        {data.probe_health.recommendations.map((item, index) => <p key={`${index}-${item}`}>{item}</p>)}
      </div>}
      {data?.probe_health?.last_attempt?.created_at ? <p className="mt-2 text-[11px] text-slate-400">
        最近探测任务：{new Date(data.probe_health.last_attempt.created_at * 1000).toLocaleString('zh-CN', { hour12: false })} · {data.probe_health.last_attempt.status || '未知'}{data.probe_health.last_attempt.error ? ` · ${data.probe_health.last_attempt.error}` : ''}
      </p> : <p className="mt-2 text-[11px] text-amber-200">尚无历史探测任务记录；满足覆盖与端点条件后由服务端自动创建任务。</p>}
      <details className="mt-2 border-t border-slate-800 pt-2 text-slate-300">
        <summary className="cursor-pointer font-semibold text-sky-300">没有可探测端口时怎么处理？</summary>
        <p className="mt-2 leading-5">Agent 会自动读取 Incus / Podman 端口发布、容器公网地址和宿主机现有 TCP DNAT 规则，并与容器实际监听端口核对。若公网映射由宿主机之外的上游 NAT 提供，且宿主机没有对应转发规则或可读映射，当前没有可靠数据可自动确定公网地址与端口；系统会继续显示待评估，不猜测并探测端口。</p>
      </details>
    </div>
    {error && <p className="mt-3 rounded-lg border border-rose-800 bg-rose-950/30 p-2 text-xs text-rose-200" role="alert">{error}</p>}
    <div className="mt-3 grid min-w-0 gap-2 md:grid-cols-2">
      {data?.candidates.map(candidate => <div key={candidate.node_id} className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-slate-100" title={candidate.host_id}>{candidate.host_id}</p>
          <p className="mt-1 text-[11px] text-slate-400">Agent {candidate.agent_version || '未知'} · 最近上报 {candidate.last_seen ? new Date(candidate.last_seen * 1000).toLocaleString('zh-CN', { hour12: false }) : '未知'} · {candidate.role === 'disabled' ? (candidate.probe_online ? 'Agent 在线' : 'Agent 离线') : candidate.probe_online ? '探针在线' : '探针离线'} · 公网网段 {candidate.network_id || '等待 Agent 探测时自动识别'}</p>
          {candidate.role !== 'disabled' && (!candidate.region || (candidate.role === 'mainland' && !candidate.carrier)) && <p className="mt-1 text-[11px] text-amber-200">覆盖信息未完整标注{!candidate.region ? ' · 地区' : ''}{candidate.role === 'mainland' && !candidate.carrier ? ' · 运营商' : ''}</p>}
          {candidate.role !== 'disabled' && <div className="mt-2 grid max-w-xl grid-cols-2 gap-2">
            <input aria-label={`${candidate.host_id} 探针地区`} maxLength={80} value={candidate.region || ''} placeholder="地区（如：枣庄，山东）" disabled={!!busyNode} onChange={event => updateCandidate(candidate.node_id, 'region', event.target.value)} onBlur={() => save(candidate, candidate.role)} className="min-h-8 min-w-0 rounded border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 placeholder:text-slate-500" />
            <input aria-label={`${candidate.host_id} 探针运营商`} maxLength={100} value={candidate.carrier || ''} placeholder="运营商（如：联通 BGP）" disabled={!!busyNode} onChange={event => updateCandidate(candidate.node_id, 'carrier', event.target.value)} onBlur={() => save(candidate, candidate.role)} className="min-h-8 min-w-0 rounded border border-slate-700 bg-slate-950 px-2 text-[11px] text-slate-200 placeholder:text-slate-500" />
          </div>}
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
