import React, { useCallback, useEffect, useState } from 'react';
import { Loader2, Radio, RefreshCw } from 'lucide-react';
import { request } from '../../api/client';

type ProbeRole = 'disabled' | 'mainland' | 'overseas';
interface Candidate {
  host_id: string;
  node_id: string;
  agent_version: string;
  last_seen: number;
  role: ProbeRole;
  region?: string;
  carrier?: string;
  network_id?: string;
  network_identity_updated_at?: number;
  ipv4_default_route?: boolean | null;
  ipv6_default_route?: boolean | null;
  route_capabilities_updated_at?: number;
  probe_online?: boolean;
  last_seen_age_seconds?: number | null;
}
interface ProbeEndpointResult {
  ip: string;
  port: number;
  success: boolean | null;
  latency_ms: number | null;
  error: string;
  attempts: number;
}
interface LatestRoleResult {
  status: string;
  created_at: number;
  finished_at: number;
  source_host_id: string;
  source_region: string;
  source_carrier: string;
  source_network_id?: string;
  target_host_id: string;
  target_node_id: string;
  error: string;
  endpoints: ProbeEndpointResult[];
}
interface ManageData {
  minimum_mainland: number;
  minimum_overseas: number;
  coverage: { mainland: number; overseas: number };
  target_coverage?: {
    online_hosts: number;
    hosts_with_targets: number;
    hosts_with_independent_probes?: number;
    hosts_ready_for_probe?: number;
    hosts_with_partial_probe_coverage?: number;
    target_endpoints: number;
    discovery?: Record<string, number>;
    eligible_endpoints?: number;
    eligible_containers?: number;
    sampled_containers?: number;
    sample_limit_per_host?: number;
    sample_date_utc?: string;
    missing_reasons: Array<{ reason: string; hosts: number }>;
    probe_missing_reasons?: Array<{ reason: string; hosts: number }>;
    family_missing_reasons?: Array<{ reason: string; hosts: number }>;
  };
  probe_health?: {
    window_seconds: number;
    jobs: Record<string, number>;
    last_finished_at: number;
    last_attempt?: { status?: string; created_at?: number; finished_at?: number; error?: string };
    roles?: Record<
      'mainland' | 'overseas',
      {
        configured: number;
        online: number;
        offline: number;
        missing_region: number;
        missing_carrier: number;
        online_missing_region?: number;
        online_missing_carrier?: number;
        distinct_regions: number;
        distinct_carriers: number;
        distinct_networks?: number;
        online_missing_network_identity?: number;
        online_ipv4_default_route?: number;
        online_ipv4_no_default_route?: number;
        online_ipv4_route_unknown?: number;
        online_ipv6_default_route?: number;
        online_ipv6_no_default_route?: number;
        online_ipv6_route_unknown?: number;
      }
    >;
    latest_role_results?: Partial<Record<'mainland' | 'overseas', LatestRoleResult | null>>;
    recommendations?: string[];
  };
  candidates: Candidate[];
}

const roleLabel: Record<ProbeRole, string> = {
  disabled: '不参与',
  mainland: '国内探测点',
  overseas: '海外探测点',
};
const routeLabel = (value: boolean | null | undefined) =>
  value === true ? '默认路由存在' : value === false ? '未发现默认路由' : 'Agent 未上报';

export const GfwProbeManage: React.FC = () => {
  const [data, setData] = useState<ManageData>();
  const [busyNode, setBusyNode] = useState('');
  const [error, setError] = useState('');
  const load = useCallback(async () => setData(await request<ManageData>('/api/v1/gfw-probes/manage')), []);
  useEffect(() => {
    load().catch((e) => setError((e as Error).message));
  }, [load]);

  const save = async (candidate: Candidate, role: ProbeRole) => {
    setBusyNode(candidate.node_id);
    setError('');
    try {
      await request('/api/v1/gfw-probes/role', {
        method: 'POST',
        body: JSON.stringify({
          host_id: candidate.host_id,
          node_id: candidate.node_id,
          role,
          region: candidate.region || '',
          carrier: candidate.carrier || '',
        }),
      });
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusyNode('');
    }
  };

  const updateCandidate = (nodeId: string, field: 'region' | 'carrier', value: string) => {
    setData((current) =>
      current
        ? {
            ...current,
            candidates: current.candidates.map((candidate) =>
              candidate.node_id === nodeId ? { ...candidate, [field]: value } : candidate
            ),
          }
        : current
    );
  };

  const mainlandNetworks = data?.probe_health?.roles?.mainland?.distinct_networks || 0;
  const overseasNetworks = data?.probe_health?.roles?.overseas?.distinct_networks || 0;
  const roleNetworkBaselineReady =
    !!data &&
    data.coverage.mainland >= data.minimum_mainland &&
    data.coverage.overseas >= data.minimum_overseas &&
    mainlandNetworks >= data.minimum_mainland &&
    overseasNetworks >= data.minimum_overseas;

  return (
    <section className="rn2-card mt-5 overflow-hidden text-[#0b1636]" aria-busy={!!busyNode}>
      <div className="rn2-card-head">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
            <Radio size={18} aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <span className="rn2-eyebrow block">GFW PROBE · REACHABILITY NODES</span>
            <h2 className="mt-0.5 text-base font-bold text-white">国内连通性探测节点</h2>
          </div>
        </div>
        <button
          type="button"
          className="rn2-btn rn2-btn-ghost rn2-btn-sm"
          onClick={() => load().catch((e) => setError((e as Error).message))}
          disabled={!data || !!busyNode}
          aria-label="刷新探测节点"
        >
          <RefreshCw size={15} aria-hidden="true" />
          <span>刷新</span>
        </button>
      </div>

      <div className="space-y-4 p-5 sm:p-6">
        <p className="max-w-4xl text-xs leading-6 text-[#31485e]">
          此处只配置“从哪里探测”。同一公网 TCP 端点需由至少 2 个不同已识别公网网段的国内探针连续超时，同时海外探针连接成功，连续 3 轮后记录为“疑似 GFW Blocked”。这是大陆与海外的连通性差异，不能单独证明具体封锁机制；拒绝连接和探针网络错误只记为未知。原端点连续 2 轮恢复后结束周期。端口由 Agent 自动发现，不需要手填；ICMP ping 不作为阻断证据。
        </p>

        <div
          className={`rounded-xl border p-3.5 text-xs font-medium leading-5 ${
            roleNetworkBaselineReady
              ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]'
              : 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]'
          }`}
        >
          在线节点：国内 {data?.coverage.mainland || 0}/{data?.minimum_mainland || 2} · 海外 {data?.coverage.overseas || 0}/
          {data?.minimum_overseas || 1}；已识别不同公网网段：国内 {mainlandNetworks}/{data?.minimum_mainland || 2} · 海外{' '}
          {overseasNetworks}/{data?.minimum_overseas || 1}。
          {roleNetworkBaselineReady
            ? '角色和独立网段达到基础门槛；每台目标仍按自身 IPv4/IPv6 地址族、探针路由和端点映射分别判定。'
            : '探针角色或独立网段未达到基础门槛；系统仍会写入具体缺口诊断，不会仅显示等待状态。'}
        </div>

        <div className="space-y-2 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4 text-xs text-[#31485e]">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <strong className="text-sm font-bold text-[#0b1636]">被测主机与有效探测覆盖</strong>
            <span className="font-mono font-semibold text-[#0657b8] tabular-nums">
              可发现端点 {data?.target_coverage?.hosts_with_targets || 0}/{data?.target_coverage?.online_hosts || 0} 台 · 完整覆盖{' '}
              {data?.target_coverage?.hosts_ready_for_probe || 0} 台 · 部分采样{' '}
              {data?.target_coverage?.hosts_with_partial_probe_coverage || 0} 台 · 今日抽测{' '}
              {data?.target_coverage?.sampled_containers || 0}/{data?.target_coverage?.eligible_containers || 0} 个容器
            </span>
          </div>
          <p>
            “可发现端点”表示找到了明确的公网 IP:TCP 端口；“完整覆盖”还要求排除目标主机自身后，国内与海外独立网段满足判定门槛。“部分采样”会继续收集当前可用探针的结果，帮助定位网络问题，但只要证据门槛不足，状态就保持未知。探针不会自测。
          </p>
          <p className="leading-5">
            自动采集 Incus 代理 / 网络转发、Podman 已发布 TCP 端口、宿主机明确的 TCP DNAT 规则，以及容器直接持有的公网 IPv4/IPv6 + 实际监听端口。每天按稳定轮换抽取每台母鸡最多 2 个不同容器，通常每个容器抽测一个已存在的公网 TCP 端口；已确认受阻的端口优先复测以确认恢复。当天继续按约 5 分钟周期复测样本，累积证据。不会创建端口映射；未抽中的容器或端口仍是未验证状态。上游 NAT 若未在宿主机配置中留下明确端口转发，系统不会把出口 IP 猜成入站公网 IP。
          </p>
          <p className="leading-5">
            探测任务按目标 IPv4/IPv6 分派给有对应路由的探针。路由字段只表示 Agent 内核是否看到默认路由；任务中的实际 TCP 连接结果才用于判断。“未发现默认路由”仍可能存在策略路由，最终以实际探测回执为准。
          </p>
          <p className="font-mono text-[#506483]">
            今日 UTC {data?.target_coverage?.sample_date_utc || '—'} · 抽测端点 {data?.target_coverage?.target_endpoints || 0} 个 · 有明确映射的端点共{' '}
            {data?.target_coverage?.eligible_endpoints || 0} 个
          </p>
          {data?.target_coverage?.discovery && (
            <p className="text-[#31485e]">
              来源清单：直连公网 {data.target_coverage.discovery.direct_public_listener || 0} · Podman 发布{' '}
              {data.target_coverage.discovery.podman_publish || 0} · Incus Proxy/Forward{' '}
              {Number(data.target_coverage.discovery.incus_proxy || 0) +
                Number(data.target_coverage.discovery.incus_forward || 0)}{' '}
              · 宿主机 DNAT {data.target_coverage.discovery.host_dnat || 0}；目标无监听{' '}
              {data.target_coverage.discovery.mapping_target_not_listening || 0} · 监听地址待核实{' '}
              {Number(data.target_coverage.discovery.direct_listener_address_unverified || 0) +
                Number(data.target_coverage.discovery.mapping_listener_address_unverified || 0)}{' '}
              · 公网地址未匹配 {data.target_coverage.discovery.mapping_without_host_public_ip || 0} · 归属冲突{' '}
              {data.target_coverage.discovery.ambiguous_sockets || 0}
            </p>
          )}
          {!!data?.target_coverage?.missing_reasons?.length && (
            <div className="space-y-1 font-medium text-[#9a5b00]">
              {data.target_coverage.missing_reasons.map((item) => (
                <p key={item.reason} className="break-words">
                  {item.hosts} 台：{item.reason}
                </p>
              ))}
            </div>
          )}
          {!!data?.target_coverage?.probe_missing_reasons?.length && (
            <div className="space-y-1 font-medium text-[#9a5b00]">
              {data.target_coverage.probe_missing_reasons.map((item) => (
                <p key={item.reason} className="break-words">
                  {item.hosts} 台：{item.reason}
                </p>
              ))}
            </div>
          )}
          {!!data?.target_coverage?.family_missing_reasons?.length && (
            <div className="space-y-1 font-medium text-[#9a5b00]">
              {data.target_coverage.family_missing_reasons.map((item) => (
                <p key={item.reason} className="break-words">
                  {item.hosts} 台：{item.reason}
                </p>
              ))}
            </div>
          )}
          {data?.probe_health && (
            <p className="border-t border-[#d2dfec] pt-2.5 text-[#31485e]">
              最近 24 小时探针任务：回传完成 {data.probe_health.jobs.complete || 0} · 失败 {data.probe_health.jobs.failed || 0} · 超时{' '}
              {data.probe_health.jobs.expired || 0} · 排队/运行 {data.probe_health.jobs.queued || 0}/
              {data.probe_health.jobs.running || 0}；最近完成{' '}
              {data.probe_health.last_finished_at
                ? new Date(data.probe_health.last_finished_at * 1000).toLocaleString('zh-CN', { hour12: false })
                : '最近 24 小时暂无完成任务'}
              。任务完成代表探针已回传，不代表端口可达。
            </p>
          )}
          {data?.probe_health?.roles && (
            <div className="grid gap-3 border-t border-[#d2dfec] pt-3 text-xs sm:grid-cols-2">
              {(['mainland', 'overseas'] as const).map((role) => {
                const stats = data.probe_health?.roles?.[role];
                if (!stats) return null;
                return (
                  <div key={role} className="rounded-xl border border-[#cedae7] bg-white p-3">
                    <p className="font-bold text-[#0b1636]">
                      {role === 'mainland' ? '国内探针' : '海外探针'}：在线 {stats.online}/
                      {role === 'mainland' ? data.minimum_mainland : data.minimum_overseas} · 已配置 {stats.configured} · 离线{' '}
                      {stats.offline}
                    </p>
                    <p className="mt-1 text-[#31485e]">
                      已识别公网网段 {stats.distinct_networks || 0} · 地区 {stats.distinct_regions} 个 · 运营商{' '}
                      {stats.distinct_carriers} 个 · 来源待识别 {stats.online_missing_network_identity || 0}
                    </p>
                    <p className="mt-1 text-[#506483]">
                      IPv4 默认路由：存在 {stats.online_ipv4_default_route || 0} · 未发现 {stats.online_ipv4_no_default_route || 0} · 未上报{' '}
                      {stats.online_ipv4_route_unknown || 0}；IPv6：存在 {stats.online_ipv6_default_route || 0} · 未发现{' '}
                      {stats.online_ipv6_no_default_route || 0} · 未上报 {stats.online_ipv6_route_unknown || 0}
                    </p>
                    {(() => {
                      const latest = data.probe_health?.latest_role_results?.[role];
                      return latest ? (
                        <div className="mt-2 rounded-lg border border-[#dce5ef] bg-[#f4f8fd] p-2.5">
                          <p className="font-semibold text-[#0b1636]">
                            最近实际端口结果 ·{' '}
                            {latest.finished_at
                              ? new Date(latest.finished_at * 1000).toLocaleString('zh-CN', { hour12: false })
                              : latest.status}
                          </p>
                          <p className="mt-1 break-all text-[#506483]">
                            目标：{latest.target_host_id || '未知'} · 来源：
                            {latest.source_region || latest.source_host_id || '未知'}
                            {latest.source_carrier ? ` / ${latest.source_carrier}` : ''} · 网段 {latest.source_network_id || '待识别'}
                          </p>
                          {latest.endpoints.length ? (
                            <div className="mt-1 space-y-1">
                              {latest.endpoints.map((endpoint, index) => {
                                const probeErrorLabels: Record<string, string> = {
                                  timeout: '连接超时（单次超时不证明阻断）',
                                  refused: '目标端口拒绝连接',
                                  family_unsupported: '探针系统不支持该 IP 版本',
                                  no_route: '探针缺少到目标的路由',
                                  host_unreachable: '探针网络报告目标不可达',
                                  local_policy_block: '探针本机策略拒绝连接',
                                  network_error: '未分类探针网络错误',
                                };
                                const endpointError = endpoint.error
                                  ? probeErrorLabels[endpoint.error] || endpoint.error
                                  : '';
                                return (
                                  <p
                                    key={`${endpoint.ip}:${endpoint.port}:${index}`}
                                    className={
                                      endpoint.success === true
                                        ? 'font-medium text-[#147468]'
                                        : endpoint.success === false
                                          ? 'font-medium text-[#9a5b00]'
                                          : 'text-[#506483]'
                                    }
                                  >
                                    <span className="font-mono font-semibold">
                                      {endpoint.ip}:{endpoint.port}
                                    </span>{' '}
                                    ·{' '}
                                    {endpoint.success === true
                                      ? `可连接${endpoint.latency_ms != null ? ` · ${endpoint.latency_ms.toFixed(1)} ms` : ''}`
                                      : endpoint.success === false
                                        ? endpointError || '连接失败'
                                        : `无端口结果${endpointError ? ` · ${endpointError}` : ''}`}
                                  </p>
                                );
                              })}
                            </div>
                          ) : (
                            <p className="mt-1 font-medium text-[#9a5b00]">
                              任务 {latest.status}，没有端口结果{latest.error ? ` · ${latest.error}` : ''}
                            </p>
                          )}
                        </div>
                      ) : (
                        <p className="mt-2 text-[#506483]">该角色尚无已完成探测结果。</p>
                      );
                    })()}
                  </div>
                );
              })}
            </div>
          )}
          {!!data?.probe_health?.recommendations?.length && (
            <div className="space-y-1 rounded-lg border border-[#f7d58b] bg-[#fef6e4] p-2.5 text-xs font-medium text-[#9a5b00]">
              {data.probe_health.recommendations.map((item, index) => (
                <p key={`${index}-${item}`}>{item}</p>
              ))}
            </div>
          )}
          {data?.probe_health?.last_attempt?.created_at ? (
            <p className="font-mono text-[11px] text-[#506483]">
              最近探测任务：{new Date(data.probe_health.last_attempt.created_at * 1000).toLocaleString('zh-CN', { hour12: false })} ·{' '}
              {data.probe_health.last_attempt.status || '未知'}
              {data.probe_health.last_attempt.error ? ` · ${data.probe_health.last_attempt.error}` : ''}
            </p>
          ) : (
            <p className="text-[11px] font-medium text-[#9a5b00]">
              尚无历史探测任务记录；满足覆盖与端点条件后由服务端自动创建任务。
            </p>
          )}
          <details className="border-t border-[#d2dfec] pt-2 text-[#31485e]">
            <summary className="cursor-pointer font-bold text-[#087bff]">没有可探测端口时怎么处理？</summary>
            <p className="mt-2 leading-5">
              Agent 会自动读取 Incus / Podman 端口发布、容器公网地址和宿主机现有 TCP DNAT 规则，并与容器实际监听端口核对。若公网映射由宿主机之外的上游 NAT 提供，且宿主机没有对应转发规则或可读映射，当前没有可靠数据可自动确定公网地址与端口；系统会继续显示待评估，不猜测并探测端口。
            </p>
          </details>
        </div>

        {error && (
          <p className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-3 text-xs font-medium text-[#b41835]" role="alert">
            {error}
          </p>
        )}

        <div className="grid min-w-0 gap-3 md:grid-cols-2">
          {data?.candidates.map((candidate) => (
            <div
              key={candidate.node_id}
              className="flex min-w-0 flex-wrap items-center justify-between gap-3 rounded-xl border border-[#cedae7] bg-white p-3.5 transition-colors hover:border-[#087bff]/50"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-bold text-[#0b1636]" title={candidate.host_id}>
                  {candidate.host_id}
                </p>
                <p className="mt-1 text-[11px] text-[#506483]">
                  Agent {candidate.agent_version || '未知'} · 最近上报{' '}
                  {candidate.last_seen ? new Date(candidate.last_seen * 1000).toLocaleString('zh-CN', { hour12: false }) : '未知'} ·{' '}
                  {candidate.role === 'disabled'
                    ? candidate.probe_online
                      ? 'Agent 在线'
                      : 'Agent 离线'
                    : candidate.probe_online
                      ? '探针在线'
                      : '探针离线'}{' '}
                  · 公网网段 {candidate.network_id || '等待 Agent 探测时自动识别'}
                </p>
                {candidate.role !== 'disabled' && (
                  <p className="mt-1 text-[11px] text-[#506483]">
                    路由上报：IPv4 {routeLabel(candidate.ipv4_default_route)} · IPv6 {routeLabel(candidate.ipv6_default_route)}
                    {candidate.route_capabilities_updated_at
                      ? ` · ${new Date(candidate.route_capabilities_updated_at * 1000).toLocaleString('zh-CN', { hour12: false })}`
                      : ''}
                  </p>
                )}
                {candidate.role !== 'disabled' &&
                  (!candidate.region || (candidate.role === 'mainland' && !candidate.carrier)) && (
                    <p className="mt-1 text-[11px] font-semibold text-[#9a5b00]">
                      覆盖信息未完整标注{!candidate.region ? ' · 地区' : ''}
                      {candidate.role === 'mainland' && !candidate.carrier ? ' · 运营商' : ''}
                    </p>
                  )}
                {candidate.role !== 'disabled' && (
                  <div className="mt-2 grid max-w-xl grid-cols-2 gap-2">
                    <input
                      aria-label={`${candidate.host_id} 探针地区`}
                      maxLength={80}
                      value={candidate.region || ''}
                      placeholder="地区（如：枣庄，山东）"
                      disabled={!!busyNode}
                      onChange={(event) => updateCandidate(candidate.node_id, 'region', event.target.value)}
                      onBlur={() => save(candidate, candidate.role)}
                      className="rn2-input-sm min-w-0 text-[11px]"
                    />
                    <input
                      aria-label={`${candidate.host_id} 探针运营商`}
                      maxLength={100}
                      value={candidate.carrier || ''}
                      placeholder="运营商（如：联通 BGP）"
                      disabled={!!busyNode}
                      onChange={(event) => updateCandidate(candidate.node_id, 'carrier', event.target.value)}
                      onBlur={() => save(candidate, candidate.role)}
                      className="rn2-input-sm min-w-0 text-[11px]"
                    />
                  </div>
                )}
              </div>
              <label className="flex shrink-0 items-center gap-2 text-xs text-[#31485e]">
                <span className="sr-only">{candidate.host_id} 的探测区域</span>
                {busyNode === candidate.node_id && <Loader2 size={14} className="animate-spin text-[#087bff]" />}
                <select
                  className="rn2-select-sm max-w-40"
                  value={candidate.role}
                  disabled={!!busyNode}
                  onChange={(event) => save(candidate, event.target.value as ProbeRole)}
                >
                  {(Object.keys(roleLabel) as ProbeRole[]).map((role) => (
                    <option key={role} value={role}>
                      {roleLabel[role]}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          ))}
        </div>
        {data && data.candidates.length === 0 && (
          <p className="mt-3 text-xs text-[#506483]">当前没有已注册的 Agent 节点。</p>
        )}
      </div>
    </section>
  );
};
