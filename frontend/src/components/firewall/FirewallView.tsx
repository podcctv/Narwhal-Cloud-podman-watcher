import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, ChevronLeft, ChevronRight, Clock3, Layers, LoaderCircle, Network, Plus, RefreshCw, Server, Shield, Trash2 } from 'lucide-react';
import { ContainerItem, FleetFirewallPolicyResponse, HostFirewallAbusePolicy, HostFirewallLiveRule, HostFirewallPolicyResponse, HostFirewallRule, SecurityStatusItem } from '../../api/types';
import { api } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { FirewallNodePicker } from './FirewallNodePicker';
import type { FirewallNodeFilter } from './FirewallNodePicker';

interface FirewallViewProps {
  containers: ContainerItem[];
  telemetry: SecurityStatusItem[];
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

type HostOption = { host_id: string; node_id: string; stale: boolean };
type RuleDraft = {
  priority: number;
  direction: 'in' | 'out';
  protocol: HostFirewallRule['protocol'];
  action: 'block' | 'pass';
  enabled: boolean;
  port_start: number;
  port_end: number | '';
  ip_type: HostFirewallRule['ip_type'];
  ip: string;
  countries: string;
};
type CnRiskDirection = 'in' | 'out' | 'both';
type CnRiskAction = 'pass' | 'block';
type CnRiskProtocol = 'socks' | 'wireguard' | 'fet' | 'mtproto' | 'openvpn';
type FirewallScope = 'host' | 'fleet';
type InterfaceFilter = 'all' | 'incus' | 'podman';

const FLEET_NODE_PAGE_SIZE = 6;

const cnRiskProtocolOptions: Array<{ protocol: CnRiskProtocol; label: string; note: string }> = [
  { protocol: 'socks', label: 'SOCKS', note: '协议特征识别，不代表服务未授权' },
  { protocol: 'wireguard', label: 'WireGuard', note: '基于可见握手特征识别' },
  { protocol: 'fet', label: '疑似 SS / FET', note: '高熵启发式，可能误报其他加密流量' },
  { protocol: 'mtproto', label: 'MTProto', note: '已知混淆初始化标记，覆盖不完整' },
  { protocol: 'openvpn', label: 'OpenVPN（仅入站）', note: 'VPN 协议命中不等于滥用' },
];

const emptyAbuse: HostFirewallAbusePolicy = { speedtest: false, mining: false, bt: false, interfaces: [], runtimes: [] };
const defaultDraft = (): RuleDraft => ({
  priority: 100, direction: 'in', protocol: 'tcp', action: 'block', enabled: true,
  port_start: 0, port_end: '', ip_type: 'any', ip: '', countries: '',
});
const statusLabel: Record<string, string> = {
  queued: '排队中', dispatched: '节点处理中', running: '执行中', succeeded: '已应用', failed: '执行失败', cancelled: '已被新配置取代',
};
const fleetStateLabel: Record<string, string> = {
  unregistered: '未注册 Agent', offline: '节点离线', awaiting_capability: '等待能力上报',
  awaiting_rfw_capability: '等待 RFW 协议能力核验', rfw_protocol_update_required: '缺少所需 RFW 协议能力',
  firewall_status_stale: '防火墙状态过期', runman_update_required: '需更新 Runman', runman_unavailable: 'Runman 不可用', queued: '策略排队中',
  awaiting_interfaces: '等待网卡清单', interfaces_not_found: '未发现目标网桥',
  apply_failed: '策略应用失败', drifted: '实际规则偏差', last_apply_succeeded: '最近回执成功', not_synced: '待同步', ready: '已就绪',
};
const protocolLabels: Record<string, string> = {
  http: 'HTTP', tls: 'TLS', socks: 'SOCKS', ssh: 'SSH', fet: 'FET',
  wireguard: 'WireGuard', openvpn: 'OpenVPN', quic: 'QUIC', mtproto: 'MTProto',
};
const readbackStatusLabel: Record<string, string> = {
  ready: 'RFW 读回可用', unavailable: 'RFW 读回不可用', unsupported: '需更新组件', unknown: '等待首次读回',
};
const syncStatusLabel: Record<string, string> = {
  in_sync: '与平台期望一致', drifted: '发现策略偏差', unknown: '尚无同步结果',
};
const runtimeReasonLabel: Record<string, string> = {
  ok: '接口探测正常',
  platform_unsupported: '当前操作系统不支持 Unix 控制接口',
  api_endpoint_missing: '接口路径不存在，Runman 版本过旧或服务未加载防火墙接口',
  unexpected_http: '接口返回异常 HTTP 状态',
  http_error: '本机控制接口响应格式异常',
  socket_missing: '缺少 /run/narwhal-agent/firewall.sock；检查 Runman 防火墙接口服务',
  socket_permission_denied: '当前 Agent 无权访问防火墙 socket；检查服务用户和 socket 权限',
  socket_refused: '防火墙 socket 存在但没有服务接收；检查 Runman 服务状态',
  socket_timeout: 'Runman 防火墙接口响应超时；检查服务是否卡住',
  socket_error: '连接本机防火墙 socket 失败；检查 socket 和服务状态',
  no_report: '尚未收到主机安全状态上报',
  no_capability_report: '上报中没有防火墙能力信息；更新并重启 Watcher Agent',
  legacy_report: '旧版 Agent 未提供失败原因；更新 Watcher Agent 后可查看具体原因',
};

const runtimeStatusHelp = (status?: HostFirewallPolicyResponse['runtime_status']) => {
  if (!status) return '等待 Watcher Agent 上报防火墙接口状态。';
  if (status.control_api_reason === 'no_report') return '还没有收到这台母机的安全状态上报；检查 Agent 是否已安装、运行并能连接主控。';
  if (status.control_api_reason === 'no_capability_report') return 'Agent 有上报，但内容没有 Runman 防火墙能力字段；更新并重启 Watcher Agent 后等待下一次上报。';
  if (status.stale) return '防火墙接口状态已超过 15 分钟未更新；先检查 Watcher Agent 是否持续上报，再刷新此页。';
  const reason = runtimeReasonLabel[status.control_api_reason || ''];
  if (status.control_api === 'unsupported') return (reason || 'Runman 防火墙 API 版本较旧') + '；更新 Runman 并重启其防火墙接口服务。';
  if (status.control_api === 'unavailable') {
    const http = status.control_api_http_status ? '（HTTP ' + status.control_api_http_status + '）' : '';
    return (reason || '无法连接 Runman 防火墙接口') + http + '。修复对应的 socket、权限或服务状态后刷新。';
  }
  if (status.control_api === 'ready') return 'Runman 防火墙控制接口可用；RFW 规则读回状态会单独显示。';
  return (reason || '等待能力上报') + '。检查 Watcher Agent 的安全状态上报。';
};

const newRuleKey = () => globalThis.crypto?.randomUUID?.() || `rule-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

export const FirewallView: React.FC<FirewallViewProps> = ({ containers, telemetry, onToast }) => {
  const hosts = useMemo(() => {
    const byId = new Map<string, HostOption>();
    containers.forEach((item) => byId.set(item.host_id, {
      host_id: item.host_id, node_id: '', stale: Boolean(item.alerts?.stale),
    }));
    telemetry.forEach((item) => byId.set(item.host_id, {
      host_id: item.host_id, node_id: item.node_id || '', stale: Boolean(item.stale),
    }));
    return [...byId.values()].sort((a, b) => a.host_id.localeCompare(b.host_id));
  }, [containers, telemetry]);

  const [hostId, setHostId] = useState('');
  const [scope, setScope] = useState<FirewallScope>('host');
  const [pendingScope, setPendingScope] = useState<FirewallScope | null>(null);
  const [scopeConfirmOpen, setScopeConfirmOpen] = useState(false);
  const [hostSearch, setHostSearch] = useState('');
  const [hostFilter, setHostFilter] = useState<FirewallNodeFilter>('all');
  const [fleetHostSearch, setFleetHostSearch] = useState('');
  const [fleetHostFilter, setFleetHostFilter] = useState<'all' | 'attention' | 'online' | 'offline' | 'interfaces' | 'drifted'>('attention');
  const [fleetNodePage, setFleetNodePage] = useState(0);
  const [hostInterfaceFilter, setHostInterfaceFilter] = useState<InterfaceFilter>('all');
  const [snapshot, setSnapshot] = useState<HostFirewallPolicyResponse | null>(null);
  const [fleetSnapshot, setFleetSnapshot] = useState<FleetFirewallPolicyResponse | null>(null);
  const [rules, setRules] = useState<HostFirewallRule[]>([]);
  const [abuse, setAbuse] = useState<HostFirewallAbusePolicy>(emptyAbuse);
  const [ruleDraft, setRuleDraft] = useState<RuleDraft>(defaultDraft);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [formError, setFormError] = useState('');
  const [fleetLoading, setFleetLoading] = useState(false);
  const [fleetSaving, setFleetSaving] = useState(false);
  const [fleetConfirmOpen, setFleetConfirmOpen] = useState(false);
  const [cnRiskDirection, setCnRiskDirection] = useState<CnRiskDirection>('both');
  const [cnRiskAction, setCnRiskAction] = useState<CnRiskAction>('pass');
  const [cnRiskProtocols, setCnRiskProtocols] = useState<CnRiskProtocol[]>(['socks', 'wireguard', 'fet']);
  const [pendingManualDelete, setPendingManualDelete] = useState<HostFirewallLiveRule | null>(null);
  const [deletingManualRuleId, setDeletingManualRuleId] = useState<number | null>(null);
  const [recoveryIntent, setRecoveryIntent] = useState<'retry' | 'rollback' | null>(null);
  const [recoveringPolicy, setRecoveringPolicy] = useState(false);

  const selectedHost = hosts.find((host) => host.host_id === hostId);
  const protocolCapability = (protocol: string): 'supported' | 'unsupported' | 'unknown' => {
    const readback = snapshot?.live_readback;
    if (!readback || readback.status !== 'ready' || readback.stale || !readback.capabilities_known) return 'unknown';
    const capability = readback.protocol_capabilities?.[protocol];
    if (capability) return capability;
    return readback.supported_protocols?.includes(protocol) ? 'supported' : 'unsupported';
  };
  const protocolCapabilityHelp = (protocol: string) => {
    const capability = protocolCapability(protocol);
    if (capability === 'unsupported') return `当前母机运行中的 RFW 未声明支持 ${protocolLabels[protocol] || protocol}；需要带有该协议检测能力的 RFW 构建，单独更新 Watcher Agent 不会增加协议识别能力。`;
    if (capability === 'unknown') return `尚未拿到当前母机新鲜的 RFW ${protocolLabels[protocol] || protocol} 能力读回；刷新状态并等待节点上报后再配置。`;
    return '';
  };
  const interfaceInventory = snapshot?.interface_inventory;
  const eligibleInterfaces = useMemo(
    () => (interfaceInventory?.interfaces || []).filter((item) => item.firewall_eligible && item.runtimes.length > 0),
    [interfaceInventory],
  );
  const visibleEligibleInterfaces = useMemo(
    () => hostInterfaceFilter === 'all'
      ? eligibleInterfaces
      : eligibleInterfaces.filter((item) => item.runtimes.includes(hostInterfaceFilter)),
    [eligibleInterfaces, hostInterfaceFilter],
  );
  const fleetHosts = fleetSnapshot?.hosts || [];
  const fleetAttentionCount = fleetHosts.filter((host) => !['last_apply_succeeded', 'ready'].includes(host.state)).length;
  const fleetInterfaceIssueCount = fleetHosts.filter((host) => host.container_interfaces.status !== 'ready'
    || host.container_interfaces.stale
    || (!host.container_interfaces.by_runtime.incus.length && !host.container_interfaces.by_runtime.podman.length)).length;
  const fleetDriftedCount = fleetHosts.filter((host) => host.state === 'drifted').length;
  const fleetNetworkCoverage = useMemo(() => ({
    incus: fleetHosts.filter((host) => host.container_interfaces.status === 'ready' && !host.container_interfaces.stale && host.container_interfaces.by_runtime.incus.length > 0).length,
    podman: fleetHosts.filter((host) => host.container_interfaces.status === 'ready' && !host.container_interfaces.stale && host.container_interfaces.by_runtime.podman.length > 0).length,
  }), [fleetHosts]);
  const filteredFleetHosts = useMemo(() => {
    const query = fleetHostSearch.trim().toLocaleLowerCase();
    const rank: Record<string, number> = {
      apply_failed: 0, drifted: 1, interfaces_not_found: 2, awaiting_interfaces: 3,
      runman_update_required: 4, runman_unavailable: 5, firewall_status_stale: 6,
      rfw_protocol_update_required: 7, offline: 8, awaiting_capability: 9,
      awaiting_rfw_capability: 10, queued: 11, not_synced: 12,
      last_apply_succeeded: 13, ready: 14, unregistered: 15,
    };
    return fleetHosts.filter((host) => {
      if (query && !host.host_id.toLocaleLowerCase().includes(query)) return false;
      if (fleetHostFilter === 'attention' && ['last_apply_succeeded', 'ready'].includes(host.state)) return false;
      if (fleetHostFilter === 'online' && !host.online) return false;
      if (fleetHostFilter === 'offline' && host.online) return false;
      if (fleetHostFilter === 'interfaces' && host.container_interfaces.status === 'ready'
        && !host.container_interfaces.stale
        && (host.container_interfaces.by_runtime.incus.length > 0 || host.container_interfaces.by_runtime.podman.length > 0)) return false;
      if (fleetHostFilter === 'drifted' && host.state !== 'drifted') return false;
      return true;
    }).sort((a, b) => (rank[a.state] ?? 20) - (rank[b.state] ?? 20) || a.host_id.localeCompare(b.host_id));
  }, [fleetHostFilter, fleetHostSearch, fleetHosts]);
  const fleetPageCount = Math.max(1, Math.ceil(filteredFleetHosts.length / FLEET_NODE_PAGE_SIZE));
  const currentFleetNodePage = Math.min(fleetNodePage, fleetPageCount - 1);
  const visibleFleetHosts = filteredFleetHosts.slice(
    currentFleetNodePage * FLEET_NODE_PAGE_SIZE,
    (currentFleetNodePage + 1) * FLEET_NODE_PAGE_SIZE,
  );
  const activeAction = snapshot?.latest_action;
  const pending = Boolean(activeAction && ['queued', 'dispatched', 'running'].includes(activeAction.status));
  const liveReadbackReady = Boolean(snapshot?.live_readback?.status === 'ready' && !snapshot.live_readback.stale);
  const hostRecoveryEditable = Boolean(snapshot?.agent_ready && snapshot?.runtime_status?.control_api === 'ready'
    && fleetSnapshot && fleetSnapshot.revision === 0);
  const canRetryPolicy = Boolean(hostRecoveryEditable && !selectedHost?.stale && liveReadbackReady && !pending
    && (activeAction?.status === 'failed' || snapshot?.live_readback?.sync_status === 'drifted'));
  const canRollbackPolicy = Boolean(hostRecoveryEditable && !selectedHost?.stale && liveReadbackReady && !pending
    && (snapshot?.policy_history?.length || 0) > 0);

  useEffect(() => setFleetNodePage(0), [fleetHostFilter, fleetHostSearch]);
  useEffect(() => setFleetNodePage((page) => Math.min(page, fleetPageCount - 1)), [fleetPageCount]);

  useEffect(() => {
    if (!hosts.length) {
      setHostId('');
      return;
    }
    if (!hosts.some((host) => host.host_id === hostId)) setHostId(hosts[0].host_id);
  }, [hosts, hostId]);

  const loadPolicy = useCallback(async (replaceDraft = true) => {
    if (!hostId) return;
    setLoading(true);
    try {
      const result = await api.getHostFirewallPolicy(hostId);
      setSnapshot(result);
      if (replaceDraft) {
        setRules(result.policy?.rules || []);
        const nextAbuse = { ...emptyAbuse, ...(result.policy?.abuse || {}) };
        setAbuse(nextAbuse);
        setDirty(false);
      }
    } catch (error: any) {
      onToast('error', `读取母机防火墙配置失败：${error.message || error}`);
    } finally {
      setLoading(false);
    }
  }, [hostId, onToast]);

  const loadFleetPolicy = useCallback(async () => {
    setFleetLoading(true);
    try {
      setFleetSnapshot(await api.getFleetFirewallPolicy());
    } catch (error: any) {
      onToast('error', `读取全局防火墙状态失败：${error.message || error}`);
    } finally {
      setFleetLoading(false);
    }
  }, [onToast]);

  useEffect(() => {
    void loadFleetPolicy();
    const timer = window.setInterval(() => { void loadFleetPolicy(); }, 30000);
    return () => window.clearInterval(timer);
  }, [loadFleetPolicy]);

  useEffect(() => {
    if (scope !== 'fleet' || !fleetSnapshot || fleetSnapshot.revision < 1 || dirty) return;
    setRules(fleetSnapshot.policy.rules || []);
    setAbuse({ ...emptyAbuse, ...(fleetSnapshot.policy.abuse || {}) });
  }, [fleetSnapshot, dirty, scope]);

  useEffect(() => {
    if (scope !== 'host') return;
    setSnapshot(null);
    setRules([]);
    setAbuse(emptyAbuse);
    setDirty(false);
    if (hostId) loadPolicy(true);
  }, [hostId, loadPolicy, scope]);

  useEffect(() => {
    if (!hostId || scope !== 'host') return;
    const timer = window.setInterval(() => { void loadPolicy(false); }, pending ? 4000 : 10000);
    return () => window.clearInterval(timer);
  }, [hostId, pending, loadPolicy, scope]);

  const updateDraft = <K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) => {
    setRuleDraft((current) => ({ ...current, [key]: value }));
  };

  const addRule = () => {
    setFormError('');
    if (scope === 'host' && ['http', 'tls', 'socks', 'ssh', 'fet', 'wireguard', 'openvpn', 'quic', 'mtproto'].includes(ruleDraft.protocol)) {
      const capability = protocolCapability(ruleDraft.protocol);
      if (capability !== 'supported') {
        setFormError(protocolCapabilityHelp(ruleDraft.protocol));
        return;
      }
    }
    if (ruleDraft.ip_type === 'cidr' && !ruleDraft.ip.trim()) {
      setFormError('请填写 CIDR 网段，例如 192.0.2.0/24。');
      return;
    }
    const countries = ruleDraft.countries.split(/[\s,，]+/).map((value) => value.trim().toUpperCase()).filter(Boolean);
    if (ruleDraft.ip_type === 'geoip' && (!countries.length || countries.some((value) => !/^[A-Z]{2}$/.test(value)))) {
      setFormError('GeoIP 请输入两位国家代码，例如 CN,US。');
      return;
    }
    const rule: HostFirewallRule = {
      key: newRuleKey(), priority: ruleDraft.priority, direction: ruleDraft.direction,
      protocol: ruleDraft.protocol, action: ruleDraft.action, enabled: ruleDraft.enabled,
      port_start: ruleDraft.port_start, ip_type: ruleDraft.ip_type,
      ...(ruleDraft.port_end === '' ? {} : { port_end: ruleDraft.port_end }),
      ...(ruleDraft.ip_type === 'cidr' ? { ip: ruleDraft.ip.trim() } : {}),
      ...(ruleDraft.ip_type === 'geoip' ? { countries: [...new Set(countries)] } : {}),
    };
    setRules((items) => [...items, rule]);
    setDirty(true);
    setRuleDraft(defaultDraft());
  };

  const copyManualRuleToPolicy = (source: HostFirewallLiveRule) => {
    if (scope !== 'host' || !canEdit) {
      onToast('error', '当前策略不可编辑；先确认母机在线、Runman 可用且没有全局模板锁定。');
      return;
    }
    if (!canDeleteManualRules) {
      onToast('error', '需要母机在线且 RFW 读回新鲜；当前留存快照不能作为迁移依据。');
      return;
    }
    if (source.direction === 'out' && !outboundProtocols.includes(source.protocol)) {
      onToast('error', `当前网页策略不支持 ${source.protocol} 出站匹配；原手工规则保持不变。`);
      return;
    }
    if (['http', 'tls', 'socks', 'ssh', 'fet', 'wireguard', 'openvpn', 'quic', 'mtproto'].includes(source.protocol)
        && protocolCapability(source.protocol) !== 'supported') {
      onToast('error', protocolCapabilityHelp(source.protocol) + '；原手工规则保持不变。');
      return;
    }
    const sameRule = (item: HostFirewallRule) => item.direction === source.direction
      && item.protocol === source.protocol && item.action === source.action
      && item.enabled === source.enabled && item.port_start === source.port_start
      && (item.port_end ?? item.port_start) === source.port_end
      && item.ip_type === source.ip_type && (item.ip || '') === (source.ip || '')
      && [...(item.countries || [])].sort().join(',') === [...(source.countries || [])].sort().join(',');
    if (rules.some(sameRule)) {
      onToast('info', '策略草稿里已经有相同规则；可直接编辑草稿，保存并确认读回后再处理原手工规则。');
      return;
    }
    const copy: HostFirewallRule = {
      key: newRuleKey(), priority: source.priority, direction: source.direction,
      protocol: source.protocol, action: source.action, enabled: source.enabled,
      port_start: source.port_start, ip_type: source.ip_type,
      ...(source.port_end === source.port_start ? {} : { port_end: source.port_end }),
      ...(source.ip_type === 'cidr' && source.ip ? { ip: source.ip } : {}),
      ...(source.ip_type === 'geoip' ? { countries: [...(source.countries || [])] } : {}),
    };
    setRules((items) => [...items, copy]);
    setDirty(true);
    onToast('info', '已复制到网页策略草稿。保存并在 RFW 读回确认新规则生效后，再删除原手工规则；迁移期间原规则会保留。');
  };

  const setAbuseOption = (key: 'speedtest' | 'mining' | 'bt', value: boolean) => {
    setAbuse((current) => ({ ...current, [key]: value }));
    setDirty(true);
  };

  const setAbuseInterfaces = (interfaces: string[]) => {
    setAbuse((current) => ({ ...current, interfaces: [...new Set(interfaces)] }));
    setDirty(true);
  };

  const toggleAbuseInterface = (name: string, checked: boolean) => {
    if (interfaceInventory?.stale) return;
    const current = abuse.interfaces || [];
    setAbuseInterfaces(checked ? [...current, name] : current.filter((item) => item !== name));
  };

  const toggleRuntimeInterfaces = (runtime: 'incus' | 'podman') => {
    if (interfaceInventory?.stale) return;
    const runtimeNames = eligibleInterfaces.filter((item) => item.runtimes.includes(runtime)).map((item) => item.name);
    if (!runtimeNames.length) return;
    const current = abuse.interfaces || [];
    const allSelected = runtimeNames.every((name) => current.includes(name));
    if (allSelected) {
      setAbuseInterfaces(current.filter((name) => {
        if (!runtimeNames.includes(name)) return true;
        const selected = eligibleInterfaces.find((item) => item.name === name);
        return Boolean(selected?.runtimes.some((other) => other !== runtime && current.includes(name)));
      }));
      return;
    }
    setAbuseInterfaces([...current, ...runtimeNames]);
  };

  const toggleFleetRuntime = (runtime: 'incus' | 'podman', checked: boolean) => {
    if (fleetNetworkCoverage[runtime] === 0) return;
    setAbuse((current) => {
      const selected = current.runtimes || [];
      const runtimes = checked
        ? [...new Set([...selected, runtime])]
        : selected.filter((item) => item !== runtime);
      return { ...current, interfaces: [], runtimes };
    });
    setDirty(true);
  };

  const removeRule = (key: string) => {
    setRules((items) => items.filter((rule) => rule.key !== key));
    setDirty(true);
  };

  const confirmManualRuleDelete = useCallback(async () => {
    if (!hostId || !pendingManualDelete || deletingManualRuleId !== null) return;
    const rule = pendingManualDelete;
    setDeletingManualRuleId(rule.id);
    try {
      const result = await api.deleteHostFirewallRule(hostId, rule.id);
      setPendingManualDelete(null);
      setSnapshot((current) => current ? {
        ...current,
        latest_action: { id: result.action_id, status: 'queued', message: `手工 RFW 规则 #${rule.id} 删除已排队`, updated_at_utc8: '' },
      } : current);
      onToast('success', `RFW 规则 #${rule.id} 的删除请求已排队；母机执行后会读回确认。`);
      void loadPolicy(false);
    } catch (error: any) {
      onToast('error', `RFW 规则未删除：${error.message || error}`);
    } finally {
      setDeletingManualRuleId(null);
    }
  }, [deletingManualRuleId, hostId, loadPolicy, onToast, pendingManualDelete]);

  const addCnRiskPolicyPreset = () => {
    const directions: Array<'in' | 'out'> = cnRiskDirection === 'both'
      ? ['in', 'out']
      : [cnRiskDirection];
    const protocols = cnRiskProtocols;
    if (scope === 'host') {
      const unavailable = protocols.filter((protocol) => protocolCapability(protocol) !== 'supported');
      if (unavailable.length) {
        onToast('error', unavailable.map((protocol) => protocolCapabilityHelp(protocol)).join(' '));
        return;
      }
    }
    if (!protocols.length) {
      onToast('error', '请至少选择一种当前方向支持的协议。');
      return;
    }
    const nextRules = [...rules];
    let added = 0;
    let adjusted = 0;
    for (const protocol of protocols) {
      const protocolDirections: Array<'in' | 'out'> = protocol === 'openvpn' ? ['in'] : directions;
      for (const direction of protocolDirections) {
        const matching = nextRules
          .map((rule, index) => ({ rule, index }))
          .filter(({ rule }) => rule.direction === direction
            && rule.protocol === protocol
            && rule.ip_type === 'geoip'
            && rule.countries?.length === 1
            && rule.countries[0].toUpperCase() === 'CN'
            && rule.port_start === 0
            && (rule.port_end === undefined || rule.port_end === 0));
        if (matching.length) {
          for (const { rule, index } of matching) {
            if (rule.action !== cnRiskAction || !rule.enabled) {
              nextRules[index] = { ...rule, action: cnRiskAction, enabled: true };
              adjusted += 1;
            }
          }
          continue;
        }
        nextRules.push({
          key: newRuleKey(), priority: 100000 - added, direction, protocol,
          action: cnRiskAction, enabled: true, port_start: 0, ip_type: 'geoip', countries: ['CN'],
        });
        added += 1;
      }
    }
    if (nextRules.length > 64) {
      onToast('error', `RFW 最多支持 64 条规则；本次需要 ${nextRules.length - rules.length} 条空位，当前有 ${rules.length} 条。`);
      return;
    }
    if (!added && !adjusted) {
      onToast('info', '所选 CN 协议与方向规则已存在且启用；没有重复添加。');
      return;
    }
    setRules(nextRules);
    setDirty(true);
    const directionLabel = cnRiskDirection === 'both' ? '入站来源与出站目标' : cnRiskDirection === 'in' ? '入站来源' : '出站目标';
    const actionLabel = cnRiskAction === 'pass' ? '仅告警（流量仍放行）' : '阻断并告警';
    const openVpnNote = cnRiskProtocols.includes('openvpn') ? '；OpenVPN 固定按入站匹配，其它协议按所选方向匹配' : '';
    onToast('info', `CN ${directionLabel}规则草稿已更新：新增 ${added} 条、调整 ${adjusted} 条；${actionLabel}${openVpnNote}。草稿尚未生效，请检查后保存或同步全局。`);
  };

  const confirmApply = useCallback(async () => {
    if (!hostId || saving) return;
    const anyAbuseEnabled = abuse.speedtest || abuse.mining || abuse.bt;
    const interfaces = anyAbuseEnabled ? [...new Set((abuse.interfaces || []).map((item) => item.trim()).filter(Boolean))] : [];
    const knownInterfaces = new Set(eligibleInterfaces.map((item) => item.name));
    const unknownInterfaces = interfaces.filter((name) => !knownInterfaces.has(name));
    if (interfaces.length > 16 || (anyAbuseEnabled && (!interfaces.length || interfaceInventory?.status !== 'ready' || interfaceInventory.stale || unknownInterfaces.length > 0))) {
      setConfirmOpen(false);
      onToast('error', interfaceInventory?.stale ? '网卡清单已过期，请刷新并等待母机重新上报后再应用。' : unknownInterfaces.length ? `以下网卡已不在当前采集清单中，请先从草稿移除：${unknownInterfaces.join(', ')}` : '启用防滥用规则前，请从最新采集到的 Incus / Podman 网桥中至少选择一个。');
      return;
    }
    const policyAbuse = { ...abuse, interfaces, runtimes: [] };
    setSaving(true);
    try {
      const result = await api.updateHostFirewallPolicy(hostId, { rules, abuse: policyAbuse });
      setSnapshot((current) => current ? {
        ...current,
        revision: result.revision,
        policy: { rules, abuse: policyAbuse },
        latest_action: { id: result.action_id, status: 'queued', message: '', updated_at_utc8: '' },
      } : current);
      setAbuse(policyAbuse);
      setDirty(false);
      setConfirmOpen(false);
      onToast('success', `策略版本 #${result.revision} 已保存，等待母机 Agent 执行。`);
    } catch (error: any) {
      onToast('error', `策略未能排队：${error.message || error}`);
    } finally {
      setSaving(false);
    }
  }, [abuse, eligibleInterfaces, hostId, interfaceInventory, onToast, rules, saving]);

  const confirmPolicyRecovery = useCallback(async () => {
    if (!hostId || !recoveryIntent || recoveringPolicy) return;
    setRecoveringPolicy(true);
    try {
      const result = await api.recoverHostFirewallPolicy(hostId, recoveryIntent);
      onToast('success', recoveryIntent === 'retry'
        ? `策略重试已排队，当前策略版本 #${result.revision}。`
        : `已将历史版本 #${result.restored_revision} 作为新版本 #${result.revision} 排队回滚。`);
      setRecoveryIntent(null);
      await loadPolicy(false);
    } catch (error: any) {
      onToast('error', `防火墙策略${recoveryIntent === 'retry' ? '重试' : '回滚'}未能排队：${error.message || error}`);
    } finally {
      setRecoveringPolicy(false);
    }
  }, [hostId, loadPolicy, onToast, recoveringPolicy, recoveryIntent]);

  const confirmFleetApply = useCallback(async () => {
    if (fleetSaving) return;
    const anyAbuseEnabled = abuse.speedtest || abuse.mining || abuse.bt;
    const runtimes = anyAbuseEnabled ? [...new Set(abuse.runtimes || [])] : [];
    const uncoveredRuntimes = runtimes.filter((runtime) => fleetNetworkCoverage[runtime] === 0);
    if (anyAbuseEnabled && (!runtimes.length || uncoveredRuntimes.length)) {
      setFleetConfirmOpen(false);
      onToast('error', !runtimes.length
        ? '启用全局防滥用规则前，请至少选择 Incus 或 Podman。'
        : `所选运行时目前没有任何节点报告可用网桥：${uncoveredRuntimes.map((runtime) => runtime === 'incus' ? 'Incus' : 'Podman').join('、')}。请刷新节点清单或取消该选择。`);
      return;
    }
    setFleetSaving(true);
    try {
      const policyAbuse = { ...abuse, interfaces: [], runtimes };
      const result = await api.updateFleetFirewallPolicy({ rules, abuse: policyAbuse });
      setFleetConfirmOpen(false);
      setAbuse(policyAbuse);
      setDirty(false);
      await loadFleetPolicy();
      const deferredForNetwork = result.network_deferred_hosts ?? 0;
      onToast('success', `全局策略版本 #${result.revision} 已保存：${result.queued_hosts} 台已排队，${deferredForNetwork} 台等待网卡清单，${Math.max(0, result.deferred_hosts - deferredForNetwork)} 台等待其它能力上线。`);
    } catch (error: any) {
      onToast('error', `全局策略未能保存：${error.message || error}`);
    } finally {
      setFleetSaving(false);
    }
  }, [abuse, fleetNetworkCoverage, fleetSaving, loadFleetPolicy, onToast, rules]);

  const loadFleetDraft = () => {
    if (!fleetSnapshot) return;
    setRules(fleetSnapshot.policy.rules || []);
    setAbuse({ ...emptyAbuse, ...(fleetSnapshot.policy.abuse || {}) });
    setDirty(false);
    onToast('info', `已载入全局策略版本 #${fleetSnapshot.revision} 到编辑器。`);
  };

  const applyScopeChange = (next: FirewallScope) => {
    setScope(next);
    setFormError('');
    setDirty(false);
    if (next === 'fleet') {
      if (fleetSnapshot && fleetSnapshot.revision > 0) {
        setRules(fleetSnapshot.policy.rules || []);
        setAbuse({ ...emptyAbuse, ...(fleetSnapshot.policy.abuse || {}) });
      } else {
        setRules([]);
        setAbuse(emptyAbuse);
      }
      return;
    }
    if (hostId) void loadPolicy(true);
  };

  const requestScopeChange = (next: FirewallScope) => {
    if (next === scope) return;
    if (dirty) {
      setPendingScope(next);
      setScopeConfirmOpen(true);
      return;
    }
    applyScopeChange(next);
  };

  const copyHostDraftToFleet = async () => {
    if (!hostId || !snapshot) return;
    try {
      const hostPolicy = await api.getHostFirewallPolicy(hostId);
      const selectedNames = new Set(hostPolicy.policy.abuse.interfaces || []);
      const runtimes = [...new Set((hostPolicy.interface_inventory?.interfaces || [])
        .filter((item) => selectedNames.has(item.name) && item.firewall_eligible)
        .flatMap((item) => item.runtimes))];
      setRules(hostPolicy.policy.rules || []);
      setAbuse({ ...emptyAbuse, ...hostPolicy.policy.abuse, interfaces: [], runtimes });
      setDirty(true);
      onToast('info', `已从 ${hostId} 复制规则；容器网卡已转换为运行时选择（${runtimes.map((item) => item === 'incus' ? 'Incus' : 'Podman').join(' + ') || '未选择'}），请检查后再同步。`);
    } catch (error: any) {
      onToast('error', `复制单机策略失败：${error.message || error}`);
    }
  };

  if (!hosts.length) {
    return <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-6 text-center">
      <Shield className="mx-auto h-8 w-8 text-slate-500" aria-hidden="true" />
      <h2 className="mt-3 text-base font-semibold text-slate-100">暂无可配置母机</h2>
      <p className="mt-2 text-sm text-slate-400">主机首次上报后会出现在这里。</p>
    </section>;
  }

  const outboundProtocols: HostFirewallRule['protocol'][] = ['all', 'tcp', 'udp', 'socks', 'fet', 'wireguard', 'mtproto'];
  const protocols: HostFirewallRule['protocol'][] = ['all', 'tcp', 'udp', 'http', 'tls', 'socks', 'ssh', 'fet', 'wireguard', 'openvpn', 'quic', 'mtproto'];
  const runtimeReady = snapshot?.runtime_status?.control_api === 'ready' && !snapshot.runtime_status.stale;
  const fleetAuthoritative = (fleetSnapshot?.revision ?? 0) > 0;
  const canEdit = scope === 'host'
    ? Boolean(snapshot?.agent_ready && runtimeReady && fleetSnapshot && !fleetAuthoritative)
    : Boolean(fleetSnapshot);
  const canDeleteManualRules = Boolean(scope === 'host' && snapshot?.agent_ready && runtimeReady
    && !selectedHost?.stale && snapshot?.live_readback?.status === 'ready' && !snapshot.live_readback.stale);
  const blockingRules = rules.filter((rule) => rule.enabled && rule.action === 'block').length;
  const enabledAbuse = Number(abuse.speedtest) + Number(abuse.mining) + Number(abuse.bt);
  const anyAbuseEnabled = enabledAbuse > 0;

  return <div className="mx-auto mt-6 max-w-6xl space-y-5 pb-8">
    <header className="flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
      <div className="flex min-w-0 items-start gap-3">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-700/60 bg-sky-950/50 text-sky-300"><Shield className="h-5 w-5" aria-hidden="true" /></span>
        <div className="min-w-0">
          <h2 className="text-lg font-bold text-slate-100">母机防火墙策略</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">单机或全局保存期望策略，由 Watcher 排队并通过本机 Runman 的受限 Unix 接口应用到 RFW。</p>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">8792 是 Agent 面板端口；RFW API 默认仅监听 127.0.0.1:7734（地址可配置）。Watcher 通过 Agent 受限控制通道读回和同步，不需要将 RFW API 暴露到公网。</p>
        </div>
      </div>
      <button type="button" onClick={() => scope === 'host' ? void loadPolicy(true) : void loadFleetPolicy()} disabled={scope === 'host' ? loading || !hostId : fleetLoading} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-200 transition-colors hover:bg-slate-700 focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:opacity-50">
        {(scope === 'host' ? loading : fleetLoading) ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}刷新状态
      </button>
    </header>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-2" aria-label="选择防火墙配置范围">
      <div className="grid gap-2 sm:grid-cols-2" role="tablist" aria-label="防火墙配置范围">
        {([
          ['host', '单台母鸡', '只改当前选中的节点', Server],
          ['fleet', '全体母鸡', '按每台节点的运行时自动匹配网卡', Layers],
        ] as const).map(([key, title, description, Icon]) => <button key={key} type="button" role="tab" aria-selected={scope === key} onClick={() => requestScopeChange(key)} className={`flex min-h-16 items-center gap-3 rounded-xl border px-4 py-3 text-left transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400 ${scope === key ? 'border-sky-600 bg-sky-950/50' : 'border-transparent bg-slate-950/40 hover:border-slate-700'}`}>
          <Icon className={`h-5 w-5 shrink-0 ${scope === key ? 'text-sky-300' : 'text-slate-500'}`} aria-hidden="true" />
          <span className="min-w-0"><span className="block text-sm font-semibold text-slate-100">{title}</span><span className="mt-0.5 block text-xs leading-4 text-slate-400">{description}</span></span>
          {scope === key && <Check className="ml-auto h-4 w-4 shrink-0 text-sky-300" aria-hidden="true" />}
        </button>)}
      </div>
    </section>

    {scope === 'host' && <section className="grid gap-4 lg:grid-cols-[minmax(240px,0.8fr)_minmax(0,1.2fr)]">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <FirewallNodePicker
          hosts={hosts}
          fleetHosts={fleetHosts}
          selectedHostId={hostId}
          search={hostSearch}
          filter={hostFilter}
          onSearchChange={setHostSearch}
          onFilterChange={setHostFilter}
          onSelect={setHostId}
        />
        <details className="mt-3 rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <summary className="cursor-pointer select-none text-xs font-medium text-slate-300">查看所选母机的能力与同步详情</summary>
          <div className="mt-3 flex flex-wrap gap-2 text-[10px]">
            <span className={`rounded-full border px-2.5 py-1 ${selectedHost?.stale ? 'border-amber-700 bg-amber-950/50 text-amber-200' : 'border-emerald-700 bg-emerald-950/50 text-emerald-200'}`}>{selectedHost?.stale ? '心跳过期' : '心跳正常'}</span>
            <span className={`rounded-full border px-2.5 py-1 ${snapshot?.agent_ready ? 'border-sky-700 bg-sky-950/50 text-sky-200' : 'border-slate-700 bg-slate-950 text-slate-300'}`}>{snapshot?.agent_ready ? 'Watcher 已注册' : 'Watcher 未注册'}</span>
            <span className={`rounded-full border px-2.5 py-1 ${runtimeReady ? 'border-emerald-700 bg-emerald-950/50 text-emerald-200' : snapshot?.runtime_status?.control_api === 'unsupported' ? 'border-amber-700 bg-amber-950/50 text-amber-200' : 'border-slate-700 bg-slate-950 text-slate-300'}`}>{snapshot?.runtime_status?.stale ? '防火墙状态过期' : runtimeReady ? 'Runman 防火墙接口可用' : snapshot?.runtime_status?.control_api === 'unsupported' ? '需更新 Runman' : snapshot?.runtime_status?.control_api === 'unavailable' ? 'Runman 接口不可用' : '等待能力上报'}</span>
            {snapshot && <span className="rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-slate-300">策略版本 #{snapshot.revision}</span>}
            {snapshot?.live_readback && <span className={`rounded-full border px-2.5 py-1 ${snapshot.live_readback.status === 'ready' && !snapshot.live_readback.stale ? snapshot.live_readback.sync_status === 'drifted' ? 'border-rose-800 bg-rose-950/50 text-rose-200' : 'border-emerald-800 bg-emerald-950/50 text-emerald-200' : 'border-amber-800 bg-amber-950/50 text-amber-200'}`}>{readbackStatusLabel[snapshot.live_readback.status]} · {syncStatusLabel[snapshot.live_readback.sync_status || 'unknown']}</span>}
          </div>
        </details>
        {selectedHost?.stale && <p className="mt-3 text-xs leading-5 text-amber-200">母机当前离线。可以保存期望配置，Agent 恢复连接后会自动执行。</p>}
        {snapshot?.agent_ready && !runtimeReady && <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100/80">{runtimeStatusHelp(snapshot?.runtime_status)} 如果 RFW 读回同时显示不可用或过期，那是另一条链路；先分别检查 Runman 控制 socket 和 RFW API，再刷新状态。</p>}
        {snapshot?.live_readback?.mtproto_support === 'unsupported' && !snapshot.live_readback.stale && <p className="mt-3 rounded-lg border border-rose-900/70 bg-rose-950/30 p-3 text-xs leading-5 text-rose-100/90">这台母机当前运行的 RFW 能力清单没有 MTProto。需要先发布并安装包含 MTProto 检测能力的 RFW 构建，再刷新并确认能力读回；只升级 Watcher Agent 或 Runman 不会补上 RFW 的协议识别实现。</p>}
        {snapshot?.live_readback?.mtproto_support === 'unknown' && <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100/90">这台母机还没有新鲜的 MTProto 能力读回。先刷新状态并等待节点上报；未知状态下系统不会排队应用 MTProto 规则。</p>}
        {fleetAuthoritative && <p className="mt-3 text-xs leading-5 text-sky-200">全局模板版本 #{fleetSnapshot?.revision} 已启用并作为统一期望策略；此处单机编辑已锁定。请在下方编辑并同步全局模板。</p>}
        {!fleetSnapshot && <p className="mt-3 text-xs leading-5 text-slate-400">正在确认全局策略状态；读取完成前暂不开放单机下发。</p>}
      </div>

      <div className="rounded-2xl border border-amber-800/60 bg-amber-950/20 p-4">
        <div className="flex gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
          <div>
            <h3 className="text-sm font-semibold text-amber-100">生效范围与保护边界</h3>
            <ul className="mt-2 space-y-1.5 text-xs leading-5 text-amber-100/80">
              <li>RFW 原生规则作用于母机 RFW 接口，可能影响这台母机上的所有业务和容器。</li>
              <li>下方三项防滥用规则只匹配容器转发流量，不改宿主机 INPUT/OUTPUT；本地手工 RFW 规则不由本页面删除或覆盖。</li>
              <li>本页只配置并核验经 Agent/RFW 接口登记的规则；不会管理 UFW、nftables、iptables、firewalld、云厂商安全组或其他独立防火墙，因此不能代表宿主机全部防火墙配置。</li>
              <li>Incus 与系统防火墙可能相互影响；本地手工 RFW 规则需逐条确认后才可删除。应用后请核对节点读回与实际网络状态。</li>
              <li>未启用进程强杀、容器文件陷阱、内核参数修改或任意脚本执行。</li>
            </ul>
          </div>
        </div>
      </div>
    </section>}

    {scope === 'fleet' && <section className="rounded-2xl border border-sky-800/60 bg-slate-900/70 p-4 sm:p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <h3 className="text-sm font-bold text-slate-100">全局策略模板 <span className="ml-2 font-normal text-slate-400">版本 #{fleetSnapshot?.revision ?? 0}</span></h3>
          <p className="mt-1 text-xs leading-5 text-slate-400">模板只保存 Incus / Podman 目标；每台母机按自己的最新网卡清单解析 bridge。网卡未上报或没有匹配网络的节点会等待，不会猜接口名或错误套用。</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void loadFleetPolicy()} disabled={fleetLoading} className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50">{fleetLoading ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />}刷新全局状态</button>
          {fleetSnapshot && fleetSnapshot.revision > 0
            ? <button type="button" onClick={loadFleetDraft} className="inline-flex min-h-10 items-center justify-center rounded-lg border border-slate-700 bg-slate-800 px-3 text-xs text-slate-200 hover:bg-slate-700">重新载入已保存模板</button>
            : <button type="button" onClick={() => void copyHostDraftToFleet()} disabled={!snapshot || !hostId} className="inline-flex min-h-10 items-center justify-center rounded-lg border border-slate-700 bg-slate-800 px-3 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50">从所选母鸡复制规则</button>}
        </div>
      </div>
      {fleetSnapshot && <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          ['管理节点', fleetSnapshot.counts.total], ['在线节点', fleetSnapshot.counts.online],
          ['应用成功', fleetSnapshot.counts.last_apply_succeeded], ['需关注', fleetAttentionCount],
        ].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <div className="text-[10px] text-slate-500">{label}</div><div className="mt-1 font-mono text-lg font-semibold tabular-nums text-slate-100">{value}</div>
        </div>)}
      </div>}
      {fleetSnapshot && <details className="mt-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
        <summary className="cursor-pointer select-none text-xs font-medium text-slate-300">更多同步指标 <span className="ml-1 text-slate-500">待处理 {fleetSnapshot.counts.deferred} · 网卡待映射 {fleetSnapshot.counts.network_deferred} · 策略偏差 {fleetSnapshot.counts.drifted_hosts}</span></summary>
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
          {[
            ['Runman 可用', fleetSnapshot.counts.control_ready], ['读回正常', fleetSnapshot.counts.live_readback_current],
            ['读回异常 / 过期', fleetSnapshot.counts.readback_unavailable],
            ['协议支持 / 需升级 / 待核验', `${fleetSnapshot.counts.required_protocols_supported_hosts} / ${fleetSnapshot.counts.required_protocols_unsupported_hosts} / ${fleetSnapshot.counts.required_protocols_unknown_hosts}`],
          ].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className="text-[10px] text-slate-500">{label}</div><div className="mt-1 font-mono text-sm font-semibold tabular-nums text-slate-200">{value}</div>
          </div>)}
        </div>
      </details>}
      <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
        <span className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-slate-300">Incus 网桥可映射 <strong className="ml-1 font-mono tabular-nums text-slate-100">{fleetNetworkCoverage.incus}/{fleetHosts.length}</strong> 台</span>
        <span className="rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-slate-300">Podman 网桥可映射 <strong className="ml-1 font-mono tabular-nums text-slate-100">{fleetNetworkCoverage.podman}/{fleetHosts.length}</strong> 台</span>
      </div>
      <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h4 className="text-xs font-semibold text-slate-200">母机同步状态</h4>
            <p className="mt-1 text-[10px] text-slate-500">{filteredFleetHosts.length} / {fleetHosts.length} 台 · 待处理 {fleetAttentionCount} · 每页最多 {FLEET_NODE_PAGE_SIZE} 台</p>
          </div>
          <input type="search" value={fleetHostSearch} onChange={(event) => setFleetHostSearch(event.target.value)} placeholder="搜索母机…" className="min-h-10 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-hidden focus:ring-2 focus:ring-sky-400 sm:max-w-xs" aria-label="搜索全局策略母机" />
        </div>
        <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="按状态筛选母机">
          {([
            ['attention', `需关注 ${fleetAttentionCount}`], ['all', `全部 ${fleetHosts.length}`],
            ['online', `在线 ${fleetSnapshot?.counts.online ?? 0}`], ['offline', `离线 ${Math.max(0, fleetHosts.length - (fleetSnapshot?.counts.online ?? 0))}`],
            ['interfaces', `网卡待处理 ${fleetInterfaceIssueCount}`], ['drifted', `策略偏差 ${fleetDriftedCount}`],
          ] as const).map(([key, label]) => <button key={key} type="button" onClick={() => setFleetHostFilter(key)} aria-pressed={fleetHostFilter === key} className={`min-h-9 rounded-lg border px-3 text-[11px] transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400 ${fleetHostFilter === key ? 'border-sky-700 bg-sky-950/60 text-sky-100' : 'border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800'}`}>{label}</button>)}
        </div>
        {filteredFleetHosts.length ? <>
          <div className="mt-3 space-y-1.5">
          {visibleFleetHosts.map((host) => <details key={host.host_id} className="rounded-lg border border-slate-800 bg-slate-950/70">
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5">
              <strong className="min-w-0 flex-1 break-all text-[11px] text-slate-200">{host.host_id}</strong>
              <span className={`rounded-full border px-2 py-0.5 text-[10px] ${host.state === 'last_apply_succeeded' || host.state === 'ready' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200' : host.state === 'apply_failed' || host.state === 'runman_update_required' || host.state === 'rfw_protocol_update_required' || host.state === 'drifted' ? 'border-rose-800 bg-rose-950/40 text-rose-200' : 'border-amber-800 bg-amber-950/40 text-amber-200'}`}>{fleetStateLabel[host.state] || host.state}</span>
              <span className={`text-[10px] ${host.container_interfaces.stale || host.container_interfaces.status !== 'ready' ? 'text-amber-300' : 'text-slate-500'}`}>{host.container_interfaces.stale || host.container_interfaces.status !== 'ready' ? '网卡清单过期/未采集' : `${host.container_interfaces.by_runtime.incus.length ? `Incus ${host.container_interfaces.by_runtime.incus.length}` : ''}${host.container_interfaces.by_runtime.incus.length && host.container_interfaces.by_runtime.podman.length ? ' · ' : ''}${host.container_interfaces.by_runtime.podman.length ? `Podman ${host.container_interfaces.by_runtime.podman.length}` : ''}${!host.container_interfaces.by_runtime.incus.length && !host.container_interfaces.by_runtime.podman.length ? '无可用容器网桥' : ''}`}</span>
              <span className="text-[10px] text-slate-500">Watcher {host.agent_version}</span>
              <span className={`text-[10px] ${host.live_readback.sync_status === 'drifted' && !host.live_readback.stale ? 'text-rose-300' : host.live_readback.status === 'ready' && !host.live_readback.stale ? 'text-emerald-300' : 'text-amber-300'}`}>{readbackStatusLabel[host.live_readback.status] || '等待读回'}{host.live_readback.stale ? ' · 过期' : ''}</span>
            </summary>
            <div className="grid gap-2 border-t border-slate-800 px-3 py-3 text-[10px] sm:grid-cols-2">
              <div className="text-slate-400">本地修订 <span className="font-mono tabular-nums text-slate-200">#{host.local_revision}</span> · 全局修订 <span className="font-mono tabular-nums text-slate-200">#{host.fleet_revision}</span></div>
              <div className={host.control_api_stale || host.control_api === 'unavailable' || host.control_api === 'unsupported' ? 'text-amber-300' : 'text-slate-400'}>
                Runman 控制接口：{host.control_api_stale ? '状态过期' : host.control_api === 'ready' ? '可用' : host.control_api === 'unsupported' ? '需更新' : host.control_api === 'unavailable' ? '不可用' : '未知'} · {runtimeReasonLabel[host.control_api_reason || ''] || '旧版 Agent 未提供原因'}{host.control_api_http_status ? '（HTTP ' + host.control_api_http_status + '）' : ''}
              </div>
              <div className={host.unsupported_protocols?.length ? 'text-rose-300' : host.unknown_protocols?.length ? 'text-amber-300' : 'text-emerald-300'}>
                {host.required_protocols?.length
                  ? host.unsupported_protocols?.length
                    ? `RFW 未声明支持：${host.unsupported_protocols.map((protocol) => protocolLabels[protocol] || protocol).join(', ')}`
                    : host.unknown_protocols?.length
                      ? `等待新鲜能力读回：${host.unknown_protocols.map((protocol) => protocolLabels[protocol] || protocol).join(', ')}`
                      : `能力已确认：${host.required_protocols.map((protocol) => protocolLabels[protocol] || protocol).join(', ')}`
                  : '当前策略无需应用层协议能力'}{host.live_readback.rfw_api_version ? ` · RFW API ${host.live_readback.rfw_api_version}` : ''}
              </div>
              <div className="text-slate-400">实际规则 <span className="font-mono tabular-nums text-slate-200">{host.live_readback.rule_count ?? 0}</span> 条 · 平台管理 <span className="font-mono tabular-nums text-slate-200">{host.live_readback.managed_rule_count ?? 0}</span> 条{(host.live_readback.drift_count || host.live_readback.missing_count) ? ` · 偏差 ${host.live_readback.drift_count || 0} / 缺失 ${host.live_readback.missing_count || 0}` : ''}</div>
              <div className={host.container_interfaces.stale || host.container_interfaces.status !== 'ready' ? 'text-amber-300' : 'text-slate-400'}>
                网卡清单{host.container_interfaces.stale || host.container_interfaces.status !== 'ready' ? '未就绪 / 过期' : '最新'} · Incus: <code className="text-slate-200">{host.container_interfaces.by_runtime.incus.join(', ') || '无'}</code> · Podman: <code className="text-slate-200">{host.container_interfaces.by_runtime.podman.join(', ') || '无'}</code>
              </div>
              {host.last_action?.message && <p className="wrap-break-word leading-4 text-slate-400 sm:col-span-2">{host.last_action.message}</p>}
            </div>
          </details>)}
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2" aria-label="全局策略母机分页">
            <span className="text-[10px] text-slate-500">显示 {currentFleetNodePage * FLEET_NODE_PAGE_SIZE + 1}–{Math.min((currentFleetNodePage + 1) * FLEET_NODE_PAGE_SIZE, filteredFleetHosts.length)} / {filteredFleetHosts.length} 台</span>
            <div className="flex gap-1.5">
              <button type="button" onClick={() => setFleetNodePage(Math.max(0, currentFleetNodePage - 1))} disabled={currentFleetNodePage === 0} aria-label="上一页全局策略母机" className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-slate-700 px-2.5 text-[10px] text-slate-300 hover:bg-slate-800 focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-40"><ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />上一页</button>
              <span className="inline-flex min-h-9 min-w-12 items-center justify-center rounded-lg border border-slate-800 bg-slate-950 px-2 font-mono text-[10px] tabular-nums text-slate-400">{currentFleetNodePage + 1} / {fleetPageCount}</span>
              <button type="button" onClick={() => setFleetNodePage(Math.min(fleetPageCount - 1, currentFleetNodePage + 1))} disabled={currentFleetNodePage >= fleetPageCount - 1} aria-label="下一页全局策略母机" className="inline-flex min-h-9 items-center gap-1 rounded-lg border border-slate-700 px-2.5 text-[10px] text-slate-300 hover:bg-slate-800 focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-40">下一页<ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></button>
            </div>
          </div>
        </> : <p className="mt-3 rounded-lg border border-slate-800 bg-slate-950 px-3 py-4 text-center text-xs text-slate-500">没有符合当前筛选条件的母机。</p>}
      </div>
      <p className="mt-4 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[11px] leading-5 text-amber-100/80">实时读回来自节点运行中 RFW 的规则 API，并与平台管理的期望规则逐项比对；它不是直接读取 eBPF 内核 map。手工规则只能在新鲜读回后逐条确认删除；平台规则从期望列表移除并应用，避免被自动同步重新创建。MTProto 策略仅下发给能力明确支持的节点。</p>
    </section>}

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="flex flex-col gap-2 border-b border-slate-800 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <div>
          <h3 className="text-sm font-bold text-slate-100">所选母机的 RFW 实际规则</h3>
          <p className="mt-1 text-xs leading-5 text-slate-400">读取母机 RFW 当前规则；平台规则从期望列表移除后应用，手工规则可在新鲜读回并确认后单条删除。</p>
        </div>
        {snapshot?.live_readback?.last_success_at ? <span className="text-[10px] text-slate-500">最近成功读回：{new Date(snapshot.live_readback.last_success_at * 1000).toLocaleString()}</span> : null}
      </div>
      {snapshot?.live_readback?.stale && <p className="mx-4 mt-4 rounded-lg border border-amber-900/60 bg-amber-950/30 p-3 text-xs leading-5 text-amber-100/80 sm:mx-5">当前没有新鲜的 RFW 读回。以下若有规则，是最近一次成功读回的留存快照，不能视为当前生效状态。</p>}
      {!snapshot?.live_readback?.snapshot ? <p className="px-5 py-7 text-center text-sm text-slate-400">{readbackStatusLabel[snapshot?.live_readback?.status || 'unknown'] || '等待节点上报'}。请确认 Watcher 与 Runman 已更新且 RFW API 正常。</p> : snapshot.live_readback.snapshot.rules.length ? <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-xs">
          <thead className="bg-slate-950/60 text-slate-400"><tr><th className="px-4 py-3 font-medium">来源 / 同步</th><th className="px-4 py-3 font-medium">方向 / 协议</th><th className="px-4 py-3 font-medium">端口</th><th className="px-4 py-3 font-medium">IP 匹配</th><th className="px-4 py-3 font-medium">动作 / 优先级</th><th className="px-4 py-3 font-medium">RFW ID</th><th className="px-4 py-3 text-right font-medium">操作</th></tr></thead>
          <tbody>{snapshot.live_readback.snapshot.rules.map((rule) => <tr key={rule.id} className="border-t border-slate-800 text-slate-200">
            <td className="px-4 py-3"><span className={`rounded-full border px-2 py-1 ${rule.sync_state === 'drifted' || rule.sync_state === 'orphaned' ? 'border-rose-800 bg-rose-950/50 text-rose-200' : rule.origin === 'platform' ? 'border-sky-800 bg-sky-950/50 text-sky-200' : 'border-slate-700 bg-slate-950 text-slate-300'}`}>{rule.origin === 'platform' ? `平台 · ${rule.sync_state === 'in_sync' ? '一致' : rule.sync_state === 'orphaned' ? '多余' : '偏差'}` : '手工 · 可单条删除'}</span>{rule.managed_key && <span className="ml-2 text-slate-500">{rule.managed_key}</span>}</td>
            <td className="px-4 py-3">{rule.direction === 'in' ? '入站' : '出站'} · <code>{rule.protocol}</code></td>
            <td className="px-4 py-3 font-mono">{rule.port_start === 0 && rule.port_end === 0 ? '任意' : rule.port_start === rule.port_end ? rule.port_start : `${rule.port_start}–${rule.port_end}`}</td>
            <td className="px-4 py-3">{rule.ip_type === 'any' ? '任意 IP' : rule.ip_type === 'cidr' ? rule.ip : (rule.countries || []).join(', ')}</td>
            <td className="px-4 py-3"><span className={rule.action === 'block' ? 'text-rose-300' : 'text-emerald-300'}>{rule.enabled ? rule.action === 'block' ? '阻断' : '放行' : '停用'}</span> · P{rule.priority}</td>
            <td className="px-4 py-3 font-mono tabular-nums text-slate-400">#{rule.id}</td>
            <td className="px-4 py-2 text-right">
              {rule.origin === 'manual' ? <div className="inline-flex flex-wrap justify-end gap-1.5">
                <button type="button" onClick={() => copyManualRuleToPolicy(rule)} disabled={scope !== 'host' || !canEdit || !canDeleteManualRules} className="inline-flex min-h-9 items-center justify-center gap-1.5 rounded-lg border border-sky-800/70 bg-sky-950/30 px-2.5 text-[11px] font-medium text-sky-200 hover:bg-sky-900/40 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-45" title={scope === 'host' && canEdit && canDeleteManualRules ? '复制到网页策略草稿；保存并读回确认前保留原规则' : '需要单机编辑权限和新鲜 RFW 读回'}><Layers className="h-3.5 w-3.5" aria-hidden="true" />复制到策略草稿</button>
                <button type="button" onClick={() => setPendingManualDelete(rule)} disabled={!canDeleteManualRules || deletingManualRuleId === rule.id} className="inline-flex min-h-9 items-center justify-center gap-1.5 rounded-lg border border-rose-800/70 bg-rose-950/40 px-2.5 text-[11px] font-medium text-rose-200 hover:bg-rose-900/50 focus:outline-none focus:ring-2 focus:ring-rose-400 disabled:cursor-not-allowed disabled:opacity-45" title={canDeleteManualRules ? '确认后只删除当前显示的这条手工 RFW 规则' : '需要母机在线且 RFW 读回新鲜'}>{deletingManualRuleId === rule.id ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />}删除</button>
              </div>
                : rule.managed_key && rules.some((item) => item.key === rule.managed_key) ? <button type="button" onClick={() => removeRule(rule.managed_key!)} disabled={!canEdit} className="min-h-9 rounded-lg border border-slate-700 px-2.5 text-[11px] text-slate-300 hover:border-rose-800 hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-45" title="从当前期望策略草稿中移除；保存并应用后同步删除">从期望策略移除</button>
                  : <span className="text-[10px] text-slate-500">通过期望策略同步</span>}
            </td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="px-5 py-7 text-center text-sm text-slate-400">最近一次 RFW 读回没有规则。</p>}
      {snapshot?.live_readback?.snapshot && <p className="border-t border-slate-800 px-4 py-3 text-[10px] leading-5 text-slate-500 sm:px-5">读回版本 #{snapshot.live_readback.snapshot.policy_revision} · 平台规则 {snapshot.live_readback.snapshot.managed_rule_count} · 偏差 {snapshot.live_readback.snapshot.drift_count} · 缺失 {snapshot.live_readback.snapshot.missing_count}。读回证明 RFW 用户态规则表，不是内核 map 的逐项确认。</p>}
    </section>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <div>
          <h3 className="text-sm font-bold text-slate-100">CN 危险协议策略 <span className="ml-2 font-normal text-slate-400">生成草稿，不会立即生效</span></h3>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div><label htmlFor="fw-cn-direction" className="mb-1 block text-xs font-medium text-slate-300">其它协议的 CN 匹配方向</label><select id="fw-cn-direction" value={cnRiskDirection} onChange={(event) => setCnRiskDirection(event.target.value as CnRiskDirection)} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"><option value="in">入站：来源 IP 属于 CN</option><option value="out">出站：目标 IP 属于 CN</option><option value="both">双向：来源或目标 IP 属于 CN</option></select></div>
          <div><label htmlFor="fw-cn-action" className="mb-1 block text-xs font-medium text-slate-300">命中后的策略</label><select id="fw-cn-action" value={cnRiskAction} onChange={(event) => setCnRiskAction(event.target.value as CnRiskAction)} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"><option value="pass">仅告警：放行流量并生成提醒</option><option value="block">阻断并告警</option></select></div>
          <div className="flex items-end"><button type="button" onClick={addCnRiskPolicyPreset} disabled={rules.length >= 64} className={`inline-flex min-h-11 w-full items-center justify-center gap-2 rounded-lg border px-3 text-xs font-semibold disabled:opacity-50 ${cnRiskAction === 'block' ? 'border-rose-700/70 bg-rose-950/50 text-rose-100 hover:bg-rose-900/60' : 'border-amber-700/70 bg-amber-950/40 text-amber-100 hover:bg-amber-900/50'}`}>生成所选 CN 规则草稿</button></div>
        </div>
        <fieldset className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
          <legend className="mb-2 text-xs font-medium text-slate-300">协议（可多选）</legend>
          {cnRiskProtocolOptions.map((option) => {
            const checked = cnRiskProtocols.includes(option.protocol);
            const capability = scope === 'host' ? protocolCapability(option.protocol) : 'supported';
            const unavailable = scope === 'host' && capability !== 'supported';
            const capabilityLabel = capability === 'unsupported' ? '当前 RFW 不支持' : capability === 'unknown' ? '等待 RFW 能力读回' : '';
            return <label key={option.protocol} title={unavailable ? protocolCapabilityHelp(option.protocol) : undefined} className={`flex min-h-16 items-start gap-2 rounded-lg border p-3 ${unavailable ? 'cursor-not-allowed border-amber-900/60 bg-amber-950/10' : 'cursor-pointer border-slate-800 bg-slate-950/60 hover:border-slate-600'}`}>
              <input type="checkbox" checked={checked} disabled={unavailable && !checked} onChange={(event) => setCnRiskProtocols((current) => event.target.checked ? [...new Set([...current, option.protocol])] : current.filter((protocol) => protocol !== option.protocol))} className="mt-0.5 h-4 w-4 shrink-0 accent-sky-500 disabled:opacity-40" />
              <span className="min-w-0"><span className="block text-xs font-semibold text-slate-100">{option.label}{capabilityLabel && <span className="ml-1 font-normal text-amber-300">· {capabilityLabel}</span>}</span><span className="mt-1 block text-[10px] leading-4 text-slate-400">{option.note}</span></span>
            </label>;
          })}
        </fieldset>
        <p className="mt-3 rounded-lg border border-sky-900/70 bg-sky-950/30 p-3 text-xs leading-5 text-sky-100/80">作用范围：母机 RFW 实例配置的网卡；当前规则 API 没有逐条绑定网卡的字段，因此这里不会伪装成可选网卡。下面“容器转发端口保护”才支持选择已采集的 Incus / Podman 网桥。OpenVPN 只匹配入站，其它勾选协议按上方方向生成规则。</p>
        <p className="mt-3 text-xs leading-5 text-slate-400">入站匹配 CN 来源，出站匹配 CN 目标。FET 只是疑似 SS 的高熵启发式，可能误报其他非 TLS 加密流量；MTProto 依赖已知初始化标记且覆盖不完整；WireGuard 主要能识别初始握手。当前 RFW 仅覆盖 IPv4。命中规则后，节点事件会回传平台并进入安全告警。</p>
        <p className="mt-1 text-xs leading-5 text-amber-200/80">“仅告警”会放行连接，不是拦截；“阻断并告警”才会拒绝匹配流量。生成后先检查规则，再单机保存或同步全局模板。单机只开放新鲜读回明确支持的协议；全局模板会让不支持或能力未知的节点等待，不会盲目下发。协议支持必须由节点运行的 RFW 实际实现并上报，更新 Watcher Agent 本身不会增加协议检测能力。</p>
      </div>
      <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4 sm:p-5">
        <div><label htmlFor="fw-priority" className="mb-1 block text-xs text-slate-300">优先级</label><input id="fw-priority" type="number" min={0} max={100000} value={ruleDraft.priority} onChange={(e) => updateDraft('priority', Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-direction" className="mb-1 block text-xs text-slate-300">方向</label><select id="fw-direction" value={ruleDraft.direction} onChange={(e) => { const direction = e.target.value as 'in' | 'out'; updateDraft('direction', direction); if (direction === 'out' && !outboundProtocols.includes(ruleDraft.protocol)) updateDraft('protocol', 'tcp'); }} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"><option value="in">入站</option><option value="out">出站</option></select></div>
        <div><label htmlFor="fw-protocol" className="mb-1 block text-xs text-slate-300">协议</label><select id="fw-protocol" value={ruleDraft.protocol} onChange={(e) => updateDraft('protocol', e.target.value as HostFirewallRule['protocol'])} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400">{protocols.filter((protocol) => ruleDraft.direction === 'in' || outboundProtocols.includes(protocol)).map((protocol) => {
          const isApplicationProtocol = ['http', 'tls', 'socks', 'ssh', 'fet', 'wireguard', 'openvpn', 'quic', 'mtproto'].includes(protocol);
          const capability = isApplicationProtocol && scope === 'host' ? protocolCapability(protocol) : 'supported';
          const unavailable = isApplicationProtocol && scope === 'host' && capability !== 'supported';
          return <option key={protocol} value={protocol} disabled={unavailable && ruleDraft.protocol !== protocol}>{protocol}{capability === 'unsupported' ? '（当前 RFW 不支持）' : capability === 'unknown' ? '（待能力读回）' : ''}</option>;
        })}</select></div>
        <div><label htmlFor="fw-action" className="mb-1 block text-xs text-slate-300">动作</label><select id="fw-action" value={ruleDraft.action} onChange={(e) => updateDraft('action', e.target.value as 'block' | 'pass')} aria-describedby="fw-action-help" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"><option value="block">阻断</option><option value="pass">放行</option></select></div>
        <div><label htmlFor="fw-port-start" className="mb-1 block text-xs text-slate-300">起始端口（0 表示任意）</label><input id="fw-port-start" type="number" min={0} max={65535} value={ruleDraft.port_start} onChange={(e) => updateDraft('port_start', Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-port-end" className="mb-1 block text-xs text-slate-300">结束端口（可留空）</label><input id="fw-port-end" type="number" min={0} max={65535} value={ruleDraft.port_end} onChange={(e) => updateDraft('port_end', e.target.value === '' ? '' : Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-ip-type" className="mb-1 block text-xs text-slate-300">来源 / 目标匹配</label><select id="fw-ip-type" value={ruleDraft.ip_type} onChange={(e) => updateDraft('ip_type', e.target.value as HostFirewallRule['ip_type'])} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"><option value="any">任意 IP</option><option value="cidr">CIDR 网段</option><option value="geoip">GeoIP 国家</option></select></div>
        {ruleDraft.ip_type === 'cidr' && <div><label htmlFor="fw-cidr" className="mb-1 block text-xs text-slate-300">CIDR</label><input id="fw-cidr" value={ruleDraft.ip} onChange={(e) => updateDraft('ip', e.target.value)} placeholder="192.0.2.0/24" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-hidden focus:ring-2 focus:ring-sky-400" /></div>}
        {ruleDraft.ip_type === 'geoip' && <div><label htmlFor="fw-countries" className="mb-1 block text-xs text-slate-300">国家代码（逗号分隔）</label><input id="fw-countries" value={ruleDraft.countries} onChange={(e) => updateDraft('countries', e.target.value)} placeholder="CN,US" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-hidden focus:ring-2 focus:ring-sky-400" /></div>}
      </div>
      <p id="fw-action-help" className="px-4 pb-3 text-xs leading-5 text-slate-400 sm:px-5"><span className="font-semibold text-rose-300">阻断</span> 会拦截命中流量并回传阻断事件；<span className="font-semibold text-amber-300">放行</span> 只会对平台告警协议集合生成安全提醒。协议识别依赖首包/首报文特征，未识别到协议时不会生成应用协议告警。</p>
      <div className="flex flex-col gap-3 border-t border-slate-800 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <label className="inline-flex min-h-11 items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={ruleDraft.enabled} onChange={(e) => updateDraft('enabled', e.target.checked)} className="h-4 w-4 accent-sky-500" />创建后启用</label>
        <button type="button" onClick={addRule} disabled={rules.length >= 64} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-sky-700 bg-sky-950/60 px-4 text-sm font-semibold text-sky-200 transition-colors hover:bg-sky-900/70 focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:opacity-50"><Plus className="h-4 w-4" aria-hidden="true" />加入期望规则</button>
      </div>
      {formError && <p className="px-5 pb-3 text-sm text-rose-300" role="alert">{formError}</p>}
      <div className="overflow-x-auto border-t border-slate-800">
        {rules.length ? <table className="w-full min-w-[720px] text-left text-xs">
          <thead className="bg-slate-950/60 text-slate-400"><tr><th className="px-4 py-3 font-medium">状态</th><th className="px-4 py-3 font-medium">方向 / 协议</th><th className="px-4 py-3 font-medium">端口</th><th className="px-4 py-3 font-medium">IP 匹配</th><th className="px-4 py-3 font-medium">动作 / 优先级</th><th className="px-4 py-3 text-right font-medium">操作</th></tr></thead>
          <tbody>{rules.map((rule) => <tr key={rule.key} className="border-t border-slate-800 text-slate-200">
            <td className="px-4 py-3"><span className={`rounded-full border px-2 py-1 ${rule.enabled ? 'border-emerald-800 bg-emerald-950/50 text-emerald-200' : 'border-slate-700 bg-slate-950 text-slate-400'}`}>{rule.enabled ? '启用' : '停用'}</span></td>
            <td className="px-4 py-3">{rule.direction === 'in' ? '入站' : '出站'} · <code>{rule.protocol}</code></td>
            <td className="px-4 py-3 font-mono">{rule.port_start === 0 && rule.port_end === undefined ? '任意' : `${rule.port_start}${rule.port_end === undefined ? '' : `–${rule.port_end}`}`}</td>
            <td className="px-4 py-3">{rule.ip_type === 'any' ? '任意 IP' : rule.ip_type === 'cidr' ? rule.ip : (rule.countries || []).join(', ')}</td>
            <td className="px-4 py-3"><span className={rule.action === 'block' ? 'text-rose-300' : 'text-emerald-300'}>{rule.action === 'block' ? '阻断' : '放行'}</span> · P{rule.priority}</td>
            <td className="px-4 py-3 text-right"><button type="button" onClick={() => removeRule(rule.key)} aria-label={`移除 ${rule.protocol} 规则`} className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-lg border border-slate-700 text-slate-300 transition-colors hover:border-rose-700 hover:bg-rose-950/40 hover:text-rose-200 focus:outline-hidden focus:ring-2 focus:ring-rose-400"><Trash2 className="h-4 w-4" aria-hidden="true" /></button></td>
          </tr>)}</tbody>
        </table> : <p className="px-5 py-7 text-center text-sm text-slate-400">暂无 Watcher 管理的规则。已有 RFW 本地手工规则保持不变。</p>}
      </div>
    </section>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-bold text-slate-100">容器转发端口保护</h3>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[10px] text-slate-400">默认关闭 · Incus / Podman</span>
        </div>
        <p className="mt-1 text-xs leading-5 text-slate-400">先选网桥范围，再启用端口规则。它只匹配进入容器的 FORWARD 流量，不检查宿主机 INPUT/OUTPUT，也不识别进程名称或加密协议。</p>
      </div>

      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h4 className="text-xs font-semibold text-slate-200">1. 选择生效的容器网络</h4>
            <p className="mt-1 max-w-3xl text-[10px] leading-4 text-slate-400">选择后下方端口模板只作用于这些桥接网卡。不会自动全选；清单过期或未采集时不能勾选。</p>
          </div>
          {scope === 'host' && <div className="flex flex-wrap items-center gap-2">
            <span className={interfaceInventory?.status === 'ready' && !interfaceInventory.stale ? 'rounded-full border border-emerald-800 bg-emerald-950/40 px-2.5 py-1 text-[10px] text-emerald-200' : 'rounded-full border border-amber-800 bg-amber-950/40 px-2.5 py-1 text-[10px] text-amber-200'}>
              {interfaceInventory?.status === 'ready' ? interfaceInventory.stale ? '网卡清单已过期' : '已采集 ' + eligibleInterfaces.length + ' 张容器网桥' : '等待 Agent 采集'}
            </span>
            <span className="rounded-full border border-sky-900/70 bg-sky-950/40 px-2.5 py-1 text-[10px] text-sky-200">已选 {eligibleInterfaces.filter((item) => abuse.interfaces.includes(item.name)).length} 张</span>
          </div>}
        </div>

        {scope === 'host' ? <>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {(['incus', 'podman'] as const).map((runtime) => {
              const runtimeInterfaces = eligibleInterfaces.filter((item) => item.runtimes.includes(runtime));
              const selectedCount = runtimeInterfaces.filter((item) => abuse.interfaces.includes(item.name)).length;
              const checked = runtimeInterfaces.length > 0 && selectedCount === runtimeInterfaces.length;
              const runtimeLabel = runtime === 'incus' ? 'Incus' : 'Podman';
              return <label key={runtime} className={runtimeInterfaces.length && !interfaceInventory?.stale ? checked ? 'flex min-h-14 cursor-pointer items-center gap-3 rounded-lg border border-sky-700 bg-sky-950/40 p-3' : 'flex min-h-14 cursor-pointer items-center gap-3 rounded-lg border border-slate-700 bg-slate-950/60 p-3 hover:border-slate-600' : 'flex min-h-14 items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/30 p-3 opacity-55'}>
                <input type="checkbox" checked={checked} disabled={!runtimeInterfaces.length || interfaceInventory?.stale} onChange={() => toggleRuntimeInterfaces(runtime)} className="h-4 w-4 shrink-0 accent-sky-500" aria-label={'选择全部 ' + runtimeLabel + ' 网桥'} />
                <span className="min-w-0 flex-1">
                  <span className="block text-xs font-semibold text-slate-100">{runtimeLabel}</span>
                  <span className="mt-0.5 block text-[10px] text-slate-400">{runtimeInterfaces.length ? '发现 ' + runtimeInterfaces.length + ' 张 · 已选 ' + selectedCount : '未发现已确认的桥接网卡'}</span>
                </span>
                <span className="max-w-[45%] truncate font-mono text-[10px] text-slate-500">{runtimeInterfaces.map((item) => item.name).join(', ')}</span>
              </label>;
            })}
          </div>

          {eligibleInterfaces.length > 0 && <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="按容器运行时筛选网卡">
              {([
                ['all', '全部', eligibleInterfaces.length],
                ['incus', 'Incus', eligibleInterfaces.filter((item) => item.runtimes.includes('incus')).length],
                ['podman', 'Podman', eligibleInterfaces.filter((item) => item.runtimes.includes('podman')).length],
              ] as const).map(([key, label, count]) => <button key={key} type="button" onClick={() => setHostInterfaceFilter(key)} aria-pressed={hostInterfaceFilter === key} className={hostInterfaceFilter === key ? 'min-h-9 rounded-lg border border-sky-700 bg-sky-950/60 px-3 text-[10px] text-sky-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400' : 'min-h-9 rounded-lg border border-slate-700 bg-slate-950/70 px-3 text-[10px] text-slate-400 hover:bg-slate-800 focus:outline-hidden focus:ring-2 focus:ring-sky-400'}>{label}<span className="ml-1.5 font-mono tabular-nums">{count}</span></button>)}
            </div>
            <span className="text-[10px] text-slate-500">筛选不改变勾选</span>
          </div>}

          {eligibleInterfaces.length > 0 ? visibleEligibleInterfaces.length ? <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {visibleEligibleInterfaces.map((item) => <label key={item.name} className={interfaceInventory?.stale ? 'flex min-h-20 items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/30 p-3 opacity-60' : abuse.interfaces.includes(item.name) ? 'flex min-h-20 cursor-pointer items-start gap-3 rounded-lg border border-sky-700 bg-sky-950/30 p-3' : 'flex min-h-20 cursor-pointer items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3 hover:border-slate-600'}>
              <input type="checkbox" checked={abuse.interfaces.includes(item.name)} disabled={interfaceInventory?.stale} onChange={(event) => toggleAbuseInterface(item.name, event.target.checked)} className="mt-0.5 h-4 w-4 shrink-0 accent-sky-500" aria-label={'选择 ' + item.name + ' 容器网卡'} />
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-1.5"><code className="text-xs font-semibold text-slate-100">{item.name}</code>{item.runtimes.map((runtime) => <span key={runtime} className="rounded-sm border border-sky-900/70 bg-sky-950/50 px-1.5 py-0.5 text-[9px] uppercase text-sky-200">{runtime}</span>)}<span className={item.state === 'up' ? 'rounded-sm border border-emerald-900 bg-emerald-950/40 px-1.5 py-0.5 text-[9px] text-emerald-200' : 'rounded-sm border border-amber-900 bg-amber-950/40 px-1.5 py-0.5 text-[9px] text-amber-200'}>{item.state === 'up' ? '在线' : item.state}</span></span>
                <span className="mt-1 block break-all text-[10px] leading-4 text-slate-500">{(item.network_names.length ? item.network_names.join(', ') : item.kind) + (item.mtu ? ' · MTU ' + item.mtu : '') + (item.addresses.length ? ' · ' + item.addresses.slice(0, 2).join(', ') : '')}</span>
              </span>
            </label>)}
          </div> : <p className="mt-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-[11px] leading-5 text-slate-400">当前筛选没有可显示的网卡，请切换到“全部”或其他运行时。</p> : <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[11px] leading-5 text-amber-100/80">{interfaceInventory?.stale ? '网卡清单已过期，请刷新并等待母机上报后再选择。' : '尚无已确认的 Incus / Podman bridge；请检查 Agent 版本、运行时网络模式后刷新，系统不会猜测网卡名称。'}</p>}

          {(abuse.interfaces || []).some((name) => !eligibleInterfaces.some((item) => item.name === name)) && <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[10px] text-amber-100/80">
            <span>旧策略里有未被新清单确认的网卡：{abuse.interfaces.filter((name) => !eligibleInterfaces.some((item) => item.name === name)).join(', ')}</span>
            <button type="button" onClick={() => setAbuseInterfaces(abuse.interfaces.filter((name) => eligibleInterfaces.some((item) => item.name === name)))} className="min-h-8 rounded-sm border border-amber-800 px-2.5 text-amber-100 hover:bg-amber-900/40">从草稿移除</button>
          </div>}
        </> : <>
          <p className="mt-2 text-[10px] leading-4 text-slate-400">全局模式按运行时选择，不复制某台母鸡的网卡名。每台主机只会在新鲜清单中映射对应运行时的 bridge。</p>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {(['incus', 'podman'] as const).map((runtime) => {
              const selected = (abuse.runtimes || []).includes(runtime);
              const coverage = fleetNetworkCoverage[runtime];
              const runtimeLabel = runtime === 'incus' ? 'Incus' : 'Podman';
              return <label key={runtime} className={selected ? 'flex min-h-20 cursor-pointer items-start gap-3 rounded-xl border border-sky-700 bg-sky-950/40 p-4' : coverage > 0 ? 'flex min-h-20 cursor-pointer items-start gap-3 rounded-xl border border-slate-700 bg-slate-950/50 p-4 hover:border-slate-600' : 'flex min-h-20 items-start gap-3 rounded-xl border border-slate-700 bg-slate-950/50 p-4 opacity-60'}>
                <input type="checkbox" checked={selected} disabled={coverage === 0} onChange={(event) => toggleFleetRuntime(runtime, event.target.checked)} className="mt-1 h-4 w-4 shrink-0 accent-sky-500" aria-label={'全局选择 ' + runtimeLabel + ' 容器网络'} />
                <span className="min-w-0 flex-1"><span className="block text-sm font-semibold text-slate-100">{runtimeLabel}</span><span className="mt-1 block text-[11px] leading-5 text-slate-400">{'当前 ' + coverage + ' / ' + fleetHosts.length + ' 台母机报告了可用 bridge' + (coverage < fleetHosts.length ? ' · ' + (fleetHosts.length - coverage) + ' 台尚未就绪' : '')}</span></span>
                <Network className={selected ? 'mt-0.5 h-4 w-4 shrink-0 text-sky-300' : 'mt-0.5 h-4 w-4 shrink-0 text-slate-500'} aria-hidden="true" />
              </label>;
            })}
          </div>
          {fleetSnapshot?.revision && (abuse.interfaces || []).length > 0 && !(abuse.runtimes || []).length && <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[10px] leading-4 text-amber-100/80">旧全局模板使用具体网卡名称，无法安全映射到不同母机；请重新选择 Incus / Podman。</p>}
        </>}
      </div>

      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h4 className="text-xs font-semibold text-slate-200">2. 启用要拦截的固定端口规则</h4>
            <p className="mt-1 text-[10px] leading-4 text-slate-400">这些不是应用识别开关；只按目的端口阻断，改用随机端口后无法识别。规则仅针对上一步勾选的容器桥接网络。</p>
          </div>
          <span className="rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-[10px] text-slate-300">已启用 {enabledAbuse} / 3 项</span>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          {([
            ['speedtest', 'iperf3 测速端口', 'TCP / UDP 目的端口 5201。只拦此端口，不会按进程名识别测速软件。'],
            ['mining', '常见矿池端口', 'TCP 目的端口 3333、4444、5555、6666、7777、8888、9999、14433、14444。随机端口不在覆盖范围。'],
            ['bt', '常见 BT / P2P 端口', 'TCP / UDP 目的端口 6881–6889、6969、51413、4662、4672。其它端口不在覆盖范围。'],
          ] as const).map(([key, title, description]) => <label key={key} className={abuse[key] ? 'flex min-h-28 cursor-pointer items-start gap-3 rounded-xl border border-rose-800/70 bg-rose-950/20 p-4 transition-colors' : 'flex min-h-28 cursor-pointer items-start gap-3 rounded-xl border border-slate-700 bg-slate-950/60 p-4 transition-colors hover:border-slate-600'}>
            <input type="checkbox" checked={abuse[key]} onChange={(event) => setAbuseOption(key, event.target.checked)} className="mt-1 h-4 w-4 shrink-0 accent-sky-500" aria-label={title} />
            <span className="min-w-0"><span className="flex items-center gap-2"><span className="text-sm font-semibold text-slate-100">{title}</span><span className={abuse[key] ? 'rounded-full border border-rose-800 bg-rose-950/50 px-2 py-0.5 text-[9px] text-rose-200' : 'rounded-full border border-slate-700 bg-slate-950 px-2 py-0.5 text-[9px] text-slate-500'}>{abuse[key] ? '启用' : '关闭'}</span></span><span className="mt-1 block text-xs leading-5 text-slate-400">{description}</span></span>
          </label>)}
        </div>
        {anyAbuseEnabled && scope === 'host' && abuse.interfaces.length === 0 && <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[11px] leading-5 text-amber-100/80">已有端口模板启用，但没有选择目标网卡。请先在上方勾选一个 Incus / Podman 网桥，系统不会自动全选。</p>}
        {anyAbuseEnabled && scope === 'fleet' && (abuse.runtimes || []).length === 0 && <p className="mt-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3 text-[11px] leading-5 text-amber-100/80">已有端口模板启用，但没有选择 Incus / Podman 运行时；请选择目标范围后再同步。</p>}
        {!anyAbuseEnabled && <p className="mt-3 text-[10px] leading-4 text-slate-500">当前没有启用端口规则，因此不会产生容器流量拦截。选择网卡只保存在本次草稿；启用模板后才会随策略应用。</p>}
      </div>
      <p className="mx-4 mb-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-[10px] leading-4 text-slate-400 sm:mx-5 sm:mb-5">容器端口模板只覆盖 bridge 转发流量；host、pasta、macvlan / ipvlan 等网络模式不在此路径。母机级协议规则作用于 RFW 实例自身的接口范围，两种配置互不改变。应用后检查节点回执和 RFW 读回。</p>
    </section>



    <section className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
      <div className="min-w-0">
        {scope === 'host' ? <>
          <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-slate-100">
            {pending ? <Clock3 className="h-4 w-4 text-amber-300" aria-hidden="true" /> : activeAction?.status === 'succeeded' ? <Check className="h-4 w-4 text-emerald-300" aria-hidden="true" /> : null}
            <span>{activeAction ? `最近执行：${statusLabel[activeAction.status] || activeAction.status}` : '尚未下发过策略'}</span>
            {activeAction?.updated_at_utc8 && <span className="text-xs font-normal text-slate-400">{activeAction.updated_at_utc8}</span>}
          </div>
          {activeAction?.message && <p className={`mt-1 wrap-break-word text-xs leading-5 ${activeAction.status === 'failed' ? 'text-rose-300' : 'text-slate-400'}`}>{activeAction.message}</p>}
          {scope === 'host' && <>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="text-[10px] text-slate-500">历史策略 {snapshot?.policy_history?.length || 0} 条</span>
              <button type="button" onClick={() => setRecoveryIntent('retry')} disabled={!canRetryPolicy || recoveringPolicy} title="仅在主机在线且 RFW 实时读回新鲜时可用" className="min-h-9 rounded-lg border border-amber-800/70 bg-amber-950/30 px-3 text-[10px] font-medium text-amber-200 hover:bg-amber-900/40 disabled:cursor-not-allowed disabled:opacity-40">安全重试当前策略</button>
              <button type="button" onClick={() => setRecoveryIntent('rollback')} disabled={!canRollbackPolicy || recoveringPolicy} title="回滚会创建新的策略版本并排队，不覆盖历史记录" className="min-h-9 rounded-lg border border-sky-800/70 bg-sky-950/30 px-3 text-[10px] font-medium text-sky-200 hover:bg-sky-900/40 disabled:cursor-not-allowed disabled:opacity-40">回滚到上一版本</button>
            </div>
            {!!snapshot?.policy_history?.length && <details className="mt-2 max-w-2xl rounded-lg border border-slate-800 bg-slate-950/40 p-2.5">
              <summary className="cursor-pointer select-none text-[10px] text-slate-400">查看策略变更记录</summary>
              <div className="mt-2 space-y-1.5">{snapshot.policy_history.slice(0, 5).map((item) => <div key={`${item.revision}-${item.updated_at_utc8}`} className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-slate-500"><span className="font-mono text-slate-300">版本 #{item.revision}</span><span>{item.updated_at_utc8}</span>{item.updated_by && <span>操作者 {item.updated_by}</span>}<span>{item.policy.rules?.length || 0} 条规则</span></div>)}</div>
            </details>}
          </>}
        </> : <>
          <div className="text-sm font-semibold text-slate-100">全局模板版本 #{fleetSnapshot?.revision ?? 0} · {fleetSnapshot?.counts.total ?? 0} 台登记母机</div>
          <p className="mt-1 text-xs text-slate-400">已应用 {fleetSnapshot?.counts.last_apply_succeeded ?? 0} · 待处理 {fleetSnapshot?.counts.deferred ?? 0} · 等待网卡 {fleetSnapshot?.counts.network_deferred ?? 0} · 策略偏差 {fleetSnapshot?.counts.drifted_hosts ?? 0}</p>
        </>}
        {dirty && <p className="mt-1 text-xs text-amber-200">有未保存的更改</p>}
      </div>
      <button type="button" onClick={() => scope === 'host' ? setConfirmOpen(true) : setFleetConfirmOpen(true)} disabled={!dirty || !canEdit || (scope === 'host' ? saving : fleetSaving)} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-rose-700/70 bg-rose-950/50 px-4 text-sm font-semibold text-rose-100 transition-colors hover:bg-rose-900/60 focus:outline-hidden focus:ring-2 focus:ring-rose-400 disabled:cursor-not-allowed disabled:opacity-45">{(scope === 'host' ? saving : fleetSaving) && <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />}{scope === 'host' ? '保存并应用到这台母鸡' : '保存并同步全体母鸡'}</button>
    </section>

    <ConfirmDialog open={scopeConfirmOpen} title="切换配置范围？" description="当前草稿尚未保存。切换后会放弃这份草稿，并载入目标范围的已保存策略。" confirmLabel="放弃草稿并切换" tone="primary" onConfirm={() => { if (pendingScope) applyScopeChange(pendingScope); setPendingScope(null); setScopeConfirmOpen(false); }} onCancel={() => { setPendingScope(null); setScopeConfirmOpen(false); }} />
    <ConfirmDialog open={pendingManualDelete !== null} title="删除这条手工 RFW 规则？" description={`这只会删除 ${hostId} 上当前读回的 RFW 规则 #${pendingManualDelete?.id ?? ''}。执行前 Runman 会再次核对规则 ID 与完整规则内容；若规则已变化或已被平台接管，删除会被拒绝。`} confirmLabel="确认删除并排队" tone="danger" isSubmitting={deletingManualRuleId !== null} onConfirm={confirmManualRuleDelete} onCancel={() => { if (deletingManualRuleId === null) setPendingManualDelete(null); }}>
      {pendingManualDelete && <div className="mt-4 rounded-lg border border-rose-900/70 bg-rose-950/40 p-3 text-xs leading-5 text-rose-100/90">{pendingManualDelete.direction === 'in' ? '入站' : '出站'} {pendingManualDelete.protocol} · 端口 {pendingManualDelete.port_start === 0 && pendingManualDelete.port_end === 0 ? '任意' : pendingManualDelete.port_start === pendingManualDelete.port_end ? pendingManualDelete.port_start : `${pendingManualDelete.port_start}–${pendingManualDelete.port_end}`} · {pendingManualDelete.ip_type === 'any' ? '任意 IP' : pendingManualDelete.ip_type === 'cidr' ? pendingManualDelete.ip : (pendingManualDelete.countries || []).join(', ')} · {pendingManualDelete.action === 'block' ? '阻断' : '放行'} · P{pendingManualDelete.priority}</div>}
    </ConfirmDialog>
    <ConfirmDialog open={recoveryIntent !== null} title={recoveryIntent === 'retry' ? '重试当前母机防火墙策略？' : '回滚到上一条历史策略？'} description={recoveryIntent === 'retry' ? `这会把 ${hostId} 当前保存的策略作为新修订重新排队。执行前系统会检查主机在线状态、RFW 实时读回、接口映射和协议能力。` : `这会把 ${hostId} 最近一条历史策略作为新修订排队应用；如果历史规则引用了当前无法确认的接口，系统会拒绝下发。`} confirmLabel={recoveryIntent === 'retry' ? '确认重试并排队' : '确认回滚并排队'} tone="danger" isSubmitting={recoveringPolicy} onConfirm={confirmPolicyRecovery} onCancel={() => { if (!recoveringPolicy) setRecoveryIntent(null); }}>
      <p className="mt-4 rounded-lg border border-amber-900/60 bg-amber-950/30 p-3 text-xs leading-5 text-amber-100/80">只有管理员可执行。它会发送一个主机范围的 RFW 操作，但不会触碰其他母机；若正在运行全局模板、Agent 离线或读回过期，后端会拒绝请求。</p>
    </ConfirmDialog>
    <ConfirmDialog open={confirmOpen && scope === 'host'} title="应用母机防火墙策略？" description={`此配置将应用于 ${hostId}。RFW 协议规则可能影响该母机的全部容器和服务；已启用 ${blockingRules} 条阻断规则与 ${enabledAbuse} 项固定端口防滥用策略。平台只自动删除自身登记的规则；手工规则需在实时读回后逐条确认删除。`} confirmLabel="确认并排队" tone="danger" isSubmitting={saving} onConfirm={confirmApply} onCancel={() => setConfirmOpen(false)}>
      <div className="mt-4 rounded-lg border border-rose-900/70 bg-rose-950/40 p-3 text-xs leading-5 text-rose-100/90">执行依赖 Watcher Agent、支持 firewall.sock 的 Runman Agent 与运行中的 RFW。Watcher 离线时排队等待；成功回执是 Runman 应用结果，不等同于平台实时读取内核规则。</div>
    </ConfirmDialog>
    <ConfirmDialog open={fleetConfirmOpen && scope === 'fleet'} title="保存并同步全局防火墙策略？" description={`全局版本将递增并覆盖单机期望策略。当前有 ${blockingRules} 条启用阻断规则、${enabledAbuse} 项固定端口策略；容器网络选择：${(abuse.runtimes || []).map((runtime) => runtime === 'incus' ? 'Incus' : 'Podman').join(' + ') || '未启用'}。每个节点会按本机网卡清单独立映射；无法安全映射的节点将等待，不会应用错误接口名。`} confirmLabel="确认并同步全体" tone="danger" isSubmitting={fleetSaving} onConfirm={confirmFleetApply} onCancel={() => setFleetConfirmOpen(false)}>
      <div className="mt-4 rounded-lg border border-rose-900/70 bg-rose-950/40 p-3 text-xs leading-5 text-rose-100/90">CN GeoIP 规则可按入站来源或出站目标阻断匹配流量，可能影响母机上全部容器与服务。FET 是启发式特征、存在误报；MTProto 仅能识别特定初始化标记，且不做 TCP 重组。节点只有在运行中的 RFW 明确报告支持后才会应用 MTProto 规则；若读回不支持，必须先部署含该检测能力的 RFW 构建。IPv6 暂不支持。策略应用回执不等于内核规则实时读回，节点事件采集可能因缓冲区覆盖而不完整。</div>
    </ConfirmDialog>
  </div>;
};
