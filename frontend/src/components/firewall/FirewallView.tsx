import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Check, Clock3, LoaderCircle, Plus, RefreshCw, Shield, Trash2 } from 'lucide-react';
import { ContainerItem, HostFirewallAbusePolicy, HostFirewallPolicyResponse, HostFirewallRule, SecurityStatusItem } from '../../api/types';
import { api } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';

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

const emptyAbuse: HostFirewallAbusePolicy = { speedtest: false, mining: false, bt: false, interfaces: [] };
const defaultDraft = (): RuleDraft => ({
  priority: 100, direction: 'in', protocol: 'tcp', action: 'block', enabled: true,
  port_start: 0, port_end: '', ip_type: 'any', ip: '', countries: '',
});
const statusLabel: Record<string, string> = {
  queued: '排队中', dispatched: '节点处理中', running: '执行中', succeeded: '已应用', failed: '执行失败', cancelled: '已被新配置取代',
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
  const [snapshot, setSnapshot] = useState<HostFirewallPolicyResponse | null>(null);
  const [rules, setRules] = useState<HostFirewallRule[]>([]);
  const [abuse, setAbuse] = useState<HostFirewallAbusePolicy>(emptyAbuse);
  const [interfaceText, setInterfaceText] = useState('');
  const [ruleDraft, setRuleDraft] = useState<RuleDraft>(defaultDraft);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [formError, setFormError] = useState('');

  const selectedHost = hosts.find((host) => host.host_id === hostId);
  const activeAction = snapshot?.latest_action;
  const pending = Boolean(activeAction && ['queued', 'dispatched', 'running'].includes(activeAction.status));

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
        setAbuse({ ...emptyAbuse, ...(result.policy?.abuse || {}) });
        setInterfaceText((result.policy?.abuse?.interfaces || []).join(', '));
        setDirty(false);
      }
    } catch (error: any) {
      onToast('error', `读取母机防火墙配置失败：${error.message || error}`);
    } finally {
      setLoading(false);
    }
  }, [hostId, onToast]);

  useEffect(() => {
    setSnapshot(null);
    setRules([]);
    setAbuse(emptyAbuse);
    setInterfaceText('');
    setDirty(false);
    if (hostId) loadPolicy(true);
  }, [hostId, loadPolicy]);

  useEffect(() => {
    if (!hostId || !pending || dirty) return;
    const timer = window.setInterval(() => { void loadPolicy(false); }, 4000);
    return () => window.clearInterval(timer);
  }, [hostId, pending, dirty, loadPolicy]);

  const updateDraft = <K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) => {
    setRuleDraft((current) => ({ ...current, [key]: value }));
  };

  const addRule = () => {
    setFormError('');
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

  const setAbuseOption = (key: 'speedtest' | 'mining' | 'bt', value: boolean) => {
    setAbuse((current) => ({ ...current, [key]: value }));
    setDirty(true);
  };

  const setAbuseInterfaces = (value: string) => {
    setInterfaceText(value);
    setDirty(true);
  };

  const removeRule = (key: string) => {
    setRules((items) => items.filter((rule) => rule.key !== key));
    setDirty(true);
  };

  const confirmApply = useCallback(async () => {
    if (!hostId || saving) return;
    const interfaces = [...new Set(interfaceText.split(/[\s,，]+/).map((item) => item.trim()).filter(Boolean))];
    const anyAbuseEnabled = abuse.speedtest || abuse.mining || abuse.bt;
    if (interfaces.length > 16 || interfaces.some((name) => !/^[A-Za-z0-9_.-]{1,15}$/.test(name)) || (anyAbuseEnabled && !interfaces.length)) {
      setConfirmOpen(false);
      onToast('error', '防滥用规则启用时必须填写 1–16 个有效 Linux 容器桥接网卡名（例如 incusbr0、podman0）。');
      return;
    }
    const policyAbuse = { ...abuse, interfaces };
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
      setInterfaceText(interfaces.join(', '));
      setDirty(false);
      setConfirmOpen(false);
      onToast('success', `策略版本 #${result.revision} 已保存，等待母机 Agent 执行。`);
    } catch (error: any) {
      onToast('error', `策略未能排队：${error.message || error}`);
    } finally {
      setSaving(false);
    }
  }, [abuse, hostId, interfaceText, onToast, rules, saving]);

  if (!hosts.length) {
    return <section className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-6 text-center">
      <Shield className="mx-auto h-8 w-8 text-slate-500" aria-hidden="true" />
      <h2 className="mt-3 text-base font-semibold text-slate-100">暂无可配置母机</h2>
      <p className="mt-2 text-sm text-slate-400">主机首次上报后会出现在这里。</p>
    </section>;
  }

  const outboundProtocols: HostFirewallRule['protocol'][] = ['all', 'tcp', 'udp'];
  const protocols: HostFirewallRule['protocol'][] = ['all', 'tcp', 'udp', 'http', 'tls', 'socks', 'ssh', 'fet', 'wireguard', 'openvpn', 'quic'];
  const canEdit = Boolean(snapshot?.agent_ready);
  const blockingRules = rules.filter((rule) => rule.enabled && rule.action === 'block').length;
  const enabledAbuse = Object.values(abuse).filter(Boolean).length;

  return <div className="mx-auto mt-6 max-w-6xl space-y-5 pb-8">
    <header className="flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
      <div className="flex min-w-0 items-start gap-3">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-700/60 bg-sky-950/50 text-sky-300"><Shield className="h-5 w-5" aria-hidden="true" /></span>
        <div className="min-w-0">
          <h2 className="text-lg font-bold text-slate-100">母机防火墙策略</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">按主机保存配置，由 Watcher Agent 排队并通过本机 Runman 控制接口应用到现有 RFW。</p>
        </div>
      </div>
      <button type="button" onClick={() => loadPolicy(true)} disabled={loading || !hostId} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-200 transition-colors hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-50">
        {loading ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}刷新状态
      </button>
    </header>

    <section className="grid gap-4 lg:grid-cols-[minmax(240px,0.8fr)_minmax(0,1.2fr)]">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
        <label htmlFor="firewall-host" className="mb-2 block text-sm font-semibold text-slate-200">选择母机</label>
        <select id="firewall-host" value={hostId} onChange={(event) => setHostId(event.target.value)} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400">
          {hosts.map((host) => <option key={host.host_id} value={host.host_id}>{host.host_id}</option>)}
        </select>
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          <span className={`rounded-full border px-2.5 py-1 ${selectedHost?.stale ? 'border-amber-700 bg-amber-950/50 text-amber-200' : 'border-emerald-700 bg-emerald-950/50 text-emerald-200'}`}>{selectedHost?.stale ? '心跳过期' : '心跳正常'}</span>
          <span className={`rounded-full border px-2.5 py-1 ${snapshot?.agent_ready ? 'border-sky-700 bg-sky-950/50 text-sky-200' : 'border-slate-700 bg-slate-950 text-slate-300'}`}>{snapshot?.agent_ready ? 'Agent 可下发' : 'Agent 未注册/旧版'}</span>
          {snapshot && <span className="rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-slate-300">策略版本 #{snapshot.revision}</span>}
        </div>
        {selectedHost?.stale && <p className="mt-3 text-xs leading-5 text-amber-200">母机当前离线。可以保存期望配置，Agent 恢复连接后会自动执行。</p>}
        {!snapshot?.agent_ready && <p className="mt-3 text-xs leading-5 text-slate-400">该主机需要先上报 Watcher 节点身份，并更新 Runman Agent 以启用本机防火墙控制接口。</p>}
      </div>

      <div className="rounded-2xl border border-amber-800/60 bg-amber-950/20 p-4">
        <div className="flex gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
          <div>
            <h3 className="text-sm font-semibold text-amber-100">生效范围与保护边界</h3>
            <ul className="mt-2 space-y-1.5 text-xs leading-5 text-amber-100/80">
              <li>RFW 原生规则作用于母机 RFW 接口，可能影响这台母机上的所有业务和容器。</li>
              <li>下方三项防滥用规则只匹配容器转发流量，不改宿主机 INPUT/OUTPUT；本地手工 RFW 规则不由本页面删除或覆盖。</li>
              <li>未启用进程强杀、容器文件陷阱、内核参数修改或任意脚本执行。</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <h3 className="text-sm font-bold text-slate-100">RFW 协议与端口规则 <span className="ml-2 font-normal text-slate-400">Watcher 仅管理自己创建的规则</span></h3>
        <p className="mt-1 text-xs leading-5 text-slate-400">方向支持入站/出站；HTTP、TLS、SOCKS、SSH、FET、WireGuard、OpenVPN、QUIC 等 DPI 协议仅支持入站。</p>
      </div>
      <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4 sm:p-5">
        <div><label htmlFor="fw-priority" className="mb-1 block text-xs text-slate-300">优先级</label><input id="fw-priority" type="number" min={0} max={100000} value={ruleDraft.priority} onChange={(e) => updateDraft('priority', Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-direction" className="mb-1 block text-xs text-slate-300">方向</label><select id="fw-direction" value={ruleDraft.direction} onChange={(e) => { const direction = e.target.value as 'in' | 'out'; updateDraft('direction', direction); if (direction === 'out' && !outboundProtocols.includes(ruleDraft.protocol)) updateDraft('protocol', 'tcp'); }} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400"><option value="in">入站</option><option value="out">出站</option></select></div>
        <div><label htmlFor="fw-protocol" className="mb-1 block text-xs text-slate-300">协议</label><select id="fw-protocol" value={ruleDraft.protocol} onChange={(e) => updateDraft('protocol', e.target.value as HostFirewallRule['protocol'])} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400">{protocols.filter((protocol) => ruleDraft.direction === 'in' || outboundProtocols.includes(protocol)).map((protocol) => <option key={protocol} value={protocol}>{protocol}</option>)}</select></div>
        <div><label htmlFor="fw-action" className="mb-1 block text-xs text-slate-300">动作</label><select id="fw-action" value={ruleDraft.action} onChange={(e) => updateDraft('action', e.target.value as 'block' | 'pass')} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400"><option value="block">阻断</option><option value="pass">放行</option></select></div>
        <div><label htmlFor="fw-port-start" className="mb-1 block text-xs text-slate-300">起始端口（0 表示任意）</label><input id="fw-port-start" type="number" min={0} max={65535} value={ruleDraft.port_start} onChange={(e) => updateDraft('port_start', Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-port-end" className="mb-1 block text-xs text-slate-300">结束端口（可留空）</label><input id="fw-port-end" type="number" min={0} max={65535} value={ruleDraft.port_end} onChange={(e) => updateDraft('port_end', e.target.value === '' ? '' : Number(e.target.value))} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400" /></div>
        <div><label htmlFor="fw-ip-type" className="mb-1 block text-xs text-slate-300">来源 / 目标匹配</label><select id="fw-ip-type" value={ruleDraft.ip_type} onChange={(e) => updateDraft('ip_type', e.target.value as HostFirewallRule['ip_type'])} className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-400"><option value="any">任意 IP</option><option value="cidr">CIDR 网段</option><option value="geoip">GeoIP 国家</option></select></div>
        {ruleDraft.ip_type === 'cidr' && <div><label htmlFor="fw-cidr" className="mb-1 block text-xs text-slate-300">CIDR</label><input id="fw-cidr" value={ruleDraft.ip} onChange={(e) => updateDraft('ip', e.target.value)} placeholder="192.0.2.0/24" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-400" /></div>}
        {ruleDraft.ip_type === 'geoip' && <div><label htmlFor="fw-countries" className="mb-1 block text-xs text-slate-300">国家代码（逗号分隔）</label><input id="fw-countries" value={ruleDraft.countries} onChange={(e) => updateDraft('countries', e.target.value)} placeholder="CN,US" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-400" /></div>}
      </div>
      <div className="flex flex-col gap-3 border-t border-slate-800 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
        <label className="inline-flex min-h-11 items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={ruleDraft.enabled} onChange={(e) => updateDraft('enabled', e.target.checked)} className="h-4 w-4 accent-sky-500" />创建后启用</label>
        <button type="button" onClick={addRule} disabled={rules.length >= 100} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg border border-sky-700 bg-sky-950/60 px-4 text-sm font-semibold text-sky-200 transition-colors hover:bg-sky-900/70 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-50"><Plus className="h-4 w-4" aria-hidden="true" />加入期望规则</button>
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
            <td className="px-4 py-3 text-right"><button type="button" onClick={() => removeRule(rule.key)} aria-label={`移除 ${rule.protocol} 规则`} className="inline-flex min-h-10 min-w-10 items-center justify-center rounded-lg border border-slate-700 text-slate-300 transition-colors hover:border-rose-700 hover:bg-rose-950/40 hover:text-rose-200 focus:outline-none focus:ring-2 focus:ring-rose-400"><Trash2 className="h-4 w-4" aria-hidden="true" /></button></td>
          </tr>)}</tbody>
        </table> : <p className="px-5 py-7 text-center text-sm text-slate-400">暂无 Watcher 管理的规则。已有 RFW 本地手工规则保持不变。</p>}
      </div>
    </section>

    <section className="rounded-2xl border border-slate-800 bg-slate-900/70">
      <div className="border-b border-slate-800 px-4 py-4 sm:px-5">
        <h3 className="text-sm font-bold text-slate-100">容器转发防滥用 <span className="ml-2 font-normal text-slate-400">默认关闭 · 固定端口规则</span></h3>
        <p className="mt-1 text-xs leading-5 text-slate-400">只在 FORWARD 容器流量路径检查目标端口；不会处理宿主机自身的 INPUT/OUTPUT 流量。</p>
      </div>
      <div className="grid gap-3 p-4 md:grid-cols-3 sm:p-5">
        {([
          ['speedtest', 'iperf3 常用测速端口', '阻断 TCP/UDP 5201。不会识别 CloudflareSpeedTest 等只通过进程名或内容特征判断的工具。'],
          ['mining', '常见矿池端口', '阻断 TCP 3333、4444、5555、6666、7777、8888、9999、14433、14444。'],
          ['bt', '常见 BT / P2P 端口', '阻断 TCP/UDP 6881–6889、6969、51413、4662、4672。其它随机端口不在此规则覆盖范围。'],
        ] as const).map(([key, title, description]) => <label key={key} className="flex min-h-28 cursor-pointer items-start gap-3 rounded-xl border border-slate-700 bg-slate-950/60 p-4 transition-colors hover:border-slate-600">
          <input type="checkbox" checked={abuse[key]} onChange={(event) => setAbuseOption(key, event.target.checked)} className="mt-1 h-4 w-4 shrink-0 accent-sky-500" aria-label={title} />
          <span><span className="block text-sm font-semibold text-slate-100">{title}</span><span className="mt-1 block text-xs leading-5 text-slate-400">{description}</span></span>
        </label>)}
      </div>
      <div className="px-4 pb-4 sm:px-5">
        <label htmlFor="fw-bridge-interfaces" className="mb-1 block text-xs font-medium text-slate-300">容器桥接网卡（启用上方规则时必填）</label>
        <input id="fw-bridge-interfaces" value={interfaceText} onChange={(event) => setAbuseInterfaces(event.target.value)} placeholder="例如 incusbr0, podman0" className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-400" aria-describedby="fw-bridge-help" />
        <p id="fw-bridge-help" className="mt-1 text-xs leading-5 text-slate-400">只匹配从这里进入宿主机 FORWARD 链的容器出站流量；Runman 会确认网卡实际存在且为 Linux bridge。不填或网卡无效则拒绝应用。Host 网络、macvlan/ipvlan 等不经过该路径的容器不受影响。</p>
      </div>
      <p className="mx-4 mb-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs leading-5 text-slate-400 sm:mx-5 sm:mb-5">DD 重装、MTProto 特征、跑分/代理面板/OpenVPN 等包含 DPI、域名/内容匹配或进程/文件干预；当前版本未把这些高影响行为接入自动策略。</p>
    </section>

    <section className="flex flex-col gap-3 rounded-2xl border border-slate-800 bg-slate-900/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-slate-100">
          {pending ? <Clock3 className="h-4 w-4 text-amber-300" aria-hidden="true" /> : activeAction?.status === 'succeeded' ? <Check className="h-4 w-4 text-emerald-300" aria-hidden="true" /> : null}
          <span>{activeAction ? `最近执行：${statusLabel[activeAction.status] || activeAction.status}` : '尚未下发过策略'}</span>
          {activeAction?.updated_at_utc8 && <span className="text-xs font-normal text-slate-400">{activeAction.updated_at_utc8}</span>}
        </div>
        {activeAction?.message && <p className={`mt-1 break-words text-xs leading-5 ${activeAction.status === 'failed' ? 'text-rose-300' : 'text-slate-400'}`}>{activeAction.message}</p>}
        {dirty && <p className="mt-1 text-xs text-amber-200">有未保存的更改</p>}
      </div>
      <button type="button" onClick={() => setConfirmOpen(true)} disabled={!dirty || !canEdit || saving} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-rose-700/70 bg-rose-950/50 px-4 text-sm font-semibold text-rose-100 transition-colors hover:bg-rose-900/60 focus:outline-none focus:ring-2 focus:ring-rose-400 disabled:cursor-not-allowed disabled:opacity-45">{saving && <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />}保存并应用到母机</button>
    </section>

    <ConfirmDialog open={confirmOpen} title="应用母机防火墙策略？" description={`此配置将应用于 ${hostId}。RFW 协议规则可能影响该母机的全部容器和服务；已启用 ${blockingRules} 条阻断规则与 ${enabledAbuse} 项固定端口防滥用策略。Watcher 只会删除自身登记的规则。`} confirmLabel="确认并排队" tone="danger" isSubmitting={saving} onConfirm={confirmApply} onCancel={() => setConfirmOpen(false)}>
      <div className="mt-4 rounded-lg border border-rose-900/70 bg-rose-950/40 p-3 text-xs leading-5 text-rose-100/90">执行依赖母机上的兼容版 Watcher Agent、Runman Agent 与已运行的 RFW。Agent 离线时只保存并排队，不会显示为已应用；若 Runman 已接收期望配置但 RFW 暂不可用，会持续重试并在这里显示最近一次下发结果。</div>
    </ConfirmDialog>
  </div>;
};
