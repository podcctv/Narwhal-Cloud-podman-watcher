import React from 'react';
import { SecurityAlert } from '../../api/types';

const REASONS: Record<string, string> = {
  configuration_scan_incomplete: '配置扫描未完成',
  config_file_changed_during_scan: '扫描期间配置文件发生变化',
  config_not_known_before_process_start: '无法确认进程已加载当前配置',
  process_generation_unavailable: '进程运行代次无法确认',
  live_listener_not_confirmed: '未找到配置对应的实时监听',
  listener_protocol_or_owner_ambiguous: '监听进程或协议归属不明确',
  shared_configured_port: '该端口还配置了其他协议',
  shared_live_listener: '该端口被其他监听服务共用',
  listener_inventory_incomplete: '实时监听清单不完整',
  shared_network_namespace: '与其他服务共用网络命名空间',
  container_namespace_unavailable: '容器网络命名空间不可用',
  firewall_permission_denied: 'Agent 缺少防火墙权限',
  firewall_dependency_unavailable: '缺少 nftables 或 nsenter',
  firewall_apply_failed: '防火墙规则应用失败',
  firewall_readback_failed: '防火墙规则读回未确认',
  firewall_readback_unavailable: '防火墙规则无法读回',
  firewall_readback_invalid: '防火墙读回数据无效',
  previous_guard_rule_preserved: '证据不足，保留旧阻断规则',
};

const stageLabel: Record<string, string> = {
  confirmed: '已确认',
  confirmed_for_blocked_endpoints: '已确认（对应阻断端点）',
  partially_confirmed: '部分确认',
  not_detected: '未检测到受保护协议',
  not_detected_or_incomplete: '未发现或采集不完整',
  pending_or_unverified: '待核实',
  pending_or_internal_only: '待核实或仅内部监听',
  not_required: '无需阻断',
  removal_unverified: '规则移除待核验',
  failed_or_unavailable: '失败或不可读',
  not_confirmed: '未确认',
};

const stageTone = (value: string) => {
  if (['confirmed', 'confirmed_for_blocked_endpoints', 'not_required', 'not_detected'].includes(value)) return 'text-emerald-200';
  if (['partially_confirmed', 'removal_unverified', 'not_detected_or_incomplete', 'pending_or_unverified', 'pending_or_internal_only'].includes(value)) return 'text-amber-200';
  if (['failed_or_unavailable'].includes(value)) return 'text-rose-200';
  return 'text-slate-300';
};

const endpointLabel = (item: Record<string, any>, applicationProtocol: string) => {
  const process = String(item.process || '进程未知');
  const pid = Number(item.pid || 0);
  const transport = String(item.proto || (Array.isArray(item.transports) ? item.transports.join('+') : '')).toUpperCase();
  const port = Number(item.port || 0);
  return `${process}${pid > 1 ? ` PID ${pid}` : ''} · ${applicationProtocol.toUpperCase()} · ${transport ? `${transport}/` : ''}${port || '端口未知'}`;
};

export const ProtocolGuardEvidence: React.FC<{ alert: SecurityAlert }> = ({ alert }) => {
  const protocol = alert.type.startsWith('trojan_') ? 'trojan' : alert.type.startsWith('vmess_') ? 'vmess' : '';
  if (!protocol) return null;
  const guard = alert.details?.[`${protocol}_guard`];
  if (!guard || typeof guard !== 'object') return null;

  const chain = guard.evidence_chain || {};
  const configured = Array.isArray(guard.configured_endpoints) ? guard.configured_endpoints : [];
  const blocked = Array.isArray(guard.blocked_endpoints) ? guard.blocked_endpoints : [];
  const pending = Array.isArray(guard.pending_endpoints) ? guard.pending_endpoints : [];
  const stages = [
    ['配置读取', chain.configuration || (guard.detected ? 'confirmed' : 'not_detected_or_incomplete')],
    ['进程与监听', chain.process_owner_and_listener || (blocked.length ? 'confirmed_for_blocked_endpoints' : 'pending_or_unverified')],
    ['公网暴露', chain.public_exposure || (blocked.length ? 'confirmed_for_blocked_endpoints' : 'pending_or_internal_only')],
    ['防火墙读回', chain.firewall_readback || 'not_confirmed'],
  ];
  const title = protocol === 'trojan' ? 'Trojan 端口证据链' : 'VMess 端口证据链';

  return <details className="mt-2 rounded-lg border border-slate-700/80 bg-slate-950/40 px-3 py-2 text-[11px]">
    <summary className="cursor-pointer font-semibold text-sky-200">{title} · 配置 {configured.length} · 已阻断 {blocked.length} · 待核实 {pending.length}</summary>
    <div className="mt-2 grid gap-1 sm:grid-cols-2">
      {stages.map(([label, value]) => <p key={label} className="min-w-0"><span className="text-slate-400">{label}：</span><span className={stageTone(value)}>{stageLabel[value] || value}</span></p>)}
    </div>
    {configured.length > 0 && <div className="mt-2 border-t border-slate-800 pt-2">
      <p className="font-semibold text-slate-300">配置中检测到的入口</p>
      <ul className="mt-1 space-y-1 text-slate-400">{configured.slice(0, 12).map((item: Record<string, any>, index: number) => <li key={`${item.pid}-${item.port}-${index}`} className="break-all">{endpointLabel(item, protocol)}{item.port_config_complete ? ' · 配置解析完整' : ''}</li>)}</ul>
    </div>}
    {blocked.length > 0 && <div className="mt-2 border-t border-slate-800 pt-2">
      <p className="font-semibold text-emerald-200">规则已读回确认</p>
      <ul className="mt-1 space-y-1 text-slate-300">{blocked.slice(0, 12).map((item: Record<string, any>, index: number) => <li key={`${item.proto}-${item.port}-${index}`} className="break-all">{endpointLabel(item, protocol)}</li>)}</ul>
    </div>}
    {pending.length > 0 && <div className="mt-2 border-t border-slate-800 pt-2">
      <p className="font-semibold text-amber-200">尚未阻断的端点及原因</p>
      <ul className="mt-1 space-y-1 text-slate-300">{pending.slice(0, 12).map((item: Record<string, any>, index: number) => <li key={`${item.proto}-${item.port}-${index}`} className="break-all">{endpointLabel(item, protocol)} · {REASONS[item.reason] || item.reason || '证据不足'}</li>)}</ul>
    </div>}
    {chain.listener_inventory_source && <p className="mt-2 border-t border-slate-800 pt-2 text-slate-500">监听清单来源：{chain.listener_inventory_source}{chain.listener_inventory_reason ? ` · ${chain.listener_inventory_reason}` : ''}</p>}
    <p className="mt-1 text-slate-500">只有配置端口与当前监听、公网暴露都能对应，且容器网络命名空间规则读回成功，才标记为已阻断。</p>
  </details>;
};
