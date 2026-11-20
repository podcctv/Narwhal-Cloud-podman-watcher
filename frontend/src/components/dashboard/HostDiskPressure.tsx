import React from 'react';
import { HardDrive } from 'lucide-react';
import { ContainerItem } from '../../api/types';
import { fmtBytes } from '../../api/client';

export function hostDiskPressure(items: ContainerItem[]) {
  const current = items.find(c => !c.alerts?.stale && !c.alerts?.host_stale && ((c.disk_root_total_bytes || 0) > 0 || (c.disk_data_total_bytes || 0) > 0));
  if (!current) return null;
  const volumes = [
    { label: '根分区 /', total: current.disk_root_total_bytes || 0, available: current.disk_root_avail_bytes || 0, percent: current.disk_root_used_percent },
    { label: `数据分区 ${current.disk_data_mountpoint || '/'}`, total: current.disk_data_total_bytes || 0, available: current.disk_data_avail_bytes || 0, percent: current.disk_used_percent },
  ].filter(v => Number.isFinite(v.total) && v.total > 0 && Number.isFinite(v.available) && v.available >= 0)
    .map(v => ({ ...v, percent: typeof v.percent === 'number' && Number.isFinite(v.percent) ? v.percent : (v.total - v.available) / v.total * 100 }))
    .filter(v => v.percent >= 90).sort((a, b) => b.percent - a.percent);
  return volumes[0] || null;
}

export const HostDiskPressure: React.FC<{ items: ContainerItem[] }> = ({ items }) => {
  const pressure = hostDiskPressure(items);
  if (!pressure) return null;
  const critical = pressure.percent >= 95;
  return (
    <div
      role="status"
      className={`flex items-start gap-2.5 border-t px-4 py-3 text-sm ${
        critical
          ? 'border-[#f9b8c4] bg-[#ffeef1] text-[#9f1239]'
          : 'border-[#f7d58b] bg-[#fef6e4] text-[#78350f]'
      }`}
    >
      <HardDrive aria-hidden="true" className={`mt-0.5 h-4 w-4 shrink-0 ${critical ? 'text-[#b41835]' : 'text-[#b45309]'}`} />
      <p className="min-w-0 wrap-break-word">
        <span className="font-bold tabular-nums">宿主机磁盘空间不足 · {pressure.percent.toFixed(1)}%</span>
        <span className={`mt-1 block text-xs ${critical ? 'text-[#9f1239]' : 'text-[#9a5b00]'}`}>
          {pressure.label} · 可用 {fmtBytes(pressure.available)} / {fmtBytes(pressure.total)}。请到运维中心 → 存储管理扫描清理；达到 90% 时持续提醒，安全清理不会删除业务数据。
        </span>
      </p>
    </div>
  );
};
