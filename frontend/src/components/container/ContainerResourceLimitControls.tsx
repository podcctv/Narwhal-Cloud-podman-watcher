import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { CheckCircle2, Gauge, Lock, RefreshCw, ShieldAlert, Sliders, Sparkles, Trash2 } from 'lucide-react';
import {
  ContainerIdentity,
  ContainerItem,
  ManualBandwidthLimitResponse,
  ManualContainerResourceLimit,
  ManualResourceLimitsResponse,
} from '../../api/types';
import { api } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';

interface ContainerResourceLimitControlsProps {
  identity: ContainerIdentity;
  container: ContainerItem | null;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh: () => void;
}

type RuntimeKind = 'incus' | 'podman' | 'runman';

const parseCpusFromGuard = (cpuGuard: Record<string, any> | undefined): number | null => {
  if (!cpuGuard) return null;
  const raw = String(cpuGuard.actual_limit || cpuGuard.active_limit || '').trim();
  if (raw) {
    // Runman format: "<quota> <period>" or "max <period>"
    const spaceParts = raw.split(/\s+/);
    if (spaceParts.length === 2 && /^\d+$/.test(spaceParts[0]) && /^\d+$/.test(spaceParts[1])) {
      const q = Number(spaceParts[0]);
      const p = Number(spaceParts[1]);
      if (p > 0) return Math.round((q / p) * 100) / 100;
    }
    // Incus format: "50ms/100ms" or "50%"
    if (raw.includes('/')) {
      const [l, r] = raw.split('/');
      const q = parseFloat(l.replace(/ms/gi, '').trim());
      const p = parseFloat(r.replace(/ms/gi, '').trim());
      if (Number.isFinite(q) && Number.isFinite(p) && p > 0) {
        return Math.round((q / p) * 100) / 100;
      }
    }
    if (raw.endsWith('%')) {
      const pct = parseFloat(raw.slice(0, -1));
      if (Number.isFinite(pct) && pct > 0) return Math.round((pct / 100) * 100) / 100;
    }
    // Podman format: "quota|period|nano|"
    if (raw.includes('|')) {
      const parts = raw.split('|');
      const q = Number(parts[0]);
      const p = Number(parts[1]);
      if (Number.isFinite(q) && q > 0 && Number.isFinite(p) && p > 0) {
        return Math.round((q / p) * 100) / 100;
      }
    }
  }
  if (Number.isFinite(Number(cpuGuard.effective_cpus)) && Number(cpuGuard.effective_cpus) > 0) {
    return Math.round(Number(cpuGuard.effective_cpus) * 100) / 100;
  }
  return null;
};

const parseMemoryMbFromGuard = (memoryGuard: Record<string, any> | undefined): number | null => {
  if (!memoryGuard) return null;
  if (Number.isFinite(Number(memoryGuard.manual_mb)) && Number(memoryGuard.manual_mb) >= 16) {
    return Math.round(Number(memoryGuard.manual_mb));
  }
  const raw = String(memoryGuard.actual_limit || memoryGuard.active_limit || '').trim();
  if (/^\d+$/.test(raw)) {
    const mb = Math.round(Number(raw) / (1024 * 1024));
    if (mb >= 16) return mb;
  }
  return null;
};

const parseIoFromGuard = (
  ioGuard: Record<string, any> | undefined,
): { device: string; readMbps: number | null; writeMbps: number | null } => {
  if (!ioGuard) return { device: '', readMbps: null, writeMbps: null };
  const device = typeof ioGuard.device === 'string' ? ioGuard.device.trim() : '';
  const raw = ioGuard.actual_limit ?? ioGuard.active_limit;
  let rbps: number | null = null;
  let wbps: number | null = null;
  if (typeof raw === 'string') {
    for (const tok of raw.split(/\s+/)) {
      const [k, v] = tok.split('=');
      if (k === 'rbps' && /^\d+$/.test(v || '')) rbps = Number(v);
      if (k === 'wbps' && /^\d+$/.test(v || '')) wbps = Number(v);
    }
  } else if (raw && typeof raw === 'object') {
    if (/^\d+$/.test(String(raw.rbps || ''))) rbps = Number(raw.rbps);
    if (/^\d+$/.test(String(raw.wbps || ''))) wbps = Number(raw.wbps);
  }
  return {
    device,
    readMbps: rbps ? Math.max(1, Math.round(rbps / (1024 * 1024))) : null,
    writeMbps: wbps ? Math.max(1, Math.round(wbps / (1024 * 1024))) : null,
  };
};

const sourceLabel = (source?: string, manualActive?: boolean) => {
  if (source === 'auto_over_manual') return { text: '主动 + 自动联合收紧', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' };
  if (source === 'manual' || manualActive) return { text: '主动限制生效中', tone: 'border-[#9ccaff] bg-[#e8f3ff] text-[#0657b8]' };
  if (source === 'auto') return { text: '自动压力保护中', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' };
  return { text: '未启用额外限制', tone: 'border-[#cbd7e6] bg-[#f4f8fd] text-[#4a607a]' };
};

export const ContainerResourceLimitControls: React.FC<ContainerResourceLimitControlsProps> = ({
  identity,
  container,
  onToast,
  onRefresh,
}) => {
  const formHeadingId = useId();
  const bwFormHeadingId = useId();
  const baseId = useId();
  const runtime = identity.runtime as RuntimeKind;
  const project = identity.project || '';
  const targetContainerId =
    runtime === 'runman'
      ? container?.container_generation_id || identity.container_id || ''
      : container?.container_id || identity.container_id || '';

  const [resContext, setResContext] = useState<ManualResourceLimitsResponse | null>(null);
  const [bwContext, setBwContext] = useState<ManualBandwidthLimitResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [savingResource, setSavingResource] = useState(false);
  const [savingBandwidth, setSavingBandwidth] = useState(false);
  const [confirmClearTarget, setConfirmClearTarget] = useState<'resource' | 'bandwidth' | null>(null);

  // Resource form state
  const [mode, setMode] = useState<'cooperate' | 'lock'>('cooperate');
  const [cpuInput, setCpuInput] = useState('');
  const [memInput, setMemInput] = useState('');
  const [ioReadInput, setIoReadInput] = useState('');
  const [ioWriteInput, setIoWriteInput] = useState('');
  const [ioDeviceInput, setIoDeviceInput] = useState('');
  const [noteInput, setNoteInput] = useState('');
  const [resTouched, setResTouched] = useState<Record<string, boolean>>({});
  const [resSubmitted, setResSubmitted] = useState(false);

  // Bandwidth form state
  const [bwUpInput, setBwUpInput] = useState('');
  const [bwDownInput, setBwDownInput] = useState('');
  const [bwTouched, setBwTouched] = useState<Record<string, boolean>>({});
  const [bwSubmitted, setBwSubmitted] = useState(false);

  const cpuRef = useRef<HTMLInputElement>(null);
  const bwUpRef = useRef<HTMLInputElement>(null);

  const loadPolicies = async () => {
    setLoading(true);
    try {
      const [resData, bwData] = await Promise.all([
        api.getHostResourceLimits(identity.host_id),
        api.getManualBandwidthLimits(identity.host_id),
      ]);
      setResContext(resData);
      setBwContext(bwData);

      const matchedRes = resData.policy.limits.find(
        (item) =>
          item.runtime === runtime &&
          (item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      );
      if (matchedRes) {
        setMode(matchedRes.mode === 'lock' ? 'lock' : 'cooperate');
        setCpuInput(matchedRes.cpu_cpus != null ? String(matchedRes.cpu_cpus) : '');
        setMemInput(matchedRes.memory_high_mb != null ? String(matchedRes.memory_high_mb) : '');
        setIoReadInput(matchedRes.io_read_mbps != null ? String(matchedRes.io_read_mbps) : '');
        setIoWriteInput(matchedRes.io_write_mbps != null ? String(matchedRes.io_write_mbps) : '');
        setIoDeviceInput(matchedRes.io_device || '');
        setNoteInput(matchedRes.note || '');
      } else {
        setMode('cooperate');
        setCpuInput('');
        setMemInput('');
        setIoReadInput('');
        setIoWriteInput('');
        setIoDeviceInput('');
        setNoteInput('');
      }
      setResTouched({});
      setResSubmitted(false);

      const matchedBw = bwData.policy.limits.find(
        (item) =>
          item.scope === 'container' &&
          item.runtime === runtime &&
          (item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      );
      setBwUpInput(matchedBw ? String(matchedBw.upload_mbps || 0) : '');
      setBwDownInput(matchedBw ? String(matchedBw.download_mbps || 0) : '');
      setBwTouched({});
      setBwSubmitted(false);
    } catch (error: any) {
      onToast('error', `读取主动限额配置失败：${error?.message || error}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadPolicies();
  }, [identity.host_id, identity.runtime, identity.project, identity.container_name, targetContainerId]);

  const savedRule: ManualContainerResourceLimit | undefined = useMemo(
    () =>
      resContext?.policy.limits.find(
        (item) =>
          item.runtime === runtime &&
          (item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      ),
    [resContext, runtime, project, identity.container_name, targetContainerId],
  );

  const savedBwRule = useMemo(
    () =>
      bwContext?.policy.limits.find(
        (item) =>
          item.scope === 'container' &&
          item.runtime === runtime &&
          (item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      ),
    [bwContext, runtime, project, identity.container_name, targetContainerId],
  );

  const reportedResItem = useMemo(
    () =>
      resContext?.reported?.items?.find(
        (item) =>
          item.runtime === runtime &&
          (item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      ),
    [resContext, runtime, project, identity.container_name, targetContainerId],
  );

  const autoBwItem = useMemo(
    () =>
      (bwContext?.reported?.auto_throttle?.items || []).find(
        (item: Record<string, unknown>) =>
          item.runtime === runtime &&
          String(item.project || '') === project &&
          item.container_name === identity.container_name &&
          (!targetContainerId || item.container_id === targetContainerId),
      ) as Record<string, any> | undefined,
    [bwContext, runtime, project, identity.container_name, targetContainerId],
  );

  const cpuGuard = container?.security?.cpu_guard;
  const memoryGuard = container?.security?.memory_guard;
  const ioGuard = container?.security?.io_guard;

  const hasAutoGuardActive = Boolean(
    ['limited', 'active', 'escalating'].includes(cpuGuard?.state || '') ||
      ['limited', 'active', 'escalating'].includes(memoryGuard?.state || '') ||
      ['limited', 'active', 'escalating'].includes(ioGuard?.state || ''),
  );

  const validateResourceField = (field: string): string => {
    if (field === 'cpu_cpus' && cpuInput.trim() !== '') {
      const val = Number(cpuInput.trim());
      if (!Number.isFinite(val) || val < 0.05 || val > 64) {
        return '请输入 0.05 到 64 之间的核数（例如 0.5）';
      }
    }
    if (field === 'memory_high_mb' && memInput.trim() !== '') {
      const val = Number(memInput.trim());
      if (!Number.isInteger(val) || val < 16 || val > 1048576) {
        return '请输入 16 到 1048576 之间的整数 MB';
      }
    }
    if (field === 'io_read_mbps' && ioReadInput.trim() !== '') {
      const val = Number(ioReadInput.trim());
      if (!Number.isInteger(val) || val < 1 || val > 10000) {
        return '请输入 1 到 10000 之间的整数 MB/s';
      }
    }
    if (field === 'io_write_mbps' && ioWriteInput.trim() !== '') {
      const val = Number(ioWriteInput.trim());
      if (!Number.isInteger(val) || val < 1 || val > 10000) {
        return '请输入 1 到 10000 之间的整数 MB/s';
      }
    }
    if (field === 'io_device' && ioDeviceInput.trim() !== '' && !/^\d+:\d+$/.test(ioDeviceInput.trim())) {
      return '请留空自动识别，或填写 MAJOR:MINOR 设备号（如 8:0）';
    }
    return '';
  };

  const cpuError = (resTouched.cpu_cpus || resSubmitted) ? validateResourceField('cpu_cpus') : '';
  const memError = (resTouched.memory_high_mb || resSubmitted) ? validateResourceField('memory_high_mb') : '';
  const ioReadError = (resTouched.io_read_mbps || resSubmitted) ? validateResourceField('io_read_mbps') : '';
  const ioWriteError = (resTouched.io_write_mbps || resSubmitted) ? validateResourceField('io_write_mbps') : '';
  const ioDeviceError = (resTouched.io_device || resSubmitted) ? validateResourceField('io_device') : '';
  const anyResourceValueEntered = Boolean(
    cpuInput.trim() || memInput.trim() || ioReadInput.trim() || ioWriteInput.trim(),
  );
  const resFormMissingValueError =
    resSubmitted && !anyResourceValueEntered ? '请至少填写 CPU、内存或磁盘 I/O 中的一项限额' : '';

  const validateBandwidthField = (raw: string): string => {
    if (raw.trim() === '') return '';
    const val = Number(raw.trim());
    if (!Number.isInteger(val) || val < 0 || val > 100000) {
      return '请输入 0 到 100000 之间的整数 Mbps';
    }
    return '';
  };

  const bwUpError = (bwTouched.up || bwSubmitted) ? validateBandwidthField(bwUpInput) : '';
  const bwDownError = (bwTouched.down || bwSubmitted) ? validateBandwidthField(bwDownInput) : '';
  const bwPairMissingError =
    bwSubmitted &&
    (Number(bwUpInput || 0) <= 0 && Number(bwDownInput || 0) <= 0)
      ? '请至少将上行或下行速率设置为大于 0 Mbps（如需解除限速请点击“解除带宽限速”）'
      : '';

  const adoptActiveAutoLimits = () => {
    const autoCpu = parseCpusFromGuard(cpuGuard);
    const autoMem = parseMemoryMbFromGuard(memoryGuard);
    const autoIo = parseIoFromGuard(ioGuard);
    if (autoCpu != null) setCpuInput(String(autoCpu));
    if (autoMem != null) setMemInput(String(autoMem));
    if (autoIo.readMbps != null) setIoReadInput(String(autoIo.readMbps));
    if (autoIo.writeMbps != null) setIoWriteInput(String(autoIo.writeMbps));
    if (autoIo.device) setIoDeviceInput(autoIo.device);
    onToast('info', '已将当前自动保护限额填入表单，核对后点击“保存并联动应用”即可接管为持久规则');
  };

  const handleSaveResourceLimit = async (event: React.FormEvent) => {
    event.preventDefault();
    setResSubmitted(true);
    if (!targetContainerId) {
      onToast('error', '容器实例身份或 Runman 代次 ID 暂不可用，无法绑定主动限额');
      return;
    }
    const fieldErrs = [
      validateResourceField('cpu_cpus'),
      validateResourceField('memory_high_mb'),
      validateResourceField('io_read_mbps'),
      validateResourceField('io_write_mbps'),
      validateResourceField('io_device'),
    ];
    if (fieldErrs.some(Boolean) || !anyResourceValueEntered) {
      cpuRef.current?.focus();
      return;
    }

    setSavingResource(true);
    try {
      const res = await api.updateContainerResourceLimit(identity.host_id, {
        runtime,
        project,
        container_name: identity.container_name,
        container_id: targetContainerId,
        mode,
        cpu_cpus: cpuInput.trim() ? Number(cpuInput.trim()) : null,
        memory_high_mb: memInput.trim() ? Number(memInput.trim()) : null,
        io_device: ioDeviceInput.trim(),
        io_read_mbps: ioReadInput.trim() ? Number(ioReadInput.trim()) : null,
        io_write_mbps: ioWriteInput.trim() ? Number(ioWriteInput.trim()) : null,
        note: noteInput.trim(),
      });
      onToast('success', `容器主动资源限额已保存（修订 ${res.revision}），节点下次动作轮询时生效`);
      await loadPolicies();
      onRefresh();
    } catch (error: any) {
      onToast('error', `保存失败：${error?.message || error}`);
    } finally {
      setSavingResource(false);
    }
  };

  const handleClearResourceLimit = async () => {
    if (!targetContainerId) return;
    setSavingResource(true);
    try {
      const res = await api.updateContainerResourceLimit(identity.host_id, {
        runtime,
        project,
        container_name: identity.container_name,
        container_id: targetContainerId,
        clear: true,
      });
      onToast('success', `已解除容器主动资源限额（修订 ${res.revision}），节点将恢复原配额或交还自动保护`);
      await loadPolicies();
      onRefresh();
    } catch (error: any) {
      onToast('error', `解除失败：${error?.message || error}`);
    } finally {
      setSavingResource(false);
    }
  };

  const handleSaveBandwidthLimit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBwSubmitted(true);
    if (!targetContainerId) {
      onToast('error', '容器身份暂不可用，无法保存带宽限速');
      return;
    }
    const upErr = validateBandwidthField(bwUpInput);
    const downErr = validateBandwidthField(bwDownInput);
    const up = Number(bwUpInput.trim() || 0);
    const down = Number(bwDownInput.trim() || 0);
    if (upErr || downErr || (up <= 0 && down <= 0)) {
      bwUpRef.current?.focus();
      return;
    }
    setSavingBandwidth(true);
    try {
      const res = await api.updateContainerBandwidthLimit(identity.host_id, {
        runtime,
        project,
        container_name: identity.container_name,
        container_id: targetContainerId,
        upload_mbps: up,
        download_mbps: down,
      });
      onToast('success', `单容器带宽限速已保存（修订 ${res.revision}），将与母机自动阶梯限速取更严上限联合生效`);
      await loadPolicies();
      onRefresh();
    } catch (error: any) {
      onToast('error', `保存带宽限速失败：${error?.message || error}`);
    } finally {
      setSavingBandwidth(false);
    }
  };

  const handleClearBandwidthLimit = async () => {
    if (!targetContainerId) return;
    setSavingBandwidth(true);
    try {
      const res = await api.updateContainerBandwidthLimit(identity.host_id, {
        runtime,
        project,
        container_name: identity.container_name,
        container_id: targetContainerId,
        upload_mbps: 0,
        download_mbps: 0,
        clear: true,
      });
      onToast('success', `已解除该容器主动带宽限速（修订 ${res.revision}）`);
      await loadPolicies();
      onRefresh();
    } catch (error: any) {
      onToast('error', `解除带宽限速失败：${error?.message || error}`);
    } finally {
      setSavingBandwidth(false);
    }
  };

  const savedRev = Number(resContext?.policy?.revision || 0);
  const reportedRev = Number(resContext?.reported?.revision || 0);
  const waitingForApply = Boolean(resContext?.host_online && savedRev > reportedRev);

  const cpuSource = sourceLabel(cpuGuard?.effective_source, cpuGuard?.manual_active);
  const memSource = sourceLabel(memoryGuard?.effective_source, memoryGuard?.manual_active);
  const ioSource = sourceLabel(ioGuard?.effective_source, ioGuard?.manual_active);
  const bwAutoActive = autoBwItem?.state === 'limited';
  const bwSource =
    savedBwRule && bwAutoActive
      ? { text: '主动 + 自动阶梯联合生效', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' }
      : savedBwRule
      ? { text: '主动带宽限速生效', tone: 'border-[#9ccaff] bg-[#e8f3ff] text-[#0657b8]' }
      : bwAutoActive
      ? { text: '自动阶梯带宽限速中', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' }
      : { text: '未限速', tone: 'border-[#cbd7e6] bg-[#f4f8fd] text-[#4a607a]' };

  return (
    <div className="space-y-4 border-t border-[#d2dfec] pt-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h4 id={formHeadingId} className="flex items-center gap-2 text-xs font-extrabold text-[#0e233c]">
            <Sliders className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
            <span>主动资源限额与自动保护联动</span>
          </h4>
          <p className="mt-0.5 text-[11px] leading-relaxed text-[#4a607a]">
            支持在容器上直接设定 CPU、内存与磁盘 I/O 长期上限，并与 Watcher 自动压力保护协同（取更严值，压力恢复时回落至你的主动上限而非放开）。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {hasAutoGuardActive && (
            <button
              type="button"
              onClick={adoptActiveAutoLimits}
              className="rn2-btn rn2-btn-sm rn2-btn-blue min-h-9"
            >
              <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
              <span>接管当前自动限额</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => void loadPolicies()}
            disabled={loading || savingResource || savingBandwidth}
            className="rn2-btn rn2-btn-sm rn2-btn-ghost min-h-9"
            aria-label="刷新容器主动限额状态"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>刷新</span>
          </button>
        </div>
      </div>

      {/* 4-Dimension Linkage Status Strip */}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-[11px]">
          <span className="block font-bold text-[#31485e]">CPU 裁决</span>
          <span className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${cpuSource.tone}`}>
            {cpuSource.text}
          </span>
        </div>
        <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-[11px]">
          <span className="block font-bold text-[#31485e]">内存裁决</span>
          <span className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${memSource.tone}`}>
            {memSource.text}
          </span>
        </div>
        <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-[11px]">
          <span className="block font-bold text-[#31485e]">磁盘 I/O 裁决</span>
          <span className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${ioSource.tone}`}>
            {ioSource.text}
          </span>
        </div>
        <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5 text-[11px]">
          <span className="block font-bold text-[#31485e]">网络带宽裁决</span>
          <span className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-bold ${bwSource.tone}`}>
            {bwSource.text}
          </span>
        </div>
      </div>

      {runtime === 'runman' && (
        <div className="rounded-xl border border-[#a9d1ff] bg-[#e8f3ff]/70 px-3 py-2 text-[11px] leading-relaxed text-[#0657b8]">
          Runman 主动限额绑定当前代次 ID（<span className="font-mono font-bold">{targetContainerId || '未确认'}</span>），实例重建后不会误继承旧容器限额。
        </div>
      )}

      {(waitingForApply || reportedResItem) && (
        <div
          role="status"
          aria-live="polite"
          className={`flex items-start gap-2 rounded-xl border px-3 py-2 text-xs ${
            waitingForApply
              ? 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]'
              : reportedResItem?.state === 'applied'
              ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]'
              : 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]'
          }`}
        >
          {reportedResItem?.state === 'applied' && !waitingForApply ? (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          ) : (
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          )}
          <div className="min-w-0">
            <span className="font-bold">
              {waitingForApply
                ? `策略已保存（修订 ${savedRev}），等待节点下次动作轮询应用并读回（当前节点确认修订 ${reportedRev}）`
                : reportedResItem?.message || '已同步'}
            </span>
            {reportedResItem && (
              <div className="mt-0.5 font-mono text-[11px]">
                {reportedResItem.effective_cpu ? `CPU=${reportedResItem.effective_cpu} ` : ''}
                {reportedResItem.effective_memory ? `内存=${reportedResItem.effective_memory} ` : ''}
                {reportedResItem.effective_io ? `IO=${reportedResItem.effective_io}` : ''}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Resource Limits Form */}
      <form
        aria-labelledby={formHeadingId}
        onSubmit={(e) => void handleSaveResourceLimit(e)}
        className="space-y-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5"
      >
        <fieldset className="space-y-2">
          <legend className="text-xs font-extrabold text-[#0b1636]">与 Watcher 自动保护的联动策略</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            <label
              htmlFor={`${baseId}-mode-cooperate`}
              className={`flex min-h-11 cursor-pointer items-start gap-2.5 rounded-xl border p-2.5 text-xs transition-colors ${
                mode === 'cooperate'
                  ? 'border-[#087bff] bg-white text-[#0b1636] shadow-xs'
                  : 'border-[#d2dfec] bg-white/60 text-[#31485e]'
              }`}
            >
              <input
                id={`${baseId}-mode-cooperate`}
                name="linkage_mode"
                type="radio"
                value="cooperate"
                checked={mode === 'cooperate'}
                onChange={() => setMode('cooperate')}
                className="mt-0.5 accent-[#087bff]"
              />
              <span>
                <span className="block font-bold">协同联动（推荐）</span>
                <span className="mt-0.5 block text-[11px] text-[#4a607a]">
                  取主动与自动更严者；自动压力缓解后自动回退至你的主动上限，不恢复到不限。
                </span>
              </span>
            </label>

            <label
              htmlFor={`${baseId}-mode-lock`}
              className={`flex min-h-11 cursor-pointer items-start gap-2.5 rounded-xl border p-2.5 text-xs transition-colors ${
                mode === 'lock'
                  ? 'border-[#087bff] bg-white text-[#0b1636] shadow-xs'
                  : 'border-[#d2dfec] bg-white/60 text-[#31485e]'
              }`}
            >
              <input
                id={`${baseId}-mode-lock`}
                name="linkage_mode"
                type="radio"
                value="lock"
                checked={mode === 'lock'}
                onChange={() => setMode('lock')}
                className="mt-0.5 accent-[#087bff]"
              />
              <span>
                <span className="flex items-center gap-1 font-bold">
                  <Lock className="h-3 w-3 text-[#087bff]" aria-hidden="true" />
                  锁定主动限额
                </span>
                <span className="mt-0.5 block text-[11px] text-[#4a607a]">
                  始终锁定当前设定上限，禁止自动资源保护继续下调覆盖。
                </span>
              </span>
            </label>
          </div>
        </fieldset>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor={`${baseId}-cpu`} className="block text-xs font-semibold text-[#31485e]">
              CPU 核心上限（核，0.05–64，可留空）
            </label>
            <input
              ref={cpuRef}
              id={`${baseId}-cpu`}
              name="cpu_cpus"
              type="text"
              inputMode="decimal"
              value={cpuInput}
              aria-invalid={Boolean(cpuError)}
              aria-describedby={cpuError ? `${baseId}-cpu-err` : `${baseId}-cpu-help`}
              onChange={(e) => {
                setCpuInput(e.target.value);
                if (resTouched.cpu_cpus) setResSubmitted(false);
              }}
              onBlur={() => setResTouched((prev) => ({ ...prev, cpu_cpus: true }))}
              placeholder="例如 0.5 或 1"
              className="rn2-input mt-1.5 font-mono"
            />
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              {[0.25, 0.5, 1, 2].map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setCpuInput(String(preset))}
                  className="rounded-lg border border-[#cedae7] bg-white px-2 py-0.5 font-mono text-[11px] font-semibold text-[#31485e] hover:border-[#087bff] hover:text-[#0657b8]"
                >
                  {preset} 核
                </button>
              ))}
            </div>
            {cpuError ? (
              <p id={`${baseId}-cpu-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {cpuError}
              </p>
            ) : (
              <p id={`${baseId}-cpu-help`} className="mt-1 text-[11px] text-[#697b9c]">
                支持按 0.05 核步进配置（不超过容器原配额上限）。
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-mem`} className="block text-xs font-semibold text-[#31485e]">
              内存软上限 memory.high（MB，可留空）
            </label>
            <input
              id={`${baseId}-mem`}
              name="memory_high_mb"
              type="text"
              inputMode="numeric"
              value={memInput}
              aria-invalid={Boolean(memError)}
              aria-describedby={memError ? `${baseId}-mem-err` : `${baseId}-mem-help`}
              onChange={(e) => setMemInput(e.target.value)}
              onBlur={() => setResTouched((prev) => ({ ...prev, memory_high_mb: true }))}
              placeholder="例如 256 或 512"
              className="rn2-input mt-1.5 font-mono"
            />
            {memError ? (
              <p id={`${baseId}-mem-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {memError}
              </p>
            ) : (
              <p id={`${baseId}-mem-help`} className="mt-1 text-[11px] text-[#697b9c]">
                达到软上限时由内核回收页缓存而不直接 OOM 强杀。
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-ior`} className="block text-xs font-semibold text-[#31485e]">
              磁盘读取上限（MB/s，可留空）
            </label>
            <input
              id={`${baseId}-ior`}
              name="io_read_mbps"
              type="text"
              inputMode="numeric"
              value={ioReadInput}
              aria-invalid={Boolean(ioReadError)}
              aria-describedby={ioReadError ? `${baseId}-ior-err` : undefined}
              onChange={(e) => setIoReadInput(e.target.value)}
              onBlur={() => setResTouched((prev) => ({ ...prev, io_read_mbps: true }))}
              placeholder="例如 20"
              className="rn2-input mt-1.5 font-mono"
            />
            {ioReadError && (
              <p id={`${baseId}-ior-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {ioReadError}
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-iow`} className="block text-xs font-semibold text-[#31485e]">
              磁盘写入上限（MB/s，可留空）
            </label>
            <input
              id={`${baseId}-iow`}
              name="io_write_mbps"
              type="text"
              inputMode="numeric"
              value={ioWriteInput}
              aria-invalid={Boolean(ioWriteError)}
              aria-describedby={ioWriteError ? `${baseId}-iow-err` : undefined}
              onChange={(e) => setIoWriteInput(e.target.value)}
              onBlur={() => setResTouched((prev) => ({ ...prev, io_write_mbps: true }))}
              placeholder="例如 20"
              className="rn2-input mt-1.5 font-mono"
            />
            {ioWriteError && (
              <p id={`${baseId}-iow-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {ioWriteError}
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-iodev`} className="block text-xs font-semibold text-[#31485e]">
              磁盘设备号（可选，默认自动识别）
            </label>
            <input
              id={`${baseId}-iodev`}
              name="io_device"
              type="text"
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              value={ioDeviceInput}
              aria-invalid={Boolean(ioDeviceError)}
              aria-describedby={ioDeviceError ? `${baseId}-iodev-err` : undefined}
              onChange={(e) => setIoDeviceInput(e.target.value)}
              onBlur={() => setResTouched((prev) => ({ ...prev, io_device: true }))}
              placeholder="留空自动识别，或如 8:0"
              className="rn2-input mt-1.5 font-mono"
            />
            {ioDeviceError && (
              <p id={`${baseId}-iodev-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {ioDeviceError}
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-note`} className="block text-xs font-semibold text-[#31485e]">
              备注（可选，最多 120 字）
            </label>
            <input
              id={`${baseId}-note`}
              name="note"
              type="text"
              maxLength={120}
              value={noteInput}
              onChange={(e) => setNoteInput(e.target.value)}
              placeholder="例如：限制跑满单核用户"
              className="rn2-input mt-1.5"
            />
          </div>
        </div>

        {resFormMissingValueError && (
          <p role="alert" className="text-xs font-semibold text-[#b41835]">
            {resFormMissingValueError}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            type="submit"
            disabled={savingResource || !resContext?.host_online || !targetContainerId}
            className="rn2-btn rn2-btn-orange rn2-btn-sm min-h-11"
          >
            <span>{savingResource ? '保存中…' : '保存并联动应用'}</span>
          </button>
          {savedRule && (
            <button
              type="button"
              disabled={savingResource}
              onClick={() => setConfirmClearTarget('resource')}
              className="rn2-btn rn2-btn-danger rn2-btn-sm min-h-11"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>解除主动资源限额</span>
            </button>
          )}
        </div>
      </form>

      {/* Container Network Bandwidth Form (shares host tc-guard policy & auto_throttle) */}
      <form
        aria-labelledby={bwFormHeadingId}
        onSubmit={(e) => void handleSaveBandwidthLimit(e)}
        className="space-y-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h5 id={bwFormHeadingId} className="flex items-center gap-1.5 text-xs font-extrabold text-[#0e233c]">
            <Gauge className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
            <span>单容器网卡带宽限速（tc policer · 与母机自动阶梯限速联动）</span>
          </h5>
          {bwContext?.policy?.auto_throttle?.enabled && (
            <span className="rounded-full border border-[#9de2d8] bg-[#e6f7f4] px-2 py-0.5 text-[10px] font-bold text-[#147468]">
              母机自动阶梯联动已开启
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor={`${baseId}-bw-up`} className="block text-xs font-semibold text-[#31485e]">
              上行速率上限（Mbps，0 表示不限该方向）
            </label>
            <input
              ref={bwUpRef}
              id={`${baseId}-bw-up`}
              name="upload_mbps"
              type="text"
              inputMode="numeric"
              value={bwUpInput}
              aria-invalid={Boolean(bwUpError)}
              aria-describedby={bwUpError ? `${baseId}-bw-up-err` : undefined}
              onChange={(e) => setBwUpInput(e.target.value)}
              onBlur={() => setBwTouched((prev) => ({ ...prev, up: true }))}
              placeholder="例如 50"
              className="rn2-input mt-1.5 font-mono"
            />
            {bwUpError && (
              <p id={`${baseId}-bw-up-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {bwUpError}
              </p>
            )}
          </div>

          <div>
            <label htmlFor={`${baseId}-bw-down`} className="block text-xs font-semibold text-[#31485e]">
              下行速率上限（Mbps，0 表示不限该方向）
            </label>
            <input
              id={`${baseId}-bw-down`}
              name="download_mbps"
              type="text"
              inputMode="numeric"
              value={bwDownInput}
              aria-invalid={Boolean(bwDownError)}
              aria-describedby={bwDownError ? `${baseId}-bw-down-err` : undefined}
              onChange={(e) => setBwDownInput(e.target.value)}
              onBlur={() => setBwTouched((prev) => ({ ...prev, down: true }))}
              placeholder="例如 50"
              className="rn2-input mt-1.5 font-mono"
            />
            {bwDownError && (
              <p id={`${baseId}-bw-down-err`} className="mt-1 text-[11px] font-semibold text-[#b41835]">
                {bwDownError}
              </p>
            )}
          </div>
        </div>

        {bwPairMissingError && (
          <p role="alert" className="text-xs font-semibold text-[#b41835]">
            {bwPairMissingError}
          </p>
        )}

        {bwAutoActive && (
          <p className="text-[11px] font-medium text-[#9a5b00]">
            当前自动阶梯限速生效中：上行 {autoBwItem?.upload_limit_mbps ?? 0} Mbps · 下行 {autoBwItem?.download_limit_mbps ?? 0} Mbps（联动会取主动与自动更严者）。
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            type="submit"
            disabled={savingBandwidth || !bwContext?.host_online || !targetContainerId}
            className="rn2-btn rn2-btn-blue rn2-btn-sm min-h-11"
          >
            <span>{savingBandwidth ? '应用中…' : '应用容器带宽限速'}</span>
          </button>
          {savedBwRule && (
            <button
              type="button"
              disabled={savingBandwidth}
              onClick={() => setConfirmClearTarget('bandwidth')}
              className="rn2-btn rn2-btn-danger rn2-btn-sm min-h-11"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span>解除带宽限速</span>
            </button>
          )}
        </div>
      </form>

      <ConfirmDialog
        open={Boolean(confirmClearTarget)}
        title={confirmClearTarget === 'bandwidth' ? '确认解除单容器带宽限速？' : '确认解除主动资源限额？'}
        description={
          confirmClearTarget === 'bandwidth'
            ? `将移除 ${identity.container_name} 的手动 tc 限速规则；若母机开启自动阶梯保护，则交还自动保护裁决。`
            : `将移除 ${identity.container_name} 的主动 CPU/内存/IO 上限并恢复容器原配额；若当前仍处于高压力，将自动交还 Watcher 资源保护。`
        }
        confirmLabel={confirmClearTarget === 'bandwidth' ? '解除带宽限速' : '解除资源限额'}
        tone="danger"
        isSubmitting={savingResource || savingBandwidth}
        onCancel={() => setConfirmClearTarget(null)}
        onConfirm={async () => {
          const t = confirmClearTarget;
          setConfirmClearTarget(null);
          if (t === 'resource') {
            await handleClearResourceLimit();
          } else if (t === 'bandwidth') {
            await handleClearBandwidthLimit();
          }
        }}
      />
    </div>
  );
};
