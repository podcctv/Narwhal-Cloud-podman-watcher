import { SecurityAlert } from '../../api/types';

const generationPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const processPattern = /^[a-zA-Z0-9_.@-]{2,80}$/;
const startTicksPattern = /^[0-9]{1,24}$/;
const fileGenerationPattern = /^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$/;

const hasRunmanTargetEvidence = (alert: SecurityAlert): boolean => {
  const details = alert.details || {};
  if (alert.project !== 'default' || !generationPattern.test(String(details.instance_id || ''))) return false;
  const processTargets = Array.isArray(details.process_targets) ? details.process_targets : [];
  const fileTargets = Array.isArray(details.file_targets) ? details.file_targets : [];
  const hasProcess = processTargets.some((item: any) =>
    Number.isInteger(item?.pid) && item.pid > 1 && item.pid <= 4194304
    && /^[a-zA-Z0-9_.@+-]{1,80}$/.test(String(item.process || ''))
    && processPattern.test(String(item.pattern || ''))
    && startTicksPattern.test(String(item.start_ticks || '')) && Number(item.start_ticks) > 0);
  const hasFile = fileTargets.some((item: any) =>
    typeof item?.path === 'string' && item.path.startsWith('/') && item.path.length <= 256
    && fileGenerationPattern.test(String(item.generation || ''))
    && ['config', 'service', 'binary'].includes(String(item.kind || '')));
  return hasProcess || hasFile;
};

export const hasRemediationEvidence = (alert: SecurityAlert): boolean => {
  const details = alert.details || {};
  const runman = alert.runtime === 'runman';
  if (!['incus', 'podman', 'runman'].includes(alert.runtime)) return false;
  if (runman && !hasRunmanTargetEvidence(alert)) return false;
  if (alert.type === 'unauthorized_panel_pairing') {
    return (details.process_patterns || []).length > 0 || (details.config_files || []).length > 0;
  }
  if (alert.type === 'socks_weak_auth') {
    return !runman && ['no_auth', 'weak_password'].includes(details.socks_auth_mode)
      && (details.socks_processes || []).length > 0;
  }
  if (alert.type === 'malicious_process') {
    const hasXmrig = (details.malicious_processes || []).some((item: any) => item?.process === 'xmrig');
    return hasXmrig && (!runman || (details.process_targets || []).some((item: any) =>
      item?.process === 'xmrig' && item?.pattern === 'xmrig' && startTicksPattern.test(String(item.start_ticks || ''))));
  }
  return false;
};
