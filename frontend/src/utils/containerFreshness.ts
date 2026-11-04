import type { ContainerItem } from '../api/types';

/**
 * A live container must be present in the host's latest inventory report.
 * The agent submits the host heartbeat and all current container samples with
 * the same timestamp, so an older sample is only a retained snapshot.
 */
export const isCurrentContainerInventoryItem = (container: ContainerItem): boolean => {
  const sampleTimestamp = Number(container.timestamp || 0);
  const hostReportTimestamp = Number(container.host_report_timestamp || container.timestamp || 0);
  return sampleTimestamp > 0
    && sampleTimestamp === hostReportTimestamp
    && !container.alerts?.stale
    && !container.alerts?.host_stale;
};
