export interface ConnectionAttributionEvidence {
  evidence_status?: string;
  captured_sockets?: number | null;
  expected_connection_count?: number;
  confirmed_local_initiated?: number;
  probable_local_initiated?: number;
  confirmed_remote_initiated?: number;
  probable_remote_initiated?: number;
  unknown_direction?: number;
  process_attributed_sockets?: number;
  conntrack_confirmed_sockets?: number;
}

/**
 * Treat missing/empty socket details as unknown when the alert itself reports
 * live connections. Historical and active alert views must not render these
 * unavailable counters as measured zeroes.
 */
export const connectionAttributionUnavailable = (
  evidence?: ConnectionAttributionEvidence | null,
  expectedConnectionCount?: number,
): boolean => {
  if (!evidence) return true;
  if (evidence.evidence_status === 'unavailable') return true;

  const captured = typeof evidence.captured_sockets === 'number' && Number.isFinite(evidence.captured_sockets)
    ? Math.max(0, evidence.captured_sockets)
    : null;
  const reportedExpected = typeof evidence.expected_connection_count === 'number' && Number.isFinite(evidence.expected_connection_count)
    ? Math.max(0, evidence.expected_connection_count)
    : 0;
  const expected = Math.max(0, Number(expectedConnectionCount || 0), reportedExpected);

  if (evidence.evidence_status === 'no_connections') return expected > 0;
  if (expected > 0 && (captured === null || captured === 0)) return true;
  if (evidence.evidence_status === 'available' || evidence.evidence_status === 'partial') return false;
  return captured === null;
};

export const formatConnectionEvidenceCount = (value: number | null | undefined, unavailable: boolean): string => {
  if (unavailable || typeof value !== 'number' || !Number.isFinite(value)) return '未采集';
  return String(Math.max(0, value));
};

export const formatConnectionEvidenceRatio = (
  numerator: number | null | undefined,
  denominator: number | null | undefined,
  unavailable: boolean,
): string => unavailable
  ? '未采集'
  : `${formatConnectionEvidenceCount(numerator, false)}/${formatConnectionEvidenceCount(denominator, false)}`;
