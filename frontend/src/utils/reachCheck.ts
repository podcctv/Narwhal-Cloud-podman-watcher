/**
 * Global Reachability & Carrier Connectivity Engine
 * Inspired by yt1988/reach-check, tailored for Narwhal Cloud Container Watcher.
 * Lightweight, zero-daemon client-driven Globalping API probes with SSRF and bad-port protections.
 */

export interface ReachRegion {
  id: string;
  group: 'cn' | 'apac' | 'emea' | 'am';
  name: string;
  flag: string;
  carrier?: 'telecom' | 'unicom' | 'mobile';
  asn?: number;
  city?: string;
  country: string;
  loc: { country?: string; city?: string; asn?: number };
}

export const REACH_REGIONS: ReachRegion[] = [
  // China 3 Major Carriers
  { id: 'cn-telecom', group: 'cn', name: '中国电信 (China Telecom)', flag: '🇨🇳', carrier: 'telecom', asn: 4134, country: 'CN', loc: { country: 'CN', asn: 4134 } },
  { id: 'cn-unicom', group: 'cn', name: '中国联通 (China Unicom)', flag: '🇨🇳', carrier: 'unicom', asn: 4837, country: 'CN', loc: { country: 'CN', asn: 4837 } },
  { id: 'cn-mobile', group: 'cn', name: '中国移动 (China Mobile)', flag: '🇨🇳', carrier: 'mobile', asn: 9808, country: 'CN', loc: { country: 'CN', asn: 9808 } },

  // APAC
  { id: 'apac-hk', group: 'apac', name: '中国香港 (Hong Kong)', flag: '🇭🇰', country: 'HK', loc: { country: 'HK' } },
  { id: 'apac-tw', group: 'apac', name: '中国台湾 (Taiwan)', flag: '🇨🇳', country: 'TW', loc: { country: 'TW' } },
  { id: 'apac-jp', group: 'apac', name: '日本东京 (Tokyo)', flag: '🇯🇵', city: 'Tokyo', country: 'JP', loc: { city: 'Tokyo' } },
  { id: 'apac-kr', group: 'apac', name: '韩国首尔 (Seoul)', flag: '🇰🇷', country: 'KR', loc: { country: 'KR' } },
  { id: 'apac-sg', group: 'apac', name: '新加坡 (Singapore)', flag: '🇸🇬', country: 'SG', loc: { country: 'SG' } },
  { id: 'apac-in', group: 'apac', name: '印度孟买 (Mumbai)', flag: '🇮🇳', country: 'IN', loc: { country: 'IN' } },
  { id: 'apac-au', group: 'apac', name: '澳大利亚悉尼 (Sydney)', flag: '🇦🇺', country: 'AU', loc: { country: 'AU' } },

  // EMEA
  { id: 'emea-gb', group: 'emea', name: '英国伦敦 (London)', flag: '🇬🇧', city: 'London', country: 'GB', loc: { city: 'London' } },
  { id: 'emea-de', group: 'emea', name: '德国法兰克福 (Frankfurt)', flag: '🇩🇪', city: 'Frankfurt', country: 'DE', loc: { city: 'Frankfurt' } },
  { id: 'emea-ru', group: 'emea', name: '俄罗斯莫斯科 (Moscow)', flag: '🇷🇺', country: 'RU', loc: { country: 'RU' } },
  { id: 'emea-ae', group: 'emea', name: '阿联酋迪拜 (Dubai)', flag: '🇦🇪', country: 'AE', loc: { country: 'AE' } },
  { id: 'emea-za', group: 'emea', name: '南非约翰内斯堡 (Johannesburg)', flag: '🇿🇦', country: 'ZA', loc: { country: 'ZA' } },

  // Americas
  { id: 'am-us-la', group: 'am', name: '美国洛杉矶 (Los Angeles)', flag: '🇺🇸', city: 'Los Angeles', country: 'US', loc: { city: 'Los Angeles' } },
  { id: 'am-us-ny', group: 'am', name: '美国纽约 (New York)', flag: '🇺🇸', city: 'New York', country: 'US', loc: { city: 'New York' } },
  { id: 'am-br', group: 'am', name: '巴西圣保罗 (Sao Paulo)', flag: '🇧🇷', city: 'Sao Paulo', country: 'BR', loc: { city: 'Sao Paulo' } },
];

export interface ProbeTimings {
  dns?: number;
  tcp?: number;
  tls?: number;
  ttfb?: number;
  total: number;
}

export type ProbeStatusCode = 'ok' | 'timeout' | 'refused' | 'dns_error' | 'tls_error' | 'blocked' | 'error' | 'skipped' | 'testing';

export interface RegionResult {
  region: ReachRegion;
  status: ProbeStatusCode;
  timings: ProbeTimings;
  ip?: string;
  error?: string;
  checkedAt: number;
}

export type ReachVerdict = 'ok' | 'gfw_blocked' | 'cn_only' | 'partial' | 'timeout' | 'refused' | 'dns_error' | 'tls_error' | 'error';

export interface ReachCheckSummary {
  target: string;
  port: number;
  protocol: 'TCP' | 'HTTP' | 'HTTPS' | 'PING';
  verdict: ReachVerdict;
  verdictLabel: string;
  verdictDescription: string;
  advice: string[];
  results: RegionResult[];
  browserResult?: RegionResult;
  stats: {
    total: number;
    success: number;
    failed: number;
    cnSuccess: number;
    cnTotal: number;
    cnAverageMs: number | null;
    globalAverageMs: number | null;
    minLatencyMs: number | null;
    maxLatencyMs: number | null;
    cnTelecomMs?: number | null;
    cnUnicomMs?: number | null;
    cnMobileMs?: number | null;
  };
  checkedAt: number;
}

/**
 * Security audit: detect RFC 1918, CGNAT, loopback, link-local, multicast and bogon IPs to prevent SSRF.
 */
export function isPrivateOrBogonIP(host: string): boolean {
  const trimmed = host.trim().toLowerCase();
  if (trimmed === 'localhost' || trimmed === '127.0.0.1' || trimmed === '::1' || trimmed === '0.0.0.0') return true;
  const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const a = Number(ipv4Match[1]);
    const b = Number(ipv4Match[2]);
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 127) return true; // 127.0.0.0/8
    if (a === 169 && b === 254) return true; // 169.254.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a >= 224) return true; // Multicast / Reserved
    if (a === 0) return true;
  }
  if (trimmed.startsWith('fc') || trimmed.startsWith('fd') || trimmed.startsWith('fe80') || trimmed === '::') return true;
  return false;
}

/**
 * WHATWG Fetch restricted ports: browsers block fetch() to these ports for security.
 */
export function isRestrictedBrowserPort(port: number): boolean {
  const BAD_PORTS = new Set([
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 77, 79, 87, 95, 101, 102, 103, 104,
    109, 110, 111, 113, 115, 117, 119, 123, 135, 139, 143, 179, 389, 445, 465, 512, 513, 514, 515, 526,
    530, 531, 532, 540, 556, 563, 587, 601, 636, 993, 995, 2049, 3659, 4045, 6000
  ]);
  return BAD_PORTS.has(port);
}

export function validateTarget(host: string, port: number): { valid: boolean; error?: string } {
  const cleanHost = host.trim();
  if (!cleanHost) return { valid: false, error: '请输入检测目标主机名或 IP 地址' };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { valid: false, error: '端口范围必须在 1 到 65535 之间' };
  if (!/^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$/.test(cleanHost) && !cleanHost.includes(':')) {
    return { valid: false, error: '目标主机名或 IP 地址格式无效' };
  }
  if (isPrivateOrBogonIP(cleanHost)) {
    return { valid: false, error: '禁止向外部探针发送私有或局域网保留 IP（SSRF 防御）' };
  }
  return { valid: true };
}

/**
 * Diagnostic logic: classify failures into actionable verdicts.
 */
export function diagnoseReachability(results: RegionResult[]): {
  verdict: ReachVerdict;
  label: string;
  desc: string;
  advice: string[];
} {
  const validResults = results.filter(r => r.status !== 'skipped');
  const total = validResults.length;
  if (total === 0) {
    return {
      verdict: 'error',
      label: '暂无有效检测结果',
      desc: '未能获取到任何节点的有效检测数据。',
      advice: ['请检查网络连接或稍后重试。']
    };
  }

  const okResults = validResults.filter(r => r.status === 'ok');
  const cnResults = validResults.filter(r => r.region.group === 'cn');
  const overseasResults = validResults.filter(r => r.region.group !== 'cn');
  const cnOk = cnResults.filter(r => r.status === 'ok');
  const overseasOk = overseasResults.filter(r => r.status === 'ok');

  if (okResults.length === total) {
    return {
      verdict: 'ok',
      label: '三网通畅 · 全球可达',
      desc: `全部 ${total} 个检测节点（含中国电信、联通、移动三大运营商）均成功连接。`,
      advice: ['服务在全球各主要区域及国内三大运营商均处于良好可达状态，无需额外调整。']
    };
  }

  if (overseasOk.length >= Math.max(1, Math.floor(overseasResults.length * 0.6)) && cnOk.length === 0) {
    return {
      verdict: 'gfw_blocked',
      label: '疑似 GFW 阻断 · 国内异常',
      desc: '海外节点多数可正常连通，但中国电信、联通、移动三大运营商均连接超时或阻断。',
      advice: [
        '检查目标端口是否被墙：可尝试在母机或容器上更换监听端口进行测试。',
        '检查域名是否遭遇 DNS 污染或 SNI 阻断：通过不同网络 nslookup 校验解析是否一致。',
        '建议为该服务前置 CDN（如 Cloudflare）或国内合规反代/隧道中转。'
      ]
    };
  }

  if (cnOk.length > 0 && overseasOk.length === 0) {
    return {
      verdict: 'cn_only',
      label: '仅国内可达 · 海外受阻',
      desc: '国内运营商可正常连接，但海外国际节点全部超时或阻断。',
      advice: [
        '检查 VPS 机房或云服务商是否开启了海外流量黑洞或安全组海外阻断。',
        '核对 DNS 是否配置了按地域智能解析。'
      ]
    };
  }

  if (okResults.length === 0) {
    const allRefused = validResults.every(r => r.status === 'refused');
    const allDns = validResults.every(r => r.status === 'dns_error');
    if (allDns) {
      return {
        verdict: 'dns_error',
        label: '域名解析失败',
        desc: '所有节点均无法解析目标域名。',
        advice: [
          '检查域名的权威 DNS 解析配置，确保 A/AAAA 记录已正确指向服务器 IP。',
          '若刚修改解析，请等待全球 DNS 缓存同步（通常需要 5-15 分钟）。'
        ]
      };
    }
    if (allRefused) {
      return {
        verdict: 'refused',
        label: '目标端口拒绝连接 (Connection Refused)',
        desc: '所有探针均收到 RST 拒绝包，表明主机网络通畅但无服务在目标端口监听。',
        advice: [
          '检查服务进程是否已正常运行（如 `systemctl status` 或 `podman/docker ps`）。',
          '确认服务监听地址为 `0.0.0.0` 或 `::`，而非仅限本地 `127.0.0.1`。',
          '核对反向代理（如 Caddy/Nginx）的端口转发配置是否与后端匹配。'
        ]
      };
    }
    return {
      verdict: 'timeout',
      label: '全网连接超时',
      desc: '所有探针均无法在限时内完成 TCP 握手。',
      advice: [
        '检查云平台安全组（Security Group）是否已放行该入站端口。',
        '检查宿主机内部防火墙（如 `ufw`, `iptables`, `nftables`）的规则。',
        '确认母机网络是否在线，网关与默认路由是否正常。'
      ]
    };
  }

  return {
    verdict: 'partial',
    label: '部分区域受阻',
    desc: `${okResults.length}/${total} 个区域可达，部分运营商或地区连接异常。`,
    advice: [
      '排查异常节点所属运营商的国际出口链路是否有丢包或高峰期网络拥塞。',
      '检查服务器是否配置了基于 GeoIP 的访客过滤或防火墙限速。'
    ]
  };
}

/**
 * Local Browser direct probe using fetch() and performance.now()
 */
export async function probeFromBrowser(host: string, port: number, protocol: 'HTTP' | 'HTTPS' | 'TCP'): Promise<RegionResult> {
  const browserRegion: ReachRegion = {
    id: 'browser-local',
    group: 'cn',
    name: '访客本地浏览器 (Your Browser)',
    flag: '🌐',
    country: 'Local',
    loc: {}
  };

  if (isRestrictedBrowserPort(port)) {
    return {
      region: browserRegion,
      status: 'skipped',
      timings: { total: 0 },
      error: '浏览器安全限制端口（跳过本地，由外部探针检测）',
      checkedAt: Date.now()
    };
  }

  const proto = protocol === 'HTTPS' ? 'https' : 'http';
  const url = `${proto}://${host}:${port}/favicon.ico?_rc=${Date.now()}`;
  const t0 = performance.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    await fetch(url, {
      mode: 'no-cors',
      cache: 'no-store',
      credentials: 'omit',
      signal: controller.signal
    });
    const duration = Math.round(performance.now() - t0);
    return {
      region: browserRegion,
      status: 'ok',
      timings: { total: duration, ttfb: duration },
      checkedAt: Date.now()
    };
  } catch (err: any) {
    const duration = Math.round(performance.now() - t0);
    if (err?.name === 'AbortError') {
      return {
        region: browserRegion,
        status: 'timeout',
        timings: { total: 8000 },
        error: '本地连接超时 (8s)',
        checkedAt: Date.now()
      };
    }
    return {
      region: browserRegion,
      status: 'refused',
      timings: { total: duration },
      error: '无法建立连接 (Connection failed)',
      checkedAt: Date.now()
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Execute 18-region reachability check via Globalping API
 */
export async function executeReachCheck(
  host: string,
  port: number,
  protocol: 'TCP' | 'HTTP' | 'HTTPS' = 'TCP',
  onProgress?: (results: RegionResult[], finished: number, total: number) => void
): Promise<ReachCheckSummary> {
  const val = validateTarget(host, port);
  if (!val.valid) throw new Error(val.error);

  const initialResults: RegionResult[] = REACH_REGIONS.map(reg => ({
    region: reg,
    status: 'testing',
    timings: { total: 0 },
    checkedAt: Date.now()
  }));

  if (onProgress) onProgress(initialResults, 0, REACH_REGIONS.length);

  // Dispatch browser probe in parallel
  const browserPromise = probeFromBrowser(host, port, protocol);

  const gpEndpoint = 'https://api.globalping.io/v1';
  // Globalping API requires type in ['ping', 'traceroute', 'dns', 'mtr', 'http'].
  // For TCP connect timings on any port, type 'http' tests TCP handshake latency.
  const measurementType = 'http';

  const locationsPayload = REACH_REGIONS.map(r => ({
    ...r.loc,
    limit: 1
  }));

  const measurementBody: Record<string, any> = {
    type: measurementType,
    target: host,
    inProgressUpdates: true,
    locations: locationsPayload,
    measurementOptions: {
      port: port,
      protocol: protocol === 'HTTPS' ? 'HTTPS' : 'HTTP',
    }
  };

  let measurementId = '';
  const storedApiKey = (typeof window !== 'undefined' ? localStorage.getItem('narwhal_globalping_key') || '' : '').trim();
  const requestHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
  if (storedApiKey) {
    requestHeaders['Authorization'] = `Bearer ${storedApiKey}`;
  }

  try {
    const postRes = await fetch(`${gpEndpoint}/measurements`, {
      method: 'POST',
      headers: requestHeaders,
      body: JSON.stringify(measurementBody)
    });

    if (!postRes.ok) {
      if (postRes.status === 429) {
        throw new Error('探针配额受限 (HTTP 429)：公共免费额度已耗尽，请稍候再试或配置 Globalping API Key。');
      }
      const errText = await postRes.text().catch(() => '');
      throw new Error(`Globalping API 响应异常 (${postRes.status}): ${errText.slice(0, 100)}`);
    }

    const postData = await postRes.json();
    measurementId = postData.id;
  } catch (err: any) {
    // If Globalping API fails, fallback gracefully
    const fallbackResults: RegionResult[] = REACH_REGIONS.map(r => ({
      region: r,
      status: 'error',
      timings: { total: 0 },
      error: err.message || '公共探针接口请求失败',
      checkedAt: Date.now()
    }));
    const browserResult = await browserPromise;
    return {
      target: host,
      port,
      protocol,
      verdict: 'error',
      verdictLabel: '探针接口异常',
      verdictDescription: err.message || '无法连接到公共探测节点网络',
      advice: ['请检查本地网络或稍后再试。'],
      results: fallbackResults,
      browserResult,
      stats: { total: 18, success: 0, failed: 18, cnSuccess: 0, cnTotal: 3, cnAverageMs: null, globalAverageMs: null, minLatencyMs: null, maxLatencyMs: null },
      checkedAt: Date.now()
    };
  }

  // Poll for measurement completion
  const resultMap = new Map<string, RegionResult>(initialResults.map(r => [r.region.id, r]));
  let finishedCount = 0;
  const maxPolls = 30; // 30 seconds max

  for (let poll = 0; poll < maxPolls; poll++) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      const pollRes = await fetch(`${gpEndpoint}/measurements/${measurementId}`, {
        headers: storedApiKey ? { 'Authorization': `Bearer ${storedApiKey}` } : {},
      });
      if (!pollRes.ok) continue;
      const mData = await pollRes.json();
      const rawResults = mData.results || [];

      // Match raw results back to REACH_REGIONS
      const matched = new Set<string>();
      for (const resItem of rawResults) {
        const probe = resItem.probe || {};
        const probeResult = resItem.result || {};

        // Find best match in REACH_REGIONS
        let targetRegion = REACH_REGIONS.find(r => {
          if (matched.has(r.id)) return false;
          if (r.carrier && probe.asn === r.carrier) return true;
          if (r.asn && probe.asn === r.asn) return true;
          if (r.city && probe.city && probe.city.toLowerCase().includes(r.city.toLowerCase())) return true;
          if (r.country && probe.country === r.country) return true;
          return false;
        });

        if (!targetRegion) {
          targetRegion = REACH_REGIONS.find(r => !matched.has(r.id));
        }

        if (targetRegion) {
          matched.add(targetRegion.id);
          const rawStatus = probeResult.status || '';
          let statusCode: ProbeStatusCode = 'error';
          let totalMs = 0;
          let dnsMs: number | undefined;
          let tcpMs: number | undefined;
          let tlsMs: number | undefined;
          let ttfbMs: number | undefined;

          if (rawStatus === 'finished' || rawStatus === 'success') {
            statusCode = 'ok';
            const timings = probeResult.timings || {};
            totalMs = Math.round(probeResult.totalTime || timings.total || probeResult.latency || 0);
            dnsMs = timings.dns ? Math.round(timings.dns) : undefined;
            tcpMs = timings.tcp ? Math.round(timings.tcp) : undefined;
            tlsMs = timings.tls ? Math.round(timings.tls) : undefined;
            ttfbMs = timings.firstByte ? Math.round(timings.firstByte) : undefined;
          } else if (rawStatus === 'timeout' || String(probeResult.rawOutput || '').toLowerCase().includes('timeout')) {
            statusCode = 'timeout';
          } else if (String(probeResult.rawOutput || '').toLowerCase().includes('refused')) {
            statusCode = 'refused';
          } else if (String(probeResult.rawOutput || '').toLowerCase().includes('dns')) {
            statusCode = 'dns_error';
          } else if (String(probeResult.rawOutput || '').toLowerCase().includes('tls') || String(probeResult.rawOutput || '').toLowerCase().includes('certificate')) {
            statusCode = 'tls_error';
          } else {
            statusCode = rawStatus === 'failed' ? 'error' : 'timeout';
          }

          resultMap.set(targetRegion.id, {
            region: targetRegion,
            status: statusCode,
            timings: { total: totalMs, dns: dnsMs, tcp: tcpMs, tls: tlsMs, ttfb: ttfbMs },
            ip: probeResult.resolvedAddress || probe.ip,
            error: statusCode !== 'ok' ? (probeResult.rawOutput || rawStatus || '连接失败') : undefined,
            checkedAt: Date.now()
          });
        }
      }

      finishedCount = Array.from(resultMap.values()).filter(r => r.status !== 'testing').length;
      if (onProgress) {
        onProgress(Array.from(resultMap.values()), finishedCount, REACH_REGIONS.length);
      }

      if (mData.status === 'finished' || finishedCount >= REACH_REGIONS.length) {
        break;
      }
    } catch {
      // Continue polling on transient fetch failure
    }
  }

  // Any remaining 'testing' nodes become timeout
  for (const [id, res] of resultMap.entries()) {
    if (res.status === 'testing') {
      resultMap.set(id, {
        ...res,
        status: 'timeout',
        error: '探测请求超时无回包',
        checkedAt: Date.now()
      });
    }
  }

  const finalResults = Array.from(resultMap.values());
  const browserResult = await browserPromise;
  const diagnosis = diagnoseReachability(finalResults);

  // Calculate statistics
  const okList = finalResults.filter(r => r.status === 'ok');
  const cnOkList = finalResults.filter(r => r.region.group === 'cn' && r.status === 'ok');
  const latencies = okList.map(r => r.timings.total).filter(t => t > 0);
  const cnLatencies = cnOkList.map(r => r.timings.total).filter(t => t > 0);

  const stats = {
    total: finalResults.length,
    success: okList.length,
    failed: finalResults.length - okList.length,
    cnSuccess: cnOkList.length,
    cnTotal: 3,
    cnAverageMs: cnLatencies.length > 0 ? Math.round(cnLatencies.reduce((a, b) => a + b, 0) / cnLatencies.length) : null,
    globalAverageMs: latencies.length > 0 ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null,
    minLatencyMs: latencies.length > 0 ? Math.min(...latencies) : null,
    maxLatencyMs: latencies.length > 0 ? Math.max(...latencies) : null
  };

  const summary: ReachCheckSummary = {
    target: host,
    port,
    protocol,
    verdict: diagnosis.verdict,
    verdictLabel: diagnosis.label,
    verdictDescription: diagnosis.desc,
    advice: diagnosis.advice,
    results: finalResults,
    browserResult,
    stats,
    checkedAt: Date.now()
  };

  // Cache in sessionStorage
  try {
    sessionStorage.setItem(`reach:${host}:${port}`, JSON.stringify(summary));
  } catch {}

  return summary;
}
