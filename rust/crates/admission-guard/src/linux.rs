use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use net_guard::{json_val_to_string, CommandRunner, LiveCommandRunner};
use runtime_drivers::JsonVal;
use transport::sha256_hex;

use crate::observe::is_valid_ifname;
use crate::policy::{is_non_business_ipv4, is_non_business_ipv6};
use crate::AdmissionError;

const MAX_NFT_STDOUT_BYTES: usize = 2 * 1024 * 1024;

pub fn is_valid_table_name(table: &str) -> bool {
    let Some(hex) = table.strip_prefix("nwguard_") else {
        return false;
    };
    hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_safe_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !is_non_business_ipv4(v4),
        IpAddr::V6(v6) => !is_non_business_ipv6(v6),
    }
}

/// Pure-Rust IPv4 (no fragments, valid IHL) and IPv6 (hop-by-hop/routing/dstopt
/// extension headers up to 8 hops) TCP/UDP packet parser.
/// Returns `(src_ip, dst_ip, proto, sport, dport)`.
pub fn packet(raw: &[u8]) -> Result<(String, String, u8, u16, u16), AdmissionError> {
    if raw.is_empty() {
        return Err(AdmissionError::Value("empty packet".to_string()));
    }
    let version = raw[0] >> 4;
    let (src, dst, offset, proto) = if version == 4 && raw.len() >= 20 {
        let ihl_bytes = ((raw[0] & 0x0f) as usize) * 4;
        let proto = raw[9];
        let frag_field = u16::from_be_bytes([raw[6], raw[7]]);
        if ihl_bytes < 20 || (frag_field & 0x1fff) != 0 {
            return Err(AdmissionError::Value(
                "fragment or invalid header".to_string(),
            ));
        }
        let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]).to_string();
        let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]).to_string();
        (src_ip, dst_ip, ihl_bytes, proto)
    } else if version == 6 && raw.len() >= 40 {
        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&raw[8..24]);
        dst_bytes.copy_from_slice(&raw[24..40]);
        let src_ip = Ipv6Addr::from(src_bytes).to_string();
        let dst_ip = Ipv6Addr::from(dst_bytes).to_string();
        let mut offset = 40usize;
        let mut proto = raw[6];
        for _ in 0..8 {
            if proto == 6 || proto == 17 {
                break;
            }
            if !matches!(proto, 0 | 43 | 60) || raw.len() < offset + 2 {
                return Err(AdmissionError::Value("unsupported extension".to_string()));
            }
            let nxt = raw[offset];
            let length = ((raw[offset + 1] as usize) + 1) * 8;
            offset += length;
            proto = nxt;
        }
        (src_ip, dst_ip, offset, proto)
    } else {
        return Err(AdmissionError::Value("invalid IP header".to_string()));
    };

    if (proto != 6 && proto != 17) || raw.len() < offset + 4 {
        return Err(AdmissionError::Value("invalid transport".to_string()));
    }
    let sport = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    let dport = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
    Ok((src, dst, proto, sport, dport))
}

fn source_ips_by_family(sources: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for item in sources {
        let Ok(addr) = item.trim().parse::<IpAddr>() else {
            continue;
        };
        if !is_safe_unicast(addr) {
            continue;
        }
        let s = addr.to_string();
        match addr {
            IpAddr::V4(_) => {
                if !v4.contains(&s) {
                    v4.push(s);
                }
            }
            IpAddr::V6(_) => {
                if !v6.contains(&s) {
                    v6.push(s);
                }
            }
        }
    }
    (v4, v6)
}

#[allow(clippy::too_many_arguments)]
pub fn rules(
    table: &str,
    ips: &[String],
    queue: u16,
    sources: &[String],
    limited: bool,
    management_ports: &[u16],
    interfaces: &[String],
    source_limit: usize,
    source_idle: u64,
    listening_ports: &[u16],
) -> Result<String, AdmissionError> {
    if !is_valid_table_name(table) || !(20000..60000).contains(&queue) || queue % 2 != 0 {
        return Err(AdmissionError::Value("invalid rule identity".to_string()));
    }
    let mut by_v4 = Vec::new();
    let mut by_v6 = Vec::new();
    for value in ips {
        let addr: IpAddr = value
            .trim()
            .parse()
            .map_err(|_| AdmissionError::Value("invalid container address".to_string()))?;
        if !is_safe_unicast(addr) {
            return Err(AdmissionError::Value(
                "unsafe container address".to_string(),
            ));
        }
        match addr {
            IpAddr::V4(v4) => by_v4.push(v4.to_string()),
            IpAddr::V6(v6) => by_v6.push(v6.to_string()),
        }
    }
    if (by_v4.is_empty() && by_v6.is_empty()) || ips.len() > 32 {
        return Err(AdmissionError::Value(
            "container addresses unavailable".to_string(),
        ));
    }
    if interfaces.is_empty()
        || interfaces.len() > 8
        || interfaces.iter().any(|x| !is_valid_ifname(x))
    {
        return Err(AdmissionError::Value(
            "verified private veth required".to_string(),
        ));
    }
    if source_limit > 64 || !(30..=3600).contains(&source_idle) {
        return Err(AdmissionError::Value("invalid source limit".to_string()));
    }

    let quoted_devs: Vec<String> = interfaces.iter().map(|x| format!("\"{x}\"")).collect();
    let devices = format!("{{ {} }}", quoted_devs.join(", "));
    let mut lines = vec![format!("add table inet {table}")];

    if source_limit > 0 {
        for (family, kind) in [(4u8, "ipv4_addr"), (6u8, "ipv6_addr")] {
            lines.push(format!(
                "add set inet {table} sources{family} {{ type {kind}; flags dynamic,timeout; timeout {source_idle}s; size 256; }}"
            ));
        }
        let (src4, src6) = source_ips_by_family(sources);
        for (family, values) in [(4u8, src4), (6u8, src6)] {
            if !values.is_empty() {
                let take_vals: Vec<String> = values.into_iter().take(source_limit).collect();
                lines.push(format!(
                    "add element inet {table} sources{family} {{ {} }}",
                    take_vals.join(", ")
                ));
            }
        }
    }

    lines.push(format!("add chain inet {table} incoming"));
    lines.push(format!("add chain inet {table} outgoing"));
    lines.push(format!(
        "add chain inet {table} forward {{ type filter hook forward priority -20; policy accept; }}"
    ));

    for (family, values) in [(4u8, &by_v4), (6u8, &by_v6)] {
        if values.is_empty() {
            continue;
        }
        let kind = if family == 4 { "ip" } else { "ip6" };
        let joined = values.join(", ");
        lines.push(format!(
            "add rule inet {table} forward oifname {devices} {kind} daddr {{ {joined} }} ct direction original meta l4proto {{ tcp, udp }} jump incoming"
        ));
        if limited {
            lines.push(format!(
                "add rule inet {table} forward iifname {devices} {kind} saddr {{ {joined} }} ct direction original meta l4proto tcp ct state new jump outgoing"
            ));
        }
    }

    let mut ports: Vec<u16> = management_ports.iter().copied().collect();
    ports.sort_unstable();
    ports.dedup();
    if !ports.is_empty() {
        if ports.len() > 8 || ports.contains(&0) {
            return Err(AdmissionError::Value(
                "invalid management ports".to_string(),
            ));
        }
        let ports_str: Vec<String> = ports.iter().map(u16::to_string).collect();
        lines.push(format!(
            "add rule inet {table} incoming meta l4proto tcp tcp dport {{ {} }} return",
            ports_str.join(", ")
        ));
    }

    let mut valid_listen: Vec<u16> = listening_ports
        .iter()
        .copied()
        .filter(|&p| p > 0)
        .collect();
    valid_listen.sort_unstable();
    valid_listen.dedup();
    if valid_listen.len() > 64 {
        valid_listen.truncate(64);
    }
    if source_limit > 0 && !valid_listen.is_empty() {
        let listen_str: Vec<String> = valid_listen.iter().map(u16::to_string).collect();
        lines.push(format!(
            "add rule inet {table} incoming meta l4proto tcp tcp dport != {{ {} }} return",
            listen_str.join(", ")
        ));
    }

    if source_limit > 0 {
        for family in [4u8, 6u8] {
            let kind = if family == 4 { "ip" } else { "ip6" };
            lines.push(format!(
                "add rule inet {table} incoming {kind} saddr @sources{family} update @sources{family} {{ {kind} saddr timeout {source_idle}s }}"
            ));
        }
        lines.push(format!(
            "add rule inet {table} incoming meta l4proto tcp ct bytes < 4096 ct state established queue num {queue} bypass"
        ));
        lines.push(format!(
            "add rule inet {table} incoming meta l4proto udp ct bytes < 2048 ct state new queue num {queue} bypass"
        ));
        lines.push(format!(
            "add rule inet {table} incoming ct state != new return"
        ));
    }

    if limited {
        lines.push(format!(
            "add rule inet {table} incoming meta l4proto tcp ct state new queue num {queue}"
        ));
        lines.push(format!(
            "add rule inet {table} outgoing meta l4proto tcp ct state new queue num {}",
            queue + 1
        ));
    }

    if source_limit > 0 {
        for family in [4u8, 6u8] {
            let kind = if family == 4 { "ip" } else { "ip6" };
            lines.push(format!(
                "add rule inet {table} incoming {kind} saddr @sources{family} return"
            ));
        }
        lines.push(format!(
            "add rule inet {table} incoming ct state new queue num {queue} bypass"
        ));
    }

    lines.push(format!("add rule inet {table} incoming return"));
    lines.push(format!("add rule inet {table} outgoing return"));
    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out)
}

pub trait NftRunner: Send {
    fn run(&mut self, args: &[String], data: Option<&str>) -> Result<String, AdmissionError>;
}

pub struct LiveNftRunner<C: CommandRunner = LiveCommandRunner> {
    pub inner: C,
}

impl Default for LiveNftRunner<LiveCommandRunner> {
    fn default() -> Self {
        Self {
            inner: LiveCommandRunner,
        }
    }
}

impl<C: CommandRunner + Send> LiveNftRunner<C> {
    pub fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C: CommandRunner + Send> NftRunner for LiveNftRunner<C> {
    fn run(&mut self, args: &[String], data: Option<&str>) -> Result<String, AdmissionError> {
        let prog = args.first().map(String::as_str).unwrap_or("nft");
        let (ok, output) = self.inner.run(args, data);
        if !ok || output.len() > MAX_NFT_STDOUT_BYTES {
            return Err(AdmissionError::Runtime(format!(
                "local admission command failed: {prog}"
            )));
        }
        Ok(output)
    }
}

pub struct ClosureNftRunner<F>(pub F);

impl<F> NftRunner for ClosureNftRunner<F>
where
    F: FnMut(&[String], Option<&str>) -> Result<String, AdmissionError> + Send,
{
    fn run(&mut self, args: &[String], data: Option<&str>) -> Result<String, AdmissionError> {
        (self.0)(args, data)
    }
}

pub fn stabilize_nft_item(item: &JsonVal) -> JsonVal {
    match item {
        JsonVal::Arr(arr) => JsonVal::Arr(arr.iter().map(stabilize_nft_item).collect()),
        JsonVal::Obj(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                if k == "handle" || k == "index" {
                    continue;
                }
                if k == "counter" {
                    out.insert(k.clone(), JsonVal::Obj(BTreeMap::new()));
                } else {
                    out.insert(k.clone(), stabilize_nft_item(v));
                }
            }
            JsonVal::Obj(out)
        }
        other => other.clone(),
    }
}

pub struct Nft<R: NftRunner = LiveNftRunner> {
    pub runner: R,
    pub digests: BTreeMap<String, String>,
}

impl Default for Nft<LiveNftRunner> {
    fn default() -> Self {
        Self::new(LiveNftRunner::default())
    }
}

impl<R: NftRunner> Nft<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            digests: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply(
        &mut self,
        table: &str,
        ips: &[String],
        queue: u16,
        sources: &[String],
        limited: bool,
        management_ports: &[u16],
        interfaces: &[String],
        source_limit: usize,
        source_idle: u64,
        listening_ports: &[u16],
    ) -> Result<(), AdmissionError> {
        let mut text = rules(
            table,
            ips,
            queue,
            sources,
            limited,
            management_ports,
            interfaces,
            source_limit,
            source_idle,
            listening_ports,
        )?;
        let list_cmd = vec![
            "nft".to_string(),
            "list".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table.to_string(),
        ];
        if self.runner.run(&list_cmd, None).is_ok() {
            text = format!("delete table inet {table}\n{text}");
        }
        let check_cmd = vec![
            "nft".to_string(),
            "--check".to_string(),
            "-f".to_string(),
            "-".to_string(),
        ];
        self.runner.run(&check_cmd, Some(&text))?;
        let apply_cmd = vec!["nft".to_string(), "-f".to_string(), "-".to_string()];
        self.runner.run(&apply_cmd, Some(&text))?;
        Ok(())
    }

    pub fn admit(&mut self, table: &str, source: &str) -> Result<(), AdmissionError> {
        let parsed: IpAddr = source
            .trim()
            .parse()
            .map_err(|_| AdmissionError::Value(format!("invalid source IP: {source}")))?;
        let version = match parsed {
            IpAddr::V4(_) => "4",
            IpAddr::V6(_) => "6",
        };
        let cmd = vec![
            "nft".to_string(),
            "add".to_string(),
            "element".to_string(),
            "inet".to_string(),
            table.to_string(),
            format!("sources{version}"),
            "{".to_string(),
            parsed.to_string(),
            "}".to_string(),
        ];
        self.runner.run(&cmd, None)?;
        Ok(())
    }

    pub fn live(&mut self, table: &str) -> Result<BTreeSet<String>, AdmissionError> {
        let cmd = vec![
            "nft".to_string(),
            "-j".to_string(),
            "list".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table.to_string(),
        ];
        let raw = self.runner.run(&cmd, None)?;
        let value = JsonVal::parse(&raw)
            .map_err(|_| AdmissionError::Value("invalid nftables JSON output".to_string()))?;
        let nftables = value
            .get("nftables")
            .and_then(JsonVal::as_arr)
            .unwrap_or(&[]);

        let mut definition = Vec::new();
        for item in nftables {
            if item.get("metainfo").is_some() {
                continue;
            }
            let mut stabilized = stabilize_nft_item(item);
            if let JsonVal::Obj(ref mut map) = stabilized {
                if let Some(JsonVal::Obj(ref mut set_map)) = map.get_mut("set") {
                    set_map.remove("elem");
                }
            }
            definition.push(stabilized);
        }

        let def_json = json_val_to_string(&JsonVal::Arr(definition), false);
        let digest = sha256_hex(def_json.as_bytes());
        self.digests.insert(table.to_string(), digest);

        let mut result = BTreeSet::new();
        for item in nftables {
            let Some(entry) = item.get("set") else {
                continue;
            };
            if !matches!(entry.get_str("name"), Some("sources4" | "sources6")) {
                continue;
            }
            if let Some(elems) = entry.get("elem").and_then(JsonVal::as_arr) {
                for elem in elems {
                    let val_opt = elem
                        .as_str()
                        .or_else(|| elem.get("elem").and_then(|e| e.get_str("val")));
                    if let Some(val_str) = val_opt {
                        if let Ok(ip) = val_str.parse::<IpAddr>() {
                            result.insert(ip.to_string());
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn remove(&mut self, table: &str) -> Result<(), AdmissionError> {
        if !is_valid_table_name(table) {
            return Err(AdmissionError::Value("invalid table".to_string()));
        }
        let del_cmd = vec![
            "nft".to_string(),
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table.to_string(),
        ];
        if let Err(err) = self.runner.run(&del_cmd, None) {
            let list_cmd = vec![
                "nft".to_string(),
                "-j".to_string(),
                "list".to_string(),
                "tables".to_string(),
            ];
            let raw = self.runner.run(&list_cmd, None)?;
            let parsed = JsonVal::parse(&raw)
                .map_err(|_| AdmissionError::Value("invalid nft tables JSON".to_string()))?;
            let still_exists = parsed
                .get("nftables")
                .and_then(JsonVal::as_arr)
                .is_some_and(|arr| {
                    arr.iter().any(|x| {
                        let t = x.get("table");
                        t.and_then(|tb| tb.get_str("family")) == Some("inet")
                            && t.and_then(|tb| tb.get_str("name")) == Some(table)
                    })
                });
            if still_exists {
                return Err(err);
            }
        }
        Ok(())
    }
}

pub trait QueueBackend: Send {
    fn add(&mut self, number: u16) -> Result<(), AdmissionError>;
    fn remove(&mut self, number: u16) -> Result<(), AdmissionError>;
    fn healthy(&self) -> bool;
    fn close(&mut self);
}

#[derive(Debug, Default)]
pub struct NoopQueueBackend {
    pub active_queues: BTreeSet<u16>,
    pub closed: bool,
}

impl NoopQueueBackend {
    pub fn new() -> Self {
        Self {
            active_queues: BTreeSet::new(),
            closed: false,
        }
    }
}

impl QueueBackend for NoopQueueBackend {
    fn add(&mut self, number: u16) -> Result<(), AdmissionError> {
        if self.closed {
            return Err(AdmissionError::Runtime("queue backend closed".to_string()));
        }
        self.active_queues.insert(number);
        Ok(())
    }

    fn remove(&mut self, number: u16) -> Result<(), AdmissionError> {
        self.active_queues.remove(&number);
        Ok(())
    }

    fn healthy(&self) -> bool {
        !self.closed
    }

    fn close(&mut self) {
        self.closed = true;
        self.active_queues.clear();
    }
}

#[cfg(unix)]
const NFQ_PYTHON_WORKER: &str = r#"import ctypes as C, ctypes.util, os, select, socket, struct, sys

libname = ctypes.util.find_library('netfilter_queue')
if not libname:
    sys.stdout.write('ERR libnetfilter_queue is unavailable\n')
    sys.stdout.flush()
    sys.exit(1)

lib = C.CDLL(libname)
defs = {
    'nfq_open': ([], C.c_void_p),
    'nfq_fd': ([C.c_void_p], C.c_int),
    'nfq_bind_pf': ([C.c_void_p, C.c_uint16], C.c_int),
    'nfq_set_mode': ([C.c_void_p, C.c_uint8, C.c_uint32], C.c_int),
    'nfq_set_queue_maxlen': ([C.c_void_p, C.c_uint32], C.c_int),
    'nfq_handle_packet': ([C.c_void_p, C.c_void_p, C.c_int], C.c_int),
    'nfq_get_msg_packet_hdr': ([C.c_void_p], C.c_void_p),
    'nfq_get_payload': ([C.c_void_p, C.POINTER(C.c_void_p)], C.c_int),
    'nfq_set_verdict': ([C.c_void_p, C.c_uint32, C.c_uint32, C.c_uint32, C.c_void_p], C.c_int),
    'nfq_destroy_queue': ([C.c_void_p], C.c_int),
    'nfq_close': ([C.c_void_p], C.c_int),
}
for name, (args, res) in defs.items():
    fn = getattr(lib, name)
    fn.argtypes = args
    fn.restype = res

CB = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
lib.nfq_create_queue.argtypes = [C.c_void_p, C.c_uint16, CB, C.c_void_p]
lib.nfq_create_queue.restype = C.c_void_p

handle = lib.nfq_open()
if not handle:
    sys.stdout.write('ERR NFQUEUE handle unavailable\n')
    sys.stdout.flush()
    sys.exit(1)

for fam in (socket.AF_INET, socket.AF_INET6):
    if lib.nfq_bind_pf(handle, fam) < 0:
        lib.nfq_close(handle)
        sys.stdout.write('ERR NFQUEUE protocol binding unavailable\n')
        sys.stdout.flush()
        sys.exit(1)

fd = lib.nfq_fd(handle)
stdin_fd = sys.stdin.fileno()
handles = {}
deferred_cmds = []
stopped = False

def callback(qh, msg, data, ctx):
    global stopped
    hdr = lib.nfq_get_msg_packet_hdr(data)
    if not hdr:
        return 0
    pkt_id = struct.unpack('!I', C.string_at(hdr, 4))[0]
    ptr = C.c_void_p()
    length = lib.nfq_get_payload(data, C.byref(ptr))
    qnum = int(ctx or 0)
    accepted = 0
    if length > 0:
        raw_hex = C.string_at(ptr, min(length, 2048)).hex()
        sys.stdout.write(f'P {qnum} {pkt_id} {raw_hex}\n')
        sys.stdout.flush()
        while True:
            line = sys.stdin.readline()
            if not line:
                stopped = True
                break
            parts = line.strip().split()
            if len(parts) == 3 and parts[0] == 'V' and int(parts[1]) == pkt_id:
                accepted = 1 if parts[2] == '1' else 0
                break
            else:
                deferred_cmds.append(parts)
    if lib.nfq_set_verdict(qh, pkt_id, accepted, 0, None) < 0:
        stopped = True
    return 0

cb_ref = CB(callback)

def run_cmd(parts):
    global stopped
    if not parts:
        return
    op = parts[0]
    if op == 'A' and len(parts) == 2:
        qnum = int(parts[1])
        if qnum in handles:
            sys.stdout.write('OK\n')
            sys.stdout.flush()
            return
        qh = lib.nfq_create_queue(handle, qnum, cb_ref, C.c_void_p(qnum))
        if not qh:
            sys.stdout.write('ERR admission queue number already in use\n')
            sys.stdout.flush()
            return
        if lib.nfq_set_mode(qh, 2, 2048) < 0 or lib.nfq_set_queue_maxlen(qh, 1024) < 0:
            lib.nfq_destroy_queue(qh)
            sys.stdout.write('ERR admission queue configuration unavailable\n')
            sys.stdout.flush()
            return
        handles[qnum] = qh
        sys.stdout.write('OK\n')
        sys.stdout.flush()
    elif op == 'R' and len(parts) == 2:
        qnum = int(parts[1])
        qh = handles.pop(qnum, None)
        if qh:
            lib.nfq_destroy_queue(qh)
        sys.stdout.write('OK\n')
        sys.stdout.flush()
    elif op == 'Q':
        stopped = True
        sys.stdout.write('OK\n')
        sys.stdout.flush()

sys.stdout.write('READY\n')
sys.stdout.flush()

try:
    while not stopped:
        while deferred_cmds and not stopped:
            run_cmd(deferred_cmds.pop(0))
        if stopped:
            break
        rlist, _, _ = select.select([stdin_fd, fd], [], [], 0.05)
        if stdin_fd in rlist:
            line = sys.stdin.readline()
            if not line:
                break
            run_cmd(line.strip().split())
            if stopped:
                break
        if fd in rlist:
            raw = os.read(fd, 131072)
            if not raw or lib.nfq_handle_packet(handle, C.create_string_buffer(raw), len(raw)) < 0:
                break
finally:
    for qh in list(handles.values()):
        lib.nfq_destroy_queue(qh)
    handles.clear()
    lib.nfq_close(handle)
"#;

#[cfg(unix)]
pub struct SubprocessNfqBackend {
    child: std::process::Child,
    stdin: std::sync::Arc<std::sync::Mutex<std::process::ChildStdin>>,
    ack_rx: std::sync::mpsc::Receiver<Result<(), String>>,
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reader_thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl SubprocessNfqBackend {
    pub fn new<F>(decide: F) -> Result<Self, AdmissionError>
    where
        F: Fn(u16, &[u8]) -> bool + Send + Sync + 'static,
    {
        Self::with_python("python3", decide)
    }

    pub fn with_python<F>(python_bin: &str, decide: F) -> Result<Self, AdmissionError>
    where
        F: Fn(u16, &[u8]) -> bool + Send + Sync + 'static,
    {
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        let mut child = Command::new(python_bin)
            .args(["-u", "-c", NFQ_PYTHON_WORKER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(AdmissionError::from_io)?;

        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| AdmissionError::Runtime("NFQUEUE worker stdin unavailable".to_string()))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| AdmissionError::Runtime("NFQUEUE worker stdout unavailable".to_string()))?;

        let stdin_arc = Arc::new(Mutex::new(child_stdin));
        let stdin_for_thread = Arc::clone(&stdin_arc);
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_for_thread = Arc::clone(&stopped);
        let (ack_tx, ack_rx) = mpsc::sync_channel::<Result<(), String>>(4);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);

        let reader_thread = thread::Builder::new()
            .name("narwhal-admission-packets".to_string())
            .spawn(move || {
                let mut reader = BufReader::new(child_stdout);
                let mut line = String::new();
                let mut ready_sent = false;

                while !stopped_for_thread.load(Ordering::Relaxed) {
                    line.clear();
                    let n = match reader.read_line(&mut line) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                    let trimmed = line.trim();
                    if !ready_sent {
                        ready_sent = true;
                        if trimmed == "READY" {
                            let _ = ready_tx.send(Ok(()));
                            continue;
                        } else {
                            let msg = trimmed.strip_prefix("ERR ").unwrap_or(trimmed).to_string();
                            let _ = ready_tx.send(Err(msg));
                            break;
                        }
                    }
                    if trimmed == "OK" {
                        let _ = ack_tx.send(Ok(()));
                    } else if let Some(err_msg) = trimmed.strip_prefix("ERR ") {
                        let _ = ack_tx.send(Err(err_msg.to_string()));
                    } else if let Some(rest) = trimmed.strip_prefix("P ") {
                        let mut parts = rest.split_whitespace();
                        let (Some(q_str), Some(id_str), Some(hex_str)) =
                            (parts.next(), parts.next(), parts.next())
                        else {
                            continue;
                        };
                        let Ok(qnum) = q_str.parse::<u16>() else {
                            continue;
                        };
                        let Ok(pkt_id) = id_str.parse::<u32>() else {
                            continue;
                        };
                        let payload = decode_hex(hex_str).unwrap_or_default();
                        let accepted = decide(qnum, &payload);
                        let verdict_line =
                            format!("V {pkt_id} {}\n", if accepted { 1 } else { 0 });
                        if let Ok(mut guard) = stdin_for_thread.lock() {
                            if guard.write_all(verdict_line.as_bytes()).is_err()
                                || guard.flush().is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                if !ready_sent {
                    let _ = ready_tx.send(Err("libnetfilter_queue is unavailable".to_string()));
                }
                stopped_for_thread.store(true, Ordering::Relaxed);
            })
            .map_err(|e| AdmissionError::Runtime(format!("failed to spawn NFQUEUE thread: {e}")))?;

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                child,
                stdin: stdin_arc,
                ack_rx,
                stopped,
                reader_thread: Some(reader_thread),
            }),
            Ok(Err(msg)) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(AdmissionError::Runtime(msg))
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(AdmissionError::Timeout(
                    "NFQUEUE helper startup timed out".to_string(),
                ))
            }
        }
    }

    fn send_control(&mut self, cmd_line: &str) -> Result<(), AdmissionError> {
        use std::io::Write;
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        if self.stopped.load(Ordering::Relaxed) {
            return Err(AdmissionError::Runtime(
                "NFQUEUE worker is stopped".to_string(),
            ));
        }
        {
            let mut guard = self
                .stdin
                .lock()
                .map_err(|_| AdmissionError::Runtime("NFQUEUE stdin lock poisoned".to_string()))?;
            guard
                .write_all(cmd_line.as_bytes())
                .map_err(AdmissionError::from_io)?;
            guard.flush().map_err(AdmissionError::from_io)?;
        }
        match self.ack_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(msg)) => Err(AdmissionError::Runtime(msg)),
            Err(_) => {
                self.stopped.store(true, Ordering::Relaxed);
                Err(AdmissionError::Runtime(
                    "NFQUEUE control command failed".to_string(),
                ))
            }
        }
    }
}

#[cfg(unix)]
impl QueueBackend for SubprocessNfqBackend {
    fn add(&mut self, number: u16) -> Result<(), AdmissionError> {
        self.send_control(&format!("A {number}\n"))
    }

    fn remove(&mut self, number: u16) -> Result<(), AdmissionError> {
        self.send_control(&format!("R {number}\n"))
    }

    fn healthy(&self) -> bool {
        use std::sync::atomic::Ordering;
        !self.stopped.load(Ordering::Relaxed) && self.reader_thread.is_some()
    }

    fn close(&mut self) {
        use std::sync::atomic::Ordering;
        if !self.stopped.swap(true, Ordering::Relaxed) {
            let _ = self.send_control("Q\n");
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(unix)]
impl Drop for SubprocessNfqBackend {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(unix)]
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let s = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(out)
}
