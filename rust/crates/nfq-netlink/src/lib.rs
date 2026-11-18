//! Pure-`std` Linux `NETLINK_NETFILTER` NFQUEUE client (no external crates, no `python3` subprocess).

pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const NFNL_SUBSYS_QUEUE: u16 = 3;
pub const NFQNL_MSG_PACKET: u16 = (NFNL_SUBSYS_QUEUE << 8) | 0;
pub const NFQNL_MSG_VERDICT: u16 = (NFNL_SUBSYS_QUEUE << 8) | 1;
pub const NFQNL_MSG_CONFIG: u16 = (NFNL_SUBSYS_QUEUE << 8) | 2;

pub const NLMSG_ERROR: u16 = 2;
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;

pub const NFQNL_CFG_CMD_BIND: u8 = 1;
pub const NFQNL_CFG_CMD_UNBIND: u8 = 2;
pub const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
pub const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;

pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
pub const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
pub const NFQNL_COPY_PACKET: u8 = 2;

pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_VERDICT_HDR: u16 = 2;
pub const NFQA_PAYLOAD: u16 = 10;

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

pub const DEFAULT_COPY_RANGE: u32 = 2048;
pub const DEFAULT_QUEUE_MAXLEN: u32 = 1024;

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn push_nlattr(buf: &mut Vec<u8>, nla_type: u16, payload: &[u8]) {
    let nla_len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&nla_len.to_ne_bytes());
    buf.extend_from_slice(&nla_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(payload.len()) - payload.len();
    buf.resize(buf.len() + pad, 0);
}

fn build_nfgen_msg(
    msg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    res_id_be: u16,
    attrs: &[u8],
) -> Vec<u8> {
    let total_len = (16 + 4 + attrs.len()) as u32;
    let mut out = Vec::with_capacity(total_len as usize);
    out.extend_from_slice(&total_len.to_ne_bytes());
    out.extend_from_slice(&msg_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid = 0 (kernel)
    out.push(family);
    out.push(0); // NFNETLINK_V0
    out.extend_from_slice(&res_id_be.to_be_bytes());
    out.extend_from_slice(attrs);
    out
}

pub fn encode_pf_bind_msg(seq: u32, pf: u16, bind: bool) -> Vec<u8> {
    let cmd = if bind {
        NFQNL_CFG_CMD_PF_BIND
    } else {
        NFQNL_CFG_CMD_PF_UNBIND
    };
    let mut cfg_cmd = [0u8; 4];
    cfg_cmd[0] = cmd;
    cfg_cmd[2..4].copy_from_slice(&pf.to_be_bytes());
    let mut attrs = Vec::with_capacity(8);
    push_nlattr(&mut attrs, NFQA_CFG_CMD, &cfg_cmd);
    build_nfgen_msg(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        AF_UNSPEC,
        0,
        &attrs,
    )
}

pub fn encode_queue_bind_msg(
    seq: u32,
    qnum: u16,
    copy_range: u32,
    maxlen: u32,
) -> Vec<u8> {
    let mut attrs = Vec::with_capacity(32);
    let cfg_cmd = [NFQNL_CFG_CMD_BIND, 0, 0, 0];
    push_nlattr(&mut attrs, NFQA_CFG_CMD, &cfg_cmd);

    let mut params = [0u8; 5];
    params[0..4].copy_from_slice(&copy_range.to_be_bytes());
    params[4] = NFQNL_COPY_PACKET;
    push_nlattr(&mut attrs, NFQA_CFG_PARAMS, &params);

    push_nlattr(&mut attrs, NFQA_CFG_QUEUE_MAXLEN, &maxlen.to_be_bytes());

    build_nfgen_msg(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        AF_UNSPEC,
        qnum,
        &attrs,
    )
}

pub fn encode_queue_unbind_msg(seq: u32, qnum: u16) -> Vec<u8> {
    let mut attrs = Vec::with_capacity(8);
    let cfg_cmd = [NFQNL_CFG_CMD_UNBIND, 0, 0, 0];
    push_nlattr(&mut attrs, NFQA_CFG_CMD, &cfg_cmd);
    build_nfgen_msg(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        AF_UNSPEC,
        qnum,
        &attrs,
    )
}

pub fn encode_verdict_msg(seq: u32, qnum: u16, packet_id: u32, accept: bool) -> Vec<u8> {
    let verdict = if accept { NF_ACCEPT } else { NF_DROP };
    let mut vhdr = [0u8; 8];
    vhdr[0..4].copy_from_slice(&verdict.to_be_bytes());
    vhdr[4..8].copy_from_slice(&packet_id.to_be_bytes());
    let mut attrs = Vec::with_capacity(12);
    push_nlattr(&mut attrs, NFQA_VERDICT_HDR, &vhdr);
    build_nfgen_msg(NFQNL_MSG_VERDICT, NLM_F_REQUEST, seq, AF_UNSPEC, qnum, &attrs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfqPacket<'a> {
    pub qnum: u16,
    pub packet_id: u32,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkEvent<'a> {
    Packet(NfqPacket<'a>),
    Ack { seq: u32, errno: i32 },
    Other,
}

pub fn parse_netlink_messages(buf: &[u8]) -> Vec<NetlinkEvent<'_>> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset + 16 <= buf.len() {
        let msg_len = u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        if msg_len < 16 || offset + msg_len > buf.len() {
            break;
        }
        let msg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
        let msg_slice = &buf[offset..offset + msg_len];
        if msg_type == NLMSG_ERROR && msg_slice.len() >= 24 {
            let errno = i32::from_ne_bytes([
                msg_slice[16],
                msg_slice[17],
                msg_slice[18],
                msg_slice[19],
            ]);
            let ack_seq = if msg_slice.len() >= 32 {
                u32::from_ne_bytes([
                    msg_slice[28],
                    msg_slice[29],
                    msg_slice[30],
                    msg_slice[31],
                ])
            } else {
                0
            };
            events.push(NetlinkEvent::Ack { seq: ack_seq, errno });
        } else if msg_type == NFQNL_MSG_PACKET && msg_slice.len() >= 20 {
            let qnum = u16::from_be_bytes([msg_slice[18], msg_slice[19]]);
            let mut attr_off = 20usize;
            let mut packet_id = None;
            let mut payload: &[u8] = &[];
            while attr_off + 4 <= msg_slice.len() {
                let nla_len =
                    u16::from_ne_bytes([msg_slice[attr_off], msg_slice[attr_off + 1]]) as usize;
                let nla_type =
                    u16::from_ne_bytes([msg_slice[attr_off + 2], msg_slice[attr_off + 3]]) & 0x7fff;
                if nla_len < 4 || attr_off + nla_len > msg_slice.len() {
                    break;
                }
                let val = &msg_slice[attr_off + 4..attr_off + nla_len];
                if nla_type == NFQA_PACKET_HDR && val.len() >= 4 {
                    packet_id = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                } else if nla_type == NFQA_PAYLOAD {
                    payload = val;
                }
                let step = align4(nla_len);
                if step == 0 {
                    break;
                }
                attr_off += step;
            }
            if let Some(pid) = packet_id {
                events.push(NetlinkEvent::Packet(NfqPacket {
                    qnum,
                    packet_id: pid,
                    payload,
                }));
            }
        } else {
            events.push(NetlinkEvent::Other);
        }
        let step = align4(msg_len);
        if step == 0 {
            break;
        }
        offset += step;
    }
    events
}

#[cfg(target_os = "linux")]
mod linux_sock {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};
    use std::io;
    use std::os::raw::{c_int, c_void};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};

    const AF_NETLINK_C: c_int = 16;
    const SOCK_RAW_C: c_int = 3;
    const SOCK_NONBLOCK_C: c_int = 0o4000;
    const SOCK_CLOEXEC_C: c_int = 0o2000000;
    const NETLINK_NETFILTER_C: c_int = 12;
    const SOL_NETLINK_C: c_int = 270;
    const NETLINK_NO_ENOBUFS_C: c_int = 5;
    const POLLIN_C: i16 = 0x0001;

    #[repr(C)]
    struct SockAddrNl {
        nl_family: u16,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const SockAddrNl, len: u32) -> c_int;
        fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: u32,
        ) -> c_int;
        fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    enum Cmd {
        Add(u16),
        Remove(u16),
        Stop,
    }

    struct PendingCmd {
        cmd: Cmd,
        done: Arc<(Mutex<Option<Result<(), String>>>, std::sync::Condvar)>,
    }

    pub struct NativeNfqHandle {
        stop: Arc<AtomicBool>,
        cmds: Arc<Mutex<VecDeque<PendingCmd>>>,
        worker: Option<JoinHandle<()>>,
        queues: Mutex<BTreeSet<u16>>,
    }

    fn send_all(fd: c_int, msg: &[u8]) -> Result<(), String> {
        let rc = unsafe { send(fd, msg.as_ptr().cast(), msg.len(), 0) };
        if rc < 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    fn wait_ack(fd: c_int, target_seq: u32, buf: &mut [u8]) -> Result<(), String> {
        for _ in 0..32 {
            let mut pfd = PollFd {
                fd,
                events: POLLIN_C,
                revents: 0,
            };
            let prc = unsafe { poll(&mut pfd, 1, 200) };
            if prc <= 0 {
                return Err("NFQUEUE netlink ack timed out".to_string());
            }
            let n = unsafe { recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                continue;
            }
            for ev in parse_netlink_messages(&buf[..n as usize]) {
                if let NetlinkEvent::Ack { seq, errno } = ev {
                    if seq == target_seq || seq == 0 {
                        if errno == 0 {
                            return Ok(());
                        }
                        return Err(format!("netlink error errno={}", -errno));
                    }
                }
            }
        }
        Err("NFQUEUE netlink ack missing".to_string())
    }

    impl NativeNfqHandle {
        pub fn new<F>(decide: F) -> Result<Self, String>
        where
            F: Fn(u16, &[u8]) -> bool + Send + Sync + 'static,
        {
            let fd = unsafe {
                socket(
                    AF_NETLINK_C,
                    SOCK_RAW_C | SOCK_NONBLOCK_C | SOCK_CLOEXEC_C,
                    NETLINK_NETFILTER_C,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "failed to open AF_NETLINK NFQUEUE socket: {}",
                    io::Error::last_os_error()
                ));
            }
            let sa = SockAddrNl {
                nl_family: AF_NETLINK_C as u16,
                nl_pad: 0,
                nl_pid: 0,
                nl_groups: 0,
            };
            if unsafe { bind(fd, &sa, std::mem::size_of::<SockAddrNl>() as u32) } < 0 {
                let err = io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(format!("failed to bind AF_NETLINK socket: {err}"));
            }
            let one: c_int = 1;
            unsafe {
                let _ = setsockopt(
                    fd,
                    SOL_NETLINK_C,
                    NETLINK_NO_ENOBUFS_C,
                    (&one as *const c_int).cast(),
                    std::mem::size_of::<c_int>() as u32,
                );
            }
            let mut ack_buf = vec![0u8; 8192];
            for (idx, pf) in [AF_INET, AF_INET6].iter().enumerate() {
                let seq = (idx + 1) as u32;
                let _ = send_all(fd, &encode_pf_bind_msg(seq, *pf, true));
                let _ = wait_ack(fd, seq, &mut ack_buf);
            }

            let stop = Arc::new(AtomicBool::new(false));
            let cmds: Arc<Mutex<VecDeque<PendingCmd>>> = Arc::new(Mutex::new(VecDeque::new()));
            let stop_w = Arc::clone(&stop);
            let cmds_w = Arc::clone(&cmds);

            let worker = thread::Builder::new()
                .name("narwhal-nfq-netlink".to_string())
                .spawn(move || {
                    let mut seq: u32 = 10;
                    let mut buf = vec![0u8; 65536];
                    let mut bound = BTreeSet::new();
                    while !stop_w.load(Ordering::Relaxed) {
                        loop {
                            let next = cmds_w.lock().ok().and_then(|mut q| q.pop_front());
                            let Some(pending) = next else {
                                break;
                            };
                            let res = match pending.cmd {
                                Cmd::Add(qnum) => {
                                    if bound.contains(&qnum) {
                                        Ok(())
                                    } else {
                                        seq = seq.wrapping_add(1);
                                        let msg = encode_queue_bind_msg(
                                            seq,
                                            qnum,
                                            DEFAULT_COPY_RANGE,
                                            DEFAULT_QUEUE_MAXLEN,
                                        );
                                        match send_all(fd, &msg)
                                            .and_then(|()| wait_ack(fd, seq, &mut buf))
                                        {
                                            Ok(()) => {
                                                bound.insert(qnum);
                                                Ok(())
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                }
                                Cmd::Remove(qnum) => {
                                    if bound.remove(&qnum) {
                                        seq = seq.wrapping_add(1);
                                        let msg = encode_queue_unbind_msg(seq, qnum);
                                        let _ = send_all(fd, &msg);
                                        let _ = wait_ack(fd, seq, &mut buf);
                                    }
                                    Ok(())
                                }
                                Cmd::Stop => {
                                    stop_w.store(true, Ordering::Relaxed);
                                    Ok(())
                                }
                            };
                            let (lock, cv) = &*pending.done;
                            if let Ok(mut guard) = lock.lock() {
                                *guard = Some(res);
                                cv.notify_all();
                            }
                            if stop_w.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        if stop_w.load(Ordering::Relaxed) {
                            break;
                        }
                        let mut pfd = PollFd {
                            fd,
                            events: POLLIN_C,
                            revents: 0,
                        };
                        let prc = unsafe { poll(&mut pfd, 1, 50) };
                        if prc <= 0 {
                            continue;
                        }
                        loop {
                            let n = unsafe { recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
                            if n <= 0 {
                                break;
                            }
                            for ev in parse_netlink_messages(&buf[..n as usize]) {
                                if let NetlinkEvent::Packet(pkt) = ev {
                                    let accept = decide(pkt.qnum, pkt.payload);
                                    seq = seq.wrapping_add(1);
                                    let vmsg =
                                        encode_verdict_msg(seq, pkt.qnum, pkt.packet_id, accept);
                                    let _ = send_all(fd, &vmsg);
                                }
                            }
                        }
                    }
                    for qnum in bound {
                        seq = seq.wrapping_add(1);
                        let _ = send_all(fd, &encode_queue_unbind_msg(seq, qnum));
                    }
                    unsafe { close(fd) };
                })
                .map_err(|e| format!("failed to spawn NFQUEUE netlink thread: {e}"))?;

            Ok(Self {
                stop,
                cmds,
                worker: Some(worker),
                queues: Mutex::new(BTreeSet::new()),
            })
        }

        fn send_cmd(&self, cmd: Cmd) -> Result<(), String> {
            let done = Arc::new((Mutex::new(None), std::sync::Condvar::new()));
            if let Ok(mut q) = self.cmds.lock() {
                q.push_back(PendingCmd {
                    cmd,
                    done: Arc::clone(&done),
                });
            } else {
                return Err("NFQUEUE command queue poisoned".to_string());
            }
            let (lock, cv) = &*done;
            let mut guard = lock
                .lock()
                .map_err(|_| "NFQUEUE ack lock poisoned".to_string())?;
            while guard.is_none() {
                let (g, timeout) = cv
                    .wait_timeout(guard, std::time::Duration::from_secs(3))
                    .map_err(|_| "NFQUEUE ack wait failed".to_string())?;
                guard = g;
                if timeout.timed_out() && guard.is_none() {
                    return Err("NFQUEUE netlink worker timed out".to_string());
                }
            }
            guard.take().unwrap_or(Ok(()))
        }

        pub fn add_queue(&self, queue: u16) -> Result<(), String> {
            self.send_cmd(Cmd::Add(queue))?;
            if let Ok(mut qs) = self.queues.lock() {
                qs.insert(queue);
            }
            Ok(())
        }

        pub fn remove_queue(&self, queue: u16) -> Result<(), String> {
            let _ = self.send_cmd(Cmd::Remove(queue));
            if let Ok(mut qs) = self.queues.lock() {
                qs.remove(&queue);
            }
            Ok(())
        }

        pub fn is_healthy(&self) -> bool {
            !self.stop.load(Ordering::Relaxed)
                && self
                    .worker
                    .as_ref()
                    .map(|h| !h.is_finished())
                    .unwrap_or(false)
        }

        pub fn queue_count(&self) -> usize {
            self.queues.lock().map(|q| q.len()).unwrap_or(0)
        }
    }

    impl Drop for NativeNfqHandle {
        fn drop(&mut self) {
            let _ = self.send_cmd(Cmd::Stop);
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.worker.take() {
                let _ = handle.join();
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_sock::NativeNfqHandle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_queue_bind_and_verdict_and_parse_packet() {
        let bind_msg = encode_queue_bind_msg(7, 4201, DEFAULT_COPY_RANGE, DEFAULT_QUEUE_MAXLEN);
        assert_eq!(
            u16::from_ne_bytes([bind_msg[4], bind_msg[5]]),
            NFQNL_MSG_CONFIG
        );
        assert_eq!(u16::from_be_bytes([bind_msg[18], bind_msg[19]]), 4201);

        let verdict_msg = encode_verdict_msg(8, 4201, 0x11223344, false);
        assert_eq!(
            u16::from_ne_bytes([verdict_msg[4], verdict_msg[5]]),
            NFQNL_MSG_VERDICT
        );
        // NFQA_VERDICT_HDR starts at offset 20: nla_len(2), nla_type(2), verdict(4), id(4)
        assert_eq!(
            u32::from_be_bytes([
                verdict_msg[24],
                verdict_msg[25],
                verdict_msg[26],
                verdict_msg[27]
            ]),
            NF_DROP
        );
        assert_eq!(
            u32::from_be_bytes([
                verdict_msg[28],
                verdict_msg[29],
                verdict_msg[30],
                verdict_msg[31]
            ]),
            0x11223344
        );

        // Synthetic NFQNL_MSG_PACKET with NFQA_PACKET_HDR + NFQA_PAYLOAD
        let mut attrs = Vec::new();
        let mut phdr = [0u8; 7];
        phdr[0..4].copy_from_slice(&99u32.to_be_bytes());
        push_nlattr(&mut attrs, NFQA_PACKET_HDR, &phdr);
        push_nlattr(&mut attrs, NFQA_PAYLOAD, &[0x45, 0x00, 0x00, 0x14]);
        let pkt_msg = build_nfgen_msg(NFQNL_MSG_PACKET, 0, 0, AF_INET as u8, 4201, &attrs);
        let parsed = parse_netlink_messages(&pkt_msg);
        assert_eq!(
            parsed,
            vec![NetlinkEvent::Packet(NfqPacket {
                qnum: 4201,
                packet_id: 99,
                payload: &[0x45, 0x00, 0x00, 0x14],
            })]
        );
    }
}
