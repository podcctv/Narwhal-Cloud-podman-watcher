//! Pure-`std`, `#![forbid(unsafe_code)]` TLS & QUIC Initial SNI parser and
//! whitelist enforcer for container ingress traffic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use transport::hmac_sha256;

pub const SNI_WHITELIST: &[&str] = &[
    "dl-cdn.alpinelinux.org",
    "deb.debian.org",
    "crates.io",
    "pypi.org",
    "rubygems.org",
    "addons.mozilla.org",
    "formulae.brew.sh",
    "static.rust-lang.org",
    "cpan.org",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniParse {
    Found(String),
    MissingSni,
    Malformed,
    NotHandshake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniDecision {
    Allow,
    Block {
        reason: &'static str,
        sni: Option<String>,
        proto: u8,
        dport: u16,
        src_ip: IpAddr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Packet<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub tcp_flags: u8,
    pub payload: &'a [u8],
}

pub fn normalize_sni(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(trimmed)
}

pub fn is_allowed_sni(raw: &str) -> bool {
    let Some(norm) = normalize_sni(raw) else {
        return false;
    };
    SNI_WHITELIST.iter().any(|&allowed| norm == allowed)
}

pub fn extract_l4_payload(raw: &[u8]) -> Option<L4Packet<'_>> {
    if raw.len() < 20 {
        return None;
    }
    let version = raw[0] >> 4;
    let (src_ip, dst_ip, mut proto, mut offset, total_end) = match version {
        4 => {
            let ihl = ((raw[0] & 0x0f) as usize) * 4;
            if ihl < 20 || raw.len() < ihl {
                return None;
            }
            let tot = u16::from_be_bytes([raw[2], raw[3]]) as usize;
            let end = tot.min(raw.len());
            if end < ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]));
            (src, dst, raw[9], ihl, end)
        }
        6 => {
            if raw.len() < 40 {
                return None;
            }
            let plen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
            let end = (40 + plen).min(raw.len());
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&raw[8..24]);
            d.copy_from_slice(&raw[24..40]);
            (
                IpAddr::V6(Ipv6Addr::from(s)),
                IpAddr::V6(Ipv6Addr::from(d)),
                raw[6],
                40usize,
                end,
            )
        }
        _ => return None,
    };

    if version == 6 {
        let mut hops = 0u8;
        while matches!(proto, 0 | 43 | 44 | 60) && hops < 6 {
            hops += 1;
            if proto == 44 {
                if offset + 8 > total_end {
                    return None;
                }
                proto = raw[offset];
                offset += 8;
            } else {
                if offset + 2 > total_end {
                    return None;
                }
                let next = raw[offset];
                let hdr_len = (raw[offset + 1] as usize + 1) * 8;
                if offset + hdr_len > total_end {
                    return None;
                }
                proto = next;
                offset += hdr_len;
            }
        }
    }

    match proto {
        6 => {
            if offset + 20 > total_end {
                return None;
            }
            let sport = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let dport = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            let data_off = ((raw[offset + 12] >> 4) as usize) * 4;
            let tcp_flags = raw[offset + 13];
            if data_off < 20 || offset + data_off > total_end {
                return None;
            }
            Some(L4Packet {
                src_ip,
                dst_ip,
                proto,
                sport,
                dport,
                tcp_flags,
                payload: &raw[offset + data_off..total_end],
            })
        }
        17 => {
            if offset + 8 > total_end {
                return None;
            }
            let sport = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let dport = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            let ulen = u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]) as usize;
            let end = if ulen >= 8 {
                (offset + ulen).min(total_end)
            } else {
                total_end
            };
            Some(L4Packet {
                src_ip,
                dst_ip,
                proto,
                sport,
                dport,
                tcp_flags: 0,
                payload: &raw[offset + 8..end],
            })
        }
        _ => None,
    }
}

/// Parses a TCP TLS Record containing a ClientHello (`0x16 0x03 0x00..=0x04 ... 0x01`).
pub fn extract_tls_client_hello_sni(payload: &[u8]) -> SniParse {
    if payload.len() < 6 {
        return SniParse::NotHandshake;
    }
    if payload[0] != 0x16 || payload[1] != 0x03 || payload[2] > 0x04 {
        return SniParse::NotHandshake;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if rec_len == 0 {
        return SniParse::Malformed;
    }
    let rec_end = (5 + rec_len).min(payload.len());
    parse_tls_handshake_client_hello_sni(&payload[5..rec_end])
}

/// Parses a raw TLS Handshake message starting with HandshakeType (`0x01` = ClientHello).
pub fn parse_tls_handshake_client_hello_sni(hs: &[u8]) -> SniParse {
    if hs.len() < 4 || hs[0] != 0x01 {
        return SniParse::NotHandshake;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs_len < 34 || 4 + hs_len > hs.len() {
        return SniParse::Malformed;
    }
    let body = &hs[4..4 + hs_len];
    // legacy_version (2) + random (32) = 34
    let mut pos = 34usize;
    if pos >= body.len() {
        return SniParse::Malformed;
    }
    let sid_len = body[pos] as usize;
    pos += 1;
    if pos + sid_len > body.len() {
        return SniParse::Malformed;
    }
    pos += sid_len;
    if pos + 2 > body.len() {
        return SniParse::Malformed;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if cs_len == 0 || (cs_len & 1) != 0 || pos + cs_len > body.len() {
        return SniParse::Malformed;
    }
    pos += cs_len;
    if pos >= body.len() {
        return SniParse::Malformed;
    }
    let comp_len = body[pos] as usize;
    pos += 1;
    if comp_len == 0 || pos + comp_len > body.len() {
        return SniParse::Malformed;
    }
    pos += comp_len;
    if pos == body.len() {
        return SniParse::MissingSni;
    }
    if pos + 2 > body.len() {
        return SniParse::Malformed;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_total > body.len() {
        return SniParse::Malformed;
    }
    let ext_end = pos + ext_total;
    while pos < ext_end {
        if pos + 4 > ext_end {
            return SniParse::Malformed;
        }
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return SniParse::Malformed;
        }
        if ext_type == 0x0000 {
            let ext_data = &body[pos..pos + ext_len];
            if ext_data.len() < 2 {
                return SniParse::Malformed;
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if 2 + list_len > ext_data.len() {
                return SniParse::Malformed;
            }
            let mut spos = 2usize;
            let send = 2 + list_len;
            while spos < send {
                if spos + 3 > send {
                    return SniParse::Malformed;
                }
                let name_type = ext_data[spos];
                let name_len = u16::from_be_bytes([ext_data[spos + 1], ext_data[spos + 2]]) as usize;
                spos += 3;
                if spos + name_len > send {
                    return SniParse::Malformed;
                }
                if name_type == 0x00 {
                    let Ok(s) = std::str::from_utf8(&ext_data[spos..spos + name_len]) else {
                        return SniParse::Malformed;
                    };
                    return match normalize_sni(s) {
                        Some(norm) => SniParse::Found(norm),
                        None => SniParse::Malformed,
                    };
                }
                spos += name_len;
            }
            return SniParse::MissingSni;
        }
        pos += ext_len;
    }
    SniParse::MissingSni
}

// ============================================================================
// Pure-std RFC 9001 QUIC v1/v2 Initial Packet Decryption (AES-128-GCM + HKDF)
// ============================================================================

const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

#[rustfmt::skip]
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0] = *key;
    for r in 0..10 {
        let prev = rk[r];
        let mut next = [0u8; 16];
        next[0] = prev[0] ^ AES_SBOX[prev[13] as usize] ^ AES_RCON[r];
        next[1] = prev[1] ^ AES_SBOX[prev[14] as usize];
        next[2] = prev[2] ^ AES_SBOX[prev[15] as usize];
        next[3] = prev[3] ^ AES_SBOX[prev[12] as usize];
        for i in 4..16 {
            next[i] = prev[i] ^ next[i - 4];
        }
        rk[r + 1] = next;
    }
    rk
}

fn aes128_encrypt_block(rk: &[[u8; 16]; 11], input: &[u8; 16]) -> [u8; 16] {
    let mut s = *input;
    for i in 0..16 {
        s[i] ^= rk[0][i];
    }
    for round in 1..=10 {
        for b in &mut s {
            *b = AES_SBOX[*b as usize];
        }
        // ShiftRows (column-major)
        let t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1;
        s.swap(2, 10); s.swap(6, 14);
        let t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3;
        if round < 10 {
            for col in 0..4 {
                let c = col * 4;
                let (a0, a1, a2, a3) = (s[c], s[c + 1], s[c + 2], s[c + 3]);
                let t = a0 ^ a1 ^ a2 ^ a3;
                s[c] ^= t ^ xtime(a0 ^ a1);
                s[c + 1] ^= t ^ xtime(a1 ^ a2);
                s[c + 2] ^= t ^ xtime(a2 ^ a3);
                s[c + 3] ^= t ^ xtime(a3 ^ a0);
            }
        }
        for i in 0..16 {
            s[i] ^= rk[round][i];
        }
    }
    s
}

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = 0u128;
    let mut v = u128::from_be_bytes(*y);
    let xb = u128::from_be_bytes(*x);
    for i in 0..128 {
        if (xb >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000u128;
        }
    }
    z.to_be_bytes()
}

fn ghash_update(acc: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    for chunk in data.chunks(16) {
        for (i, &b) in chunk.iter().enumerate() {
            acc[i] ^= b;
        }
        *acc = gf128_mul(acc, h);
    }
}

fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    let rk = aes128_key_expand(key);
    let h = aes128_encrypt_block(&rk, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut acc = [0u8; 16];
    ghash_update(&mut acc, &h, aad);
    ghash_update(&mut acc, &h, ciphertext);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_update(&mut acc, &h, &lens);

    let s0 = aes128_encrypt_block(&rk, &j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = acc[i] ^ s0[i];
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return None;
    }

    let mut plain = Vec::with_capacity(ciphertext.len());
    let mut ctr = 2u32;
    for chunk in ciphertext.chunks(16) {
        let mut cb = j0;
        cb[12..16].copy_from_slice(&ctr.to_be_bytes());
        let ks = aes128_encrypt_block(&rk, &cb);
        for (i, &b) in chunk.iter().enumerate() {
            plain.push(b ^ ks[i]);
        }
        ctr = ctr.wrapping_add(1);
    }
    Some(plain)
}

fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], out_len: usize) -> Vec<u8> {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(4 + full_label_len);
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0u8);

    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(&info);
        msg.push(counter);
        let block = hmac_sha256(secret, &msg);
        t = block.to_vec();
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn read_quic_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if *pos + len > buf.len() {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[*pos + 1..*pos + len] {
        val = (val << 8) | (b as u64);
    }
    *pos += len;
    Some(val)
}

/// Parses a QUIC v1/v2 Initial packet, decrypts CRYPTO frames, and extracts TLS ClientHello SNI.
pub fn extract_quic_initial_sni(udp_payload: &[u8]) -> SniParse {
    if udp_payload.len() < 16 {
        return SniParse::NotHandshake;
    }
    let first = udp_payload[0];
    // Long header bit (0x80) + Fixed bit (0x40)
    if (first & 0xc0) != 0xc0 {
        return SniParse::NotHandshake;
    }
    let version = u32::from_be_bytes([udp_payload[1], udp_payload[2], udp_payload[3], udp_payload[4]]);
    let (salt, is_v2) = match version {
        0x0000_0001 => (&QUIC_V1_SALT, false),
        0x6b33_43cf => (&QUIC_V2_SALT, true),
        _ => return SniParse::NotHandshake,
    };
    let pkt_type = (first >> 4) & 0x03;
    let expected_initial_type = if is_v2 { 1 } else { 0 };
    if pkt_type != expected_initial_type {
        return SniParse::NotHandshake;
    }

    let mut pos = 5usize;
    let dcid_len = *udp_payload.get(pos).unwrap_or(&255) as usize;
    pos += 1;
    if dcid_len > 20 || pos + dcid_len >= udp_payload.len() {
        return SniParse::Malformed;
    }
    let dcid = &udp_payload[pos..pos + dcid_len];
    pos += dcid_len;

    let scid_len = *udp_payload.get(pos).unwrap_or(&255) as usize;
    pos += 1;
    if scid_len > 20 || pos + scid_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    pos += scid_len;

    let Some(token_len) = read_quic_varint(udp_payload, &mut pos) else {
        return SniParse::Malformed;
    };
    let token_len = token_len as usize;
    if pos + token_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    pos += token_len;

    let Some(pkt_len) = read_quic_varint(udp_payload, &mut pos) else {
        return SniParse::Malformed;
    };
    let pkt_len = pkt_len as usize;
    if pkt_len < 20 || pos + pkt_len > udp_payload.len() {
        return SniParse::Malformed;
    }
    let pn_offset = pos;
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > udp_payload.len() {
        return SniParse::Malformed;
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&udp_payload[sample_offset..sample_offset + 16]);

    // Derive initial_secret -> client_in -> key, iv, hp
    let initial_secret = hmac_sha256(salt, dcid);
    let client_in_vec = hkdf_expand_label(&initial_secret, b"client in", 32);
    let mut client_in = [0u8; 32];
    client_in.copy_from_slice(&client_in_vec);

    let (lbl_key, lbl_iv, lbl_hp) = if is_v2 {
        (b"quicv2 key".as_slice(), b"quicv2 iv".as_slice(), b"quicv2 hp".as_slice())
    } else {
        (b"quic key".as_slice(), b"quic iv".as_slice(), b"quic hp".as_slice())
    };
    let mut key = [0u8; 16];
    key.copy_from_slice(&hkdf_expand_label(&client_in, lbl_key, 16));
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&hkdf_expand_label(&client_in, lbl_iv, 12));
    let mut hp_key = [0u8; 16];
    hp_key.copy_from_slice(&hkdf_expand_label(&client_in, lbl_hp, 16));

    let hp_rk = aes128_key_expand(&hp_key);
    let mask = aes128_encrypt_block(&hp_rk, &sample);
    let unmasked_first = first ^ (mask[0] & 0x0f);
    let pn_len = ((unmasked_first & 0x03) as usize) + 1;
    if pn_offset + pn_len + 16 > pn_offset + pkt_len {
        return SniParse::Malformed;
    }

    let mut header = udp_payload[..pn_offset + pn_len].to_vec();
    header[0] = unmasked_first;
    let mut pn_val = 0u64;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn_val = (pn_val << 8) | (header[pn_offset + i] as u64);
    }

    let mut nonce = iv;
    let pn_bytes = pn_val.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }

    let enc_start = pn_offset + pn_len;
    let enc_end = pn_offset + pkt_len;
    if enc_end - enc_start < 16 {
        return SniParse::Malformed;
    }
    let ct = &udp_payload[enc_start..enc_end - 16];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&udp_payload[enc_end - 16..enc_end]);

    let Some(plain) = aes128_gcm_decrypt(&key, &nonce, &header, ct, &tag) else {
        return SniParse::Malformed;
    };

    // Extract CRYPTO frames (type 0x06) starting at offset 0
    let mut crypto_chunks: Vec<(usize, &[u8])> = Vec::new();
    let mut fpos = 0usize;
    while fpos < plain.len() {
        let ftype = plain[fpos];
        fpos += 1;
        match ftype {
            0x00 | 0x01 => continue, // PADDING or PING
            0x06 => {
                let Some(off) = read_quic_varint(&plain, &mut fpos) else {
                    return SniParse::Malformed;
                };
                let Some(len) = read_quic_varint(&plain, &mut fpos) else {
                    return SniParse::Malformed;
                };
                let off = off as usize;
                let len = len as usize;
                if fpos + len > plain.len() || off > 8192 {
                    return SniParse::Malformed;
                }
                crypto_chunks.push((off, &plain[fpos..fpos + len]));
                fpos += len;
            }
            _ => break,
        }
    }
    if crypto_chunks.is_empty() {
        return SniParse::MissingSni;
    }
    crypto_chunks.sort_by_key(|(off, _)| *off);
    let mut assembled = Vec::new();
    for (off, chunk) in crypto_chunks {
        if off == assembled.len() {
            assembled.extend_from_slice(chunk);
        } else if off < assembled.len() && off + chunk.len() > assembled.len() {
            let skip = assembled.len() - off;
            assembled.extend_from_slice(&chunk[skip..]);
        }
    }
    if assembled.is_empty() {
        return SniParse::Malformed;
    }
    parse_tls_handshake_client_hello_sni(&assembled)
}

pub fn is_allowed_sni_with_override(raw: &str, allowed_override: Option<&[String]>) -> bool {
    let Some(norm) = normalize_sni(raw) else {
        return false;
    };
    if let Some(list) = allowed_override {
        return list.iter().any(|allowed| norm == *allowed);
    }
    SNI_WHITELIST.iter().any(|&allowed| norm == allowed)
}

pub fn evaluate_inbound_sni(raw_ip_packet: &[u8], is_cn_src: bool) -> SniDecision {
    evaluate_inbound_sni_with_policy(raw_ip_packet, is_cn_src, None, true)
}

pub fn evaluate_inbound_sni_with_policy(
    raw_ip_packet: &[u8],
    is_cn_src: bool,
    allowed_override: Option<&[String]>,
    block_cn_missing_sni: bool,
) -> SniDecision {
    let Some(l4) = extract_l4_payload(raw_ip_packet) else {
        return SniDecision::Allow;
    };
    if l4.payload.is_empty() {
        return SniDecision::Allow;
    }
    let parsed = match l4.proto {
        6 => extract_tls_client_hello_sni(l4.payload),
        17 => extract_quic_initial_sni(l4.payload),
        _ => SniParse::NotHandshake,
    };
    match parsed {
        SniParse::Found(sni) => {
            if is_allowed_sni_with_override(&sni, allowed_override) {
                SniDecision::Allow
            } else {
                SniDecision::Block {
                    reason: "disallowed_sni",
                    sni: Some(sni),
                    proto: l4.proto,
                    dport: l4.dport,
                    src_ip: l4.src_ip,
                }
            }
        }
        SniParse::MissingSni | SniParse::Malformed => {
            if is_cn_src && block_cn_missing_sni {
                SniDecision::Block {
                    reason: "missing_or_invalid_sni_cn",
                    sni: None,
                    proto: l4.proto,
                    dport: l4.dport,
                    src_ip: l4.src_ip,
                }
            } else {
                SniDecision::Allow
            }
        }
        SniParse::NotHandshake => SniDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_hs(sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let nb = name.as_bytes();
            let entry_len = 3 + nb.len();
            let list_len = entry_len;
            let ext_len = 2 + list_len;
            ext.extend_from_slice(&0x0000u16.to_be_bytes());
            ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
            ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            ext.push(0x00);
            ext.extend_from_slice(&(nb.len() as u16).to_be_bytes());
            ext.extend_from_slice(nb);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0x00); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(0x01);
        body.push(0x00); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let len = body.len();
        hs.push(((len >> 16) & 0xff) as u8);
        hs.push(((len >> 8) & 0xff) as u8);
        hs.push((len & 0xff) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    fn build_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[32] = 0x50; // 20B TCP header
        pkt[33] = flags;
        pkt[40..].copy_from_slice(payload);
        pkt
    }

    fn build_ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&sport.to_be_bytes());
        pkt[22..24].copy_from_slice(&dport.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    fn aes128_gcm_encrypt_for_test(
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        plain: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        let rk = aes128_key_expand(key);
        let h = aes128_encrypt_block(&rk, &[0u8; 16]);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let mut ct = Vec::with_capacity(plain.len());
        let mut ctr = 2u32;
        for chunk in plain.chunks(16) {
            let mut cb = j0;
            cb[12..16].copy_from_slice(&ctr.to_be_bytes());
            let ks = aes128_encrypt_block(&rk, &cb);
            for (i, &b) in chunk.iter().enumerate() {
                ct.push(b ^ ks[i]);
            }
            ctr = ctr.wrapping_add(1);
        }

        let mut acc = [0u8; 16];
        ghash_update(&mut acc, &h, aad);
        ghash_update(&mut acc, &h, &ct);
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
        ghash_update(&mut acc, &h, &lens);
        let s0 = aes128_encrypt_block(&rk, &j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = acc[i] ^ s0[i];
        }
        (ct, tag)
    }

    fn build_quic_initial_packet(dcid: &[u8], crypto_hs: &[u8]) -> Vec<u8> {
        let initial_secret = hmac_sha256(&QUIC_V1_SALT, dcid);
        let client_in_vec = hkdf_expand_label(&initial_secret, b"client in", 32);
        let mut client_in = [0u8; 32];
        client_in.copy_from_slice(&client_in_vec);
        let mut key = [0u8; 16];
        key.copy_from_slice(&hkdf_expand_label(&client_in, b"quic key", 16));
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&hkdf_expand_label(&client_in, b"quic iv", 12));
        let mut hp_key = [0u8; 16];
        hp_key.copy_from_slice(&hkdf_expand_label(&client_in, b"quic hp", 16));

        let mut plain = Vec::new();
        plain.push(0x06); // CRYPTO
        plain.push(0x00); // offset = 0
        // 2-byte varint length
        let len_v = (crypto_hs.len() as u16) | 0x4000;
        plain.extend_from_slice(&len_v.to_be_bytes());
        plain.extend_from_slice(crypto_hs);
        while plain.len() < 32 {
            plain.push(0x00);
        }

        let mut header = Vec::new();
        header.push(0xc0); // Initial, pn_len = 1 (0x00)
        header.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0x00); // scid len
        header.push(0x00); // token len
        let pkt_len = 1 + plain.len() + 16;
        let pkt_len_v = (pkt_len as u16) | 0x4000;
        header.extend_from_slice(&pkt_len_v.to_be_bytes());
        let pn_offset = header.len();
        header.push(0x01); // pn = 1

        let mut nonce = iv;
        nonce[11] ^= 0x01;
        let (ct, tag) = aes128_gcm_encrypt_for_test(&key, &nonce, &header, &plain);

        let mut pkt = header;
        pkt.extend_from_slice(&ct);
        pkt.extend_from_slice(&tag);

        let mut sample = [0u8; 16];
        sample.copy_from_slice(&pkt[pn_offset + 4..pn_offset + 20]);
        let hp_rk = aes128_key_expand(&hp_key);
        let mask = aes128_encrypt_block(&hp_rk, &sample);
        pkt[0] ^= mask[0] & 0x0f;
        pkt[pn_offset] ^= mask[1];
        pkt
    }

    #[test]
    fn test_tls_sni_whitelist_and_cn_missing_sni_policy() {
        let allowed_hs = build_client_hello_hs(Some("DEB.DEBIAN.ORG."));
        let mut allowed_tls = vec![0x16, 0x03, 0x01];
        allowed_tls.extend_from_slice(&(allowed_hs.len() as u16).to_be_bytes());
        allowed_tls.extend_from_slice(&allowed_hs);
        let pkt_ok = build_ipv4_tcp([1, 2, 3, 4], [10, 0, 0, 2], 50000, 443, 0x18, &allowed_tls);
        assert_eq!(evaluate_inbound_sni(&pkt_ok, true), SniDecision::Allow);

        let bad_hs = build_client_hello_hs(Some("www.microsoft.com"));
        let mut bad_tls = vec![0x16, 0x03, 0x01];
        bad_tls.extend_from_slice(&(bad_hs.len() as u16).to_be_bytes());
        bad_tls.extend_from_slice(&bad_hs);
        let pkt_bad = build_ipv4_tcp([8, 8, 8, 8], [10, 0, 0, 2], 50001, 8443, 0x18, &bad_tls);
        assert!(matches!(
            evaluate_inbound_sni(&pkt_bad, false),
            SniDecision::Block { reason: "disallowed_sni", sni: Some(ref s), dport: 8443, .. } if s == "www.microsoft.com"
        ));

        let no_sni_hs = build_client_hello_hs(None);
        let mut no_sni_tls = vec![0x16, 0x03, 0x01];
        no_sni_tls.extend_from_slice(&(no_sni_hs.len() as u16).to_be_bytes());
        no_sni_tls.extend_from_slice(&no_sni_hs);
        let pkt_no_sni = build_ipv4_tcp([1, 2, 3, 4], [10, 0, 0, 2], 50002, 443, 0x18, &no_sni_tls);
        // Non-CN allows missing SNI; CN blocks missing SNI
        assert_eq!(evaluate_inbound_sni(&pkt_no_sni, false), SniDecision::Allow);
        assert!(matches!(
            evaluate_inbound_sni(&pkt_no_sni, true),
            SniDecision::Block { reason: "missing_or_invalid_sni_cn", sni: None, .. }
        ));
    }

    #[test]
    fn test_quic_initial_decryption_and_sni_whitelist() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let allowed_hs = build_client_hello_hs(Some("crates.io"));
        let quic_ok = build_quic_initial_packet(&dcid, &allowed_hs);
        let udp_ok = build_ipv4_udp([1, 2, 3, 4], [10, 0, 0, 2], 40000, 443, &quic_ok);
        assert_eq!(evaluate_inbound_sni(&udp_ok, true), SniDecision::Allow);

        let bad_hs = build_client_hello_hs(Some("evil-sni.example.com"));
        let quic_bad = build_quic_initial_packet(&dcid, &bad_hs);
        let udp_bad = build_ipv4_udp([8, 8, 4, 4], [10, 0, 0, 2], 40001, 443, &quic_bad);
        assert!(matches!(
            evaluate_inbound_sni(&udp_bad, false),
            SniDecision::Block { reason: "disallowed_sni", sni: Some(ref s), proto: 17, dport: 443, .. } if s == "evil-sni.example.com"
        ));

        let no_sni_hs = build_client_hello_hs(None);
        let quic_no_sni = build_quic_initial_packet(&dcid, &no_sni_hs);
        let udp_no_sni = build_ipv4_udp([1, 2, 3, 4], [10, 0, 0, 2], 40002, 443, &quic_no_sni);
        assert_eq!(evaluate_inbound_sni(&udp_no_sni, false), SniDecision::Allow);
        assert!(matches!(
            evaluate_inbound_sni(&udp_no_sni, true),
            SniDecision::Block { reason: "missing_or_invalid_sni_cn", sni: None, proto: 17, .. }
        ));
    }
}
