#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const MAX_METADATA_SEARCH: usize = 128 * 1024;
const MAX_POINTER_DEPTH: usize = 16;

static DB_CACHE: OnceLock<Mutex<Option<(String, MmdbDb)>>> = OnceLock::new();

#[derive(Clone)]
pub struct MmdbDb {
    data: Vec<u8>,
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    node_byte_size: usize,
    search_tree_size: usize,
    data_section_start: usize,
    ipv4_start_node: u32,
}

impl MmdbDb {
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        let search_start = data.len().saturating_sub(MAX_METADATA_SEARCH);
        let marker_pos = data[search_start..]
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .map(|p| search_start + p)
            .ok_or_else(|| "missing MaxMind metadata marker".to_string())?;
        let meta_start = marker_pos + METADATA_MARKER.len();
        let (node_count, record_size, ip_version) = parse_metadata(&data, meta_start)?;
        if !matches!(record_size, 24 | 28 | 32) {
            return Err(format!("unsupported record_size: {record_size}"));
        }
        if !matches!(ip_version, 4 | 6) {
            return Err(format!("unsupported ip_version: {ip_version}"));
        }
        let node_byte_size = (record_size as usize * 2) / 8;
        let search_tree_size = (node_count as usize)
            .checked_mul(node_byte_size)
            .ok_or_else(|| "search_tree_size overflow".to_string())?;
        let data_section_start = search_tree_size
            .checked_add(16)
            .ok_or_else(|| "data_section_start overflow".to_string())?;
        if data_section_start > marker_pos {
            return Err("invalid MMDB: search tree exceeds file size".to_string());
        }

        let mut db = Self {
            data,
            node_count,
            record_size,
            ip_version,
            node_byte_size,
            search_tree_size,
            data_section_start,
            ipv4_start_node: 0,
        };
        if ip_version == 6 {
            let mut node = 0u32;
            for _ in 0..96 {
                if node >= db.node_count {
                    break;
                }
                node = db.read_record(node, 0)?;
            }
            db.ipv4_start_node = node;
        }
        Ok(db)
    }

    fn read_record(&self, node: u32, bit: u8) -> Result<u32, String> {
        let offset = (node as usize)
            .checked_mul(self.node_byte_size)
            .ok_or_else(|| "node offset overflow".to_string())?;
        let end = offset + self.node_byte_size;
        let rec = self
            .data
            .get(offset..end)
            .ok_or_else(|| "node offset out of bounds".to_string())?;
        let val = match self.record_size {
            24 => {
                if bit == 0 {
                    u32::from_be_bytes([0, rec[0], rec[1], rec[2]])
                } else {
                    u32::from_be_bytes([0, rec[3], rec[4], rec[5]])
                }
            }
            28 => {
                let mid = rec[3] as u32;
                if bit == 0 {
                    ((mid >> 4) << 24) | u32::from_be_bytes([0, rec[0], rec[1], rec[2]])
                } else {
                    ((mid & 0x0f) << 24) | u32::from_be_bytes([0, rec[4], rec[5], rec[6]])
                }
            }
            32 => {
                if bit == 0 {
                    u32::from_be_bytes([rec[0], rec[1], rec[2], rec[3]])
                } else {
                    u32::from_be_bytes([rec[4], rec[5], rec[6], rec[7]])
                }
            }
            _ => return Err("unsupported record_size".to_string()),
        };
        Ok(val)
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => {
                let start = if self.ip_version == 6 {
                    self.ipv4_start_node
                } else {
                    0
                };
                if start == self.node_count {
                    return None;
                }
                if start > self.node_count {
                    let offset = self.search_tree_size + (start as usize - self.node_count as usize);
                    return extract_country_iso(&self.data, self.data_section_start, offset);
                }
                self.lookup_bits(start, &v4.octets())
            }
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        return self.lookup_bits(0, &v4.octets());
                    }
                    return None;
                }
                self.lookup_bits(0, &v6.octets())
            }
        }
    }

    fn lookup_bits(&self, mut node: u32, bytes: &[u8]) -> Option<String> {
        for &byte in bytes {
            for shift in (0..8).rev() {
                let bit = (byte >> shift) & 1;
                node = self.read_record(node, bit).ok()?;
                if node == self.node_count {
                    return None;
                }
                if node > self.node_count {
                    let offset = self.search_tree_size + (node as usize - self.node_count as usize);
                    return extract_country_iso(&self.data, self.data_section_start, offset);
                }
            }
        }
        None
    }
}

fn read_control_header(
    data: &[u8],
    data_section_start: usize,
    pos: usize,
) -> Result<(u8, usize, usize), String> {
    let ctrl = *data.get(pos).ok_or_else(|| "unexpected EOF".to_string())?;
    let mut cur = pos + 1;
    let mut dtype = ctrl >> 5;
    if dtype == 0 {
        let ext = *data
            .get(cur)
            .ok_or_else(|| "unexpected EOF in extended type".to_string())?;
        cur += 1;
        dtype = 7 + ext;
    }
    if dtype == 1 {
        let ptr_size = ((ctrl >> 3) & 0x03) + 1;
        let val_bits = (ctrl & 0x07) as usize;
        let ptr = match ptr_size {
            1 => {
                let b0 = *data.get(cur).ok_or_else(|| "EOF in ptr1".to_string())? as usize;
                cur += 1;
                (val_bits << 8) | b0
            }
            2 => {
                let b = data.get(cur..cur + 2).ok_or_else(|| "EOF in ptr2".to_string())?;
                cur += 2;
                ((val_bits << 16) | ((b[0] as usize) << 8) | (b[1] as usize)) + 2048
            }
            3 => {
                let b = data.get(cur..cur + 3).ok_or_else(|| "EOF in ptr3".to_string())?;
                cur += 3;
                ((val_bits << 24)
                    | ((b[0] as usize) << 16)
                    | ((b[1] as usize) << 8)
                    | (b[2] as usize))
                    + 526_336
            }
            4 => {
                let b = data.get(cur..cur + 4).ok_or_else(|| "EOF in ptr4".to_string())?;
                cur += 4;
                ((b[0] as usize) << 24)
                    | ((b[1] as usize) << 16)
                    | ((b[2] as usize) << 8)
                    | (b[3] as usize)
            }
            _ => unreachable!(),
        };
        return Ok((1, data_section_start + ptr, cur));
    }
    if dtype == 14 {
        let bval = (ctrl & 0x1f) as usize;
        return Ok((14, bval, cur));
    }
    let size_bits = (ctrl & 0x1f) as usize;
    let size = match size_bits {
        0..=28 => size_bits,
        29 => {
            let b0 = *data.get(cur).ok_or_else(|| "EOF in size29".to_string())? as usize;
            cur += 1;
            29 + b0
        }
        30 => {
            let b = data.get(cur..cur + 2).ok_or_else(|| "EOF in size30".to_string())?;
            cur += 2;
            285 + (((b[0] as usize) << 8) | (b[1] as usize))
        }
        31 => {
            let b = data.get(cur..cur + 3).ok_or_else(|| "EOF in size31".to_string())?;
            cur += 3;
            65_821 + (((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
        }
        _ => unreachable!(),
    };
    Ok((dtype, size, cur))
}

fn resolve_header(
    data: &[u8],
    data_section_start: usize,
    pos: usize,
    depth: usize,
) -> Result<(u8, usize, usize, usize), String> {
    let (dtype, val, next_after_ptr) = read_control_header(data, data_section_start, pos)?;
    if dtype == 1 {
        if depth >= MAX_POINTER_DEPTH {
            return Err("pointer recursion limit exceeded".to_string());
        }
        let (inner_type, inner_val, inner_cur, _) =
            resolve_header(data, data_section_start, val, depth + 1)?;
        Ok((inner_type, inner_val, inner_cur, next_after_ptr))
    } else {
        Ok((dtype, val, next_after_ptr, next_after_ptr))
    }
}

fn read_uint(data: &[u8], pos: usize, size: usize) -> Result<u64, String> {
    if size > 8 {
        return Err("uint size > 8".to_string());
    }
    let slice = data
        .get(pos..pos + size)
        .ok_or_else(|| "EOF in uint".to_string())?;
    let mut out = 0u64;
    for &b in slice {
        out = (out << 8) | (b as u64);
    }
    Ok(out)
}

fn read_utf8<'a>(
    data: &'a [u8],
    data_section_start: usize,
    pos: usize,
) -> Result<(&'a str, usize), String> {
    let (dtype, size, val_pos, next_pos) = resolve_header(data, data_section_start, pos, 0)?;
    if dtype != 2 {
        return Err(format!("expected utf8_string, got {dtype}"));
    }
    let slice = data
        .get(val_pos..val_pos + size)
        .ok_or_else(|| "EOF in utf8_string".to_string())?;
    let s = std::str::from_utf8(slice).map_err(|_| "invalid utf8".to_string())?;
    Ok((s, next_pos))
}

fn skip_value(
    data: &[u8],
    data_section_start: usize,
    pos: usize,
    depth: usize,
) -> Result<usize, String> {
    if depth >= 32 {
        return Err("MMDB nesting limit exceeded".to_string());
    }
    let (dtype, val, cur, next_after_ptr) = resolve_header(data, data_section_start, pos, 0)?;
    let _after_payload = match dtype {
        2 | 4 | 5 | 6 | 8 | 9 | 10 => cur + val,
        3 => cur + 8,
        15 => cur + 4,
        13 | 14 => cur,
        7 => {
            let mut p = cur;
            for _ in 0..val {
                p = skip_value(data, data_section_start, p, depth + 1)?;
                p = skip_value(data, data_section_start, p, depth + 1)?;
            }
            p
        }
        11 => {
            let mut p = cur;
            for _ in 0..val {
                p = skip_value(data, data_section_start, p, depth + 1)?;
            }
            p
        }
        _ => return Err(format!("unknown MMDB type {dtype}")),
    };
    if next_after_ptr != cur {
        Ok(next_after_ptr)
    } else {
        Ok(_after_payload)
    }
}

fn parse_metadata(data: &[u8], meta_start: usize) -> Result<(u32, u16, u16), String> {
    let (dtype, map_len, mut cur) = read_control_header(data, meta_start, meta_start)?;
    if dtype != 7 {
        return Err("MMDB metadata is not a map".to_string());
    }
    let mut node_count: Option<u32> = None;
    let mut record_size: Option<u16> = None;
    let mut ip_version: Option<u16> = None;

    for _ in 0..map_len {
        let (key, next_k) = read_utf8(data, meta_start, cur)?;
        cur = next_k;
        match key {
            "node_count" => {
                let (vt, vs, vp, next_v) = resolve_header(data, meta_start, cur, 0)?;
                if !matches!(vt, 5 | 6 | 9) {
                    return Err("invalid node_count type".to_string());
                }
                node_count = Some(read_uint(data, vp, vs)? as u32);
                cur = next_v + if next_v == vp { vs } else { 0 };
            }
            "record_size" => {
                let (vt, vs, vp, next_v) = resolve_header(data, meta_start, cur, 0)?;
                if !matches!(vt, 5 | 6 | 9) {
                    return Err("invalid record_size type".to_string());
                }
                record_size = Some(read_uint(data, vp, vs)? as u16);
                cur = next_v + if next_v == vp { vs } else { 0 };
            }
            "ip_version" => {
                let (vt, vs, vp, next_v) = resolve_header(data, meta_start, cur, 0)?;
                if !matches!(vt, 5 | 6 | 9) {
                    return Err("invalid ip_version type".to_string());
                }
                ip_version = Some(read_uint(data, vp, vs)? as u16);
                cur = next_v + if next_v == vp { vs } else { 0 };
            }
            _ => {
                cur = skip_value(data, meta_start, cur, 0)?;
            }
        }
    }
    Ok((
        node_count.ok_or_else(|| "missing node_count".to_string())?,
        record_size.ok_or_else(|| "missing record_size".to_string())?,
        ip_version.ok_or_else(|| "missing ip_version".to_string())?,
    ))
}

fn extract_country_iso(data: &[u8], data_section_start: usize, offset: usize) -> Option<String> {
    let (dtype, map_len, mut cur, _) = resolve_header(data, data_section_start, offset, 0).ok()?;
    if dtype != 7 {
        return None;
    }
    for _ in 0..map_len {
        let (key, next_k) = read_utf8(data, data_section_start, cur).ok()?;
        cur = next_k;
        if key == "country" {
            let (ct, clen, mut ccur, _) =
                resolve_header(data, data_section_start, cur, 0).ok()?;
            if ct == 7 {
                for _ in 0..clen {
                    let (ckey, next_ck) = read_utf8(data, data_section_start, ccur).ok()?;
                    ccur = next_ck;
                    if ckey == "iso_code" {
                        if let Ok((code, _)) = read_utf8(data, data_section_start, ccur) {
                            let trimmed = code.trim();
                            if trimmed.len() == 2 && trimmed.bytes().all(|b| b.is_ascii_alphabetic())
                            {
                                return Some(trimmed.to_ascii_uppercase());
                            }
                        }
                        return None;
                    } else {
                        ccur = skip_value(data, data_section_start, ccur, 0).ok()?;
                    }
                }
            }
            return None;
        } else {
            cur = skip_value(data, data_section_start, cur, 0).ok()?;
        }
    }
    None
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn lookup_countries(db_path: &Path, ips: &[String]) -> String {
    let path_str = db_path.to_string_lossy().to_string();
    let cache = DB_CACHE.get_or_init(|| Mutex::new(None));
    let db = {
        let mut guard = match cache.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let needs_load = match guard.as_ref() {
            Some((cached_path, _)) => cached_path != &path_str,
            None => true,
        };
        if needs_load {
            let bytes = match fs::read(db_path) {
                Ok(b) => b,
                Err(e) => {
                    return format!(
                        "{{\"available\":false,\"error\":{}}}",
                        json_escape(&format!("cannot read db: {e}"))
                    );
                }
            };
            let parsed = match MmdbDb::from_bytes(bytes) {
                Ok(d) => d,
                Err(e) => {
                    return format!(
                        "{{\"available\":false,\"error\":{}}}",
                        json_escape(&e)
                    );
                }
            };
            *guard = Some((path_str, parsed.clone()));
            parsed
        } else {
            guard.as_ref().unwrap().1.clone()
        }
    };

    let mut entries = String::new();
    let mut first = true;
    for raw_ip in ips {
        let trimmed = raw_ip.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(ip) = trimmed.parse::<IpAddr>() else {
            continue;
        };
        if let Some(code) = db.lookup_country(ip) {
            if !first {
                entries.push(',');
            }
            first = false;
            let _ = write!(entries, "{}:{}", json_escape(trimmed), json_escape(&code));
        }
    }
    format!("{{\"available\":true,\"countries\":{{{entries}}}}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_utf8(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let len = s.len();
        if len < 29 {
            out.push((2 << 5) | (len as u8));
        } else {
            out.push((2 << 5) | 29);
            out.push((len - 29) as u8);
        }
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn encode_uint(dtype: u8, val: u64) -> Vec<u8> {
        let bytes = val.to_be_bytes();
        let first_nz = bytes.iter().position(|&b| b != 0).unwrap_or(8);
        let slice = &bytes[first_nz..];
        let mut out = vec![(dtype << 5) | (slice.len() as u8)];
        out.extend_from_slice(slice);
        out
    }

    fn build_minimal_mmdb_v4_24bit() -> Vec<u8> {
        // 1 node (root): bit 0 -> data record (node_count + 16 + 0 = 17), bit 1 -> not found (1)
        let mut data_sec = Vec::new();
        // Record at offset 0: {"country": {"iso_code": "US"}}
        data_sec.push((7 << 5) | 1);
        data_sec.extend(encode_utf8("country"));
        data_sec.push((7 << 5) | 1);
        data_sec.extend(encode_utf8("iso_code"));
        data_sec.extend(encode_utf8("US"));

        let node_count: u32 = 1;
        let rec_left = node_count + 16; // offset 0 in data_sec
        let rec_right = node_count; // not found

        let mut buf = Vec::new();
        // 1 node of 24-bit records (6 bytes)
        buf.extend_from_slice(&rec_left.to_be_bytes()[1..4]);
        buf.extend_from_slice(&rec_right.to_be_bytes()[1..4]);
        // 16-byte zero separator
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&data_sec);
        buf.extend_from_slice(METADATA_MARKER);
        // Metadata map: 3 keys
        buf.push((7 << 5) | 3);
        buf.extend(encode_utf8("node_count"));
        buf.extend(encode_uint(6, 1));
        buf.extend(encode_utf8("record_size"));
        buf.extend(encode_uint(5, 24));
        buf.extend(encode_utf8("ip_version"));
        buf.extend(encode_uint(5, 4));
        buf
    }

    #[test]
    fn test_minimal_mmdb_lookup() {
        let bytes = build_minimal_mmdb_v4_24bit();
        let db = MmdbDb::from_bytes(bytes).expect("parse minimal mmdb");
        // 1.0.0.0 has first bit 0 -> US
        assert_eq!(
            db.lookup_country("1.2.3.4".parse().unwrap()).as_deref(),
            Some("US")
        );
        // 128.0.0.0 has first bit 1 -> None
        assert_eq!(db.lookup_country("128.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn test_pointer_resolution_in_country_record() {
        let mut data_sec = Vec::new();
        // Offset 0: "US"
        data_sec.extend(encode_utf8("US"));
        let us_len = data_sec.len();
        // Offset us_len: {"country": {"iso_code": <ptr to 0>}}
        data_sec.push((7 << 5) | 1);
        data_sec.extend(encode_utf8("country"));
        data_sec.push((7 << 5) | 1);
        data_sec.extend(encode_utf8("iso_code"));
        // 1-byte pointer to offset 0: (1 << 5) | 0, 0
        data_sec.push(1 << 5);
        data_sec.push(0);

        let mut buf = Vec::new();
        let rec_left = 1 + 16 + (us_len as u32);
        buf.extend_from_slice(&rec_left.to_be_bytes()[1..4]);
        buf.extend_from_slice(&1u32.to_be_bytes()[1..4]);
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&data_sec);
        buf.extend_from_slice(METADATA_MARKER);
        buf.push((7 << 5) | 3);
        buf.extend(encode_utf8("node_count"));
        buf.extend(encode_uint(6, 1));
        buf.extend(encode_utf8("record_size"));
        buf.extend(encode_uint(5, 24));
        buf.extend(encode_utf8("ip_version"));
        buf.extend(encode_uint(5, 4));

        let db = MmdbDb::from_bytes(buf).expect("parse ptr mmdb");
        assert_eq!(
            db.lookup_country("8.8.8.8".parse().unwrap()).as_deref(),
            Some("US")
        );
    }
}
