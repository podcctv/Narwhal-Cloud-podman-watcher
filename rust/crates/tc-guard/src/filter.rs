use std::collections::BTreeSet;

use transport::sha256_hex;

use crate::*;

// ---------------------------------------------------------------------------
// 5. Deterministic tc filter handles, command generation, & readback parsing
// ---------------------------------------------------------------------------

/// Compute the deterministic 32-bit `tc` filter handle `"0x6" + sha256_hex(owner_key\0direction)[..7]`.
pub fn filter_handle_str(owner_key: &str, direction: &str) -> String {
    let mut input = Vec::with_capacity(owner_key.len() + 1 + direction.len());
    input.extend_from_slice(owner_key.as_bytes());
    input.push(0);
    input.extend_from_slice(direction.as_bytes());
    let digest = sha256_hex(&input);
    format!("0x6{}", &digest[..7])
}

/// Compute the deterministic `tc` filter handle for a typed `Direction`.
pub fn filter_handle(owner_key: &str, direction: Direction) -> String {
    filter_handle_str(owner_key, direction.as_str())
}

/// Build `tc filter <add|change>` arguments (plus optional `nsenter` prefix).
pub fn build_tc_filter_command(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    verb: &str,
    pref: u16,
    handle: &str,
    rate_mbps: u32,
) -> Vec<String> {
    let mut args = Vec::with_capacity(prefix.len() + 18);
    args.extend(prefix.iter().cloned());
    args.extend([
        "tc".to_string(),
        "filter".to_string(),
        verb.to_string(),
        "dev".to_string(),
        interface.to_string(),
        direction.tc_direction().to_string(),
        "protocol".to_string(),
        "all".to_string(),
        "pref".to_string(),
        pref.to_string(),
        "handle".to_string(),
        handle.to_string(),
        "matchall".to_string(),
        "action".to_string(),
        "police".to_string(),
        "rate".to_string(),
        format!("{rate_mbps}mbit"),
        "burst".to_string(),
        "256k".to_string(),
        "conform-exceed".to_string(),
        "drop".to_string(),
    ]);
    args
}

/// Build `tc filter del` arguments (plus optional `nsenter` prefix).
pub fn build_tc_filter_del_command(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    pref: u16,
    handle: &str,
) -> Vec<String> {
    let mut args = Vec::with_capacity(prefix.len() + 12);
    args.extend(prefix.iter().cloned());
    args.extend([
        "tc".to_string(),
        "filter".to_string(),
        "del".to_string(),
        "dev".to_string(),
        interface.to_string(),
        direction.tc_direction().to_string(),
        "protocol".to_string(),
        "all".to_string(),
        "pref".to_string(),
        pref.to_string(),
        "handle".to_string(),
        handle.to_string(),
    ]);
    args
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub(crate) fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let h = haystack.as_bytes();
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(word) {
        let idx = start + rel;
        let left_ok = idx == 0 || !is_word_char(h[idx - 1]);
        let end = idx + word.len();
        let right_ok = end == h.len() || !is_word_char(h[end]);
        if left_ok && right_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Split `tc filter show` output on `"filter protocol "` boundaries (keeping each marker).
pub fn split_filter_blocks(listing: &str) -> Vec<&str> {
    let marker = "filter protocol ";
    let mut starts = Vec::new();
    let mut offset = 0usize;
    while let Some(rel) = listing[offset..].find(marker) {
        let pos = offset + rel;
        starts.push(pos);
        offset = pos + marker.len();
    }
    if starts.is_empty() {
        return vec![listing];
    }
    let mut blocks = Vec::with_capacity(starts.len() + 1);
    if starts[0] > 0 {
        blocks.push(&listing[..starts[0]]);
    } else {
        blocks.push("");
    }
    for idx in 0..starts.len() {
        let begin = starts[idx];
        let end = starts.get(idx + 1).copied().unwrap_or(listing.len());
        blocks.push(&listing[begin..end]);
    }
    blocks
}

fn block_has_kv_token(block: &str, key: &str, expected_val: &str) -> bool {
    let bytes = block.as_bytes();
    let mut offset = 0usize;
    while let Some(rel) = block[offset..].find(key) {
        let idx = offset + rel;
        let left_ok = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut pos = idx + key.len();
        if left_ok && pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if block[pos..].starts_with(expected_val) {
                let val_end = pos + expected_val.len();
                if val_end == bytes.len() || !is_word_char(bytes[val_end]) {
                    return true;
                }
            }
        }
        offset = idx + 1;
    }
    false
}

fn find_all_prefs_in_text(text: &str) -> Vec<u16> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find("pref") {
        let idx = offset + rel;
        let left_ok = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut pos = idx + 4;
        if left_ok && pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let d_start = pos;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos > d_start && (pos == bytes.len() || !is_word_char(bytes[pos])) {
                if let Ok(pref) = text[d_start..pos].parse::<u32>() {
                    if (1..=65535).contains(&pref) {
                        out.push(pref as u16);
                    }
                }
            }
        }
        offset = idx + 1;
    }
    out
}

/// Parse `\brate\s+([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?bit(?:/s)?|[kmgt]?bps)\b` (case-insensitive) to Mbps.
pub fn parse_police_rate_mbps(block: &str) -> Option<f64> {
    let bytes = block.as_bytes();
    let mut i = 0usize;
    while i + 4 < bytes.len() {
        if (i == 0 || !is_word_char(bytes[i - 1]))
            && bytes[i..i + 4].eq_ignore_ascii_case(b"rate")
            && bytes[i + 4].is_ascii_whitespace()
        {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let num_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > num_start {
                if j + 1 < bytes.len() && bytes[j] == b'.' && bytes[j + 1].is_ascii_digit() {
                    j += 1;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                let num_end = j;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() {
                    let prefix_mult = match bytes[j].to_ascii_lowercase() {
                        b'k' => {
                            j += 1;
                            Some(1_000.0_f64)
                        }
                        b'm' => {
                            j += 1;
                            Some(1_000_000.0_f64)
                        }
                        b'g' => {
                            j += 1;
                            Some(1_000_000_000.0_f64)
                        }
                        b't' => {
                            j += 1;
                            Some(1_000_000_000_000.0_f64)
                        }
                        _ => None,
                    };
                    let mult = prefix_mult.unwrap_or(1.0);
                    let rest = &bytes[j..];
                    let unit_len = if rest.len() >= 3 && rest[..3].eq_ignore_ascii_case(b"bit") {
                        if rest.len() >= 5 && rest[3..5].eq_ignore_ascii_case(b"/s") {
                            Some(5)
                        } else {
                            Some(3)
                        }
                    } else if rest.len() >= 3 && rest[..3].eq_ignore_ascii_case(b"bps") {
                        Some(3)
                    } else {
                        None
                    };
                    if let Some(ulen) = unit_len {
                        let u_end = j + ulen;
                        if u_end == bytes.len() || !is_word_char(bytes[u_end]) {
                            if let Ok(val) = block[num_start..num_end].parse::<f64>() {
                                if val.is_finite() {
                                    return Some(val * mult / 1_000_000.0);
                                }
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

pub fn filter_present(listing: &str, handle: &str, pref: u16) -> bool {
    let pref_str = pref.to_string();
    for block in split_filter_blocks(listing) {
        if block_has_kv_token(block, "handle", handle)
            && block_has_kv_token(block, "pref", &pref_str)
        {
            return true;
        }
    }
    false
}

pub fn filter_has_police_action(
    listing: &str,
    handle: &str,
    pref: u16,
    rate_mbps: Option<u32>,
) -> bool {
    let pref_str = pref.to_string();
    for block in split_filter_blocks(listing) {
        if !(block_has_kv_token(block, "handle", handle)
            && block_has_kv_token(block, "pref", &pref_str)
            && block.contains("police"))
        {
            continue;
        }
        let Some(target_mbps) = rate_mbps else {
            return true;
        };
        if let Some(actual_mbps) = parse_police_rate_mbps(block) {
            let target_f = target_mbps as f64;
            let tol = 0.001_f64.max(target_f * 0.001);
            if (actual_mbps - target_f).abs() <= tol {
                return true;
            }
        }
    }
    false
}

pub fn filter_preference(listing: &str, handle: &str) -> Option<u16> {
    for block in split_filter_blocks(listing) {
        if !block_has_kv_token(block, "handle", handle) {
            continue;
        }
        if let Some(pref) = find_all_prefs_in_text(block).into_iter().next() {
            return Some(pref);
        }
    }
    None
}

pub fn occupied_preferences(listing: &str) -> BTreeSet<u16> {
    find_all_prefs_in_text(listing).into_iter().collect()
}

pub fn next_free_preference(listing: &str, direction: Direction, preferred: Option<u16>) -> u16 {
    let occupied = occupied_preferences(listing);
    let first = preferred
        .filter(|&p| (PREF_RANGE_START..PREF_RANGE_END).contains(&p))
        .unwrap_or_else(|| direction.default_pref());
    if !occupied.contains(&first) {
        return first;
    }
    for candidate in PREF_RANGE_START..PREF_RANGE_END {
        if candidate != first && !occupied.contains(&candidate) {
            return candidate;
        }
    }
    0
}

/// Extract field 22 (`starttime` ticks) from `/proc/<pid>/stat`, tolerating spaces/parens in `comm`.
pub fn parse_proc_start_ticks(raw: &str) -> Result<String, String> {
    let Some(close) = raw.rfind(')') else {
        return Err("malformed proc stat".to_string());
    };
    let after = &raw[close + 1..];
    let Some(value) = after.split_whitespace().nth(19) else {
        return Err("malformed proc stat".to_string());
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid proc start time".to_string());
    }
    Ok(value.to_string())
}
