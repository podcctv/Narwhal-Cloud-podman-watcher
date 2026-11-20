use crate::*;

// ---------------------------------------------------------------------------
// 9. tc qdisc / filter application, removal, & rollback
// ---------------------------------------------------------------------------

pub fn ensure_clsact<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    let (code, listing) =
        call_with_prefix(runner, prefix, &["tc", "qdisc", "show", "dev", interface]);
    if code == 0 && contains_word(&listing, "clsact") {
        return Ok(());
    }
    let (add_code, message) =
        call_with_prefix(runner, prefix, &["tc", "qdisc", "add", "dev", interface, "clsact"]);
    if add_code != 0 {
        let (re_code, re_listing) =
            call_with_prefix(runner, prefix, &["tc", "qdisc", "show", "dev", interface]);
        if re_code != 0 || !contains_word(&re_listing, "clsact") {
            let reason = if message.is_empty() {
                "tc failed"
            } else {
                message.as_str()
            };
            return Err(BandwidthError::policy(format!(
                "cannot add an agent-managed clsact qdisc: {}",
                truncate_chars(reason, 240)
            )));
        }
    }
    Ok(())
}

pub(crate) fn filter_listing<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    direction: Direction,
    runner: &mut R,
) -> Result<String, BandwidthError> {
    let (code, listing) = call_with_prefix(
        runner,
        prefix,
        &[
            "tc",
            "filter",
            "show",
            "dev",
            interface,
            direction.tc_direction(),
        ],
    );
    if code != 0 {
        return Err(BandwidthError::policy(
            "cannot verify existing filters on interface",
        ));
    }
    Ok(listing)
}

pub fn apply_filter<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    owner_key: &str,
    direction: Direction,
    rate_mbps: u32,
    previously_owned: bool,
    preferred_pref: Option<u16>,
    runner: &mut R,
) -> Result<u16, BandwidthError> {
    let handle = filter_handle(owner_key, direction);
    ensure_clsact(prefix, interface, runner)?;
    let mut listing = filter_listing(prefix, interface, direction, runner)?;
    let owned_pref = filter_preference(&listing, &handle);
    if owned_pref.is_some() && !previously_owned {
        return Err(BandwidthError::policy(
            "reserved filter identity already exists; left unchanged",
        ));
    }
    let mut pref = owned_pref.unwrap_or_else(|| {
        next_free_preference(
            &listing,
            direction,
            Some(preferred_pref.unwrap_or_else(|| direction.default_pref())),
        )
    });
    if pref == 0 {
        return Err(BandwidthError::policy(
            "no free tc filter priority is available on this interface",
        ));
    }

    for _attempt in 0..5 {
        let replacing_owned = previously_owned && owned_pref == Some(pref);
        let verb = if replacing_owned { "change" } else { "add" };
        let cmd = build_tc_filter_command(
            prefix,
            interface,
            direction,
            verb,
            pref,
            &handle,
            rate_mbps,
        );
        let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let (code, message) = runner.run_cmd(&refs, DEFAULT_OUTPUT_LIMIT);
        if code == 0 {
            let verified = filter_listing(prefix, interface, direction, runner)?;
            if !filter_has_police_action(&verified, &handle, pref, Some(rate_mbps)) {
                return Err(BandwidthError::policy(format!(
                    "bandwidth policer readback did not confirm {rate_mbps} Mbps at priority {pref}"
                )));
            }
            return Ok(pref);
        }
        let msg_lower = message.to_ascii_lowercase();
        if replacing_owned && msg_lower.contains("file exists") {
            let verified = filter_listing(prefix, interface, direction, runner)?;
            if filter_has_police_action(&verified, &handle, pref, Some(rate_mbps)) {
                return Ok(pref);
            }
            let detail = if message.is_empty() {
                "tc failed"
            } else {
                message.as_str()
            };
            return Err(BandwidthError::policy(format!(
                "owned bandwidth filter change failed at priority {pref}; readback did not confirm {rate_mbps} Mbps: {}",
                truncate_chars(detail, 180)
            )));
        }
        if verb == "add" && msg_lower.contains("file exists") {
            listing = filter_listing(prefix, interface, direction, runner)?;
            if filter_preference(&listing, &handle).is_some() {
                return Err(BandwidthError::policy(
                    "filter identity appeared during apply; left unchanged",
                ));
            }
            let next_preferred = if pref < PREF_RANGE_END {
                Some(pref + 1)
            } else {
                None
            };
            pref = next_free_preference(&listing, direction, next_preferred);
            if pref != 0 {
                continue;
            }
            return Err(BandwidthError::policy(
                "no free tc filter priority is available on this interface",
            ));
        }
        let detail = if message.is_empty() {
            "tc failed"
        } else {
            message.as_str()
        };
        return Err(BandwidthError::policy(format!(
            "bandwidth policer was not confirmed (tc filter {verb}, priority {pref}, {}): {}",
            direction.as_str(),
            truncate_chars(detail, 200)
        )));
    }

    Err(BandwidthError::policy(
        "tc filter priorities kept colliding; no foreign filter was changed",
    ))
}

pub fn remove_filter<R: TcRunner>(
    prefix: &[String],
    interface: &str,
    owner_key: &str,
    direction: Direction,
    preferred_pref: Option<u16>,
    runner: &mut R,
) -> Result<bool, BandwidthError> {
    let handle = filter_handle(owner_key, direction);
    let listing = filter_listing(prefix, interface, direction, runner)?;
    let pref = preferred_pref
        .filter(|&p| filter_present(&listing, &handle, p))
        .or_else(|| filter_preference(&listing, &handle));
    let Some(pref) = pref else {
        return Ok(false);
    };
    let cmd = build_tc_filter_del_command(prefix, interface, direction, pref, &handle);
    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let (code, message) = runner.run_cmd(&refs, DEFAULT_OUTPUT_LIMIT);
    if code != 0 {
        let detail = if message.is_empty() {
            "tc failed"
        } else {
            message.as_str()
        };
        return Err(BandwidthError::policy(format!(
            "owned bandwidth filter could not be removed: {}",
            truncate_chars(detail, 240)
        )));
    }
    let after = filter_listing(prefix, interface, direction, runner)?;
    if filter_present(&after, &handle, pref) {
        return Err(BandwidthError::policy(
            "owned bandwidth filter remains after removal",
        ));
    }
    Ok(true)
}

#[derive(Debug, Clone)]
pub(crate) struct RollbackOperation {
    pub(crate) prefix: Vec<String>,
    pub(crate) interface: String,
    pub(crate) owner_key: String,
    pub(crate) direction: Direction,
    pub(crate) previously_owned: bool,
    pub(crate) previous_rate_mbps: Option<u32>,
    pub(crate) previous_pref: Option<u16>,
}

pub(crate) fn rollback_bandwidth_mutation<R: TcRunner>(
    op: &RollbackOperation,
    runner: &mut R,
) -> Result<(), BandwidthError> {
    if op.previously_owned {
        let rate = op.previous_rate_mbps.unwrap_or(0);
        if rate == 0 {
            return Err(BandwidthError::policy(
                "previous owned tc rate is unavailable; rollback cannot be verified",
            ));
        }
        apply_filter(
            &op.prefix,
            &op.interface,
            &op.owner_key,
            op.direction,
            rate,
            true,
            op.previous_pref,
            runner,
        )?;
        return Ok(());
    }
    let _ = remove_filter(
        &op.prefix,
        &op.interface,
        &op.owner_key,
        op.direction,
        None,
        runner,
    )?;
    Ok(())
}

