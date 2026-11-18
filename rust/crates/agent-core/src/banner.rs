use std::fmt::Write as _;
use crate::json_escape;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MotdDeliveryState {
    pub(crate) banner_hash: String,
    pub(crate) status: String,
    pub(crate) shell_delivery: String,
    pub(crate) ssh_banner_state: String,
    pub(crate) notice_ids: Vec<String>,
    pub(crate) error: String,
    pub(crate) updated_at: u64,
}

impl MotdDeliveryState {
    pub(crate) fn to_json(&self) -> String {
        let mut ids_json = String::from("[");
        for (i, id) in self.notice_ids.iter().enumerate() {
            if i > 0 {
                ids_json.push(',');
            }
            let _ = write!(ids_json, "\"{}\"", json_escape(id));
        }
        ids_json.push(']');
        format!(
            "{{\"status\":\"{}\",\"shell_delivery\":\"{}\",\"ssh_banner_state\":\"{}\",\"notice_ids\":{},\"updated_at\":{},\"error\":\"{}\"}}",
            json_escape(&self.status),
            json_escape(&self.shell_delivery),
            json_escape(&self.ssh_banner_state),
            ids_json,
            self.updated_at,
            json_escape(&self.error),
        )
    }
}


#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn fnv1a_hex(content: &str, notice_ids: &[String]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in content.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    for id in notice_ids {
        h ^= 0xff;
        for b in id.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    format!("{h:016x}")
}

pub fn build_shell_banner_install_script(content: &str) -> Option<String> {
    if content.is_empty() || content.len() > 32 * 1024 || content.contains('\0') {
        return None;
    }
    let marker = "# NARWHAL MANAGED INTERACTIVE BANNER v1";
    let hook = format!(
        "{marker}\n[ -t 0 ] && [ -r /etc/narwhal-banner.txt ] && cat /etc/narwhal-banner.txt 2>/dev/null || true\n"
    );
    let q_banner = abuse_guard::shlex_quote(&format!("{}\n", content.trim_end()));
    let q_hook = abuse_guard::shlex_quote(&hook);
    Some(format!(
        r#"set -eu
[ ! -L /etc/profile.d ]
mkdir -p /etc/profile.d
banner=/etc/narwhal-banner.txt
hook=/etc/profile.d/90-narwhal-banner.sh
if [ -e "$hook" ] && {{ [ ! -f "$hook" ] || ! grep -Fqx '{marker}' "$hook"; }}; then
  echo NARWHAL_SHELL_CONFLICT
  exit 1
fi
tmp_b=$(mktemp /etc/.narwhal-banner.XXXXXX)
tmp_h=$(mktemp /etc/profile.d/.narwhal-banner.XXXXXX)
printf '%s' {q_banner} > "$tmp_b"
printf '%s' {q_hook} > "$tmp_h"
chmod 644 "$tmp_b" "$tmp_h"
changed=0
if ! cmp -s "$tmp_b" "$banner" 2>/dev/null; then mv -f "$tmp_b" "$banner"; changed=1; else rm -f "$tmp_b"; fi
if ! cmp -s "$tmp_h" "$hook" 2>/dev/null; then mv -f "$tmp_h" "$hook"; changed=1; else rm -f "$tmp_h"; fi
echo "NARWHAL_SHELL_OK:$changed"
"#
    ))
}

pub fn build_ssh_banner_install_script(content: &str) -> Option<String> {
    if content.is_empty() || content.len() > 32 * 1024 || content.contains('\0') {
        return None;
    }
    let marker = "# NARWHAL MANAGED PREAUTH BANNER v1";
    let banner_content = format!("{marker}\n{}\n", content.trim_end());
    let dropin_content = format!("{marker}\nBanner /etc/ssh/narwhal-banner\n");
    let q_banner = abuse_guard::shlex_quote(&banner_content);
    let q_dropin = abuse_guard::shlex_quote(&dropin_content);
    Some(format!(
        r#"set -eu
cfg=/etc/ssh/sshd_config
dropdir=/etc/ssh/sshd_config.d
drop=/etc/ssh/sshd_config.d/90-narwhal-banner.conf
banner=/etc/ssh/narwhal-banner
sshd=$(command -v sshd 2>/dev/null || true)
[ -n "$sshd" ] || [ ! -x /usr/sbin/sshd ] || sshd=/usr/sbin/sshd
if [ -z "$sshd" ] || [ ! -f "$cfg" ] || [ ! -d "$dropdir" ]; then
  echo NARWHAL_SSH_BANNER_STATE=unsupported
  exit 0
fi
if ! awk '/^[[:space:]]*#/ {{next}} tolower($1)=="match" {{exit}} tolower($1)=="include" && $2 ~ /^\/etc\/ssh\/sshd_config\.d\/.*\.conf$/ {{found=1}} END {{exit !found}}' "$cfg"; then
  echo NARWHAL_SSH_BANNER_STATE=include_unavailable
  exit 0
fi
if grep -Eiq '^[[:space:]]*Banner[[:space:]]+' "$cfg"; then
  echo NARWHAL_SSH_BANNER_STATE=preserved_operator_config
  exit 0
fi
for f in "$dropdir"/*.conf; do
  [ -f "$f" ] || continue
  [ "$f" = "$drop" ] && continue
  if grep -Eiq '^[[:space:]]*Banner[[:space:]]+' "$f"; then
    echo NARWHAL_SSH_BANNER_STATE=preserved_operator_config
    exit 0
  fi
done
if [ -e "$drop" ] && {{ [ ! -f "$drop" ] || ! grep -Fqx '{marker}' "$drop"; }}; then
  echo NARWHAL_SSH_BANNER_STATE=dropin_conflict
  exit 0
fi
if [ -e "$banner" ] && {{ [ ! -f "$banner" ] || ! grep -Fqx '{marker}' "$banner"; }}; then
  echo NARWHAL_SSH_BANNER_STATE=banner_file_conflict
  exit 0
fi
tmp_banner=$(mktemp /etc/ssh/.narwhal-banner.XXXXXX)
tmp_drop=$(mktemp "$dropdir/.narwhal-banner.XXXXXX")
printf '%s' {q_banner} > "$tmp_banner"
printf '%s' {q_dropin} > "$tmp_drop"
chmod 644 "$tmp_banner" "$tmp_drop"
if cmp -s "$tmp_banner" "$banner" 2>/dev/null && cmp -s "$tmp_drop" "$drop" 2>/dev/null; then
  rm -f "$tmp_banner" "$tmp_drop"
  echo NARWHAL_SSH_BANNER_STATE=active
  exit 0
fi
mv -f "$tmp_banner" "$banner"
mv -f "$tmp_drop" "$drop"
if ! "$sshd" -t -f "$cfg"; then rm -f "$drop" "$banner"; echo NARWHAL_SSH_BANNER_STATE=config_invalid; exit 1; fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
elif command -v service >/dev/null 2>&1; then
  service ssh reload >/dev/null 2>&1 || service sshd reload >/dev/null 2>&1 || true
fi
echo NARWHAL_SSH_BANNER_STATE=active
"#
    ))
}

