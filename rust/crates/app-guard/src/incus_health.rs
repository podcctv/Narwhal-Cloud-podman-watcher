#![allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proc_probe::json_escape;
use runtime_drivers::JsonVal;
use crate::*;

use super::util::{
    bounded_env_f64, has_word_match, json_str, json_val_to_string, parse_iso8601_epoch,
    percent_decode, truncate_chars, JsonObjBuilder,
};

pub const INCUS_ALERT_TYPES: &[&str] = &[
    "incus_instance_error",
    "incus_lifecycle_operation_stuck",
    "incus_lifecycle_operation_unverified",
    "incus_api_unavailable",
    "incus_operation_inventory_unavailable",
    "incus_api_slow",
];

pub const DEFAULT_COMMAND_TIMEOUT_SECONDS: f64 = 8.0;
pub const DEFAULT_STUCK_OPERATION_SECONDS: f64 = 300.0;
pub const DEFAULT_SLOW_API_MILLISECONDS: f64 = 3000.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IncusHealthConfig {
    pub command_timeout_seconds: f64,
    pub stuck_operation_seconds: f64,
    pub slow_api_milliseconds: f64,
}

impl Default for IncusHealthConfig {
    fn default() -> Self {
        Self {
            command_timeout_seconds: DEFAULT_COMMAND_TIMEOUT_SECONDS,
            stuck_operation_seconds: DEFAULT_STUCK_OPERATION_SECONDS,
            slow_api_milliseconds: DEFAULT_SLOW_API_MILLISECONDS,
        }
    }
}

impl IncusHealthConfig {
    pub fn from_env() -> Self {
        Self {
            command_timeout_seconds: bounded_env_f64(
                "INCUS_HEALTH_COMMAND_TIMEOUT_SECONDS",
                DEFAULT_COMMAND_TIMEOUT_SECONDS,
                3.0,
                15.0,
            ),
            stuck_operation_seconds: bounded_env_f64(
                "INCUS_STUCK_OPERATION_SECONDS",
                DEFAULT_STUCK_OPERATION_SECONDS,
                60.0,
                3600.0,
            ),
            slow_api_milliseconds: bounded_env_f64(
                "INCUS_SLOW_API_MILLISECONDS",
                DEFAULT_SLOW_API_MILLISECONDS,
                500.0,
                10000.0,
            ),
        }
    }

    pub fn normalized(&self) -> Self {
        let finite = |v: f64, d: f64| if v.is_finite() { v } else { d };
        Self {
            command_timeout_seconds: finite(
                self.command_timeout_seconds,
                DEFAULT_COMMAND_TIMEOUT_SECONDS,
            )
            .clamp(3.0, 15.0),
            stuck_operation_seconds: finite(
                self.stuck_operation_seconds,
                DEFAULT_STUCK_OPERATION_SECONDS,
            )
            .clamp(60.0, 3600.0),
            slow_api_milliseconds: finite(
                self.slow_api_milliseconds,
                DEFAULT_SLOW_API_MILLISECONDS,
            )
            .clamp(500.0, 10000.0),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IncusScan {
    pub ok: bool,
    pub items: Vec<JsonVal>,
    pub latency_ms: f64,
    pub error: String,
}

impl IncusScan {
    pub fn unavailable(error: &str, latency_ms: f64) -> Self {
        Self {
            ok: false,
            items: Vec::new(),
            latency_ms: if latency_ms.is_finite() && latency_ms >= 0.0 {
                (latency_ms * 10.0).round() / 10.0
            } else {
                0.0
            },
            error: error.to_string(),
        }
    }

    /// Parse a `client/incus_health.py` scan envelope JSON (`{"ok":...,"items":[...],"latency_ms":...,"error":...}`).
    pub fn from_json(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Self::unavailable("not_checked", 0.0);
        }
        let Ok(val) = JsonVal::parse(trimmed) else {
            return Self::unavailable("invalid_json", 0.0);
        };
        let Some(obj) = val.as_obj() else {
            return Self::unavailable("not_checked", 0.0);
        };
        let ok = obj.get("ok").and_then(JsonVal::as_bool) == Some(true);
        let latency_ms = obj
            .get("latency_ms")
            .and_then(JsonVal::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0)
            .unwrap_or(0.0);
        let error = obj
            .get("error")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let items = if ok {
            obj.get("items")
                .and_then(JsonVal::as_arr)
                .map(|arr| arr.iter().filter(|x| x.as_obj().is_some()).cloned().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Self {
            ok,
            items,
            latency_ms,
            error,
        }
    }

    /// Parse raw `incus ... --format=json` CLI output matching `_run_json`.
    pub fn from_cli_output(
        exit_ok: bool,
        stdout: &str,
        latency_ms: f64,
        error_hint: &str,
    ) -> Self {
        let rounded = if latency_ms.is_finite() && latency_ms >= 0.0 {
            (latency_ms * 10.0).round() / 10.0
        } else {
            0.0
        };
        if !exit_ok {
            let err = if error_hint.is_empty() {
                "command_failed"
            } else {
                error_hint
            };
            return Self::unavailable(err, rounded);
        }
        let Ok(val) = JsonVal::parse(stdout.trim()) else {
            return Self::unavailable("invalid_json", rounded);
        };
        let Some(arr) = val.as_arr() else {
            return Self::unavailable("invalid_shape", rounded);
        };
        if arr.iter().any(|item| item.as_obj().is_none()) {
            return Self::unavailable("invalid_shape", rounded);
        }
        Self {
            ok: true,
            items: arr.to_vec(),
            latency_ms: rounded,
            error: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IncusSnapshotReport {
    pub status: String,
    pub scan_status: String,
    pub snapshot_json: String,
    pub health_json: String,
    pub operations_health_json: String,
    pub alerts_json: String,
    pub error_instance_count: usize,
    pub active_lifecycle_operation_count: usize,
    pub stuck_lifecycle_operation_count: usize,
}

fn all_projects(project: &str) -> bool {
    let trimmed = project.trim();
    trimmed.is_empty() || matches!(trimmed.to_ascii_lowercase().as_str(), "all" | "*")
}

fn instance_project(instance: &JsonVal, default_project: &str) -> String {
    let raw = instance
        .get_str("project")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(default_project);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

fn instance_name(instance: &JsonVal) -> String {
    instance
        .get_str("name")
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn instance_status(instance: &JsonVal) -> String {
    instance
        .get_str("status")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}

fn instance_uuid(instance: &JsonVal) -> String {
    let raw = instance
        .get("config")
        .and_then(|c| c.get_str("volatile.uuid"))
        .map(str::trim)
        .unwrap_or("");
    truncate_chars(raw, 100)
}

fn operation_is_running(operation: &JsonVal) -> bool {
    if operation
        .get_str("status")
        .map(|s| s.trim().eq_ignore_ascii_case("running"))
        == Some(true)
    {
        return true;
    }
    if operation.get_i64("status_code") == Some(103) {
        return true;
    }
    if operation
        .get_str("status_code")
        .and_then(|s| s.trim().parse::<i64>().ok())
        == Some(103)
    {
        return true;
    }
    false
}

pub fn incus_lifecycle_action(operation: &JsonVal) -> Option<&'static str> {
    let metadata = operation.get("metadata");
    let desc = operation.get_str("description").unwrap_or("");
    let m_action = metadata.and_then(|m| m.get_str("action")).unwrap_or("");
    let m_name = metadata.and_then(|m| m.get_str("name")).unwrap_or("");
    let combined = format!("{desc} {m_action} {m_name}").to_ascii_lowercase();

    if has_word_match(&combined, &["restart", "restarting", "reboot", "rebooting"]) {
        Some("restart")
    } else if has_word_match(&combined, &["stop", "stopping"]) {
        Some("stop")
    } else if has_word_match(&combined, &["start", "starting"]) {
        Some("start")
    } else if has_word_match(&combined, &["delete", "deleting", "remove", "removing"]) {
        Some("delete")
    } else {
        None
    }
}

pub fn parse_incus_created_epoch(raw: &str) -> Option<f64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    parse_iso8601_epoch(trimmed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationTarget {
    name: String,
    project: String,
}

fn extract_resource_urls(operation: &JsonVal) -> Vec<String> {
    let Some(resources) = operation.get("resources") else {
        return Vec::new();
    };
    let raw_val = resources
        .get("instances")
        .filter(|v| match v {
            JsonVal::Arr(a) => !a.is_empty(),
            JsonVal::Str(s) => !s.is_empty(),
            _ => false,
        })
        .or_else(|| resources.get("containers"));
    match raw_val {
        Some(JsonVal::Str(s)) => vec![s.clone()],
        Some(JsonVal::Arr(arr)) => arr
            .iter()
            .filter_map(JsonVal::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn operation_targets(operation: &JsonVal, default_project: &str) -> Vec<OperationTarget> {
    let mut targets = Vec::new();
    for resource in extract_resource_urls(operation) {
        let without_frag = resource.split('#').next().unwrap_or(&resource);
        let (path_and_auth, query) = without_frag
            .split_once('?')
            .unwrap_or((without_frag, ""));
        let path = if let Some((_, after_scheme)) = path_and_auth.split_once("://") {
            match after_scheme.find('/') {
                Some(idx) => &after_scheme[idx..],
                None => "",
            }
        } else {
            path_and_auth
        };
        let components: Vec<String> = path
            .split('/')
            .filter(|p| !p.is_empty())
            .map(|p| percent_decode(p, false))
            .collect();

        let mut name = String::new();
        for kind in ["instances", "containers"] {
            if let Some(pos) = components.iter().position(|c| c == kind) {
                if pos + 1 < components.len() {
                    name = components[pos + 1].clone();
                    break;
                }
            }
        }
        if name.is_empty() {
            continue;
        }
        let mut project = String::new();
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if percent_decode(k, true) == "project" {
                    let decoded = percent_decode(v, true);
                    if !decoded.is_empty() {
                        project = decoded;
                        break;
                    }
                }
            }
        }
        if project.is_empty() {
            project = default_project.to_string();
        }
        targets.push(OperationTarget {
            name: truncate_chars(&name, 200),
            project: truncate_chars(&project, 100),
        });
    }
    targets
}

enum ObsVal {
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
}

impl ObsVal {
    fn to_json(&self) -> String {
        match self {
            Self::Str(s) => json_str(s),
            Self::I64(v) => format!("{v}"),
            Self::U64(v) => format!("{v}"),
            Self::F64(v) => super::util::json_f64(*v),
            Self::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_alert_json(
    alert_type: &str,
    severity: &str,
    title: &str,
    message: &str,
    project: &str,
    name: &str,
    alert_key: &str,
    value: f64,
    threshold: f64,
    top_instance_id: Option<&str>,
    observation: Vec<(&str, ObsVal)>,
) -> String {
    let mut obs_buf = String::from("{");
    for (i, (k, v)) in observation.iter().enumerate() {
        if i > 0 {
            obs_buf.push(',');
        }
        obs_buf.push_str(&json_str(k));
        obs_buf.push(':');
        obs_buf.push_str(&v.to_json());
    }
    obs_buf.push('}');

    let mut b = JsonObjBuilder::new();
    b.str("type", alert_type);
    b.str("severity", severity);
    b.str("title", title);
    b.str("message", message);
    b.f64("value", value);
    b.f64("threshold", threshold);
    b.str("runtime", "incus");
    b.str("project", &truncate_chars(project, 100));
    b.str("container_name", &truncate_chars(name, 200));
    b.str("alert_key", &truncate_chars(alert_key, 240));
    b.raw("observation", &obs_buf);
    if let Some(inst_id) = top_instance_id {
        if !inst_id.is_empty() {
            b.str("instance_id", &truncate_chars(inst_id, 100));
        }
    }
    b.finish()
}

/// Build the Incus health snapshot, `operations.health` entry, and alerts JSON
/// matching `client/incus_health.py` and `client/operations.py`.
pub fn build_incus_snapshot(
    instance_scan: &IncusScan,
    operation_scan: &IncusScan,
    project: &str,
    now_epoch: f64,
    config: &IncusHealthConfig,
) -> IncusSnapshotReport {
    let cfg = config.normalized();
    let now = if now_epoch.is_finite() && now_epoch >= 0.0 {
        now_epoch
    } else {
        super::util::now_unix_secs() as f64
    };

    let instance_ok = instance_scan.ok;
    let operation_ok = operation_scan.ok;
    let scan_status = if instance_ok && operation_ok {
        "complete"
    } else if instance_ok || operation_ok {
        "partial"
    } else {
        "unavailable"
    };

    let selected_all = all_projects(project);
    let selected_project = if selected_all {
        ""
    } else {
        let trimmed = project.trim();
        if trimmed.is_empty() {
            "default"
        } else {
            trimmed
        }
    };

    let instances: Vec<&JsonVal> = if instance_ok {
        instance_scan
            .items
            .iter()
            .filter(|item| item.as_obj().is_some())
            .collect()
    } else {
        Vec::new()
    };

    let mut container_targets: BTreeSet<(String, String)> = BTreeSet::new();
    for inst in &instances {
        let name = instance_name(inst);
        if !name.is_empty() {
            container_targets.insert((instance_project(inst, "default"), name));
        }
    }

    let mut error_instances_json: Vec<String> = Vec::new();
    let mut alerts_json_items: Vec<String> = Vec::new();

    for inst in &instances {
        if instance_status(inst) != "error" {
            continue;
        }
        let name = instance_name(inst);
        if name.is_empty() {
            continue;
        }
        let item_project = instance_project(inst, "default");
        let identity = instance_uuid(inst);
        let pid_val = inst.get("state").and_then(|s| s.get("pid"));
        let pid_str = match pid_val {
            Some(JsonVal::Num(n)) if n.is_finite() => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Some(JsonVal::Str(s)) if !s.is_empty() => s.clone(),
            _ => "unknown".to_string(),
        };
        let raw_status = inst
            .get_str("status")
            .filter(|s| !s.is_empty())
            .unwrap_or("Error");

        let mut eb = JsonObjBuilder::new();
        eb.str("name", &name);
        eb.str("project", &item_project);
        eb.str("status", raw_status);
        match pid_val {
            Some(v) => eb.raw("pid", &json_val_to_string(v)),
            None => eb.raw("pid", "null"),
        }
        eb.str("instance_id", &identity);
        error_instances_json.push(eb.finish());

        let log_hint = if identity.is_empty() {
            "/var/log/incus/<instance-id>/lxc.log".to_string()
        } else {
            format!("/var/log/incus/{identity}/lxc.log")
        };
        let id_key = if identity.is_empty() {
            "unknown"
        } else {
            identity.as_str()
        };
        let pid_obs = match pid_val {
            Some(JsonVal::Num(n)) if n.is_finite() => {
                if n.fract() == 0.0 {
                    ObsVal::I64(*n as i64)
                } else {
                    ObsVal::F64(*n)
                }
            }
            Some(JsonVal::Str(s)) if !s.is_empty() => ObsVal::Str(s.clone()),
            _ => ObsVal::Str("unknown".to_string()),
        };

        alerts_json_items.push(build_alert_json(
            "incus_instance_error",
            "critical",
            "Incus 实例进入 ERROR，自动停止已暂停",
            &format!(
                "Incus 报告 {item_project}/{name} 状态为 ERROR（PID={pid_str}）。Watcher 不会再次提交 stop/restart/delete；保留实例现场并人工检查 {log_hint}、forkexec.log、控制台日志及对应 Incus 操作。"
            ),
            &item_project,
            &name,
            &format!("instance:{item_project}:{name}:{id_key}"),
            0.0,
            0.0,
            if identity.is_empty() {
                None
            } else {
                Some(identity.as_str())
            },
            vec![
                ("status", ObsVal::Str("error".to_string())),
                ("pid", pid_obs),
                ("instance_id", ObsVal::Str(identity.clone())),
                ("automatic_action", ObsVal::Str("alert_only".to_string())),
            ],
        ));
    }

    let operation_rows: Vec<&JsonVal> = if operation_ok {
        operation_scan
            .items
            .iter()
            .filter(|item| item.as_obj().is_some())
            .collect()
    } else {
        Vec::new()
    };

    let mut active_lifecycle_json: Vec<String> = Vec::new();
    let mut stuck_operations_json: Vec<String> = Vec::new();
    let stuck_after = cfg.stuck_operation_seconds;

    for op in &operation_rows {
        if !operation_is_running(op) {
            continue;
        }
        let Some(action) = incus_lifecycle_action(op) else {
            continue;
        };
        let default_proj = if selected_all {
            "default"
        } else {
            selected_project
        };
        let targets = operation_targets(op, default_proj);
        let matched_targets: Vec<OperationTarget> = targets
            .iter()
            .filter(|t| container_targets.contains(&(t.project.clone(), t.name.clone())))
            .cloned()
            .collect();
        if matched_targets.is_empty() && !targets.is_empty() {
            continue;
        }
        let created_raw = op.get_str("created_at").unwrap_or("");
        let created_epoch = parse_incus_created_epoch(created_raw).filter(|v| *v != 0.0);
        let age = created_epoch.map(|c| {
            let diff = now - c;
            if diff <= 0.0 {
                0u64
            } else {
                diff as u64
            }
        });
        let op_id = truncate_chars(
            op.get_str("id").filter(|s| !s.is_empty()).unwrap_or("unknown"),
            100,
        );
        let description = truncate_chars(
            op.get_str("description")
                .filter(|s| !s.is_empty())
                .unwrap_or(action),
            200,
        );
        let may_cancel = op.get_bool("may_cancel") == Some(true);
        let created_str = truncate_chars(created_raw, 80);

        let iter_targets = if matched_targets.is_empty() {
            vec![OperationTarget {
                name: String::new(),
                project: String::new(),
            }]
        } else {
            matched_targets
        };

        for target in iter_targets {
            let target_known = !target.name.is_empty();
            let mut sb = JsonObjBuilder::new();
            sb.str("id", &op_id);
            sb.str("name", &target.name);
            sb.str("project", &target.project);
            sb.str("action", action);
            sb.str("description", &description);
            sb.str("created_at", &created_str);
            match age {
                Some(a) => sb.u64("age_seconds", a),
                None => sb.raw("age_seconds", "null"),
            }
            sb.bool("may_cancel", may_cancel);
            sb.bool("target_known", target_known);
            let summary_json = sb.finish();
            active_lifecycle_json.push(summary_json.clone());

            let target_label = if target_known {
                format!("{}/{}", target.project, target.name)
            } else {
                "目标实例未知".to_string()
            };

            let Some(age_secs) = age else {
                alerts_json_items.push(build_alert_json(
                    "incus_lifecycle_operation_unverified",
                    "warning",
                    "Incus 生命周期操作时长无法核实",
                    &format!(
                        "Incus 操作 {op_id}（{description}）仍在运行，但创建时间缺失或无法解析，目标为 {target_label}。自动停止已暂停；先核对操作状态和实例日志。"
                    ),
                    &target.project,
                    &target.name,
                    &format!("operation:{op_id}:age-unknown"),
                    0.0,
                    0.0,
                    None,
                    vec![
                        ("operation_id", ObsVal::Str(op_id.clone())),
                        ("operation_action", ObsVal::Str(action.to_string())),
                        ("target_known", ObsVal::Bool(target_known)),
                        ("may_cancel", ObsVal::Bool(may_cancel)),
                    ],
                ));
                continue;
            };

            if (age_secs as f64) < stuck_after {
                continue;
            }
            stuck_operations_json.push(summary_json);
            let cancel_label = if may_cancel { "可取消" } else { "不可取消" };
            alerts_json_items.push(build_alert_json(
                "incus_lifecycle_operation_stuck",
                "critical",
                "Incus 实例状态变更操作长时间未完成",
                &format!(
                    "Incus 操作 {op_id}（{description}）已运行约 {age_secs} 秒，目标为 {target_label}，状态显示{cancel_label}。Watcher 不会重复提交停止/重启；不要用 operation delete 当作强制解锁，也不会自动重启 Incus 守护进程。"
                ),
                &target.project,
                &target.name,
                &format!("operation:{op_id}"),
                0.0,
                stuck_after,
                None,
                vec![
                    ("age_seconds", ObsVal::U64(age_secs)),
                    ("operation_id", ObsVal::Str(op_id.clone())),
                    ("operation_action", ObsVal::Str(action.to_string())),
                    ("may_cancel", ObsVal::Bool(may_cancel)),
                ],
            ));
        }
    }

    if !instance_ok {
        let cmd_status = if instance_scan.error.is_empty() {
            "unavailable"
        } else {
            instance_scan.error.as_str()
        };
        alerts_json_items.push(build_alert_json(
            "incus_api_unavailable",
            "warning",
            "Incus 实例状态读取失败",
            "Watcher 未能在限定时间内取得完整 Incus 容器清单；容器状态保持未知，已暂停本轮 Incus 自动停机判断。检查 incus CLI/守护进程和 systemd 状态。",
            "",
            "",
            "api:instances",
            0.0,
            0.0,
            None,
            vec![("command_status", ObsVal::Str(cmd_status.to_string()))],
        ));
    }

    if !operation_ok {
        let cmd_status = if operation_scan.error.is_empty() {
            "unavailable"
        } else {
            operation_scan.error.as_str()
        };
        alerts_json_items.push(build_alert_json(
            "incus_operation_inventory_unavailable",
            "warning",
            "Incus 后台操作清单读取失败",
            "Watcher 无法确认 Incus 是否已有启动、停止、重启或删除操作；本轮会暂停所有 Incus 自动停机，不会冒险重复提交。检查 Incus API 与 incus.service。",
            "",
            "",
            "api:operations",
            0.0,
            0.0,
            None,
            vec![("command_status", ObsVal::Str(cmd_status.to_string()))],
        ));
    }

    let inst_lat = if instance_scan.latency_ms.is_finite() && instance_scan.latency_ms >= 0.0 {
        instance_scan.latency_ms
    } else {
        0.0
    };
    let op_lat = if operation_scan.latency_ms.is_finite() && operation_scan.latency_ms >= 0.0 {
        operation_scan.latency_ms
    } else {
        0.0
    };

    for (label, scan_ok, latency) in [
        ("instances", instance_ok, inst_lat),
        ("operations", operation_ok, op_lat),
    ] {
        if scan_ok && latency >= cfg.slow_api_milliseconds {
            alerts_json_items.push(build_alert_json(
                "incus_api_slow",
                "warning",
                "Incus 管理 API 响应变慢",
                &format!(
                    "Incus {label} 查询耗时约 {latency:.0} ms。Watcher 只记录与告警，不会重启 Incus 服务。"
                ),
                "",
                "",
                &format!("api:slow:{label}"),
                0.0,
                cfg.slow_api_milliseconds,
                None,
                vec![
                    ("latency_ms", ObsVal::F64(latency)),
                    ("query", ObsVal::Str(label.to_string())),
                ],
            ));
        }
    }

    let status = if scan_status == "unavailable" {
        "unavailable"
    } else if !alerts_json_items.is_empty() {
        "degraded"
    } else if scan_status != "complete" {
        "partial"
    } else {
        "healthy"
    };

    let error_count = error_instances_json.len();
    let active_count = active_lifecycle_json.len();
    let stuck_count = stuck_operations_json.len();

    let bounded_error_instances = format!(
        "[{}]",
        error_instances_json
            .into_iter()
            .take(100)
            .collect::<Vec<_>>()
            .join(",")
    );
    let bounded_active_ops = format!(
        "[{}]",
        active_lifecycle_json
            .into_iter()
            .take(100)
            .collect::<Vec<_>>()
            .join(",")
    );
    let bounded_stuck_ops = format!(
        "[{}]",
        stuck_operations_json
            .into_iter()
            .take(100)
            .collect::<Vec<_>>()
            .join(",")
    );
    let alerts_json = format!(
        "[{}]",
        alerts_json_items
            .into_iter()
            .take(200)
            .collect::<Vec<_>>()
            .join(",")
    );

    let mut lat_b = JsonObjBuilder::new();
    lat_b.f64("instances", inst_lat);
    lat_b.f64("operations", op_lat);
    let latency_obj_json = lat_b.finish();

    let mut snap = JsonObjBuilder::new();
    snap.str("status", status);
    snap.str("scan_status", scan_status);
    snap.i64("observed_at", now as i64);
    snap.str(
        "project_scope",
        if selected_all {
            "all"
        } else {
            selected_project
        },
    );
    snap.usize("instance_count", instances.len());
    snap.usize("error_instance_count", error_count);
    snap.raw("error_instances", &bounded_error_instances);
    snap.usize("operation_count", operation_rows.len());
    snap.usize("active_lifecycle_operation_count", active_count);
    snap.usize("stuck_lifecycle_operation_count", stuck_count);
    snap.raw("active_lifecycle_operations", &bounded_active_ops);
    snap.raw("stuck_lifecycle_operations", &bounded_stuck_ops);
    snap.raw("api_latency_ms", &latency_obj_json);
    snap.f64("command_timeout_seconds", cfg.command_timeout_seconds);
    snap.f64("stuck_operation_threshold_seconds", stuck_after);
    snap.raw(
        "automatic_recovery",
        "{\"error_instance\":\"alert_only\",\"duplicate_lifecycle_actions\":\"blocked\",\"incus_daemon_restart\":\"manual_only\"}",
    );
    snap.raw("alerts", &alerts_json);
    let snapshot_json = snap.finish();

    let ops_health_status = if status == "healthy" && scan_status == "complete" {
        "healthy"
    } else if scan_status == "unavailable" {
        "unavailable"
    } else {
        "warning"
    };

    let mut det = JsonObjBuilder::new();
    det.str("scan_status", scan_status);
    det.usize("instances", instances.len());
    det.usize("error_instances", error_count);
    det.usize("active_lifecycle_operations", active_count);
    det.usize("stuck_lifecycle_operations", stuck_count);
    det.raw("api_latency_ms", &latency_obj_json);
    let details_json = det.finish();

    let mut oh = JsonObjBuilder::new();
    oh.str("source", "incus_runtime");
    oh.str("status", ops_health_status);
    oh.raw("details", &details_json);
    oh.str(
        "guidance",
        "状态变更异常仅告警并保留现场；先核对实例日志和 Incus 操作，不重复停止，不自动重启 Incus 守护进程。",
    );
    let operations_health_json = oh.finish();

    IncusSnapshotReport {
        status: status.to_string(),
        scan_status: scan_status.to_string(),
        health_json: snapshot_json.clone(),
        snapshot_json,
        operations_health_json,
        alerts_json,
        error_instance_count: error_count,
        active_lifecycle_operation_count: active_count,
        stuck_lifecycle_operation_count: stuck_count,
    }
}

/// Build Incus runtime snapshot JSON matching `client/incus_health.py::build_snapshot`.
pub fn build_incus_snapshot_json(
    instance_scan_json: &str,
    operation_scan_json: &str,
    project: &str,
    now_epoch: f64,
) -> String {
    let inst = IncusScan::from_json(instance_scan_json);
    let ops = IncusScan::from_json(operation_scan_json);
    let cfg = IncusHealthConfig::from_env();
    build_incus_snapshot(&inst, &ops, project, now_epoch, &cfg).snapshot_json
}

/// Build both `(operations_health_json, alerts_json)` from raw scan inputs.
pub fn build_incus_health_and_alerts_json(
    instance_scan_json: &str,
    operation_scan_json: &str,
    project: &str,
    now_epoch: f64,
) -> (String, String) {
    let inst = IncusScan::from_json(instance_scan_json);
    let ops = IncusScan::from_json(operation_scan_json);
    let cfg = IncusHealthConfig::from_env();
    let report = build_incus_snapshot(&inst, &ops, project, now_epoch, &cfg);
    (report.operations_health_json, report.alerts_json)
}

/// Build the `operations.health` `"incus_runtime"` object matching `client/operations.py`.
pub fn build_incus_operations_health_json(snapshot_json: &str) -> String {
    let Ok(val) = JsonVal::parse(snapshot_json) else {
        return String::new();
    };
    let Some(obj) = val.as_obj() else {
        return String::new();
    };
    let scan_status = obj
        .get("scan_status")
        .and_then(JsonVal::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");
    let runtime_status = obj
        .get("status")
        .and_then(JsonVal::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");
    let health_status = if runtime_status == "healthy" && scan_status == "complete" {
        "healthy"
    } else if scan_status == "unavailable" {
        "unavailable"
    } else {
        "warning"
    };

    let api_latency_raw = obj
        .get("api_latency_ms")
        .filter(|v| v.as_obj().is_some())
        .map(json_val_to_string)
        .unwrap_or_else(|| "{}".to_string());

    let mut det = JsonObjBuilder::new();
    det.str("scan_status", scan_status);
    det.i64(
        "instances",
        obj.get("instance_count").and_then(JsonVal::as_i64).unwrap_or(0),
    );
    det.i64(
        "error_instances",
        obj.get("error_instance_count")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0),
    );
    det.i64(
        "active_lifecycle_operations",
        obj.get("active_lifecycle_operation_count")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0),
    );
    det.i64(
        "stuck_lifecycle_operations",
        obj.get("stuck_lifecycle_operation_count")
            .and_then(JsonVal::as_i64)
            .unwrap_or(0),
    );
    det.raw("api_latency_ms", &api_latency_raw);

    let mut oh = JsonObjBuilder::new();
    oh.str("source", "incus_runtime");
    oh.str("status", health_status);
    oh.raw("details", &det.finish());
    oh.str(
        "guidance",
        "状态变更异常仅告警并保留现场；先核对实例日志和 Incus 操作，不重复停止，不自动重启 Incus 守护进程。",
    );
    oh.finish()
}

/// Pure fail-closed preflight matching `client/incus_health.py::stop_preflight`.
pub fn evaluate_incus_stop_preflight(
    instance_scan: &IncusScan,
    operation_scan: &IncusScan,
    project: &str,
    name: &str,
    config: &IncusHealthConfig,
) -> Result<(), String> {
    let cfg = config.normalized();
    let proj = {
        let p = project.trim();
        if p.is_empty() {
            "default"
        } else {
            p
        }
    };
    let target_name = name.trim();
    if all_projects(proj) || target_name.is_empty() {
        return Err("Incus stop skipped: exact project and instance identity are required".to_string());
    }
    if !instance_scan.ok {
        return Err("Incus stop skipped: current instance state could not be verified".to_string());
    }
    if instance_scan.latency_ms >= cfg.slow_api_milliseconds {
        return Err("Incus stop skipped: instance query is slow; leave lifecycle state untouched".to_string());
    }
    let matches: Vec<&JsonVal> = instance_scan
        .items
        .iter()
        .filter(|item| instance_name(item) == target_name)
        .collect();
    if matches.len() != 1 {
        return Err("Incus stop skipped: the exact instance could not be identified".to_string());
    }
    let instance = matches[0];
    let kind = instance
        .get_str("type")
        .unwrap_or("container")
        .to_ascii_lowercase();
    if !matches!(kind.as_str(), "container" | "") {
        return Err("Incus stop skipped: target is not a container".to_string());
    }
    if instance_status(instance) != "running" {
        let st = instance.get_str("status").unwrap_or("unknown");
        return Err(format!(
            "Incus stop skipped: target state is {st}; no repeated stop submitted"
        ));
    }

    if !operation_scan.ok {
        return Err("Incus stop skipped: pending lifecycle operations could not be checked".to_string());
    }
    if operation_scan.latency_ms >= cfg.slow_api_milliseconds {
        return Err("Incus stop skipped: operation query is slow; leave lifecycle state untouched".to_string());
    }
    for op in &operation_scan.items {
        if !operation_is_running(op) || incus_lifecycle_action(op).is_none() {
            continue;
        }
        let targets = operation_targets(op, proj);
        if targets.is_empty()
            || targets
                .iter()
                .any(|t| t.project == proj && t.name == target_name)
        {
            let op_id = op.get_str("id").filter(|s| !s.is_empty()).unwrap_or("unknown");
            return Err(format!(
                "Incus stop skipped: lifecycle operation {op_id} is already running for this target or has an unknown target"
            ));
        }
    }
    Ok(())
}
