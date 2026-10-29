"""Deterministic, evidence-based copy for end users; never invent remediation."""
import json
import math
import re
import time
import unicodedata

try:
    from server import connection_policy
except ImportError:
    import connection_policy


def clean(value, limit=500):
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value or ""))
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(c for c in text if unicodedata.category(c) not in {"Cc", "Cf"} or c == "\n")
    text = re.sub(r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2[已隐藏]", text)
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1[已隐藏]@", text)
    return text[:limit]


def loads(value):
    try:
        result = json.loads(value or "{}")
        return result if isinstance(result, dict) else {}
    except (TypeError, ValueError):
        return {}


def num(value):
    try:
        n = float(value)
        return min(n, 1e18) if math.isfinite(n) and n >= 0 else 0
    except (TypeError, ValueError):
        return 0


def fmt(value):
    return f"{num(value):,.1f}".removesuffix(".0")


def names(items):
    return "、".join(clean(v, 80) for v in items[:4] if isinstance(v, str) and v) if isinstance(items, list) else ""


def protocol_block_evidence(details, protocol):
    """Return endpoint facts only when the node confirms this protocol's block."""
    protocol = str(protocol or "").strip().lower()
    if protocol not in {"vmess", "trojan"}:
        return None
    guard = details.get(f"{protocol}_guard") if isinstance(details, dict) else None
    if not isinstance(guard, dict) or guard.get("state") not in {"blocked", "partial"}:
        return None
    remediation = details.get("automatic_remediation")
    if not isinstance(remediation, dict) or remediation.get("attempted") is not True:
        return None
    # A fully-blocked notice is valid only when the Agent explicitly confirms
    # the firewall readback. Partial state may still carry individually
    # confirmed endpoints while other ports remain pending.
    if guard.get("state") == "blocked" and remediation.get("succeeded") is not True:
        return None
    raw = guard.get("blocked_endpoints")
    if not isinstance(raw, list) or not raw or len(raw) > 32:
        return None
    endpoints = []
    for item in raw:
        if not isinstance(item, dict):
            return None
        process = str(item.get("process") or "").lower()
        pid, port, proto = item.get("pid"), item.get("port"), str(item.get("proto") or "").lower()
        if (process not in {"xray", "v2ray", "sing-box"}
                or type(pid) is not int or not 1 < pid <= 4194304
                or type(port) is not int or not 1 <= port <= 65535
                or proto not in {"tcp", "udp"}):
            return None
        endpoints.append({"process": process, "pid": pid, "port": port, "proto": proto})
    endpoints = sorted({(e["process"], e["pid"], e["proto"], e["port"]) for e in endpoints})
    if not endpoints:
        return None
    return {
        "protocol": protocol,
        "state": guard["state"],
        "blocked_endpoints": [dict(process=p, pid=pid, proto=proto, port=port) for p, pid, proto, port in endpoints],
        "pending_count": len(guard.get("pending_endpoints", [])) if isinstance(guard.get("pending_endpoints"), list) else 0,
    }


def vmess_block_evidence(details):
    """Backward-compatible VMess evidence validator."""
    return protocol_block_evidence(details, "vmess")


def trojan_block_evidence(details):
    return protocol_block_evidence(details, "trojan")


METRICS = {
    "container_connection_count": ("连接数量达到保护观察线", "当前连接", "个", "这是连接数量保护信号，未关联到具体用户身份，不代表用户滥用；系统仅按预设策略保护实例。"),
    "socks_inbound_fanout": ("代理接入来源 IP 较多", "不同来源 IP", "个", "IP 数量不能证明账号共享、客户本人操作或恶意行为；可能来自正常用户、NAT、监控或扫描器。请结合连接状态和应用访问日志核查；本提醒不会自动处罚客户。"),
    "inbound_ip_fanout": ("容器接入来源 IP 较多", "不同来源 IP", "个", "IP 数量只是网络观测结果，不能证明客户本人操作或存在恶意行为；来源也可能是正常用户、NAT、监控或扫描器。请结合连接状态、访问日志和信誉记录核查；本提醒不会自动停容器或处罚客户。"),
    "ddos_bandwidth": ("收到的网络流量异常增大，可能存在攻击或业务流量突增", "下载速度", "Mbps", "请检查网络访问及业务情况；如影响正常使用，请发工单。"),
    "ddos_packets": ("短时间内收到大量网络数据，可能存在异常访问", "接收数据包", "个/秒", "请检查访问来源；如持续异常或影响正常使用，请发工单。"),
    "ddos_syn": ("容器未完成连接请求偏多或持续增加", "未完成连接", "个", "这是网络保护观测信号，不能单独证明攻击或客户行为；系统需要连续样本和内核队列信号佐证，不会据此自动封锁或处罚用户。"),
    "cc_total_rps": ("网站短时间内收到大量请求，可能存在异常访问或业务流量突增", "网站请求", "次/秒", "请检查访问记录，确认请求来源，并限制异常访问。"),
    "cc_single_ip": ("网站被同一来源频繁访问", "该来源请求", "次/秒", "请检查该来源的访问记录，并限制异常访问。"),
    "cc_4xx_ratio": ("网站无法正常处理的请求比例偏高", "无效请求比例", "%", "请检查访问记录、页面链接及接口设置。"),
    "http_5xx_ratio": ("网站处理请求时频繁出错，部分用户可能无法正常访问", "服务端错误比例", "%", "请检查网站程序、数据库和服务器资源。"),
    "web_scan": ("网站出现疑似敏感路径探测", "命中敏感路径规则", "次", "请保护网站后台，并检查访问记录。"),
    "http_abuse": ("同一来源反复访问失败，可能存在异常接口请求", "该来源失败请求", "次", "请检查访问记录，并加强后台及接口的访问限制。"),
    "port_scan": ("发现疑似探测服务器开放端口的访问", "不同被探测端口", "个", "请关闭不需要的端口，并检查防火墙设置。"),
    "vmess_block_release_unverified": ("VMess 端口恢复待核实", "待核实端口", "个", "旧端口阻断暂时保留；请联系管理员确认服务已停止后再恢复端口。"),
    "outbound_fanout": ("同时连接较多外部地址，需要确认是否为正常业务", "不同外部地址", "个", "请检查代理使用情况及后台程序。"),
    "outbound_sensitive_ports": ("需要重点关注的对外连接异常增多", "敏感端口连接", "个", "请检查发起连接的程序及用途。"),
    "outbound_bandwidth_abuse": ("对外发送流量明显偏高", "上传速度", "Mbps", "请核对上传、备份和代理任务，停止不需要的任务。"),
    "outbound_packet_abuse": ("短时间内对外发送大量网络数据", "发送数据包", "个/秒", "请检查后台程序及代理使用情况。"),
    "outbound_connection_churn": ("频繁建立新的对外连接", "新建连接", "次/秒", "请检查程序重试及连接目标。"),
    "outbound_connection_failures": ("对外连接频繁失败", "连接失败", "次/秒", "请检查目标地址、网络设置及程序重试情况。"),
    "udp_outbound_flood": ("对外发送 UDP 数据异常增多", "UDP 数据包", "个/秒", "请检查相关代理、游戏或网络程序。"),
    "process_fanout_abuse": ("同时运行的程序数量异常增多", "运行程序", "个", "请检查重复启动及后台任务，停止不需要的程序。"),
    "hy2_high_concurrency": ("Hysteria 2 代理同时连接较多", "UDP 并发连接", "个", "请检查账号共享、异常连接及代理参数。"),
}


def issue(alert, details):
    kind = alert.get("alert_type", alert.get("type", ""))
    obs = details.get("observation") or details
    if kind in {"vmess_port_blocked", "trojan_port_blocked"}:
        protocol = "vmess" if kind == "vmess_port_blocked" else "trojan"
        evidence = protocol_block_evidence(details, protocol)
        if evidence:
            runtime = clean(alert.get("runtime") or "容器", 40)
            project = clean(alert.get("project") or "default", 100)
            container = clean(alert.get("container_name") or "未命名", 120)
            instance_id = clean(details.get("instance_id") or "", 200)
            endpoints = evidence["blocked_endpoints"]
            targets = "；".join(
                f"{item['process']}（容器内 PID {item['pid']}）监听 {item['proto'].upper()}/{item['port']}"
                for item in endpoints
            )
            identity = f"容器 {runtime}/{project}/{container}"
            if instance_id:
                identity += f"（实例 ID {instance_id[:12]}）"
            facts = f"已确认 {identity} 内 {protocol.upper()} 进程及监听：{targets}；系统只在该容器网络命名空间阻断列出的协议/端口，没有停止进程、容器或其他端口。"
            if evidence["state"] == "partial" or evidence["pending_count"]:
                facts += f"另有 {protocol.upper()} 入口仍待核实，不能据此认为全部入口都已阻断。"
            if protocol == "vmess":
                advice = "这不是对您进行滥用定性。该端口已按平台策略限制；如需继续提供服务，建议迁移到 VLESS + Reality + Vision，并先确认新端口不会与其他业务冲突。"
            else:
                advice = "这不是对您进行滥用定性。请联系管理员核对端口策略；如需继续使用相关服务，请先确认替代端口不会与其他业务冲突。"
            return f"已按平台网络策略限制 {protocol.upper()} 入站", facts, advice
    if kind in {'inbound_source_blocked','tcp_concurrency_limited','admission_unverified'}:
        data=details.get('admission') or {}
        if kind=='inbound_source_blocked':
            sources='、'.join(clean(x.get('ip'),50) for x in data.get('sources',[])[:5])
            blocked='、'.join(clean(x,50) for x in list(data.get('blocked',{}))[:5])
            return '旧版来源数量规则曾拒绝新连接', f"旧版 Agent 当时按最多 5 个来源放行，并拒绝后续新增来源。放行来源：{sources or '详见管理面板'}；被拒绝来源：{blocked or '详见管理面板'}。来源 IP 数量不能证明恶意或客户违规；当前版本不会仅按来源数量封禁。", '这是历史处置记录，不代表当前仍在拦截。请结合业务访问日志核实；如有正常用户连接受影响，请联系管理员。'
        if kind=='tcp_concurrency_limited':
            return '服务器同时连接过多，已启用保护', f"TCP 当前 {fmt(data.get('tcp_connections'))} 条，新连接上限 500 条；最少限制 30 分钟，已追加 {fmt(data.get('extensions'))} 次。已有连接会自然回落；复查仍达到 500 条会再追加 30 分钟。", '请停止不需要的任务或异常连接；有效采样持续低于 500 条至少 2 分钟，且本轮期限已到，才会解除限制。'
        return '服务器网络保护需要管理员检查','当前无法确认采样或保护规则已生效；未将证据不足视为恢复。','请发工单，由管理员核查处理。'
    if kind=='pasarguard_node_removed':
        return '服务器发现禁止运行的 PasarGuard Node 服务', '已核实程序或镜像归属，具体清理结果见下方处理回执。', '请勿再次安装此服务；如有疑问，请发工单。'
    if kind == "speedtest_attempt_blocked":
        guard = details.get("speedtest_guard") if isinstance(details.get("speedtest_guard"), dict) else {}
        labels = {"ookla": "Ookla Speedtest", "cloudflare": "Cloudflare Speed Test", "fast": "FAST.com", "tcpquality": "TcpQuality / Lisaweb"}
        targets = []
        for item in guard.get("blocked_attempts", []) if isinstance(guard.get("blocked_attempts"), list) else []:
            if not isinstance(item, dict) or item.get("service") not in labels:
                continue
            target = clean(item.get("target"), 160)
            if target:
                targets.append(f"{labels[item['service']]}（{target}）")
        facts = "已拦截的测速目标：" + "、".join(sorted(set(targets))[:8]) + "。" if targets else clean(alert.get("message"), 300)
        return "测速连接请求已被拦截", facts, "这是管理员设置的资源保护策略，不代表认定您有滥用行为。如确有测速或业务需要，请联系管理员申请临时放行。"
    if kind == "cpu_pressure_protection":
        cpu = details.get("cpu_guard") if isinstance(details.get("cpu_guard"), dict) else {}
        action = details.get("automatic_remediation") if isinstance(details.get("automatic_remediation"), dict) else {}
        process = cpu.get("top_process") if isinstance(cpu.get("top_process"), dict) else {}
        applied = action.get("succeeded") is True and cpu.get("limit_applied") is not False
        restore_failed = cpu.get("restore_failed") is True or action.get("restore_succeeded") is False
        if restore_failed:
            title = "服务器 CPU 已回落，但临时保护限额未能自动恢复"
        elif applied:
            title = "服务器持续高 CPU，已启用临时保护"
        else:
            title = "服务器持续高 CPU，自动保护未能确认生效"
        facts = []
        if cpu.get("container_cpu_percent") is not None:
            facts.append(f"容器 CPU {fmt(cpu.get('container_cpu_percent'))}%")
        if cpu.get("effective_cpus") is not None:
            facts.append(f"可用 CPU {fmt(cpu.get('effective_cpus'))} 核")
        if cpu.get("host_busy_percent") is not None:
            facts.append(f"主机 CPU 忙碌 {fmt(cpu.get('host_busy_percent'))}%")
        if cpu.get("host_iowait_percent") is not None:
            facts.append(f"主机 IO 等待 {fmt(cpu.get('host_iowait_percent'))}%")
        if cpu.get("confirmed_duration_seconds") is not None:
            facts.append(f"连续高占用确认 {fmt(num(cpu.get('confirmed_duration_seconds'))/60)} 分钟（有效采样 {fmt(cpu.get('sample_count'))}/{fmt(cpu.get('required_samples'))} 次）")
        if cpu.get("threshold_percent_of_one_cpu") is not None:
            facts.append(f"判断阈值：单核 CPU {fmt(cpu.get('threshold_percent_of_one_cpu'))}% 或容器配额饱和；主机 CPU 忙碌 {fmt(cpu.get('host_busy_threshold_percent'))}%")
        if process.get("available") is True:
            facts.append(f"触发时进程 {clean(process.get('process') or 'unknown', 120)}（容器内 PID {fmt(process.get('pid'))}），{fmt(process.get('sampled_seconds'))} 秒采样 CPU {fmt(process.get('cpu_percent'))}%")
        else:
            facts.append("触发时未取得可确认的进程级采样；自动判断依据是容器运行时 CPU 区间指标")
        if applied:
            original = clean(action.get("original_limit") or "原配额", 80)
            active = clean(action.get("active_limit") or "临时配额", 80)
            tier = max(1, min(3, int(num(cpu.get("tier")) or num(action.get("tier")) or 1)))
            ratio = int(num(cpu.get("tier_percent_of_original")) or {1: 50, 2: 25, 3: 10}.get(tier, 50))
            facts.append(f"容器 CPU 第 {tier} 阶保护：约为原有效 CPU 容量 {ratio}%（{original} → {active}）")
            if restore_failed:
                facts.append("原 CPU 配额自动恢复失败；临时保护配额仍在生效")
        else:
            facts.append("系统未停止进程或容器；当前未确认 CPU 限额生效")
        advice = (
            "请检查该进程对应的任务和日志。临时配额会在容器 CPU 连续回落后自动恢复；本次措施是主机资源保护，不代表认定客户滥用。"
            if applied and not restore_failed else
            "请管理员检查容器运行时及 CPU 配额读回结果；系统没有停止进程或容器。本次告警是主机资源保护，不代表认定客户滥用。"
        )
        if restore_failed:
            advice = "临时 CPU 配额仍在保护容器，但原配额未能自动恢复。请管理员检查容器运行时配置后手动恢复；系统没有停止进程或容器。"
        return title, "；".join(facts) + "。", advice
    if kind == "io_pressure_protection":
        io = details.get("io_guard") if isinstance(details.get("io_guard"), dict) else {}
        action = details.get("automatic_remediation") if isinstance(details.get("automatic_remediation"), dict) else {}
        applied = action.get("succeeded") is True and io.get("limit_applied") is not False
        restore_failed = io.get("restore_failed") is True or io.get("state") == "restore_failed"
        if restore_failed:
            title = "服务器磁盘 I/O 压力已回落，但原限额未能恢复"
        elif applied:
            title = "服务器持续磁盘 I/O 繁忙，已启用容器保护"
        else:
            title = "服务器磁盘 I/O 保护未能确认生效"
        facts = []
        if io.get("device"):
            facts.append(f"受影响磁盘设备 {clean(io.get('device'), 32)}")
        if io.get("device_busy_percent") is not None:
            facts.append(f"设备繁忙 {fmt(io.get('device_busy_percent'))}%")
        rates = io.get("container_rates") if isinstance(io.get("container_rates"), dict) else io.get("observed_rates")
        if isinstance(rates, dict):
            facts.append(
                f"容器采样读写约 {fmt(num(rates.get('rbps'))/1024/1024)} / {fmt(num(rates.get('wbps'))/1024/1024)} MiB/s，"
                f"{fmt(rates.get('riops'))} / {fmt(rates.get('wiops'))} IOPS"
            )
        if io.get("dominant_share_percent") is not None:
            facts.append(f"容器占该设备采样 I/O {fmt(io.get('dominant_share_percent'))}%")
        if io.get("confirmed_duration_seconds") is not None:
            facts.append(f"持续确认 {fmt(num(io.get('confirmed_duration_seconds'))/60)} 分钟（有效采样 {fmt(io.get('sample_count'))}/{fmt(io.get('required_samples'))} 次）")
        if applied:
            tier = max(1, min(3, int(num(io.get("tier")) or 1)))
            ratio = int(num(io.get("tier_percent_of_baseline")) or {1: 50, 2: 25, 3: 10}.get(tier, 50))
            facts.append(f"第 {tier} 阶设备级读写限额约为触发基线的 {ratio}%")
            facts.append("限额只作用于该容器在该磁盘设备上的 I/O；没有停止进程或容器")
        else:
            facts.append("系统未确认容器级 I/O 限额生效；没有停止进程或容器")
        advice = (
            "这是宿主机资源保护提醒，不代表认定客户滥用。限额会在设备压力与容器 I/O 持续回落后自动恢复；请检查容器内的数据库、日志、下载或备份任务。"
            if applied and not restore_failed else
            "这是宿主机资源保护提醒，不代表认定客户滥用。请管理员核查 cgroup v2 设备归属、io.max 写入和读回结果。"
        )
        if restore_failed:
            advice = "原磁盘 I/O 限额未能自动恢复；临时保护仍可能生效。请管理员检查 cgroup v2 io.max 后手动恢复原值。"
        return title, "；".join(facts) + "。", advice
    if kind in METRICS:
        description, label, unit, advice = METRICS[kind]
        value, threshold = num(alert.get("value")), num(alert.get("threshold"))
        if unit == "Mbps":
            value, threshold = value * 8 / 1e6, threshold * 8 / 1e6
        if unit == "%":
            value, threshold = value * 100, threshold * 100
        facts = f"{label} {fmt(value)} {unit}，告警阈值 {fmt(threshold)} {unit}。"
        source = obs.get("source_ip")
        if not source:
            match = re.search(r"来源\s+([0-9a-fA-F:.]+)\s", str(alert.get("message", "")))
            source = match[1] if match else ""
        if source:
            facts += f"来源 IP：{clean(source, 80)}。"
        if obs.get("http_requests"):
            facts += f"本次统计 {fmt(obs['http_requests'])} 次请求。"
        return description, facts, advice
    if kind in {"socks_weak_auth", "socks_auth_unknown", "socks_password_review"}:
        service = names(details.get("socks_processes")) or "SOCKS"
        if kind == 'socks_password_review':
            return f"发现 {service} 代理正在提供服务，已确认要求认证，但密码安全性需要检查", listener_text(details), "请核对是否为本人安装，检查密码是否足够安全，或关闭不需要的代理。"
        mode = details.get("socks_auth_mode")
        reason = "没有密码保护" if mode == "no_auth" else "密码过于简单" if mode == "weak_password" else "认证设置尚未确认"
        facts = listener_text(details)
        return f"发现 {service} 代理{reason}，存在被未经授权使用的风险", facts, "请检查代理设置，设置安全密码，或关闭不需要的代理。"
    if kind == 'standalone_proxy_panel':
        panels = details.get('standalone_panels', [])
        services = names([p.get('panel') for p in panels if isinstance(p, dict)]) or '独立代理管理面板'
        return f"检测到 {services}，需要核对使用设置", listener_text(details), "这条提醒仅表示面板已安装，不代表已确认弱密码或异常行为，系统没有因此停止业务。请检查登录认证和代理配置，关闭不需要的服务。"
    if kind == "unauthorized_panel_pairing":
        service = names(details.get("process_patterns")) or "第三方面板对接组件"
        domains = names(details.get("unapproved_domains"))
        facts = f"对接域名：{domains}。" if domains else "尚未确认具体对接域名。"
        return f"发现未获批准的 {service} 对接特征，需要检查", facts + listener_text(details), "请检查组件来源、对接设置及启动任务，不要重新启用未经允许的对接。"
    if kind == "malicious_process":
        processes = details.get("malicious_processes", [])
        services = [p.get("process") for p in processes if isinstance(p, dict)]
        confirmed = "xmrig" in services
        label = names(services) or "未确认名称的程序"
        return f"发现 {'XMRig 挖矿程序' if confirmed else '可疑程序 ' + label}", "", "请检查程序来源、登录账号及启动任务，避免风险再次出现。"
    if kind == "container_security_risk":
        risks = obs.get("configuration_risks", [])
        facts = names([r.get("message") or r.get("code", "") for r in risks if isinstance(r, dict)])
        return "发现权限过高或隔离不足的运行配置", clean(facts or alert.get("message"), 300), "请关闭不需要的高权限和目录共享设置。"
    if kind == "traffic_imbalance":
        facts = f"收发比例 {fmt(alert.get('value'))} 倍，告警阈值 {fmt(alert.get('threshold'))} 倍。"
        if "rx_bps" in obs and "tx_bps" in obs:
            facts += f"下载 {fmt(num(obs['rx_bps'])*8/1e6)} Mbps，上传 {fmt(num(obs['tx_bps'])*8/1e6)} Mbps。"
        return "接收和发送流量差异明显", facts, "请核对下载、上传及代理任务；流量不均衡不一定是攻击。"
    if kind == "hy2_abnormal_throttle":
        facts = f"UDP 并发 {fmt(alert.get('value'))} 个，观察阈值 {fmt(alert.get('threshold'))} 个。"
        if obs.get('covered_seconds'):
            facts += f"有效采样跨度 {fmt(obs['covered_seconds'])} 秒。"
        if obs.get('bandwidth_threshold_bps'):
            facts += f"流量观察阈值 {fmt(num(obs['bandwidth_threshold_bps'])*8/1e6)} Mbps。"
        return "Hysteria 2 代理出现异常连接或流量，达到限速策略观察条件", facts, "请检查代理参数及使用情况。"
    if kind == "ops_bandwidth_saturation":
        facts = (f"{obs.get('direction_label', '网络')}平均速度 {fmt(obs.get('rate_mbps'))} Mbps，"
                 f"实例带宽 {fmt(obs.get('capacity_mbps'))} Mbps，占用 {fmt(num(obs.get('utilization'))*100)}%。"
                 f"最近 {fmt(num(obs.get('covered_seconds'))/60)} 分钟有效采样持续达到 {fmt(num(obs.get('ratio'))*100)}% 提醒线。")
        return "长时间接近占满带宽，可能影响正常使用", facts, "请检查下载、上传、备份及代理任务。系统不会仅因此自动停机。"
    if kind == "ops_baseline_anomaly":
        values, baseline = obs.get("values", []), obs.get("baseline", [])
        facts = ""
        if len(values) >= 2 and len(baseline) >= 2:
            facts = f"下载 {fmt(num(values[0])*8/1e6)} Mbps（平时参考 {fmt(num(baseline[0])*8/1e6)} Mbps），连接 {fmt(values[1])} 个（平时参考 {fmt(baseline[1])} 个）。"
        return "网络及连接使用情况明显高于平时", facts, "请确认是否有新任务、业务增长或异常程序。"
    if kind == "ops_policy_signal":
        facts = []
        for key, label, factor, unit in (("connections", "连接", 1, "个"), ("rx_bps", "下载", 8/1e6, "Mbps"), ("http_rps", "网站请求", 1, "次/秒")):
            if obs.get("signals", {}).get(key) and key in obs.get("values", {}) and key in obs.get("thresholds", {}):
                facts.append(f"{label} {fmt(num(obs['values'][key])*factor)} {unit}，阈值 {fmt(num(obs['thresholds'][key])*factor)} {unit}")
        return "运行指标达到该实例的保护观察线", "；".join(facts) or "具体数值未采集。", "这是运行保护信号，未关联到具体用户身份，不代表用户滥用；仅由管理员依据保护策略处理。"
    if kind == "ops_connection_guard":
        facts = f"连接 {fmt(obs.get('connection_count'))} 个，保护阈值 {fmt(obs.get('threshold'))} 个。"
        if obs.get('duration_verified') is True and type(obs.get('sample_count')) is int and obs['sample_count'] >= 2:
            facts += f"已由 {obs['sample_count']} 次有效采样核验，覆盖 {fmt(num(obs.get('duration_seconds'))/60)} 分钟；相邻采样间隔不超过 {fmt(obs.get('max_gap_seconds'))} 秒。"
        else:
            facts += "持续时长未通过有效采样核验；请以消息检测时间为准。"
        return "连接数量达到主机保护条件", facts, "该信号尚未关联到具体用户或认证记录，不代表认定用户滥用。系统按主机保护策略处理；如需恢复服务，请联系管理员。"
    if kind.startswith('ops_service:'):
        facts = f"检查结果：{'无法连接或访问失败' if obs.get('status')=='failed' else '响应或证书需要关注'}。"
        if 'latency_ms' in obs:
            facts += f"响应耗时 {fmt(obs['latency_ms'])} 毫秒。"
        if 'tls_days' in obs:
            facts += f"证书剩余 {fmt(obs['tls_days'])} 天。"
        return '业务服务检查发现异常', facts, '请检查网站或服务状态、网络设置和证书。'
    return "发现需要检查的运行异常", clean(alert.get("message"), 250), "请检查相关设置及后台任务。"


def listener_text(details):
    listeners = details.get("service_listeners", [])
    facts = []
    for item in listeners[:4] if isinstance(listeners, list) else []:
        if not isinstance(item, dict):
            continue
        process = clean(item.get("process"), 80)
        endpoint = clean(item.get("local"), 100)
        if process and endpoint and item.get("pid"):
            facts.append(f"{process} 监听 {endpoint}（实例内部地址）")
    return "；".join(facts) + ("。" if facts else "")


def receipt_items(items):
    result = []
    for item in items[:20] if isinstance(items,list) else []:
        if not isinstance(item,dict) or item.get('kind') not in {'process','stop_service','service','config','binary','startup'} or item.get('status') not in {'ok','failed'}:
            continue
        target = str(item.get('target') or '')
        if re.fullmatch(r'[A-Za-z0-9_./@:+-]{1,240}',target):
            result.append({k:item[k] for k in ('kind','target','status')})
    return result


def execution_text(details, action=None):
    result = details.get("automatic_remediation", {})
    result = result if isinstance(result, dict) else {}
    if action and action.get("status") in {"succeeded", "failed"}:
        result = {"attempted": True, "succeeded": action['status'] == 'succeeded', "message": action.get('result_message', ''), "action_type": action.get('action_type'), "params": loads(action.get('params_json')), "items":action.get('items',[])}
    if result.get("attempted") is not True:
        return ""
    success = result.get("succeeded") is True
    raw = str(result.get("message") or "")
    counts = {k: int(v) for k, v in re.findall(r"\b(killed_processes|stopped_services|removed_services|removed_configs|removed_binaries|cleanup_errors|stop_errors)=(\d+)\b", raw)}
    entries = receipt_items(result.get("items"))
    if not entries:
        entries = receipt_items([{"kind":k,"target":t,"status":s} for k,t,s in re.findall(r"@@NW_ACTION\t([a-z_]+)\t([^\t\n]+)\t(ok|failed)", raw)])
    labels = {"process": "停止进程", "stop_service": "停止服务", "service": "清理服务配置", "config": "删除配置文件", "binary": "删除程序文件", "startup": "清理启动项"}
    parts = []
    for key, label in (("killed_processes", "停止进程"), ("stopped_services", "停止服务"), ("removed_services", "清理服务配置"), ("removed_configs", "删除配置文件"), ("removed_binaries", "删除程序文件")):
        if counts.get(key):
            parts.append(f"{label} {counts[key]} 项")
    for item in entries[:6]:
        if isinstance(item, dict) and item.get("kind") in labels and item.get("status") in {"ok", "failed"}:
            parts.append(f"{labels[item['kind']]} {clean(item.get('target'), 120)}：{'完成' if item['status']=='ok' else '失败'}")
    params = result.get("params") or {}
    if len(entries) > 6:
        parts.append(f"另外 {len(entries)-6} 项处理记录已保存，需要详情请发工单")
    if success and result.get("action_type") == "stop_container":
        parts.append("系统已停止该实例，未删除实例")
    if success and result.get("action_type") == "apply_udp_throttle":
        parts.append(f"相关代理已限速至 {fmt(params.get('rate_mbps'))} Mbps，计划 {fmt(num(params.get('duration'))/60)} 分钟")
    text = "系统已执行处理操作" if success else "系统尝试处理，但未能全部完成"
    return text + ("：" + "；".join(parts) if parts else "（具体处理清单未上报）") + "。"


def render(alert, state, node="", action=None):
    alert = dict(alert)
    details = loads(alert.get("details_json"))
    description, facts, advice = issue(alert, details)
    if alert.get('alert_type') == 'container_connection_count':
        facts += '\n' + connection_policy.text(details.get('connection_policy'))
    name = clean(node or alert.get("host_id"), 100)
    # Full instance identity avoids ambiguous short IDs across two tenants.
    instance = clean(alert.get("container_name"), 200)
    identity = f"您的 {name} 服务器（实例 {instance}）"
    outcome = execution_text(details, action)
    if alert.get("alert_type") in {"vmess_port_blocked", "trojan_port_blocked"} and protocol_block_evidence(
        details, "vmess" if alert.get("alert_type") == "vmess_port_blocked" else "trojan"
    ):
        outcome = ""
    if alert.get("alert_type") in {"cpu_pressure_protection", "io_pressure_protection"}:
        outcome = ""
    subject = "服务器服务策略提醒" if alert.get("alert_type") in {"vmess_port_blocked", "trojan_port_blocked"} else "服务器资源保护提醒" if alert.get("alert_type") in {"cpu_pressure_protection", "io_pressure_protection"} else "服务器运行提醒" if alert.get("alert_type") in {"http_5xx_ratio", "ops_bandwidth_saturation", "ops_baseline_anomaly", "hy2_high_concurrency"} else "服务器安全提醒"
    if state == "verified":
        subject = "服务器安全复查通知"
        text = f"{identity}此前{description}。\n本次复查未再发现该问题。请保持安全设置，并留意后续使用情况。"
    else:
        text = f"{identity}{description}。\n{facts}\n{outcome}"
        if state == "awaiting_report":
            text += "正在等待新的采样复查，尚未确认问题已解决。"
        elif state == "unverified":
            text += "采集证据不足，暂时无法确认是否已恢复。"
        elif state == "resolved":
            text += "该提醒已结束，但尚未验证问题已彻底解决。"
        elif state == "recurring":
            text += "复查仍发现该问题，或问题再次出现。"
        text += "\n" + advice
    try:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(min(num(alert.get("last_seen")), 253402271999) + 28800))
    except (ValueError, OverflowError, OSError):
        when = "未采集"
    footer = f"\n检测时间：{when}（北京时间）\n如有其他疑问，请发工单。"
    # Keep the help footer and complete messages when building digests.
    return subject, clean(text, 1800 - len(footer)) + footer
