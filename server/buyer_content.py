"""Deterministic, evidence-based copy for end users; never invent remediation."""
import json
import math
import re
import time
import unicodedata


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


METRICS = {
    "container_connection_count": ("同时连接过多", "当前连接", "个", "请检查代理账号、后台任务及访问记录，限制异常连接。"),
    "socks_inbound_fanout": ("代理访问来源过多", "不同访问来源", "个", "请检查代理账号共享情况，并限制不需要的访问。"),
    "inbound_ip_fanout": ("访问来源较多", "不同访问来源", "个", "请核对业务访问量，并检查是否存在异常访问。"),
    "ddos_bandwidth": ("收到的网络流量异常增大，可能存在攻击或业务流量突增", "下载速度", "Mbps", "请检查网络访问及业务情况；如影响正常使用，请发工单。"),
    "ddos_packets": ("短时间内收到大量网络数据，可能存在异常访问", "接收数据包", "个/秒", "请检查访问来源；如持续异常或影响正常使用，请发工单。"),
    "ddos_syn": ("未完成连接请求异常增多，可能影响正常连接", "未完成连接", "个", "请检查服务访问情况；如连接困难，请发工单。"),
    "cc_total_rps": ("网站短时间内收到大量请求，可能存在异常访问或业务流量突增", "网站请求", "次/秒", "请检查访问记录，确认请求来源，并限制异常访问。"),
    "cc_single_ip": ("网站被同一来源频繁访问", "该来源请求", "次/秒", "请检查该来源的访问记录，并限制异常访问。"),
    "cc_4xx_ratio": ("网站无法正常处理的请求比例偏高", "无效请求比例", "%", "请检查访问记录、页面链接及接口设置。"),
    "http_5xx_ratio": ("网站处理请求时频繁出错，部分用户可能无法正常访问", "服务端错误比例", "%", "请检查网站程序、数据库和服务器资源。"),
    "web_scan": ("网站出现疑似敏感路径探测", "命中敏感路径规则", "次", "请保护网站后台，并检查访问记录。"),
    "http_abuse": ("同一来源反复访问失败，可能存在异常接口请求", "该来源失败请求", "次", "请检查访问记录，并加强后台及接口的访问限制。"),
    "port_scan": ("发现疑似探测服务器开放端口的访问", "不同被探测端口", "个", "请关闭不需要的端口，并检查防火墙设置。"),
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
    if kind in {"socks_weak_auth", "socks_auth_unknown"}:
        service = names(details.get("socks_processes")) or "SOCKS"
        mode = details.get("socks_auth_mode")
        reason = "没有密码保护" if mode == "no_auth" else "密码过于简单" if mode == "weak_password" else "认证设置尚未确认"
        facts = listener_text(details)
        return f"发现 {service} 代理{reason}，存在被未经授权使用的风险", facts, "请检查代理设置，设置安全密码，或关闭不需要的代理。"
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
        return "使用情况超过该实例的提醒范围", "；".join(facts) or "具体数值未采集，请检查业务使用情况。", "请核对业务访问及后台任务。"
    if kind == "ops_connection_guard":
        return "连接数量长时间超过安全限制", f"连接 {fmt(obs.get('connection_count'))} 个，限制 {fmt(obs.get('threshold'))} 个；有效采样跨度 {fmt(num(obs.get('duration_seconds'))/60)} 分钟。", "请检查代理账号和后台任务；需要协助恢复服务时，请发工单。"
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
    name = clean(node or alert.get("host_id"), 100)
    # Full instance identity avoids ambiguous short IDs across two tenants.
    instance = clean(alert.get("container_name"), 200)
    identity = f"您的 {name} 服务器（实例 {instance}）"
    outcome = execution_text(details, action)
    subject = "服务器运行提醒" if alert.get("alert_type") in {"http_5xx_ratio", "ops_bandwidth_saturation", "ops_baseline_anomaly", "hy2_high_concurrency"} else "服务器安全提醒"
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
