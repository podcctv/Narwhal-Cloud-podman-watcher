"""Node-local read-only health, service probes and bounded log onboarding."""
import glob
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit
import requests

_config = {"services": []}
_discoveries = []


def state_path():
    return Path(os.getenv("NARWHAL_OPERATIONS_STATE", "/var/lib/narwhal-monitor/operations.json"))


def configure(config):
    global _config
    if not isinstance(config, dict) or not isinstance(config.get("services"), list):
        return
    _config = {"services": config["services"][:20]}
    try:
        path = state_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd,"w") as f:
            json.dump(_config, f)
        os.replace(tmp,path)
    except OSError:
        pass  # In-memory probes still work in a read-only container.


def load_config():
    global _config
    try:
        data=json.loads(state_path().read_text())
        if isinstance(data,dict) and isinstance(data.get("services"),list):
            _config={"services":data["services"][:20]}
    except (ValueError,OSError):
        pass


def discover_logs(parse):
    results=[]
    paths=set()
    for pattern in ("/var/log/nginx/*access*.log", "/var/log/caddy/*access*.log", "/var/log/apache2/*access*.log"):
        paths.update(glob.glob(pattern)[:20])
    paths.update(p.strip() for p in os.getenv("SECURITY_ACCESS_LOG_PATHS", "").split(",") if p.strip() and "*" not in p)
    for name in sorted(paths)[:30]:
        item={"path":name,"status":"unavailable","samples":0,"parsed":0,"parse_errors":0,"formats":[],"methods":[],"statuses":[],"modified_at":0}
        try:
            with open(name,"rb") as f:
                f.seek(0,2)
                f.seek(max(0,f.tell()-16384))
                lines=f.read(16384).decode("utf-8","replace").splitlines()[-20:]
            methods=set()
            statuses=set()
            formats=set()
            for line in lines:
                parsed=parse(line)
                item["samples"]+=1
                if parsed:
                    item["parsed"]+=1
                    methods.add(str(parsed.get("method", "")))
                    statuses.add(int(parsed.get("status",0)))
                    formats.add("json" if line.lstrip().startswith("{") else "combined")
                else:
                    item["parse_errors"]+=1
            item.update(status="healthy" if item["parsed"] else "idle" if not lines else "parse_error",methods=sorted(methods),statuses=sorted(statuses),formats=sorted(formats),modified_at=int(os.stat(name).st_mtime))
        except FileNotFoundError:
            item["status"]="missing"
        except PermissionError:
            item["status"]="permission_denied"
        except OSError:
            item["status"]="read_error"
        results.append(item)
    global _discoveries
    _discoveries=results
    return results


def probe(service):
    result={"id":service.get("id"),"status":"failed","latency_ms":None,"checked_at":int(time.time())}
    start=time.monotonic()
    try:
        target=str(service.get("target",""))
        url=urlsplit(target)
        kind=service.get("kind")
        if url.username or url.password or not url.hostname or kind not in ("tcp","http") or url.scheme not in ("tcp","http","https"):
            raise ValueError("invalid probe target")
        if kind=="tcp":
            with socket.create_connection((url.hostname,url.port or 0),timeout=3):
                pass
        else:
            # No redirects: avoid probing a different endpoint or metadata target.
            with requests.get(target,timeout=(3,3),allow_redirects=False,stream=True) as response:
                result["http_status"]=response.status_code
                if not 200<=response.status_code<400:
                    raise ValueError(f"HTTP {response.status_code}")
        result["latency_ms"]=round((time.monotonic()-start)*1000,1)
        result["status"]="warning" if result["latency_ms"]>=service.get("latency_warning_ms",1000) else "healthy"
        if url.scheme=="https":
            with socket.create_connection((url.hostname,url.port or 443),timeout=3) as raw:
                with ssl.create_default_context().wrap_socket(raw,server_hostname=url.hostname) as tls:
                    cert=tls.getpeercert()
            expiry=ssl.cert_time_to_seconds(cert["notAfter"])
            result["tls_days_remaining"]=round((expiry-time.time())/86400,1)
            if result["tls_days_remaining"]<service.get("tls_warning_days",14):
                result["status"]="warning"
        return result
    except Exception as e:
        # Do not expose URL query or request exception repr (may contain credentials).
        result["error"]=str(e)[:150] if isinstance(e,ValueError) else type(e).__name__
        return result


def collect(security, containers, interval):
    access=security.get("access_log",{})
    if not security.get("enabled"):
        log_status="disabled"
    elif access.get("unreadable_files"):
        log_status="permission_denied"
    elif not access.get("readable_files"):
        log_status="not_configured" if not access.get("enabled") else "missing"
    elif access.get("parse_errors") and not access.get("requests"):
        log_status="parse_error"
    else:
        log_status="healthy" if access.get("requests") else "idle"
    health=[{"source":"http_logs","status":log_status,"details":{k:access.get(k,0) for k in ("readable_files","missing_files","unreadable_files","parse_errors","requests")},"guidance":"使用日志向导发现路径，确认 JSON/combined 格式和 Agent 读取权限"},
            {"source":"network_counters","status":"healthy" if all(c.get("traffic_counters",{}).get("available") for c in containers) and containers else "partial" if containers else "idle","details":{"containers":len(containers),"available":sum(bool(c.get("traffic_counters",{}).get("available")) for c in containers)},"guidance":"检查运行时统计接口、/proc 网络命名空间权限；首采样不产生速率"},
            {"source":"security","status":"healthy" if security.get("enabled") else "disabled","guidance":"启用 SECURITY_MONITOR_ENABLED；执行复查要求新安全样本"}]
    with ThreadPoolExecutor(max_workers=4) as pool:
        services=list(pool.map(probe,_config.get("services",[])[:20]))
    upgrade_result={}
    try:
        upgrade_result=json.loads(Path("/opt/narwhal-monitor/managed-update-result.json").read_text())
    except (OSError,ValueError):
        pass
    return {"health":health,"services":services,"log_discovery":_discoveries,"architecture":platform.machine(),"interval_seconds":interval,"upgrade_result":upgrade_result,
            "managed_upgrade":os.path.isfile("/opt/narwhal-monitor/managed-client-update.sh") and bool(shutil.which("systemd-run")),
            "capabilities":["operations-v1","service-probes","log-discovery","post-remediation-recheck"],"schema_version":1}


def schedule_upgrade(action,node_id):
    params=action.get("params",{})
    if not node_id or params.get("expected_node_id")!=node_id:
        return False,"host action node identity mismatch"
    rollback=action.get("action_type")=="managed_rollback"
    revision=str(params.get("revision",""))
    version=str(params.get("version",""))
    if not rollback and (not re.fullmatch(r"[0-9a-f]{40}",revision) or not re.fullmatch(r"\d+\.\d+\.\d+",version)):
        return False,"invalid immutable upgrade target"
    script="/opt/narwhal-monitor/managed-client-update.sh"
    if not os.path.isfile(script) or not shutil.which("systemd-run"):
        return False,"managed update requires installed host/systemd agent"
    args=["systemd-run","--unit",f"narwhal-managed-{int(action.get('id',0))}","--collect","--property=Type=oneshot","--property=TimeoutStartSec=15min","/bin/bash",script]
    args += ["rollback",str(int(action.get("id",0)))] if rollback else ["upgrade",revision,version,str(int(action.get("id",0)))]
    result=subprocess.run(args,capture_output=True,text=True,timeout=10)
    return result.returncode==0,"scheduled managed rollback" if rollback else "scheduled immutable upgrade"
