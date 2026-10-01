"""Post-login MOTD only: truthful, bounded, persistent, safe terminal text."""
import hashlib
import json
import os
import shlex
import stat
import tempfile
import time
import unicodedata
import re

START = "# >>> NARWHAL SECURITY ALERT BEGIN >>>"
END = "# <<< NARWHAL SECURITY ALERT END <<<"
incidents = {}
_loaded_path = ""
_checks = {}
LABELS = {"active": ("风险存在", "ACTIVE"), "awaiting_report": ("已执行，待复查", "AWAITING VERIFICATION"),
          "verified": ("复查通过", "VERIFIED"), "resolved": ("本轮未检出 / 历史事件", "NO LONGER OBSERVED"),
          "recurring": ("风险复发 / 处置失败", "RECURRING / FAILED"), "unverified": ("证据不足，未确认恢复", "UNVERIFIED")}


def safe(value, limit=300):
    text=re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value or ""))
    text=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text="".join(c for c in text if unicodedata.category(c) not in {"Cc","Cf"})
    return re.sub(r"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]",text)[:limit]


def render(name, entries, target_hint="", version="dev", language=None, width=None, color=None):
    language=language or os.getenv("SECURITY_MOTD_LANGUAGE","zh")
    try:
        width=max(40,min(100,int(width or os.getenv("SECURITY_MOTD_WIDTH","72"))))
    except ValueError:
        width=72
    if color is None:
        color=os.getenv("SECURITY_MOTD_COLOR","false").lower() in {"true","1","yes"} and not os.getenv("NO_COLOR") and os.getenv("TERM")!="dumb"
    english=language=="en"
    ordered=sorted(entries,key=lambda e: (e.get("state","active") not in {"active","recurring"}, e.get("severity")!="critical"))[:3]
    state=ordered[0].get("state","active") if ordered else "verified"
    severity=ordered[0].get("severity","warning") if ordered else "info"
    label=LABELS.get(state,LABELS["unverified"])[int(english)]
    ansi="\033[31m" if state in {"active","recurring"} and severity=="critical" else "\033[32m" if state=="verified" else "\033[33m"
    lines=[f"NARWHAL SECURITY / Watcher {safe(version,30)}", f"{'Target' if english else '容器'}: {safe(name)} {safe(target_hint)}",
           f"{'Status' if english else '状态'}: {label} [{severity.upper()}]"]
    if color:
        lines[2]=ansi+lines[2]+"\033[0m"
    for e in ordered:
        lines.extend([f"{safe(e.get('event_id') or 'LOCAL')} | {safe(e.get('type'))} | {safe(e.get('timestamp'))}",
                      LABELS.get(e.get("state","active"),LABELS["unverified"])[int(english)],
                      safe(e.get("detail")), safe(e.get("action"))])
    lines.append("Inspect processes, SSH keys and scheduled tasks. Execution is not verification." if english else "请检查进程、SSH 密钥与定时任务。执行成功不等于复查通过。")
    # East Asian display width: use cells, not len(), and don't truncate event IDs.
    wrapped=[]
    for line in lines:
        if "\033" in line:
            wrapped.append(line)
            continue
        current=""
        cells=0
        for c in line:
            n=0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W","F"} else 1
            if cells+n>width:
                wrapped.append(current)
                current=""
                cells=0
            current+=c
            cells+=n
        wrapped.append(current)
    return "\n".join(wrapped)+"\n"


def merge(original, banner):
    # Preserve every byte outside owned marker blocks, including whitespace.
    pattern=re.compile(re.escape(START)+r"\n.*?"+re.escape(END)+r"\n?",re.S)
    cleaned=pattern.sub("",original)
    if (START in cleaned) or (END in cleaned):
        raise ValueError("MOTD 标记不完整，保留原文件并拒绝覆盖")
    return f"{START}\n{banner.rstrip()}\n{END}\n"+cleaned if banner else cleaned


def state_path():
    return os.getenv("SECURITY_MOTD_STATE_FILE","/opt/narwhal-monitor/motd-state.json")


def load_state():
    global _loaded_path
    path=state_path()
    if _loaded_path==path:
        return
    _loaded_path=path
    try:
        with open(path,encoding="utf-8") as f:
            data=json.load(f)
        if isinstance(data,dict) and len(data)<=1000:
            for key,value in data.items():
                if isinstance(value,list):
                    incidents.setdefault(key,[e for e in value[:3] if isinstance(e,dict)])
    except (OSError,ValueError):
        pass


def persist():
    path=state_path()
    parent=os.path.dirname(path) or "."
    temp=""
    try:
        os.makedirs(parent,mode=0o700,exist_ok=True)
        fd,temp=tempfile.mkstemp(prefix=".motd-state-",dir=parent)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(dict(list(incidents.items())[-1000:]),f,ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp,path)
    except OSError:
        if temp:
            try: os.unlink(temp)
            except OSError: pass
        return False
    return True


def write_proc(pid, banner):
    """Do not follow a container-controlled /etc or /etc/motd symlink on the host."""
    rootfd=os.open(f"/proc/{pid}/root",os.O_RDONLY|os.O_DIRECTORY)
    etcfd=None
    temporary=".narwhal-motd-"+os.urandom(8).hex()
    try:
        etcfd=os.open("etc",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        original=""
        info=None
        try:
            fd=os.open("motd",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=etcfd)
            with os.fdopen(fd,"r",encoding="utf-8") as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size>65536:
                    raise ValueError("MOTD 不是有界普通文件")
                original=f.read(65537)
        except FileNotFoundError:
            pass
        content=merge(original,banner)
        if original==content:
            return False
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=etcfd)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fchmod(f.fileno(),stat.S_IMODE(info.st_mode) if info else 0o644)
            if info:
                os.fchown(f.fileno(),info.st_uid,info.st_gid)
            os.fsync(f.fileno())
        os.rename(temporary,"motd",src_dir_fd=etcfd,dst_dir_fd=etcfd)
        checkfd=os.open("motd",os.O_RDONLY|os.O_NOFOLLOW,dir_fd=etcfd)
        with os.fdopen(checkfd,"r",encoding="utf-8") as f:
            if f.read(65537)!=content:
                raise OSError("MOTD 写后校验失败")
        return True
    finally:
        if etcfd is not None:
            try: os.unlink(temporary,dir_fd=etcfd)
            except FileNotFoundError: pass
            os.close(etcfd)
        os.close(rootfd)


def update(container, alerts, threat_types, checked_exec, server_states, version):
    delivery={"status":"disabled","mechanism":"post_login_motd"}
    container.setdefault("security",{})["motd_delivery"]=delivery
    if os.getenv("SECURITY_INJECT_MOTD_ALERT","true").lower() in {"false","0","off","no"} or (container.get("runtime")=="docker" and container.get("monitor_mode")=="notice"):
        return False
    name=str(container.get("name") or "")
    if not name:
        return False
    load_state()
    key=json.dumps([container.get("runtime",""),container.get("project",""),name,str(container.get("id") or "")],ensure_ascii=False)
    entries=incidents.setdefault(key,[])
    now=time.time()
    relevant=[a for a in alerts if a.get("severity")=="critical" or a.get("type") in threat_types]
    for a in relevant:
        e=next((e for e in entries if e.get("type")==a.get("type")),None)
        if e is None:
            e={"type":a.get("type"),"event_id":"LOCAL-"+hashlib.sha256((key+str(a.get("type"))+str(int(now))).encode()).hexdigest()[:12]}
            entries.append(e)
        rem=a.get("automatic_remediation") or a.get("socks_auth_enforcement") or {}
        success=isinstance(rem,dict) and rem.get("succeeded") is True
        failed=isinstance(rem,dict) and rem.get("attempted") is True and not success
        e.update(time_epoch=now,timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime(now)),
                 detail=safe(a.get("message")),severity=a.get("severity","warning"),clean_samples=0,
                 state="awaiting_report" if success else "recurring" if failed else "active",
                 action="Execution succeeded; awaiting verification" if success else "Execution failed" if failed else "Detected; not remediated")
    present={a.get("type") for a in relevant}
    for e in entries:
        matching=next((s for s in server_states if (s.get("runtime"),s.get("project"),s.get("name"),s.get("type"))==(container.get("runtime",""),container.get("project",""),name,e.get("type")) and now-float(s.get("updated_at",0))<900),None)
        if matching:
            e["event_id"]=safe(matching.get("event_id"),80)
        if e.get("type") not in present:
            socks=container.get("security",{}).get("socks_proxy",{})
            unknown=e.get("type")=="socks_weak_auth" and ("detected" not in socks or (socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}))
            e["clean_samples"]=0 if unknown else int(e.get("clean_samples",0))+1
            e["state"]="unverified" if unknown else "verified" if e["clean_samples"]>=2 else "resolved"
            e["action"]="Two fresh samples verified clean" if e["state"]=="verified" else "Awaiting fresh evidence"
            if matching and matching.get("state") in {"recurring","unverified","awaiting_report","suppressed"}:
                e["state"]=matching["state"]
    try: retention=max(3600,min(7*86400,float(os.getenv("SECURITY_MOTD_ALERT_RETENTION_HOURS","24"))*3600))
    except ValueError: retention=86400
    entries[:]=sorted([e for e in entries if now-float(e.get("time_epoch",0))<retention and e.get("state")!="suppressed"],key=lambda e:e.get("time_epoch",0),reverse=True)[:3]
    for k in list(incidents):
        if not incidents[k] or all(now-float(e.get("time_epoch",0))>=retention for e in incidents[k]):
            incidents.pop(k,None)
    for k in list(_checks):
        if k not in incidents or now-_checks[k][0]>86400:
            _checks.pop(k,None)
    if len(_checks)>1000:
        for k in sorted(_checks,key=lambda k:_checks[k][0])[:-1000]:
            _checks.pop(k,None)
    persisted=persist()
    banner=render(name,entries,version=version) if entries else ""
    changed=False
    try:
        pid=int(container.get("pid") or 0)
        if pid>1:
            changed=write_proc(pid,banner)
            delivery.update(status="written" if changed else "unchanged",method="proc_atomic")
        else:
            raise OSError("无容器 PID")
    except (OSError,ValueError,AttributeError):
        try:
            ok,original=checked_exec(container,"[ ! -L /etc/motd ] && { [ ! -e /etc/motd ] || [ -f /etc/motd ]; } && { [ ! -f /etc/motd ] || [ $(wc -c < /etc/motd) -le 65536 ]; } && { cat /etc/motd 2>/dev/null || [ ! -e /etc/motd ]; }")
            if not ok:
                raise OSError("容器 MOTD 读取失败")
            content=merge(original,banner)
            if original!=content:
                command="set -eu; [ ! -L /etc/motd ]; t=$(mktemp /etc/.narwhal-motd.XXXXXX); trap 'rm -f -- \"$t\"' EXIT; if [ -f /etc/motd ]; then cp -p /etc/motd \"$t\"; else chmod 644 \"$t\"; fi; printf '%s' "+shlex.quote(content)+" > \"$t\"; mv -f -- \"$t\" /etc/motd"
                ok,_=checked_exec(container,command)
                if not ok:
                    raise OSError("容器 MOTD 写入失败")
                ok,check=checked_exec(container,"cat /etc/motd")
                if not ok or check!=content:
                    raise OSError("MOTD 写后校验失败")
                changed=True
            delivery.update(status="written" if changed else "unchanged",method="runtime_atomic")
        except (OSError,ValueError):
            delivery.update(status="failed",error="MOTD 写入 / 校验失败；原内容或符号链接已保留")
    delivery["state_persisted"]=persisted
    delivery["event_ids"]=[e["event_id"] for e in entries]
    # Read-only login mechanism check, not a promise that an SSH session displayed it.
    if key not in _checks or now-_checks[key][0]>3600:
        ok,mechanism=checked_exec(container,"if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep '^printmotd '; fi; if grep -qs pam_motd /etc/pam.d/sshd; then printf 'pam_motd\\n'; fi; if grep -qs '/etc/motd' /etc/profile; then printf 'profile_motd\\n'; fi; true")
        _checks[key]=(now,"configured" if ok and any(v in mechanism for v in ("printmotd yes","pam_motd","profile_motd")) else "unverified")
    delivery["login_display"]=_checks[key][1]
    return changed
