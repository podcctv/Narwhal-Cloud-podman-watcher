"""Post-login MOTD only: truthful, bounded, persistent, safe terminal text."""
import hashlib
import base64
import gzip
import json
import os
import shlex
import stat
import tempfile
import time
import unicodedata
import re
from datetime import datetime, timedelta, timezone

START = "# >>> NARWHAL SECURITY ALERT BEGIN >>>"
END = "# <<< NARWHAL SECURITY ALERT END <<<"
incidents = {}
_loaded_path = ""
_checks = {}
SHELL_START = "# >>> NARWHAL SHELL BANNER BEGIN >>>"
SHELL_END = "# <<< NARWHAL SHELL BANNER END <<<"
CHANNEL = "https://t.me/flanker_channel"
FONT = {
    'F': [' _____ ', '|  ___|', '| |_   ', '|  _|  ', '|_|    '],
    'L': [' _     ', '| |    ', '| |    ', '| |___ ', '|_____|'],
    'A': ['    _    ', '   / \\   ', '  / _ \\  ', ' / ___ \\ ', '/_/   \\_\\'],
    'N': [' _   _ ', '| \\ | |', '|  \\| |', '| |\\  |', '|_| \\_|'],
    'K': [' _  __ ', '| |/ / ', "| ' /  ", '| . \\  ', '|_|\\_\\ '],
    'E': [' _____ ', '| ____|', '|  _|  ', '| |___ ', '|_____|'],
    'R': [' ____  ', '|  _ \\ ', '| |_) |', '|  _ < ', '|_| \\_\\'],
    'H': [' _   _ ', '| | | |', '| |_| |', '|  _  |', '|_| |_|'],
    'O': ['  ___  ', ' / _ \\ ', '| | | |', '| |_| |', ' \\___/ '],
    'S': [' ____  ', '/ ___| ', '\\___ \\ ', ' ___) |', '|____/ '],
    'T': [' _____ ', '|_   _|', '  | |  ', '  | |  ', '  |_|  '],
    'I': [' ___ ', '|_ _|', ' | | ', ' | | ', '|___|'],
    'G': ['  ____ ', ' / ___|', '| |  _ ', '| |_| |', ' \\____|'],
}
LABELS = {"active": ("待检查，尚未确认恢复", "Needs review; recovery unconfirmed"), "awaiting_report": ("已执行处理，等待复查确认", "Action executed; awaiting verification"),
          "verified": ("已恢复", "RECOVERED"), "resolved": ("本轮未检出，待复查", "NOT OBSERVED; AWAITING VERIFICATION"),
          "recurring": ("风险复发 / 处置失败", "RECURRING / FAILED"), "unverified": ("证据不足，未确认恢复", "UNVERIFIED")}


def safe(value, limit=300):
    text=re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value or ""))
    text=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text="".join(c for c in text if unicodedata.category(c) not in {"Cc","Cf"})
    return re.sub(r"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]",text)[:limit]


def cell_width(text):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {'W', 'F'} else 1 for c in text)


def wrap_cells(text, width):
    lines, current, cells = [], '', 0
    for c in text:
        size = cell_width(c)
        if cells + size > width:
            lines.append(current)
            current, cells = '', 0
        current += c
        cells += size
    return lines + [current]


def beijing_time(epoch=None, legacy=""):
    """Fixed UTC+8, independent of the host/container timezone or tzdata."""
    try:
        if epoch is None:
            epoch = datetime.strptime(legacy, '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc).timestamp()
        return datetime.fromtimestamp(float(epoch), timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OverflowError, OSError):
        return ''


def customer_metrics(entry, english=False):
    """Only meaningful typed measurements, not generic value/threshold counters."""
    numbers = {f'{float(n):g}' for n in re.findall(r'-?\d+(?:\.\d+)?', safe(entry.get('detail')))}
    values = {k: f'{float(v):g}' for k, v in re.findall(r'(value|threshold|duration_seconds)=(-?\d+(?:\.\d+)?)', safe(entry.get('metrics')))}
    kind = entry.get('type')
    unit = {'container_connection_count': ('连接', '条', 'Connections'), 'connections': ('连接', '条', 'Connections'),
            'hy2_high_concurrency': ('UDP 并发', '条', 'UDP connections'), 'cpu': ('CPU', '%', 'CPU'),
            'memory': ('内存占用', '%', 'Memory'), 'process_fanout_abuse': ('进程', '个', 'Processes'),
            'inbound_ip_fanout': ('访问来源', '个 IP', 'Client IPs'), 'outbound_fanout': ('外部地址', '个 IP', 'External IPs')}.get(kind)
    result = []
    if unit and 'value' in values and values['value'] not in numbers:
        result.append(f'{unit[2] if english else unit[0]} {values["value"]}{"" if english else " " + unit[1]}')
        if 'threshold' in values:
            result[-1] += f' (warning {values["threshold"]})' if english else f'（预警 {values["threshold"]} {unit[1]}）'
    if 'duration_seconds' in values:
        minutes = float(values['duration_seconds']) / 60
        if minutes >= 0:
            result.append(f'Duration {minutes:g} min' if english else f'持续 {minutes:g} 分钟')
    return '；'.join(result)


def customer_copy(entry, english=False):
    """Version 2: a concrete cause and actionable advice, never a raw report."""
    title, reason = safe(entry.get('title') or entry.get('type')), safe(entry.get('detail'))
    if entry.get('type') == 'user_notice':
        return title, safe(entry.get('detail'), 1600), [], ''
    if not english and (not entry.get('title') or title == entry.get('type')):
        title = {'cc_attack':'HTTP 访问异常','socks_weak_auth':'代理认证风险','socks_auth_unknown':'代理认证待确认',
                 'container_connection_count':'容器连接数偏高','connections':'容器连接数偏高',
                 'cpu':'CPU 占用偏高','memory':'内存占用偏高','malicious_process':'可疑程序',
                 'outbound_fanout':'外部连接偏多','port_scan':'疑似端口扫描',
                 'vmess_port_blocked':'VMess 入站端口已自动阻断','vmess_block_unverified':'VMess 入站保护待核实',
                 'vmess_block_release_unverified':'VMess 端口恢复待核实',
                 'trojan_port_blocked':'Trojan 入站端口已自动阻断','trojan_block_unverified':'Trojan 入站保护待核实',
                 'trojan_block_release_unverified':'Trojan 端口恢复待核实',
                 'speedtest_service_blocked':'测速目标连接已按策略限制'}.get(entry.get('type'), title or '运行异常')
    details = entry.get('customer') if isinstance(entry.get('customer'), dict) else {}
    extra = []
    advice = 'Please check the related settings and background tasks.' if english else '请检查相关设置和后台任务；需要协助时请联系管理员。'
    if entry.get('type') == 'unauthorized_panel_pairing':
        def field(key, label):
            items = details.get(key)
            if isinstance(items, list):
                return '、'.join(safe(v, 100) for v in items[:4] if isinstance(v, str))
            match = re.search(label + r'\s+([^；;]+)', reason)
            return safe(match[1], 200) if match else ''
        domains, programs = field('domains', '未授权面板域名'), field('programs', '节点程序特征')
        title = 'Suspected third-party panel integration' if english else '疑似第三方面板对接'
        program = programs or ('A panel component' if english else '面板对接组件')
        if domains:
            reason = f'{program} points to a panel outside the allowed list.' if english else f'{program} 配置的面板地址不在允许列表内。'
            extra.append(('Panel: ' if english else '面板：') + domains)
        else:
            reason = f'Panel integration indicators found for {program}; authorization needs review.' if english else f'检测到 {program} 面板对接特征，需确认是否经过允许。'
        advice = 'Please confirm whether you configured this panel and contact the administrator to review it.' if english else '请确认该面板是否为你自行配置；如需继续使用，请联系管理员核实。'
    elif entry.get('type') in {'container_connection_count', 'connections', 'hy2_high_concurrency'}:
        advice = 'Please check shared proxy accounts, background tasks and unexpected connections.' if english else '请检查代理账号共享、后台任务及异常连接。'
    elif entry.get('type') in {'socks_weak_auth', 'socks_auth_unknown'}:
        advice = 'Please secure the proxy authentication or disable the unwanted service.' if english else '请检查代理认证，设置安全密码，或关闭不需要的代理。'
    elif entry.get('type') == 'vmess_port_blocked':
        advice = 'This is a platform network-policy notice, not an abuse finding. VMess inbound traffic on the listed ports was blocked without stopping other services. Please migrate the service to VLESS + Reality + Vision.' if english else '这是平台网络策略提醒，不代表认定您有滥用行为。系统只阻断了列出的 VMess 入站端口，没有停止进程、容器或其他端口。建议迁移到 VLESS + Reality + Vision。'
    elif entry.get('type') == 'vmess_block_unverified':
        advice = 'The service was not stopped because the port or network ownership could not be verified. Please review the listed port and migrate to VLESS + Reality + Vision.' if english else '由于端口或网络归属无法确认，系统没有自动阻断。请核对提示的端口；确认后可迁移到 VLESS + Reality + Vision。'
    elif entry.get('type') == 'vmess_block_release_unverified':
        advice = 'The previous network rule is being kept because the service stop or rule removal could not be verified. Please contact the administrator to review the listed port.' if english else '由于尚不能确认服务已停止或规则已删除，系统暂时保留了原端口阻断。请联系管理员核实提示的端口；其他服务和容器未停止。'
    elif entry.get('type') == 'trojan_port_blocked':
        advice = 'This is a network-policy notice, not an abuse finding. Only the verified Trojan listener ports were blocked; other services were left running. Please contact the administrator if you need help.' if english else '这是网络保护策略提醒，不代表认定您有滥用行为。系统只阻断了已确认的 Trojan 监听端口，其他服务仍在运行；如需继续使用，请联系管理员确认端口策略。'
    elif entry.get('type') == 'trojan_block_unverified':
        advice = 'The service was not stopped because its live listener or firewall rule could not be verified. Please ask the administrator to review the listed process and port.' if english else '由于实时监听或防火墙规则无法核实，系统没有确认封锁。请管理员根据提示的进程和端口复核。'
    elif entry.get('type') == 'trojan_block_release_unverified':
        advice = 'The previous network rule remains until the listener is confirmed absent and rule removal is verified.' if english else '旧端口规则会保留，直到确认监听已消失且规则删除结果可读回验证。'
    elif entry.get('type') == 'speedtest_service_blocked':
        advice = ('This is an administrator-configured resource policy, not an abuse finding. Only the listed DNS targets, destination IPs, or verified service listeners were restricted after local readback; no process or container was stopped.'
                  if english else '这是管理员设置的资源保护策略，不代表认定用户滥用。仅对消息列出的出站域名、测速目标 IP 或已确认入站服务入口应用了限制，并经本地读回确认；没有停止进程或容器。如业务需要访问这些目标，请联系管理员。')
    elif entry.get('type') in {'malicious_process', 'confirmed_abuse'}:
        advice = 'Please review the program source and startup tasks; contact the administrator before restoring access.' if english else '请检查程序来源及启动任务；如已隔离，请联系管理员复核后恢复。'
    elif entry.get('type') in {'cpu', 'memory', 'process_fanout_abuse'}:
        advice = 'Please check resource usage and repeated background tasks.' if english else '请检查资源占用及重复运行的后台任务。'
    reason = re.sub(r'\b(?:value|threshold|duration_seconds)=\S+', '', reason).strip(' /；;')
    return title, reason, extra, advice


def observed_epoch(entry):
    try:
        value = entry.get('time_epoch')
        if value is None:
            value = datetime.strptime(entry.get('timestamp', ''), '%Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc).timestamp()
        return int(value)
    except (ValueError, TypeError, OverflowError):
        return None


def relative_age(epoch, now, english=False):
    if epoch is None or epoch < 0 or now < epoch:
        return 'time unknown' if english else '时间待核实'
    minutes = int((now - epoch) // 60)
    if minutes < 1:
        return 'just now' if english else '刚刚'
    if minutes < 60:
        return f'{minutes} minutes ago' if english else f'{minutes}分钟前'
    hours = minutes // 60
    if hours < 24:
        return f'{hours}h {minutes % 60}m ago' if english else f'{hours}小时{minutes % 60}分钟前'
    return f'{hours // 24}d {hours % 24}h ago' if english else f'{hours // 24}天{hours % 24}小时前'


def historical_detail(entry):
    # The saved evidence is unchanged; only customer-facing tense is adjusted.
    text = safe(entry.get('detail')).replace('当前', '当时').replace('目前', '当时')
    return re.sub(r'\bcurrently\b', 'at the time', text, flags=re.I)


def select_entries(entries):
    # Reserve a separate slot for the latest recovery, even when new risks appear.
    notices = sorted((e for e in entries if e.get('type') == 'user_notice'), key=lambda e: -e.get('time_epoch', 0))[:1]
    current = sorted((e for e in entries if not e.get('historical') and e.get('type') != 'user_notice'), key=lambda e: (
        e.get('state', 'active') not in {'active', 'recurring'}, e.get('severity') != 'critical', -e.get('time_epoch', 0)))[:3]
    history = sorted((e for e in entries if e.get('historical')),
                     key=lambda e: e.get('recovered_at_epoch', e.get('time_epoch', 0)), reverse=True)[:1]
    return notices + current[:3-len(notices)] + history


def render(name, entries, target_hint="", version="dev", language=None, width=None, color=None, stale=False, sampled_at=None, _dynamic_history_age=False):
    language=language or os.getenv("SECURITY_MOTD_LANGUAGE","zh")
    try:
        width=max(12,min(100,int(width or os.getenv("SECURITY_MOTD_WIDTH","72"))))
    except ValueError:
        width=72
    if color is None:
        color=os.getenv("SECURITY_MOTD_COLOR","false").lower() in {"true","1","yes"} and not os.getenv("NO_COLOR") and os.getenv("TERM")!="dumb"
    english=language=="en"
    ordered=select_entries(entries)
    inner = width - 2
    lines = []
    def tint(text, code):
        return f'\033[{code}m{text}\033[0m' if color else text
    def border(left, right):
        lines.append(tint(left + '─' * inner + right, '32'))
    def row(text='', code='37', center=False):
        available = inner if center else max(1, inner - 4)
        for part in wrap_cells(text, available):
            extra = inner - cell_width(part)
            left = extra // 2 if center else min(2, extra)
            body = ' ' * left + part + ' ' * (extra - left)
            lines.append(tint('│', '32') + tint(body, code) + tint('│', '32'))
    border('╭', '╮')
    if inner >= 61:
        row()
        for word in ('FLANKER', 'HOSTING'):
            glyphs = [FONT[c] for c in word]
            sizes = [max(map(len, g)) for g in glyphs]
            for i in range(5):
                row(' '.join(g[i].ljust(size) for g, size in zip(glyphs, sizes)), '32', True)
            row()
    else:
        row('FLANKER HOSTING', '32', True)
    row('弗兰克托管', '37', True)
    border('├', '┤')
    outstanding = [e for e in ordered if e.get('state', 'active') != 'verified']
    if stale:
        status = 'Monitoring sample expired; current status unknown' if english else '监测数据已过期，当前状态未知'
        status_color = '33'
    elif outstanding:
        status = f'{len(outstanding)} security notice(s) need review' if english else f'有 {len(outstanding)} 项安全提醒待确认'
        status_color = '31' if any(e.get('severity') == 'critical' and e.get('state', 'active') in {'active', 'recurring'} for e in outstanding) else '33'
    else:
        status = 'No anomalies currently detected' if english else '目前容器无异常'
        status_color = '32'
    row(('Status: ' if english else '状态：') + status, status_color)
    if sampled_at is not None:
        row(('Updated (UTC+8): ' if english else '更新（北京时间）：') + beijing_time(sampled_at))
    for e in ordered:
        row()
        state = e.get('state', 'active')
        code = '32' if state == 'verified' else '31' if state in {'active', 'recurring'} and e.get('severity') == 'critical' else '33'
        historical = state == 'verified'
        title, reason, extra, advice = customer_copy(e, english)
        if historical:
            row('Historical alert · Recovered' if english else '历史告警 · 已恢复', code)
            row(title, code)
            reason = historical_detail({'detail': reason})
            row(('At the time: ' if english else '当时情况：') + reason, code)
            epoch = observed_epoch(e)
            if _dynamic_history_age and epoch is not None and epoch >= 0:
                # A bounded metadata row, replaced by the login-time shell renderer.
                lines.append(f'@@AGE:{epoch}:{int(english)}')
            else:
                reference = (' (as of update)' if english else '（截至更新时间）') if sampled_at is not None and epoch is not None else ''
                row(('Last occurred: ' if english else '最近发生：') + relative_age(epoch, sampled_at if sampled_at is not None else time.time(), english) + reference)
            recovery_epoch = observed_epoch({'time_epoch': e.get('recovered_at_epoch')})
            if recovery_epoch is not None and recovery_epoch >= 0:
                if _dynamic_history_age:
                    lines.append(f'@@AGE:{int(recovery_epoch)}:{int(english)}:1')
                else:
                    row(('Recovered: ' if english else '恢复于：') + relative_age(recovery_epoch, sampled_at if sampled_at is not None else time.time(), english))
                first_epoch = observed_epoch({'time_epoch': e.get('first_seen_epoch')})
                if first_epoch is not None and 0 <= first_epoch <= recovery_epoch and 'duration_seconds=' not in str(e.get('metrics', '')):
                    minutes = (recovery_epoch - first_epoch) / 60
                    row(f'Alert duration about {minutes:.0f} minutes' if english else f'告警持续约 {minutes:.0f} 分钟', code)
        else:
            row('【' + title + '】', code)
            row(('Cause: ' if english else '原因：') + reason, code)
        for detail in extra:
            row(detail, code)
        if not historical:
            row(('Handling: ' if english else '处理：') + LABELS.get(state, LABELS['unverified'])[int(english)], code)
            row(('Advice: ' if english else '建议：') + advice, code)
        metrics = customer_metrics(e, english)
        if metrics:
            row((('Historical data: ' if english else '当时数据：') if historical else '') + metrics, code)
        detected = beijing_time(e.get('time_epoch'), e.get('timestamp', ''))
        if detected and (stale or state == 'verified' or detected != beijing_time(sampled_at)):
            row(('Last observed (UTC+8): ' if english else '发生时间（北京时间）：' if historical else '最近发生（北京时间）：') + detected)
        recovered = beijing_time(e.get('recovered_at_epoch')) if e.get('recovered_at_epoch') is not None else ''
        if recovered:
            row(('Recovered (UTC+8): ' if english else '恢复（北京时间）：') + recovered)
    border('├', '┤')
    row(('Channel: ' if english else '频道：') + CHANNEL)
    border('╰', '╯')
    return '\n'.join(lines) + '\n'


def shell_renderer(name, entries, version, sampled_at=None):
    """Bounded pre-rendered widths, decoded by standard BusyBox/coreutils tools."""
    sampled_at = int(time.time()) if sampled_at is None else int(sampled_at)
    cards = []
    for stale in (False, True):
        for width in (12, 16, 24, 32, 40, 52, 68, 80, 100):
            cards.append(f'@@{int(stale)}:{width}\n' + render(name, entries, version=version, width=width, color=True, stale=stale, sampled_at=sampled_at, _dynamic_history_age=True))
    return '''#!/bin/sh
# NARWHAL MANAGED INTERACTIVE BANNER v1
[ -t 1 ] || exit 0
exec 3<&1
cols=$(stty size <&3 2>/dev/null | awk '{print $2}')
exec 3<&-
case "$cols" in ''|*[!0-9]*|0) cols=${COLUMNS:-80};; esac
case "$cols" in ''|*[!0-9]*|0) cols=80;; esac
[ "$cols" -ge 12 ] || exit 0
width=12
for size in 16 24 32 40 52 68 80 100; do
    [ "$size" -le "$cols" ] && width=$size
done
color=1
if [ "${NO_COLOR+x}" = x ] || [ "${TERM:-dumb}" = dumb ] || [ "${SECURITY_MOTD_COLOR:-true}" = false ]; then color=0; fi
now=$(date +%s 2>/dev/null)
stale=1
case "$now" in ''|*[!0-9]*) :;; *) [ "$now" -ge SAMPLE_EPOCH ] && [ "$((now - SAMPLE_EPOCH))" -le 900 ] && stale=0;; esac
base64 -d <<'NARWHAL_CARD_DATA' | gzip -dc | LC_ALL=C awk -v key="@@$stale:$width" -v color="$color" -v width="$width" -v now="$now" '
    function age(epoch, english, minutes, hours) {
        if (now !~ /^[0-9]+$/ || now < epoch) return english ? "time unknown" : "时间待核实"
        minutes=int((now-epoch)/60)
        if (minutes<1) return english ? "just now" : "刚刚"
        if (minutes<60) return english ? minutes " minutes ago" : minutes "分钟前"
        hours=int(minutes/60)
        if (hours<24) return english ? hours "h " minutes%60 "m ago" : hours "小时" minutes%60 "分钟前"
        return english ? int(hours/24) "d " hours%24 "h ago" : int(hours/24) "天" hours%24 "小时前"
    }
    function age_line(part, cells, body, esc) {
        body="  " part sprintf("%*s",width-4-cells,"")
        esc=sprintf("%c",27)
        if (color) printf "%s[32m│%s[0m%s[37m%s%s[0m%s[32m│%s[0m\\n",esc,esc,esc,body,esc,esc,esc
        else print "│" body "│"
    }
    function age_rows(text, i, ch, bytes, size, part, cells) {
        # Text is generated only from numeric ages and fixed ASCII/CJK literals.
        # In LC_ALL=C, these CJK literals use three UTF-8 bytes / two cells.
        part="";cells=0
        for (i=1;i<=length(text);i+=bytes) {
            ch=substr(text,i,1);bytes=(ch ~ /^[ -~]$/ ? 1 : 3);size=(bytes==1 ? 1 : 2)
            ch=substr(text,i,bytes)
            if (cells+size>width-6) { age_line(part,cells);part="";cells=0 }
            part=part ch;cells+=size
        }
        age_line(part,cells)
    }
    /^@@[01]:[0-9]+$/ { selected=($0 == key); next }
    selected && /^@@AGE:[0-9]+:[01](:[01])?$/ {
        split($0,fields,":")
        age_rows((fields[4]==1 ? (fields[3]==1 ? "Recovered: " : "恢复于：") : (fields[3]==1 ? "Last occurred: " : "最近发生：")) age(fields[2],fields[3]))
        next
    }
    selected { if (!color) gsub(sprintf("%c",27) "\\\\[[0-9;]*m", ""); print }
'
'''.replace('SAMPLE_EPOCH', str(sampled_at)) + base64.b64encode(gzip.compress(''.join(cards).encode(), mtime=0)).decode() + '\nNARWHAL_CARD_DATA\n'


def shell_hook():
    return '''# NARWHAL MANAGED INTERACTIVE BANNER v1
case $- in
  *i*) if [ -z "${NARWHAL_BANNER_SHOWN:-}" ] && [ -t 1 ] && [ -r /etc/narwhal-banner.sh ]; then
         NARWHAL_BANNER_SHOWN=1
         COLUMNS=${COLUMNS:-80} /bin/sh /etc/narwhal-banner.sh
       fi;;
esac
'''


def merge_shell(original, hook):
    pattern = re.compile(re.escape(SHELL_START) + r'\n.*?' + re.escape(SHELL_END) + r'\n?', re.S)
    cleaned = pattern.sub('', original)
    if SHELL_START in cleaned or SHELL_END in cleaned:
        raise ValueError('shell hook markers incomplete')
    return SHELL_START + '\n' + hook + SHELL_END + '\n' + cleaned


def install_shell(container, entries, checked_exec, version, now):
    read = "[ ! -L /root ] && [ -d /root ] && [ ! -L /root/.bashrc ] && { [ ! -e /root/.bashrc ] || [ -f /root/.bashrc ]; } && { [ ! -e /root/.bashrc ] || [ $(wc -c < /root/.bashrc) -le 65536 ]; } && { cat /root/.bashrc 2>/dev/null || [ ! -e /root/.bashrc ]; }"
    ok, original = checked_exec(container, read)
    if not ok:
        return False, False
    try:
        rc = merge_shell(original, shell_hook())
    except ValueError:
        return False, False
    files = [('/etc/narwhal-banner.sh', shell_renderer(str(container['name']), entries, version, now), '644'),
             ('/etc/profile.d/90-narwhal-banner.sh', shell_hook(), '644'), ('/root/.bashrc', rc, None)]
    commands = ["set -eu; for tool in awk stty date base64 gzip cmp; do command -v \"$tool\" >/dev/null || exit 1; done; [ ! -L /etc/profile.d ]; mkdir -p /etc/profile.d; changed=0"]
    for path, content, mode in files:
        owned = '' if path == '/root/.bashrc' else f"if [ -e {path} ]; then grep -q '^# NARWHAL MANAGED INTERACTIVE BANNER v1$' {path} || exit 1; fi; "
        commands.append(f"[ ! -L {path} ]; [ ! -e {path} ] || [ -f {path} ]; " + owned +
                        f"t=$(mktemp {path}.XXXXXX); trap 'rm -f -- \"$t\"' EXIT; " +
                        (f"chmod {mode} \"$t\"; " if mode else f"if [ -e {path} ]; then cp -p {path} \"$t\"; else chmod 644 \"$t\"; fi; ") +
                        "printf '%s' " + shlex.quote(content) + f" > \"$t\"; if cmp -s \"$t\" {path}; then rm -f -- \"$t\"; else mv -f -- \"$t\" {path}; changed=1; fi; trap - EXIT; " +
                        f"printf '%s' {shlex.quote(content)} | cmp -s - {path}")
    commands.append("printf '\\nNARWHAL_SHELL_OK:%s\\n' \"$changed\"")
    ok, result = checked_exec(container, '; '.join(commands))
    return ok and 'NARWHAL_SHELL_OK:' in result, 'NARWHAL_SHELL_OK:1' in result


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
                    incidents.setdefault(key,[e for e in value[:4] if isinstance(e,dict)])
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


def update(container, alerts, threat_types, checked_exec, server_states, version, partial=False):
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
    notices = [s for s in server_states if s.get('type') == 'user_notice'
        and (s.get('runtime'), s.get('project'), s.get('name')) == (container.get('runtime',''), container.get('project',''), name)
        and (not s.get('expected_container_id') or s.get('expected_container_id') == str(container.get('id') or ''))
        and now-float(s.get('updated_at',0)) < 900 and float(s.get('expires_at',0)) > now
        and re.fullmatch(r'NOTICE-[0-9a-f]{32}', str(s.get('event_id','')))]
    # Manual notices remain until their explicit expiry, independent of alert recovery.
    entries[:] = [e for e in entries if e.get('type') != 'user_notice']
    for s in notices[:5]:
        entries.append({'type':'user_notice','event_id':s['event_id'],'time_epoch':s.get('created_at',now),
            'first_seen_epoch':s.get('created_at',now), 'title':safe(s.get('title')),
            'detail':safe(str(s.get('message','')).replace('\n','；'),1600), 'severity':'warning','state':'active','clean_samples':0,
            'action':'用户通知；请检查设置', 'expires_at':s['expires_at']})
    relevant=[a for a in alerts if a.get('type') != 'standalone_proxy_panel' and (a.get("severity") in {"warning", "critical"} or a.get("type") in threat_types)]
    for a in relevant:
        e=next((e for e in entries if e.get("type")==a.get("type") and not e.get('historical') and e.get('state') != 'verified'),None)
        if e is None:
            e={"type":a.get("type"),"first_seen_epoch":now,"event_id":"LOCAL-"+hashlib.sha256((key+str(a.get("type"))+str(int(now))).encode()).hexdigest()[:12]}
            entries.append(e)
        rem=a.get("automatic_remediation") or a.get("socks_auth_enforcement") or {}
        success=isinstance(rem,dict) and rem.get("succeeded") is True
        failed=isinstance(rem,dict) and rem.get("attempted") is True and not success
        observation = a.get('observation') if isinstance(a.get('observation'), dict) else {}
        metrics = []
        for field in ('value', 'threshold', 'duration_seconds'):
            value = observation.get(field, a.get(field))
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                metrics.append(f'{field}={value}')
        e.update(time_epoch=now,timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime(now)),
                 title=safe(a.get('title') or a.get('type')), metrics=' / '.join(metrics),
                 detail=safe(a.get("message")),severity=a.get("severity","warning"),clean_samples=0,
                 state="awaiting_report" if success else "recurring" if failed else "active",
                 action="Execution succeeded; awaiting verification" if success else "Execution failed" if failed else "Detected; not remediated")
        e['customer'] = {key: [safe(v, 100) for v in a.get(field, [])[:4] if isinstance(v, str)]
                         for key, field in (('domains', 'unapproved_domains'), ('programs', 'process_patterns')) if isinstance(a.get(field), list)}
    present={a.get("type") for a in relevant}
    for e in entries:
        if e.get('type') == 'user_notice':
            continue
        if e.get('historical') or e.get('state') == 'verified':
            e['historical'] = True
            # Legacy snapshots have no recovery timestamp. Retain them for a full
            # week after migration, without presenting migration time as recovery.
            if 'recovered_at_epoch' not in e:
                e.setdefault('retained_from_epoch', now)
            continue
        matching=next((s for s in server_states if (s.get("runtime"),s.get("project"),s.get("name"),s.get("type"))==(container.get("runtime",""),container.get("project",""),name,e.get("type")) and now-float(s.get("updated_at",0))<900),None)
        if matching:
            e["event_id"]=safe(matching.get("event_id"),80)
        if e.get("type") not in present:
            if partial:
                continue  # Incremental notices are not a clean observation.
            socks=container.get("security",{}).get("socks_proxy",{})
            unknown=e.get("type") in {"socks_weak_auth", "socks_password_review"} and ("detected" not in socks or (socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}))
            e["clean_samples"]=0 if unknown else int(e.get("clean_samples",0))+1
            e["state"]="unverified" if unknown else "verified" if e["clean_samples"]>=2 else "resolved"
            e["action"]="Two fresh samples verified clean" if e["state"]=="verified" else "Awaiting fresh evidence"
            if matching and matching.get("state") in {"recurring","unverified","awaiting_report","suppressed"}:
                e["state"]=matching["state"]
            if e['state'] == 'verified':
                e['historical'] = True
                e.setdefault('recovered_at_epoch', now)
    try: retention=max(7*86400,min(30*86400,float(os.getenv("SECURITY_MOTD_ALERT_RETENTION_HOURS","168"))*3600))
    except ValueError: retention=7*86400
    for k in list(incidents):
        incidents[k][:] = select_entries([e for e in incidents[k] if e.get('state') != 'suppressed'
            and now-float(e.get('recovered_at_epoch', e.get('retained_from_epoch', e.get('time_epoch', 0)))) <= retention])
        if not incidents[k]:
            incidents.pop(k,None)
    for k in list(_checks):
        if k not in incidents or now-_checks[k][0]>86400:
            _checks.pop(k,None)
    if len(_checks)>1000:
        for k in sorted(_checks,key=lambda k:_checks[k][0])[:-1000]:
            _checks.pop(k,None)
    persisted=persist()
    # Default branding remains even after incident retention expires. A shell hook
    # renders at session width; MOTD is the fallback only, preventing SSH duplicates.
    shell_ok, shell_changed = install_shell(container, entries, checked_exec, version, int(now))
    banner="" if shell_ok else render(name,entries,version=version,sampled_at=int(now))
    changed=shell_changed
    delivery['shell_delivery'] = 'installed' if shell_ok else 'failed'
    try:
        pid=int(container.get("pid") or 0)
        if pid>1:
            changed=write_proc(pid,banner) or changed
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
    if shell_ok or delivery.get('status') in {'written','unchanged'}:
        delivery['format_version'] = 2
    delivery["event_ids"]=[e["event_id"] for e in entries]
    # Only IDs selected for actual rendering may be acknowledged as delivered.
    delivery['notice_ids'] = [e['event_id'] for e in select_entries(entries) if e.get('type') == 'user_notice']
    # Read-only login mechanism check, not a promise that an SSH session displayed it.
    if key not in _checks or now-_checks[key][0]>3600:
        ok,mechanism=checked_exec(container,"if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep '^printmotd '; fi; if grep -qs pam_motd /etc/pam.d/sshd; then printf 'pam_motd\\n'; fi; if grep -qs '/etc/motd' /etc/profile; then printf 'profile_motd\\n'; fi; true")
        _checks[key]=(now,"configured" if ok and any(v in mechanism for v in ("printmotd yes","pam_motd","profile_motd")) else "unverified")
    delivery["login_display"]=_checks[key][1]
    if shell_ok:
        delivery.update(mechanism='interactive_shell_card', login_display='configured')
    return changed
