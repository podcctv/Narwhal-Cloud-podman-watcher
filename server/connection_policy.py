"""Deterministic, bounded connection evidence and continuous-window policy.

Socket totals include TCP states and UDP sockets, not people or HTTP requests.
Old/partial/host-network samples are notification-only. No process kill or
firewall rule is inferred from an aggregate count.
"""
import json
import time


def initialize(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS connection_windows(
        host_id TEXT, runtime TEXT, project TEXT, container_name TEXT,
        payload TEXT NOT NULL, PRIMARY KEY(host_id,runtime,project,container_name))""")


def metrics(container, now, stale_seconds=900):
    sec = container.get('security') or {}
    m = sec.get('connection_metrics') if isinstance(sec, dict) else None
    if not isinstance(m, dict) or m.get('schema') != 1 or m.get('valid') is not True:
        return None
    fields = ('total', 'tcp_total', 'tcp_established', 'tcp_pending', 'tcp_time_wait', 'udp_sockets', 'sampled_at')
    if any(type(m.get(k)) is not int or m[k] < 0 for k in fields):
        return None
    if (not isinstance(m.get('epoch'), str) or not m['epoch'] or len(m['epoch']) > 200
            or m.get('source') != 'container_proc_net'
            or m['total'] != m['tcp_total'] + m['udp_sockets']
            or m['tcp_established'] + m['tcp_pending'] + m['tcp_time_wait'] > m['tcp_total']
            or m['sampled_at'] > now + 30 or now - m['sampled_at'] > stale_seconds
            or m['total'] != container.get('conn_count')):
        return None
    return m


def observe(conn, host, ts, containers, critical, stop, duration, max_gap, now=None, auto_stop=True, before_stop=None):
    now = int(time.time()) if now is None else now
    queued = 0
    active = set()
    for c in containers:
        key = (host, str(c.get('runtime') or 'podman').lower()[:40], str(c.get('project') or '')[:100], str(c.get('name') or 'unknown')[:200])
        active.add(key)
        row = conn.execute('SELECT payload FROM connection_windows WHERE host_id=? AND runtime=? AND project=? AND container_name=?', key).fetchone()
        old = json.loads(row[0]) if row else {}
        m = metrics(c, now)
        policy = {'metric': 'TCP 各状态 + UDP socket 总数', 'critical_threshold': critical,
                  'stop_threshold': stop, 'required_duration_seconds': duration,
                  'critical_duration_seconds': 0, 'stop_duration_seconds': 0,
                  'max_gap_seconds': max_gap, 'valid': m is not None,
                  'status': 'waiting_threshold', 'reason': '未达到自动停机门槛'}
        if m is None:
            state = {'last': max(ts, old.get('last', 0)), 'epoch': '', 'critical_since': 0, 'stop_since': 0}
            policy.update(status='unverified', reason='采样缺失、过期或口径未验证；仅提醒，不自动停止')
        elif m['sampled_at'] <= old.get('last', 0):
            # Replayed/out-of-order samples neither extend nor erase a newer window.
            c['connection_policy'] = {**policy, **old.get('policy', {}), 'status': 'out_of_order', 'reason': '重复或乱序采样，不计入连续时长'}
            continue
        else:
            stamp = m['sampled_at']
            epoch = f"{m['epoch']}:{critical}:{stop}:{duration}:{max_gap}"
            continuous = old.get('epoch') == epoch and 0 < stamp - old.get('last', 0) <= max_gap
            state = {'last': stamp, 'epoch': epoch}
            state['retries'] = old.get('retries', 0) if continuous else 0
            for label, threshold in (('critical', critical), ('stop', stop)):
                above = m['total'] > threshold
                state[label + '_since'] = (old.get(label + '_since') or stamp) if above and continuous else stamp if above else 0
                state[label + '_samples'] = old.get(label + '_samples', 0) + 1 if above and continuous else 1 if above else 0
                policy[label + '_duration_seconds'] = stamp - state[label + '_since'] if above else 0
            if m['total'] > stop:
                policy.update(status='waiting_duration', reason='已超过停机门槛，等待连续有效采样达到要求')
            if policy['critical_duration_seconds'] >= 900:
                policy['escalated'] = True
                if m['total'] <= stop:
                    policy['reason'] = '严重超标已持续至少15分钟：刷新取证并升级提醒，尚未达到停机门槛'
            pending = conn.execute("SELECT id,status,updated_at,attempts,params_json FROM security_actions WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND action_type='stop_container' ORDER BY id DESC LIMIT 1", key).fetchone()
            if pending:
                previous = json.loads(pending['params_json'])
                if previous.get('threshold') != stop or previous.get('required_duration_seconds') != duration:
                    pending = None  # A different policy cannot lend a pending action/retry history.
            if pending and pending['status'] == 'succeeded' and pending['updated_at'] >= state['stop_since'] and state['stop_since']:
                state['stop_since'], state['stop_samples'] = stamp, 1
                policy['stop_duration_seconds'] = 0
            ready = (m['total'] > stop and policy['stop_duration_seconds'] >= duration
                     and state['stop_samples'] >= (2 if duration <= 300 else 3) and key[1] in ('podman', 'incus'))
            if not auto_stop:
                ready = False
                policy.update(status='disabled', reason='自动停机保护已暂停；继续采集和提醒')
            if pending and pending['status'] in ('queued', 'dispatched', 'running'):
                policy.update(status=pending['status'], action_id=pending['id'], reason='停机保护动作已下发，等待节点回执')
                if now - pending['updated_at'] > max_gap:
                    policy['reason'] = '停机动作等待回执已超时：需要管理员排查；不会重复下发'
            elif ready and pending and pending['status'] == 'failed' and (state['retries'] >= 3 or now - pending['updated_at'] < 900):
                policy.update(status='failed', action_id=pending['id'], reason='停机保护执行失败：需要管理员排查，已限制重试频率')
            elif ready:
                params = {'reason': 'sustained_connection_overload', 'connection_count': m['total'],
                          'threshold': stop, 'duration_seconds': policy['stop_duration_seconds'],
                          'required_duration_seconds': duration, 'metric_schema': 1,
                          'metric_epoch': m['epoch'], 'observed_at': stamp, 'expires_at': now + max_gap,
                          'stop_since':state['stop_since']}
                # Protection is independent of delivery/mapping/API availability.
                params['notice_best_effort'] = True
                action = conn.execute("""INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at)
                    VALUES(0,?,?,?,?,'stop_container',?,'queued','system:connection-guard',?,?)""", (*key, json.dumps(params), now, now)).lastrowid
                policy.update(status='queued', action_id=action, reason='已立即下发停机保护；通知尽力发送，不阻塞处置；不会删除实例')
                state['retries'] += 1
                queued += 1
                if before_stop:
                    conn.execute('SAVEPOINT connection_notice')
                    try:
                        notice = before_stop(conn, key, params, now)
                        policy.update(notification_status=notice.get('status', 'queued'), notification_id=notice.get('notice_id', ''))
                        conn.execute('RELEASE connection_notice')
                    except Exception:
                        conn.execute('ROLLBACK TO connection_notice')
                        conn.execute('RELEASE connection_notice')
                        policy['notification_status'] = 'failed'
            if m['total'] > stop:
                conn.execute('INSERT OR REPLACE INTO connection_overloads VALUES(?,?,?,?,?,?,?,?)', (*key, state['stop_since'], stamp, state['stop_samples'], policy.get('action_id')))
        if not m or m['total'] <= stop:
            conn.execute('DELETE FROM connection_overloads WHERE host_id=? AND runtime=? AND project=? AND container_name=?', key)
        state['policy'] = policy
        c['connection_policy'] = policy
        conn.execute('INSERT OR REPLACE INTO connection_windows VALUES(?,?,?,?,?)', (*key, json.dumps(state)))
    for row in conn.execute('SELECT host_id,runtime,project,container_name FROM connection_windows WHERE host_id=?', (host,)).fetchall():
        if tuple(row) not in active:
            for table in ('connection_windows', 'connection_overloads'):
                conn.execute(f'DELETE FROM {table} WHERE host_id=? AND runtime=? AND project=? AND container_name=?', tuple(row))
    return queued


def enrich_alerts(alerts, containers):
    by_key = {(c.get('runtime', 'podman'), c.get('project', ''), c.get('name')): c for c in containers}
    # Connection-only operational signals duplicate the dedicated connection alert.
    dedicated = {(a.get('runtime'), a.get('project', ''), a.get('container_name')) for a in alerts if a.get('type') == 'container_connection_count'}
    result = []
    for alert in alerts:
        a = dict(alert)
        key = (a.get('runtime'), a.get('project', ''), a.get('container_name'))
        obs = a.get('observation') or {}
        if a.get('type') == 'ops_policy_signal' and key in dedicated and obs.get('signals', {}).get('connections') and not any(v for k, v in obs.get('signals', {}).items() if k != 'connections'):
            continue
        if a.get('type') == 'container_connection_count':
            c = by_key.get(key, {})
            a['connection_policy'] = c.get('connection_policy', {})
            a['connection_metrics'] = c.get('security', {}).get('connection_metrics', {})
        result.append(a)
    return result


def text(policy):
    if not isinstance(policy, dict) or not all(k in policy for k in ('metric','stop_threshold','required_duration_seconds','reason')):
        return '连续严重超标时长尚未验证；旧记录不能作为停机依据。'
    covered = f"{policy.get('critical_duration_seconds', 0)//60} 分钟（有效采样覆盖）" if policy.get('valid') else '尚未验证'
    return (f"统计口径：{policy['metric']}\n"
            f"连续严重超标：{covered}\n"
            f"自动停机：超过 {policy['stop_threshold']}，持续 {policy['required_duration_seconds']//60} 分钟，立即停机保护，通知失败不阻塞；"
            f"当前停机门槛覆盖 {policy.get('stop_duration_seconds', 0)//60} 分钟\n"
            f"处理状态：{policy['reason']}\n"
            '无法准确归属的服务不会自动限流或停止。')
