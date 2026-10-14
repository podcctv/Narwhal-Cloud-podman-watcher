"""Signed incremental abuse events and administrator-reviewed network release."""
import json
import re
import time
from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse


KINDS = {'outbound_scan', 'authentication_bruteforce', 'credential_stuffing', 'identity_enumeration'}


def initialize(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS network_quarantines(
        host_id TEXT NOT NULL, runtime TEXT NOT NULL, project TEXT NOT NULL,
        container_name TEXT NOT NULL, instance_id TEXT NOT NULL,
        alert_id INTEGER NOT NULL, status TEXT NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        PRIMARY KEY(host_id,runtime,project,container_name,instance_id))''')


def normalized_alert(value):
    if not isinstance(value, dict) or value.get('type') != 'prohibited_activity':
        raise HTTPException(400, 'invalid abuse event type')
    runtime, project, name, identity = (str(value.get(k) or '') for k in ('runtime', 'project', 'container_name', 'instance_id'))
    if runtime not in {'incus', 'podman'} or not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}', name) or not re.fullmatch(r'[A-Za-z0-9-]{12,100}', identity):
        raise HTTPException(400, 'stable supported instance identity required')
    if project and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', project):
        raise HTTPException(400, 'invalid project')
    source = value.get('abuse_evidence')
    if not isinstance(source, list) or not 1 <= len(source) <= 20:
        raise HTTPException(400, 'bounded corroborated evidence required')
    evidence = []
    for item in source:
        if not isinstance(item, dict) or item.get('kind') not in KINDS or item.get('confidence') != 'high':
            raise HTTPException(400, 'high-confidence feature evidence required')
        if not isinstance(item.get('pid'), int) or not 1 < item['pid'] <= 4194304 or not re.fullmatch(r'\d{1,32}', str(item.get('start_ticks') or '')):
            raise HTTPException(400, 'process incarnation required')
        features = item.get('features', {})
        if not isinstance(features, dict) or not isinstance(features.get('corroborating_samples'), int) or features['corroborating_samples'] < 2:
            raise HTTPException(400, 'multiple fresh corroborating samples required')
        clean = {k: item[k] for k in ('kind', 'confidence', 'pid', 'start_ticks')}
        for key in ('basis', 'tool', 'source_sha256'):
            text = str(item.get(key) or '')
            if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', text):
                clean[key] = text
        clean['features'] = {k: v for k, v in features.items() if k in {'http_calls', 'enumeration', 'dictionary_inputs', 'identity_generator', 'concurrency', 'corroborating_samples'} and isinstance(v, (bool, int)) and 0 <= v <= 1000000}
        for key in ('public_target_count', 'owned_http_connections', 'pending_attempts', 'vertical_ports', 'horizontal_targets', 'failed_ratio'):
            if isinstance(item.get(key), (int, float)) and 0 <= item[key] <= 1000000000:
                clean[key] = item[key]
        evidence.append(clean)
    network = value.get('network_quarantine') or {}
    state = network.get('status') if isinstance(network, dict) else None
    if state not in {'isolated', 'failed', 'release_failed'}:
        raise HTTPException(400, 'invalid isolation outcome')
    if state == 'isolated' and (network.get('ingress_blocked') is not True or network.get('egress_blocked') is not True):
        raise HTTPException(400, 'both directions must be verified')
    labels = {'outbound_scan':'对外扫描','authentication_bruteforce':'认证爆破','credential_stuffing':'撞库','identity_enumeration':'身份信息枚举'}
    return {'type': 'prohibited_activity', 'severity': 'critical', 'runtime': runtime, 'project': project,
            'container_name': name, 'instance_id': identity,
            'title': '违规活动：'+'、'.join(dict.fromkeys(labels[e['kind']] for e in evidence)),
            'message': '已验证并隔离全部受管入站和出站网络；保留容器与磁盘，等待管理员复核。' if state == 'isolated' else '发现高置信度违规活动，但双向隔离未能完整验证；需要立即人工处理，未删除数据。',
            'value': len(evidence), 'threshold': 1, 'abuse_evidence': evidence,
            'network_quarantine': {'status':state, 'ingress_blocked': state == 'isolated',
                                   'egress_blocked': state == 'isolated', 'data_preserved': True}}


def queue_release(conn, alert_id, requested_by, queue, now=None):
    now = int(time.time()) if now is None else now
    alert = conn.execute('SELECT * FROM security_alerts WHERE id=?', (alert_id,)).fetchone()
    if not alert or alert['alert_type'] != 'prohibited_activity':
        raise HTTPException(404, 'quarantine alert not found')
    details = json.loads(alert['details_json'] or '{}')
    identity = str(details.get('instance_id') or '')
    record = conn.execute('SELECT status FROM network_quarantines WHERE alert_id=? AND instance_id=?', (alert_id, identity)).fetchone()
    if not record or record['status'] == 'released':
        raise HTTPException(409, 'no pending quarantine review')
    host = conn.execute('SELECT node_id,last_seen FROM hosts WHERE host_id=?', (alert['host_id'],)).fetchone()
    if not host or not host['node_id'] or now-host['last_seen'] > 900:
        raise HTTPException(409, 'node is stale; cannot safely restore connectivity')
    return queue(conn, alert, 'release_network_quarantine', {'instance_id': identity, 'expected_node_id': host['node_id']}, requested_by)


def record_release_result(conn, row, params, status, now):
    if row['action_type'] != 'release_network_quarantine' or status not in {'succeeded', 'failed'}:
        return
    state = 'released' if status == 'succeeded' else 'release_failed'
    conn.execute('UPDATE network_quarantines SET status=?,updated_at=? WHERE alert_id=? AND instance_id=?',
                 (state, now, row['alert_id'], params.get('instance_id')))
    old = conn.execute('SELECT details_json FROM security_alerts WHERE id=?', (row['alert_id'],)).fetchone()
    if old:
        details = json.loads(old[0] or '{}')
        details.setdefault('network_quarantine', {}).update(status=state, ingress_blocked=False, egress_blocked=False)
        message = ('管理员已解除隔离，正在重新监测；不等于风险已恢复，若再次命中将重新隔离。'
                   if status == 'succeeded' else '解除隔离未能完整验证，需要人工检查；未删除容器或数据。')
        conn.execute('UPDATE security_alerts SET details_json=?,message=?,status=? WHERE id=?',
                     (json.dumps(details, ensure_ascii=False), message, 'resolved' if status == 'succeeded' else 'active', row['alert_id']))


def telegram_delivery(conn, alert_id):
    """Report delivery proof, not just acceptance of the signed Agent event."""
    bots = conn.execute("SELECT id,target FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
    if not bots:
        return {'state': 'unconfigured', 'delivered_targets': 0, 'configured_targets': 0}
    delivered = 0
    for bot in bots:
        row = conn.execute('SELECT message_id FROM telegram_alert_messages WHERE bot_id=? AND alert_id=?',
                           (bot['id'], alert_id)).fetchone()
        if row and row['message_id'] > 0:
            delivered += 1
    # This confirms initial delivery; live card refresh errors remain separately
    # visible in notification_bots. Never return targets or bot credentials.
    return {'state': 'delivered' if delivered == len(bots) else 'pending',
            'delivered_targets': delivered, 'configured_targets': len(bots)}


def attach(app, db, verify_signature, signed_response, process_alerts, sync_bots, queue):
    @app.post('/api/v1/abuse/events')
    async def event(request: Request, x_timestamp: str = Header(default=''), x_signature: str = Header(default='')):
        body = await request.body()
        verify_signature(body, x_timestamp, x_signature)
        if len(body) > 65536:
            raise HTTPException(413, 'event too large')
        try:
            payload = json.loads(body)
            host_id, node_id = str(payload.get('host_id') or ''), str(payload.get('node_id') or '')
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(400, 'invalid event payload')
        alert = normalized_alert(payload.get('alert'))
        now = int(time.time())
        conn = db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            host = conn.execute('SELECT node_id FROM hosts WHERE host_id=?', (host_id,)).fetchone()
            if not host or not node_id or host['node_id'] != node_id:
                raise HTTPException(403, 'event belongs to another node')
            process_alerts(conn, host_id, now, [alert], partial=True)
            record = conn.execute("SELECT id FROM security_alerts WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND alert_type='prohibited_activity' AND json_extract(details_json,'$.instance_id')=? ORDER BY last_seen DESC LIMIT 1",
                                  (host_id, alert['runtime'], alert['project'], alert['container_name'], alert['instance_id'])).fetchone()
            conn.execute('''INSERT INTO network_quarantines VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host_id,runtime,project,container_name,instance_id) DO UPDATE SET
                alert_id=excluded.alert_id,status=excluded.status,updated_at=excluded.updated_at''',
                         (host_id, alert['runtime'], alert['project'], alert['container_name'], alert['instance_id'], record['id'], alert['network_quarantine']['status'], now, now))
            conn.commit()
        finally:
            conn.close()
        sync_bots(host_id, now)
        conn = db()
        try:
            delivery = telegram_delivery(conn, record['id'])
        finally:
            conn.close()
        return signed_response({'ok': True, 'alert_id': record['id'], 'telegram_delivery': delivery}, x_timestamp)

    @app.get('/api/v1/security/quarantines')
    def quarantines():
        conn = db()
        try:
            rows = conn.execute('''SELECT q.*,a.title,a.message,a.details_json,h.last_seen host_last_seen,
                (SELECT s.status FROM security_actions s WHERE s.alert_id=q.alert_id
                 AND s.action_type='release_network_quarantine' ORDER BY s.id DESC LIMIT 1) release_action_status
                FROM network_quarantines q JOIN security_alerts a ON a.id=q.alert_id
                LEFT JOIN hosts h ON h.host_id=q.host_id WHERE q.status<>'released'
                ORDER BY q.updated_at DESC LIMIT 200''').fetchall()
            return {'items': [{**{k: r[k] for k in r.keys() if k != 'details_json'},
                               'details':json.loads(r['details_json'] or '{}')} for r in rows]}
        finally:
            conn.close()

    @app.post('/api/v1/security/alerts/{alert_id}/release-quarantine')
    async def release(alert_id: int, request: Request):
        if getattr(request.state, 'dashboard_role', 'viewer') != 'admin':
            raise HTTPException(403, 'administrator review required')
        payload = await request.json()
        if not isinstance(payload, dict) or payload.get('confirmed') is not True:
            raise HTTPException(400, 'explicit review confirmation required')
        conn = db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            action, queued = queue_release(conn, alert_id, str(getattr(request.state, 'dashboard_user', 'admin')), queue)
            conn.commit()
            return JSONResponse({'ok': True, 'queued': queued, 'action_id': action['id']}, status_code=202 if queued else 200)
        finally:
            conn.close()

