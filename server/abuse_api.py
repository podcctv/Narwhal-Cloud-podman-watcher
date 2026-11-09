"""Signed incremental abuse events and administrator-reviewed network release."""
import json
import re
import time
from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse


KINDS = {'outbound_scan', 'authentication_bruteforce', 'credential_stuffing', 'identity_enumeration'}
REPLACEMENT_REVIEW_VERSION = (1, 7, 188)
RUNMAN_VM_ID_RE = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')
RUNMAN_GENERATION_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')


def supports_replacement_review(version):
    try:
        parsed = tuple(int(part) for part in str(version or '').split('.'))
        return len(parsed) == 3 and parsed >= REPLACEMENT_REVIEW_VERSION
    except (TypeError, ValueError):
        return False


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
    if runtime == 'runman':
        valid_identity = project == 'default' and RUNMAN_VM_ID_RE.fullmatch(name) and RUNMAN_GENERATION_RE.fullmatch(identity)
    else:
        valid_identity = runtime in {'incus', 'podman'} and re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}', name) and re.fullmatch(r'[A-Za-z0-9-]{12,100}', identity)
    if not valid_identity:
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
        if not isinstance(item.get('pid'), int) or isinstance(item['pid'], bool) or not 1 <= item['pid'] <= 4194304 or not re.fullmatch(r'\d{1,32}', str(item.get('start_ticks') or '')):
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
        for key in ('target_count', 'private_target_count', 'public_target_count', 'owned_http_connections', 'pending_attempts', 'vertical_ports', 'horizontal_targets', 'failed_ratio', 'pending_ratio'):
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
    if not record or record['status'] in {'released', 'replaced'}:
        raise HTTPException(409, 'no pending quarantine review')
    if conn.execute("SELECT 1 FROM security_actions WHERE alert_id=? AND action_type='confirm_replaced_network_quarantine' AND status IN ('queued','dispatched','running') LIMIT 1", (alert_id,)).fetchone():
        raise HTTPException(409, 'container replacement review is already in progress')
    host = conn.execute('SELECT node_id,last_seen FROM hosts WHERE host_id=?', (alert['host_id'],)).fetchone()
    if not host or not host['node_id'] or not 0 <= now-int(host['last_seen'] or 0) <= 900:
        raise HTTPException(409, 'node is stale; cannot safely restore connectivity')
    return queue(conn, alert, 'release_network_quarantine', {'instance_id': identity, 'expected_node_id': host['node_id']}, requested_by)


def queue_replacement_review(conn, alert_id, requested_by, queue, now=None):
    """Queue a node-side proof that the quarantined identity was replaced."""
    now = int(time.time()) if now is None else now
    alert = conn.execute('SELECT * FROM security_alerts WHERE id=?', (alert_id,)).fetchone()
    if not alert or alert['alert_type'] != 'prohibited_activity':
        raise HTTPException(404, 'quarantine alert not found')
    details = json.loads(alert['details_json'] or '{}')
    identity = str(details.get('instance_id') or '')
    record = conn.execute(
        'SELECT status FROM network_quarantines WHERE alert_id=? AND instance_id=?',
        (alert_id, identity),
    ).fetchone()
    if not record or record['status'] in {'released', 'replaced'}:
        raise HTTPException(409, 'no pending quarantine replacement review')
    if conn.execute("SELECT 1 FROM security_actions WHERE alert_id=? AND action_type='release_network_quarantine' AND status IN ('queued','dispatched','running') LIMIT 1", (alert_id,)).fetchone():
        raise HTTPException(409, 'network release review is already in progress')
    host = conn.execute('SELECT node_id,last_seen,agent_version FROM hosts WHERE host_id=?', (alert['host_id'],)).fetchone()
    if not host or not host['node_id'] or not 0 <= now-int(host['last_seen'] or 0) <= 900:
        raise HTTPException(409, 'node is stale; replacement cannot be verified')
    if not supports_replacement_review(host['agent_version']):
        raise HTTPException(409, 'Client 1.7.188 or newer is required for replacement identity review')
    return queue(conn, alert, 'confirm_replaced_network_quarantine', {
        'instance_id': identity, 'expected_node_id': host['node_id'],
    }, requested_by)


def record_release_result(conn, row, params, status, now, message=''):
    if row['action_type'] != 'release_network_quarantine' or status not in {'succeeded', 'failed'}:
        return
    old_identity = str(params.get('instance_id') or '')
    is_deleted = 'container_deleted' in str(message or '')
    state = 'replaced' if is_deleted else ('released' if status == 'succeeded' else 'release_failed')
    conn.execute('UPDATE network_quarantines SET status=?,updated_at=? WHERE alert_id=? AND instance_id=?',
                 (state, now, row['alert_id'], old_identity))
    old = conn.execute('SELECT details_json FROM security_alerts WHERE id=?', (row['alert_id'],)).fetchone()
    if old:
        details = json.loads(old[0] or '{}')
        details.setdefault('network_quarantine', {}).update(
            status=state, ingress_blocked=False, egress_blocked=False,
            container_deleted=is_deleted,
        )
        if is_deleted:
            result_message = (
                f'管理员复核确认旧实例 {old_identity} 及其容器已被用户删除；'
                '旧隔离记录已归档，无需恢复网络。'
            )
        else:
            result_message = (
                '管理员已解除隔离，正在重新监测；不等于风险已恢复，若再次命中将重新隔离。'
                if status == 'succeeded' else '解除隔离未能完整验证，需要人工检查；未删除容器或数据。'
            )
        conn.execute('UPDATE security_alerts SET details_json=?,message=?,status=? WHERE id=?',
                     (json.dumps(details, ensure_ascii=False), result_message, 'resolved' if status == 'succeeded' else 'active', row['alert_id']))


def record_replacement_result(conn, row, params, status, now, message=''):
    if row['action_type'] != 'confirm_replaced_network_quarantine' or status not in {'succeeded', 'failed'}:
        return
    old_identity = str(params.get('instance_id') or '')
    quarantine = conn.execute(
        'SELECT status FROM network_quarantines WHERE alert_id=? AND instance_id=?',
        (row['alert_id'], old_identity),
    ).fetchone()
    proof = re.fullmatch(
        r'replacement_verified current_instance_id=([A-Za-z0-9-]{4,100}) '
        r'(?:container_deleted=true )?old_instance_absent=true old_journal_cleared=true',
        str(message or '').strip(),
    )
    new_identity = proof.group(1) if proof else ''
    if status == 'succeeded' and (
        not quarantine or quarantine['status'] in {'released', 'replaced'}
        or not new_identity or (new_identity != 'none' and new_identity == old_identity)
    ):
        status = 'failed'
        conn.execute(
            "UPDATE security_actions SET status='failed',result_message=?,updated_at=? WHERE id=?",
            ('replacement proof missing or invalid; quarantine remains pending', now, row['id']),
        )
    old = conn.execute('SELECT details_json FROM security_alerts WHERE id=?', (row['alert_id'],)).fetchone()
    if status == 'succeeded':
        conn.execute(
            "UPDATE network_quarantines SET status='replaced',updated_at=? WHERE alert_id=? AND instance_id=?",
            (now, row['alert_id'], old_identity),
        )
        if old:
            details = json.loads(old[0] or '{}')
            is_deleted = new_identity == 'none' or 'container_deleted=true' in str(message or '')
            details.setdefault('network_quarantine', {}).update(
                status='replaced', ingress_blocked=False, egress_blocked=False,
                replaced_instance_id=new_identity, replacement_verified_at=now,
                container_deleted=is_deleted,
            )
            if is_deleted:
                result_message = (
                    f'管理员复核确认旧实例 {old_identity} 及其容器已被用户删除；'
                    '旧隔离记录已归档，不再占用资源配额。'
                )
            else:
                result_message = (
                    f'管理员复核确认旧实例 {old_identity} 已不存在；新实例 {new_identity} 未被改动。'
                    '旧隔离记录已归档；新实例仍会按当前身份持续监测。'
                )
            conn.execute(
                "UPDATE security_alerts SET details_json=?,message=?,status='resolved' WHERE id=?",
                (json.dumps(details, ensure_ascii=False), result_message, row['alert_id']),
            )
    else:
        conn.execute(
            "UPDATE network_quarantines SET updated_at=? WHERE alert_id=? AND instance_id=? AND status NOT IN ('released','replaced')",
            (now, row['alert_id'], old_identity),
        )
        if old:
            details = json.loads(old[0] or '{}')
            details.setdefault('network_quarantine', {}).update(replacement_review='unverified')
            conn.execute(
                "UPDATE security_alerts SET details_json=?,message=?,status='active' WHERE id=?",
                (json.dumps(details, ensure_ascii=False),
                 '未能验证旧容器身份已被替换；隔离记录仍待管理员复核，未改动任何容器网络。', row['alert_id']),
            )


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
        chunks = bytearray()
        async for chunk in request.stream():
            if len(chunks)+len(chunk)>65536:
                raise HTTPException(413, 'event too large')
            chunks.extend(chunk)
        body = bytes(chunks)
        verify_signature(body, x_timestamp, x_signature)
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
            rows = conn.execute('''SELECT q.*,a.title,a.message,a.details_json,h.last_seen host_last_seen,h.agent_version host_agent_version,
                (SELECT s.status FROM security_actions s WHERE s.alert_id=q.alert_id
                 AND s.action_type='release_network_quarantine' ORDER BY s.id DESC LIMIT 1) release_action_status,
                (SELECT s.status FROM security_actions s WHERE s.alert_id=q.alert_id
                 AND s.action_type='confirm_replaced_network_quarantine' ORDER BY s.id DESC LIMIT 1) replacement_action_status
                FROM network_quarantines q JOIN security_alerts a ON a.id=q.alert_id
                LEFT JOIN hosts h ON h.host_id=q.host_id WHERE q.status NOT IN ('released','replaced')
                ORDER BY q.updated_at DESC LIMIT 200''').fetchall()
            items = []
            for row in rows:
                item = {**{key: row[key] for key in row.keys() if key != 'details_json'},
                        'details': json.loads(row['details_json'] or '{}')}
                item['replacement_review_supported'] = supports_replacement_review(item.get('host_agent_version'))
                items.append(item)
            return {'items': items}
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

    @app.post('/api/v1/security/alerts/{alert_id}/confirm-container-replaced')
    async def confirm_container_replaced(alert_id: int, request: Request):
        if getattr(request.state, 'dashboard_role', 'viewer') != 'admin':
            raise HTTPException(403, 'administrator review required')
        payload = await request.json()
        if not isinstance(payload, dict) or payload.get('confirmed') is not True:
            raise HTTPException(400, 'explicit replacement review confirmation required')
        conn = db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            action, queued = queue_replacement_review(
                conn, alert_id, str(getattr(request.state, 'dashboard_user', 'admin')), queue,
            )
            conn.commit()
            return JSONResponse({'ok': True, 'queued': queued, 'action_id': action['id']}, status_code=202 if queued else 200)
        finally:
            conn.close()

