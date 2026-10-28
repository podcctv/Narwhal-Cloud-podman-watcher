"""Master-led, fixed-revision fleet reconciliation; never races local timers."""
import asyncio
import json
import logging
import os
import re
import time
import urllib.request
try:
    from server import upgrade_health
except ImportError:
    import upgrade_health

REPOSITORY = 'podcctv/Narwhal-Cloud-podman-watcher'
ACTIVE = ('queued', 'dispatched', 'running')


def settings(conn):
    row = conn.execute("SELECT payload FROM ops_settings WHERE key='fleet_updates'").fetchone()
    return {'enabled': True, 'holds': [], **(json.loads(row[0]) if row else {})}


def save(conn, value):
    conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('fleet_updates',?)", (json.dumps(value),))


def reclaim_superseded_actions(conn, now):
    """Release dispatch slots held by actions from superseded campaigns."""
    conn.execute(
        """UPDATE security_actions
           SET status='failed', result_message=?, updated_at=?
           WHERE action_type='managed_upgrade'
             AND status IN ('queued','dispatched','running')
             AND id IN (
                 SELECT n.action_id
                 FROM ops_upgrade_nodes n
                 JOIN ops_upgrades u ON u.id=n.campaign
                 WHERE n.action_id IS NOT NULL
                   AND u.status='superseded'
             )""",
        ('自动发布已被较新版本取代；旧动作不再派发', now),
    )
    conn.execute(
        """UPDATE ops_upgrade_nodes SET status='superseded'
           WHERE status IN ('pending','dispatched','running')
             AND campaign IN (
                 SELECT id FROM ops_upgrades
                 WHERE status='superseded'
             )"""
    )


def resolve(version):
    """Require this running image's immutable build revision, not just a tag."""
    revision = os.getenv('NARWHAL_REVISION', '')
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('running image has no immutable build revision')
    def get(path):
        req = urllib.request.Request(path, headers={'User-Agent': 'Narwhal-Fleet'})
        with urllib.request.urlopen(req, timeout=12) as response:
            return response.read(100_000)
    # The commits endpoint may include a large file list/diff; truncating it at
    # 100 KB can turn a valid response into malformed JSON. The Git ref endpoint
    # returns only the branch's commit pointer, which is all we need here.
    ref = get(f'https://api.github.com/repos/{REPOSITORY}/git/ref/heads/main')
    head = json.loads(ref)['object']['sha']
    if head != revision or get(f'https://raw.githubusercontent.com/{REPOSITORY}/{revision}/VERSION').decode().strip() != version:
        raise ValueError('running release is not the current published main')
    return revision


def reconcile(conn, version, revision, now=None):
    """One transactional tick. No network I/O; retries and state survive restart."""
    now = int(time.time()) if now is None else now
    conn.execute('BEGIN IMMEDIATE')
    cfg = settings(conn)
    if not cfg['enabled']:
        conn.rollback()
        return
    reclaim_superseded_actions(conn, now)
    hosts = conn.execute('SELECT h.*,o.payload AS ops_payload,o.ts AS ops_ts FROM hosts h JOIN ops_hosts o ON o.host_id=h.host_id AND o.node=h.node_id ORDER BY h.last_seen DESC,h.host_id LIMIT 500').fetchall()
    eligible = {h['host_id']: h for h in hosts if h['node_id'] and json.loads(h['ops_payload']).get('managed_upgrade') and h['host_id'] not in cfg['holds']}
    campaign = conn.execute("SELECT * FROM ops_upgrades WHERE version=? AND revision=? ORDER BY id DESC LIMIT 1", (version, revision)).fetchone()
    # Manual campaigns remain under operator control. Never silently promote one.
    if campaign and not json.loads(campaign['payload']).get('automatic'):
        conn.commit()
        return
    # A paused campaign is an explicit operator safety boundary. Do not let a
    # later coordinator tick silently restart it or send more nodes.
    if campaign and campaign['status'] == 'paused':
        save(conn, {**cfg, 'last_checked': now, 'target_version': version, 'campaign': campaign['id']})
        conn.commit()
        return
    if not campaign:
        candidates = [h for h in eligible.values() if re.fullmatch(r'\d+\.\d+\.\d+',h['agent_version'] or '') and tuple(map(int,h['agent_version'].split('.'))) < tuple(map(int,version.split('.'))) and now-h['last_seen'] <= 900]
        if not candidates:
            conn.commit()
            return
        candidates.sort(key=lambda h: tuple(map(int,h['agent_version'].split('.'))) if re.fullmatch(r'\d+\.\d+\.\d+',h['agent_version'] or '') else (0,0,0),reverse=True)
        canary = candidates[0]['host_id']
        meta = {'automatic': True, 'canary': canary, 'attempts': {}, 'retry_at': {}, 'nodes': {}}
        ident = conn.execute("INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES(?,?,'canary',?,?)", (version, revision, now, json.dumps(meta))).lastrowid
        campaign = conn.execute('SELECT * FROM ops_upgrades WHERE id=?', (ident,)).fetchone()
        # A newer deployed release supersedes only unsent work from older releases.
        for old in conn.execute("SELECT id,version FROM ops_upgrades WHERE status IN ('canary','rollout') AND id<>?", (ident,)).fetchall():
            if tuple(map(int, old['version'].split('.'))) < tuple(map(int, version.split('.'))):
                conn.execute("UPDATE ops_upgrade_nodes SET status='superseded' WHERE campaign=? AND status='pending' AND action_id IS NULL", (old['id'],))
                conn.execute("UPDATE ops_upgrades SET status='superseded' WHERE id=?", (old['id'],))
        reclaim_superseded_actions(conn, now)
    meta = json.loads(campaign['payload'])
    ident = campaign['id']
    for host, h in eligible.items():
        # Never downgrade a client ahead of the running server.
        if not re.fullmatch(r'\d+\.\d+\.\d+', h['agent_version'] or '') or tuple(map(int, h['agent_version'].split('.'))) >= tuple(map(int, version.split('.'))):
            continue
        conn.execute("INSERT OR IGNORE INTO ops_upgrade_nodes VALUES(?,?,NULL,'pending',?)", (ident, host, h['agent_version']))
    nodes = conn.execute('SELECT * FROM ops_upgrade_nodes WHERE campaign=?', (ident,)).fetchall()
    for n in nodes:
        if n['status'] not in {'dispatched','failed'}:
            continue
        a = conn.execute('SELECT status,created_at,result_message FROM security_actions WHERE id=?', (n['action_id'],)).fetchone()
        if a and (a['status'] == 'failed' or now-a['created_at'] > 1800):
            conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE campaign=? AND host_id=?", (ident, n['host_id']))
            reason = str(a['result_message'] or 'fleet upgrade timed out')[:400]
            if a['status'] != 'failed':
                reason = 'Client 未在 30 分钟内回报升级结果'
                conn.execute("UPDATE security_actions SET status='failed',result_message=?,updated_at=? WHERE id=? AND status IN ('queued','dispatched','running')", (reason, now, n['action_id']))
            if int(meta['attempts'].get(n['host_id'], 0)) >= 3:
                meta.update(paused_at=now, paused_host=n['host_id'], pause_kind='install_failure', paused_from_status=campaign['status'], paused_reason=reason)
                conn.execute("UPDATE ops_upgrades SET status='paused',payload=? WHERE id=?", (json.dumps(meta), ident))
                save(conn, {**cfg, 'last_checked': now, 'target_version': version, 'campaign': ident,
                            'error': f"节点 {n['host_id']} 升级失败三次，自动发布已暂停"})
                conn.commit()
                return
            meta['retry_at'].setdefault(n['host_id'], now + 300 * 2**min(3, meta['attempts'].get(n['host_id'], 1)-1))
    # An automatic rollout must not wait forever for a canary that stopped
    # reporting. Keep retrying a live canary (and keep the existing three
    # attempt safety budget), but transfer the canary role when its enrollment
    # is no longer eligible or its latest host/operations sample is stale.
    # The old node remains in the campaign and can be retried during rollout
    # if it returns; no host hold or health gate is bypassed.
    canary_host = str(meta.get('canary') or '')
    canary_row = conn.execute(
        'SELECT status FROM ops_upgrade_nodes WHERE campaign=? AND host_id=?',
        (ident, canary_host),
    ).fetchone()
    current_canary = eligible.get(canary_host)
    canary_fresh = bool(
        current_canary
        and now - int(current_canary['last_seen'] or 0) <= 900
        and 0 <= now - int(current_canary['ops_ts'] or 0) <= 900
        and canary_host not in cfg['holds']
    )
    if (
        meta.get('automatic') is True
        and campaign['status'] == 'canary'
        and not (canary_row and canary_row['status'] == 'verified')
        and not canary_fresh
    ):
        node_rows = {
            row['host_id']: row['status']
            for row in conn.execute(
                'SELECT host_id,status FROM ops_upgrade_nodes WHERE campaign=?',
                (ident,),
            ).fetchall()
        }
        replacements = []
        for host, candidate in eligible.items():
            status = node_rows.get(host)
            if host == canary_host or status != 'pending':
                continue
            if now - int(candidate['last_seen'] or 0) > 900 or not 0 <= now - int(candidate['ops_ts'] or 0) <= 900:
                continue
            if not re.fullmatch(r'\d+\.\d+\.\d+', candidate['agent_version'] or ''):
                continue
            if tuple(map(int, candidate['agent_version'].split('.'))) >= tuple(map(int, version.split('.'))):
                continue
            if meta.get('nodes', {}).get(host, candidate['node_id']) != candidate['node_id']:
                continue
            if meta.get('attempts', {}).get(host, 0) >= 3:
                continue
            replacements.append(candidate)
        replacements.sort(
            key=lambda h: (
                tuple(map(int, h['agent_version'].split('.'))),
                int(h['last_seen'] or 0),
                h['host_id'],
            ),
            reverse=True,
        )
        if replacements:
            replacement = replacements[0]
            history = meta.setdefault('canary_history', [])
            history.append({
                'from': canary_host,
                'to': replacement['host_id'],
                'at': now,
                'reason': 'previous canary is offline or its operational sample is stale',
            })
            meta['canary'] = replacement['host_id']
            canary_host = replacement['host_id']
            # Preserve the failed/offline node's retry timer, but do not let
            # it keep the new canary's explanatory state or rollout gate.
            save(conn, {**cfg, 'last_checked': now, 'target_version': version,
                        'campaign': ident, 'error': ''})
        elif not canary_fresh:
            save(conn, {**cfg, 'last_checked': now, 'target_version': version,
                        'campaign': ident, 'error': '灰度节点已离线；等待有新鲜上报的候选节点'})
    canary = conn.execute('SELECT n.status,a.updated_at FROM ops_upgrade_nodes n LEFT JOIN security_actions a ON a.id=n.action_id WHERE n.campaign=? AND n.host_id=?', (ident, meta['canary'])).fetchone()
    h = eligible.get(meta['canary'])
    promote = bool(canary and canary['status'] == 'verified' and h and h['agent_version'] == version and 0<=now-h['ops_ts']<=900 and canary['updated_at'] and now>=canary['updated_at']+120 and h['ops_ts'] >= canary['updated_at']+120)
    if promote:
        promote, _ = upgrade_health.check(json.loads(h['ops_payload']))
    if promote:
        conn.execute("UPDATE ops_upgrades SET status='rollout' WHERE id=?", (ident,))
    permitted = campaign['status'] in {'rollout', 'verified'} or promote
    running = conn.execute("SELECT COUNT(*) FROM security_actions WHERE action_type IN ('managed_upgrade','managed_rollback') AND status IN ('queued','dispatched','running')").fetchone()[0]
    for n in conn.execute('SELECT * FROM ops_upgrade_nodes WHERE campaign=? ORDER BY host_id', (ident,)).fetchall():
        host = n['host_id']; h = eligible.get(host)
        if n['status']=='failed' and host not in meta['retry_at']:
            meta['retry_at'][host]=now+300
        if running >= 3 or not h or now-h['last_seen'] > 900 or n['status'] not in {'pending', 'failed'}:
            continue
        if not permitted and host != meta['canary']:
            continue
        if meta['attempts'].get(host, 0) >= 3 or now < meta['retry_at'].get(host, 0):
            continue
        # Bind the current enrollment; replacing a host identity requires a new campaign.
        expected = meta['nodes'].setdefault(host, h['node_id'])
        if expected != h['node_id']:
            continue
        if conn.execute("SELECT 1 FROM security_actions WHERE host_id=? AND action_type IN ('managed_upgrade','managed_rollback') AND status IN ('queued','dispatched','running')", (host,)).fetchone():
            continue
        params = json.dumps({'revision': revision, 'version': version, 'expected_node_id': expected})
        action = conn.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,'host','','__host__','managed_upgrade',?,'queued','automatic-fleet',?,?)", (host, params, now, now)).lastrowid
        conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?", (action, ident, host))
        meta['attempts'][host] = meta['attempts'].get(host, 0)+1
        meta['retry_at'].pop(host,None)
        running += 1
    remaining = conn.execute("SELECT COUNT(*) FROM ops_upgrade_nodes WHERE campaign=? AND status<>'verified'", (ident,)).fetchone()[0]
    conn.execute('UPDATE ops_upgrades SET payload=?,status=CASE WHEN ?=0 THEN \'verified\' ELSE status END WHERE id=?', (json.dumps(meta), remaining, ident))
    save(conn, {**cfg, 'last_checked': now, 'target_version': version, 'campaign': ident, 'error': ''})
    conn.commit()


async def run(db, version):
    await asyncio.sleep(45)
    while True:
        try:
            revision = await asyncio.to_thread(resolve, version())
            # Recheck publication every tick; GitHub unavailable => no new dispatch.
            def tick():
                conn = db()
                try:
                    reconcile(conn, version(), revision)
                finally:
                    conn.close()
            await asyncio.to_thread(tick)
        except Exception as exc:
            logging.warning('Fleet reconciliation deferred: %s', type(exc).__name__)
            conn=db()
            try:
                save(conn,{**settings(conn),'error':'发布验证或协调失败，保留现状，稍后重试','last_checked':int(time.time())})
                conn.commit()
            finally:
                conn.close()
        await asyncio.sleep(180)
