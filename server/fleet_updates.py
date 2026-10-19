"""Master-led, fixed-revision fleet reconciliation; never races local timers."""
import asyncio
import json
import logging
import os
import re
import time
import urllib.request

REPOSITORY = 'podcctv/Narwhal-Cloud-podman-watcher'
ACTIVE = ('queued', 'dispatched', 'running')


def settings(conn):
    row = conn.execute("SELECT payload FROM ops_settings WHERE key='fleet_updates'").fetchone()
    return {'enabled': True, 'holds': [], **(json.loads(row[0]) if row else {})}


def save(conn, value):
    conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('fleet_updates',?)", (json.dumps(value),))


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
    hosts = conn.execute('SELECT h.*,o.payload AS ops_payload,o.ts AS ops_ts FROM hosts h JOIN ops_hosts o ON o.host_id=h.host_id AND o.node=h.node_id ORDER BY h.last_seen DESC,h.host_id LIMIT 500').fetchall()
    eligible = {h['host_id']: h for h in hosts if h['node_id'] and json.loads(h['ops_payload']).get('managed_upgrade') and h['host_id'] not in cfg['holds']}
    campaign = conn.execute("SELECT * FROM ops_upgrades WHERE version=? AND revision=? ORDER BY id DESC LIMIT 1", (version, revision)).fetchone()
    # Manual campaigns remain under operator control. Never silently promote one.
    if campaign and not json.loads(campaign['payload']).get('automatic'):
        conn.rollback()
        return
    if not campaign:
        candidates = [h for h in eligible.values() if re.fullmatch(r'\d+\.\d+\.\d+',h['agent_version'] or '') and tuple(map(int,h['agent_version'].split('.'))) < tuple(map(int,version.split('.'))) and now-h['last_seen'] <= 900]
        if not candidates:
            conn.rollback()
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
        a = conn.execute('SELECT status,created_at FROM security_actions WHERE id=?', (n['action_id'],)).fetchone()
        if a and (a['status'] == 'failed' or now-a['created_at'] > 1800):
            conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE campaign=? AND host_id=?", (ident, n['host_id']))
            conn.execute("UPDATE security_actions SET status='failed',result_message='fleet upgrade timed out',updated_at=? WHERE id=? AND status IN ('queued','dispatched','running')", (now, n['action_id']))
            meta['retry_at'].setdefault(n['host_id'],now + 300 * 2**min(3, meta['attempts'].get(n['host_id'], 1)-1))
    canary = conn.execute('SELECT n.status,a.updated_at FROM ops_upgrade_nodes n LEFT JOIN security_actions a ON a.id=n.action_id WHERE n.campaign=? AND n.host_id=?', (ident, meta['canary'])).fetchone()
    h = eligible.get(meta['canary'])
    promote = bool(canary and canary['status'] == 'verified' and h and h['agent_version'] == version and 0<=now-h['ops_ts']<=900 and canary['updated_at'] and now>=canary['updated_at']+120 and h['ops_ts'] >= canary['updated_at']+120)
    if promote:
        health = json.loads(h['ops_payload']).get('health', [])
        core = [x for x in health if x.get('source') in {'network_counters', 'security'}]
        promote = bool(core) and all(x.get('status') in {'healthy', 'idle'} for x in core)
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
