"""Corroborate fresh abuse evidence, quarantine, and retain an operator review state."""
import copy
import hashlib
import json
import threading
import time

try:
    from client import abuse_detection as detection, network_quarantine as isolation
except ImportError:
    import abuse_detection as detection
    import network_quarantine as isolation


TITLES = {'outbound_scan': '对外扫描', 'authentication_bruteforce': '认证爆破',
          'credential_stuffing': '撞库', 'identity_enumeration': '身份信息枚举'}


class Engine:
    def __init__(self, journal=None, confirm_seconds=20, max_gap=180):
        self.journal = journal or isolation.Journal()
        self.confirm_seconds = max(20, confirm_seconds)
        self.max_gap = max_gap
        self.candidates = {}
        self.results = {}
        self.notified = {}
        self.worker = None
        self.cursor = 0
        self.lock = threading.RLock()

    def _find_record(self, key):
        records = self.journal.read()
        if key in records:
            return records[key]
        runtime, project, name, identity = json.loads(key)
        for previous, record in list(records.items()):
            try:
                old_runtime, old_project, old_name, old_identity = json.loads(previous)
            except (ValueError, TypeError):
                continue
            if (old_runtime, old_project, old_identity) == (runtime, project, identity):
                # Renames never release connectivity or lose a recovery record.
                records[key] = records.pop(previous)
                self.journal.write(records)
                return record
        return None

    def check(self, container, instance_id, driver, processes, sockets, now=None):
        with self.lock:
            return self._check(container, instance_id, driver, processes, sockets, now)

    def _check(self, container, instance_id, driver, processes, sockets, now=None):
        now = time.time() if now is None else now
        key = isolation.target(container['runtime'], container.get('project', ''), container['name'], instance_id)
        existing = self._find_record(key)
        if existing:
            findings = existing['evidence']
        else:
            findings = []
            process_tokens = {int(p['pid']): p.get('start_ticks') for p in processes if isinstance(p, dict) and str(p.get('pid', '')).isdigit()}
            for process in processes:
                findings.extend(detection.evaluate_process(process, sockets))
            for item in detection.network_evidence(sockets):
                if process_tokens.get(item['pid']):
                    item['start_ticks'] = str(process_tokens[item['pid']])
                    findings.append(item)
            current_keys = set()
            confirmed = []
            for item in findings:
                token = (key, item['kind'], item.get('pid'), item.get('start_ticks'), item.get('source_sha256', ''), item.get('basis'))
                current_keys.add(token)
                previous = self.candidates.get(token)
                if previous and 0 <= now-previous['last_seen'] <= self.max_gap:
                    previous['last_seen'] = now
                    previous['samples'] += 1
                else:
                    previous = {'first_seen': now, 'last_seen': now, 'samples': 1}
                    self.candidates[token] = previous
                if previous['samples'] >= 2 and now-previous['first_seen'] >= self.confirm_seconds:
                    value = copy.deepcopy(item)
                    value['confidence'] = 'high'
                    value['features'] = {**value.get('features', {}), 'corroborating_samples': previous['samples']}
                    confirmed.append(value)
            for token in list(self.candidates):
                if (token[0] == key and token not in current_keys) or now-self.candidates[token]['last_seen'] > self.max_gap:
                    self.candidates.pop(token, None)
            if not confirmed:
                return {'state': 'suspected' if findings else 'not_observed', 'observed_at': now,
                        'instance_id': instance_id, 'findings': isolation.safe_evidence(findings) if findings else []}
            findings = confirmed
        try:
            if not existing and hasattr(driver, 'check_evidence'):
                driver.check_evidence(findings)
            quarantine = isolation.quarantine(self.journal, key, driver, findings)
        except isolation.QuarantineError as exc:
            quarantine = {'status': 'failed', 'ingress_blocked': False, 'egress_blocked': False,
                          'error': str(exc), 'data_preserved': True}
        titles = '、'.join(dict.fromkeys(TITLES.get(item['kind'], item['kind']) for item in findings))
        success = quarantine['status'] == 'isolated'
        message = (f'高置信度命中：{titles}；已隔离容器全部受管入站和出站网络；容器与磁盘保留，等待管理员复核。'
                   if success else f'高置信度命中：{titles}；双向隔离未能完整验证，必须人工处理；未删除容器或数据。')
        alert = {'type': 'prohibited_activity', 'severity': 'critical', 'title': '违规活动：'+titles,
                 'runtime': container['runtime'], 'project': container.get('project', ''),
                 'container_name': container['name'], 'instance_id': instance_id,
                 'message': message, 'value': len(findings), 'threshold': 1,
                 'abuse_evidence': isolation.safe_evidence(findings), 'network_quarantine': quarantine}
        result = {'state': quarantine['status'], 'observed_at': now, 'instance_id': instance_id, 'alert': alert}
        return result

    def notify(self, result, emit, now):
        alert = result.get('alert')
        if not alert:
            return
        identity = (alert['runtime'], alert['project'], alert['container_name'], alert['instance_id'])
        signature = hashlib.sha256(json.dumps([alert['abuse_evidence'], alert['network_quarantine']['status']], sort_keys=True).encode()).hexdigest()
        previous = self.notified.get(identity)
        if previous and previous[0] == signature and now-previous[1] < 300:
            result['notification_pending'] = previous[2]
            return
        try:
            response = emit(alert)
        except Exception:
            result['notification_pending'] = True
            return
        # An authenticated server ACK is not proof of Telegram delivery.
        delivered = isinstance(response, dict) and response.get('telegram_delivery', {}).get('state') == 'delivered'
        result['event_relayed'] = True
        result['notification_pending'] = not delivered
        self.notified[identity] = (signature, now if delivered else now-270, not delivered)

    def schedule(self, containers, provider, emit, batch_size=8):
        """One bounded worker; diagnostics never block the normal Agent loop."""
        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                return False
            eligible = [c for c in containers if c.get('runtime') in {'podman', 'incus'} and c.get('name') not in isolation.PROTECTED]
            if not eligible:
                return False
            selected = [eligible[(self.cursor+i) % len(eligible)] for i in range(min(batch_size, len(eligible)))]
            self.cursor = (self.cursor+len(selected)) % len(eligible)
            selected = [{k: c.get(k) for k in ('runtime', 'runtime_bin', 'project', 'name', 'id', 'pid', 'stable_id')} for c in selected]
            def work():
                for container in selected:
                    key = (container['runtime'], container.get('project', ''), container['name'])
                    try:
                        instance_id, driver, processes, sockets = provider(container)
                        with self.lock:
                            result = self.check(container, instance_id, driver, processes, sockets)
                            self.notify(result, emit, time.time())
                            self.results[key] = result
                    except Exception:
                        # No untrusted output or source code in logs/errors.
                        result = {'state': 'collection_failed', 'observed_at': time.time(),
                                  'coverage': 'unavailable; not a clean observation'}
                        with self.lock:
                            previous = self.results.get(key, {})
                            if previous.get('alert'):
                                result = copy.deepcopy(previous)
                                result['collection_failed_at'] = time.time()
                                result['coverage'] = 'unavailable; previous isolation is not freshly verified'
                                result['state'] = 'unverified'
                                result['alert']['network_quarantine'].update(status='unverified', ingress_blocked=False, egress_blocked=False)
                                result['alert']['message'] = '上次已要求双向隔离，但本次采集不可用；当前网络状态待确认，仍需管理员复核。'
                            self.results[key] = result
            self.worker = threading.Thread(target=work, name='narwhal-abuse-guard', daemon=True)
            self.worker.start()
            return True

    def status(self, container, now=None):
        now = time.time() if now is None else now
        key = (container['runtime'], container.get('project', ''), container['name'])
        with self.lock:
            result = copy.deepcopy(self.results.get(key, {}))
        identity = str(container.get('stable_id') or container.get('id') or '')
        seen = str(result.get('instance_id') or '')
        if identity and seen and identity != seen and not (container['runtime'] == 'podman' and len(identity) >= 12 and seen.startswith(identity)):
            return {'state': 'pending', 'coverage': 'instance identity changed'}
        if now-float(result.get('observed_at', 0)) > 900:
            if result.get('alert'):
                result.update(state='stale', coverage='previous isolation is not freshly verified; review still required')
                result['alert']['network_quarantine'].update(status='unverified', ingress_blocked=False, egress_blocked=False)
                result['alert']['message'] = '隔离验证采样已过期；保留待复核事件，当前网络状态待确认，不表示风险已恢复。'
                return result
            return {'state': 'stale', 'coverage': 'no fresh abuse sample; not verified clean'}
        return result

    def forget(self, container, instance_id):
        """Called under the engine lock after an explicit reviewed release."""
        key = isolation.target(container['runtime'], container.get('project', ''), container['name'], instance_id)
        self.results.pop((container['runtime'], container.get('project', ''), container['name']), None)
        self.notified.pop((container['runtime'], container.get('project', ''), container['name'], instance_id), None)
        for token in list(self.candidates):
            if token[0] == key:
                self.candidates.pop(token, None)


_engine = None


def engine():
    global _engine
    if _engine is None:
        _engine = Engine()
    return _engine


def status(container):
    # Reading normal telemetry must not create host-only state on dev/Windows or
    # before the POSIX worker is configured. This is not a clean observation.
    if _engine is None:
        return {'state': 'pending', 'coverage': 'abuse worker has not sampled this instance'}
    return _engine.status(container)

