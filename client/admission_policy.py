"""Deterministic node-local network policy. No networking, subprocess or AI.

Source IPs are network peers, not user identities. When the active-source limit
is enabled (default 10), a container admits *new* inbound flows only from at
most N currently active source IPs. A slot frees itself once the source has
been idle (no packets) for SOURCE_IDLE seconds, so a scanner cannot hold a slot
permanently. Existing connections are never cut. A limit of 0 keeps the older
observation-only behaviour. IPv4-mapped IPv6 is normalized. Unknown evidence
cannot release the separate TCP concurrency protection.
"""
import ipaddress
import os
import time

SAMPLE_GAP = 30
WINDOW = 120
PERIOD = 1800
DEFAULT_SOURCE_LIMIT = 10
MAX_SOURCE_LIMIT = 64
SOURCE_IDLE = 120
OBSERVE_SAMPLE = 5
BLOCKED_MAX = 32


def source_limit_from_env():
    """Configured active-source limit; 0 disables enforcement (observe only)."""
    raw = os.getenv('SECURITY_ADMISSION_SOURCE_LIMIT', str(DEFAULT_SOURCE_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_SOURCE_LIMIT
    return max(0, min(MAX_SOURCE_LIMIT, value))


def address(value):
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local:
        raise ValueError('not a business source')
    return str(parsed)


class Policy:
    def __init__(self, saved=None, source_limit=0):
        self.data = dict(saved or {})
        self.data.setdefault('sources', [])
        self.data.setdefault('blocked', {})
        self.data.setdefault('blocked_packets', 0)
        self.data.setdefault('tcp_denied', 0)
        self.data.setdefault('extensions', 0)
        self.source_limit = max(0, min(MAX_SOURCE_LIMIT, int(source_limit or 0)))
        self.pending = {}
        self.flows = set()
        self.sample_at = 0
        self.last_denied_at = 0

    @property
    def enforced(self):
        return self.source_limit > 0

    def capacity(self):
        return self.source_limit if self.enforced else OBSERVE_SAMPLE

    def seed(self, sources, now):
        """The first complete observation seeds slots from live established sources."""
        if self.data.get('seeded'):
            return
        seen = {x['ip'] for x in self.data['sources']}
        for value in sources:
            try:
                ip = address(value)
            except ValueError:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            if len(self.data['sources']) < self.capacity():
                self.data['sources'].append({'ip': ip, 'first_seen': now, 'last_seen': now})
        self.data.update(seeded=True, source_order_basis='first_complete_observation')

    def observe_source(self, source, now):
        """Record a bounded sample of current IPs without an admission decision."""
        ip = address(source)
        if any(x['ip'] == ip for x in self.data['sources']):
            return False
        if len(self.data['sources']) < self.capacity():
            self.data['sources'].append({'ip': ip, 'first_seen': now, 'last_seen': now})
            return True
        return False

    def _expire_idle(self, now):
        keep = [s for s in self.data['sources']
                if now - int(s.get('last_seen', s.get('first_seen', 0))) <= SOURCE_IDLE]
        changed = len(keep) != len(self.data['sources'])
        self.data['sources'] = keep
        return changed

    def admit_source(self, source, now):
        """Admission decision for a NEW inbound flow; returns (accepted, slot_added).

        Only called for sources the kernel fast path does not already know.
        """
        ip = address(source)
        if not self.enforced:
            return True, self.observe_source(ip, now)
        for entry in self.data['sources']:
            if entry['ip'] == ip:
                entry['last_seen'] = now
                return True, False
        self._expire_idle(now)
        if len(self.data['sources']) < self.source_limit:
            self.data['sources'].append({'ip': ip, 'first_seen': now, 'last_seen': now})
            self.data['blocked'].pop(ip, None)
            return True, True
        self.data['blocked_packets'] += 1
        self.data['last_blocked_at'] = now
        blocked = self.data['blocked']
        if ip not in blocked and len(blocked) >= BLOCKED_MAX:
            blocked.pop(min(blocked, key=lambda key: blocked[key].get('last_seen', 0)))
        item = blocked.setdefault(ip, {'first_seen': now, 'packets': 0})
        item.update(last_seen=now, packets=item.get('packets', 0) + 1)
        return False, False

    def admit_tcp(self, flow, now):
        if not self.data.get('limited'):
            return True
        if flow in self.flows or flow in self.pending:
            return True
        # Never grant slots from stale or incomplete observations.
        if now-self.sample_at > SAMPLE_GAP or len(self.flows | set(self.pending)) >= 500:
            self.data['tcp_denied'] += 1
            self.last_denied_at = now
            return False
        self.pending[flow] = now
        return True

    def _refresh_sources(self, inbound, live_sources, now):
        if not self.enforced:
            # Observation-only: a bounded sample of currently established peers.
            live = set(inbound) | set(live_sources)
            old_sources = self.data['sources']
            self.data['sources'] = [s for s in old_sources if s['ip'] in live]
            changed = len(old_sources) != len(self.data['sources'])
            for value in list(inbound) + list(live_sources):
                changed = self.observe_source(value, now) or changed
            return changed
        # Enforced: the kernel's per-container timeout set is the authority for
        # which admitted sources are still active (refreshed on every packet).
        kernel = set()
        for value in live_sources:
            try:
                kernel.add(address(value))
            except ValueError:
                continue
        old = len(self.data['sources'])
        keep = []
        for entry in self.data['sources']:
            if entry['ip'] in kernel:
                entry['last_seen'] = now
                keep.append(entry)
            elif now - int(entry.get('last_seen', entry.get('first_seen', 0))) <= SAMPLE_GAP:
                # Just admitted; the kernel element may not be visible yet.
                keep.append(entry)
        self.data['sources'] = keep
        known = {x['ip'] for x in keep}
        for ip in sorted(kernel - known):
            if len(self.data['sources']) >= self.source_limit:
                break
            self.data['sources'].append({'ip': ip, 'first_seen': now, 'last_seen': now})
        return len(self.data['sources']) != old

    def observe(self, flows, inbound, live_sources, now=None, valid=True, epoch=''):
        now = int(time.time()) if now is None else now
        if not valid or not epoch:
            self.data['sample_state'] = 'unverified'
            self.data['above_since'] = 0
            self.data['below_since'] = 0
            return False
        previous = self.data.get('sampled_at', 0)
        if now <= previous:
            return False
        same = self.data.get('epoch') == epoch and 0 < now-previous <= SAMPLE_GAP
        self.flows = set(flows)
        # A complete fresh kernel snapshot covers old SYN reservations. Replays
        # retain a reservation for a bounded handshake interval.
        self.pending = {k:v for k,v in self.pending.items() if k not in self.flows and now-v < 30}
        self.sample_at = now
        self.data.update(epoch=epoch, sampled_at=now, sample_state='valid', tcp_connections=len(self.flows))
        self.seed(inbound, now)
        changed = self._refresh_sources(inbound, live_sources, now)
        count = len(self.flows)
        above = (self.data.get('above_since') or now) if same and count > 1000 else now if count > 1000 else 0
        below = (self.data.get('below_since') or now) if same and count < 500 and now-self.last_denied_at > WINDOW else now if count < 500 and now-self.last_denied_at > WINDOW else 0
        self.data.update(above_since=above, below_since=below)
        if not self.data.get('limited') and above and now-above >= WINDOW:
            self.data.update(limited=True, limited_since=now, review_at=now+PERIOD, extensions=0, event='limited')
            changed = True
        elif self.data.get('limited') and now >= self.data['review_at']:
            if below and now-below >= WINDOW:
                self.data.update(limited=False, recovered_at=now, event='released')
                changed = True
            elif count >= 500 or now-self.last_denied_at <= WINDOW:
                self.data.update(review_at=max(now, self.data['review_at'])+PERIOD,
                                 extensions=self.data['extensions']+1, event='extended')
        return changed

    def status(self):
        return {k:v for k,v in self.data.items() if k in {
            'sample_state','sampled_at','tcp_connections','sources','source_order_basis',
            'blocked','blocked_packets','tcp_denied','limited','limited_since',
            'review_at','extensions','recovered_at','event','last_blocked_at'}}
