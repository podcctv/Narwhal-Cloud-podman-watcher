"""Deterministic node-local admission policy. No networking, subprocess or AI.

First-observed source order is recorded, never represented as historical arrival
order. IPv4-mapped IPv6 is normalized. Unknown evidence cannot release protection.
"""
import ipaddress
import time

SAMPLE_GAP = 30
WINDOW = 120
PERIOD = 1800


def address(value):
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local:
        raise ValueError('not a business source')
    return str(parsed)


class Policy:
    def __init__(self, saved=None):
        self.data = dict(saved or {})
        self.data.setdefault('sources', [])
        self.data.setdefault('blocked', {})
        self.data.setdefault('blocked_packets', 0)
        self.data.setdefault('tcp_denied', 0)
        self.data.setdefault('extensions', 0)
        self.pending = {}
        self.flows = set()
        self.sample_at = 0
        self.last_denied_at = 0

    def seed(self, sources, now):
        """Only the first complete observation seeds slots; later sources queue."""
        if self.data.get('seeded'):
            return
        seen = set()
        for value in sources:
            try:
                ip = address(value)
            except ValueError:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            if len(self.data['sources']) < 5:
                self.data['sources'].append({'ip': ip, 'first_seen': now})
        self.data.update(seeded=True, source_order_basis='first_complete_observation')

    def admit_source(self, source, now):
        ip = address(source)
        if any(x['ip'] == ip for x in self.data['sources']):
            return True, False
        if len(self.data['sources']) < 5:
            self.data['sources'].append({'ip': ip, 'first_seen': now})
            return True, True
        self.data['blocked_packets'] += 1
        blocked = self.data['blocked']
        if ip not in blocked and len(blocked)>=32:
            blocked.pop(min(blocked,key=lambda key:blocked[key].get('last_seen',0)))
        item = blocked.setdefault(ip, {'first_seen': now, 'packets': 0})
        item.update(last_seen=now, packets=item['packets']+1)
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
        live = set(inbound) | set(live_sources)
        old_sources = self.data['sources']
        self.data['sources'] = [s for s in old_sources if s['ip'] in live]
        changed = len(old_sources) != len(self.data['sources'])
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
            'review_at','extensions','recovered_at','event'}}
