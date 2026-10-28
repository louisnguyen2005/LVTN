"""Host PC -> Windows gateway -> sandbox VM reachability: probes, pool inventory and stored state."""
import json
import re
import socket
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from .errors import Rejected

LINK_STATUSES = ('UP', 'DOWN', 'MISMATCH')


def validate_links(cfg):
    names = set()
    for link in cfg.get('links', []):
        name = link.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[\w .()-]{1,64}', name) or name in names:
            raise ValueError('Link names must be unique, 1-64 plain characters')
        names.add(name)
        for key in ('gateway', 'vm'):
            if not isinstance(link.get(key), str) or not re.fullmatch(r'[\w.-]{1,253}:\d{1,5}', link[key]):
                raise ValueError('Link endpoints use host:port')
        if 'health' in link:
            url = urlsplit(link['health'])
            if url.scheme not in ('http', 'https') or not url.hostname or url.path != '/health' or url.query:
                raise ValueError('Link health must be an HTTP(S) /health URL')
        for key in ('expected_identity', 'node', 'team', 'role'):
            if key in link and not (isinstance(link[key], str) and len(link[key]) <= 128):
                raise ValueError('Invalid link ' + key)


def topology_nodes(path):
    """Map lab IP -> host name from topology.yml net_mappings (no YAML dependency on the gateway PC)."""
    try:
        text = Path(path).read_text(encoding='utf-8')
    except OSError:
        return {}
    block = text.split('net_mappings:', 1)[-1].split('router_mappings:', 1)[0]
    pairs = re.findall(r'-\s*host:\s*([\w-]+)\s+network:\s*[\w-]+\s+ip:\s*([\d.]+)', block)
    return {ip: host for host, ip in pairs}


def node_identity(sandbox, host):
    """Identity reported by /health, as provisioned: shared server = sandbox UUID, attackerN = UUID-attackerN."""
    return sandbox if host == 'server' else f'{sandbox}-{host}'


def links_from_gateway(gateway, sandbox=None, nodes=None):
    """One link per forwarded service in CyberRangeCZ-Windows-Gateway/config.json."""
    nodes = nodes or {}
    links = []
    for s in gateway['services']:
        host = nodes.get(s['sandboxIp'])
        link = {'name': s['name'][:64], 'host': gateway['gatewayIp'], 'port': int(s['gatewayPort']),
                'gateway': f"{gateway['gatewayIp']}:{int(s['gatewayPort'])}",
                'vm': f"{s['sandboxIp']}:{int(s['sandboxPort'])}"}
        if host:
            link['node'] = host
            link['role'] = 'server' if host == 'server' else 'team'
            number = re.fullmatch(r'attacker(\d+)', host)
            if number:
                link['team'] = f'team{int(number.group(1)):02d}'
        if s.get('protocol', 'http') == 'http' and sandbox and host:
            link['health'] = f"http://{link['gateway']}/health"
            link['expected_identity'] = node_identity(sandbox, host)
        links.append(link)
    return links


def probe(link, timeout=2):
    """TCP connect through the gateway port; with `health`, also confirm WHICH VM answered."""
    started = time.monotonic()
    identity = None
    try:
        if link.get('health'):
            opener = build_opener(ProxyHandler({}))
            try:
                with opener.open(Request(link['health'], headers={'Accept': 'application/json'}), timeout=timeout) as r:
                    body = json.loads(r.read(65536))
                identity = body.get('sandbox') if isinstance(body, dict) and isinstance(body.get('sandbox'), str) else None
                if link.get('expected_identity') and identity != link['expected_identity']:
                    status, detail = 'MISMATCH', 'Wrong VM behind this gateway port'
                else:
                    status, detail = 'UP', 'HTTP /health OK, VM identity verified'
            except HTTPError as exc:
                # The tunnel and the VM answer; the service itself is the team's problem, not the link's.
                status, detail = 'UP', f'Reachable; service answered HTTP {exc.code}'
            except ValueError:
                status, detail = 'UP', 'Reachable; /health is not JSON'
        else:
            with socket.create_connection((link['host'], int(link['port'])), timeout=timeout):
                status, detail = 'UP', 'TCP connect OK'
    except OSError as exc:
        reason = getattr(exc, 'reason', None)
        status, detail = 'DOWN', type(reason if isinstance(reason, BaseException) else exc).__name__
    return {'name': link['name'], 'status': status, 'identity': identity,
            'latency_ms': round((time.monotonic() - started) * 1000), 'detail': detail}


class LinkMixin:
    def record_links(self, data):
        known = {l['name']: l for l in self.cfg.get('links', [])}
        rows = data.get('links') if isinstance(data, dict) else None
        if not isinstance(rows, list) or not 0 < len(rows) <= 64:
            raise Rejected('Invalid link report')
        now = self.clock()
        with self.connect(write=True) as db:
            for row in rows:
                link = known.get(row.get('name'))
                latency, detail, identity = row.get('latency_ms'), row.get('detail', ''), row.get('identity')
                if link is None or row.get('status') not in LINK_STATUSES or type(latency) is not int or not 0 <= latency <= 600000 \
                        or not isinstance(detail, str) or not (identity is None or isinstance(identity, str)):
                    raise Rejected('Unknown link or invalid status')
                db.execute('''INSERT OR REPLACE INTO links(name,gateway,vm,status,latency_ms,detail,checked_at,identity)
                              VALUES(?,?,?,?,?,?,?,?)''',
                           (link['name'], link['gateway'], link['vm'], row['status'], latency, detail[:120], now,
                            identity[:128] if identity else None))
                db.execute('INSERT INTO link_checks(name,status,latency_ms,checked_at) VALUES(?,?,?,?)',
                           (link['name'], row['status'], latency, now))
            db.execute('DELETE FROM link_checks WHERE id <= (SELECT MAX(id) FROM link_checks) - 5000')
        return {'recorded': len(rows)}

    def network(self):
        with self.connect() as db:
            latest = {r['name']: dict(r) for r in db.execute('SELECT * FROM links')}
            history = {}
            for r in db.execute('SELECT name,status,latency_ms FROM link_checks ORDER BY id DESC LIMIT 2000'):
                if len(history.setdefault(r['name'], [])) < 20:
                    history[r['name']].append((r['status'], r['latency_ms']))
        links = []
        for link in self.cfg.get('links', []):
            row = latest.get(link['name'], {'status': 'UNKNOWN', 'latency_ms': None, 'detail': 'Not probed yet',
                                            'checked_at': None, 'identity': None})
            recent = list(reversed(history.get(link['name'], [])))
            up = [ms for st, ms in recent if st == 'UP']
            links.append({'name': link['name'], 'gateway': link['gateway'], 'vm': link['vm'],
                          'node': link.get('node'), 'team': link.get('team'), 'role': link.get('role'),
                          'verified': bool(link.get('expected_identity')),
                          'identity_ok': row.get('identity') == link.get('expected_identity') if row.get('identity') else None,
                          'status': row['status'], 'latency_ms': row['latency_ms'], 'detail': row['detail'],
                          'checked_at': row['checked_at'], 'recent': [st for st, _ in recent],
                          'uptime': round(100 * len(up) / len(recent)) if recent else None,
                          'avg_latency_ms': round(sum(up) / len(up)) if up else None})
        gateway = links[0]['gateway'].rsplit(':', 1)[0] if links else None
        return {'server_time': self.clock(), 'gateway': gateway, 'links': links}
