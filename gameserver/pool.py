"""Pool connectivity check from the real (host) PC: which sandbox VM answers behind each gateway port.

    py -3 -m gameserver.pool                 # one pass, table output
    py -3 -m gameserver.pool --watch 10      # repeat every 10 s
    py -3 -m gameserver.pool --json          # machine-readable

Path: this PC -> Windows gateway (ssh -L forwards) -> CyberRangeCZ jump host -> VM in the pool.
UP = the VM answered with the identity provisioned for it; MISMATCH = a different VM/sandbox answered
(stale allocation or swapped port); DOWN = the forward or the VM is not reachable.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import time
from uuid import UUID

from .links import links_from_gateway, probe, topology_nodes


def load_links(gateway_path, topology_path):
    gateway = json.loads(Path(gateway_path).read_text(encoding='utf-8-sig'))
    matched = re.search(r'sandbox-id-([0-9a-fA-F-]{36})-user-config$', gateway.get('sshConfig', ''))
    sandbox = str(UUID(matched.group(1))) if matched else None
    return sandbox, links_from_gateway(gateway, sandbox, topology_nodes(topology_path))


def check(links, timeout):
    with ThreadPoolExecutor(max_workers=min(8, len(links) or 1)) as pool:
        rows = list(pool.map(lambda link: probe(link, timeout), links))
    return [{**{k: link.get(k) for k in ('node', 'team', 'gateway', 'vm')}, **row} for link, row in zip(links, rows)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--gateway-config', type=Path, default=Path('CyberRangeCZ-Windows-Gateway/config.json'))
    parser.add_argument('--topology', type=Path, default=Path('topology.yml'))
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--watch', type=float, default=0, help='Seconds between passes; 0 = once')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    sandbox, links = load_links(args.gateway_config, args.topology)
    if not links:
        parser.error('No forwarded services in the gateway config')
    try:
        while True:
            rows = check(links, args.timeout)
            if args.json:
                print(json.dumps({'sandbox': sandbox, 'checked_at': time.time(), 'links': rows}, ensure_ascii=False), flush=True)
            else:
                print(f"\nSandbox {sandbox or '(unknown: sshConfig has no sandbox id)'} - {time.strftime('%H:%M:%S')}")
                for r in rows:
                    print(f"  {r['status']:<8} {r['latency_ms']:>5} ms  {r['gateway']:<21} -> {r['vm']:<17} "
                          f"{(r['node'] or '?'):<10} {r['detail']}", flush=True)
            if not args.watch:
                return 0 if all(r['status'] == 'UP' for r in rows) else 1
            time.sleep(args.watch)
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
