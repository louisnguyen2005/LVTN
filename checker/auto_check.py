"""Continuously check team services through the gateway and keep local results.

No database or third-party package is required. Stop with Ctrl+C.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID

from web_health import check_service, check_web


HERE = Path(__file__).resolve().parent
DEFAULT_GATEWAY = HERE.parent / 'CyberRangeCZ-Windows-Gateway' / 'config.json'
SANDBOX_CONFIG_PATTERN = re.compile(r'sandbox-id-([0-9a-fA-F-]{36})-user-config$', re.I)


def load_targets(config_path, gateway_path):
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    gateway = json.loads(gateway_path.read_text(encoding='utf-8-sig'))
    match = SANDBOX_CONFIG_PATTERN.search(gateway['sshConfig'])
    if not match:
        raise ValueError('gateway sshConfig must identify an allocated sandbox')
    sandbox_id = str(UUID(match.group(1)))
    targets = config['targets']
    if not isinstance(targets, list) or not targets:
        raise ValueError('target config must contain at least one target')
    names = set()
    urls = set()
    gateway_ports = {int(service['gatewayPort']) for service in gateway['services']}
    for target in targets:
        name = target['name']
        url = target['url']
        suffix = target['expected_sandbox_suffix']
        parsed = urlsplit(url)
        if not name or name in names or url in urls:
            raise ValueError('target names and URLs must be nonempty and unique')
        if parsed.scheme != 'http' or parsed.hostname != gateway['gatewayIp'] or parsed.port not in gateway_ports or parsed.path != '/health' or parsed.query or parsed.fragment or parsed.username:
            raise ValueError(f'{name}: health URL must match a configured gateway port')
        if not isinstance(suffix, str) or not re.fullmatch(r'-attacker[1-9][0-9]*', suffix):
            raise ValueError(f'{name}: invalid expected_sandbox_suffix')
        target['expected_sandbox'] = sandbox_id + suffix
        names.add(name)
        urls.add(url)
    return sandbox_id, targets


def load_credentials(path, targets):
    if path is None:
        return None
    credentials = json.loads(path.read_text(encoding='utf-8-sig'))
    expected = {target['name'] for target in targets}
    if not isinstance(credentials, dict) or set(credentials) != expected:
        raise ValueError('credentials must contain exactly one password for each team')
    if any(not isinstance(password, str) or not password for password in credentials.values()):
        raise ValueError('each team password must be a nonempty string')
    return credentials


def run_round(sandbox_id, targets, timeout, credentials):
    with ThreadPoolExecutor(max_workers=min(len(targets), 8)) as executor:
        if credentials is None:
            results = list(executor.map(lambda target: check_web(target, timeout), targets))
            for result in results:
                result['check_level'] = 'health'
        else:
            results = list(executor.map(
                lambda target: check_service(target, credentials[target['name']], timeout), targets))
    return {
        'schema_version': 1,
        'checked_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'sandbox_id': sandbox_id,
        'check_level': 'health' if credentials is None else 'functional',
        'all_up': all(row['status'] == 'UP' for row in results),
        'results': results,
    }


def save_round(output_dir, record):
    output_dir.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(record, ensure_ascii=False)
    with (output_dir / 'history.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(serialized + '\n')
        stream.flush()
    temporary = output_dir / 'latest.json.tmp'
    temporary.write_text(serialized + '\n', encoding='utf-8')
    temporary.replace(output_dir / 'latest.json')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=HERE / 'web_targets_gateway.json')
    parser.add_argument('--gateway-config', type=Path, default=DEFAULT_GATEWAY)
    parser.add_argument('--output-dir', type=Path, default=HERE / 'results')
    parser.add_argument('--credentials', type=Path,
                        help='Private JSON mapping team names to ServiceDesk passwords')
    parser.add_argument('--interval', type=float, default=10, help='Seconds between rounds')
    parser.add_argument('--timeout', type=float, default=3, help='Timeout per target in seconds')
    parser.add_argument('--rounds', type=int, default=0, help='Number of rounds; 0 runs continuously')
    args = parser.parse_args(argv)
    if args.interval <= 0 or args.timeout <= 0 or args.rounds < 0:
        parser.error('interval and timeout must be positive; rounds must be nonnegative')
    try:
        sandbox_id, targets = load_targets(args.config, args.gateway_config)
        credentials = load_credentials(args.credentials, targets)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(f'invalid configuration: {exc}')
    completed = 0
    all_rounds_up = True
    try:
        while args.rounds == 0 or completed < args.rounds:
            started = time.monotonic()
            record = run_round(sandbox_id, targets, args.timeout, credentials)
            try:
                save_round(args.output_dir, record)
            except OSError as exc:
                print(f'Cannot save checker result: {exc}', file=sys.stderr)
                return 2
            print(json.dumps(record, ensure_ascii=False), flush=True)
            completed += 1
            all_rounds_up &= record['all_up']
            if args.rounds == 0 or completed < args.rounds:
                time.sleep(max(0, args.interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        return 130
    return 0 if all_rounds_up else 1


if __name__ == '__main__':
    raise SystemExit(main())
