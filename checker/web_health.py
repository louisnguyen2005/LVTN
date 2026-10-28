"""Check four ServiceDesk HTTP endpoints. Python 3; no external packages."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import time
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_json_bounded(response):
    body = response.read(65537)
    if len(body) > 65536:
        raise ValueError('Response too large')
    return json.loads(body)


def check_web(target, timeout):
    started = time.monotonic()
    result = {'name': target['name'], 'url': target['url'], 'status': 'DOWN'}
    try:
        opener = build_opener(ProxyHandler({}), NoRedirect())
        with opener.open(Request(target['url'], headers={'Accept': 'application/json'}),
                         timeout=timeout) as response:
            if response.status != 200:
                raise ValueError('Expected HTTP 200')
            health = read_json_bounded(response)
            if not isinstance(health, dict) or health.get('status') != 'ok':
                raise ValueError('Expected JSON status=ok')
            if isinstance(health.get('sandbox'), str):
                result['sandbox'] = health['sandbox']
            if target.get('expected_sandbox') and health.get('sandbox') != target['expected_sandbox']:
                raise ValueError('Wrong sandbox identity: expected ' + target['expected_sandbox'])
            if target.get('expected_service') and health.get('service') != target['expected_service']:
                raise ValueError('Wrong service identity: expected ' + target['expected_service'])
            if target.get('expected_sandbox_suffix'):
                sandbox = health.get('sandbox')
                if not isinstance(sandbox, str) or not sandbox.endswith(target['expected_sandbox_suffix']):
                    raise ValueError('Wrong team identity')
        result['status'] = 'UP'
        result['detail'] = 'HTTP 200, status=ok'
    except HTTPError as exc:
        result['status'] = 'MUMBLE'
        result['detail'] = f'HTTP {exc.code} from health endpoint'
    except (URLError, TimeoutError, ConnectionError) as exc:
        result['detail'] = type(exc).__name__ + ': ' + str(exc)
    except (ValueError, json.JSONDecodeError) as exc:
        result['status'] = 'MUMBLE'
        result['detail'] = type(exc).__name__ + ': ' + str(exc)
    except Exception as exc:
        result['status'] = 'ERROR'
        result['detail'] = type(exc).__name__ + ': ' + str(exc)
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result


def check_service(target, password, timeout):
    """Check legitimate ServiceDesk login and ticket reads without changing data."""
    result = check_web(target, timeout)
    result['check_level'] = 'functional'
    if result['status'] != 'UP':
        return result
    started = time.monotonic()
    try:
        parsed = urlsplit(target['url'])
        base_url = f'{parsed.scheme}://{parsed.netloc}'
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))
        form = urlencode({'username': 'alice', 'password': password}).encode('utf-8')
        with opener.open(Request(base_url + '/login', data=form,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'}),
                         timeout=timeout) as response:
            if response.status != 200 or read_json_bounded(response).get('user') != 'alice':
                raise ValueError('Login response is invalid')
        with opener.open(base_url + '/api/tickets', timeout=timeout) as response:
            tickets = read_json_bounded(response)
            if response.status != 200 or not isinstance(tickets, list):
                raise ValueError('Ticket list is invalid')
            if not any(row.get('id') == 1201 and row.get('owner') == 'alice' for row in tickets):
                raise ValueError('Alice ticket missing from list')
        with opener.open(base_url + '/api/tickets/1201', timeout=timeout) as response:
            ticket = read_json_bounded(response)
            if response.status != 200 or ticket.get('owner') != 'alice':
                raise ValueError('Alice ticket is unavailable')
            if ticket.get('private_note') != 'Alice workspace: ' + target['expected_sandbox']:
                raise ValueError('Alice ticket data is missing or belongs to another sandbox')
        result['detail'] = 'Health, login, ticket list and ticket read OK'
    except HTTPError as exc:
        result['status'] = 'MUMBLE'
        result['detail'] = f'HTTP {exc.code} during functional check'
    except (URLError, TimeoutError, ConnectionError) as exc:
        result['status'] = 'DOWN'
        result['detail'] = type(exc).__name__ + ': ' + str(exc)
    except Exception as exc:
        result['status'] = 'MUMBLE'
        result['detail'] = type(exc).__name__ + ': ' + str(exc)
    result['elapsed_ms'] += round((time.monotonic() - started) * 1000)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='web_targets.json')
    parser.add_argument('--timeout', type=float, default=3)
    parser.add_argument('--interval', type=float, default=0,
                        help='Seconds between checks; 0 runs once')
    parser.add_argument('--json', action='store_true', help='Output JSON per round')
    args = parser.parse_args()
    if args.timeout <= 0 or args.interval < 0:
        parser.error('timeout must be positive; interval must be nonnegative')
    with open(args.config, encoding='utf-8-sig') as stream:
        targets = json.load(stream)['targets']
    if not targets or any(not t.get('name') or not t.get('url', '').startswith(('http://', 'https://')) for t in targets):
        parser.error('config needs named targets with HTTP(S) URLs')
    try:
        while True:
            with ThreadPoolExecutor(max_workers=min(len(targets), 4)) as executor:
                results = list(executor.map(lambda t: check_web(t, args.timeout), targets))
            checked_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
            if args.json:
                print(json.dumps({'checked_at': checked_at, 'results': results}), flush=True)
            else:
                print('\nChecked at ' + checked_at, flush=True)
                for row in results:
                    print(f"{row['name']:<12} {row['status']:<5} {row['elapsed_ms']:>5} ms  {row['url']}  {row['detail']}", flush=True)
            if not args.interval:
                return 0 if all(r['status'] == 'UP' for r in results) else 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
