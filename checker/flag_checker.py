"""Traced flag checker: CHECK -> PUT -> GET with one verdict per action and per stored flag.

Statuses follow the usual attack/defense convention (HackerDom checksystem, ForcAD, FAUST):
UP      every action worked;
CORRUPT the service works but an older, still-valid flag can no longer be retrieved;
MUMBLE  the service answers but behaves wrongly (bad identity, broken API, wrong data);
DOWN    no connection, timeout or HTTP 5xx.
"""
from http.cookiejar import CookieJar
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener

SEVERITY = {'UP': 0, 'CORRUPT': 1, 'MUMBLE': 2, 'DOWN': 3, 'ERROR': 4}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def client():
    return build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(CookieJar()))


def request(opener, url, timeout, data=None):
    payload = urlencode(data).encode() if data is not None else None
    req = Request(url, data=payload, headers={'Accept': 'application/json'})
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Service response too large')
        return json.loads(raw)


class FlagMissing(Exception):
    """The service is healthy but a stored flag is gone or altered."""


def classify(exc):
    if isinstance(exc, FlagMissing):
        return 'CORRUPT', str(exc)
    if isinstance(exc, HTTPError):
        return ('DOWN' if exc.code >= 500 else 'MUMBLE'), f'HTTP {exc.code}'
    if isinstance(exc, (URLError, TimeoutError, ConnectionError, OSError)):
        return 'DOWN', 'Connection failed or timed out'
    if isinstance(exc, ValueError):
        return 'MUMBLE', str(exc)[:160]
    if isinstance(exc, (KeyError, TypeError, AttributeError)):
        return 'MUMBLE', 'Invalid service response'
    return 'ERROR', 'Unexpected checker exception'


class Trace:
    def __init__(self):
        self.actions = []

    def run(self, action, step, flag_id=None):
        """Run one checker action, record its verdict, and return (ok, value)."""
        started = time.monotonic()
        try:
            value, status, detail = step(), 'UP', 'OK'
        except Exception as exc:
            value = None
            status, detail = classify(exc)
        self.actions.append({'action': action, 'flag_id': flag_id, 'status': status, 'detail': detail,
                             'elapsed_ms': round((time.monotonic() - started) * 1000)})
        return status == 'UP', value


def check_health(opener, base, job, timeout):
    health = request(opener, base + '/health', timeout)
    if health.get('status') != 'ok' or health.get('sandbox') != job['expected_sandbox']:
        raise ValueError('Wrong service health or sandbox identity')
    if 'tickets-v2' not in health.get('capabilities', []):
        raise ValueError('Reprovision ServiceDesk: tickets-v2 is required')


def put_flag(opener, base, current, timeout):
    # Each flag lives in a new ordinary account: no privileged checker endpoint exists.
    try:
        request(opener, base + '/register', timeout, {'username': current['username'], 'password': current['password']})
    except HTTPError as exc:
        if exc.code != 409:
            raise
    login = request(opener, base + '/login', timeout, {'username': current['username'], 'password': current['password']})
    if login.get('user') != current['username']:
        raise ValueError('Wrong login identity')
    title = 'Service request ' + current['id']
    tickets = request(opener, base + '/api/tickets', timeout)
    if not isinstance(tickets, list):
        raise ValueError('Invalid ticket list')
    matching = [t for t in tickets if t.get('title') == title and t.get('owner') == current['username']]
    if matching:
        ticket_id = matching[0]['id']
    else:
        ticket_id = request(opener, base + '/api/tickets', timeout, {'title': title, 'private_note': current['value']})['id']
    if type(ticket_id) is not int or ticket_id < 1:
        raise ValueError('Invalid ticket identifier')
    return ticket_id


def get_flag(opener, base, flag, ticket_id, timeout, login=True):
    if login:
        try:
            request(opener, base + '/login', timeout, {'username': flag['username'], 'password': flag['password']})
        except HTTPError as exc:
            if exc.code == 401:
                raise FlagMissing('Flag owner account is gone')
            raise
    try:
        ticket = request(opener, base + f'/api/tickets/{ticket_id}', timeout)
    except HTTPError as exc:
        if exc.code == 404:
            raise FlagMissing('Flag ticket is gone')
        raise
    if ticket.get('owner') != flag['username'] or ticket.get('private_note') != flag['value']:
        raise FlagMissing('Stored flag is missing or changed')


def run_flag_check(job, timeout=3):
    """job: url (origin), expected_sandbox, current flag and the still-valid previous flags."""
    started = time.monotonic()
    base = job['url'].removesuffix('/health').rstrip('/')
    current = job['current']
    trace = Trace()
    opener = client()
    result = {'status': 'UP', 'detail': '', 'ticket_id': None, 'actions': trace.actions, 'flags': []}

    ok, _ = trace.run('CHECK', lambda: check_health(opener, base, job, timeout))
    if ok:
        ok, ticket_id = trace.run('PUT', lambda: put_flag(opener, base, current, timeout), current['id'])
        if ok:
            result['ticket_id'] = ticket_id
            ok, _ = trace.run('GET', lambda: get_flag(opener, base, current, ticket_id, timeout, login=False), current['id'])
            if trace.actions[-1]['status'] == 'CORRUPT':
                # A flag that cannot be read back right after PUT is broken storage, not a lost flag.
                trace.actions[-1].update(status='MUMBLE', detail='New flag cannot be retrieved by its owner')
            result['flags'].append({'flag_id': current['id'], 'status': trace.actions[-1]['status']})
    if ok:
        # Every still-valid older flag must survive the team's patches; check each one.
        for old in job.get('previous', []):
            trace.run('GET', lambda old=old: get_flag(client(), base, old, old['ticket_id'], timeout), old['id'])
            result['flags'].append({'flag_id': old['id'], 'status': trace.actions[-1]['status']})
    worst = max(trace.actions, key=lambda a: SEVERITY[a['status']])
    if worst['status'] == 'UP':
        result['detail'] = f"CHECK, PUT, GET OK; {len(job.get('previous', []))} previous flag(s) intact"
    else:
        result['status'] = worst['status']
        result['detail'] = f"{worst['action']}: {worst['detail']}"
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result
