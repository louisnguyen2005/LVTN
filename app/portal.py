"""ServiceDesk lab: deliberate object authorization flaws, no quiz or flags."""
import argparse
import hmac
import json
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from http import HTTPStatus
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Serve concurrent requests with a bounded number of worker threads."""

    daemon_threads = True
    request_queue_size = 128
    max_workers = 32

    def __init__(self, *args, **kwargs):
        self._worker_slots = threading.BoundedSemaphore(self.max_workers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


def create_app(database, password, sandbox_id, enforce_owner=False):
    if not password or not sandbox_id:
        raise ValueError('Lab password and sandbox identity are required')
    database = Path(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute('CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, status TEXT, private_note TEXT)')
        connection.executemany('INSERT OR IGNORE INTO tickets VALUES (?, ?, ?, ?, ?)', [
            (1201, 'alice', 'Laptop cannot connect to Wi-Fi', 'open', 'Alice workspace: ' + sandbox_id),
            (1401, 'bob', 'Internal project access request', 'open', 'Bob private workspace: ' + sandbox_id),
        ])
    sessions = {}
    sessions_lock = threading.Lock()
    page = Path(__file__).with_name('portal.html').read_bytes()

    def app(env, start):
        path = env.get('PATH_INFO', '/')
        method = env.get('REQUEST_METHOD', 'GET')

        def respond(status, payload, headers=None, html=False):
            body = payload if html else json.dumps(payload, ensure_ascii=False).encode('utf-8')
            start(f'{status} {HTTPStatus(status).phrase}', [
                ('Content-Type', 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8'),
                ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'),
                ('X-Content-Type-Options', 'nosniff'),
            ] + (headers or []))
            return [body]

        if method not in ['GET', 'POST']:
            return respond(405, {'error': 'Method not allowed'})
        if path == '/' and method == 'GET':
            return respond(200, page, html=True)
        if path == '/health' and method == 'GET':
            return respond(200, {'status': 'ok', 'sandbox': sandbox_id})
        form = {}
        if method == 'POST':
            try:
                size = int(env.get('CONTENT_LENGTH') or 0)
                if not 0 <= size <= 4096:
                    return respond(413, {'error': 'Request too large'})
                form = parse_qs(env['wsgi.input'].read(size).decode('utf-8'), max_num_fields=8)
            except (ValueError, UnicodeDecodeError):
                return respond(400, {'error': 'Invalid request'})
        if path == '/login' and method == 'POST':
            candidate = form.get('password', [''])[0]
            if form.get('username') != ['alice'] or not hmac.compare_digest(candidate.encode(), password.encode()):
                return respond(401, {'error': 'Invalid login'})
            now = time.time()
            token = secrets.token_urlsafe(32)
            with sessions_lock:
                for old in list(sessions):
                    if sessions[old] <= now:
                        del sessions[old]
                sessions[token] = now + 1800
            return respond(200, {'user': 'alice'}, [('Set-Cookie', f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')])
        try:
            cookies = SimpleCookie(env.get('HTTP_COOKIE', ''))
            token = cookies['session'].value if 'session' in cookies else ''
        except CookieError:
            token = ''
        with sessions_lock:
            session_expiry = sessions.get(token, 0)
        if session_expiry <= time.time():
            return respond(401, {'error': 'Login required'})
        if path == '/logout' and method == 'POST':
            with sessions_lock:
                sessions.pop(token, None)
            return respond(200, {'status': 'logged out'}, [('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')])
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.row_factory = sqlite3.Row
            if path == '/api/tickets' and method == 'GET':
                rows = connection.execute('SELECT id, owner, title, status FROM tickets WHERE owner = ?', ('alice',))
                return respond(200, [dict(row) for row in rows])
            if not path.startswith('/api/tickets/'):
                return respond(404, {'error': 'Not found'})
            try:
                ticket_id = int(path.rsplit('/', 1)[-1])
            except ValueError:
                return respond(404, {'error': 'Ticket not found'})
            row = connection.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
            if row is None:
                return respond(404, {'error': 'Ticket not found'})
            # Both read and update intentionally omit owner authorization in lab mode.
            if enforce_owner and row['owner'] != 'alice':
                return respond(403, {'error': 'Forbidden'})
            if method == 'POST':
                status = form.get('status', [''])[0]
                if status not in ['open', 'closed']:
                    return respond(400, {'error': 'Status must be open or closed'})
                connection.execute('UPDATE tickets SET status = ? WHERE id = ?', (status, ticket_id))
                row = connection.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
            return respond(200, dict(row))

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--host', default='127.0.0.1')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    with make_server(args.host, args.port, create_app(**config), server_class=ThreadingWSGIServer) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
