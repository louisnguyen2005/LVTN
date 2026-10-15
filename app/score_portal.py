"""Point lookup lab (tra cuu diem): a deliberate IDOR on student score records.

Each team VM runs its own copy. A student logs in with the team password, lists
their own score records, and -- because /api/scores/<record_id> performs no owner
authorization -- can read any record by id, including the hidden teacher "audit"
record whose remark holds this box's flag: MeKoDataCTF{teamNN_xxxxxxxx}.
"""
import argparse
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import closing
from http import HTTPStatus
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

# recordId where the teacher/registrar "audit" remarks live. point.js documents
# this range as an internal note; the flag is stored on the first audit record.
AUDIT_BASE = 9000


def create_app(database, password, sandbox_id, flag,
               student_id=20260101, student_name='Sinh vien Team',
               student_class='MeKoData-2026', enforce_owner=False):
    if not password or not sandbox_id or not flag:
        raise ValueError('Lab password, sandbox identity and flag are required')
    student_id = int(student_id)
    database = Path(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            'CREATE TABLE IF NOT EXISTS scores ('
            'record_id INTEGER PRIMARY KEY, student_id INTEGER, student_name TEXT, '
            'subject TEXT, score REAL, remark TEXT)')
        connection.executemany(
            'INSERT OR IGNORE INTO scores VALUES (?, ?, ?, ?, ?, ?)', [
                # The logged-in student's own records (listed by /api/scores).
                (1001, student_id, student_name, 'Toan',     8.5, 'Diem giua ky da duyet'),
                (1002, student_id, student_name, 'Vat ly',   7.0, 'Can nop lai bai thuc hanh'),
                (1003, student_id, student_name, 'Tin hoc',  9.0, 'Hoan thanh do an'),
                # Peer records -- reachable only by changing the recordId (IDOR).
                (1004, student_id + 1, 'Tran Thi B', 'Toan',   6.5, 'Nghi 2 buoi'),
                (1005, student_id + 2, 'Le Van C',   'Vat ly', 8.0, 'Ok'),
                # Internal audit record. No owner, not in any student's list.
                (AUDIT_BASE + 1, 0, 'phong-giao-vu', 'AUDIT', None,
                 'Ghi chu giao vu (noi bo - khong hien thi cho sinh vien): ' + flag),
            ])
    sessions = {}
    html = Path(__file__).with_name('score.html').read_bytes()
    point_js = Path(__file__).with_name('point.js').read_bytes()

    def app(env, start):
        path = env.get('PATH_INFO', '/')
        method = env.get('REQUEST_METHOD', 'GET')

        def respond(status, payload, headers=None, raw=None):
            if raw is not None:
                body, ctype = raw
            else:
                body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
                ctype = 'application/json; charset=utf-8'
            start(f'{status} {HTTPStatus(status).phrase}', [
                ('Content-Type', ctype),
                ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'),
                ('X-Content-Type-Options', 'nosniff'),
            ] + (headers or []))
            return [body]

        if method not in ['GET', 'POST']:
            return respond(405, {'error': 'Method not allowed'})
        if path == '/' and method == 'GET':
            return respond(200, None, raw=(html, 'text/html; charset=utf-8'))
        if path == '/static/point.js' and method == 'GET':
            # Served fresh on every refresh so the API map is always visible.
            return respond(200, None, raw=(point_js, 'application/javascript; charset=utf-8'))
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
            if form.get('username') != ['student'] or not hmac.compare_digest(candidate.encode(), password.encode()):
                return respond(401, {'error': 'Sai tai khoan hoac mat khau'})
            now = time.time()
            for old in list(sessions):
                if sessions[old] <= now:
                    del sessions[old]
            token = secrets.token_urlsafe(32)
            sessions[token] = now + 1800
            return respond(200, {'user': 'student'}, [('Set-Cookie', f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')])
        try:
            cookies = SimpleCookie(env.get('HTTP_COOKIE', ''))
            token = cookies['session'].value if 'session' in cookies else ''
        except CookieError:
            token = ''
        if sessions.get(token, 0) <= time.time():
            return respond(401, {'error': 'Can dang nhap'})
        if path == '/logout' and method == 'POST':
            del sessions[token]
            return respond(200, {'status': 'logged out'}, [('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')])
        if path == '/api/me' and method == 'GET':
            return respond(200, {'student_id': student_id, 'name': student_name, 'class': student_class})
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.row_factory = sqlite3.Row
            if path == '/api/scores' and method == 'GET':
                # Only the logged-in student's own records are listed here.
                rows = connection.execute(
                    'SELECT record_id, student_id, student_name, subject, score, remark '
                    'FROM scores WHERE student_id = ? ORDER BY record_id', (student_id,))
                return respond(200, [dict(row) for row in rows])
            if not path.startswith('/api/scores/'):
                return respond(404, {'error': 'Not found'})
            try:
                record_id = int(path.rsplit('/', 1)[-1])
            except ValueError:
                return respond(404, {'error': 'Khong tim thay ban ghi'})
            row = connection.execute('SELECT * FROM scores WHERE record_id = ?', (record_id,)).fetchone()
            if row is None:
                return respond(404, {'error': 'Khong tim thay ban ghi'})
            # IDOR: detail lookup intentionally omits the owner authorization check.
            # Set enforce_owner=True (the fixed build) to require the record to
            # belong to the logged-in student.
            if enforce_owner and row['student_id'] != student_id:
                return respond(403, {'error': 'Forbidden'})
            return respond(200, dict(row))

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--host', default='127.0.0.1')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    with make_server(args.host, args.port, create_app(**config)) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
