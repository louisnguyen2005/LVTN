"""Authenticated JSON API and public scoreboard. Bind loopback by default."""
import argparse
from collections import defaultdict, deque
import hmac
import json
from pathlib import Path
import sys
import threading
from wsgiref.simple_server import make_server

from app.portal import ThreadingWSGIServer
from .store import Store, Rejected, digest
from .local import runtime_file,local_settings


def create_app(store):
    config = store.cfg
    rates, rate_lock = defaultdict(deque), threading.Lock()
    team_tokens = {digest(t['token']): t['id'] for t in config['teams']}
    page = Path(__file__).with_name('scoreboard.html').read_bytes()

    def app(env, start):
        path, method = env.get('PATH_INFO', '/'), env.get('REQUEST_METHOD', 'GET')

        def response(code, payload, html=False):
            from http import HTTPStatus
            data = payload if html else json.dumps(payload, ensure_ascii=False).encode()
            headers = [('Content-Type', 'text/html; charset=utf-8' if html else 'application/json; charset=utf-8'),
                       ('Content-Length',str(len(data))), ('Cache-Control','no-store'),
                       ('X-Content-Type-Options','nosniff'), ('Referrer-Policy','no-referrer'),
                       ('X-Frame-Options','DENY')]
            start(f'{code} {HTTPStatus(code).phrase}',headers)
            return [data]

        def auth(role):
            header = env.get('HTTP_AUTHORIZATION','')
            token = header[7:] if header.startswith('Bearer ') else ''
            if not token or len(token) > 256:
                raise Rejected('Bearer token required',401)
            if role == 'team':
                team = team_tokens.get(digest(token))
                if not team:
                    raise Rejected('Invalid team token',403)
                return team
            if not hmac.compare_digest(token.encode(), config[role+'_token'].encode()):
                raise Rejected('Invalid token',403)

        def body():
            if env.get('CONTENT_TYPE','').split(';')[0] != 'application/json':
                raise Rejected('Use application/json',415)
            try:
                length = int(env.get('CONTENT_LENGTH') or 0)
                if not 0 < length <= 32768:
                    raise Rejected('Invalid body length',413)
                value = json.loads(env['wsgi.input'].read(length))
                if not isinstance(value,dict):
                    raise ValueError()
                return value
            except (ValueError, UnicodeDecodeError):
                raise Rejected('Invalid JSON body')

        try:
            if method == 'GET' and path == '/':
                return response(200,page,True)
            if method == 'GET' and path == '/health':
                return response(200,{'status':'ok','event_id':config['event_id']})
            if method == 'GET' and path == '/api/scoreboard':
                return response(200,store.public())
            if method == 'GET' and path == '/api/attack-data':
                return response(200,store.attack_data())
            if method == 'GET' and path == '/api/checks':
                return response(200,store.history())
            if path == '/api/checker/plan' and method == 'GET':
                auth('checker')
                return response(200,store.plan())
            if path == '/api/checker/result' and method == 'POST':
                auth('checker')
                return response(200,store.result(body()))
            if path == '/api/submit' and method == 'POST':
                team = auth('team')
                with rate_lock:
                    times = rates[team]
                    now = store.clock()
                    while times and times[0] <= now-60:
                        times.popleft()
                    if len(times) >= 60:
                        raise Rejected('Limit: 60 submissions per minute',429)
                    times.append(now)
                return response(200,store.submit(team,body().get('flag')))
            if path in ('/api/admin/start','/api/admin/finish') and method == 'POST':
                auth('admin')
                body()
                return response(200,store.start() if path.endswith('/start') else store.finish())
            return response(404,{'error':'Not found'})
        except Rejected as exc:
            return response(exc.status,{'error':str(exc)})
        except Exception as exc:
            print('Backend error: '+type(exc).__name__,file=sys.stderr,flush=True)
            return response(500,{'error':'Backend error; consult operator logs'})
    return app


def load_store(config_path):
    path = Path(config_path).resolve()
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    database = Path(config.get('database','competition.sqlite'))
    if not database.is_absolute():
        database = path.parent/database
    return Store(database,config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int)
    args = parser.parse_args()
    store = load_store(runtime_file('config.json',args.config))
    port=args.port if args.port is not None else local_settings().get('backend_port',9000)
    with make_server(args.host,port,create_app(store),server_class=ThreadingWSGIServer) as server:
        print(f'Scoreboard http://{args.host}:{server.server_port}/ (event phase: {store.public()["phase"]})',flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
