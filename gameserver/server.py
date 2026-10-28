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


class RateLimiter:
    """60 flags per team per minute, shared by the HTTP and TCP submission interfaces."""

    def __init__(self, clock, per_minute=60):
        self.clock, self.per_minute = clock, per_minute
        self.rates, self.lock = defaultdict(deque), threading.Lock()

    def take(self, team, count):
        with self.lock:
            times = self.rates[team]
            now = self.clock()
            while times and times[0] <= now-60:
                times.popleft()
            if len(times)+count > self.per_minute:
                raise Rejected(f'Limit: {self.per_minute} flags per minute',429)
            times.extend([now]*count)


def create_app(store, limiter=None, submit_port=None):
    config = store.cfg
    limiter = limiter or RateLimiter(store.clock)
    limit = limiter.take
    team_tokens = {digest(t['token']): t['id'] for t in config['teams']}
    page = Path(__file__).with_name('scoreboard.html').read_bytes()
    submit_page = Path(__file__).with_name('submit.html').read_bytes()

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
            if method == 'GET' and path == '/submit':
                return response(200,submit_page,True)
            if method == 'GET' and path == '/api/trace':
                return response(200,store.trace())
            if method == 'GET' and path == '/api/flags':
                return response(200,store.flag_overview() if store.ad else {'flags':[]})
            if method == 'GET' and path == '/api/info':
                # Contestant-facing connection facts: how to submit, never any secret.
                return response(200,{'event_id':config['event_id'],'mode':store.rules.get('mode'),
                                     'flag_format':'FLAG{[A-Za-z0-9_-]{32}}','submit_tcp_port':submit_port,
                                     'rate_limit_per_minute':limiter.per_minute,'teams':[t['id'] for t in config['teams']]})
            if method == 'GET' and path == '/api/feed':
                return response(200,store.feed())
            if method == 'GET' and path == '/api/network':
                return response(200,store.network())
            if method == 'GET' and path == '/api/team/status':
                return response(200,store.team_status(auth('team')))
            if path == '/api/checker/links' and method == 'POST':
                auth('checker')
                return response(200,store.record_links(body()))
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
                data = body()
                if 'flags' in data:
                    # Batch form for exploit scripts: {"flags": [...]} returns one verdict per flag.
                    flags = data['flags']
                    if not isinstance(flags,list) or not 0 < len(flags) <= 20:
                        raise Rejected('Send 1-20 flags per request')
                    limit(team,len(flags))
                    return response(200,{'results':[{'flag':f if isinstance(f,str) and len(f)<=64 else None,**store.submit(team,f)} for f in flags]})
                limit(team,1)
                return response(200,store.submit(team,data.get('flag')))
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
    parser.add_argument('--config',type=Path,default=Path('gameserver/runtime-sla/config.json'))
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=9000)
    parser.add_argument('--submit-port',type=int,default=31337,help='TCP flag submission port (A/D mode); 0 disables it')
    args = parser.parse_args()
    store = load_store(args.config)
    limiter = RateLimiter(store.clock)
    tcp = None
    if store.ad and args.submit_port:
        from .submit_tcp import serve_tcp
        tcp = serve_tcp(store,limiter,args.host,args.submit_port)
        print(f'TCP flag submission on {args.host}:{args.submit_port}',flush=True)
    with make_server(args.host,args.port,create_app(store,limiter,args.submit_port if tcp else None),server_class=ThreadingWSGIServer) as server:
        print(f'Scoreboard http://{args.host}:{server.server_port}/ (event phase: {store.public()["phase"]})',flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if tcp:
                tcp.shutdown()


if __name__ == '__main__':
    main()
