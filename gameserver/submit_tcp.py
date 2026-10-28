"""Line-based TCP flag submission, the classic A/D interface for exploit scripts.

    $ nc 127.0.0.1 31337
    CTF flag submission. Send your team token, then one flag per line.
    <team token>
    OK team02
    FLAG{...}
    FLAG{...} ACCEPTED +50

Each flag gets exactly one answer line: "<flag> <VERDICT> +<points>". Shares the HTTP rate limit.
"""
import socketserver
import threading
from .errors import Rejected
from .store import digest

MAX_LINE = 256


class Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def say(self, text):
        self.wfile.write((text + '\n').encode())

    def readline(self):
        raw = self.rfile.readline(MAX_LINE + 1)
        if not raw:
            return None
        if len(raw) > MAX_LINE:
            raise ValueError('line too long')
        return raw.decode('utf-8', 'replace').strip()

    def handle(self):
        server = self.server
        try:
            self.say('CTF flag submission. Send your team token, then one flag per line.')
            token = self.readline()
            team = server.team_tokens.get(digest(token)) if token else None
            if not team:
                self.say('ERR invalid team token')
                return
            self.say('OK ' + team)
            while True:
                line = self.readline()
                if line is None:
                    return
                if not line:
                    continue
                try:
                    server.limiter.take(team, 1)
                    result = server.store.submit(team, line)
                    self.say(f"{line[:64]} {result['verdict']} +{result['points']}")
                except Rejected as exc:
                    self.say(f'{line[:64]} ERR {exc}')
        except (OSError, ValueError):
            return


class FlagSubmitServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, store, limiter):
        self.store, self.limiter = store, limiter
        self.team_tokens = {digest(t['token']): t['id'] for t in store.cfg['teams']}
        super().__init__(address, Handler)


def serve_tcp(store, limiter, host, port):
    """Start the TCP submission server in a daemon thread and return it (call shutdown() to stop)."""
    server = FlagSubmitServer((host, port), store, limiter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
