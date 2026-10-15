"""MeKoData CTF flag validator (scaffold).

A tiny HTTP service for the `checker` server. It loads the known per-team flags
from a config file and validates submitted flags. Replace or extend this with a
full scoreboard/checker later -- the systemd unit and config path stay the same.

Endpoints:
  GET  /health                       -> {"status": "ok"}
  GET  /validate?team=team01&flag=X  -> {"valid": bool, "team": "team01"|null}
  POST /validate  (team=..&flag=..)  -> same as GET
"""
import argparse
import hmac
import json
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server


def create_app(flags):
    # flags: {"team01": "MeKoDataCTF{team01_...}", ...}
    flags = {str(team): str(value) for team, value in flags.items()}
    if not flags:
        raise ValueError('At least one team flag is required')

    def match(submitted):
        """Return the team a submitted flag belongs to, or None (constant-ish time)."""
        found = None
        for team, value in flags.items():
            if hmac.compare_digest(submitted.encode(), value.encode()):
                found = team
        return found

    def app(env, start):
        path = env.get('PATH_INFO', '/')
        method = env.get('REQUEST_METHOD', 'GET')

        def respond(status, payload):
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            start(f'{status} {HTTPStatus(status).phrase}', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'),
                ('X-Content-Type-Options', 'nosniff'),
            ])
            return [body]

        if path == '/health' and method == 'GET':
            return respond(200, {'status': 'ok', 'teams': sorted(flags)})
        if path != '/validate' or method not in ['GET', 'POST']:
            return respond(404, {'error': 'Not found'})
        try:
            if method == 'POST':
                size = int(env.get('CONTENT_LENGTH') or 0)
                if not 0 <= size <= 4096:
                    return respond(413, {'error': 'Request too large'})
                params = parse_qs(env['wsgi.input'].read(size).decode('utf-8'), max_num_fields=8)
            else:
                params = parse_qs(env.get('QUERY_STRING', ''), max_num_fields=8)
        except (ValueError, UnicodeDecodeError):
            return respond(400, {'error': 'Invalid request'})
        submitted = params.get('flag', [''])[0]
        claimed = params.get('team', [''])[0]
        if not submitted:
            return respond(400, {'error': 'flag is required'})
        owner = match(submitted)
        valid = owner is not None and (not claimed or claimed == owner)
        return respond(200, {'valid': valid, 'team': owner if valid else None})

    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))
    with make_server(args.host, args.port, create_app(config['flags'])) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
