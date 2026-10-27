"""Small identity page on each attacker VM for HTTP connectivity checks."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def handler_for(node):
    if node not in {'attacker1', 'attacker2', 'attacker3', 'attacker4'}:
        raise ValueError('Unexpected attacker node')

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/health':
                body = json.dumps({'node': node}).encode('utf-8')
                mime = 'application/json; charset=utf-8'
            elif self.path == '/':
                body = (f'<!doctype html><html lang="en"><meta charset="utf-8">'
                        f'<title>{node}</title><h1>{node}</h1>'
                        '<p>IDOR lab attacker machine. ServiceDesk: '
                        '<a href="http://10.80.0.20/">http://10.80.0.20/</a></p></html>').encode('utf-8')
                mime = 'text/html; charset=utf-8'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=80)
    args = parser.parse_args()
    with ThreadingHTTPServer((args.host, args.port), handler_for(args.node)) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
