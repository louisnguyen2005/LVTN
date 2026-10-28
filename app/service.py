"""Run the implementation selected by the provisioned per-instance config."""
import argparse
import json
from pathlib import Path
from wsgiref.simple_server import make_server
try:
    from .portal import ThreadingWSGIServer,create_app as portal_app
    from .shop import create_app as shop_app
except ImportError:
    from portal import ThreadingWSGIServer,create_app as portal_app
    from shop import create_app as shop_app


def create_app(**config):
    kind=config.pop('implementation','servicedesk-demo')
    if kind not in ('webshop','servicedesk-demo'):
        raise ValueError('Unknown implementation')
    config.pop('listen_port',None)
    return (shop_app if kind=='webshop' else portal_app)(**config)


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int)
    args=p.parse_args();config=json.loads(Path(args.config).read_text(encoding='utf-8'));port=config.get('listen_port',8080)
    app=create_app(**config)
    with make_server(args.host,args.port or port,app,server_class=ThreadingWSGIServer) as server:server.serve_forever()


if __name__=='__main__':main()
