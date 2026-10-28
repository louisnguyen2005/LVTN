"""Offline SLA demo: two service rounds, 15 ticks each, automatic health checks."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import threading
import time
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import ThreadingWSGIServer
from app.service import create_app as service_app
from .setup import initialize,DEFAULT_RULES
from .server import create_app as backend_app
from .store import Store
from .worker import run_once
from .worker import next_delay
from .deployment import load_deployment


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):
        pass


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fast',action='store_true',help='Accelerate one hour into 150 seconds, preserving 2 rounds / 30 ticks')
    parser.add_argument('--no-outage',action='store_true',help='Disable simulated team02 service outage at tick 3')
    parser.add_argument('--exit-after-finish',action='store_true')
    parser.add_argument('--port',type=int,default=19000)
    args=parser.parse_args()
    deployment=load_deployment()
    root=Path('gameserver')/('runtime-demo-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid4().hex[:6])
    sandbox=str(uuid4())
    with ExitStack() as stack:
        def listen(app,port=0):
            server=stack.enter_context(make_server('127.0.0.1',port,app,server_class=ThreadingWSGIServer,handler_class=Quiet))
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            stack.callback(thread.join,2); stack.callback(server.shutdown)
            return server.server_port
        holder={}
        def simulate(app,enabled):
            def wrapper(env,start):
                store=holder.get('store')
                if enabled and store:
                    with store.connect() as db:
                        state=store.state(db)
                    if state['phase']=='running' and state['tick']==3:
                        raw=b'{"status":"down","detail":"Simulated outage for tick 3"}'
                        start('503 Service Unavailable',[('Content-Type','application/json'),('Content-Length',str(len(raw)))])
                        return [raw]
                return app(env,start)
            return wrapper
        targets=[]
        services=[]
        for round_number,definition in enumerate(deployment['services'],1):
            service={'id':definition['id'],'name':definition['name']+' demo',
                     'vulnerability_count':definition['vulnerability_count'],'check':definition['check'],'targets':{}}
            for i,team in enumerate(deployment['teams'],1):
                identity=sandbox+'-'+team['node']
                app=service_app(database=str(root/f"{definition['id']}-{team['id']}.sqlite"),
                    password='local-demo-alice-password',sandbox_id=identity,service_id=definition['id'],
                    implementation=definition.get('implementation','servicedesk-demo'),
                    vulnerabilities=definition.get('vulnerabilities',{}))
                port=listen(simulate(app,not args.no_outage and round_number==1 and i==2))
                service['targets'][team['id']]={'url':f'http://127.0.0.1:{port}/health','expected_sandbox':identity,'expected_service':definition['id']}
                if round_number==1:
                    targets.append({'team':team['id'],'url':f'http://127.0.0.1:{port}','expected_sandbox':identity})
            services.append(service)
        # initialize uses a separate empty directory so service databases are preserved.
        event=root/'event'
        rules=dict(deployment['rules'])
        if args.fast:rules.update(round_seconds=rules['round_seconds']//rules['tick_seconds']*5,tick_seconds=5)
        cfg=initialize(event,'sla-demo-'+uuid4().hex[:8],sandbox,targets,f'http://127.0.0.1:{args.port}',
                       rules,services=services,demo=True)
        store=Store(event/'competition.sqlite',cfg)
        holder['store']=store
        listen(backend_app(store),args.port)
        store.start()
        worker=json.loads((event/'worker.json').read_text())
        print(f'Demo scoreboard: http://127.0.0.1:{args.port}/',flush=True)
        print(f'Database and config: {event}',flush=True)
        per_round=rules['round_seconds']//rules['tick_seconds']
        print(f'{rules["max_rounds"]} rounds, {per_round} ticks/round, {per_round*rules["max_rounds"]} ticks total. Tick={rules["tick_seconds"]}s; duration={rules["round_seconds"]*rules["max_rounds"]}s.',flush=True)
        print('NOVA MART demo instances with five intentional challenge paths; browser checks are manual.',flush=True)
        if not args.no_outage:
            print(f'Demo outage: {deployment["teams"][1]["id"]} {deployment["services"][0]["id"]} DOWN at tick 3, recovers at tick 4.',flush=True)
        try:
            while True:
                started=time.monotonic()
                try:result=run_once(worker)
                except Exception as exc:
                    print('Demo checker/backend failure: '+type(exc).__name__+'; next poll will continue.',flush=True)
                    time.sleep(1)
                    continue
                if result['phase']=='finished':
                    if args.exit_after_finish:
                        break
                    print('Event finished. Scoreboard remains open until Ctrl+C.',flush=True)
                    while True:
                        time.sleep(1)
                time.sleep(next_delay(result,time.monotonic()-started))
        except KeyboardInterrupt:
            pass


if __name__=='__main__':
    main()
