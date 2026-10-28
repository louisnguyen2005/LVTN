"""Offline demo: two service rounds, 15 ticks each; A/D flags (default) or SLA-only health checks."""
import argparse
from contextlib import ExitStack
import json
import random
from pathlib import Path
import threading
import time
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import create_app,ThreadingWSGIServer
from .setup import initialize,DEFAULT_RULES
from .ad import AD_TICK_RULES
from .server import create_app as backend_app,RateLimiter
from .submit_tcp import serve_tcp
from .store import Store
from .worker import run_once


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):
        pass


def attackers(store,tick_seconds):
    """Simulated teams: each 'successful attack' takes a planted flag straight from the organizer DB."""
    skill={'team01':.55,'team02':.25,'team03':.4,'team04':.15}
    while True:
        time.sleep(max(.4,tick_seconds/3)*random.uniform(.6,1.4))
        try:
            with store.connect() as db:
                state=store.state(db)
                if state['phase']!='running':
                    continue
                flags=db.execute('SELECT team,value FROM tick_flags WHERE ticket_id IS NOT NULL AND tick<=? AND expires_tick>?',
                                 (state['tick'],state['tick'])).fetchall()
            for team,chance in skill.items():
                targets=[f for f in flags if f['team']!=team]
                if targets and random.random()<chance:
                    store.submit(team,random.choice(targets)['value'])
        except Exception as exc:
            print('Demo attacker error: '+type(exc).__name__,flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fast',action='store_true',help='Accelerate: 2 rounds / 30 ticks in 60 s (sla) or 3 min (ad)')
    parser.add_argument('--no-outage',action='store_true',help='Disable simulated team02 service outage at tick 3')
    parser.add_argument('--exit-after-finish',action='store_true')
    parser.add_argument('--port',type=int,default=19000)
    parser.add_argument('--submit-port',type=int,default=19337,help='TCP flag submission port; 0 disables it')
    parser.add_argument('--mode',choices=['ad','sla'],default='ad',help='ad: flags + simulated attackers; sla: health only')
    parser.add_argument('--no-bots',action='store_true',help='A/D mode: do not simulate attacking teams')
    args=parser.parse_args()
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
        for round_number in (1,2):
            service={'id':f'service{round_number:02d}','name':f'ServiceDesk v{round_number} (demo)',
                     'vulnerability_count':5,'check':'flag' if args.mode=='ad' else 'health','targets':{}}
            for i in range(1,5):
                identity=sandbox+f'-attacker{i}'
                app=create_app(root/f'round{round_number}-team{i}.sqlite','local-demo-alice-password',identity)
                port=listen(simulate(app,not args.no_outage and round_number==1 and i==2))
                service['targets'][f'team{i:02d}']={'url':f'http://127.0.0.1:{port}/health','expected_sandbox':identity}
                if round_number==1:
                    targets.append({'team':f'team{i:02d}','url':f'http://127.0.0.1:{port}','expected_sandbox':identity})
            services.append(service)
        # initialize uses a separate empty directory so service databases are preserved.
        event=root/'event'
        base=AD_TICK_RULES if args.mode=='ad' else DEFAULT_RULES
        # Flag PUT/GET needs several PBKDF2 logins per team, so A/D fast ticks are 6 s (3 min total).
        fast={'round_seconds':90,'tick_seconds':6} if args.mode=='ad' else {'round_seconds':30,'tick_seconds':2}
        rules={**base,**fast} if args.fast else base
        # Demo links stand in for gateway ports 8011-8014 -> attackerN:8080.
        links=[{'name':f'team{i:02d} ServiceDesk','host':'127.0.0.1','port':int(t['url'].rsplit(':',1)[1]),
                'gateway':f"127.0.0.1:{t['url'].rsplit(':',1)[1]}",'vm':f'10.80.0.{10+i}:8080',
                'node':f'attacker{i}','team':t['team'],'role':'team',
                'health':t['url']+'/health','expected_identity':t['expected_sandbox']}
               for i,t in enumerate(targets,1)]
        cfg=initialize(event,args.mode+'-demo-'+uuid4().hex[:8],sandbox,targets,f'http://127.0.0.1:{args.port}',
                       rules,services=services,demo=True,links=links)
        store=Store(event/'competition.sqlite',cfg)
        holder['store']=store
        limiter=RateLimiter(store.clock)
        submit_port=None
        if args.mode=='ad' and args.submit_port:
            tcp=serve_tcp(store,limiter,'127.0.0.1',args.submit_port)
            stack.callback(tcp.server_close); stack.callback(tcp.shutdown)
            submit_port=tcp.server_address[1]
        listen(backend_app(store,limiter,submit_port),args.port)
        store.start()
        if args.mode=='ad' and not args.no_bots:
            threading.Thread(target=attackers,args=(store,rules['tick_seconds']),daemon=True).start()
        worker=json.loads((event/'worker.json').read_text())
        print(f'Demo scoreboard: http://127.0.0.1:{args.port}/   flag submit: http://127.0.0.1:{args.port}/submit',flush=True)
        if submit_port:
            print(f'TCP flag submission: nc 127.0.0.1 {submit_port}  (team tokens: {event / "teams"})',flush=True)
        print(f'Database and config: {event}',flush=True)
        print(f'2 rounds, 15 ticks/round, 30 ticks total. Tick={rules["tick_seconds"]}s; duration={rules["round_seconds"]*2}s.',flush=True)
        print('Simulates two services; vulnerability_count=5 is schedule metadata, not five implemented vulnerabilities.',flush=True)
        if not args.no_outage:
            print('Demo outage: team02 service01 DOWN at tick 3, recovers at tick 4.',flush=True)
        try:
            while True:
                try:
                    result=run_once(worker)
                except Exception as exc:
                    print('Worker/backend failure: '+type(exc).__name__+'; retrying',flush=True)
                    time.sleep(1)
                    continue
                if result['phase']=='finished':
                    if args.exit_after_finish:
                        break
                    print('Event finished. Scoreboard remains open until Ctrl+C.',flush=True)
                    while True:
                        time.sleep(1)
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__=='__main__':
    main()
