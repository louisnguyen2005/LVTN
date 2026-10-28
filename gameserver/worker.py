"""Run round assignments through gateway URLs; post results through backend API."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import secrets
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,ProxyHandler

from checker.attack_defense import check_job,NoRedirect
from checker.service_tick import check_tick_job
from .local import runtime_file


def api(config,path,data=None,token_key='checker_token'):
    origin = config['backend_url'].rstrip('/')
    parsed = urlsplit(origin)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path:
        raise ValueError('backend_url must be an HTTP(S) origin')
    payload = json.dumps(data).encode() if data is not None else None
    req = Request(origin+path,data=payload,headers={
        'Authorization':'Bearer '+config[token_key], 'Content-Type':'application/json'})
    with build_opener(ProxyHandler({}),NoRedirect()).open(req,timeout=15) as response:
        raw = response.read(4*1024*1024+1)
        if len(raw)>4*1024*1024:
            raise ValueError('Backend response too large')
        return json.loads(raw)


def run_once(config,timeout=3):
    plan = api(config,'/api/checker/plan')
    if not plan['jobs']:
        return plan
    with ThreadPoolExecutor(max_workers=min(8,len(plan['jobs']))) as pool:
        if plan.get('mode')=='sla':
            results=list(pool.map(lambda job:check_tick_job(job,plan['tick'],timeout),plan['jobs']))
        else:
            results = list(pool.map(lambda job: check_job(job,plan['round'],timeout),plan['jobs']))
    for result in results:
        # Replay after a lost acknowledgement is safe; DB has UNIQUE(round,team).
        ack=api(config,'/api/checker/result',result)
        if plan.get('mode')=='sla':
            result['sla_points']=ack['sla_points']
        print(json.dumps(result,ensure_ascii=False),flush=True)
    return {**plan,'results':results}


def next_delay(plan,elapsed):
    deadline=plan.get('tick_ends_at') or plan.get('round_ends_at')
    if deadline is None:return 1
    return max(.02,min(1,deadline-plan['server_time']-elapsed))


def preflight(config,timeout):
    targets = config.get('preflight_targets',[])
    if not targets:
        raise ValueError('No preflight targets in worker config')
    success = True
    for t in targets:
        if config.get('mode')=='sla':
            result=check_tick_job(t,0,timeout)
            success &= result['status']=='UP'
            print(json.dumps(result,ensure_ascii=False),flush=True)
            continue
        ident = secrets.token_hex(16)
        job = {**t,'previous':[],'current':{'id':ident,'username':'check_'+ident[:24],
               'password':secrets.token_urlsafe(24),'value':'FLAG{'+secrets.token_urlsafe(32)+'}'}}
        result = check_job(job,0,timeout)
        success &= result['status']=='UP'
        print(json.dumps(result,ensure_ascii=False),flush=True)
    return 0 if success else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path)
    parser.add_argument('--timeout',type=float,default=3)
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--preflight',action='store_true')
    args=parser.parse_args()
    if args.timeout<=0:
        parser.error('timeout must be positive')
    config=json.loads(runtime_file('worker.json',args.config).read_text(encoding='utf-8-sig'))
    if args.preflight:
        return preflight(config,args.timeout)
    try:
        while True:
            started=time.monotonic()
            delay=1
            try:
                result=run_once(config,args.timeout)
                if args.once:
                    return 0 if all(r['status']=='UP' for r in result.get('results',[])) else 1
                if result['phase']=='finished':
                    return 0
                delay=next_delay(result,time.monotonic()-started)
            except Exception as exc:
                print('Worker/backend failure: '+type(exc).__name__+'; retrying without changing score',file=sys.stderr,flush=True)
                if args.once:
                    return 2
            time.sleep(delay)
    except KeyboardInterrupt:
        return 130


if __name__=='__main__':
    raise SystemExit(main())
