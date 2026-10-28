"""Real HTTP checks with a controlled clock for the full one-hour schedule."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request,build_opener,ProxyHandler
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import ThreadingWSGIServer
from gameserver.server import create_app
from gameserver.setup import initialize,DEFAULT_RULES
from gameserver.store import Store,validate_config
from gameserver.worker import run_once,preflight


class Quiet(WSGIRequestHandler):
    def log_message(self,*args): pass


class TickScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.now=1000.; self.sandbox=str(uuid4()); self.listeners=[]
        self.failures={}; self.calls={}; self.services=[]; teams=[]
        for s in (1,2):
            service={'id':f'service{s:02d}','name':f'Service {s}','vulnerability_count':5,'check':'health','targets':{}}
            for n in range(1,5):
                team=f'team{n:02d}'; key=(service['id'],team)
                identity=self.sandbox+f'-attacker{n}'
                def app(env,start,key=key,identity=identity):
                    self.calls[key]=self.calls.get(key,0)+1
                    fail=self.failures.get(key)
                    raw=json.dumps({'status':'ok','sandbox':'wrong' if fail=='identity' else identity}).encode()
                    start('503 Service Unavailable' if fail==503 else '200 OK',
                          [('Content-Type','application/json'),('Content-Length',str(len(raw)))])
                    return [raw]
                server=self.listen(app); url=f'http://127.0.0.1:{server.server_port}'
                service['targets'][team]={'url':url+'/health','expected_sandbox':identity}
                if s==1:teams.append({'team':team,'url':url,'expected_sandbox':identity})
            self.services.append(service)
        self.cfg=initialize(self.root/'event','sla-test',self.sandbox,teams,services=self.services)
        self.store=Store(self.root/'event/competition.sqlite',self.cfg,clock=lambda:self.now)
        self.server=self.listen(create_app(self.store)); self.base=f'http://127.0.0.1:{self.server.server_port}'
        self.worker={'backend_url':self.base,'checker_token':self.cfg['checker_token']}

    def listen(self,app):
        server=make_server('127.0.0.1',0,app,server_class=ThreadingWSGIServer,handler_class=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.listeners.append((server,thread));return server

    def tearDown(self):
        for server,thread in reversed(self.listeners):
            server.shutdown();server.server_close();thread.join(2)
        self.temp.cleanup()

    def api(self,path,data=None,token=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        req=Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        with build_opener(ProxyHandler({})).open(req,timeout=5) as r:return json.load(r)

    def check(self):
        with redirect_stdout(io.StringIO()):return run_once(self.worker,1)

    def test_exact_30_ticks_switch_service_down_zero_then_recovery(self):
        state=self.store.start();self.assertEqual(state['total_seconds'],3600)
        self.assertEqual(state['total_ticks'],30);self.assertEqual(state['ticks_per_round'],15)
        for tick in range(1,31):
            self.now=1000+(tick-1)*120
            self.failures[('service01','team02')]=503 if tick==3 else None
            result=self.check()
            self.assertEqual(result['tick'],tick)
            self.assertEqual(result['round'],1 if tick<=15 else 2)
            self.assertEqual(result['tick_in_round'],(tick-1)%15+1)
            self.assertEqual(result['service']['id'],'service01' if tick<=15 else 'service02')
            self.assertEqual(result['service']['vulnerability_count'],5)
            if tick==3:
                down=next(r for r in result['results'] if r['team']=='team02')
                self.assertEqual(down['status'],'DOWN');self.assertEqual(down['sla_points'],0)
            else:self.assertTrue(all(r['status']=='UP' and r['sla_points']==1 for r in result['results']))
            before=dict(self.calls)
            self.assertFalse(self.check()['jobs'])
            self.assertEqual(self.calls,before)
            self.api('/api/checker/result',result['results'][0],self.cfg['checker_token'])
        self.now=4600
        board=self.api('/api/scoreboard')
        self.assertEqual(board['phase'],'finished');self.assertEqual(board['round'],2);self.assertEqual(board['tick'],30)
        self.assertEqual({t['team']:t['sla_points'] for t in board['teams']},
                         {'team01':30,'team02':29,'team03':30,'team04':30})
        self.assertTrue(all(t['checks']==30 for t in board['teams']))
        history=self.api('/api/checks')['checks'];self.assertEqual(len(history),120)
        self.assertEqual({r['service_id'] for r in history if r['tick']<=15},{'service01'})
        self.assertEqual({r['service_id'] for r in history if r['tick']>=16},{'service02'})
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM ticks').fetchone()[0],30)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM competition_rounds').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM flags').fetchone()[0],0)

    def test_missing_tick_late_result_wrong_service_and_finish(self):
        self.store.start();self.now=1120
        board=self.api('/api/scoreboard')
        self.assertTrue(all(t['sla_points']==0 and t['checks']==1 for t in board['teams']))
        result={'tick':1,'team':'team01','service_id':'service01','status':'UP','elapsed_ms':1,'detail':'ok'}
        with self.assertRaises(HTTPError) as failure:self.api('/api/checker/result',result,self.cfg['checker_token'])
        self.assertEqual(failure.exception.code,409)
        wrong={**result,'tick':2,'service_id':'service02'}
        with self.assertRaises(HTTPError) as failure:self.api('/api/checker/result',wrong,self.cfg['checker_token'])
        self.assertEqual(failure.exception.code,409)
        self.api('/api/checker/result',{**result,'tick':2},self.cfg['checker_token'])
        self.now=1180;self.store.finish();self.now+=7200
        board=self.store.public()
        self.assertEqual(board['phase'],'finished')
        self.assertTrue(all(t['checks']==2 for t in board['teams']))
        self.assertEqual(next(t for t in board['teams'] if t['team']=='team01')['sla_points'],1)
        self.assertEqual(len(self.store.history()['checks']),8)
        restored=Store(self.store.path,self.cfg,clock=lambda:self.now)
        self.assertEqual(restored.public()['teams'],board['teams'])

    def test_preflight_only_round_one_and_round_two_independent(self):
        for n in range(1,5):self.failures[('service02',f'team{n:02d}')]=503
        worker=json.loads((self.root/'event/worker.json').read_text())
        with redirect_stdout(io.StringIO()):self.assertEqual(preflight(worker,1),0)
        self.assertTrue(all(s=='service01' for s,t in self.calls))
        self.store.start();self.assertTrue(all(r['status']=='UP' for r in self.check()['results']))
        self.now=2800
        self.failures[('service02','team04')]='identity'
        result=self.check();self.assertEqual(result['tick'],16);self.assertEqual(result['round'],2)
        self.assertTrue(all(r['sla_points']==0 for r in result['results']))
        self.assertEqual({r['team']:r['status'] for r in result['results']},
                         {'team01':'DOWN','team02':'DOWN','team03':'DOWN','team04':'MUMBLE'})
        invalid=copy.deepcopy(self.cfg);invalid['rules']['tick_seconds']=121
        with self.assertRaises(ValueError):validate_config(invalid)
        invalid=copy.deepcopy(self.cfg);invalid['services'][1]['targets'].pop('team04')
        with self.assertRaises(ValueError):validate_config(invalid)
        with self.assertRaises(HTTPError) as failure:self.api('/api/submit',{'flag':'FLAG{unused}'},self.cfg['teams'][0]['token'])
        self.assertEqual(failure.exception.code,409)


if __name__=='__main__':unittest.main()
