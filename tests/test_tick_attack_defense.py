"""End-to-end local functional checks for shop flag planting, captures and monitoring."""
from contextlib import redirect_stdout
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
from app.service import create_app as service_app
from gameserver.server import create_app as backend_app
from gameserver.setup import initialize
from gameserver.store import Store
from gameserver.worker import run_once


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass


class TickAttackDefenseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.now=1000.0;self.listeners=[]
        self.sandbox=str(uuid4());self.teams=['team01','team02'];self.services=[];self.targets=[]
        for round_number in (1,2):
            service={'id':f'shop0{round_number}','name':f'NOVA MART round {round_number}',
                'vulnerability_count':5,'check':'shop','implementation':'webshop','targets':{}}
            for number,team in enumerate(self.teams,1):
                identity=f'{self.sandbox}-attacker{number}'
                app=service_app(database=str(self.root/f'{service["id"]}-{team}.sqlite'),password='local-customer-password-123',
                    sandbox_id=identity,service_id=service['id'],implementation='webshop',
                    vulnerabilities={'sqli':True,'captcha_bypass':True,'xss':True,'csrf':True,'brute_force':True})
                port=self.listen(app)
                service['targets'][team]={'url':f'http://127.0.0.1:{port}/health','expected_sandbox':identity,'expected_service':service['id']}
                if round_number==1:self.targets.append({'team':team,'url':f'http://127.0.0.1:{port}','expected_sandbox':identity})
            self.services.append(service)
        rules={'mode':'sla','scoring':'attack_defense','round_seconds':20,'max_rounds':2,'tick_seconds':10,
            'sla_points':1,'attack_points':100,'defense_penalty':100,'flag_ttl_ticks':2}
        cfg=initialize(self.root/'runtime','shop-ad-test',self.sandbox,self.targets,services=self.services,rules=rules)
        self.store=Store(self.root/'runtime/competition.sqlite',cfg,clock=lambda:self.now)
        self.backend_port=self.listen(backend_app(self.store));self.base=f'http://127.0.0.1:{self.backend_port}'
        self.worker={'backend_url':self.base,'checker_token':cfg['checker_token']};self.cfg=cfg
    def listen(self,app):
        server=make_server('127.0.0.1',0,app,server_class=ThreadingWSGIServer,handler_class=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.listeners.append((server,thread));return server.server_port
    def tearDown(self):
        for server,thread in reversed(self.listeners):server.shutdown();server.server_close();thread.join(2)
        self.temp.cleanup()
    def api(self,path,payload=None,token=None):
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        req=Request(self.base+path,data=json.dumps(payload).encode() if payload is not None else None,headers=headers)
        with build_opener(ProxyHandler({})).open(req,timeout=8) as r:return json.load(r)
    def tick(self):
        with redirect_stdout(io.StringIO()):return run_once(self.worker,timeout=5)

    def test_checker_plants_private_orders_and_capture_changes_live_score(self):
        self.store.start();plan=self.tick();self.assertEqual(plan['tick'],1)
        self.assertTrue(all(r['status']=='UP' and r['object_id'] for r in plan['results']),plan['results'])
        board=self.api('/api/scoreboard');self.assertTrue(all(t['sla_points']==1 for t in board['teams']))
        flags=self.api('/api/attack-data')['flags'];self.assertEqual(len(flags),2)
        self.assertTrue(all({'value','password'}.isdisjoint(flag) for flag in flags))
        victim_job=next(j for j in plan['jobs'] if j['team']=='team01')
        attack=self.api('/api/submit',{'flag':victim_job['current']['value']},self.cfg['teams'][1]['token'])
        self.assertEqual(attack,{'verdict':'ACCEPTED','points':100})
        duplicate=self.api('/api/submit',{'flag':victim_job['current']['value']},self.cfg['teams'][1]['token'])
        self.assertEqual(duplicate['verdict'],'DUPLICATE')
        board=self.api('/api/scoreboard');scores={t['team']:t for t in board['teams']}
        self.assertEqual(scores['team02']['score'],101);self.assertEqual(scores['team02']['captures'],1)
        self.assertEqual(scores['team01']['score'],-99);self.assertEqual(scores['team01']['lost_flags'],1)
        self.assertEqual(board['captures'][0]['object_id'],next(r['object_id'] for r in plan['results'] if r['team']=='team01'))

    def test_monitor_token_and_expiration_are_isolated(self):
        self.store.start();plan=self.tick();flag=next(j['current']['value'] for j in plan['jobs'] if j['team']=='team01')
        with self.assertRaises(HTTPError) as failure:self.api('/api/monitor')
        self.assertEqual(failure.exception.code,401)
        monitor=self.api('/api/monitor',token=self.cfg['monitor_token'])
        self.assertEqual(monitor['total_rows']['tick_flags'],2)
        self.assertIn('workers',monitor)
        self.now=1020.0
        next_plan=self.api('/api/checker/plan',token=self.cfg['checker_token'])
        self.assertEqual(next_plan['tick'],3);self.assertEqual(next_plan['service']['id'],'shop02')
        active=self.api('/api/attack-data')['flags'];self.assertFalse(any(item['tick']==1 for item in active))
        self.assertNotIn(flag,json.dumps(active))


if __name__=='__main__':unittest.main()
