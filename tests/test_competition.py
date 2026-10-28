"""End-to-end checks against four real HTTP services and the SQLite API."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout,closing
from http.cookiejar import CookieJar
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request,build_opener,ProxyHandler
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import create_app,ThreadingWSGIServer
from checker.attack_defense import client,request
from gameserver.server import create_app as backend_app
from gameserver.setup import initialize,AD_RULES as DEFAULT_RULES
from gameserver.store import Store
from gameserver.worker import run_once


class Quiet(WSGIRequestHandler):
    def log_message(self,*args):
        pass


class CompetitionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.listeners=[]; self.service_apps=[]; self.sandbox=str(uuid4()); self.now=1000.
        self.targets=[]
        for n in range(1,5):
            app=create_app(self.root/f'team{n}.sqlite','alice-example-password',self.sandbox+f'-attacker{n}')
            self.service_apps.append(app)
            server=self.listen(app)
            self.targets.append({'team':f'team{n:02d}','url':f'http://127.0.0.1:{server.server_port}',
                                 'expected_sandbox':self.sandbox+f'-attacker{n}'})
        self.cfg=initialize(self.root/'event','test-event',self.sandbox,self.targets,rules=DEFAULT_RULES)
        self.store=Store(self.root/'event/competition.sqlite',self.cfg,clock=lambda:self.now)
        self.backend=self.listen(backend_app(self.store)); self.base=f'http://127.0.0.1:{self.backend.server_port}'
        self.worker={'backend_url':self.base,'checker_token':self.cfg['checker_token']}

    def listen(self,app,port=0):
        server=make_server('127.0.0.1',port,app,server_class=ThreadingWSGIServer,handler_class=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.listeners.append((server,thread))
        return server

    def tearDown(self):
        for server,thread in reversed(self.listeners):
            server.shutdown(); server.server_close(); thread.join(2)
        self.temp.cleanup()

    def api(self,path,data=None,token=None):
        headers={'Content-Type':'application/json'}
        if token: headers['Authorization']='Bearer '+token
        req=Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        with build_opener(ProxyHandler({})).open(req,timeout=5) as r:
            return json.load(r)

    def start(self):
        return self.api('/api/admin/start',{},self.cfg['admin_token'])

    def run_round(self):
        with redirect_stdout(io.StringIO()):
            return run_once(self.worker,.7)

    def stolen_flag(self,team=1):
        flag_id=next(f['ticket_id'] for f in self.api('/api/attack-data')['flags'] if f['team']==f'team{team:02d}')
        opener=client(); base=self.targets[team-1]['url']
        user='attacker_'+uuid4().hex[:12]
        request(opener,base+'/register',3,{'username':user,'password':'attacker-example-password'})
        request(opener,base+'/login',3,{'username':user,'password':'attacker-example-password'})
        return request(opener,base+f'/api/tickets/{flag_id}',3)['private_note']

    def test_put_get_capture_scores_replay_and_restart(self):
        self.start(); result=self.run_round()
        self.assertTrue(all(r['status']=='UP' for r in result['results']))
        board=self.api('/api/scoreboard')
        self.assertEqual([t['sla_points'] for t in board['teams']],[10]*4)
        value=self.stolen_flag()
        token=self.cfg['teams'][1]['token']
        with ThreadPoolExecutor(max_workers=6) as pool:
            submissions=list(pool.map(lambda _:self.api('/api/submit',{'flag':value},token),range(6)))
        self.assertEqual(sum(s['verdict']=='ACCEPTED' for s in submissions),1)
        self.assertEqual(sum(s['verdict']=='DUPLICATE' for s in submissions),5)
        self.assertEqual(self.api('/api/submit',{'flag':value},self.cfg['teams'][0]['token'])['verdict'],'SELF')
        self.assertEqual(self.api('/api/submit',{'flag':'FLAG{invalid}'},token)['verdict'],'INVALID')
        self.api('/api/checker/result',result['results'][0],self.cfg['checker_token'])
        scores={t['team']:t['score'] for t in self.api('/api/scoreboard')['teams']}
        self.assertEqual(scores,{'team01':-90,'team02':110,'team03':10,'team04':10})
        restarted=Store(self.store.path,self.cfg,clock=lambda:self.now)
        self.assertEqual(scores,{t['team']:t['score'] for t in restarted.public()['teams']})
        public=json.dumps([self.api('/api/scoreboard'),self.api('/api/attack-data'),self.api('/api/checks')])
        self.assertNotIn(value,public)
        self.assertNotIn(self.cfg['checker_token'],public)
        backup=self.root/'backup.sqlite'; self.store.backup(backup)
        with closing(sqlite3.connect(backup)) as db: self.assertEqual(db.execute('SELECT COUNT(*) FROM captures').fetchone()[0],1)

    def test_patch_blocks_idor_but_owner_checker_stays_up(self):
        self.start(); self.run_round()
        self.listeners[0][0].set_app(create_app(self.root/'team1.sqlite','alice-example-password',self.sandbox+'-attacker1',True))
        with self.assertRaises(HTTPError) as failure: self.stolen_flag()
        self.assertEqual(failure.exception.code,403)
        self.now+=60
        result=self.run_round()
        self.assertTrue(all(r['status']=='UP' for r in result['results']))
        self.assertTrue(all(t['sla_points']==20 for t in self.store.public()['teams']))

    def test_old_flag_integrity_deadlines_and_missing_round(self):
        self.start(); first=self.run_round(); value=self.stolen_flag()
        with closing(sqlite3.connect(self.root/'team1.sqlite')) as db, db:
            db.execute('UPDATE tickets SET private_note=? WHERE id=?',('deleted flag',first['results'][0]['ticket_id']))
        self.now+=60
        self.assertTrue(all(t['current_status']=='PENDING' for t in self.store.public()['teams']))
        second=self.run_round()
        self.assertEqual(second['results'][0]['status'],'MUMBLE')
        self.assertTrue(all(r['status']=='UP' for r in second['results'][1:]))
        # Round 3 was not judged: no invented SLA points and no retroactive result accepted.
        self.now+=120
        self.assertEqual(self.api('/api/submit',{'flag':value},self.cfg['teams'][1]['token'])['verdict'],'EXPIRED')
        self.assertEqual({t['team']:t['sla_points'] for t in self.store.public()['teams']},
                         {'team01':10,'team02':20,'team03':20,'team04':20})
        fabricated={**second['results'][0],'round':3}
        with self.assertRaises(HTTPError) as failure: self.api('/api/checker/result',fabricated,self.cfg['checker_token'])
        self.assertEqual(failure.exception.code,409)

    def test_authentication_wrong_identity_and_finished_event(self):
        for token in (None,self.cfg['teams'][0]['token'],self.cfg['admin_token']):
            with self.assertRaises(HTTPError): self.api('/api/checker/plan',token=token)
        with self.assertRaises(HTTPError): self.api('/api/admin/start',{},self.cfg['checker_token'])
        self.start()
        self.listeners[0][0].set_app(create_app(self.root/'wrong.sqlite','alice-example-password',str(uuid4())+'-attacker1'))
        result=self.run_round(); self.assertEqual(result['results'][0]['status'],'MUMBLE')
        value=self.stolen_flag(team=2)
        self.api('/api/admin/finish',{},self.cfg['admin_token'])
        self.assertEqual(self.api('/api/submit',{'flag':value},self.cfg['teams'][0]['token'])['verdict'],'NOT_RUNNING')
        self.assertFalse(self.api('/api/checker/plan',token=self.cfg['checker_token'])['jobs'])
        self.assertEqual(self.api('/api/admin/start',{},self.cfg['admin_token'])['phase'],'finished')

    def test_service_down_then_recovers_next_round(self):
        self.start()
        server,thread=self.listeners[0]; port=server.server_port
        server.shutdown(); server.server_close(); thread.join(2)
        result=self.run_round()
        self.assertEqual(result['results'][0]['status'],'DOWN')
        self.assertTrue(all(r['status']=='UP' for r in result['results'][1:]))
        self.listen(self.service_apps[0],port)
        self.now+=60
        result=self.run_round()
        self.assertTrue(all(r['status']=='UP' for r in result['results']))


if __name__=='__main__': unittest.main()
