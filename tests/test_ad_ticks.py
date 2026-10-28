"""Attack/defense on the tick schedule: flag PUT/GET, signed validation, scoring, links."""
from contextlib import redirect_stdout,closing
import io
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request,build_opener,ProxyHandler
from uuid import uuid4
from wsgiref.simple_server import make_server,WSGIRequestHandler

from app.portal import create_app,ThreadingWSGIServer
from gameserver.ad import AD_TICK_RULES,FlagSigner
from gameserver.server import create_app as backend_app
from gameserver.setup import initialize
from gameserver.store import Store
from gameserver.worker import run_once


class Quiet(WSGIRequestHandler):
    def log_message(self,*args): pass


class AdTickTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.now=1000.; self.sandbox=str(uuid4()); self.listeners=[]; teams=[]; services=[]
        self.dbs={}
        for s in (1,2):
            service={'id':f'service{s:02d}','name':f'ServiceDesk {s}','vulnerability_count':5,'check':'flag','targets':{}}
            for n in range(1,5):
                team=f'team{n:02d}'; identity=self.sandbox+f'-attacker{n}'
                path=self.root/f's{s}-team{n}.sqlite'; self.dbs[(s,team)]=path
                server=self.listen(create_app(path,'alice-example-password',identity))
                url=f'http://127.0.0.1:{server.server_port}'
                service['targets'][team]={'url':url+'/health','expected_sandbox':identity}
                if s==1: teams.append({'team':team,'url':url,'expected_sandbox':identity})
            services.append(service)
        self.closed=socket.socket(); self.closed.bind(('127.0.0.1',0)); closed_port=self.closed.getsockname()[1]
        links=[{'name':'team01 link','host':'127.0.0.1','port':int(teams[0]['url'].rsplit(':',1)[1]),
                'gateway':'127.0.0.1:1','vm':'10.80.0.11:8080'},
               {'name':'dead link','host':'127.0.0.1','port':closed_port,'gateway':'127.0.0.1:2','vm':'10.80.0.12:8080'}]
        rules={**AD_TICK_RULES,'flag_ttl_ticks':3}
        self.cfg=initialize(self.root/'event','ad-test',self.sandbox,teams,rules=rules,services=services,links=links)
        self.store=Store(self.root/'event/competition.sqlite',self.cfg,clock=lambda:self.now)
        self.base=f'http://127.0.0.1:{self.listen(backend_app(self.store)).server_port}'
        self.worker={**json.loads((self.root/'event/worker.json').read_text()),'backend_url':self.base}

    def listen(self,app):
        server=make_server('127.0.0.1',0,app,server_class=ThreadingWSGIServer,handler_class=Quiet)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.listeners.append((server,thread)); return server

    def tearDown(self):
        for server,thread in reversed(self.listeners):
            server.shutdown(); server.server_close(); thread.join(2)
        self.closed.close(); self.temp.cleanup()

    def api(self,path,data=None,token=None):
        headers={'Content-Type':'application/json'}
        if token: headers['Authorization']='Bearer '+token
        req=Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
        with build_opener(ProxyHandler({})).open(req,timeout=5) as r: return json.load(r)

    def tick(self):
        with redirect_stdout(io.StringIO()): return run_once(self.worker,2)

    def planted(self,team,tick):
        # Stands in for a successful attack: the organizer DB knows which value was planted.
        with closing(sqlite3.connect(self.store.path)) as db:
            return db.execute('SELECT value FROM tick_flags WHERE team=? AND tick=?',(team,tick)).fetchone()[0]

    def token(self,team): return next(t['token'] for t in self.cfg['teams'] if t['id']==team)

    def submit(self,team,flag): return self.api('/api/submit',{'flag':flag},self.token(team))['verdict']

    def test_put_get_submit_score_and_privacy(self):
        self.assertEqual(self.submit('team02','FLAG{'+'A'*32+'}'),'NOT_RUNNING')
        self.api('/api/admin/start',{},self.cfg['admin_token'])
        first=self.tick()
        self.assertEqual([r['status'] for r in first['results']],['UP']*4)
        self.assertTrue(all(r['ticket_id'] for r in first['results']))
        flag=self.planted('team01',1)
        self.assertEqual(self.submit('team02',flag),'ACCEPTED')
        self.assertEqual(self.submit('team02',' '+flag+'\n'),'DUPLICATE')
        self.assertEqual(self.submit('team01',flag),'SELF')
        forged='FLAG{'+FlagSigner('x'*32).new()[5:-1]+'}'
        self.assertEqual(self.submit('team03',forged),'INVALID')
        self.assertEqual(self.submit('team03','flag{nope}'),'FORMAT')
        batch=self.api('/api/submit',{'flags':[flag,'junk']},self.token('team03'))['results']
        self.assertEqual([r['verdict'] for r in batch],['ACCEPTED','FORMAT'])
        board={t['team']:t for t in self.api('/api/scoreboard')['teams']}
        self.assertEqual(board['team01']['score'],10-2*25)
        self.assertEqual(board['team02']['score'],10+50)
        self.assertEqual(board['team02']['rank'],1)
        self.assertEqual(board['team01']['flags_lost'],2)
        feed=self.api('/api/feed')
        self.assertEqual(feed['captures'],2)
        self.assertEqual([e['first_blood'] for e in reversed(feed['events'])],[True,False])
        status=self.api('/api/team/status',token=self.token('team03'))
        self.assertEqual(status['verdicts'],{'ACCEPTED':1,'FORMAT':2,'INVALID':1})
        with self.assertRaises(HTTPError) as denied: self.api('/api/team/status')
        self.assertEqual(denied.exception.code,401)
        public=json.dumps([self.api(p) for p in ('/api/scoreboard','/api/checks','/api/feed','/api/attack-data','/api/network')])
        self.assertNotIn(flag,public); self.assertNotIn(self.cfg['flag_secret'],public)
        self.assertEqual(len(self.api('/api/attack-data')['flags']),4)
        restarted=Store(self.store.path,self.cfg,clock=lambda:self.now)
        self.assertEqual({t['team']:t['score'] for t in restarted.public()['teams']},{k:v['score'] for k,v in board.items()})

    def test_expiry_previous_flag_integrity_and_round_switch(self):
        self.api('/api/admin/start',{},self.cfg['admin_token'])
        first=self.tick(); flag=self.planted('team01',1)
        # A team that "patches" by wiping data loses SLA on the next GET.
        with closing(sqlite3.connect(self.dbs[(1,'team02')])) as db, db:
            db.execute('UPDATE tickets SET private_note=? WHERE id=?',('wiped',first['results'][1]['ticket_id']))
        self.now+=120; second=self.tick()
        self.assertEqual({r['team']:r['status'] for r in second['results']},
                         {'team01':'UP','team02':'CORRUPT','team03':'UP','team04':'UP'})
        self.assertIsNotNone(second['results'][1]['ticket_id'])
        # The checker trace pins the failure on the GET of the tick-1 flag; nothing secret is published.
        trace=[a for a in self.api('/api/trace')['actions'] if a['tick']==2 and a['team']=='team02']
        self.assertEqual([(a['action'],a['status'],a['flag_tick']) for a in reversed(trace)],
                         [('CHECK','UP',None),('PUT','UP',2),('GET','UP',2),('GET','CORRUPT',1)])
        self.assertNotIn('flag_id',trace[0])
        flags={(f['team'],f['tick']):f for f in self.api('/api/flags')['flags']}
        self.assertEqual(flags[('team02',1)]['last_check'],'CORRUPT')
        self.assertEqual(flags[('team01',1)]['last_check'],'UP')
        self.assertTrue(flags[('team01',1)]['active'])
        self.assertEqual(self.api('/api/scoreboard')['teams'][-1]['statuses'].get('CORRUPT',0)+
                         sum(t['statuses'].get('CORRUPT',0) for t in self.api('/api/scoreboard')['teams'][:-1]),1)
        self.now+=240
        self.assertEqual(self.submit('team03',flag),'EXPIRED')
        self.now=1000+15*120; switched=self.tick()
        self.assertEqual(switched['tick'],16); self.assertEqual({r['service_id'] for r in switched['results']},{'service02'})
        self.assertEqual([r['status'] for r in switched['results']],['UP']*4)
        missed={c['tick'] for c in self.api('/api/checks')['checks'] if c['status']=='ERROR'}
        self.assertEqual(missed,set(range(3,16)))
        fake={**switched['results'][0],'flag_id':'0'*32}
        with self.assertRaises(HTTPError) as failure:
            self.api('/api/checker/result',{**fake,'tick':17},self.cfg['checker_token'])
        self.assertEqual(failure.exception.code,409)

    def test_tcp_submission_shares_verdicts_and_rate_limit(self):
        from gameserver.server import RateLimiter
        from gameserver.submit_tcp import serve_tcp
        tcp=serve_tcp(self.store,RateLimiter(lambda:self.now,per_minute=3),'127.0.0.1',0)
        self.addCleanup(tcp.server_close); self.addCleanup(tcp.shutdown)
        self.api('/api/admin/start',{},self.cfg['admin_token']); self.tick()
        flag=self.planted('team01',1)
        with socket.create_connection(tcp.server_address,timeout=5) as conn:
            stream=conn.makefile('rw',newline='\n')
            self.assertIn('team token',stream.readline())
            stream.write(self.token('team03')+'\n'); stream.flush()
            self.assertEqual(stream.readline().strip(),'OK team03')
            for line in (flag,flag,'nope','x'):
                stream.write(line+'\n'); stream.flush()
            answers=[stream.readline().strip() for _ in range(4)]
        self.assertEqual(answers[0],flag+' ACCEPTED +50')
        self.assertEqual(answers[1],flag+' DUPLICATE +0')
        self.assertEqual(answers[2],'nope FORMAT +0')
        self.assertTrue(answers[3].startswith('x ERR Limit'))
        with socket.create_connection(tcp.server_address,timeout=5) as conn:
            stream=conn.makefile('rw',newline='\n'); stream.readline()
            stream.write('wrong-token\n'); stream.flush()
            self.assertEqual(stream.readline().strip(),'ERR invalid team token')
        board={t['team']:t for t in self.api('/api/scoreboard')['teams']}
        self.assertEqual(board['team03']['captures'],1)

    def test_link_probe_verifies_vm_identity(self):
        from gameserver.links import probe
        team1=self.cfg['services'][0]['targets']['team01']['url']
        right={'name':'a','health':team1,'expected_identity':self.sandbox+'-attacker1'}
        wrong={**right,'expected_identity':self.sandbox+'-attacker2'}
        self.assertEqual(probe(right)['status'],'UP')
        self.assertEqual(probe(right)['identity'],self.sandbox+'-attacker1')
        self.assertEqual(probe(wrong)['status'],'MISMATCH')
        dead={'name':'d','health':f'http://127.0.0.1:{self.closed.getsockname()[1]}/health'}
        self.assertEqual(probe(dead,1)['status'],'DOWN')

    def test_links_reported_and_validated(self):
        self.api('/api/admin/start',{},self.cfg['admin_token']); self.tick()
        links={l['name']:l for l in self.api('/api/network')['links']}
        self.assertEqual(links['team01 link']['status'],'UP'); self.assertEqual(links['dead link']['status'],'DOWN')
        self.assertEqual(links['team01 link']['recent'],['UP'])
        with self.assertRaises(HTTPError) as bad:
            self.api('/api/checker/links',{'links':[{'name':'other','status':'UP','latency_ms':1}]},self.cfg['checker_token'])
        self.assertEqual(bad.exception.code,400)
        with self.assertRaises(HTTPError) as anon:
            self.api('/api/checker/links',{'links':[]},self.token('team01'))
        self.assertEqual(anon.exception.code,403)


if __name__=='__main__': unittest.main()
