"""Two-level schedule: competition rounds select services; ticks award SLA."""
import hashlib
import math
import re
import secrets
from urllib.parse import urlsplit
from .errors import Rejected


def validate_sla(cfg):
    rules = cfg['rules']
    for key in ('round_seconds','max_rounds','tick_seconds','sla_points'):
        value = rules[key]
        if type(value) is not int or value < (0 if key == 'sla_points' else 1):
            raise ValueError('Invalid SLA rule: '+key)
    if rules['round_seconds'] % rules['tick_seconds']:
        raise ValueError('Each round must contain a whole number of ticks')
    if rules.get('scoring','sla') not in ('sla','attack_defense'):
        raise ValueError('scoring must be sla or attack_defense')
    if rules.get('scoring')=='attack_defense':
        for key in ('attack_points','defense_penalty','flag_ttl_ticks'):
            value=rules.get(key)
            if type(value) is not int or value<1:
                raise ValueError('Invalid attack/defense rule: '+key)
    total = rules['round_seconds']//rules['tick_seconds']*rules['max_rounds']
    if total > 100000:
        raise ValueError('Too many ticks')
    services = cfg.get('services',[])
    if len(services) != rules['max_rounds']:
        raise ValueError('Configure exactly one service per competition round')
    ids=set()
    teams={t['id'] for t in cfg['teams']}
    for service in services:
        if not isinstance(service.get('id'),str) or not service['id'] or service['id'] in ids:
            raise ValueError('Service IDs must be nonempty and unique')
        ids.add(service['id'])
        if not isinstance(service.get('name'),str) or not service['name']:
            raise ValueError('Service name required')
        if type(service.get('vulnerability_count')) is not int or service['vulnerability_count'] < 1:
            raise ValueError('Set vulnerability_count for each service')
        if service.get('check','health') not in ('health','functional','workflow','shop'):
            raise ValueError('Use health, functional or workflow service checks')
        if set(service['targets']) != teams:
            raise ValueError('Each service must have exactly one target for each team')
        for target in service['targets'].values():
            url=urlsplit(target['url'])
            if url.scheme not in ('http','https') or not url.hostname or '<' in target['url'] or url.username or url.password or url.query or url.fragment or url.path!='/health':
                raise ValueError('Fill every service target with a real /health HTTP(S) URL')
            if not target['expected_sandbox'].startswith(cfg['sandbox_id']+'-'):
                raise ValueError('Service target belongs to another sandbox')
            if target.get('expected_service') and target['expected_service']!=service['id']:
                raise ValueError('Wrong expected service identity')
            if service.get('check','health')=='functional' and not target.get('password'):
                raise ValueError('Functional mode needs the ServiceDesk password per target')


class SlaMixin:
    def sla_state(self, db):
        event=db.execute('SELECT started_at,ended_at FROM event').fetchone()
        now=self.clock()
        r=self.rules
        per_round=r['round_seconds']//r['tick_seconds']
        total=per_round*r['max_rounds']
        base={'mode':'sla','demo':bool(self.cfg.get('demo')), 'server_time':now,
              'ticks_per_round':per_round,'total_ticks':total,
              'total_seconds':r['round_seconds']*r['max_rounds']}
        if event['started_at'] is None:
            return {**base,'phase':'ready','round':None,'tick':None,'tick_in_round':None,
                    'service':None,'tick_ends_at':None,'round_ends_at':None,'event_ends_at':None}
        start=event['started_at']
        stop=start+base['total_seconds']
        clock=min(now,event['ended_at']) if event['ended_at'] is not None else now
        active=event['ended_at'] is None and start<=clock<stop
        elapsed=max(0,min(clock-start,base['total_seconds']))
        tick=min(math.floor(elapsed/r['tick_seconds'])+1,total)
        round_number=(tick-1)//per_round+1
        service=self.cfg['services'][round_number-1]
        return {**base,'phase':'running' if active else 'finished','round':round_number,
                'tick':tick,'tick_in_round':(tick-1)%per_round+1,
                'service':{k:service[k] for k in ('id','name','vulnerability_count')},
                'tick_ends_at':start+tick*r['tick_seconds'] if active else None,
                'round_ends_at':start+round_number*r['round_seconds'] if active else None,
                'event_ends_at':stop}

    def sla_start(self, db, now):
        per_round=self.rules['round_seconds']//self.rules['tick_seconds']
        for i,service in enumerate(self.cfg['services'],1):
            begin=now+(i-1)*self.rules['round_seconds']
            db.execute('INSERT INTO competition_rounds VALUES(?,?,?,?)',
                       (i,service['id'],begin,begin+self.rules['round_seconds']))
            for j in range(per_round):
                n=(i-1)*per_round+j+1
                begin_tick=begin+j*self.rules['tick_seconds']
                db.execute('INSERT INTO ticks VALUES(?,?,?,?,?)',
                           (n,i,service['id'],begin_tick,begin_tick+self.rules['tick_seconds']))

    def finalize_ticks(self, db):
        event=db.execute('SELECT started_at,ended_at FROM event').fetchone()
        if event['started_at'] is None:
            return
        now=self.clock()
        # Missing measurements are recorded separately from a real service DOWN.
        db.execute('''INSERT OR IGNORE INTO tick_checks
            (tick,team,status,detail,elapsed_ms,checked_at,sla_points,source)
            SELECT t.number,teams.id,'ERROR','No checker result before tick deadline',0,
                   CASE WHEN ? IS NOT NULL THEN MIN(t.ends_at,?) ELSE t.ends_at END,0,'scheduler'
            FROM ticks t CROSS JOIN teams
            WHERE (? IS NULL AND t.ends_at<=?) OR (? IS NOT NULL AND t.starts_at<?)''',
                   (event['ended_at'],event['ended_at'],event['ended_at'],now,event['ended_at'],event['ended_at']))

    def sla_plan(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            state=self.sla_state(db)
            jobs=[]
            if state['phase']=='running':
                service=self.cfg['services'][state['round']-1]
                for team,target in service['targets'].items():
                    if db.execute('SELECT 1 FROM tick_checks WHERE tick=? AND team=?',(state['tick'],team)).fetchone():
                        continue
                    job={'team':team,'service_id':service['id'],
                         'check_level':service.get('check','health'),**target}
                    if self.rules.get('scoring')=='attack_defense':
                        flag=db.execute('SELECT * FROM tick_flags WHERE tick=? AND team=?',(state['tick'],team)).fetchone()
                        if flag is None:
                            ident=secrets.token_hex(16)
                            value='FLAG{'+secrets.token_urlsafe(32)+'}'
                            username='check_'+ident[:24]
                            password=secrets.token_urlsafe(24)
                            ttl=self.rules['flag_ttl_ticks']
                            expires=min(state['tick']+ttl,(state['round']*state['ticks_per_round'])+1)
                            db.execute('INSERT INTO tick_flags(id,team,tick,service_id,expires_tick,value,value_hash,username,password) VALUES(?,?,?,?,?,?,?,?,?)',
                                (ident,team,state['tick'],service['id'],expires,value,hashlib.sha256(value.encode()).hexdigest(),username,password))
                            flag=db.execute('SELECT * FROM tick_flags WHERE id=?',(ident,)).fetchone()
                        previous=db.execute('''SELECT id,tick,expires_tick,username,password,object_id FROM tick_flags
                            WHERE team=? AND service_id=? AND tick<? AND expires_tick>? AND object_id IS NOT NULL ORDER BY tick''',
                            (team,service['id'],state['tick'],state['tick'])).fetchall()
                        job['current']={'id':flag['id'],'username':flag['username'],'password':flag['password'],
                                        'value':self._flag_value_for_checker(db,flag['id'])}
                        job['previous']=[{**dict(f),'value_hash':None,'value':self._flag_value_for_checker(db,f['id'])} for f in previous]
                    jobs.append(job)
            return {**state,'event_id':self.cfg['event_id'],'jobs':jobs}

    @staticmethod
    def _flag_value_for_checker(db, ident):
        # Database ACLs protect organizer flag assignments; public APIs expose hashes and
        # order metadata only, never this value or its checker account password.
        row=db.execute('SELECT value FROM tick_flags WHERE id=?',(ident,)).fetchone()
        return row['value'] if row else ''

    def sla_result(self, data):
        tick,team,status=data.get('tick'),data.get('team'),data.get('status')
        elapsed=data.get('elapsed_ms')
        detail=data.get('detail','')
        if type(tick) is not int or not isinstance(team,str) or team not in self.teams or status not in ('UP','DOWN','MUMBLE','ERROR') or type(elapsed) is not int or not 0<=elapsed<=3600000 or not isinstance(detail,str):
            raise Rejected('Invalid tick result')
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            row=db.execute('SELECT status,sla_points,source FROM tick_checks WHERE tick=? AND team=?',(tick,team)).fetchone()
            if row and row['source']=='worker':
                return {'recorded':True,'duplicate':True,'status':row['status'],'sla_points':row['sla_points']}
            state=self.sla_state(db)
            if state['phase']!='running' or state['tick']!=tick:
                raise Rejected('Tick deadline passed',409)
            if data.get('service_id')!=state['service']['id']:
                raise Rejected('Wrong service for this competition round',409)
            points=self.rules['sla_points'] if status=='UP' else 0
            if self.rules.get('scoring')=='attack_defense':
                assigned=db.execute('SELECT * FROM tick_flags WHERE tick=? AND team=?',(tick,team)).fetchone()
                if assigned is None or data.get('flag_id')!=assigned['id']:
                    raise Rejected('Flag assignment does not match',409)
                object_id=data.get('object_id')
                if status=='UP' and (type(object_id) is not int or object_id<1):
                    raise Rejected('UP requires a verified shop order flag',409)
                if status!='UP' and object_id is not None:
                    raise Rejected('A failed check cannot plant a flag')
                if status=='UP':
                    db.execute('UPDATE tick_flags SET object_id=?,planted_at=? WHERE id=?',(object_id,self.clock(),assigned['id']))
            detail=re.sub(r'FLAG\{[^}]*\}','[redacted]',detail)[:300]
            db.execute('INSERT INTO tick_checks VALUES(?,?,?,?,?,?,?,?)',
                       (tick,team,status,detail,elapsed,self.clock(),points,'worker'))
            return {'recorded':True,'duplicate':False,'status':status,'sla_points':points}

    def sla_public(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            state=self.sla_state(db)
            board=[]
            for team in self.teams:
                stats=db.execute("SELECT COUNT(*) n,COALESCE(SUM(sla_points),0) points,COALESCE(SUM(status='UP'),0) good FROM tick_checks WHERE team=?",(team,)).fetchone()
                latest=db.execute('SELECT c.*,t.competition_round,t.service_id FROM tick_checks c JOIN ticks t ON t.number=c.tick WHERE team=? ORDER BY tick DESC LIMIT 1',(team,)).fetchone()
                current=latest if latest and latest['tick']==state['tick'] else None
                wins=lost=0
                attack=penalty=0
                if self.rules.get('scoring')=='attack_defense':
                    wins=db.execute('SELECT COUNT(*) FROM tick_captures WHERE attacker=?',(team,)).fetchone()[0]
                    lost=db.execute('SELECT COUNT(*) FROM tick_captures c JOIN tick_flags f ON f.id=c.flag_id WHERE f.team=?',(team,)).fetchone()[0]
                    attack=wins*self.rules['attack_points'];penalty=lost*self.rules['defense_penalty']
                board.append({'team':team,'score':stats['points']+attack-penalty,'sla_points':stats['points'],
                              'attack_points':attack,'defense_penalty':penalty,'captures':wins,'lost_flags':lost,
                              'up_checks':stats['good'],'checks':stats['n'],
                              'max_sla_points':state['total_ticks']*self.rules['sla_points'],
                              'latest':dict(latest) if latest else None,
                              'current_sla':current['sla_points'] if current else None,
                              'current_status':current['status'] if current else ('PENDING' if state['phase']=='running' else 'UNCHECKED')})
            board.sort(key=lambda t:(-t['score'],t['team']))
            captures=[]
            if self.rules.get('scoring')=='attack_defense':
                captures=[dict(r) for r in db.execute('''SELECT c.attacker,f.team AS victim,f.tick,f.service_id,f.object_id,c.captured_at
                    FROM tick_captures c JOIN tick_flags f ON f.id=c.flag_id ORDER BY c.captured_at DESC LIMIT 50''')]
            return {**state,'event_id':self.cfg['event_id'],'sandbox_id':self.cfg['sandbox_id'],
                    'rules':self.rules,'teams':board,'captures':captures}

    def sla_attack_data(self):
        if self.rules.get('scoring')!='attack_defense': return {'flags':[]}
        with self.connect(write=True) as db:
            state=self.sla_state(db)
            if state['phase']!='running':return {'flags':[]}
            rows=db.execute('''SELECT id,team,tick,expires_tick,service_id,object_id FROM tick_flags
                WHERE tick<=? AND expires_tick>? AND object_id IS NOT NULL AND service_id=? ORDER BY tick,team''',
                (state['tick'],state['tick'],state['service']['id'])).fetchall()
            return {'tick':state['tick'],'service':state['service']['id'],'flags':[dict(r) for r in rows]}

    def sla_submit(self, attacker, value):
        if self.rules.get('scoring')!='attack_defense':raise Rejected('Flag submission is not enabled',409)
        if not isinstance(value,str) or len(value)>128:raise Rejected('Invalid flag format')
        value_hash=hashlib.sha256(value.encode()).hexdigest()
        with self.connect(write=True) as db:
            state=self.sla_state(db);flag=db.execute('SELECT * FROM tick_flags WHERE value_hash=?',(value_hash,)).fetchone()
            verdict='INVALID'
            if state['phase']!='running':verdict='NOT_RUNNING'
            elif flag is not None:
                if flag['team']==attacker:verdict='SELF'
                elif flag['object_id'] is None:verdict='NOT_PLANTED'
                elif flag['service_id']!=state['service']['id'] or not flag['tick']<=state['tick']<flag['expires_tick']:verdict='EXPIRED'
                elif db.execute('SELECT 1 FROM tick_captures WHERE flag_id=?',(flag['id'],)).fetchone():verdict='DUPLICATE'
                else:
                    db.execute('INSERT INTO tick_captures VALUES(?,?,?)',(flag['id'],attacker,self.clock()))
                    verdict='ACCEPTED'
            db.execute('INSERT INTO tick_submissions(attacker,value_hash,verdict,submitted_at) VALUES(?,?,?,?)',
                       (attacker,value_hash,verdict,self.clock()))
            return {'verdict':verdict,'points':self.rules['attack_points'] if verdict=='ACCEPTED' else 0}

    def sla_monitor(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db);state=self.sla_state(db)
            totals={table:db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] for table in ('tick_checks','tick_flags','tick_captures','tick_submissions')}
            workers=[dict(r) for r in db.execute('SELECT name,heartbeat_at,detail FROM worker_status ORDER BY name')]
            latest=db.execute('SELECT MAX(checked_at) FROM tick_checks WHERE source="worker"').fetchone()[0]
            by_status=[dict(r) for r in db.execute('SELECT status,COUNT(*) AS count FROM tick_checks GROUP BY status ORDER BY status')]
            missing=0
            if state['phase']=='running':
                missing=db.execute('SELECT COUNT(*) FROM tick_checks WHERE tick=? AND status="ERROR" AND source="scheduler"',(state['tick'],)).fetchone()[0]
            return {'mode':'sla','phase':state['phase'],'event_id':self.cfg['event_id'],'sandbox_id':self.cfg['sandbox_id'],
                    'round':state['round'],'tick':state['tick'],'service':state['service'],'total_ticks':state['total_ticks'],
                    'tick_ends_at':state['tick_ends_at'],'total_rows':totals,'latest_checker_result_at':latest,
                    'current_tick_scheduler_errors':missing,'checks_by_status':by_status,'workers':workers}

    def sla_history(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            rows=db.execute('''SELECT c.*,t.competition_round AS round,t.service_id,s.name AS service_name
                FROM tick_checks c JOIN ticks t ON t.number=c.tick JOIN services s ON s.id=t.service_id
                ORDER BY tick DESC,team LIMIT 256''').fetchall()
            return {'mode':'sla','checks':[dict(r) for r in rows]}
