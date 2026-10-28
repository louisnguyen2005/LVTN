"""Two-level schedule: competition rounds select services; ticks award SLA."""
import math
import re
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
        checks=('health','functional','flag') if rules.get('mode')=='ad' else ('health','functional')
        if service.get('check','health') not in checks:
            raise ValueError('Use one of these service checks: '+', '.join(checks))
        if set(service['targets']) != teams:
            raise ValueError('Each service must have exactly one target for each team')
        for target in service['targets'].values():
            url=urlsplit(target['url'])
            if url.scheme not in ('http','https') or not url.hostname or '<' in target['url'] or url.username or url.password or url.query or url.fragment or url.path!='/health':
                raise ValueError('Fill every service target with a real /health HTTP(S) URL')
            if not target['expected_sandbox'].startswith(cfg['sandbox_id']+'-'):
                raise ValueError('Service target belongs to another sandbox')
            if service.get('check','health')=='functional' and not target.get('password'):
                raise ValueError('Functional mode needs the ServiceDesk password per target')


class SlaMixin:
    def sla_state(self, db):
        event=db.execute('SELECT started_at,ended_at FROM event').fetchone()
        now=self.clock()
        r=self.rules
        per_round=r['round_seconds']//r['tick_seconds']
        total=per_round*r['max_rounds']
        base={'mode':r.get('mode','sla'),'demo':bool(self.cfg.get('demo')), 'server_time':now,
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
                    jobs.append({'team':team,'service_id':service['id'],
                                 'check_level':service.get('check','health'),**target})
            return {**state,'event_id':self.cfg['event_id'],'jobs':jobs}

    def sla_result(self, data):
        tick,team,status=data.get('tick'),data.get('team'),data.get('status')
        elapsed=data.get('elapsed_ms')
        detail=data.get('detail','')
        if type(tick) is not int or not isinstance(team,str) or team not in self.teams or status not in ('UP','DOWN','MUMBLE','ERROR') or type(elapsed) is not int or not 0<=elapsed<=3600000 or not isinstance(detail,str):
            raise Rejected('Invalid tick result')
        with self.connect(write=True) as db:
            # The single health/functional measurement is kept as a CHECK row of the checker trace.
            return self.record_tick(db,data,lambda db:self.store_trace(db,tick,team,data['service_id'],data,[],[]))

    def record_tick(self, db, data, before_insert=None):
        tick,team,status=data['tick'],data['team'],data['status']
        self.finalize_ticks(db)
        row=db.execute('SELECT status,sla_points,source FROM tick_checks WHERE tick=? AND team=?',(tick,team)).fetchone()
        if row and row['source']=='worker':
            return {'recorded':True,'duplicate':True,'status':row['status'],'sla_points':row['sla_points']}
        state=self.sla_state(db)
        if state['phase']!='running' or state['tick']!=tick:
            raise Rejected('Tick deadline passed',409)
        if data.get('service_id')!=state['service']['id']:
            raise Rejected('Wrong service for this competition round',409)
        if before_insert:
            before_insert(db)
        points=self.rules['sla_points'] if status=='UP' else 0
        # Never store a raw flag in a diagnostic field.
        detail=re.sub(r'FLAG\{[^}]*\}','[redacted]',data.get('detail',''))[:300]
        db.execute('INSERT INTO tick_checks VALUES(?,?,?,?,?,?,?,?)',
                   (tick,team,status,detail,data['elapsed_ms'],self.clock(),points,'worker'))
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
                statuses={r['status']:r['n'] for r in db.execute('SELECT status,COUNT(*) n FROM tick_checks WHERE team=? GROUP BY status',(team,))}
                board.append({'team':team,'score':stats['points'],'sla_points':stats['points'],
                              'up_checks':stats['good'],'checks':stats['n'],'statuses':statuses,
                              'max_sla_points':state['total_ticks']*self.rules['sla_points'],
                              'latest':dict(latest) if latest else None,
                              'current_sla':current['sla_points'] if current else None,
                              'current_status':current['status'] if current else ('PENDING' if state['phase']=='running' else 'UNCHECKED')})
            board.sort(key=lambda t:(-t['score'],t['team']))
            return {**state,'event_id':self.cfg['event_id'],'sandbox_id':self.cfg['sandbox_id'],
                    'rules':self.rules,'teams':board}

    def sla_history(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            rows=db.execute('''SELECT c.*,t.competition_round AS round,t.service_id,s.name AS service_name
                FROM tick_checks c JOIN ticks t ON t.number=c.tick JOIN services s ON s.id=t.service_id
                ORDER BY tick DESC,team LIMIT 256''').fetchall()
            return {'mode':self.rules.get('mode','sla'),'checks':[dict(r) for r in rows]}
