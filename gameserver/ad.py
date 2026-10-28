"""Attack/defense on the tick schedule: one signed flag per team/tick, validation and scoring."""
import base64
import hashlib
import hmac
import re
import secrets
from .errors import Rejected


FLAG_PATTERN = re.compile(r'FLAG\{([A-Za-z0-9_-]{32})\}')
VERDICTS = ('ACCEPTED','DUPLICATE','SELF','EXPIRED','NOT_PLANTED','INVALID','FORMAT','NOT_RUNNING')
STATUSES = ('UP','CORRUPT','MUMBLE','DOWN','ERROR')
ACTIONS = ('CHECK','PUT','GET')
AD_TICK_RULES = {'mode':'ad','round_seconds':1800,'max_rounds':2,'tick_seconds':120,'sla_points':10,
                 'flag_ttl_ticks':5,'attack_points':50,'defense_penalty':25}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_ad(cfg):
    rules = cfg['rules']
    for key, minimum in (('flag_ttl_ticks',1),('attack_points',0),('defense_penalty',0)):
        value = rules.get(key)
        if type(value) is not int or value < minimum:
            raise ValueError('Invalid A/D rule: '+key)
    if not any(s.get('check') == 'flag' for s in cfg['services']):
        raise ValueError('A/D mode needs at least one service with check=flag')
    secret = cfg.get('flag_secret')
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError('A/D mode needs a random flag_secret of at least 32 characters')


def redact(text):
    return re.sub(r'FLAG\{[^}]*\}','[redacted]',text)[:200]


def validate_trace(data):
    """Optional per-action trace and per-flag verdicts sent by the checker with a tick result."""
    actions, flags = data.get('actions', []), data.get('flags', [])
    if not isinstance(actions, list) or not isinstance(flags, list) or len(actions) > 64 or len(flags) > 64:
        raise Rejected('Invalid checker trace')
    for a in actions:
        if not isinstance(a, dict) or a.get('action') not in ACTIONS or a.get('status') not in STATUSES                 or type(a.get('elapsed_ms')) is not int or not 0 <= a['elapsed_ms'] <= 3600000                 or not isinstance(a.get('detail',''), str) or not isinstance(a.get('flag_id') or '', str):
            raise Rejected('Invalid checker action')
    for f in flags:
        if not isinstance(f, dict) or not isinstance(f.get('flag_id'), str) or f.get('status') not in STATUSES:
            raise Rejected('Invalid flag verdict')
    return actions, flags


class FlagSigner:
    """FLAG{base64url(nonce || HMAC(nonce))}: forged or mistyped flags are rejected before any DB lookup."""

    def __init__(self, secret):
        self.key = secret.encode()

    def mac(self, nonce):
        return hmac.new(self.key, nonce, hashlib.sha256).digest()[:12]

    def new(self):
        nonce = secrets.token_bytes(12)
        return 'FLAG{'+base64.urlsafe_b64encode(nonce+self.mac(nonce)).decode()+'}'

    def problem(self, value):
        """Return None for a well-formed, correctly signed flag, otherwise the rejection verdict."""
        if not isinstance(value, str):
            return 'FORMAT'
        matched = FLAG_PATTERN.fullmatch(value)
        if not matched:
            return 'FORMAT'
        raw = base64.urlsafe_b64decode(matched.group(1))
        return None if hmac.compare_digest(raw[12:], self.mac(raw[:12])) else 'INVALID'


class AdMixin:
    def flag_for(self, db, tick, team, service_id):
        flag = db.execute('SELECT * FROM tick_flags WHERE tick=? AND team=?', (tick, team)).fetchone()
        if flag is None:
            value = self.signer.new()
            ident = secrets.token_hex(16)
            db.execute('''INSERT INTO tick_flags(id,tick,team,service_id,expires_tick,value,value_hash,username,password,created_at)
                          VALUES(?,?,?,?,?,?,?,?,?,?)''',
                       (ident, tick, team, service_id, tick+self.rules['flag_ttl_ticks'], value, digest(value),
                        'check_'+secrets.token_hex(12), secrets.token_urlsafe(24), self.clock()))
            flag = db.execute('SELECT * FROM tick_flags WHERE id=?', (ident,)).fetchone()
        return flag

    def ad_plan(self):
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            state = self.sla_state(db)
            jobs = []
            if state['phase'] == 'running':
                tick = state['tick']
                service = self.cfg['services'][state['round']-1]
                level = service.get('check','health')
                for team, target in service['targets'].items():
                    if db.execute('SELECT 1 FROM tick_checks WHERE tick=? AND team=?', (tick, team)).fetchone():
                        continue
                    job = {'team':team,'service_id':service['id'],'check_level':level,**target}
                    if level == 'flag':
                        job['current'] = dict(self.flag_for(db, tick, team, service['id']))
                        # GET: every still-valid flag of this service must survive the team's patches.
                        job['previous'] = [dict(r) for r in db.execute(
                            '''SELECT * FROM tick_flags WHERE team=? AND service_id=? AND tick<? AND expires_tick>?
                               AND ticket_id IS NOT NULL ORDER BY tick''', (team, service['id'], tick, tick))]
                    jobs.append(job)
            return {**state,'event_id':self.cfg['event_id'],'jobs':jobs}

    def ad_result(self, data):
        tick, team, status = data.get('tick'), data.get('team'), data.get('status')
        elapsed, detail, ticket_id = data.get('elapsed_ms'), data.get('detail',''), data.get('ticket_id')
        if type(tick) is not int or not isinstance(team,str) or team not in self.teams or status not in STATUSES or type(elapsed) is not int or not 0<=elapsed<=3600000 or not isinstance(detail,str):
            raise Rejected('Invalid tick result')
        if ticket_id is not None and (type(ticket_id) is not int or ticket_id < 1):
            raise Rejected('Invalid ticket_id')
        actions, flag_states = validate_trace(data)

        def attach(db):
            service = self.cfg['services'][self.sla_state(db)['round']-1]
            self.store_trace(db, tick, team, service['id'], data, actions, flag_states)
            if service.get('check') != 'flag':
                return
            flag = db.execute('SELECT id FROM tick_flags WHERE tick=? AND team=?', (tick, team)).fetchone()
            if flag is None or flag['id'] != data.get('flag_id'):
                raise Rejected('Flag assignment does not match', 409)
            if status == 'UP' and ticket_id is None:
                raise Rejected('UP requires a verified flag ticket')
            # A planted flag stays stealable even if an older flag was lost (MUMBLE).
            if ticket_id is not None:
                db.execute('UPDATE tick_flags SET ticket_id=?,placed_at=? WHERE id=?', (ticket_id, self.clock(), flag['id']))

        with self.connect(write=True) as db:
            return self.record_tick(db, data, attach)

    def store_trace(self, db, tick, team, service_id, data, actions, flag_states):
        if not actions:
            # Health/functional checks have a single implicit CHECK step.
            actions = [{'action':'CHECK','status':data['status'],'detail':data.get('detail',''),'elapsed_ms':data['elapsed_ms']}]
        owned = {r['id'] for r in db.execute('SELECT id FROM tick_flags WHERE team=? AND service_id=?', (team, service_id))}
        now = self.clock()
        for a in actions:
            # A trace may only reference this team's own flags of the active service.
            flag_id = a.get('flag_id') if a.get('flag_id') in owned else None
            db.execute('''INSERT INTO checker_actions(tick,team,service_id,action,flag_id,status,detail,elapsed_ms,created_at)
                          VALUES(?,?,?,?,?,?,?,?,?)''',
                       (tick, team, service_id, a['action'], flag_id, a['status'], redact(a.get('detail','')), a['elapsed_ms'], now))
        for f in flag_states:
            if f['flag_id'] in owned:
                db.execute('INSERT OR REPLACE INTO flag_checks VALUES(?,?,?,?)', (f['flag_id'], tick, f['status'], now))

    def trace(self, limit=120):
        """Public checker console: what each action saw, never flag values, credentials or flag IDs."""
        with self.connect() as db:
            rows = db.execute('''SELECT a.id,a.tick,a.team,a.service_id,a.action,a.status,a.detail,a.elapsed_ms,a.created_at,
                                        f.tick AS flag_tick
                                 FROM checker_actions a LEFT JOIN tick_flags f ON f.id=a.flag_id
                                 ORDER BY a.id DESC LIMIT ?''', (limit,)).fetchall()
            return {'actions':[dict(r) for r in rows]}

    def flag_overview(self):
        """Flag lifecycle per team/tick: planted, last integrity check, times stolen. No values."""
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            state = self.sla_state(db)
            current = state['tick'] or 0
            rows = db.execute('''SELECT f.tick,f.team,f.service_id,f.expires_tick,f.ticket_id IS NOT NULL AS planted,
                       (SELECT COUNT(*) FROM tick_captures c WHERE c.flag_id=f.id) AS stolen,
                       (SELECT status FROM flag_checks k WHERE k.flag_id=f.id ORDER BY k.tick DESC LIMIT 1) AS last_check,
                       (SELECT MAX(tick) FROM flag_checks k WHERE k.flag_id=f.id) AS last_check_tick
                FROM tick_flags f ORDER BY f.tick DESC, f.team LIMIT 400''').fetchall()
            flags = []
            for r in rows:
                row = dict(r)
                row['planted'] = bool(row['planted'])
                row['active'] = state['phase']=='running' and row['planted'] and row['tick'] <= current < row['expires_tick']
                flags.append(row)
            totals = db.execute('''SELECT COUNT(*) total,COALESCE(SUM(ticket_id IS NOT NULL),0) planted,
                       (SELECT COUNT(DISTINCT flag_id) FROM tick_captures) stolen FROM tick_flags''').fetchone()
            return {'tick':state['tick'],'ttl_ticks':self.rules.get('flag_ttl_ticks'),'flags':flags,**dict(totals)}

    def ad_submit(self, attacker, value):
        verdict = self.signer.problem(value.strip() if isinstance(value,str) else value)
        hashed = digest(value.strip()) if isinstance(value,str) and len(value) <= 256 else ''
        points = 0
        with self.connect(write=True) as db:
            self.finalize_ticks(db)
            state = self.sla_state(db)
            if state['phase'] != 'running':
                verdict = 'NOT_RUNNING'
            elif verdict is None:
                flag = db.execute('SELECT * FROM tick_flags WHERE value_hash=?', (hashed,)).fetchone()
                if flag is None:
                    verdict = 'INVALID'
                elif flag['team'] == attacker:
                    verdict = 'SELF'
                elif flag['ticket_id'] is None:
                    verdict = 'NOT_PLANTED'
                elif not flag['tick'] <= state['tick'] < flag['expires_tick']:
                    verdict = 'EXPIRED'
                elif db.execute('SELECT 1 FROM tick_captures WHERE attacker=? AND flag_id=?', (attacker, flag['id'])).fetchone():
                    verdict = 'DUPLICATE'
                else:
                    points = self.rules['attack_points']
                    db.execute('INSERT INTO tick_captures VALUES(?,?,?,?,?,?)',
                               (attacker, flag['id'], state['tick'], self.clock(), points, self.rules['defense_penalty']))
                    verdict = 'ACCEPTED'
            db.execute('INSERT INTO tick_submissions(attacker,flag_hash,verdict,tick,submitted_at) VALUES(?,?,?,?,?)',
                       (attacker, hashed, verdict, state['tick'], self.clock()))
        return {'verdict':verdict,'points':points}

    def ad_public(self):
        board = self.sla_public()
        with self.connect() as db:
            for row in board['teams']:
                team = row['team']
                won = db.execute('SELECT COUNT(*) n,COALESCE(SUM(attack_points),0) p FROM tick_captures WHERE attacker=?', (team,)).fetchone()
                lost = db.execute('''SELECT COUNT(*) n,COALESCE(SUM(c.defense_penalty),0) p FROM tick_captures c
                                     JOIN tick_flags f ON f.id=c.flag_id WHERE f.team=?''', (team,)).fetchone()
                planted = db.execute('SELECT COUNT(*) FROM tick_flags WHERE team=? AND ticket_id IS NOT NULL', (team,)).fetchone()[0]
                row.update(attack_points=won['p'], captures=won['n'], defense_penalty=lost['p'], flags_lost=lost['n'],
                           flags_planted=planted, score=row['sla_points']+won['p']-lost['p'])
        board['teams'].sort(key=lambda t:(-t['score'],t['team']))
        for rank, row in enumerate(board['teams'], 1):
            row['rank'] = rank
        board['services'] = [{'round':i,'id':s['id'],'name':s['name'],'vulnerability_count':s['vulnerability_count'],
                              'check':s.get('check','health')} for i, s in enumerate(self.cfg['services'], 1)]
        return board

    def ad_attack_data(self):
        with self.connect() as db:
            state = self.sla_state(db)
            if state['phase'] != 'running':
                return {'tick':state['tick'],'flags':[]}
            # Public flag IDs (ticket numbers) tell attackers where to look, never the flag value.
            rows = db.execute('''SELECT team,service_id,tick,expires_tick,ticket_id FROM tick_flags
                                 WHERE tick<=? AND expires_tick>? AND ticket_id IS NOT NULL ORDER BY tick,team''',
                              (state['tick'], state['tick'])).fetchall()
            return {'tick':state['tick'],'flags':[dict(r) for r in rows]}

    def feed(self):
        with self.connect() as db:
            rows = db.execute('''SELECT c.attacker,f.team AS victim,f.service_id,s.name AS service_name,c.tick,
                       c.captured_at,c.attack_points,
                       c.rowid=(SELECT MIN(c2.rowid) FROM tick_captures c2 JOIN tick_flags f2 ON f2.id=c2.flag_id
                                      WHERE f2.service_id=f.service_id) AS first_blood
                FROM tick_captures c JOIN tick_flags f ON f.id=c.flag_id JOIN services s ON s.id=f.service_id
                ORDER BY c.rowid DESC LIMIT 50''').fetchall()
            totals = db.execute('SELECT (SELECT COUNT(*) FROM tick_captures) captures,(SELECT COUNT(*) FROM tick_submissions) submissions').fetchone()
            return {'events':[{**dict(r),'first_blood':bool(r['first_blood'])} for r in rows],**dict(totals)}

    def team_status(self, team):
        with self.connect() as db:
            counts = {r['verdict']:r['n'] for r in db.execute(
                'SELECT verdict,COUNT(*) n FROM tick_submissions WHERE attacker=? GROUP BY verdict', (team,))}
            recent = db.execute('SELECT verdict,tick,submitted_at FROM tick_submissions WHERE attacker=? ORDER BY id DESC LIMIT 20', (team,)).fetchall()
            return {'team':team,'verdicts':counts,'recent':[dict(r) for r in recent]}
