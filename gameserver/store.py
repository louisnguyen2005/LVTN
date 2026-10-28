"""Transactional event state. Only the backend opens this SQLite database."""
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID
from .errors import Rejected
from .sla import SlaMixin, validate_sla


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def validate_config(cfg):
    UUID(cfg['sandbox_id'])
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', cfg['event_id']):
        raise ValueError('Invalid event_id')
    sla=cfg['rules'].get('mode')=='sla'
    if sla:
        validate_sla(cfg)
    for key in (() if sla else ('round_seconds', 'max_rounds', 'flag_ttl_rounds', 'sla_points', 'attack_points', 'defense_penalty')):
        value = cfg['rules'][key]
        if type(value) is not int or value < (1 if key in ('round_seconds', 'max_rounds', 'flag_ttl_rounds') else 0):
            raise ValueError('Invalid rule: ' + key)
    if not sla and (cfg['rules']['round_seconds'] < 5 or cfg['rules']['max_rounds'] > 100000):
        raise ValueError('round_seconds must be >=5; max_rounds must be <=100000')
    names = set()
    tokens = [cfg['admin_token'], cfg['checker_token']]
    if cfg.get('monitor_token') is not None:tokens.append(cfg['monitor_token'])
    if not 2 <= len(cfg['teams']) <= 64:
        raise ValueError('Configure 2-64 teams')
    for team in cfg['teams']:
        name = team['id']
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,48}', name) or name in names:
            raise ValueError('Duplicate or invalid team')
        names.add(name)
        url = urlsplit(team['url'])
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
            raise ValueError('Team URL must be an HTTP(S) origin')
        if not team['expected_sandbox'].startswith(cfg['sandbox_id'] + '-'):
            raise ValueError('Wrong sandbox identity')
        tokens.append(team['token'])
    if any(not isinstance(t, str) or len(t) < 32 for t in tokens) or len(set(tokens)) != len(tokens):
        raise ValueError('Use distinct random tokens of at least 32 characters')


class Store(SlaMixin):
    def __init__(self, path, cfg, clock=time.time):
        validate_config(cfg)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cfg, self.clock = cfg, clock
        self.rules = cfg['rules']
        self.sla = self.rules.get('mode')=='sla'
        self.teams = {t['id']: t for t in cfg['teams']}
        frozen = json.dumps(cfg, sort_keys=True, separators=(',', ':'))
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript(Path(__file__).with_name('schema.sql').read_text(encoding='utf-8'))
            rows = db.execute('SELECT * FROM event').fetchall()
            if rows and (rows[0]['id'] != cfg['event_id'] or rows[0]['configuration'] != frozen):
                raise ValueError('Database belongs to another configuration. Restore its original config or create a NEW event/runtime directory.')
            if not rows:
                db.execute('INSERT INTO event(id,sandbox_id,configuration) VALUES(?,?,?)', (cfg['event_id'], cfg['sandbox_id'], frozen))
                db.executemany('INSERT INTO teams VALUES(?,?)', [(t['id'], digest(t['token'])) for t in cfg['teams']])
                if self.sla:
                    db.executemany('INSERT INTO services VALUES(?,?,?)',[(s['id'],s['name'],s['vulnerability_count']) for s in cfg['services']])
        # Config and DB contain checker credentials; restrict Unix permissions as well.
        self.path.chmod(0o600)

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def state(self, db):
        if self.sla:
            return self.sla_state(db)
        event = db.execute('SELECT started_at,ended_at FROM event').fetchone()
        start, end = event['started_at'], event['ended_at']
        now = self.clock()
        if start is None:
            return {'phase': 'ready', 'round': None, 'server_time': now, 'round_ends_at': None}
        number = math.floor((now - start) / self.rules['round_seconds']) + 1
        running = end is None and 1 <= number <= self.rules['max_rounds']
        return {'phase': 'running' if running else 'finished', 'round': min(max(number, 1), self.rules['max_rounds']),
                'server_time': now, 'round_ends_at': start + number * self.rules['round_seconds'] if running else None}

    def start(self):
        with self.connect(write=True) as db:
            event = db.execute('SELECT started_at FROM event').fetchone()
            if event['started_at'] is None:
                now = self.clock()
                db.execute('UPDATE event SET started_at=?', (now,))
                if self.sla:
                    self.sla_start(db,now)
                else:
                    db.executemany('INSERT INTO rounds VALUES(?,?,?)', [
                        (n, now+(n-1)*self.rules['round_seconds'], now+n*self.rules['round_seconds'])
                        for n in range(1, self.rules['max_rounds']+1)])
                db.execute('INSERT INTO audit(action,created_at,detail) VALUES(?,?,?)', ('start', now, '{}'))
            return self.state(db)

    def finish(self):
        with self.connect(write=True) as db:
            if db.execute('SELECT started_at FROM event').fetchone()[0] is None:
                raise Rejected('Event has not started', 409)
            db.execute('UPDATE event SET ended_at=COALESCE(ended_at,?)', (self.clock(),))
            return self.state(db)

    def plan(self):
        if self.sla:
            return self.sla_plan()
        with self.connect(write=True) as db:
            state = self.state(db)
            jobs = []
            if state['phase'] == 'running':
                n = state['round']
                for team, target in self.teams.items():
                    if db.execute('SELECT 1 FROM checks WHERE round=? AND team=?', (n, team)).fetchone():
                        continue
                    flag = db.execute('SELECT * FROM flags WHERE round=? AND team=?', (n, team)).fetchone()
                    if flag is None:
                        ident = secrets.token_hex(16)
                        value = 'FLAG{' + secrets.token_urlsafe(32) + '}'
                        db.execute('INSERT INTO flags(id,team,round,expires_round,value,value_hash,username,password) VALUES(?,?,?,?,?,?,?,?)',
                                   (ident, team, n, n+self.rules['flag_ttl_rounds'], value, digest(value), 'check_'+secrets.token_hex(12), secrets.token_urlsafe(24)))
                        flag = db.execute('SELECT * FROM flags WHERE id=?', (ident,)).fetchone()
                    previous = db.execute('SELECT * FROM flags WHERE team=? AND round<? AND expires_round>? AND ticket_id IS NOT NULL ORDER BY round', (team, n, n)).fetchall()
                    jobs.append({'team': team, 'url': target['url'], 'expected_sandbox': target['expected_sandbox'],
                                 'current': dict(flag), 'previous': [dict(f) for f in previous]})
            return {**state, 'event_id': self.cfg['event_id'], 'jobs': jobs}

    def result(self, data):
        if self.sla:
            return self.sla_result(data)
        n, team = data.get('round'), data.get('team')
        status, elapsed = data.get('status'), data.get('elapsed_ms')
        ticket_id = data.get('ticket_id')
        if type(n) is not int or not isinstance(team,str) or team not in self.teams or status not in ('UP','DOWN','MUMBLE','ERROR') or type(elapsed) is not int or not 0 <= elapsed <= 3600000:
            raise Rejected('Invalid result')
        if ticket_id is not None and (type(ticket_id) is not int or ticket_id < 1):
            raise Rejected('Invalid ticket_id')
        if status == 'UP' and ticket_id is None:
            raise Rejected('UP requires a verified flag ticket')
        with self.connect(write=True) as db:
            # Replayed acknowledgements are harmless, including after the deadline.
            if db.execute('SELECT 1 FROM checks WHERE round=? AND team=?', (n, team)).fetchone():
                return {'recorded': True, 'duplicate': True}
            state = self.state(db)
            if state['phase'] != 'running' or state['round'] != n:
                raise Rejected('Round deadline passed', 409)
            flag = db.execute('SELECT id FROM flags WHERE round=? AND team=?', (n, team)).fetchone()
            if flag is None or flag['id'] != data.get('flag_id'):
                raise Rejected('Flag assignment does not match', 409)
            if ticket_id is not None:
                db.execute('UPDATE flags SET ticket_id=? WHERE id=?', (ticket_id, flag['id']))
            detail = data.get('detail', '')
            if not isinstance(detail, str):
                raise Rejected('Invalid detail')
            # Never store a raw flag in a diagnostic field.
            detail = re.sub(r'FLAG\{[^}]*\}', '[redacted]', detail)[:300]
            db.execute('INSERT INTO checks VALUES(?,?,?,?,?,?)', (n, team, status, detail, elapsed, self.clock()))
            return {'recorded': True, 'duplicate': False}

    def submit(self, attacker, value):
        if self.sla:
            return self.sla_submit(attacker,value)
        if not isinstance(value, str) or len(value) > 128:
            raise Rejected('Invalid flag format')
        hashed = digest(value)
        with self.connect(write=True) as db:
            state = self.state(db)
            flag = db.execute('SELECT * FROM flags WHERE value_hash=?', (hashed,)).fetchone()
            verdict = 'INVALID'
            if state['phase'] != 'running':
                verdict = 'NOT_RUNNING'
            elif flag:
                if flag['team'] == attacker:
                    verdict = 'SELF'
                elif flag['ticket_id'] is None:
                    verdict = 'NOT_PLANTED'
                elif not flag['round'] <= state['round'] < flag['expires_round']:
                    verdict = 'EXPIRED'
                elif db.execute('SELECT 1 FROM captures WHERE attacker=? AND flag_id=?', (attacker, flag['id'])).fetchone():
                    verdict = 'DUPLICATE'
                else:
                    db.execute('INSERT INTO captures VALUES(?,?,?)', (attacker, flag['id'], self.clock()))
                    verdict = 'ACCEPTED'
            db.execute('INSERT INTO submissions(attacker,flag_hash,verdict,submitted_at) VALUES(?,?,?,?)', (attacker, hashed, verdict, self.clock()))
            return {'verdict': verdict, 'points': self.rules['attack_points'] if verdict == 'ACCEPTED' else 0}

    def public(self):
        if self.sla:
            return self.sla_public()
        with self.connect() as db:
            state = self.state(db)
            board = []
            for team in self.teams:
                good = db.execute("SELECT COUNT(*) FROM checks WHERE team=? AND status='UP'", (team,)).fetchone()[0]
                count = db.execute('SELECT COUNT(*) FROM checks WHERE team=?', (team,)).fetchone()[0]
                wins = db.execute('SELECT COUNT(*) FROM captures WHERE attacker=?', (team,)).fetchone()[0]
                lost = db.execute('SELECT COUNT(*) FROM captures c JOIN flags f ON c.flag_id=f.id WHERE f.team=?', (team,)).fetchone()[0]
                latest = db.execute('SELECT round,status,elapsed_ms FROM checks WHERE team=? ORDER BY round DESC LIMIT 1', (team,)).fetchone()
                sla = good*self.rules['sla_points']
                attack, penalty = wins*self.rules['attack_points'], lost*self.rules['defense_penalty']
                board.append({'team':team, 'score':sla+attack-penalty, 'sla_points':sla, 'attack_points':attack,
                              'defense_penalty':penalty, 'up_checks':good, 'checks':count,
                              'latest':dict(latest) if latest else None,
                              'current_status': (latest['status'] if latest and latest['round'] == state['round'] else ('PENDING' if state['phase']=='running' else 'UNCHECKED'))})
            board.sort(key=lambda t:(-t['score'],t['team']))
            return {**state, 'event_id': self.cfg['event_id'], 'sandbox_id': self.cfg['sandbox_id'], 'rules':self.rules, 'teams':board}

    def attack_data(self):
        if self.sla:
            return self.sla_attack_data()
        with self.connect() as db:
            state = self.state(db)
            if state['phase'] != 'running':
                return {'flags':[]}
            rows = db.execute('SELECT id,team,round,expires_round,ticket_id FROM flags WHERE round<=? AND expires_round>? AND ticket_id IS NOT NULL ORDER BY round,team', (state['round'],state['round'])).fetchall()
            return {'flags':[dict(r) for r in rows]}

    def history(self):
        if self.sla:
            return self.sla_history()
        with self.connect() as db:
            rows = db.execute('SELECT * FROM checks ORDER BY round DESC,team LIMIT 256').fetchall()
            return {'checks':[dict(r) for r in rows]}

    def backup(self, destination):
        with self.connect() as db:
            target = sqlite3.connect(destination)
            try:
                db.backup(target)
            finally:
                target.close()
