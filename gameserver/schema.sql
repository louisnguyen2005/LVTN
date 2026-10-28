PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS event (
 id TEXT PRIMARY KEY, sandbox_id TEXT NOT NULL, configuration TEXT NOT NULL,
 started_at REAL, ended_at REAL
);
CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS rounds (
 number INTEGER PRIMARY KEY, starts_at REAL NOT NULL, ends_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS flags (
 id TEXT PRIMARY KEY, team TEXT NOT NULL REFERENCES teams(id),
 round INTEGER NOT NULL REFERENCES rounds(number), expires_round INTEGER NOT NULL,
 value TEXT NOT NULL, value_hash TEXT UNIQUE NOT NULL,
 username TEXT NOT NULL, password TEXT NOT NULL, ticket_id INTEGER,
 UNIQUE(team, round)
);
CREATE TABLE IF NOT EXISTS checks (
 round INTEGER NOT NULL REFERENCES rounds(number), team TEXT NOT NULL REFERENCES teams(id),
 status TEXT NOT NULL CHECK(status IN ('UP','DOWN','MUMBLE','ERROR')),
 detail TEXT NOT NULL, elapsed_ms INTEGER NOT NULL, checked_at REAL NOT NULL,
 PRIMARY KEY(round, team)
);
CREATE TABLE IF NOT EXISTS captures (
 attacker TEXT NOT NULL REFERENCES teams(id), flag_id TEXT NOT NULL REFERENCES flags(id),
 captured_at REAL NOT NULL, PRIMARY KEY(attacker, flag_id)
);
CREATE TABLE IF NOT EXISTS submissions (
 id INTEGER PRIMARY KEY, attacker TEXT NOT NULL REFERENCES teams(id),
 flag_hash TEXT NOT NULL, verdict TEXT NOT NULL, submitted_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, created_at REAL NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS flags_active ON flags(expires_round, team);
CREATE TABLE IF NOT EXISTS services (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, vulnerability_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS competition_rounds (
 number INTEGER PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id),
 starts_at REAL NOT NULL, ends_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ticks (
 number INTEGER PRIMARY KEY, competition_round INTEGER NOT NULL REFERENCES competition_rounds(number),
 service_id TEXT NOT NULL REFERENCES services(id), starts_at REAL NOT NULL, ends_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tick_checks (
 tick INTEGER NOT NULL REFERENCES ticks(number), team TEXT NOT NULL REFERENCES teams(id),
 status TEXT NOT NULL CHECK(status IN ('UP','DOWN','CORRUPT','MUMBLE','ERROR')),
 detail TEXT NOT NULL, elapsed_ms INTEGER NOT NULL, checked_at REAL NOT NULL,
 sla_points INTEGER NOT NULL, source TEXT NOT NULL,
 PRIMARY KEY(tick,team)
);
-- Attack/defense on the tick schedule: one flag per team per tick, stored in the active service.
CREATE TABLE IF NOT EXISTS tick_flags (
 id TEXT PRIMARY KEY, tick INTEGER NOT NULL REFERENCES ticks(number), team TEXT NOT NULL REFERENCES teams(id),
 service_id TEXT NOT NULL REFERENCES services(id), expires_tick INTEGER NOT NULL,
 value TEXT NOT NULL, value_hash TEXT UNIQUE NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL,
 ticket_id INTEGER, created_at REAL NOT NULL, placed_at REAL,
 UNIQUE(tick, team)
);
CREATE INDEX IF NOT EXISTS tick_flags_active ON tick_flags(team, service_id, expires_tick);
-- Points are frozen at capture time so later rule reads cannot rewrite history.
CREATE TABLE IF NOT EXISTS tick_captures (
 attacker TEXT NOT NULL REFERENCES teams(id), flag_id TEXT NOT NULL REFERENCES tick_flags(id),
 tick INTEGER NOT NULL, captured_at REAL NOT NULL,
 attack_points INTEGER NOT NULL, defense_penalty INTEGER NOT NULL,
 PRIMARY KEY(attacker, flag_id)
);
CREATE TABLE IF NOT EXISTS tick_submissions (
 id INTEGER PRIMARY KEY, attacker TEXT NOT NULL REFERENCES teams(id), flag_hash TEXT NOT NULL,
 verdict TEXT NOT NULL, tick INTEGER, submitted_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS tick_submissions_attacker ON tick_submissions(attacker, id);
-- Host PC -> Windows gateway -> sandbox VM reachability measured by the worker.
CREATE TABLE IF NOT EXISTS links (
 name TEXT PRIMARY KEY, gateway TEXT NOT NULL, vm TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('UP','DOWN','MISMATCH')), latency_ms INTEGER NOT NULL,
 detail TEXT NOT NULL, checked_at REAL NOT NULL,
 identity TEXT -- sandbox identity the VM reported over HTTP /health (NULL for plain TCP probes)
);
CREATE TABLE IF NOT EXISTS link_checks (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, latency_ms INTEGER NOT NULL, checked_at REAL NOT NULL
);
-- Checker trace: one row per CHECK/PUT/GET action, so operators and teams see WHY a tick failed.
CREATE TABLE IF NOT EXISTS checker_actions (
 id INTEGER PRIMARY KEY, tick INTEGER NOT NULL REFERENCES ticks(number), team TEXT NOT NULL REFERENCES teams(id),
 service_id TEXT NOT NULL REFERENCES services(id), action TEXT NOT NULL CHECK(action IN ('CHECK','PUT','GET')),
 flag_id TEXT REFERENCES tick_flags(id), status TEXT NOT NULL, detail TEXT NOT NULL,
 elapsed_ms INTEGER NOT NULL, created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS checker_actions_tick ON checker_actions(tick, team);
-- Flag lifecycle: whether each stored flag was still retrievable when the checker looked in a tick.
CREATE TABLE IF NOT EXISTS flag_checks (
 flag_id TEXT NOT NULL REFERENCES tick_flags(id), tick INTEGER NOT NULL REFERENCES ticks(number),
 status TEXT NOT NULL, checked_at REAL NOT NULL, PRIMARY KEY(flag_id, tick)
);
