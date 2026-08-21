'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

let db;

function init(databaseFile) {
  const abs = path.resolve(databaseFile);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  db = new Database(abs);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      service TEXT NOT NULL,
      remote_ip TEXT,
      remote_port INTEGER,
      local_port INTEGER,
      type TEXT NOT NULL,
      username TEXT,
      password TEXT,
      command TEXT,
      session_id TEXT,
      details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_ip ON events(remote_ip);

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      service TEXT NOT NULL,
      remote_ip TEXT,
      remote_port INTEGER,
      username TEXT,
      opened_at INTEGER NOT NULL,
      closed_at INTEGER,
      command_count INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_opened ON sessions(opened_at DESC);
  `);
}

function insertEvent(evt) {
  const stmt = db.prepare(`
    INSERT INTO events
      (ts, service, remote_ip, remote_port, local_port, type, username, password, command, session_id, details)
    VALUES
      (@ts, @service, @remote_ip, @remote_port, @local_port, @type, @username, @password, @command, @session_id, @details)
  `);
  const info = stmt.run({
    ts: evt.ts || Date.now(),
    service: evt.service,
    remote_ip: evt.remoteIp || null,
    remote_port: evt.remotePort || null,
    local_port: evt.localPort || null,
    type: evt.type,
    username: evt.username || null,
    password: evt.password || null,
    command: evt.command || null,
    session_id: evt.sessionId || null,
    details: evt.details ? JSON.stringify(evt.details) : null
  });
  return info.lastInsertRowid;
}

function openSession(sess) {
  const stmt = db.prepare(`
    INSERT INTO sessions (id, service, remote_ip, remote_port, username, opened_at)
    VALUES (@id, @service, @remote_ip, @remote_port, @username, @opened_at)
  `);
  stmt.run({
    id: sess.id,
    service: sess.service,
    remote_ip: sess.remoteIp || null,
    remote_port: sess.remotePort || null,
    username: sess.username || null,
    opened_at: Date.now()
  });
}

function closeSession(id) {
  db.prepare('UPDATE sessions SET closed_at = ? WHERE id = ?').run(Date.now(), id);
}

function setSessionUsername(id, username) {
  db.prepare('UPDATE sessions SET username = COALESCE(username, ?) WHERE id = ?').run(username, id);
}

function incrementSessionCommands(id) {
  db.prepare('UPDATE sessions SET command_count = command_count + 1 WHERE id = ?').run(id);
}

function trim(maxRows) {
  if (!maxRows) return;
  const row = db.prepare('SELECT COUNT(*) AS c FROM events').get();
  if (row.c > maxRows) {
    const cutoff = db
      .prepare('SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?')
      .get(maxRows);
    if (cutoff) db.prepare('DELETE FROM events WHERE id < ?').run(cutoff.id);
  }
}

function getRecentEvents({ limit = 200, service, ip, type, sessionId, since } = {}) {
  const where = [];
  const params = {};
  if (service) { where.push('service = @service'); params.service = service; }
  if (ip) { where.push('remote_ip = @ip'); params.ip = ip; }
  if (type) { where.push('type = @type'); params.type = type; }
  if (sessionId) { where.push('session_id = @sessionId'); params.sessionId = sessionId; }
  if (since) { where.push('ts >= @since'); params.since = since; }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const rows = db
    .prepare(`SELECT * FROM events ${clause} ORDER BY id DESC LIMIT @limit`)
    .all({ ...params, limit });
  return rows.map(hydrateEvent).reverse();
}

function getSessions({ limit = 100, service } = {}) {
  const where = [];
  const params = {};
  if (service) { where.push('service = @service'); params.service = service; }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  return db
    .prepare(`SELECT * FROM sessions ${clause} ORDER BY opened_at DESC LIMIT @limit`)
    .all({ ...params, limit });
}

function getSession(id) {
  const s = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!s) return null;
  const events = db
    .prepare('SELECT * FROM events WHERE session_id = ? ORDER BY id ASC')
    .all(id)
    .map(hydrateEvent);
  return { ...s, events };
}

function getStats() {
  const total = db.prepare('SELECT COUNT(*) AS c FROM events').get().c;
  const last24h = db
    .prepare('SELECT COUNT(*) AS c FROM events WHERE ts >= ?')
    .get(Date.now() - 24 * 3600 * 1000).c;
  const uniqueIps = db
    .prepare('SELECT COUNT(DISTINCT remote_ip) AS c FROM events WHERE remote_ip IS NOT NULL')
    .get().c;
  const byService = db
    .prepare('SELECT service, COUNT(*) AS c FROM events GROUP BY service ORDER BY c DESC')
    .all();
  const topIps = db
    .prepare(`
      SELECT remote_ip, COUNT(*) AS c
      FROM events WHERE remote_ip IS NOT NULL
      GROUP BY remote_ip ORDER BY c DESC LIMIT 10
    `)
    .all();
  const topCreds = db
    .prepare(`
      SELECT username, password, COUNT(*) AS c
      FROM events
      WHERE type IN ('auth_attempt','login_attempt') AND username IS NOT NULL
      GROUP BY username, password ORDER BY c DESC LIMIT 10
    `)
    .all();
  const topCommands = db
    .prepare(`
      SELECT command, COUNT(*) AS c
      FROM events WHERE command IS NOT NULL
      GROUP BY command ORDER BY c DESC LIMIT 15
    `)
    .all();
  const activeSessions = db
    .prepare('SELECT COUNT(*) AS c FROM sessions WHERE closed_at IS NULL')
    .get().c;
  return { total, last24h, uniqueIps, byService, topIps, topCreds, topCommands, activeSessions };
}

function hydrateEvent(row) {
  return {
    ...row,
    details: row.details ? safeParse(row.details) : null
  };
}

function safeParse(s) {
  try { return JSON.parse(s); } catch { return s; }
}

module.exports = {
  init,
  insertEvent,
  openSession,
  closeSession,
  setSessionUsername,
  incrementSessionCommands,
  trim,
  getRecentEvents,
  getSessions,
  getSession,
  getStats
};
