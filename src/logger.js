'use strict';

const { EventEmitter } = require('events');
const db = require('./db');

const emitter = new EventEmitter();
emitter.setMaxListeners(0);

let maxRows = 200000;
let trimCounter = 0;

function configure({ maxLogRows } = {}) {
  if (maxLogRows) maxRows = maxLogRows;
}

function log(evt) {
  const record = {
    ts: Date.now(),
    ...evt
  };
  try {
    const id = db.insertEvent(record);
    record.id = id;
  } catch (err) {
    console.error('[logger] failed to insert event', err.message);
  }
  emitter.emit('event', record);

  const line = format(record);
  console.log(line);

  if (++trimCounter % 500 === 0) {
    try { db.trim(maxRows); } catch (err) { console.error('[logger] trim error', err.message); }
  }
  return record;
}

function format(evt) {
  const time = new Date(evt.ts).toISOString();
  const parts = [
    `[${time}]`,
    `[${evt.service}]`,
    `[${evt.type}]`,
    evt.remoteIp ? `${evt.remoteIp}:${evt.remotePort || ''}` : ''
  ];
  if (evt.username) parts.push(`user=${JSON.stringify(evt.username)}`);
  if (evt.password) parts.push(`pass=${JSON.stringify(evt.password)}`);
  if (evt.command) parts.push(`cmd=${JSON.stringify(evt.command)}`);
  if (evt.details) parts.push(`details=${JSON.stringify(evt.details)}`);
  return parts.filter(Boolean).join(' ');
}

function openSession(sess) {
  db.openSession(sess);
  emitter.emit('session:open', sess);
}

function closeSession(id) {
  db.closeSession(id);
  emitter.emit('session:close', { id });
}

function setSessionUsername(id, username) {
  db.setSessionUsername(id, username);
}

function commandLogged(sessionId) {
  db.incrementSessionCommands(sessionId);
}

module.exports = {
  configure,
  log,
  openSession,
  closeSession,
  setSessionUsername,
  commandLogged,
  on: (evt, cb) => emitter.on(evt, cb),
  off: (evt, cb) => emitter.off(evt, cb)
};
