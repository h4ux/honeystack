'use strict';

const http = require('http');
const path = require('path');
const express = require('express');
const { Server: IoServer } = require('socket.io');
const db = require('../db');
const logger = require('../logger');

let server;
let io;
let app;

function basicAuth(username, password) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Basic ')) return challenge(res);
    let decoded;
    try { decoded = Buffer.from(header.slice(6), 'base64').toString('utf8'); }
    catch { return challenge(res); }
    const idx = decoded.indexOf(':');
    if (idx < 0) return challenge(res);
    const u = decoded.slice(0, idx);
    const p = decoded.slice(idx + 1);
    if (u === username && p === password) return next();
    return challenge(res);
  };
}

function challenge(res) {
  res.setHeader('WWW-Authenticate', 'Basic realm="honeypot"');
  res.status(401).send('Authentication required');
}

async function start(cfg, ctx) {
  app = express();
  app.use(express.json({ limit: '256kb' }));

  const bindHost = cfg.dashboard.bindLoopbackOnly ? '127.0.0.1' : (cfg.dashboard.host || '0.0.0.0');
  const auth = basicAuth(cfg.dashboard.username, cfg.dashboard.password);

  app.use('/api', auth);
  app.use('/', auth);

  app.get('/api/config', (_req, res) => res.json(ctx.getConfig()));

  app.put('/api/config', async (req, res) => {
    const newCfg = req.body;
    if (!newCfg || typeof newCfg !== 'object') return res.status(400).json({ error: 'invalid config' });
    try {
      await ctx.onConfigUpdate(newCfg);
      res.json(ctx.getConfig());
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/services', (_req, res) => res.json(ctx.manager.list()));

  app.get('/api/events', (req, res) => {
    const events = db.getRecentEvents({
      limit: Math.min(Number(req.query.limit) || 200, 2000),
      service: req.query.service || undefined,
      ip: req.query.ip || undefined,
      type: req.query.type || undefined,
      sessionId: req.query.sessionId || undefined
    });
    res.json({ events });
  });

  app.get('/api/sessions', (req, res) => {
    const sessions = db.getSessions({
      limit: Math.min(Number(req.query.limit) || 100, 500),
      service: req.query.service || undefined
    });
    res.json({ sessions });
  });

  app.get('/api/sessions/:id', (req, res) => {
    const s = db.getSession(req.params.id);
    if (!s) return res.status(404).json({ error: 'not found' });
    res.json(s);
  });

  app.get('/api/stats', (_req, res) => res.json(db.getStats()));

  app.use(express.static(path.join(__dirname, '..', '..', 'public')));

  server = http.createServer(app);
  io = new IoServer(server, { cors: { origin: '*' } });

  io.use((socket, next) => {
    const auth = socket.handshake.auth || {};
    if (auth.username === cfg.dashboard.username && auth.password === cfg.dashboard.password) return next();
    // Allow same-origin from the dashboard page (which already passed HTTP auth) via cookie-less handshake.
    const header = socket.handshake.headers.authorization || '';
    if (header.startsWith('Basic ')) {
      try {
        const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx >= 0 && decoded.slice(0, idx) === cfg.dashboard.username && decoded.slice(idx + 1) === cfg.dashboard.password) {
          return next();
        }
      } catch { /* ignore */ }
    }
    next(new Error('unauthorized'));
  });

  const forward = (evt, payload) => io.emit(evt, payload);
  logger.on('event', (evt) => forward('event', evt));
  logger.on('session:open', (s) => forward('session:open', s));
  logger.on('session:close', (s) => forward('session:close', s));

  await new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(cfg.dashboard.port, bindHost, () => {
      server.off('error', reject);
      resolve();
    });
  });
  console.log(`[dashboard] listening on http://${bindHost}:${cfg.dashboard.port}`);
}

async function stop() {
  if (io) await new Promise((r) => io.close(() => r()));
  if (server) await new Promise((r) => server.close(() => r()));
}

module.exports = { start, stop };
