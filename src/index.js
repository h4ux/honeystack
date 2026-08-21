#!/usr/bin/env node
'use strict';

const path = require('path');
const config = require('./config');
const db = require('./db');
const logger = require('./logger');
const manager = require('./manager');
const dashboard = require('./dashboard/server');

async function main() {
  const cfg = config.load();
  db.init(cfg.storage.databaseFile);
  logger.configure({ maxLogRows: cfg.storage.maxLogRows });

  const runtime = { cfg };

  await manager.syncFromConfig(cfg);
  await dashboard.start(cfg, {
    manager,
    onConfigUpdate: async (newCfg) => {
      runtime.cfg = newCfg;
      config.save(newCfg);
      await manager.syncFromConfig(newCfg);
    },
    getConfig: () => runtime.cfg
  });

  logger.log({ service: 'system', type: 'startup', details: { pid: process.pid, cwd: process.cwd() } });

  const shutdown = async (signal) => {
    console.log(`\n[system] received ${signal}, shutting down…`);
    logger.log({ service: 'system', type: 'shutdown', details: { signal } });
    try { await manager.stopAll(); } catch { /* noop */ }
    try { await dashboard.stop(); } catch { /* noop */ }
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  process.on('uncaughtException', (err) => {
    console.error('[uncaughtException]', err);
    logger.log({ service: 'system', type: 'uncaught_exception', details: { message: err.message, stack: err.stack } });
  });
  process.on('unhandledRejection', (err) => {
    console.error('[unhandledRejection]', err);
    logger.log({ service: 'system', type: 'unhandled_rejection', details: { message: String(err) } });
  });
}

main().catch((err) => {
  console.error('[fatal]', err);
  process.exit(1);
});
