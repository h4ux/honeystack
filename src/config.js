'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULTS_PATH = path.join(__dirname, '..', 'config.default.json');
const USER_PATH = process.env.HONEYPOT_CONFIG || path.join(__dirname, '..', 'config.json');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function deepMerge(target, source) {
  if (Array.isArray(source)) return source.slice();
  if (source && typeof source === 'object') {
    const out = { ...(target && typeof target === 'object' ? target : {}) };
    for (const k of Object.keys(source)) out[k] = deepMerge(out[k], source[k]);
    return out;
  }
  return source;
}

function load() {
  const defaults = readJson(DEFAULTS_PATH);
  let user = {};
  if (fs.existsSync(USER_PATH)) {
    try { user = readJson(USER_PATH); }
    catch (err) { console.error('[config] failed to parse user config, using defaults:', err.message); }
  } else {
    fs.writeFileSync(USER_PATH, JSON.stringify(defaults, null, 2));
    user = defaults;
  }
  return deepMerge(defaults, user);
}

function save(cfg) {
  fs.writeFileSync(USER_PATH, JSON.stringify(cfg, null, 2));
}

function path_() { return USER_PATH; }

module.exports = { load, save, path: path_ };
