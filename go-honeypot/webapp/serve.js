#!/usr/bin/env node
/*
 * serve.js — zero-dependency static file server for the honeypot webapp,
 * with a built-in WebSocket proxy to the Go control API.
 *
 *   node serve.js [--port 5173] [--host 127.0.0.1]
 *                 [--api-host 127.0.0.1] [--api-port 9090]
 *                 [--key-file ../server/data/auth.key]
 *
 * Why the proxy: browsers refuse plain ws:// from an https:// page, and
 * when you reach this page through a tunnel/port-forward, "127.0.0.1" in
 * the connect form means *your* machine, not the honeypot host. Proxying
 * /api through this same origin means only one port has to be reachable
 * and the scheme always matches the page (ws:// or wss://).
 */
'use strict';

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const url = require('url');

const argv = process.argv.slice(2);
function arg(name, def) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : def;
}

const port = Number(process.env.PORT || arg('--port', 5173));
const host = process.env.HOST || arg('--host', '127.0.0.1');
const apiHost = process.env.API_HOST || arg('--api-host', '127.0.0.1');
const apiPort = Number(process.env.API_PORT || arg('--api-port', 9090));
const keyFile = process.env.KEY_FILE ||
  arg('--key-file', path.join(__dirname, '..', 'server', 'data', 'auth.key'));
const root = __dirname;

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png'
};

function readAuthKey() {
  try {
    return fs.readFileSync(keyFile, 'utf8').trim() || null;
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = decodeURIComponent(parsed.pathname || '/');

  // Tells the page it can connect through this origin, and hands it the
  // auth key when the key file is readable (local runs), so there is
  // nothing to copy/paste.
  if (pathname === '/__meta') {
    const body = JSON.stringify({
      proxy: true,
      apiHost,
      apiPort,
      authKey: readAuthKey()
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(body);
  }

  // Non-upgrade hits on /api (e.g. a health probe) get proxied too.
  if (pathname === '/api' || pathname === '/health') {
    const proxyReq = http.request(
      { host: apiHost, port: apiPort, path: req.url, method: req.method, headers: req.headers },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );
    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('control API unreachable at ' + apiHost + ':' + apiPort + ' — ' + err.message);
    });
    return req.pipe(proxyReq);
  }

  let filePath = path.normalize(path.join(root, pathname));
  if (!filePath.startsWith(root)) {
    res.writeHead(403);
    return res.end('forbidden');
  }
  // Vercel injects these at the edge; locally they do not exist and must
  // not fall through to index.html, or the browser parses HTML as JS.
  if (pathname.startsWith('/_vercel/')) {
    res.writeHead(204);
    return res.end();
  }
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      if (!err && stat.isDirectory()) {
        return sendFile(res, path.join(filePath, 'index.html'));
      }
      return sendFile(res, path.join(root, 'index.html'));
    }
    sendFile(res, filePath);
  });
});

// Raw WebSocket proxy: replay the handshake to the control API, then
// pipe bytes both ways.
server.on('upgrade', (req, socket, head) => {
  if (!(req.url || '').startsWith('/api')) {
    socket.destroy();
    return;
  }
  const upstream = net.connect(apiPort, apiHost, () => {
    let raw = `GET ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      let value = req.rawHeaders[i + 1];
      if (name.toLowerCase() === 'host') value = `${apiHost}:${apiPort}`;
      raw += `${name}: ${value}\r\n`;
    }
    raw += '\r\n';
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
});

server.listen(port, host, () => {
  const shown = host === '0.0.0.0' ? '127.0.0.1' : host;
  console.log(`honeypot webapp : http://${shown}:${port}/`);
  console.log(`control API     : ${apiHost}:${apiPort} (proxied at /api on this origin)`);
  console.log(readAuthKey()
    ? `auth key        : loaded from ${keyFile} (the page will prefill it)`
    : `auth key        : ${keyFile} not readable — paste the key manually`);
});

function sendFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('not found');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}
