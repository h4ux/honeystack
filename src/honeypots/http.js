'use strict';

const http = require('http');
const crypto = require('crypto');

class HttpHoneypot {
  constructor(cfg, logger) {
    this.cfg = cfg;
    this.logger = logger;
    this.server = null;
  }

  updateConfig(cfg) { this.cfg = cfg; }

  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this._handle(req, res));
      this.server.on('error', reject);
      this.server.listen(this.cfg.port, '0.0.0.0', () => {
        this.server.off('error', reject);
        this.server.on('error', (err) => {
          this.logger.log({ service: 'http', type: 'server_error', details: { error: err.message } });
        });
        resolve();
      });
    });
  }

  _handle(req, res) {
    const sessionId = crypto.randomBytes(6).toString('hex');
    const meta = {
      service: 'http',
      remoteIp: req.socket.remoteAddress?.replace(/^::ffff:/, '') || null,
      remotePort: req.socket.remotePort || null,
      localPort: this.cfg.port,
      sessionId
    };

    const chunks = [];
    let bodySize = 0;
    req.on('data', (c) => {
      bodySize += c.length;
      if (bodySize <= 65536) chunks.push(c);
    });
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8').slice(0, 65536);
      const parsedBody = safeParseBody(body, req.headers['content-type']);

      const isLogin = req.url.startsWith(this.cfg.loginPagePath || '/login') && req.method === 'POST';
      const attempt = parsedBody && (parsedBody.username || parsedBody.user || parsedBody.email || parsedBody.login);
      const password = parsedBody && (parsedBody.password || parsedBody.pass || parsedBody.passwd);

      this.logger.log({
        ...meta,
        type: isLogin && attempt ? 'login_attempt' : 'request',
        command: `${req.method} ${req.url}`,
        username: attempt || null,
        password: password || null,
        details: {
          method: req.method,
          url: req.url,
          headers: req.headers,
          body: body.length ? body.slice(0, 4096) : null
        }
      });

      res.setHeader('Server', this.cfg.serverHeader || 'Apache/2.4.52 (Ubuntu)');
      res.setHeader('Content-Type', 'text/html; charset=UTF-8');

      if (req.url === '/' || req.url === '/index.html' || req.url === '/index.php') {
        res.writeHead(200);
        return res.end(renderHome());
      }
      if (req.url.startsWith(this.cfg.loginPagePath || '/login')) {
        res.writeHead(isLogin ? 401 : 200);
        return res.end(renderLogin(isLogin ? 'Invalid credentials.' : null));
      }
      if (req.url === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n');
      }
      if (/\/wp-login\.php|\/wp-admin|\/administrator|\/phpmyadmin/.test(req.url)) {
        res.writeHead(200);
        return res.end(renderLogin(null));
      }
      res.writeHead(404);
      res.end('<!doctype html><title>404 Not Found</title><h1>Not Found</h1><p>The requested URL was not found on this server.</p>');
    });
  }

  stop() {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }
}

function safeParseBody(body, contentType) {
  if (!body) return null;
  const ct = (contentType || '').toLowerCase();
  try {
    if (ct.includes('application/json')) return JSON.parse(body);
    if (ct.includes('application/x-www-form-urlencoded')) {
      const out = {};
      for (const pair of body.split('&')) {
        const [k, v] = pair.split('=');
        if (!k) continue;
        out[decodeURIComponent(k.replace(/\+/g, ' '))] = decodeURIComponent((v || '').replace(/\+/g, ' '));
      }
      return out;
    }
  } catch { /* ignore parse errors */ }
  return null;
}

function renderHome() {
  return `<!doctype html><html><head><title>Welcome</title></head><body>
<h1>It works!</h1>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<p><a href="/login">Login</a></p>
</body></html>`;
}

function renderLogin(error) {
  return `<!doctype html><html><head><title>Login</title></head><body>
<h2>Sign in</h2>
${error ? `<p style="color:red">${error}</p>` : ''}
<form method="POST" action="/login">
  <label>Username <input name="username" autofocus></label><br>
  <label>Password <input name="password" type="password"></label><br>
  <button type="submit">Log in</button>
</form>
</body></html>`;
}

module.exports = { create: (cfg, logger) => new HttpHoneypot(cfg, logger) };
