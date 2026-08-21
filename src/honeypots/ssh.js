'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Server: SSHServer, utils: sshUtils } = require('ssh2');
const shell = require('./ssh_shell');

const KEY_DIR = path.join(__dirname, '..', '..', 'data', 'keys');
const KEY_PATH = path.join(KEY_DIR, 'ssh_host_rsa_key');

function ensureHostKey() {
  fs.mkdirSync(KEY_DIR, { recursive: true });
  if (fs.existsSync(KEY_PATH)) return fs.readFileSync(KEY_PATH);
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
  fs.writeFileSync(KEY_PATH, privateKey, { mode: 0o600 });
  return privateKey;
}

class SshHoneypot {
  constructor(cfg, logger) {
    this.cfg = cfg;
    this.logger = logger;
    this.hostKey = ensureHostKey();
    this.server = null;
    this.clients = new Set();
  }

  updateConfig(cfg) { this.cfg = cfg; }

  _shouldAccept(username, password) {
    const fa = this.cfg.fakeAuth || {};
    if ((fa.rejectAlwaysUsernames || []).includes(username)) return false;
    if ((fa.acceptedPasswords || []).length && fa.acceptedPasswords.includes(password)) return true;
    if ((fa.acceptedUsernames || []).includes(username)) {
      if (fa.mode === 'always') return true;
      if (fa.mode === 'random') {
        return Math.random() < (typeof fa.acceptProbability === 'number' ? fa.acceptProbability : 0.15);
      }
      if (fa.mode === 'first-attempt') return true;
    }
    if (fa.mode === 'random-any') {
      return Math.random() < (typeof fa.acceptProbability === 'number' ? fa.acceptProbability : 0.05);
    }
    return false;
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = new SSHServer(
        {
          hostKeys: [this.hostKey],
          banner: undefined,
          ident: this.cfg.banner || undefined
        },
        (client, info) => this._handleClient(client, info)
      );
      this.server.on('error', reject);
      this.server.listen(this.cfg.port, '0.0.0.0', () => {
        this.server.off('error', reject);
        this.server.on('error', (err) => {
          this.logger.log({ service: 'ssh', type: 'server_error', details: { error: err.message } });
        });
        resolve();
      });
    });
  }

  _handleClient(client, info) {
    const meta = {
      remoteIp: info?.ip || client._sock?.remoteAddress?.replace(/^::ffff:/, '') || null,
      remotePort: client._sock?.remotePort || null,
      localPort: this.cfg.port
    };
    const sessionId = crypto.randomBytes(8).toString('hex');
    this.clients.add(client);

    this.logger.log({
      service: 'ssh',
      type: 'connection',
      sessionId,
      ...meta,
      details: { header: info?.header || null }
    });
    this.logger.openSession({ id: sessionId, service: 'ssh', ...meta });

    let authedUser = null;

    client.on('authentication', (ctx) => {
      const detailBase = {
        service: 'ssh',
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        sessionId,
        username: ctx.username
      };
      if (ctx.method === 'password') {
        this.logger.log({
          ...detailBase,
          type: 'auth_attempt',
          password: ctx.password,
          details: { method: 'password' }
        });
        if (this._shouldAccept(ctx.username, ctx.password)) {
          authedUser = ctx.username;
          this.logger.setSessionUsername(sessionId, ctx.username);
          this.logger.log({
            ...detailBase,
            type: 'auth_success',
            password: ctx.password,
            details: { method: 'password' }
          });
          return ctx.accept();
        }
        return ctx.reject(['password', 'publickey', 'keyboard-interactive'], false);
      }
      if (ctx.method === 'publickey') {
        const fp = ctx.key && sshUtils.parseKey(ctx.key.data)?.getPublicSSH?.().toString('base64').slice(0, 32);
        this.logger.log({
          ...detailBase,
          type: 'auth_attempt',
          details: { method: 'publickey', algo: ctx.key?.algo, fingerprint: fp }
        });
        return ctx.reject(['password'], false);
      }
      if (ctx.method === 'keyboard-interactive') {
        this.logger.log({ ...detailBase, type: 'auth_attempt', details: { method: 'keyboard-interactive' } });
        return ctx.prompt([{ prompt: 'Password: ', echo: false }], (answers) => {
          const password = answers?.[0] || '';
          this.logger.log({
            ...detailBase,
            type: 'auth_attempt',
            password,
            details: { method: 'keyboard-interactive-response' }
          });
          if (this._shouldAccept(ctx.username, password)) {
            authedUser = ctx.username;
            this.logger.setSessionUsername(sessionId, ctx.username);
            this.logger.log({
              ...detailBase,
              type: 'auth_success',
              password,
              details: { method: 'keyboard-interactive' }
            });
            return ctx.accept();
          }
          return ctx.reject(['password'], false);
        });
      }
      this.logger.log({ ...detailBase, type: 'auth_attempt', details: { method: ctx.method } });
      ctx.reject(['password'], false);
    });

    client.on('ready', () => {
      this.logger.log({
        service: 'ssh',
        type: 'authenticated',
        sessionId,
        ...meta,
        username: authedUser
      });

      client.on('session', (accept) => {
        const session = accept();
        this._handleSession(session, { ...meta, sessionId, username: authedUser });
      });
    });

    client.on('error', () => { /* keep quiet on protocol errors */ });

    client.on('close', () => {
      this.clients.delete(client);
      this.logger.log({
        service: 'ssh',
        type: 'connection_closed',
        sessionId,
        ...meta,
        username: authedUser
      });
      this.logger.closeSession(sessionId);
    });
  }

  _handleSession(session, meta) {
    let ptyInfo = null;
    session.on('pty', (accept, _reject, info) => { ptyInfo = info; accept(); });
    session.on('env', (accept, _reject, info) => {
      this.logger.log({
        service: 'ssh',
        type: 'env',
        sessionId: meta.sessionId,
        username: meta.username,
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        details: { key: info.key, value: info.value }
      });
      accept?.();
    });

    session.on('shell', (accept) => {
      const stream = accept();
      const env = shell.buildEnv({ ...this.cfg.shell, username: meta.username });

      const motd = (this.cfg.shell?.motd || '').replace(/\$\(date[^)]*\)/g, () => new Date().toString());
      if (motd) stream.write(motd.replace(/\n/g, '\r\n') + '\r\n');
      stream.write(shell.prompt(env));

      let buf = '';
      stream.on('data', (data) => {
        const str = data.toString('utf8');
        for (const ch of str) {
          const code = ch.charCodeAt(0);
          if (ch === '\r' || ch === '\n') {
            stream.write('\r\n');
            const command = buf;
            buf = '';
            if (command.trim().length) {
              this.logger.log({
                service: 'ssh',
                type: 'command',
                sessionId: meta.sessionId,
                username: meta.username,
                remoteIp: meta.remoteIp,
                remotePort: meta.remotePort,
                localPort: meta.localPort,
                command
              });
              this.logger.commandLogged(meta.sessionId);
              const out = shell.runCommand(command, env);
              if (out && typeof out === 'object' && out.exit) {
                stream.write('logout\r\n');
                try { stream.exit(0); } catch { /* noop */ }
                try { stream.end(); } catch { /* noop */ }
                return;
              }
              if (typeof out === 'string' && out.length) {
                stream.write(out.replace(/\n/g, '\r\n'));
              }
            }
            stream.write(shell.prompt(env));
          } else if (code === 127 || code === 8) {
            if (buf.length > 0) { buf = buf.slice(0, -1); stream.write('\b \b'); }
          } else if (code === 3) {
            stream.write('^C\r\n');
            buf = '';
            stream.write(shell.prompt(env));
          } else if (code === 4) {
            if (!buf.length) {
              stream.write('logout\r\n');
              try { stream.exit(0); } catch { /* noop */ }
              try { stream.end(); } catch { /* noop */ }
              return;
            }
          } else if (code === 9) {
            stream.write('\x07');
          } else if (code >= 32 && code < 127) {
            buf += ch;
            stream.write(ch);
          }
        }
      });
      stream.on('close', () => { /* noop */ });
    });

    session.on('exec', (accept, _reject, info) => {
      this.logger.log({
        service: 'ssh',
        type: 'exec',
        sessionId: meta.sessionId,
        username: meta.username,
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        command: info.command
      });
      this.logger.commandLogged(meta.sessionId);
      const stream = accept();
      const env = shell.buildEnv({ ...this.cfg.shell, username: meta.username });
      const out = shell.runCommand(info.command, env);
      if (typeof out === 'string' && out.length) stream.write(out);
      stream.exit(0);
      stream.end();
    });

    session.on('subsystem', (accept, reject, info) => {
      this.logger.log({
        service: 'ssh',
        type: 'subsystem',
        sessionId: meta.sessionId,
        username: meta.username,
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        details: { name: info.name }
      });
      reject();
    });
  }

  stop() {
    return new Promise((resolve) => {
      for (const c of this.clients) try { c.end(); } catch { /* noop */ }
      this.clients.clear();
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }
}

module.exports = {
  create: (cfg, logger) => new SshHoneypot(cfg, logger)
};
