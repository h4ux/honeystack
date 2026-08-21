'use strict';

const { TcpHoneypot } = require('./base');

class TelnetHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'telnet', port: cfg.port }, logger);
    this.cfg = cfg;
  }

  updateConfig(cfg) { this.cfg = cfg; }

  onConnection(socket, meta) {
    let stage = 'user';
    let username = '';
    let attempts = 0;
    let buf = '';

    const send = (s) => { try { socket.write(s); } catch { /* noop */ } };
    // Negotiate: WILL ECHO, WILL SUPPRESS-GA
    send(Buffer.from([0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03]));
    send(this.cfg.banner || '\r\nUbuntu 22.04 LTS\r\nlogin: ');

    socket.on('data', (data) => {
      // Strip telnet negotiation bytes
      const clean = stripTelnet(data).toString('utf8');
      for (const ch of clean) {
        if (ch === '\r' || ch === '\n') {
          if (!buf.length && stage === 'user') { send(''); continue; }
          if (stage === 'user') {
            username = buf;
            buf = '';
            send('\r\nPassword: ');
            stage = 'password';
          } else if (stage === 'password') {
            const password = buf;
            buf = '';
            attempts += 1;
            this.logger.log({
              service: 'telnet',
              type: 'login_attempt',
              sessionId: meta.sessionId,
              remoteIp: meta.remoteIp,
              remotePort: meta.remotePort,
              localPort: meta.localPort,
              username,
              password
            });
            if (attempts >= 3) {
              send('\r\nLogin incorrect. Too many failures.\r\n');
              try { socket.end(); } catch { /* noop */ }
              return;
            }
            send('\r\nLogin incorrect\r\nlogin: ');
            stage = 'user';
          }
        } else if (ch === '\x7f' || ch === '\b') {
          buf = buf.slice(0, -1);
        } else if (ch >= ' ' && ch <= '~') {
          buf += ch;
        }
      }
    });
  }
}

function stripTelnet(buf) {
  const out = [];
  let i = 0;
  while (i < buf.length) {
    if (buf[i] === 0xff) {
      const cmd = buf[i + 1];
      if (cmd === 0xff) { out.push(0xff); i += 2; }
      else if (cmd >= 0xfb && cmd <= 0xfe) i += 3;
      else if (cmd === 0xfa) {
        i += 2;
        while (i < buf.length && buf[i] !== 0xf0) i += 1;
        i += 1;
      } else i += 2;
    } else {
      out.push(buf[i]);
      i += 1;
    }
  }
  return Buffer.from(out);
}

module.exports = { create: (cfg, logger) => new TelnetHoneypot(cfg, logger) };
