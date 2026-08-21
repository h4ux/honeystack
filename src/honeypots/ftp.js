'use strict';

const { TcpHoneypot } = require('./base');

class FtpHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'ftp', port: cfg.port }, logger);
    this.cfg = cfg;
  }

  updateConfig(cfg) { this.cfg = cfg; }

  onConnection(socket, meta) {
    let username = null;
    let buf = '';
    const send = (s) => { try { socket.write(s); } catch { /* noop */ } };

    send(this.cfg.banner || '220 (vsFTPd 3.0.5)\r\n');

    socket.on('data', (data) => {
      buf += data.toString('utf8');
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).replace(/\r$/, '');
        buf = buf.slice(idx + 1);
        this._handleLine(socket, meta, line, (u) => { username = u; }, () => username);
      }
    });
  }

  _handleLine(socket, meta, line, setUser, getUser) {
    const send = (s) => { try { socket.write(s + '\r\n'); } catch { /* noop */ } };
    const spaceIdx = line.indexOf(' ');
    const cmd = (spaceIdx >= 0 ? line.slice(0, spaceIdx) : line).toUpperCase();
    const arg = spaceIdx >= 0 ? line.slice(spaceIdx + 1) : '';

    this.logger.log({
      service: 'ftp',
      type: 'command',
      sessionId: meta.sessionId,
      remoteIp: meta.remoteIp,
      remotePort: meta.remotePort,
      localPort: meta.localPort,
      command: line,
      username: getUser(),
      details: { cmd, arg }
    });

    switch (cmd) {
      case 'USER':
        setUser(arg);
        send('331 Please specify the password.');
        break;
      case 'PASS':
        this.logger.log({
          service: 'ftp',
          type: 'login_attempt',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp,
          remotePort: meta.remotePort,
          localPort: meta.localPort,
          username: getUser(),
          password: arg
        });
        send('530 Login incorrect.');
        break;
      case 'SYST':
        send('215 UNIX Type: L8');
        break;
      case 'FEAT':
        send('211-Features:\r\n PASV\r\n UTF8\r\n211 End');
        break;
      case 'AUTH':
        send('530 Please login with USER and PASS.');
        break;
      case 'QUIT':
        send('221 Goodbye.');
        try { socket.end(); } catch { /* noop */ }
        break;
      default:
        send('530 Please login with USER and PASS.');
    }
  }
}

module.exports = { create: (cfg, logger) => new FtpHoneypot(cfg, logger) };
