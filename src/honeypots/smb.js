'use strict';

const { TcpHoneypot } = require('./base');

// Not a real SMB implementation, but enough to log the negotiation
// request and reject the connection cleanly.
class SmbHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'smb', port: cfg.port }, logger);
  }

  onConnection(socket, meta) {
    let received = Buffer.alloc(0);
    socket.on('data', (data) => {
      received = Buffer.concat([received, data]).slice(0, 8192);
      this.logger.log({
        service: 'smb',
        type: 'payload',
        sessionId: meta.sessionId,
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        details: {
          hex: received.slice(0, 128).toString('hex'),
          length: received.length,
          looksSmb2: received.length >= 8 && received[4] === 0xfe && received.slice(5, 8).toString() === 'SMB'
        }
      });
      try { socket.end(); } catch { /* noop */ }
    });
  }
}

module.exports = { create: (cfg, logger) => new SmbHoneypot(cfg, logger) };
