'use strict';

const { TcpHoneypot } = require('./base');

class VncHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'vnc', port: cfg.port }, logger);
    this.cfg = cfg;
  }

  onConnection(socket, meta) {
    let stage = 'version';
    let challenge = null;
    const send = (b) => { try { socket.write(b); } catch { /* noop */ } };
    send(Buffer.from(this.cfg.banner || 'RFB 003.008\n'));

    socket.on('data', (data) => {
      if (stage === 'version') {
        this.logger.log({
          service: 'vnc', type: 'client_version',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp, remotePort: meta.remotePort, localPort: meta.localPort,
          details: { version: data.toString('utf8').trim() }
        });
        // Offer VNC Authentication only
        send(Buffer.from([0x01, 0x02]));
        stage = 'sec';
        return;
      }
      if (stage === 'sec') {
        if (data[0] === 0x02) {
          challenge = require('crypto').randomBytes(16);
          send(challenge);
          stage = 'challenge';
        } else {
          try { socket.end(); } catch { /* noop */ }
        }
        return;
      }
      if (stage === 'challenge') {
        this.logger.log({
          service: 'vnc', type: 'auth_attempt',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp, remotePort: meta.remotePort, localPort: meta.localPort,
          details: {
            challengeHex: challenge?.toString('hex') || null,
            responseHex: data.slice(0, 16).toString('hex')
          }
        });
        send(Buffer.from([0x00, 0x00, 0x00, 0x01])); // failed
        try { socket.end(); } catch { /* noop */ }
      }
    });
  }
}

module.exports = { create: (cfg, logger) => new VncHoneypot(cfg, logger) };
