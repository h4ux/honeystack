'use strict';

const { TcpHoneypot } = require('./base');

// Emulates the very first bytes of an RDP handshake (X.224 connection
// confirm) so scanners fingerprint the port as RDP. Everything is logged.
class RdpHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'rdp', port: cfg.port }, logger);
  }

  onConnection(socket, meta) {
    let received = Buffer.alloc(0);
    let stage = 0;

    socket.on('data', (data) => {
      received = Buffer.concat([received, data]).slice(0, 4096);
      this.logger.log({
        service: 'rdp',
        type: 'payload',
        sessionId: meta.sessionId,
        remoteIp: meta.remoteIp,
        remotePort: meta.remotePort,
        localPort: meta.localPort,
        details: { hex: received.slice(0, 256).toString('hex'), length: received.length }
      });

      if (stage === 0 && received.length >= 5 && received[0] === 0x03) {
        // Respond with X.224 Connection Confirm and RDP Negotiation Response advertising TLS
        const resp = Buffer.from([
          0x03, 0x00, 0x00, 0x13, // TPKT header, length 0x13
          0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // X.224 CC
          0x02, 0x00, 0x08, 0x00, // RDP_NEG_RSP header
          0x02, 0x00, 0x00, 0x00, // selected protocol: TLS
          0x00, 0x00
        ]);
        try { socket.write(resp); } catch { /* noop */ }
        stage = 1;
        // After the handshake real RDP negotiates TLS; we just linger and
        // log whatever bytes arrive so scanners see an open TCP path.
        return;
      }

      if (stage === 1 && received.length > 512) {
        try { socket.end(); } catch { /* noop */ }
      }
    });
  }
}

module.exports = { create: (cfg, logger) => new RdpHoneypot(cfg, logger) };
