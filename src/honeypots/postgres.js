'use strict';

const { TcpHoneypot } = require('./base');

class PostgresHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'postgres', port: cfg.port }, logger);
  }

  onConnection(socket, meta) {
    let buf = Buffer.alloc(0);
    const send = (b) => { try { socket.write(b); } catch { /* noop */ } };

    socket.on('data', (data) => {
      buf = Buffer.concat([buf, data]).slice(0, 8192);
      if (buf.length < 8) return;

      // SSLRequest is 8 bytes: length=8, code=80877103
      if (buf.length >= 8 && buf.readUInt32BE(0) === 8 && buf.readUInt32BE(4) === 80877103) {
        send(Buffer.from('N'));
        buf = buf.slice(8);
        return;
      }

      const len = buf.readUInt32BE(0);
      if (buf.length < len) return;

      const payload = buf.slice(4, len);
      if (payload.length >= 4 && payload.readUInt32BE(0) === 196608) {
        // StartupMessage: parse null-terminated key/value pairs
        const params = {};
        let off = 4;
        while (off < payload.length) {
          const kEnd = payload.indexOf(0x00, off);
          if (kEnd < 0) break;
          const key = payload.slice(off, kEnd).toString('utf8');
          off = kEnd + 1;
          const vEnd = payload.indexOf(0x00, off);
          if (vEnd < 0) break;
          const value = payload.slice(off, vEnd).toString('utf8');
          off = vEnd + 1;
          if (!key) break;
          params[key] = value;
        }
        this.logger.log({
          service: 'postgres',
          type: 'login_attempt',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp,
          remotePort: meta.remotePort,
          localPort: meta.localPort,
          username: params.user || null,
          details: { params }
        });
        const err = buildError('FATAL', '28P01', `password authentication failed for user "${params.user || 'unknown'}"`);
        send(err);
        try { socket.end(); } catch { /* noop */ }
      }
      buf = Buffer.alloc(0);
    });
  }
}

function buildError(severity, code, message) {
  const fields = Buffer.concat([
    Buffer.from('S' + severity + '\0', 'binary'),
    Buffer.from('C' + code + '\0', 'binary'),
    Buffer.from('M' + message + '\0', 'binary'),
    Buffer.from([0x00])
  ]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(fields.length + 4, 0);
  return Buffer.concat([Buffer.from('E'), len, fields]);
}

module.exports = { create: (cfg, logger) => new PostgresHoneypot(cfg, logger) };
