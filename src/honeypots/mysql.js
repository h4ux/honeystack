'use strict';

const crypto = require('crypto');
const { TcpHoneypot } = require('./base');

class MysqlHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'mysql', port: cfg.port }, logger);
    this.cfg = cfg;
  }

  updateConfig(cfg) { this.cfg = cfg; }

  onConnection(socket, meta) {
    const version = (this.cfg.serverVersion || '8.0.36') + '\0';
    const threadId = Math.floor(Math.random() * 1e6);
    const salt1 = crypto.randomBytes(8);
    const salt2 = crypto.randomBytes(12);

    const capabilities = 0xffff;
    const capabilitiesUpper = 0x807f;
    const buf = Buffer.concat([
      Buffer.from([0x0a]),
      Buffer.from(version, 'binary'),
      u32le(threadId),
      salt1,
      Buffer.from([0x00]),
      u16le(capabilities & 0xffff),
      Buffer.from([0x21]),
      u16le(0x0002),
      u16le(capabilitiesUpper),
      Buffer.from([0x15]),
      Buffer.alloc(10, 0),
      salt2,
      Buffer.from([0x00])
    ]);
    const packet = Buffer.concat([lengthAndSeq(buf.length, 0), buf]);
    try { socket.write(packet); } catch { /* noop */ }

    let received = Buffer.alloc(0);
    socket.on('data', (data) => {
      received = Buffer.concat([received, data]).slice(0, 8192);
      const parsed = parseHandshakeResponse(received);
      if (parsed && parsed.username) {
        this.logger.log({
          service: 'mysql',
          type: 'login_attempt',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp,
          remotePort: meta.remotePort,
          localPort: meta.localPort,
          username: parsed.username,
          password: parsed.authHex ? '<sha1:' + parsed.authHex + '>' : null,
          details: { database: parsed.database, plugin: parsed.plugin }
        });
        const err = buildErrorPacket(1045, "28000", `Access denied for user '${parsed.username}'@'${meta.remoteIp || 'unknown'}' (using password: YES)`);
        try { socket.write(err); } catch { /* noop */ }
        try { socket.end(); } catch { /* noop */ }
      }
    });
  }
}

function u16le(v) { const b = Buffer.alloc(2); b.writeUInt16LE(v, 0); return b; }
function u32le(v) { const b = Buffer.alloc(4); b.writeUInt32LE(v, 0); return b; }
function lengthAndSeq(len, seq) {
  const b = Buffer.alloc(4);
  b.writeUIntLE(len, 0, 3);
  b[3] = seq;
  return b;
}

function parseHandshakeResponse(buf) {
  if (buf.length < 5) return null;
  const payloadLen = buf.readUIntLE(0, 3);
  if (buf.length < 4 + payloadLen) return null;
  const p = buf.slice(4, 4 + payloadLen);
  if (p.length < 32) return null;
  // clientFlags(4) maxPacket(4) charset(1) reserved(23) username(null-term)
  let off = 32;
  const end = p.indexOf(0x00, off);
  if (end < 0) return null;
  const username = p.slice(off, end).toString('utf8');
  off = end + 1;
  if (off >= p.length) return { username };
  const authLen = p[off];
  off += 1;
  const auth = p.slice(off, off + authLen);
  off += authLen;
  let database = null;
  const dbEnd = p.indexOf(0x00, off);
  if (dbEnd >= 0) database = p.slice(off, dbEnd).toString('utf8');
  return { username, authHex: auth.toString('hex').slice(0, 40), database, plugin: null };
}

function buildErrorPacket(code, sqlState, message) {
  const body = Buffer.concat([
    Buffer.from([0xff]),
    u16le(code),
    Buffer.from('#'),
    Buffer.from(sqlState),
    Buffer.from(message)
  ]);
  return Buffer.concat([lengthAndSeq(body.length, 2), body]);
}

module.exports = { create: (cfg, logger) => new MysqlHoneypot(cfg, logger) };
