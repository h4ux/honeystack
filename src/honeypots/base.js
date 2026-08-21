'use strict';

const net = require('net');
const crypto = require('crypto');

class TcpHoneypot {
  constructor({ name, port, host = '0.0.0.0' }, logger) {
    this.name = name;
    this.port = port;
    this.host = host;
    this.logger = logger;
    this.server = null;
    this.connections = new Set();
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this._wrap(socket));
      this.server.on('error', reject);
      this.server.listen(this.port, this.host, () => {
        this.server.off('error', reject);
        this.server.on('error', (err) => {
          this.logger.log({ service: this.name, type: 'server_error', details: { error: err.message } });
        });
        resolve();
      });
    });
  }

  _wrap(socket) {
    const meta = {
      remoteIp: socket.remoteAddress?.replace(/^::ffff:/, '') || null,
      remotePort: socket.remotePort || null,
      localPort: this.port
    };
    const sessionId = crypto.randomBytes(8).toString('hex');
    socket.setKeepAlive(false);
    socket.setTimeout(60000);
    socket.on('timeout', () => {
      try { socket.end(); } catch { /* noop */ }
    });
    socket.on('error', () => { /* swallow noisy resets */ });

    this.connections.add(socket);
    socket.on('close', () => {
      this.connections.delete(socket);
      this.logger.log({
        service: this.name,
        type: 'connection_closed',
        sessionId,
        ...meta
      });
    });

    this.logger.log({
      service: this.name,
      type: 'connection',
      sessionId,
      ...meta
    });

    try {
      this.onConnection(socket, { ...meta, sessionId });
    } catch (err) {
      this.logger.log({
        service: this.name,
        type: 'handler_error',
        sessionId,
        ...meta,
        details: { error: err.message }
      });
      try { socket.destroy(); } catch { /* noop */ }
    }
  }

  onConnection(_socket, _meta) {
    // Override in subclass
  }

  stop() {
    return new Promise((resolve) => {
      for (const s of this.connections) {
        try { s.destroy(); } catch { /* noop */ }
      }
      this.connections.clear();
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  updateConfig(_cfg) { /* optional */ }
}

module.exports = { TcpHoneypot };
