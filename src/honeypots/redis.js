'use strict';

const { TcpHoneypot } = require('./base');

class RedisHoneypot extends TcpHoneypot {
  constructor(cfg, logger) {
    super({ name: 'redis', port: cfg.port }, logger);
  }

  onConnection(socket, meta) {
    let buf = '';
    const send = (s) => { try { socket.write(s); } catch { /* noop */ } };

    socket.on('data', (data) => {
      buf += data.toString('utf8');
      const commands = parseRespCommands(buf);
      buf = commands.remainder;
      for (const cmd of commands.list) {
        const upper = cmd[0]?.toUpperCase() || '';
        this.logger.log({
          service: 'redis',
          type: upper === 'AUTH' ? 'login_attempt' : 'command',
          sessionId: meta.sessionId,
          remoteIp: meta.remoteIp,
          remotePort: meta.remotePort,
          localPort: meta.localPort,
          command: cmd.join(' '),
          username: upper === 'AUTH' ? (cmd.length > 2 ? cmd[1] : 'default') : null,
          password: upper === 'AUTH' ? (cmd.length > 2 ? cmd[2] : cmd[1]) : null
        });
        if (upper === 'AUTH') {
          send('-WRONGPASS invalid username-password pair or user is disabled.\r\n');
        } else if (upper === 'PING') {
          send('+PONG\r\n');
        } else if (upper === 'QUIT') {
          send('+OK\r\n');
          try { socket.end(); } catch { /* noop */ }
        } else {
          send('-NOAUTH Authentication required.\r\n');
        }
      }
    });
  }
}

function parseRespCommands(input) {
  const list = [];
  let i = 0;
  while (i < input.length) {
    const start = i;
    if (input[i] === '*') {
      const nl = input.indexOf('\r\n', i);
      if (nl < 0) break;
      const count = parseInt(input.slice(i + 1, nl), 10);
      i = nl + 2;
      const parts = [];
      let ok = true;
      for (let n = 0; n < count; n += 1) {
        if (input[i] !== '$') { ok = false; break; }
        const nl2 = input.indexOf('\r\n', i);
        if (nl2 < 0) { ok = false; break; }
        const len = parseInt(input.slice(i + 1, nl2), 10);
        i = nl2 + 2;
        if (input.length < i + len + 2) { ok = false; break; }
        parts.push(input.slice(i, i + len));
        i += len + 2;
      }
      if (!ok) { i = start; break; }
      list.push(parts);
    } else {
      // inline command
      const nl = input.indexOf('\r\n', i);
      if (nl < 0) break;
      const parts = input.slice(i, nl).split(/\s+/).filter(Boolean);
      if (parts.length) list.push(parts);
      i = nl + 2;
    }
  }
  return { list, remainder: input.slice(i) };
}

module.exports = { create: (cfg, logger) => new RedisHoneypot(cfg, logger) };
