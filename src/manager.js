'use strict';

const logger = require('./logger');

const registry = {
  ssh: require('./honeypots/ssh'),
  telnet: require('./honeypots/telnet'),
  ftp: require('./honeypots/ftp'),
  http: require('./honeypots/http'),
  rdp: require('./honeypots/rdp'),
  mysql: require('./honeypots/mysql'),
  vnc: require('./honeypots/vnc'),
  smb: require('./honeypots/smb'),
  redis: require('./honeypots/redis'),
  postgres: require('./honeypots/postgres')
};

class Manager {
  constructor() {
    this.instances = new Map();
    this.status = new Map();
  }

  list() {
    return Object.keys(registry).map((name) => ({
      name,
      running: this.status.get(name)?.running || false,
      port: this.status.get(name)?.port || null,
      error: this.status.get(name)?.error || null
    }));
  }

  async syncFromConfig(cfg) {
    for (const [name, factory] of Object.entries(registry)) {
      const svcCfg = cfg.services[name] || {};
      const running = this.instances.has(name);
      if (svcCfg.enabled && !running) await this.start(name, svcCfg);
      else if (!svcCfg.enabled && running) await this.stop(name);
      else if (svcCfg.enabled && running) {
        // Restart if the port or key options changed
        const st = this.status.get(name);
        if (st.port !== svcCfg.port) {
          await this.stop(name);
          await this.start(name, svcCfg);
        } else {
          this.instances.get(name).updateConfig?.(svcCfg);
        }
      }
    }
  }

  async start(name, svcCfg) {
    const factory = registry[name];
    if (!factory) throw new Error(`Unknown service: ${name}`);
    try {
      const instance = await factory.create(svcCfg, logger);
      await instance.start();
      this.instances.set(name, instance);
      this.status.set(name, { running: true, port: svcCfg.port, error: null });
      logger.log({ service: 'system', type: 'service_started', details: { name, port: svcCfg.port } });
    } catch (err) {
      this.status.set(name, { running: false, port: svcCfg.port, error: err.message });
      logger.log({ service: 'system', type: 'service_error', details: { name, error: err.message } });
    }
  }

  async stop(name) {
    const instance = this.instances.get(name);
    if (!instance) return;
    try {
      await instance.stop();
    } catch (err) {
      console.error(`[manager] error stopping ${name}:`, err.message);
    }
    this.instances.delete(name);
    this.status.set(name, { running: false, port: null, error: null });
    logger.log({ service: 'system', type: 'service_stopped', details: { name } });
  }

  async stopAll() {
    for (const name of Array.from(this.instances.keys())) await this.stop(name);
  }
}

module.exports = new Manager();
