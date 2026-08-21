/* Remote honeypot control webapp. Connects to a Go binary over a
   WebSocket, authenticated with a per-run key. No build step. */
(function () {
  const STORAGE_KEY = 'honeypot-remote-conn-v1';

  const state = {
    ws: null,
    conn: null,
    events: [],
    maxEvents: 500,
    paused: false,
    filter: { service: '', type: '', ip: '' },
    services: [],
    config: null,
    selectedSession: null,
    currentTab: 'live',
    reqSeq: 0,
    pending: new Map(),
    autoReconnect: true,
    reconnectAttempts: 0
  };

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  // ---- Connection UI ----
  const remembered = safeParse(localStorage.getItem(STORAGE_KEY));
  if (remembered) {
    $('#conn-host').value = remembered.host || '';
    $('#conn-port').value = remembered.port || 9090;
    $('#conn-key').value = remembered.key || '';
    $('#conn-secure').checked = !!remembered.secure;
    if (typeof remembered.proxy === 'boolean') $('#conn-proxy').checked = remembered.proxy;
  }

  function syncProxyFields() {
    const useProxy = $('#conn-proxy').checked && !$('#conn-proxy-row').hidden;
    $('#conn-direct-fields').hidden = useProxy;
    $('#conn-secure-row').hidden = useProxy;
    $('#conn-host').required = !useProxy;
    $('#conn-port').required = !useProxy;
  }
  $('#conn-proxy').addEventListener('change', syncProxyFields);
  syncProxyFields();

  // Ask the local server whether it can proxy /api for us. When it can,
  // that is the reliable path: same origin, matching ws/wss scheme, and
  // only one port needs to be reachable.
  fetch('/__meta', { cache: 'no-store' })
    .then((r) => (r.ok ? r.json() : null))
    .then((meta) => {
      if (!meta || !meta.proxy) return;
      $('#conn-proxy-row').hidden = false;
      $('#conn-proxy-hint').textContent = `→ ${meta.apiHost}:${meta.apiPort}`;
      // The key file is authoritative: the daemon rotates the key on every
      // restart, so a remembered value is often stale.
      if (meta.authKey) $('#conn-key').value = meta.authKey;
      syncProxyFields();
      if ($('#conn-key').value) $('#connect-form').requestSubmit();
    })
    .catch(() => {});

  $('#connect-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const conn = {
      proxy: $('#conn-proxy').checked && !$('#conn-proxy-row').hidden,
      host: $('#conn-host').value.trim(),
      port: Number($('#conn-port').value),
      key: $('#conn-key').value.trim(),
      secure: $('#conn-secure').checked
    };
    if ($('#conn-remember').checked) localStorage.setItem(STORAGE_KEY, JSON.stringify(conn));
    else localStorage.removeItem(STORAGE_KEY);
    state.conn = conn;
    state.autoReconnect = true;
    state.reconnectAttempts = 0;
    connect();
  });

  $('#disconnect').addEventListener('click', () => {
    state.autoReconnect = false;
    if (state.ws) state.ws.close();
    showConnectDialog();
  });

  async function connect() {
    if (!state.conn) return showConnectDialog();
    const { host, port, secure, proxy } = state.conn;

    // The daemon rotates its key every time it starts. Refresh it before
    // every proxied connection, including automatic reconnects after a
    // daemon restart, so the page never loops on a stale token.
    if (proxy) {
      try {
        const response = await fetch('/__meta', { cache: 'no-store' });
        const meta = response.ok ? await response.json() : null;
        if (meta?.authKey) {
          state.conn.key = meta.authKey;
          $('#conn-key').value = meta.authKey;
          if ($('#conn-remember').checked) {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state.conn));
          }
        }
      } catch { /* connect below will report the actual socket error */ }
    }
    const key = state.conn.key;

    let url, label;
    if (proxy) {
      // Same origin as this page, so the scheme always matches (an
      // https:// page must use wss://) and no extra port is needed.
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
      url = `${scheme}://${location.host}/api?token=${encodeURIComponent(key)}`;
      label = `${scheme}://${location.host}`;
    } else {
      const scheme = secure ? 'wss' : 'ws';
      url = `${scheme}://${host}:${port}/api?token=${encodeURIComponent(key)}`;
      label = `${scheme}://${host}:${port}`;
    }
    $('#conn-error').textContent = 'Connecting to ' + label + '…';

    // Drop any previous socket, otherwise reconnects stack up and the
    // daemon ends up holding several live clients per tab.
    if (state.ws) {
      const old = state.ws;
      state.ws = null;
      old.onopen = old.onclose = old.onerror = old.onmessage = null;
      try { old.close(); } catch { /* already closing */ }
    }

    let ws;
    try { ws = new WebSocket(url); }
    catch (err) { $('#conn-error').textContent = 'Invalid URL: ' + err.message; return; }
    state.ws = ws;

    ws.addEventListener('open', () => {
      $('#conn-error').textContent = '';
      state.reconnectAttempts = 0;
      hideConnectDialog();
      $('#conn-dot').classList.add('on');
      $('#status-summary').textContent = 'live';
      $('#conn-target').textContent = label;
    });
    ws.addEventListener('close', (ev) => {
      if (state.ws !== ws) return; // superseded by a newer socket
      $('#conn-dot').classList.remove('on');
      $('#status-summary').textContent = 'disconnected';
      const wasConnected = $('#connect-overlay').hidden;
      if (state.autoReconnect && wasConnected) {
        const delay = Math.min(30000, 1000 * Math.pow(2, state.reconnectAttempts++));
        $('#status-summary').textContent = `reconnecting in ${Math.round(delay / 1000)}s`;
        setTimeout(() => { if (state.autoReconnect && state.ws === ws) connect(); }, delay);
      } else {
        showConnectDialog();
        $('#conn-error').textContent = ev.reason ? 'Disconnected: ' + ev.reason : 'Disconnected (code ' + ev.code + ')';
      }
    });
    ws.addEventListener('error', () => {
      $('#conn-error').textContent = proxy
        ? 'WebSocket error — is the honeypot daemon running, and is the auth key current?'
        : 'WebSocket error — check host, port, TLS, and auth key. If this page is served over HTTPS, plain ws:// is blocked; use the proxy option instead.';
    });
    ws.addEventListener('message', (ev) => {
      if (state.ws !== ws) return;
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      // One malformed event must not take the whole dashboard down.
      try { handleMessage(msg); } catch (err) { console.error('handleMessage', err, msg); }
    });
  }

  function showConnectDialog() {
    $('#connect-overlay').hidden = false;
    $('#topbar').hidden = true;
    $('#main').hidden = true;
  }
  function hideConnectDialog() {
    $('#connect-overlay').hidden = true;
    $('#topbar').hidden = false;
    $('#main').hidden = false;
  }

  function send(type, payload) {
    return new Promise((resolve, reject) => {
      if (!state.ws || state.ws.readyState !== 1) return reject(new Error('not connected'));
      const reqId = 'r' + (++state.reqSeq);
      state.pending.set(reqId, { resolve, reject });
      state.ws.send(JSON.stringify({ type, reqId, payload }));
      setTimeout(() => {
        if (state.pending.has(reqId)) {
          state.pending.delete(reqId);
          reject(new Error('timeout waiting for ' + type));
        }
      }, 15000);
    });
  }

  function handleMessage(msg) {
    // Reply to a request?
    if (msg.reqId && state.pending.has(msg.reqId)) {
      const { resolve, reject } = state.pending.get(msg.reqId);
      state.pending.delete(msg.reqId);
      if (msg.error) reject(new Error(msg.error));
      else resolve(msg.payload);
      return;
    }
    switch (msg.type) {
      case 'hello':
        state.config = msg.payload.config;
        state.services = msg.payload.services;
        state.events = msg.payload.events || [];
        for (const e of state.events) updateFilterOptions(e);
        rerenderFeed();
        if (state.currentTab === 'stats') renderStats(msg.payload.stats);
        break;
      case 'event':
        onEvent(msg.payload);
        break;
      case 'error':
        console.warn('server error:', msg.error);
        break;
    }
  }

  function onEvent(evt) {
    if (state.paused) return;
    state.events.push(evt);
    if (state.events.length > state.maxEvents) state.events.shift();
    updateFilterOptions(evt);
    renderNewEvent(evt);
    if (state.currentTab === 'stats') refreshStats();
    if ((evt.service === 'ssh' && (evt.type === 'authenticated' || evt.type === 'connection_closed' || evt.type === 'auth_success')) && state.currentTab === 'sessions') {
      refreshSessions();
    }
  }

  // ---- Tabs ----
  $$('.tab').forEach((btn) => btn.addEventListener('click', () => selectTab(btn.dataset.tab)));
  function selectTab(tab) {
    state.currentTab = tab;
    $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + tab));
    if (tab === 'sessions') refreshSessions();
    if (tab === 'services') refreshServices();
    if (tab === 'config') loadConfig();
    if (tab === 'stats') refreshStats();
  }

  // ---- Live ----
  $('#paused').addEventListener('change', (e) => { state.paused = e.target.checked; });
  $('#clear-feed').addEventListener('click', () => { state.events = []; $('#feed').innerHTML = ''; });
  ['#filter-service', '#filter-type', '#filter-ip'].forEach((sel) =>
    $(sel).addEventListener('input', () => {
      state.filter.service = $('#filter-service').value;
      state.filter.type = $('#filter-type').value;
      state.filter.ip = $('#filter-ip').value.trim();
      rerenderFeed();
    })
  );

  function updateFilterOptions(evt) {
    ensureOption('#filter-service', evt.service);
    ensureOption('#filter-type', evt.type);
  }
  function ensureOption(sel, value) {
    if (!value) return;
    const el = $(sel);
    if (!Array.from(el.options).some((o) => o.value === value)) {
      const opt = document.createElement('option');
      opt.value = value; opt.textContent = value;
      el.appendChild(opt);
    }
  }
  function passesFilter(evt) {
    if (state.filter.service && evt.service !== state.filter.service) return false;
    if (state.filter.type && evt.type !== state.filter.type) return false;
    if (state.filter.ip && (evt.remoteIp || '') !== state.filter.ip) return false;
    return true;
  }
  function renderNewEvent(evt) {
    if (!passesFilter(evt)) return;
    const feed = $('#feed');
    feed.appendChild(renderEventNode(evt));
    while (feed.children.length > state.maxEvents) feed.removeChild(feed.firstChild);
    if ($('#autoscroll').checked) feed.scrollTop = feed.scrollHeight;
  }
  function rerenderFeed() {
    const feed = $('#feed');
    feed.innerHTML = '';
    for (const e of state.events) if (passesFilter(e)) feed.appendChild(renderEventNode(e));
    if ($('#autoscroll').checked) feed.scrollTop = feed.scrollHeight;
  }
  function renderEventNode(evt) {
    const div = document.createElement('div');
    div.className = 'event ' + evt.type + ' ' + evt.service;
    const time = new Date(evt.ts).toLocaleTimeString();
    const ip = evt.remoteIp || '';
    const port = evt.remotePort || '';
    const localPort = evt.localPort || '';
    let details = '';
    if (evt.username) details += ` user=${evt.username}`;
    if (evt.password) details += ` pass=${evt.password}`;
    if (evt.command) details += ` cmd=${evt.command}`;
    if (evt.details && typeof evt.details === 'object') {
      const parts = [];
      for (const [k, v] of Object.entries(evt.details)) {
        if (v == null) continue;
        parts.push(`${k}=${typeof v === 'object' ? JSON.stringify(v).slice(0, 120) : String(v).slice(0, 120)}`);
      }
      if (parts.length) details += ' ' + parts.join(' ');
    }
    div.innerHTML = `
      <span class="time">${escape(time)}</span>
      <span class="service">${escape(evt.service)}</span>
      <span class="type">${escape(evt.type)}</span>
      <span class="ip">${escape(ip)}${port ? ':' + port : ''}</span>
      <span class="details">${escape(details.trim())}</span>
      <span class="badge">→ :${localPort || ''}</span>
    `;
    if (evt.sessionId) {
      div.style.cursor = 'pointer';
      div.title = 'Click to open session transcript';
      div.addEventListener('click', () => {
        state.selectedSession = evt.sessionId;
        selectTab('sessions');
        setTimeout(() => openSession(evt.sessionId), 100);
      });
    }
    return div;
  }

  // ---- Sessions ----
  $('#refresh-sessions').addEventListener('click', refreshSessions);
  async function refreshSessions() {
    try {
      const sessions = await send('get_sessions', { service: 'ssh', limit: 200 });
      const list = $('#sessions');
      list.innerHTML = '';
      for (const s of sessions) {
        const li = document.createElement('li');
        if (s.id === state.selectedSession) li.classList.add('active');
        const t = new Date(s.openedAt).toLocaleString();
        const status = s.closedAt ? 'closed' : 'active';
        li.innerHTML = `
          <div><span class="ip">${escape(s.remoteIp || '')}</span> <span class="user">${escape(s.username || '')}</span></div>
          <div class="time">${escape(t)} · ${escape(status)} · ${s.commandCount || 0} cmds</div>
        `;
        li.addEventListener('click', () => { state.selectedSession = s.id; openSession(s.id); refreshSessions(); });
        list.appendChild(li);
      }
    } catch (err) { console.warn(err); }
  }
  async function openSession(id) {
    try {
      const s = await send('get_session', { id });
      $('#session-meta').innerHTML = `
        Session <b>${escape(s.id)}</b> · ${escape(s.service)} ·
        from <b>${escape(s.remoteIp || '')}</b> · user <b>${escape(s.username || '')}</b> ·
        opened ${escape(new Date(s.openedAt).toLocaleString())}
        ${s.closedAt ? ' · closed ' + escape(new Date(s.closedAt).toLocaleString()) : ' · <span style="color:var(--ok)">active</span>'}
      `;
      const pre = $('#session-transcript');
      pre.innerHTML = '';
      for (const evt of s.events || []) {
        const line = document.createElement('div');
        const t = new Date(evt.ts).toLocaleTimeString();
        if (evt.type === 'command') {
          line.innerHTML = `<span class="meta">[${escape(t)}]</span> <span class="prompt">${escape(s.username || 'root')}@honeypot:~$</span> <span class="cmd">${escape(evt.command)}</span>`;
        } else if (evt.type === 'exec') {
          line.innerHTML = `<span class="meta">[${escape(t)}]</span> <span class="prompt">ssh exec:</span> <span class="cmd">${escape(evt.command)}</span>`;
        } else if (evt.type === 'auth_attempt' || evt.type === 'auth_success' || evt.type === 'login_attempt') {
          line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.type)} user=${escape(evt.username || '')} pass=${escape(evt.password || '')}</span>`;
        } else {
          line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.type)}${evt.details ? ' ' + escape(JSON.stringify(evt.details)) : ''}</span>`;
        }
        pre.appendChild(line);
      }
      pre.scrollTop = pre.scrollHeight;
    } catch (err) { $('#session-transcript').textContent = 'Error: ' + err.message; }
  }

  // ---- Services ----
  async function refreshServices() {
    try {
      state.services = await send('list_services', {});
      state.config = await send('get_config', {});
      const grid = $('#services-grid');
      grid.innerHTML = '';
      for (const svc of state.services) {
        const cfg = state.config.services[svc.name] || {};
        const card = document.createElement('div');
        card.className = 'service-card';
        const status = svc.error ? '<span class="pill err">error</span>' : (svc.running ? '<span class="pill on">running</span>' : '<span class="pill off">stopped</span>');
        const isSsh = svc.name === 'ssh';
        card.innerHTML = `
          <h3>${escape(svc.name)}</h3>
          <div class="port">port ${escape(cfg.port ?? svc.port ?? '')}</div>
          <div class="row">
            <div>${status}${svc.error ? '<div class="muted" style="font-size:11px;margin-top:4px;">' + escape(svc.error) + '</div>' : ''}</div>
            <label class="switch"><input type="checkbox" ${cfg.enabled ? 'checked' : ''} data-svc="${escape(svc.name)}"><span class="slider"></span></label>
          </div>
          <div class="row" style="gap:8px;">
            <label class="muted" style="flex:1;">port <input type="number" data-port="${escape(svc.name)}" value="${escape(cfg.port ?? '')}" style="width:80px;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);"></label>
          </div>
          ${isSsh ? renderSshExtras(cfg) : ''}
        `;
        grid.appendChild(card);
      }
      $$('#services-grid input[type="checkbox"][data-svc]').forEach((el) => {
        el.addEventListener('change', async () => {
          state.config.services[el.dataset.svc].enabled = el.checked;
          await saveConfig();
          refreshServices();
        });
      });
      $$('#services-grid input[data-port]').forEach((el) => {
        el.addEventListener('change', async () => {
          state.config.services[el.dataset.port].port = Number(el.value);
          await saveConfig();
          refreshServices();
        });
      });
      $$('#services-grid select[data-ssh-mode]').forEach((el) => el.addEventListener('change', async () => { state.config.services.ssh.fakeAuth.mode = el.value; await saveConfig(); }));
      $$('#services-grid input[data-ssh-prob]').forEach((el) => el.addEventListener('change', async () => { state.config.services.ssh.fakeAuth.acceptProbability = Number(el.value); await saveConfig(); }));
      $$('#services-grid input[data-ssh-users]').forEach((el) => el.addEventListener('change', async () => { state.config.services.ssh.fakeAuth.acceptedUsernames = el.value.split(',').map((s) => s.trim()).filter(Boolean); await saveConfig(); }));
    } catch (err) { console.warn(err); }
  }
  function renderSshExtras(cfg) {
    const fa = cfg.fakeAuth || {};
    return `
      <hr style="border:0;border-top:1px solid var(--border);margin:12px 0;">
      <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:6px;">SSH fake-auth</div>
      <label class="muted" style="display:block;margin-bottom:6px;">mode
        <select data-ssh-mode style="background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;">
          ${['always','random','random-any','first-attempt','never'].map((m) => `<option value="${m}" ${fa.mode === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
      </label>
      <label class="muted" style="display:block;margin-bottom:6px;">accept probability
        <input type="number" step="0.01" min="0" max="1" data-ssh-prob value="${escape(fa.acceptProbability ?? 0.15)}" style="width:80px;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);">
      </label>
      <label class="muted" style="display:block;">accepted usernames (comma-separated)
        <input type="text" data-ssh-users value="${escape((fa.acceptedUsernames || []).join(','))}" style="width:100%;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);">
      </label>
    `;
  }
  async function saveConfig() {
    try {
      state.config = await send('update_config', state.config);
    } catch (err) { console.warn('config save failed', err); }
  }

  // ---- Config editor ----
  $('#config-reload').addEventListener('click', loadConfig);
  $('#config-save').addEventListener('click', async () => {
    let parsed;
    try { parsed = JSON.parse($('#config-editor').value); }
    catch (err) {
      $('#config-status').textContent = 'Invalid JSON: ' + err.message;
      $('#config-status').style.color = 'var(--danger)';
      return;
    }
    try {
      state.config = await send('update_config', parsed);
      $('#config-status').textContent = 'Config applied at ' + new Date().toLocaleTimeString();
      $('#config-status').style.color = 'var(--ok)';
    } catch (err) {
      $('#config-status').textContent = err.message;
      $('#config-status').style.color = 'var(--danger)';
    }
  });
  async function loadConfig() {
    try {
      state.config = await send('get_config', {});
      $('#config-editor').value = JSON.stringify(state.config, null, 2);
      $('#config-status').textContent = '';
    } catch (err) { $('#config-status').textContent = err.message; }
  }

  // ---- Stats ----
  async function refreshStats() {
    try {
      const s = await send('get_stats', {});
      renderStats(s);
    } catch (err) { console.warn(err); }
  }
  function renderStats(s) {
    const cards = [
      ['Total events', s.total],
      ['Last 24 hours', s.last24h],
      ['Unique source IPs', s.uniqueIps],
      ['Active sessions', s.activeSessions]
    ];
    $('#stats-cards').innerHTML = cards.map(([l, v]) => `<div class="card"><div class="label">${l}</div><div class="value">${v ?? 0}</div></div>`).join('');
    $('#stats-ips tbody').innerHTML = (s.topIps || []).map((r) => `<tr><td>${escape(r.key)}</td><td>${r.count}</td></tr>`).join('');
    $('#stats-services tbody').innerHTML = (s.byService || []).map((r) => `<tr><td>${escape(r.key)}</td><td>${r.count}</td></tr>`).join('');
    $('#stats-creds tbody').innerHTML = (s.topCreds || []).map((r) => `<tr><td>${escape(r.username || '')}</td><td>${escape(r.password || '')}</td><td>${r.count}</td></tr>`).join('');
    $('#stats-commands tbody').innerHTML = (s.topCommands || []).map((r) => `<tr><td>${escape(r.key || '')}</td><td>${r.count}</td></tr>`).join('');
  }

  // ---- Helpers ----
  function escape(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
  function safeParse(s) { try { return s ? JSON.parse(s) : null; } catch { return null; } }
})();
