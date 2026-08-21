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
    reconnectAttempts: 0,
    stats: null,
    statsAt: 0,
    statsTimer: null
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
    $('#conn-relay').checked = !!remembered.relay;
    if (typeof remembered.proxy === 'boolean') $('#conn-proxy').checked = remembered.proxy;
  }

  if (location.protocol === 'https:') {
    $('#conn-relay').checked = true;
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
      relay: $('#conn-relay').checked,
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
    stopPoll();
    if (state.ws) state.ws.close();
    showConnectDialog();
  });

  async function connect() {
    if (!state.conn) return showConnectDialog();
    const { host, port, secure, proxy, relay } = state.conn;
    const useHttp = relay && !proxy;

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
    if (useHttp) {
      state.mode = 'http';
      $('#conn-error').textContent = 'Connecting via HTTPS relay…';
      try {
        const hello = await httpSend('hello');
        handleMessage({ type: 'hello', payload: hello });
        hideConnectDialog();
        $('#conn-dot').classList.add('on');
        $('#status-summary').textContent = 'live (poll)';
        $('#conn-target').textContent = `${host}:${port} via relay`;
        startPoll();
      } catch (err) {
        $('#conn-error').textContent = err.message;
      }
      return;
    }
    state.mode = 'ws';

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
    if (state.mode === 'http') return httpSend(type, payload);
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

  function restUrl(path) {
    const { host, port, key, secure, relay } = state.conn;
    if (relay) {
      const qs = new URLSearchParams({ host, port: String(port), path, token: key });
      if (secure) qs.set('tls', '1');
      return '/api/proxy?' + qs.toString();
    }
    const scheme = secure ? 'https' : 'http';
    return `${scheme}://${host}:${port}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(key)}`;
  }

  async function httpSend(type, payload) {
    const map = {
      hello: ['GET', '/v1/hello'],
      get_config: ['GET', '/v1/config'],
      list_services: ['GET', '/v1/services'],
      get_stats: ['GET', '/v1/stats'],
      get_range: ['GET', '/v1/range'],
      ping: ['GET', '/health']
    };
    let method = 'GET';
    let path = '/v1/hello';
    let body;
    if (type === 'update_config') {
      method = 'PUT'; path = '/v1/config'; body = JSON.stringify(payload);
    } else if (type === 'get_events') {
      const q = new URLSearchParams();
      if (payload) Object.entries(payload).forEach(([k, v]) => { if (v != null && v !== '') q.set(k, v); });
      path = '/v1/events' + (q.toString() ? '?' + q : '');
    } else if (type === 'get_sessions') {
      const q = new URLSearchParams();
      if (payload?.service) q.set('service', payload.service);
      q.set('limit', String(payload?.limit || 200));
      path = '/v1/sessions?' + q;
    } else if (type === 'get_session') {
      path = '/v1/session?id=' + encodeURIComponent(payload.id);
    } else if (map[type]) {
      [method, path] = map[type];
    }
    const res = await fetch(restUrl(path), {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Auth-Key': state.conn.key },
      body: method === 'GET' ? undefined : body
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }

  function startPoll() {
    stopPoll();
    state.pollTimer = setInterval(async () => {
      try {
        const since = state.events.length ? state.events[state.events.length - 1].ts : 0;
        const events = await httpSend('get_events', { since: since + 1, limit: 100 });
        for (const e of events || []) onEvent(e);
      } catch (err) {
        $('#status-summary').textContent = 'poll error';
      }
    }, 2000);
  }
  function stopPoll() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
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
        renderLiveStrip();
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
    if (state.currentTab === 'live') scheduleLiveStrip();
    if (state.currentTab === 'stats') refreshStats();
    if ((evt.type === 'authenticated' || evt.type === 'connection_closed' || evt.type === 'auth_success' || evt.type === 'connection') && state.currentTab === 'sessions') {
      refreshSessions();
    }
  }

  // ---- Tabs ----
  $$('.tab').forEach((btn) => btn.addEventListener('click', () => selectTab(btn.dataset.tab)));
  function selectTab(tab) {
    state.currentTab = tab;
    if (tab !== 'sessions') document.body.classList.remove('session-open');
    $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + tab));
    // Keep the active tab visible in the scrollable strip on phones.
    const activeTab = $(`.tab[data-tab="${tab}"]`);
    if (activeTab && activeTab.scrollIntoView) {
      activeTab.scrollIntoView({ inline: 'center', block: 'nearest', behavior: 'smooth' });
    }
    if (tab === 'live') renderLiveStrip();
    if (tab === 'sessions') refreshSessions();
    if (tab === 'history') initHistory();
    if (tab === 'services') refreshServices();
    if (tab === 'config') loadConfig();
    if (tab === 'stats') refreshStats(true);
  }

  // ---- Live ----
  $('#paused').addEventListener('change', (e) => { state.paused = e.target.checked; });
  $('#clear-feed').addEventListener('click', () => { state.events = []; $('#feed').innerHTML = ''; renderLiveStrip(); });
  ['#filter-service', '#filter-type', '#filter-ip'].forEach((sel) =>
    $(sel).addEventListener('input', () => {
      state.filter.service = $('#filter-service').value;
      state.filter.type = $('#filter-type').value;
      state.filter.ip = $('#filter-ip').value.trim();
      rerenderFeed();
      renderLiveStrip();
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
      const sessions = await send('get_sessions', { service: $('#session-service-filter')?.value || '', limit: 200 });
      const list = $('#sessions');
      const filter = $('#session-service-filter');
      const seen = new Set(Array.from(filter.options).map((o) => o.value));
      list.innerHTML = '';
      for (const s of sessions) {
        if (s.service && !seen.has(s.service)) {
          const opt = document.createElement('option');
          opt.value = s.service; opt.textContent = s.service;
          filter.appendChild(opt);
          seen.add(s.service);
        }
        const li = document.createElement('li');
        if (s.id === state.selectedSession) li.classList.add('active');
        const t = new Date(s.openedAt).toLocaleString();
        const status = s.closedAt ? 'closed' : 'active';
        li.innerHTML = `
          <div><span class="ip">${escape(s.remoteIp || '')}</span> <span class="user">${escape(s.username || '')}</span> <span class="muted">${escape(s.service || '')}</span></div>
          <div class="time">${escape(t)} · ${escape(status)} · ${s.commandCount || 0} cmds</div>
        `;
        li.addEventListener('click', () => { state.selectedSession = s.id; openSession(s.id); refreshSessions(); });
        list.appendChild(li);
      }
    } catch (err) { console.warn(err); }
  }
  async function openSession(id) {
    // On phones the list and the transcript share the screen; opening a
    // session swaps the panes (see body.session-open in the stylesheet).
    document.body.classList.add('session-open');
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
        } else if (evt.type === 'auth_attempt' || evt.type === 'auth_success' || evt.type === 'login_attempt' || evt.type === 'payload' || evt.type === 'datagram') {
          line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.service || '')} ${escape(evt.type)} user=${escape(evt.username || '')} pass=${escape(evt.password || '')} ${escape(evt.command || '')}</span>`;
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
      await refreshStats();
      const traffic = new Map((state.stats?.serviceStats || []).map((r) => [r.service, r]));
      const grid = $('#services-grid');
      grid.innerHTML = '';
      for (const svc of state.services) {
        const cfg = state.config.services[svc.name] || {};
        const card = document.createElement('div');
        card.className = 'service-card';
        const status = svc.error ? '<span class="pill err">error</span>' : (svc.running ? '<span class="pill on">running</span>' : '<span class="pill off">stopped</span>');
        const isInteractive = ['ssh', 'telnet', 'ftp', 'http', 'redis', 'mysql'].includes(svc.name);
        const t = traffic.get(svc.name);
        card.innerHTML = `
          <h3><span style="display:inline-block;width:9px;height:9px;border-radius:2px;background:${window.Charts ? Charts.colorFor(svc.name, 0) : 'var(--accent)'};margin-right:7px;"></span>${escape(svc.name)}</h3>
          <div class="port">port ${escape(cfg.port ?? svc.port ?? '')} ${escape(cfg.protocol || 'tcp')}</div>
          <div class="port" style="margin-top:6px;">${t
            ? `${num(t.events)} events · ${num(t.uniqueIps)} IPs · ${num(t.attempts)} logins${t.accepted ? ' · ' + num(t.accepted) + ' granted' : ''}`
            : 'no traffic recorded'}</div>
          <div class="port">${t && t.lastSeen ? 'last hit ' + escape(shortStamp(t.lastSeen)) : ''}</div>
          <div class="row">
            <div>${status}${svc.error ? '<div class="muted" style="font-size:11px;margin-top:4px;">' + escape(svc.error) + '</div>' : ''}</div>
            <label class="switch"><input type="checkbox" ${cfg.enabled ? 'checked' : ''} data-svc="${escape(svc.name)}"><span class="slider"></span></label>
          </div>
          <div class="row" style="gap:8px;">
            <label class="muted" style="flex:1;">port <input type="number" data-port="${escape(svc.name)}" value="${escape(cfg.port ?? '')}" style="width:80px;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);"></label>
          </div>
          ${isInteractive ? renderFakeAuthExtras(svc.name, cfg) : ''}
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
      $$('#services-grid select[data-fa-mode]').forEach((el) => el.addEventListener('change', async () => {
        const name = el.dataset.faMode;
        state.config.services[name].fakeAuth = state.config.services[name].fakeAuth || {};
        state.config.services[name].fakeAuth.mode = el.value;
        await saveConfig();
      }));
      $$('#services-grid input[data-fa-prob]').forEach((el) => el.addEventListener('change', async () => {
        const name = el.dataset.faProb;
        state.config.services[name].fakeAuth = state.config.services[name].fakeAuth || {};
        state.config.services[name].fakeAuth.acceptProbability = Number(el.value);
        await saveConfig();
      }));
      $$('#services-grid input[data-fa-users]').forEach((el) => el.addEventListener('change', async () => {
        const name = el.dataset.faUsers;
        state.config.services[name].fakeAuth = state.config.services[name].fakeAuth || {};
        state.config.services[name].fakeAuth.acceptedUsernames = el.value.split(',').map((s) => s.trim()).filter(Boolean);
        await saveConfig();
      }));
    } catch (err) { console.warn(err); }
  }
  function renderFakeAuthExtras(name, cfg) {
    const fa = cfg.fakeAuth || {};
    return `
      <hr style="border:0;border-top:1px solid var(--border);margin:12px 0;">
      <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:6px;">Fake access</div>
      <label class="muted" style="display:block;margin-bottom:6px;">mode
        <select data-fa-mode="${escape(name)}" style="background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;">
          ${['always','random','random-any','first-attempt','never'].map((m) => `<option value="${m}" ${fa.mode === m ? 'selected' : ''}>${m}</option>`).join('')}
        </select>
      </label>
      <label class="muted" style="display:block;margin-bottom:6px;">accept probability
        <input type="number" step="0.01" min="0" max="1" data-fa-prob="${escape(name)}" value="${escape(fa.acceptProbability ?? 0.15)}" style="width:80px;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);">
      </label>
      <label class="muted" style="display:block;">accepted usernames (comma-separated)
        <input type="text" data-fa-users="${escape(name)}" value="${escape((fa.acceptedUsernames || []).join(','))}" style="width:100%;background:var(--panel-2);color:var(--text);border:1px solid var(--border);padding:4px 6px;border-radius:6px;font-family:var(--mono);">
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
  // The daemon recomputes the whole aggregate on every call, so a busy
  // honeypot would otherwise re-render the tab per event.
  const STATS_MIN_INTERVAL = 2000;
  function refreshStats(force) {
    const now = Date.now();
    if (!force && now - state.statsAt < STATS_MIN_INTERVAL) {
      if (!state.statsTimer) {
        state.statsTimer = setTimeout(() => { state.statsTimer = null; refreshStats(true); },
          STATS_MIN_INTERVAL - (now - state.statsAt));
      }
      return Promise.resolve(state.stats);
    }
    state.statsAt = now;
    return send('get_stats', {})
      .then((s) => {
        state.stats = s;
        if (state.currentTab === 'stats') renderStats(s);
        return s;
      })
      .catch((err) => { console.warn(err); return null; });
  }

  const CARD_COLORS = ['c-blue', 'c-cyan', 'c-mint', 'c-violet', 'c-amber', 'c-rose'];

  function renderStats(s) {
    if (!s || typeof s !== 'object') return;
    state.stats = s;

    const timeline = Array.isArray(s.timeline) && s.timeline.length
      ? s.timeline
      : (s.hourly || []).map((r) => ({ label: r.key, count: r.count, attempts: 0, accepted: 0, uniqueIps: 0 }));
    const counts = timeline.map((b) => b.count || 0);
    const attempts = s.attempts != null ? s.attempts : (s.rejected || 0);
    const accepted = s.accepted || 0;
    const acceptRate = attempts ? Math.round((accepted / attempts) * 100) : 0;
    const busiest = (s.byService || [])[0];
    const perHour = s.last24h ? Math.round(s.last24h / 24) : 0;
    const perMin = s.eventsPerMin != null ? s.eventsPerMin : (s.lastHour || 0) / 60;

    const cards = [
      { label: 'Events retained', value: s.total, sub: s.firstEventTs ? 'oldest ' + shortStamp(s.firstEventTs) : 'nothing logged yet' },
      { label: 'Last 24 hours', value: s.last24h, sub: `≈ ${num(perHour)}/hour`, spark: counts },
      { label: 'Last hour', value: s.lastHour, sub: `${perMin.toFixed(perMin < 10 ? 1 : 0)} events/min` },
      { label: 'Unique attackers', value: s.uniqueIps, sub: `${num(s.uniqueIps24h)} seen in last 24h` },
      { label: 'Credential attempts', value: attempts, sub: `${num(s.rejected)} refused · ${num(accepted)} granted` },
      { label: 'Fake access granted', value: accepted, sub: `${acceptRate}% of all attempts` },
      { label: 'Shell sessions', value: s.shellSessions, sub: `${num(s.commands)} commands captured` },
      { label: 'Open sessions', value: s.activeSessions, sub: `${num(s.totalSessions)} sessions retained` },
      { label: 'Busiest service', value: busiest ? busiest.key : '—', sub: busiest ? `${num(busiest.count)} events` : 'no traffic yet', text: true },
      { label: 'Peak hour (UTC)', value: s.peakHour || '—', sub: s.peakHourCount ? `${num(s.peakHourCount)} events in that hour` : 'last 24h', text: true }
    ];
    $('#stats-cards').innerHTML = cards.map((c, i) => `
      <div class="card ${CARD_COLORS[i % CARD_COLORS.length]}">
        <div class="label">${escape(c.label)}</div>
        <div class="value">${c.text ? escape(String(c.value)) : num(c.value)}</div>
        <div class="sub">${escape(c.sub)}</div>
        ${c.spark ? '<canvas class="spark" data-spark="1"></canvas>' : ''}
      </div>`).join('');
    const spark = $('#stats-cards canvas[data-spark]');
    if (spark && window.Charts) Charts.sparkline(spark, counts, { color: '#6bd2ff', height: 30 });

    const range = s.firstEventTs && s.lastEventTs
      ? `${shortStamp(s.firstEventTs)} → ${shortStamp(s.lastEventTs)}`
      : 'no events yet';
    $('#stats-window').innerHTML = `Retained window: <b>${escape(range)}</b> · all counters cover the memory ring plus whatever was replayed from <code>events.ndjson</code>.`;
    $('#stats-peak').textContent = s.peakHour ? `busiest hour ${s.peakHour} UTC (${num(s.peakHourCount)})` : '';

    drawStatsCharts(s, timeline);

    tableRows('#stats-ips', s.topIps, (r) => [r.key, num(r.count)]);
    tableRows('#stats-services', s.byService, (r) => [serviceCell(r.key), num(r.count)], true);
    tableRows('#stats-creds', s.topCreds, (r) => [r.username || '—', r.password || '—', num(r.count)]);
    tableRows('#stats-commands', s.topCommands, (r) => [r.key, num(r.count)]);
    tableRows('#stats-users', s.topUsernames, (r) => [r.key, num(r.count)]);
    tableRows('#stats-passwords', s.topPasswords, (r) => [r.key, num(r.count)]);
    tableRows('#stats-paths', s.topPaths, (r) => [r.key, num(r.count)]);
    tableRows('#stats-clients', s.topClients, (r) => [r.key, num(r.count)]);

    const svcRows = s.serviceStats || [];
    $('#stats-service-table tbody').innerHTML = svcRows.map((r) => `
      <tr>
        <td>${serviceCell(r.service)}</td>
        <td>${r.port ? escape(String(r.port)) : '—'}</td>
        <td>${num(r.events)}</td>
        <td>${num(r.uniqueIps)}</td>
        <td>${num(r.attempts)}</td>
        <td>${num(r.accepted)}</td>
        <td>${num(r.commands)}</td>
        <td>${r.lastSeen ? escape(shortStamp(r.lastSeen)) : '—'}</td>
      </tr>`).join('');
    $('#stats-service-wrap').hidden = !svcRows.length;
    $('#stats-service-title').hidden = !svcRows.length;
  }

  function drawStatsCharts(s, timeline) {
    if (!window.Charts) return;
    const C = window.Charts;

    panel('#chart-hourly', timeline.length, (canvas) => {
      C.timeline(canvas, {
        rows: timeline.map((b) => b.label),
        series: [
          { label: 'all events', color: '#6b8afd', values: timeline.map((b) => b.count || 0) },
          { label: 'credential attempts', color: '#ffcf6b', values: timeline.map((b) => b.attempts || 0), fill: false },
          { label: 'access granted', color: '#7cf2c8', values: timeline.map((b) => b.accepted || 0), kind: 'bar' },
          { label: 'unique IPs', color: '#b98bff', values: timeline.map((b) => b.uniqueIps || 0), fill: false }
        ]
      }, { theme: 'dark', aspect: 3.4, maxHeight: 300 });
    });

    panel('#chart-service', (s.byService || []).length, (canvas) => {
      C.donut(canvas, (s.byService || []).map((r) => ({ label: r.key, value: r.count })), { theme: 'dark', centerLabel: 'events', maxHeight: 260 });
    });

    panel('#chart-types', (s.byType || []).length, (canvas) => {
      C.hbars(canvas, (s.byType || []).slice(0, 9).map((r, i) => ({ label: r.key, value: r.count, color: typeColor(r.key, i) })), { theme: 'dark' });
    });

    panel('#chart-ips', (s.topIps || []).length, (canvas) => {
      C.hbars(canvas, (s.topIps || []).slice(0, 9).map((r, i) => ({ label: r.key, value: r.count })), { theme: 'dark', labelWidth: 150 });
    });

    panel('#chart-ports', (s.topPorts || []).length, (canvas) => {
      C.hbars(canvas, (s.topPorts || []).slice(0, 9).map((r) => {
        const svc = String(r.key).split('/')[1] || '';
        return { label: r.key, value: r.count, color: C.colorFor(svc, 0) };
      }), { theme: 'dark', unit: 'events' });
    });

    panel('#chart-daily', (s.daily || []).length, (canvas) => {
      C.bars(canvas, (s.daily || []).map((b) => ({ label: b.label, value: b.count, color: '#6bd2ff' })), { theme: 'dark', aspect: 3.6, maxHeight: 240 });
    });

    panel('#chart-heatmap', (s.heatmap && s.heatmap.max) ? 1 : 0, (canvas) => {
      C.heatmap(canvas, s.heatmap, { theme: 'dark', height: 196 });
    });
  }

  // Hide a chart's whole panel when the daemon has nothing to plot (or is
  // an older build that does not send that series at all).
  function panel(sel, hasData, draw) {
    const canvas = $(sel);
    if (!canvas) return;
    const box = canvas.closest('.panel');
    if (box) box.hidden = !hasData;
    if (!hasData) return;
    draw(canvas);
  }

  const TYPE_COLORS = {
    auth_success: '#7cf2c8', authenticated: '#9dff6b', auth_attempt: '#ffcf6b',
    login_attempt: '#ffa26b', command: '#6bd2ff', exec: '#6bffe4',
    connection: '#6b8afd', connection_closed: '#8892b8', payload: '#b98bff',
    query: '#d88bff', request: '#6bb8fd', datagram: '#c9b06b',
    server_error: '#ff6b8b', handler_error: '#ff6b8b', service_error: '#ff6b8b'
  };
  function typeColor(key, i) { return TYPE_COLORS[key] || Charts.PALETTE[i % Charts.PALETTE.length]; }

  function serviceCell(name) {
    const color = window.Charts ? Charts.colorFor(name, 0) : 'var(--accent)';
    return `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${color};margin-right:6px;"></span>${escape(name)}`;
  }

  function tableRows(sel, rows, map, raw) {
    const table = $(sel);
    if (!table) return;
    const list = rows || [];
    const body = table.querySelector('tbody');
    body.innerHTML = list.map((r) => '<tr>' + map(r).map((cell, i) =>
      `<td>${raw && i === 0 ? cell : escape(String(cell))}</td>`).join('') + '</tr>').join('');
    const holder = table.parentElement;
    if (holder && holder.parentElement && holder.parentElement.classList.contains('two-col')) {
      holder.hidden = !list.length;
    }
  }

  function num(v) { return Number(v || 0).toLocaleString(); }
  function shortStamp(ms) {
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return '—';
    // Some locales put U+202F before AM/PM; the PDF fonts cannot show it.
    return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
      .replace(/[\u202f\u00a0]/g, ' ');
  }

  const statsRefreshBtn = $('#stats-refresh');
  if (statsRefreshBtn) statsRefreshBtn.addEventListener('click', () => refreshStats(true));

  // Canvas pixels are sized to the CSS box, so a resize needs a repaint.
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (state.currentTab !== 'stats' || !window.Charts) return;
      $$('#tab-stats canvas').forEach((c) => Charts.redraw(c));
    }, 200);
  });

  // ---- Live counter strip ----
  let liveStripTimer = null;
  function scheduleLiveStrip() {
    if (liveStripTimer) return;
    liveStripTimer = setTimeout(() => { liveStripTimer = null; renderLiveStrip(); }, 500);
  }
  function renderLiveStrip() {
    const el = $('#live-strip');
    if (!el) return;
    const events = state.events || [];
    const shown = events.filter(passesFilter);
    const ips = new Set();
    const svc = new Map();
    let attempts = 0;
    let granted = 0;
    for (const e of events) {
      if (e.remoteIp) ips.add(e.remoteIp);
      if (e.service) svc.set(e.service, (svc.get(e.service) || 0) + 1);
      if (e.type === 'auth_attempt' || e.type === 'login_attempt' || e.type === 'auth_success') attempts++;
      if (e.type === 'auth_success') granted++;
    }
    const last = events.length ? events[events.length - 1].ts : 0;
    const top = Array.from(svc.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const chips = [
      chip('in buffer', `${num(shown.length)}${shown.length !== events.length ? ' / ' + num(events.length) : ''}`),
      chip('source IPs', num(ips.size)),
      chip('cred. attempts', num(attempts)),
      chip('granted', num(granted)),
      chip('last event', last ? ago(last) : '—')
    ].concat(top.map(([name, count]) =>
      `<span class="chip"><span class="sw" style="background:${window.Charts ? Charts.colorFor(name, 0) : 'var(--accent)'}"></span>${escape(name)} <b>${num(count)}</b></span>`));
    el.innerHTML = chips.join('');
  }
  function chip(label, value) { return `<span class="chip">${escape(label)} <b>${escape(String(value))}</b></span>`; }
  function ago(ts) {
    const secs = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (secs < 60) return secs + 's ago';
    if (secs < 3600) return Math.round(secs / 60) + 'm ago';
    if (secs < 86400) return Math.round(secs / 3600) + 'h ago';
    return Math.round(secs / 86400) + 'd ago';
  }
  setInterval(() => { if (state.currentTab === 'live') renderLiveStrip(); }, 15000);

  const addForm = $('#add-service');
  if (addForm) addForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = $('#add-svc-name').value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    if (!name) return;
    if (!state.config.services) state.config.services = {};
    state.config.services[name] = {
      enabled: true,
      port: Number($('#add-svc-port').value),
      protocol: $('#add-svc-proto').value,
      kind: 'generic',
      banner: $('#add-svc-banner').value
    };
    await saveConfig();
    refreshServices();
  });

  const sessFilter = $('#session-service-filter');
  if (sessFilter) sessFilter.addEventListener('change', refreshSessions);

  const sessBack = $('#sessions-back');
  if (sessBack) sessBack.addEventListener('click', () => {
    document.body.classList.remove('session-open');
    state.selectedSession = null;
  });

  // ---- History ----
  let historyRows = [];
  let historyInit = false;

  function localToMs(value) {
    if (!value) return 0;
    const ms = new Date(value).getTime();
    return Number.isFinite(ms) ? ms : 0;
  }
  function msToLocalInput(ms) {
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  async function initHistory() {
    // Mirror whatever services/types the live feed has already seen.
    for (const opt of Array.from($('#filter-service').options)) ensureOption('#hist-service', opt.value);
    for (const opt of Array.from($('#filter-type').options)) ensureOption('#hist-type', opt.value);
    if (historyInit) return;
    historyInit = true;
    try {
      const r = await send('get_range', {});
      if (r?.oldest) {
        $('#hist-from').value = msToLocalInput(r.oldest);
        $('#hist-to').value = msToLocalInput(r.newest || Date.now());
      }
    } catch { /* older daemons have no get_range; filters still work */ }
    runHistory();
  }

  async function runHistory() {
    const payload = {
      service: $('#hist-service').value,
      type: $('#hist-type').value,
      ip: $('#hist-ip').value.trim(),
      q: $('#hist-q').value.trim(),
      since: localToMs($('#hist-from').value),
      until: localToMs($('#hist-to').value),
      limit: Number($('#hist-limit').value) || 1000
    };
    $('#hist-summary').textContent = 'Querying…';
    try {
      const rows = await send('get_events', payload);
      historyRows = rows || [];
      renderHistory();
    } catch (err) {
      $('#hist-summary').textContent = 'Query failed: ' + err.message;
    }
  }

  function renderHistory() {
    const tbody = $('#hist-table tbody');
    tbody.innerHTML = '';
    for (const e of historyRows) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td data-label="Time">${escape(new Date(e.ts).toLocaleString())}</td>
        <td data-label="Service">${escape(e.service || '')}</td>
        <td data-label="Type">${escape(e.type || '')}</td>
        <td data-label="Source">${escape(e.remoteIp || '')}${e.remotePort ? ':' + e.remotePort : ''}</td>
        <td data-label="User">${escape(e.username || '')}</td>
        <td data-label="Password">${escape(e.password || '')}</td>
        <td data-label="Detail">${escape(detailText(e))}</td>
      `;
      if (e.sessionId) {
        tr.style.cursor = 'pointer';
        tr.title = 'Open session transcript';
        tr.addEventListener('click', () => {
          state.selectedSession = e.sessionId;
          selectTab('sessions');
          setTimeout(() => openSession(e.sessionId), 100);
        });
      }
      tbody.appendChild(tr);
    }
    const span = historyRows.length
      ? `${new Date(historyRows[0].ts).toLocaleString()} → ${new Date(historyRows[historyRows.length - 1].ts).toLocaleString()}`
      : 'no events in range';
    $('#hist-summary').textContent = `${historyRows.length} events · ${span}`;
  }

  function detailText(e) {
    let out = e.command || '';
    if (e.details && typeof e.details === 'object') {
      const parts = [];
      for (const [k, v] of Object.entries(e.details)) {
        if (v == null) continue;
        parts.push(`${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`);
      }
      if (parts.length) out += (out ? ' · ' : '') + parts.join(' ');
    }
    return out;
  }

  $('#hist-run').addEventListener('click', runHistory);
  $('#hist-24h').addEventListener('click', () => {
    $('#hist-from').value = msToLocalInput(Date.now() - 24 * 3600 * 1000);
    $('#hist-to').value = msToLocalInput(Date.now());
    runHistory();
  });
  $('#hist-all').addEventListener('click', async () => {
    $('#hist-from').value = '';
    $('#hist-to').value = '';
    $('#hist-limit').value = 20000;
    runHistory();
  });
  $('#hist-ip').addEventListener('keydown', (e) => { if (e.key === 'Enter') runHistory(); });
  $('#hist-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') runHistory(); });

  $('#hist-csv').addEventListener('click', () => {
    const head = ['time', 'service', 'type', 'remoteIp', 'remotePort', 'localPort', 'username', 'password', 'command', 'sessionId'];
    const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    const lines = [head.join(',')];
    for (const e of historyRows) {
      lines.push([
        new Date(e.ts).toISOString(), e.service, e.type, e.remoteIp, e.remotePort,
        e.localPort, e.username, e.password, detailText(e), e.sessionId
      ].map(esc).join(','));
    }
    download(new Blob([lines.join('\n')], { type: 'text/csv' }), `honeystack-events-${stamp()}.csv`);
  });

  $('#hist-pdf').addEventListener('click', () => buildPdf(historyRows));
  $('#stats-pdf').addEventListener('click', async () => {
    if (!historyRows.length) {
      try { historyRows = await send('get_events', { limit: 1000 }); } catch { /* report still useful */ }
    }
    buildPdf(historyRows);
  });

  async function buildPdf(rows) {
    let stats = {};
    try { stats = await send('get_stats', {}); } catch { /* keep going */ }
    // The charts may never have been painted if the user went straight to
    // the report, and a blank canvas would embed as an empty image.
    try { renderStats(stats); } catch { /* charts are optional in the PDF */ }

    const doc = new PdfDoc('Honeystack report');
    const target = $('#conn-target').textContent || `${state.conn?.host || ''}:${state.conn?.port || ''}`;

    doc.text('Honeystack honeypot report', { size: 20, bold: true });
    doc.text(`Generated ${new Date().toLocaleString()}`, { size: 10, color: [0.4, 0.43, 0.53] });
    doc.text(`Source: ${target}`, { size: 10, color: [0.4, 0.43, 0.53] });
    doc.space(6);
    doc.rule();

    doc.text('Summary', { size: 13, bold: true });
    doc.space(2);
    const attempts = stats.attempts != null ? stats.attempts : (stats.rejected ?? 0);
    const summary = [
      ['Retained window', stats.firstEventTs
        ? `${shortStamp(stats.firstEventTs)} -> ${shortStamp(stats.lastEventTs)}`
        : 'no events'],
      ['Total events retained', num(stats.total)],
      ['Events last 24h', num(stats.last24h)],
      ['Events last hour', num(stats.lastHour)],
      ['Busiest hour (UTC)', stats.peakHour ? `${stats.peakHour} (${num(stats.peakHourCount)} events)` : '-'],
      ['Unique source IPs', `${num(stats.uniqueIps)} (${num(stats.uniqueIps24h)} in last 24h)`],
      ['Credential attempts', num(attempts)],
      ['Fake access granted', `${num(stats.accepted)}${attempts ? ' (' + Math.round(((stats.accepted || 0) / attempts) * 100) + '% of attempts)' : ''}`],
      ['Attempts refused', num(stats.rejected)],
      ['Fake shell sessions', num(stats.shellSessions)],
      ['Commands captured', num(stats.commands)],
      ['Sessions (open / retained)', `${num(stats.activeSessions)} / ${num(stats.totalSessions)}`]
    ];
    doc.table(['Metric', 'Value'], summary, [230, 200], 9.5);
    doc.space(8);

    // The on-screen charts are dark; repaint the same data light-themed at
    // print resolution so the report is readable on paper.
    const REPORT_CHARTS = [
      ['Activity - last 24 hours (UTC)', '#chart-hourly', 900, 265],
      ['Events by service', '#chart-service', 900, 300],
      ['Event types', '#chart-types', 900, 0],
      ['Noisiest source IPs', '#chart-ips', 900, 0],
      ['Targeted ports', '#chart-ports', 900, 0],
      ['Daily volume - last 14 days', '#chart-daily', 900, 250],
      ['When the scanning happens (weekday x hour, UTC)', '#chart-heatmap', 900, 250]
    ];
    for (const [heading, canvasSel, cw, ch] of REPORT_CHARTS) {
      const live = $(canvasSel);
      if (!live || !live.__chart) continue;
      const flat = window.Charts ? Charts.offscreen(live, cw, ch || undefined) : null;
      const canvas = flat || live;
      if (!canvas.width) continue;
      const jpeg = jpegFromCanvas(canvas);
      if (!jpeg) continue;
      const w = PDF_PAGE.W - PDF_PAGE.MARGIN * 2;
      const drawH = w * (canvas.height / canvas.width);
      // Keep the heading with its chart instead of orphaning it at the
      // bottom of the previous page.
      if (doc.current.y - drawH - 30 < PDF_PAGE.MARGIN) doc.newPage();
      doc.text(heading, { size: 12, bold: true });
      doc.image(jpeg, w, drawH, canvas.width, canvas.height);
      doc.space(4);
    }

    const section = (title, headers, data, widths) => {
      if (!data.length) return;
      doc.space(4);
      doc.text(title, { size: 13, bold: true });
      doc.space(2);
      doc.table(headers, data, widths, 9);
      doc.space(6);
    };

    section('Per-service breakdown',
      ['Service', 'Port', 'Events', 'IPs', 'Logins', 'Granted', 'Cmds', 'Last hit'],
      (stats.serviceStats || []).map((r) => [
        r.service, r.port || '', r.events, r.uniqueIps, r.attempts, r.accepted, r.commands,
        r.lastSeen ? shortStamp(r.lastSeen) : ''
      ]), [86, 40, 54, 44, 50, 54, 44, 118]);
    section('Top source IPs', ['IP', 'Events'],
      (stats.topIps || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Events by service', ['Service', 'Events'],
      (stats.byService || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Event types', ['Type', 'Count'],
      (stats.byType || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Targeted ports', ['Port / service', 'Events'],
      (stats.topPorts || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Top credentials', ['Username', 'Password', 'Count'],
      (stats.topCreds || []).map((r) => [r.username, r.password, r.count]), [170, 250, 60]);
    section('Top usernames', ['Username', 'Tries'],
      (stats.topUsernames || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Top passwords', ['Password', 'Tries'],
      (stats.topPasswords || []).map((r) => [r.key, r.count]), [260, 90]);
    section('Top commands', ['Command', 'Count'],
      (stats.topCommands || []).map((r) => [r.key, r.count]), [430, 60]);
    section('Requested HTTP paths', ['Path', 'Hits'],
      (stats.topPaths || []).map((r) => [r.key, r.count]), [430, 60]);
    section('Client fingerprints', ['User agent / version', 'Hits'],
      (stats.topClients || []).map((r) => [r.key, r.count]), [430, 60]);

    const list = (rows || []).slice(-400);
    if (list.length) {
      doc.space(4);
      doc.text(`Events (${list.length} most recent of ${rows.length} in view)`, { size: 13, bold: true });
      doc.space(2);
      doc.table(
        ['Time', 'Service', 'Type', 'Source', 'User', 'Detail'],
        list.map((e) => [
          new Date(e.ts).toLocaleString(),
          e.service || '',
          e.type || '',
          e.remoteIp || '',
          e.username || '',
          detailText(e)
        ]),
        [104, 62, 78, 86, 58, 127],
        7.5
      );
    }

    download(doc.build(), `honeystack-report-${stamp()}.pdf`);
  }

  function jpegFromCanvas(canvas) {
    // Charts are drawn on a transparent canvas; JPEG has no alpha, so
    // composite onto white first or the bars come out on black.
    try {
      const flat = document.createElement('canvas');
      flat.width = canvas.width;
      flat.height = canvas.height;
      const c = flat.getContext('2d');
      c.fillStyle = '#ffffff';
      c.fillRect(0, 0, flat.width, flat.height);
      c.drawImage(canvas, 0, 0);
      return flat.toDataURL('image/jpeg', 0.85);
    } catch {
      return null;
    }
  }

  function stamp() {
    return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  }

  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ---- Helpers ----
  function escape(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
  function safeParse(s) { try { return s ? JSON.parse(s) : null; } catch { return null; } }
})();
