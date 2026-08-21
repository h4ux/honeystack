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
    filter: { service: '', type: '', ip: '', country: '' },
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
    statsTimer: null,
    build: null,
    release: null,
    geoStats: null,
    geoByIp: new Map(),
    geoPending: new Set(),
    sessionsShown: 0
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
      get_version: ['GET', '/v1/version'],
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
      for (const key of ['service', 'ip', 'username', 'country', 'status', 'q', 'sort']) {
        if (payload && payload[key]) q.set(key, payload[key]);
      }
      if (payload?.minCommands) q.set('minCommands', String(payload.minCommands));
      if (payload?.since) q.set('since', String(payload.since));
      if (payload?.until) q.set('until', String(payload.until));
      q.set('limit', String(payload?.limit || 200));
      path = '/v1/sessions?' + q;
    } else if (type === 'geo_lookup') {
      const ips = (payload && payload.ips) || [];
      path = '/v1/geo?ips=' + encodeURIComponent(ips.join(','));
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
        state.build = msg.payload.build || null;
        state.geoStats = msg.payload.geo || null;
        renderUpdateState();
        checkForUpdate(false);
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
  ['#filter-service', '#filter-type', '#filter-ip', '#filter-country'].forEach((sel) =>
    $(sel).addEventListener('input', () => {
      state.filter.service = $('#filter-service').value;
      state.filter.type = $('#filter-type').value;
      state.filter.ip = $('#filter-ip').value.trim();
      state.filter.country = $('#filter-country').value;
      rerenderFeed();
      renderLiveStrip();
    })
  );

  function updateFilterOptions(evt) {
    ensureOption('#filter-service', evt.service);
    ensureOption('#filter-type', evt.type);
    const loc = geoOf(evt);
    if (loc && loc.countryCode) {
      ensureOption('#filter-country', loc.countryCode);
      ensureOption('#hist-country', loc.countryCode);
      ensureOption('#sess-country', loc.countryCode);
    }
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
    if (state.filter.country && !countryMatches(evt, state.filter.country)) return false;
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
      <span class="service">${svcIcon(evt.service, 13)}${escape(evt.service)}</span>
      <span class="type">${escape(evt.type)}</span>
      <span class="ip">${escape(ip)}${port ? ':' + port : ''} ${ip ? geoBadge(evt) : ''}</span>
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
  // The daemon does the filtering, so a busy honeypot does not have to ship
  // every session to the browser just to hide most of them.
  function sessionFilterPayload() {
    return {
      service: $('#session-service-filter')?.value || '',
      country: $('#sess-country')?.value || '',
      status: $('#sess-status')?.value || '',
      ip: ($('#sess-ip')?.value || '').trim(),
      username: ($('#sess-user')?.value || '').trim(),
      q: ($('#sess-q')?.value || '').trim(),
      minCommands: Number($('#sess-mincmds')?.value || 0) || 0,
      sort: $('#sess-sort')?.value || 'recent',
      limit: 300
    };
  }

  async function refreshSessions() {
    try {
      const payload = sessionFilterPayload();
      const sessions = await send('get_sessions', payload) || [];
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
        if (s.countryCode) ensureOption('#sess-country', s.countryCode);
        else if (s.remoteIp) queueGeo(s.remoteIp);
        const li = document.createElement('li');
        if (s.id === state.selectedSession) li.classList.add('active');
        const t = new Date(s.openedAt).toLocaleString();
        const status = s.closedAt ? 'closed' : 'active';
        const dur = durationText(s);
        li.innerHTML = `
          <div><span class="ip">${escape(s.remoteIp || '')}</span> ${s.remoteIp ? geoBadge(s) : ''} <span class="user">${escape(s.username || '')}</span> <span class="muted">${svcIcon(s.service, 12)}${escape(s.service || '')}</span></div>
          <div class="time">${escape(t)} · ${escape(status)}${dur ? ' · ' + escape(dur) : ''} · ${s.commandCount || 0} cmds${s.org ? ' · ' + escape(truncate(s.org, 28)) : ''}</div>
        `;
        li.addEventListener('click', () => { state.selectedSession = s.id; openSession(s.id); refreshSessions(); });
        list.appendChild(li);
      }
      state.sessionsShown = sessions.length;
      const active = sessions.filter((x) => !x.closedAt).length;
      const cmds = sessions.reduce((a, x) => a + (x.commandCount || 0), 0);
      const countEl = $('#sess-count');
      if (countEl) {
        countEl.textContent = sessions.length
          ? `${sessions.length} sessions · ${active} active · ${cmds} commands`
          : 'no sessions match these filters';
      }
    } catch (err) { console.warn(err); }
  }

  function durationText(sess) {
    if (!sess.openedAt) return '';
    const end = sess.closedAt || Date.now();
    const secs = Math.max(0, Math.round((end - sess.openedAt) / 1000));
    if (secs < 60) return secs + 's';
    if (secs < 3600) return Math.round(secs / 60) + 'm';
    return (secs / 3600).toFixed(1) + 'h';
  }

  function truncate(s, n) {
    const str = String(s || '');
    return str.length > n ? str.slice(0, n - 1) + '…' : str;
  }
  async function openSession(id) {
    // On phones the list and the transcript share the screen; opening a
    // session swaps the panes (see body.session-open in the stylesheet).
    document.body.classList.add('session-open');
    try {
      const s = await send('get_session', { id });
      $('#session-meta').innerHTML = `
        Session <b>${escape(s.id)}</b> · ${svcIcon(s.service, 14)}${escape(s.service)} ·
        from <b>${escape(s.remoteIp || '')}</b> ${s.remoteIp ? geoBadge(s) : ''}${s.org ? ' <span class="muted">' + escape(s.org) + '</span>' : ''} · user <b>${escape(s.username || '')}</b> ·
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
          <h3>${svcIcon(svc.name, 18)}${escape(svc.name)}</h3>
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

  // ---- GeoIP ----
  // The daemon annotates events it can resolve from cache at log time; the
  // rest are filled in here by asking for a batch of IPs and re-rendering.
  const GEO_TTL_MS = 6 * 60 * 60 * 1000;

  function geoFor(ip) {
    if (!ip) return null;
    const hit = state.geoByIp.get(ip);
    if (hit && Date.now() - hit.at < GEO_TTL_MS) return hit.loc;
    return null;
  }

  function rememberGeo(ip, loc) {
    if (!ip || !loc) return;
    state.geoByIp.set(ip, { loc, at: Date.now() });
    if (loc.countryCode) ensureOption('#filter-country', loc.countryCode);
  }

  // Pull country data for whatever IPs we have seen but cannot label yet.
  let geoTimer = null;
  function queueGeo(ip) {
    if (!ip || state.geoByIp.has(ip) || state.geoPending.has(ip)) return;
    state.geoPending.add(ip);
    if (geoTimer) return;
    geoTimer = setTimeout(flushGeo, 400);
  }
  async function flushGeo() {
    geoTimer = null;
    const ips = Array.from(state.geoPending).slice(0, 500);
    if (!ips.length) return;
    ips.forEach((ip) => state.geoPending.delete(ip));
    try {
      const res = await send('geo_lookup', { ips });
      const locations = (res && res.locations) || {};
      let learned = 0;
      for (const [ip, loc] of Object.entries(locations)) {
        rememberGeo(ip, loc);
        learned++;
      }
      // Remember the misses too, so we do not ask again on every event.
      for (const ip of ips) {
        if (!locations[ip]) state.geoByIp.set(ip, { loc: null, at: Date.now() });
      }
      if (res && res.geo) state.geoStats = res.geo;
      if (learned) {
        if (state.currentTab === 'live') rerenderFeed();
        if (state.currentTab === 'history') renderHistoryRows();
        if (state.currentTab === 'sessions') refreshSessions();
        if (state.currentTab === 'stats') refreshStats(true);
      }
    } catch (err) {
      console.warn('geo lookup failed', err);
    }
    if (state.geoPending.size) geoTimer = setTimeout(flushGeo, 1500);
  }

  // An event may already carry its country; otherwise use the cache.
  function geoOf(row) {
    if (!row) return null;
    if (row.countryCode || row.country) {
      const loc = { countryCode: row.countryCode, country: row.country, org: row.org };
      if (row.remoteIp && !state.geoByIp.has(row.remoteIp)) rememberGeo(row.remoteIp, loc);
      return loc;
    }
    const cached = geoFor(row.remoteIp);
    if (cached) return cached;
    queueGeo(row.remoteIp);
    return null;
  }

  function flagEmoji(code) {
    if (!code || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) return '🏳';
    return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  }

  // Compact badge for tables and the live feed.
  function geoBadge(row) {
    const loc = geoOf(row);
    if (!loc) return '<span class="geo unknown" title="country not resolved yet">··</span>';
    if (loc.private) return `<span class="geo" title="${escape(loc.country || 'private range')}">🏠 local</span>`;
    if (!loc.countryCode) return '<span class="geo unknown">··</span>';
    const title = [loc.country, loc.city, loc.org || loc.asn].filter(Boolean).join(' · ');
    return `<span class="geo" title="${escape(title)}"><span class="flag">${flagEmoji(loc.countryCode)}</span>${escape(loc.countryCode)}</span>`;
  }

  function geoLabel(row) {
    const loc = geoOf(row);
    if (!loc) return '';
    if (loc.private) return 'local';
    return [loc.countryCode, loc.country].filter(Boolean).join(' ');
  }

  function countryMatches(row, wanted) {
    if (!wanted) return true;
    const loc = geoOf(row);
    return !!loc && String(loc.countryCode || '').toUpperCase() === wanted.toUpperCase();
  }

  // ---- Version check / update instructions ----
  const RELEASE_CACHE_KEY = 'honeypot-release-cache-v1';
  const RELEASE_TTL_MS = 30 * 60 * 1000;

  function repoName() {
    return (state.build && state.build.repo) || 'h4ux/honeystack';
  }

  async function checkForUpdate(force) {
    const repo = repoName();
    const cached = safeParse(localStorage.getItem(RELEASE_CACHE_KEY));
    if (!force && cached && cached.repo === repo && Date.now() - cached.at < RELEASE_TTL_MS) {
      state.release = cached.release;
      renderUpdateState();
      return;
    }
    try {
      // api.github.com allows cross-origin GETs, so this works from the
      // Vercel-hosted page as well as a local one.
      let res = await fetch(`https://api.github.com/repos/${repo}/releases/tags/nightly`, {
        headers: { Accept: 'application/vnd.github+json' }
      });
      if (!res.ok) {
        res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
          headers: { Accept: 'application/vnd.github+json' }
        });
      }
      if (!res.ok) throw new Error('GitHub API returned ' + res.status);
      const rel = await res.json();
      state.release = {
        name: rel.name || rel.tag_name,
        tag: rel.tag_name,
        url: rel.html_url,
        publishedAt: rel.published_at,
        commit: releaseCommit(rel),
        assets: (rel.assets || []).length
      };
      localStorage.setItem(RELEASE_CACHE_KEY, JSON.stringify({ repo, at: Date.now(), release: state.release }));
    } catch (err) {
      state.release = { error: err.message };
    }
    renderUpdateState();
  }

  // CI puts the commit in the release title ("Nightly e16c23d") and in the
  // notes ("Automated build from `<sha>`").
  function releaseCommit(rel) {
    const fromName = /([0-9a-f]{7,40})/.exec(rel.name || '');
    const fromBody = /build from `([0-9a-f]{7,40})`/i.exec(rel.body || '');
    return (fromBody && fromBody[1]) || (fromName && fromName[1]) || '';
  }

  function updateState() {
    const build = state.build || {};
    const rel = state.release || {};
    if (rel.error) return 'unknown';
    if (!build.commit || build.commit === 'none' || !rel.commit) return 'unknown';
    const a = build.commit.toLowerCase();
    const b = rel.commit.toLowerCase();
    return (a.startsWith(b) || b.startsWith(a)) ? 'current' : 'available';
  }

  function renderUpdateState() {
    const chip = $('#update-chip');
    if (!chip) return;
    const build = state.build || {};
    const short = (build.commit || '').slice(0, 7);
    const state_ = updateState();
    chip.hidden = false;
    chip.classList.toggle('update', state_ === 'available');
    chip.classList.toggle('current', state_ === 'current');
    const label = build.version && build.version !== 'dev'
      ? build.version + (short ? ' · ' + short : '')
      : (short || 'dev build');
    chip.textContent = state_ === 'available' ? '⬆ update available' : label;
    chip.title = state_ === 'available'
      ? `Server is on ${short || 'an unknown build'}; ${(state.release.commit || '').slice(0, 7)} is published — click for instructions`
      : 'Server build info';
    renderUpdateDialog();
  }

  function renderUpdateDialog() {
    const build = state.build || {};
    const rel = state.release || {};
    const st = updateState();
    const statusEl = $('#update-status');
    if (statusEl) {
      statusEl.className = 'update-status ' + st;
      if (st === 'available') {
        statusEl.innerHTML = `<b>Update available.</b> The server runs <code>${escape((build.commit || '').slice(0, 7))}</code>; the latest published build is <code>${escape((rel.commit || '').slice(0, 7))}</code>.`;
      } else if (st === 'current') {
        statusEl.innerHTML = `<b>Up to date.</b> The server runs the latest published build (<code>${escape((build.commit || '').slice(0, 7))}</code>).`;
      } else if (rel.error) {
        statusEl.innerHTML = `Could not reach the GitHub release API: ${escape(rel.error)}. The update command below still works.`;
      } else {
        statusEl.innerHTML = 'This build does not report a commit, so it cannot be compared with the published release. Updating is still safe — it backs up and rolls back on failure.';
      }
    }

    const rows = [
      ['Version', build.version || '—'],
      ['Commit', build.commit || '—'],
      ['Go / platform', [build.goVersion, build.os && build.arch ? build.os + '/' + build.arch : ''].filter(Boolean).join(' · ') || '—'],
      ['Binary', build.binary || '—'],
      ['Listeners', build.services != null ? String(build.services) : '—'],
      ['Started', build.startedAt ? `${new Date(build.startedAt).toLocaleString()} (up ${uptime(build.startedAt)})` : '—'],
      ['Repository', repoName()],
      ['Latest release', rel.name ? `${rel.name}${rel.publishedAt ? ' · ' + new Date(rel.publishedAt).toLocaleString() : ''}` : (rel.error ? 'unavailable' : '—')],
      ['GeoIP', geoStatusText()]
    ];
    const body = $('#update-table tbody');
    if (body) {
      body.innerHTML = rows.map(([k, v]) => `<tr><td>${escape(k)}</td><td>${escape(String(v))}</td></tr>`).join('');
    }

    const base = `https://raw.githubusercontent.com/${repoName()}/main/go-honeypot/scripts/update-server.sh`;
    const cmd = $('#update-cmd');
    // One line, no pipe: a failed or truncated download cannot silently
    // run, and curl reports the error instead of swallowing it.
    if (cmd) cmd.textContent = `curl -fsSL --show-error ${base} -o update-server.sh && sudo bash update-server.sh`;
    const alt = $('#update-cmd-alt');
    if (alt) {
      alt.textContent = [
        '# read it before running it',
        `curl -fsSL --show-error ${base} -o update-server.sh`,
        'less update-server.sh && sudo bash update-server.sh',
        '',
        '# short form (pipe); --show-error means a failed download is not silent',
        `curl -fsSL --show-error ${base} | sudo bash`,
        '',
        '# unattended (answers yes to every prompt)',
        `curl -fsSL --show-error ${base} | sudo bash -s -- --yes`,
        '',
        '# just compare versions, change nothing',
        `curl -fsSL --show-error ${base} | sudo bash -s -- --check`,
        '',
        '# undo the last update',
        `curl -fsSL --show-error ${base} | sudo bash -s -- --rollback`
      ].join('\n');
    }
    const link = $('#update-release-link');
    if (link) {
      link.href = rel.url || `https://github.com/${repoName()}/releases`;
    }
  }

  function geoStatusText() {
    const g = state.geoStats;
    if (!g) return '—';
    if (!g.enabled) return 'disabled on the server';
    return `on · ${g.cached || 0} IPs cached · ${g.lookups || 0} lookups · ${g.failures || 0} failed`;
  }

  function uptime(startedAt) {
    const secs = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
  }

  $('#update-chip').addEventListener('click', () => {
    renderUpdateDialog();
    $('#update-overlay').hidden = false;
  });
  $('#update-close').addEventListener('click', () => { $('#update-overlay').hidden = true; });
  $('#update-overlay').addEventListener('click', (e) => {
    if (e.target === $('#update-overlay')) $('#update-overlay').hidden = true;
  });
  $('#update-recheck').addEventListener('click', () => {
    $('#update-status').textContent = 'Checking…';
    checkForUpdate(true);
  });
  $$('.copy-btn').forEach((btn) => btn.addEventListener('click', async () => {
    const target = $(btn.dataset.copy);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = old; }, 1200);
    } catch {
      // Clipboard is blocked in some contexts; select the text instead.
      const range = document.createRange();
      range.selectNodeContents(target);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') $('#update-overlay').hidden = true;
  });

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
      { label: 'Peak hour (UTC)', value: s.peakHour || '—', sub: s.peakHourCount ? `${num(s.peakHourCount)} events in that hour` : 'last 24h', text: true },
      {
        label: 'Uptime this run',
        value: s.startedAt ? durationMs(Date.now() - s.startedAt) : '—',
        sub: s.startedAt ? 'started ' + shortStamp(s.startedAt) : 'server did not report a start time',
        text: true,
        live: 'uptime'
      },
      {
        label: 'First hit after start',
        value: s.timeToFirstEventMs >= 0 ? '+' + durationMs(s.timeToFirstEventMs) : 'waiting',
        sub: s.timeToFirstEventMs >= 0
          ? `${s.firstEventService || 'unknown'} · ${shortStamp(s.firstEventSinceStart)} · ${num(s.trafficSinceStart != null ? s.trafficSinceStart : s.eventsSinceStart)} hits this run`
          : (s.startedAt ? 'nothing has hit this run yet (' + durationMs(Date.now() - s.startedAt) + ' so far)' : 'no data'),
        text: true,
        live: s.timeToFirstEventMs >= 0 ? null : 'waiting'
      },
      {
        label: 'Countries seen',
        value: (s.topCountries || []).length,
        sub: (s.topCountries || [])[0]
          ? `top: ${flagEmoji(s.topCountries[0].code)} ${s.topCountries[0].name || s.topCountries[0].code} (${num(s.topCountries[0].count)})`
          : (state.geoStats && state.geoStats.enabled ? 'resolving…' : 'geoip disabled on server'),
        text: false
      }
    ];
    $('#stats-cards').innerHTML = cards.map((c, i) => `
      <div class="card ${CARD_COLORS[i % CARD_COLORS.length]}"${c.live ? ` data-live="${c.live}"` : ''}>
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
    const runLine = s.startedAt
      ? ` · this run started <b>${escape(shortStamp(s.startedAt))}</b> (<span id="stats-uptime">${escape(durationMs(Date.now() - s.startedAt))}</span> ago) with <b>${num(s.trafficSinceStart != null ? s.trafficSinceStart : s.eventsSinceStart)}</b> inbound events since`
      : '';
    $('#stats-window').innerHTML = `Retained window: <b>${escape(range)}</b> · all counters cover the memory ring plus whatever was replayed from <code>events.ndjson</code>${runLine}.`;
    $('#stats-peak').textContent = s.peakHour ? `busiest hour ${s.peakHour} UTC (${num(s.peakHourCount)})` : '';

    drawStatsCharts(s, timeline);

    tableRows('#stats-ips', s.topIps, (r) => {
      const row = { remoteIp: r.key };
      return [escape(r.key), geoBadge(row) + ' ' + escape(geoLabel(row).replace(/^\S+\s*/, '')), num(r.count)];
    }, true);
    tableRows('#stats-countries', s.topCountries, (r) => [
      `${flagEmoji(r.code)} ${escape(r.name || r.code || 'unknown')}`,
      num(r.uniqueIps), num(r.count)
    ], true);
    tableRows('#stats-services', s.byService, (r) => [serviceCell(r.key), num(r.count)], true);
    $('#geo-status').textContent = geoStatusText();
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
        <td>${num(r.eventsSinceStart)}</td>
        <td>${firstHitCell(r, s.startedAt)}</td>
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

    panel('#chart-countries', (s.topCountries || []).length, (canvas) => {
      C.hbars(canvas, (s.topCountries || []).slice(0, 9).map((r) => ({
        label: `${flagEmoji(r.code)} ${r.code || r.name || '??'}`,
        value: r.count,
        note: [r.name, r.uniqueIps ? r.uniqueIps + ' unique IPs' : ''].filter(Boolean).join(' · ')
      })), { theme: 'dark', labelWidth: 110 });
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
    if (window.ServiceIcons) return ServiceIcons.label(name, 15);
    const color = window.Charts ? Charts.colorFor(name, 0) : 'var(--accent)';
    return `<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${color};margin-right:6px;"></span>${escape(name)}`;
  }

  // raw=true means the mapper already produced HTML for every cell.
  function tableRows(sel, rows, map, raw) {
    const table = $(sel);
    if (!table) return;
    const list = rows || [];
    const body = table.querySelector('tbody');
    body.innerHTML = list.map((r) => '<tr>' + map(r).map((cell) =>
      `<td>${raw ? cell : escape(String(cell))}</td>`).join('') + '</tr>').join('');
    const holder = table.parentElement;
    if (holder && holder.parentElement && holder.parentElement.classList.contains('two-col')) {
      holder.hidden = !list.length;
    }
  }

  function num(v) { return Number(v || 0).toLocaleString(); }

  // Compact, human duration: 0s, 42s, 3m 07s, 5h 12m, 3d 4h.
  function durationMs(ms) {
    const total = Math.max(0, Math.round((Number(ms) || 0) / 1000));
    if (total < 60) return total + 's';
    const m = Math.floor(total / 60), sec = total % 60;
    if (m < 60) return `${m}m ${String(sec).padStart(2, '0')}s`;
    const h = Math.floor(m / 60), min = m % 60;
    if (h < 24) return `${h}h ${String(min).padStart(2, '0')}m`;
    const d = Math.floor(h / 24);
    return `${d}d ${h % 24}h`;
  }

  // "+2m 14s" once a listener has been touched this run, otherwise how long
  // it has been quiet since the daemon started.
  function firstHitCell(row, startedAt) {
    if (row.timeToFirstMs != null && row.timeToFirstMs >= 0) {
      const when = row.firstSinceStart ? shortStamp(row.firstSinceStart) : '';
      return `<span title="${escape(when)}">+${escape(durationMs(row.timeToFirstMs))}</span>`;
    }
    const quiet = startedAt ? durationMs(Date.now() - startedAt) : '';
    return `<span class="muted" title="no traffic on this listener since the daemon started">not yet${quiet ? ' · ' + escape(quiet) : ''}</span>`;
  }

  // The uptime tiles count in real time instead of freezing at render time.
  setInterval(() => {
    if (state.currentTab !== 'stats' || !state.stats || !state.stats.startedAt) return;
    const elapsed = durationMs(Date.now() - state.stats.startedAt);
    const upCard = $('#stats-cards .card[data-live="uptime"] .value');
    if (upCard) upCard.textContent = elapsed;
    const waitCard = $('#stats-cards .card[data-live="waiting"] .sub');
    if (waitCard) waitCard.textContent = `nothing has hit this run yet (${elapsed} so far)`;
    const inline = $('#stats-uptime');
    if (inline) inline.textContent = elapsed;
  }, 1000);
  function svcIcon(name, size) {
    return window.ServiceIcons ? ServiceIcons.svg(name, size || 14) : '';
  }
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
      `<span class="chip">${svcIcon(name, 13)}${escape(name)} <b>${num(count)}</b></span>`));
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

  ['#session-service-filter', '#sess-country', '#sess-status', '#sess-sort'].forEach((sel) => {
    const el = $(sel);
    if (el) el.addEventListener('change', refreshSessions);
  });
  let sessDebounce;
  ['#sess-q', '#sess-ip', '#sess-user', '#sess-mincmds'].forEach((sel) => {
    const el = $(sel);
    if (!el) return;
    el.addEventListener('input', () => {
      clearTimeout(sessDebounce);
      sessDebounce = setTimeout(refreshSessions, 250);
    });
  });
  const sessReset = $('#sess-reset');
  if (sessReset) sessReset.addEventListener('click', () => {
    ['#sess-q', '#sess-ip', '#sess-user'].forEach((sel) => { if ($(sel)) $(sel).value = ''; });
    if ($('#sess-mincmds')) $('#sess-mincmds').value = 0;
    ['#session-service-filter', '#sess-country', '#sess-status'].forEach((sel) => { if ($(sel)) $(sel).value = ''; });
    if ($('#sess-sort')) $('#sess-sort').value = 'recent';
    refreshSessions();
  });

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

  const renderHistoryRows = () => renderHistory();

  function renderHistory() {
    const tbody = $('#hist-table tbody');
    tbody.innerHTML = '';
    const wantCountry = $('#hist-country') ? $('#hist-country').value : '';
    const shown = wantCountry ? historyRows.filter((e) => countryMatches(e, wantCountry)) : historyRows;
    for (const e of shown) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td data-label="Time">${escape(new Date(e.ts).toLocaleString())}</td>
        <td data-label="Service">${escape(e.service || '')}</td>
        <td data-label="Type">${escape(e.type || '')}</td>
        <td data-label="Source">${escape(e.remoteIp || '')}${e.remotePort ? ':' + e.remotePort : ''}</td>
        <td data-label="Country">${e.remoteIp ? geoBadge(e) + ' ' + escape(geoLabel(e).replace(/^\S+\s*/, '')) : ''}</td>
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
    const span = shown.length
      ? `${new Date(shown[0].ts).toLocaleString()} → ${new Date(shown[shown.length - 1].ts).toLocaleString()}`
      : 'no events in range';
    const filtered = shown.length !== historyRows.length ? ` (of ${historyRows.length} queried)` : '';
    $('#hist-summary').textContent = `${shown.length} events${filtered} · ${span}`;
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
  $('#hist-country').addEventListener('change', () => renderHistory());
  $('#hist-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') runHistory(); });

  $('#hist-csv').addEventListener('click', () => {
    const head = ['time', 'service', 'type', 'remoteIp', 'remotePort', 'localPort',
      'countryCode', 'country', 'org', 'username', 'password', 'command', 'sessionId'];
    const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    const lines = [head.join(',')];
    for (const e of historyRows) {
      const loc = geoOf(e) || {};
      lines.push([
        new Date(e.ts).toISOString(), e.service, e.type, e.remoteIp, e.remotePort,
        e.localPort, loc.countryCode || '', loc.country || '', loc.org || '',
        e.username, e.password, detailText(e), e.sessionId
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
      ['Sessions (open / retained)', `${num(stats.activeSessions)} / ${num(stats.totalSessions)}`],
      ['Countries seen', String((stats.topCountries || []).length)],
      ['This run started', stats.startedAt ? `${shortStamp(stats.startedAt)} (up ${durationMs(stats.uptimeMs)})` : '-'],
      ['Events this run', `${num(stats.eventsSinceStart)} logged, ${num(stats.trafficSinceStart)} inbound`],
      ['First hit after start', stats.timeToFirstEventMs >= 0
        ? `+${durationMs(stats.timeToFirstEventMs)} (${stats.firstEventService || '?'} at ${shortStamp(stats.firstEventSinceStart)})`
        : 'nothing yet'],
      ['Server build', state.build ? `${state.build.version || '?'} (${(state.build.commit || '').slice(0, 7)})` : 'unknown']
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
      ['Source countries', '#chart-countries', 900, 0],
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
      ['Service', 'Port', 'Events', 'Run', '1st hit', 'IPs', 'Logins', 'Granted', 'Cmds', 'Last hit'],
      (stats.serviceStats || []).map((r) => [
        r.service, r.port || '', r.events, r.eventsSinceStart,
        r.timeToFirstMs >= 0 ? '+' + durationMs(r.timeToFirstMs) : 'not yet',
        r.uniqueIps, r.attempts, r.accepted, r.commands,
        r.lastSeen ? shortStamp(r.lastSeen) : ''
      ]), [72, 36, 44, 34, 52, 34, 44, 46, 36, 96]);
    section('Top source IPs', ['IP', 'Country', 'Events'],
      (stats.topIps || []).map((r) => {
        const loc = geoOf({ remoteIp: r.key }) || {};
        return [r.key, [loc.countryCode, loc.country].filter(Boolean).join(' ') || '', r.count];
      }), [170, 180, 90]);
    section('Source countries', ['Country', 'Code', 'Unique IPs', 'Events'],
      (stats.topCountries || []).map((r) => [r.name || '', r.code || '', r.uniqueIps, r.count]),
      [200, 60, 90, 90]);
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
        ['Time', 'Service', 'Type', 'Source', 'CC', 'User', 'Detail'],
        list.map((e) => [
          new Date(e.ts).toLocaleString(),
          e.service || '',
          e.type || '',
          e.remoteIp || '',
          (geoOf(e) || {}).countryCode || '',
          e.username || '',
          detailText(e)
        ]),
        [100, 56, 72, 84, 24, 52, 127],
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
