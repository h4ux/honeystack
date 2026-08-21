/* eslint-disable no-undef */
(function () {
  const state = {
    events: [],
    maxEvents: 500,
    paused: false,
    filter: { service: '', type: '', ip: '' },
    services: [],
    config: null,
    selectedSession: null,
    currentTab: 'live'
  };

  const socket = io({
    transports: ['websocket', 'polling'],
    withCredentials: true
  });

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  socket.on('connect', () => {
    $('#conn-dot').classList.add('on');
    $('#status-summary').textContent = 'live';
  });
  socket.on('disconnect', () => {
    $('#conn-dot').classList.remove('on');
    $('#status-summary').textContent = 'disconnected';
  });

  socket.on('event', (evt) => {
    if (state.paused) return;
    state.events.push(evt);
    if (state.events.length > state.maxEvents) state.events.shift();
    updateFilterOptions(evt);
    renderNewEvent(evt);
  });

  socket.on('session:open', () => { if (state.currentTab === 'sessions') refreshSessions(); });
  socket.on('session:close', () => { if (state.currentTab === 'sessions') refreshSessions(); });

  // Tabs
  $$('.tab').forEach((btn) => {
    btn.addEventListener('click', () => selectTab(btn.dataset.tab));
  });
  function selectTab(tab) {
    state.currentTab = tab;
    $$('.tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    $$('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === 'tab-' + tab));
    if (tab === 'sessions') refreshSessions();
    if (tab === 'services') refreshServices();
    if (tab === 'config') loadConfig();
    if (tab === 'stats') refreshStats();
  }

  // Live feed
  $('#autoscroll'); $('#paused').addEventListener('change', (e) => { state.paused = e.target.checked; });
  $('#clear-feed').addEventListener('click', () => { state.events = []; $('#feed').innerHTML = ''; });
  ['#filter-service', '#filter-type', '#filter-ip'].forEach((sel) => {
    $(sel).addEventListener('input', () => {
      state.filter.service = $('#filter-service').value;
      state.filter.type = $('#filter-type').value;
      state.filter.ip = $('#filter-ip').value.trim();
      rerenderFeed();
    });
  });

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
    if (state.filter.ip && evt.remote_ip !== state.filter.ip && evt.remoteIp !== state.filter.ip) return false;
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
    const ip = evt.remote_ip || evt.remoteIp || '';
    const port = evt.remote_port || evt.remotePort || '';
    const localPort = evt.local_port || evt.localPort || '';
    const rawDetails = evt.details;
    let details = '';
    if (evt.username) details += ` user=${evt.username}`;
    if (evt.password) details += ` pass=${evt.password}`;
    if (evt.command) details += ` cmd=${evt.command}`;
    if (rawDetails) {
      const d = typeof rawDetails === 'string' ? tryParse(rawDetails) : rawDetails;
      if (d && typeof d === 'object') {
        const parts = [];
        for (const [k, v] of Object.entries(d)) {
          if (v === null || v === undefined) continue;
          if (typeof v === 'object') parts.push(`${k}=${JSON.stringify(v).slice(0, 120)}`);
          else parts.push(`${k}=${String(v).slice(0, 120)}`);
        }
        if (parts.length) details += ' ' + parts.join(' ');
      }
    }
    div.innerHTML = `
      <span class="time">${escape(time)}</span>
      <span class="service">${escape(evt.service)}</span>
      <span class="type">${escape(evt.type)}</span>
      <span class="ip">${escape(ip)}${port ? ':' + port : ''}</span>
      <span class="details">${escape(details.trim())}</span>
      <span class="badge">→ :${localPort || ''}</span>
    `;
    if (evt.session_id || evt.sessionId) {
      div.style.cursor = 'pointer';
      div.title = 'Click to open session transcript';
      div.addEventListener('click', () => {
        state.selectedSession = evt.session_id || evt.sessionId;
        selectTab('sessions');
        setTimeout(() => openSession(state.selectedSession), 100);
      });
    }
    return div;
  }

  function tryParse(s) { try { return JSON.parse(s); } catch { return s; } }
  function escape(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Sessions
  $('#refresh-sessions').addEventListener('click', refreshSessions);
  async function refreshSessions() {
    const res = await fetch('/api/sessions?service=ssh&limit=200');
    const { sessions } = await res.json();
    const list = $('#sessions');
    list.innerHTML = '';
    for (const s of sessions) {
      const li = document.createElement('li');
      if (s.id === state.selectedSession) li.classList.add('active');
      const t = new Date(s.opened_at).toLocaleString();
      const state_ = s.closed_at ? 'closed' : 'active';
      li.innerHTML = `
        <div><span class="ip">${escape(s.remote_ip || '')}</span> <span class="user">${escape(s.username || '')}</span></div>
        <div class="time">${escape(t)} · ${escape(state_)} · ${s.command_count || 0} cmds</div>
      `;
      li.addEventListener('click', () => {
        state.selectedSession = s.id;
        openSession(s.id);
        refreshSessions();
      });
      list.appendChild(li);
    }
  }

  async function openSession(id) {
    const res = await fetch('/api/sessions/' + encodeURIComponent(id));
    if (!res.ok) { $('#session-transcript').textContent = 'Session not found.'; return; }
    const s = await res.json();
    $('#session-meta').innerHTML = `
      Session <b>${escape(s.id)}</b> · ${escape(s.service)} ·
      from <b>${escape(s.remote_ip || '')}</b> · user <b>${escape(s.username || '')}</b> ·
      opened ${escape(new Date(s.opened_at).toLocaleString())}
      ${s.closed_at ? ' · closed ' + escape(new Date(s.closed_at).toLocaleString()) : ' · <span style="color:var(--ok)">active</span>'}
    `;
    const pre = $('#session-transcript');
    pre.innerHTML = '';
    for (const evt of s.events) {
      const line = document.createElement('div');
      const t = new Date(evt.ts).toLocaleTimeString();
      if (evt.type === 'command') {
        line.innerHTML = `<span class="meta">[${escape(t)}]</span> <span class="prompt">${escape(s.username || 'root')}@honeypot:~$</span> <span class="cmd">${escape(evt.command)}</span>`;
      } else if (evt.type === 'exec') {
        line.innerHTML = `<span class="meta">[${escape(t)}]</span> <span class="prompt">ssh exec:</span> <span class="cmd">${escape(evt.command)}</span>`;
      } else if (evt.type === 'auth_attempt' || evt.type === 'auth_success' || evt.type === 'login_attempt') {
        line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.type)} user=${escape(evt.username || '')} pass=${escape(evt.password || '')}</span>`;
      } else if (evt.type === 'connection' || evt.type === 'connection_closed' || evt.type === 'authenticated') {
        line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.type)}${evt.details ? ' ' + escape(JSON.stringify(evt.details)) : ''}</span>`;
      } else if (evt.type === 'env') {
        line.innerHTML = `<span class="meta">[${escape(t)}] env ${escape(evt.details?.key)}=${escape(evt.details?.value)}</span>`;
      } else {
        line.innerHTML = `<span class="meta">[${escape(t)}] ${escape(evt.type)}${evt.details ? ' ' + escape(JSON.stringify(evt.details)) : ''}</span>`;
      }
      pre.appendChild(line);
    }
    pre.scrollTop = pre.scrollHeight;
  }

  // Services
  async function refreshServices() {
    const [servicesRes, cfgRes] = await Promise.all([fetch('/api/services'), fetch('/api/config')]);
    state.services = await servicesRes.json();
    state.config = await cfgRes.json();
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
    $$('#services-grid select[data-ssh-mode]').forEach((el) => {
      el.addEventListener('change', async () => {
        state.config.services.ssh.fakeAuth.mode = el.value;
        await saveConfig();
      });
    });
    $$('#services-grid input[data-ssh-prob]').forEach((el) => {
      el.addEventListener('change', async () => {
        state.config.services.ssh.fakeAuth.acceptProbability = Number(el.value);
        await saveConfig();
      });
    });
    $$('#services-grid input[data-ssh-users]').forEach((el) => {
      el.addEventListener('change', async () => {
        state.config.services.ssh.fakeAuth.acceptedUsernames = el.value.split(',').map((s) => s.trim()).filter(Boolean);
        await saveConfig();
      });
    });
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
    const res = await fetch('/api/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(state.config)
    });
    if (!res.ok) console.error('config save failed', await res.text());
    state.config = await res.json();
  }

  // Config editor
  $('#config-reload').addEventListener('click', loadConfig);
  $('#config-save').addEventListener('click', async () => {
    try {
      const parsed = JSON.parse($('#config-editor').value);
      state.config = parsed;
      await saveConfig();
      $('#config-status').textContent = 'Config applied at ' + new Date().toLocaleTimeString();
    } catch (err) {
      $('#config-status').textContent = 'Invalid JSON: ' + err.message;
      $('#config-status').style.color = 'var(--danger)';
      return;
    }
    $('#config-status').style.color = 'var(--ok)';
  });
  async function loadConfig() {
    const res = await fetch('/api/config');
    state.config = await res.json();
    $('#config-editor').value = JSON.stringify(state.config, null, 2);
    $('#config-status').textContent = '';
  }

  // Stats
  async function refreshStats() {
    const res = await fetch('/api/stats');
    const s = await res.json();
    const cards = [
      ['Total events', s.total],
      ['Last 24 hours', s.last24h],
      ['Unique source IPs', s.uniqueIps],
      ['Active sessions', s.activeSessions]
    ];
    $('#stats-cards').innerHTML = cards.map(([l, v]) => `<div class="card"><div class="label">${l}</div><div class="value">${v ?? 0}</div></div>`).join('');
    $('#stats-ips tbody').innerHTML = (s.topIps || []).map((r) => `<tr><td>${escape(r.remote_ip)}</td><td>${r.c}</td></tr>`).join('');
    $('#stats-services tbody').innerHTML = (s.byService || []).map((r) => `<tr><td>${escape(r.service)}</td><td>${r.c}</td></tr>`).join('');
    $('#stats-creds tbody').innerHTML = (s.topCreds || []).map((r) => `<tr><td>${escape(r.username || '')}</td><td>${escape(r.password || '')}</td><td>${r.c}</td></tr>`).join('');
    $('#stats-commands tbody').innerHTML = (s.topCommands || []).map((r) => `<tr><td>${escape(r.command || '')}</td><td>${r.c}</td></tr>`).join('');
  }

  // Preload live feed
  fetch('/api/events?limit=200')
    .then((r) => r.json())
    .then(({ events }) => {
      state.events = events;
      for (const e of events) updateFilterOptions(e);
      rerenderFeed();
    });

  setInterval(() => { if (state.currentTab === 'stats') refreshStats(); }, 5000);
})();
