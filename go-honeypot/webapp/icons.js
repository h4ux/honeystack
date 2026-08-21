/* icons.js — one glyph per honeypot service.
   These are protocol glyphs drawn here rather than vendor logos: no
   trademarked marks ship with the dashboard, and every service (including
   ones you add yourself) still gets a recognisable icon. Each glyph is a
   24x24 stroke drawing that inherits its colour from the service palette
   in charts.js. */
(function () {
  // Stroke paths, drawn on a 24x24 grid.
  const GLYPHS = {
    // A terminal window with a prompt: interactive shells.
    terminal: '<rect x="2.5" y="4" width="19" height="16" rx="2.5"/><path d="M2.5 8h19"/><path d="M6 12l2.5 2.5L6 17"/><path d="M11 17h6"/>',
    // A screen on a stand: remote desktops.
    screen: '<rect x="2.5" y="4" width="19" height="12.5" rx="2"/><path d="M9 20h6M12 16.5V20"/><path d="M6 8.5h6"/>',
    // Stacked discs: databases.
    database: '<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6"/><path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/>',
    // Lightning over discs: in-memory caches.
    cache: '<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6"/><path d="M13 9.5l-3 4h2.5l-1 4 3.5-4.5H12z"/>',
    // A globe: anything HTTP.
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><ellipse cx="12" cy="12" rx="4" ry="9"/>',
    // Folder with an up/down arrow: file transfer.
    transfer: '<path d="M3 7.5A1.5 1.5 0 014.5 6H9l2 2.5h8.5A1.5 1.5 0 0121 10v7.5a1.5 1.5 0 01-1.5 1.5h-15A1.5 1.5 0 013 17.5z"/><path d="M12 16.5v-5M9.5 14l2.5-2.5 2.5 2.5"/>',
    // Envelope: mail protocols.
    envelope: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="M3 7l9 6.5L21 7"/>',
    // Two arrows passing through a gate: forward proxies.
    proxy: '<path d="M3 8h7l3 4h8"/><path d="M18 9l3 3-3 3"/><path d="M3 16h7"/><rect x="10" y="4" width="4" height="16" rx="1.5"/>',
    // Shield with a tunnel: VPN endpoints.
    shield: '<path d="M12 2.5l8 3v6.5c0 5-3.4 8.4-8 9.5-4.6-1.1-8-4.5-8-9.5V5.5z"/><path d="M8.5 12h7M12 8.5v7"/>',
    // Handset: SIP / VoIP.
    phone: '<path d="M7 3.5h3l1.5 4-2 1.5a11 11 0 005.5 5.5l1.5-2 4 1.5v3a2 2 0 01-2.2 2A16.5 16.5 0 015 5.7 2 2 0 017 3.5z"/>',
    // Signpost: DNS lookups.
    signpost: '<path d="M12 3v18"/><path d="M12 6h6l2 2.5-2 2.5h-6z"/><path d="M12 13H6l-2 2.5 2 2.5h6z"/>',
    // Gauge: SNMP polling.
    gauge: '<path d="M3.5 17a9 9 0 1117 0"/><path d="M12 17l4.5-5"/><circle cx="12" cy="17" r="1.6"/>',
    // Clock: NTP.
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.5l3.5 2"/>',
    // Directory tree: LDAP.
    directory: '<rect x="9" y="2.5" width="6" height="5" rx="1"/><rect x="2.5" y="16.5" width="6" height="5" rx="1"/><rect x="15.5" y="16.5" width="6" height="5" rx="1"/><path d="M12 7.5v4.5M5.5 16.5V12h13v4.5M12 12v-0"/>',
    // Broadcast waves: MQTT / pub-sub.
    broadcast: '<circle cx="12" cy="18" r="2"/><path d="M7.5 14.5a6 6 0 019 0"/><path d="M4.5 11a10 10 0 0115 0"/>',
    // Shipping container: Docker Engine API.
    container: '<rect x="2.5" y="7.5" width="19" height="11" rx="1.5"/><path d="M7 7.5v11M12 7.5v11M17 7.5v11"/>',
    // Phone body with a bug: ADB.
    mobile: '<rect x="6" y="2.5" width="12" height="19" rx="2.5"/><path d="M10.5 5.5h3"/><circle cx="12" cy="17.5" r="1.4"/>',
    // Magnifier over a document: search engines.
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5L21 21"/>',
    // Plug: generic listener.
    plug: '<path d="M9 3v5M15 3v5"/><path d="M6.5 8h11v3a5.5 5.5 0 01-11 0z"/><path d="M12 16.5V21"/>',
    // Gear: the daemon itself.
    gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.5l1.2 2.6 2.8-.7.5 2.9 2.7 1-1.4 2.6 1.9 2.2-2.4 1.6.4 2.9-2.9.2-1.3 2.6-2.5-1.5-2.5 1.5-1.3-2.6-2.9-.2.4-2.9L2.3 14l1.9-2.2-1.4-2.6 2.7-1 .5-2.9 2.8.7z"/>'
  };

  // Which glyph each service uses. Unknown names fall back by keyword, then
  // to the generic plug.
  const MAP = {
    ssh: 'terminal', telnet: 'terminal',
    rdp: 'screen', vnc: 'screen',
    mysql: 'database', postgres: 'database', mssql: 'database',
    mongodb: 'database', clickhouse: 'database', 'clickhouse-native': 'database',
    redis: 'cache', memcached: 'cache',
    http: 'globe', 'http-alt': 'globe',
    elasticsearch: 'search',
    docker: 'container',
    mqtt: 'broadcast',
    ftp: 'transfer', smb: 'transfer', rsync: 'transfer', tftp: 'transfer',
    smtp: 'envelope', 'smtp-submission': 'envelope', imap: 'envelope', pop3: 'envelope',
    squid: 'proxy', 'http-proxy': 'proxy', socks: 'proxy',
    openvpn: 'shield', 'openvpn-tcp': 'shield', 'ipsec-ike': 'shield',
    'ipsec-natt': 'shield', wireguard: 'shield', l2tp: 'shield', pptp: 'shield',
    sip: 'phone', 'sip-tcp': 'phone',
    dns: 'signpost',
    snmp: 'gauge',
    ntp: 'clock',
    ldap: 'directory',
    adb: 'mobile',
    system: 'gear'
  };

  const KEYWORDS = [
    [/ssh|shell|telnet/, 'terminal'],
    [/rdp|vnc|desktop/, 'screen'],
    [/sql|mongo|db|clickhouse|cassandra|oracle/, 'database'],
    [/redis|memcache|cache/, 'cache'],
    [/http|web|nginx|apache|jenkins|grafana|kibana/, 'globe'],
    [/ftp|smb|rsync|tftp|share|file/, 'transfer'],
    [/smtp|imap|pop|mail/, 'envelope'],
    [/proxy|squid|socks/, 'proxy'],
    [/vpn|ipsec|wireguard|l2tp|pptp|tunnel/, 'shield'],
    [/sip|voip|asterisk/, 'phone'],
    [/dns|resolver/, 'signpost'],
    [/snmp/, 'gauge'],
    [/ntp|time/, 'clock'],
    [/ldap|directory/, 'directory'],
    [/adb|android/, 'mobile'],
    [/mqtt|amqp|kafka|queue/, 'broadcast'],
    [/docker|container|kube/, 'container'],
    [/elastic|search|solr/, 'search']
  ];

  function glyphFor(service) {
    const name = String(service || '').toLowerCase();
    if (MAP[name]) return MAP[name];
    for (const [re, glyph] of KEYWORDS) {
      if (re.test(name)) return glyph;
    }
    return 'plug';
  }

  function colorFor(service) {
    return (window.Charts && Charts.colorFor) ? Charts.colorFor(service, 0) : '#6b8afd';
  }

  /* Inline SVG for one service. size is in px; strokes scale with it. */
  function svg(service, size, opts) {
    const o = opts || {};
    const px = size || 16;
    const glyph = GLYPHS[glyphFor(service)] || GLYPHS.plug;
    const color = o.color || colorFor(service);
    const width = o.strokeWidth || (px <= 14 ? 2 : 1.7);
    const label = String(service || '');
    return `<svg class="svc-icon" viewBox="0 0 24 24" width="${px}" height="${px}" role="img" aria-label="${escapeAttr(label)}"` +
      ` fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round">${glyph}</svg>`;
  }

  /* Icon + name, the shape most tables want. */
  function label(service, size) {
    return `<span class="svc-label">${svg(service, size || 15)}<span>${escapeAttr(service || '')}</span></span>`;
  }

  function escapeAttr(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  window.ServiceIcons = { svg, label, glyphFor, colorFor, GLYPHS, MAP };
})();
