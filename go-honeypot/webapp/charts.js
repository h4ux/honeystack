/* charts.js — tiny canvas charting used by the stats dashboard.
   No dependencies, no build step. Every chart is theme-able so the same
   data can be painted dark for the screen and light for the PDF report,
   and every chart remembers its inputs on the canvas element so it can
   be repainted on resize. */
(function () {
  const PALETTE = [
    '#6b8afd', '#7cf2c8', '#ffcf6b', '#ff6b8b', '#b98bff',
    '#6bd2ff', '#ffa26b', '#9dff6b', '#ff6bd2', '#6bffe4',
    '#fd8a6b', '#8bffb9'
  ];

  // Stable per-service colours: the same listener keeps its colour across
  // the donut, the tables and the timeline instead of shifting whenever
  // the ranking changes.
  const NAMED = {
    ssh: '#6b8afd', telnet: '#7cf2c8', ftp: '#ffcf6b', http: '#ff6b8b',
    rdp: '#b98bff', mysql: '#6bd2ff', vnc: '#ffa26b', smb: '#9dff6b',
    redis: '#ff6bd2', postgres: '#6bffe4', clickhouse: '#fd8a6b',
    'clickhouse-native': '#c9b06b', mssql: '#8bffb9', mongodb: '#7dd87d',
    elasticsearch: '#f2d06b', docker: '#6bb8fd', mqtt: '#d88bff',
    system: '#8892b8'
  };

  const THEMES = {
    dark: {
      bg: '#141b33',
      grid: 'rgba(255,255,255,0.07)',
      axis: 'rgba(255,255,255,0.16)',
      text: '#e6e9f2',
      muted: '#8892b8',
      track: 'rgba(255,255,255,0.05)',
      ring: '#141b33'
    },
    light: {
      bg: '#ffffff',
      grid: 'rgba(16,20,40,0.09)',
      axis: 'rgba(16,20,40,0.25)',
      text: '#151a2b',
      muted: '#5b6480',
      track: 'rgba(16,20,40,0.06)',
      ring: '#ffffff'
    }
  };

  function colorFor(key, i) {
    const k = String(key || '').toLowerCase();
    if (NAMED[k]) return NAMED[k];
    return PALETTE[i % PALETTE.length];
  }

  function theme(name) { return THEMES[name] || THEMES.dark; }

  /* Size the backing store to the CSS box at device resolution so text
     and hairlines stay crisp. Offscreen canvases (the PDF path) have no
     layout box, so they pass explicit width/height. */
  function fit(canvas, opts) {
    const o = opts || {};
    const dpr = o.dpr || Math.min(window.devicePixelRatio || 1, 2);
    const cssW = o.width || canvas.clientWidth || 640;
    // Aspect keeps charts proportional on phones; maxHeight stops the
    // wide panels from turning into billboards on a desktop monitor.
    let cssH = o.height || Math.max(140, Math.round(cssW / (o.aspect || 2.6)));
    if (o.maxHeight) cssH = Math.min(cssH, o.maxHeight);
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    if (!o.width) canvas.style.height = cssH + 'px';
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    return { ctx, w: cssW, h: cssH };
  }

  function roundRect(ctx, x, y, w, h, r) {
    const rad = Math.max(0, Math.min(r, Math.abs(w) / 2, Math.abs(h) / 2));
    ctx.beginPath();
    ctx.moveTo(x + rad, y);
    ctx.arcTo(x + w, y, x + w, y + h, rad);
    ctx.arcTo(x + w, y + h, x, y + h, rad);
    ctx.arcTo(x, y + h, x, y, rad);
    ctx.arcTo(x, y, x + w, y, rad);
    ctx.closePath();
  }

  function fade(ctx, x0, y0, x1, y1, color, from, to) {
    const g = ctx.createLinearGradient(x0, y0, x1, y1);
    g.addColorStop(0, alpha(color, from));
    g.addColorStop(1, alpha(color, to));
    return g;
  }

  function alpha(hex, a) {
    const h = String(hex).replace('#', '');
    const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
    const n = parseInt(full, 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }

  function niceMax(v) {
    if (v <= 5) return Math.max(1, v);
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    for (const step of [1, 2, 2.5, 5, 10]) {
      if (v <= step * mag) return step * mag;
    }
    return 10 * mag;
  }

  function fmt(n) {
    const v = Number(n) || 0;
    if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (Math.abs(v) >= 1e4) return (v / 1e3).toFixed(0) + 'k';
    if (Math.abs(v) >= 1e3) return (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(v);
  }

  function yAxis(ctx, box, max, t, ticks) {
    const n = ticks || 4;
    ctx.font = '10px system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= n; i++) {
      const val = (max / n) * i;
      const y = box.y + box.h - (box.h * i) / n;
      ctx.strokeStyle = t.grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(box.x, Math.round(y) + 0.5);
      ctx.lineTo(box.x + box.w, Math.round(y) + 0.5);
      ctx.stroke();
      ctx.fillStyle = t.muted;
      ctx.fillText(fmt(Math.round(val)), box.x - 6, y);
    }
    ctx.textAlign = 'left';
  }

  /* ---------- hover tooltip ----------
     Every chart records rectangles it painted; one delegated listener per
     canvas turns them into a floating readout. */
  let tip;
  function tooltip() {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'chart-tip';
      tip.hidden = true;
      document.body.appendChild(tip);
    }
    return tip;
  }

  function bindHover(canvas) {
    if (canvas.__hoverBound) return;
    canvas.__hoverBound = true;
    canvas.addEventListener('mousemove', (ev) => {
      const hits = canvas.__hits || [];
      const r = canvas.getBoundingClientRect();
      const x = ev.clientX - r.left;
      const y = ev.clientY - r.top;
      let found = null;
      for (const hit of hits) {
        if (x >= hit.x && x <= hit.x + hit.w && y >= hit.y && y <= hit.y + hit.h) { found = hit; break; }
      }
      const el = tooltip();
      if (!found) { el.hidden = true; return; }
      el.innerHTML = found.html;
      el.hidden = false;
      el.style.left = Math.round(ev.clientX + 12) + 'px';
      el.style.top = Math.round(ev.clientY + 12) + 'px';
    });
    canvas.addEventListener('mouseleave', () => { tooltip().hidden = true; });
  }

  function remember(canvas, kind, data, opts) {
    canvas.__chart = { kind, data, opts: opts || {} };
    if (!opts || !opts.width) bindHover(canvas);
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ---------- area / line series over time ---------- */
  function timeline(canvas, data, opts) {
    remember(canvas, 'timeline', data, opts);
    const o = opts || {};
    const t = theme(o.theme);
    const { ctx, w, h } = fit(canvas, Object.assign({ aspect: 3 }, o));
    const rows = data.rows || [];
    const series = (data.series || []).filter((s) => s.values && s.values.length);

    ctx.fillStyle = t.bg;
    roundRect(ctx, 0, 0, w, h, 12);
    ctx.fill();
    if (!rows.length || !series.length) return emptyState(ctx, w, h, t);

    const box = { x: 44, y: 14, w: w - 58, h: h - 46 };
    let max = 0;
    for (const s of series) for (const v of s.values) max = Math.max(max, v || 0);
    max = niceMax(max);
    yAxis(ctx, box, max, t);

    const stepX = box.w / Math.max(1, rows.length - 1);
    const px = (i) => box.x + stepX * i;
    const py = (v) => box.y + box.h - (Math.min(v, max) / max) * box.h;

    // Bars first (they read as "volume"), then lines on top.
    for (const s of series.filter((s) => s.kind === 'bar')) {
      const bw = Math.max(2, stepX * 0.55);
      s.values.forEach((v, i) => {
        if (!v) return;
        const y = py(v);
        ctx.fillStyle = fade(ctx, 0, y, 0, box.y + box.h, s.color, 0.95, 0.35);
        roundRect(ctx, px(i) - bw / 2, y, bw, box.y + box.h - y, 2);
        ctx.fill();
      });
    }
    for (const s of series.filter((s) => s.kind !== 'bar')) {
      ctx.beginPath();
      s.values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
      if (s.fill !== false) {
        ctx.lineTo(px(s.values.length - 1), box.y + box.h);
        ctx.lineTo(px(0), box.y + box.h);
        ctx.closePath();
        ctx.fillStyle = fade(ctx, 0, box.y, 0, box.y + box.h, s.color, 0.38, 0.02);
        ctx.fill();
        ctx.beginPath();
        s.values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
      }
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.stroke();
      // Dots only when the series is short enough to stay readable.
      if (rows.length <= 32) {
        s.values.forEach((v, i) => {
          ctx.fillStyle = s.color;
          ctx.beginPath();
          ctx.arc(px(i), py(v), 2.4, 0, Math.PI * 2);
          ctx.fill();
        });
      }
    }

    // x labels, thinned so they never collide
    ctx.font = '10px system-ui, sans-serif';
    ctx.fillStyle = t.muted;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const every = Math.ceil(rows.length / Math.max(4, Math.floor(box.w / 56)));
    rows.forEach((label, i) => {
      if (i % every) return;
      ctx.fillText(String(label), px(i), box.y + box.h + 8);
    });
    ctx.textAlign = 'left';

    canvas.__hits = rows.map((label, i) => ({
      x: px(i) - stepX / 2, y: box.y, w: Math.max(6, stepX), h: box.h,
      html: `<b>${esc(label)}</b>` + series.map((s) =>
        `<span style="color:${s.color}">■</span> ${esc(s.label)}: ${fmt(s.values[i] || 0)}`).join('<br>')
    }));
    legend(ctx, series, box.x, 6, t, w);
  }

  function legend(ctx, series, x, y, t, w) {
    ctx.font = '10px system-ui, sans-serif';
    ctx.textBaseline = 'top';
    let cx = x;
    for (const s of series) {
      const label = String(s.label || '');
      const tw = ctx.measureText(label).width + 16;
      if (cx + tw > w - 8) break;
      ctx.fillStyle = s.color;
      roundRect(ctx, cx, y + 2, 8, 8, 2);
      ctx.fill();
      ctx.fillStyle = t.muted;
      ctx.fillText(label, cx + 12, y + 1);
      cx += tw + 8;
    }
  }

  function emptyState(ctx, w, h, t) {
    ctx.fillStyle = t.muted;
    ctx.font = '12px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('no data yet', w / 2, h / 2);
    ctx.textAlign = 'left';
  }

  /* ---------- vertical bars ---------- */
  function bars(canvas, rows, opts) {
    remember(canvas, 'bars', rows, opts);
    const o = opts || {};
    const t = theme(o.theme);
    const { ctx, w, h } = fit(canvas, Object.assign({ aspect: 3 }, o));
    ctx.fillStyle = t.bg;
    roundRect(ctx, 0, 0, w, h, 12);
    ctx.fill();
    if (!rows.length) return emptyState(ctx, w, h, t);

    const box = { x: 44, y: 14, w: w - 58, h: h - 46 };
    const max = niceMax(Math.max(1, ...rows.map((r) => r.value || 0)));
    yAxis(ctx, box, max, t);

    const slot = box.w / rows.length;
    const bw = Math.max(3, Math.min(46, slot * 0.68));
    canvas.__hits = [];
    rows.forEach((r, i) => {
      const color = r.color || colorFor(r.label, i);
      const bh = ((r.value || 0) / max) * box.h;
      const x = box.x + slot * i + (slot - bw) / 2;
      const y = box.y + box.h - bh;
      ctx.fillStyle = fade(ctx, 0, y, 0, box.y + box.h, color, 1, 0.28);
      roundRect(ctx, x, y, bw, Math.max(bh, 1.5), 3);
      ctx.fill();
      canvas.__hits.push({ x: box.x + slot * i, y: box.y, w: slot, h: box.h, html: `<b>${esc(r.label)}</b><br>${fmt(r.value)} ${esc(o.unit || 'events')}` });
      ctx.font = '10px system-ui, sans-serif';
      ctx.fillStyle = t.muted;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const label = String(r.label || '');
      const every = Math.ceil(rows.length / Math.max(3, Math.floor(box.w / 52)));
      if (i % every === 0) ctx.fillText(label.length > 9 ? label.slice(0, 8) + '…' : label, x + bw / 2, box.y + box.h + 8);
      ctx.textAlign = 'left';
    });
  }

  /* ---------- horizontal bars (rankings) ---------- */
  function hbars(canvas, rows, opts) {
    remember(canvas, 'hbars', rows, opts);
    const o = opts || {};
    const t = theme(o.theme);
    const count = Math.max(1, rows.length);
    const rowH = o.rowHeight || 22;
    const { ctx, w, h } = fit(canvas, Object.assign({ height: o.height || (count * rowH + 26) }, o));
    ctx.fillStyle = t.bg;
    roundRect(ctx, 0, 0, w, h, 12);
    ctx.fill();
    if (!rows.length) return emptyState(ctx, w, h, t);

    const labelW = Math.min(o.labelWidth || 130, Math.round(w * 0.42));
    const valueW = 46;
    const trackX = labelW + 10;
    const trackW = Math.max(20, w - trackX - valueW - 12);
    const max = Math.max(1, ...rows.map((r) => r.value || 0));
    canvas.__hits = [];
    rows.forEach((r, i) => {
      const color = r.color || colorFor(r.label, i);
      const y = 14 + i * rowH;
      const bh = Math.min(14, rowH - 8);
      ctx.font = '11px system-ui, sans-serif';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = t.text;
      const label = String(r.label || '');
      let shown = label;
      while (shown.length > 4 && ctx.measureText(shown).width > labelW) shown = shown.slice(0, -2);
      ctx.fillText(shown === label ? label : shown + '…', 12, y + bh / 2);

      ctx.fillStyle = t.track;
      roundRect(ctx, trackX, y, trackW, bh, bh / 2);
      ctx.fill();
      const bw = Math.max(2, ((r.value || 0) / max) * trackW);
      ctx.fillStyle = fade(ctx, trackX, 0, trackX + bw, 0, color, 0.55, 1);
      roundRect(ctx, trackX, y, bw, bh, bh / 2);
      ctx.fill();

      ctx.fillStyle = t.muted;
      ctx.textAlign = 'right';
      ctx.fillText(fmt(r.value), w - 12, y + bh / 2);
      ctx.textAlign = 'left';
      canvas.__hits.push({
        x: 0, y: y - 3, w, h: rowH,
        html: `<b>${esc(label)}</b><br>${fmt(r.value)} ${esc(o.unit || 'events')}${r.note ? '<br>' + esc(r.note) : ''}`
      });
    });
  }

  /* ---------- donut ---------- */
  function donut(canvas, rows, opts) {
    remember(canvas, 'donut', rows, opts);
    const o = opts || {};
    const t = theme(o.theme);
    const { ctx, w, h } = fit(canvas, Object.assign({ aspect: 1.9 }, o));
    ctx.fillStyle = t.bg;
    roundRect(ctx, 0, 0, w, h, 12);
    ctx.fill();
    const total = rows.reduce((a, r) => a + (r.value || 0), 0);
    if (!total) return emptyState(ctx, w, h, t);

    const r = Math.min(h * 0.42, w * 0.24);
    const cx = 16 + r + 8;
    const cy = h / 2;
    let ang = -Math.PI / 2;
    canvas.__hits = [];
    rows.forEach((row, i) => {
      const frac = (row.value || 0) / total;
      const end = ang + frac * Math.PI * 2;
      const color = row.color || colorFor(row.label, i);
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, ang, end);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
      ang = end;
    });
    // hole
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.6, 0, Math.PI * 2);
    ctx.fillStyle = t.bg;
    ctx.fill();
    ctx.fillStyle = t.text;
    ctx.font = '600 16px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(fmt(total), cx, cy + 2);
    ctx.font = '9px system-ui, sans-serif';
    ctx.fillStyle = t.muted;
    ctx.fillText(String(o.centerLabel || 'events').toUpperCase(), cx, cy + 15);
    ctx.textAlign = 'left';

    // legend column
    const lx = cx + r + 18;
    const perRow = 17;
    const maxRows = Math.max(1, Math.floor((h - 16) / perRow));
    ctx.textBaseline = 'middle';
    rows.slice(0, maxRows).forEach((row, i) => {
      const y = 14 + i * perRow;
      const color = row.color || colorFor(row.label, i);
      ctx.fillStyle = color;
      roundRect(ctx, lx, y - 4, 9, 9, 2);
      ctx.fill();
      ctx.font = '11px system-ui, sans-serif';
      ctx.fillStyle = t.text;
      const pct = Math.round(((row.value || 0) / total) * 100);
      let label = String(row.label || '');
      const room = w - lx - 70;
      while (label.length > 3 && ctx.measureText(label).width > room) label = label.slice(0, -2);
      ctx.fillText(label, lx + 15, y);
      ctx.fillStyle = t.muted;
      ctx.textAlign = 'right';
      ctx.fillText(`${fmt(row.value)} · ${pct}%`, w - 12, y);
      ctx.textAlign = 'left';
      canvas.__hits.push({ x: lx, y: y - 8, w: w - lx, h: perRow, html: `<b>${esc(row.label)}</b><br>${fmt(row.value)} events · ${pct}%` });
    });
    if (rows.length > maxRows) {
      ctx.fillStyle = t.muted;
      ctx.font = '10px system-ui, sans-serif';
      ctx.fillText(`+${rows.length - maxRows} more`, lx + 15, 14 + maxRows * perRow);
    }
  }

  /* ---------- weekday x hour heatmap ---------- */
  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  function heatmap(canvas, data, opts) {
    remember(canvas, 'heatmap', data, opts);
    const o = opts || {};
    const t = theme(o.theme);
    const grid = data.grid || [];
    const { ctx, w, h } = fit(canvas, Object.assign({ height: o.height || 196 }, o));
    ctx.fillStyle = t.bg;
    roundRect(ctx, 0, 0, w, h, 12);
    ctx.fill();
    const max = data.max || Math.max(1, ...grid);
    if (!grid.length || !max) return emptyState(ctx, w, h, t);

    const left = 34, top = 22, right = 10, bottom = 18;
    const cellW = (w - left - right) / 24;
    const cellH = (h - top - bottom) / 7;
    canvas.__hits = [];
    ctx.font = '9px system-ui, sans-serif';
    ctx.textBaseline = 'middle';
    for (let d = 0; d < 7; d++) {
      ctx.fillStyle = t.muted;
      ctx.textAlign = 'right';
      ctx.fillText(DAYS[d], left - 6, top + cellH * d + cellH / 2);
      ctx.textAlign = 'left';
      for (let hr = 0; hr < 24; hr++) {
        const v = grid[d * 24 + hr] || 0;
        const x = left + cellW * hr;
        const y = top + cellH * d;
        ctx.fillStyle = v ? heatColor(v / max) : t.track;
        roundRect(ctx, x + 1, y + 1, cellW - 2, cellH - 2, 2);
        ctx.fill();
        canvas.__hits.push({ x, y, w: cellW, h: cellH, html: `<b>${DAYS[d]} ${String(hr).padStart(2, '0')}:00 UTC</b><br>${fmt(v)} events` });
      }
    }
    ctx.fillStyle = t.muted;
    ctx.textBaseline = 'top';
    for (let hr = 0; hr < 24; hr += 3) {
      ctx.fillText(String(hr).padStart(2, '0'), left + cellW * hr, h - bottom + 3);
    }
    ctx.fillText('hour of day (UTC) — colour is event volume', left, 6);
  }

  // blue → mint → amber → rose, so busy cells pop out of the grid.
  function heatColor(f) {
    const stops = [
      [0.00, [43, 52, 93]],
      [0.20, [107, 138, 253]],
      [0.45, [124, 242, 200]],
      [0.72, [255, 207, 107]],
      [1.00, [255, 107, 139]]
    ];
    const x = Math.max(0, Math.min(1, f));
    for (let i = 1; i < stops.length; i++) {
      if (x <= stops[i][0]) {
        const [p0, c0] = stops[i - 1];
        const [p1, c1] = stops[i];
        const k = (x - p0) / (p1 - p0 || 1);
        const c = c0.map((v, j) => Math.round(v + (c1[j] - v) * k));
        return `rgb(${c[0]},${c[1]},${c[2]})`;
      }
    }
    return 'rgb(255,107,139)';
  }

  /* ---------- inline sparkline (KPI cards) ---------- */
  function sparkline(canvas, values, opts) {
    remember(canvas, 'sparkline', values, opts);
    const o = opts || {};
    const { ctx, w, h } = fit(canvas, Object.assign({ height: o.height || 34 }, o));
    if (!values.length) return;
    const max = Math.max(1, ...values);
    const color = o.color || PALETTE[0];
    const px = (i) => (w / Math.max(1, values.length - 1)) * i;
    const py = (v) => h - 3 - (v / max) * (h - 8);
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.lineTo(px(values.length - 1), h);
    ctx.lineTo(px(0), h);
    ctx.closePath();
    ctx.fillStyle = fade(ctx, 0, 0, 0, h, color, 0.45, 0.02);
    ctx.fill();
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  }

  /* Repaint a canvas from what it was last drawn with (resize, theme
     switch, or an offscreen light-theme copy for the PDF). */
  function redraw(canvas, override) {
    const spec = canvas.__chart;
    if (!spec) return false;
    const api = { timeline, bars, hbars, donut, heatmap, sparkline };
    const fn = api[spec.kind];
    if (!fn) return false;
    fn(canvas, spec.data, Object.assign({}, spec.opts, override || {}));
    return true;
  }

  /* Draw the same data into a detached canvas at a fixed size — used to
     get light-theme chart images into the PDF report. */
  function offscreen(canvas, width, height) {
    const spec = canvas.__chart;
    if (!spec) return null;
    const out = document.createElement('canvas');
    const api = { timeline, bars, hbars, donut, heatmap, sparkline };
    const fn = api[spec.kind];
    if (!fn) return null;
    // Only override height when we actually have one: a key set to
    // undefined would clobber the per-chart default (row-count sizing for
    // hbars, for instance) and leave a band of empty canvas.
    const override = { theme: 'light', width, dpr: 2 };
    const h = height || spec.opts.height;
    if (h) override.height = h;
    fn(out, spec.data, Object.assign({}, spec.opts, override));
    return out;
  }

  window.Charts = {
    PALETTE, colorFor, timeline, bars, hbars, donut, heatmap, sparkline,
    redraw, offscreen, fmt, heatColor
  };
})();
