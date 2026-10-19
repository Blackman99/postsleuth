(() => {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const NS = 'http://www.w3.org/2000/svg';

  /* ---------- network map: trains ---------- */
  const svg = document.getElementById('netmap');
  const layer = document.getElementById('trains');
  const routes = {
    gmail:   'M100,180 H220 L320,280 H600',
    outlook: 'M100,380 H220 L320,280 H800 H1000',
    fast:    'M100,180 H220 L320,280 H800 L890,370 H1000',
    local:   'M100,380 H220 L320,280 H600 V160 L660,100 H1000',
    bounce:  'M100,180 H220 L320,280 H720 V520 L680,560 H360 L320,520 V280',
    loop:    'M600,280 L660,340 V440 L620,480 H580 L540,440 V340 L600,280'
  };
  const paths = {};
  for (const [k, d] of Object.entries(routes)) {
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d);
    paths[k] = { el: p, len: 0 };
  }
  const hidden = document.createElementNS(NS, 'g');
  hidden.setAttribute('visibility', 'hidden');
  Object.values(paths).forEach(p => hidden.appendChild(p.el));
  svg.appendChild(hidden);
  Object.values(paths).forEach(p => { p.len = p.el.getTotalLength(); });

  function makeTrain(cls) {
    const r = document.createElementNS(NS, 'rect');
    r.setAttribute('width', 26); r.setAttribute('height', 12); r.setAttribute('rx', 6);
    r.setAttribute('x', -13); r.setAttribute('y', -6);
    r.setAttribute('class', 'train ' + (cls || ''));
    layer.appendChild(r);
    return r;
  }
  function place(r, path, dist) {
    const L = path.len;
    const d = Math.max(0, Math.min(L, dist));
    const a = path.el.getPointAtLength(d);
    const b = path.el.getPointAtLength(Math.min(L, d + 1));
    const ang = Math.atan2(b.y - a.y, b.x - a.x) * 180 / Math.PI;
    r.setAttribute('transform', `translate(${a.x.toFixed(1)},${a.y.toFixed(1)}) rotate(${ang.toFixed(1)})`);
  }

  const count = document.getElementById('loopcount');
  let waiting = 205;
  const loopers = [];

  if (reduce) {
    // Parked trains, final state.
    [[paths.outlook, 0.62], [paths.fast, 0.95], [paths.local, 0.8], [paths.bounce, 0.7]].forEach(([p, f], i) => {
      place(makeTrain(i === 3 ? 'back' : ''), p, p.len * f);
    });
    for (let i = 0; i < 5; i++) place(makeTrain('stuck'), paths.loop, paths.loop.len * i / 5);
  } else {
    const SPEED = 0.15; // px per ms
    const trains = [];
    const plan = ['gmail', 'fast', 'gmail', 'local', 'outlook', 'gmail', 'bounce', 'gmail', 'fast', 'gmail', 'local'];
    let next = 0, lastSpawn = -9999;
    let visible = true;
    new IntersectionObserver(es => { visible = es[0].isIntersecting; }).observe(svg);
    function spawn(t) {
      const kind = plan[next++ % plan.length];
      const cls = kind === 'bounce' ? '' : '';
      trains.push({ kind, r: makeTrain(cls), d: 0, t0: t });
    }
    function tick(t, dt, draw = true) {
      if (t - lastSpawn > 950) { spawn(t); lastSpawn = t; }
      for (let i = trains.length - 1; i >= 0; i--) {
        const tr = trains[i];
        tr.d += SPEED * dt;
        const p = paths[tr.kind];
        if (tr.kind === 'bounce' && tr.d > paths.bounce.len * 0.33) tr.r.classList.add('back');
        if (tr.d >= p.len) {
          if (tr.kind === 'gmail') {
            tr.r.classList.add('stuck');
            loopers.push({ r: tr.r, d: 0 });
            if (loopers.length > 6) loopers.shift().r.remove();
            waiting++; count.textContent = waiting + ' waiting';
          } else {
            tr.r.remove();
          }
          trains.splice(i, 1);
          continue;
        }
        if (draw) place(tr.r, p, tr.d);
      }
      loopers.forEach(lp => {
        lp.d = (lp.d + SPEED * 0.6 * dt) % paths.loop.len;
        if (draw) place(lp.r, paths.loop, lp.d);
      });
    }
    // warm up so the first frame already shows a running network
    for (let i = 0; i < 4; i++) loopers.push({ r: makeTrain('stuck'), d: paths.loop.len * i / 4 });
    let vt = 0;
    for (; vt < 7000; vt += 16) tick(vt, 16, false);
    tick(vt, 0);
    waiting = 205; count.textContent = '205 waiting';
    let last = null;
    function frame(t) {
      if (last === null) last = t;
      const dt = Math.min(48, t - last); last = t;
      if (visible && !document.hidden) { vt += dt; tick(vt, dt); }
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  const sc = document.querySelector('.map-scroll');
  if (sc && sc.scrollWidth > sc.clientWidth + 4) sc.scrollLeft = sc.scrollWidth * 0.52 - sc.clientWidth / 2;

  /* ---------- strip maps: train passes, stations light ---------- */
  document.querySelectorAll('[data-strip]').forEach(strip => {
    const stops = [...strip.querySelectorAll('.stops li')];
    const tr = strip.querySelector('.strain');
    if (reduce) { stops.forEach(s => s.classList.add('lit')); return; }
    const io = new IntersectionObserver(es => {
      if (!es[0].isIntersecting) return;
      io.disconnect();
      const dur = 1800 + stops.length * 120, t0 = performance.now();
      tr.style.opacity = 1;
      const svgW = strip.querySelector('.strip-svg').getBoundingClientRect().width || 1;
      function step(t) {
        const f = Math.min(1, (t - t0) / dur);
        const e = f < .5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2;
        tr.setAttribute('x', 8 + e * 964);
        const xPx = e * svgW;
        stops.forEach(s => {
          const dot = s.querySelector('.dot').getBoundingClientRect();
          const base = strip.querySelector('.strip-svg').getBoundingClientRect().left;
          if (dot.left - base <= xPx + 4) s.classList.add('lit');
        });
        if (f < 1) requestAnimationFrame(step); else stops.forEach(s => s.classList.add('lit'));
      }
      requestAnimationFrame(step);
    }, { threshold: 0.4 });
    io.observe(strip);
  });

  /* ---------- qshape platform matrix ---------- */
  const data = {
    buckets: ['5', '10', '20', '40', '80', '160', '320', '640', '1280', '1280+'],
    rows: [
      ['TOTAL', 205, [0, 1, 8, 14, 22, 42, 72, 10, 20, 16]],
      ['gmail.com', 141, [0, 1, 6, 12, 21, 36, 65, 0, 0, 0]],
      ['outlook.com', 23, [0, 0, 0, 0, 0, 1, 4, 7, 7, 4]],
      ['oldcorp.example', 14, [0, 0, 0, 0, 0, 0, 0, 1, 5, 8]],
      ['hotmail.com', 11, [0, 0, 0, 0, 0, 0, 1, 2, 6, 2]],
      ['googlemail.com', 9, [0, 0, 0, 1, 1, 5, 2, 0, 0, 0]],
      ['acme-typo.example', 4, [0, 0, 0, 0, 0, 0, 0, 1, 2, 1]]
    ]
  };
  const m = document.getElementById('matrix');
  const g = document.createElement('div');
  g.className = 'mx';
  const cell = (cls, txt) => { const d = document.createElement('div'); d.className = cls; if (txt !== undefined) d.textContent = txt; g.appendChild(d); return d; };
  cell('h', ''); cell('h', 'T'); data.buckets.forEach(b => cell('h', b));
  data.rows.forEach(([dom, tot, cells], ri) => {
    cell('d', dom); cell('t', tot);
    cells.forEach((n, ci) => {
      const c = cell('c');
      if (n > 0) {
        const i = document.createElement('i');
        const s = Math.round(6 + Math.sqrt(n) * 2.6);
        i.style.width = i.style.height = Math.min(s, 28) + 'px';
        if (ri === 0) i.style.background = '#241a33';
        i.style.transitionDelay = (ci * 90 + ri * 25) + 'ms';
        c.title = `${dom}: ${n} message(s), ${data.buckets[ci]} min bucket`;
        c.appendChild(i);
      }
    });
  });
  m.appendChild(g);
  if (reduce) g.classList.add('on');
  else new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { g.classList.add('on'); o.disconnect(); } }, { threshold: 0.35 }).observe(m);


  /* ---------- connections: provider playbook notices ---------- */
  const conn = document.querySelector('[data-conn]');
  if (conn) {
    conn.classList.add('js');
    const tabs = [...conn.querySelectorAll('[role=tab]')];
    const panels = tabs.map(t => document.getElementById(t.getAttribute('aria-controls')));
    let run = 0;
    // a train runs down the line and each step lights as it passes
    function ride(panel) {
      const ol = panel.querySelector('.n-steps');
      const steps = [...ol.children].filter(n => n.tagName === 'LI');
      steps.forEach(li => li.classList.remove('lit'));
      if (reduce) { steps.forEach(li => li.classList.add('lit')); return; }
      let tr = ol.querySelector('.n-train');
      if (!tr) { tr = document.createElement('span'); tr.className = 'n-train'; tr.setAttribute('aria-hidden', 'true'); ol.appendChild(tr); }
      const id = ++run, t0 = performance.now(), dur = 380 * steps.length + 300;
      const top = steps[0].offsetTop + 8, end = steps[steps.length - 1].offsetTop + 8;
      function f(t) {
        if (id !== run) return;
        const k = Math.min(1, (t - t0) / dur);
        const e = 1 - Math.pow(1 - k, 2);
        const y = top + (end - top) * e;
        tr.style.transform = `translateY(${y.toFixed(1)}px)`;
        steps.forEach(li => { if (li.offsetTop + 4 <= y + 4) li.classList.add('lit'); });
        if (k < 1) requestAnimationFrame(f);
        else { steps.forEach(li => li.classList.add('lit')); tr.style.opacity = 0; }
      }
      tr.style.transition = 'none'; tr.style.transform = `translateY(${top}px)`; tr.style.opacity = 1; void tr.offsetWidth; tr.style.transition = '';
      requestAnimationFrame(f);
    }
    function select(i, focus) {
      tabs.forEach((t, j) => {
        const on = i === j;
        t.setAttribute('aria-selected', on);
        t.tabIndex = on ? 0 : -1;
        panels[j].hidden = !on;
      });
      if (focus) tabs[i].focus();
      ride(panels[i]);
    }
    tabs.forEach((t, i) => {
      t.addEventListener('click', () => select(i));
      t.addEventListener('keydown', e => {
        const k = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
        if (k) { e.preventDefault(); select((i + k + tabs.length) % tabs.length, true); }
        else if (e.key === 'Home') { e.preventDefault(); select(0, true); }
        else if (e.key === 'End') { e.preventDefault(); select(tabs.length - 1, true); }
      });
    });
    tabs.forEach((t, j) => { t.tabIndex = j === 0 ? 0 : -1; panels[j].hidden = j !== 0; });
    panels.forEach(p => p.tabIndex = 0);
    if (reduce) ride(panels[0]);
    else new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { o.disconnect(); ride(panels[0]); } }, { threshold: 0.45 }).observe(conn);
  }

  /* ---------- points lever ---------- */
  const lever = document.getElementById('lever');
  const sec = lever.closest('.points');
  lever.addEventListener('click', () => {
    const on = lever.getAttribute('aria-pressed') !== 'true';
    lever.setAttribute('aria-pressed', on);
    lever.querySelector('span').textContent = on ? 'on' : 'off';
    sec.classList.toggle('open', on);
  });
})();
