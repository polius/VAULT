// The seal: a fine-line pattern, like the ones on banknotes, drawn from a
// file's salt. The salt is random and stored in the clear in every .vault
// header, so the pattern identifies the file and reveals nothing about it. The
// same file always draws the same seal.
//
// Three rings of interlaced strands. Each strand is a circle whose radius
// waves a whole number of times; the salt's first bytes choose how many waves,
// how many strands and how strong the second harmonic is in each ring.
//
// Everything is built with DOM calls (no HTML parsing, so Trusted Types has
// nothing to object to) and animated through CSS custom properties.

const NS = 'http://www.w3.org/2000/svg';
const TAU = Math.PI * 2;
const C = 160; // the drawing is 320 units square
// What an unissued seal looks like: a fixed pattern, drawn faintly.
const SPECIMEN = Uint8Array.of(0x5a, 0x0c, 0x4e, 0x19, 0xa3, 0xd2, 0x7f, 0x6b, 0x88);
const MICRO = 'VAULT · ENCRYPTED IN THIS BROWSER · NOTHING IS UPLOADED · OPEN SOURCE · ';
// How far the three rings are turned away from rest, in degrees per unit of spin.
const TURN = [160, -230, 300];
// Decrypting: each ring stops when progress reaches its share, like tumblers.
const STOPS = [0.45, 0.75, 1];

let serial = 0;

function svg(name, attrs = {}, children = []) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}

function strand(radius, amp, waves, phase, harmonic, steps) {
  let d = '';
  for (let i = 0; i < steps; i++) {
    const t = (i / steps) * TAU;
    const r = radius + amp * Math.sin(waves * t + phase) + harmonic * amp * Math.sin(2 * waves * t + 2 * phase + 1.1);
    d += `${i ? 'L' : 'M'}${(C + r * Math.cos(t)).toFixed(1)} ${(C + r * Math.sin(t)).toFixed(1)}`;
  }
  return `${d}Z`;
}

// The path data of the three rings. `lite` draws fewer strands, for small sizes.
export function ringPaths(salt, lite = false) {
  const b = (i) => salt[i % salt.length];
  const rings = [
    {
      r: 116,
      amp: 12.5,
      waves: 11 + (b(0) % 9),
      strands: lite ? 3 : 5 + (b(1) % 3),
      h: [0, 0.28, 0.45][b(2) % 3],
      dir: 1,
    },
    {
      r: 81,
      amp: 10.5,
      waves: 6 + (b(3) % 6),
      strands: lite ? 2 : 4 + (b(4) % 3),
      h: [0.3, 0, 0.5][b(5) % 3],
      dir: -1,
    },
    { r: 47, amp: 13, waves: 5 + (b(6) % 5), strands: lite ? 2 : 3 + (b(7) % 2), h: [0, 0.35][b(8) % 2], dir: 1 },
  ];
  return rings.map(({ r, amp, waves, strands, h, dir }, ring) => {
    const steps = Math.round((lite ? 300 : 520) * (r / 116)) + (ring ? 40 : 0);
    return Array.from({ length: strands }, (_, k) => strand(r, amp, waves, (dir * TAU * k) / strands, h, steps));
  });
}

// "7C3A 91F2 0B5E": the first six bytes of the salt.
export function sealNumber(salt) {
  const hex = Array.from(salt.subarray(0, 6), (v) => v.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}

function draw(salt, { lite, broken }) {
  const id = `seal${++serial}`;
  const defs = svg('defs');
  const groups = ringPaths(salt, lite).map((paths, i) => {
    const g = svg('g', { id: `${id}r${i}` });
    for (const d of paths) g.append(svg('path', { d, pathLength: '1' }));
    // A hairline circle between the rings turns with the ring inside it.
    if (i < 2) g.append(svg('circle', { cx: C, cy: C, r: i ? 63.5 : 98.5, pathLength: '1' }));
    return g;
  });
  defs.append(...groups);
  if (!lite) defs.append(svg('path', { id: `${id}t`, d: `M${C} 18.5A141.5 141.5 0 1 1 ${C - 0.1} 18.5` }));

  // One copy of everything that makes up the face of the seal.
  const face = () => {
    const rings = () =>
      groups.map((g, i) => svg('g', { class: `seal-ring seal-ring-${i + 1}` }, [svg('use', { href: `#${g.id}` })]));
    const parts = [
      svg('circle', { class: 'seal-rim', cx: C, cy: C, r: lite ? 157 : 158 }),
      svg('circle', { class: 'seal-rim', cx: C, cy: C, r: lite ? 149 : 133 }),
    ];
    if (!lite) {
      const text = svg('text', { class: 'seal-micro' });
      const path = svg('textPath', { href: `#${id}t`, textLength: '884', lengthAdjust: 'spacing' });
      path.textContent = MICRO + MICRO;
      text.append(path);
      parts.push(svg('circle', { class: 'seal-rim', cx: C, cy: C, r: 154.5 }), text);
    }
    parts.push(
      svg('g', { class: 'seal-ghost' }, rings()),
      svg('g', { class: 'seal-ink' }, rings()),
      svg('use', { class: 'seal-mark', href: '#logo', x: 143, y: 142, width: 34, height: 34 }),
    );
    return parts;
  };

  const root = svg('svg', {
    class: `seal-svg ${lite ? 'seal-lite' : 'seal-full'}`,
    viewBox: '0 0 320 320',
    'stroke-width': lite ? '1.8' : '0.72',
    'aria-hidden': 'true',
    focusable: 'false',
  });
  root.append(defs);
  if (broken) {
    // Two halves, cut along the diagonal, that slide apart.
    for (const [half, points] of [
      ['a', '-20,-20 340,-20 -20,340'],
      ['b', '340,-20 340,340 -20,340'],
    ]) {
      defs.append(svg('clipPath', { id: `${id}${half}` }, [svg('polygon', { points })]));
      root.append(
        svg('g', { class: `seal-half seal-half-${half}` }, [svg('g', { 'clip-path': `url(#${id}${half})` }, face())]),
      );
    }
  } else {
    root.append(...face(), svg('circle', { class: 'seal-ripple', cx: C, cy: C, r: 158 }));
  }
  return root;
}

const clamp = (x) => Math.max(0, Math.min(1, x));
const easeOut = (x) => 1 - (1 - clamp(x)) ** 3;
const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);

// host: the element the two drawings (full and small) live in.
export function createSeal(host) {
  const calm = globalThis.matchMedia?.('(prefers-reduced-motion: reduce)');
  let salt = null;
  let mode = ''; // blank | drawing | sealed | broken
  let kind = 'seal'; // what a run is doing: 'seal' (encrypting) or 'open' (decrypting)
  let phase = 'rest'; // rest | key | run | settle
  let target = 0; // progress reported by the app, 0..1
  let shown = 0; // progress on screen, eased towards target
  let spin = 0; // how far the rings are from rest
  let held = [0, 0, 0]; // ring angles when the key phase ended (decrypting)
  let raf = 0;
  let last = 0;
  let settle = null; // { from, spin, start, ms, then }

  function paint(next, { stamp = false } = {}) {
    mode = next;
    host.dataset.mode = next;
    host.classList.remove('seal-split', 'seal-deny');
    host.classList.toggle('seal-stamp', stamp);
    const pattern = salt ?? SPECIMEN;
    host.replaceChildren(
      draw(pattern, { lite: false, broken: next === 'broken' }),
      draw(pattern, { lite: true, broken: next === 'broken' }),
    );
  }

  function angles() {
    if (kind === 'open') {
      if (phase === 'key') return TURN.map((t) => -t * spin);
      return held.map((a, i) => a * (1 - easeOut(shown / STOPS[i])));
    }
    return TURN.map((t) => t * spin);
  }

  function apply() {
    host.style.setProperty('--seal-p', shown.toFixed(4));
    angles().forEach((a, i) => {
      host.style.setProperty(`--seal-a${i + 1}`, `${a.toFixed(2)}deg`);
    });
  }

  function stop() {
    cancelAnimationFrame(raf);
    raf = 0;
    phase = 'rest';
    settle = null;
  }

  function still() {
    stop();
    spin = 0;
    held = [0, 0, 0];
  }

  function frame(now) {
    const dt = Math.min(64, now - last);
    last = now;
    if (phase === 'key') {
      // No measurable progress yet: the rings turn slowly while the key is derived.
      spin += dt * 0.00012;
    } else if (phase === 'run') {
      shown += (target - shown) * (1 - Math.exp(-dt / 140));
      if (kind === 'seal') spin = held[0] * (1 - shown) ** 2;
    } else if (phase === 'settle') {
      const k = easeOut((now - settle.start) / settle.ms);
      shown = settle.from + (1 - settle.from) * k;
      if (kind === 'seal') spin = settle.spin * (1 - k);
      if (k >= 1) {
        const { then } = settle;
        still();
        shown = 1;
        apply();
        then();
        return;
      }
    }
    apply();
    raf = requestAnimationFrame(frame);
  }

  function loop() {
    if (raf) return;
    last = performance.now();
    raf = requestAnimationFrame(frame);
  }

  // Finishes whatever is on screen (ink and rings), then shows the result.
  function finish(then) {
    if (calm?.matches || (phase !== 'run' && phase !== 'key')) {
      still();
      then();
      return;
    }
    if (phase === 'key') held = kind === 'open' ? angles() : [spin, 0, 0];
    settle = { from: shown, spin, start: performance.now(), ms: 650, then };
    phase = 'settle';
    loop();
  }

  return {
    // No file is sealed yet: the faint specimen.
    blank() {
      still();
      salt = null;
      shown = 0;
      paint('blank');
      apply();
    },

    // A sealed file, at rest. stamp: press it once, as the last step of encrypting.
    sealed(bytes, { stamp = false } = {}) {
      const done = () => {
        salt = bytes;
        shown = 1;
        paint('sealed', { stamp: stamp && !calm?.matches });
        apply();
      };
      if (stamp && same(salt, bytes)) finish(done);
      else {
        still();
        done();
      }
    },

    // A job has started and the key is being derived. kind: 'seal' or 'open'.
    start(bytes, what) {
      still();
      salt = bytes;
      kind = what;
      target = 0;
      // While decrypting the ink stays whole (the stylesheet sees to that);
      // `shown` only counts progress.
      shown = 0;
      paint(what === 'open' ? 'sealed' : 'drawing');
      if (calm?.matches) {
        apply();
        return;
      }
      spin = 1;
      phase = 'key';
      apply();
      loop();
    },

    // The key is ready and bytes are flowing: progress now drives the drawing.
    run(bytes, what) {
      if (phase !== 'key' || kind !== what || !same(salt, bytes)) this.start(bytes, what);
      if (calm?.matches) return;
      held = what === 'open' ? angles() : [spin, 0, 0];
      shown = 0;
      target = 0;
      phase = 'run';
      loop();
    },

    progress(fraction) {
      target = clamp(fraction);
      if (calm?.matches && kind === 'seal' && mode === 'drawing') {
        shown = target;
        apply();
      }
    },

    // Decrypted: the rings come to rest, then the seal breaks in two.
    broken(bytes) {
      const done = () => {
        salt = bytes;
        shown = 1;
        paint('broken');
        apply();
        // Two frames, so the halves start together and the transition runs.
        requestAnimationFrame(() => requestAnimationFrame(() => host.classList.add('seal-split')));
      };
      if (same(salt, bytes)) finish(done);
      else {
        still();
        done();
      }
    },

    // The password was wrong: the seal stays shut and shakes once.
    deny() {
      host.classList.remove('seal-deny');
      // Reading a layout property restarts the animation if it is asked for twice.
      void host.offsetWidth;
      host.classList.add('seal-deny');
    },
  };
}

// The fine-line band above the footer: five waves that swell and thin.
export function drawBand(host) {
  const W = 1200;
  const H = 14;
  const root = svg('svg', {
    viewBox: `0 0 ${W} ${H}`,
    preserveAspectRatio: 'none',
    'aria-hidden': 'true',
    focusable: 'false',
  });
  for (let k = 0; k < 5; k++) {
    let d = '';
    for (let x = 0; x <= W; x += 3) {
      const swell = 0.55 + 0.45 * Math.sin((x / W) * TAU * 3 + 0.6);
      const y = H / 2 + (H / 2 - 1) * Math.sin((x / W) * TAU * 34 + (k * TAU) / 5) * swell;
      d += `${x ? 'L' : 'M'}${x} ${y.toFixed(1)}`;
    }
    root.append(svg('path', { d }));
  }
  host.replaceChildren(root);
}
