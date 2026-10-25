/* VAULT video — deterministic render engine.
 *
 * Everything on screen is a pure function of the video timestamp t. The capture
 * harness calls window.__render(t) once per frame and screenshots the page; no
 * wall-clock animation is ever used, so every frame is reproducible.
 *
 * Scenes register into window.SCENES (see scenes.js). Each gets its own layer
 * with an inner camera; the engine owns the cuts between layers, the shared
 * background, the accent colour and the sound-effect cue list.
 */
(function () {
  const SCENES = (window.SCENES = {});

  // ---- math / easing ------------------------------------------------------
  const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
  const lerp = (a, b, t) => a + (b - a) * t;
  const ramp = (t, a, b) => (b <= a ? (t >= b ? 1 : 0) : clamp((t - a) / (b - a)));
  const outQuint = (t) => 1 - Math.pow(1 - clamp(t), 5);
  const outCubic = (t) => 1 - Math.pow(1 - clamp(t), 3);
  const outExpo = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * clamp(t)));
  const inCubic = (t) => Math.pow(clamp(t), 3);
  const inOutCubic = (t) => { t = clamp(t); return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  const inOutSine = (t) => -(Math.cos(Math.PI * clamp(t)) - 1) / 2;
  const outBack = (t, s = 1.4) => { t = clamp(t); return 1 + (s + 1) * Math.pow(t - 1, 3) + s * Math.pow(t - 1, 2); };
  // a damped spring settling on 1 — for things that land with a little weight
  const spring = (t, k = 7, z = 5) => (t <= 0 ? 0 : 1 - Math.exp(-z * t) * Math.cos(k * t));

  // seeded noise, so "random" things are identical on every render
  function rnd(i) { const x = Math.sin(i * 127.1 + 311.7) * 43758.5453; return x - Math.floor(x); }

  /* fade + rise (+ scale, + a short de-blur) from p = 0..1 */
  function reveal(node, p, o = {}) {
    if (!node) return p;
    const e = (o.ease || outQuint)(p);
    if (p <= 0) { node.style.visibility = "hidden"; return p; }
    node.style.visibility = "visible";
    node.style.opacity = clamp(e * (o.alpha ?? 1)).toFixed(4);
    const dy = (o.dy ?? 30) * (1 - e), dx = (o.dx ?? 0) * (1 - e);
    const sc = lerp(o.scale ?? 1, 1, e);
    const base = o.base || "";
    node.style.transform = `${base} translate3d(${dx.toFixed(2)}px, ${dy.toFixed(2)}px, 0) scale(${sc.toFixed(4)})`;
    const bl = (o.blur ?? 0) * (1 - e);
    node.style.filter = bl > 0.3 ? `blur(${bl.toFixed(2)}px)` : "none";
    return p;
  }
  function hide(node) { node.style.visibility = "hidden"; }

  // ---- DOM helpers ----------------------------------------------------------
  const NS = "http://www.w3.org/2000/svg";
  function el(tag, cls, parent, html) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    if (parent) parent.appendChild(n);
    return n;
  }
  function svg(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  /* centre-anchored box at (x, y); its own transform stays free for reveal() */
  function at(parent, x, y, cls, html) {
    const wrap = el("div", "ctr", parent);
    wrap.style.left = x + "px"; wrap.style.top = y + "px";
    return el("div", cls || "", wrap, html);
  }
  const cache = new WeakMap();
  function setText(node, s) { if (cache.get(node) !== s) { node.textContent = s; cache.set(node, s); } }
  function setHTML(node, s) { if (cache.get(node) !== s) { node.innerHTML = s; cache.set(node, s); } }

  /* kinetic words: split `text` into masked words. Returns the inner spans. */
  function words(parent, text, wordCls) {
    return text.split(" ").map((w, i, all) => {
      const k = el("span", "kt", parent);
      const s = el("span", wordCls || "", k);
      s.textContent = w;
      if (i < all.length - 1) parent.appendChild(document.createTextNode(" "));
      return s;
    });
  }
  /* rise each word out of its mask, staggered, starting at t0 */
  function kin(spans, t, t0, stagger = 0.06, dur = 0.55, out = null) {
    spans.forEach((s, i) => {
      const p = outQuint(ramp(t, t0 + i * stagger, t0 + i * stagger + dur));
      let y = (1 - p) * 140, r = (1 - p) * 4;
      if (out != null) {  // and leave upward
        const q = inCubic(ramp(t, out + i * stagger * 0.5, out + i * stagger * 0.5 + 0.35));
        y -= q * 140;
      }
      s.style.transform = `translateY(${y.toFixed(2)}%) rotate(${r.toFixed(2)}deg)`;
    });
  }

  // ---- fonts ------------------------------------------------------------------
  // measured layouts must wait for real metrics; the harness awaits __ready
  const AFTER_FONTS = [];
  let fontsSettled = false;
  function afterFonts(fn) { AFTER_FONTS.push(fn); }
  function settleFonts() { if (!fontsSettled) { fontsSettled = true; AFTER_FONTS.forEach((fn) => fn()); } }

  const A = { clamp, lerp, ramp, rnd, outQuint, outCubic, outExpo, inCubic, inOutCubic, inOutSine,
              outBack, spring, reveal, hide, el, svg, at, setText, setHTML, words, kin, afterFonts };
  window.Toolkit = A;

  // ---- timeline, cues, accent ------------------------------------------------
  let TL = null;
  const CUES = [];                 // sound effects: { t, type, gain }
  const ACCENT_KEYS = [];          // { t, rgb }
  const hex2rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  const BRAND = "#5b9bff";     // the app's encrypt blue (dark theme)

  function api(scene, layer, cam) {
    const t0 = scene.start;
    return Object.assign({
      tl: TL.d, scene, layer, cam, t0, W: 1920, H: 1080,
      dur: scene.end - scene.start,
      on: (id, label) => TL.byId[id].onsets[label] - t0,
      segStart: (id) => TL.byId[id].start - t0,
      segEnd: (id) => TL.byId[id].end - t0,
      cue: (type, t, gain = 1) => CUES.push({ t: +(t0 + t).toFixed(3), type, gain }),
      accent: (t, hex) => ACCENT_KEYS.push({ t: t0 + t, rgb: hex2rgb(hex) }),
    }, A);
  }

  function accentAt(t) {
    let c = hex2rgb(BRAND);
    for (const k of ACCENT_KEYS) {
      if (t < k.t) break;
      const p = inOutCubic(ramp(t, k.t, k.t + 0.7));
      c = c.map((v, i) => lerp(v, k.rgb[i], p));
    }
    return c;
  }

  // ---- background ---------------------------------------------------------------
  const DUST = 34;
  function paintBackground(t) {
    const bg = document.getElementById("bg");
    const g1 = bg.querySelector(".g1"), g2 = bg.querySelector(".g2");
    g1.style.transform = `translate(${(-420 + 160 * Math.sin(t * 0.13)).toFixed(1)}px, ${(-860 + 120 * Math.cos(t * 0.11)).toFixed(1)}px)`;
    g2.style.transform = `translate(${(980 + 140 * Math.sin(t * 0.09 + 2)).toFixed(1)}px, ${(-120 + 110 * Math.sin(t * 0.07 + 1)).toFixed(1)}px)`;
    // the dial drifts, and every cut turns it a notch (alternate rings, opposite ways)
    let notch = 0;
    for (let i = 1; i < built.length; i++) {
      const s0 = built[i].scene.start;
      notch += outBack(ramp(t, s0 - 0.3, s0 + 0.5), 1.2);
    }
    DIAL.forEach(([ring, dir, speed], i) => {
      const a = dir * (t * speed + notch * (i % 2 ? 9 : 15));
      ring.setAttribute("transform", `rotate(${a.toFixed(3)} 960 1240)`);
    });
    const dots = bg.querySelector(".dust").children;
    for (let i = 0; i < dots.length; i++) {
      const sp = 8 + rnd(i + 3) * 18;
      const x = rnd(i) * 1920 + 30 * Math.sin(t * 0.3 + i);
      const y = (((rnd(i + 11) * 1200 - t * sp) % 1200) + 1200) % 1200 - 60;
      const tw = 0.25 + 0.55 * (0.5 + 0.5 * Math.sin(t * (0.6 + rnd(i + 7)) + i * 2.1));
      const s = 0.5 + rnd(i + 5) * 1.3;
      dots[i].style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) scale(${s.toFixed(2)})`;
      dots[i].style.opacity = (tw * 0.55).toFixed(3);
    }
  }

  // concentric rings of ticks: [radius, stroke width, dash, opacity, direction, drift deg/s]
  const DIAL = [];
  function buildDial() {
    const g = document.querySelector("#bg .dial");
    [[560, 2.5, "2 26", 0.22, 1, 0.8], [700, 16, "2.5 11", 0.09, -1, 0.5], [770, 2.5, "70 22", 0.14, 1, 0.35],
     [930, 4, "3 40", 0.17, -1, 0.3], [1120, 2, "1.5 14", 0.14, 1, 0.2]].forEach(([r, w, dash, op, dir, sp]) => {
      const c = svg("circle", { cx: 960, cy: 1240, r, "stroke-width": w, "stroke-dasharray": dash, opacity: op }, g);
      DIAL.push([c, dir, sp]);
    });
  }

  // ---- build + render -----------------------------------------------------------
  let built = null;
  const CUT_OUT = 0.32, CUT_IN = 0.5;     // the push-through at every scene change

  function build() {
    const root = document.getElementById("scenes");
    built = [];
    TL.scenes.forEach((scene, idx) => {
      const layer = el("div", "layer", root);
      layer.style.zIndex = 10 + idx;
      const cam = el("div", "cam", layer);
      ACCENT_KEYS.push({ t: scene.start, rgb: hex2rgb(BRAND) });
      const render = SCENES[scene.name](cam, api(scene, layer, cam));
      built.push({ scene, layer, render });
      if (idx > 0) CUES.push({ t: +(scene.start - 0.28).toFixed(3), type: "whoosh", gain: 1 });
    });
    ACCENT_KEYS.sort((a, b) => a.t - b.t);
    CUES.sort((a, b) => a.t - b.t);
  }

  function render(t) {
    settleFonts();
    const acc = accentAt(t);
    const rs = document.documentElement.style;
    rs.setProperty("--accent", `rgb(${acc.map(Math.round).join(",")})`);
    rs.setProperty("--accent-l", `rgb(${acc.map((v) => Math.round(lerp(v, 255, 0.4))).join(",")})`);
    paintBackground(t);

    for (let i = 0; i < built.length; i++) {
      const { scene: s, layer, render: r } = built[i];
      const last = i === built.length - 1;
      const outP = last ? 0 : ramp(t, s.end - CUT_OUT, s.end + 0.04);
      const inP = i === 0 ? 1 : ramp(t, s.start - 0.04, s.start + CUT_IN);
      // display, not visibility: a revealed child would show through a hidden parent
      if (outP >= 1 || inP <= 0) { layer.style.display = "none"; continue; }
      layer.style.display = "";
      const eo = inCubic(outP), ei = outQuint(inP);
      layer.style.opacity = ((1 - eo) * ei).toFixed(4);
      const sc = lerp(1, 1.14, eo) * lerp(0.9, 1, ei);
      layer.style.transform = `scale(${sc.toFixed(5)})`;
      const bl = 10 * eo + 8 * (1 - ei);
      layer.style.filter = bl > 0.4 ? `blur(${bl.toFixed(2)}px)` : "none";
      r(t - s.start, t);
    }

    // a light sweep rides every cut
    const sw = document.getElementById("sweep");
    let swp = -1;
    for (let i = 1; i < built.length; i++) {
      const s0 = built[i].scene.start;
      if (t > s0 - 0.35 && t < s0 + 0.45) swp = ramp(t, s0 - 0.35, s0 + 0.45);
    }
    if (swp >= 0) {
      sw.style.opacity = Math.sin(Math.PI * swp).toFixed(3);
      sw.style.transform = `translateX(${lerp(-1300, 2600, inOutSine(swp)).toFixed(1)}px) rotate(45deg)`;
    } else sw.style.opacity = 0;

    const fadeIn = ramp(t, 0, 0.5);
    const fadeOut = 1 - ramp(t, TL.d.video_end - 1.2, TL.d.video_end - 0.05);
    document.getElementById("blackout").style.opacity = (1 - Math.min(fadeIn, fadeOut)).toFixed(4);
  }

  // ---- capture API --------------------------------------------------------------
  window.__init = function (data) {
    const byId = {};
    data.segments.forEach((s) => (byId[s.id] = s));
    TL = { d: data, byId, scenes: data.scenes };
    const dust = document.querySelector("#bg .dust");
    for (let i = 0; i < DUST; i++) el("i", "", dust);
    buildDial();
    build();
    window.__ready = Promise.all([
      document.fonts.load('800 132px "Inter"'),
      document.fonts.load('400 20px "Inter"'),
      document.fonts.load('700 46px "JBMono"'),
    ]).then(() => document.fonts.ready).then(() => true);
  };
  window.__render = render;
  window.__cues = () => CUES;
  window.__duration = () => (TL ? TL.d.video_end : 0);
  window.__poster = function () { el("div", "", document.getElementById("stage")).id = "poster-play"; };
})();
