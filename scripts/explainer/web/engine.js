/* VAULT film — deterministic render engine.
 *
 * Everything on screen is a pure function of the video timestamp t. The capture
 * harness calls window.__render(t) once per frame and screenshots the page; no
 * wall-clock animation is ever used, so every frame is reproducible.
 *
 * Scenes register into window.SCENES (see scenes.js). Each gets its own layer
 * with an inner camera; the engine owns the cuts between layers, the ground
 * they sit on and the sound-effect cue list. It also loads what the scenes
 * borrow from the app itself: the mark, the seal's geometry and the recorded
 * screens (states.py).
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

  /* fade + rise (+ scale) from p = 0..1 */
  function reveal(node, p, o = {}) {
    if (!node) return p;
    const e = (o.ease || outQuint)(p);
    if (p <= 0) { node.style.visibility = "hidden"; return p; }
    node.style.visibility = "visible";
    node.style.opacity = clamp(Math.min(1, p * 3) * (o.alpha ?? 1)).toFixed(4);
    const dy = (o.dy ?? 30) * (1 - e), dx = (o.dx ?? 0) * (1 - e);
    const sc = lerp(o.scale ?? 1, 1, e);
    const base = o.base || "";
    node.style.transform = `${base} translate3d(${dx.toFixed(2)}px, ${dy.toFixed(2)}px, 0) scale(${sc.toFixed(4)})`;
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
      let y = (1 - p) * 125;
      if (out != null) {  // and leave upward
        const q = inCubic(ramp(t, out + i * stagger * 0.5, out + i * stagger * 0.5 + 0.35));
        y -= q * 125;
      }
      s.style.transform = `translateY(${y.toFixed(2)}%)`;
    });
  }

  // ---- fonts ------------------------------------------------------------------
  // measured layouts must wait for real metrics; the harness awaits __ready
  const AFTER_FONTS = [];
  let fontsSettled = false;
  function afterFonts(fn) { AFTER_FONTS.push(fn); }
  function settleFonts() { if (!fontsSettled) { fontsSettled = true; AFTER_FONTS.forEach((fn) => fn()); } }

  // ---- borrowed from the app -----------------------------------------------------
  const APP = { ringPaths: null, states: null };   // filled by __init
  const PENDING = [];                               // things scenes are still loading (app windows)

  /* One wavy strand around (cx, cy): the curve every seal ring is made of. */
  function strand(cx, cy, radius, amp, waves, phase, harmonic, steps) {
    let d = "";
    for (let i = 0; i < steps; i++) {
      const a = (i / steps) * Math.PI * 2;
      const r = radius + amp * Math.sin(waves * a + phase) + harmonic * amp * Math.sin(2 * waves * a + 2 * phase + 1.1);
      d += `${i ? "L" : "M"}${(cx + r * Math.cos(a)).toFixed(1)} ${(cy + r * Math.sin(a)).toFixed(1)}`;
    }
    return d + "Z";
  }

  const A = { clamp, lerp, ramp, rnd, outQuint, outCubic, outExpo, inCubic, inOutCubic, inOutSine,
              outBack, spring, reveal, hide, el, svg, at, setText, setHTML, words, kin, afterFonts,
              strand, APP, PENDING };
  window.Toolkit = A;

  // ---- timeline, cues ----------------------------------------------------------
  let TL = null;
  const CUES = [];                 // sound effects: { t, type, gain }

  function api(scene, layer, cam) {
    const t0 = scene.start;
    return Object.assign({
      tl: TL.d, scene, layer, cam, t0, W: 1920, H: 1080,
      dur: scene.end - scene.start,
      on: (id, label) => TL.byId[id].onsets[label] - t0,
      segStart: (id) => TL.byId[id].start - t0,
      segEnd: (id) => TL.byId[id].end - t0,
      cue: (type, t, gain = 1) => CUES.push({ t: +(t0 + t).toFixed(3), type, gain }),
    }, A);
  }

  // ---- the ground ------------------------------------------------------------------
  // rings of the medallion: [radius, amplitude, waves, strands, second harmonic, direction, drift deg/s]
  const RINGS = [
    [742, 46, 30, 5, 0.3, 1, 0.5],
    [905, 54, 38, 6, 0, -1, 0.36],
    [1085, 62, 46, 6, 0.4, 1, 0.26],
  ];
  const ROSE = [];
  function buildGround() {
    const g = document.querySelector("#bg .rosette");
    RINGS.forEach(([r, amp, waves, n, h, dir, speed]) => {
      const ring = svg("g", {}, g);
      for (let k = 0; k < n; k++) {
        svg("path", { d: strand(960, 540, r, amp, waves, (dir * Math.PI * 2 * k) / n, h, Math.round(r * 2.6)) }, ring);
      }
      svg("circle", { cx: 960, cy: 540, r: r - amp - 32, class: "hair" }, ring);
      ROSE.push([ring, dir, speed, waves]);
    });
  }
  function paintGround(t) {
    // every cut turns the rings a notch, alternate rings opposite ways
    let notch = 0;
    for (let i = 1; i < built.length; i++) {
      const s0 = built[i].scene.start;
      notch += inOutCubic(ramp(t, s0 - 0.35, s0 + 0.55));
    }
    ROSE.forEach(([ring, dir, speed, waves]) => {
      const a = dir * (t * speed + notch * (720 / waves));
      ring.setAttribute("transform", `rotate(${a.toFixed(3)} 960 540)`);
    });
    document.getElementById("bg").style.opacity = ramp(t, 0, 0.9).toFixed(3);
  }

  // ---- build + render -----------------------------------------------------------
  let built = null;
  const CUT_OUT = 0.3, CUT_IN = 0.5;     // every scene change: one sheet lifts away, the next settles

  function build() {
    const root = document.getElementById("scenes");
    built = [];
    TL.scenes.forEach((scene, idx) => {
      const layer = el("div", "layer", root);
      layer.style.zIndex = 10 + idx;
      const cam = el("div", "cam", layer);
      const render = SCENES[scene.name](cam, api(scene, layer, cam));
      built.push({ scene, layer, render });
      if (idx > 0) CUES.push({ t: +(scene.start - 0.28).toFixed(3), type: "whoosh", gain: 0.8 });
    });
    CUES.sort((a, b) => a.t - b.t);
  }

  function render(t) {
    settleFonts();
    paintGround(t);
    for (let i = 0; i < built.length; i++) {
      const { scene: s, layer, render: r } = built[i];
      const last = i === built.length - 1;
      const outP = last ? 0 : ramp(t, s.end - CUT_OUT, s.end + 0.02);
      const inP = i === 0 ? 1 : ramp(t, s.start - 0.02, s.start + CUT_IN);
      // display, not visibility: a revealed child would show through a hidden parent
      if (outP >= 1 || inP <= 0) { layer.style.display = "none"; continue; }
      layer.style.display = "";
      const eo = inCubic(outP), ei = outQuint(inP);
      layer.style.opacity = ((1 - eo) * Math.min(1, inP * 2.5)).toFixed(4);
      layer.style.transform = `translateY(${(-36 * eo + 44 * (1 - ei)).toFixed(2)}px)`;
      r(t - s.start, t);
    }
  }

  // ---- capture API --------------------------------------------------------------
  async function loadMark() {
    // the icon, straight from the app: as a symbol (#mark), and its two halves for the opening
    const text = await (await fetch("/src/assets/logo.svg")).text();
    const src = new DOMParser().parseFromString(text, "image/svg+xml").documentElement;
    const sym = svg("symbol", { id: "mark", viewBox: src.getAttribute("viewBox") }, document.getElementById("sprite"));
    for (const n of [...src.children]) if (n.tagName !== "title" && n.tagName !== "style") sym.appendChild(document.importNode(n, true));
    const halves = [...src.querySelectorAll("path")];
    APP.shield = { d: halves[0].getAttribute("d"), fills: halves.map((h) => h.getAttribute("fill")) };
  }

  window.__init = function (data) {
    const byId = {};
    data.segments.forEach((s) => (byId[s.id] = s));
    TL = { d: data, byId, scenes: data.scenes };
    window.__ready = (async () => {
      const [seal, states] = await Promise.all([
        import("/src/js/seal.js"),
        fetch("states.json").then((r) => r.json()),
        loadMark(),
        document.fonts.load('640 96px "Archivo"'),
        document.fonts.load('500 20px "JetBrains Mono"'),
      ]);
      APP.ringPaths = seal.ringPaths;
      APP.sealNumber = seal.sealNumber;
      APP.states = states;
      buildGround();
      build();
      await Promise.all(PENDING);
      await document.fonts.ready;
      return true;
    })();
    return window.__ready;
  };
  window.__render = render;
  window.__cues = () => CUES;
  window.__duration = () => (TL ? TL.d.video_end : 0);
  window.__poster = function () {
    // README thumbnail: a play button at the centre of the seal on screen, where the
    // mark sits. If the app is on screen it is the app's seal, without the film's header.
    document.querySelectorAll(".caprow").forEach((n) => { n.style.display = "none"; });
    document.querySelectorAll(".win .chrome").forEach((n) => { n.style.visibility = "hidden"; });
    const play = el("div", "", document.getElementById("stage"));
    play.id = "poster-play";
    const shown = built.filter((b) => b.layer.style.display !== "none").map((b) => b.layer);
    const frame = shown.map((l) => l.querySelector("iframe")).find(Boolean);
    let at = null;
    if (frame) {
      const box = frame.getBoundingClientRect(), k = box.width / frame.offsetWidth;
      const seal = frame.contentDocument.getElementById("seal").getBoundingClientRect();
      at = [box.left + (seal.left + seal.width / 2) * k, box.top + (seal.top + seal.height / 2) * k];
    } else {
      // the largest seal the film itself has drawn
      const seals = shown.flatMap((l) => [...l.querySelectorAll(".fseal")]).map((n) => n.getBoundingClientRect());
      const big = seals.sort((a, b) => b.width - a.width)[0];
      if (big) at = [big.left + big.width / 2, big.top + big.height / 2];
    }
    if (at) { play.style.left = at[0] + "px"; play.style.top = at[1] + "px"; }
  };
})();
