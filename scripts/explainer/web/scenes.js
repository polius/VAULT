/* VAULT film — the scenes.
 *
 * Every scene is a function (cam, api) -> render(t) where t is seconds since the
 * scene's start (negative while it is cutting in). `cam` is the scene's camera:
 * transform it to push, pan or drift the whole shot. Moments come from the
 * narration via api.on(line, anchor) / api.segStart(line), so a frame is a pure
 * function of t and the visuals track the voice. Sound effects are registered
 * up front with api.cue(type, t) and mixed by sfx.py.
 *
 * The app on screen is the app: its own stylesheet, showing screens recorded
 * from a real run (states.py). The scenes only move what moves in it, with the
 * same arithmetic as src/js/seal.js: the percentage, the line under it, and the
 * seal's ink and rings.
 */
(function () {
  const A = window.Toolkit;
  const { clamp, lerp, ramp, rnd, outQuint, outCubic, inCubic, inOutCubic, inOutSine,
          outBack, spring, reveal, el, svg, at, setText, setHTML, words, kin, APP, PENDING } = A;

  const TAU = Math.PI * 2;
  // src/js/seal.js: how far the rings are turned per unit of spin, and where each stops when opening
  const TURN = [160, -230, 300], STOPS = [0.45, 0.75, 1];
  const MICRO = "VAULT · ENCRYPTED IN THIS BROWSER · NOTHING IS UPLOADED · OPEN SOURCE · ";
  // the pattern of the seal on the app's landing page, before any file has one
  const SPECIMEN = [0x5a, 0x0c, 0x4e, 0x19, 0xa3, 0xd2, 0x7f, 0x6b, 0x88];

  /* ------------------------------------------------------------------ *
   *  icons — the app's own (24px grid, stroked), plus a few more
   * ------------------------------------------------------------------ */
  const P = {
    lock: `<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>`,
    file: `<path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 3v5h5"/>`,
    mail: `<rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3.8 7l8.2 6 8.2-6"/>`,
    cloud: `<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z"/>`,
    usb: `<rect x="7" y="9" width="10" height="12.5" rx="2"/><path d="M9 9V3.5h6V9"/><path d="M10.6 5.6h.01M13.4 5.6h.01"/>`,
    key: `<circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8 20 3M16.5 6.5l2.5 2.5M14 9l2 2"/>`,
  };
  const icon = (name, size, sw = 1.7) =>
    `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" stroke-width="${sw}" aria-hidden="true">${P[name]}</svg>`;
  const mark = (size) =>
    `<svg class="icon-mark" width="${size}" height="${size}" viewBox="0 0 16 16" aria-hidden="true"><use href="#mark"/></svg>`;

  /* ------------------------------------------------------------------ *
   *  the seal, at film size: the app's geometry (ringPaths), drawn here
   *  so it can be as large as the frame
   * ------------------------------------------------------------------ */
  let sealId = 0;
  function sealNode(salt, size, o = {}) {
    const id = "fs" + sealId++, lite = !!o.lite;
    const s = svg("svg", { class: "fseal", viewBox: "0 0 320 320", width: size, height: size });
    if (lite) s.style.strokeWidth = o.weight || 1.8;
    const deco = svg("g", {}, s);
    for (const r of lite ? [157, 149] : [158, 154.5, 133]) svg("circle", { class: "rim", cx: 160, cy: 160, r }, deco);
    if (!lite) {
      svg("path", { id: id + "t", d: "M160 18.5A141.5 141.5 0 1 1 159.9 18.5" }, svg("defs", {}, s));
      const text = svg("text", { class: "micro" }, deco);
      svg("textPath", { href: `#${id}t`, textLength: 884, lengthAdjust: "spacing" }, text).textContent = MICRO + MICRO;
    }
    const paths = APP.ringPaths(Uint8Array.from(salt), lite);
    const layer = (cls) => {
      const g = svg("g", { class: cls }, s);
      return [g, paths.map((ds, i) => {
        const ring = svg("g", {}, g);
        ring.style.transformOrigin = "160px 160px";
        ds.forEach((d) => svg("path", { d, pathLength: 1 }, ring));
        if (i < 2) svg("circle", { cx: 160, cy: 160, r: i ? 63.5 : 98.5, pathLength: 1 }, ring);
        return ring;
      })];
    };
    const [ghostG, ghost] = layer("ghost"), [inkG, ink] = layer("ink");
    const mark = o.mark === false ? null : svg("use", { class: "mark", href: "#mark", x: 143, y: 142, width: 34, height: 34 }, s);
    if (mark) mark.style.transformOrigin = "160px 160px";
    const ripple = svg("circle", { cx: 160, cy: 160, r: 158, opacity: 0 }, s);
    ripple.style.transformOrigin = "160px 160px";
    return {
      node: s,
      /* p: share of the ink drawn; a: ring angles; ghost: the faint copy underneath */
      set({ p = 1, a = [0, 0, 0], ghost: gh = p < 1, mark: m = 1, markScale = 1, ripple: rp = -1, deco: dc = 1 }) {
        inkG.style.strokeDashoffset = (1 - p).toFixed(4);
        inkG.style.visibility = p > 0 ? "" : "hidden";
        ghostG.style.display = gh ? "" : "none";
        ghostG.style.opacity = (0.42 * dc).toFixed(3);
        ink.forEach((r, i) => { r.style.transform = `rotate(${a[i].toFixed(2)}deg)`; });
        ghost.forEach((r, i) => { r.style.transform = `rotate(${(-0.6 * a[i]).toFixed(2)}deg)`; });
        deco.style.opacity = dc.toFixed(3);
        if (mark) { mark.style.opacity = m.toFixed(3); mark.style.transform = `scale(${markScale.toFixed(4)})`; }
        if (rp >= 0 && rp < 1) {
          const e = outCubic(rp);
          ripple.setAttribute("opacity", (0.9 * (1 - e)).toFixed(3));
          ripple.style.transform = `scale(${(1 + 0.17 * e).toFixed(4)})`;
        } else ripple.setAttribute("opacity", 0);
      },
    };
  }
  /* the press that ends a sealing (app.css: seal-press, seal-ripple, seal-pop) */
  const pressScale = (tau) => {
    if (tau <= 0 || tau >= 0.6) return 1;
    const e = outCubic(tau / 0.6);
    return e < 0.26 ? lerp(1, 0.948, e / 0.26) : lerp(0.948, 1, (e - 0.26) / 0.74);
  };
  const popScale = (tau) => lerp(0.45, 1, outBack(ramp(tau, 0, 0.65), 1.9));
  const spinAngles = (spin, dir = 1) => TURN.map((v) => dir * v * spin);

  /* camera: interpolate between keyframes [t, scale, x, y, dur] with an ease */
  function camera(cam, t, keys, drift = 1) {
    let s = keys[0][1], x = keys[0][2], y = keys[0][3];
    for (let i = 1; i < keys.length; i++) {
      const [t1, s1, x1, y1, d = 0.9] = keys[i];
      const p = inOutCubic(ramp(t, t1, t1 + d));
      s = lerp(s, s1, p); x = lerp(x, x1, p); y = lerp(y, y1, p);
    }
    x += drift * 5 * Math.sin(t * 0.45); y += drift * 3 * Math.cos(t * 0.37);
    cam.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px) scale(${s.toFixed(5)})`;
  }
  /* push in on a point: at u = 1 the point `from` sits at `to`, `zoom` times larger */
  function pushIn(cam, u, from, to, zoom) {
    const z = lerp(1, zoom, u);
    const x = u * (to[0] - 960 - (from[0] - 960) * zoom), y = u * (to[1] - 540 - (from[1] - 540) * zoom);
    cam.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px) scale(${z.toFixed(5)})`;
  }

  const blink = (t, period = 1.0) => (((t % period) + period) % period < period * 0.55 ? 1 : 0);
  function typeCues(api, t0, text, rate, gain = 0.6) {
    for (let i = 0; i < text.length; i++) api.cue("key", t0 + i * rate + (rnd(i * 3.1 + t0) - 0.5) * rate * 0.35, gain);
  }
  const typed = (text, t, t0, rate) => text.slice(0, clamp(Math.floor((t - t0) / rate) + 1, 0, text.length) * (t >= t0 ? 1 : 0));
  const hex = (seed, n) => { let s = ""; for (let i = 0; i < n; i++) s += Math.floor(rnd(seed + i * 7.3) * 256).toString(16).padStart(2, "0"); return s; };

  /* a position that eases between waypoints [t, x, y] */
  function path(keys) {
    return (t) => {
      if (t <= keys[0][0]) return [keys[0][1], keys[0][2]];
      for (let i = 1; i < keys.length; i++) {
        if (t < keys[i][0]) {
          const p = inOutCubic(ramp(t, keys[i - 1][0], keys[i][0]));
          return [lerp(keys[i - 1][1], keys[i][1], p), lerp(keys[i - 1][2], keys[i][2], p)];
        }
      }
      const k = keys[keys.length - 1];
      return [k[1], k[2]];
    };
  }

  /* the pointer, with a press and a ripple on each click */
  const POINTER = `<svg viewBox="0 0 24 24" width="40" height="40" style="overflow:visible"><path d="M5 2.5l14.5 8-6.4 1.7-3.2 6.6z"
    fill="#10201a" stroke="#fbfcfa" stroke-width="1.4" stroke-linejoin="round"/></svg>`;
  function pointer(parent) {
    const n = el("div", "cursor", parent, POINTER);
    const rip = el("div", "ripple", parent);
    n.style.transformOrigin = "8px 4px";
    return function (t, [x, y], clicks, alpha = 1) {
      let press = 0, rp = -1;
      for (const c of clicks) {
        if (t > c - 0.08 && t < c + 0.18) press = Math.max(press, Math.sin(Math.PI * ramp(t, c - 0.08, c + 0.18)));
        if (t >= c && t < c + 0.5) rp = ramp(t, c, c + 0.5);
      }
      n.style.opacity = alpha.toFixed(3);
      n.style.transform = `translate(${(x - 8).toFixed(1)}px, ${(y - 4).toFixed(1)}px) scale(${(1 - 0.16 * press).toFixed(3)})`;
      if (rp >= 0) {
        rip.style.opacity = ((1 - rp) * 0.7 * alpha).toFixed(3);
        rip.style.left = x + "px"; rip.style.top = y + "px";
        rip.style.transform = `scale(${(0.3 + 0.8 * outCubic(rp)).toFixed(3)})`;
      } else rip.style.opacity = 0;
      return press;
    };
  }

  /* the header above the app: one numbered step at a time */
  function captions(layer, items) {
    const row = el("div", "caprow", layer);
    return items.map(([n, title, sub]) => {
      const c = el("div", "cap", row);
      const num = el("div", "n", c, n);
      const ws = words(el("div", "t", c), title);
      const s = el("div", "capsub", row, sub);
      return { num, ws, s };
    });
  }
  function playCaptions(caps, t, starts) {
    caps.forEach((c, i) => {
      const t0 = starts[i], t1 = starts[i + 1] == null ? null : starts[i + 1] - 0.3;
      kin(c.ws, t, t0, 0.05, 0.5, t1);
      const a = ramp(t, t0 - 0.05, t0 + 0.3) * (t1 == null ? 1 : 1 - ramp(t, t1, t1 + 0.25));
      c.num.style.opacity = a.toFixed(3);
      c.s.style.opacity = (ramp(t, t0 + 0.25, t0 + 0.65) * (t1 == null ? 1 : 1 - ramp(t, t1, t1 + 0.25))).toFixed(3);
    });
  }

  /* ====================================================================== *
   *  the app, in a browser window
   * ====================================================================== */
  const WIN = { x: 289, y: 140, scale: 1.22 }, CHROME = 44;
  // the close shot: the page fills the frame from just under its top bar, below the film's header
  const FILL = { from: [960, WIN.y + 2 + CHROME + WIN.scale * 338], to: [960, 600], zoom: 1.45 };

  function appWindow(parent, { x, y, scale }) {
    const { width: W, height: H } = APP.states.view;
    const win = el("div", "win", parent);
    Object.assign(win.style, { left: x + "px", top: y + "px", width: W * scale + 4 + "px", height: H * scale + CHROME + 4 + "px" });
    win.innerHTML = `<div class="chrome"><i></i><i></i><i></i><div class="url">${icon("lock", 15, 2.2)}vault.alzina.dev</div></div>
      <div class="vp"><iframe src="app.html" width="${W}" height="${H}" scrolling="no" tabindex="-1"></iframe></div>`;
    const frame = win.querySelector("iframe");
    Object.assign(win.querySelector(".vp").style, { width: W * scale + "px", height: H * scale + "px" });
    frame.style.transform = `scale(${scale})`;
    let doc = null, shown = null;
    PENDING.push(new Promise((done) => frame.addEventListener("load", async () => {
      doc = frame.contentDocument;
      await Promise.all([doc.fonts.load('600 16px "Archivo"'), doc.fonts.load('400 14px "JetBrains Mono"')]);
      done();
    })));
    const $ = (sel) => doc.querySelector(sel);
    return {
      win, $,
      /* where the pointer will click: each point is measured once, on the screen that shows it */
      measure(points) {
        const M = {};
        A.afterFonts(() => {
          for (const name in points) {
            const [key, sel, fx, fy] = points[name];
            this.show(key);
            M[name] = this.pt(sel, fx, fy);
          }
        });
        return M;
      },
      /* show one of the recorded screens; returns true when it has just changed */
      show(key) {
        if (shown === key) return false;
        doc.body.innerHTML = APP.states.states[key];
        doc.body.className = "";
        shown = key;
        return true;
      },
      /* where a point of an element of the app is, in the camera's space */
      pt(sel, fx = 0.5, fy = 0.5) {
        const r = $(sel).getBoundingClientRect();
        return [x + 2 + scale * (r.left + r.width * fx), y + 2 + CHROME + scale * (r.top + r.height * fy)];
      },
      /* the page's drop overlay, as while a file is held over it */
      dragging(on) {
        $("#dropOverlay").hidden = !on;
        doc.body.classList.toggle("dragging", on);
      },
      /* "58%" (app.js: setPct) and the line under it (setFill) */
      progress(fraction) {
        const small = doc.createElement("small");
        small.textContent = "%";
        $("#workPct").replaceChildren(String(Math.floor(fraction * 100)), small);
        $("#progress").style.setProperty("--p", fraction.toFixed(4));
      },
      /* key derivation has no measurable progress: a short piece slides back and forth (app.css: slide) */
      sliding(tau) {
        const u = (tau / 1.1) % 2;
        $(".track-fill").style.transform = `translateX(${(258 * inOutSine(u < 1 ? u : 2 - u)).toFixed(1)}%)`;
      },
      /* the seal beside the work: its mode, its ink and its three ring angles */
      seal(mode, p, a) {
        const host = $("#seal");
        host.dataset.mode = mode;
        host.style.setProperty("--seal-p", p.toFixed(4));
        a.forEach((v, i) => host.style.setProperty(`--seal-a${i + 1}`, `${v.toFixed(2)}deg`));
        return host;
      },
      press(sel, amount) {
        const b = $(sel);
        b.style.transform = amount > 0 ? `scale(${(1 - 0.03 * amount).toFixed(4)})` : "";
      },
    };
  }
  /* the dragged file */
  function dragFile(parent, emblem, name, size) {
    return at(parent, 0, 0, "dragfile", `<div class="fi">${emblem}</div><div>${name}<small>${size}</small></div>`);
  }
  function moveTo(node, [x, y], scale, alpha) {
    node.parentElement.style.left = x.toFixed(1) + "px";
    node.parentElement.style.top = y.toFixed(1) + "px";
    node.style.transform = `scale(${scale.toFixed(3)}) rotate(${(-3 * (1 - scale)).toFixed(2)}deg)`;
    node.style.opacity = alpha.toFixed(3);
  }
  const liteSeal = (salt, size, weight) => { const s = sealNode(salt, size, { lite: true, weight }); s.set({ p: 1 }); return s.node.outerHTML; };

  /* ====================================================================== *
   *  OPEN — the two halves of the shield lock together, and a seal grows around it
   * ====================================================================== */
  function open(cam, api) {
    const SIZE = 640, K0 = 300, K1 = (SIZE * 34) / 320, CX0 = 960, CX1 = 470, CY = 540;
    const grp = el("div", "abs", cam);
    const S = sealNode(SPECIMEN, SIZE, { mark: false });
    at(grp, 0, 0, "").appendChild(S.node);
    const half = (id, points, fill) => `<clipPath id="${id}"><polygon points="${points}"/></clipPath>
      <g><path clip-path="url(#${id})" fill="${fill}" d="${APP.shield.d}"/></g>`;
    const kn = at(grp, 0, 0, "", `<svg class="icon-mark" width="${K0}" height="${K0}" viewBox="0 0 16 16">
      ${half("opena", "0,0 16,0 0,16", APP.shield.fills[0])}${half("openb", "16,0 16,16 0,16", APP.shield.fills[1])}</svg>`);
    const [ha, hb] = kn.querySelectorAll("g");

    const X = 880;
    const wm = el("div", "abs wordmark", cam, "VAULT".split("").map((c) => `<span>${c}</span>`).join(""));
    Object.assign(wm.style, { left: X + "px", top: "262px", fontSize: "150px" });
    const letters = [...wm.children];
    const rule = el("div", "rule", cam);
    Object.assign(rule.style, { left: X + "px", top: "470px", width: "920px" });
    const lines = ["Encrypt any file", "with a password,", "right in your browser."].map((txt, i) => {
      const h = el("div", "abs headline" + (i === 2 ? " g" : ""), cam);
      Object.assign(h.style, { left: X + "px", top: 514 + i * 92 + "px", fontSize: "74px" });
      return words(h, txt);
    });

    const J0 = 0.35, HIT = 1.45, G0 = HIT + 0.3, G1 = G0 + 1.3;
    const s1 = api.segStart("open1"), s2 = api.segStart("open2");
    const STAMP = Math.max(G1 + 0.05, s1 + 0.8);
    api.cue("swish", J0 + 0.2, 0.6);
    api.cue("hit", HIT, 1);
    api.cue("stream", G0 + 0.15, 0.5);
    api.cue("thud", STAMP, 0.5);
    const L = [s2 - 0.05, api.on("open2", "password") - 0.45, api.on("open2", "browser") - 0.15];

    return function (t) {
      camera(cam, t, [[0, 1.05, 0, 0], [0.2, 1.0, 0, 0, HIT], [s2, 1.025, 0, 0, 6]]);
      const m = inOutCubic(ramp(t, G0, G0 + 0.9));
      grp.style.transform = `translate(${lerp(CX0, CX1, m).toFixed(1)}px, ${CY}px)`;

      // the shield: its halves glide in along the diagonal and lock
      const join = t < HIT ? inCubic(ramp(t, J0, HIT)) : 1, off = 9 * (1 - join);
      ha.setAttribute("transform", `translate(${(-off).toFixed(3)} ${(-off).toFixed(3)})`);
      hb.setAttribute("transform", `translate(${off.toFixed(3)} ${off.toFixed(3)})`);
      ha.setAttribute("opacity", clamp(join * 3).toFixed(3));
      hb.setAttribute("opacity", clamp(join * 3).toFixed(3));
      const punch = t > HIT ? Math.exp(-(t - HIT) * 8) * 0.1 : 0;
      const shrink = inOutCubic(ramp(t, G0, G0 + 0.85));
      const press = pressScale(t - STAMP);
      kn.style.transform = `scale(${(lerp(1, K1 / K0, shrink) * (1 + punch) * press).toFixed(5)})`;

      // the seal grows around it: the ink runs along every strand while the rings settle
      const u = ramp(t, G0 + 0.1, G1);
      S.set({ p: outCubic(u), a: spinAngles(0.5 * (1 - u) ** 2), ghost: t < STAMP, mark: 0,
              deco: ramp(t, G0, G0 + 0.6), ripple: t >= STAMP ? ramp(t, STAMP, STAMP + 1) : -1 });
      S.node.style.transform = `scale(${press.toFixed(4)})`;

      letters.forEach((s, i) => {
        const p = outQuint(ramp(t, s1 + 0.2 + i * 0.07, s1 + 0.7 + i * 0.07));
        s.style.opacity = Math.min(1, p * 2).toFixed(3);
        s.style.transform = `translateX(${(-36 * (1 - p)).toFixed(1)}px)`;
      });
      rule.style.transform = `scaleX(${outQuint(ramp(t, s2 - 0.45, s2 + 0.4)).toFixed(4)})`;
      lines.forEach((ws, i) => kin(ws, t, L[i], 0.06, 0.6));
    };
  }

  /* ====================================================================== *
   *  DEMO / DECRYPT — the real flow, in the app
   * ====================================================================== */
  function demo(cam, api) {
    const S = APP.states;
    const W = appWindow(cam, WIN);
    const caps = captions(api.layer, [
      ["01", "Drop in a file.", "Files, or a whole folder."],
      ["02", "Pick a password.", "Or let VAULT make a strong one."],
      ["03", "Press Encrypt.", "The seal is drawn as the file encrypts."],
      ["04", "A seal of its own.", "Drawn from the random salt in the file."],
    ]);
    const chip = dragFile(cam, icon("file", 34), S.file, "2.4 MB");
    const cur = pointer(cam);
    const M = W.measure({ tray: ["empty", ".tray", 0.2, 0.3], dice: ["job", "#genBtn", 0.5, 0.55],
      copy: ["generated", "#copyBtn", 0.5, 0.6], go: ["copied", "#encGo", 0.6, 0.6] });

    // ---- the beats ----
    const d1 = api.segStart("demo1"), d2 = api.segStart("demo2"), d3 = api.segStart("demo3"), d4 = api.segStart("demo4");
    const DRAG0 = api.on("demo1", "drop") - 0.25, DROP = DRAG0 + 1.2;
    const GEN = api.on("demo2", "make") + 0.05, COPY = GEN + 1.55;
    const GO = api.on("demo3", "encrypt") - 0.02;
    const KDF = GO + 0.05, ENC0 = KDF + 0.6;
    const STAMP = api.segEnd("demo3") + 0.4, DONE = STAMP - 0.32, ENC1 = DONE - 0.12;
    const BACK = api.on("demo4", "own") - 0.25;
    api.cue("swish", DRAG0 + 0.1, 0.5);
    api.cue("pop", DROP, 0.9);
    api.cue("blip", GEN, 0.8);
    for (let i = 0; i < 4; i++) api.cue("tick", GEN + 0.3 + i * 0.07, 0.5);
    api.cue("enter", COPY, 0.6);
    api.cue("enter", GO, 0.9);
    api.cue("stream", ENC0, 0.8);
    api.cue("stream", ENC0 + 0.9, 0.6);
    api.cue("thud", STAMP, 0.9);
    api.cue("chime", STAMP + 0.12, 0.9);
    const prog = (t) => inOutSine(ramp(t, ENC0, ENC1));
    const HELD = 1 + 0.12 * (ENC0 - KDF);      // seal.js: the rings turn slowly while the key is derived

    return function (t) {
      reveal(W.win, ramp(t, -0.3, 0.45), { dy: 50 });
      playCaptions(caps, t, [d1 - 0.15, d2 - 0.15, d3 - 0.15, d4 - 0.1]);

      const key = t < DROP ? "empty" : t < GEN ? "job" : t < COPY ? "generated" : t < KDF ? "copied"
        : t < ENC0 ? "enc-kdf" : t < DONE ? "enc-run" : "enc-done";
      W.show(key);

      // pointer: the file is dragged in, then the dice, Copy, Encrypt
      const { tray, dice, copy, go } = M;
      const pos = path([[DRAG0, 150, 1010], [DROP, tray[0], tray[1]], [GEN - 0.8, tray[0], tray[1]],
        [GEN, dice[0], dice[1]], [COPY - 0.75, dice[0], dice[1]], [COPY, copy[0], copy[1]],
        [GO - 0.7, copy[0], copy[1]], [GO, go[0], go[1]], [GO + 0.25, go[0], go[1]], [GO + 1.3, go[0] + 150, go[1] + 190]])(t);
      const press = cur(t, pos, [GEN, COPY, GO], ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, GO + 0.6, GO + 1.0)));
      const dragging = ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, DROP - 0.05, DROP + 0.12));
      moveTo(chip, [pos[0] + 80, pos[1] + 56], lerp(0.85, 1, ramp(t, DRAG0 - 0.3, DRAG0)) * lerp(1, 0.7, ramp(t, DROP - 0.1, DROP + 0.12)), dragging);

      if (key === "empty") W.dragging(t > DROP - 0.55);
      if (key === "job") W.press("#genBtn", press);
      if (key === "generated" || key === "copied") {
        W.$("#encPwd").value = S.phrase;
        // the passphrase settles left to right
        const out = W.$("#genPhrase");
        let pw = "";
        for (let i = 0; i < S.phrase.length; i++) {
          const settled = t >= GEN + 0.05 + i * 0.008 || S.phrase[i] === "-";
          pw += settled ? S.phrase[i] : "abcdefghijklmnopqrstuvwxyz"[Math.floor(rnd(i * 13 + Math.floor(t * 40)) * 26)];
        }
        if (out.textContent !== pw) out.textContent = pw;
        if (key === "generated") W.press("#copyBtn", t > COPY - 0.3 ? press : 0);
        else W.press("#encGo", t > GO - 0.3 ? press : 0);
      }
      if (key === "enc-kdf") {
        W.seal("drawing", 0, spinAngles(1 + 0.12 * (t - KDF)));
        W.sliding(t - KDF);
      }
      if (key === "enc-run" || key === "enc-done") {
        // the ink follows the progress a moment behind, and the rings slow as it fills (seal.js)
        const shown = t < STAMP ? Math.min(prog(t - 0.12), 0.9999) : 1;
        const host = W.seal(t < STAMP ? "drawing" : "sealed", shown, spinAngles(HELD * (1 - shown) ** 2));
        if (key === "enc-run") {
          W.progress(prog(t));
          W.$("#workStats").textContent = prog(t) >= 1 ? "2.4 MB · finishing…" : "";
        } else {
          const full = host.querySelector(".seal-full"), tau = t - STAMP;
          full.style.transform = `scale(${pressScale(tau).toFixed(4)})`;
          const rp = host.querySelector(".seal-ripple"), e = outCubic(ramp(tau, 0, 1));
          rp.style.opacity = tau > 0 && tau < 1 ? (0.9 * (1 - e)).toFixed(3) : 0;
          rp.style.transform = `scale(${(1 + 0.17 * e).toFixed(4)})`;
          const mk = host.querySelector(".seal-full .seal-mark");
          mk.style.opacity = tau < 0 ? 0.34 : lerp(0.34, 1, ramp(tau, 0, 0.3)).toFixed(3);
          mk.style.transform = tau > 0 ? `scale(${popScale(tau).toFixed(4)})` : "";
        }
      }

      // push in until the app fills the frame while the seal is drawn, and hold until it has been named
      pushIn(cam, inOutCubic(ramp(t, GO + 0.25, GO + 1.25)) * (1 - inOutCubic(ramp(t, BACK, BACK + 0.9))), FILL.from, FILL.to, FILL.zoom);
    };
  }

  function decrypt(cam, api) {
    const S = APP.states;
    const W = appWindow(cam, WIN);
    const caps = captions(api.layer, [
      ["01", "Drop it back in.", "VAULT switches to Decrypt."],
      ["02", "Type the password.", "Checked before anything is saved."],
      ["03", "The seal breaks.", "Your file is back, exactly as it was."],
    ]);
    const chip = dragFile(cam, liteSeal(S.salt, 46, 6.5), S.sealed, "2.4 MB");
    const cur = pointer(cam);
    const M = W.measure({ tray: ["empty", ".tray", 0.2, 0.3], pwd: ["dec-job", "#decPwd", 0.3, 0.6], go: ["dec-job", "#decGo", 0.6, 0.6] });

    const d1 = api.segStart("decrypt1"), d2 = api.segStart("decrypt2");
    const DRAG0 = d1 - 0.4, DROP = api.on("decrypt1", "drop") + 0.2;
    const N = S.phrase.length, RATE = 0.013;
    const TYPE0 = api.on("decrypt1", "type") - 0.1;
    const GO = TYPE0 + N * RATE + 0.3, KDF = GO + 0.05, DEC0 = KDF + 0.55;
    const BREAK = Math.max(api.on("decrypt2", "breaks") - 0.05, DEC0 + 1.5), DONE = BREAK - 0.35, DEC1 = DONE - 0.1;
    const BACK = api.on("decrypt2", "back") + 0.85;
    const prog = (t) => inOutSine(ramp(t, DEC0, DEC1));
    const when = (p) => DEC0 + (DEC1 - DEC0) * Math.acos(1 - 2 * p) / Math.PI + 0.12;   // when the seal shows p
    const HELD = spinAngles(1 + 0.12 * (DEC0 - KDF), -1);
    api.cue("swish", DRAG0 + 0.1, 0.5);
    api.cue("pop", DROP, 0.9);
    for (let i = 0; i < N; i += 6) api.cue("key", TYPE0 + i * RATE + (rnd(i) - 0.5) * 0.012, 0.5);   // a quick run of keys
    api.cue("enter", GO, 0.9);
    api.cue("stream", DEC0, 0.6);
    // the rings stop one after another, like tumblers
    api.cue("tick", when(0.45) - 0.12, 0.9);
    api.cue("tick", when(0.75) - 0.1, 0.9);
    api.cue("tick", when(0.999) - 0.05, 1);
    api.cue("thud", BREAK, 0.8);
    api.cue("chime", BREAK + 0.15, 0.9);

    return function (t) {
      reveal(W.win, ramp(t, -0.3, 0.45), { dy: 50 });
      playCaptions(caps, t, [d1 - 0.15, api.on("decrypt1", "type") - 0.3, d2 - 0.15]);

      const key = t < DROP ? "empty" : t < KDF ? "dec-job" : t < DEC0 ? "dec-kdf" : t < DONE ? "dec-run" : "dec-done";
      W.show(key);

      const { tray, pwd, go } = M;
      const pos = path([[DRAG0, 150, 1010], [DROP, tray[0], tray[1]], [TYPE0 - 0.65, tray[0], tray[1]],
        [TYPE0 - 0.15, pwd[0], pwd[1]], [GO - 0.6, pwd[0], pwd[1]], [GO, go[0], go[1]], [GO + 0.25, go[0], go[1]],
        [GO + 1.3, go[0] + 150, go[1] + 190]])(t);
      const press = cur(t, pos, [TYPE0 - 0.12, GO], ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, GO + 0.6, GO + 1.0)));
      const dragging = ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, DROP - 0.05, DROP + 0.12));
      moveTo(chip, [pos[0] + 110, pos[1] + 56], lerp(0.85, 1, ramp(t, DRAG0 - 0.3, DRAG0)) * lerp(1, 0.7, ramp(t, DROP - 0.1, DROP + 0.12)), dragging);

      if (key === "empty") W.dragging(t > DROP - 0.55);
      if (key === "dec-job") {
        const n = t < TYPE0 ? 0 : Math.min(N, Math.floor((t - TYPE0) / RATE) + 1);
        W.$("#decPwd").value = "x".repeat(n);
        const row = W.$("#decPwd").parentElement, focus = t > TYPE0 - 0.12;
        row.style.borderColor = focus ? "var(--ink)" : "";
        row.style.boxShadow = focus ? "0 0 0 1px var(--ink)" : "";
        W.press("#decGo", t > GO - 0.3 ? press : 0);
      }
      if (key === "dec-kdf") {
        W.seal("sealed", 0, spinAngles(1 + 0.12 * (t - KDF), -1));
        W.sliding(t - KDF);
      }
      if (key === "dec-run" || key === "dec-done") {
        // each ring turns back to rest and stops when progress reaches its share (seal.js)
        const shown = prog(t - 0.12);
        const host = W.seal(key === "dec-run" ? "sealed" : "broken", shown,
          HELD.map((a, i) => a * (1 - outCubic(shown / STOPS[i]))));
        if (key === "dec-run") {
          W.progress(prog(t));
          W.$("#workStats").textContent = prog(t) >= 1 ? "2.4 MB · finishing…" : "";
        } else {
          // the two halves slide apart along the diagonal (app.css: seal-split)
          const k = 7 * outBack(ramp(t, BREAK, BREAK + 0.85), 2.2);
          host.querySelectorAll(".seal-half-a").forEach((h) => { h.style.transform = `translate(${-k}px, ${-k}px)`; });
          host.querySelectorAll(".seal-half-b").forEach((h) => { h.style.transform = `translate(${k}px, ${k}px)`; });
        }
      }

      pushIn(cam, inOutCubic(ramp(t, GO + 0.25, GO + 1.25)) * (1 - inOutCubic(ramp(t, BACK, BACK + 0.9))), FILL.from, FILL.to, FILL.zoom);
    };
  }

  /* ====================================================================== *
   *  LOCAL — it all happens on your device
   * ====================================================================== */
  function local(cam, api) {
    const CX = 480, CY = 700, R = 232;
    const lines = ["It all happens", "on your device."].map((txt, i) => {
      const h = el("div", "abs headline" + (i ? " g" : ""), cam);
      Object.assign(h.style, { left: "150px", top: 150 + i * 96 + "px", fontSize: "86px" });
      return words(h, txt);
    });
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible", fill: "none" }, cam);
    const dev = svg("g", {}, g);
    svg("circle", { cx: CX, cy: CY, r: R, stroke: "var(--field-line)", "stroke-width": 1.2 }, dev);
    svg("circle", { cx: CX, cy: CY, r: R - 36, stroke: "var(--field-line)", "stroke-width": 1.2 }, dev);
    svg("path", { id: "devrim", d: `M${CX} ${CY - R + 24}A${R - 24} ${R - 24} 0 1 1 ${CX - 0.1} ${CY - R + 24}` }, svg("defs", {}, g));
    const rim = svg("g", {}, dev);
    const rimText = svg("text", { class: "rimtext" }, rim);
    svg("textPath", { href: "#devrim", textLength: Math.round(TAU * (R - 24)) - 6, lengthAdjust: "spacing" }, rimText)
      .textContent = "EVERYTHING HAPPENS IN THIS TAB · NOTHING IS UPLOADED · ".repeat(2);
    // a laptop, drawn in line
    svg("rect", { x: CX - 118, y: CY - 92, width: 236, height: 152, rx: 9, fill: "var(--surface)", stroke: "var(--ink)", "stroke-width": 2.5 }, dev);
    svg("rect", { x: CX - 156, y: CY + 68, width: 312, height: 12, rx: 6, fill: "var(--surface)", stroke: "var(--ink)", "stroke-width": 2.5 }, dev);
    const icon = at(cam, CX, CY - 16, "", mark(84));

    const KEYS = [["uploaded", "Uploads", "everything stays in this tab"], ["accounts", "Accounts", "nothing to sign up for"],
      ["tracking", "Tracking", "no analytics, no third-party code"]];
    const rows = KEYS.map(([k, name, sub], i) => {
      const row = el("div", "prow", cam);
      row.style.top = 316 + i * 150 + "px";
      const lbl = el("div", "label", row, name);
      const ws = words(el("div", "val", row), "None.");
      const s = el("div", "sub", row, sub);
      const t0 = api.on("local1", k) - 0.1;
      api.cue("thud", t0 + 0.05, i === 0 ? 1 : 0.85);
      return { row, lbl, ws, s, t0 };
    });
    const last = el("div", "rule thin", cam);
    Object.assign(last.style, { left: "1010px", top: 316 + 3 * 150 + "px", width: "760px" });
    const dv = api.on("local1", "device");
    api.cue("pop", dv - 0.1, 0.7);

    return function (t) {
      camera(cam, t, [[0, 1.03, 0, 6], [0, 1.0, 0, 0, 6]], 1);
      kin(lines[0], t, -0.05, 0.06, 0.55);
      kin(lines[1], t, dv - 0.3, 0.06, 0.55);
      const d = ramp(t, dv - 0.45, dv + 0.35);
      dev.setAttribute("opacity", Math.min(1, d * 2.5).toFixed(3));
      dev.setAttribute("transform", `translate(0 ${(28 * (1 - outQuint(d))).toFixed(1)})`);
      rim.setAttribute("transform", `rotate(${(t * 5).toFixed(2)} ${CX} ${CY})`);
      reveal(icon, ramp(t, dv, dv + 0.5), { dy: 0, scale: 0.6, ease: outBack });
      rows.forEach((r, i) => {
        r.row.style.opacity = ramp(t, 0.15 + i * 0.1, 0.6 + i * 0.1).toFixed(3);
        r.lbl.style.opacity = lerp(0.45, 1, ramp(t, r.t0 - 0.05, r.t0 + 0.2)).toFixed(3);
        kin(r.ws, t, r.t0, 0.05, 0.5);
        r.s.style.opacity = ramp(t, r.t0 + 0.3, r.t0 + 0.7).toFixed(3);
      });
      last.style.opacity = ramp(t, 0.45, 0.9).toFixed(3);
    };
  }

  /* ====================================================================== *
   *  INSIDE — a slow key, then every piece sealed
   * ====================================================================== */
  function inside(cam, api) {
    const S = APP.states;
    const R1 = 452, R2 = 790;
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible" }, cam);
    const line = (x1, y1, x2, y2) => svg("path", { d: `M${x1} ${y1}L${x2} ${y2}`, stroke: "var(--field-line)", "stroke-width": 1.5, fill: "none" }, g);
    const a1 = line(612, R1, 770, R1), a2 = line(1152, R1, 1362, R1), a3 = line(560, R2, 728, R2), a4 = line(1202, R2, 1336, R2);
    const dot = () => svg("circle", { r: 7, fill: "var(--seal)", opacity: 0 }, g);
    const dots = [dot(), dot(), dot(), dot()];

    const pw = at(cam, 420, R1, "chip", `${icon("lock", 28, 1.9)}<span>${S.phrase.slice(0, 18)}…</span>`);
    const box = at(cam, 960, R1, "box card", `<div class="ttl">Argon2id</div><div class="memgrid"></div><div class="mt">64 MiB of memory · 3 passes</div>`);
    const cells = [];
    const grid = box.querySelector(".memgrid");
    for (let i = 0; i < 48; i++) cells.push(el("i", "", grid));
    const slow = at(cam, 960, R1 - 158, "tag warn", "Slow on purpose");
    const key = at(cam, 1500, R1, "chip", `${icon("key", 30, 1.9)}<span>256-bit key</span>`);
    const keyFly = at(cam, 0, 0, "keydisc", icon("key", 34, 2));

    const file = at(cam, 420, R2, "dragfile", `<div class="fi">${icon("file", 34)}</div><div>${S.file}<small>2.4 MB</small></div>`);
    const PX = [800, 965, 1130];
    const pieces = PX.map((x, i) => {
      const n = el("div", "piece", cam);
      n.innerHTML = `<div class="hx">${[0, 1, 2].map((r) => hex(i * 31 + r * 5, 4)).join("\n")}</div>
        <div class="stamp">${mark(30)}</div><div class="idx">${i === 2 ? "0.4 MiB" : "1 MiB"}</div>`;
      return { n, lk: n.querySelector(".stamp"), hx: n.querySelector(".hx"), x };
    });
    const aes = at(cam, 965, R2 - 132, "note");
    aes.innerHTML = `<b>AES-256-GCM</b> · one piece at a time`;
    const tamper = at(cam, 965, R2 + 114, "tag bad", "Changed? It won’t open.");
    const out = at(cam, 1500, R2, "dragfile", `<div class="fi">${liteSeal(S.salt, 46, 6.5)}</div><div>${S.sealed}<small>2.4 MB</small></div>`);

    const heads = ["Your password becomes a key.", "Then every piece is sealed."].map((txt) => {
      const h = el("div", "abs headline", api.layer);
      Object.assign(h.style, { left: "150px", top: "118px", fontSize: "76px" });
      return words(h, txt);
    });

    const s2 = api.segStart("inside2");
    const ARG = api.on("inside1", "argon") - 0.1, KEY = api.on("inside1", "key"), SLOW = api.on("inside1", "slow");
    const AES = api.on("inside2", "aes") - 0.2, PIECE = api.on("inside2", "piece"), CHG = api.on("inside2", "change");
    const SEAL = (i) => PIECE + 0.1 + i * 0.2, OUT = SEAL(2) + 0.45;
    api.cue("blip", ARG + 0.35, 0.6);
    api.cue("pop", KEY + 0.05, 0.9);
    api.cue("tick", SLOW, 0.6);
    api.cue("swish", AES, 0.6);
    [0, 1, 2].forEach((i) => api.cue("thud", SEAL(i), 0.5));
    api.cue("deny", CHG + 0.05, 0.8);

    const flow = (d, p, [x1, y1], [x2, y2]) => {
      d.setAttribute("cx", lerp(x1, x2, p).toFixed(1)); d.setAttribute("cy", lerp(y1, y2, p).toFixed(1));
      d.setAttribute("opacity", (p > 0 && p < 1 ? Math.sin(Math.PI * p) : 0).toFixed(3));
    };

    return function (t) {
      camera(cam, t, [[0, 1.2, 0, 120], [s2 - 0.7, 1.2, 0, 8, 1.3]], 0.6);
      kin(heads[0], t, -0.1, 0.06, 0.55, s2 - 0.75);
      kin(heads[1], t, s2 - 0.35, 0.06, 0.55);

      // row 1: password -> Argon2id -> key
      reveal(pw, ramp(t, 0, 0.45), { dy: 30 });
      reveal(box, ramp(t, 0.1, 0.6), { dy: 30 });
      a1.setAttribute("opacity", ramp(t, 0.3, 0.6).toFixed(3));
      a2.setAttribute("opacity", ramp(t, 0.4, 0.7).toFixed(3));
      flow(dots[0], ramp(t, ARG, ARG + 0.4), [612, R1], [770, R1]);
      const work = ramp(t, ARG + 0.35, ARG + 0.5) * (1 - ramp(t, KEY, KEY + 0.4));
      cells.forEach((c, i) => {
        const on = work > 0 && rnd(i * 7 + Math.floor(t * 14)) > 0.55;
        c.style.background = on ? "var(--seal)" : t > KEY ? "var(--soft)" : "";
        c.style.borderColor = on ? "var(--seal)" : "";
      });
      reveal(slow, ramp(t, SLOW - 0.15, SLOW + 0.3), { dy: 12, ease: outBack, alpha: 1 - ramp(t, s2 - 0.7, s2 - 0.3) });
      flow(dots[1], ramp(t, KEY - 0.35, KEY + 0.05), [1152, R1], [1362, R1]);
      const kp = ramp(t, KEY, KEY + 0.5);
      key.style.visibility = kp > 0 ? "visible" : "hidden";
      key.style.opacity = Math.min(1, kp * 4).toFixed(3);
      key.style.transform = `scale(${(kp <= 0 ? 0 : spring(kp * 1.3, 9, 5)).toFixed(4)})`;

      // row 2: the file is cut into pieces, the key seals each, out comes .vault
      reveal(file, ramp(t, s2 - 0.5, s2), { dy: 30 });
      a3.setAttribute("opacity", ramp(t, AES, AES + 0.3).toFixed(3));
      a4.setAttribute("opacity", ramp(t, OUT - 0.3, OUT).toFixed(3));
      reveal(aes, ramp(t, AES + 0.1, AES + 0.5), { dy: 14 });
      pieces.forEach((p, i) => {
        const q = outQuint(ramp(t, AES + i * 0.12, AES + 0.6 + i * 0.12));
        const x = lerp(420, p.x, q);
        const shake = t > CHG && t < CHG + 0.45 && i === 1 ? Math.sin((t - CHG) * 60) * 8 * (1 - (t - CHG) / 0.45) : 0;
        p.n.style.left = (x + shake).toFixed(1) + "px"; p.n.style.top = R2 + "px";
        p.n.style.opacity = Math.min(1, q * 2).toFixed(3);
        p.n.style.visibility = q > 0 ? "visible" : "hidden";
        const s = ramp(t, SEAL(i) - 0.05, SEAL(i) + 0.35);
        p.lk.style.transform = `scale(${(s <= 0 ? 0 : spring(s * 1.3, 10, 5)).toFixed(4)})`;
        p.hx.style.opacity = lerp(1, 0.4, s).toFixed(3);
        const red = i === 1 ? ramp(t, CHG, CHG + 0.15) * (1 - ramp(t, CHG + 0.9, CHG + 1.4)) : 0;
        p.n.style.borderColor = red > 0.5 ? "var(--danger)" : "";
        p.lk.style.borderColor = red > 0.5 ? "var(--danger)" : "";
      });
      reveal(tamper, ramp(t, CHG + 0.05, CHG + 0.4), { dy: 10, alpha: 1 - ramp(t, CHG + 1.2, CHG + 1.6) });
      file.style.opacity = lerp(1, 0.5, ramp(t, AES, AES + 0.6)).toFixed(3);
      // the key drops onto the pieces as they are sealed
      const kf = ramp(t, AES - 0.1, PIECE + 0.05), kd = ramp(t, SEAL(2) + 0.25, SEAL(2) + 0.55);
      const kx = t < PIECE + 0.05 ? lerp(1500, PX[0], inOutCubic(kf)) : lerp(PX[0], PX[2], inOutCubic(ramp(t, SEAL(0), SEAL(2))));
      const ky = t < PIECE + 0.05 ? lerp(R1, R2 - 112, inOutCubic(kf)) - 110 * Math.sin(Math.PI * kf) : R2 - 112;
      keyFly.parentElement.style.left = kx.toFixed(1) + "px"; keyFly.parentElement.style.top = ky.toFixed(1) + "px";
      keyFly.style.opacity = (kf > 0 ? 1 - kd : 0).toFixed(3);
      keyFly.style.transform = `scale(${(0.9 + 0.12 * Math.sin(Math.PI * kf)).toFixed(3)})`;
      reveal(out, ramp(t, OUT, OUT + 0.5), { dy: 0, dx: -30 });
      flow(dots[2], ramp(t, AES, AES + 0.5), [560, R2], [728, R2]);
      flow(dots[3], ramp(t, OUT - 0.4, OUT), [1202, R2], [1336, R2]);
    };
  }

  /* ====================================================================== *
   *  SHARE — send it anywhere; to anyone else, it is noise
   * ====================================================================== */
  function share(cam, api) {
    const S = APP.states;
    const FX = 960, FY = 430;
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible" }, cam);
    const DEST = [["email", "mail", "Email", 520, 800], ["cloud", "cloud", "Cloud drive", 960, 830], ["usb", "usb", "USB stick", 1400, 800]];
    const dests = DEST.map(([k, ic, name, x, y]) => {
      const d = el("div", "dest", cam);
      d.style.left = x + "px"; d.style.top = y + "px";
      d.innerHTML = `<div class="card">${icon(ic, 70, 1.5)}</div><div class="label">${name}</div>`;
      const arc = svg("path", { d: `M${FX} ${FY + 74} Q ${(FX + x) / 2} ${FY + 64} ${x} ${y - 100}`, fill: "none", stroke: "var(--field-line)",
        "stroke-width": 1.5, "stroke-dasharray": "2 9", "stroke-linecap": "round", opacity: 0 }, g);
      const t0 = api.on("share1", k) - 0.15;
      api.cue("swish", t0, 0.55); api.cue("pop", t0 + 0.55, 0.75);
      return { d, arc, tok: null, t0, x, y, card: d.querySelector(".card") };
    });
    const vf = at(cam, FX, FY, "vfile card", `${liteSeal(S.salt, 92, 4)}<div><div class="nm">${S.sealed}</div><div class="mt">2.4 MB · seal no. ${S.sealNo}</div></div>`);
    dests.forEach((d) => { d.tok = at(cam, 0, 0, "", liteSeal(S.salt, 58, 5.5)); d.tok.style.background = "var(--paper)"; d.tok.style.borderRadius = "50%"; });
    // the bytes inside, as anyone without the password sees them
    const peek = at(cam, FX, 760, "night", "");
    Object.assign(peek.style, { width: "1180px", height: "330px", overflow: "hidden", position: "relative" });
    const rows = [...Array(8)].map((_, r) => {
      const n = el("div", "noise", peek);
      n.style.left = "44px"; n.style.top = 22 + r * 37 + "px";
      return n;
    });
    const plbl = at(cam, FX, 562, "label", "What anyone else sees");

    const heads = ["Send it anywhere.", "Without the password, it’s noise."].map((txt) => {
      const h = el("div", "abs headline", api.layer);
      Object.assign(h.style, { left: "150px", top: "118px", fontSize: "76px" });
      return words(h, txt);
    });
    const s2 = api.segStart("share2"), W0 = api.on("share2", "without") - 0.2;
    api.cue("stream", W0 + 0.3, 0.6);

    return function (t) {
      camera(cam, t, [[0, 1.18, 0, 30], [W0, 1.18, 0, 16, 1.0]], 0.6);
      kin(heads[0], t, -0.1, 0.07, 0.55, s2 - 0.6);
      kin(heads[1], t, s2 - 0.25, 0.06, 0.55);
      const up = inOutCubic(ramp(t, W0, W0 + 0.7));
      reveal(vf, ramp(t, -0.2, 0.4), { dy: 40 });
      vf.parentElement.style.top = lerp(FY, 400, up).toFixed(1) + "px";
      const gone = ramp(t, W0 - 0.1, W0 + 0.4);
      dests.forEach((d, i) => {
        reveal(d.d, ramp(t, 0.1 + i * 0.12, 0.6 + i * 0.12), { dy: 30, base: "translate(-50%,-50%)", alpha: 1 - gone });
        if (gone >= 1) d.d.style.visibility = "hidden";
        const u = ramp(t, d.t0, d.t0 + 0.55);
        d.arc.setAttribute("opacity", (ramp(t, d.t0 - 0.1, d.t0 + 0.2) * (1 - gone)).toFixed(3));
        d.arc.setAttribute("stroke-dashoffset", (-t * 30).toFixed(1));
        const e = inOutCubic(u);
        const x = (1 - e) * (1 - e) * FX + 2 * e * (1 - e) * ((FX + d.x) / 2) + e * e * d.x;
        const y = (1 - e) * (1 - e) * (FY + 74) + 2 * e * (1 - e) * (FY + 64) + e * e * (d.y - 28);
        d.tok.parentElement.style.left = x.toFixed(1) + "px"; d.tok.parentElement.style.top = y.toFixed(1) + "px";
        d.tok.style.opacity = (u > 0 && u < 1 ? Math.min(1, u * 8, (1 - u) * 8) : 0).toFixed(3);
        const land = ramp(t, d.t0 + 0.5, d.t0 + 0.6);
        d.card.style.color = land > 0.5 ? "var(--seal)" : "";
        d.card.style.borderColor = land > 0.5 ? "var(--seal)" : "";
        d.card.style.transform = `scale(${(1 + 0.07 * land * Math.exp(-Math.max(0, t - d.t0 - 0.55) * 5)).toFixed(3)})`;
      });
      reveal(peek, ramp(t, W0 + 0.2, W0 + 0.8), { dy: 40 });
      reveal(plbl, ramp(t, W0 + 0.5, W0 + 0.9), { dy: 10 });
      const tick = Math.floor(t * 10);
      rows.forEach((r, i) => {
        let s = "";
        for (let k = 0; k < 21; k++) s += hex(i * 97 + k * 3 + (k + i + tick) % 9 * 11, 1) + (k % 7 === 6 ? "   " : " ");
        setText(r, s);
      });
    };
  }

  /* ====================================================================== *
   *  SELFHOST — free, open source, yours to run
   * ====================================================================== */
  function selfhost(cam, api) {
    const mk = (txt, top, cls) => {
      const h = el("div", "abs headline" + cls, cam);
      Object.assign(h.style, { left: "150px", top: top + "px", fontSize: "80px" });
      return words(h, txt);
    };
    const h1w = mk("Free and open source.", 338, ""), h2w = mk("Run your own.", 426, " g");
    const rule = el("div", "rule", cam);
    Object.assign(rule.style, { left: "150px", top: "556px", width: "800px" });
    const sub = el("div", "abs note", cam, `MIT licence · <b>github.com/polius/vault</b>`);
    Object.assign(sub.style, { left: "150px", top: "588px", fontSize: "26px" });

    const T = el("div", "term night", cam);
    Object.assign(T.style, { left: "1090px", top: "306px", width: "700px", height: "372px" });
    T.innerHTML = `<div class="tb"><i></i><i></i><i></i><div class="ttl">you@server</div></div><div class="body"></div>`;
    const body = T.querySelector(".body");
    const ln = () => el("div", "ln", body);
    const cmd1 = ln(), cmd2 = ln(), out1 = ln(), next = ln();
    out1.innerHTML = `<span class="f">${hex(42, 17)}…</span>`;
    const then = el("div", "abs note", cam, `then open <b>http://localhost</b>`);
    Object.assign(then.style, { left: "1090px", top: "706px", fontSize: "24px" });

    // the command in the README
    const C1 = "docker run -d --name vault \\", C2 = "  -p 80:8080 poliuscorp/vault", RATE = 0.03;
    const c0 = api.on("self2", "command") - 1.0;
    const c1 = c0 + C1.length * RATE + 0.05;
    const enter = c1 + C2.length * RATE + 0.12;
    typeCues(api, c0, C1 + C2, RATE, 0.45);
    api.cue("enter", enter, 0.9);
    api.cue("chime", enter + 0.5, 0.5);

    return function (t) {
      camera(cam, t, [[0, 1.03, 0, 0], [0, 1.0, 0, 0, 5]]);
      kin(h1w, t, -0.1, 0.07, 0.55);
      kin(h2w, t, api.on("self2", "own") - 0.35, 0.07, 0.55);
      const o = api.on("self1", "open");
      rule.style.transform = `scaleX(${outQuint(ramp(t, o - 0.2, o + 0.6)).toFixed(4)})`;
      reveal(sub, ramp(t, o, o + 0.5), { dy: 14 });
      reveal(T, ramp(t, -0.1, 0.6), { dy: 50 });
      const caret = (on) => (on && blink(t, 0.9) ? '<span class="caret"></span>' : "");
      setHTML(cmd1, `<span class="p">$</span> ${typed(C1, t, c0, RATE)}${caret(t < c1)}`);
      setHTML(cmd2, t < c1 ? "" : `${typed(C2, t, c1, RATE)}${caret(t < enter)}`);
      reveal(out1, ramp(t, enter + 0.2, enter + 0.4), { dy: 8 });
      setHTML(next, t < enter + 0.45 ? "" : `<span class="p">$</span> ${caret(true)}`);
      reveal(then, ramp(t, enter + 0.5, enter + 0.95), { dy: 12 });
    };
  }

  /* ====================================================================== *
   *  OUTRO — the seal, the name, the promise, where to try it
   * ====================================================================== */
  function outro(cam, api) {
    const SIZE = 640, CX = 470, CY = 540, X = 880;
    const S = sealNode(SPECIMEN, SIZE);
    const sw = at(cam, CX, CY, "");
    sw.appendChild(S.node);
    const wm = el("div", "abs wordmark", cam, "VAULT");
    Object.assign(wm.style, { left: X + "px", top: "232px", fontSize: "150px" });
    const rule = el("div", "rule", cam);
    Object.assign(rule.style, { left: X + "px", top: "440px", width: "920px" });
    const lines = ["Your files,", "encrypted locally."].map((txt, i) => {
      const h = el("div", "abs headline" + (i ? " g" : ""), cam);
      Object.assign(h.style, { left: X + "px", top: 484 + i * 92 + "px", fontSize: "74px" });
      return words(h, txt);
    });
    const tr = el("div", "abs try", cam, "vault.alzina.dev");
    Object.assign(tr.style, { left: X + "px", top: "722px" });
    const url = el("div", "abs note", cam, `<b>github.com/polius/vault</b> · open source · MIT`);
    Object.assign(url.style, { left: X + "px", top: "828px", fontSize: "23px" });

    const HIT = api.segStart("outro1") - 0.12;
    api.cue("hit", HIT, 1);
    const T0 = api.on("outro2", "files") - 0.1, T1 = api.on("outro2", "locally") - 0.25;
    const END = api.on("outro2", "locally") + 0.35;
    api.cue("pop", END + 0.1, 0.6);

    return function (t) {
      camera(cam, t, [[0, 1.0, 0, 0], [HIT, 1.03, 0, 0, 8]]);
      // the seal is pressed onto the page: its rings settle, the mark lands
      const tau = t - HIT, u = ramp(t, HIT - 0.45, HIT + 1.1);
      S.set({ p: outCubic(ramp(t, HIT - 0.45, HIT + 0.05)), a: spinAngles(0.35 * (1 - u) ** 2), ghost: tau < 0,
              mark: lerp(0.34, 1, ramp(tau, 0, 0.3)), markScale: tau > 0 ? popScale(tau) : 1,
              deco: ramp(t, HIT - 0.5, HIT - 0.1), ripple: tau >= 0 ? ramp(tau, 0, 1) : -1 });
      S.node.style.transform = `scale(${pressScale(tau).toFixed(4)})`;
      reveal(wm, ramp(t, HIT - 0.05, HIT + 0.55), { dy: 0, dx: -40 });
      rule.style.transform = `scaleX(${outQuint(ramp(t, T0 - 0.4, T0 + 0.4)).toFixed(4)})`;
      kin(lines[0], t, T0, 0.07, 0.6);
      kin(lines[1], t, T1, 0.07, 0.6);
      reveal(tr, ramp(t, END, END + 0.5), { dy: 20 });
      reveal(url, ramp(t, END + 0.35, END + 0.85), { dy: 14 });
    };
  }

  Object.assign(window.SCENES, { open, demo, local, inside, share, decrypt, selfhost, outro });
})();
