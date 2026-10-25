/* VAULT video — the scenes.
 *
 * Every scene is a function (cam, api) -> render(t) where t is seconds since the
 * scene's start (negative while it is cutting in). `cam` is the scene's camera:
 * transform it to push, pan or drift the whole shot. Moments come from the
 * narration via api.on(line, anchor) / api.segStart(line), so a frame is a pure
 * function of t and the visuals track the voice. Sound effects are registered
 * up front with api.cue(type, t) and mixed by sfx.py.
 *
 * The app on screen is a replica of src/index.html in its dark theme, built
 * from the same markup, sizes and strings, so it stays recognisable.
 */
(function () {
  const A = window.Toolkit;
  const { clamp, lerp, ramp, rnd, outQuint, outCubic, outExpo, inCubic, inOutCubic, inOutSine,
          outBack, spring, reveal, el, svg, at, setText, setHTML, words, kin, afterFonts } = A;

  const BLUE = "#5b9bff", GREEN = "#3ecf8e", AMBER = "#ffad32";
  const PASS = "glue-escalator-crux-taekwondo-strenuous-acrobat";
  const FILE = "Quarterly report.pdf", VFILE = "Quarterly report.pdf.vault", SIZE = "2.5 MB";

  /* ------------------------------------------------------------------ *
   *  icons — the app's own sprite (24px grid, stroked), plus a few more
   * ------------------------------------------------------------------ */
  const P = {
    lock: `<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>`,
    unlock: `<rect x="4.5" y="10.5" width="15" height="10.5" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 7.6-1.8"/>`,
    upload: `<path d="M12 15V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 15v3.5A2.5 2.5 0 0 0 6.5 21h11a2.5 2.5 0 0 0 2.5-2.5V15"/>`,
    folder: `<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2h7.4A2.5 2.5 0 0 1 21 9.5v8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/>`,
    file: `<path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 3v5h5"/>`,
    files: `<path d="M15 2.5H9.5A2.5 2.5 0 0 0 7 5v10a2.5 2.5 0 0 0 2.5 2.5h7A2.5 2.5 0 0 0 19 15V6.5z"/><path d="M15 2.5v4h4"/><path d="M4 7.5V18a3 3 0 0 0 3 3h8"/>`,
    vault: `<path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8z"/><path d="M14 3v5h5"/><rect x="9" y="13" width="6" height="4.5" rx="1"/><path d="M10.5 13v-1.2a1.5 1.5 0 0 1 3 0V13"/>`,
    x: `<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>`,
    eye: `<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>`,
    eyeoff: `<path d="M3.5 3.5l17 17"/><path d="M10.4 5.6A9 9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 0 1-2.9 3.7M6.6 6.9C4 8.6 2.5 12 2.5 12S6 18.5 12 18.5a8.7 8.7 0 0 0 4.6-1.3"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>`,
    dice: `<rect x="3.5" y="3.5" width="17" height="17" rx="3.5"/><circle cx="8.5" cy="8.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="15.5" cy="15.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="15.5" cy="8.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="8.5" cy="15.5" r="1.3" fill="currentColor" stroke="none"/>`,
    copy: `<rect x="9" y="9" width="11.5" height="11.5" rx="2.5"/><path d="M15 9V6a2.5 2.5 0 0 0-2.5-2.5h-6A2.5 2.5 0 0 0 4 6v6a2.5 2.5 0 0 0 2.5 2.5H9"/>`,
    check: `<path d="M5 12.5l4.5 4.5L19 7.5"/>`,
    info: `<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><circle cx="12" cy="7.8" r=".9" fill="currentColor" stroke="none"/>`,
    chev: `<path d="M9 6l6 6-6 6"/>`,
    github: `<path fill="currentColor" stroke="none" d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.54-3.88-1.54-.53-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.56-.29-5.25-1.28-5.25-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5z"/>`,
    mail: `<rect x="3" y="5.5" width="18" height="13" rx="2.5"/><path d="M3.8 7l8.2 6 8.2-6"/>`,
    cloud: `<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z"/>`,
    usb: `<rect x="7" y="9" width="10" height="12.5" rx="2"/><path d="M9 9V3.5h6V9"/><path d="M10.6 5.6h.01M13.4 5.6h.01"/>`,
    user: `<circle cx="12" cy="8" r="3.6"/><path d="M5 20.5c.8-3.6 3.6-5.6 7-5.6s6.2 2 7 5.6"/>`,
    chart: `<path d="M4 20V10M10 20V4M16 20v-7M21 20H3"/>`,
    key: `<circle cx="8" cy="15" r="4.5"/><path d="M11.2 11.8 20 3M16.5 6.5l2.5 2.5M14 9l2 2"/>`,
    globe: `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>`,
    arrow: `<path d="M5 12h14M13 6l6 6-6 6"/>`,
  };
  const icon = (name, cls = "icon") => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${P[name]}</svg>`;
  const bigIcon = (name, size, sw = 1.7) =>
    `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name]}</svg>`;

  /* the logo: a shield split on the diagonal, blue (encrypt) over green (decrypt) */
  const SHIELD = "M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.777 11.777 0 0 0 2.517 2.453 7.159 7.159 0 0 0 1.048.625c.28.132.581.24.829.24s.548-.108.829-.24a7.158 7.158 0 0 0 1.048-.625 11.775 11.775 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.263 62.467 62.467 0 0 0-2.887-.87C9.843.266 8.69 0 8 0z";
  let shieldId = 0;
  function shieldSvg(cls = "") {
    const id = "sh" + shieldId++;
    return `<svg class="${cls}" viewBox="0 0 16 16" style="overflow:visible" aria-hidden="true">
      <defs>
        <clipPath id="${id}a"><polygon points="0,0 16,0 0,16"/></clipPath>
        <clipPath id="${id}b"><polygon points="16,0 16,16 0,16"/></clipPath>
      </defs>
      <g class="ha"><g clip-path="url(#${id}a)"><path fill="#3b82f6" d="${SHIELD}"/></g></g>
      <g class="hb"><g clip-path="url(#${id}b)"><path fill="#10b981" d="${SHIELD}"/></g></g>
    </svg>`;
  }
  /* the lockup: shield + VAULT. join 0..1 brings the halves together; letters 0..5 */
  function lockup(parent, size) {
    const n = el("div", "lockup", parent);
    n.style.fontSize = size + "px";
    n.innerHTML = `${shieldSvg("mark")}<div class="word">${"VAULT".split("").map((c) => `<span>${c}</span>`).join("")}</div>`;
    const mark = n.querySelector(".mark"), ha = n.querySelector(".ha"), hb = n.querySelector(".hb");
    const letters = [...n.querySelectorAll(".word span")];
    let shift = 0;
    afterFonts(() => {
      const r = n.getBoundingClientRect(), m = mark.getBoundingClientRect();
      shift = (r.left + r.width / 2) - (m.left + m.width / 2);
    });
    return {
      node: n, mark,
      set(join, k, centre = 0) {
        const o = 9 * (1 - join);
        ha.setAttribute("transform", `translate(${(-o).toFixed(3)} ${(-o).toFixed(3)})`);
        hb.setAttribute("transform", `translate(${o.toFixed(3)} ${o.toFixed(3)})`);
        ha.setAttribute("opacity", clamp(join * 3).toFixed(3));
        hb.setAttribute("opacity", clamp(join * 3).toFixed(3));
        mark.style.transform = `translateX(${(shift * centre).toFixed(1)}px)`;
        letters.forEach((s, i) => {
          const p = outQuint(clamp(k - i));
          s.style.opacity = p.toFixed(3);
          s.style.transform = `translateX(${(-40 * (1 - p)).toFixed(1)}px)`;
        });
      },
    };
  }

  /* a soft light, drawn as a gradient (no blur filters) */
  function bloom(parent, x, y, size, color) {
    const b = el("div", "abs", parent);
    Object.assign(b.style, { left: x - size / 2 + "px", top: y - size / 2 + "px", width: size + "px", height: size + "px",
      borderRadius: "50%", background: `radial-gradient(closest-side, ${color}, transparent)` });
    return b;
  }

  /* camera: interpolate between keyframes [t, scale, x, y, dur] with an ease */
  function camera(cam, t, keys, drift = 1) {
    let s = keys[0][1], x = keys[0][2], y = keys[0][3];
    for (let i = 1; i < keys.length; i++) {
      const [t1, s1, x1, y1, d = 0.9] = keys[i];
      const p = inOutCubic(ramp(t, t1, t1 + d));
      s = lerp(s, s1, p); x = lerp(x, x1, p); y = lerp(y, y1, p);
    }
    x += drift * 6 * Math.sin(t * 0.45); y += drift * 4 * Math.cos(t * 0.37);
    s *= 1 + 0.004 * drift * Math.sin(t * 0.3);
    cam.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px) scale(${s.toFixed(5)})`;
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
  const POINTER = `<svg viewBox="0 0 24 24" width="44" height="44" style="overflow:visible"><path d="M5 2.5l14.5 8-6.4 1.7-3.2 6.6z"
    fill="#fff" stroke="#0b0f15" stroke-width="1.3" stroke-linejoin="round"/></svg>`;
  function pointer(parent) {
    const n = el("div", "cursor", parent, POINTER);
    const rip = el("div", "ripple", parent);
    n.style.transformOrigin = "9px 4px";
    return function (t, [x, y], clicks, alpha = 1) {
      let press = 0, rp = -1, at = 0;
      for (const c of clicks) {
        if (t > c - 0.08 && t < c + 0.18) press = Math.max(press, Math.sin(Math.PI * ramp(t, c - 0.08, c + 0.18)));
        if (t >= c && t < c + 0.55) { rp = ramp(t, c, c + 0.55); at = c; }
      }
      n.style.opacity = alpha.toFixed(3);
      n.style.transform = `translate(${(x - 9).toFixed(1)}px, ${(y - 4).toFixed(1)}px) scale(${(1 - 0.16 * press).toFixed(3)})`;
      if (rp >= 0) {
        rip.style.opacity = ((1 - rp) * 0.9 * alpha).toFixed(3);
        rip.style.left = x + "px"; rip.style.top = y + "px";
        rip.style.transform = `scale(${(0.3 + 0.9 * outCubic(rp)).toFixed(3)})`;
      } else rip.style.opacity = 0;
      return at;
    };
  }

  /* the step captions beside the app: numbered, because they are a sequence */
  function stepCaptions(layer, items) {
    const box = el("div", "steps", layer);
    return items.map(([n, title, sub]) => {
      const s = el("div", "step", box);
      el("div", "n", s, n);
      const tt = el("div", "t", s);
      const ws = words(tt, title);
      const ss = el("div", "s", s, sub);
      return { s, ws, ss };
    });
  }
  function playSteps(steps, t, starts) {
    steps.forEach((st, i) => {
      kin(st.ws, t, starts[i], 0.06, 0.55);
      reveal(st.ss, ramp(t, starts[i] + 0.25, starts[i] + 0.75), { dy: 14 });
      reveal(st.s.querySelector(".n"), ramp(t, starts[i] - 0.05, starts[i] + 0.4), { dy: 0, dx: -16 });
      const next = starts[i + 1];
      st.s.style.opacity = next == null ? 1 : lerp(1, 0.3, ramp(t, next - 0.1, next + 0.35)).toFixed(3);
    });
  }

  /* ====================================================================== *
   *  the app, in a browser window
   * ====================================================================== */
  const ZOOM = 1.3;
  function appWindow(parent, { x, y, w, h, mode }) {
    const enc = mode === "enc";
    const win = el("div", "win", parent);
    Object.assign(win.style, { left: x + "px", top: y + "px", width: w + "px", height: h + "px" });
    win.innerHTML = `<div class="chrome"><i></i><i></i><i></i><div class="url">${bigIcon("lock", 17, 2.2)}vault.alzina.dev</div></div>
      <div class="vp"><div class="app"></div></div>`;
    const vp = win.querySelector(".vp"), app = win.querySelector(".app");
    app.style.zoom = ZOOM;
    app.style.width = (w / ZOOM) + "px";
    const vpH = (h - 60) / ZOOM;

    const job = enc ? `
      <div class="mode"><div class="pill"></div><span>${icon("lock")}Encrypt</span><span>${icon("unlock")}Decrypt</span></div>
      <div class="selection">${icon("file", "icon icon-lg")}<div class="txt"><span class="nm">${FILE}</span><span class="mt">${SIZE}</span></div><div class="x">${icon("x")}</div></div>
      <div class="field"><div class="lbl">Password</div>
        <div class="input pwd"><div class="val"></div><div class="ib dice">${icon("dice")}</div><div class="ib">${icon("eyeoff")}</div></div>
        <div class="meter"><div class="bars"><i></i><i></i><i></i><i></i></div><span class="mtxt"><b>Very strong</b> · longer than the age of the universe to guess</span></div>
        <div class="muted">There is no password recovery. If you lose it, the file can't be opened.</div>
      </div>
      <div style="display:grid">
        <div class="field confirm" style="grid-area:1/1"><div class="lbl">Confirm password</div><div class="input"><div class="val"></div></div></div>
        <div class="generated" style="grid-area:1/1;align-self:center">${icon("info")}<p>Generated passphrase, about 77 bits. <b>Store it now in a password manager.</b> It can't be recovered.</p>
          <div class="btn btn-small">${icon("copy")}Copy</div></div>
      </div>
      <div class="opts">${icon("chev")}Options</div>
      <div class="btn btn-primary btn-wide go">${icon("lock")}<span>Encrypt</span></div>` : `
      <div class="mode"><div class="pill" style="left:calc(50% + 2px)"></div><span>${icon("lock")}Encrypt</span><span style="color:var(--unlock)">${icon("unlock")}Decrypt</span></div>
      <div class="selection">${icon("vault", "icon icon-lg")}<div class="txt"><span class="nm">${VFILE}</span><span class="mt">${SIZE} · VAULT file</span></div><div class="x">${icon("x")}</div></div>
      <div class="field"><div class="lbl">Password</div>
        <div class="input pwd"><div class="val dots"></div><div class="ib">${icon("eye")}</div></div>
      </div>
      <div class="btn btn-unlock btn-wide go">${icon("unlock")}<span>Decrypt</span></div>`;

    app.innerHTML = `
      <div class="topbar"><div class="brand">${shieldSvg()}<span class="wordmark">VAULT</span></div>
        <div style="display:flex;gap:10px;align-items:center"><div class="theme"><span>Auto</span><span>Light</span><span>Dark</span></div>
        <div style="width:38px;height:38px;border:1px solid var(--a-line);border-radius:50%;display:grid;place-items:center;color:var(--a-muted)">${icon("github")}</div></div></div>
      <div class="intro"><h1>Encrypt files locally</h1><p class="lede">Lock any file or folder with a password. Nothing is ever uploaded.</p></div>
      <div class="panel">
        <div class="state s0"><div class="dropzone"><div class="ico">${icon("upload", "icon icon-lg")}</div>
          <div class="ttl">Drop files or a folder here</div><div class="sub2">Drop a <b>.vault</b> file to decrypt it.</div>
          <div class="btns"><div class="btn btn-primary">${icon("files")}Choose files</div><div class="btn btn-secondary">${icon("folder")}Choose a folder</div></div></div></div>
        <div class="state s1">${job}</div>
        <div class="state s2"><div class="work-head"><span class="ph">Encrypting…</span><span class="pc">0%</span></div>
          <div class="progress"><b></b></div><div class="work-stats">2.5 MB of 2.5 MB</div>
          <div class="btn btn-secondary" style="justify-self:start">${icon("x")}Cancel</div></div>
        <div class="state s3 done"><div class="badge">${icon("check", "icon icon-lg")}</div>
          <h2>${enc ? "Encrypted" : "Decrypted"}</h2>
          <div class="done-file"><div class="fi">${icon(enc ? "vault" : "file", "icon icon-lg")}</div>
            <div><div class="nm">${enc ? VFILE : FILE}</div><div class="muted">${SIZE} · Saved to your downloads</div></div></div>
          ${enc ? `<div class="note">Keep your password safe. Without it, no one can open this file.</div>` : ""}
          <div class="btn btn-secondary">Encrypt or decrypt another file</div></div>
      </div>`;
    const overlay = el("div", "app-overlay", vp, `<div class="card">${icon("upload")}Drop to add</div>`);
    const $ = (s) => app.querySelector(s);
    const panel = $(".panel"), states = [0, 1, 2, 3].map((i) => $(".s" + i));
    if (!enc) $(".done-file .fi").style.cssText = "color:var(--unlock);background:var(--unlock-soft)";
    if (!enc) { $(".progress b").style.background = "var(--unlock)"; }

    // measured once fonts are in (identity transforms at that point)
    const M = { H: [300, 600, 200, 380], panelTop: 220, rects: {} };
    afterFonts(() => {
      M.H = states.map((s) => s.offsetHeight + 64);
      M.panelTop = panel.offsetTop;
      const pick = (sel) => { const r = app.querySelector(sel).getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; };
      M.rects = { drop: pick(".dropzone"), go: pick(".go"), pwd: pick(".pwd"), dice: enc ? pick(".dice") : null };
      states.forEach((s) => { s.style.visibility = "hidden"; });
    });

    const W = { panelH: 0, scroll: 0 };
    return {
      win, app, overlay, $, M,
      /* weights per state, cross-faded through a dip */
      states(wts) {
        let H = 0;
        wts.forEach((wt, i) => {
          H += wt * M.H[i];
          const a = ramp(wt, 0.55, 1);
          const s = states[i];
          s.style.visibility = a > 0 ? "visible" : "hidden";
          s.style.opacity = a.toFixed(3);
          s.style.transform = `translateY(${(10 * (1 - a)).toFixed(1)}px)`;
        });
        panel.style.height = H.toFixed(1) + "px";
        // the page scrolls when the panel outgrows the window
        const need = Math.max(0, M.panelTop + H + 28 - vpH);
        const sc = inOutSine(clamp(need / 60)) * (M.panelTop - 26);
        app.style.transform = `translateY(${(-sc).toFixed(1)}px)`;
        W.scroll = sc;
      },
      /* a point measured in the app, where it is now on stage */
      pt(name) { const [px, py] = M.rects[name]; return [px, py - W.scroll * ZOOM]; },
    };
  }
  /* state weights from a list of [time, state] switches */
  function stateWeights(t, switches, dur = 0.5) {
    const w = [0, 0, 0, 0];
    let cur = switches[0][1];
    w[cur] = 1;
    for (let i = 1; i < switches.length; i++) {
      const [ts, s] = switches[i];
      const p = inOutCubic(ramp(t, ts, ts + dur));
      if (p <= 0) break;
      w[cur] *= 1 - p; w[s] += p;
      if (p >= 1) { w.fill(0); w[s] = 1; }
      cur = s;
    }
    return w;
  }
  /* the dragged file */
  function dragFile(parent, name, ic) {
    return at(parent, 0, 0, "dragfile", `<div class="fi">${bigIcon(ic, 32)}</div><div>${name}<small>${SIZE}</small></div>`);
  }
  function moveTo(node, [x, y], scale, alpha) {
    node.parentElement.style.left = x.toFixed(1) + "px";
    node.parentElement.style.top = y.toFixed(1) + "px";
    node.style.transform = `scale(${scale.toFixed(3)}) rotate(${(-3 * (1 - scale)).toFixed(2)}deg)`;
    node.style.opacity = alpha.toFixed(3);
  }

  /* ====================================================================== *
   *  OPEN — the shield locks together; the promise rises underneath
   * ====================================================================== */
  function open(cam, api) {
    const halo = bloom(cam, 960, 470, 1600, "color-mix(in srgb, var(--blue) 30%, transparent)");
    const halo2 = bloom(cam, 1060, 560, 1100, "color-mix(in srgb, var(--green) 22%, transparent)");
    const wrap = at(cam, 960, 470, "");
    const lk = lockup(wrap, 168);
    const l1 = at(cam, 960, 650, "headline");
    const l2 = at(cam, 960, 750, "headline grad");
    const w1 = words(l1, "Encrypt any file with a password,");
    const w2 = words(l2, "right in your browser.");

    const J0 = 0.35, HIT = 1.45, K0 = HIT + 0.2, KR = 0.07;
    api.cue("swish", J0 + 0.25, 0.7);
    api.cue("hit", HIT, 1);
    for (let i = 0; i < 5; i++) api.cue("tick", K0 + i * KR, 0.45);
    const s2 = api.segStart("open2");

    return function (t) {
      camera(cam, t, [[0, 1.08, 0, 0], [HIT, 1.0, 0, 0, 5]]);
      // the halves glide in on the diagonal and lock with a hit
      const j = t < HIT ? inCubic(ramp(t, J0, HIT)) : 1;
      const k = t < K0 ? 0 : (t - K0) / KR * 0.55;
      const centre = 1 - outQuint(ramp(t, K0 - 0.05, K0 + 0.6));
      lk.set(j, k, centre);
      const punch = t > HIT ? Math.exp(-(t - HIT) * 7) * 0.07 : 0;
      const lift = outQuint(ramp(t, s2 - 0.35, s2 + 0.55));
      wrap.style.transform = `translateY(${(-160 * lift).toFixed(1)}px) scale(${(1 + punch - 0.22 * lift).toFixed(4)})`;
      const flash = t > HIT ? Math.exp(-(t - HIT) * 2.2) : 0;
      halo.style.opacity = (ramp(t, 0.2, HIT) * 0.35 + 0.65 * flash + 0.15 * lift).toFixed(3);
      halo2.style.opacity = (0.5 * flash + 0.25 * ramp(t, HIT, HIT + 1)).toFixed(3);
      halo.style.transform = halo2.style.transform = `translateY(${(-160 * lift).toFixed(1)}px)`;
      kin(w1, t, s2 - 0.05, 0.065, 0.6);
      kin(w2, t, api.on("open2", "browser") - 0.15, 0.075, 0.6);
    };
  }

  /* ====================================================================== *
   *  DEMO / DECRYPT — the real flow, in the app
   * ====================================================================== */
  const WIN = { x: 880, y: 66, w: 990, h: 948 };

  function demo(cam, api) {
    const layer = api.layer;
    const A = appWindow(cam, { ...WIN, mode: "enc" });
    const steps = stepCaptions(layer, [
      ["01", "Drop a file.", "Files, or a whole folder."],
      ["02", "Pick a password.", "Or generate a strong one."],
      ["03", "Press Encrypt.", "Out comes a .vault file."],
    ]);
    const chip = dragFile(cam, FILE, "file");
    const cur = pointer(cam);
    const val = A.$(".pwd .val"), bars = [...A.$(".bars").children], mtxt = A.$(".mtxt"), meter = A.$(".meter");
    const confirm = A.$(".confirm"), gen = A.$(".generated"), go = A.$(".go"), pwdBox = A.$(".pwd");
    const ph = A.$(".ph"), pc = A.$(".pc"), fill = A.$(".progress b"), stats = A.$(".work-stats");
    const badge = A.$(".badge");

    // ---- the beats ----
    const d1 = api.segStart("demo1"), d2 = api.segStart("demo2"), d3 = api.segStart("demo3");
    const DRAG0 = api.on("demo1", "drop") - 0.2, DROP = DRAG0 + 1.15;
    const GEN = api.on("demo2", "make") + 0.05;
    const GO = api.on("demo3", "encrypt") + 0.1;
    const ENC0 = GO + 0.55, ENC1 = ENC0 + 0.9, DONE = Math.max(ENC1 + 0.15, api.on("demo3", "sealed") - 0.05);
    api.cue("swish", DRAG0 + 0.1, 0.5);
    api.cue("pop", DROP, 0.9);
    api.cue("blip", GEN, 0.8);
    for (let i = 0; i < 4; i++) api.cue("tick", GEN + 0.45 + i * 0.08, 0.55);
    api.cue("enter", GO, 0.9);
    api.cue("stream", ENC0, 0.8);
    api.cue("chime", DONE, 1);

    return function (t) {
      camera(cam, t, [[0, 1.0, 0, 0], [GEN - 0.9, 1.03, -18, -18, 1.2], [GO + 0.4, 1.0, 0, 0, 1.0]]);
      reveal(A.win, ramp(t, -0.3, 0.45), { dy: 60, scale: 0.97 });
      playSteps(steps, t, [d1 - 0.1, d2 - 0.1, d3 - 0.1]);

      // pointer: the file is dragged in, then the dice, then Encrypt
      const drop = A.M.rects.drop ? A.pt("drop") : [1300, 600];
      const dice = A.M.rects.dice ? A.pt("dice") : [1500, 600];
      const goP = A.M.rects.go ? A.pt("go") : [1300, 900];
      const pos = path([[DRAG0, 380, 930], [DROP, drop[0], drop[1] + 20], [GEN - 0.75, drop[0], drop[1] + 20],
        [GEN, dice[0], dice[1]], [GO - 0.7, dice[0], dice[1]], [GO, goP[0] + 40, goP[1]], [GO + 1.2, goP[0] + 160, goP[1] + 140]])(t);
      cur(t, pos, [GEN, GO], ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, ENC0, ENC0 + 0.4)));
      const dragging = ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, DROP - 0.05, DROP + 0.15));
      moveTo(chip, [pos[0] + 150, pos[1] + 30], lerp(0.85, 1, ramp(t, DRAG0 - 0.3, DRAG0)) * lerp(1, 0.6, ramp(t, DROP - 0.1, DROP + 0.15)), dragging);
      const over = ramp(t, DROP - 0.6, DROP - 0.4) * (1 - ramp(t, DROP, DROP + 0.25));
      A.overlay.style.opacity = over.toFixed(3);
      A.$(".dropzone").classList.toggle("hot", over > 0.5);

      // panel states
      A.states(stateWeights(t, [[0, 0], [DROP, 1], [GO + 0.05, 2], [DONE, 3]], 0.45));
      // password: focused, then generated (letters settle left to right)
      pwdBox.classList.toggle("focus", t > DROP + 0.3 && t < GO);
      let pw = "";
      if (t >= GEN) {
        for (let i = 0; i < PASS.length; i++) {
          const settle = GEN + 0.06 + i * 0.008;
          pw += t >= settle || PASS[i] === "-" ? PASS[i] : "abcdefghijklmnopqrstuvwxyz"[Math.floor(rnd(i * 13 + Math.floor(t * 40)) * 26)];
        }
      }
      setHTML(val, pw || (t > DROP + 0.3 && blink(t - DROP, 1.0) ? '<span style="display:inline-block;width:1.5px;height:20px;background:var(--a-ink);vertical-align:-4px"></span>' : ""));
      bars.forEach((b, i) => { b.style.background = t > GEN + 0.45 + i * 0.08 ? "var(--unlock)" : ""; });
      meter.style.opacity = ramp(t, GEN + 0.4, GEN + 0.6).toFixed(3);
      mtxt.style.opacity = ramp(t, GEN + 0.7, GEN + 0.9).toFixed(3);
      const g = ramp(t, GEN + 0.35, GEN + 0.75);
      confirm.style.opacity = (1 - ramp(g, 0, 0.5)).toFixed(3);
      gen.style.opacity = ramp(g, 0.5, 1).toFixed(3);
      gen.style.transform = `translateY(${(8 * (1 - g)).toFixed(1)}px)`;
      const press = t > GO - 0.06 && t < GO + 0.2 ? Math.sin(Math.PI * ramp(t, GO - 0.06, GO + 0.2)) : 0;
      go.style.transform = `scale(${(1 - 0.025 * press).toFixed(4)})`;
      go.style.filter = press > 0 ? `brightness(${(1 + 0.15 * press).toFixed(3)})` : "none";

      // working: the key first, then the bytes
      if (t < ENC0) {
        setText(ph, "Deriving a key from your password…"); setText(pc, "");
        fill.style.width = "35%"; fill.style.marginLeft = (((t * 1.1) % 1.3) * 100 - 35).toFixed(1) + "%";
        setText(stats, "This takes a moment on purpose: it makes guessing passwords slow.");
      } else {
        const p = inOutSine(ramp(t, ENC0, ENC1));
        setText(ph, "Encrypting…"); setText(pc, Math.round(p * 100) + "%");
        fill.style.marginLeft = "0"; fill.style.width = (p * 100).toFixed(1) + "%";
        setText(stats, `${(2.5 * p).toFixed(1)} MB of 2.5 MB · 41.6 MB/s`);
      }
      const b = ramp(t, DONE + 0.1, DONE + 0.7);
      badge.style.transform = `scale(${(b <= 0 ? 0.4 : spring(b * 1.3, 10, 5)).toFixed(4)})`;
    };
  }

  function decrypt(cam, api) {
    const layer = api.layer;
    api.accent(0, GREEN);
    const A = appWindow(cam, { ...WIN, mode: "dec" });
    const steps = stepCaptions(layer, [
      ["01", "Drop it back in.", "VAULT switches to Decrypt."],
      ["02", "Type the password.", "Checked before anything is saved."],
      ["03", "It’s back.", "Exactly as it was."],
    ]);
    const chip = dragFile(cam, VFILE, "vault");
    const cur = pointer(cam);
    const val = A.$(".pwd .val"), pwdBox = A.$(".pwd"), go = A.$(".go");
    const ph = A.$(".ph"), pc = A.$(".pc"), fill = A.$(".progress b"), stats = A.$(".work-stats");
    const badge = A.$(".badge");

    const d1 = api.segStart("decrypt1"), d2 = api.segStart("decrypt2");
    const DRAG0 = d1 - 0.35, DROP = api.on("decrypt1", "drop") + 0.25;
    const TYPE0 = api.on("decrypt1", "type") - 0.05, N = 14, RATE = 0.055;
    const GO = TYPE0 + N * RATE + 0.3;
    const DEC0 = GO + 0.5, DEC1 = DEC0 + 0.7, DONE = Math.max(DEC1 + 0.12, api.on("decrypt2", "back") - 0.25);
    api.cue("swish", DRAG0 + 0.1, 0.5);
    api.cue("pop", DROP, 0.9);
    for (let i = 0; i < N; i++) api.cue("key", TYPE0 + i * RATE + (rnd(i) - 0.5) * 0.02, 0.5);
    api.cue("enter", GO, 0.9);
    api.cue("stream", DEC0, 0.7);
    api.cue("chime", DONE, 1);

    return function (t) {
      camera(cam, t, [[0, 1.0, 0, 0], [TYPE0 - 0.8, 1.03, -18, -10, 1.0], [GO + 0.4, 1.0, 0, 0, 1.0]]);
      reveal(A.win, ramp(t, -0.3, 0.45), { dy: 60, scale: 0.97 });
      playSteps(steps, t, [d1 - 0.1, api.on("decrypt1", "type") - 0.2, d2 - 0.1]);

      const drop = A.M.rects.drop ? A.pt("drop") : [1300, 600];
      const pwd = A.M.rects.pwd ? A.pt("pwd") : [1300, 700];
      const goP = A.M.rects.go ? A.pt("go") : [1300, 800];
      const pos = path([[DRAG0, 380, 930], [DROP, drop[0], drop[1] + 20], [TYPE0 - 0.6, drop[0], drop[1] + 20],
        [TYPE0 - 0.15, pwd[0] + 80, pwd[1] + 4], [GO - 0.55, pwd[0] + 80, pwd[1] + 4], [GO, goP[0] + 40, goP[1]],
        [GO + 1.2, goP[0] + 160, goP[1] + 140]])(t);
      cur(t, pos, [TYPE0 - 0.12, GO], ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, DEC0, DEC0 + 0.4)));
      const dragging = ramp(t, DRAG0 - 0.3, DRAG0) * (1 - ramp(t, DROP - 0.05, DROP + 0.15));
      moveTo(chip, [pos[0] + 170, pos[1] + 30], lerp(0.85, 1, ramp(t, DRAG0 - 0.3, DRAG0)) * lerp(1, 0.6, ramp(t, DROP - 0.1, DROP + 0.15)), dragging);
      const over = ramp(t, DROP - 0.6, DROP - 0.4) * (1 - ramp(t, DROP, DROP + 0.25));
      A.overlay.style.opacity = over.toFixed(3);
      A.$(".dropzone").classList.toggle("hot", over > 0.5);

      A.states(stateWeights(t, [[0, 0], [DROP, 1], [GO + 0.05, 2], [DONE, 3]], 0.45));
      pwdBox.style.setProperty("--focus", "var(--unlock)");
      pwdBox.classList.toggle("focus", t > TYPE0 - 0.15 && t < GO);
      const n = t < TYPE0 ? 0 : Math.min(N, Math.floor((t - TYPE0) / RATE) + 1);
      setText(val, "•".repeat(n));
      const press = t > GO - 0.06 && t < GO + 0.2 ? Math.sin(Math.PI * ramp(t, GO - 0.06, GO + 0.2)) : 0;
      go.style.transform = `scale(${(1 - 0.025 * press).toFixed(4)})`;

      if (t < DEC0) {
        setText(ph, "Checking the password…"); setText(pc, "");
        fill.style.width = "35%"; fill.style.marginLeft = (((t * 1.1) % 1.3) * 100 - 35).toFixed(1) + "%";
        setText(stats, "This takes a moment on purpose: it makes guessing passwords slow.");
      } else {
        const p = inOutSine(ramp(t, DEC0, DEC1));
        setText(ph, "Decrypting…"); setText(pc, Math.round(p * 100) + "%");
        fill.style.marginLeft = "0"; fill.style.width = (p * 100).toFixed(1) + "%";
        setText(stats, `${(2.5 * p).toFixed(1)} MB of 2.5 MB · 44.2 MB/s`);
      }
      const b = ramp(t, DONE + 0.1, DONE + 0.7);
      badge.style.transform = `scale(${(b <= 0 ? 0.4 : spring(b * 1.3, 10, 5)).toFixed(4)})`;
    };
  }

  /* ====================================================================== *
   *  LOCAL — it all happens on your device
   * ====================================================================== */
  const LAPTOP = `<svg width="380" height="284" viewBox="0 0 118 88" fill="none" aria-hidden="true">
    <rect x="15" y="5" width="88" height="62" rx="9" fill="#0a0f17" stroke="currentColor" stroke-width="2.4"/>
    <rect x="21" y="11" width="76" height="50" rx="4" fill="#141b26"/>
    <rect x="4" y="73" width="110" height="8" rx="4" fill="#7d8694"/>
  </svg>`;
  function local(cam, api) {
    const layer = api.layer;
    const CX = 560, CY = 600;
    const halo = bloom(cam, CX, CY, 900, "color-mix(in srgb, var(--blue) 26%, transparent)");
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible" }, cam);
    const ring = svg("circle", { cx: CX, cy: CY, r: 300, fill: "rgba(91,155,255,0.035)", stroke: "var(--accent)",
      "stroke-width": 2.5, "stroke-dasharray": "10 13", "stroke-opacity": 0.6 }, g);
    const ringLbl = svg("text", { x: CX, y: CY + 345, class: "", "text-anchor": "middle",
      style: "font: 600 22px var(--mono); letter-spacing: 0.18em; fill: var(--dim)" }, g);
    ringLbl.textContent = "YOUR DEVICE";
    const lap = at(cam, CX, CY - 10, "", LAPTOP);
    lap.style.color = "var(--ink)";
    const scr = at(cam, CX, CY - 34, "", shieldSvg());
    scr.querySelector("svg").setAttribute("width", "92"); scr.querySelector("svg").setAttribute("height", "92");
    const lockB = at(cam, CX + 42, CY + 4, "", `<div style="width:46px;height:46px;border-radius:14px;display:grid;place-items:center;background:var(--blue);color:#08111f">${bigIcon("lock", 26, 2.4)}</div>`);

    const head = at(layer, 960, 150, "headline");
    const hw = words(head, "It all happens on your device.");
    const rows = [
      ["uploaded", "cloud", "Nothing is uploaded."],
      ["accounts", "user", "No accounts."],
      ["tracking", "chart", "No tracking."],
    ].map(([k, ic, txt], i) => {
      const y = 440 + i * 180;
      const card = at(cam, 1110, y, "glass", `<div style="width:120px;height:120px;display:grid;place-items:center;color:var(--dim);position:relative">
        ${bigIcon(ic, 58)}<svg width="120" height="120" viewBox="0 0 120 120" style="position:absolute;inset:0"><path class="slash" d="M30 30L90 90"
        stroke="var(--red)" stroke-width="6" stroke-linecap="round" pathLength="100" stroke-dasharray="100 100" stroke-dashoffset="100"/></svg></div>`);
      const tx = el("div", "abs no", cam);
      Object.assign(tx.style, { left: "1210px", top: y - 32 + "px" });
      const ws = words(tx, txt);
      const t0 = api.on("local1", k) - 0.1;
      api.cue("thud", t0 + 0.05, i === 0 ? 1 : 0.85);
      return { card, slash: card.querySelector(".slash"), ws, t0, tx };
    });
    const dev = api.on("local1", "device");
    api.cue("pop", dev - 0.1, 0.7);

    return function (t) {
      camera(cam, t, [[0, 1.04, 0, 10], [0, 1.0, 0, 0, 6]], 1.1);
      kin(hw, t, -0.05, 0.06, 0.55);
      const d = ramp(t, dev - 0.4, dev + 0.3);
      reveal(lap, d, { dy: 40, scale: 0.92 });
      reveal(scr, ramp(t, dev - 0.1, dev + 0.4), { dy: 0, scale: 0.6 });
      reveal(lockB, ramp(t, dev + 0.2, dev + 0.6), { dy: 0, scale: 0.4, ease: outBack });
      ring.setAttribute("opacity", ramp(t, dev - 0.2, dev + 0.5).toFixed(3));
      ring.setAttribute("r", lerp(240, 300, outQuint(ramp(t, dev - 0.2, dev + 0.7))).toFixed(1));
      ring.setAttribute("stroke-dashoffset", (-t * 14).toFixed(1));
      ringLbl.setAttribute("opacity", ramp(t, dev + 0.2, dev + 0.7).toFixed(3));
      halo.style.opacity = (0.8 * d).toFixed(3);
      rows.forEach((r, i) => {
        const p = ramp(t, r.t0 - 0.1, r.t0 + 0.5);
        r.card.style.transform = `scale(${(p <= 0 ? 0 : spring(p * 1.4, 9, 4.5)).toFixed(4)})`;
        r.card.style.opacity = Math.min(1, p * 4).toFixed(3);
        r.slash.setAttribute("stroke-dashoffset", (100 * (1 - outCubic(ramp(t, r.t0 + 0.12, r.t0 + 0.42)))).toFixed(1));
        kin(r.ws, t, r.t0, 0.05, 0.5);
        const next = rows[i + 1];
        const back = next ? ramp(t, next.t0, next.t0 + 0.4) : 0;
        r.tx.style.opacity = lerp(1, 0.45, back).toFixed(3);
      });
    };
  }

  /* ====================================================================== *
   *  INSIDE — a slow key, then every piece sealed
   * ====================================================================== */
  function inside(cam, api) {
    const layer = api.layer;
    const R1 = 455, R2 = 820;
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible" }, cam);
    const line = (x1, y1, x2, y2) => svg("path", { d: `M${x1} ${y1}L${x2} ${y2}`, stroke: "rgba(255,255,255,0.22)", "stroke-width": 3,
      "stroke-dasharray": "3 11", "stroke-linecap": "round", fill: "none" }, g);
    const a1 = line(545, R1, 700, R1), a2 = line(1222, R1, 1380, R1), a3 = line(530, R2, 680, R2), a4 = line(1245, R2, 1385, R2);
    const dot = () => svg("circle", { r: 8, fill: "var(--accent-l)", opacity: 0 }, g);
    const dots = [dot(), dot(), dot(), dot()];

    const pw = at(cam, 330, R1, "chip", `${bigIcon("lock", 30, 2)}<span>glue-escalator-crux…</span>`);
    const box = at(cam, 960, R1, "box glass", `<div class="ttl mono">Argon2id</div><div class="memgrid"></div><div class="mt">64 MiB of memory · 3 passes</div>`);
    const cells = [];
    const grid = box.querySelector(".memgrid");
    for (let i = 0; i < 48; i++) cells.push(el("i", "", grid));
    const slow = at(cam, 960, R1 - 168, "", `<div style="font: 650 26px var(--font); color: ${AMBER}; padding: 8px 20px; border-radius: 999px;
      border: 1.5px solid color-mix(in srgb, ${AMBER} 55%, transparent); background: color-mix(in srgb, ${AMBER} 12%, rgba(8,10,14,0.85)); white-space: nowrap">Slow on purpose</div>`);
    const key = at(cam, 1590, R1, "chip", `<span style="color:var(--accent-l);display:grid">${bigIcon("key", 34, 2)}</span><span>256-bit key</span>`);
    const keyFly = at(cam, 0, 0, "", `<div style="width:62px;height:62px;border-radius:18px;display:grid;place-items:center;background:var(--accent);color:#08111f">${bigIcon("key", 36, 2.2)}</div>`);

    const file = at(cam, 330, R2, "dragfile", `<div class="fi">${bigIcon("file", 32)}</div><div>${FILE}<small>${SIZE}</small></div>`);
    const PX = [790, 960, 1130];
    const pieces = PX.map((x, i) => {
      const n = el("div", "piece", cam);
      n.innerHTML = `<div class="hx">${[0, 1, 2, 3].map((r) => hex(i * 31 + r * 5, 4)).join("\n")}</div>
        <div class="lk">${bigIcon("lock", 28, 2.4)}</div><div class="idx">${i === 2 ? "0.4 MiB" : "1 MiB"}</div>`;
      return { n, lk: n.querySelector(".lk"), hx: n.querySelector(".hx"), x };
    });
    const aes = at(cam, 960, R2 - 165, "mlabel");
    aes.innerHTML = `<span style="color:var(--ink);font-weight:700">AES-256-GCM</span> · one piece at a time`;
    const tamper = at(cam, 960, R2 + 128, "", `<div style="font: 650 24px var(--font); color: var(--red); padding: 8px 20px; border-radius: 999px;
      border: 1.5px solid color-mix(in srgb, var(--red) 55%, transparent); background: color-mix(in srgb, var(--red) 12%, rgba(8,10,14,0.85)); white-space: nowrap">Edited? It won’t open.</div>`);
    const out = at(cam, 1600, R2, "dragfile", `<div class="fi">${bigIcon("vault", 32)}</div><div>${VFILE}<small>${SIZE}</small></div>`);

    const h1 = at(layer, 960, 140, "headline"), h2 = at(layer, 960, 140, "headline");
    const h1w = words(h1, "Your password becomes a key.");
    const h2w = words(h2, "Then every piece is sealed.");

    const s1 = api.segStart("inside1"), s2 = api.segStart("inside2");
    const ARG = api.on("inside1", "argon") - 0.1, KEY = api.on("inside1", "key"), SLOW = api.on("inside1", "slow");
    const AES = api.on("inside2", "aes") - 0.2, PIECE = api.on("inside2", "piece"), CHG = api.on("inside2", "change");
    const SEAL = (i) => PIECE + 0.1 + i * 0.2, OUT = SEAL(2) + 0.45;
    api.cue("blip", ARG + 0.35, 0.6);
    api.cue("pop", KEY + 0.05, 0.9);
    api.cue("tick", SLOW, 0.6);
    api.cue("swish", AES, 0.6);
    [0, 1, 2].forEach((i) => api.cue("pop", SEAL(i), 0.75));
    api.cue("deny", CHG + 0.05, 0.8);

    const flow = (d, p, [x1, y1], [x2, y2]) => {
      d.setAttribute("cx", lerp(x1, x2, p).toFixed(1)); d.setAttribute("cy", lerp(y1, y2, p).toFixed(1));
      d.setAttribute("opacity", (p > 0 && p < 1 ? Math.sin(Math.PI * p) : 0).toFixed(3));
    };

    return function (t) {
      camera(cam, t, [[0, 1.0, 0, 0], [s2 - 0.6, 1.0, 0, -20, 1.4]], 0.9);
      kin(h1w, t, -0.1, 0.06, 0.55, s2 - 0.75);
      kin(h2w, t, s2 - 0.35, 0.06, 0.55);

      // row 1: password -> Argon2id -> key
      reveal(pw, ramp(t, 0, 0.45), { dy: 30 });
      reveal(box, ramp(t, 0.1, 0.6), { dy: 30, scale: 0.95 });
      a1.setAttribute("opacity", ramp(t, 0.3, 0.6).toFixed(3));
      a2.setAttribute("opacity", ramp(t, 0.4, 0.7).toFixed(3));
      flow(dots[0], ramp(t, ARG, ARG + 0.4), [545, R1], [700, R1]);
      const work = ramp(t, ARG + 0.35, ARG + 0.5) * (1 - ramp(t, KEY, KEY + 0.4));
      cells.forEach((c, i) => {
        const on = work > 0 && rnd(i * 7 + Math.floor(t * 14)) > 0.55;
        c.style.background = on ? `color-mix(in srgb, var(--accent) ${Math.round(40 + 50 * rnd(i + Math.floor(t * 14)))}%, transparent)` :
          t > KEY ? "color-mix(in srgb, var(--accent) 22%, transparent)" : "";
      });
      box.style.borderColor = `color-mix(in srgb, var(--accent) ${Math.round(70 * work)}%, rgba(255,255,255,0.12))`;
      reveal(slow, ramp(t, SLOW - 0.15, SLOW + 0.3), { dy: 12, scale: 0.9, ease: outBack });
            flow(dots[1], ramp(t, KEY - 0.35, KEY + 0.05), [1222, R1], [1380, R1]);
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
        const x = lerp(330, p.x, q);
        const shake = t > CHG && t < CHG + 0.45 && i === 1 ? Math.sin((t - CHG) * 60) * 8 * (1 - (t - CHG) / 0.45) : 0;
        p.n.style.left = (x + shake).toFixed(1) + "px"; p.n.style.top = R2 + "px";
        p.n.style.opacity = q.toFixed(3);
        p.n.style.visibility = q > 0 ? "visible" : "hidden";
        const s = ramp(t, SEAL(i) - 0.05, SEAL(i) + 0.35);
        p.lk.style.transform = `scale(${(s <= 0 ? 0 : spring(s * 1.3, 10, 5)).toFixed(4)})`;
        p.hx.style.opacity = lerp(1, 0.35, s).toFixed(3);
        const red = i === 1 ? ramp(t, CHG, CHG + 0.15) * (1 - ramp(t, CHG + 0.9, CHG + 1.4)) : 0;
        p.n.style.borderColor = red > 0 ? `color-mix(in srgb, var(--red) ${Math.round(80 * red)}%, rgba(255,255,255,0.13))` : "";
        p.lk.style.background = red > 0.5 ? "var(--red)" : "";
      });
      reveal(tamper, ramp(t, CHG + 0.05, CHG + 0.4), { dy: 10, alpha: 1 - ramp(t, CHG + 1.2, CHG + 1.6) });
      file.style.opacity = lerp(1, 0.45, ramp(t, AES, AES + 0.6)).toFixed(3);
      // the key drops onto the pieces as they are sealed
      const kf = ramp(t, AES - 0.1, PIECE + 0.05), kd = ramp(t, SEAL(2) + 0.25, SEAL(2) + 0.55);
      const kx = t < PIECE + 0.05 ? lerp(1590, PX[0], inOutCubic(kf)) : lerp(PX[0], PX[2], inOutCubic(ramp(t, SEAL(0), SEAL(2))));
      const ky = t < PIECE + 0.05 ? lerp(R1, R2 - 108, inOutCubic(kf)) - 120 * Math.sin(Math.PI * kf) : R2 - 108;
      keyFly.parentElement.style.left = kx.toFixed(1) + "px"; keyFly.parentElement.style.top = ky.toFixed(1) + "px";
      keyFly.style.opacity = (kf > 0 ? 1 - kd : 0).toFixed(3);
      keyFly.style.transform = `scale(${(0.9 + 0.12 * Math.sin(Math.PI * kf)).toFixed(3)})`;
      reveal(out, ramp(t, OUT, OUT + 0.5), { dy: 0, dx: -30, scale: 0.94 });
      flow(dots[2], ramp(t, AES, AES + 0.5), [530, R2], [680, R2]);
      flow(dots[3], ramp(t, OUT - 0.4, OUT), [1245, R2], [1385, R2]);
    };
  }

  /* ====================================================================== *
   *  SHARE — send it anywhere; to anyone else, it is noise
   * ====================================================================== */
  function share(cam, api) {
    const layer = api.layer;
    const FX = 960, FY = 420;
    const halo = bloom(cam, FX, FY, 1100, "color-mix(in srgb, var(--blue) 24%, transparent)");
    const g = svg("svg", { width: 1920, height: 1080, style: "position:absolute;inset:0;overflow:visible" }, cam);
    const vf = at(cam, FX, FY, "vfile glass", `<div class="fi">${bigIcon("vault", 50)}</div><div><div class="nm">${VFILE}</div><div class="mt">${SIZE} · encrypted</div></div>`);
    const DEST = [["email", "mail", "Email", 520, 800], ["cloud", "cloud", "Cloud drive", 960, 830], ["usb", "usb", "USB stick", 1400, 800]];
    const dests = DEST.map(([k, ic, name, x, y]) => {
      const d = el("div", "dest", cam);
      d.style.left = x + "px"; d.style.top = y + "px";
      d.innerHTML = `<div class="card glass">${bigIcon(ic, 68)}</div><div class="label">${name}</div>`;
      const arc = svg("path", { d: `M${FX} ${FY + 70} Q ${(FX + x) / 2} ${FY + 60} ${x} ${y - 90}`, fill: "none", stroke: "var(--accent)",
        "stroke-width": 3, "stroke-dasharray": "2 12", "stroke-linecap": "round", opacity: 0 }, g);
      const tok = at(cam, 0, 0, "", `<div style="width:56px;height:56px;border-radius:16px;display:grid;place-items:center;background:var(--accent);color:#08111f">${bigIcon("vault", 32, 2.2)}</div>`);
      const t0 = api.on("share1", k) - 0.15;
      api.cue("swish", t0, 0.55); api.cue("pop", t0 + 0.55, 0.75);
      return { d, arc, tok, t0, x, y, card: d.querySelector(".card") };
    });
    // the bytes inside, as anyone without the password sees them
    const peek = at(cam, FX, 720, "glass", "");
    Object.assign(peek.style, { width: "1180px", height: "330px", overflow: "hidden", position: "relative" });
    const rows = [...Array(8)].map((_, r) => {
      const n = el("div", "noise", peek);
      n.style.left = "40px"; n.style.top = 22 + r * 37 + "px";
      return n;
    });
    const plbl = at(cam, FX, 525, "mlabel", "what anyone else sees");

    const h1 = at(layer, 960, 150, "headline"), h2 = at(layer, 960, 150, "headline");
    const h1w = words(h1, "Send it anywhere.");
    const h2w = words(h2, "Without the password, it’s noise.");
    const s2 = api.segStart("share2"), W0 = api.on("share2", "without") - 0.2, NOISE = api.on("share2", "noise");
    api.cue("stream", W0 + 0.3, 0.6);

    return function (t) {
      camera(cam, t, [[0, 1.02, 0, 0], [W0, 1.0, 0, -10, 1.0]]);
      kin(h1w, t, -0.1, 0.07, 0.55, s2 - 0.6);
      kin(h2w, t, s2 - 0.25, 0.06, 0.55);
      reveal(vf, ramp(t, -0.2, 0.4), { dy: 40, scale: 0.94 });
      const up = inOutCubic(ramp(t, W0, W0 + 0.7));
      vf.parentElement.style.top = lerp(FY, 360, up).toFixed(1) + "px";
      halo.style.opacity = (0.7 + 0.3 * Math.sin(t * 1.3)).toFixed(3);
      const gone = ramp(t, W0 - 0.1, W0 + 0.4);
      dests.forEach((d, i) => {
        reveal(d.d, ramp(t, 0.1 + i * 0.12, 0.6 + i * 0.12), { dy: 30, base: "translate(-50%,-50%)", alpha: 1 - gone });
        if (gone >= 1) d.d.style.visibility = "hidden";
        const u = ramp(t, d.t0, d.t0 + 0.55);
        d.arc.setAttribute("opacity", (0.5 * ramp(t, d.t0 - 0.1, d.t0 + 0.2) * (1 - gone)).toFixed(3));
        d.arc.setAttribute("stroke-dashoffset", (-t * 40).toFixed(1));
        const e = inOutCubic(u);
        const x = (1 - e) * (1 - e) * FX + 2 * e * (1 - e) * ((FX + d.x) / 2) + e * e * d.x;
        const y = (1 - e) * (1 - e) * (FY + 70) + 2 * e * (1 - e) * (FY + 60) + e * e * (d.y - 20);
        d.tok.parentElement.style.left = x.toFixed(1) + "px"; d.tok.parentElement.style.top = y.toFixed(1) + "px";
        d.tok.style.opacity = (u > 0 && u < 1 ? Math.min(1, u * 8, (1 - u) * 8) : 0).toFixed(3);
        const land = ramp(t, d.t0 + 0.5, d.t0 + 0.6) * Math.exp(-Math.max(0, t - d.t0 - 0.55) * 1.2);
        d.card.style.borderColor = `color-mix(in srgb, var(--accent) ${Math.round(80 * land)}%, rgba(255,255,255,0.12))`;
        d.card.style.color = land > 0.05 ? "var(--accent-l)" : "";
        d.card.style.transform = `scale(${(1 + 0.08 * land).toFixed(3)})`;
      });
      reveal(peek, ramp(t, W0 + 0.2, W0 + 0.8), { dy: 40, scale: 0.97 });
      reveal(plbl, ramp(t, W0 + 0.5, W0 + 0.9), { dy: 10 });
      const tick = Math.floor(t * 10);
      rows.forEach((r, i) => {
        let s = "";
        for (let k = 0; k < 24; k++) s += hex(i * 97 + k * 3 + (k + i + tick) % 9 * 11, 1) + (k % 8 === 7 ? "   " : " ");
        setText(r, s);
        r.style.color = NOISE && t > NOISE - 0.1 && t < NOISE + 0.6 ? "rgba(168,200,255,0.75)" : "";
      });
    };
  }

  /* ====================================================================== *
   *  SELFHOST — free, open source, yours to run
   * ====================================================================== */
  function selfhost(cam, api) {
    const halo = bloom(cam, 1380, 540, 1300, "color-mix(in srgb, var(--blue) 20%, transparent)");
    const h1 = el("div", "abs headline", cam); Object.assign(h1.style, { left: "150px", top: "350px", fontSize: "84px" });
    const h1w = words(h1, "Free and open source.");
    const h2 = el("div", "abs headline grad", cam); Object.assign(h2.style, { left: "150px", top: "462px", fontSize: "84px" });
    const h2w = words(h2, "Run your own.");
    const sub = el("div", "abs sub", cam); Object.assign(sub.style, { left: "154px", top: "600px", fontSize: "34px" });
    sub.innerHTML = `MIT License · <span style="font-family:var(--mono);color:var(--ink)">github.com/polius/vault</span>`;

    const T = el("div", "term", cam);
    Object.assign(T.style, { left: "1110px", top: "330px", width: "700px", height: "360px" });
    T.innerHTML = `<div class="tb"><i></i><i></i><i></i><div class="ttl">you@server — zsh</div></div><div class="body"></div>`;
    const body = T.querySelector(".body");
    const ln = () => el("div", "ln", body);
    const cmd1 = ln(), cmd2 = ln(), out1 = ln(); ln(); const out2 = ln();
    out1.innerHTML = `<span class="f">${hex(42, 32).slice(0, 38)}…</span>`;
    out2.innerHTML = `<span class="ok" style="color:var(--green)">✓</span> <span class="d">VAULT is up on</span> <span class="a">http://localhost</span>`;

    const C1 = "docker run -d -p 80:8080 \\", C2 = "  poliuscorp/vault", RATE = 0.032;
    const c0 = api.on("self2", "command") - 0.9;
    const c1 = c0 + C1.length * RATE + 0.05;
    const enter = c1 + C2.length * RATE + 0.1;
    typeCues(api, c0, C1 + C2, RATE, 0.45);
    api.cue("enter", enter, 0.9);
    api.cue("chime", enter + 0.6, 0.5);

    return function (t) {
      camera(cam, t, [[0, 1.04, 0, 0], [0, 1.0, 0, 0, 5]]);
      kin(h1w, t, -0.1, 0.07, 0.55);
      kin(h2w, t, api.on("self2", "own") - 0.35, 0.07, 0.55);
      reveal(sub, ramp(t, api.on("self1", "open"), api.on("self1", "open") + 0.5), { dy: 14 });
      reveal(T, ramp(t, -0.1, 0.6), { dy: 50, scale: 0.96 });
      halo.style.opacity = (0.6 + 0.4 * ramp(t, enter, enter + 0.4)).toFixed(3);
      const caret = (on) => (on && blink(t, 0.9) ? '<span class="caret"></span>' : "");
      setHTML(cmd1, `<span class="p">$</span> ${typed(C1, t, c0, RATE)}${caret(t < c1)}`);
      setHTML(cmd2, t < c1 ? "" : `${typed(C2, t, c1, RATE)}${caret(t < enter)}`);
      reveal(out1, ramp(t, enter + 0.2, enter + 0.4), { dy: 8 });
      reveal(out2, ramp(t, enter + 0.55, enter + 0.85), { dy: 8 });
    };
  }

  /* ====================================================================== *
   *  OUTRO — the name, the promise, where to try it
   * ====================================================================== */
  function outro(cam, api) {
    const halo = bloom(cam, 960, 330, 1500, "color-mix(in srgb, var(--blue) 28%, transparent)");
    const halo2 = bloom(cam, 1060, 400, 1000, "color-mix(in srgb, var(--green) 18%, transparent)");
    const wrap = at(cam, 960, 330, "");
    const lk = lockup(wrap, 140);
    const tag = at(cam, 960, 520, "headline");
    const tw = words(tag, "Your files, encrypted locally.");
    tag.style.fontSize = "64px";
    const tr = at(cam, 960, 690, "try", `${bigIcon("globe", 30, 2)}vault.alzina.dev`);
    const url = at(cam, 960, 860, "url");
    url.innerHTML = `github.com/polius/vault<b>·</b>open source<b>·</b>MIT`;

    const HIT = api.segStart("outro1") - 0.12;
    api.cue("hit", HIT, 1);
    const T0 = api.on("outro2", "files") - 0.1;
    api.cue("pop", api.on("outro2", "locally") + 0.4, 0.6);

    return function (t) {
      camera(cam, t, [[0, 1.0, 0, 0], [HIT, 1.04, 0, 0, 8]]);
      const pin = ramp(t, HIT - 0.3, HIT);
      lk.set(t < HIT ? inCubic(pin) : 1, 5, 0);
      const punch = t > HIT ? Math.exp(-(t - HIT) * 6) * 0.05 : 0;
      wrap.style.opacity = outQuint(ramp(t, HIT - 0.3, HIT - 0.1)).toFixed(3);
      wrap.style.transform = `scale(${(lerp(1.2, 1, outExpo(pin)) + punch).toFixed(4)})`;
      const fl = t > HIT ? Math.exp(-Math.max(0, t - HIT) * 1.8) : 0;
      halo.style.opacity = (pin * (0.45 + 0.55 * fl)).toFixed(3);
      halo2.style.opacity = (pin * (0.4 + 0.4 * fl)).toFixed(3);
      kin(tw, t, T0, 0.07, 0.6);
      reveal(tr, ramp(t, api.on("outro2", "locally") + 0.3, api.on("outro2", "locally") + 0.8), { dy: 24, scale: 0.95, ease: outBack });
      reveal(url, ramp(t, api.on("outro2", "locally") + 0.7, api.on("outro2", "locally") + 1.2), { dy: 14 });
    };
  }

  Object.assign(window.SCENES, { open, demo, local, inside, share, decrypt, selfhost, outro });
})();
