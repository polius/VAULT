# VAULT video

The VAULT promo: a **~68-second, 1920×1080, 60 fps MP4** with a neural
voice-over, an original synthesized score, and sound design cued from the
picture. It is linked from the project README.

It is built from scratch: a small **web "video engine"** (HTML/CSS/JS)
rendered deterministically by headless Chromium, one frame at a time. The
pipeline is the one behind the [fsend](https://github.com/polius/fsend) video.

Design rules the film follows, so any future edit stays on-model:

- **One idea per shot.** Every screen says one thing, in big type, and the
  narration says the same thing at the same moment.
- **It looks like the app.** Paper, one green ink, fine lines, the app's two
  typefaces (Archivo and JetBrains Mono, read from `src/assets/fonts/`). Small
  corners, thin lines, no shadows, glows or gradients. Green means sealed.
- **Show the product, not a copy of it.** The encrypt and decrypt scenes are
  the app itself: its own stylesheet, showing screens that `states.py` records
  from a real run (a file is encrypted, then decrypted). The film only moves
  what moves, with the arithmetic of `src/js/seal.js`: the percentage, the
  line under it, and the seal's ink and rings.
- **The seal carries the story.** The film opens on one strand being drawn,
  woven into the mark, and a seal growing around it. Encrypting draws a seal
  and presses it; decrypting turns its rings back and breaks it; the end card
  presses one last seal.
- **Fine lines behind everything.** A medallion of guilloche rings frames the
  picture, like the ground of a banknote. It drifts, and turns a notch at
  every cut. Cuts are plain: one sheet lifts away, the next settles.
- **Only true claims.** Everything said or shown matches the app, `FORMAT.md`
  and `SECURITY.md`. Check there before changing a line.
- **Every sound has a cause on screen.** Scenes register their own cues, so
  sound and picture cannot drift apart.

This folder holds **only the source**. Frames, audio, the model weights and the
MP4 itself are all generated and git-ignored. Regenerate with `./make.sh`.

---

## Why not a screen recording

If every pixel is a **pure function of the timestamp**, then

- the same input always produces the same frame (reviews are meaningful),
- we can render at 2× and downsample, so type and thin strokes stay crisp at
  1080p (supersampling),
- timing is driven by the *measured* narration audio, so the visuals stay in
  sync no matter how fast the voice reads.

So the "renderer" is a web page, and the "render farm" is `page.screenshot()`
in a loop.

Scene arc, timed to the narration:

```
open (strand, mark, seal, name)  →  demo (encrypt, the seal is drawn)  →  local
     →  inside (Argon2id, AES-GCM)  →  share  →  decrypt (the seal breaks)
     →  selfhost  →  outro
```

---

## Setup

Needs **Python 3.10+**, **ffmpeg**, and a network connection for the first run.

```sh
cd scripts/explainer
./setup.sh --models        # venv + deps + chromium + Kokoro weights (~340 MB)
```

Everything is installed *inside this folder* (`.venv/`, `models/`).

## Build

```sh
./make.sh                                   # the whole pipeline -> vault-video.mp4
./make.sh --output ~/Desktop/vault.mp4
```

Stages (`build.py` prints them as `[n/8]`):

1. **narration**: `narration.py` synthesizes every line with **Kokoro-82M**
   (local ONNX, voice `af_heart`) and lays out `timeline.json`: scene windows
   plus *word onsets*. Each clip is transcribed back with **faster-whisper**
   (`small.en`, fetched once into `models/whisper/`): its word timestamps place
   the onsets, so a visual lands on the exact word it is spoken, and the
   transcript is printed as `heard:`, so a mispronounced word shows up in the
   build log. The script spells the name "Vault" so the voice says the word
   instead of spelling it out.
2. **the app's screens**: `states.py` opens the real app (`src/`) in headless
   Chromium, encrypts a file and decrypts the result, and saves the page's
   markup at every step to `web/states.json`. The page's random numbers are
   seeded for this run, so every build gets the same passphrase, the same salt
   and therefore the same seal.
3. **cues**: the page is loaded once and the scenes' sound-effect cues are
   dumped to `cues.json`.
4. **capture**: `capture.py` drives headless Chromium, calling
   `window.__render(t)` and screenshotting every frame at **2×**, across
   parallel workers.
5. **audio**: `sfx.py` renders the cues, `music.py` composes the score, the
   voice ducks the score through a sidechain compressor, and the mix is
   two-pass loudness-normalized.
6. **encode**: lanczos-downscale to 1080p, BT.709 tags, x264 CRF 20. No film
   grain: the picture is flat paper, with no gradients to band.
7. **captions**: a `.srt` sidecar, one cue per sentence.
8. **mux**.

Useful flags:

```sh
./make.sh --skip-capture          # re-encode / re-mix from frames/ on disk (keeps web/states.json)
./make.sh --skip-narration        # reuse audio/ + timeline.json
./make.sh --workers 4 --crf 17    # fewer capture processes, a larger and finer encode
FPS=30 ./make.sh                  # a faster draft (also re-times the narration)
```

To look at stills while iterating on the visuals (fast, 1×, no encode):

```sh
.venv/bin/python capture.py --preview 9.5,27,38      # -> preview/*.png
```

To regenerate the README thumbnail:

```sh
./make.sh --poster 17.5                               # -> docs/assets/video-poster.png
```

---

## Files

| File | Role |
|---|---|
| `narration.py` | the script and pacing. **Start here** to change the wording. |
| `states.py` | runs the real app once and records its screens to `web/states.json` (`--seed`, `--shots`) |
| `web/engine.js` | the renderer: `render(t)`, scene layers and cameras, the cuts, the medallion behind everything, the cue registry; loads the mark, the seal's geometry and the recorded screens from the app |
| `web/scenes.js` | the eight scenes, the app window, the film-size seal, the pointer |
| `web/app.html` | the page inside the app window: the app's own stylesheet, with every animation switched off |
| `web/style.css` | palette (the app's light theme), type, cards, the terminal |
| `capture.py` | http server (it serves the whole repository, so the film can read `src/`) + Playwright frame loop (`--preview`, `--poster`, `--cues`) |
| `music.py` | the score: 104 BPM, Dm9–Bbmaj7–Fmaj7–C; kick, hats, claps, bass, supersaw pad, pluck arpeggio, risers, sidechain, convolution reverb, arranged from the timeline |
| `sfx.py` | the sound design: whoosh, key, enter, pop, swish, hit, thud, chime, deny, blip, tick, stream |
| `build.py` | orchestrates all seven stages |
| `setup.sh` / `make.sh` | one-time setup / one-shot build |

## Customizing

- **Wording and pacing**: edit `LINES` in `narration.py`. `GAP_SAME`,
  `GAP_SCENE` and `GAP_EXTRA` decide how fast the film feels. Adding a line?
  Give it a scene and, if a visual should land on a word, an anchor
  (`{"sealed": "sealed"}`); scenes read it with `api.on("<line-id>", "<anchor>")`.
- **Visuals**: `web/scenes.js` and `web/style.css`. A scene moves its camera
  with `camera(cam, t, keys)` or `pushIn(...)`, and makes a sound with
  `api.cue(type, t, gain)`.
- **The app changed?** Rebuild: `states.py` records the new screens. If an
  element the film points at or moves was renamed, update its selector in
  `web/scenes.js` (`#genBtn`, `#encGo`, `#workPct`, `#seal`, and so on). If the
  seal's motion changed in `src/js/seal.js`, mirror it in `demo()` and
  `decrypt()`.
- **A different seal?** `./.venv/bin/python states.py --seed 7 --shots /tmp/shots`
  tries another seed and saves a picture of each screen; set the default seed
  in `states.py` once you like one.

## Notes

- **Nothing moves by itself.** The app's own animations and transitions are
  switched off in `web/app.html`; the scenes set every moving value from the
  film's clock. A CSS animation would run on the wall clock and differ from
  frame to frame.
- The app window is an `<iframe>`, and an iframe in a hidden layer has no
  layout: points the pointer clicks are measured once, in `afterFonts()`,
  while every layer is still shown (`appWindow().measure`).
- Fine lines are what the encoder spends its bits on. CRF 20 gives about
  34 MB; CRF 17 about 52 MB, with no difference you can see in a still.
- Hidden scene layers use `display: none`, not `visibility: hidden`: a child
  set to `visibility: visible` by a reveal would otherwise show through.
- `at(parent, x, y, …)` already centres its child; don't add another
  `translate(-50%, -50%)` to it.
- Layout that depends on text size is measured in `afterFonts()`, which runs
  on the first rendered frame, before any transform is applied. Give every
  element its real text before then: an empty line measures as zero height.
- **Do not commit** `frames/`, `preview/`, `audio/`, `captions/`,
  `timeline.json`, `cues.json`, `web/states.json`, `*.wav`, `*.mp4`, `models/`
  or `.venv/`.
