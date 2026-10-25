# VAULT video

The VAULT promo: a **~64-second, 1920×1080, 60 fps MP4** with a neural
voice-over, an original synthesized score, and sound design cued from the
picture. It is linked from the project README.

It is built from scratch: a small **web "video engine"** (HTML/CSS/JS)
rendered deterministically by headless Chromium, one frame at a time. The
pipeline is the one behind the [fsend](https://github.com/polius/fsend) video.

Design rules the film follows, so any future edit stays on-model:

- **One idea per shot.** Every screen says one thing, in big type, and the
  narration says the same thing at the same moment.
- **Show the product.** The encrypt and decrypt scenes are a replica of the
  real app in its dark theme (same markup, sizes and strings as
  `src/index.html`), driven by a pointer: drop, generate, encrypt, done.
- **Blue locks, green unlocks**, as in the logo and the app. The film opens on
  the two halves of the shield locking together and closes on them; the
  decrypt scene turns the film green.
- **A vault, not a network.** Behind everything turns a combination dial that
  clicks a notch at every cut, and each cut is a seam of light on the shield's
  own diagonal, blue on one side and green on the other.
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
open (shield locks, name)  →  demo (encrypt)  →  local  →  inside (Argon2id, AES-GCM)
     →  share  →  decrypt  →  selfhost  →  outro
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

Stages (`build.py` prints them as `[n/7]`):

1. **narration**: `narration.py` synthesizes every line with **Kokoro-82M**
   (local ONNX, voice `af_heart`) and lays out `timeline.json`: scene windows
   plus *word onsets*. Each clip is transcribed back with **faster-whisper**
   (`small.en`, fetched once into `models/whisper/`): its word timestamps place
   the onsets, so a visual lands on the exact word it is spoken, and the
   transcript is printed as `heard:`, so a mispronounced word shows up in the
   build log. The script spells the name "Vault" so the voice says the word
   instead of spelling it out.
2. **cues**: the page is loaded once and the scenes' sound-effect cues are
   dumped to `cues.json`.
3. **capture**: `capture.py` drives headless Chromium, calling
   `window.__render(t)` and screenshotting every frame at **2×**, across
   parallel workers.
4. **audio**: `sfx.py` renders the cues, `music.py` composes the score, the
   voice ducks the score through a sidechain compressor, and the mix is
   two-pass loudness-normalized.
5. **encode**: lanczos-downscale to 1080p, BT.709 tags, a whisper of grain,
   x264 CRF 17.
6. **captions**: a `.srt` sidecar, one cue per sentence.
7. **mux**.

Useful flags:

```sh
./make.sh --skip-capture          # re-encode / re-mix from frames/ on disk
./make.sh --skip-narration        # reuse audio/ + timeline.json
./make.sh --workers 4 --crf 16 --grain 0
FPS=30 ./make.sh                  # a faster draft (also re-times the narration)
```

To look at stills while iterating on the visuals (fast, 1×, no encode):

```sh
.venv/bin/python capture.py --preview 9.5,27,38      # -> preview/*.png
```

To regenerate the README thumbnail:

```sh
./make.sh --poster 13.9                               # -> docs/assets/video-poster.png
```

---

## Files

| File | Role |
|---|---|
| `narration.py` | the script and pacing. **Start here** to change the wording. |
| `web/engine.js` | the renderer: `render(t)`, scene layers and cameras, push-through cuts with the diagonal seam, the dial background, accent colour keys, the cue registry |
| `web/scenes.js` | the eight scenes, the app replica, the pointer |
| `web/style.css` | palette (the app's dark theme), type, the app replica, cards |
| `web/fonts/` | Inter + JetBrains Mono (both OFL), committed for offline builds |
| `capture.py` | http server + Playwright frame loop (`--preview`, `--poster`, `--cues`) |
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
  with `camera(cam, t, keys)`, recolours the film with `api.accent(t, hex)`,
  and makes a sound with `api.cue(type, t, gain)`.
- **The app changed?** Update the replica in `appWindow()` (markup and strings)
  and `style.css` (the `.app` rules) so the film keeps matching it.

## Notes

- **Rendering cost is fill-rate bound.** Soft light is drawn with radial
  gradients, never `filter: blur()` on large layers. Film grain is added once
  by ffmpeg.
- Hidden scene layers use `display: none`, not `visibility: hidden`: a child
  set to `visibility: visible` by a reveal would otherwise show through.
- `at(parent, x, y, …)` already centres its child; don't add another
  `translate(-50%, -50%)` to it.
- Layout that depends on text size is measured in `afterFonts()`, which runs
  on the first rendered frame, before any transform is applied. Give every
  element its real text before then: an empty line measures as zero height.
- `api.accent()` keys at or after the scene's start: the engine resets the
  accent to blue at every scene start.
- **Do not commit** `frames/`, `preview/`, `audio/`, `captions/`,
  `timeline.json`, `cues.json`, `*.wav`, `*.mp4`, `models/` or `.venv/`.
