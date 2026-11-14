#!/usr/bin/env python3
"""Record the real app's screens, so the film shows VAULT itself and not a copy.

The film is rendered one frame at a time, so the app cannot simply run in it:
deriving a key and encrypting take real time. Instead this script runs the real
app (src/) once in headless Chromium: it encrypts a file, then decrypts the
result, and saves the page's markup at every step into web/states.json. The
film puts those screens back inside the app's own stylesheet and only moves
what moves: the percentage, the line under it and the seal.

The page's random numbers are seeded, so every build gets the same passphrase,
the same salt and therefore the same seal.

  states.py                       # -> web/states.json
  states.py --seed 7 --shots dir  # try another seed, and save a picture of each screen
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import tempfile

from capture import ROOT, serve

HERE = os.path.dirname(os.path.abspath(__file__))

# The app's window in the film (CSS pixels). Wide enough for its two columns.
VIEW = {"width": 1100, "height": 700}
FILE_NAME = "Tax return.pdf"
FILE_SIZE = 2_400_000

# A small seeded generator in place of the browser's, in this run only.
SEEDED = """
(() => {
  let a = SEED >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0);
  };
  crypto.getRandomValues = (view) => {
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    for (let i = 0; i < bytes.length; i++) bytes[i] = next() & 255;
    return view;
  };
  // Save through a plain download link, as most browsers do: a headless
  // browser has no save dialog to answer.
  delete window.showSaveFilePicker;
  Object.defineProperty(navigator, 'serviceWorker', { value: undefined });
})();
"""

# Saves the page the first time each step and each phase of the work is seen.
WATCH = """
() => {
  window.__seen = {};
  const main = document.getElementById('main');
  const look = () => {
    const view = main.dataset.view;
    const kdf = 'kdf' in document.getElementById('bar').dataset;
    const phase = document.getElementById('workPhase').textContent;
    const key = view !== 'work' ? view : kdf ? 'kdf' : /^(En|De)crypting/.test(phase) ? 'run' : 'start';
    if (!(key in window.__seen)) window.__seen[key] = document.body.innerHTML;
  };
  new MutationObserver(look).observe(document.body,
    { subtree: true, childList: true, attributes: true, characterData: true });
}
"""


def body(page):
    return page.evaluate("document.body.innerHTML")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "web", "states.json"))
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--shots", default=None, help="also save a picture of each screen here")
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    states, shots = {}, args.shots
    if shots:
        os.makedirs(shots, exist_ok=True)

    def keep(page, name, html=None):
        states[name] = html if html is not None else body(page)
        if shots and html is None:
            page.screenshot(path=os.path.join(shots, f"{name}.png"))

    work = tempfile.mkdtemp(prefix="vault-film-")
    plain = os.path.join(work, FILE_NAME)
    with open(plain, "wb") as f:
        f.write(os.urandom(FILE_SIZE))

    with sync_playwright() as pw:
        httpd, port = serve(ROOT)
        try:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport=VIEW, device_scale_factor=2, color_scheme="light",
                                      accept_downloads=True,
                                      permissions=["clipboard-read", "clipboard-write"])
            ctx.add_init_script(SEEDED.replace("SEED", str(args.seed)))
            page = ctx.new_page()
            url = f"http://127.0.0.1:{port}/src/index.html"

            # ---- encrypt ----
            page.goto(url, wait_until="networkidle")
            page.wait_for_selector("html[data-ready]")
            keep(page, "empty")
            page.set_input_files("#pickFiles", plain)
            page.wait_for_selector("#encForm:not([hidden])")
            keep(page, "job")
            page.click("#genBtn")
            page.wait_for_selector("#generated:not([hidden])")
            page.evaluate("document.activeElement.blur()")
            phrase = page.input_value("#encPwd")
            keep(page, "generated")
            # Copying it is how the app knows the passphrase was kept somewhere.
            page.click("#copyBtn")
            page.wait_for_selector("#copyBtn span:text-is('Copied')")
            page.evaluate("document.activeElement.blur()")
            keep(page, "copied")
            page.evaluate(WATCH)
            with page.expect_download() as dl:
                page.click("#encGo")
            sealed = os.path.join(work, dl.value.suggested_filename)
            dl.value.save_as(sealed)
            page.wait_for_selector("#main[data-view=done]")
            page.wait_for_timeout(1500)          # the stamp has landed
            seen = page.evaluate("window.__seen")
            keep(page, "enc-kdf", seen["kdf"])
            keep(page, "enc-run", seen["run"])
            keep(page, "enc-done")
            seal_no = page.inner_text("#sealNo")

            # ---- decrypt ----
            page.goto(url, wait_until="networkidle")
            page.wait_for_selector("html[data-ready]")
            page.set_input_files("#pickFiles", sealed)
            page.wait_for_selector("#decForm:not([hidden])")
            page.wait_for_selector("#sealNo.num")
            keep(page, "dec-job")
            page.fill("#decPwd", phrase)
            page.evaluate("document.activeElement.blur()")
            page.evaluate(WATCH)
            with page.expect_download():
                page.click("#decGo")
            page.wait_for_selector("#main[data-view=done]")
            page.wait_for_timeout(1500)          # the seal has split
            seen = page.evaluate("window.__seen")
            keep(page, "dec-kdf", seen["kdf"])
            keep(page, "dec-run", seen["run"])
            keep(page, "dec-done")
            browser.close()
        finally:
            httpd.shutdown()

    # The salt is public: it sits in the file's header, and the seal is drawn from it.
    with open(sealed, "rb") as f:
        salt = re.search(rb'"salt":"([^"]+)"', f.read(600)).group(1).decode()
    salt = list(base64.b64decode(salt))

    data = {"view": VIEW, "salt": salt, "file": FILE_NAME, "sealed": os.path.basename(sealed), "phrase": phrase,
            "sealNo": seal_no, "states": states}
    with open(args.out, "w") as f:
        json.dump(data, f)
    print(f"states: {len(states)} screens -> {args.out}  ({os.path.getsize(args.out) / 1e3:.0f} kB)")
    print(f"  seed {args.seed} · seal no. {seal_no} · {phrase}")


if __name__ == "__main__":
    main()
