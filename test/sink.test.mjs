// Sinks, run against the REAL src/sw.js in a stubbed ServiceWorkerGlobalScope.
// Covers backpressure (audit M6), cancel/abort in both directions, the Firefox
// fetch-after-end ordering, headers, and the fs -> sw -> blob fallback chain.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { concat, randU8 } from './helpers.mjs';

// ---- service worker scope ----
const sw = {};
globalThis.self = {
  addEventListener: (type, fn) => {
    sw[type] = fn;
  },
  skipWaiting: () => {},
  clients: { claim: async () => {} },
};
// Timers left by sw.js (GC) and sink.js (iframe cleanup) must not hold the process open.
const realSetInterval = globalThis.setInterval;
const realSetTimeout = globalThis.setTimeout;
globalThis.setInterval = (fn, ms) => realSetInterval(fn, ms).unref();
globalThis.setTimeout = (fn, ms, ...args) => realSetTimeout(fn, ms, ...args).unref();
await import('../src/sw.js');

// ---- page scope ----
let autoFetch = true;
const pendingFetches = [];
const responses = [];
function dispatchFetch(url) {
  return new Promise((resolve) => {
    sw.fetch({ request: { url }, respondWith: resolve });
  });
}
const registration = {
  active: {
    postMessage(data) {
      sw.message({ data });
    },
  },
};
const created = [];
globalThis.isSecureContext = true;
globalThis.document = {
  body: {
    appendChild(el) {
      if (el.src && el.tagName === 'IFRAME') {
        const go = () => responses.push(dispatchFetch(el.src));
        if (autoFetch) go();
        else pendingFetches.push(go);
      }
      if (el.tagName === 'A') el.clicked = true;
    },
  },
  createElement(tag) {
    const el = { tagName: tag.toUpperCase(), remove() {}, click() {} };
    created.push(el);
    return el;
  },
};
Object.defineProperty(globalThis, 'navigator', {
  configurable: true,
  value: { serviceWorker: { register: async () => registration } },
});
const blobUrls = new Map();
URL.createObjectURL = (b) => {
  const u = `blob:${blobUrls.size}`;
  blobUrls.set(u, b);
  return u;
};
URL.revokeObjectURL = () => {};

const { openSink, sinkState, preferredMode } = await import('../src/js/sink.js');

const tick = (ms = 20) => new Promise((r) => realSetTimeout(r, ms));

async function readAll(response) {
  return new Uint8Array(await response.arrayBuffer());
}

describe('Service Worker sink', () => {
  it('is preferred when the File System Access API is missing', async () => {
    assert.equal(await preferredMode(), 'sw');
  });

  it('round-trips bytes and sets download headers', async () => {
    const parts = [randU8(1000), randU8(70_000), randU8(1)];
    const size = parts.reduce((n, p) => n + p.length, 0);
    const sink = await openSink({ name: 'résumé "final".pdf', size });
    assert.equal(sink.mode, 'sw');
    for (const p of parts) await sink.write(p);
    await sink.close();
    const res = await responses.at(-1);
    assert.equal(res.headers.get('Content-Length'), String(size));
    assert.equal(
      res.headers.get('Content-Disposition'),
      `attachment; filename="r_sum_ _final_.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%22final%22.pdf`,
    );
    assert.equal(res.headers.get('Cache-Control'), 'no-store');
    assert.ok(Buffer.from(await readAll(res)).equals(Buffer.from(concat(...parts))));
  });

  it('never detaches the caller’s bytes', async () => {
    const sink = await openSink({ name: 'x', size: 4 });
    const bytes = new Uint8Array([1, 2, 3, 4]);
    await sink.write(bytes);
    assert.equal(bytes.length, 4);
    assert.deepEqual([...bytes], [1, 2, 3, 4]);
    await sink.close();
    await readAll(await responses.at(-1));
  });

  it('applies backpressure: writes wait while the download is not being read (audit M6)', async () => {
    const sink = await openSink({ name: 'slow.bin', size: 50 * 1024 });
    const res = await responses.at(-1);
    let completed = 0;
    const writing = (async () => {
      for (let i = 0; i < 50; i++) {
        await sink.write(randU8(1024));
        completed++;
      }
      await sink.close();
    })();
    await tick(100);
    assert.ok(completed <= 5, `${completed} writes completed with nobody reading`);
    const body = await readAll(res);
    await writing;
    assert.equal(completed, 50);
    assert.equal(body.length, 50 * 1024);
  });

  it('cancelling the download rejects the next write with AbortError', async () => {
    const sink = await openSink({ name: 'c.bin', size: 10_000 });
    const res = await responses.at(-1);
    await res.body.cancel();
    await tick();
    await assert.rejects(
      (async () => {
        for (let i = 0; i < 20; i++) await sink.write(randU8(500));
      })(),
      { name: 'AbortError' },
    );
  });

  it('aborting from the page fails the download instead of truncating it', async () => {
    const sink = await openSink({ name: 'a.bin', size: 10_000 });
    const res = await responses.at(-1);
    await sink.write(randU8(500));
    await sink.abort();
    await assert.rejects(readAll(res));
  });

  it('serves a transfer whose fetch arrives after the end (Firefox ordering)', async () => {
    autoFetch = false;
    try {
      const sink = await openSink({ name: 'late.bin', size: 3000 });
      const data = randU8(3000);
      await sink.write(data.subarray(0, 1000));
      await sink.write(data.subarray(1000));
      await sink.close();
      pendingFetches.shift()();
      const body = await readAll(await responses.at(-1));
      assert.ok(Buffer.from(body).equals(Buffer.from(data)));
    } finally {
      autoFetch = true;
    }
  });

  it('serves each transfer once', async () => {
    const sink = await openSink({ name: 'once.bin', size: 1 });
    await sink.write(new Uint8Array([7]));
    await sink.close();
    const first = await responses.at(-1);
    const iframe = created.filter((e) => e.tagName === 'IFRAME').at(-1);
    const second = await dispatchFetch(iframe.src);
    assert.equal(first.status, 200);
    assert.equal(second.status, 404);
    await readAll(first);
  });

  it('ignores unrelated requests', () => {
    let responded = false;
    sw.fetch({ request: { url: 'https://vault.test/index.html' }, respondWith: () => (responded = true) });
    assert.equal(responded, false);
  });
});

describe('fallback chain', () => {
  it('fs is preferred when available, and the user dismissing it is not a fallback', async () => {
    globalThis.showSaveFilePicker = async () => {
      throw new DOMException('dismissed', 'AbortError');
    };
    try {
      assert.equal(await preferredMode(), 'fs');
      await assert.rejects(openSink({ name: 'x.vault', size: 1 }), { name: 'AbortError' });
    } finally {
      delete globalThis.showSaveFilePicker;
    }
  });

  it('a missing user gesture surfaces as SecurityError so the UI can ask for a click', async () => {
    globalThis.showSaveFilePicker = async () => {
      throw new DOMException('needs activation', 'SecurityError');
    };
    try {
      await assert.rejects(openSink({ name: 'x.vault', size: 1 }), { name: 'SecurityError' });
    } finally {
      delete globalThis.showSaveFilePicker;
    }
  });

  it('fs writes through to the chosen file', async () => {
    const written = [];
    globalThis.showSaveFilePicker = async (opts) => ({
      name: opts.suggestedName,
      createWritable: async () => ({
        write: async (b) => written.push(b),
        close: async () => {},
        abort: async () => {},
      }),
    });
    try {
      const sink = await openSink({ name: 'doc.pdf.vault', size: 3 });
      assert.equal(sink.mode, 'fs');
      await sink.write(new Uint8Array([1, 2, 3]));
      await sink.close();
      assert.deepEqual([...written[0]], [1, 2, 3]);
    } finally {
      delete globalThis.showSaveFilePicker;
    }
  });

  it('an fs failure other than cancel falls back to the next sink', async (t) => {
    t.mock.method(console, 'warn', () => {});
    globalThis.showSaveFilePicker = async () => {
      throw new TypeError('broken');
    };
    try {
      const sink = await openSink({ name: 'y', size: 1 });
      assert.equal(sink.mode, 'sw');
      await sink.write(new Uint8Array([1]));
      await sink.close();
      await readAll(await responses.at(-1));
    } finally {
      delete globalThis.showSaveFilePicker;
    }
  });

  it('blob collects everything and offers a download link', async () => {
    sinkState.forced = 'blob';
    try {
      const sink = await openSink({ name: 'b.bin', size: 6 });
      const chunk = new Uint8Array([1, 2, 3]);
      await sink.write(chunk);
      await sink.write(new Uint8Array([4, 5, 6]));
      await sink.close();
      const a = created.filter((e) => e.tagName === 'A').at(-1);
      assert.equal(a.download, 'b.bin');
      const blob = blobUrls.get(a.href);
      assert.deepEqual([...new Uint8Array(await blob.arrayBuffer())], [1, 2, 3, 4, 5, 6]);
    } finally {
      sinkState.forced = null;
    }
  });
});
