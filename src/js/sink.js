// Sinks: where output bytes go.
//   'fs'   File System Access API (Chromium, secure context): writes straight to the chosen file.
//   'sw'   Service Worker download: bytes stream through a MessagePort into an
//          intercepted download response, with backpressure. Nothing is staged on disk.
//   'blob' In-memory Blob, then a download link. Holds the whole output.
//
//   const sink = await openSink({ name, size, mime })
//   await sink.write(bytes)   await sink.close()   await sink.abort()
//
// write() never modifies or detaches the caller's bytes, and callers never
// modify bytes after passing them to write().
//
// Selection: fs > sw > blob. AbortError (the user dismissed a save dialog or
// cancelled the download) is never turned into a fallback.

import { scriptURL } from './tt.js';

const MODES = ['fs', 'sw', 'blob'];
const SW_READY_TIMEOUT_MS = 4000;
const SW_HANDSHAKE_TIMEOUT_MS = 5000;
const SW_KEEPALIVE_MS = 10_000;

// Testing override: ?sink=fs|sw|blob forces a mode for one page load.
function readOverride() {
  try {
    const mode = new URLSearchParams(globalThis.location?.search).get('sink');
    return MODES.includes(mode) ? mode : null;
  } catch {
    return null;
  }
}

const secure = () => globalThis.isSecureContext === true;
const hasFs = () => typeof globalThis.showSaveFilePicker === 'function' && secure();
const hasSw = () => typeof navigator !== 'undefined' && 'serviceWorker' in navigator && secure();

export const sinkState = {
  forced: readOverride(),
  registration: null,
  ready: null, // Promise<ServiceWorkerRegistration|null>, set by registerServiceWorker()
};

let registering = null;

// Idempotent. Resolves to the active registration, or null if unavailable.
export function registerServiceWorker() {
  if (registering) return registering;
  registering = (async () => {
    if (!hasSw()) return null;
    try {
      const reg = await navigator.serviceWorker.register(scriptURL('../sw.js'), {
        scope: new URL('../', import.meta.url).pathname,
        updateViaCache: 'none',
      });
      const worker = reg.active ?? reg.installing ?? reg.waiting;
      if (!reg.active && worker) {
        await new Promise((resolve) => {
          const done = () => worker.state === 'activated' || worker.state === 'redundant';
          if (done()) return resolve();
          worker.addEventListener('statechange', () => done() && resolve());
        });
      }
      sinkState.registration = reg.active ? reg : null;
      return sinkState.registration;
    } catch (err) {
      console.warn('Service Worker registration failed:', err);
      return null;
    }
  })();
  sinkState.ready = registering;
  return registering;
}

async function swAvailable() {
  if (!hasSw()) return false;
  const reg = await Promise.race([
    registerServiceWorker(),
    new Promise((r) => setTimeout(() => r(null), SW_READY_TIMEOUT_MS)),
  ]);
  return Boolean(reg?.active);
}

// The mode that openSink() will try first. 'blob' means the whole output is
// held in memory, which the UI warns about for large outputs.
export async function preferredMode() {
  if (sinkState.forced) return sinkState.forced;
  if (hasFs()) return 'fs';
  if (await swAvailable()) return 'sw';
  return 'blob';
}

// VAULT 1.x staged Service Worker downloads in the origin-private file system
// and could leave plaintext behind. Remove any leftovers.
export async function sweepLegacyStaging() {
  try {
    const root = await navigator.storage?.getDirectory?.();
    if (!root) return 0;
    const stale = [];
    for await (const name of root.keys()) if (name.startsWith('vault-part-')) stale.push(name);
    await Promise.all(stale.map((n) => root.removeEntry(n).catch(() => {})));
    return stale.length;
  } catch {
    return 0;
  }
}

async function openFsSink({ name }) {
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot) : '';
  const handle = await globalThis.showSaveFilePicker({
    suggestedName: name,
    ...(/^\.[\w-]{1,16}$/.test(ext)
      ? { types: [{ description: 'File', accept: { 'application/octet-stream': [ext] } }] }
      : {}),
  });
  const writable = await handle.createWritable();
  return {
    mode: 'fs',
    name: handle.name,
    write: (bytes) => writable.write(bytes),
    close: () => writable.close(),
    async abort() {
      await writable.abort().catch(() => {});
    },
  };
}

async function openSwSink({ name, size, mime }) {
  if (!(await swAvailable())) throw new Error('Service Worker is not active');
  const reg = sinkState.registration;
  const id = crypto.randomUUID();
  const channel = new MessageChannel();
  const port = channel.port1;

  let credits = 0;
  let failure = null;
  let wake = null;
  let handshake;
  let timer;
  const ready = new Promise((resolve, reject) => {
    handshake = resolve;
    timer = setTimeout(() => reject(new Error('Service Worker did not respond')), SW_HANDSHAKE_TIMEOUT_MS);
  }).finally(() => clearTimeout(timer));
  port.onmessage = ({ data }) => {
    if (data?.type === 'ready') handshake();
    else if (data?.type === 'pull') credits++;
    else if (data?.type === 'cancel') {
      failure = new DOMException('The download was cancelled', 'AbortError');
      port.close();
    }
    wake?.();
  };

  reg.active.postMessage({ type: 'register', id, name, size, mime, port: channel.port2 }, [channel.port2]);
  await ready;

  const iframe = document.createElement('iframe');
  iframe.hidden = true;
  iframe.title = 'Download';
  iframe.src = new URL(`../__download/${encodeURIComponent(id)}`, import.meta.url).href;
  document.body.appendChild(iframe);

  // Message events keep the worker alive during long transfers.
  const keepalive = setInterval(() => reg.active?.postMessage({ type: 'ping' }), SW_KEEPALIVE_MS);
  const cleanup = () => {
    clearInterval(keepalive);
    setTimeout(() => iframe.remove(), 30_000);
  };

  return {
    mode: 'sw',
    name,
    async write(bytes) {
      while (!credits && !failure) await new Promise((r) => (wake = r));
      if (failure) throw failure;
      credits--;
      // Transfer a copy: callers may still need their bytes (format.js reuses the header).
      const buf = bytes.slice().buffer;
      port.postMessage(buf, [buf]);
    },
    async close() {
      port.postMessage({ type: 'end' });
      port.close();
      cleanup();
    },
    async abort() {
      failure ??= new DOMException('Cancelled', 'AbortError');
      wake?.();
      port.postMessage({ type: 'abort' });
      port.close();
      cleanup();
    },
  };
}

function openBlobSink({ name, mime }) {
  let parts = [];
  return {
    mode: 'blob',
    name,
    async write(bytes) {
      parts.push(bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength ? bytes : bytes.slice());
    },
    async close() {
      const url = URL.createObjectURL(new Blob(parts, { type: mime || 'application/octet-stream' }));
      parts = [];
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.hidden = true;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
    async abort() {
      parts = [];
    },
  };
}

const openers = { fs: openFsSink, sw: openSwSink, blob: openBlobSink };

export async function openSink(opts) {
  const first = await preferredMode();
  const chain = sinkState.forced ? [first] : MODES.slice(MODES.indexOf(first));
  let lastErr;
  for (const mode of chain) {
    try {
      return await openers[mode](opts);
    } catch (err) {
      if (err?.name === 'AbortError') throw err;
      // The save dialog needs a recent click; let the caller ask for one.
      if (mode === 'fs' && (err?.name === 'SecurityError' || err?.name === 'NotAllowedError')) throw err;
      console.warn(`Sink '${mode}' failed, trying the next one:`, err);
      lastErr = err;
    }
  }
  throw lastErr;
}
