// Sink: where output bytes go, ported from FileSync. Three implementations:
//   'fs'   File System Access API (Chromium, secure context): streams straight to disk.
//   'sw'   Service Worker download: bytes stage into OPFS, then stream through a
//          MessageChannel into an intercepted /__download/{id} response at close().
//   'blob' In-memory Blob fallback (plain HTTP / old browsers). Holds the whole output.
//
// Common interface:
//   const sink = await openSink({ id, name, size, mime })
//   await sink.write(uint8Array)   await sink.close()   await sink.abort(reason?)
//
// Selection priority is fs > sw > blob. AbortError (user dismissed the save
// picker) is never swallowed into a fallback.

const SINK_MODES = ['auto', 'fs', 'sw', 'blob'];

// Debug/testing override: /?sink=fs|sw|blob forces a mode for one page load.
function readOverride() {
  try {
    const mode = new URLSearchParams(window.location.search).get('sink');
    return mode && SINK_MODES.includes(mode) && mode !== 'auto' ? mode : null;
  } catch {
    return null;
  }
}

function detectSinkAvailability() {
  const secure = typeof window !== 'undefined' && window.isSecureContext === true;
  const out = {
    fs:   { available: false, reason: '' },
    sw:   { available: false, reason: '' },
    blob: { available: true,  reason: 'Available (always — fallback path).' },
  };
  if (typeof window === 'undefined') return out;

  if (typeof window.showSaveFilePicker !== 'function') {
    out.fs.reason = 'Not supported by this browser (Chromium-only API).';
  } else if (!secure) {
    out.fs.reason = 'Requires HTTPS or localhost (secure context).';
  } else {
    out.fs.available = true;
  }

  if (!('serviceWorker' in navigator)) {
    out.sw.reason = 'Not supported by this browser.';
  } else if (!secure) {
    out.sw.reason = 'Requires HTTPS or localhost (secure context).';
  } else {
    // The worker may still be installing; registerServiceWorker() refines this.
    out.sw.available = true;
  }
  return out;
}

function detectAuto(avail) {
  if (avail.fs.available) return 'fs';
  if (avail.sw.available) return 'sw';
  return 'blob';
}

export const sinkState = {
  forced: readOverride(),
  availability: detectSinkAvailability(),
  auto: detectAuto(detectSinkAvailability()),
  serviceWorkerReady: false,
  serviceWorkerRegistration: null,
};

export function resolveSinkMode() {
  const mode = sinkState.forced || sinkState.auto;
  if (mode === 'fs' && typeof window.showSaveFilePicker !== 'function')
    throw new Error('File System Access API is not available in this browser.');
  if (mode === 'sw') {
    if (!window.isSecureContext) throw new Error('Service Worker sink requires HTTPS (or localhost).');
    if (!('serviceWorker' in navigator)) throw new Error('Service Workers are not available in this browser.');
    if (!sinkState.serviceWorkerReady) throw new Error('Service Worker has not finished registering yet.');
  }
  return mode;
}

// Cap the wait for a stuck worker so app boot never hangs on a failed install.
const SW_ACTIVATION_TIMEOUT_MS = 10_000;

export async function registerServiceWorker() {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
  if (!window.isSecureContext) return;
  try {
    // updateViaCache:'none' — SW update checks must never be served from the
    // HTTP cache, or a deployed worker fix can stay invisible for hours.
    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/', updateViaCache: 'none' });
    sinkState.serviceWorkerRegistration = reg;
    if (reg.active) {
      sinkState.serviceWorkerReady = true;
    } else {
      const activated = await new Promise((resolve) => {
        const worker = reg.installing || reg.waiting;
        if (!worker) { resolve(false); return; }
        let done = false;
        const finish = (ok) => { if (done) return; done = true; resolve(ok); };
        worker.addEventListener('statechange', () => {
          if (worker.state === 'activated') finish(true);
          else if (worker.state === 'redundant') finish(false);
        });
        setTimeout(() => finish(false), SW_ACTIVATION_TIMEOUT_MS);
      });
      sinkState.serviceWorkerReady = activated;
    }
    if (!sinkState.serviceWorkerReady) {
      sinkState.availability.sw.available = false;
    }
    sinkState.auto = detectAuto(sinkState.availability);
  } catch (err) {
    console.warn('Service Worker registration failed:', err);
    sinkState.availability.sw.available = false;
    sinkState.auto = detectAuto(sinkState.availability);
  }
}

async function openFsSink({ name, mime }) {
  const handle = await window.showSaveFilePicker({
    suggestedName: name,
    types: mime ? [{ description: 'File', accept: { [mime]: [extensionFromName(name)] } }] : undefined,
  });
  const writable = await handle.createWritable();
  return {
    mode: 'fs',
    async write(chunk) { await writable.write(chunk); },
    async close() { await writable.close(); },
    async abort() {
      try { await writable.abort(); } catch {}
    },
  };
}

function extensionFromName(name) {
  const idx = name.lastIndexOf('.');
  return idx >= 0 ? name.slice(idx) : '';
}

// Stages bytes into an OPFS file, then at close() streams it into the SW response.
// A failed transfer never leaves a partial download behind.
async function openSwSink({ id, name, size, mime }) {
  if (!navigator.storage || typeof navigator.storage.getDirectory !== 'function') {
    throw new Error('OPFS is not available in this browser.');
  }
  const root = await navigator.storage.getDirectory();
  const stagingName = `vault-part-${id}`;
  try { await root.removeEntry(stagingName); } catch {}
  const handle = await root.getFileHandle(stagingName, { create: true });
  const writable = await handle.createWritable();

  const deliver = async () => {
    await writable.close();
    const reg = sinkState.serviceWorkerRegistration;
    const sw = reg && reg.active;
    if (!sw) throw new Error('Service Worker not available.');

    const channel = new MessageChannel();
    const ready = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Service Worker did not respond.')), 5000);
      channel.port1.onmessage = (ev) => {
        if (ev.data?.type === 'ready') { clearTimeout(timeout); resolve(); }
      };
    });

    sw.postMessage({ type: 'register', id, name, size, mime, port: channel.port2 }, [channel.port2]);
    await ready;

    // Trigger the download by navigating a hidden iframe to the intercepted URL.
    const iframe = document.createElement('iframe');
    iframe.hidden = true;
    iframe.src = `/__download/${encodeURIComponent(id)}`;
    document.body.appendChild(iframe);

    const port = channel.port1;
    const stagedFile = await handle.getFile();
    const reader = stagedFile.stream().getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const buf = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      port.postMessage(buf, [buf]);
    }
    port.postMessage({ type: 'end' });
    port.close();
    setTimeout(() => iframe.remove(), 1000);
    setTimeout(() => { root.removeEntry(stagingName).catch(() => {}); }, 30_000);
  };

  return {
    mode: 'sw',
    async write(chunk) { await writable.write(chunk); },
    async close() { await deliver(); },
    async abort() {
      try { await writable.close(); } catch {}
      try { await root.removeEntry(stagingName); } catch {}
    },
  };
}

function openBlobSink({ name, mime }) {
  const chunks = [];
  return {
    mode: 'blob',
    async write(chunk) {
      // Copy into a stable reference; the caller may reuse the buffer.
      chunks.push(new Uint8Array(chunk));
    },
    async close() {
      const blob = new Blob(chunks, mime ? { type: mime } : undefined);
      chunks.length = 0;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    },
    async abort() {
      chunks.length = 0;
    },
  };
}

export async function openSink({ id, name, size, mime }) {
  const mode = resolveSinkMode();
  try {
    if (mode === 'fs') return await openFsSink({ name, mime });
    if (mode === 'sw') return await openSwSink({ id, name, size, mime });
    return openBlobSink({ name, mime });
  } catch (err) {
    // User cancel (dismissed save picker) propagates without fallback.
    if (err && err.name === 'AbortError') throw err;
    // Forced mode: surface the real error instead of masking it.
    if (sinkState.forced) throw err;
    // Otherwise fall down the chain fs -> sw -> blob.
    if (mode === 'fs') {
      try {
        if (sinkState.availability.sw.available && sinkState.serviceWorkerReady) {
          return await openSwSink({ id, name, size, mime });
        }
      } catch (swErr) {
        if (swErr && swErr.name === 'AbortError') throw swErr;
      }
      return openBlobSink({ name, mime });
    }
    if (mode === 'sw') return openBlobSink({ name, mime });
    throw err;
  }
}
