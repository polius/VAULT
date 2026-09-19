// Browser-API fakes (disk-backed) so the fs and sw sink paths run for real in Node:
// fs writes stream through node:fs to actual files; sw runs the REAL src/sw.js
// against an OPFS emulator and delivers through its fetch/message listeners.
import { MessageChannel } from 'node:worker_threads';
import { mkdtemp, mkdir, open, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { sinkState } from '../src/js/sink.js';

// --- Real src/sw.js under a stubbed ServiceWorkerGlobalScope ---
export const swListeners = {};
globalThis.self = {
  addEventListener: (type, fn) => { (swListeners[type] ||= []).push(fn); },
  skipWaiting: async () => {},
  clients: { claim: async () => {} },
};
// sw.js's GC interval must not hold the test process open.
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (fn, ms) => realSetInterval(fn, ms).unref();
await import('../src/sw.js');

export async function makeTempDir() {
  return mkdtemp(path.join(tmpdir(), 'vault-sink-'));
}

export function cleanupTempDir(dir) {
  return rm(dir, { recursive: true, force: true });
}

// Fake showSaveFilePicker whose createWritable streams to a real file on disk.
export function installDiskFsSink(dir) {
  const state = { path: null, suggestedName: null };
  globalThis.window.showSaveFilePicker = async (opts) => {
    state.suggestedName = opts.suggestedName;
    state.path = path.join(dir, String(opts.suggestedName).replace(/[^\w.-]/g, '_'));
    const fh = await open(state.path, 'w');
    return {
      createWritable: async () => ({
        async write(chunk) { await fh.write(chunk); },
        async close() { await fh.close(); },
        async abort() { await fh.close().catch(() => {}); },
      }),
    };
  };
  return state;
}

// OPFS emulator backed by a real directory; only what openSwSink uses.
function makeOpfsEmulator(dir) {
  return {
    async removeEntry(name) { await rm(path.join(dir, name), { force: true }); },
    async getFileHandle(name, { create = false } = {}) {
      const p = path.join(dir, name);
      if (create) await mkdir(dir, { recursive: true });
      return {
        createWritable: async () => {
          const fh = await open(p, 'w');
          return {
            async write(chunk) { await fh.write(chunk); },
            async close() { await fh.close(); },
            async abort() { await fh.close().catch(() => {}); await rm(p, { force: true }); },
          };
        },
        getFile: async () => new File([await readFile(p)], name),
      };
    },
  };
}

// Bridges sink.js to the real sw.js: postMessage('register') invokes the SW's
// message listener, then simulates the iframe fetch of /__download/{id}.
//
// `fetchAfterEnd` reproduces Firefox's ordering for small files: the page drains
// the staged OPFS file and sends 'end' before the navigation's fetch event is
// dispatched, so the fetch must still find a live entry (regression guard for
// deleting the transfer on 'end', which 404'd the download in Firefox).
export function makeSwBridge({ fetchAfterEnd = false } = {}) {
  const downloads = [];
  // A real browser keeps transferred ports alive internally; emulate that or
  // the GC may collect port2 between register and delivery (flaky, rare).
  const transferredPorts = new Set();
  const registration = {
    active: {
      postMessage(msg) {
        if (msg.port) transferredPorts.add(msg.port);
        swListeners.message[0]({ data: msg });
        let resolve;
        const entry = { promise: new Promise((r) => { resolve = r; }) };
        downloads.push(entry);
        const dispatchFetch = () => {
          swListeners.fetch[0]({
            request: { url: `https://vault.local/__download/${msg.id}` },
            respondWith: resolve,
          });
        };
        if (fetchAfterEnd) {
          const port = msg.port;
          const swHandler = port.onmessage;
          port.onmessage = (ev) => {
            swHandler(ev);
            if (ev.data && ev.data.type === 'end') dispatchFetch();
          };
        } else {
          queueMicrotask(dispatchFetch);
        }
      },
    },
  };
  return { registration, downloads };
}

// Activates the sw sink end to end (secure context + OPFS + SW registration).
export function installSwSink(opfsDir, bridge) {
  globalThis.window.isSecureContext = true;
  Object.defineProperty(globalThis, 'navigator', {
    value: {
      clipboard: { writeText: async () => {} },
      serviceWorker: {},
      storage: { getDirectory: async () => makeOpfsEmulator(opfsDir) },
    },
    configurable: true,
  });
  sinkState.serviceWorkerReady = true;
  sinkState.serviceWorkerRegistration = bridge.registration;
}

export function resetSinks() {
  delete globalThis.window.showSaveFilePicker;
  sinkState.forced = null;
}
