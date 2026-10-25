// VAULT streaming-download Service Worker.
//
// The page registers a transfer with { type: 'register', id, name, size, mime, port },
// then navigates a hidden iframe to __download/{id}. This worker answers that
// request with a stream fed through the port, with backpressure: it posts
// { type: 'pull' } whenever the stream wants another chunk, and the page sends
// exactly one ArrayBuffer per pull. { type: 'end' } closes the stream,
// { type: 'abort' } errors it (the browser then marks the download failed), and
// if the user cancels the download the page receives { type: 'cancel' }. When
// the request arrives the worker posts { type: 'start' }: some browsers skip
// the worker (Firefox after a forced reload, or with DevTools' cache disabled),
// and the page uses another sink if it never hears this.
//
// The entry stays in the map after 'end': Firefox can dispatch the iframe's
// fetch after a small file has already been fully streamed. `served` stops a
// second fetch of the same transfer; the timer below reclaims old entries.

const transfers = new Map();
const HIGH_WATER = 4; // chunks buffered in the worker, ~4 MiB
const TTL_MS = 5 * 60_000;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
  const msg = event.data;
  if (msg?.type !== 'register') return; // 'ping' only keeps the worker alive
  const { id, name, size, mime, port } = msg;
  if (typeof id !== 'string' || !port) return;

  let controller;
  let pending = null;
  const stream = new ReadableStream(
    {
      start(c) {
        controller = c;
      },
      pull() {
        port.postMessage({ type: 'pull' });
        return new Promise((resolve) => {
          pending = resolve;
        });
      },
      cancel() {
        port.postMessage({ type: 'cancel' });
        port.close();
        transfers.delete(id);
      },
    },
    new CountQueuingStrategy({ highWaterMark: HIGH_WATER }),
  );

  const settle = () => {
    pending?.();
    pending = null;
  };
  port.onmessage = ({ data }) => {
    try {
      if (data instanceof ArrayBuffer) controller.enqueue(new Uint8Array(data));
      else if (data?.type === 'end') {
        port.close();
        controller.close();
      } else if (data?.type === 'abort') {
        port.close();
        transfers.delete(id);
        controller.error(new Error('Transfer aborted'));
      }
    } catch {
      // The stream was already closed or cancelled.
    }
    settle();
  };

  transfers.set(id, { name, size, mime: mime || 'application/octet-stream', stream, port, createdAt: Date.now() });
  port.postMessage({ type: 'ready' });
});

function contentDisposition(name) {
  const ascii = String(name)
    .replace(/[^\x20-\x7e]/g, '_')
    .replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

self.addEventListener('fetch', (event) => {
  const match = new URL(event.request.url).pathname.match(/\/__download\/([A-Za-z0-9-]+)$/);
  if (!match) return;
  const entry = transfers.get(match[1]);
  if (!entry || entry.served) {
    event.respondWith(new Response('Transfer not found or already served.', { status: 404 }));
    return;
  }
  entry.served = true;
  entry.port.postMessage({ type: 'start' });
  const headers = new Headers({
    'Content-Type': entry.mime,
    'Content-Disposition': contentDisposition(entry.name),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  if (Number.isSafeInteger(entry.size) && entry.size > 0) headers.set('Content-Length', String(entry.size));
  event.respondWith(new Response(entry.stream, { headers }));
});

setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of transfers) if (now - entry.createdAt > TTL_MS) transfers.delete(id);
}, 30_000);
