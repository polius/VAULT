// VAULT streaming-download Service Worker.
// Page registers a transfer via `{ type: 'register', id, name, size, mime, port }`,
// then navigates to /__download/{id}; this SW serves a Response fed by the port.
// Port messages: ArrayBuffer/Uint8Array -> chunk, { type: 'end' } -> close.

const transfers = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg || msg.type !== 'register') return;

  const { id, name, size, mime, port } = msg;
  if (!id || !port) return;

  let controller;
  const stream = new ReadableStream({
    start(c) { controller = c; },
    cancel() {
      transfers.delete(id);
    },
  });

  port.onmessage = (ev) => {
    const data = ev.data;
    if (data instanceof ArrayBuffer) {
      controller.enqueue(new Uint8Array(data));
      return;
    }
    if (ArrayBuffer.isView(data)) {
      controller.enqueue(data);
      return;
    }
    if (data && data.type === 'end') {
      try { controller.close(); } catch {}
      transfers.delete(id);
    }
  };

  transfers.set(id, { name, size, mime: mime || 'application/octet-stream', stream, createdAt: Date.now() });
  port.postMessage({ type: 'ready' });
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const match = url.pathname.match(/^\/__download\/([A-Za-z0-9._-]+)$/);
  if (!match) return;

  const entry = transfers.get(match[1]);
  if (!entry) {
    event.respondWith(new Response('Transfer not found or expired.', { status: 404 }));
    return;
  }

  const headers = new Headers({
    'Content-Type': entry.mime,
    'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(entry.name)}`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  if (Number.isFinite(entry.size) && entry.size > 0) {
    headers.set('Content-Length', String(entry.size));
  }

  event.respondWith(new Response(entry.stream, { headers }));
});

// GC transfers that registered but were never fetched.
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of transfers) {
    if (now - entry.createdAt > 5 * 60_000) transfers.delete(id);
  }
}, 15_000);
