// Streaming ZIP writer for multi-file and folder input. Entries are STOREd (no
// compression: the output is encrypted next, and most large files are already
// compressed). Sizes are known up front, so the whole archive is planned first:
// its exact length is known before a byte is written. CRCs follow each entry in
// a data descriptor. ZIP64 records are used only when a size, offset or entry
// count needs them (or when forced, for tests).

const SIG_LOCAL = 0x04034b50;
const SIG_DESCRIPTOR = 0x08074b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_LOCATOR64 = 0x07064b50;
const MAX32 = 0xffffffff;
const MAX16 = 0xffff;
const FLAG_DESCRIPTOR = 0x0008;
const FLAG_UTF8 = 0x0800;

const te = new TextEncoder();

const CRC_TABLE = (() => {
  const t = new Uint32Array(256 * 4);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  // Slicing-by-4 tables.
  for (let n = 0; n < 256; n++) {
    for (let s = 1; s < 4; s++) t[s * 256 + n] = (t[(s - 1) * 256 + n] >>> 8) ^ t[t[(s - 1) * 256 + n] & 0xff];
  }
  return t;
})();

export function crc32(bytes, crc = 0) {
  let c = ~crc >>> 0;
  let i = 0;
  const n = bytes.length;
  for (; i + 4 <= n; i += 4) {
    c ^= bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
    c =
      CRC_TABLE[768 + (c & 0xff)] ^
      CRC_TABLE[512 + ((c >>> 8) & 0xff)] ^
      CRC_TABLE[256 + ((c >>> 16) & 0xff)] ^
      CRC_TABLE[c >>> 24];
  }
  for (; i < n; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

// Normalizes a relative path for an archive entry: forward slashes, no leading
// slash, no empty, "." or ".." segments (so extraction can't escape its folder).
export function safeEntryPath(path) {
  const parts = String(path)
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s && s !== '.' && s !== '..')
    // biome-ignore lint/suspicious/noControlCharactersInRegex: replacing control characters is the point
    .map((s) => s.replace(/[\u0000-\u001f]/g, '_'));
  return parts.join('/');
}

function dosDateTime(ms) {
  const d = new Date(Number.isFinite(ms) ? ms : Date.now());
  const year = Math.min(Math.max(d.getFullYear(), 1980), 2107);
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

class Writer {
  constructor(size) {
    this.buf = new Uint8Array(size);
    this.view = new DataView(this.buf.buffer);
    this.pos = 0;
  }
  u16(v) {
    this.view.setUint16(this.pos, v, true);
    this.pos += 2;
  }
  u32(v) {
    this.view.setUint32(this.pos, v, true);
    this.pos += 4;
  }
  u64(v) {
    this.view.setBigUint64(this.pos, BigInt(v), true);
    this.pos += 8;
  }
  bytes(b) {
    this.buf.set(b, this.pos);
    this.pos += b.length;
  }
}

// entries: [{ path, size, lastModified, dir?, file? }]. Returns the plan with
// every offset resolved and the exact archive size.
export function planZip(entries, { forceZip64 = false } = {}) {
  const seen = new Set();
  let offset = 0;
  const planned = entries.map((e) => {
    let path = safeEntryPath(e.path);
    if (!path) throw new Error(`Invalid entry path: ${e.path}`);
    if (e.dir) path += '/';
    if (seen.has(path)) throw new Error(`Duplicate entry path: ${path}`);
    seen.add(path);
    const name = te.encode(path);
    if (name.length > MAX16) throw new Error(`Entry path too long: ${path}`);
    const size = e.dir ? 0 : e.size;
    const zip64 = forceZip64 || size >= MAX32;
    const localLen = 30 + name.length + (zip64 ? 20 : 0);
    const descLen = e.dir ? 0 : zip64 ? 24 : 16;
    const entry = { ...e, path, name, size, zip64, offset, localLen, descLen, ...dosDateTime(e.lastModified) };
    offset += localLen + size + descLen;
    return entry;
  });
  const cdOffset = offset;
  let cdSize = 0;
  for (const e of planned) {
    e.offset64 = forceZip64 || e.offset >= MAX32;
    const fields = (e.zip64 ? 2 : 0) + (e.offset64 ? 1 : 0);
    e.cdExtra = fields ? 4 + fields * 8 : 0;
    cdSize += 46 + e.name.length + e.cdExtra;
  }
  const zip64End = forceZip64 || planned.length > MAX16 || cdOffset >= MAX32 || cdSize >= MAX32;
  const size = cdOffset + cdSize + (zip64End ? 56 + 20 : 0) + 22;
  return { entries: planned, cdOffset, cdSize, zip64End, size };
}

function localHeader(e) {
  const w = new Writer(e.localLen);
  w.u32(SIG_LOCAL);
  w.u16(e.zip64 ? 45 : 20);
  w.u16(e.dir ? FLAG_UTF8 : FLAG_UTF8 | FLAG_DESCRIPTOR);
  w.u16(0); // stored
  w.u16(e.time);
  w.u16(e.date);
  w.u32(0); // crc: in the data descriptor
  w.u32(e.zip64 ? MAX32 : 0);
  w.u32(e.zip64 ? MAX32 : 0);
  w.u16(e.name.length);
  w.u16(e.zip64 ? 20 : 0);
  w.bytes(e.name);
  if (e.zip64) {
    w.u16(0x0001);
    w.u16(16);
    w.u64(0);
    w.u64(0);
  }
  return w.buf;
}

function descriptor(e) {
  const w = new Writer(e.descLen);
  w.u32(SIG_DESCRIPTOR);
  w.u32(e.crc);
  if (e.zip64) {
    w.u64(e.size);
    w.u64(e.size);
  } else {
    w.u32(e.size);
    w.u32(e.size);
  }
  return w.buf;
}

function centralDirectory(plan) {
  const w = new Writer(plan.cdSize);
  for (const e of plan.entries) {
    w.u32(SIG_CENTRAL);
    w.u16((3 << 8) | 45); // made by: UNIX, spec 4.5
    w.u16(e.zip64 || e.offset64 ? 45 : 20);
    w.u16(e.dir ? FLAG_UTF8 : FLAG_UTF8 | FLAG_DESCRIPTOR);
    w.u16(0);
    w.u16(e.time);
    w.u16(e.date);
    w.u32(e.crc ?? 0);
    w.u32(e.zip64 ? MAX32 : e.size);
    w.u32(e.zip64 ? MAX32 : e.size);
    w.u16(e.name.length);
    w.u16(e.cdExtra);
    w.u16(0); // comment
    w.u16(0); // disk
    w.u16(0); // internal attributes
    w.u32(e.dir ? ((0o40755 << 16) | 0x10) >>> 0 : (0o100644 << 16) >>> 0);
    w.u32(e.offset64 ? MAX32 : e.offset);
    w.bytes(e.name);
    if (e.cdExtra) {
      w.u16(0x0001);
      w.u16(e.cdExtra - 4);
      if (e.zip64) {
        w.u64(e.size);
        w.u64(e.size);
      }
      if (e.offset64) w.u64(e.offset);
    }
  }
  return w.buf;
}

function endRecords(plan) {
  const n = plan.entries.length;
  const w = new Writer((plan.zip64End ? 76 : 0) + 22);
  if (plan.zip64End) {
    const eocd64At = plan.cdOffset + plan.cdSize;
    w.u32(SIG_EOCD64);
    w.u64(44);
    w.u16((3 << 8) | 45);
    w.u16(45);
    w.u32(0);
    w.u32(0);
    w.u64(n);
    w.u64(n);
    w.u64(plan.cdSize);
    w.u64(plan.cdOffset);
    w.u32(SIG_LOCATOR64);
    w.u32(0);
    w.u64(eocd64At);
    w.u32(1);
  }
  w.u32(SIG_EOCD);
  w.u16(0);
  w.u16(0);
  w.u16(plan.zip64End ? MAX16 : n);
  w.u16(plan.zip64End ? MAX16 : n);
  w.u32(plan.zip64End ? MAX32 : plan.cdSize);
  w.u32(plan.zip64End ? MAX32 : plan.cdOffset);
  w.u16(0);
  return w.buf;
}

// Yields the archive bytes. `read(entry)` returns an async iterable of the
// entry's bytes; it must produce exactly entry.size bytes.
export async function* zipStream(plan, read) {
  for (const e of plan.entries) {
    yield localHeader(e);
    if (e.dir) continue;
    let crc = 0;
    let got = 0;
    for await (const piece of read(e)) {
      got += piece.length;
      if (got > e.size) throw new Error(`${e.path} grew while it was being read`);
      crc = crc32(piece, crc);
      yield piece;
    }
    if (got !== e.size) throw new Error(`${e.path} shrank while it was being read`);
    e.crc = crc;
    yield descriptor(e);
  }
  yield centralDirectory(plan);
  yield endRecords(plan);
}
