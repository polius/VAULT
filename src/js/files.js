// Turning what the user picked or dropped into a list of entries, and naming
// outputs. Pure except for the DataTransfer and FileSystemEntry walking.

// Removes characters that are unsafe or misleading in a file name: path
// separators, control and reserved characters, and bidirectional overrides
// (which can disguise "fdp.exe" as "exe.pdf").
export function safeFileName(name, fallback = 'file') {
  const clean = String(name)
    .normalize('NFC')
    .replace(/[‪-‮⁦-⁩‎‏؜]/g, '')
    // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
    .replace(/[\\/:*?"<>|\u0000-\u001f\u007f]/g, '_')
    .replace(/^\s+|[\s.]+$/g, '')
    .slice(0, 240);
  return clean && clean !== '.' && clean !== '..' ? clean : fallback;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1000) return `${bytes} ${bytes === 1 ? 'byte' : 'bytes'}`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let i = -1;
  do {
    v /= 1000;
    i++;
  } while (v >= 1000 && i < units.length - 1);
  return `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, '')} ${units[i]}`;
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '';
  if (seconds < 1) return 'less than a second';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m} min ${Math.round(seconds % 60)} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

// Selection model: { files: [{ file, path }], dirs: [path] }. A folder keeps its
// relative paths; loose files sit at the archive root.
export function fromFileList(list) {
  const files = [...list].map((file) => ({ file, path: file.webkitRelativePath || file.name }));
  return { files, dirs: [] };
}

function readAllEntries(reader) {
  return new Promise((resolve, reject) => {
    const all = [];
    const next = () =>
      reader.readEntries((batch) => {
        if (!batch.length) return resolve(all);
        all.push(...batch);
        next();
      }, reject);
    next();
  });
}

async function walk(entry, prefix, out) {
  const path = prefix ? `${prefix}/${entry.name}` : entry.name;
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    out.files.push({ file, path });
  } else if (entry.isDirectory) {
    const children = await readAllEntries(entry.createReader());
    if (!children.length) out.dirs.push(path);
    for (const child of children) await walk(child, path, out);
  }
}

// Reads a drop, including dropped folders. Must be called synchronously inside
// the drop handler: DataTransfer items expire after the event returns. Plain
// files come straight from getAsFile(); only folders need the entries API.
export function fromDataTransfer(dt) {
  const items = [...(dt.items ?? [])]
    .filter((i) => i.kind === 'file')
    .map((i) => ({ entry: i.webkitGetAsEntry?.(), file: i.getAsFile?.() }));
  if (!items.some((i) => i.entry?.isDirectory)) {
    const files = items.map((i) => i.file).filter(Boolean);
    return Promise.resolve(fromFileList(files.length ? files : (dt.files ?? [])));
  }
  return (async () => {
    const out = { files: [], dirs: [] };
    for (const { entry, file } of items) {
      if (entry?.isDirectory) await walk(entry, '', out);
      else if (file) out.files.push({ file, path: file.name });
    }
    return out;
  })();
}

// Makes archive paths unique ("a.txt", "a (2).txt") so two dropped files with
// the same name from different places don't collide.
export function dedupePaths(selection) {
  const seen = new Set();
  const unique = (path) => {
    let candidate = path;
    let n = 2;
    while (seen.has(candidate.toLowerCase())) {
      const slash = path.lastIndexOf('/');
      const dot = path.lastIndexOf('.');
      candidate = dot > slash + 1 ? `${path.slice(0, dot)} (${n})${path.slice(dot)}` : `${path} (${n})`;
      n++;
    }
    seen.add(candidate.toLowerCase());
    return candidate;
  };
  return {
    files: selection.files.map((f) => ({ ...f, path: unique(f.path) })),
    dirs: selection.dirs.map(unique),
  };
}

// A single top-level folder names the archive after itself.
export function archiveName(selection, now = new Date()) {
  const tops = new Set([...selection.files.map((f) => f.path), ...selection.dirs].map((p) => p.split('/')[0]));
  const nested = selection.files.every((f) => f.path.includes('/'));
  if (tops.size === 1 && nested) return `${safeFileName([...tops][0], 'folder')}.zip`;
  const d = now.toISOString().slice(0, 10);
  return `files-${d}.zip`;
}

export function neutralName(now = new Date()) {
  const rand = [...crypto.getRandomValues(new Uint8Array(3))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `vault-${now.toISOString().slice(0, 10)}-${rand}.vault`;
}
