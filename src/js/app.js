// VAULT UI. One object, the file bar, carries the selection, the progress and
// the result; under it the page moves through four views: pick -> job -> work
// -> done. All crypto lives in format.js; this file only wires it to the page.

import {
  archiveName,
  dedupePaths,
  formatBytes,
  formatDuration,
  fromDataTransfer,
  fromFileList,
  neutralName,
  safeFileName,
} from './files.js';
import { E, encrypt, encryptedSize, fileSource, inspect, unlock } from './format.js';
import { generatePassphrase, passphraseBits } from './passphrase.js';
import { openSink, preferredMode, registerServiceWorker, sweepLegacyStaging } from './sink.js';
import { attackerSentence, estimate, loadDictionaries, meterPhrase, rate } from './strength.js';
import { planZip, zipStream } from './zip.js';

// Above this, the in-memory fallback sink asks before continuing.
const MEMORY_WARN_BYTES = 512 * 1024 * 1024;
const MAX_LISTED_FILES = 500;
// Several selected files are checked for being VAULT files only up to this many.
const MAX_VAULT_BATCH = 50;
const BASE_TITLE = document.title;

const $ = (id) => document.getElementById(id);
const ui = Object.fromEntries(
  [
    'main',
    'app',
    'insecure',
    'how',
    'pick',
    'pickError',
    'pickFiles',
    'pickFolder',
    'pickFilesBtn',
    'pickFolderBtn',
    'dropOverlay',
    'dropText',
    'stateTitle',
    'bar',
    'selIcon',
    'selName',
    'selMeta',
    'fillIcon',
    'fillName',
    'fillMeta',
    'progress',
    'progressFill',
    'clearBtn',
    'job',
    'fileList',
    'fileListSummary',
    'fileListItems',
    'vaultInfo',
    'encForm',
    'encPwd',
    'encCaps',
    'genLink',
    'genBtn',
    'encShow',
    'meter',
    'strengthText',
    'generated',
    'genPhrase',
    'copyBtn',
    'confirmField',
    'encPwd2',
    'confirmHelp',
    'hideName',
    'hideNameExample',
    'encGo',
    'saveAs',
    'decForm',
    'decPwd',
    'decCaps',
    'decShow',
    'decGo',
    'message',
    'messageText',
    'messageAction',
    'switchMode',
    'work',
    'workPhase',
    'workPct',
    'workStats',
    'cancelBtn',
    'done',
    'doneMeta',
    'doneDetail',
    'downloadAgain',
    'againBtn',
    'live',
  ].map((id) => [id, $(id)]),
);

const state = {
  view: 'pick',
  selection: null, // { files: [{ file, path }], dirs: [path] }
  info: null, // inspect() result for the .vault file being decrypted
  infoError: null, // why the selection can't be decrypted
  auto: 'encrypt', // what the selection implies
  mode: 'encrypt', // what the person is doing: 'encrypt' | 'decrypt'
  queue: [], // [{ file, info }]: .vault files still to decrypt, in order
  decrypted: [], // what this run has decrypted so far
  generated: null, // the generated passphrase, while unchanged
  saved: false, // the generated passphrase was copied out of the page
  proceed: null, // 'unsaved' | 'weak' | 'memory': the next click on the same action continues anyway
  session: null, // unlocked decrypt session waiting for a save location
  controller: null,
  sink: null,
  results: [], // in-memory results that can be downloaded again
  resume: null,
  dicts: null,
};

// ---------- small helpers ----------

function announce(text) {
  ui.live.textContent = '';
  requestAnimationFrame(() => {
    ui.live.textContent = text;
  });
}

function show(view) {
  state.view = view;
  ui.main.dataset.view = view;
  for (const v of ['pick', 'job', 'work', 'done']) ui[v].hidden = v !== view;
  ui.progress.hidden = view !== 'work';
  if (view !== 'work') {
    delete ui.bar.dataset.kdf;
    document.title = BASE_TITLE;
  }
}

function setIcon(svg, id) {
  svg.querySelector('use').setAttribute('href', `#${id}`);
}

function setMessage(kind, text, action) {
  if (!kind) {
    ui.message.hidden = true;
    state.resume = null;
    return;
  }
  // Sit right above the active form's main button.
  const form = state.mode === 'decrypt' ? ui.decForm : ui.encForm;
  form.insertBefore(ui.message, form.querySelector('.actions'));
  ui.message.className = `notice notice-${kind}`;
  ui.message.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  setIcon(ui.message.querySelector('svg'), kind === 'info' ? 'i-info' : 'i-alert');
  ui.messageText.textContent = text;
  ui.messageAction.hidden = !action;
  state.resume = action?.run ?? null;
  if (action) ui.messageAction.textContent = action.label;
  ui.message.hidden = false;
}

function setButtonLabel(btn, text) {
  btn.querySelector('span').textContent = text;
}

function encryptLabel() {
  const n = state.selection?.files.length ?? 0;
  return n > 1 ? `Encrypt ${n} files` : 'Encrypt';
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const sizeOf = (files) => files.reduce((n, f) => n + f.file.size, 0);

// ---------- the bar ----------

// A long name loses its middle, never its extension: the tail never shrinks.
// Names with right-to-left text stay whole and shorten at the end instead.
function nameNodes(name) {
  const head = document.createElement('span');
  head.className = 'head';
  if (name.length <= 16 || /[֐-ࣿיִ-﷿ﹰ-ﻼ]/.test(name)) {
    head.textContent = name;
    return [head];
  }
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.length - dot : 0;
  const keep = Math.min(Math.floor(name.length / 2), Math.max(10, ext + 4));
  const tail = document.createElement('span');
  tail.className = 'tail';
  head.textContent = name.slice(0, -keep);
  tail.textContent = name.slice(-keep);
  return [head, tail];
}

function setFill(pct) {
  ui.bar.style.setProperty('--fill', String(pct));
}

// state: empty | open | sealing | sealed | opening | opened
function setBar({ state: s, name = '', meta = '', glyph = 'i-file', fill = 0 }) {
  ui.bar.dataset.state = s;
  for (const [n, m, g] of [
    [ui.selName, ui.selMeta, ui.selIcon],
    [ui.fillName, ui.fillMeta, ui.fillIcon],
  ]) {
    n.replaceChildren(...nameNodes(name));
    m.textContent = meta;
    setIcon(g, glyph);
  }
  ui.selName.title = name;
  setFill(fill);
}

// The word above the bar names the state, so it never rests on colour alone.
function setTitle(text) {
  ui.stateTitle.textContent = text;
  ui.stateTitle.hidden = !text;
}

// ---------- errors ----------

function explain(err, context) {
  if (err?.name === 'AbortError') return { kind: 'info', text: 'Cancelled. Nothing was saved.' };
  const legacy = state.info && state.info.version < 3;
  switch (err?.code) {
    case E.NOT_VAULT:
      return { kind: 'error', text: "This isn't a VAULT file." };
    case E.UNSUPPORTED:
      return { kind: 'error', text: 'This file was made by a newer version of VAULT. Update VAULT to open it.' };
    case E.BAD_HEADER:
      return { kind: 'error', text: 'This looks like a VAULT file, but its header is damaged, so it can’t be opened.' };
    case E.WRONG_PASSWORD:
      return {
        kind: 'error',
        text: legacy ? 'Wrong password, or the file is damaged.' : 'Wrong password. Check it and try again.',
      };
    case E.CORRUPTED:
      return {
        kind: 'error',
        text:
          context === 'stream'
            ? 'The file is damaged or was changed after it was encrypted. The partial output was discarded.'
            : 'The file is damaged or was changed after it was encrypted, so it can’t be opened.',
      };
    case E.LEGACY_EMPTY:
      return {
        kind: 'error',
        text: 'This is an empty file from VAULT 1.x. That version didn’t protect empty files, so the password can’t be checked.',
      };
    case E.SOURCE_CHANGED:
      return {
        kind: 'error',
        text: 'A file changed while VAULT was reading it. Try again once it has finished changing.',
      };
    case E.TOO_LARGE:
      return { kind: 'error', text: err.message };
  }
  if (err?.name === 'QuotaExceededError')
    return { kind: 'error', text: 'There isn’t enough free disk space to save the result.' };
  if (err?.name === 'NotReadableError' || err?.name === 'NotFoundError')
    return {
      kind: 'error',
      text: 'A file couldn’t be read. It may have been moved, deleted or locked by another app.',
    };
  if (/grew|shrank/.test(err?.message ?? ''))
    return { kind: 'error', text: `A file changed while VAULT was reading it: ${err.message}.` };
  return { kind: 'error', text: `Something went wrong: ${err?.message || err}` };
}

// ---------- progress ----------

// drain: decrypting empties a filled bar; encrypting fills an empty one.
function makeProgress(verb, name, { drain = false } = {}) {
  let started = 0;
  let painted = 0;
  let slowNote = 0;
  const phase = (p) => {
    const kdf = p === 'kdf';
    clearTimeout(slowNote);
    if (kdf) {
      ui.bar.dataset.kdf = '';
      setFill(drain ? 100 : 4);
      ui.workPhase.textContent =
        verb === 'Encrypting' ? 'Deriving a key from your password…' : 'Checking the password…';
      ui.workPct.textContent = '';
      ui.workStats.textContent = '';
      ui.progress.removeAttribute('aria-valuenow');
      ui.progress.removeAttribute('aria-valuetext');
      document.title = `${verb} ${name} · VAULT`;
      // Only worth reading if the phase lasts long enough to read it.
      slowNote = setTimeout(() => {
        if (state.view === 'work' && 'kdf' in ui.bar.dataset)
          ui.workStats.textContent = 'This takes a moment on purpose: it makes guessing passwords slow.';
      }, 500);
    } else {
      delete ui.bar.dataset.kdf;
      started = performance.now();
      ui.workPhase.textContent = `${verb}…`;
      ui.workStats.textContent = '';
      update(0, 1, true);
    }
  };
  const update = (done, total, force = false) => {
    const now = performance.now();
    if (!force && now - painted < 100 && done < total) return;
    painted = now;
    const pct = total ? Math.min(100, (done / total) * 100) : 100;
    const rounded = Math.floor(pct);
    setFill(drain ? 100 - pct : pct);
    ui.progress.setAttribute('aria-valuenow', String(rounded));
    ui.progress.setAttribute('aria-valuetext', `${rounded}%`);
    ui.workPct.textContent = `${rounded}%`;
    // The tab says how far it got, for people who switch away (audit F8).
    document.title = `${rounded}% · ${verb} ${name}`;
    const secs = (now - started) / 1000;
    if (secs > 0.5 && done > 0 && done < total) {
      const rate = done / secs;
      ui.workStats.textContent = `${formatBytes(done)} of ${formatBytes(total)} · ${formatBytes(rate)}/s · ${formatDuration((total - done) / rate)} left`;
    } else if (done >= total) {
      ui.workStats.textContent = `${formatBytes(total)} · finishing…`;
    }
  };
  return { phase, update };
}

// ---------- selection ----------

function outName() {
  const { files, dirs } = state.selection;
  if (ui.hideName.checked) return ui.hideNameExample.textContent;
  const single = files.length === 1 && !dirs.length;
  return `${safeFileName(single ? files[0].file.name : archiveName(state.selection))}.vault`;
}

function renderBar() {
  const { files, dirs } = state.selection;
  if (state.mode === 'decrypt') {
    const many = state.queue.length > 1;
    setBar({
      state: 'sealed',
      name: many ? `${state.queue.length} VAULT files` : files[0].file.name,
      meta: formatBytes(sizeOf(files)),
      glyph: 'i-lock',
      fill: 100,
    });
    return;
  }
  const single = files.length === 1 && !dirs.length;
  const parts = [formatBytes(sizeOf(files))];
  if (!single) parts.unshift(plural(files.length, 'file'));
  setBar({
    state: 'open',
    name: single ? files[0].file.name : archiveName(state.selection).replace(/\.zip$/, ''),
    meta: parts.join(' · '),
    glyph: single ? 'i-file' : 'i-files',
  });
}

function renderFileList() {
  const { files, dirs } = state.selection;
  const single = files.length === 1 && !dirs.length;
  ui.fileList.hidden = single;
  ui.fileList.open = false;
  ui.fileListSummary.textContent = 'Show files';
  ui.fileListItems.replaceChildren(
    ...files.slice(0, MAX_LISTED_FILES).map((f) => {
      const li = document.createElement('li');
      const name = document.createElement('span');
      const size = document.createElement('span');
      name.className = 'file-path';
      size.className = 'file-size';
      name.textContent = f.path;
      size.textContent = formatBytes(f.file.size);
      li.append(name, size);
      return li;
    }),
  );
  if (files.length > MAX_LISTED_FILES) {
    const li = document.createElement('li');
    li.textContent = `and ${files.length - MAX_LISTED_FILES} more`;
    ui.fileListItems.append(li);
  }
  for (const dir of dirs.slice(0, MAX_LISTED_FILES)) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    const kind = document.createElement('span');
    name.className = 'file-path';
    kind.className = 'file-size';
    name.textContent = `${dir}/`;
    kind.textContent = 'empty folder';
    li.append(name, kind);
    ui.fileListItems.append(li);
  }
}

function renderVaultInfo() {
  const el = ui.vaultInfo;
  el.hidden = state.mode !== 'decrypt';
  if (el.hidden) return;
  if (state.infoError) {
    el.textContent = explain(state.infoError).text;
    el.className = 'vault-info help error';
    return;
  }
  el.className = 'vault-info';
  if (state.queue.length > 1) {
    const legacy = state.queue.some((q) => q.info.version < 3);
    el.textContent =
      `${state.queue.length} VAULT files. Enter their password to open them one after another; each one is saved on its own.` +
      (legacy ? ' Some were made with VAULT 1.x; encrypt them again afterwards to upgrade them.' : '');
    return;
  }
  const { version, legacy } = state.info;
  if (version === 3) {
    el.textContent = 'A VAULT file. Enter its password to open it. Its original name and size stay hidden until then.';
  } else {
    el.textContent =
      `Encrypted with VAULT 1.x (format ${version}) · original name ${legacy.name} · ${formatBytes(legacy.size)}. ` +
      (version === 1
        ? 'This early format is less resistant to tampering. After opening it, encrypt it again to upgrade it.'
        : 'After opening it, you can encrypt it again to upgrade to the current, stronger format.');
  }
}

// The app knows which mode applies; a quiet link covers the rare other case (audit F4).
function renderSwitch() {
  const many = state.selection.files.length > 1;
  ui.switchMode.hidden = state.auto !== 'decrypt';
  ui.switchMode.textContent =
    state.mode === 'decrypt'
      ? many
        ? 'Encrypt these files into one instead'
        : 'Encrypt this file again instead'
      : many
        ? 'Decrypt them instead'
        : 'Decrypt it instead';
}

function renderSaveAs() {
  ui.saveAs.textContent = `saves ${outName()}`;
}

function renderJob() {
  const many = state.queue.length > 1;
  setTitle(state.mode === 'decrypt' ? (many ? `Decrypt ${state.queue.length} files` : 'Decrypt') : 'Encrypt');
  renderBar();
  ui.decGo.disabled = Boolean(state.infoError);
  setButtonLabel(ui.encGo, encryptLabel());
  setButtonLabel(ui.decGo, many ? `Decrypt ${state.queue.length} files` : 'Decrypt');
  renderVaultInfo();
  renderSwitch();
  renderSaveAs();
}

function setMode(mode) {
  state.mode = mode;
  state.proceed = null;
  state.session = null;
  ui.app.dataset.mode = mode;
  ui.encForm.hidden = mode !== 'encrypt';
  ui.decForm.hidden = mode !== 'decrypt';
  ui.hideNameExample.textContent = neutralName();
  renderJob();
  setMessage(null);
}

function releaseResults() {
  for (const r of state.results) r.release();
  state.results = [];
}

// Looks inside each file: a .vault file is recognised by its bytes, whatever its name.
async function classify() {
  const { files, dirs } = state.selection;
  state.info = null;
  state.infoError = null;
  state.queue = [];
  if (dirs.length || !files.length) return 'encrypt';
  if (files.length === 1) {
    try {
      state.info = await inspect(files[0].file);
      state.queue = [{ file: files[0].file, info: state.info }];
      return 'decrypt';
    } catch (err) {
      if (err?.name !== 'VaultError') throw err;
      if (err.code === E.NOT_VAULT) return 'encrypt';
      state.infoError = err;
      state.queue = [{ file: files[0].file, info: null }];
      return 'decrypt';
    }
  }
  if (files.length > MAX_VAULT_BATCH) return 'encrypt';
  const infos = await Promise.all(files.map((f) => inspect(f.file).catch(() => null)));
  if (!infos.every(Boolean)) return 'encrypt';
  state.queue = files.map((f, i) => ({ file: f.file, info: infos[i] }));
  state.info = infos[0];
  return 'decrypt';
}

async function select(selection) {
  if (state.view === 'work') {
    announce('Wait for the current file to finish, or cancel it first.');
    return;
  }
  ui.pickError.hidden = true;
  if (!selection.files.length && !selection.dirs.length) {
    if (state.view !== 'pick') reset();
    ui.pickError.textContent = 'That folder is empty. There is nothing to encrypt.';
    ui.pickError.hidden = false;
    return;
  }
  releaseResults();
  state.selection = dedupePaths(selection);
  state.decrypted = [];
  try {
    state.auto = await classify();
  } catch {
    const name = state.selection.files[0].file.name;
    if (state.view !== 'pick') reset();
    ui.pickError.textContent = `Couldn’t read “${name}”. To add a folder, drop it or use Choose a folder.`;
    ui.pickError.hidden = false;
    state.selection = null;
    return;
  }
  renderFileList();
  setMode(state.auto);
  show('job');
  const name = ui.selName.textContent;
  announce(
    state.mode === 'decrypt'
      ? `${name} selected. Enter the password to decrypt ${state.queue.length > 1 ? 'them' : 'it'}.`
      : `${name} selected. Choose a password to encrypt it.`,
  );
  (state.mode === 'decrypt' ? ui.decPwd : ui.encPwd).focus();
}

function clearSecrets() {
  ui.encPwd.value = '';
  ui.encPwd2.value = '';
  ui.decPwd.value = '';
  state.generated = null;
  state.saved = false;
  state.session = null;
  setShown(ui.encShow, [ui.encPwd, ui.encPwd2], false);
  setShown(ui.decShow, [ui.decPwd], false);
  updateEncryptFields();
}

function reset() {
  clearSecrets();
  releaseResults();
  state.selection = null;
  state.info = null;
  state.infoError = null;
  state.queue = [];
  state.decrypted = [];
  state.proceed = null;
  ui.hideName.checked = false;
  ui.pickError.hidden = true;
  setMessage(null);
  setBar({ state: 'empty' });
  setTitle('');
  show('pick');
  ui.pickFilesBtn.focus();
}

// ---------- password fields ----------

function setShown(btn, inputs, shown) {
  for (const i of inputs) i.type = shown ? 'text' : 'password';
  btn.setAttribute('aria-pressed', String(shown));
  btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
  btn.title = btn.getAttribute('aria-label');
  setIcon(btn.querySelector('svg'), shown ? 'i-eye-off' : 'i-eye');
}

function updateStrength() {
  const pw = ui.encPwd.value;
  // A passphrase VAULT generated is rated by the generator's entropy.
  const e = pw && pw === state.generated ? rate(passphraseBits()) : estimate(pw, state.dicts);
  if (!e) {
    ui.meter.dataset.empty = '';
    ui.strengthText.textContent = '';
    return;
  }
  delete ui.meter.dataset.empty;
  ui.meter.dataset.score = String(e.score);
  const label = document.createElement('b');
  label.textContent = e.label;
  ui.strengthText.replaceChildren(label, ` · ${meterPhrase(e.crackSeconds)}`);
}

function updateConfirm(final = false) {
  const pw = ui.encPwd.value;
  const confirm = ui.encPwd2.value;
  const mismatch = confirm && confirm !== pw && (final || confirm.length >= pw.length);
  ui.encPwd2.setAttribute('aria-invalid', String(Boolean(mismatch) || (final && !confirm)));
  if (mismatch) {
    ui.confirmHelp.textContent = 'The passwords don’t match.';
    ui.confirmHelp.className = 'help reserve error';
  } else if (confirm && confirm === pw) {
    ui.confirmHelp.textContent = 'The passwords match.';
    ui.confirmHelp.className = 'help reserve ok';
  } else if (final && !confirm) {
    ui.confirmHelp.textContent = 'Type the password again to confirm it.';
    ui.confirmHelp.className = 'help reserve error';
  } else {
    ui.confirmHelp.textContent = '';
    ui.confirmHelp.className = 'help reserve';
  }
}

function updateEncryptFields() {
  if (state.generated && ui.encPwd.value !== state.generated) {
    state.generated = null;
    state.saved = false;
  }
  ui.generated.hidden = !state.generated;
  ui.genPhrase.textContent = state.generated ?? '';
  ui.confirmField.hidden = Boolean(state.generated);
  ui.encPwd.removeAttribute('aria-invalid');
  if (state.proceed === 'weak' || state.proceed === 'unsaved') {
    state.proceed = null;
    setMessage(null);
    setButtonLabel(ui.encGo, encryptLabel());
  }
  updateStrength();
  updateConfirm();
}

async function ensureDictionaries() {
  if (state.dicts) return state.dicts;
  try {
    state.dicts = await loadDictionaries();
    updateStrength();
  } catch (err) {
    console.warn('Password dictionaries failed to load:', err);
  }
  return state.dicts;
}

const isMac = /Mac|iPhone|iPad/.test(navigator.userAgentData?.platform ?? navigator.platform ?? '');

async function copyPassphrase() {
  const label = ui.copyBtn.querySelector('span');
  try {
    await navigator.clipboard.writeText(ui.encPwd.value);
    state.saved = true;
    label.textContent = 'Copied';
    announce('Passphrase copied to the clipboard.');
  } catch {
    const range = document.createRange();
    range.selectNodeContents(ui.genPhrase);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    label.textContent = isMac ? 'Press ⌘C' : 'Press Ctrl+C';
  }
  setTimeout(() => {
    label.textContent = 'Copy';
  }, 2500);
}

// ---------- running a job ----------

function begin(mode) {
  ui.app.dataset.mode = mode;
  setMessage(null);
  ui.workPct.textContent = '';
  ui.workStats.textContent = '';
  ui.workPhase.textContent = 'Starting…';
  ui.cancelBtn.disabled = false;
  state.controller = new AbortController();
  setTitle(mode === 'encrypt' ? 'Encrypting' : 'Decrypting');
  show('work');
  ui.cancelBtn.focus();
}

// Back to the form, with the bar showing the selection again.
function backToJob() {
  show('job');
  renderJob();
}

// After a multi-file decrypt stops part-way, only the files still to do stay selected.
function keepRemaining() {
  const left = new Set(state.queue.map((q) => q.file));
  state.selection = {
    files: state.selection.files.filter((f) => left.has(f.file)),
    dirs: [],
  };
  state.info = state.queue[0]?.info ?? null;
  state.decrypted = [];
  releaseResults();
  renderFileList();
}

function fail(err, context) {
  if (err?.name !== 'VaultError' && err?.name !== 'AbortError') console.error(err);
  state.sink = null;
  let { kind, text } = explain(err, context);
  const done = state.decrypted.length;
  if (state.mode === 'decrypt' && done) {
    const total = done + state.queue.length;
    const next = state.queue[0]?.file.name;
    text =
      err?.code === E.WRONG_PASSWORD
        ? `${done} of ${total} files decrypted and saved. “${next}” needs a different password.`
        : `${done} of ${total} files decrypted and saved. ${text}`;
    keepRemaining();
  }
  backToJob();
  setMessage(kind, text);
  announce(text);
  if (err?.code === E.WRONG_PASSWORD) {
    // Keep it: the person is still here, and needs it to find the typo (audit F10).
    ui.decPwd.focus();
    ui.decPwd.select();
  } else if (state.mode === 'encrypt') ui.encGo.focus();
  else ui.decGo.focus();
}

// A download is handed to the browser; VAULT can't know what it did with it (audit F9).
const savedWhere = (mode) => (mode === 'fs' ? 'Saved where you chose' : 'Sent to your browser’s downloads');

// notes: short sentences, one line each on a laptop.
function finish({ title, bar, size, where, notes = [] }) {
  state.sink = null;
  state.controller = null;
  clearSecrets();
  setTitle(title);
  setBar(bar);
  ui.doneMeta.textContent = where;
  ui.downloadAgain.hidden = !state.results.length;
  ui.downloadAgain.textContent = state.results.length > 1 ? 'Download them again' : 'Download again';
  ui.doneDetail.replaceChildren(
    ...notes.map((text) => {
      const p = document.createElement('p');
      p.textContent = text;
      return p;
    }),
  );
  show('done');
  ui.stateTitle.focus();
  announce(`${title}: ${bar.name}, ${formatBytes(size)}. ${where}. ${notes.join(' ')}`);
}

async function needsMemoryConfirm(bytes, run) {
  if (state.proceed === 'memory' || bytes <= MEMORY_WARN_BYTES || (await preferredMode()) !== 'blob') return false;
  state.proceed = 'memory';
  setMessage(
    'warn',
    `This browser can’t save directly to disk here, so VAULT has to hold the whole result (${formatBytes(bytes)}) in memory. That may fail or slow the device down.`,
    { label: 'Continue anyway', run },
  );
  return true;
}

function buildEncryptJob() {
  const { files, dirs } = state.selection;
  if (files.length === 1 && !dirs.length) {
    const { file } = files[0];
    return {
      meta: { name: file.name, type: 'file', mtime: file.lastModified },
      size: file.size,
      source: () => fileSource(file),
    };
  }
  const plan = planZip([
    ...files.map((f) => ({ path: f.path, size: f.file.size, lastModified: f.file.lastModified, file: f.file })),
    ...dirs.map((path) => ({ path, dir: true })),
  ]);
  return {
    meta: { name: archiveName(state.selection), type: 'zip', count: files.length },
    size: plan.size,
    source: () => zipStream(plan, (e) => fileSource(e.file)),
  };
}

async function startEncrypt() {
  const password = ui.encPwd.value;
  if (!password) {
    ui.encPwd.setAttribute('aria-invalid', 'true');
    setMessage('error', 'Enter a password, or generate a passphrase.');
    ui.encPwd.focus();
    return;
  }
  if (!state.generated && ui.encPwd2.value !== password) {
    updateConfirm(true);
    ui.encPwd2.focus();
    announce(ui.confirmHelp.textContent);
    return;
  }
  // A generated passphrase skips the confirmation field, so ask once whether it
  // was stored: VAULT forgets it the moment the run ends (audit F1).
  if (state.generated && !state.saved && state.proceed !== 'unsaved') {
    state.proceed = 'unsaved';
    setMessage(
      'warn',
      'Have you saved this passphrase? VAULT forgets it as soon as the file is encrypted, and nobody can recover it.',
      { label: 'Copy passphrase', run: copyPassphrase },
    );
    setButtonLabel(ui.encGo, 'I saved it. Encrypt');
    announce(ui.messageText.textContent);
    return;
  }
  const strength = estimate(password, await ensureDictionaries());
  if (strength.weak && state.proceed !== 'weak') {
    state.proceed = 'weak';
    setMessage(
      'warn',
      `This password is ${strength.label.toLowerCase()}. ${attackerSentence(strength.crackSeconds)} Use a longer one or generate a passphrase, or encrypt anyway.`,
    );
    setButtonLabel(ui.encGo, 'Encrypt anyway');
    announce(ui.messageText.textContent);
    return;
  }

  let job;
  try {
    job = buildEncryptJob();
  } catch (err) {
    setMessage('error', explain(err).text);
    return;
  }
  const name = outName();
  const outSize = encryptedSize({ meta: job.meta, size: job.size });
  if (await needsMemoryConfirm(outSize, startEncrypt)) return;
  state.proceed = null;
  setButtonLabel(ui.encGo, encryptLabel());

  begin('encrypt');
  const barName = ui.selName.title;
  setBar({ state: 'sealing', name: barName, meta: ui.selMeta.textContent, glyph: 'i-lock', fill: 0 });
  const { signal } = state.controller;
  const progress = makeProgress('Encrypting', barName);
  try {
    state.sink = await openSink({ name, size: outSize });
    const out = encrypt({
      password,
      meta: job.meta,
      size: job.size,
      source: job.source(),
      signal,
      onPhase: progress.phase,
      onProgress: progress.update,
    });
    for await (const bytes of out) {
      signal.throwIfAborted();
      await state.sink.write(bytes);
    }
    signal.throwIfAborted();
    await state.sink.close();
    const { mode } = state.sink;
    if (mode === 'blob') state.results.push(state.sink);
    const many = job.meta.type === 'zip';
    finish({
      title: 'Encrypted',
      bar: { state: 'sealed', name: state.sink.name, meta: formatBytes(outSize), glyph: 'i-lock', fill: 100 },
      size: outSize,
      where: savedWhere(mode),
      notes: [
        many
          ? 'Your original files are unchanged. Delete them yourself if you only want to keep the encrypted copy.'
          : 'Your original file is unchanged. Delete it yourself if you only want to keep the encrypted copy.',
        'Without the password, nobody can open it, not even you.',
      ],
    });
  } catch (err) {
    await state.sink?.abort();
    if (err?.name === 'SecurityError' || err?.name === 'NotAllowedError') {
      state.sink = null;
      backToJob();
      setMessage('info', 'Your browser needs one more click before it can show the save dialog.', {
        label: 'Choose where to save',
        run: startEncrypt,
      });
      return;
    }
    fail(err, 'stream');
  }
}

async function startDecrypt() {
  const password = ui.decPwd.value;
  if (!password) {
    setMessage('error', 'Enter the password this file was encrypted with.');
    ui.decPwd.focus();
    return;
  }
  state.decrypted = [];
  begin('decrypt');
  await unlockNext(password);
}

// Decrypts the .vault files in the queue one after another with one password.
async function unlockNext(password) {
  const { file, info } = state.queue[0];
  const total = state.decrypted.length + state.queue.length;
  state.info = info;
  setTitle(total > 1 ? `Decrypting ${state.decrypted.length + 1} of ${total}` : 'Decrypting');
  setBar({ state: 'sealed', name: file.name, meta: formatBytes(file.size), glyph: 'i-lock', fill: 100 });
  const progress = makeProgress('Decrypting', file.name, { drain: true });
  try {
    state.session = await unlock(file, password, { info, onPhase: progress.phase });
  } catch (err) {
    fail(err, 'unlock');
    return;
  }
  await saveDecrypted(progress);
}

async function saveDecrypted(progress) {
  const { session } = state;
  if (!session) return;
  const name = safeFileName(session.meta.name);
  if (await needsMemoryConfirm(session.meta.size, () => saveDecrypted())) {
    backToJob();
    return;
  }
  state.proceed = null;
  if (state.view !== 'work') begin('decrypt');
  const total = state.decrypted.length + state.queue.length;
  if (total > 1) setTitle(`Decrypting ${state.decrypted.length + 1} of ${total}`);
  // The original name is the first thing VAULT decrypts: show it, then drain the fill.
  setBar({ state: 'opening', name, meta: formatBytes(session.meta.size), glyph: 'i-unlock', fill: 100 });
  const run = progress ?? makeProgress('Decrypting', name, { drain: true });
  const { signal } = state.controller;
  try {
    signal.throwIfAborted();
    state.sink = await openSink({ name, size: session.meta.size });
    run.phase('decrypt');
    for await (const plain of session.chunks({ signal, onProgress: run.update })) {
      signal.throwIfAborted();
      await state.sink.write(plain);
    }
    signal.throwIfAborted();
    await state.sink.close();
    const sink = state.sink;
    state.sink = null;
    if (sink.mode === 'blob') state.results.push(sink);
    state.decrypted.push({
      name: sink.name,
      size: session.meta.size,
      zip: session.meta.type === 'zip' ? (session.meta.count ?? 'several') : 0,
      legacy: session.warnings.length > 0,
      mode: sink.mode,
    });
    state.session = null;
    state.queue.shift();
    if (state.queue.length) await unlockNext(ui.decPwd.value);
    else finishDecrypt();
  } catch (err) {
    await state.sink?.abort();
    if (err?.name === 'SecurityError' || err?.name === 'NotAllowedError') {
      state.sink = null;
      backToJob();
      setMessage('info', `Password correct. Your browser needs one more click to show the save dialog for “${name}”.`, {
        label: `Save ${name}`,
        run: () => saveDecrypted(),
      });
      return;
    }
    if (err?.name === 'AbortError') state.session = null;
    fail(err, 'stream');
  }
}

function finishDecrypt() {
  const items = state.decrypted;
  const size = items.reduce((n, i) => n + i.size, 0);
  const notes = [];
  for (const i of items)
    if (i.zip)
      notes.push(
        `${items.length > 1 ? `${i.name} is a` : 'A'} ZIP archive with ${i.zip} files. Open it to extract them.`,
      );
  if (items.some((i) => i.legacy)) notes.push('Made with an older VAULT format. Encrypt it again to upgrade it.');
  if (items.length > 1) notes.unshift(`Saved ${items.map((i) => i.name).join(', ')}.`);
  const one = items.length === 1;
  finish({
    title: 'Decrypted',
    bar: {
      state: 'opened',
      name: one ? items[0].name : plural(items.length, 'file'),
      meta: formatBytes(size),
      glyph: 'i-unlock',
      fill: 0,
    },
    size,
    where: savedWhere(items.at(-1).mode),
    notes,
  });
}

// ---------- wiring ----------

function wire() {
  // Drag and drop anywhere on the page. Files dropped outside the bar must
  // never fall through to the browser, which would open them and leave VAULT.
  let depth = 0;
  const hasFiles = (e) => [...(e.dataTransfer?.types ?? [])].includes('Files');
  window.addEventListener('dragenter', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    if (state.view !== 'work') {
      ui.dropText.textContent = state.view === 'pick' ? 'Drop to choose' : 'Drop to replace';
      ui.dropOverlay.hidden = false;
      document.body.classList.add('dragging');
    }
  });
  window.addEventListener('dragover', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = state.view === 'work' ? 'none' : 'copy';
  });
  const endDrag = () => {
    depth = 0;
    ui.dropOverlay.hidden = true;
    document.body.classList.remove('dragging');
  };
  window.addEventListener('dragleave', (e) => {
    if (!hasFiles(e)) return;
    depth = Math.max(0, depth - 1);
    if (!depth) endDrag();
  });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    endDrag();
    if (state.view === 'work') {
      announce('Wait for the current file to finish, or cancel it first.');
      return;
    }
    fromDataTransfer(e.dataTransfer).then(select, (err) => {
      if (state.view !== 'pick') reset();
      ui.pickError.textContent = `Couldn’t read what was dropped: ${err.message}`;
      ui.pickError.hidden = false;
    });
  });

  ui.pickFilesBtn.addEventListener('click', () => ui.pickFiles.click());
  ui.pickFolderBtn.addEventListener('click', () => ui.pickFolder.click());
  for (const input of [ui.pickFiles, ui.pickFolder]) {
    input.addEventListener('change', () => {
      const selection = fromFileList(input.files);
      input.value = '';
      // An empty folder picked with the button arrives as no files at all.
      if (selection.files.length || input === ui.pickFolder) select(selection);
    });
  }

  ui.fileList.addEventListener('toggle', () => {
    ui.fileListSummary.textContent = ui.fileList.open ? 'Hide files' : 'Show files';
  });

  ui.clearBtn.addEventListener('click', reset);
  ui.againBtn.addEventListener('click', reset);
  ui.downloadAgain.addEventListener('click', () => {
    for (const r of state.results) r.again();
  });
  ui.switchMode.addEventListener('click', () => {
    setMode(state.mode === 'decrypt' ? 'encrypt' : 'decrypt');
    (state.mode === 'decrypt' ? ui.decPwd : ui.encPwd).focus();
  });
  ui.hideName.addEventListener('change', renderSaveAs);

  // Caps Lock, while a password field has focus (audit F10).
  for (const [input, hint] of [
    [ui.encPwd, ui.encCaps],
    [ui.encPwd2, ui.encCaps],
    [ui.decPwd, ui.decCaps],
  ]) {
    const check = (e) => {
      hint.hidden = !e.getModifierState?.('CapsLock');
    };
    input.addEventListener('keydown', check);
    input.addEventListener('keyup', check);
    input.addEventListener('blur', () => {
      hint.hidden = true;
    });
  }

  ui.encPwd.addEventListener('focus', ensureDictionaries, { once: true });
  ui.encPwd.addEventListener('input', updateEncryptFields);
  // Tab goes from Password to Confirm; Shift+Tab from Confirm still reaches the
  // generate and show buttons in between.
  ui.encPwd.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab' || e.shiftKey || e.altKey || e.ctrlKey || e.metaKey || ui.confirmField.hidden) return;
    e.preventDefault();
    ui.encPwd2.focus();
  });
  ui.encPwd2.addEventListener('input', () => updateConfirm());
  ui.encPwd2.addEventListener('blur', () => ui.encPwd2.value && updateConfirm(true));
  ui.encShow.addEventListener('click', () =>
    setShown(ui.encShow, [ui.encPwd, ui.encPwd2], ui.encShow.getAttribute('aria-pressed') !== 'true'),
  );
  ui.decShow.addEventListener('click', () =>
    setShown(ui.decShow, [ui.decPwd], ui.decShow.getAttribute('aria-pressed') !== 'true'),
  );
  ui.decPwd.addEventListener('input', () => {
    if (!ui.message.hidden && state.resume === null) setMessage(null);
  });

  const generate = async () => {
    const phrase = await generatePassphrase();
    ui.encPwd.value = phrase;
    ui.encPwd2.value = '';
    state.generated = phrase;
    state.saved = false;
    // Shown once, whole, in the block below; the field keeps it masked.
    setShown(ui.encShow, [ui.encPwd, ui.encPwd2], false);
    updateEncryptFields();
    ui.encPwd.focus();
    announce('Passphrase generated and shown below the password field. Store it before you continue.');
  };
  ui.genBtn.addEventListener('click', generate);
  ui.genLink.addEventListener('click', generate);

  ui.copyBtn.addEventListener('click', copyPassphrase);
  // Copying by hand counts as storing it too.
  for (const el of [ui.encPwd, ui.genPhrase]) {
    el.addEventListener('copy', () => {
      if (state.generated) state.saved = true;
    });
  }

  ui.encForm.addEventListener('submit', (e) => {
    e.preventDefault();
    startEncrypt();
  });
  ui.decForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (state.session) saveDecrypted();
    else startDecrypt();
  });
  ui.messageAction.addEventListener('click', () => state.resume?.());

  ui.cancelBtn.addEventListener('click', () => {
    ui.cancelBtn.disabled = true;
    ui.workPhase.textContent = 'Cancelling…';
    state.controller?.abort(new DOMException('Cancelled', 'AbortError'));
    state.sink?.abort();
  });

  window.addEventListener('beforeunload', (e) => {
    if (state.view === 'work') e.preventDefault();
  });
}

function boot() {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
    ui.main.dataset.view = 'insecure';
    ui.insecure.hidden = false;
    ui.app.hidden = true;
    ui.how.hidden = true;
    return;
  }
  wire();
  registerServiceWorker();
  sweepLegacyStaging();
  setBar({ state: 'empty' });
  show('pick');
  document.documentElement.dataset.ready = 'true';
}

boot();
