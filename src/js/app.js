// VAULT UI. One panel moves through four views: pick -> job -> work -> done.
// All crypto lives in format.js; this file only wires it to the page.

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
import { generatePassphrase } from './passphrase.js';
import { openSink, preferredMode, registerServiceWorker, sweepLegacyStaging } from './sink.js';
import { describeCrackTime, estimate, loadDictionaries } from './strength.js';
import { planZip, zipStream } from './zip.js';

// Above this, the in-memory fallback sink asks before continuing.
const MEMORY_WARN_BYTES = 512 * 1024 * 1024;
const MAX_LISTED_FILES = 500;

const $ = (id) => document.getElementById(id);
const ui = Object.fromEntries(
  [
    'app',
    'insecure',
    'how',
    'pick',
    'pickError',
    'dropzone',
    'pickFiles',
    'pickFolder',
    'pickFilesBtn',
    'pickFolderBtn',
    'dropOverlay',
    'job',
    'modeEnc',
    'modeDec',
    'selIcon',
    'selName',
    'selMeta',
    'clearBtn',
    'fileList',
    'fileListItems',
    'vaultInfo',
    'encForm',
    'encPwd',
    'genBtn',
    'encShow',
    'meter',
    'strengthText',
    'generated',
    'copyBtn',
    'confirmField',
    'encPwd2',
    'confirmHelp',
    'hideName',
    'encGo',
    'decForm',
    'decPwd',
    'decShow',
    'decGo',
    'message',
    'messageText',
    'messageAction',
    'work',
    'workPhase',
    'workPct',
    'progress',
    'progressFill',
    'workStats',
    'cancelBtn',
    'done',
    'doneTitle',
    'doneIcon',
    'doneName',
    'doneMeta',
    'doneDetail',
    'againBtn',
    'live',
  ].map((id) => [id, $(id)]),
);

const state = {
  view: 'pick',
  selection: null, // { files: [{ file, path }], dirs: [path] }
  info: null, // inspect() result when the selection is one .vault file
  infoError: null, // why the selection can't be decrypted
  mode: 'encrypt',
  generated: null, // the generated passphrase, while unchanged
  proceed: null, // 'weak' | 'memory': the next click on the same action continues anyway
  session: null, // unlocked decrypt session waiting for a save location
  controller: null,
  sink: null,
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
  for (const v of ['pick', 'job', 'work', 'done']) ui[v].hidden = v !== view;
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
  // Sit right above the active form's main button, where the eye already is.
  const form = state.mode === 'decrypt' ? ui.decForm : ui.encForm;
  form.insertBefore(ui.message, form.querySelector('[type="submit"]'));
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

// ---------- errors ----------

function explain(err, context) {
  if (err?.name === 'AbortError') return { kind: 'info', text: 'Cancelled. Nothing was saved.' };
  const legacy = state.info && state.info.version < 3;
  switch (err?.code) {
    case E.NOT_VAULT:
      return { kind: 'error', text: "This isn't a VAULT file. Choose Encrypt to protect it, or pick a .vault file." };
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

function makeProgress(verb) {
  let started = 0;
  let painted = 0;
  const phase = (p) => {
    const kdf = p === 'kdf';
    ui.progress.classList.toggle('indeterminate', kdf);
    if (kdf) {
      ui.workPhase.textContent =
        verb === 'Encrypting' ? 'Deriving a key from your password…' : 'Checking the password…';
      ui.workPct.textContent = '';
      ui.workStats.textContent = 'This takes a moment on purpose: it makes guessing passwords slow.';
      ui.progress.removeAttribute('aria-valuenow');
      ui.progress.removeAttribute('aria-valuetext');
      ui.progressFill.style.width = '';
    } else {
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
    ui.progressFill.style.width = `${pct}%`;
    ui.progress.setAttribute('aria-valuenow', String(rounded));
    ui.progress.setAttribute('aria-valuetext', `${rounded}%`);
    ui.workPct.textContent = `${rounded}%`;
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

function renderSelection() {
  const { files, dirs } = state.selection;
  const total = files.reduce((n, f) => n + f.file.size, 0);
  const single = files.length === 1 && !dirs.length;
  ui.selName.textContent = single ? files[0].file.name : archiveName(state.selection).replace(/\.zip$/, '');
  ui.selName.title = ui.selName.textContent;
  const parts = single
    ? [formatBytes(total)]
    : [`${files.length} file${files.length === 1 ? '' : 's'}`, formatBytes(total), 'packed into one ZIP'];
  if (dirs.length) parts.splice(1, 0, `${dirs.length} empty folder${dirs.length === 1 ? '' : 's'}`);
  ui.selMeta.textContent = parts.join(' · ');
  setIcon(ui.selIcon, single ? (state.info ? 'i-vault' : 'i-file') : 'i-files');

  ui.fileList.hidden = single;
  ui.fileList.open = false;
  ui.fileListItems.replaceChildren(
    ...files.slice(0, MAX_LISTED_FILES).map((f) => {
      const li = document.createElement('li');
      const name = document.createElement('span');
      const size = document.createElement('span');
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
  const { version, legacy, kdf } = state.info;
  el.className = 'vault-info';
  if (version === 3) {
    el.textContent = `Encrypted with VAULT · format 3 · ${kdf}. The original name and size stay hidden until you unlock it.`;
  } else {
    el.textContent =
      `Encrypted with VAULT 1.x (format ${version}) · original name ${legacy.name} · ${formatBytes(legacy.size)}. ` +
      (version === 1
        ? 'This early format is less resistant to tampering. After opening it, encrypt it again to upgrade it.'
        : 'After opening it, you can encrypt it again to upgrade to the current, stronger format.');
  }
}

function setMode(mode) {
  state.mode = mode;
  state.proceed = null;
  state.session = null;
  ui.app.dataset.mode = mode;
  ui.modeEnc.checked = mode === 'encrypt';
  ui.modeDec.checked = mode === 'decrypt';
  const single = state.selection.files.length === 1 && !state.selection.dirs.length;
  ui.modeDec.disabled = !single;
  ui.modeDec.closest('label').title = single ? '' : 'Decrypt works on one .vault file at a time';
  ui.encForm.hidden = mode !== 'encrypt';
  ui.decForm.hidden = mode !== 'decrypt';
  ui.decGo.disabled = Boolean(state.infoError);
  setButtonLabel(ui.encGo, encryptLabel());
  renderVaultInfo();
  setMessage(null);
}

async function select(selection) {
  if (state.view === 'work') {
    announce('Wait for the current file to finish, or cancel it first.');
    return;
  }
  ui.pickError.hidden = true;
  if (!selection.files.length && !selection.dirs.length) {
    ui.pickError.textContent = 'That folder is empty. There is nothing to encrypt.';
    ui.pickError.hidden = false;
    return;
  }
  state.selection = dedupePaths(selection);
  state.info = null;
  state.infoError = null;
  let mode = 'encrypt';
  const { files, dirs } = state.selection;
  if (files.length === 1 && !dirs.length) {
    try {
      state.info = await inspect(files[0].file);
      mode = 'decrypt';
    } catch (err) {
      if (err?.name !== 'VaultError') {
        ui.pickError.textContent = `Couldn’t read “${files[0].file.name}”. To add a folder, drop it or use Choose a folder.`;
        ui.pickError.hidden = false;
        state.selection = null;
        return;
      }
      state.infoError = err;
      if (err.code !== E.NOT_VAULT) mode = 'decrypt';
    }
  }
  renderSelection();
  setMode(mode);
  show('job');
  announce(
    mode === 'decrypt'
      ? `${files[0].file.name} selected. Enter the password to decrypt it.`
      : `${ui.selName.textContent} selected. Choose a password to encrypt it.`,
  );
  (mode === 'decrypt' ? ui.decPwd : ui.encPwd).focus();
}

function clearSecrets() {
  ui.encPwd.value = '';
  ui.encPwd2.value = '';
  ui.decPwd.value = '';
  state.generated = null;
  state.session = null;
  setShown(ui.encShow, [ui.encPwd, ui.encPwd2], false);
  setShown(ui.decShow, [ui.decPwd], false);
  updateEncryptFields();
}

function reset() {
  clearSecrets();
  state.selection = null;
  state.info = null;
  state.infoError = null;
  state.proceed = null;
  ui.hideName.checked = false;
  ui.pickError.hidden = true;
  setMessage(null);
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
  const e = estimate(pw, state.dicts);
  ui.meter.hidden = !e;
  if (!e) return;
  ui.meter.dataset.score = String(e.score);
  const label = document.createElement('b');
  label.textContent = e.label;
  ui.strengthText.replaceChildren(label, ` · ${describeCrackTime(e.crackSeconds)} to guess`);
}

function updateConfirm(final = false) {
  const pw = ui.encPwd.value;
  const confirm = ui.encPwd2.value;
  const mismatch = confirm && confirm !== pw && (final || confirm.length >= pw.length);
  ui.encPwd2.setAttribute('aria-invalid', String(Boolean(mismatch) || (final && !confirm)));
  if (mismatch) {
    ui.confirmHelp.textContent = 'The passwords don’t match.';
    ui.confirmHelp.className = 'help error';
  } else if (confirm && confirm === pw) {
    ui.confirmHelp.textContent = 'The passwords match.';
    ui.confirmHelp.className = 'help ok';
  } else if (final && !confirm) {
    ui.confirmHelp.textContent = 'Type the password again to confirm it.';
    ui.confirmHelp.className = 'help error';
  } else {
    ui.confirmHelp.textContent = '';
    ui.confirmHelp.className = 'help';
  }
}

function updateEncryptFields() {
  if (state.generated && ui.encPwd.value !== state.generated) state.generated = null;
  ui.generated.hidden = !state.generated;
  ui.confirmField.hidden = Boolean(state.generated);
  ui.encPwd.removeAttribute('aria-invalid');
  if (state.proceed === 'weak') {
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

// ---------- running a job ----------

function begin(mode) {
  ui.app.dataset.mode = mode;
  setMessage(null);
  ui.progressFill.style.width = '0';
  ui.workPct.textContent = '';
  ui.workStats.textContent = '';
  ui.workPhase.textContent = 'Starting…';
  ui.cancelBtn.disabled = false;
  state.controller = new AbortController();
  show('work');
  ui.cancelBtn.focus();
}

function fail(err, context) {
  if (err?.name !== 'VaultError' && err?.name !== 'AbortError') console.error(err);
  state.sink = null;
  const { kind, text } = explain(err, context);
  show('job');
  setMessage(kind, text);
  announce(text);
  if (err?.code === E.WRONG_PASSWORD) {
    ui.decPwd.value = '';
    ui.decPwd.focus();
  } else if (state.mode === 'encrypt') ui.encGo.focus();
  else ui.decGo.focus();
}

// notes: short sentences, one line each on a laptop.
function finish({ title, icon, size, notes = [] }) {
  const { name } = state.sink;
  const meta = `${formatBytes(size)} · ${state.sink.mode === 'fs' ? 'Saved where you chose' : 'Saved to your downloads'}`;
  state.sink = null;
  state.controller = null;
  clearSecrets();
  ui.doneTitle.textContent = title;
  setIcon(ui.doneIcon, icon);
  ui.doneName.textContent = name;
  ui.doneMeta.textContent = meta;
  ui.doneDetail.replaceChildren(
    ...notes.map((text) => {
      const p = document.createElement('p');
      p.textContent = text;
      return p;
    }),
  );
  show('done');
  ui.doneTitle.focus();
  announce(`${title}: ${name}. ${meta}. ${notes.join(' ')}`);
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
  const strength = estimate(password, await ensureDictionaries());
  if (strength.weak && state.proceed !== 'weak') {
    state.proceed = 'weak';
    setMessage(
      'warn',
      `This password is ${strength.label.toLowerCase()}. A well-equipped attacker could guess it in ${describeCrackTime(strength.crackSeconds)}. Use a longer one or generate a passphrase, or encrypt anyway.`,
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
  const outName = ui.hideName.checked ? neutralName() : `${safeFileName(job.meta.name)}.vault`;
  const outSize = encryptedSize({ meta: job.meta, size: job.size });
  if (await needsMemoryConfirm(outSize, startEncrypt)) return;
  state.proceed = null;
  setButtonLabel(ui.encGo, encryptLabel());

  begin('encrypt');
  const { signal } = state.controller;
  const progress = makeProgress('Encrypting');
  try {
    state.sink = await openSink({ name: outName, size: outSize });
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
    finish({
      title: 'Encrypted',
      icon: 'i-vault',
      size: outSize,
      notes: ['Keep your password safe. Without it, no one can open this file.'],
    });
  } catch (err) {
    await state.sink?.abort();
    if (err?.name === 'SecurityError' || err?.name === 'NotAllowedError') {
      show('job');
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
  const { file } = state.selection.files[0];
  begin('decrypt');
  const progress = makeProgress('Decrypting');
  try {
    state.session = await unlock(file, password, { info: state.info, onPhase: progress.phase });
  } catch (err) {
    fail(err, 'unlock');
    return;
  }
  ui.decPwd.value = '';
  await saveDecrypted(progress);
}

async function saveDecrypted(progress = makeProgress('Decrypting')) {
  const { session } = state;
  if (!session) return;
  const name = safeFileName(session.meta.name);
  if (await needsMemoryConfirm(session.meta.size, () => saveDecrypted())) {
    show('job');
    return;
  }
  state.proceed = null;
  if (state.view !== 'work') begin('decrypt');
  const { signal } = state.controller;
  try {
    signal.throwIfAborted();
    state.sink = await openSink({ name, size: session.meta.size });
    progress.phase('decrypt');
    for await (const plain of session.chunks({ signal, onProgress: progress.update })) {
      signal.throwIfAborted();
      await state.sink.write(plain);
    }
    signal.throwIfAborted();
    await state.sink.close();
    const zip = session.meta.type === 'zip';
    const notes = [];
    if (zip) notes.push(`A ZIP archive with ${session.meta.count ?? 'several'} files. Open it to extract them.`);
    if (session.warnings.length) notes.push('Made with an older VAULT format. Encrypt it again to upgrade it.');
    finish({ title: 'Decrypted', icon: zip ? 'i-files' : 'i-file', size: session.meta.size, notes });
  } catch (err) {
    await state.sink?.abort();
    if (err?.name === 'SecurityError' || err?.name === 'NotAllowedError') {
      show('job');
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

// ---------- wiring ----------

function wire() {
  // Drag and drop anywhere on the page. Files dropped outside the panel must
  // never fall through to the browser, which would open them and leave VAULT.
  let depth = 0;
  const hasFiles = (e) => [...(e.dataTransfer?.types ?? [])].includes('Files');
  window.addEventListener('dragenter', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    if (state.view !== 'work') {
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
      ui.pickError.textContent = `Couldn’t read what was dropped: ${err.message}`;
      ui.pickError.hidden = false;
    });
  });

  ui.dropzone.addEventListener('click', (e) => {
    if (!e.target.closest('button')) ui.pickFiles.click();
  });
  ui.pickFilesBtn.addEventListener('click', () => ui.pickFiles.click());
  ui.pickFolderBtn.addEventListener('click', () => ui.pickFolder.click());
  for (const input of [ui.pickFiles, ui.pickFolder]) {
    input.addEventListener('change', () => {
      const selection = fromFileList(input.files);
      input.value = '';
      if (selection.files.length) select(selection);
    });
  }

  ui.clearBtn.addEventListener('click', reset);
  ui.againBtn.addEventListener('click', reset);
  ui.modeEnc.addEventListener('change', () => setMode('encrypt'));
  ui.modeDec.addEventListener('change', () => setMode('decrypt'));

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

  ui.genBtn.addEventListener('click', async () => {
    const phrase = await generatePassphrase();
    ui.encPwd.value = phrase;
    ui.encPwd2.value = '';
    state.generated = phrase;
    setShown(ui.encShow, [ui.encPwd, ui.encPwd2], true);
    updateEncryptFields();
    ui.encPwd.focus();
    announce('Passphrase generated and shown in the password field. Store it before you continue.');
  });

  ui.copyBtn.addEventListener('click', async () => {
    const label = ui.copyBtn.querySelector('span');
    try {
      await navigator.clipboard.writeText(ui.encPwd.value);
      label.textContent = 'Copied';
      announce('Passphrase copied to the clipboard.');
    } catch {
      ui.encPwd.focus();
      ui.encPwd.select();
      label.textContent = 'Press Ctrl+C';
    }
    setTimeout(() => {
      label.textContent = 'Copy';
    }, 2500);
  });

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
    ui.insecure.hidden = false;
    ui.app.hidden = true;
    ui.how.hidden = true;
    return;
  }
  wire();
  registerServiceWorker();
  sweepLegacyStaging();
  show('pick');
  document.documentElement.dataset.ready = 'true';
}

boot();
