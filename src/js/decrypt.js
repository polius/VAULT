import { showToast, displayFileInfo, setupDragAndDrop, clearFileInput, confirmLargeFile } from './utils.js';
import { b64u8, buildAAD, deriveKey, concatBytes } from './crypto-common.js';
import { openSink, registerServiceWorker } from './sink.js';

const decDec = new TextDecoder();

const decFile = document.getElementById('decFile');
const decPwd = document.getElementById('decPwd');
const decPwdToggle = document.getElementById('decPwdToggle');
const decPwdToggleIcon = document.getElementById('decPwdToggleIcon');
const decBtn = document.getElementById('decBtn');
const decCancel = document.getElementById('decCancel');
const decBar = document.getElementById('decBar');
const decStatus = document.getElementById('decStatus');
const decLog = document.getElementById('decLog');

registerServiceWorker();

// File info display
decFile.addEventListener('change', () => {
  displayFileInfo(decFile.files[0], 'decFileInfo');
  decPwd.focus();
});

decPwd.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    decBtn.click();
  }
});

decPwdToggle.addEventListener('click', () => {
  if (decPwd.type === 'password') {
    decPwd.type = 'text';
    decPwdToggleIcon.classList.remove('bi-eye-fill');
    decPwdToggleIcon.classList.add('bi-eye-slash-fill');
  } else {
    decPwd.type = 'password';
    decPwdToggleIcon.classList.remove('bi-eye-slash-fill');
    decPwdToggleIcon.classList.add('bi-eye-fill');
  }
});

// Setup drag & drop
setupDragAndDrop(decFile, 'decFileInfo');

// The header is attacker-controllable, so validate/clamp it before it drives key
// derivation or buffer sizing. Unbounded iterations would otherwise hang the tab.
const MAX_ITERATIONS = 5_000_000;
const MAX_CHUNK = 64 * 1024 * 1024; // 64 MiB
const MIN_CHUNK = 4096; // every released version wrote 1 MiB, so a floor is safe
const MAX_META = 4096;

function validateMeta(meta, dataLen) {
  if (typeof meta.salt !== 'string' || meta.salt.length === 0) throw new Error('Invalid metadata: salt');
  if (!Number.isInteger(meta.iterations) || meta.iterations < 1 || meta.iterations > MAX_ITERATIONS)
    throw new Error('Invalid metadata: iterations');
  if (!Number.isInteger(meta.size) || meta.size < 0 || meta.size > dataLen)
    throw new Error('Invalid metadata: size');
  if (!Number.isInteger(meta.chunk) || meta.chunk < MIN_CHUNK || meta.chunk > MAX_CHUNK)
    throw new Error('Invalid metadata: chunk');
  if (typeof meta.filename !== 'string' || meta.filename.length === 0)
    throw new Error('Invalid metadata: filename');
  if (meta.kdf !== undefined && meta.kdf !== 'PBKDF2') throw new Error('Invalid metadata: kdf');
  if (meta.hash !== undefined && meta.hash !== 'SHA-512') throw new Error('Invalid metadata: hash');
}

let cancelRequested = false;
decCancel.addEventListener('click', () => { cancelRequested = true; });

decBtn.onclick = async () => {
  const file = decFile.files[0];
  const pw   = decPwd.value;
  if (!file || !pw) return showToast('Please select an encrypted file and enter the password');
  if (!confirmLargeFile(file)) return;

  // Reset UI
  cancelRequested = false;
  const decCard = document.getElementById('decCard');
  decCard.classList.add('processing');
  decStatus.style.display = 'block';
  decLog.style.display = 'none';
  decBar.style.width = '0%';
  decBar.textContent = '0%';
  decBar.className = 'progress-bar bg-warning text-dark progress-bar-striped progress-bar-animated';
  decCancel.style.display = '';
  decPwd.disabled = true;
  decBtn.disabled = true;
  decBtn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Decrypting…';

  let sink = null;
  try {
    // Read only the header incrementally — never buffer the whole ciphertext.
    const head = new Uint8Array(await file.slice(0, 9).arrayBuffer());
    if (head.length < 9 || decDec.decode(head.slice(0, 4)) !== 'AES1') throw new Error('Bad magic');

    const version = head[4];
    if (version !== 1 && version !== 2) throw new Error('Bad version');

    const metaLen = new DataView(head.buffer, 5, 4).getUint32(0, true);
    if (metaLen > MAX_META || 9 + metaLen > file.size) throw new Error('Bad header');

    const metaBytes = new Uint8Array(await file.slice(9, 9 + metaLen).arrayBuffer());
    const meta = JSON.parse(decDec.decode(metaBytes));
    validateMeta(meta, file.size);

    // Header bytes covering magic | version | metaLen | meta — authenticated as
    // AAD in version 2 so any tampering with the metadata fails decryption.
    const header = concatBytes(head, metaBytes);

    // Open the output before deriving the key so the fs save picker appears early.
    sink = await openSink({ id: crypto.randomUUID(), name: meta.filename, size: meta.size, mime: 'application/octet-stream' });

    const key = await deriveKey(pw, b64u8(meta.salt), meta.iterations, 'decrypt');

    // Stream: each Blob.slice().arrayBuffer() reads only that block from the
    // OS-backed file, so peak memory stays at one chunk of plaintext.
    let offset = 9 + metaLen;
    let done = 0;
    let index = 0;

    while (done < meta.size) {
      if (cancelRequested) throw new DOMException('Cancelled', 'AbortError');
      const iv = new Uint8Array(await file.slice(offset, offset + 12).arrayBuffer());
      const chunkSize = Math.min(meta.chunk, meta.size - done);
      const ct = new Uint8Array(await file.slice(offset + 12, offset + 12 + chunkSize + 16).arrayBuffer());
      offset += 12 + chunkSize + 16;

      const isLast = done + chunkSize >= meta.size;
      const params = version === 2
        ? { name: 'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }
        : { name: 'AES-GCM', iv };
      const pt = new Uint8Array(await crypto.subtle.decrypt(params, key, ct));
      await sink.write(pt);

      done += pt.length;
      index++;
      const pct = ((done / meta.size) * 100).toFixed(1);
      decBar.style.width = pct + '%';
      decBar.textContent = pct + '%';
    }

    await sink.close();
    sink = null;

    // UI update
    decBar.classList.remove('bg-warning', 'text-dark', 'progress-bar-striped', 'progress-bar-animated');
    decBar.classList.add('bg-success', 'text-white');
    decLog.style.display = 'block';
    decLog.className = 'status-log success';
    const icon = decLog.querySelector('.success-icon');
    const message = decLog.querySelector('.status-message');
    icon.style.display = 'inline-block';
    message.textContent = 'File successfully decrypted';

    // Clear inputs
    clearFileInput(decFile, 'decFileInfo');
    decPwd.value = '';
  } catch (e) {
    // Keep the user-facing message generic; log details to the console for debugging.
    console.error('Decryption failed:', e);
    if (sink) { try { await sink.abort(); } catch {} }
    decLog.className = 'status-log error';
    const icon = decLog.querySelector('.success-icon');
    const message = decLog.querySelector('.status-message');
    icon.style.display = 'none';
    message.textContent = e.name === 'AbortError' ? 'Operation cancelled' : 'Incorrect password or file is corrupted';
    decLog.style.display = 'block';
    if (e.name !== 'AbortError') {
      setTimeout(() => {
        decPwd.value = '';
        decPwd.focus();
      }, 100);
    }
  } finally {
    decCard.classList.remove('processing');
    decCancel.style.display = 'none';
    decPwd.disabled = false;
    decBtn.disabled = false;
    decBtn.innerHTML = '<i class="bi bi-unlock-fill"></i> Decrypt';
  }
};
