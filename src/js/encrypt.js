import { showToast, displayFileInfo, updatePasswordStrength, setupDragAndDrop, clearFileInput, confirmLargeFile } from './utils.js';
import { concatBytes, buildAAD, deriveKey } from './crypto-common.js';
import { openSink, registerServiceWorker } from './sink.js';

const enc = new TextEncoder();

const encFile = document.getElementById('encFile');
const encPwd = document.getElementById('encPwd');
const encPwdGenerate = document.getElementById('encPwdGenerate');
const encPwdToggle = document.getElementById('encPwdToggle');
const encPwdToggleIcon = document.getElementById('encPwdToggleIcon');
const encBtn = document.getElementById('encBtn');
const encCancel = document.getElementById('encCancel');
const encBar = document.getElementById('encBar');
const encStatus = document.getElementById('encStatus');
const encLog = document.getElementById('encLog');

registerServiceWorker();

// Password strength indicator
encPwd.addEventListener('input', () => {
  updatePasswordStrength(encPwd.value, 'encPwdStrength');
});

// File info display
encFile.addEventListener('change', () => {
  displayFileInfo(encFile.files[0], 'encFileInfo');
  encPwd.focus();
});

encPwd.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    encBtn.click();
  }
});

function generateRandomAESKeyBase64() {
  const array = new Uint8Array(32); // 32 bytes = 256 bits
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

encPwdGenerate.addEventListener('click', () => {
  const newPw = generateRandomAESKeyBase64();
  encPwd.value = newPw;
  encPwd.focus();
  updatePasswordStrength(newPw, 'encPwdStrength');
  navigator.clipboard.writeText(newPw)
    .then(() => showToast('Password generated and copied to clipboard', 'success'))
    .catch(() => showToast('Password generated (clipboard copy failed — copy it manually)', 'warning'));
});

encPwdToggle.addEventListener('click', () => {
  if (encPwd.type === 'password') {
    encPwd.type = 'text';
    encPwdToggleIcon.classList.remove('bi-eye-fill');
    encPwdToggleIcon.classList.add('bi-eye-slash-fill');
  } else {
    encPwd.type = 'password';
    encPwdToggleIcon.classList.remove('bi-eye-slash-fill');
    encPwdToggleIcon.classList.add('bi-eye-fill');
  }
});

// Setup drag & drop
setupDragAndDrop(encFile, 'encFileInfo');

let cancelRequested = false;
encCancel.addEventListener('click', () => { cancelRequested = true; });

encBtn.onclick = async () => {
  const file = encFile.files[0];
  const pw   = encPwd.value;
  if (!file || !pw) {
    showToast('Please select a file and enter a password');
    return;
  }
  if (!confirmLargeFile(file)) return;

  // Reset UI
  cancelRequested = false;
  const encCard = document.getElementById('encCard');
  encCard.classList.add('processing');
  encStatus.style.display = 'block';
  encLog.style.display = 'none';
  encBar.style.width = '0%';
  encBar.textContent = '0%';
  encBar.className = 'progress-bar bg-warning text-dark progress-bar-striped progress-bar-animated';
  encCancel.style.display = '';
  encPwd.disabled = true;
  encBtn.disabled = true;
  encBtn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Encrypting…';

  let sink = null;
  try {
    const CHUNK = 1_048_576; // 1 MiB
    const salt  = crypto.getRandomValues(new Uint8Array(16));
    const iter  = 600_000;

    const meta = {
      filename : file.name,
      size     : file.size,
      salt     : btoa(String.fromCharCode(...salt)),
      iterations: iter,
      chunk    : CHUNK,
      kdf      : "PBKDF2",
      hash     : "SHA-512",
    };

    const metaBytes = enc.encode(JSON.stringify(meta));

    // Header: magic(4) | version(1) | metaLen(4, LE) | meta. Version 2 binds the
    // header + chunk index + last-flag into each chunk's GCM tag (see buildAAD).
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, metaBytes.length, true);
    const header = concatBytes(enc.encode('AES1'), new Uint8Array([2]), lenBuf, metaBytes);

    // Open the output first (fs sink shows the save picker now), then derive.
    const outSize = header.length + file.size + 28 * Math.ceil(file.size / CHUNK);
    sink = await openSink({ id: crypto.randomUUID(), name: file.name + '.vault', size: outSize, mime: 'application/octet-stream' });

    const key = await deriveKey(pw, salt, iter, 'encrypt');

    await sink.write(header);

    // Stream: one plaintext chunk in memory at a time, output written as iv||ct.
    let offset = 0;
    let index = 0;
    while (offset < file.size) {
      if (cancelRequested) throw new DOMException('Cancelled', 'AbortError');
      const chunk = new Uint8Array(await file.slice(offset, offset + CHUNK).arrayBuffer());
      const isLast = offset + chunk.length >= file.size;
      const iv    = crypto.getRandomValues(new Uint8Array(12));
      const ct    = new Uint8Array(await crypto.subtle.encrypt(
        { name:'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }, key, chunk));
      await sink.write(concatBytes(iv, ct));

      offset += chunk.length;
      index++;
      const pct = ((offset / file.size) * 100).toFixed(1);
      encBar.style.width = pct + '%';
      encBar.textContent = pct + '%';
    }

    await sink.close();
    sink = null;

    // UI reset
    encBar.classList.remove('bg-warning', 'text-dark', 'progress-bar-striped', 'progress-bar-animated');
    encBar.classList.add('bg-success', 'text-white');
    encLog.style.display = 'block';
    encLog.className = 'status-log success';
    const icon = encLog.querySelector('.success-icon');
    const message = encLog.querySelector('.status-message');
    icon.style.display = 'inline-block';
    message.textContent = 'File successfully encrypted';

    // Clear inputs
    clearFileInput(encFile, 'encFileInfo');
    encPwd.value = '';
    document.getElementById('encPwdStrength').style.display = 'none';
  } catch (e) {
    if (sink) { try { await sink.abort(); } catch {} }
    encLog.className = 'status-log error';
    const icon = encLog.querySelector('.success-icon');
    const message = encLog.querySelector('.status-message');
    icon.style.display = 'none';
    message.textContent = e.name === 'AbortError' ? 'Operation cancelled' : 'Encryption failed: ' + e.message;
    encLog.style.display = 'block';
  } finally {
    encCard.classList.remove('processing');
    encCancel.style.display = 'none';
    encPwd.disabled = false;
    encBtn.disabled = false;
    encBtn.innerHTML = '<i class="bi bi-lock-fill"></i> Encrypt';
  }
};
