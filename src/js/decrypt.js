import { showToast, displayFileInfo, setupDragAndDrop, clearFileInput } from './utils.js';

const decEnc = new TextEncoder(), decDec = new TextDecoder();

const decFile = document.getElementById('decFile');
const decPwd = document.getElementById('decPwd');
const decPwdGenerate = document.getElementById('decPwdGenerate');
const decPwdToggle = document.getElementById('decPwdToggle');
const decPwdToggleIcon = document.getElementById('decPwdToggleIcon');
const decBtn = document.getElementById('decBtn');
const decBar = document.getElementById('decBar');
const decStatus = document.getElementById('decStatus');
const decLog = document.getElementById('decLog');

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

function b64u8(b) { return Uint8Array.from(atob(b), c => c.charCodeAt(0)) }

// Mirror of encrypt.js: header || LE32(index) || isLast byte.
function buildAAD(header, index, isLast) {
  const aad = new Uint8Array(header.length + 5);
  aad.set(header, 0);
  new DataView(aad.buffer).setUint32(header.length, index, true);
  aad[header.length + 4] = isLast ? 1 : 0;
  return aad;
}

// The header is attacker-controllable, so validate/clamp it before it drives key
// derivation or buffer sizing. Unbounded iterations would otherwise hang the tab.
const MAX_ITERATIONS = 5_000_000;
const MAX_CHUNK = 64 * 1024 * 1024; // 64 MiB

function validateMeta(meta, dataLen) {
  if (typeof meta.salt !== 'string' || meta.salt.length === 0) throw new Error('Invalid metadata: salt');
  if (!Number.isInteger(meta.iterations) || meta.iterations < 1 || meta.iterations > MAX_ITERATIONS)
    throw new Error('Invalid metadata: iterations');
  if (!Number.isInteger(meta.size) || meta.size < 0 || meta.size > dataLen)
    throw new Error('Invalid metadata: size');
  if (!Number.isInteger(meta.chunk) || meta.chunk < 1 || meta.chunk > MAX_CHUNK)
    throw new Error('Invalid metadata: chunk');
  if (typeof meta.filename !== 'string' || meta.filename.length === 0)
    throw new Error('Invalid metadata: filename');
}

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', decEnc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: iter,
      hash: 'SHA-512'
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

decBtn.onclick = async () => {
  const file = decFile.files[0];
  const pw   = decPwd.value;
  if (!file || !pw) return showToast('Please select an encrypted file and enter the password');

  // Reset UI
  const decCard = document.getElementById('decCard');
  decCard.classList.add('processing');
  decStatus.style.display = 'block';
  decLog.style.display = 'none';
  decBar.style.width = '0%';
  decBar.textContent = '0%';
  decBar.className = 'progress-bar bg-warning text-dark progress-bar-striped progress-bar-animated';
  decPwd.disabled = true;
  decBtn.disabled = true;
  decBtn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Decrypting…';

  try {
    // Read entire file into memory
    const data = new Uint8Array(await file.arrayBuffer());
    let offset = 0;

    // Header
    const magic = new TextDecoder().decode(data.slice(offset, offset + 4)); offset += 4;
    if (magic !== 'AES1') throw new Error('Bad magic');

    const version = data[offset]; offset += 1;
    if (version !== 1 && version !== 2) throw new Error('Bad version');

    const hdrLen = new DataView(data.buffer, offset, 4).getUint32(0, true);
    offset += 4;

    const metaStr = new TextDecoder().decode(data.slice(offset, offset + hdrLen));
    offset += hdrLen;
    const meta = JSON.parse(metaStr);
    validateMeta(meta, data.length);

    // Header bytes covering magic | version | metaLen | meta — authenticated as
    // AAD in version 2 so any tampering with the metadata fails decryption.
    const header = data.slice(0, offset);

    const key = await deriveKey(pw, b64u8(meta.salt), meta.iterations);

    // Collect decrypted chunks
    const chunks = [];
    let done = 0;
    let index = 0;

    while (done < meta.size) {
      const iv = data.slice(offset, offset + 12); offset += 12;
      const chunkSize = Math.min(meta.chunk, meta.size - done);
      const ct = data.slice(offset, offset + chunkSize + 16); offset += chunkSize + 16;

      const isLast = done + chunkSize >= meta.size;
      const params = version === 2
        ? { name: 'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }
        : { name: 'AES-GCM', iv };
      const pt = new Uint8Array(await crypto.subtle.decrypt(params, key, ct));
      chunks.push(pt);

      done += pt.length;
      index++;
      const pct = ((done / meta.size) * 100).toFixed(1);
      decBar.style.width = pct + '%';
      decBar.textContent = pct + '%';
    }

    // Build final Blob and trigger download
    const finalBlob = new Blob(chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(finalBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.filename;
    a.click();
    URL.revokeObjectURL(url);

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
    decLog.className = 'status-log error';
    const icon = decLog.querySelector('.success-icon');
    const message = decLog.querySelector('.status-message');
    icon.style.display = 'none';
    message.textContent = 'Incorrect password or file is corrupted';
    decLog.style.display = 'block';
    setTimeout(() => {
      decPwd.value = '';
      decPwd.focus();
    }, 100);
  } finally {
    decCard.classList.remove('processing');
    decPwd.disabled = false;
    decBtn.disabled = false;
    decBtn.innerHTML = '<i class="bi bi-unlock-fill"></i> Decrypt';
  }
};
