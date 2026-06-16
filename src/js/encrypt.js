import { showToast, displayFileInfo, updatePasswordStrength, setupDragAndDrop, clearFileInput } from './utils.js';

const enc = new TextEncoder();

const encFile = document.getElementById('encFile');
const encPwd = document.getElementById('encPwd');
const encPwdGenerate = document.getElementById('encPwdGenerate');
const encPwdToggle = document.getElementById('encPwdToggle');
const encPwdToggleIcon = document.getElementById('encPwdToggleIcon');
const encBtn = document.getElementById('encBtn');
const encBar = document.getElementById('encBar');
const encStatus = document.getElementById('encStatus');
const encLog = document.getElementById('encLog');

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
  navigator.clipboard.writeText(newPw);
  showToast('Password generated and copied to clipboard', 'success');
  updatePasswordStrength(newPw, 'encPwdStrength');
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

function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.length; }
  return out;
}

// Per-chunk Additional Authenticated Data. Binding the full header, the chunk
// index and an "is last chunk" flag into the GCM tag makes the metadata
// tamper-evident and prevents chunk reordering, duplication and truncation.
function buildAAD(header, index, isLast) {
  const aad = new Uint8Array(header.length + 5);
  aad.set(header, 0);
  new DataView(aad.buffer).setUint32(header.length, index, true);
  aad[header.length + 4] = isLast ? 1 : 0;
  return aad;
}

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
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
    ['encrypt']
  );
}

encBtn.onclick = async () => {
  const file = encFile.files[0];
  const pw   = encPwd.value;
  if (!file || !pw) {
    showToast('Please select a file and enter a password');
    return;
  }

  // Reset UI
  const encCard = document.getElementById('encCard');
  encCard.classList.add('processing');
  encStatus.style.display = 'block';
  encLog.style.display = 'none';
  encBar.style.width = '0%';
  encBar.textContent = '0%';
  encBar.className = 'progress-bar bg-warning text-dark progress-bar-striped progress-bar-animated';
  encPwd.disabled = true;
  encBtn.disabled = true;
  encBtn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Encrypting…';

  try {
    const CHUNK = 1_048_576; // 1 MiB
    const salt  = crypto.getRandomValues(new Uint8Array(16));
    const iter  = 600_000;
    const key   = await deriveKey(pw, salt, iter);

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

  const chunks = [header];

  // File, chunk-by-chunk
  let offset = 0;
  let index = 0;
  while (offset < file.size) {
    const blob  = file.slice(offset, offset + CHUNK);
    const chunk = new Uint8Array(await blob.arrayBuffer());
    const isLast = offset + chunk.length >= file.size;
    const iv    = crypto.getRandomValues(new Uint8Array(12));
    const ct    = new Uint8Array(await crypto.subtle.encrypt(
      { name:'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }, key, chunk));
    chunks.push(iv);
    chunks.push(ct);

    offset += chunk.length;
    index++;
    const pct = ((offset / file.size) * 100).toFixed(1);
    encBar.style.width = pct + '%';
    encBar.textContent = pct + '%';
  }

    // Finalize
    const finalBlob = new Blob(chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(finalBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name + '.vault';
    a.click();
    URL.revokeObjectURL(url);

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
    encLog.className = 'status-log error';
    const icon = encLog.querySelector('.success-icon');
    const message = encLog.querySelector('.status-message');
    icon.style.display = 'none';
    message.textContent = 'Encryption failed: ' + e.message;
    encLog.style.display = 'block';
  } finally {
    encCard.classList.remove('processing');
    encPwd.disabled = false;
    encBtn.disabled = false;
    encBtn.innerHTML = '<i class="bi bi-lock-fill"></i> Encrypt';
  }
};
