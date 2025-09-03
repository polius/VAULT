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

decFile.onchange = () => {
  decPwd.focus();
}

function b64u8(b) { return Uint8Array.from(atob(b), c => c.charCodeAt(0)) }

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
  if (!file || !pw) return alert('Select a .vault file and enter a password.');

  decStatus.style.display = 'block';
  decPwd.disabled = true;
  decBtn.disabled = true;

  try {
    // Read entire file into memory
    const data = new Uint8Array(await file.arrayBuffer());
    let offset = 0;

    // Header
    const magic = new TextDecoder().decode(data.slice(offset, offset + 4)); offset += 4;
    if (magic !== 'AES1') throw new Error('Bad magic');

    const version = data[offset]; offset += 1;
    if (version !== 1) throw new Error('Bad version');

    const hdrLen = new DataView(data.buffer, offset, 4).getUint32(0, true);
    offset += 4;

    const metaStr = new TextDecoder().decode(data.slice(offset, offset + hdrLen));
    offset += hdrLen;
    const meta = JSON.parse(metaStr);

    const key = await deriveKey(pw, b64u8(meta.salt), meta.iterations);

    // Collect decrypted chunks
    const chunks = [];
    let done = 0;

    while (done < meta.size) {
      const iv = data.slice(offset, offset + 12); offset += 12;
      const chunkSize = Math.min(meta.chunk, meta.size - done);
      const ct = data.slice(offset, offset + chunkSize + 16); offset += chunkSize + 16;

      const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
      chunks.push(pt);

      done += pt.length;
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
    decLog.textContent = '✅ File successfully decrypted.';
  } catch (e) {
    console.log(e.message);
    decLog.textContent = '❌ Incorrect password or file is corrupted.';
    decLog.style.display = 'block';
    setTimeout(() => {
      decPwd.value = '';
      decPwd.focus();
    }, 100);
  } finally {
    decPwd.disabled = false;
    decBtn.disabled = false;
  }
};
