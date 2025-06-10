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

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:iter, hash:'SHA-256' },
    base, { name:'AES-GCM', length:256 }, false, ['encrypt']
  );
}

encFile.onchange = () => {
  encPwd.focus();
}

encBtn.onclick = async () => {
  const file = encFile.files[0];
  const pw   = encPwd.value;
  if (!file || !pw) return alert('Choose a file and enter password.');

  encStatus.style.display = 'block';
  encPwd.disabled = true;
  encBtn.disabled = true;

  const CHUNK = 1_048_576; // 1 MiB
  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const iter  = 250_000;
  const key   = await deriveKey(pw, salt, iter);

  const meta = {
    filename : file.name,
    size     : file.size,
    salt     : btoa(String.fromCharCode(...salt)),
    iterations: iter,
    chunk    : CHUNK
  };

  const metaBytes = enc.encode(JSON.stringify(meta));
  const hdrSize   = 4 + 1 + 4 + metaBytes.length;  // magic + ver + len + meta
  const writer = streamSaver.createWriteStream(
    file.name + '.aes',
    {
      size: hdrSize + file.size + Math.ceil(file.size / CHUNK) * 28
    }
  ).getWriter();

  // Header
  await writer.write(enc.encode('AES1'));  // magic
  await writer.write(new Uint8Array([1])); // version
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, metaBytes.length, true);
  await writer.write(lenBuf);
  await writer.write(metaBytes);

  // File, chunk-by-chunk
  let offset = 0;
  while (offset < file.size) {
    const blob  = file.slice(offset, offset + CHUNK);
    const chunk = new Uint8Array(await blob.arrayBuffer());
    const iv    = crypto.getRandomValues(new Uint8Array(12));
    const ct    = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, chunk));
    await writer.write(iv);
    await writer.write(ct);
    offset += chunk.length;
    const pct = ((offset / file.size) * 100).toFixed(1);
    encBar.style.width = pct + '%';
    encBar.textContent = pct + '%';
  }
  await writer.close();
  encBar.classList.remove('bg-warning', 'text-dark', 'progress-bar-striped', 'progress-bar-animated');
  encBar.classList.add('bg-success', 'text-white');
  encLog.style.display = 'block';
  encLog.textContent = '✅ File successfully encrypted.';
};