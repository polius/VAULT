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

function b64u8(b) { return Uint8Array.from(atob(b), c => c.charCodeAt(0)) }

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', decEnc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations: iter, hash:'SHA-256' },
    base,
    { name:'AES-GCM', length:256 },
    false,
    ['decrypt']
  );
}

function makeReader(rdr) {
  let buf = new Uint8Array();
  return async n => {
    while (buf.length < n) {
      const {done, value} = await rdr.read();
      if (done) throw new Error('Truncated file');
      const tmp = new Uint8Array(buf.length + value.length);
      tmp.set(buf);
      tmp.set(value, buf.length);
      buf = tmp;
    }
    const out = buf.slice(0, n);
    buf = buf.slice(n);
    return out;
  };
}

decFile.onchange = () => {
  decPwd.focus();
}

decBtn.onclick = async () => {
  const file = decFile.files[0];
  const pw   = decPwd.value;
  if (!file || !pw) return alert('Select a .vault file and enter a password.');

  decStatus.style.display = 'block';
  decPwd.disabled = true;
  decBtn.disabled = true;

  const rdr = file.stream().getReader();
  const rN = makeReader(rdr);

  try {
    if (decDec.decode(await rN(4)) !== 'AES1') throw new Error('Bad magic');
    if ((await rN(1))[0] !== 1) throw new Error('Bad version');

    const hdrLen = new DataView((await rN(4)).buffer).getUint32(0, true);
    const meta = JSON.parse(decDec.decode(await rN(hdrLen)));

    const key = await deriveKey(pw, b64u8(meta.salt), meta.iterations);
    const wr = streamSaver.createWriteStream(meta.filename, {size:meta.size}).getWriter();

    let done = 0;
    while (done < meta.size) {
      const iv = await rN(12);
      const chunk = Math.min(meta.chunk, meta.size - done);
      const ct = await rN(chunk+16);
      const pt = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct));
      await wr.write(pt);
      done += pt.length;
      const pct = ((done / meta.size) * 100).toFixed(1);
      decBar.style.width = pct + '%';
      decBar.textContent = pct + '%';
    }
    await wr.close();
    decBar.classList.remove('bg-warning', 'text-dark', 'progress-bar-striped', 'progress-bar-animated');
    decBar.classList.add('bg-success', 'text-white');
    decLog.style.display = 'block';
    decLog.textContent = '✅ File successfully decrypted.';
  } catch(e) {
    decPwd.disabled = false;
    decBtn.disabled = false;
    decPwd.value = '';
    decPwd.focus();
    decLog.style.display = 'block';
    decLog.textContent = '❌ Incorrect password or file is corrupted.';
    console.log(e.message)
  }
};