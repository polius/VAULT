export function showToast(message, type = 'warning') {
  const container = document.getElementById('toast-container');
  if (!container) {
    console.error('Toast container not found');
    return;
  }

  const iconMap = {
    warning: 'bi-exclamation-triangle-fill',
    error: 'bi-x-circle-fill',
    success: 'bi-check-circle-fill',
  };

  const toast = document.createElement('div');
  toast.className = `app-toast ${type}`;
  const toastIcon = document.createElement('i');
  toastIcon.className = `bi ${iconMap[type] || iconMap.warning}`;
  const toastText = document.createElement('span');
  toastText.textContent = message;
  toast.append(toastIcon, toastText);
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Both encrypt and decrypt buffer the entire file (plus a second copy) in memory,
// so very large files can freeze or crash the tab. Warn the user before committing.
export const LARGE_FILE_THRESHOLD = 1024 * 1024 * 1024; // 1 GiB

export function confirmLargeFile(file) {
  if (!file || file.size <= LARGE_FILE_THRESHOLD) return true;
  return window.confirm(
    `This file is large (${formatFileSize(file.size)}). Processing happens entirely ` +
    `in your browser's memory and may freeze or crash the tab. Continue?`
  );
}

export function calculatePasswordStrength(password) {
  if (!password) return null;
  
  let score = 0;
  
  // Length
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  
  // Character variety
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  
  // Determine strength
  if (score <= 3) return { level: 'weak', text: 'Weak' };
  if (score <= 5) return { level: 'medium', text: 'Medium' };
  return { level: 'strong', text: 'Strong' };
}

export function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

export function displayFileInfo(file, infoElementId) {
  const infoElement = document.getElementById(infoElementId);
  if (!infoElement) return;
  
  const dropZone = infoElement.closest('.drop-zone');
  const prompt = dropZone?.querySelector('.drop-zone-prompt');
  
  if (!file) {
    infoElement.style.display = 'none';
    infoElement.innerHTML = '';
    if (dropZone) dropZone.classList.remove('has-file');
    if (prompt) prompt.style.display = '';
    return;
  }
  
  const card = dropZone?.closest('.card');
  const isDecrypt = card?.classList.contains('decrypt');
  const icon = isDecrypt ? 'bi-file-earmark-lock2' : 'bi-file-earmark';

  // Build the file-info node via the DOM API. file.name is attacker-controllable
  // (it comes from the OS filename of a dropped/selected file), so it must never
  // be interpolated into innerHTML — use textContent/setAttribute instead.
  infoElement.replaceChildren();

  const fileIcon = document.createElement('i');
  fileIcon.className = `bi ${icon}`;

  const nameEl = document.createElement('span');
  nameEl.className = 'file-name';
  nameEl.title = file.name;
  nameEl.textContent = file.name;

  const sizeEl = document.createElement('span');
  sizeEl.className = 'file-size';
  sizeEl.textContent = formatFileSize(file.size);

  const removeBtn = document.createElement('button');
  removeBtn.className = 'file-remove';
  removeBtn.type = 'button';
  removeBtn.title = 'Remove file';
  removeBtn.setAttribute('aria-label', 'Remove file');
  const removeIcon = document.createElement('i');
  removeIcon.className = 'bi bi-x-lg';
  removeBtn.appendChild(removeIcon);

  infoElement.append(fileIcon, nameEl, sizeEl, removeBtn);
  infoElement.style.display = 'flex';
  if (dropZone) dropZone.classList.add('has-file');
  if (prompt) prompt.style.display = 'none';
  
  removeBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    const fileInput = dropZone?.querySelector('input[type="file"]');
    if (fileInput) fileInput.value = '';
    infoElement.style.display = 'none';
    infoElement.replaceChildren();
    if (dropZone) dropZone.classList.remove('has-file');
    if (prompt) prompt.style.display = '';
  });
}

export function clearFileInput(fileInput, fileInfoElementId) {
  fileInput.value = '';
  const infoElement = document.getElementById(fileInfoElementId);
  if (!infoElement) return;
  infoElement.style.display = 'none';
  infoElement.innerHTML = '';
  const dropZone = infoElement.closest('.drop-zone');
  if (dropZone) dropZone.classList.remove('has-file');
  const prompt = dropZone?.querySelector('.drop-zone-prompt');
  if (prompt) prompt.style.display = '';
}

export function updatePasswordStrength(password, strengthElementId) {
  const strengthElement = document.getElementById(strengthElementId);
  if (!strengthElement) return;
  
  const strength = calculatePasswordStrength(password);
  
  if (!strength || !password) {
    strengthElement.style.display = 'none';
    return;
  }
  
  const fill = strengthElement.querySelector('.strength-fill');
  const text = strengthElement.querySelector('.strength-text');
  
  fill.className = `strength-fill ${strength.level}`;
  text.className = `strength-text ${strength.level}`;
  text.textContent = strength.text;
  strengthElement.style.display = 'flex';
}

export function setupDragAndDrop(fileInput, fileInfoElementId) {
  const dropZone = fileInput.closest('.drop-zone');
  const card = fileInput.closest('.card');
  if (!card) return;
  
  let dragCounter = 0;
  
  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }
  
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    card.addEventListener(eventName, preventDefaults, false);
  });
  
  card.addEventListener('dragenter', () => {
    dragCounter++;
    if (dropZone) dropZone.classList.add('drag-over');
  }, false);
  
  card.addEventListener('dragleave', () => {
    dragCounter--;
    if (dragCounter === 0 && dropZone) {
      dropZone.classList.remove('drag-over');
    }
  }, false);
  
  card.addEventListener('drop', (e) => {
    dragCounter = 0;
    if (dropZone) dropZone.classList.remove('drag-over');
    
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      fileInput.files = files;
      displayFileInfo(files[0], fileInfoElementId);
      const pwdInput = card.querySelector('input[type="password"], input[type="text"][id*="Pwd"]');
      if (pwdInput) pwdInput.focus();
    }
  }, false);
}
