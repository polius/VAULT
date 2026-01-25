export function showToast(message, type = 'warning') {
  const container = document.getElementById('toast-container');
  if (!container) {
    console.error('Toast container not found');
    return;
  }
  const toast = document.createElement('div');
  toast.className = `app-toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
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
  
  if (!file) {
    infoElement.style.display = 'none';
    return;
  }
  
  infoElement.innerHTML = `
    <i class="bi bi-file-earmark-text"></i>
    <span class="file-name" title="${file.name}">${file.name}</span>
    <span class="file-size">${formatFileSize(file.size)}</span>
  `;
  infoElement.style.display = 'flex';
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
  const card = fileInput.closest('.card');
  
  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }
  
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    card.addEventListener(eventName, preventDefaults, false);
  });
  
  ['dragenter', 'dragover'].forEach(eventName => {
    card.addEventListener(eventName, () => {
      card.classList.add('drag-over');
    }, false);
  });
  
  ['dragleave', 'drop'].forEach(eventName => {
    card.addEventListener(eventName, () => {
      card.classList.remove('drag-over');
    }, false);
  });
  
  card.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      fileInput.files = files;
      displayFileInfo(files[0], fileInfoElementId);
      // Find and focus the password input in the same card
      const pwdInput = card.querySelector('input[type="password"], input[type="text"][id*="Pwd"]');
      if (pwdInput) pwdInput.focus();
    }
  }, false);
}
