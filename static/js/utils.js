// utils.js - Funciones generales reutilizables: validaciones, toggle password

// Función para validar email
function validateEmail(email) {
  const emailRegex = /^\S+@\S+\.\S+$/;
  return emailRegex.test(email);
}

// Función genérica para validar formulario (campos required)
function validateForm(formId, validations = {}) {
  const form = document.getElementById(formId);
  if (!form) return true; // Si no existe, asumir válido

  let isValid = true;
  const errorDiv = form.querySelector('.alert.alert-danger') || document.getElementById(`${formId.replace('-form', '')}-error`) || form.parentElement.querySelector('.alert.alert-danger');
  let errorMsg = '';

  // Validar campos required por defecto
  const requiredFields = form.querySelectorAll('[required]');
  requiredFields.forEach(field => {
    if (!field.value.trim()) {
      isValid = false;
      errorMsg = `${field.name || field.placeholder || 'Campo'} es obligatorio.`;
      return;
    }
  });

  // Validaciones específicas si se proporcionan
  Object.keys(validations).forEach(key => {
    const field = document.getElementById(key);
    if (field) {
      const validator = validations[key];
      if (!validator(field.value.trim())) {
        isValid = false;
        errorMsg = validator.error || 'Campo inválido.';
      }
    }
  });

  if (!isValid && errorDiv) {
    errorDiv.textContent = errorMsg;
    errorDiv.classList.remove('d-none');
  }

  return isValid;
}

// Función para toggle password
function initTogglePassword(passwordId = 'password', toggleId = 'togglePassword', eyeId = 'eyeIcon') {
  const toggle = document.getElementById(toggleId);
  const passwordInput = document.getElementById(passwordId);
  const eyeIcon = document.getElementById(eyeId);
  if (toggle && passwordInput && eyeIcon) {
    toggle.addEventListener('click', () => {
      const type = passwordInput.type === 'password' ? 'text' : 'password';
      passwordInput.type = type;
      eyeIcon.className = type === 'password' ? 'bi bi-eye' : 'bi bi-eye-slash';
    });
  }
}

// Inicializador general para formularios
function initFormValidation(formId, customValidations = {}) {
  const form = document.getElementById(formId);
  if (form) {
    form.addEventListener('submit', (e) => {
      if (!validateForm(formId, customValidations)) {
        e.preventDefault();
      }
    });
  }
}

// Mostrar un toast no bloqueante usando Bootstrap
function showToast(message, type = 'info', timeout = 4000) {
  try {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
      container.style.zIndex = '11';
      document.body.appendChild(container);
    }
    const colorClass = type === 'success' ? 'success' : (type === 'error' ? 'danger' : 'secondary');
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${colorClass} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML = `<div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
    container.appendChild(toastEl);
    const bsToast = new bootstrap.Toast(toastEl, { delay: timeout });
    bsToast.show();
    toastEl.addEventListener('hidden.bs.toast', () => {
      toastEl.remove();
    });
  } catch (error) {
    console.error('Error mostrando toast:', error);
  }
}

// Inicializador principal
document.addEventListener('DOMContentLoaded', () => {
  // Inicializar toggle password si existe
  initTogglePassword();

  // Inicializar validaciones para formularios comunes si se detectan
  if (document.getElementById('login-form')) {
    initFormValidation('login-form', {
      'email': (value) => validateEmail(value) || { error: 'El correo electrónico no es válido.' }
    });
  }
});
