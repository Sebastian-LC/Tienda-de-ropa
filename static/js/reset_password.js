// Función para toggle de contraseña
function togglePassword(targetId) {
  const input = document.getElementById(targetId);
  const icon = document.querySelector(`[data-target="${targetId}"] i`);
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.remove('fa-eye');
    icon.classList.add('fa-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.remove('fa-eye-slash');
    icon.classList.add('fa-eye');
  }
}

// Agregar event listeners a los botones toggle
document.querySelectorAll('.toggle-password').forEach(button => {
  button.addEventListener('click', function() {
    const targetId = this.getAttribute('data-target');
    togglePassword(targetId);
  });
});

document.getElementById('reset-form').addEventListener('submit', function(e) {
  const pass1 = document.querySelector('input[name="password"]').value;
  const pass2 = document.querySelector('input[name="password2"]').value;
  let errorMsg = '';
  if (!pass1) errorMsg = 'La nueva contraseña es obligatoria.';
  else if (pass1.length < 6) errorMsg = 'La contraseña debe tener al menos 6 caracteres.';
  else if (pass1 !== pass2) errorMsg = 'Las contraseñas no coinciden.';
  if (errorMsg) {
    e.preventDefault();
    const errorDiv = document.getElementById('reset-error');
    errorDiv.textContent = errorMsg;
    errorDiv.classList.remove('d-none');
  }
});

// Mostrar mensajes de éxito del servidor al cargar la página
document.addEventListener('DOMContentLoaded', function() {
  const successAlerts = document.querySelectorAll('.alert-success');
  successAlerts.forEach(alert => {
    alert.classList.remove('d-none');
    if (!alert.classList.contains('show')) {
      alert.classList.add('show');
    }
  });

  // Si hay mensaje de éxito, redirigir automáticamente al inicio de sesión después de 3 segundos
  if (successAlerts.length > 0) {
    setTimeout(() => {
      window.location.href = '/';
    }, 3000);
  }
});
