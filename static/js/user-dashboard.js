// user-dashboard.js - Validaciones específicas para dashboard de usuario (prenda y consulta)

document.addEventListener('DOMContentLoaded', () => {
  // Validación de creación de prenda
  const prendaForm = document.getElementById('prenda-form');
  if (prendaForm) {
    prendaForm.addEventListener('submit', (e) => {
      const tipo = document.getElementById('tipo-prenda').value.trim();
      const errorDiv = document.getElementById('prenda-error');
      let errorMsg = '';
      if (!tipo) {
        errorMsg = 'Debes seleccionar un tipo de prenda.';
      }
      // Agregar más validaciones si es necesario (e.g., tela, talla)
      if (errorMsg) {
        e.preventDefault();
        if (errorDiv) {
          errorDiv.textContent = errorMsg;
          errorDiv.classList.remove('d-none');
        }
      }
    });
  }

  // Validación de consultas
  const consultaForm = document.getElementById('consulta-form');
  if (consultaForm) {
    consultaForm.addEventListener('submit', (e) => {
      const nombre = document.getElementById('nombre').value.trim();
      const email = document.getElementById('email').value.trim();
      const mensaje = document.getElementById('mensaje').value.trim();
      const errorDiv = document.getElementById('consulta-error');
      let errorMsg = '';
      if (!nombre) {
        errorMsg = 'El nombre es obligatorio.';
      } else if (!email) {
        errorMsg = 'El correo es obligatorio.';
      } else if (!validateEmail(email)) {  // Usar función de utils.js
        errorMsg = 'El correo electrónico no es válido.';
      } else if (!mensaje) {
        errorMsg = 'El mensaje es obligatorio.';
      }
      if (errorMsg) {
        e.preventDefault();
        if (errorDiv) {
          errorDiv.textContent = errorMsg;
          errorDiv.classList.remove('d-none');
        }
      }
    });
  }
});

// Función auxiliar para email (si utils.js no está cargado, pero preferir utils)
function validateEmail(email) {
  const emailRegex = /^\S+@\S+\.\S+$/;
  return emailRegex.test(email);
}
