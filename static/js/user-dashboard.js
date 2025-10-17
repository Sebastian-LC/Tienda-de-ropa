// user-dashboard.js - Validaciones específicas para dashboard de usuario (prenda y consulta)

document.addEventListener('DOMContentLoaded', () => {
  // Cargar tipos de prenda al cambiar prenda
  window.loadTiposPrenda = function() {
    const idPrenda = document.getElementById('id_prenda').value;
    const tipoSelect = document.getElementById('id_tipo_prenda');
    if (!idPrenda) {
      tipoSelect.innerHTML = '<option value="">Selecciona un tipo</option>';
      return;
    }
    fetch(`/tipos_prenda?id_prenda=${idPrenda}`)
      .then(response => response.json())
      .then(data => {
        tipoSelect.innerHTML = '<option value="">Selecciona un tipo</option>';
        data.forEach(tipo => {
          const option = document.createElement('option');
          option.value = tipo.id;
          option.textContent = tipo.nombre;
          tipoSelect.appendChild(option);
        });
      })
      .catch(error => console.error('Error cargando tipos de prenda:', error));
  };

  // Función para actualizar el resumen
  window.updateSummary = function() {
    const prenda = document.getElementById('id_prenda').selectedOptions[0]?.text || '';
    const tipo = document.getElementById('id_tipo_prenda').selectedOptions[0]?.text || '';
    const tela = document.getElementById('id_tela').selectedOptions[0]?.text || '';
    const estilo = document.getElementById('id_estilo').selectedOptions[0]?.text || '';
    const molde = document.getElementById('id_molde').selectedOptions[0]?.text || '';
    const summary = [prenda, tipo, tela, estilo, molde].filter(s => s).join(' - ');
    document.getElementById('prenda-summary').textContent = summary || 'Selecciona opciones para ver el resumen.';
    document.getElementById('descripcion').value = summary;
  };

  // Validación de creación de prenda
  const crearPrendaBtn = document.getElementById('crear-prenda-btn');
  if (crearPrendaBtn) {
    crearPrendaBtn.addEventListener('click', () => {
      const formData = new FormData(document.getElementById('prenda-form'));
      const data = Object.fromEntries(formData.entries());

      // Validar campos obligatorios
      const requiredFields = ['nombre', 'id_prenda', 'id_tipo_prenda', 'id_tela', 'id_estilo', 'id_molde'];
      const missingFields = requiredFields.filter(field => !data[field]);
      if (missingFields.length > 0) {
        showPrendaError('Todos los campos son obligatorios.');
        return;
      }

      // Enviar datos al servidor
      fetch('/crear_prenda', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(data)
      })
      .then(response => response.json())
      .then(result => {
        if (result.ok) {
          showPrendaSuccess(result.msg);
          document.getElementById('prenda-form').reset();
          updateSummary(); // Reset summary
        } else {
          showPrendaError(result.msg);
        }
      })
      .catch(error => {
        console.error('Error:', error);
        showPrendaError('Error al crear la prenda.');
      });
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

function showPrendaError(msg) {
  const errorDiv = document.getElementById('prenda-error');
  const successDiv = document.getElementById('prenda-success');
  errorDiv.textContent = msg;
  errorDiv.classList.remove('d-none');
  successDiv.classList.add('d-none');
}

function showPrendaSuccess(msg) {
  const errorDiv = document.getElementById('prenda-error');
  const successDiv = document.getElementById('prenda-success');
  successDiv.textContent = msg;
  successDiv.classList.remove('d-none');
  errorDiv.classList.add('d-none');
}

// Función auxiliar para email (si utils.js no está cargado, pero preferir utils)
function validateEmail(email) {
  const emailRegex = /^\S+@\S+\.\S+$/;
  return emailRegex.test(email);
}
