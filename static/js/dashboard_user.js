let currentMode = 'basico';
let canvas, ctx, img;
let updatePreviewTimeout;

function doUpdatePreview() {
  const tipo = document.getElementById('tipo-prenda')?.value || '';
  const estilo = document.getElementById('estilo-prenda')?.value || '';
  const tela = document.getElementById('tela-prenda')?.value || '';
  const color = document.getElementById('color-prenda')?.value || '#f8fbff';

  // Pintar la camiseta con el color seleccionado
  if (canvas) {
    pintarCamiseta(color);
  } else {
    // Cambiar color con CSS para dashboard_user.html
    const previewImg = document.querySelector('.preview-img');
    if (previewImg) {
      previewImg.style.setProperty('--selected-color', color);
    }
  }

  // Generar JSON
  const data = {
    tipo: tipo,
    estilo: estilo,
    tela: tela,
    color: color,
    modo: currentMode
  };

  if (currentMode === 'basico') {
    data.talla = document.getElementById('talla-basica')?.value || '';
  } else {
    data.medidas = {
      cuello: parseFloat(document.getElementById('cuello')?.value) || 0,
      torax: parseFloat(document.getElementById('torax')?.value) || 0,
      largoTotal: parseFloat(document.getElementById('largo-total')?.value) || 0,
      sisa: parseFloat(document.getElementById('sisa')?.value) || 0,
      largoManga: parseFloat(document.getElementById('largo-manga')?.value) || 0,
      brazo: parseFloat(document.getElementById('brazo')?.value) || 0,
      hombro: parseFloat(document.getElementById('hombro')?.value) || 0
    };
  }

  const jsonOutput = document.getElementById('json-output');
  if (jsonOutput) {
    jsonOutput.textContent = JSON.stringify(data, null, 2);
  }
}

function mostrarSeccion(seccionId) {
  // Ocultar todas las secciones
  const secciones = document.querySelectorAll('main section');
  secciones.forEach(seccion => {
    seccion.classList.add('d-none');
  });
  // Mostrar la sección seleccionada
  const seccion = document.getElementById(seccionId);
  if (seccion) {
    seccion.classList.remove('d-none');
  }
}

function setMode(mode) {
  currentMode = mode;
  const basicoOptions = document.getElementById('basico-options');
  const avanzadoOptions = document.getElementById('avanzado-options');
  const modeBtns = document.querySelectorAll('.mode-btn');

  modeBtns.forEach(btn => btn.classList.remove('active'));

  if (mode === 'basico') {
    basicoOptions.style.display = 'block';
    avanzadoOptions.style.display = 'none';
    document.querySelector('button[onclick="setMode(\'basico\')"]').classList.add('active');
  } else {
    basicoOptions.style.display = 'none';
    avanzadoOptions.style.display = 'block';
    document.querySelector('button[onclick="setMode(\'avanzado\')"]').classList.add('active');
  }
  updatePreview();
}

function updatePreview() {
  // Limpiar timeout anterior si existe
  if (updatePreviewTimeout) {
    clearTimeout(updatePreviewTimeout);
  }

  // Ejecutar updatePreview después de un pequeño delay para evitar llamadas excesivas
  updatePreviewTimeout = setTimeout(doUpdatePreview, 50);
}

function pintarCamiseta(color) {
  if (!canvas || !ctx || !img) return;

  // Limpia el canvas
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Dibuja la base de la camiseta en blanco y negro para conservar textura
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  // Aplica el color de fondo
  ctx.globalCompositeOperation = 'source-atop';
  ctx.fillStyle = color;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Devuelve el modo normal
  ctx.globalCompositeOperation = 'multiply';
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

  ctx.globalCompositeOperation = 'source-over';
}

function updatePreviewSize() {
  const width = document.getElementById('preview-width').value;
  const height = document.getElementById('preview-height').value;
  const previewImg = document.querySelector('.preview-img');
  previewImg.style.width = width + 'px';
  previewImg.style.height = height + 'px';
}

function guardarDiseno() {
  const jsonData = document.getElementById('json-output').textContent;
  // Simular envío al backend (aquí puedes integrar con fetch o AJAX)
  console.log('Guardando diseño:', jsonData);
  alert('Diseño guardado exitosamente!\n' + jsonData);
  // Aquí puedes enviar los datos al servidor
  // fetch('/api/guardar-diseno', { method: 'POST', body: jsonData, headers: {'Content-Type': 'application/json'} });
}

function autoResizeInput(input) {
  const span = document.createElement('span');
  span.style.visibility = 'hidden';
  span.style.position = 'absolute';
  span.style.whiteSpace = 'pre';
  span.style.font = window.getComputedStyle(input).font;
  span.style.padding = window.getComputedStyle(input).padding;
  span.style.border = window.getComputedStyle(input).border;
  span.textContent = input.value || input.placeholder || '0';
  document.body.appendChild(span);
  input.style.width = (span.offsetWidth + 10) + 'px'; // +10 for some padding
  document.body.removeChild(span);
}

// user-dashboard.js - Validaciones específicas para dashboard de usuario (prenda y consulta)

document.addEventListener('DOMContentLoaded', () => {
  // Inicializar preview
  canvas = document.getElementById('prenda-canvas') || document.getElementById('canvas');
  if (canvas) {
    ctx = canvas.getContext('2d');
    img = document.getElementById('prenda-img') || new Image();
    if (!img.src) {
      img.crossOrigin = "anonymous";
      img.src = "../static/logo/camiseta1.png"; // Imagen base con detalles
    }

    img.onload = () => {
      const colorInput = document.getElementById('color-prenda') || document.getElementById('color');
      pintarCamiseta(colorInput ? colorInput.value : '#f8fbff');
    };

    img.onerror = () => {
      console.log('Error al cargar la imagen de la prenda');
    };
  }

  updatePreview();
  // Agregar event listeners a todos los inputs
  const inputs = document.querySelectorAll('select, input');
  inputs.forEach(input => {
    input.addEventListener('change', updatePreview);
  });

  // For prueba.html color change
  const colorInput = document.getElementById('color');
  if (colorInput) {
    colorInput.addEventListener('input', (e) => {
      pintarCamiseta(e.target.value);
    });
  }

  // Auto-resize inputs numéricos
  const numberInputs = document.querySelectorAll('input[type="number"]');
  numberInputs.forEach(input => {
    autoResizeInput(input);
    input.addEventListener('input', () => autoResizeInput(input));
  });

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
    const prendaSummary = document.getElementById('prenda-summary');
    if (prendaSummary) {
      prendaSummary.textContent = summary || 'Selecciona opciones para ver el resumen.';
    }
    const descripcion = document.getElementById('descripcion');
    if (descripcion) {
      descripcion.value = summary;
    }
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
  if (errorDiv) {
    errorDiv.textContent = msg;
    errorDiv.classList.remove('d-none');
  }
  if (successDiv) {
    successDiv.classList.add('d-none');
  }
}

function showPrendaSuccess(msg) {
  const errorDiv = document.getElementById('prenda-error');
  const successDiv = document.getElementById('prenda-success');
  if (successDiv) {
    successDiv.textContent = msg;
    successDiv.classList.remove('d-none');
  }
  if (errorDiv) {
    errorDiv.classList.add('d-none');
  }
}

// Función auxiliar para email (si utils.js no está cargado, pero preferir utils)
function validateEmail(email) {
  const emailRegex = /^\S+@\S+\.\S+$/;
  return emailRegex.test(email);
}
