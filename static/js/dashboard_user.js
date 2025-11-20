let currentMode = 'basico';
let canvas, ctx, img;
let updatePreviewTimeout;

// Variables para el editor interactivo
const canvasContainer = document.getElementById('canvas-container');
let overlayImg = null;
const upload = document.getElementById('upload');
const overlay = document.getElementById('overlay');
const overlayContainer = document.getElementById('overlayContainer');
const interactiveArea = document.getElementById('interactiveArea');

let isDragging = false;
let isResizing = false;
let isRotating = false;

let startClientX = 0, startClientY = 0;
let startW = 0, startH = 0;
let startRotationDeg = 0;
let overlayRotation = 0;
let rotationOffset = 0;
let startCenter = null;
let startDistance = 0;
let dragOffset = { x: 0, y: 0 };
let aspectRatio = 1;

let overlayX = 200, overlayY = 200, overlayW = 120, overlayH = 120;

const toRad = deg => deg * Math.PI / 180;
const toDeg = rad => rad * 180 / Math.PI;

// Mostrar un toast no bloqueante usando Bootstrap
function showToast(message, type = 'info', timeout = 4000) {
  try {
    const container = document.getElementById('toast-container');
    if (!container) {
      console.log('TOAST:', message);
      return;
    }
    const colorClass = type === 'success' ? 'success' : (type === 'error' ? 'danger' : 'secondary');
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${colorClass} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML = `<div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>`;
    container.appendChild(toastEl);
    // eslint-disable-next-line no-undef
    const bsToast = new bootstrap.Toast(toastEl, { delay: timeout });
    bsToast.show();
    toastEl.addEventListener('hidden.bs.toast', () => {
      toastEl.remove();
    });
  } catch (e) {
    console.log('showToast error', e, message);
  }
}

function getCenter(rect) {
  return {
    x: rect.left + rect.width / 2,
    y: rect.top + rect.height / 2
  };
}

document.querySelectorAll('.handle').forEach(h => {
  h.addEventListener('mousedown', e => {
    e.stopPropagation();
    e.preventDefault();

    const rect = overlayContainer.getBoundingClientRect();
    const parentRect = interactiveArea.getBoundingClientRect();

    startClientX = e.clientX;
    startClientY = e.clientY;
    startW = overlayContainer.offsetWidth;
    startH = overlayContainer.offsetHeight;

    const cx = rect.left + rect.width / 2 - parentRect.left;
    const cy = rect.top + rect.height / 2 - parentRect.top;
    startCenter = { x: cx, y: cy };

    if (h.classList.contains('rotate')) {
      isRotating = true;
      const startAngleMouse = Math.atan2(e.clientY - (cy + parentRect.top), e.clientX - (cx + parentRect.left));
      rotationOffset = overlayRotation - toDeg(startAngleMouse);
    } else if (h.classList.contains('bottom-right')) {
      isResizing = true;
      startDistance = Math.sqrt(
        (e.clientX - (cx + parentRect.left)) ** 2 +
        (e.clientY - (cy + parentRect.top)) ** 2
      );
    }
  });
});

overlayContainer.addEventListener('mousedown', e => {
  if (e.target.classList.contains('handle')) return;
  e.preventDefault();
  isDragging = true;
  const parentRect = interactiveArea.getBoundingClientRect();
  dragOffset.x = e.clientX - (overlayContainer.offsetLeft + parentRect.left);
  dragOffset.y = e.clientY - (overlayContainer.offsetTop + parentRect.top);
});

window.addEventListener('mousemove', e => {
  if (isDragging) {
    const parentRect = interactiveArea.getBoundingClientRect();
    const left = e.clientX - parentRect.left - dragOffset.x;
    const top = e.clientY - parentRect.top - dragOffset.y;
    overlayContainer.style.left = `${left}px`;
    overlayContainer.style.top = `${top}px`;
    return;
  }

  if (isResizing) {
    const parentRect = interactiveArea.getBoundingClientRect();
    const dx = e.clientX - (startCenter.x + parentRect.left);
    const dy = e.clientY - (startCenter.y + parentRect.top);
    const currentDistance = Math.sqrt(dx * dx + dy * dy);
    const scale = currentDistance / startDistance;

    const newW = startW * scale;
    const newH = newW / aspectRatio;

    const newLeft = startCenter.x - newW / 2;
    const newTop = startCenter.y - newH / 2;

    overlayContainer.style.width = `${newW}px`;
    overlayContainer.style.height = `${newH}px`;
    overlayContainer.style.left = `${newLeft}px`;
    overlayContainer.style.top = `${newTop}px`;
    overlayContainer.style.transform = `rotate(${overlayRotation}deg)`;
    return;
  }

  if (isRotating) {
    const parentRect = interactiveArea.getBoundingClientRect();
    const cx = startCenter.x + parentRect.left;
    const cy = startCenter.y + parentRect.top;
    const angle = Math.atan2(e.clientY - cy, e.clientX - cx);
    overlayRotation = (toDeg(angle) + rotationOffset);
    overlayContainer.style.transform = `rotate(${overlayRotation}deg)`;
  }
});

window.addEventListener('mouseup', () => {
  isDragging = false;
  isResizing = false;
  isRotating = false;
});

upload.addEventListener('change', e => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = () => {
    overlayImg = new Image();
    overlayImg.onload = () => {
      overlay.src = overlayImg.src;

      const parentRect = interactiveArea.getBoundingClientRect();
      const maxW = parentRect.width * 0.6;
      const maxH = parentRect.height * 0.6;
      const aspect = overlayImg.width / overlayImg.height;

      let w = maxW;
      let h = w / aspect;
      if (h > maxH) {
        h = maxH;
        w = h * aspect;
      }

      const left = (parentRect.width - w) / 2;
      const top = (parentRect.height - h) / 2;

      overlayContainer.style.width = `${w}px`;
      overlayContainer.style.height = `${h}px`;
      overlayContainer.style.left = `${left}px`;
      overlayContainer.style.top = `${top}px`;
      overlayContainer.style.transform = `rotate(0deg)`;

      overlayRotation = 0;
      aspectRatio = overlayImg.width / overlayImg.height;

      // Habilitar la interacción después de subir la imagen
      overlayContainer.classList.remove('disabled');
    };
    overlayImg.src = reader.result;
  };
  reader.readAsDataURL(file);
});

function doUpdatePreview() {
  const data = collectDesignData();

  // Pintar la camiseta con el color seleccionado
  if (canvas) {
    pintarCamiseta(data.color);
  } else {
    // Cambiar color con CSS para dashboard_user.html
    const previewImg = document.querySelector('.preview-img');
    if (previewImg) {
      previewImg.style.setProperty('--selected-color', data.color);
    }
  }

  // Generar JSON (ya obtenido)

  if (currentMode === 'basico') {
    data.talla = document.getElementById('talla-basica')?.value || '';
    // For persistence, send id_talla (store the selected talla string/value)
    data.id_talla = data.talla || '';
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

  const summaryOutput = document.getElementById('summary-output');
  if (summaryOutput) {
    let summaryHTML = '<ul class="summary-list">';
    summaryHTML += `<li><strong>Tipo de prenda:</strong> ${data.tipo_label || data.tipo_id || 'No seleccionado'}</li>`;
    summaryHTML += `<li><strong>Estilo:</strong> ${data.estilo_label || data.estilo_id || 'No seleccionado'}</li>`;
    summaryHTML += `<li><strong>Tela:</strong> ${data.tela_label || data.tela_id || 'No seleccionado'}</li>`;
    summaryHTML += `<li><strong>Color:</strong> <span style="display:inline-block;width:20px;height:20px;background-color:${data.color};border:1px solid #000;"></span> ${data.color}</li>`;
    summaryHTML += `<li><strong>Modo:</strong> ${data.modo === 'basico' ? 'Básico' : 'Avanzado'}</li>`;
    if (data.modo === 'basico') {
      summaryHTML += `<li><strong>Talla:</strong> ${data.talla || 'No seleccionado'}</li>`;
    } else {
      summaryHTML += '<li><strong>Medidas personalizadas:</strong></li><ul>';
      summaryHTML += `<li>Contorno de cuello: ${data.medidas.cuello || 0} cm</li>`;
      summaryHTML += `<li>Contorno de tórax: ${data.medidas.torax || 0} cm</li>`;
      summaryHTML += `<li>Largo total: ${data.medidas.largoTotal || 0} cm</li>`;
      summaryHTML += `<li>Contorno de sisa: ${data.medidas.sisa || 0} cm</li>`;
      summaryHTML += `<li>Largo de manga: ${data.medidas.largoManga || 0} cm</li>`;
      summaryHTML += `<li>Contorno de brazo: ${data.medidas.brazo || 0} cm</li>`;
      summaryHTML += `<li>Ancho de hombro: ${data.medidas.hombro || 0} cm</li>`;
      summaryHTML += '</ul>';
    }
    summaryHTML += '</ul>';
    summaryOutput.innerHTML = summaryHTML;
  }
  // Si están las opciones principales (usando ids actuales), programar envío al backend
  if (data.tipo_id && data.estilo_id && data.tela_id) {
    scheduleSendDesign(data);
  }
}

// Recopila los datos actuales del formulario y devuelve el objeto JSON
function collectDesignData() {
  // Usar los mismos IDs que el HTML (`id_prenda`, `id_estilo`, `id_tela`, `color`, `id_molde`)
  const tipoEl = document.getElementById('id_prenda');
  const estiloEl = document.getElementById('id_estilo');
  const telaEl = document.getElementById('id_tela');
  const moldeEl = document.getElementById('id_molde');
  const colorEl = document.getElementById('color');

  const tipo_id = tipoEl?.value || '';
  const tipo_label = tipoEl?.selectedOptions?.[0]?.text || '';
  const estilo_id = estiloEl?.value || '';
  const estilo_label = estiloEl?.selectedOptions?.[0]?.text || '';
  const tela_id = telaEl?.value || '';
  const tela_label = telaEl?.selectedOptions?.[0]?.text || '';
  const molde_id = moldeEl?.value || '';
  const molde_label = moldeEl?.selectedOptions?.[0]?.text || '';
  const color = colorEl?.value || '#f8fbff';

  const data = {
    tipo_id: tipo_id,
    tipo_label: tipo_label,
    estilo_id: estilo_id,
    estilo_label: estilo_label,
    tela_id: tela_id,
    tela_label: tela_label,
    molde_id: molde_id,
    molde_label: molde_label,
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

  return data;
}

// Envío al backend con debounce/tonting para evitar spam
let sendDesignTimeout = null;
let lastSentDesignJSON = null;
function scheduleSendDesign(data) {
  const json = JSON.stringify(data);
  if (json === lastSentDesignJSON) return; // no enviar si no cambió
  if (sendDesignTimeout) clearTimeout(sendDesignTimeout);
  sendDesignTimeout = setTimeout(() => {
    // Autosave: nunca insertar como producto, solo backup
    const sendData = Object.assign({}, data, { save_as_product: false });
    sendDesign(sendData).catch(err => console.error('Error enviando diseño:', err));
  }, 700);
}

function sendDesign(data) {
  lastSentDesignJSON = JSON.stringify(data);
  return fetch('/api/guardar-diseno', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
  .then(resp => resp.json())
  .then(res => {
    if (!res.ok) {
      console.warn('Servidor respondió con error al guardar diseño:', res.msg || res);
    } else {
      console.log('Diseño guardado en backend:', res);
    }
    return res;
  });
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
  const modeSelect = document.getElementById('modo-personalizacion');

  if (mode === 'basico') {
    basicoOptions.style.display = 'block';
    avanzadoOptions.style.display = 'none';
  } else {
    basicoOptions.style.display = 'none';
    avanzadoOptions.style.display = 'block';
  }
  updatePreview();
  // Al cargar la página, refrescar la tabla de Informes
  try { refreshInformes(); } catch (e) { console.warn('refreshInformes init error', e); }
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

function aplicarMascaraPrenda() {
  if (!canvas || !ctx || !img) return;

  // Crear un path que siga el contorno de la prenda (simplificado)
  ctx.save();
  ctx.globalCompositeOperation = 'destination-in';

  // Dibujar la forma de la prenda como máscara
  ctx.beginPath();
  // Cuello
  ctx.ellipse(200, 80, 40, 30, 0, 0, Math.PI * 2);
  ctx.fill();

  // Cuerpo
  ctx.beginPath();
  ctx.moveTo(160, 110);
  ctx.lineTo(240, 110);
  ctx.lineTo(250, 200);
  ctx.lineTo(150, 200);
  ctx.closePath();
  ctx.fill();

  // Mangas
  ctx.beginPath();
  ctx.ellipse(140, 140, 20, 40, Math.PI / 2, 0, Math.PI * 2);
  ctx.fill();

  ctx.beginPath();
  ctx.ellipse(260, 140, 20, 40, Math.PI / 2, 0, Math.PI * 2);
  ctx.fill();

  ctx.restore();
}

function updatePreviewSize() {
  const width = document.getElementById('preview-width').value;
  const height = document.getElementById('preview-height').value;
  const previewImg = document.querySelector('.preview-img');
  previewImg.style.width = width + 'px';
  previewImg.style.height = height + 'px';
}

function guardarDiseno() {
  // Recolectar datos y enviar al backend inmediatamente
  const data = collectDesignData();
  // Evitar que un auto-save pendiente provoque un segundo POST:
  if (typeof sendDesignTimeout !== 'undefined' && sendDesignTimeout) {
    clearTimeout(sendDesignTimeout);
    sendDesignTimeout = null;
  }
  try {
    lastSentDesignJSON = JSON.stringify(data);
  } catch (e) {
    lastSentDesignJSON = null;
  }
  // Envío manual: marcar para que se guarde como producto
  const sendData = Object.assign({}, data, { save_as_product: true });
  // Only persist id_molde when in advanced mode (modo personalizado avanzado)
  if (currentMode !== 'avanzado') {
    // ensure we do not send molde id for non-advanced saves
    sendData.molde_id = null;
    sendData.id_molde = null;
  } else {
    // if advanced, make sure id_talla is not sent as a selected talla
    // (advanced uses measurements or molde)
    sendData.id_talla = sendData.id_talla || '';
  }
  sendDesign(sendData)
    .then(res => {
      // Mostrar notificación no bloqueante en UI
      if (res && res.ok) {
        console.log('Diseño guardado en servidor (manual save)', res);
        showToast('Diseño guardado correctamente', 'success', 3500);
        // Actualizar la tabla Informes
        try { refreshInformes(); } catch (e) { console.warn('Error refrescando informes:', e); }
      } else {
        console.warn('Error al guardar diseño en el servidor:', res.msg || res);
        showToast('Error al guardar diseño. Revisa la consola.', 'error', 6000);
      }
    })
    .catch(err => {
      console.error('Error guardando diseño:', err);
      showToast('Error al guardar diseño. Revisa la consola.', 'error', 6000);
    });
}

// Refresca la tabla Informes solicitando /api/user_products y rendereando el tbody
function refreshInformes() {
  fetch('/api/user_products')
    .then(resp => resp.json())
    .then(data => {
      if (!data || !data.ok) {
        console.warn('No se pudo obtener productos para informes:', data);
        return;
      }
      const products = data.products || [];
      const tbody = document.querySelector('#informes table tbody');
      if (!tbody) return;
      tbody.innerHTML = '';
      // Helper: parsear fecha de DB (YYYY-MM-DD HH:MM:SS o ISO) y convertir a zona Colombia
      function formatDateToBogota(dbDateStr) {
        if (!dbDateStr) return '';
        let s = String(dbDateStr).trim();
        let d;
        // Si ya es ISO con T
        if (s.includes('T')) {
          d = new Date(s);
        } else {
          // Convertir 'YYYY-MM-DD HH:MM:SS' -> 'YYYY-MM-DDTHH:MM:SSZ' asumiendo UTC almacenado
          d = new Date(s.replace(' ', 'T') + 'Z');
        }
        if (isNaN(d.getTime())) return dbDateStr;
        try {
          return d.toLocaleString('es-CO', { timeZone: 'America/Bogota', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
        } catch (e) {
          return d.toString();
        }
      }

      products.forEach(p => {
        const tr = document.createElement('tr');
        const date = document.createElement('td'); date.textContent = formatDateToBogota(p.date) || '';
        const prenda = document.createElement('td'); prenda.textContent = p.prenda || '';
        const estilo = document.createElement('td'); estilo.textContent = p.estilo || '';
        const tela = document.createElement('td'); tela.textContent = p.tela || '';
        const tallaTd = document.createElement('td'); tallaTd.textContent = p.talla || '';
        const molde = document.createElement('td'); molde.textContent = p.molde || '';
        const descripcion = document.createElement('td'); descripcion.textContent = p.descripcion || '';
        const estado = document.createElement('td'); estado.textContent = p.estado || '';
        tr.appendChild(date);
        tr.appendChild(prenda);
        tr.appendChild(estilo);
        tr.appendChild(tela);
        tr.appendChild(tallaTd);
        tr.appendChild(molde);
        tr.appendChild(descripcion);
        tr.appendChild(estado);
        tbody.appendChild(tr);
      });
    })
    .catch(err => console.error('Error refrescando informes:', err));
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
  // Agregar event listener al botón de subir imagen
  const uploadBtn = document.getElementById('upload-btn');
  const uploadInput = document.getElementById('upload');
  if (uploadBtn && uploadInput) {
    uploadBtn.addEventListener('click', () => {
      uploadInput.click();
    });
  }
  // Inicializar preview
  canvas = document.getElementById('prenda-canvas') || document.getElementById('canvas');
  if (canvas) {
    ctx = canvas.getContext('2d');
    img = document.getElementById('prenda-img') || new Image();
    if (!img.src) {
      img.crossOrigin = "anonymous";
      img.src = "../static/logo/imagenes_base/camiseta_m_corta.png"; // Imagen base con detalles
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
  // Cargar tallas desde la base de datos
  function loadTallas() {
    const tallaSelect = document.getElementById('talla-basica');
    if (!tallaSelect) return;
    fetch('/api/tallas')
      .then(resp => resp.json())
      .then(data => {
        // Esperamos un array de strings
        tallaSelect.innerHTML = '<option value="">Selecciona talla</option>';
        data.forEach(t => {
          const option = document.createElement('option');
          option.value = t;
          option.textContent = t;
          tallaSelect.appendChild(option);
        });
      })
      .catch(err => console.error('Error cargando tallas:', err));
  }
  try { loadTallas(); } catch (e) { console.warn('loadTallas error', e); }
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

  // Auto-resize inputs numéricos, excepto en avanzado-options
  const numberInputs = document.querySelectorAll('input[type="number"]:not(#avanzado-options input[type="number"])');
  numberInputs.forEach(input => {
    autoResizeInput(input);
    input.addEventListener('input', () => autoResizeInput(input));
  });

  // Cargar tipos de prenda al cambiar prenda
  window.loadTiposPrenda = function() {
    const idPrenda = document.getElementById('id_prenda')?.value || '';
    // elemento opcional: id_tipo_prenda puede no existir en la plantilla actual
    const tipoSelect = document.getElementById('id_tipo_prenda');
    if (!tipoSelect) return; // nada que llenar si no existe
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

  // Cargar estilos de prenda al cambiar prenda (esta función es llamada desde el HTML onchange)
  window.loadEstilosPrenda = function() {
    const idPrenda = document.getElementById('id_prenda')?.value || '';
    const estiloSelect = document.getElementById('id_estilo');
    if (!estiloSelect) return;
    if (!idPrenda) {
      estiloSelect.innerHTML = '<option value="">Selecciona estilo</option>';
      return;
    }
    fetch(`/estilos_prenda?id_prenda=${idPrenda}`)
      .then(response => response.json())
      .then(data => {
        estiloSelect.innerHTML = '<option value="">Selecciona estilo</option>';
        data.forEach(estilo => {
          const option = document.createElement('option');
          option.value = estilo.id;
          option.textContent = estilo.nombre;
          estiloSelect.appendChild(option);
        });
      })
      .catch(error => console.error('Error cargando estilos de prenda:', error));
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
