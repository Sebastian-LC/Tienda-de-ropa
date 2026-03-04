// session.js - Manejo de sesión: temporizador, warnings, extensión (reutilizable en dashboards)

let sessionTimeout = 10 * 60; // 10 minutos en segundos
let warningShown = false;
let countdownInterval = null;
let lastSync = Date.now();

// Función para mostrar warning de sesión
function showSessionWarning() {
  if (!document.getElementById('session-warning')) {
    const div = document.createElement('div');
    div.id = 'session-warning';
    div.className = 'alert alert-warning position-fixed top-0 start-50 translate-middle-x mt-3';
    div.style.zIndex = 2000;
    div.innerHTML = '<b>¡Atención!</b> Tu sesión se cerrará automáticamente en <span id="countdown">2:00</span> por inactividad.';
    document.body.appendChild(div);
    
    // Contador regresivo
    let countdown = 120;
    const countdownEl = document.getElementById('countdown');
    countdownInterval = setInterval(() => {
      countdown--;
      const minutes = Math.floor(countdown / 60);
      const seconds = countdown % 60;
      countdownEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
      if (countdown <= 0) {
        clearInterval(countdownInterval);
        div.remove();
      }
    }, 1000);
    
    setTimeout(() => {
      clearInterval(countdownInterval);
      div.remove();
    }, 120000); // Quitar tras 2 min
  }
}

// Actualizar display del timer (si existe #session-timer)
function updateTimerDisplay() {
  const timerEl = document.getElementById('session-timer');
  if (timerEl) {
    const minutes = Math.floor(sessionTimeout / 60);
    const seconds = sessionTimeout % 60;
    timerEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  }
}

// Resetear timer de sesión
function resetSessionTimer() {
  sessionTimeout = 10 * 60;
  warningShown = false;
  updateTimerDisplay();
  // Extender sesión en servidor (sin debug)
  fetch('/extend_session', { method: 'GET' }).catch(console.error);
}

// Inicializar temporizador de sesión
function initSessionTimer() {
  // Decrementar cada segundo
  setInterval(() => {
    sessionTimeout--;
    updateTimerDisplay();
    if (sessionTimeout <= 120 && sessionTimeout > 0 && !warningShown) {
      showSessionWarning();
      warningShown = true;
    } else if (sessionTimeout <= 0) {
      alert('Tu sesión ha expirado. Serás redirigido al login.');
      window.location.href = '/';
    }
  }, 1000);

  // Reset en actividad del usuario
  ['click', 'keypress', 'mousemove', 'scroll'].forEach(event => {
    document.addEventListener(event, resetSessionTimer);
  });

  // Sincronizar con servidor opcionalmente (cada 10s, comentado por defecto)
  // setInterval(() => {
  //   fetch('/session_remaining')
  //     .then(r => r.json())
  //     .then(data => {
  //       sessionTimeout = data.remaining;
  //       updateTimerDisplay();
  //       lastSync = Date.now();
  //     })
  //     .catch(console.error);
  // }, 10000);
}

// Inicializador principal
document.addEventListener('DOMContentLoaded', () => {
  // Solo inicializar si hay elementos de sesión (e.g., #session-timer para admin)
  if (document.getElementById('session-timer')) {
    initSessionTimer();
  }
});
