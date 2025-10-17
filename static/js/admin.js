// admin.js - Lógica específica para dashboard de admin: búsqueda, modales, refresh tabla, roles, reauth

// Variables globales para edición de usuario
let editUserId = null;
let editUserUsername = null;
let editUserEmail = null;

// Variables para reautenticación
let reauthAction = null;
let reauthUserId = null;
let reauthRoleId = null;
let reauthTarget = null;

// Función para mostrar modal de edición
function showEditUserModal(userId, username, email) {
  editUserId = userId;
  editUserUsername = username;
  editUserEmail = email;
  document.getElementById('editUserId').value = userId;
  document.getElementById('editUsername').value = username;
  document.getElementById('editEmail').value = email;
  document.getElementById('editUserError').style.display = 'none';
  const modal = new bootstrap.Modal(document.getElementById('editUserModal'));
  modal.show();
}

// Función para mostrar modal de creación
function showCreateUserModal() {
  document.getElementById('createUsername').value = '';
  document.getElementById('createEmail').value = '';
  document.getElementById('createPassword').value = '';
  document.getElementById('createConfirmPassword').value = '';
  document.getElementById('createUserError').style.display = 'none';
  const modal = new bootstrap.Modal(document.getElementById('createUserModal'));
  modal.show();
}

// Función para mostrar modal de reautenticación
function showReauthModal(action, userId, roleId, target) {
  reauthAction = action;
  reauthUserId = userId;
  reauthRoleId = roleId || null;
  reauthTarget = target || null;
  document.getElementById('reauthPassword').value = '';
  document.getElementById('reauthError').style.display = 'none';
  const modal = new bootstrap.Modal(document.getElementById('reauthModal'));
  modal.show();
}

// Función para cargar roles en selects
function loadRolesAndPopulate() {
  fetch('/admin/roles', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
    .then(r => r.json())
    .then(roles => {
      document.querySelectorAll('.role-select').forEach(select => {
        const currentRole = select.getAttribute('data-current-role');
        select.innerHTML = '';
        roles.forEach(role => {
          const option = document.createElement('option');
          option.value = role.id;
          option.textContent = role.name;
          if (String(role.id) === String(currentRole)) option.selected = true;
          select.appendChild(option);
        });
      });
    });
}

// Función para actualizar tabla de usuarios
function refreshUsersTable() {
  fetch('/admin/users', { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
    .then(r => r.text())
    .then(html => {
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      const newTbody = doc.querySelector('#usuarios tbody');
      const oldTbody = document.querySelector('#usuarios tbody');
      if (newTbody && oldTbody) {
        oldTbody.innerHTML = newTbody.innerHTML;
      } else {
        oldTbody.innerHTML = html;
      }
      loadRolesAndPopulate();
    });
}

// Inicializador principal para admin
document.addEventListener('DOMContentLoaded', () => {
  // ID del admin actual
  const currentAdminId = parseInt(document.getElementById('current-admin-id').value || '0');

  // Búsqueda de usuarios
  const searchBtn = document.getElementById('search-user-btn');
  const clearBtn = document.getElementById('clear-search-btn');
  const searchInput = document.getElementById('search-username');
  const resultsDiv = document.getElementById('search-results');
  const resultsBody = document.getElementById('search-results-body');
  const noResults = document.getElementById('search-no-results');

  if (searchBtn) {
    searchBtn.addEventListener('click', () => {
      const username = searchInput.value.trim();
      if (!username) {
        alert('Por favor ingrese un nombre de usuario para buscar.');
        return;
      }
      resultsBody.innerHTML = '<tr><td colspan="6" class="text-center"><div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Cargando...</span></div> Buscando...</td></tr>';
      resultsDiv.classList.remove('d-none');
      noResults.classList.add('d-none');

      fetch('/admin/search_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
        body: 'username=' + encodeURIComponent(username)
      })
      .then(r => r.json())
      .then(data => {
        resultsBody.innerHTML = '';
        if (data.ok && data.users && data.users.length > 0) {
          data.users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
              <td>${user.id}</td>
              <td>${user.username}</td>
              <td>${user.email}</td>
              <td>
                <form method="POST" action="/admin/disable_user" style="display:inline;">
                  <input type="hidden" name="user_id" value="${user.id}">
                  <button type="submit" class="btn btn-sm ${user.enabled_btn_class}">${user.enabled_btn_text}</button>
                </form>
              </td>
              <td>
                <select class="form-select form-select-sm role-select" data-user-id="${user.id}" data-current-role="${user.role_id}" aria-label="Seleccionar rol de usuario"></select>
              </td>
              <td>
                <button type="button" class="btn btn-sm btn-primary edit-user-btn" data-user-id="${user.id}" data-username="${user.username}" data-email="${user.email}">Editar</button>
              </td>
            `;
            resultsBody.appendChild(row);
          });
          loadRolesAndPopulate();
        } else {
          noResults.classList.remove('d-none');
        }
      })
      .catch(error => {
        console.error('Error en búsqueda:', error);
        resultsBody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Error al realizar la búsqueda. Intente nuevamente.</td></tr>';
      });
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      searchInput.value = '';
      resultsDiv.classList.add('d-none');
      noResults.classList.add('d-none');
    });
  }

  // Refresh tabla
  const refreshBtn = document.getElementById('refresh-users');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', refreshUsersTable);
  }

  // Auto-refresh tabla (comentado)
  // setInterval(refreshUsersTable, 10000);

  // Cargar roles al inicio
  loadRolesAndPopulate();

  // Actualizar tabla inmediatamente
  refreshUsersTable();

  // Event listeners para modales
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('edit-user-btn')) {
      const userId = e.target.getAttribute('data-user-id');
      const username = e.target.getAttribute('data-username');
      const email = e.target.getAttribute('data-email');
      showEditUserModal(userId, username, email);
    } else if (e.target.id === 'create-user-btn') {
      showCreateUserModal();
    }
  });

  // Confirmar creación de usuario
  const createConfirmBtn = document.getElementById('createUserConfirmBtn');
  if (createConfirmBtn) {
    createConfirmBtn.addEventListener('click', () => {
      const username = document.getElementById('createUsername').value;
      const email = document.getElementById('createEmail').value;
      const password = document.getElementById('createPassword').value;
      const confirmPassword = document.getElementById('createConfirmPassword').value;
      const first_name = document.getElementById('createFirstName').value;
      const middle_name = document.getElementById('createMiddleName').value;
      const last_name = document.getElementById('createLastName').value;
      const second_last_name = document.getElementById('createSecondLastName').value;
      const id_tipo_documento = document.getElementById('createIdTipoDocumento').value;
      const documento = document.getElementById('createDocumento').value;
      const address1 = document.getElementById('createAddress1').value;
      const address2 = document.getElementById('createAddress2').value;
      const phone1 = document.getElementById('createPhone1').value;
      const phone2 = document.getElementById('createPhone2').value;
      const errorDiv = document.getElementById('createUserError');

      if (!username || !email || !password || !confirmPassword || !first_name || !last_name || !id_tipo_documento || !documento || !address1 || !phone1) {
        errorDiv.textContent = 'Todos los campos obligatorios deben ser completados.';
        errorDiv.style.display = 'block';
        return;
      }

      if (password !== confirmPassword) {
        errorDiv.textContent = 'Las contraseñas no coinciden.';
        errorDiv.style.display = 'block';
        return;
      }

      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('email', email);
      formData.append('password', password);
      formData.append('first_name', first_name);
      formData.append('middle_name', middle_name);
      formData.append('last_name', last_name);
      formData.append('second_last_name', second_last_name);
      formData.append('id_tipo_documento', id_tipo_documento);
      formData.append('documento', documento);
      formData.append('address1', address1);
      formData.append('address2', address2);
      formData.append('phone1', phone1);
      formData.append('phone2', phone2);

      fetch('/admin/create_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
        body: formData.toString()
      })
      .then(r => r.json())
      .then(data => {
        if (data.ok) {
          const modal = bootstrap.Modal.getInstance(document.getElementById('createUserModal'));
          modal.hide();
          refreshUsersTable();
        } else {
          errorDiv.textContent = data.msg || 'Error al crear usuario';
          errorDiv.style.display = 'block';
        }
      });
    });
  }

  // Confirmar edición de usuario
  const editConfirmBtn = document.getElementById('editUserConfirmBtn');
  if (editConfirmBtn) {
    editConfirmBtn.addEventListener('click', () => {
      const userId = document.getElementById('editUserId').value;
      const username = document.getElementById('editUsername').value;
      const email = document.getElementById('editEmail').value;
      const errorDiv = document.getElementById('editUserError');

      if (!username || !email) {
        errorDiv.textContent = 'Todos los campos son obligatorios.';
        errorDiv.style.display = 'block';
        return;
      }

      fetch('/admin/update_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
        body: 'user_id=' + encodeURIComponent(userId) + '&username=' + encodeURIComponent(username) + '&email=' + encodeURIComponent(email)
      })
      .then(r => r.json())
      .then(data => {
        if (data.ok) {
          const modal = bootstrap.Modal.getInstance(document.getElementById('editUserModal'));
          modal.hide();
          // Refrescar tabla de búsqueda si está visible, sino la tabla principal
          const resultsDiv = document.getElementById('search-results');
          if (!resultsDiv.classList.contains('d-none')) {
            // Refrescar resultados de búsqueda
            const searchInput = document.getElementById('search-username');
            const usernameQuery = searchInput.value.trim();
            if (usernameQuery) {
              const resultsBody = document.getElementById('search-results-body');
              const noResults = document.getElementById('search-no-results');
              resultsBody.innerHTML = '<tr><td colspan="6" class="text-center"><div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Cargando...</span></div> Actualizando...</td></tr>';
              resultsDiv.classList.remove('d-none');
              noResults.classList.add('d-none');

              fetch('/admin/search_user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
                body: 'username=' + encodeURIComponent(usernameQuery)
              })
              .then(r => r.json())
              .then(data => {
                resultsBody.innerHTML = '';
                if (data.ok && data.users && data.users.length > 0) {
                  data.users.forEach(user => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                      <td>${user.id}</td>
                      <td>${user.username}</td>
                      <td>${user.email}</td>
                      <td>
                        <form method="POST" action="/admin/disable_user" style="display:inline;">
                          <input type="hidden" name="user_id" value="${user.id}">
                          <button type="submit" class="btn btn-sm ${user.enabled_btn_class}">${user.enabled_btn_text}</button>
                        </form>
                      </td>
                      <td>
                        <select class="form-select form-select-sm role-select" data-user-id="${user.id}" data-current-role="${user.role_id}" aria-label="Seleccionar rol de usuario"></select>
                      </td>
                      <td>
                        <button type="button" class="btn btn-sm btn-primary edit-user-btn" data-user-id="${user.id}" data-username="${user.username}" data-email="${user.email}">Editar</button>
                      </td>
                    `;
                    resultsBody.appendChild(row);
                  });
                  loadRolesAndPopulate();
                  // Refrescar también la tabla principal de usuarios
                  refreshUsersTable();
                } else {
                  noResults.classList.remove('d-none');
                  // Refrescar también la tabla principal de usuarios
                  refreshUsersTable();
                }
              });
            }
          } else {
            refreshUsersTable();
          }
        } else {
          errorDiv.textContent = data.msg || 'Error al actualizar usuario';
          errorDiv.style.display = 'block';
        }
      });
    });
  }

  // Interceptar deshabilitar usuario en tabla principal
  const usuariosSection = document.getElementById('usuarios');
  if (usuariosSection) {
    usuariosSection.addEventListener('submit', (e) => {
      if (e.target.matches('form[action="/admin/disable_user"]')) {
        e.preventDefault();
        const userId = parseInt(e.target.querySelector('input[name="user_id"]').value);
        if (userId === currentAdminId) {
          const errorDiv = document.getElementById('user-management-error');
          errorDiv.textContent = 'No puedes deshabilitarte a ti mismo.';
          errorDiv.classList.remove('d-none');
          setTimeout(() => errorDiv.classList.add('d-none'), 5000);
          return;
        }
        showReauthModal('disable', userId, null, e.target);
      }
    });
  }

  // Interceptar deshabilitar usuario en resultados de búsqueda
  const searchResultsBody = document.getElementById('search-results-body');
  if (searchResultsBody) {
    searchResultsBody.addEventListener('submit', (e) => {
      if (e.target.matches('form[action="/admin/disable_user"]')) {
        e.preventDefault();
        const userId = parseInt(e.target.querySelector('input[name="user_id"]').value);
        if (userId === currentAdminId) {
          const errorDiv = document.getElementById('user-management-error');
          errorDiv.textContent = 'No puedes deshabilitarte a ti mismo.';
          errorDiv.classList.remove('d-none');
          setTimeout(() => errorDiv.classList.add('d-none'), 5000);
          return;
        }
        showReauthModal('disable', userId, null, e.target);
      }
    });
  }

  // Interceptar cambio de rol
  document.addEventListener('change', (e) => {
    if (e.target.classList.contains('role-select')) {
      const userId = parseInt(e.target.getAttribute('data-user-id'));
      if (userId === currentAdminId) {
        const errorDiv = document.getElementById('user-management-error');
        errorDiv.textContent = 'No puedes cambiar tu propio rol.';
        errorDiv.classList.remove('d-none');
        setTimeout(() => errorDiv.classList.add('d-none'), 5000);
        e.target.value = e.target.getAttribute('data-current-role'); // Restaurar
        return;
      }
      const prevValue = e.target.getAttribute('data-current-role');
      const roleId = e.target.value;
      e.target.value = prevValue; // Restaurar temporalmente
      showReauthModal('role', userId, roleId, e.target);
      e.target.setAttribute('data-prev-value', prevValue);
    }
  });

  // Cancelar modal de reauth
  const reauthModal = document.getElementById('reauthModal');
  if (reauthModal) {
    reauthModal.addEventListener('hidden.bs.modal', () => {
      if (reauthAction === 'role' && reauthTarget) {
        reauthTarget.value = reauthTarget.getAttribute('data-prev-value');
      }
      reauthAction = null;
      reauthUserId = null;
      reauthRoleId = null;
      reauthTarget = null;
    });
  }

  // Confirmar en modal de reauth
  const reauthConfirmBtn = document.getElementById('reauthConfirmBtn');
  if (reauthConfirmBtn) {
    reauthConfirmBtn.addEventListener('click', () => {
      const password = document.getElementById('reauthPassword').value;
      if (!password) return;
      fetch('/reauthenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
        body: 'password=' + encodeURIComponent(password)
      })
      .then(r => r.json())
      .then(data => {
        if (data.ok) {
          const modal = bootstrap.Modal.getInstance(document.getElementById('reauthModal'));
          modal.hide();
          if (reauthAction === 'disable' && reauthTarget) {
            fetch('/admin/disable_user', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
              body: 'user_id=' + encodeURIComponent(reauthUserId)
            }).then(() => {
              // Refrescar tabla de búsqueda si está visible, sino la tabla principal
              const resultsDiv = document.getElementById('search-results');
              if (!resultsDiv.classList.contains('d-none')) {
                // Refrescar resultados de búsqueda
                const searchInput = document.getElementById('search-username');
                const usernameQuery = searchInput.value.trim();
                if (usernameQuery) {
                  const resultsBody = document.getElementById('search-results-body');
                  const noResults = document.getElementById('search-no-results');
                  resultsBody.innerHTML = '<tr><td colspan="6" class="text-center"><div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Cargando...</span></div> Actualizando...</td></tr>';
                  resultsDiv.classList.remove('d-none');
                  noResults.classList.add('d-none');

                  fetch('/admin/search_user', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
                    body: 'username=' + encodeURIComponent(usernameQuery)
                  })
                  .then(r => r.json())
                  .then(data => {
                    resultsBody.innerHTML = '';
                    if (data.ok && data.users && data.users.length > 0) {
                      data.users.forEach(user => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                          <td>${user.id}</td>
                          <td>${user.username}</td>
                          <td>${user.email}</td>
                          <td>
                            <form method="POST" action="/admin/disable_user" style="display:inline;">
                              <input type="hidden" name="user_id" value="${user.id}">
                              <button type="submit" class="btn btn-sm ${user.enabled_btn_class}">${user.enabled_btn_text}</button>
                            </form>
                          </td>
                          <td>
                            <select class="form-select form-select-sm role-select" data-user-id="${user.id}" data-current-role="${user.role_id}" aria-label="Seleccionar rol de usuario"></select>
                          </td>
                          <td>
                            <button type="button" class="btn btn-sm btn-primary edit-user-btn" data-user-id="${user.id}" data-username="${user.username}" data-email="${user.email}">Editar</button>
                          </td>
                        `;
                        resultsBody.appendChild(row);
                      });
                      loadRolesAndPopulate();
                    } else {
                      noResults.classList.remove('d-none');
                    }
                  });
                }
              } else {
                refreshUsersTable();
              }
            });
          } else if (reauthAction === 'role' && reauthTarget) {
            fetch('/admin/set_role', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
              body: 'user_id=' + encodeURIComponent(reauthUserId) + '&role_id=' + encodeURIComponent(reauthRoleId)
            }).then(response => {
              if (response.ok) {
                refreshUsersTable();
              } else {
                return response.text().then(text => {
                  const errorDiv = document.getElementById('roles-error');
                  errorDiv.textContent = text || 'Error al cambiar el rol.';
                  errorDiv.classList.remove('d-none');
                  // Ocultar después de 5 segundos
                  setTimeout(() => errorDiv.classList.add('d-none'), 5000);
                });
              }
            }).catch(error => {
              console.error('Error al cambiar rol:', error);
              const errorDiv = document.getElementById('roles-error');
              errorDiv.textContent = 'Error de conexión al cambiar el rol.';
              errorDiv.classList.remove('d-none');
              setTimeout(() => errorDiv.classList.add('d-none'), 5000);
            });
          }
        } else {
          document.getElementById('reauthError').textContent = data.msg || 'Contraseña incorrecta';
          document.getElementById('reauthError').style.display = 'block';
        }
      });
    });
  }

  // Permitir búsqueda con Enter
  if (searchInput) {
    searchInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        searchBtn.click();
      }
    });
  }

  // Validación de gestión de catálogo
  const catalogoForm = document.getElementById('catalogo-form');
  if (catalogoForm) {
    catalogoForm.addEventListener('submit', (e) => {
      const tela = document.getElementById('tela').value.trim();
      const color = document.getElementById('color').value.trim();
      const estampado = document.getElementById('estampado').value.trim();
      const errorDiv = document.getElementById('catalogo-error');
      let errorMsg = '';
      if (!tela) errorMsg = 'El campo Tela es obligatorio.';
      else if (!color) errorMsg = 'El campo Color es obligatorio.';
      else if (!estampado) errorMsg = 'El campo Estampado es obligatorio.';
      if (errorMsg) {
        e.preventDefault();
        errorDiv.textContent = errorMsg;
        errorDiv.classList.remove('d-none');
      }
    });
  }
});
