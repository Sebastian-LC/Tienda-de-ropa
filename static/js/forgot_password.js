document.getElementById('forgot-form').addEventListener('submit', function(e) {
  const email = document.querySelector('input[name="email"]').value.trim();
  let errorMsg = '';
  if (!email) errorMsg = 'El correo electrónico es obligatorio.';
  else if (!/^\S+@\S+\.\S+$/.test(email)) errorMsg = 'El correo electrónico no es válido.';
  if (errorMsg) {
    e.preventDefault();
    const errorDiv = document.getElementById('forgot-error');
    errorDiv.textContent = errorMsg;
    errorDiv.classList.remove('d-none');
  }
});
