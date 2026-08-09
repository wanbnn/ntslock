const board = document.querySelector('.captcha-cells');
const form = document.querySelector('#captcha-form');
const selectedInput = document.querySelector('#captcha-selected');
if (board && form && selectedInput) {
  const selected = new Set();
  board.querySelectorAll('[data-cell]').forEach(button => {
    button.addEventListener('click', () => {
      const cell = Number(button.dataset.cell);
      if (selected.has(cell)) selected.delete(cell); else selected.add(cell);
      button.classList.toggle('selected', selected.has(cell));
      button.setAttribute('aria-pressed', selected.has(cell) ? 'true' : 'false');
    });
  });
  form.addEventListener('submit', event => {
    if (!selected.size) {
      event.preventDefault();
      document.querySelector('#captcha-hint').textContent = 'Selecione pelo menos uma célula.';
      return;
    }
    selectedInput.value = [...selected].sort((a, b) => a - b).join(',');
  });
}

