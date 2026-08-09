const gate = document.querySelector('.gate');
if (gate) {
  const slug = gate.dataset.slug;
  let current = null, timer = null, poller = null, seconds = 60;
  const qr = document.querySelector('#qr'), status = document.querySelector('#gate-status');
  const countdown = document.querySelector('#countdown'), bar = document.querySelector('#timer-bar');

  async function rotate() {
    clearInterval(poller); clearInterval(timer);
    qr.innerHTML = '<div class="qr-loader"></div>'; status.textContent = 'Gerando desafio seguro…';
    try {
      const response = await fetch(`/api/gate/${encodeURIComponent(slug)}/challenge`, {method:'POST'});
      if (!response.ok) throw new Error();
      current = await response.json(); seconds = current.expires_in;
      qr.innerHTML = `<img src="${current.qr_url}" alt="QR Code de acesso, válido por 60 segundos">`;
      status.textContent = 'Aguardando confirmação pelo celular…'; updateTimer();
      timer = setInterval(() => { seconds -= 1; updateTimer(); if (seconds <= 0) rotate(); }, 1000);
      poller = setInterval(check, 1200);
    } catch (_) { status.textContent = 'Não foi possível gerar o desafio. Tentando novamente…'; setTimeout(rotate, 3000); }
  }
  function updateTimer() { countdown.textContent = `${Math.max(0, seconds)}s`; bar.style.width = `${Math.max(0, seconds / current.expires_in * 100)}%`; }
  async function check() {
    if (!current) return;
    const response = await fetch(`/api/gate/challenges/${current.challenge_id}`, {cache:'no-store'});
    if (!response.ok) return;
    const result = await response.json();
    if (result.state === 'approved') { clearInterval(timer); clearInterval(poller); status.textContent = 'Acesso confirmado. Abrindo aplicação…'; qr.classList.add('approved'); setTimeout(() => location.reload(), 700); }
  }
  rotate();
}

