const locationRoot = document.querySelector('[data-location-slug]');
if (locationRoot?.dataset.locationSlug) {
  const locationSlug = locationRoot.dataset.locationSlug;
  const locationStatus = document.querySelector('#location-status');
  const locationForm = locationRoot.querySelector('form');
  const autoContinue = locationRoot.dataset.locationContinue === 'true';
  let locationFinished = false;
  const setLocationStatus = (message, state = '') => {
    if (!locationStatus) return;
    locationStatus.textContent = message;
    locationStatus.dataset.state = state;
  };
  const locationPromise = new Promise(resolve => {
    const decline = async () => {
      try { await fetch(`/api/gate/${encodeURIComponent(locationSlug)}/location-declined`, {method:'POST',credentials:'same-origin'}); } catch (_) {}
    };
    if (!window.isSecureContext || !navigator.geolocation) {
      setLocationStatus('Localização indisponível: acesse por HTTPS para permitir o rastreamento.', 'error');
      decline().finally(() => { locationFinished = true; resolve(false); }); return;
    }
    setLocationStatus('Permita a localização no navegador para registrar a origem deste acesso.', 'pending');
    navigator.geolocation.getCurrentPosition(async position => {
      try {
        const response = await fetch(`/api/gate/${encodeURIComponent(locationSlug)}/location`, {
          method: 'POST', credentials: 'same-origin',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({latitude:position.coords.latitude,longitude:position.coords.longitude,accuracy:position.coords.accuracy}),
        });
        if (!response.ok) throw new Error();
        setLocationStatus(`Localização registrada (precisão aproximada de ${Math.round(position.coords.accuracy)} m).`, 'success');
        locationFinished = true; resolve(true);
      } catch (_) {
        setLocationStatus('A localização foi obtida, mas não pôde ser registrada.', 'error');
        locationFinished = true; resolve(false);
      }
    }, error => {
      const messages = {1:'Permissão de localização recusada. O acesso continuará com rastreabilidade apenas por IP.',2:'Não foi possível determinar sua localização.',3:'A localização demorou demais para responder.'};
      setLocationStatus(messages[error.code] || 'Localização indisponível.', 'error');
      decline().finally(() => { locationFinished = true; resolve(false); });
    }, {enableHighAccuracy:true,timeout:12000,maximumAge:60000});
  });
  if (autoContinue) locationPromise.finally(() => setTimeout(() => location.reload(), 650));
  if (locationForm) {
    locationForm.addEventListener('submit', async event => {
      if (locationFinished) return;
      event.preventDefault();
      const submitter = event.submitter;
      if (submitter) submitter.disabled = true;
      await locationPromise;
      locationForm.requestSubmit(submitter || undefined);
    });
  }
}
