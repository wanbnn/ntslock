const shell = document.querySelector('.probe-shell');
const form = document.querySelector('#probe-form');
const submit = document.querySelector('#probe-submit');
const telemetry = document.querySelector('#probe-telemetry');
const statusNode = document.querySelector('#probe-status');
const bar = document.querySelector('#probe-bar');

if (shell && form && submit && telemetry) {
  const started = performance.now();
  let pointerMoves = 0;
  let pointerEvents = 0;
  let keyEvents = 0;
  let trustedClick = false;

  addEventListener('pointermove', event => { if (event.isTrusted) pointerMoves += 1; }, {passive:true});
  addEventListener('pointerdown', event => { if (event.isTrusted) pointerEvents += 1; }, {passive:true});
  addEventListener('keydown', event => { if (event.isTrusted) keyEvents += 1; }, {passive:true});
  submit.addEventListener('click', event => { trustedClick = event.isTrusted; });

  let storage = false;
  try {
    localStorage.setItem('inlock-probe', '1');
    localStorage.removeItem('inlock-probe');
    storage = true;
  } catch (_) {}

  const automation = Boolean(
    window.callPhantom || window._phantom || window.__nightmare ||
    document.__selenium_unwrapped || document.__webdriver_evaluate ||
    document.__driver_evaluate || window.domAutomation
  );

  setTimeout(() => {
    submit.disabled = false;
    statusNode.textContent = 'Verificação inicial concluída. Confirme para continuar.';
    bar.style.width = '100%';
  }, 1100);

  form.addEventListener('submit', event => {
    if (submit.disabled) { event.preventDefault(); return; }
    telemetry.value = JSON.stringify({
      js: true,
      webdriver: navigator.webdriver === true,
      automation,
      elapsed: Math.round(performance.now() - started),
      trustedClick,
      pointerMoves,
      pointerEvents,
      keyEvents,
      cookieEnabled: navigator.cookieEnabled === true,
      storage,
      languages: Array.isArray(navigator.languages) ? navigator.languages.length : 0,
      plugins: navigator.plugins ? navigator.plugins.length : 0,
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      touchPoints: navigator.maxTouchPoints || 0,
      screenWidth: screen.width || 0,
      screenHeight: screen.height || 0,
      colorDepth: screen.colorDepth || 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
      visibility: document.visibilityState
    });
    submit.disabled = true;
    submit.textContent = 'Validando sinais…';
  });
}
