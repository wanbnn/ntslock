const cfg = JSON.parse(document.querySelector('#inlock-config').textContent);
const state = { projects: [], containers: [], events: [], selected: null, map: null, circle: null };

async function api(path, options = {}, retried = false) {
  const token = localStorage.getItem('inlock-admin-token');
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401 && !retried) {
    const next = prompt('Token administrativo do Inlock:');
    if (next) { localStorage.setItem('inlock-admin-token', next); return api(path, options, true); }
  }
  if (!response.ok) {
    let message = `Erro ${response.status}`;
    try { const body = await response.json(); message = body.detail || message; } catch (_) {}
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

const esc = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const labels = { rate_limit: 'Rate limit', geo: 'Limite geográfico', user_agent: 'User-agent', ip_allowlist: 'Whitelist de IP', ip_blocklist: 'Blacklist de IP', bot_score: 'Bot score' };
const icons = { rate_limit: '⏱', geo: '◎', user_agent: '⌁', ip_allowlist: '✓', ip_blocklist: '⊘', bot_score: '◈' };

function toast(message, kind = 'success') {
  const node = document.createElement('div'); node.className = `toast ${kind}`; node.textContent = message;
  document.querySelector('#toast-root').append(node); setTimeout(() => node.remove(), 3200);
}

function modal(content, wide = false) {
  const root = document.querySelector('#modal-root');
  root.innerHTML = `<div class="modal-backdrop"><section class="modal ${wide ? 'wide' : ''}">${content}</section></div>`;
  root.querySelector('.modal-backdrop').addEventListener('click', event => { if (event.target === event.currentTarget) closeModal(); });
  root.querySelectorAll('[data-close]').forEach(el => el.addEventListener('click', closeModal));
}
function closeModal() { if (state.map) { state.map.remove(); state.map = null; } document.querySelector('#modal-root').innerHTML = ''; }

function renderProjects(target = '#project-list') {
  const node = document.querySelector(target); if (!node) return;
  if (!state.projects.length) {
    node.innerHTML = `<div class="empty"><span>◇</span><strong>Nenhum projeto ainda</strong><p>Conecte seu primeiro container ou informe uma URL upstream.</p><button id="empty-new">Criar projeto</button></div>`;
    node.querySelector('#empty-new').onclick = openProjectForm; return;
  }
  node.classList.remove('loading');
  node.innerHTML = state.projects.map(project => `<article class="project-card" data-project="${project.id}">
    <div class="project-icon">${project.qr_required ? '▦' : '◇'}</div><div class="project-main">
      <div><strong>${esc(project.name)}</strong><span class="pill ${project.enabled ? 'on' : 'off'}">${project.enabled ? 'Ativo' : 'Pausado'}</span>${project.docker_container_id ? `<span class="pill ${project.isolation === 'protected' ? 'on' : 'off'}">${project.isolation === 'protected' ? 'Porta isolada' : 'Isolamento falhou'}</span>` : ''}</div>
      <small>${esc(project.public_host || `/p/${project.slug}`)} → ${esc(project.upstream_url)}</small>
      <div class="policy-chips">${project.policies.slice(0, 4).map(policy => `<span>${icons[policy.type]} ${esc(labels[policy.type])}</span>`).join('') || '<span>Sem políticas</span>'}</div>
    </div><button class="more" aria-label="Configurar ${esc(project.name)}">›</button></article>`).join('');
  node.querySelectorAll('[data-project]').forEach(el => el.onclick = () => openProject(Number(el.dataset.project)));
}

function renderEvents() {
  const node = document.querySelector('#event-list'); if (!node) return;
  node.classList.remove('loading');
  node.innerHTML = state.events.slice(0, 7).map(event => `<div class="event"><i class="${event.outcome}"></i><div><strong>${esc(event.project_name || 'Sistema')}</strong><span>${esc(event.action.replace('.', ' · '))}</span></div><time>${new Date(event.created_at).toLocaleTimeString('pt-BR', {hour:'2-digit',minute:'2-digit'})}</time></div>`).join('') || '<div class="empty compact">Nenhum evento registrado.</div>';
}

async function load() {
  try {
    const [summary, projects, containers, events] = await Promise.all([api('/api/summary'), api('/api/projects'), api('/api/containers'), api('/api/events?limit=100')]);
    state.projects = projects; state.containers = containers.containers; state.events = events;
    document.querySelector('#metric-projetos').textContent = summary.projects;
    document.querySelector('#metric-protegidos').textContent = summary.protected;
    document.querySelector('#metric-containers').textContent = summary.containers;
    document.querySelector('#metric-bloqueios').textContent = summary.blocked;
    if (summary.isolation.managed && !summary.isolation.secure) toast(`Isolamento Docker inativo: ${summary.isolation.error}`, 'error');
    renderProjects(); renderEvents();
  } catch (error) { toast(error.message, 'error'); }
}

function openProjectForm(container = null) {
  const ports = container?.ports || [];
  modal(`<header class="modal-head"><div><span class="overline">NOVO PROJETO</span><h2>Proteja uma aplicação</h2><p>O tráfego passará pelo Inlock antes de chegar ao upstream.</p></div><button data-close>×</button></header>
  <form id="project-form" class="form-grid">
    <label>Nome<input name="name" required minlength="2" placeholder="Portal do cliente" value="${esc(container?.name || '')}"></label>
    <label>Slug<input name="slug" required pattern="[a-z0-9-]+" placeholder="portal-cliente" value="${esc(container?.name?.toLowerCase().replace(/[^a-z0-9]+/g, '-') || '')}"></label>
    <label class="full">URL do upstream<input name="upstream_url" required type="url" placeholder="http://meu-container:3000" value="${esc(ports[0]?.url || '')}"></label>
    <label class="full">Host público <span>(opcional)</span><input name="public_host" placeholder="app.exemplo.com"></label>
    <input type="hidden" name="docker_container_id" value="${esc(container?.id || '')}">
    <label class="switch-row full"><input type="checkbox" name="qr_required"><i></i><span><strong>Exigir acesso por QR Code</strong><small>Mostra o desafio antes da aplicação.</small></span></label>
    <footer class="form-actions full"><button type="button" class="secondary" data-close>Cancelar</button><button type="submit">Criar projeto</button></footer>
  </form>`);
  document.querySelector('#project-form').onsubmit = async event => {
    event.preventDefault(); const data = Object.fromEntries(new FormData(event.target)); data.qr_required = event.target.qr_required.checked;
    try { await api('/api/projects', { method: 'POST', body: JSON.stringify(data) }); closeModal(); toast('Projeto criado e pronto para receber políticas.'); await load(); }
    catch (error) { toast(error.message, 'error'); }
  };
}

function openProject(id) {
  const project = state.projects.find(item => item.id === id); state.selected = project;
  modal(`<header class="modal-head"><div><span class="overline">PROJETO</span><h2>${esc(project.name)}</h2><p>${esc(project.upstream_url)}</p></div><button data-close>×</button></header>
    <div class="project-settings"><div class="setting-strip"><div><span>Status</span><strong>${project.enabled ? 'Proteção ativa' : 'Pausado'}</strong></div><label class="mini-switch"><input id="toggle-enabled" type="checkbox" ${project.enabled ? 'checked' : ''}><i></i></label></div>
    <div class="setting-strip"><div><span>QR Code</span><strong>${project.qr_required ? 'Obrigatório' : 'Desativado'}</strong></div><label class="mini-switch"><input id="toggle-qr" type="checkbox" ${project.qr_required ? 'checked' : ''}><i></i></label></div>
    <div class="setting-strip"><div><span>Modo totem</span><strong>${project.qr_totem_mode ? 'Abrir aplicação no celular' : 'Liberar navegador original'}</strong></div><label class="mini-switch"><input id="toggle-totem" type="checkbox" ${project.qr_totem_mode ? 'checked' : ''}><i></i></label></div>
    <div class="setting-strip"><div><span>Exposição direta do container</span><strong>${!project.docker_container_id ? 'Upstream não gerenciado' : project.isolation === 'protected' ? 'Bloqueada pelo host' : 'Falha no isolamento'}</strong></div><span class="pill ${project.isolation === 'protected' ? 'on' : 'off'}">${project.isolation === 'protected' ? 'Protegido' : 'Atenção'}</span></div></div>
    <div class="section-title policy-title"><div><h3>Políticas de acesso</h3><p>Avaliadas por prioridade antes do proxy.</p></div><button id="add-policy">+ Adicionar política</button></div>
    <div class="policy-list">${project.policies.map(policy => `<article><div class="policy-symbol">${icons[policy.type]}</div><div><strong>${esc(policy.name)}</strong><small>${esc(policySummary(policy))}</small></div><span>${policy.enabled ? 'Ativa' : 'Inativa'}</span><button data-delete-policy="${policy.id}">×</button></article>`).join('') || '<div class="empty compact">Nenhuma política configurada.</div>'}</div>
    <footer class="danger-zone"><a href="/p/${esc(project.slug)}" target="_blank">Abrir rota protegida ↗</a><button id="delete-project">Excluir projeto</button></footer>`, true);
  document.querySelector('#add-policy').onclick = () => openPolicyForm(project);
  document.querySelector('#toggle-enabled').onchange = event => patchProject(project.id, {enabled: event.target.checked});
  document.querySelector('#toggle-qr').onchange = event => { if (!event.target.checked) document.querySelector('#toggle-totem').checked = false; patchProject(project.id, event.target.checked ? {qr_required:true} : {qr_required:false, qr_totem_mode:false}); };
  document.querySelector('#toggle-totem').onchange = event => { if (event.target.checked) document.querySelector('#toggle-qr').checked = true; patchProject(project.id, {qr_totem_mode:event.target.checked, qr_required:true}); };
  document.querySelectorAll('[data-delete-policy]').forEach(button => button.onclick = async () => { await api(`/api/policies/${button.dataset.deletePolicy}`, {method:'DELETE'}); toast('Política removida.'); await load(); openProject(id); });
  document.querySelector('#delete-project').onclick = async () => { if (confirm(`Excluir ${project.name} e todas as políticas?`)) { await api(`/api/projects/${id}`, {method:'DELETE'}); closeModal(); await load(); toast('Projeto excluído.'); } };
}

async function patchProject(id, values) { try { await api(`/api/projects/${id}`, {method:'PATCH', body:JSON.stringify(values)}); toast('Configuração atualizada.'); await load(); } catch(error) { toast(error.message, 'error'); } }

function policySummary(policy) {
  const c = policy.config;
  if (policy.type === 'rate_limit') return `${c.limit || 60} requisições / ${c.window_seconds || 60}s · ${c.scope === 'global' ? 'global' : 'por IP'}`;
  if (policy.type === 'bot_score') return `Análise progressiva · CAPTCHA quando o score atingir ${c.threshold ?? 65}`;
  if (policy.type === 'geo') return [...(c.countries || []), ...(c.states || []), ...(c.cities || []), c.radius ? `${c.radius.kilometers} km` : ''].filter(Boolean).join(', ') || 'Localização configurada';
  if (policy.type === 'user_agent') return (c.patterns || []).join(', ');
  return (c.networks || []).join(', ');
}

function policyFields(type) {
  if (type === 'rate_limit') return `<label>Requisições<input name="limit" type="number" min="1" value="60"></label><label>Janela (segundos)<input name="window" type="number" min="1" value="60"></label><label class="full">Escopo<select name="scope"><option value="ip">Por endereço IP</option><option value="global">Global para o projeto</option></select></label>`;
  if (type === 'bot_score') return `<label class="full">Confiança mínima (0–100)<input name="threshold" type="number" min="0" max="100" value="65" required><small>Combina requisição, JavaScript, interação, cookies, reputação local do IP e fingerprints. Navegadores novos passam por uma verificação curta; ao atingir este valor, o visitante resolve o CAPTCHA visual.</small></label>`;
  if (type === 'user_agent') return `<label class="full">Padrões bloqueados <span>(um por linha, aceita *)</span><textarea name="patterns" rows="5" placeholder="*bot*&#10;curl/*&#10;*crawler*"></textarea></label>`;
  if (type === 'ip_allowlist' || type === 'ip_blocklist') return `<label class="full">IPs ou redes CIDR <span>(um por linha)</span><textarea name="networks" rows="5" placeholder="203.0.113.10&#10;10.20.0.0/16"></textarea></label>`;
  return `<label class="full">Países permitidos <span>(ISO, separados por vírgula)</span><input name="countries" placeholder="BR, AR, UY"></label><label>Estados permitidos<input name="states" placeholder="SP, RJ"></label><label>Cidades permitidas<input name="cities" placeholder="São Paulo"></label><label class="full">Quando a localização for desconhecida<select name="on_unknown"><option value="deny">Negar acesso</option><option value="allow">Permitir acesso</option></select></label><div class="full"><span class="map-label">Raio permitido <small>(clique no mapa; opcional)</small></span><div id="geo-map"></div><div class="radius-row"><input name="latitude" placeholder="Latitude" readonly><input name="longitude" placeholder="Longitude" readonly><input name="kilometers" type="number" min="0.1" step="0.1" value="25" aria-label="Raio em quilômetros"><span>km</span></div></div>`;
}

function openPolicyForm(project, selectedType = 'rate_limit') {
  modal(`<header class="modal-head"><div><span class="overline">NOVA POLÍTICA</span><h2>Defina quem pode entrar</h2><p>${esc(project.name)}</p></div><button data-close>×</button></header>
  <div class="type-tabs" style="grid-template-columns:repeat(auto-fit,minmax(92px,1fr))">${Object.entries(labels).map(([key,label]) => `<button data-type="${key}" class="${key === selectedType ? 'active' : ''}">${icons[key]}<span>${label}</span></button>`).join('')}</div>
  <form id="policy-form" class="form-grid"><label class="full">Nome<input name="name" required value="${esc(labels[selectedType])}"></label>${policyFields(selectedType)}
  <footer class="form-actions full"><button type="button" class="secondary" data-close>Cancelar</button><button type="submit">Ativar política</button></footer></form>`, true);
  document.querySelectorAll('[data-type]').forEach(button => button.onclick = () => openPolicyForm(project, button.dataset.type));
  if (selectedType === 'geo') setupMap();
  document.querySelector('#policy-form').onsubmit = async event => {
    event.preventDefault(); const form = new FormData(event.target); let config;
    const lines = name => String(form.get(name) || '').split(/\n|,/).map(v => v.trim()).filter(Boolean);
    if (selectedType === 'rate_limit') config = {limit:Number(form.get('limit')), window_seconds:Number(form.get('window')), scope:form.get('scope')};
    else if (selectedType === 'bot_score') config = {threshold:Number(form.get('threshold'))};
    else if (selectedType === 'user_agent') config = {patterns:lines('patterns')};
    else if (selectedType.includes('ip_')) config = {networks:lines('networks')};
    else { config = {countries:lines('countries'), states:lines('states'), cities:lines('cities'), on_unknown:form.get('on_unknown')}; if (form.get('latitude')) config.radius = {latitude:Number(form.get('latitude')), longitude:Number(form.get('longitude')), kilometers:Number(form.get('kilometers'))}; }
    try { await api(`/api/projects/${project.id}/policies`, {method:'POST', body:JSON.stringify({type:selectedType, name:form.get('name'), config})}); closeModal(); toast('Política ativada.'); await load(); openProject(project.id); } catch(error) { toast(error.message, 'error'); }
  };
}

function setupMap() {
  setTimeout(() => {
    state.map = L.map('geo-map').setView([-14.2, -51.9], 4);
    L.tileLayer(cfg.tileUrl, {maxZoom:18, attribution:'&copy; OpenStreetMap'}).addTo(state.map);
    state.map.on('click', event => {
      const km = Number(document.querySelector('[name=kilometers]').value || 25);
      if (state.circle) state.circle.remove();
      state.circle = L.circle(event.latlng, {radius:km*1000, color:'#7c6cff', fillOpacity:.16}).addTo(state.map);
      document.querySelector('[name=latitude]').value = event.latlng.lat.toFixed(6);
      document.querySelector('[name=longitude]').value = event.latlng.lng.toFixed(6);
    });
    document.querySelector('[name=kilometers]').oninput = event => state.circle?.setRadius(Number(event.target.value || 0)*1000);
  }, 50);
}

function showView(view) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  const main = document.querySelector('#main-content');
  if (view === 'overview') { location.reload(); return; }
  if (view === 'projects') { main.innerHTML = `<div class="page-head"><div><span class="overline">INVENTÁRIO</span><h2>Projetos</h2><p>Rotas, upstreams e políticas ativas.</p></div><button id="page-new">+ Novo projeto</button></div><div id="all-projects" class="project-list"></div>`; renderProjects('#all-projects'); document.querySelector('#page-new').onclick = openProjectForm; }
  if (view === 'containers') { main.innerHTML = `<div class="page-head"><div><span class="overline">DESCOBERTA AUTOMÁTICA</span><h2>Containers Docker</h2><p>${state.containers.length} workloads encontrados no daemon local.</p></div><button id="refresh">↻ Atualizar</button></div><div class="container-grid">${state.containers.map(c => `<article class="container-card"><div><span class="container-state ${c.status}"></span><strong>${esc(c.name)}</strong></div><small>${esc(c.image)}</small><p>${c.ports.map(p => p.host ? `${p.host}:${p.private}` : p.private).join(' · ') || 'Sem portas expostas'}</p><button data-import="${c.id}">Proteger container</button></article>`).join('') || '<div class="empty">Docker indisponível ou nenhum container encontrado.</div>'}</div>`; document.querySelectorAll('[data-import]').forEach(el => el.onclick = () => openProjectForm(state.containers.find(c => c.id === el.dataset.import))); document.querySelector('#refresh').onclick = async () => { await load(); showView('containers'); }; }
  if (view === 'events') { main.innerHTML = `<div class="page-head"><div><span class="overline">AUDITORIA</span><h2>Eventos</h2><p>Decisões recentes do gateway.</p></div></div><div class="events-table">${state.events.map(e => `<div><i class="${e.outcome}"></i><strong>${esc(e.project_name || 'Sistema')}</strong><span>${esc(e.action)}</span><code>${esc(e.client_ip || '—')}</code><time>${new Date(e.created_at).toLocaleString('pt-BR')}</time></div>`).join('')}</div>`; }
}

document.querySelector('#new-project').onclick = () => openProjectForm();
document.addEventListener('click', event => { const trigger = event.target.closest('[data-view]'); if (trigger) showView(trigger.dataset.view); });
load();
