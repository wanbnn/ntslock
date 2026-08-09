from __future__ import annotations

import html
import json

from pyreact import h, render_to_static_markup
from sixcons import icon
from uikitpr import Badge, Button, Card, CardBody, Heading, Stack, Text, UIProvider


def _metric(label: str, value: str, icon_name: str, tone: str = "info"):
    return Card(
        CardBody(
            Stack(
                h("div", {"className": "metric-top"}, icon(icon_name, size=18), Badge(label, tone=tone)),
                Heading(value, level=3, size="2xl", id=f"metric-{label.lower()}"),
                gap=3,
            )
        ),
        class_name="metric-card",
    )


def dashboard_markup() -> str:
    sidebar = h(
        "aside", {"className": "sidebar"},
        h("a", {"className": "brand", "href": "/"},
          h("span", {"className": "brand-mark"}, icon("shield-check", size=22)),
          h("span", None, "inlock")),
        h("nav", {"className": "nav"},
          h("button", {"className": "nav-item active", "data-view": "overview"}, icon("layout-dashboard", size=18), "Visão geral"),
          h("button", {"className": "nav-item", "data-view": "projects"}, icon("boxes", size=18), "Projetos"),
          h("button", {"className": "nav-item", "data-view": "containers"}, icon("container", size=18), "Containers"),
          h("button", {"className": "nav-item", "data-view": "events"}, icon("scroll-text", size=18), "Eventos")),
        h("div", {"className": "sidebar-foot"},
          h("span", {"className": "status-dot"}),
          h("span", None, "Gateway operacional")),
    )
    content = h(
        "div", {"className": "app-content"},
        h("header", {"className": "topbar"},
          h("div", None, Heading("Centro de controle", level=1, size="2xl"), Text("Proteja cada entrada antes que ela alcance seu app.", tone="muted")),
          Button(icon("plus", size=17), "Novo projeto", variant="primary", id="new-project")),
        h("main", {"id": "main-content"},
          h("section", {"className": "metrics"},
            _metric("Projetos", "—", "boxes"),
            _metric("Protegidos", "—", "shield-check", "success"),
            _metric("Containers", "—", "container"),
            _metric("Bloqueios", "—", "ban", "warning")),
          h("section", {"className": "content-grid"},
            h("div", None,
              h("div", {"className": "section-title"}, Heading("Projetos protegidos", level=2, size="lg"), h("button", {"className": "text-button", "data-view": "projects"}, "Ver todos")),
              h("div", {"id": "project-list", "className": "project-list loading"}, "Carregando projetos…")),
            h("div", None,
              h("div", {"className": "section-title"}, Heading("Atividade recente", level=2, size="lg")),
              h("div", {"id": "event-list", "className": "event-list loading"}, "Carregando eventos…"))))
    )
    return render_to_static_markup(UIProvider(h("div", {"className": "app-shell"}, sidebar, content), theme="dark", full_height=True))


def dashboard_html(tile_url: str) -> str:
    body = dashboard_markup()
    config = json.dumps({"tileUrl": tile_url}).replace("<", "\\u003c").replace(">", "\\u003e")
    return f"""<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Inlock — firewall de aplicação para workloads Docker">
<title>Inlock · Centro de controle</title>
<link rel="stylesheet" href="/static/vendor/leaflet/leaflet.css">
<link rel="stylesheet" href="/static/dashboard.css"></head><body>{body}
<div id="modal-root"></div><div id="toast-root"></div>
<script type="application/json" id="inlock-config">{config}</script>
<script src="/static/vendor/leaflet/leaflet.js"></script>
<script src="/static/dashboard.js" defer></script></body></html>"""


def gate_html(project: dict, return_path: str = "/") -> str:
    totem = project.get("qr_totem_mode", False)
    lead = (
        "Leia o QR Code com seu celular. A aplicação será aberta diretamente no dispositivo móvel."
        if totem else
        "Leia o QR Code com seu celular e confirme o acesso. Esta tela será liberada automaticamente."
    )
    session_title = "Totem permanente" if totem else "Sessão vinculada"
    session_copy = (
        "Cada leitura abre uma sessão somente no dispositivo móvel."
        if totem else "A aprovação libera somente este navegador."
    )
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Acesso protegido · {html.escape(project['name'])}</title>
<link rel="stylesheet" href="/static/gate.css"></head><body>
<main class="gate" data-slug="{html.escape(project['slug'])}" data-mode="{'totem' if totem else 'browser'}" data-return-path="{html.escape(return_path, quote=True)}">
 <section class="gate-copy"><a class="gate-brand" href="#"><span>◆</span> inlock</a>
  <p class="eyebrow">PRESENÇA VERIFICADA</p><h1>Acesso seguro,<br>em um scan.</h1>
  <p class="lead">{lead}</p>
  <div class="trust"><span>✓</span><div><strong>Token efêmero</strong><small>Gerado no servidor e válido por apenas 60 segundos.</small></div></div>
  <div class="trust"><span>✓</span><div><strong>{session_title}</strong><small>{session_copy}</small></div></div>
 </section>
 <section class="qr-card"><div class="qr-head"><span class="live-dot"></span><span>DESAFIO ATIVO</span><span id="countdown">60s</span></div>
  <div id="qr" class="qr-box"><div class="qr-loader"></div></div>
  <h2>Escaneie para continuar</h2><p id="gate-status">Aguardando leitura pelo celular…</p>
  <div class="timer"><i id="timer-bar"></i></div><small>O código se renova automaticamente a cada 60 segundos.</small>
 </section>
</main><script src="/static/gate.js" defer></script></body></html>"""


def approval_html(token: str, project_name: str, expired: bool = False) -> str:
    state = "Este código expirou. Volte à tela original e leia o novo QR Code." if expired else "Confirme para liberar exclusivamente o navegador que exibiu este QR Code."
    action = "" if expired else f'<form method="post"><input type="hidden" name="token" value="{html.escape(token)}"><button type="submit">Confirmar acesso</button></form>'
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirmar acesso</title><link rel="stylesheet" href="/static/gate.css"></head><body><main class="mobile-confirm"><div class="mobile-mark">◆</div><p class="eyebrow">INLOCK</p><h1>{html.escape(project_name)}</h1><p>{state}</p>{action}</main></body></html>"""


def approved_html() -> str:
    return """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acesso confirmado</title><link rel="stylesheet" href="/static/gate.css"></head><body><main class="mobile-confirm success"><div class="mobile-mark">✓</div><p class="eyebrow">ACESSO CONFIRMADO</p><h1>Tudo certo.</h1><p>O navegador original será liberado. Você já pode fechar esta página.</p></main></body></html>"""
