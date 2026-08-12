import json
import re
from pathlib import Path
from urllib.parse import parse_qsl

import httpx
import pytest
from fastapi.testclient import TestClient

import inlock.main as main_module
from inlock.config import Settings
from inlock.main import app
from inlock.policies import PolicyEngine
from inlock.security import token_hash
from inlock.store import Store


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    config = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "test.db",
        secret_key="integration-test-secret",
        admin_token="admin-test-token",
        docker_url="unix:///does/not/exist.sock",
    ).prepare()
    monkeypatch.setattr(main_module, "get_settings", lambda: config)
    with TestClient(app) as test_client:
        app.state.settings = config
        app.state.store = Store(config.database_path)
        app.state.engine = PolicyEngine()
        headers = {"Authorization": "Bearer admin-test-token"}
        yield test_client, headers


def create_project(client, headers, qr=True):
    response = client.post("/api/projects", headers=headers, json={
        "name": "Demo", "slug": "demo", "upstream_url": "http://demo.internal:3000",
        "qr_required": qr,
    })
    assert response.status_code == 201
    return response.json()


def test_project_and_policy_crud(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    response = browser.post(f"/api/projects/{project['id']}/policies", headers=headers, json={
        "type": "ip_blocklist", "name": "Bloqueios", "config": {"networks": ["203.0.113.0/24"]},
    })
    assert response.status_code == 201
    projects = browser.get("/api/projects", headers=headers).json()
    assert projects[0]["policies"][0]["config"]["networks"] == ["203.0.113.0/24"]

    invalid = browser.post(f"/api/projects/{project['id']}/policies", headers=headers, json={
        "type": "ip_blocklist", "name": "Inválida", "config": {"networks": ["not-an-ip"]},
    })
    assert invalid.status_code == 422


def test_security_report_aggregates_requests_and_suspicious_paths(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    common = {
        "method": "GET", "user_agent": "security-scanner", "country": "BR",
        "city": "Maceió", "latitude": -9.66, "longitude": -35.73,
    }
    app.state.store.audit(
        project["id"], "request", "allowed", "198.51.100.10",
        **common, path="/health", status=200, duration_ms=12.5,
    )
    app.state.store.audit(
        project["id"], "request", "denied", "198.51.100.20",
        **common, path="/.env", status=403, duration_ms=1.2, reason="ip_blocked",
    )

    response = browser.get(
        f"/api/reports?hours=24&project_id={project['id']}", headers=headers
    )
    assert response.status_code == 200
    report = response.json()
    assert report["kpis"]["requests"] == 2
    assert report["kpis"]["blocked"] == 1
    assert report["kpis"]["suspicious"] == 1
    assert report["suspicious_endpoints"] == [{"path": "/.env", "count": 1}]
    assert report["flows"][0]["coords"] == [-35.73, -9.66]


def test_browser_location_is_saved_in_an_opaque_project_cookie(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    response = browser.post(
        "/api/gate/demo/location",
        json={"latitude": -9.6658, "longitude": -35.7353, "accuracy": 18.4},
    )
    assert response.status_code == 200
    cookie_name = f"inlock_location_{project['id']}"
    opaque_token = browser.cookies[cookie_name]
    assert "httponly" in response.headers["set-cookie"].lower()
    saved = app.state.store.client_location(
        token_hash(opaque_token), project["id"], 0
    )
    assert saved["latitude"] == -9.6658
    assert saved["longitude"] == -35.7353
    assert saved["accuracy"] == 18.4


def test_browser_navigation_gets_location_gate_before_unprotected_upstream(client):
    browser, headers = client
    create_project(browser, headers, qr=False)
    response = browser.get(
        "/p/demo/private", headers={"accept": "text/html,application/xhtml+xml"}
    )
    assert response.status_code == 200
    assert "Confirme sua localização" in response.text
    assert 'data-location-slug="demo"' in response.text
    assert response.headers["permissions-policy"] == "geolocation=(self)"


def test_proprietary_login_mirrors_form_and_releases_project(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    browser.post("/api/gate/demo/location-declined")
    policy = browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={
            "type": "proprietary_login", "name": "Login corporativo",
            "config": {
                "login_url": "https://auth.internal/login",
                "success_url": "https://auth.internal/dashboard",
                "force_desktop": True,
            },
        },
    )
    assert policy.status_code == 201

    async def upstream(request: httpx.Request):
        if request.url == "https://auth.internal/login" and request.method == "GET":
            assert "Windows NT 10.0" in request.headers["user-agent"]
            assert "sec-ch-ua-mobile" not in request.headers
            return httpx.Response(
                200,
                text='<html><head><meta name="viewport" content="width=device-width"></head><body><form action="/session" method="post"><input name="user"></form></body></html>',
                headers={"content-type": "text/html", "set-cookie": "flow=abc; HttpOnly"},
            )
        if request.url == "https://auth.internal/session" and request.method == "POST":
            assert request.headers["cookie"] == "flow=abc"
            return httpx.Response(302, headers={"location": "/dashboard"})
        if request.url == "http://demo.internal:3000/private":
            assert request.headers["user-agent"] == "Mobile Browser Test"
            return httpx.Response(200, text="projeto liberado")
        return httpx.Response(404)

    old = app.state.http
    old_factory = app.state.proprietary_http_factory
    transport = httpx.MockTransport(upstream)
    app.state.http = httpx.AsyncClient(transport=transport)
    app.state.proprietary_http_factory = lambda: httpx.AsyncClient(transport=transport)
    try:
        started = browser.get(
            "/p/demo/private", headers={"accept": "text/html", "user-agent": "Mobile Browser Test"},
            follow_redirects=False,
        )
        assert started.status_code == 303
        mirrored = browser.get(started.headers["location"], headers={"user-agent": "Mobile Browser Test", "sec-ch-ua-mobile": "?1"})
        assert mirrored.status_code == 200
        assert "/auth/proprietary/" in mirrored.text
        assert '<meta name="viewport" content="width=1280">' in mirrored.text
        assert "width=device-width" not in mirrored.text
        action = re.search(r'action="([^"]+)"', mirrored.text).group(1)
        completed = browser.post(action, data={"user": "authorized"}, follow_redirects=False)
        assert completed.status_code == 303
        assert completed.headers["location"] == "/p/demo/private"
        released = browser.get("/p/demo/private", headers={"accept": "text/html", "user-agent": "Mobile Browser Test"})
        assert released.text == "projeto liberado"
    finally:
        app.state.http = old
        app.state.proprietary_http_factory = old_factory


def test_proprietary_login_follows_cross_origin_redirect_chain(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    browser.post("/api/gate/demo/location-declined")
    response = browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={
            "type": "proprietary_login", "name": "Login federado próprio",
            "config": {
                "login_url": "https://auth.internal/login",
                "success_url": "https://portal.internal/success",
            },
        },
    )
    assert response.status_code == 201

    async def upstream(request: httpx.Request):
        if request.url == "https://auth.internal/login":
            return httpx.Response(
                302, headers={
                    "location": "https://identity.internal/auth",
                    "set-cookie": "auth_flow=one; HttpOnly",
                },
            )
        if request.url == "https://identity.internal/auth":
            assert "cookie" not in request.headers
            return httpx.Response(
                302, headers={
                    "location": "https://portal.internal/success?ticket=ok",
                    "set-cookie": "identity_flow=two; HttpOnly",
                },
            )
        return httpx.Response(404)

    old = app.state.http
    old_factory = app.state.proprietary_http_factory
    transport = httpx.MockTransport(upstream)
    app.state.http = httpx.AsyncClient(transport=transport)
    app.state.proprietary_http_factory = lambda: httpx.AsyncClient(transport=transport)
    try:
        started = browser.get(
            "/p/demo/private", headers={"accept": "text/html"},
            follow_redirects=False,
        )
        first = browser.get(started.headers["location"], follow_redirects=False)
        assert first.status_code == 302
        assert first.headers["location"].startswith("/auth/proprietary/")
        second = browser.get(first.headers["location"], follow_redirects=False)
        assert second.status_code == 303
        assert second.headers["location"] == "/p/demo/private"
    finally:
        app.state.http = old
        app.state.proprietary_http_factory = old_factory


def test_proprietary_login_blocks_origin_not_discovered_by_auth_flow(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    browser.post("/api/gate/demo/location-declined")
    browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={
            "type": "proprietary_login", "name": "Login corporativo",
            "config": {
                "login_url": "https://auth.internal/login",
                "success_url": "https://portal.internal/success",
            },
        },
    )
    started = browser.get(
        "/p/demo/private", headers={"accept": "text/html"}, follow_redirects=False,
    )
    session_path = started.headers["location"].split("?", 1)[0]
    blocked = browser.get(
        session_path, params={"url": "https://unseen.example/steal"}
    )
    assert blocked.status_code == 403
    assert "fora da origem" in blocked.json()["detail"]


def test_responsive_inlock_login_mask_submits_selected_original_form(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    browser.post("/api/gate/demo/location-declined")
    policy = browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={
            "type": "proprietary_login", "name": "Login com máscara",
            "config": {
                "login_url": "https://auth.internal/login",
                "success_url": "https://auth.internal/home",
                "force_desktop": True, "login_mask": True,
                "username_selector_type": "id", "username_selector": "user-field",
                "password_selector_type": "xpath",
                "password_selector": "//input[@data-secret='main']",
                "submit_selector_type": "type", "submit_selector": "submit",
            },
        },
    )
    assert policy.status_code == 201

    async def auth_upstream(request: httpx.Request):
        if request.url == "https://auth.internal/login" and request.method == "GET":
            assert "Windows NT 10.0" in request.headers["user-agent"]
            return httpx.Response(200, text="""<html><body><form method="post" action="/session">
                <input type="hidden" name="csrf" value="token-123">
                <input id="user-field" name="corporate_user">
                <input data-secret="main" name="corporate_password" type="password">
                <button type="submit" name="operation" value="login">Login</button>
                </form></body></html>""", headers={"content-type": "text/html"})
        if request.url == "https://auth.internal/session" and request.method == "POST":
            assert dict(request.url.params) == {}
            values = dict(parse_qsl(request.content.decode()))
            assert values == {
                "csrf": "token-123", "operation": "login",
                "corporate_user": "maria", "corporate_password": "segredo",
            }
            return httpx.Response(302, headers={"location": "/home"})
        return httpx.Response(404)

    old_factory = app.state.proprietary_http_factory
    transport = httpx.MockTransport(auth_upstream)
    app.state.proprietary_http_factory = lambda: httpx.AsyncClient(transport=transport)
    try:
        started = browser.get(
            "/p/demo/private", headers={"accept": "text/html"}, follow_redirects=False,
        )
        assert started.status_code == 303
        assert started.headers["location"].endswith("/mask")
        mask = browser.get(started.headers["location"])
        assert mask.status_code == 200
        assert "Entre para" in mask.text
        assert 'name="inlock_username"' in mask.text
        completed = browser.post(
            started.headers["location"],
            data={"inlock_username": "maria", "inlock_password": "segredo"},
            follow_redirects=False,
        )
        assert completed.status_code == 303
        assert completed.headers["location"] == "/p/demo/private"
        assert f"inlock_proprietary_{project['id']}" in browser.cookies
    finally:
        app.state.proprietary_http_factory = old_factory


def test_container_project_is_rejected_when_direct_port_cannot_be_isolated(client):
    browser, headers = client

    class FailingFirewall:
        def reconcile(self, projects):
            return self.status()

        def status(self):
            return {
                "enabled": True, "available": False, "secure": False,
                "managed": True, "containers": ["abc"], "protected_ports": [],
                "loopback_ports": [], "error": "CAP_NET_ADMIN ausente",
            }

    app.state.firewall = FailingFirewall()
    response = browser.post("/api/projects", headers=headers, json={
        "name": "Exposto", "slug": "exposto", "upstream_url": "http://127.0.0.1:8088",
        "docker_container_id": "abc", "qr_required": True,
    })
    assert response.status_code == 503
    assert "não foi possível bloquear" in response.json()["detail"]
    assert browser.get("/api/projects", headers=headers).json() == []


def test_original_published_port_resolves_to_qr_gateway(client):
    browser, headers = client

    class RoutingFirewall:
        def reconcile(self, projects):
            return self.status()

        def status(self):
            return {
                "enabled": True, "available": True, "secure": True,
                "managed": True, "containers": ["website"],
                "protected_ports": ["tcp/8088"], "redirected_ports": ["tcp/8088"],
                "loopback_ports": [], "error": "",
            }

        def project_slug_for_port(self, port):
            return "website" if port == 8088 else None

    app.state.firewall = RoutingFirewall()
    response = browser.post("/api/projects", headers=headers, json={
        "name": "Website", "slug": "website", "upstream_url": "http://127.0.0.1:8088",
        "docker_container_id": "abc", "qr_required": True,
    })
    assert response.status_code == 201

    gate = browser.get("http://public.example:8088/")
    assert gate.status_code == 200
    assert 'data-slug="website"' in gate.text


def test_qr_token_rotation_and_browser_bound_approval(client):
    browser, headers = client
    project = create_project(browser, headers)
    gate = browser.get("/p/demo")
    assert gate.status_code == 200 and "data-slug=\"demo\"" in gate.text

    first = browser.post("/api/gate/demo/challenge").json()
    second = browser.post("/api/gate/demo/challenge").json()
    assert first["challenge_id"] != second["challenge_id"]
    assert browser.get(f"/api/gate/challenges/{first['challenge_id']}").json()["state"] == "superseded"

    token = second["qr_url"].removeprefix("/gate/qr/").removesuffix(".svg")
    svg = browser.get(second["qr_url"])
    assert svg.status_code == 200 and "svg" in svg.text
    approval = browser.post("/gate/approve", data={"token": token})
    assert approval.status_code == 200 and "Tudo certo" in approval.text

    bound_cookie = browser.cookies.get("inlock_browser")
    browser.cookies.delete("inlock_browser")
    missing = browser.get(f"/api/gate/challenges/{second['challenge_id']}")
    assert missing.status_code == 404
    browser.cookies.set("inlock_browser", bound_cookie)

    status = browser.get(f"/api/gate/challenges/{second['challenge_id']}")
    assert status.json()["state"] == "approved"
    assert f"inlock_access_{project['id']}" in browser.cookies


def test_totem_mode_opens_app_on_mobile_without_releasing_original_browser(client):
    browser, headers = client
    created = browser.post("/api/projects", headers=headers, json={
        "name": "Totem", "slug": "totem", "upstream_url": "http://demo.internal:3000",
        "qr_required": False, "qr_totem_mode": True,
    })
    assert created.status_code == 201
    project = created.json()
    assert project["qr_required"] and project["qr_totem_mode"]

    gate = browser.get("/p/totem/mobile/welcome?campaign=qr")
    assert 'data-mode="totem"' in gate.text
    challenge = browser.post(
        "/api/gate/totem/challenge",
        params={"return_path": "/p/totem/mobile/welcome?campaign=qr"},
    ).json()
    assert challenge["mode"] == "totem"
    token = challenge["qr_url"].split("/")[-1].removesuffix(".svg")

    approval = browser.get("/gate/approve", params={"token": token}, follow_redirects=False)
    assert approval.status_code == 200
    assert "Compartilhe sua localização" in approval.text
    assert 'data-location-slug="totem"' in approval.text
    assert browser.post("/api/gate/totem/location", json={
        "latitude": -9.6658, "longitude": -35.7353, "accuracy": 12,
    }).status_code == 200
    opened = browser.post("/gate/approve", data={"token": token}, follow_redirects=False)
    assert opened.status_code == 303
    assert opened.headers["location"] == "/p/totem/mobile/welcome?campaign=qr"
    access_cookie = f"inlock_access_{project['id']}"
    assert access_cookie in browser.cookies

    browser.cookies.delete(access_cookie)
    status = browser.get(f"/api/gate/challenges/{challenge['challenge_id']}")
    assert status.json()["state"] == "mobile_opened"
    assert access_cookie not in status.headers.get("set-cookie", "")


def test_proxy_after_qr_approval(client):
    browser, headers = client
    create_project(browser, headers)
    challenge = browser.post("/api/gate/demo/challenge").json()
    token = challenge["qr_url"].split("/")[-1].removesuffix(".svg")
    browser.post("/gate/approve", data={"token": token})
    browser.get(f"/api/gate/challenges/{challenge['challenge_id']}")

    async def upstream(request: httpx.Request):
        return httpx.Response(200, text=f"upstream:{request.url.path}")

    old = app.state.http
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    try:
        response = browser.get("/p/demo/private/dashboard")
        assert response.status_code == 200
        assert response.text == "upstream:/private/dashboard"
        assert "content-length" not in response.headers
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old


def test_proxy_preserves_streaming_response(client):
    browser, headers = client
    create_project(browser, headers, qr=False)

    class ChunkedBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"type":"status"}\n'
            yield b'{"type":"done"}\n'

    async def upstream(request: httpx.Request):
        assert request.extensions["timeout"]["read"] is None
        return httpx.Response(
            200,
            headers={
                "content-type": "application/x-ndjson; charset=utf-8",
                "x-accel-buffering": "no",
            },
            stream=ChunkedBody(),
        )

    old = app.state.http
    app.state.http = httpx.AsyncClient(
        transport=httpx.MockTransport(upstream),
        timeout=httpx.Timeout(30, read=None),
    )
    try:
        response = browser.post("/p/demo/api/ask/stream", content=b"{}")
        assert response.status_code == 200
        assert response.content == b'{"type":"status"}\n{"type":"done"}\n'
        assert response.headers["content-type"] == "application/x-ndjson; charset=utf-8"
        assert response.headers["x-accel-buffering"] == "no"
        assert "content-length" not in response.headers
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old


def test_public_host_proxies_path_that_collides_with_admin_api(client):
    browser, headers = client
    created = browser.post("/api/projects", headers=headers, json={
        "name": "Journey", "slug": "journey",
        "upstream_url": "http://journey.internal:4397",
        "public_host": "journey.example",
        "qr_required": False,
    })
    assert created.status_code == 201

    async def upstream(request: httpx.Request):
        assert request.url == "http://journey.internal:4397/api/projects"
        assert request.method == "POST"
        assert json.loads(request.content) == {"name": "Projeto do Estudio"}
        return httpx.Response(201, json={"id": 42, "name": "Projeto do Estudio"})

    old = app.state.http
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    try:
        response = browser.post(
            "http://journey.example/api/projects",
            json={"name": "Projeto do Estudio"},
        )
        assert response.status_code == 201
        assert response.json() == {"id": 42, "name": "Projeto do Estudio"}
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old


def test_bot_score_visual_challenge_releases_only_the_verified_browser(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    policy = browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={"type": "bot_score", "name": "Anti-bot", "config": {"threshold": 65}},
    )
    assert policy.status_code == 201

    challenged = browser.get(
        "/p/demo/private/dashboard?from=captcha",
        headers={"user-agent": "curl/8.12.0", "accept": "*/*"},
    )
    assert challenged.status_code == 200
    assert "NAVEGAÇÃO SUSPEITA" in challenged.text
    challenge_id = re.search(r'data-challenge="([^"]+)"', challenged.text).group(1)

    image = browser.get(f"/gate/captcha/{challenge_id}.png")
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/png"

    challenge = app.state.store.captcha(challenge_id)
    payload = challenge["payload"]
    correct = [
        str(index) for index, cell in enumerate(payload["cells"])
        if cell["shape"] == payload["target_shape"]
        and cell["color"] == payload["target_color"]
    ]
    solved = browser.post(
        "/gate/captcha/verify", follow_redirects=False,
        data={"challenge_id": challenge_id, "selected": ",".join(correct)},
    )
    assert solved.status_code == 303
    assert solved.headers["location"] == "/p/demo/private/dashboard?from=captcha"
    assert f"inlock_human_{project['id']}" in browser.cookies

    async def upstream(request: httpx.Request):
        return httpx.Response(200, text=f"human:{request.url.path}")

    old = app.state.http
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    try:
        released = browser.get(
            solved.headers["location"], headers={"user-agent": "curl/8.12.0"},
        )
        assert released.status_code == 200
        assert released.text == "human:/private/dashboard"
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old


def test_bot_score_progressive_javascript_probe_allows_browser_like_session(client):
    browser, headers = client
    project = create_project(browser, headers, qr=False)
    policy = browser.post(
        f"/api/projects/{project['id']}/policies", headers=headers,
        json={"type": "bot_score", "name": "Anti-bot", "config": {"threshold": 65}},
    )
    assert policy.status_code == 201
    browser_headers = {
        "user-agent": "Mozilla/5.0 Chrome/126.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml",
        "accept-language": "pt-BR,pt;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "sec-fetch-site": "none",
        "sec-ch-ua": '"Chromium";v="126"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
    }

    probe_page = browser.get("/p/demo/welcome", headers=browser_headers)
    assert probe_page.status_code == 200
    assert "DESAFIO PROGRESSIVO" in probe_page.text
    probe_id = re.search(r'data-probe="([^"]+)"', probe_page.text).group(1)
    telemetry = {
        "js": True, "webdriver": False, "automation": False, "elapsed": 1800,
        "trustedClick": True, "pointerMoves": 3, "pointerEvents": 1,
        "cookieEnabled": True, "storage": True, "languages": 2, "plugins": 3,
        "screenWidth": 1920, "screenHeight": 1080, "visibility": "visible",
    }
    verified = browser.post(
        "/gate/probe/verify", headers=browser_headers, follow_redirects=False,
        data={"probe_id": probe_id, "telemetry": json.dumps(telemetry)},
    )
    assert verified.status_code == 303
    assert verified.headers["location"] == "/p/demo/welcome"
    assert f"inlock_bot_proof_{project['id']}" in browser.cookies

    async def upstream(request: httpx.Request):
        return httpx.Response(200, text="browser verified")

    old = app.state.http
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    try:
        released = browser.get("/p/demo/welcome", headers=browser_headers)
        assert released.status_code == 200
        assert "Confirme sua localização" in released.text
        location = browser.post(
            "/api/gate/demo/location",
            json={"latitude": -9.66, "longitude": -35.73, "accuracy": 20},
        )
        assert location.status_code == 200
        released = browser.get("/p/demo/welcome", headers=browser_headers)
        assert released.text == "browser verified"
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old
