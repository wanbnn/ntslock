from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import inlock.main as main_module
from inlock.config import Settings
from inlock.main import app
from inlock.policies import PolicyEngine
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
    finally:
        browser.portal.call(app.state.http.aclose)
        app.state.http = old
