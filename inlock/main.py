from __future__ import annotations

import asyncio
import io
import ipaddress
import sqlite3
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from urllib.parse import quote

import httpx
import qrcode
import qrcode.image.svg
import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import Settings, get_settings
from .container_firewall import ContainerFirewall
from .docker_discovery import discover_containers
from .policies import Decision, PolicyEngine
from .schemas import PolicyCreate, ProjectCreate, ProjectUpdate
from .security import (
    browser_hash,
    client_ip,
    random_token,
    require_admin,
    sign_access,
    token_hash,
    verify_access,
)
from .store import Store
from .ui import approval_html, approved_html, dashboard_html, gate_html

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.settings = settings
    app.state.store = Store(settings.database_path)
    app.state.engine = PolicyEngine(settings.geoip_city_db)
    app.state.firewall = ContainerFirewall(
        settings.docker_url, enabled=settings.enforce_container_isolation
    )
    await asyncio.to_thread(app.state.firewall.reconcile, app.state.store.projects())
    app.state.http = httpx.AsyncClient(follow_redirects=False, timeout=30)

    async def monitor_containers() -> None:
        while True:
            await asyncio.sleep(max(2, settings.container_reconcile_seconds))
            await asyncio.to_thread(app.state.firewall.reconcile, app.state.store.projects())

    monitor = asyncio.create_task(monitor_containers(), name="inlock-container-monitor")
    try:
        yield
    finally:
        monitor.cancel()
        with suppress(asyncio.CancelledError):
            await monitor
        await app.state.http.aclose()


app = FastAPI(
    title="Inlock", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def store(request: Request) -> Store:
    return request.app.state.store


def settings(request: Request) -> Settings:
    return request.app.state.settings


def admin(request: Request) -> None:
    require_admin(request, settings(request).admin_token)


def request_project(request: Request) -> dict | None:
    host = request.url.hostname or ""
    project = store(request).project_by_host(host)
    if project:
        return project
    incoming_port = request.url.port or (443 if request.url.scheme == "https" else 80)
    slug = request.app.state.firewall.project_slug_for_port(incoming_port)
    return store(request).project_by_slug(slug) if slug else None


async def reconcile_isolation(request: Request) -> dict:
    return await asyncio.to_thread(
        request.app.state.firewall.reconcile, store(request).projects()
    )


def _validate_policy(payload: PolicyCreate) -> None:
    config = payload.config
    if payload.type in {"ip_allowlist", "ip_blocklist"}:
        networks = config.get("networks", [])
        if not isinstance(networks, list):
            raise HTTPException(422, "config.networks deve ser uma lista de IPs ou CIDRs")
        try:
            for network in networks:
                ipaddress.ip_network(network, strict=False)
        except (TypeError, ValueError):
            raise HTTPException(422, "config.networks contém um IP ou CIDR inválido") from None
    if payload.type == "rate_limit":
        try:
            valid_numbers = int(config.get("limit", 60)) >= 1 and int(config.get("window_seconds", 60)) >= 1
        except (TypeError, ValueError):
            valid_numbers = False
        if not valid_numbers:
            raise HTTPException(422, "limit e window_seconds devem ser positivos")
        if config.get("scope", "ip") not in {"ip", "global"}:
            raise HTTPException(422, "scope deve ser ip ou global")
    if payload.type == "user_agent" and not isinstance(config.get("patterns", []), list):
        raise HTTPException(422, "config.patterns deve ser uma lista")
    if payload.type == "geo":
        radius = config.get("radius")
        if radius and not all(key in radius for key in ("latitude", "longitude", "kilometers")):
            raise HTTPException(422, "radius requer latitude, longitude e kilometers")
        if radius:
            try:
                latitude = float(radius["latitude"])
                longitude = float(radius["longitude"])
                kilometers = float(radius["kilometers"])
            except (TypeError, ValueError):
                raise HTTPException(422, "radius contém valores inválidos") from None
            if not -90 <= latitude <= 90 or not -180 <= longitude <= 180 or kilometers <= 0:
                raise HTTPException(422, "latitude, longitude ou raio fora dos limites")


@app.get("/health", include_in_schema=False)
async def health(request: Request):
    docker_available = discover_containers(settings(request).docker_url)["available"]
    isolation = request.app.state.firewall.status()
    healthy = docker_available and (not isolation["managed"] or isolation["secure"])
    return {
        "status": "ok" if healthy else "degraded",
        "version": app.version,
        "docker": docker_available,
        "container_isolation": isolation,
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home(request: Request):
    host = request.url.hostname or ""
    project = request_project(request)
    if project and (not settings(request).admin_host or host != settings(request).admin_host):
        return await proxy_request(request, project, "")
    return HTMLResponse(dashboard_html(settings(request).tile_url))


@app.get("/api/summary", dependencies=[Depends(admin)])
async def summary(request: Request):
    projects = store(request).projects()
    docker = discover_containers(settings(request).docker_url)
    events = store(request).events(100)
    return {
        "projects": len(projects),
        "protected": sum(1 for item in projects if item["enabled"]),
        "containers": len(docker["containers"]),
        "blocked": sum(1 for event in events if event["outcome"] == "denied"),
        "docker_available": docker["available"],
        "isolation": request.app.state.firewall.status(),
    }


@app.get("/api/projects", dependencies=[Depends(admin)])
async def list_projects(request: Request):
    isolation = request.app.state.firewall.status()
    result = []
    for project in store(request).projects():
        project["policies"] = store(request).policies(project["id"])
        project["isolation"] = (
            "protected" if project["docker_container_id"] and isolation["secure"]
            else "unmanaged" if not project["docker_container_id"]
            else "error"
        )
        result.append(project)
    return result


@app.post("/api/projects", status_code=201, dependencies=[Depends(admin)])
async def create_project(payload: ProjectCreate, request: Request):
    try:
        project = store(request).create_project(payload.model_dump())
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Já existe um projeto com este slug") from None
    isolation = await reconcile_isolation(request)
    if project["docker_container_id"] and not isolation["secure"]:
        store(request).audit(
            project["id"], "container.isolation", "denied", error=isolation["error"]
        )
        store(request).delete_project(project["id"])
        await reconcile_isolation(request)
        raise HTTPException(
            503,
            f"Projeto não ativado: não foi possível bloquear a exposição direta do container ({isolation['error']})",
        )
    store(request).audit(project["id"], "project.created", "success", name=project["name"])
    return project


@app.patch("/api/projects/{project_id}", dependencies=[Depends(admin)])
async def update_project(project_id: int, payload: ProjectUpdate, request: Request):
    current = store(request).project(project_id)
    if not current:
        raise HTTPException(404, "Projeto não encontrado")
    changes = payload.model_dump(exclude_unset=True)
    validated = ProjectCreate.model_validate({**current, **changes}).model_dump()
    try:
        project = store(request).update_project(project_id, validated)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Já existe um projeto com este slug") from None
    isolation = await reconcile_isolation(request)
    if project["docker_container_id"] and not isolation["secure"]:
        store(request).audit(
            project_id, "container.isolation", "denied", error=isolation["error"]
        )
        store(request).update_project(project_id, current)
        await reconcile_isolation(request)
        raise HTTPException(
            503,
            f"Alteração revertida: não foi possível isolar o container ({isolation['error']})",
        )
    store(request).audit(project_id, "project.updated", "success", fields=list(changes))
    return project


@app.delete("/api/projects/{project_id}", status_code=204, dependencies=[Depends(admin)])
async def delete_project(project_id: int, request: Request):
    if not store(request).delete_project(project_id):
        raise HTTPException(404, "Projeto não encontrado")
    await reconcile_isolation(request)
    return Response(status_code=204)


@app.get("/api/projects/{project_id}/policies", dependencies=[Depends(admin)])
async def list_policies(project_id: int, request: Request):
    if not store(request).project(project_id):
        raise HTTPException(404, "Projeto não encontrado")
    return store(request).policies(project_id)


@app.post("/api/projects/{project_id}/policies", status_code=201, dependencies=[Depends(admin)])
async def create_policy(project_id: int, payload: PolicyCreate, request: Request):
    if not store(request).project(project_id):
        raise HTTPException(404, "Projeto não encontrado")
    _validate_policy(payload)
    policy = store(request).create_policy(project_id, payload.model_dump())
    store(request).audit(project_id, "policy.created", "success", type=policy["type"])
    return policy


@app.delete("/api/policies/{policy_id}", status_code=204, dependencies=[Depends(admin)])
async def delete_policy(policy_id: int, request: Request):
    if not store(request).delete_policy(policy_id):
        raise HTTPException(404, "Política não encontrada")
    return Response(status_code=204)


@app.get("/api/containers", dependencies=[Depends(admin)])
async def containers(request: Request):
    return discover_containers(settings(request).docker_url)


@app.get("/api/events", dependencies=[Depends(admin)])
async def events(request: Request, limit: int = 50):
    return store(request).events(min(max(limit, 1), 250))


@app.post("/api/gate/{slug}/challenge", include_in_schema=False)
async def create_challenge(slug: str, request: Request):
    project = store(request).project_by_slug(slug)
    if not project or not project["enabled"] or not project["qr_required"]:
        raise HTTPException(404, "Desafio indisponível")
    config = settings(request)
    browser_secret = request.cookies.get("inlock_browser") or random_token()
    now = int(time.time())
    challenge_id = random_token(18)
    opaque_token = random_token(32)
    store(request).prune_challenges(now - 300)
    store(request).save_challenge({
        "id": challenge_id,
        "project_id": project["id"],
        "browser_hash": browser_hash(browser_secret, config.secret_key),
        "token_hash": token_hash(opaque_token),
        "expires_at": now + config.qr_ttl_seconds,
        "created_at": now,
    })
    response = JSONResponse({
        "challenge_id": challenge_id,
        "qr_url": f"/gate/qr/{quote(opaque_token)}.svg",
        "expires_in": config.qr_ttl_seconds,
    })
    response.set_cookie(
        "inlock_browser", browser_secret, max_age=86400, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


@app.get("/gate/qr/{opaque_token}.svg", name="gate_qr", include_in_schema=False)
async def gate_qr(opaque_token: str, request: Request):
    challenge = store(request).challenge_by_token_hash(token_hash(opaque_token))
    if not challenge or challenge["state"] != "pending" or challenge["expires_at"] < int(time.time()):
        raise HTTPException(410, "QR Code expirado")
    approve_url = str(request.url_for("approve_gate")) + f"?token={quote(opaque_token)}"
    image = qrcode.make(approve_url, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    output = io.BytesIO()
    image.save(output)
    return Response(output.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.get("/gate/approve", name="approve_gate", response_class=HTMLResponse, include_in_schema=False)
async def approve_gate(request: Request, token: str):
    challenge = store(request).challenge_by_token_hash(token_hash(token))
    if not challenge:
        return HTMLResponse(approval_html(token, "Acesso protegido", True), 410)
    project = store(request).project(challenge["project_id"])
    expired = challenge["state"] != "pending" or challenge["expires_at"] < int(time.time())
    return HTMLResponse(approval_html(token, project["name"] if project else "Acesso protegido", expired), 410 if expired else 200)


@app.post("/gate/approve", response_class=HTMLResponse, include_in_schema=False)
async def confirm_gate(request: Request, token: str = Form(...)):
    now = int(time.time())
    challenge = store(request).challenge_by_token_hash(token_hash(token))
    if not challenge or not store(request).approve_challenge(challenge["id"], now):
        return HTMLResponse(approval_html(token, "Acesso protegido", True), 410)
    ip = client_ip(request, settings(request).trusted_proxies)
    store(request).audit(challenge["project_id"], "qr.approved", "success", ip)
    return HTMLResponse(approved_html())


@app.get("/api/gate/challenges/{challenge_id}", include_in_schema=False)
async def challenge_status(challenge_id: str, request: Request):
    challenge = store(request).challenge(challenge_id)
    browser_secret = request.cookies.get("inlock_browser", "")
    config = settings(request)
    if not challenge or not browser_secret or not __import__("hmac").compare_digest(
        challenge["browser_hash"], browser_hash(browser_secret, config.secret_key)
    ):
        raise HTTPException(404, "Desafio não encontrado")
    if challenge["expires_at"] < int(time.time()) and challenge["state"] == "pending":
        return {"state": "expired"}
    response = JSONResponse({"state": challenge["state"]})
    if challenge["state"] == "approved":
        response.set_cookie(
            f"inlock_access_{challenge['project_id']}",
            sign_access(challenge["project_id"], config.secret_key, config.access_ttl_seconds),
            max_age=config.access_ttl_seconds, httponly=True, secure=config.secure_cookies,
            samesite="lax", path="/",
        )
    return response


@app.api_route("/p/{slug}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
@app.api_route("/p/{slug}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
async def proxy_by_slug(slug: str, request: Request, path: str = ""):
    project = store(request).project_by_slug(slug)
    if not project or not project["enabled"]:
        raise HTTPException(404, "Projeto não encontrado ou desativado")
    return await proxy_request(request, project, path)


async def proxy_request(request: Request, project: dict, path: str):
    config = settings(request)
    ip = client_ip(request, config.trusted_proxies)
    decision: Decision = await request.app.state.engine.evaluate(
        project, store(request).policies(project["id"]), ip, request.headers.get("user-agent", "")
    )
    if not decision.allowed:
        store(request).audit(project["id"], "request", "denied", ip, reason=decision.reason, policy_id=decision.policy_id)
        headers = {"Retry-After": str(decision.retry_after)} if decision.retry_after else None
        return JSONResponse({"detail": "Acesso negado", "reason": decision.reason}, 429 if decision.reason == "rate_limited" else 403, headers=headers)
    if project["qr_required"]:
        access = request.cookies.get(f"inlock_access_{project['id']}", "")
        if not verify_access(access, project["id"], config.secret_key):
            return HTMLResponse(gate_html(project), headers={"Cache-Control": "no-store"})
    query = f"?{request.url.query}" if request.url.query else ""
    url = f"{project['upstream_url']}/{path}{query}"
    headers = {key: value for key, value in request.headers.items() if key.lower() not in HOP_BY_HOP and key.lower() != "cookie"}
    cookies = [part.strip() for part in request.headers.get("cookie", "").split(";") if part.strip() and not part.strip().startswith("inlock_")]
    if cookies:
        headers["cookie"] = "; ".join(cookies)
    headers["x-forwarded-for"] = ip
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-host"] = request.headers.get("host", "")
    try:
        upstream = await request.app.state.http.request(
            request.method, url, headers=headers, content=await request.body(),
        )
    except httpx.RequestError as exc:
        store(request).audit(project["id"], "proxy", "error", ip, error=type(exc).__name__)
        return JSONResponse({"detail": "Upstream indisponível"}, 502)
    response = Response(upstream.content, status_code=upstream.status_code)
    for key, value in upstream.headers.multi_items():
        if key.lower() not in HOP_BY_HOP:
            response.headers.append(key, value)
    store(request).audit(project["id"], "request", "allowed", ip, status=upstream.status_code)
    return response


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
async def proxy_by_host(path: str, request: Request):
    project = request_project(request)
    if not project:
        raise HTTPException(404, "Rota não encontrada")
    return await proxy_request(request, project, path)


def run() -> None:
    uvicorn.run("inlock.main:app", host="0.0.0.0", port=14900)


if __name__ == "__main__":
    run()
