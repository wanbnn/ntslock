from __future__ import annotations

import asyncio
import hmac
import io
import ipaddress
import re
import sqlite3
import time
from collections import Counter, defaultdict
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlparse

import httpx
import qrcode
import qrcode.image.svg
import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from .bot_defense import (
    behavior_score,
    parse_telemetry,
    request_fingerprint,
    tls_fingerprint,
)
from .captcha import create_visual_challenge, render_visual_challenge
from .config import Settings, get_settings
from .container_firewall import ContainerFirewall
from .docker_discovery import discover_containers
from .policies import Decision, PolicyEngine
from .schemas import LocationCapture, PolicyCreate, ProjectCreate, ProjectUpdate
from .security import (
    browser_hash,
    client_ip,
    random_token,
    require_admin,
    sign_access,
    sign_bot_proof,
    token_hash,
    verify_access,
    verify_bot_proof,
)
from .store import Store
from .ui import (
    approval_html,
    approved_html,
    browser_probe_html,
    captcha_html,
    dashboard_html,
    gate_html,
    location_consent_html,
)

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}
PUBLIC_GATEWAY_PATHS = ("/static", "/api/gate", "/gate", "/auth")
DESKTOP_LOGIN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.settings = settings
    app.state.store = Store(settings.database_path)
    app.state.engine = PolicyEngine(settings.geoip_city_db)
    app.state.proprietary_login_sessions = {}
    app.state.proprietary_http_factory = lambda: httpx.AsyncClient(
        follow_redirects=False, timeout=httpx.Timeout(30)
    )
    app.state.firewall = ContainerFirewall(
        settings.docker_url, enabled=settings.enforce_container_isolation
    )
    await asyncio.to_thread(app.state.firewall.reconcile, app.state.store.projects())
    app.state.http = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(30, read=None),
    )

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
        for session in app.state.proprietary_login_sessions.values():
            await session["http"].aclose()


app = FastAPI(
    title="Inlock", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def _is_public_gateway_path(path: str) -> bool:
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in PUBLIC_GATEWAY_PATHS)


@app.middleware("http")
async def proxy_public_host(request: Request, call_next):
    """Prioriza o upstream em hosts públicos antes das rotas administrativas.

    FastAPI resolve rotas explícitas como /api/projects antes do catch-all no
    fim deste módulo. Sem esta decisão por host, APIs homônimas da aplicação
    protegida acabam tratadas pelo painel administrativo do Inlock.
    """
    project = request_project(request)
    config = settings(request)
    host = (request.url.hostname or "").lower()
    admin_host = config.admin_host.strip().lower()
    if (
        project
        and (not admin_host or host != admin_host)
        and not _is_public_gateway_path(request.url.path)
    ):
        return await proxy_request(request, project, request.url.path.lstrip("/"))
    return await call_next(request)


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
    resolver = getattr(request.app.state.firewall, "project_slug_for_port", None)
    slug = resolver(incoming_port) if resolver else None
    return store(request).project_by_slug(slug) if slug else None


async def reconcile_isolation(request: Request) -> dict:
    return await asyncio.to_thread(
        request.app.state.firewall.reconcile, store(request).projects()
    )


def request_return_path(request: Request) -> str:
    path = request.url.path
    return f"{path}?{request.url.query}" if request.url.query else path


def captcha_answer_hash(challenge_id: str, selected: str) -> str:
    try:
        indexes = sorted({int(value) for value in selected.split(",") if value != ""})
    except ValueError:
        indexes = []
    if any(index < 0 or index > 8 for index in indexes):
        indexes = []
    return token_hash(f"{challenge_id}:{','.join(map(str, indexes))}")


def human_challenge_response(
    request: Request, project: dict, return_path: str, bot_score: int
) -> HTMLResponse:
    config = settings(request)
    browser_secret = request.cookies.get("inlock_human_browser") or random_token()
    challenge_id = random_token(18)
    payload, answer = create_visual_challenge()
    now = int(time.time())
    store(request).save_captcha({
        "id": challenge_id,
        "project_id": project["id"],
        "browser_hash": browser_hash(browser_secret, config.secret_key),
        "answer_hash": captcha_answer_hash(challenge_id, ",".join(map(str, answer))),
        "payload": payload,
        "return_path": return_path,
        "expires_at": now + config.captcha_ttl_seconds,
        "created_at": now,
    })
    store(request).audit(
        project["id"], "bot.challenge", "challenged",
        client_ip(request, config.trusted_proxies), score=bot_score,
    )
    response = HTMLResponse(
        captcha_html(project, challenge_id, payload["target_label"]),
        headers={"Cache-Control": "no-store"},
    )
    response.set_cookie(
        "inlock_human_browser", browser_secret, max_age=config.captcha_ttl_seconds,
        httponly=True, secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


def browser_probe_response(
    request: Request, project: dict, return_path: str, preliminary_score: int
) -> HTMLResponse:
    config = settings(request)
    browser_secret = request.cookies.get("inlock_probe_browser") or random_token()
    probe_id = random_token(18)
    created_at = time.time()
    now = int(created_at)
    store(request).save_browser_probe({
        "id": probe_id,
        "project_id": project["id"],
        "browser_hash": browser_hash(browser_secret, config.secret_key),
        "return_path": return_path,
        "expires_at": now + config.browser_probe_ttl_seconds,
        "created_at": created_at,
    })
    store(request).audit(
        project["id"], "bot.probe", "required",
        client_ip(request, config.trusted_proxies), preliminary_score=preliminary_score,
    )
    response = HTMLResponse(
        browser_probe_html(project, probe_id), headers={"Cache-Control": "no-store"}
    )
    response.set_cookie(
        "inlock_probe_browser", browser_secret,
        max_age=config.browser_proof_ttl_seconds, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


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
    if payload.type == "bot_score":
        try:
            threshold = int(config.get("threshold", 65))
        except (TypeError, ValueError):
            raise HTTPException(422, "threshold deve ser um número entre 0 e 100") from None
        if not 0 <= threshold <= 100:
            raise HTTPException(422, "threshold deve estar entre 0 e 100")
    if payload.type == "proprietary_login":
        login_url = str(config.get("login_url", ""))
        success_url = str(config.get("success_url", ""))
        login = urlparse(login_url)
        success = urlparse(success_url)
        if (
            login.scheme not in {"http", "https"} or not login.hostname
            or success.scheme not in {"http", "https"} or not success.hostname
        ):
            raise HTTPException(422, "login_url e success_url devem ser URLs HTTP(S)")
        if login.username or login.password or success.username or success.password:
            raise HTTPException(422, "URLs de autenticação não podem conter credenciais")
        if not isinstance(config.get("force_desktop", False), bool):
            raise HTTPException(422, "force_desktop deve ser verdadeiro ou falso")


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


def _same_origin(first: str, second: str) -> bool:
    left, right = urlparse(first), urlparse(second)
    return (left.scheme, left.hostname, left.port) == (
        right.scheme, right.hostname, right.port
    )


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _auth_proxy_url(session_id: str, target: str) -> str:
    return f"/auth/proprietary/{session_id}?url={quote(target, safe='')}"


def _matches_auth_success(target: str, success_url: str) -> bool:
    current, success = urlparse(target), urlparse(success_url)
    if not _same_origin(target, success_url):
        return False
    success_path = success.path.rstrip("/") or "/"
    return (
        current.path == success_path
        or (success_path != "/" and current.path.startswith(f"{success_path}/"))
    )


def _rewrite_login_html(
    content: str, base_url: str, session_id: str, session: dict,
    force_desktop: bool = False,
) -> str:
    def replace_attribute(match: re.Match) -> str:
        name, quote_char, value = match.group(1), match.group(2), match.group(3)
        if value.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
            return match.group(0)
        target = urljoin(base_url, value)
        target_origin = _origin(target)
        if not target_origin:
            return f'{name}={quote_char}#{quote_char}'
        session["allowed_origins"].add(target_origin)
        return f"{name}={quote_char}{_auth_proxy_url(session_id, target)}{quote_char}"

    content = re.sub(
        r"\b(href|src|action)=([\"'])(.*?)(?:\2)", replace_attribute,
        content, flags=re.IGNORECASE,
    )

    def replace_css(match: re.Match) -> str:
        raw = match.group(1).strip(" \t\"'")
        if raw.startswith(("data:", "#")):
            return match.group(0)
        target = urljoin(base_url, raw)
        target_origin = _origin(target)
        if not target_origin:
            return "url('')"
        session["allowed_origins"].add(target_origin)
        return f"url('{_auth_proxy_url(session_id, target)}')"

    content = re.sub(r"url\(([^)]+)\)", replace_css, content, flags=re.IGNORECASE)
    if force_desktop:
        content = re.sub(
            r"<meta\b(?=[^>]*\bname\s*=\s*([\"'])viewport\1)[^>]*>",
            "", content, flags=re.IGNORECASE,
        )
        desktop_viewport = '<meta name="viewport" content="width=1280">'
        if re.search(r"<head\b[^>]*>", content, flags=re.IGNORECASE):
            content = re.sub(
                r"(<head\b[^>]*>)", rf"\1{desktop_viewport}", content,
                count=1, flags=re.IGNORECASE,
            )
        else:
            content = desktop_viewport + content
    return content


def _auth_session(request: Request, session_id: str) -> dict:
    session = request.app.state.proprietary_login_sessions.get(session_id)
    browser_secret = request.cookies.get("inlock_proprietary_browser", "")
    if (
        not session or session["expires_at"] < int(time.time()) or not browser_secret
        or not hmac.compare_digest(
            session["browser_hash"],
            browser_hash(browser_secret, settings(request).secret_key),
        )
    ):
        raise HTTPException(410, "Sessão de autenticação expirada")
    return session


async def _complete_proprietary_login(
    request: Request, session_id: str, session: dict
) -> RedirectResponse:
    project = store(request).project(session["project_id"])
    if not project:
        raise HTTPException(404, "Projeto não encontrado")
    request.app.state.proprietary_login_sessions.pop(session_id, None)
    await session["http"].aclose()
    config = settings(request)
    response = RedirectResponse(session["return_path"], status_code=303)
    response.set_cookie(
        f"inlock_proprietary_{project['id']}",
        sign_access(project["id"], config.secret_key, config.access_ttl_seconds),
        max_age=config.access_ttl_seconds, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    store(request).audit(
        project["id"], "proprietary_login", "success",
        client_ip(request, config.trusted_proxies),
    )
    return response


@app.api_route(
    "/auth/proprietary/{session_id}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    include_in_schema=False,
)
async def proprietary_login_proxy(session_id: str, request: Request):
    session = _auth_session(request, session_id)
    target = unquote(request.query_params.get("url", ""))
    target_origin = _origin(target)
    if not target_origin or target_origin not in session["allowed_origins"]:
        raise HTTPException(403, "Destino fora da origem de autenticação autorizada")

    headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP
        and key.lower() not in {"cookie", "authorization", "origin", "referer"}
    }
    if session["force_desktop"]:
        headers["user-agent"] = DESKTOP_LOGIN_USER_AGENT
        for client_hint in (
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "viewport-width", "sec-ch-viewport-width",
        ):
            headers.pop(client_hint, None)
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if request.method not in {"GET", "HEAD"}:
        headers["origin"] = origin
    headers["referer"] = session.get("last_url") or session["login_url"]
    auth_http: httpx.AsyncClient = session["http"]
    upstream_request = auth_http.build_request(
        request.method, target, headers=headers, content=await request.body(),
    )
    try:
        upstream = await auth_http.send(upstream_request, stream=False)
    except httpx.RequestError:
        raise HTTPException(502, "Página de autenticação indisponível") from None

    session["last_url"] = str(upstream.url)

    location = upstream.headers.get("location")
    if location:
        redirect_target = urljoin(target, location)
        redirect_origin = _origin(redirect_target)
        if not redirect_origin:
            raise HTTPException(403, "Protocolo de redirecionamento bloqueado")
        session["allowed_origins"].add(redirect_origin)
        if _matches_auth_success(redirect_target, session["success_url"]):
            return await _complete_proprietary_login(request, session_id, session)
        return RedirectResponse(
            _auth_proxy_url(session_id, redirect_target), upstream.status_code
        )

    response_headers = {
        key: value for key, value in upstream.headers.items()
        if key.lower() not in HOP_BY_HOP
        and key.lower() not in {"set-cookie", "content-security-policy", "content-encoding"}
    }
    media_type = upstream.headers.get("content-type", "")
    body = upstream.content
    if "text/html" in media_type:
        body = _rewrite_login_html(
            upstream.text, target, session_id, session, session["force_desktop"]
        ).encode("utf-8")
        response_headers["content-type"] = "text/html; charset=utf-8"
        response_headers.pop("content-length", None)
    return Response(body, status_code=upstream.status_code, headers=response_headers)


SUSPICIOUS_PATH_MARKERS = (
    "/.env", "/.git", "/wp-admin", "/wp-login", "/phpmyadmin", "/xmlrpc.php",
    "/actuator", "/server-status", "/cgi-bin", "/vendor/phpunit", "/etc/passwd",
    "/config.json", "/swagger", "/admin", "../", "%2e%2e", "select%20", "union%20",
)


def _is_suspicious_path(path: str) -> bool:
    normalized = path.casefold()
    return any(marker in normalized for marker in SUSPICIOUS_PATH_MARKERS)


@app.get("/api/reports", dependencies=[Depends(admin)])
async def reports(
    request: Request, hours: int = 24, project_id: int | None = None,
    query: str = "", outcome: str = "",
):
    hours = min(max(hours, 1), 24 * 90)
    since_dt = datetime.now(UTC) - timedelta(hours=hours)
    events = store(request).report_events(since_dt.isoformat(), project_id)
    query_folded = query.strip().casefold()
    if outcome:
        events = [event for event in events if event["outcome"] == outcome]
    if query_folded:
        events = [
            event for event in events
            if query_folded in " ".join((
                event.get("project_name") or "", event["action"], event["outcome"],
                event["client_ip"], str(event["detail"].get("path", "")),
                str(event["detail"].get("user_agent", "")),
            )).casefold()
        ]

    requests = [event for event in events if event["action"] in {"request", "proxy"}]
    blocked = [event for event in events if event["outcome"] in {"denied", "suspected", "failed"}]
    suspected = [event for event in requests if _is_suspicious_path(str(event["detail"].get("path", "")))]
    unique_ips = {event["client_ip"] for event in requests if event["client_ip"]}
    durations = [float(event["detail"].get("duration_ms", 0)) for event in requests if event["detail"].get("duration_ms") is not None]

    bucket_minutes = 60 if hours <= 72 else 24 * 60
    timeline: dict[str, Counter] = defaultdict(Counter)
    ip_buckets: dict[tuple[str, str], int] = Counter()
    endpoint_counts: Counter = Counter()
    suspicious_counts: Counter = Counter()
    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    country_counts: Counter = Counter()
    flow_counts: Counter = Counter()
    for event in requests:
        detail = event["detail"]
        created = datetime.fromisoformat(event["created_at"])
        if bucket_minutes == 60:
            bucket = created.replace(minute=0, second=0, microsecond=0).isoformat()
        else:
            bucket = created.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        timeline[bucket]["blocked" if event["outcome"] != "allowed" else "allowed"] += 1
        path = str(detail.get("path", "/"))
        endpoint_counts[(detail.get("method", "—"), path)] += 1
        if _is_suspicious_path(path):
            suspicious_counts[path] += 1
        if event["client_ip"]:
            ip_counts[event["client_ip"]] += 1
            minute = created.replace(second=0, microsecond=0).isoformat()
            ip_buckets[(event["client_ip"], minute)] += 1
        status_counts[str(detail.get("status", "blocked"))] += 1
        country = detail.get("country") or "Desconhecido"
        country_counts[country] += 1
        if detail.get("latitude") is not None and detail.get("longitude") is not None:
            flow_counts[(
                event["client_ip"], float(detail["longitude"]), float(detail["latitude"]),
                detail.get("city") or country, event.get("project_name") or "Projeto",
            )] += 1

    peak_rpm = max(ip_buckets.values(), default=0)
    ddos_ips = Counter()
    for (ip, _minute), count in ip_buckets.items():
        if count >= 60:
            ddos_ips[ip] = max(ddos_ips[ip], count)

    def log_item(event: dict) -> dict:
        detail = event["detail"]
        return {
            "id": event["id"], "created_at": event["created_at"],
            "project": event.get("project_name") or "Sistema", "action": event["action"],
            "outcome": event["outcome"], "ip": event["client_ip"],
            "method": detail.get("method", "—"), "path": detail.get("path", "—"),
            "status": detail.get("status"), "duration_ms": detail.get("duration_ms"),
            "country": detail.get("country") or "—", "user_agent": detail.get("user_agent", ""),
            "reason": detail.get("reason", ""),
        }

    return {
        "range": {"hours": hours, "since": since_dt.isoformat(), "total_events": len(events)},
        "kpis": {
            "requests": len(requests), "blocked": len(blocked), "unique_ips": len(unique_ips),
            "suspicious": len(suspected), "avg_latency_ms": round(sum(durations) / len(durations), 1) if durations else 0,
            "peak_rpm": peak_rpm, "ddos_sources": len(ddos_ips),
        },
        "timeline": [{"time": key, **timeline[key]} for key in sorted(timeline)],
        "outcomes": dict(Counter(event["outcome"] for event in events)),
        "statuses": dict(status_counts),
        "top_endpoints": [{"method": key[0], "path": key[1], "count": count} for key, count in endpoint_counts.most_common(10)],
        "suspicious_endpoints": [{"path": path, "count": count} for path, count in suspicious_counts.most_common(10)],
        "top_ips": [{"ip": ip, "count": count, "peak_rpm": ddos_ips.get(ip, 0)} for ip, count in ip_counts.most_common(10)],
        "countries": [{"name": name, "value": count} for name, count in country_counts.most_common()],
        "flows": [{"ip": key[0], "coords": [key[1], key[2]], "location": key[3], "project": key[4], "count": count} for key, count in flow_counts.most_common(250)],
        "server": {"name": settings(request).server_location_name, "coords": [settings(request).server_longitude, settings(request).server_latitude]},
        "ddos": [{"ip": ip, "peak_rpm": rpm} for ip, rpm in ddos_ips.most_common(10)],
        "logs": [log_item(event) for event in events[:500]],
    }


@app.post("/gate/probe/verify", include_in_schema=False)
async def verify_browser_probe(
    request: Request, probe_id: str = Form(...), telemetry: str = Form("{}")
):
    probe = store(request).browser_probe(probe_id)
    config = settings(request)
    browser_secret = request.cookies.get("inlock_probe_browser", "")
    now = int(time.time())
    if (
        not probe or not browser_secret
        or not hmac.compare_digest(
            probe["browser_hash"], browser_hash(browser_secret, config.secret_key)
        )
    ):
        raise HTTPException(404, "Verificação de navegador não encontrada")
    project = store(request).project(probe["project_id"])
    if (
        not project or probe["state"] != "pending" or probe["expires_at"] < now
        or not store(request).consume_browser_probe(probe_id, now)
    ):
        raise HTTPException(410, "Verificação de navegador expirada")

    signals = parse_telemetry(telemetry)
    try:
        client_elapsed = float(signals.get("elapsed", 0))
    except (TypeError, ValueError):
        client_elapsed = 0
    server_elapsed = max(0, (time.time() - float(probe["created_at"])) * 1000)
    signals["elapsed"] = min(client_elapsed, server_elapsed)
    score, reasons = behavior_score(signals)
    fingerprint = request_fingerprint(request.headers)
    tls = tls_fingerprint(
        request, config.trusted_proxies, config.tls_fingerprint_header
    )
    proof = sign_bot_proof(
        project["id"], config.secret_key, config.browser_proof_ttl_seconds,
        probe["browser_hash"], score, fingerprint, tls,
    )
    store(request).audit(
        project["id"], "bot.probe", "completed",
        client_ip(request, config.trusted_proxies), behavior_score=score,
        reasons=reasons, js=signals.get("js") is True,
    )
    response = RedirectResponse(probe["return_path"] or "/", status_code=303)
    response.set_cookie(
        f"inlock_bot_proof_{project['id']}", proof,
        max_age=config.browser_proof_ttl_seconds, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


@app.get("/gate/captcha/{challenge_id}.png", include_in_schema=False)
async def captcha_image(challenge_id: str, request: Request):
    challenge = store(request).captcha(challenge_id)
    if not challenge or challenge["expires_at"] < int(time.time()):
        raise HTTPException(410, "Desafio expirado")
    return Response(
        render_visual_challenge(challenge["payload"]),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/gate/captcha/verify", include_in_schema=False)
async def verify_captcha(
    request: Request, challenge_id: str = Form(...), selected: str = Form("")
):
    challenge = store(request).captcha(challenge_id)
    browser_secret = request.cookies.get("inlock_human_browser", "")
    config = settings(request)
    now = int(time.time())
    if (
        not challenge or not browser_secret
        or not hmac.compare_digest(
            challenge["browser_hash"], browser_hash(browser_secret, config.secret_key)
        )
    ):
        raise HTTPException(404, "Desafio não encontrado")
    project = store(request).project(challenge["project_id"])
    if (
        not project or challenge["state"] != "pending"
        or challenge["expires_at"] < now
    ):
        return HTMLResponse(
            captcha_html(
                project or {"name": "Acesso protegido"}, challenge_id,
                challenge["payload"]["target_label"], "Desafio expirado. Recarregue a página."
            ),
            410,
        )
    supplied_hash = captcha_answer_hash(challenge_id, selected)
    if not hmac.compare_digest(supplied_hash, challenge["answer_hash"]):
        attempts = store(request).fail_captcha(challenge_id)
        exhausted = attempts >= 3
        message = (
            "Tentativas esgotadas. Recarregue a página para gerar outro desafio."
            if exhausted else f"Seleção incorreta. Restam {3 - attempts} tentativa(s)."
        )
        store(request).audit(
            project["id"], "bot.challenge", "failed",
            client_ip(request, config.trusted_proxies), attempts=attempts,
        )
        return HTMLResponse(
            captcha_html(project, challenge_id, challenge["payload"]["target_label"], message),
            429 if exhausted else 400,
        )
    if not store(request).solve_captcha(challenge_id, now):
        raise HTTPException(410, "Desafio expirado")
    response = RedirectResponse(challenge["return_path"] or "/", status_code=303)
    response.set_cookie(
        f"inlock_human_{project['id']}",
        sign_access(project["id"], config.secret_key, config.human_session_ttl_seconds),
        max_age=config.human_session_ttl_seconds, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    store(request).audit(
        project["id"], "bot.challenge", "solved",
        client_ip(request, config.trusted_proxies),
    )
    return response


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
    return_path = request.query_params.get("return_path", "/")
    if not return_path.startswith("/") or return_path.startswith("//"):
        return_path = "/"
    store(request).prune_challenges(now - 300)
    store(request).save_challenge({
        "id": challenge_id,
        "project_id": project["id"],
        "browser_hash": browser_hash(browser_secret, config.secret_key),
        "token_hash": token_hash(opaque_token),
        "expires_at": now + config.qr_ttl_seconds,
        "return_path": return_path,
        "created_at": now,
    })
    response = JSONResponse({
        "challenge_id": challenge_id,
        "qr_url": f"/gate/qr/{quote(opaque_token)}.svg",
        "expires_in": config.qr_ttl_seconds,
        "mode": "totem" if project["qr_totem_mode"] else "browser",
    })
    response.set_cookie(
        "inlock_browser", browser_secret, max_age=86400, httponly=True,
        secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


@app.post("/api/gate/{slug}/location", include_in_schema=False)
async def capture_client_location(
    slug: str, payload: LocationCapture, request: Request
):
    project = store(request).project_by_slug(slug)
    if not project or not project["enabled"]:
        raise HTTPException(404, "Projeto não encontrado ou desativado")
    config = settings(request)
    cookie_name = f"inlock_location_{project['id']}"
    location_token = request.cookies.get(cookie_name) or random_token(32)
    expires_at = int(time.time()) + config.location_ttl_seconds
    store(request).save_client_location(
        token_hash(location_token), project["id"], payload.latitude,
        payload.longitude, payload.accuracy, expires_at,
    )
    store(request).audit(
        project["id"], "location.captured", "success",
        client_ip(request, config.trusted_proxies), latitude=payload.latitude,
        longitude=payload.longitude, accuracy=payload.accuracy, source="browser",
    )
    response = JSONResponse({"captured": True, "accuracy": payload.accuracy})
    response.set_cookie(
        cookie_name, location_token, max_age=config.location_ttl_seconds,
        httponly=True, secure=config.secure_cookies, samesite="lax", path="/",
    )
    return response


@app.post("/api/gate/{slug}/location-declined", include_in_schema=False)
async def decline_client_location(slug: str, request: Request):
    project = store(request).project_by_slug(slug)
    if not project or not project["enabled"]:
        raise HTTPException(404, "Projeto não encontrado ou desativado")
    config = settings(request)
    store(request).audit(
        project["id"], "location.permission", "denied",
        client_ip(request, config.trusted_proxies), source="browser",
    )
    response = JSONResponse({"captured": False})
    response.set_cookie(
        f"inlock_location_attempt_{project['id']}", "denied",
        max_age=config.location_ttl_seconds, httponly=True,
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
        return HTMLResponse(approval_html(token, None, True), 410)
    project = store(request).project(challenge["project_id"])
    expired = challenge["state"] != "pending" or challenge["expires_at"] < int(time.time())
    return HTMLResponse(
        approval_html(token, project, expired), 410 if expired else 200,
        headers={"Cache-Control": "no-store", "Permissions-Policy": "geolocation=(self)"},
    )


@app.post("/gate/approve", response_class=HTMLResponse, include_in_schema=False)
async def confirm_gate(request: Request, token: str = Form(...)):
    now = int(time.time())
    challenge = store(request).challenge_by_token_hash(token_hash(token))
    project = store(request).project(challenge["project_id"]) if challenge else None
    state = "mobile_opened" if project and project["qr_totem_mode"] else "approved"
    if not challenge or not project or not store(request).approve_challenge(
        challenge["id"], now, state
    ):
        return HTMLResponse(approval_html(token, None, True), 410)
    config = settings(request)
    ip = client_ip(request, config.trusted_proxies)
    if project["qr_totem_mode"]:
        response = RedirectResponse(challenge.get("return_path") or "/", status_code=303)
        response.set_cookie(
            f"inlock_access_{project['id']}",
            sign_access(project["id"], config.secret_key, config.access_ttl_seconds),
            max_age=config.access_ttl_seconds, httponly=True,
            secure=config.secure_cookies, samesite="lax", path="/",
        )
        store(request).audit(project["id"], "qr.mobile_opened", "success", ip)
        return response
    store(request).audit(project["id"], "qr.approved", "success", ip)
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
    started_at = time.perf_counter()
    config = settings(request)
    ip = client_ip(request, config.trusted_proxies)
    location_cookie = request.cookies.get(f"inlock_location_{project['id']}", "")
    browser_location = (
        store(request).client_location(
            token_hash(location_cookie), project["id"], int(time.time())
        ) if location_cookie else None
    )
    location = request.app.state.engine.geo.locate(ip) or {}
    if browser_location:
        location = {
            **location, "latitude": browser_location["latitude"],
            "longitude": browser_location["longitude"],
            "accuracy": browser_location["accuracy"], "source": "browser",
        }
    request_detail = {
        "method": request.method,
        "path": request.url.path,
        "user_agent": request.headers.get("user-agent", "")[:500],
        "referer": request.headers.get("referer", "")[:500],
        "country": location.get("country", ""),
        "state": location.get("state", ""),
        "city": location.get("city", ""),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "location_accuracy": location.get("accuracy"),
        "location_source": location.get("source", "geoip" if location else "unknown"),
    }
    policies = store(request).policies(project["id"])
    human_access = request.cookies.get(f"inlock_human_{project['id']}", "")
    human_verified = verify_access(human_access, project["id"], config.secret_key)
    probe_browser = request.cookies.get("inlock_probe_browser", "")
    probe_digest = browser_hash(probe_browser, config.secret_key)
    proof_value = request.cookies.get(f"inlock_bot_proof_{project['id']}", "")
    proof = verify_bot_proof(
        proof_value, project["id"], config.secret_key, probe_digest
    ) if proof_value and probe_browser else None
    current_fingerprint = request_fingerprint(request.headers)
    current_tls = tls_fingerprint(
        request, config.trusted_proxies, config.tls_fingerprint_header
    )
    reputation, reputation_events = 0, {}
    if any(policy["enabled"] and policy["type"] == "bot_score" for policy in policies):
        since = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        reputation, reputation_events = store(request).ip_reputation_score(ip, since)
    bot_context = {
        "js_verified": bool(proof),
        "behavior_score": proof.get("behavior", 0) if proof else 0,
        "ip_reputation": reputation,
        "cookie_tampered": bool(proof_value and not proof),
        "request_fingerprint_changed": bool(
            proof and proof.get("request_fp") != current_fingerprint
        ),
        "tls_fingerprint_changed": bool(
            proof and proof.get("tls_fp") and current_tls
            and proof.get("tls_fp") != current_tls
        ),
        "is_navigation": (
            request.headers.get("sec-fetch-dest") == "document"
            or request.headers.get("sec-fetch-mode") == "navigate"
        ),
        "request_path": request.url.path,
    }
    decision: Decision = await request.app.state.engine.evaluate(
        project, policies, ip,
        request.headers.get("user-agent", ""), headers=request.headers,
        human_verified=human_verified, bot_context=bot_context,
    )
    if not decision.allowed:
        if decision.reason == "browser_probe_required":
            return browser_probe_response(
                request, project, request_return_path(request), decision.bot_score or 0
            )
        if decision.reason == "bot_suspected":
            store(request).audit(
                project["id"], "bot.score", "suspected", ip,
                score=decision.bot_score, context=bot_context,
                reputation_events=reputation_events,
            )
            return human_challenge_response(
                request, project, request_return_path(request), decision.bot_score or 0
            )
        store(request).audit(
            project["id"], "request", "denied", ip, **request_detail,
            reason=decision.reason, policy_id=decision.policy_id,
            bot_score=decision.bot_score,
            status=429 if decision.reason == "rate_limited" else 403,
            duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
        )
        headers = {"Retry-After": str(decision.retry_after)} if decision.retry_after else None
        return JSONResponse({"detail": "Acesso negado", "reason": decision.reason}, 429 if decision.reason == "rate_limited" else 403, headers=headers)
    if project["qr_required"]:
        access = request.cookies.get(f"inlock_access_{project['id']}", "")
        if not verify_access(access, project["id"], config.secret_key):
            return_path = request.url.path
            if request.url.query:
                return_path += f"?{request.url.query}"
            return HTMLResponse(
                gate_html(project, return_path),
                headers={
                    "Cache-Control": "no-store",
                    "Permissions-Policy": "geolocation=(self)",
                },
            )
    elif (
        not browser_location
        and not request.cookies.get(f"inlock_location_attempt_{project['id']}")
        and request.method == "GET"
        and "text/html" in request.headers.get("accept", "")
    ):
        return HTMLResponse(
            location_consent_html(project),
            headers={"Cache-Control": "no-store", "Permissions-Policy": "geolocation=(self)"},
        )
    login_policy = next((
        policy for policy in policies
        if policy["enabled"] and policy["type"] == "proprietary_login"
    ), None)
    proprietary_access = request.cookies.get(
        f"inlock_proprietary_{project['id']}", ""
    )
    if login_policy and not verify_access(
        proprietary_access, project["id"], config.secret_key
    ):
        if request.method != "GET" or "text/html" not in request.headers.get("accept", ""):
            return JSONResponse({"detail": "Autenticação proprietária necessária"}, 401)
        browser_secret = request.cookies.get("inlock_proprietary_browser") or random_token()
        session_id = random_token(24)
        return_path = request_return_path(request)
        now = int(time.time())
        sessions = request.app.state.proprietary_login_sessions
        for stale_id in [
            key for key, value in sessions.items() if value["expires_at"] < now
        ]:
            stale = sessions.pop(stale_id, None)
            if stale:
                await stale["http"].aclose()
        sessions[session_id] = {
            "project_id": project["id"],
            "policy_id": login_policy["id"],
            "login_url": login_policy["config"]["login_url"],
            "success_url": login_policy["config"]["success_url"],
            "force_desktop": bool(login_policy["config"].get("force_desktop", False)),
            "return_path": return_path,
            "browser_hash": browser_hash(browser_secret, config.secret_key),
            "last_url": "", "http": request.app.state.proprietary_http_factory(),
            "allowed_origins": {_origin(login_policy["config"]["login_url"])},
            "expires_at": now + config.proprietary_login_ttl_seconds,
        }
        response = RedirectResponse(
            _auth_proxy_url(session_id, login_policy["config"]["login_url"]), 303
        )
        response.set_cookie(
            "inlock_proprietary_browser", browser_secret,
            max_age=config.proprietary_login_ttl_seconds, httponly=True,
            secure=config.secure_cookies, samesite="lax", path="/",
        )
        store(request).audit(
            project["id"], "proprietary_login", "required", ip,
            policy_id=login_policy["id"],
        )
        return response
    query = f"?{request.url.query}" if request.url.query else ""
    url = f"{project['upstream_url']}/{path}{query}"
    headers = {key: value for key, value in request.headers.items() if key.lower() not in HOP_BY_HOP and key.lower() != "cookie"}
    cookies = [part.strip() for part in request.headers.get("cookie", "").split(";") if part.strip() and not part.strip().startswith("inlock_")]
    if cookies:
        headers["cookie"] = "; ".join(cookies)
    headers["x-forwarded-for"] = ip
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-host"] = request.headers.get("host", "")
    upstream_request = request.app.state.http.build_request(
        request.method, url, headers=headers, content=await request.body(),
    )
    try:
        upstream = await request.app.state.http.send(upstream_request, stream=True)
    except httpx.RequestError as exc:
        store(request).audit(
            project["id"], "proxy", "error", ip, **request_detail,
            error=type(exc).__name__, status=502,
            duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
        )
        return JSONResponse({"detail": "Upstream indisponível"}, 502)
    body = iter([upstream.content]) if upstream.is_stream_consumed else upstream.aiter_raw()
    response = StreamingResponse(
        body,
        status_code=upstream.status_code,
        background=BackgroundTask(upstream.aclose),
    )
    for key, value in upstream.headers.multi_items():
        if key.lower() not in HOP_BY_HOP:
            response.headers.append(key, value)
    store(request).audit(
        project["id"], "request", "allowed", ip, **request_detail,
        status=upstream.status_code,
        duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
        response_bytes=int(upstream.headers.get("content-length", 0) or 0),
        content_type=upstream.headers.get("content-type", "")[:200],
    )
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
