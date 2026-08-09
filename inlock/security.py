from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections.abc import Iterable

from fastapi import HTTPException, Request, status


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def browser_hash(value: str, secret: str) -> str:
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def random_token(bytes_: int = 32) -> str:
    return secrets.token_urlsafe(bytes_)


def sign_access(project_id: int, secret: str, ttl: int) -> str:
    payload = {"project": project_id, "exp": int(time.time()) + ttl, "nonce": random_token(12)}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def verify_access(value: str, project_id: int, secret: str) -> bool:
    try:
        body, supplied = value.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(supplied, expected):
            return False
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return payload["project"] == project_id and payload["exp"] >= int(time.time())
    except (ValueError, KeyError, json.JSONDecodeError):
        return False


def client_ip(request: Request, trusted_networks: Iterable[str]) -> str:
    peer = request.client.host if request.client else "127.0.0.1"
    try:
        peer_ip = ipaddress.ip_address(peer)
        trusted = any(peer_ip in ipaddress.ip_network(network) for network in trusted_networks)
    except ValueError:
        trusted = False
    if trusted:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        try:
            return str(ipaddress.ip_address(forwarded)) if forwarded else peer
        except ValueError:
            pass
    return peer


def require_admin(request: Request, configured_token: str) -> None:
    if configured_token:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, configured_token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token administrativo inválido")
        return
    peer = request.client.host if request.client else ""
    try:
        if not ipaddress.ip_address(peer).is_loopback:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Defina INLOCK_ADMIN_TOKEN para acesso remoto")
    except ValueError:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origem administrativa não confiável")

