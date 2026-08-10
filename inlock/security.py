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


def sign_bot_proof(
    project_id: int, secret: str, ttl: int, browser_digest: str,
    behavior_score: int, request_fingerprint: str, tls_fingerprint: str,
) -> str:
    payload = {
        "project": project_id,
        "exp": int(time.time()) + ttl,
        "browser": browser_digest,
        "behavior": min(100, max(0, int(behavior_score))),
        "request_fp": request_fingerprint,
        "tls_fp": tls_fingerprint,
        "nonce": random_token(12),
    }
    body = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def verify_bot_proof(
    value: str, project_id: int, secret: str, browser_digest: str
) -> dict | None:
    try:
        body, supplied = value.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if not hmac.compare_digest(supplied, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if (
            payload["project"] != project_id
            or payload["exp"] < int(time.time())
            or not hmac.compare_digest(payload["browser"], browser_digest)
        ):
            return None
        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


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
        candidates = (
            request.headers.get("cf-connecting-ip", "").strip(),
            request.headers.get("x-forwarded-for", "").split(",")[0].strip(),
        )
        for forwarded in candidates:
            try:
                if forwarded:
                    return str(ipaddress.ip_address(forwarded))
            except ValueError:
                continue
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
