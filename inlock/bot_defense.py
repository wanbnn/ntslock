from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import Request

FINGERPRINT_HEADERS = (
    "user-agent", "accept-language", "accept-encoding", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-platform",
)


def request_fingerprint(headers: Mapping[str, str]) -> str:
    normalized = "\n".join(
        f"{name}:{headers.get(name, '').strip().casefold()}"
        for name in FINGERPRINT_HEADERS
    )
    return hashlib.sha256(normalized.encode()).hexdigest()


def _peer_is_trusted(request: Request, trusted_networks: Iterable[str]) -> bool:
    peer = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(peer)
        return any(address in ipaddress.ip_network(item) for item in trusted_networks)
    except ValueError:
        return False


def tls_fingerprint(
    request: Request, trusted_networks: Iterable[str], forwarded_header: str = ""
) -> str:
    tls_extension = request.scope.get("extensions", {}).get("tls")
    if isinstance(tls_extension, dict):
        material = "|".join(str(tls_extension.get(key, "")) for key in (
            "tls_version", "cipher_suite", "server_name"
        ))
        if material.strip("|"):
            return f"asgi:{hashlib.sha256(material.encode()).hexdigest()}"
    ssl_object = request.scope.get("ssl_object")
    if ssl_object:
        try:
            cipher = ssl_object.cipher() or ("", "", 0)
            material = f"{ssl_object.version()}|{cipher[0]}|{cipher[1]}|{cipher[2]}"
            return f"direct:{hashlib.sha256(material.encode()).hexdigest()}"
        except (AttributeError, TypeError, ValueError):
            pass
    header = forwarded_header.strip().lower()
    if header and _peer_is_trusted(request, trusted_networks):
        supplied = request.headers.get(header, "").strip()
        if supplied and len(supplied) <= 256:
            return f"forwarded:{hashlib.sha256(supplied.encode()).hexdigest()}"
    return ""


def parse_telemetry(raw: str) -> dict[str, Any]:
    if len(raw) > 8192:
        return {"js": False, "invalid": True}
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {"js": False, "invalid": True}
    except (TypeError, json.JSONDecodeError):
        return {"js": False, "invalid": True}


def behavior_score(telemetry: Mapping[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append(reason)

    if telemetry.get("js") is not True:
        add(60, "javascript_missing")
    if telemetry.get("webdriver") is True:
        add(70, "webdriver")
    if telemetry.get("automation") is True:
        add(45, "automation_globals")
    try:
        elapsed = float(telemetry.get("elapsed", 0))
    except (TypeError, ValueError):
        elapsed = 0
    if elapsed < 700:
        add(30, "interaction_too_fast")
    elif elapsed < 1000:
        add(12, "interaction_fast")
    if telemetry.get("trustedClick") is not True:
        add(30, "untrusted_click")
    try:
        pointer_moves = int(telemetry.get("pointerMoves", 0))
        pointer_events = int(telemetry.get("pointerEvents", 0))
    except (TypeError, ValueError):
        pointer_moves = pointer_events = 0
    if pointer_moves == 0 and pointer_events == 0:
        add(8, "no_pointer_behavior")
    if telemetry.get("cookieEnabled") is not True:
        add(15, "cookies_disabled")
    if telemetry.get("storage") is not True:
        add(10, "storage_unavailable")
    try:
        if int(telemetry.get("languages", 0)) == 0:
            add(8, "languages_missing")
        if int(telemetry.get("plugins", 0)) == 0:
            add(6, "plugins_missing")
        width = int(telemetry.get("screenWidth", 0))
        height = int(telemetry.get("screenHeight", 0))
        if width < 240 or height < 240:
            add(15, "screen_invalid")
    except (TypeError, ValueError):
        add(10, "device_data_invalid")
    if telemetry.get("visibility") == "hidden":
        add(10, "hidden_execution")
    return min(100, score), reasons
