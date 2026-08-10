import time

from starlette.requests import Request

from inlock.security import (
    client_ip,
    sign_access,
    sign_bot_proof,
    verify_access,
    verify_bot_proof,
)


def request_from(peer: str, headers: list[tuple[bytes, bytes]]) -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers,
                    "client": (peer, 1234), "scheme": "https", "server": ("test", 443)})


def test_cloudflare_ip_is_used_only_from_a_trusted_proxy():
    header = [(b"cf-connecting-ip", b"203.0.113.42"), (b"x-forwarded-for", b"127.0.0.1")]
    assert client_ip(request_from("127.0.0.1", header), ["127.0.0.1/32"]) == "203.0.113.42"
    assert client_ip(request_from("198.51.100.8", header), ["127.0.0.1/32"]) == "198.51.100.8"


def test_invalid_cloudflare_ip_falls_back_to_forwarded_for():
    headers = [(b"cf-connecting-ip", b"not-an-ip"), (b"x-forwarded-for", b"203.0.113.9")]
    assert client_ip(request_from("127.0.0.1", headers), ["127.0.0.1/32"]) == "203.0.113.9"


def test_access_token_is_scoped_and_tamper_evident():
    token = sign_access(7, "test-secret", 60)
    assert verify_access(token, 7, "test-secret")
    assert not verify_access(token, 8, "test-secret")
    assert not verify_access(token + "x", 7, "test-secret")


def test_expired_access_token_is_rejected(monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 100)
    token = sign_access(1, "test-secret", 2)
    monkeypatch.setattr(time, "time", lambda: 103)
    assert not verify_access(token, 1, "test-secret")


def test_bot_proof_is_signed_project_and_browser_bound():
    proof = sign_bot_proof(4, "secret", 60, "browser-a", 12, "request-a", "tls-a")

    payload = verify_bot_proof(proof, 4, "secret", "browser-a")
    assert payload and payload["behavior"] == 12
    assert not verify_bot_proof(proof, 5, "secret", "browser-a")
    assert not verify_bot_proof(proof, 4, "secret", "browser-b")
    assert not verify_bot_proof(proof + "x", 4, "secret", "browser-a")
