import time

from inlock.security import (
    sign_access,
    sign_bot_proof,
    verify_access,
    verify_bot_proof,
)


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
