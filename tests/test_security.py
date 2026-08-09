import time

from inlock.security import sign_access, verify_access


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

