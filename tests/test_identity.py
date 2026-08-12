import json
from pathlib import Path

from inlock.identity import IdentityKeyring, stable_subject
from inlock.config import Settings
from inlock.main import _identity_forward_headers, _upstream_cookies, _upstream_headers


def test_identity_keyring_persists_and_rotates_with_overlap(tmp_path: Path):
    first = IdentityKeyring(tmp_path)
    original_kid = first.active_kid
    assert (tmp_path / "signing-keys" / f"{original_kid}.pem").stat().st_mode & 0o777 == 0o600

    restarted = IdentityKeyring(tmp_path)
    assert restarted.active_kid == original_kid
    new_kid = restarted.rotate(3600)
    assert new_kid != original_kid
    assert {item["kid"] for item in restarted.jwks()["keys"]} == {
        original_kid, new_kid,
    }
    assert restarted.revoke(new_kid) is False
    assert restarted.revoke(original_kid) is True
    assert {item["kid"] for item in restarted.jwks()["keys"]} == {new_kid}


def test_stable_subject_is_scoped_by_project_and_normalized_login():
    first = stable_subject("secret", 1, " Maria  Silva ")
    assert first == stable_subject("secret", 1, "maria silva")
    assert first != stable_subject("secret", 2, "maria silva")


def test_only_integration_cookie_is_forwarded_among_internal_cookies():
    header = (
        "inlock_access_1=private; app_preference=dark; "
        "inlock_identity_demo=signed.jwt; inlock_proprietary_1=private"
    )
    assert _upstream_cookies(header, "inlock_identity_demo") == (
        "app_preference=dark; inlock_identity_demo=signed.jwt"
    )


def test_valid_identity_creates_zero_config_trust_headers(tmp_path: Path):
    keyring = IdentityKeyring(tmp_path)
    config = Settings(data_dir=tmp_path, public_url="https://inlock.example")
    project = {"id": 18, "slug": "journeydemo"}
    now = __import__("time").time()
    token = keyring.sign({
        "iss": "https://inlock.example", "aud": "inlock:project:18",
        "sub": "stable", "name": "maria", "project_id": 18,
        "project": "journeydemo", "jti": "session", "iat": int(now),
        "nbf": int(now), "exp": int(now) + 300,
    })

    headers = _identity_forward_headers(token, project, config, keyring)

    assert headers == {
        "x-inlock-identity-token": token,
        "x-inlock-issuer": "https://inlock.example",
        "x-inlock-project-id": "18",
        "x-inlock-project": "journeydemo",
        "x-inlock-identity-jwk": json.dumps(next(
            item for item in keyring.jwks()["keys"]
            if item["kid"] == keyring.active_kid
        ), separators=(",", ":")),
    }
    assert _identity_forward_headers(token, {"id": 19, "slug": "other"}, config, keyring) == {}


def test_client_cannot_spoof_reserved_identity_headers():
    assert _upstream_headers({
        "Accept": "application/json",
        "X-Inlock-Identity-Token": "attacker-token",
        "X-Inlock-Issuer": "https://attacker.example",
        "X-Inlock-Project-ID": "999",
        "X-Inlock-Project": "fake",
        "X-Inlock-Identity-JWK": '{"kty":"OKP"}',
        "Cookie": "inlock_identity_fake=attacker-token",
    }) == {"Accept": "application/json"}
