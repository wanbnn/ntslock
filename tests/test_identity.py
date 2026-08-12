from pathlib import Path

from inlock.identity import IdentityKeyring, stable_subject
from inlock.main import _upstream_cookies


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
