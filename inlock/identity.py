from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def stable_subject(secret_key: str, project_id: int, name: str) -> str:
    normalized = " ".join(name.strip().casefold().split())
    digest = hmac.new(
        secret_key.encode(), f"identity:{project_id}:{normalized}".encode(), hashlib.sha256
    ).digest()
    return _b64url(digest)


class IdentityKeyring:
    """Persistent Ed25519 signing keys with overlapping public-key rotation."""

    def __init__(self, data_dir: Path):
        self.directory = data_dir / "signing-keys"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self.metadata_path = self.directory / "keyring.json"
        if not self.metadata_path.exists():
            self._create_initial_key()

    def _read_metadata(self) -> dict[str, Any]:
        return json.loads(self.metadata_path.read_text(encoding="utf-8"))

    def _write_metadata(self, metadata: dict[str, Any]) -> None:
        temporary = self.metadata_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.metadata_path)

    def _new_key(self) -> tuple[str, int]:
        kid = secrets.token_urlsafe(12)
        created_at = int(time.time())
        private_key = Ed25519PrivateKey.generate()
        path = self.directory / f"{kid}.pem"
        path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        path.chmod(0o600)
        return kid, created_at

    def _create_initial_key(self) -> None:
        kid, created_at = self._new_key()
        self._write_metadata({
            "active_kid": kid,
            "keys": {kid: {"created_at": created_at, "retire_after": None}},
        })

    def _private_key(self, kid: str) -> Ed25519PrivateKey:
        return serialization.load_pem_private_key(
            (self.directory / f"{kid}.pem").read_bytes(), password=None
        )

    @property
    def active_kid(self) -> str:
        return str(self._read_metadata()["active_kid"])

    def sign(self, claims: dict[str, Any]) -> str:
        kid = self.active_kid
        return jwt.encode(
            claims, self._private_key(kid), algorithm="EdDSA", headers={"kid": kid}
        )

    def rotate(self, retain_seconds: int) -> str:
        metadata = self._read_metadata()
        now = int(time.time())
        metadata["keys"][metadata["active_kid"]]["retire_after"] = now + retain_seconds
        kid, created_at = self._new_key()
        metadata["keys"][kid] = {"created_at": created_at, "retire_after": None}
        metadata["active_kid"] = kid
        self._write_metadata(metadata)
        return kid

    def revoke(self, kid: str) -> bool:
        metadata = self._read_metadata()
        if kid == metadata["active_kid"] or kid not in metadata["keys"]:
            return False
        if metadata["keys"][kid].get("revoked_at") is not None:
            return False
        metadata["keys"][kid]["revoked_at"] = int(time.time())
        self._write_metadata(metadata)
        return True

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        metadata = self._read_metadata()
        now = int(time.time())
        keys = []
        for kid, state in metadata["keys"].items():
            if state.get("revoked_at") is not None:
                continue
            if state.get("retire_after") is not None and state["retire_after"] < now:
                continue
            public = self._private_key(kid).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            keys.append({
                "kty": "OKP", "crv": "Ed25519", "use": "sig",
                "alg": "EdDSA", "kid": kid, "x": _b64url(public),
            })
        return {"keys": keys}

    def decode(self, token: str, issuer: str, audience: str) -> dict[str, Any]:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid", "")
        metadata = self._read_metadata()
        if kid not in metadata["keys"] or metadata["keys"][kid].get("revoked_at") is not None:
            raise jwt.InvalidKeyError("kid desconhecido")
        return jwt.decode(
            token, self._private_key(kid).public_key(), algorithms=["EdDSA"],
            issuer=issuer, audience=audience,
        )
