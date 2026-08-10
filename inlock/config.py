from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INLOCK_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    database_path: Path | None = None
    secret_key: str = ""
    admin_token: str = ""
    public_url: str = "http://localhost:14900"
    admin_host: str = ""
    secure_cookies: bool = False
    access_ttl_seconds: int = 8 * 60 * 60
    qr_ttl_seconds: int = 60
    captcha_ttl_seconds: int = 180
    browser_probe_ttl_seconds: int = 180
    browser_proof_ttl_seconds: int = 30 * 60
    human_session_ttl_seconds: int = 30 * 60
    location_ttl_seconds: int = 8 * 60 * 60
    tls_fingerprint_header: str = ""
    trusted_proxies: Annotated[list[str], NoDecode] = ["127.0.0.1/32", "::1/128"]
    geoip_city_db: Path | None = None
    docker_url: str = "unix:///var/run/docker.sock"
    enforce_container_isolation: bool = True
    container_reconcile_seconds: int = 10
    tile_url: str = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
    server_latitude: float = -9.6658
    server_longitude: float = -35.7353
    server_location_name: str = "Servidor Inlock"

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def split_networks(cls, value):
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    def prepare(self) -> Settings:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.database_path is None:
            self.database_path = self.data_dir / "inlock.db"
        if not self.secret_key:
            key_file = self.data_dir / ".secret-key"
            if key_file.exists():
                self.secret_key = key_file.read_text(encoding="utf-8").strip()
            else:
                self.secret_key = secrets.token_urlsafe(48)
                key_file.write_text(self.secret_key, encoding="utf-8")
                key_file.chmod(0o600)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings().prepare()
