from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    slug: str = Field(min_length=2, max_length=60)
    upstream_url: str
    public_host: str = ""
    docker_container_id: str = ""
    enabled: bool = True
    qr_required: bool = False

    @field_validator("slug")
    @classmethod
    def valid_slug(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
            raise ValueError("use letras minúsculas, números e hífens")
        return value

    @field_validator("upstream_url")
    @classmethod
    def valid_upstream(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("upstream deve ser uma URL HTTP(S)")
        if parsed.username or parsed.password:
            raise ValueError("credenciais não são permitidas na URL")
        return value.rstrip("/")

    @field_validator("public_host")
    @classmethod
    def clean_host(cls, value: str) -> str:
        return value.strip().lower().split(":", 1)[0]


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    slug: str | None = None
    upstream_url: str | None = None
    public_host: str | None = None
    docker_container_id: str | None = None
    enabled: bool | None = None
    qr_required: bool | None = None


PolicyType = Literal["rate_limit", "geo", "user_agent", "ip_allowlist", "ip_blocklist"]


class PolicyCreate(BaseModel):
    type: PolicyType
    name: str = Field(min_length=2, max_length=80)
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=10000)
    config: dict[str, Any] = Field(default_factory=dict)

