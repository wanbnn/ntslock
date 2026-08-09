from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import math
import time
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from geoip2.errors import GeoIP2Error


@dataclass
class Decision:
    allowed: bool
    reason: str = "allowed"
    policy_id: int | None = None
    retry_after: int | None = None
    bot_score: int | None = None


def calculate_bot_score(headers: Mapping[str, str] | None, user_agent: str) -> int:
    """Return a local bot-likelihood score where 0 is browser-like and 100 is automated."""
    normalized = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    agent = user_agent.casefold().strip()
    score = 0
    strong_markers = (
        "bot", "crawler", "spider", "scrapy", "curl/", "wget/", "python-requests",
        "python-httpx", "aiohttp", "go-http-client", "headlesschrome", "phantomjs",
        "selenium", "playwright",
    )
    if not agent or any(marker in agent for marker in strong_markers):
        score += 75
    elif "mozilla/5.0" not in agent:
        score += 20
    if not normalized.get("accept"):
        score += 10
    if not normalized.get("accept-language"):
        score += 8
    if not normalized.get("accept-encoding"):
        score += 5
    if not normalized.get("sec-fetch-site") and "mozilla/5.0" in agent:
        score += 8
    if normalized.get("webdriver", "").casefold() in {"1", "true", "yes"}:
        score += 45
    return min(100, score)


class RateLimiter:
    """In-memory sliding-window limiter; use a shared backend for multi-worker deployments."""

    def __init__(self):
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window
        async with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, max(1, math.ceil(window - (now - bucket[0])))
            bucket.append(now)
            return True, 0


class GeoLocator:
    def __init__(self, database: Path | None):
        self.database = database
        self._reader = None

    def locate(self, ip: str) -> dict[str, Any] | None:
        if not self.database or not self.database.exists():
            return None
        try:
            if self._reader is None:
                import geoip2.database

                self._reader = geoip2.database.Reader(str(self.database))
            result = self._reader.city(ip)
            return {
                "country": result.country.iso_code or "",
                "state": result.subdivisions.most_specific.iso_code or result.subdivisions.most_specific.name or "",
                "city": result.city.name or "",
                "latitude": result.location.latitude,
                "longitude": result.location.longitude,
            }
        except (GeoIP2Error, OSError, ValueError):
            return None


def _in_networks(ip: str, networks: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        return any(address in ipaddress.ip_network(network, strict=False) for network in networks)
    except ValueError:
        return False


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class PolicyEngine:
    def __init__(self, geo_database: Path | None = None):
        self.rates = RateLimiter()
        self.geo = GeoLocator(geo_database)

    async def evaluate(
        self, project: dict[str, Any], policies: list[dict[str, Any]], ip: str,
        user_agent: str, headers: Mapping[str, str] | None = None,
        human_verified: bool = False,
    ) -> Decision:
        location: dict[str, Any] | None = None
        for policy in policies:
            if not policy["enabled"]:
                continue
            config = policy["config"]
            policy_type = policy["type"]
            if policy_type == "ip_allowlist":
                networks = config.get("networks", [])
                if networks and not _in_networks(ip, networks):
                    return Decision(False, "ip_not_allowed", policy["id"])
            elif policy_type == "ip_blocklist":
                if _in_networks(ip, config.get("networks", [])):
                    return Decision(False, "ip_blocked", policy["id"])
            elif policy_type == "user_agent":
                normalized = user_agent.lower()
                if any(fnmatch.fnmatch(normalized, str(pattern).lower()) for pattern in config.get("patterns", [])):
                    return Decision(False, "user_agent_blocked", policy["id"])
            elif policy_type == "rate_limit":
                limit = max(1, int(config.get("limit", 60)))
                window = max(1, int(config.get("window_seconds", 60)))
                scope = config.get("scope", "ip")
                identity = "global" if scope == "global" else ip
                allowed, retry_after = await self.rates.check(
                    f"{project['id']}:{policy['id']}:{identity}", limit, window
                )
                if not allowed:
                    return Decision(False, "rate_limited", policy["id"], retry_after)
            elif policy_type == "bot_score":
                if human_verified:
                    continue
                score = calculate_bot_score(headers, user_agent)
                threshold = min(100, max(0, int(config.get("threshold", 65))))
                if score >= threshold:
                    return Decision(
                        False, "bot_suspected", policy["id"], bot_score=score
                    )
            elif policy_type == "geo":
                if location is None:
                    location = self.geo.locate(ip)
                if location is None:
                    if config.get("on_unknown", "deny") == "deny":
                        return Decision(False, "location_unknown", policy["id"])
                    continue
                countries = [str(item).upper() for item in config.get("countries", [])]
                states = [str(item).casefold() for item in config.get("states", [])]
                cities = [str(item).casefold() for item in config.get("cities", [])]
                if countries and location["country"].upper() not in countries:
                    return Decision(False, "country_blocked", policy["id"])
                if states and location["state"].casefold() not in states:
                    return Decision(False, "state_blocked", policy["id"])
                if cities and location["city"].casefold() not in cities:
                    return Decision(False, "city_blocked", policy["id"])
                radius = config.get("radius")
                if radius and location.get("latitude") is not None:
                    distance = _distance_km(
                        float(radius["latitude"]), float(radius["longitude"]),
                        float(location["latitude"]), float(location["longitude"]),
                    )
                    if distance > float(radius["kilometers"]):
                        return Decision(False, "outside_radius", policy["id"])
        return Decision(True)
