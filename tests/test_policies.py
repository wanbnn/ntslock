import pytest

from inlock.policies import PolicyEngine

PROJECT = {"id": 1}


def policy(type_, config, id_=1):
    return {"id": id_, "type": type_, "config": config, "enabled": True}


@pytest.mark.asyncio
async def test_ip_lists_and_user_agent():
    engine = PolicyEngine()
    decision = await engine.evaluate(
        PROJECT,
        [policy("ip_allowlist", {"networks": ["10.0.0.0/8"]})],
        "203.0.113.4", "Mozilla/5.0",
    )
    assert not decision.allowed and decision.reason == "ip_not_allowed"

    decision = await engine.evaluate(
        PROJECT,
        [policy("user_agent", {"patterns": ["*crawler*", "curl/*"]})],
        "10.0.0.4", "ExampleCrawler/1.0",
    )
    assert not decision.allowed and decision.reason == "user_agent_blocked"


@pytest.mark.asyncio
async def test_rate_limit_by_ip_and_global():
    engine = PolicyEngine()
    policies = [policy("rate_limit", {"limit": 2, "window_seconds": 60, "scope": "ip"})]
    assert (await engine.evaluate(PROJECT, policies, "10.0.0.1", "browser")).allowed
    assert (await engine.evaluate(PROJECT, policies, "10.0.0.1", "browser")).allowed
    blocked = await engine.evaluate(PROJECT, policies, "10.0.0.1", "browser")
    assert not blocked.allowed and blocked.retry_after > 0
    assert (await engine.evaluate(PROJECT, policies, "10.0.0.2", "browser")).allowed


@pytest.mark.asyncio
async def test_geo_unknown_is_fail_closed_by_default():
    engine = PolicyEngine()
    denied = await engine.evaluate(PROJECT, [policy("geo", {"countries": ["BR"]})], "192.0.2.1", "browser")
    allowed = await engine.evaluate(PROJECT, [policy("geo", {"countries": ["BR"], "on_unknown": "allow"})], "192.0.2.1", "browser")
    assert denied.reason == "location_unknown"
    assert allowed.allowed

