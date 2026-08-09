from starlette.requests import Request

from inlock.bot_defense import behavior_score, request_fingerprint, tls_fingerprint


def test_behavior_score_penalizes_automation_and_unnatural_interaction():
    human, human_reasons = behavior_score({
        "js": True, "webdriver": False, "automation": False, "elapsed": 1700,
        "trustedClick": True, "pointerMoves": 4, "pointerEvents": 1,
        "cookieEnabled": True, "storage": True, "languages": 2, "plugins": 3,
        "screenWidth": 1440, "screenHeight": 900, "visibility": "visible",
    })
    bot, bot_reasons = behavior_score({
        "js": True, "webdriver": True, "automation": True, "elapsed": 100,
        "trustedClick": False, "pointerMoves": 0, "pointerEvents": 0,
        "cookieEnabled": False, "storage": False, "languages": 0, "plugins": 0,
        "screenWidth": 0, "screenHeight": 0, "visibility": "hidden",
    })

    assert human == 0 and human_reasons == []
    assert bot == 100
    assert "webdriver" in bot_reasons
    assert "interaction_too_fast" in bot_reasons
    no_javascript, no_js_reasons = behavior_score({"js": False})
    assert no_javascript == 100
    assert "javascript_missing" in no_js_reasons


def test_request_fingerprint_is_stable_but_detects_browser_identity_change():
    first = {
        "user-agent": "Mozilla/5.0 Chrome/126", "accept-language": "pt-BR",
        "accept-encoding": "br", "sec-ch-ua-platform": '"Linux"',
    }
    same = {**first, "accept": "application/json", "sec-fetch-site": "same-origin"}
    changed = {**first, "sec-ch-ua-platform": '"Windows"'}

    assert request_fingerprint(first) == request_fingerprint(same)
    assert request_fingerprint(first) != request_fingerprint(changed)


def test_forwarded_tls_fingerprint_is_accepted_only_from_trusted_proxy():
    def request_from(peer: str):
        return Request({
            "type": "http", "method": "GET", "scheme": "https", "path": "/",
            "query_string": b"", "headers": [(b"x-inlock-ja4", b"t13d1516h2")],
            "client": (peer, 1234), "server": ("example.test", 443),
        })

    trusted = tls_fingerprint(
        request_from("127.0.0.1"), ["127.0.0.1/32"], "X-Inlock-JA4"
    )
    untrusted = tls_fingerprint(
        request_from("203.0.113.20"), ["127.0.0.1/32"], "X-Inlock-JA4"
    )

    assert trusted.startswith("forwarded:")
    assert untrusted == ""
