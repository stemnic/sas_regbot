"""CapSolver helper unit tests (docs-aligned v2)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.captcha.api import CapsolverError, solve_recaptcha_v2
from regbot.proxy import StickyProxy


def test_requires_api_key() -> None:
    proxy = StickyProxy("p8001", "dc.oxylabs.io:8001", "user-u", "p", provider="oxylabs")
    with pytest.raises(CapsolverError, match="CAPSOLVER_API_KEY"):
        solve_recaptcha_v2(
            api_key="",
            website_url="https://www.flysas.com/en/register/password/",
            website_key="6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6",
            proxy=proxy,
            mode="proxy",
        )


def _session_with_posts(side_effect: list) -> MagicMock:
    sess = MagicMock()
    sess.post.side_effect = side_effect
    return sess


@patch("regbot.captcha.api.get_bound_session")
def test_solve_proxy_mode_docs_fields(mock_gs: MagicMock) -> None:
    proxy = StickyProxy(
        "p8001",
        "dc.oxylabs.io:8001",
        "user-scraper2_3mi9y",
        "secret=1",
        provider="oxylabs",
    )

    create = MagicMock()
    create.raise_for_status = MagicMock()
    create.json.return_value = {"errorId": 0, "taskId": "t1"}

    ready = MagicMock()
    ready.raise_for_status = MagicMock()
    ready.json.return_value = {
        "errorId": 0,
        "status": "ready",
        "solution": {
            "gRecaptchaResponse": "TOKEN123",
            "userAgent": "Mozilla/5.0 CapSolver",
            "secChUa": '"Chromium"',
            "recaptcha-ca-e": "cookie-e",
            "createTime": 123,
        },
    }
    sess = _session_with_posts([create, ready])
    mock_gs.return_value = sess

    forced_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    )
    with patch("regbot.captcha.api.time.sleep"):
        sol = solve_recaptcha_v2(
            api_key="key",
            website_url="https://www.flysas.com/en/register/password/",
            website_key="6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6",
            proxy=proxy,
            mode="proxy",
            poll_timeout_s=30,
            is_invisible=False,
            proxy_formats=["http_colon"],
            user_agent=forced_ua,
        )
    assert sol.token == "TOKEN123"
    assert sol.user_agent == "Mozilla/5.0 CapSolver"
    assert sol.recaptcha_ca_e == "cookie-e"
    assert sol.cookie_header() == "recaptcha-ca-e=cookie-e"
    payload = sess.post.call_args_list[0].kwargs["json"]
    task = payload["task"]
    assert task["type"] == "ReCaptchaV2Task"
    assert task["isInvisible"] is False
    assert task["websiteURL"].endswith("/register/password/")
    assert task["proxy"].startswith("http:dc.oxylabs.io:8001:user-scraper2_3mi9y:")
    assert task["userAgent"] == forced_ua


@patch("regbot.captcha.api.get_bound_session")
def test_solve_proxyless_mode(mock_gs: MagicMock) -> None:
    create = MagicMock()
    create.raise_for_status = MagicMock()
    create.json.return_value = {"errorId": 0, "taskId": "t2"}
    ready = MagicMock()
    ready.raise_for_status = MagicMock()
    ready.json.return_value = {
        "errorId": 0,
        "status": "ready",
        "solution": {"gRecaptchaResponse": "TOKENLESS"},
    }
    sess = _session_with_posts([create, ready])
    mock_gs.return_value = sess

    with patch("regbot.captcha.api.time.sleep"):
        sol = solve_recaptcha_v2(
            api_key="key",
            website_url="https://www.flysas.com/en/register/password/",
            website_key="6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6",
            mode="proxyless",
            poll_timeout_s=30,
        )
    assert sol.token == "TOKENLESS"
    payload = sess.post.call_args_list[0].kwargs["json"]
    assert payload["task"]["type"] == "ReCaptchaV2TaskProxyLess"
    assert "proxy" not in payload["task"]


@patch("regbot.captcha.api.get_bound_session")
def test_solve_captcha_passes_forced_ua(mock_gs: MagicMock) -> None:
    """solve_captcha default path injects REGBOT_CAPTCHA_USER_AGENT into ReCaptchaV2Task."""
    from regbot.captcha import solve_captcha

    proxy = StickyProxy("p8001", "dc.oxylabs.io:8001", "u", "p", provider="oxylabs")
    create = MagicMock()
    create.raise_for_status = MagicMock()
    create.json.return_value = {"errorId": 0, "taskId": "t3"}
    ready = MagicMock()
    ready.raise_for_status = MagicMock()
    ready.json.return_value = {
        "errorId": 0,
        "status": "ready",
        "solution": {"gRecaptchaResponse": "T", "userAgent": "returned-ua"},
    }
    sess = _session_with_posts([create, ready])
    mock_gs.return_value = sess
    forced = "Mozilla/5.0 Chrome/146.0.0.0 forced"

    with patch("regbot.captcha.api.time.sleep"):
        sol = solve_captcha(
            mode="proxy",
            proxy=proxy,
            api_key="key",
            user_agent=forced,
        )
    assert sol.token == "T"
    task = sess.post.call_args_list[0].kwargs["json"]["task"]
    assert task["type"] == "ReCaptchaV2Task"
    assert task["userAgent"] == forced
