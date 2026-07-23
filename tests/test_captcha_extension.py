"""CapSolver extension config unit tests."""

from __future__ import annotations

from pathlib import Path

from regbot.captcha.extension import build_extension_config, default_extension_path
from regbot.proxy import StickyProxy


def test_synthetic_host_html_includes_sitekey() -> None:
    from regbot.captcha.browser import _synthetic_host_html

    html = _synthetic_host_html("6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6")
    assert "6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6" in html
    assert "g-recaptcha" in html
    assert "captchaSolvedCallback" in html


def test_extension_bundled() -> None:
    assert (default_extension_path() / "assets" / "config.js").is_file()


def test_build_extension_config_patches_proxy() -> None:
    template = (default_extension_path() / "assets" / "config.js").read_text(encoding="utf-8")
    proxy = StickyProxy(
        session_id="abc12345xxxx",
        host="brd.superproxy.io:33335",
        username="user-session-abc12345xxxx",
        password="secret",
    )
    text = build_extension_config(
        template, api_key="cap-key-xyz", proxy=proxy, use_proxy=True, recaptcha_mode="token"
    )
    assert "cap-key-xyz" in text
    assert "useProxy: true" in text
    assert "brd.superproxy.io" in text
    assert "user-session-abc12345xxxx" in text
    assert "secret" in text
    assert "enabledForRecaptcha: true" in text
    assert "reCaptchaMode: \"token\"" in text or "reCaptchaMode: 'token'" in text


def test_build_extension_config_click_mode() -> None:
    template = (default_extension_path() / "assets" / "config.js").read_text(encoding="utf-8")
    text = build_extension_config(
        template, api_key="k", proxy=None, use_proxy=False, recaptcha_mode="click"
    )
    assert "reCaptchaMode: \"click\"" in text or "reCaptchaMode: 'click'" in text
