"""TLS impersonate mapping from CapSolver user agents."""

from __future__ import annotations

from regbot.fingerprint import impersonate_for_user_agent


def test_chrome_ua_maps_to_chrome_profile() -> None:
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
    )
    profile = impersonate_for_user_agent(ua)
    assert profile.startswith("chrome")


def test_firefox_ua_maps_to_firefox() -> None:
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
    profile = impersonate_for_user_agent(ua)
    assert profile.startswith("firefox")


def test_empty_ua_uses_default() -> None:
    assert impersonate_for_user_agent(None, default="firefox147") == "firefox147"
