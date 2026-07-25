"""Proxy session and enforcement tests."""

from __future__ import annotations

import pytest

from regbot import config
from regbot.proxy import (
    StickyProxy,
    _next_oxylabs_port,
    _oxylabs_username,
    _session_username,
    new_sticky_proxy,
    reset_oxylabs_port_cycle,
)
from regbot.transport import ProxyRequiredError, ProxiedSession, is_sas_url


def test_session_username_appends_session() -> None:
    assert (
        _session_username("brd-customer-demo-zone-awards", "abc123")
        == "brd-customer-demo-zone-awards-session-abc123"
    )


def test_session_username_replaces_existing() -> None:
    assert (
        _session_username("brd-customer-demo-zone-awards-session-old123-country-us", "new456")
        == "brd-customer-demo-zone-awards-session-new456-country-us"
    )


def test_oxylabs_username_prefix() -> None:
    assert _oxylabs_username("scraper2_3mi9y", country="") == "user-scraper2_3mi9y"
    assert _oxylabs_username("user-scraper2_3mi9y", country="") == "user-scraper2_3mi9y"


def test_oxylabs_username_country_us() -> None:
    assert _oxylabs_username("scraper2_3mi9y", country="US") == "user-scraper2_3mi9y-country-US"
    assert _oxylabs_username("user-scraper2_3mi9y", country="US") == "user-scraper2_3mi9y-country-US"
    assert (
        _oxylabs_username("user-scraper2_3mi9y-country-US", country="US")
        == "user-scraper2_3mi9y-country-US"
    )
    assert _oxylabs_username("scraper2", country="country-us") == "user-scraper2-country-US"


def test_oxylabs_sticky_port_explicit(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(config, "PROXY_PROVIDER", "oxylabs")
    monkeypatch.setattr(config, "PROXY_USERNAME", "scraper2_3mi9y")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "secret=1")
    monkeypatch.setattr(config, "PROXY_HOST", "dc.oxylabs.io")
    monkeypatch.setattr(config, "OXYLABS_PORT", "")
    monkeypatch.setattr(config, "OXYLABS_COUNTRY", "US")
    monkeypatch.setattr(config, "REGBOT_PROXY_STATE_PATH", str(tmp_path / "state.json"))
    proxy = new_sticky_proxy("35467")
    assert proxy.provider == "oxylabs"
    assert proxy.host == "dc.oxylabs.io:35467"
    assert proxy.username == "user-scraper2_3mi9y-country-US"
    assert proxy.label == "oxy-35467"
    assert "country-US" in proxy.capsolver_proxy_string()
    assert proxy.capsolver_proxy_string().startswith("http:dc.oxylabs.io:35467:user-")
    assert "%3D" in proxy.proxies()["https"] or "secret" in proxy.proxies()["https"]


def test_oxylabs_port_pin(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(config, "PROXY_PROVIDER", "oxylabs")
    monkeypatch.setattr(config, "PROXY_USERNAME", "scraper2_3mi9y")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "secret")
    monkeypatch.setattr(config, "PROXY_HOST", "dc.oxylabs.io")
    monkeypatch.setattr(config, "OXYLABS_PORT", "12345")
    monkeypatch.setattr(config, "REGBOT_PROXY_STATE_PATH", str(tmp_path / "state.json"))
    proxy = new_sticky_proxy()
    assert proxy.host.endswith(":12345")


def test_oxylabs_ppt_port_in_range(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Pay-per-traffic: random sticky port in 8001–63000."""
    monkeypatch.setattr(config, "PROXY_PROVIDER", "oxylabs")
    monkeypatch.setattr(config, "PROXY_USERNAME", "scraper2_3mi9y")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "secret")
    monkeypatch.setattr(config, "PROXY_HOST", "dc.oxylabs.io")
    monkeypatch.setattr(config, "OXYLABS_PORT", "")
    monkeypatch.setattr(config, "OXYLABS_USE_PORT_LIST", False)
    monkeypatch.setattr(config, "REGBOT_PROXY_ROTATE", "ppt")
    monkeypatch.setattr(config, "OXYLABS_PORT_MIN", 8001)
    monkeypatch.setattr(config, "OXYLABS_PORT_MAX", 63000)
    monkeypatch.setattr(config, "REGBOT_PROXY_STATE_PATH", str(tmp_path / "state.json"))
    reset_oxylabs_port_cycle()

    for _ in range(20):
        port = int(_next_oxylabs_port())
        assert 8001 <= port <= 63000

    proxy = new_sticky_proxy()
    p = int(proxy.host_port()[1])
    assert 8001 <= p <= 63000
    assert proxy.host.startswith("dc.oxylabs.io:")


def test_oxylabs_ppt_avoids_last_port(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(config, "OXYLABS_PORT", "")
    monkeypatch.setattr(config, "OXYLABS_USE_PORT_LIST", False)
    monkeypatch.setattr(config, "REGBOT_PROXY_ROTATE", "ppt")
    monkeypatch.setattr(config, "OXYLABS_PORT_MIN", 9000)
    monkeypatch.setattr(config, "OXYLABS_PORT_MAX", 9001)
    monkeypatch.setattr(config, "REGBOT_PROXY_STATE_PATH", str(tmp_path / "state.json"))
    reset_oxylabs_port_cycle()

    first = _next_oxylabs_port()
    second = _next_oxylabs_port()
    # With only two ports, avoid-last should flip
    assert first != second
    third = _next_oxylabs_port()
    assert third != second


def test_oxylabs_legacy_list_roundrobin(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    state = tmp_path / "oxy_port_state.json"
    monkeypatch.setattr(config, "PROXY_PROVIDER", "oxylabs")
    monkeypatch.setattr(config, "PROXY_USERNAME", "scraper2_3mi9y")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "secret")
    monkeypatch.setattr(config, "PROXY_HOST", "dc.oxylabs.io")
    monkeypatch.setattr(config, "OXYLABS_PORT", "")
    monkeypatch.setattr(config, "OXYLABS_PORTS", "8001,8002,8003")
    monkeypatch.setattr(config, "OXYLABS_USE_PORT_LIST", True)
    monkeypatch.setattr(config, "REGBOT_PROXY_ROTATE", "roundrobin")
    monkeypatch.setattr(config, "REGBOT_PROXY_STATE_PATH", str(state))
    reset_oxylabs_port_cycle()

    ports = [new_sticky_proxy().host.split(":")[-1] for _ in range(6)]
    assert set(ports[:3]) == {"8001", "8002", "8003"}
    assert ports[3:6] == ports[:3]


def test_brightdata_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "PROXY_PROVIDER", "brightdata")
    monkeypatch.setattr(config, "PROXY_USERNAME", "user")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "secret")
    monkeypatch.setattr(config, "PROXY_HOST", "brd.superproxy.io:33335")
    proxy = new_sticky_proxy("abc12345xxxx")
    assert proxy.provider == "brightdata"
    assert "-session-abc12345xxxx" in proxy.username
    assert proxy.capsolver_proxy_string() == (
        f"http:brd.superproxy.io:33335:{proxy.username}:secret"
    )


def test_new_sticky_proxy_requires_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "PROXY_USERNAME", "")
    monkeypatch.setattr(config, "PROXY_PASSWORD", "")
    with pytest.raises(RuntimeError, match="PROXY_USERNAME"):
        new_sticky_proxy()


def test_is_sas_url() -> None:
    assert is_sas_url("https://api2.flysas.com/customer/v2/enrollment")
    assert is_sas_url("https://www.flysas.com/en/register/")
    assert not is_sas_url("https://api.capsolver.com/createTask")
    assert not is_sas_url("https://api.ipify.org/")


def test_proxied_session_refuses_empty_proxies() -> None:
    class FakeSession:
        def __init__(self, **kwargs):
            self.proxies = {}
            self.kwargs = kwargs

        def close(self):
            pass

    proxy = StickyProxy(
        session_id="testsession1",
        host="dc.oxylabs.io:8001",
        username="user-u",
        password="p",
        provider="oxylabs",
    )

    def factory(**kwargs):
        s = FakeSession(**kwargs)
        s.proxies = {}
        return s

    with pytest.raises(ProxyRequiredError):
        ProxiedSession(proxy, session_factory=factory)
