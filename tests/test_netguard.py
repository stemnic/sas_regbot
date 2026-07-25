"""Mullvad preflight and HTTP bind unit tests (no live Mullvad required)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from regbot.http_bind import SourceAddressAdapter, configure_bind, get_bound_session, make_bound_session
from regbot.netguard import (
    MullvadNotConnectedError,
    clear_mullvad_cache,
    get_curl_interface,
    parse_mullvad_connected,
    require_mullvad,
    resolve_interface_and_ip,
)


@pytest.fixture(autouse=True)
def _clear_mullvad_state() -> None:
    clear_mullvad_cache()
    configure_bind(None)
    yield
    clear_mullvad_cache()
    configure_bind(None)


def test_parse_mullvad_connected() -> None:
    assert parse_mullvad_connected("Connected\n    Relay: no-svg-wg-003")
    assert not parse_mullvad_connected("Disconnected")
    assert not parse_mullvad_connected("")
    assert not parse_mullvad_connected("Disconnecting")


def test_resolve_interface_prefers_wg0() -> None:
    pairs = [
        ("eth0", "10.0.0.5"),
        ("wg0-mullvad", "10.143.193.0"),
        ("docker0", "172.17.0.1"),
    ]
    with patch("regbot.netguard._list_ipv4_ifaces", return_value=pairs):
        name, ip = resolve_interface_and_ip(None)
    assert name == "wg0-mullvad"
    assert ip == "10.143.193.0"


def test_resolve_interface_honors_preferred() -> None:
    pairs = [
        ("wg0-mullvad", "10.143.193.0"),
        ("mullvad-custom", "10.99.0.1"),
    ]
    with patch("regbot.netguard._list_ipv4_ifaces", return_value=pairs):
        name, ip = resolve_interface_and_ip("mullvad-custom")
    assert name == "mullvad-custom"
    assert ip == "10.99.0.1"


def test_resolve_interface_missing() -> None:
    with patch("regbot.netguard._list_ipv4_ifaces", return_value=[("eth0", "1.2.3.4")]):
        with pytest.raises(MullvadNotConnectedError, match="No Mullvad"):
            resolve_interface_and_ip("wg0-mullvad")


def test_require_mullvad_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", False)
    bind = require_mullvad(probe_exit=False)
    assert bind.skipped
    assert bind.bind_ip is None


def test_require_mullvad_disconnected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_BIN", "mullvad")
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        patch("regbot.netguard._run_mullvad_status", return_value="Disconnected"),
        pytest.raises(MullvadNotConnectedError, match="not Connected"),
    ):
        require_mullvad(probe_exit=False, use_cache=False)


def test_require_mullvad_connected_no_probe_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_BIN", "mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_PROBE_EXIT", False)
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        patch(
            "regbot.netguard._run_mullvad_status",
            return_value="Connected\n    Relay: no-svg-wg-003",
        ),
        patch(
            "regbot.netguard._list_ipv4_ifaces",
            return_value=[("wg0-mullvad", "10.143.193.0")],
        ),
        patch("regbot.netguard._optional_exit_probe") as probe,
    ):
        bind = require_mullvad()
        probe.assert_not_called()
    assert bind.connected
    assert bind.interface == "wg0-mullvad"
    assert bind.bind_ip == "10.143.193.0"
    assert bind.exit_ip is None
    assert bind.probe_ok is None


def test_require_mullvad_probe_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_BIN", "mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_PROBE_EXIT", True)
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        patch(
            "regbot.netguard._run_mullvad_status",
            return_value="Connected\n    Relay: no-svg-wg-003",
        ),
        patch(
            "regbot.netguard._list_ipv4_ifaces",
            return_value=[("wg0-mullvad", "10.143.193.0")],
        ),
        patch("regbot.netguard._optional_exit_probe", return_value=("194.1.2.3", True)),
    ):
        bind = require_mullvad()
    assert bind.exit_ip == "194.1.2.3"
    assert bind.probe_ok is True


def test_require_mullvad_cache_second_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_BIN", "mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_PROBE_EXIT", False)
    status = patch(
        "regbot.netguard._run_mullvad_status",
        return_value="Connected\n    Relay: no-svg-wg-003",
    )
    ifaces = patch(
        "regbot.netguard._list_ipv4_ifaces",
        return_value=[("wg0-mullvad", "10.143.193.0")],
    )
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        status as st,
        ifaces as li,
    ):
        a = require_mullvad()
        b = require_mullvad()
        assert a is b or (a.bind_ip == b.bind_ip and a.interface == b.interface)
        assert st.call_count == 1
        assert li.call_count == 1


def test_get_curl_interface_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_CURL_BIND_INTERFACE", False)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_PROBE_EXIT", False)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        patch("regbot.netguard._run_mullvad_status", return_value="Connected"),
        patch(
            "regbot.netguard._list_ipv4_ifaces",
            return_value=[("wg0-mullvad", "10.143.193.0")],
        ),
    ):
        require_mullvad()
    assert get_curl_interface() is None


def test_get_curl_interface_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_CURL_BIND_INTERFACE", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_PROBE_EXIT", False)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    with (
        patch("regbot.netguard.shutil.which", return_value="/usr/bin/mullvad"),
        patch("regbot.netguard._run_mullvad_status", return_value="Connected"),
        patch(
            "regbot.netguard._list_ipv4_ifaces",
            return_value=[("wg0-mullvad", "10.143.193.0")],
        ),
    ):
        require_mullvad()
    assert get_curl_interface() == "10.143.193.0"


def test_source_address_adapter_sets_pool_kw() -> None:
    adapter = SourceAddressAdapter(source_address="10.143.193.0")
    with patch.object(SourceAddressAdapter.__bases__[0], "init_poolmanager") as super_init:
        adapter.init_poolmanager(10, 10)
    assert super_init.call_args.kwargs["source_address"] == ("10.143.193.0", 0)


def test_make_bound_session_no_bind() -> None:
    configure_bind(None)
    sess = make_bound_session(None)
    assert sess is not None
    sess.close()


def test_configure_bind_rebuilds_session() -> None:
    configure_bind("10.143.193.0")
    s1 = get_bound_session()
    configure_bind("10.143.193.0")
    s2 = get_bound_session()
    assert s1 is not s2
    configure_bind(None)
