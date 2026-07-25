"""Mullvad preflight and HTTP bind unit tests (no live Mullvad required)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.http_bind import SourceAddressAdapter, configure_bind, get_bound_session, make_bound_session
from regbot.netguard import (
    MullvadNotConnectedError,
    parse_mullvad_connected,
    require_mullvad,
    resolve_interface_and_ip,
)


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
        require_mullvad(probe_exit=False)


def test_require_mullvad_connected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.netguard.config.REGBOT_REQUIRE_MULLVAD", True)
    monkeypatch.setattr("regbot.netguard.config.REGBOT_BIND_INTERFACE", "wg0-mullvad")
    monkeypatch.setattr("regbot.netguard.config.REGBOT_MULLVAD_BIN", "mullvad")
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
        bind = require_mullvad(probe_exit=True)
    assert bind.connected
    assert bind.interface == "wg0-mullvad"
    assert bind.bind_ip == "10.143.193.0"
    assert bind.exit_ip == "194.1.2.3"
    assert bind.probe_ok is True


def test_source_address_adapter_sets_pool_kw() -> None:
    adapter = SourceAddressAdapter(source_address="10.143.193.0")
    with patch.object(SourceAddressAdapter.__bases__[0], "init_poolmanager") as super_init:
        adapter.init_poolmanager(10, 10)
    assert super_init.call_args.kwargs["source_address"] == ("10.143.193.0", 0)


def test_make_bound_session_no_bind() -> None:
    configure_bind(None)
    sess = make_bound_session(None)
    # Default Session has no SourceAddressAdapter mounts with source
    assert sess is not None
    sess.close()


def test_configure_bind_rebuilds_session() -> None:
    configure_bind("10.143.193.0")
    s1 = get_bound_session()
    configure_bind("10.143.193.0")
    s2 = get_bound_session()
    assert s1 is not s2  # rebuild on configure
    configure_bind(None)
