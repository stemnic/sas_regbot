"""Daily quota and circuit breaker tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.daily import (
    DailyState,
    clear_circuit,
    is_systemic_error,
    load_daily_state,
    open_circuit,
    run_daily,
    save_daily_state,
)
from regbot.store import RegisteredAccount


def test_is_systemic_error() -> None:
    assert is_systemic_error(RuntimeError("OpenInbox auth failed 401"))
    assert is_systemic_error(RuntimeError("CapSolver createTask error: insufficient balance"))
    assert is_systemic_error(RuntimeError("otpTemporaryBlocked"))
    assert is_systemic_error(RuntimeError("Mullvad is not Connected"))
    assert not is_systemic_error(RuntimeError("Enrollment HTTP 500 1015001"))


def test_daily_state_roundtrip(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    st = DailyState(date="2026-07-25", success=2, accounts=["a@b.com"])
    save_daily_state(st)
    loaded = load_daily_state(date="2026-07-25")
    assert loaded.success == 2
    assert loaded.accounts == ["a@b.com"]


def test_run_daily_quota_met(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_TARGET", 5)
    monkeypatch.setattr("regbot.daily.utc_today", lambda: "2026-07-25")
    save_daily_state(DailyState(date="2026-07-25", success=5, status="quota_met"))
    with patch("regbot.netguard.require_mullvad"):
        result = run_daily(target=5, debug=False, email_provider=MagicMock())
    assert result.exit_code == 0
    assert "Quota already met" in result.message


def test_run_daily_circuit_on_consec_fail(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_TARGET", 5)
    monkeypatch.setattr("regbot.daily.config.REGBOT_CIRCUIT_CONSEC_FAIL", 3)
    monkeypatch.setattr("regbot.daily.config.REGBOT_ACCOUNT_DELAY_S", 0)
    monkeypatch.setattr("regbot.daily.config.REG_ALERT_ENABLED", False)
    monkeypatch.setattr("regbot.daily.utc_today", lambda: "2026-07-25")

    def boom(**_kwargs):
        raise RuntimeError("Enrollment HTTP 500 1015001")

    with (
        patch("regbot.netguard.require_mullvad"),
        patch("regbot.daily.register_with_retries", side_effect=boom),
    ):
        result = run_daily(
            target=5,
            batch=5,
            max_proxy_attempts=3,
            delay_s=0,
            debug=False,
            email_provider=MagicMock(),
        )

    assert result.state.circuit_open
    assert result.state.status == "awaiting_review"
    assert result.state.consec_fail >= 3
    assert result.exit_code == 2


def test_run_daily_systemic_trips_immediately(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_TARGET", 5)
    monkeypatch.setattr("regbot.daily.config.REGBOT_ACCOUNT_DELAY_S", 0)
    monkeypatch.setattr("regbot.daily.config.REG_ALERT_ENABLED", False)
    monkeypatch.setattr("regbot.daily.utc_today", lambda: "2026-07-25")

    with (
        patch("regbot.netguard.require_mullvad"),
        patch(
            "regbot.daily.register_with_retries",
            side_effect=RuntimeError("OpenInbox 401 Unauthorized invalid key"),
        ),
    ):
        result = run_daily(
            target=5,
            batch=5,
            delay_s=0,
            debug=False,
            email_provider=MagicMock(),
        )

    assert result.state.circuit_open
    assert result.state.failures == 1
    assert "systemic" in (result.state.stop_reason or "")


def test_run_daily_default_batch_is_one(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One invocation only tries one account so cron can space the day."""
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_TARGET", 5)
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_BATCH", 1)
    monkeypatch.setattr("regbot.daily.config.REGBOT_ACCOUNT_DELAY_S", 0)
    monkeypatch.setattr("regbot.daily.utc_today", lambda: "2026-07-25")

    acc = RegisteredAccount(email="a@b.com", password="x", eb_number="1")
    with (
        patch("regbot.netguard.require_mullvad"),
        patch("regbot.daily.register_with_retries", return_value=acc) as reg,
    ):
        result = run_daily(target=5, debug=False, email_provider=MagicMock())
    assert reg.call_count == 1
    assert result.state.success == 1
    assert result.exit_code == 0


def test_clear_circuit(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.utc_today", lambda: "2026-07-25")
    st = DailyState(
        date="2026-07-25",
        circuit_open=True,
        status="awaiting_review",
        stop_reason="test",
        consec_fail=3,
    )
    save_daily_state(st)
    cleared = clear_circuit()
    assert not cleared.circuit_open
    assert cleared.consec_fail == 0


def test_open_circuit_sends_alert_once(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "daily_state.json"
    monkeypatch.setattr("regbot.daily.config.REGBOT_DAILY_STATE_PATH", str(path))
    monkeypatch.setattr("regbot.daily.config.REGBOT_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setattr("regbot.daily.config.REG_ALERT_ENABLED", True)
    st = DailyState(date="2026-07-25")
    with patch("regbot.daily.send_circuit_open_alert") as alert:
        open_circuit(st, reason="test reason", send_alert=True)
        open_circuit(st, reason="test reason again", send_alert=True)
    assert alert.call_count == 1
