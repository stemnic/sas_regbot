"""Forward Email alert client tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.alerts import AlertError, send_alert_email, send_circuit_open_alert


def test_send_alert_email_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.alerts.config.FORWARDEMAIL_API_KEY", "test-key")
    monkeypatch.setattr("regbot.alerts.config.REG_ALERT_FROM", "reg-infra@polarawards.com")
    monkeypatch.setattr("regbot.alerts.config.REG_ALERT_TO", "reg-alerts@polarawards.com")
    monkeypatch.setattr("regbot.alerts.config.FORWARDEMAIL_API_BASE", "https://api.forwardemail.net")

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"id": "abc", "status": "queued"}
    sess = MagicMock()
    sess.post.return_value = resp
    with patch("regbot.alerts.get_bound_session", return_value=sess) as gs:
        out = send_alert_email(subject="t", text="body")
    assert out["id"] == "abc"
    post = sess.post
    assert post.call_args.kwargs["auth"] == ("test-key", "")
    assert post.call_args.kwargs["data"]["from"] == "reg-infra@polarawards.com"
    assert post.call_args.kwargs["data"]["to"] == "reg-alerts@polarawards.com"
    gs.assert_called()


def test_send_alert_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.alerts.config.FORWARDEMAIL_API_KEY", "")
    with pytest.raises(AlertError, match="API_KEY"):
        send_alert_email(subject="t", text="b")


def test_circuit_alert_skipped_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.alerts.config.REG_ALERT_ENABLED", False)
    assert (
        send_circuit_open_alert(
            date="2026-07-25",
            stop_reason="test",
            success=0,
            failures=3,
            consec_fail=3,
            last_errors=["e1"],
        )
        is None
    )
