"""AnyMessage provider unit tests (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.email.anymessage import AnyMessageProvider, extract_otp
from regbot.email.base import EmailProviderError, get_email_provider


def test_extract_otp_from_html() -> None:
    html = "<p>Your code is <b>755461</b> and expires soon.</p>"
    assert extract_otp(html) == "755461"


def test_order_success() -> None:
    session = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Content-Type": "application/json"}
    response.text = '{"status":"success","id":"1001","email":"test@gmx.com"}'
    response.json.return_value = {
        "status": "success",
        "id": "1001",
        "email": "test@gmx.com",
    }
    session.get.return_value = response

    provider = AnyMessageProvider(token="tok", site="flysas.com", session=session)
    inbox = provider.create_inbox()
    assert inbox.address == "test@gmx.com"
    assert inbox.external_id == "1001"
    assert "token=tok" in session.get.call_args[0][0]
    assert "site=flysas.com" in session.get.call_args[0][0]


def test_order_no_balance() -> None:
    session = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.headers = {"Content-Type": "application/json"}
    response.text = '{"status":"error","value":"no balance"}'
    response.json.return_value = {"status": "error", "value": "no balance"}
    session.get.return_value = response

    provider = AnyMessageProvider(token="tok", site="flysas.com", session=session)
    with pytest.raises(EmailProviderError, match="no balance"):
        provider.create_inbox()


def test_wait_for_otp_polls_then_succeeds() -> None:
    session = MagicMock()
    wait = MagicMock()
    wait.status_code = 200
    wait.headers = {"Content-Type": "application/json"}
    wait.text = '{"status":"error","value":"wait message"}'
    wait.json.return_value = {"status": "error", "value": "wait message"}

    ready = MagicMock()
    ready.status_code = 200
    ready.headers = {"Content-Type": "application/json"}
    ready.text = '{"status":"success","message":"<p>Code 123456</p>"}'
    ready.json.return_value = {"status": "success", "message": "<p>Code 123456</p>"}

    session.get.side_effect = [wait, ready]
    provider = AnyMessageProvider(token="tok", site="flysas.com", session=session)
    inbox = MagicMock()
    inbox.address = "test@gmx.com"
    inbox.external_id = "1001"

    with patch("regbot.email.anymessage.time.sleep"):
        otp = provider.wait_for_otp(inbox, timeout_s=30, poll_s=0)
    assert otp == "123456"


def test_factory_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.config.ANYMESSAGE_TOKEN", "")
    monkeypatch.setattr("regbot.config.EMAIL_API_KEY", "")
    monkeypatch.setattr("regbot.email.anymessage.config.ANYMESSAGE_TOKEN", "")
    monkeypatch.setattr("regbot.email.anymessage.config.EMAIL_API_KEY", "")
    with pytest.raises(EmailProviderError, match="token"):
        get_email_provider("anymessage")


def test_fixed_email_via_factory() -> None:
    provider = get_email_provider(fixed_email="a@b.com", fixed_otp="654321")
    inbox = provider.create_inbox()
    assert inbox.address == "a@b.com"
    assert provider.wait_for_otp(inbox) == "654321"
