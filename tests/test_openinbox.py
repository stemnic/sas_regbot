"""OpenInbox provider unit tests (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.email.base import EmailProviderError, Inbox, get_email_provider
from regbot.email.openinbox import OpenInboxProvider, extract_otp


def test_extract_otp_from_html() -> None:
    assert extract_otp("<p>Your code is <b>482910</b></p>") == "482910"
    assert extract_otp("no code here") is None
    assert (
        extract_otp("SAS online - Account registration email verification code 509409")
        == "509409"
    )


def test_normalize_error_is_none_not_empty() -> None:
    """Regression: error payloads must not short-circuit list as []."""
    err = {
        "error": "inbox parameter is required",
        "usage": "GET /api/inbound/api/emails?inbox=INBOX_ID&limit=10",
    }
    assert OpenInboxProvider._normalize_email_list(err) is None


def test_normalize_v1_data_list() -> None:
    payload = {
        "success": True,
        "data": [
            {
                "id": "e1",
                "subject": "code 654321",
                "preview": "Your code is 654321",
            }
        ],
        "meta": {"total": 1},
    }
    msgs = OpenInboxProvider._normalize_email_list(payload)
    assert msgs is not None and len(msgs) == 1
    assert msgs[0]["id"] == "e1"


def test_normalize_explicit_empty_emails() -> None:
    assert OpenInboxProvider._normalize_email_list({"emails": []}) == []
    assert OpenInboxProvider._normalize_email_list({"success": True, "data": []}) == []


def test_list_emails_uses_v1_when_inbound_wrong() -> None:
    """Inbound error must not win; v1 messages must be returned."""
    provider = OpenInboxProvider(api_key="tmp_test_key")
    inbox = Inbox(address="u@example.com", external_id="inbox-uuid")

    v1_ok = MagicMock()
    v1_ok.status_code = 200
    v1_ok.content = b'{"success":true,"data":[{"id":"m1","subject":"code 111222","preview":"111222"}]}'
    v1_ok.json.return_value = {
        "success": True,
        "data": [{"id": "m1", "subject": "code 111222", "preview": "111222"}],
    }
    v1_ok.text = v1_ok.content.decode()

    session = MagicMock()
    # First call is v1 list (preferred)
    session.request.return_value = v1_ok
    provider._session = session

    msgs = provider._list_emails(inbox)
    assert len(msgs) == 1
    assert msgs[0]["id"] == "m1"
    path = session.request.call_args_list[0][0][1]
    assert "/v1/inboxes/inbox-uuid/emails" in path


def test_create_inbox_v1() -> None:
    provider = OpenInboxProvider(api_key="tmp_test_key")
    create = MagicMock()
    create.status_code = 200
    create.content = b'{"success":true,"data":{"id":"abc","email":"a@teminbox.click"}}'
    create.json.return_value = {
        "success": True,
        "data": {"id": "abc", "email": "a@teminbox.click"},
    }
    create.text = create.content.decode()
    session = MagicMock()
    session.request.return_value = create
    provider._session = session

    inbox = provider.create_inbox()
    assert inbox.address == "a@teminbox.click"
    assert inbox.external_id == "abc"
    assert "/v1/inboxes" in session.request.call_args[0][1]


def test_create_inbox_sends_prefix() -> None:
    provider = OpenInboxProvider(api_key="tmp_test_key")
    create = MagicMock()
    create.status_code = 200
    create.content = b'{"success":true,"data":{"id":"x","email":"john.smith12@splitsmarter.com"}}'
    create.json.return_value = {
        "success": True,
        "data": {"id": "x", "email": "john.smith12@splitsmarter.com"},
    }
    create.text = create.content.decode()
    session = MagicMock()
    session.request.return_value = create
    provider._session = session

    inbox = provider.create_inbox(prefix="john.smith12")
    assert "john.smith" in inbox.address
    body = session.request.call_args.kwargs.get("json") or session.request.call_args[1].get("json")
    # request(..., json=payload)
    call_kw = session.request.call_args
    payload = call_kw.kwargs.get("json") if call_kw.kwargs else None
    if payload is None and len(call_kw) > 1:
        payload = call_kw[1].get("json") if isinstance(call_kw[1], dict) else None
    # positional/keyword from MagicMock
    payload = session.request.call_args.kwargs.get("json")
    assert payload is not None
    assert payload.get("prefix", "").startswith("john.smith")


def test_wait_for_otp_from_preview() -> None:
    provider = OpenInboxProvider(api_key="tmp_test_key")
    list_resp = MagicMock()
    list_resp.status_code = 200
    list_resp.content = b"{}"
    list_resp.json.return_value = {
        "success": True,
        "data": [
            {
                "id": "e1",
                "subject": "SAS verification code 654321",
                "preview": "Just use the code below\n    654321\n",
            }
        ],
    }
    list_resp.text = "{}"
    session = MagicMock()
    session.request.return_value = list_resp
    provider._session = session

    inbox = Inbox(address="u@x.com", external_id="id1")
    with patch("regbot.email.openinbox.time.sleep"):
        otp = provider.wait_for_otp(inbox, timeout_s=10, poll_s=0)
    assert otp == "654321"


def test_requires_api_key() -> None:
    with pytest.raises(EmailProviderError, match="API key"):
        OpenInboxProvider(api_key="")


def test_factory_openinbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.config.OPENINBOX_API_KEY", "tmp_key")
    monkeypatch.setattr("regbot.config.EMAIL_API_KEY", "")
    provider = get_email_provider("openinbox")
    assert isinstance(provider, OpenInboxProvider)
