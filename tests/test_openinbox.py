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
    provider = OpenInboxProvider(api_key="tmp_test_key", banned_domains=frozenset())
    create = MagicMock()
    create.status_code = 200
    create.content = b'{"success":true,"data":{"id":"abc","email":"a@splitsmarter.com"}}'
    create.json.return_value = {
        "success": True,
        "data": {"id": "abc", "email": "a@splitsmarter.com"},
    }
    create.text = create.content.decode()
    session = MagicMock()
    session.request.return_value = create
    provider._session = session

    inbox = provider.create_inbox()
    assert inbox.address == "a@splitsmarter.com"
    assert inbox.external_id == "abc"
    assert "/v1/inboxes" in session.request.call_args[0][1]


def test_create_inbox_rejects_banned_domain_and_retries() -> None:
    banned = frozenset({"teminbox.click", "myfamilysync.app"})
    provider = OpenInboxProvider(api_key="tmp_test_key", banned_domains=banned)

    bad = MagicMock()
    bad.status_code = 200
    bad.content = (
        b'{"success":true,"data":{"id":"bad1","email":"x@teminbox.click"}}'
    )
    bad.json.return_value = {
        "success": True,
        "data": {"id": "bad1", "email": "x@teminbox.click"},
    }
    bad.text = bad.content.decode()

    deleted = MagicMock()
    deleted.status_code = 200
    deleted.content = b'{"success":true}'
    deleted.json.return_value = {"success": True}
    deleted.text = deleted.content.decode()

    good = MagicMock()
    good.status_code = 200
    good.content = (
        b'{"success":true,"data":{"id":"good1","email":"y@splitsmarter.com"}}'
    )
    good.json.return_value = {
        "success": True,
        "data": {"id": "good1", "email": "y@splitsmarter.com"},
    }
    good.text = good.content.decode()

    session = MagicMock()
    # POST create banned → DELETE → POST create ok
    session.request.side_effect = [bad, deleted, good]
    provider._session = session

    inbox = provider.create_inbox(prefix="jane.doe")
    assert inbox.address == "y@splitsmarter.com"
    assert inbox.external_id == "good1"
    methods = [c[0][0].upper() for c in session.request.call_args_list]
    paths = [c[0][1] for c in session.request.call_args_list]
    assert methods == ["POST", "DELETE", "POST"]
    assert any("bad1" in p for p in paths)


def test_create_inbox_rejects_myfamilysync() -> None:
    banned = frozenset({"teminbox.click", "myfamilysync.app"})
    provider = OpenInboxProvider(api_key="tmp_test_key", banned_domains=banned)

    bad = MagicMock()
    bad.status_code = 200
    bad.content = (
        b'{"success":true,"data":{"id":"m1","email":"a@myfamilysync.app"}}'
    )
    bad.json.return_value = {
        "success": True,
        "data": {"id": "m1", "email": "a@myfamilysync.app"},
    }
    bad.text = bad.content.decode()

    deleted = MagicMock()
    deleted.status_code = 200
    deleted.content = b"{}"
    deleted.json.return_value = {}
    deleted.text = ""

    good = MagicMock()
    good.status_code = 200
    good.content = (
        b'{"success":true,"data":{"id":"m2","email":"b@teminbox.xyz"}}'
    )
    good.json.return_value = {
        "success": True,
        "data": {"id": "m2", "email": "b@teminbox.xyz"},
    }
    good.text = good.content.decode()

    session = MagicMock()
    session.request.side_effect = [bad, deleted, good]
    provider._session = session

    inbox = provider.create_inbox()
    assert inbox.address == "b@teminbox.xyz"


def test_default_banned_domains() -> None:
    from regbot.config import openinbox_banned_domains

    banned = openinbox_banned_domains()
    assert "teminbox.click" in banned
    assert "myfamilysync.app" in banned


def test_is_banned_domain_helper() -> None:
    from regbot.email.openinbox import is_banned_domain

    banned = frozenset({"teminbox.click", "myfamilysync.app"})
    assert is_banned_domain("user@teminbox.click", banned)
    assert is_banned_domain("myfamilysync.app", banned)
    assert not is_banned_domain("user@splitsmarter.com", banned)


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


def test_looks_like_inbox_limit() -> None:
    from regbot.email.openinbox import looks_like_inbox_limit

    assert looks_like_inbox_limit(
        'Inbox limit reached. Your 7-Day Pass plan allows 10 concurrent inboxes.'
    )
    assert looks_like_inbox_limit("OpenInbox inbox limit (403): concurrent")
    assert not looks_like_inbox_limit("OpenInbox auth failed (403): invalid key")


def test_403_limit_not_auth_wording() -> None:
    provider = OpenInboxProvider(api_key="tmp_test_key")
    resp = MagicMock()
    resp.status_code = 403
    resp.content = b'{"message":"Inbox limit reached. 10 concurrent inboxes."}'
    resp.text = resp.content.decode()
    resp.json.return_value = {"message": "Inbox limit reached. 10 concurrent inboxes."}
    session = MagicMock()
    session.request.return_value = resp
    provider._session = session

    with pytest.raises(EmailProviderError, match="inbox limit") as ei:
        provider._request("POST", "/v1/inboxes", json_body={})
    assert "auth failed" not in str(ei.value).lower()


def test_401_still_auth() -> None:
    provider = OpenInboxProvider(api_key="tmp_test_key")
    resp = MagicMock()
    resp.status_code = 401
    resp.content = b'{"message":"Unauthorized"}'
    resp.text = "Unauthorized"
    session = MagicMock()
    session.request.return_value = resp
    provider._session = session

    with pytest.raises(EmailProviderError, match="auth failed"):
        provider._request("GET", "/v1/inboxes")


def test_create_inbox_frees_one_oldest_on_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At capacity: delete exactly one oldest inbox, then create succeeds."""
    monkeypatch.setattr("regbot.email.openinbox.config.REGBOT_OPENINBOX_PRUNE_OLDEST", True)
    provider = OpenInboxProvider(api_key="tmp_test_key")

    limit_body = (
        '{"statusCode":403,"message":"Inbox limit reached. Your 7-Day Pass plan '
        'allows 10 concurrent inboxes. Please delete an existing inbox."}'
    )
    limit_resp = MagicMock()
    limit_resp.status_code = 403
    limit_resp.content = limit_body.encode()
    limit_resp.text = limit_body
    limit_resp.json.return_value = {
        "statusCode": 403,
        "message": "Inbox limit reached. Your 7-Day Pass plan allows 10 concurrent inboxes.",
    }

    list_resp = MagicMock()
    list_resp.status_code = 200
    list_payload = {
        "success": True,
        "data": [
            {
                "id": "new-1",
                "email": "new@x.com",
                "createdAt": "2026-07-25T10:00:00.000Z",
            },
            {
                "id": "old-1",
                "email": "old@x.com",
                "createdAt": "2026-07-24T07:00:00.000Z",
            },
            {
                "id": "mid-1",
                "email": "mid@x.com",
                "createdAt": "2026-07-24T16:00:00.000Z",
            },
        ],
    }
    list_resp.content = b"{}"
    list_resp.text = "{}"
    list_resp.json.return_value = list_payload

    del_resp = MagicMock()
    del_resp.status_code = 204
    del_resp.content = b""
    del_resp.text = ""

    ok_resp = MagicMock()
    ok_resp.status_code = 200
    ok_resp.content = b'{"success":true,"data":{"id":"fresh","email":"fresh@x.com"}}'
    ok_resp.text = ok_resp.content.decode()
    ok_resp.json.return_value = {
        "success": True,
        "data": {"id": "fresh", "email": "fresh@x.com"},
    }

    session = MagicMock()
    # 1) POST create → limit
    # 2) GET list
    # 3) DELETE oldest
    # 4) POST create → ok
    session.request.side_effect = [limit_resp, list_resp, del_resp, ok_resp]
    provider._session = session

    inbox = provider.create_inbox(prefix="jane.doe")
    assert inbox.address == "fresh@x.com"
    assert inbox.external_id == "fresh"
    assert inbox.meta.get("pruned_oldest") is True

    methods = [c.args[0] for c in session.request.call_args_list]
    paths = [c.args[1] for c in session.request.call_args_list]
    assert methods == ["POST", "GET", "DELETE", "POST"]
    assert paths[2].endswith("/v1/inboxes/old-1")
    assert methods.count("DELETE") == 1


def test_create_inbox_limit_without_prune(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("regbot.email.openinbox.config.REGBOT_OPENINBOX_PRUNE_OLDEST", False)
    provider = OpenInboxProvider(api_key="tmp_test_key")
    limit_body = '{"message":"Inbox limit reached. 10 concurrent inboxes."}'
    limit_resp = MagicMock()
    limit_resp.status_code = 403
    limit_resp.content = limit_body.encode()
    limit_resp.text = limit_body
    session = MagicMock()
    session.request.return_value = limit_resp
    provider._session = session

    with pytest.raises(EmailProviderError, match="inbox limit"):
        provider.create_inbox()
    assert session.request.call_count == 1
