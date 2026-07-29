"""FreeCustom.Email provider unit tests (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from regbot.email.base import EmailProviderError, Inbox, get_email_provider
from regbot.email.freecustom import FreeCustomProvider, extract_otp


def test_extract_otp() -> None:
    assert extract_otp("Your code is 482910") == "482910"
    assert extract_otp("nope") is None


def test_create_inbox_register_varied_domain() -> None:
    provider = FreeCustomProvider(api_key="fce_test", domain="ditapi.info")
    domains = MagicMock()
    domains.status_code = 200
    domains.content = b'{"data":[{"domain":"haloforge.online","tier":"free","tags":[]},{"domain":"ditapi.info","tier":"free","tags":[]}]}'
    domains.json.return_value = {
        "data": [
            {"domain": "haloforge.online", "tier": "free", "tags": []},
            {"domain": "ditapi.info", "tier": "free", "tags": []},
        ]
    }
    domains.text = domains.content.decode()

    reg = MagicMock()
    reg.status_code = 200
    reg.content = b'{"success":true,"inbox":"jane.doe@haloforge.online","message":"ok"}'
    reg.json.return_value = {
        "success": True,
        "inbox": "jane.doe@haloforge.online",
        "message": "ok",
    }
    reg.text = reg.content.decode()

    session = MagicMock()
    session.request.side_effect = [domains, reg]
    provider._session = session

    with patch("regbot.email.freecustom.random.shuffle", side_effect=lambda x: x):
        inbox = provider.create_inbox(prefix="jane.doe")
    assert inbox.address == "jane.doe@haloforge.online"
    assert inbox.meta["via"] == "register"
    assert inbox.meta["domain"] == "haloforge.online"


def test_domain_pool_shuffles_free_only() -> None:
    provider = FreeCustomProvider(
        api_key="fce_test", domain="ditapi.info", banned_domains=frozenset()
    )
    domains = MagicMock()
    domains.status_code = 200
    domains.content = b"{}"
    domains.json.return_value = {
        "data": [
            {"domain": "a.info", "tier": "free", "tags": []},
            {"domain": "b.info", "tier": "free", "tags": []},
            {"domain": "pro.only", "tier": "pro", "tags": []},
        ]
    }
    domains.text = "{}"
    session = MagicMock()
    session.request.return_value = domains
    provider._session = session
    with patch("regbot.email.freecustom.random.shuffle") as shuf:
        shuf.side_effect = lambda xs: xs.reverse() or xs
        pool = provider._domain_pool()
    assert "pro.only" not in pool
    assert set(pool) == {"a.info", "b.info"}


def test_banned_domain_excluded() -> None:
    provider = FreeCustomProvider(
        api_key="fce_test",
        domain="ditapi.info",
        banned_domains=frozenset({"ditlearn.info"}),
    )
    domains = MagicMock()
    domains.status_code = 200
    domains.content = b"{}"
    domains.json.return_value = {
        "data": [
            {"domain": "ditlearn.info", "tier": "free", "tags": []},
            {"domain": "haloforge.online", "tier": "free", "tags": []},
        ]
    }
    domains.text = "{}"
    session = MagicMock()
    session.request.return_value = domains
    provider._session = session
    free = provider.free_domains()
    assert "ditlearn.info" not in free
    assert free == ["haloforge.online"]


def test_default_banned_includes_ditlearn() -> None:
    from regbot.config import freecustom_banned_domains

    banned = freecustom_banned_domains()
    assert "ditlearn.info" in banned
    assert "junkstopper.info" in banned


def test_wait_for_otp_public_token() -> None:
    provider = FreeCustomProvider(api_key="fce_test", domain="ditapi.info")
    otp_resp = MagicMock()
    otp_resp.status_code = 200
    otp_resp.content = b'{"success":true,"data":{"otp":"123456"}}'
    otp_resp.json.return_value = {"success": True, "data": {"otp": "123456"}}
    otp_resp.text = otp_resp.content.decode()
    session = MagicMock()
    session.request.return_value = otp_resp
    provider._session = session

    inbox = Inbox(
        address="a@ditapi.info",
        token="fceotp_abc",
        meta={"provider": "freecustom", "otp_url": ""},
    )
    with patch("regbot.email.freecustom.time.sleep"):
        otp = provider.wait_for_otp(inbox, timeout_s=5, poll_s=0)
    assert otp == "123456"


def test_wait_for_otp_from_message_body() -> None:
    provider = FreeCustomProvider(api_key="fce_test", domain="ditapi.info")
    # public otp miss, /otp miss, list messages, get detail
    miss = MagicMock()
    miss.status_code = 200
    miss.content = b'{"success":true,"data":{"otp":null}}'
    miss.json.return_value = {"success": True, "data": {"otp": None}}
    miss.text = miss.content.decode()

    listed = MagicMock()
    listed.status_code = 200
    listed.content = b'{"success":true,"data":{"messages":[{"id":"m1","subject":"code"}],"count":1}}'
    listed.json.return_value = {
        "success": True,
        "data": {"messages": [{"id": "m1", "subject": "code"}], "count": 1},
    }
    listed.text = listed.content.decode()

    detail = MagicMock()
    detail.status_code = 200
    detail.content = (
        b'{"success":true,"data":{"id":"m1","text":"Your verification code is 654321"}}'
    )
    detail.json.return_value = {
        "success": True,
        "data": {"id": "m1", "text": "Your verification code is 654321"},
    }
    detail.text = detail.content.decode()

    session = MagicMock()
    # no public token → /otp, list, detail
    session.request.side_effect = [miss, listed, detail]
    provider._session = session

    inbox = Inbox(address="a@ditapi.info", meta={"provider": "freecustom"})
    with patch("regbot.email.freecustom.time.sleep"):
        otp = provider.wait_for_otp(inbox, timeout_s=10, poll_s=0)
    assert otp == "654321"


def test_requires_api_key() -> None:
    with pytest.raises(EmailProviderError, match="API key"):
        FreeCustomProvider(api_key="")


def test_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.config.FREECUSTOM_API_KEY", "fce_x")
    monkeypatch.setattr("regbot.config.FREECUSTOM_DOMAIN", "ditube.info")
    p = get_email_provider("freecustom")
    assert isinstance(p, FreeCustomProvider)
    assert p.domain == "ditube.info"
