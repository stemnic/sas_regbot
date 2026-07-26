"""Mailhook provider unit tests (mocked HTTP)."""

from __future__ import annotations

import random
from unittest.mock import MagicMock, patch

import pytest

from regbot.email.base import (
    EmailProviderError,
    Inbox,
    StickyEmailProvider,
    get_email_provider,
    get_rotating_email_provider,
    pick_weighted_provider_name,
)
from regbot.email.mailhook import (
    MailhookProvider,
    extract_otp,
    looks_like_address_limit,
)


def test_extract_otp_from_mailhook_body() -> None:
    assert extract_otp("Your verification code is: 123456") == "123456"
    assert (
        extract_otp("SAS online - Account registration email verification code 509409")
        == "509409"
    )
    assert extract_otp("no code") is None


def test_looks_like_address_limit() -> None:
    assert looks_like_address_limit("email address limit reached on free tier")
    assert looks_like_address_limit("plan allows only 1 email address")
    assert not looks_like_address_limit("network timeout")


def test_create_inbox_with_local_part() -> None:
    provider = MailhookProvider(
        agent_id="mh_test",
        api_key="key",
        domain_id="5",
        auto_ensure_domain=False,
    )
    create = MagicMock()
    create.status_code = 200
    create.content = (
        b'{"data":{"id":"ea_1","type":"email_address",'
        b'"attributes":{"email":"john.smith@maple.tail.me","active":true}}}'
    )
    create.json.return_value = {
        "data": {
            "id": "ea_1",
            "type": "email_address",
            "attributes": {"email": "john.smith@maple.tail.me", "active": True},
        }
    }
    create.text = create.content.decode()
    session = MagicMock()
    session.request.return_value = create
    provider._session = session

    inbox = provider.create_inbox(prefix="john.smith")
    assert inbox.address == "john.smith@maple.tail.me"
    assert inbox.external_id == "ea_1"
    assert inbox.meta["provider"] == "mailhook"
    path = session.request.call_args[0][1]
    assert path.endswith("/email_addresses")
    assert session.request.call_args.kwargs["json"]["local_part"] == "john.smith"
    assert session.request.call_args.kwargs["json"]["domain_id"] == "5"


def test_create_inbox_random_without_prefix() -> None:
    provider = MailhookProvider(
        agent_id="mh_test",
        api_key="key",
        domain_id="5",
        auto_ensure_domain=False,
    )
    create = MagicMock()
    create.status_code = 200
    create.content = (
        b'{"data":{"id":"ea_r","attributes":{"email":"abc123@x.tail.me"}}}'
    )
    create.json.return_value = {
        "data": {"id": "ea_r", "attributes": {"email": "abc123@x.tail.me"}}
    }
    create.text = create.content.decode()
    session = MagicMock()
    session.request.return_value = create
    provider._session = session

    inbox = provider.create_inbox()
    assert inbox.address == "abc123@x.tail.me"
    assert "/email_addresses/random" in session.request.call_args[0][1]


def test_create_inbox_prunes_on_limit() -> None:
    provider = MailhookProvider(
        agent_id="mh_test",
        api_key="key",
        domain_id="5",
        auto_ensure_domain=False,
    )
    limit = MagicMock()
    limit.status_code = 422
    limit.content = b'{"error":"email address limit reached"}'
    limit.text = limit.content.decode()
    limit.json.return_value = {"error": "email address limit reached"}

    listed = MagicMock()
    listed.status_code = 200
    listed.content = (
        b'{"data":[{"id":"ea_old","attributes":{"email":"old@x.tail.me","created_at":"1"}}]}'
    )
    listed.json.return_value = {
        "data": [
            {
                "id": "ea_old",
                "attributes": {"email": "old@x.tail.me", "created_at": "1"},
            }
        ]
    }
    listed.text = listed.content.decode()

    deleted = MagicMock()
    deleted.status_code = 200
    deleted.content = b"{}"
    deleted.json.return_value = {}
    deleted.text = ""

    ok = MagicMock()
    ok.status_code = 200
    ok.content = (
        b'{"data":{"id":"ea_new","attributes":{"email":"new@x.tail.me"}}}'
    )
    ok.json.return_value = {
        "data": {"id": "ea_new", "attributes": {"email": "new@x.tail.me"}}
    }
    ok.text = ok.content.decode()

    session = MagicMock()
    # POST create (limit) → GET list → DELETE → POST create ok
    session.request.side_effect = [limit, listed, deleted, ok]
    provider._session = session

    with patch("regbot.email.mailhook.config.REGBOT_MAILHOOK_PRUNE_OLDEST", True):
        inbox = provider.create_inbox(prefix="jane.doe")
    assert inbox.address == "new@x.tail.me"
    assert inbox.external_id == "ea_new"
    assert inbox.meta.get("pruned_oldest") is True


def test_wait_for_otp_polls() -> None:
    provider = MailhookProvider(
        agent_id="mh_test",
        api_key="key",
        domain_id="5",
        auto_ensure_domain=False,
    )
    empty = MagicMock()
    empty.status_code = 200
    empty.content = b'{"data":[]}'
    empty.json.return_value = {"data": []}
    empty.text = empty.content.decode()

    ready = MagicMock()
    ready.status_code = 200
    ready.content = (
        b'{"data":[{"id":"ie_1","attributes":{'
        b'"subject":"Verify","text_body":"Your code is 654321"}}]}'
    )
    ready.json.return_value = {
        "data": [
            {
                "id": "ie_1",
                "attributes": {
                    "subject": "Verify",
                    "text_body": "Your code is 654321",
                },
            }
        ]
    }
    ready.text = ready.content.decode()

    session = MagicMock()
    session.request.side_effect = [empty, ready]
    provider._session = session
    inbox = Inbox(address="a@x.tail.me", external_id="ea_1")

    with patch("regbot.email.mailhook.time.sleep"):
        otp = provider.wait_for_otp(inbox, timeout_s=10, poll_s=0)
    assert otp == "654321"


def test_factory_mailhook(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.config.MAILHOOK_AGENT_ID", "mh_x")
    monkeypatch.setattr("regbot.config.MAILHOOK_API_KEY", "key_x")
    monkeypatch.setattr("regbot.config.MAILHOOK_DOMAIN_ID", "9")
    monkeypatch.setattr("regbot.config.MAILHOOK_AUTO_REGISTER", False)
    provider = get_email_provider("mailhook")
    assert isinstance(provider, MailhookProvider)
    assert provider.agent_id == "mh_x"
    assert provider.domain_id == "9"


def test_pick_weighted_provider_name_distribution() -> None:
    rng = random.Random(0)
    weights = [("openinbox", 5.0), ("mailhook", 1.0)]
    counts = {"openinbox": 0, "mailhook": 0}
    n = 6000
    for _ in range(n):
        counts[pick_weighted_provider_name(weights, rng=rng)] += 1
    # Mailhook ~1/6; allow statistical slack
    ratio = counts["mailhook"] / n
    assert 0.10 < ratio < 0.25
    assert counts["openinbox"] > counts["mailhook"]


def test_rotating_selects_mailhook_with_seeded_rng(monkeypatch: pytest.MonkeyPatch) -> None:
    oi = MagicMock()
    mh = MagicMock()

    def fake_try(name: str):
        if name == "openinbox":
            return oi
        if name == "mailhook":
            return mh
        return None

    monkeypatch.setattr("regbot.email.base._try_build_named", fake_try)
    # Force mailhook: roll in last 1/6 of [0,6)
    rng = random.Random()
    rng.random = lambda: 0.95  # type: ignore[method-assign]
    sticky = get_rotating_email_provider(
        rng=rng,
        weights=[("openinbox", 5.0), ("mailhook", 1.0)],
    )
    assert isinstance(sticky, StickyEmailProvider)
    assert sticky.name == "mailhook"
    assert sticky.inner is mh


def test_requires_credentials() -> None:
    with pytest.raises(EmailProviderError, match="MAILHOOK_AGENT_ID"):
        MailhookProvider(agent_id="", api_key="")
