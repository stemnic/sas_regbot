"""Offline registration flow with mocked transport / CapSolver / email."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from regbot.email.base import FakeEmailProvider
from regbot.profile import generate_us_profile
from regbot.sas_register import RegistrationError, SasRegisterClient, register_once, register_with_retries
from regbot.store import RegisteredAccount, save_account
from regbot.transport import BlockedError


def test_save_account_roundtrip(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("regbot.store.config.REGBOT_ACCOUNTS_DIR", str(tmp_path))
    account = RegisteredAccount(
        email="a@b.com",
        password="Secret1!",
        eb_number="772493862",
    )
    path = save_account(account)
    assert path.exists()
    assert (tmp_path / "accounts.jsonl").exists()
    text = path.read_text(encoding="utf-8")
    assert "772493862" in text


def test_client_builds_enrollment_body() -> None:
    session = MagicMock()
    session.post.return_value = {"ok": True}
    client = SasRegisterClient(session, ua="UA-TEST")
    profile = generate_us_profile()
    client.enroll(
        email="u@example.com",
        profile=profile,
        enrollment_token="jwt",
        captcha="captcha-token",
        terms_version=3,
    )
    args, kwargs = session.post.call_args
    assert args[0].endswith("/v2/enrollment")
    body = kwargs["json_body"]
    assert body["userName"] == "u@example.com"
    assert body["enrollmentToken"] == "jwt"
    assert body["captcha"] == "captcha-token"
    assert body["termsVersion"] == 3
    assert body["enrollmentType"] == "FULL"
    assert body["address"]["physical"][0]["country"]["code"] == "US"


def _fake_solution(token: str = "captcha-tok"):
    from regbot.captcha.api import CaptchaSolution

    return CaptchaSolution(token=token, user_agent="UA-CAP", recaptcha_ca_e="cae")


@patch("regbot.sas_register.solve_captcha", return_value=_fake_solution())
@patch("regbot.sas_register.ProxiedSession")
@patch("regbot.sas_register.new_sticky_proxy")
def test_register_once_happy_path(
    mock_proxy: MagicMock,
    mock_session_cls: MagicMock,
    mock_captcha: MagicMock,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regbot.proxy import StickyProxy

    monkeypatch.setattr("regbot.sas_register.config.PROXY_USERNAME", "user")
    monkeypatch.setattr("regbot.sas_register.config.PROXY_PASSWORD", "pass")
    monkeypatch.setattr("regbot.sas_register.config.CAPSOLVER_API_KEY", "cap-key")
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_CAPTCHA_MODE", "proxy")
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_CAPTCHA_RETRIES", 1)
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_REFRESH_TOKEN_EACH_ENROLL", False)
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_ACCOUNTS_DIR", str(tmp_path))
    monkeypatch.setattr("regbot.store.config.REGBOT_ACCOUNTS_DIR", str(tmp_path))

    proxy = StickyProxy("sess12345678", "brd.superproxy.io:33335", "user-session-sess12345678", "pass")
    mock_proxy.return_value = proxy

    session = MagicMock()
    enroll_session = MagicMock()
    mock_session_cls.return_value.__enter__.return_value = session
    mock_session_cls.return_value.__exit__.return_value = None
    session.sibling.return_value = enroll_session

    session.request.return_value = MagicMock()
    session.get_proxy_ip.return_value = "1.2.3.4"

    def post(url: str, **kwargs: Any) -> dict:
        if url.endswith("requestOtp"):
            return {"emailSendStatus": "success", "registrationStatus": "EMAIL_SENT"}
        if url.endswith("validateOtp"):
            return {"enrollmentToken": "jwt-token", "registrationStatus": "VERIFIED"}
        if url.endswith("enrollment"):
            return {
                "crmReference": "41609568",
                "engagements": {"euroBonus": {"ebNumber": "772493862"}},
            }
        raise AssertionError(url)

    def get(url: str, **kwargs: Any) -> dict:
        if "agreement" in url:
            return {"version": 3, "memberType": "EB"}
        raise AssertionError(url)

    session.post.side_effect = post
    session.get.side_effect = get
    enroll_session.post.side_effect = post
    enroll_session.close = MagicMock()

    account = register_once(
        email_provider=FakeEmailProvider("harry.test@slmails.com", "755461"),
        debug=False,
        fetch_proxy_ip=True,
    )
    assert account.eb_number == "772493862"
    assert account.email == "harry.test@slmails.com"
    assert account.password
    mock_captcha.assert_called()
    assert mock_captcha.call_args.kwargs["mode"] == "proxy"
    assert mock_captcha.call_args.kwargs["proxy"] is proxy
    session.sibling.assert_called()
    enroll_session.close.assert_called()


def test_classify_otp_already_verified() -> None:
    kind, token = SasRegisterClient.classify_otp_response(
        {
            "emailStatus": "verified",
            "enrollmentToken": "jwt-abc",
            "status": "verified",
            "registrationStatus": "VERIFIED",
        }
    )
    assert kind == "verified"
    assert token == "jwt-abc"


@patch("regbot.sas_register.solve_captcha", return_value=_fake_solution())
@patch("regbot.sas_register.ProxiedSession")
@patch("regbot.sas_register.new_sticky_proxy")
def test_resume_skips_otp(
    mock_proxy: MagicMock,
    mock_session_cls: MagicMock,
    mock_captcha: MagicMock,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regbot.proxy import StickyProxy
    from regbot.sas_register import EnrollmentResume

    monkeypatch.setattr("regbot.sas_register.config.PROXY_USERNAME", "user")
    monkeypatch.setattr("regbot.sas_register.config.PROXY_PASSWORD", "pass")
    monkeypatch.setattr("regbot.sas_register.config.CAPSOLVER_API_KEY", "cap-key")
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_CAPTCHA_MODE", "proxy")
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_CAPTCHA_RETRIES", 1)
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_REFRESH_TOKEN_EACH_ENROLL", False)
    monkeypatch.setattr("regbot.sas_register.config.REGBOT_ACCOUNTS_DIR", str(tmp_path))
    monkeypatch.setattr("regbot.store.config.REGBOT_ACCOUNTS_DIR", str(tmp_path))

    mock_proxy.return_value = StickyProxy("s", "h:1", "u", "p")
    session = MagicMock()
    enroll_session = MagicMock()
    mock_session_cls.return_value.__enter__.return_value = session
    mock_session_cls.return_value.__exit__.return_value = None
    session.sibling.return_value = enroll_session
    session.get_proxy_ip.return_value = "1.2.3.4"
    session.get.return_value = {"version": 3}
    enroll_payload = {
        "crmReference": "1",
        "engagements": {"euroBonus": {"ebNumber": "999"}},
    }
    enroll_session.post.return_value = enroll_payload
    enroll_session.close = MagicMock()

    profile = generate_us_profile()
    account = register_once(
        email_provider=FakeEmailProvider("ignored@x.com", "000000"),
        resume=EnrollmentResume(
            email="harry.musky275@slmails.com",
            enrollment_token="jwt-resume",
            profile=profile,
        ),
        fetch_proxy_ip=False,
    )
    assert account.email == "harry.musky275@slmails.com"
    assert account.eb_number == "999"
    # Enroll uses sibling session with CapSolver-aligned TLS
    assert enroll_session.post.call_args.kwargs["json_body"]["enrollmentToken"] == "jwt-resume"
    assert mock_captcha.call_args.kwargs["mode"] == "proxy"
    assert mock_captcha.call_args.kwargs["proxy"] is mock_proxy.return_value
    enroll_session.close.assert_called()


@patch("regbot.sas_register.ProxiedSession")
@patch("regbot.sas_register.new_sticky_proxy")
def test_invalid_email_fails_fast(
    mock_proxy: MagicMock,
    mock_session_cls: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regbot.proxy import StickyProxy

    monkeypatch.setattr("regbot.sas_register.config.PROXY_USERNAME", "user")
    monkeypatch.setattr("regbot.sas_register.config.PROXY_PASSWORD", "pass")
    monkeypatch.setattr("regbot.sas_register.config.CAPSOLVER_API_KEY", "cap-key")

    mock_proxy.return_value = StickyProxy("s", "h:1", "u", "p")
    session = MagicMock()
    mock_session_cls.return_value.__enter__.return_value = session
    mock_session_cls.return_value.__exit__.return_value = None
    session.get_proxy_ip.return_value = "1.2.3.4"
    session.request.return_value = MagicMock()

    with pytest.raises(RegistrationError, match="regex"):
        register_once(
            email_provider=FakeEmailProvider("bad", "123456"),
            fetch_proxy_ip=False,
        )


def test_otp_request_error_detects_rate_limit() -> None:
    err = SasRegisterClient.otp_request_error(
        {
            "status": "abused",
            "registrationStatus": "VERIFICATION_FAILED",
            "error": "otpTemporaryBlocked",
            "message": "retryLater",
            "retryEarliestAtUtc": "2026-07-23T21:07:06.751Z",
        }
    )
    assert err is not None
    assert "otpTemporaryBlocked" in err
    assert SasRegisterClient.otp_request_error(
        {"emailSendStatus": "success", "registrationStatus": "EMAIL_SENT"}
    ) is None
    assert SasRegisterClient.otp_request_error(
        {
            "status": "verified",
            "registrationStatus": "VERIFIED",
            "enrollmentToken": "jwt",
        }
    ) is None


def test_html_warm_blocked_is_soft() -> None:
    session = MagicMock()
    session.request.side_effect = BlockedError("challenge-platform", status=403, body="cf-chl")
    client = SasRegisterClient(session)
    # force HTML warm on
    import regbot.sas_register as mod

    old_skip = mod.config.REGBOT_SKIP_HTML_WARM
    old_url = mod.config.REGBOT_WARM_URL
    try:
        mod.config.REGBOT_SKIP_HTML_WARM = False
        mod.config.REGBOT_WARM_URL = "https://www.flysas.com/en/register/"
        assert client.warm_html() == "soft_fail_blocked"
    finally:
        mod.config.REGBOT_SKIP_HTML_WARM = old_skip
        mod.config.REGBOT_WARM_URL = old_url


@patch("regbot.sas_register.ProxiedSession")
@patch("regbot.sas_register.new_sticky_proxy")
def test_request_otp_business_error_not_retried(
    mock_proxy: MagicMock,
    mock_session_cls: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from regbot.proxy import StickyProxy

    monkeypatch.setattr("regbot.sas_register.config.PROXY_USERNAME", "user")
    monkeypatch.setattr("regbot.sas_register.config.PROXY_PASSWORD", "pass")
    monkeypatch.setattr("regbot.sas_register.config.CAPSOLVER_API_KEY", "cap-key")

    mock_proxy.return_value = StickyProxy("s", "h:1", "u", "p")
    session = MagicMock()
    mock_session_cls.return_value.__enter__.return_value = session
    mock_session_cls.return_value.__exit__.return_value = None
    session.get_proxy_ip.return_value = "1.2.3.4"
    session.get.return_value = {"version": 3}
    session.post.return_value = {
        "error": "otpTemporaryBlocked",
        "message": "retryLater",
        "registrationStatus": "VERIFICATION_FAILED",
    }

    with pytest.raises(RegistrationError, match="otpTemporaryBlocked"):
        register_with_retries(
            email_provider=FakeEmailProvider("harry.test@slmails.com", "755461"),
            max_attempts=3,
            fetch_proxy_ip=False,
        )
    # One attempt only — no proxy burn
    assert mock_proxy.call_count == 1
