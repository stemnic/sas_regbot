"""Manual custom-flow CLI and profile overrides."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from regbot.cli import main
from regbot.profile import build_us_profile


def test_build_us_profile_overrides() -> None:
    profile = build_us_profile(
        first_name="Harry",
        last_name="Barrier",
        gender="m",
        date_of_birth="1983-05-13",
        phone="+13026187675",
        password="wKRSsCaPI1i8o@",
    )
    assert profile.first_name == "Harry"
    assert profile.password == "wKRSsCaPI1i8o@"
    assert profile.gender == "m"


def test_cli_otp_requires_email() -> None:
    assert main(["register", "--otp", "123456"]) == 2


def test_cli_manual_email_prompts_for_otp_after_request() -> None:
    """Normal manual path: requestOtp runs, then provider has no pre-set OTP."""
    with patch("regbot.cli.register_with_retries") as reg:
        from regbot.store import RegisteredAccount

        reg.return_value = RegisteredAccount(
            email="a@b.com",
            password="Secret1!",
            eb_number="1",
            proxy_label="bd-test",
        )
        code = main(
            [
                "register",
                "--email",
                "a@b.com",
                "--first-name",
                "Harry",
                "--last-name",
                "Barrier",
            ]
        )
        assert code == 0
        kwargs = reg.call_args.kwargs
        assert kwargs["skip_request_otp"] is False
        assert kwargs["profile"].first_name == "Harry"
        provider = kwargs["email_provider"]
        assert provider.create_inbox().address == "a@b.com"
        assert provider.otp is None  # will prompt interactively


def test_cli_skip_request_otp_uses_provided_code() -> None:
    with patch("regbot.cli.register_with_retries") as reg:
        from regbot.store import RegisteredAccount

        reg.return_value = RegisteredAccount(
            email="a@b.com",
            password="Secret1!",
            eb_number="1",
            proxy_label="bd-test",
        )
        code = main(
            [
                "register",
                "--email",
                "a@b.com",
                "--otp",
                "755461",
                "--skip-request-otp",
            ]
        )
        assert code == 0
        kwargs = reg.call_args.kwargs
        assert kwargs["skip_request_otp"] is True
        assert kwargs["email_provider"].otp == "755461"
