"""Profile and password validation tests."""

from __future__ import annotations

import re
from datetime import date

from regbot.names_data import FIRST_FEMALE, FIRST_MALE, LAST_NAMES
from regbot.profile import (
    EMAIL_RE,
    PASSWORD_RE,
    email_local_prefix,
    generate_dob,
    generate_password,
    generate_us_profile,
    names_from_email,
    validate_email,
)


def test_generate_password_matches_sas_regex() -> None:
    for _ in range(20):
        pw = generate_password()
        assert PASSWORD_RE.match(pw), pw
        assert " " not in pw
        assert 8 <= len(pw) <= 50


def test_us_profile_fields() -> None:
    profile = generate_us_profile()
    assert profile.country_code == "US"
    assert profile.phone.startswith("+1")
    assert len(profile.phone) == 12  # +1 + 10 digits
    assert profile.gender in {"m", "f"}
    assert PASSWORD_RE.match(profile.password)
    addr = profile.enrollment_address("a@b.com")
    assert addr["physical"][0]["country"]["code"] == "US"
    assert addr["virtual"]["email"][0]["emailAddress"] == "a@b.com"


def test_names_from_email_strips_digits() -> None:
    assert names_from_email("harry.musky275@slmails.com") == ("Harry", "Musky")
    assert names_from_email("ronald.bush900@slmail.me") == ("Ronald", "Bush")
    assert names_from_email("harry.barrier427@slmails.com") == ("Harry", "Barrier")
    assert names_from_email("noperiods123@x.com") is None


def test_profile_from_email_matches_local_part() -> None:
    profile = generate_us_profile(email="harry.musky275@slmails.com")
    assert profile.first_name == "Harry"
    assert profile.last_name == "Musky"
    assert profile.gender == "m"


def test_dob_is_adult_and_valid() -> None:
    today = date.today()
    for _ in range(30):
        dob = date.fromisoformat(generate_dob())
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        assert 25 <= age <= 58


def test_email_regex_accepts_har_style() -> None:
    assert validate_email("harry.barrier427@slmails.com")
    assert EMAIL_RE.match("user_name.tag@example.com")
    # SAS local-part class does not include '+'
    assert not validate_email("user+tag@example.com")
    assert not validate_email("not-an-email")


def test_name_pools_are_large() -> None:
    assert len(FIRST_MALE) >= 150
    assert len(FIRST_FEMALE) >= 150
    assert len(LAST_NAMES) >= 500


def test_email_local_prefix_from_names() -> None:
    p = email_local_prefix("John", "Smith")
    assert p == "john.smith"
    p2 = email_local_prefix("Mary", "OBrien", with_digits=True, rng=__import__("random").Random(0))
    assert p2.startswith("mary.obrien")
    assert re.search(r"\d+$", p2)
