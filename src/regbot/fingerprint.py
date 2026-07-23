"""Map CapSolver solution User-Agent → curl_cffi impersonate profile.

CapSolver tokens are generated under a specific browser UA. Enrolling with a
mismatched TLS fingerprint (e.g. Firefox impersonate + Chrome UA header) is a
common cause of generic captcha/enroll failures.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Prefer profiles known available in curl_cffi 0.15+
_CHROME_CANDIDATES = (
    "chrome146",
    "chrome145",
    "chrome142",
    "chrome136",
    "chrome131",
    "chrome124",
    "chrome120",
)
_FIREFOX_CANDIDATES = (
    "firefox147",
    "firefox144",
    "firefox135",
    "firefox133",
)
_SAFARI_CANDIDATES = (
    "safari180",
    "safari184",
    "safari170",
    "safari155",
)

_CACHE: dict[str, str] = {}


def _first_available(candidates: tuple[str, ...], fallback: str) -> str:
    key = "|".join(candidates)
    if key in _CACHE:
        return _CACHE[key]
    try:
        from curl_cffi import requests as cffi_requests

        for name in candidates:
            try:
                session = cffi_requests.Session(impersonate=name)
                session.close()
                _CACHE[key] = name
                return name
            except Exception:
                continue
    except Exception:
        pass
    _CACHE[key] = fallback
    return fallback


def impersonate_for_user_agent(user_agent: str | None, *, default: str = "firefox147") -> str:
    """Return a curl_cffi impersonate profile matching the CapSolver solution UA."""
    ua = (user_agent or "").strip()
    if not ua:
        return default

    lower = ua.lower()
    # Order matters: CriOS is Chrome on iOS; Edg is Chromium-based
    if "firefox/" in lower:
        profile = _first_available(_FIREFOX_CANDIDATES, "firefox147")
    elif "edg/" in lower or "edge/" in lower:
        profile = _first_available(("edge101", "edge99") + _CHROME_CANDIDATES, "chrome136")
    elif "chrome/" in lower or "crios/" in lower or "chromium" in lower:
        # Prefer version-close chrome if we can parse Chrome/1xx
        m = re.search(r"chrome/(\d+)", lower)
        if m:
            major = int(m.group(1))
            preferred = [f"chrome{major}", f"chrome{major - 1}", f"chrome{major + 1}"]
            preferred = [p for p in preferred if any(p == c for c in _CHROME_CANDIDATES)]
            profile = _first_available(tuple(preferred) + _CHROME_CANDIDATES, "chrome136")
        else:
            profile = _first_available(_CHROME_CANDIDATES, "chrome136")
    elif "safari/" in lower and "chrome" not in lower:
        profile = _first_available(_SAFARI_CANDIDATES, "safari180")
    else:
        profile = default

    logger.info("impersonate_for_user_agent → %s (ua starts %r)", profile, ua[:72])
    return profile
