"""Captcha solvers for SAS enrollment."""

from __future__ import annotations

from .. import config
from ..proxy import StickyProxy
from .api import CaptchaSolution, CapsolverError, solve_recaptcha_manual, solve_recaptcha_v2

__all__ = [
    "CaptchaSolution",
    "CapsolverError",
    "solve_captcha",
    "solve_recaptcha_manual",
    "solve_recaptcha_v2",
]


def solve_captcha(
    *,
    mode: str,
    proxy: StickyProxy,
    api_key: str = "",
    page_url: str | None = None,
    sitekey: str | None = None,
    debug_dir: str | None = None,
    user_agent: str | None = None,
) -> CaptchaSolution:
    """Dispatch captcha solve. Default path is CapSolver HTTP + proxy (docs-aligned v2)."""
    mode = (mode or "proxy").strip().lower()
    page_url = page_url or config.RECAPTCHA_PAGE_URL
    sitekey = sitekey or config.RECAPTCHA_SITEKEY
    key = api_key or config.CAPSOLVER_API_KEY
    # Force CapSolver UA to a curl_cffi-known Chrome so enroll TLS can match the token.
    forced_ua = (user_agent if user_agent is not None else config.REGBOT_CAPTCHA_USER_AGENT) or None
    if forced_ua is not None:
        forced_ua = forced_ua.strip() or None

    if mode in {"playwright", "browser", "extension"}:
        from .browser import solve_recaptcha_playwright

        # Full solution including page navigator.userAgent for enroll TLS match
        return solve_recaptcha_playwright(
            proxy=proxy,
            api_key=key,
            page_url=page_url,
            sitekey=sitekey,
            debug_dir=debug_dir,
        )

    if mode in {"manual", "stdin"}:
        return solve_recaptcha_manual(website_url=page_url, website_key=sitekey)

    if mode in {"proxyless", "proxy_less", "noproxy"}:
        return solve_recaptcha_v2(
            api_key=key,
            website_url=page_url,
            website_key=sitekey,
            mode="proxyless",
            poll_timeout_s=config.REGBOT_CAPTCHA_TIMEOUT_S,
            is_invisible=False,
            user_agent=forced_ua,
        )

    # CapSolver ReCaptchaV2Task + same sticky proxy as enroll (Oxylabs / BD)
    return solve_recaptcha_v2(
        api_key=key,
        website_url=page_url,
        website_key=sitekey,
        proxy=proxy,
        mode="proxy",
        poll_timeout_s=config.REGBOT_CAPTCHA_TIMEOUT_S,
        is_invisible=False,
        user_agent=forced_ua,
    )
