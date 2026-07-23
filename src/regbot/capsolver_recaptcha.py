"""Backward-compatible re-exports — prefer ``regbot.captcha``."""

from .captcha.api import (  # noqa: F401
    CaptchaSolution,
    CapsolverError,
    CaptchaMode,
    ProxyFormat,
    solve_recaptcha_manual,
    solve_recaptcha_v2,
    solve_recaptcha_v2_with_proxy,
)
