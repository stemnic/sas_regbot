"""Email providers for OTP delivery (direct network — not proxied)."""

from .anymessage import AnyMessageProvider
from .base import (
    EmailProvider,
    EmailProviderError,
    FixedEmailProvider,
    Inbox,
    StickyEmailProvider,
    get_email_provider,
    get_rotating_email_provider,
)
from .freecustom import FreeCustomProvider
from .mailhook import MailhookProvider
from .openinbox import OpenInboxProvider

__all__ = [
    "AnyMessageProvider",
    "EmailProvider",
    "EmailProviderError",
    "FixedEmailProvider",
    "FreeCustomProvider",
    "Inbox",
    "MailhookProvider",
    "OpenInboxProvider",
    "StickyEmailProvider",
    "get_email_provider",
    "get_rotating_email_provider",
]
