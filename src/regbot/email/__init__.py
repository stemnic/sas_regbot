"""Email providers for OTP delivery (direct network — not proxied)."""

from .anymessage import AnyMessageProvider
from .base import (
    EmailProvider,
    EmailProviderError,
    FixedEmailProvider,
    Inbox,
    get_email_provider,
)
from .openinbox import OpenInboxProvider

__all__ = [
    "AnyMessageProvider",
    "EmailProvider",
    "EmailProviderError",
    "FixedEmailProvider",
    "Inbox",
    "OpenInboxProvider",
    "get_email_provider",
]
