"""Email provider protocol and factory."""

from __future__ import annotations

import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .. import config
from ..profile import OTP_RE

logger = logging.getLogger(__name__)

DEFAULT_OTP_PATTERN = re.compile(r"\b(\d{6})\b")


@dataclass
class Inbox:
    address: str
    password: str | None = None
    token: str | None = None
    external_id: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class EmailProvider(Protocol):
    """Create disposable inboxes and wait for SAS OTP emails (direct HTTP)."""

    def create_inbox(self, *, prefix: str | None = None) -> Inbox: ...

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str: ...


class EmailProviderError(RuntimeError):
    """Email provider failure."""


class ManualEmailProvider:
    """Semi-automated: ask for email, then after requestOtp ask for OTP on stdin."""

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        print(
            "\n=== Registration email ===\n"
            "Enter the mailbox that can receive the SAS verification code.\n",
            flush=True,
        )
        if prefix:
            print(f"(suggested local-part prefix: {prefix})", flush=True)
        address = input("Email address: ").strip()
        if not address or "@" not in address:
            raise EmailProviderError("Invalid email address")
        return Inbox(address=address)

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        print(
            f"\n=== SAS OTP ===\n"
            f"An email with a 6-digit code was requested for:\n  {inbox.address}\n"
            f"Check the inbox, then paste the code here.\n",
            flush=True,
        )
        while True:
            raw = input("Enter 6-digit OTP: ").strip()
            if OTP_RE.match(raw):
                return raw
            print(f"Invalid OTP {raw!r} — must be exactly 6 digits. Try again.", flush=True)


class FakeEmailProvider:
    """Test double: fixed email and OTP, no network."""

    def __init__(self, address: str = "test.user@example.com", otp: str = "123456") -> None:
        self.address = address
        self.otp = otp

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        return Inbox(address=self.address)

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        return self.otp


class FixedEmailProvider:
    """Manual / custom-flow provider: you supply the email address.

    Default behaviour: after SAS ``requestOtp``, **prompt on stdin** for the 6-digit code
    (you cannot know the OTP beforehand).

    Optional ``otp`` is only for rare offline/replay tests; prefer interactive paste.
    """

    def __init__(self, address: str, otp: str | None = None) -> None:
        address = address.strip()
        if not address or "@" not in address:
            raise EmailProviderError(f"Invalid fixed email address: {address!r}")
        if otp is not None and not OTP_RE.match(otp.strip()):
            raise EmailProviderError(f"OTP must be 6 digits, got {otp!r}")
        self.address = address
        self.otp = otp.strip() if otp else None

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        return Inbox(address=self.address, meta={"provider": "fixed"})

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        if self.otp:
            return self.otp
        print(
            f"\n=== SAS OTP ===\n"
            f"An email with a 6-digit code was requested for:\n  {inbox.address}\n"
            f"Check the inbox, then paste the code here.\n",
            flush=True,
        )
        while True:
            raw = input("Enter 6-digit OTP: ").strip()
            if OTP_RE.match(raw):
                return raw
            print(f"Invalid OTP {raw!r} — must be exactly 6 digits. Try again.", flush=True)


class HttpEmailProvider:
    """Generic REST adapter for temp-mail style APIs.

    Expected endpoints (override via env):
      POST {base}/inboxes  -> {"email"|"address": "...", "id"?, "token"?}
      GET  {base}/inboxes/{id}/messages  -> list of {subject, body|text|html}

    Or full URL templates via meta. Configure with EMAIL_API_BASE + EMAIL_API_KEY.
    """

    def __init__(
        self,
        *,
        api_base: str,
        api_key: str,
        domain: str = "",
    ) -> None:
        if not api_base:
            raise EmailProviderError("EMAIL_API_BASE is required for http email provider")
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.domain = domain

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            headers["X-API-Key"] = self.api_key
        return headers

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        from ..http_bind import get_bound_session

        payload: dict[str, Any] = {}
        if self.domain:
            payload["domain"] = self.domain
        if prefix:
            payload["prefix"] = prefix
        response = get_bound_session().post(
            f"{self.api_base}/inboxes",
            json=payload or None,
            headers=self._headers(),
            timeout=30,
        )
        if response.status_code >= 400:
            raise EmailProviderError(f"create_inbox failed: {response.status_code} {response.text[:500]}")
        data = response.json()
        address = data.get("email") or data.get("address") or data.get("mail")
        if not address:
            raise EmailProviderError(f"create_inbox missing email field: {data}")
        return Inbox(
            address=str(address),
            password=data.get("password"),
            token=data.get("token") or data.get("access_token"),
            external_id=str(data.get("id") or data.get("inbox_id") or ""),
            meta=data if isinstance(data, dict) else {},
        )

    def _list_messages(self, inbox: Inbox) -> list[dict[str, Any]]:
        from ..http_bind import get_bound_session

        inbox_id = inbox.external_id or inbox.address
        url = f"{self.api_base}/inboxes/{inbox_id}/messages"
        headers = self._headers()
        if inbox.token:
            headers["Authorization"] = f"Bearer {inbox.token}"
        response = get_bound_session().get(url, headers=headers, timeout=30)
        if response.status_code >= 400:
            raise EmailProviderError(f"list_messages failed: {response.status_code} {response.text[:500]}")
        data = response.json()
        if isinstance(data, list):
            return data
        for key in ("messages", "mails", "data", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        timeout = timeout_s if timeout_s is not None else config.REGBOT_OTP_TIMEOUT_S
        poll = poll_s if poll_s is not None else config.REGBOT_OTP_POLL_S
        otp_re = pattern or DEFAULT_OTP_PATTERN
        deadline = time.time() + timeout
        while time.time() < deadline:
            for msg in self._list_messages(inbox):
                blob = " ".join(
                    str(msg.get(k) or "")
                    for k in ("subject", "body", "text", "html", "content", "preview")
                )
                match = otp_re.search(blob)
                if match:
                    code = match.group(1) if match.lastindex else match.group(0)
                    if OTP_RE.match(code):
                        return code
            time.sleep(poll)
        raise EmailProviderError(f"OTP timeout after {timeout}s for {inbox.address}")


class StickyEmailProvider:
    """Wrap a pre-selected provider; exposes which name was chosen."""

    def __init__(self, name: str, inner: EmailProvider) -> None:
        self.name = name
        self.inner = inner

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        return self.inner.create_inbox(prefix=prefix)

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        return self.inner.wait_for_otp(
            inbox, timeout_s=timeout_s, poll_s=poll_s, pattern=pattern
        )


def _build_named_provider(name: str) -> EmailProvider:
    """Construct a single concrete provider by name (no rotation)."""
    provider = name.strip().lower()
    if provider in {"openinbox", "open-inbox", "open_inbox", "oi"}:
        from .openinbox import OpenInboxProvider

        return OpenInboxProvider.from_config()
    if provider in {"mailhook", "mail-hook", "mail_hook", "mh"}:
        from .mailhook import MailhookProvider

        return MailhookProvider.from_config()
    if provider in {"anymessage", "any-message", "any_message"}:
        from .anymessage import AnyMessageProvider

        return AnyMessageProvider.from_config()
    if provider in {"manual", "stdin"}:
        return ManualEmailProvider()
    if provider in {"fixed"}:
        raise EmailProviderError("EMAIL_PROVIDER=fixed requires --email on the CLI")
    if provider in {"fake", "test"}:
        return FakeEmailProvider()
    if provider in {"http", "generic"}:
        return HttpEmailProvider(
            api_base=config.EMAIL_API_BASE,
            api_key=config.EMAIL_API_KEY,
            domain=config.EMAIL_DOMAIN,
        )
    raise EmailProviderError(
        f"Unknown EMAIL_PROVIDER={provider!r}. "
        "Use openinbox|mailhook|anymessage|rotate|manual|fake|http."
    )


def _try_build_named(name: str) -> EmailProvider | None:
    try:
        return _build_named_provider(name)
    except Exception as error:  # noqa: BLE001 — soft-skip missing creds in rotate
        logger.warning("Email provider %s unavailable for rotation: %s", name, error)
        return None


def pick_weighted_provider_name(
    weights: list[tuple[str, float]] | None = None,
    *,
    rng: random.Random | None = None,
) -> str:
    """Pick a provider name by weight (default openinbox:5, mailhook:1)."""
    pairs = weights if weights is not None else config.parse_email_provider_weights()
    if not pairs:
        return "openinbox"
    r = rng or random
    total = sum(w for _, w in pairs)
    if total <= 0:
        return pairs[0][0]
    roll = r.random() * total
    acc = 0.0
    for name, weight in pairs:
        acc += weight
        if roll <= acc:
            return name
    return pairs[-1][0]


def get_rotating_email_provider(
    *,
    rng: random.Random | None = None,
    weights: list[tuple[str, float]] | None = None,
) -> StickyEmailProvider:
    """Weighted pick among available providers (Mailhook ~1/6 by default).

    Picks once and sticks for the returned instance so create_inbox + wait_for_otp
    use the same backend. Call again per registration account for diversification.
    """
    pairs = list(weights if weights is not None else config.parse_email_provider_weights())
    # Prefer stable order for tests / logs
    available: list[tuple[str, float, EmailProvider]] = []
    for name, weight in pairs:
        built = _try_build_named(name)
        if built is not None:
            available.append((name, weight, built))

    if not available:
        # Last resort: try openinbox then mailhook without weights
        for fallback in ("openinbox", "mailhook", "anymessage"):
            built = _try_build_named(fallback)
            if built is not None:
                logger.warning(
                    "Email rotation: no weighted providers available; using %s",
                    fallback,
                )
                return StickyEmailProvider(fallback, built)
        raise EmailProviderError(
            "No email providers available for rotation. "
            "Configure OPENINBOX_API_KEY and/or Mailhook credentials."
        )

    if len(available) == 1:
        name, _, built = available[0]
        logger.info("Email rotation: only %s available", name)
        return StickyEmailProvider(name, built)

    weight_pairs = [(n, w) for n, w, _ in available]
    chosen = pick_weighted_provider_name(weight_pairs, rng=rng)
    for name, _, built in available:
        if name == chosen:
            logger.info(
                "Email rotation: selected %s (weights=%s)",
                name,
                ",".join(f"{n}:{w:g}" for n, w in weight_pairs),
            )
            return StickyEmailProvider(name, built)
    # Should not happen
    name, _, built = available[0]
    return StickyEmailProvider(name, built)


def get_email_provider(
    name: str | None = None,
    *,
    fixed_email: str | None = None,
    fixed_otp: str | None = None,
    rng: random.Random | None = None,
) -> EmailProvider:
    """Return an email provider.

    If ``fixed_email`` is set, always use :class:`FixedEmailProvider` (manual custom flow),
    regardless of ``EMAIL_PROVIDER``.

    ``rotate`` (or default with weights) picks openinbox vs mailhook with
    configured weights (default 5:1 → Mailhook 1/6 of the time).
    """
    if fixed_email:
        return FixedEmailProvider(fixed_email, otp=fixed_otp)

    provider = (name or config.EMAIL_PROVIDER or "rotate").strip().lower()
    if provider in {"rotate", "rotating", "weighted", "auto"}:
        return get_rotating_email_provider(rng=rng)
    return _build_named_provider(provider)
