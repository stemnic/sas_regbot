"""AnyMessage (anymessage.shop) short-term email activation client.

API docs: https://anymessage.shop/en/docs

Traffic is **direct** (no Bright Data proxy). SAS registration still uses the sticky proxy.
"""

from __future__ import annotations

import logging
import re
import time
from html import unescape
from typing import Any
from urllib.parse import urlencode

import requests

from .. import config
from ..profile import OTP_RE
from .base import DEFAULT_OTP_PATTERN, EmailProviderError, Inbox

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WAIT_VALUES = frozenset({"wait message", "waitmessage", "wait_message"})


def _strip_html(text: str) -> str:
    plain = _HTML_TAG_RE.sub(" ", text)
    return unescape(re.sub(r"\s+", " ", plain)).strip()


def extract_otp(blob: str, pattern: re.Pattern[str] | None = None) -> str | None:
    """Pull a 6-digit OTP from HTML or plain text."""
    otp_re = pattern or DEFAULT_OTP_PATTERN
    for candidate in (blob, _strip_html(blob)):
        match = otp_re.search(candidate)
        if not match:
            continue
        code = match.group(1) if match.lastindex else match.group(0)
        if OTP_RE.match(code):
            return code
    return None


class AnyMessageProvider:
    """Order short-term emails and poll for SAS OTP via AnyMessage."""

    def __init__(
        self,
        *,
        token: str,
        site: str = "flysas.com",
        domain: str = "",
        base_url: str = "https://api.anymessage.shop",
        order_regex: str = "",
        order_subject: str = "",
        timeout: float = 30,
        session: requests.Session | None = None,
    ) -> None:
        if not token.strip():
            raise EmailProviderError(
                "AnyMessage API token is required (set ANYMESSAGE_TOKEN or EMAIL_API_KEY)"
            )
        if not site.strip():
            raise EmailProviderError("ANYMESSAGE_SITE is required (e.g. flysas.com)")
        self.token = token.strip()
        self.site = site.strip()
        self.domain = domain.strip()
        self.base_url = base_url.rstrip("/")
        self.order_regex = order_regex.strip()
        self.order_subject = order_subject.strip()
        self.timeout = timeout
        self._session = session or requests.Session()

    @classmethod
    def from_config(cls) -> AnyMessageProvider:
        token = (config.ANYMESSAGE_TOKEN or config.EMAIL_API_KEY or "").strip()
        return cls(
            token=token,
            site=config.ANYMESSAGE_SITE,
            domain=config.ANYMESSAGE_DOMAIN,
            base_url=config.ANYMESSAGE_BASE_URL,
            order_regex=config.ANYMESSAGE_ORDER_REGEX,
            order_subject=config.ANYMESSAGE_ORDER_SUBJECT,
        )

    def _get(self, path: str, params: dict[str, str]) -> dict[str, Any] | str:
        query = {k: v for k, v in params.items() if v is not None and v != ""}
        query["token"] = self.token
        url = f"{self.base_url}{path}?{urlencode(query)}"
        # Log without token
        safe_params = {k: v for k, v in query.items() if k != "token"}
        logger.debug("AnyMessage GET %s params=%s", path, safe_params)
        try:
            response = self._session.get(url, timeout=self.timeout)
        except requests.RequestException as error:
            raise EmailProviderError(f"AnyMessage request failed: {error}") from error

        if response.status_code >= 400:
            raise EmailProviderError(
                f"AnyMessage HTTP {response.status_code}: {response.text[:500]}"
            )

        content_type = (response.headers.get("Content-Type") or "").lower()
        text = response.text or ""
        if "application/json" in content_type or text.lstrip().startswith("{"):
            try:
                data = response.json()
            except ValueError as error:
                raise EmailProviderError(
                    f"AnyMessage returned non-JSON: {text[:300]}"
                ) from error
            if not isinstance(data, dict):
                raise EmailProviderError(f"AnyMessage unexpected JSON: {data!r}")
            return data
        return text

    def quantity(self) -> Any:
        """Optional stock check for the configured site."""
        data = self._get("/email/quantity", {"site": self.site})
        return data

    def create_inbox(self) -> Inbox:
        params: dict[str, str] = {"site": self.site}
        if self.domain:
            params["domain"] = self.domain
        if self.order_regex:
            params["regex"] = self.order_regex
        if self.order_subject:
            params["subject"] = self.order_subject

        data = self._get("/email/order", params)
        if not isinstance(data, dict):
            raise EmailProviderError(f"AnyMessage order returned unexpected body: {data!r}")

        status = str(data.get("status") or "").lower()
        if status != "success":
            value = data.get("value") or data
            raise EmailProviderError(f"AnyMessage order failed: {value}")

        email = data.get("email")
        order_id = data.get("id")
        if not email or not order_id:
            raise EmailProviderError(f"AnyMessage order missing email/id: {data}")

        address = str(email).strip()
        external_id = str(order_id).strip()
        logger.info("AnyMessage ordered email=%s id=%s site=%s", address, external_id, self.site)
        return Inbox(
            address=address,
            external_id=external_id,
            meta={
                "provider": "anymessage",
                "order_id": external_id,
                "site": self.site,
                "domain": self.domain,
                "raw": data,
            },
        )

    def wait_for_otp(
        self,
        inbox: Inbox,
        *,
        timeout_s: float | None = None,
        poll_s: float | None = None,
        pattern: re.Pattern[str] | None = None,
    ) -> str:
        order_id = inbox.external_id
        if not order_id:
            raise EmailProviderError("AnyMessage inbox missing order id (external_id)")

        timeout = timeout_s if timeout_s is not None else config.REGBOT_OTP_TIMEOUT_S
        poll = poll_s if poll_s is not None else config.REGBOT_OTP_POLL_S
        deadline = time.time() + timeout
        last_status: str | None = None

        while time.time() < deadline:
            data = self._get("/email/getmessage", {"id": str(order_id)})

            # preview=1 path returns pure HTML string
            if isinstance(data, str):
                code = extract_otp(data, pattern)
                if code:
                    logger.info("AnyMessage OTP received for %s", inbox.address)
                    return code
                last_status = "html-no-otp"
                time.sleep(poll)
                continue

            status = str(data.get("status") or "").lower()
            value = str(data.get("value") or "").lower()

            normalized_wait = value.replace("_", " ").strip()
            if status == "error" and (
                normalized_wait in _WAIT_VALUES or "wait" in normalized_wait
            ):
                last_status = "wait message"
                time.sleep(poll)
                continue

            if status == "success" or data.get("message"):
                message = str(data.get("message") or data.get("value") or "")
                code = extract_otp(message, pattern)
                if code:
                    logger.info("AnyMessage OTP received for %s", inbox.address)
                    return code
                last_status = "message-without-otp"
                logger.debug("AnyMessage message present but no OTP match yet")
                time.sleep(poll)
                continue

            if status == "error":
                raise EmailProviderError(f"AnyMessage getmessage error: {data.get('value') or data}")

            last_status = str(data)
            time.sleep(poll)

        raise EmailProviderError(
            f"AnyMessage OTP timeout after {timeout}s for {inbox.address} "
            f"(id={order_id}, last={last_status})"
        )
