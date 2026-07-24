"""OpenInbox.io disposable email client for SAS OTP.

API docs: https://openinbox.io/api-docs

Authenticated v1 (required for multi-account + reliable poll):
  POST /v1/inboxes
  GET  /v1/inboxes/:inboxId/emails
  GET  /v1/emails/:emailId

Inbound alt:
  GET /inbound/api/emails?inbox=:inboxId

Traffic is **direct** (not through SAS Oxylabs proxy).
"""

from __future__ import annotations

import logging
import re
import time
from html import unescape
from typing import Any

import requests

from .. import config
from ..profile import OTP_RE
from .base import DEFAULT_OTP_PATTERN, EmailProviderError, Inbox

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")


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


def _unwrap_data(payload: Any) -> Any:
    """OpenInbox often wraps resources as {success, data: …}."""
    if isinstance(payload, dict) and "data" in payload and (
        payload.get("success") is True or "data" in payload
    ):
        # Prefer nested data when present (object or list)
        return payload["data"]
    return payload


def _email_blob(msg: dict[str, Any]) -> str:
    # Unwrap if caller passed a full GET /emails/:id envelope
    inner = _unwrap_data(msg)
    if isinstance(inner, dict) and inner is not msg:
        msg = {**msg, **inner}
    parts: list[str] = []
    for key in (
        "subject",
        "textBody",
        "htmlBody",
        "text",
        "html",
        "body",
        "content",
        "preview",
        "snippet",
    ):
        val = msg.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts)


class OpenInboxProvider:
    """Create OpenInbox temp mailboxes and poll for SAS OTP codes."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://api.openinbox.io/api",
        domain: str = "",
        timeout: float = 30,
        session: requests.Session | None = None,
    ) -> None:
        if not api_key.strip():
            raise EmailProviderError(
                "OpenInbox API key is required (set OPENINBOX_API_KEY or EMAIL_API_KEY). "
                "API access needs Pro / Business / Premium / 7-Day Pass — "
                "https://openinbox.io/api-docs"
            )
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.domain = domain.strip()
        self.timeout = timeout
        self._session = session or requests.Session()

    @classmethod
    def from_config(cls) -> OpenInboxProvider:
        key = (config.OPENINBOX_API_KEY or config.EMAIL_API_KEY or "").strip()
        return cls(
            api_key=key,
            base_url=config.OPENINBOX_BASE_URL,
            domain=config.OPENINBOX_DOMAIN,
        )

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
            "X-API-KEY": self.api_key,
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        try:
            response = self._session.request(
                method.upper(),
                url,
                params=params,
                json=json_body,
                headers=self._headers(json_body=json_body is not None),
                timeout=self.timeout,
            )
        except requests.RequestException as error:
            raise EmailProviderError(f"OpenInbox request failed: {error}") from error
        if response.status_code in {401, 403}:
            raise EmailProviderError(
                f"OpenInbox auth failed ({response.status_code}): check OPENINBOX_API_KEY "
                f"and that the plan includes API access. {response.text[:300]}"
            )
        if response.status_code >= 400:
            raise EmailProviderError(
                f"OpenInbox {method.upper()} {path} → {response.status_code}: "
                f"{response.text[:500]}"
            )
        if not response.content or response.status_code == 204:
            return {}
        try:
            data = response.json()
        except Exception as error:
            raise EmailProviderError(
                f"OpenInbox non-JSON response: {response.text[:300]}"
            ) from error
        # Soft error with HTTP 200 (inbound mis-param)
        if isinstance(data, dict) and data.get("error") and "data" not in data and "emails" not in data:
            raise EmailProviderError(
                f"OpenInbox API error: {data.get('error')} "
                f"(usage={data.get('usage') or data.get('message') or ''})"
            )
        return data

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        """Create account-owned inbox via authenticated v1 API.

        ``prefix`` is sent as OpenInbox ``prefix`` (e.g. ``john.smith`` →
        ``john.smith@…``). On conflict, retries with a numeric suffix.
        """
        import random as _random

        base_prefix = (prefix or "").strip().lower()
        base_prefix = re.sub(r"[^a-z0-9._-]", "", base_prefix).strip("._-")
        last_error: Exception | None = None
        for attempt in range(5):
            payload: dict[str, Any] = {}
            if self.domain:
                payload["domain"] = self.domain
            if base_prefix:
                # Prefer bare first.last; only add digits if earlier create failed
                if attempt == 0:
                    candidate = base_prefix
                else:
                    candidate = f"{base_prefix}{_random.randint(1, 99999)}"
                payload["prefix"] = candidate[:48]
            try:
                raw = self._request("POST", "/v1/inboxes", json_body=payload or {})
            except EmailProviderError as error:
                last_error = error
                msg = str(error).lower()
                if "limit" in msg or "403" in msg:
                    raise
                # name taken / validation — retry with digits only as fallback
                logger.info("OpenInbox create retry attempt=%s: %s", attempt + 1, error)
                continue
            data = _unwrap_data(raw)
            if not isinstance(data, dict):
                last_error = EmailProviderError(f"OpenInbox create_inbox unexpected: {raw}")
                continue
            address = data.get("email") or data.get("address") or data.get("mail")
            if not address:
                last_error = EmailProviderError(f"OpenInbox create_inbox missing email: {raw}")
                continue
            inbox_id = data.get("id") or data.get("inboxId") or data.get("inbox_id") or ""
            if not inbox_id:
                last_error = EmailProviderError(f"OpenInbox create_inbox missing id: {raw}")
                continue
            logger.info(
                "OpenInbox inbox ready email=%s id=%s prefix=%s",
                address,
                inbox_id,
                payload.get("prefix") or "",
            )
            return Inbox(
                address=str(address),
                external_id=str(inbox_id),
                meta={"provider": "openinbox", "raw": data, "prefix": payload.get("prefix")},
            )
        raise EmailProviderError(
            f"OpenInbox create_inbox failed after retries: {last_error}"
        ) from last_error

    def _list_emails(self, inbox: Inbox) -> list[dict[str, Any]]:
        """List messages. Prefer v1 by id; inbound uses inbox=<id> not inboxEmail."""
        errors: list[str] = []

        if inbox.external_id:
            try:
                data = self._request("GET", f"/v1/inboxes/{inbox.external_id}/emails")
                emails = self._normalize_email_list(data)
                if emails is not None:
                    return emails
            except EmailProviderError as error:
                errors.append(str(error))

            try:
                data = self._request(
                    "GET",
                    "/inbound/api/emails",
                    params={"inbox": str(inbox.external_id), "limit": "20"},
                )
                emails = self._normalize_email_list(data)
                if emails is not None:
                    return emails
            except EmailProviderError as error:
                errors.append(str(error))

        if errors:
            # Do not silently empty-poll on hard failures
            raise EmailProviderError(
                "OpenInbox list emails failed: " + " | ".join(errors[:3])
            )
        if not inbox.external_id:
            raise EmailProviderError("OpenInbox inbox missing external_id (inbox id)")
        return []

    @staticmethod
    def _normalize_email_list(data: Any) -> list[dict[str, Any]] | None:
        """Return message list, or None if payload has no list field.

        Important: return None (not []) when the response is not a message list,
        so callers can try the next endpoint. Empty list only when API returned
        an explicit empty array.
        """
        if isinstance(data, list):
            return [m for m in data if isinstance(m, dict)]
        if not isinstance(data, dict):
            return None
        if data.get("error") and "emails" not in data and "data" not in data:
            return None
        for key in ("emails", "messages", "mails", "data", "items"):
            val = data.get(key)
            if isinstance(val, list):
                return [m for m in val if isinstance(m, dict)]
        return None

    def _fetch_full_email(self, email_id: str) -> dict[str, Any]:
        if not email_id:
            return {}
        try:
            data = self._request("GET", f"/v1/emails/{email_id}")
        except EmailProviderError:
            return {}
        unwrapped = _unwrap_data(data)
        return unwrapped if isinstance(unwrapped, dict) else {}

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
        deadline = time.time() + timeout
        seen_ids: set[str] = set()
        poll_i = 0

        while time.time() < deadline:
            poll_i += 1
            try:
                messages = self._list_emails(inbox)
            except EmailProviderError as error:
                logger.warning("OpenInbox poll error: %s", error)
                time.sleep(poll)
                continue

            logger.info(
                "OpenInbox poll #%s email=%s id=%s messages=%s",
                poll_i,
                inbox.address,
                inbox.external_id or "?",
                len(messages),
            )
            for msg in messages:
                msg_id = str(msg.get("id") or msg.get("emailId") or "")
                blob = _email_blob(msg)
                if msg_id and msg_id not in seen_ids and extract_otp(blob, pattern) is None:
                    full = self._fetch_full_email(msg_id)
                    if full:
                        blob = f"{blob} {_email_blob(full)}".strip()
                    seen_ids.add(msg_id)
                code = extract_otp(blob, pattern)
                if code:
                    logger.info(
                        "OpenInbox OTP found for %s (subject=%r)",
                        inbox.address,
                        (msg.get("subject") or "")[:80],
                    )
                    return code
            time.sleep(poll)

        raise EmailProviderError(
            f"OpenInbox OTP timeout after {timeout}s for {inbox.address}"
        )
