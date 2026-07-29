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


def looks_like_inbox_limit(message: str) -> bool:
    """True when OpenInbox rejected create due to concurrent inbox capacity."""
    low = (message or "").lower()
    if "inbox limit" in low or "concurrent inbox" in low:
        return True
    if "limit reached" in low and "inbox" in low:
        return True
    if "concurrent" in low and "inbox" in low:
        return True
    if "max active" in low and "inbox" in low:
        return True
    return False


def email_domain(address: str) -> str:
    """Return lowercased domain part of an email (or bare hostname)."""
    text = (address or "").strip().lower()
    if "@" in text:
        return text.rsplit("@", 1)[-1].strip()
    return text.lstrip("@").strip()


def is_banned_domain(address_or_domain: str, banned: frozenset[str] | set[str]) -> bool:
    """True if the address/host is on the OpenInbox ban list."""
    if not banned:
        return False
    return email_domain(address_or_domain) in banned


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
        banned_domains: frozenset[str] | set[str] | None = None,
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
        self.banned_domains = frozenset(
            banned_domains
            if banned_domains is not None
            else config.openinbox_banned_domains()
        )
        if session is not None:
            self._session = session
        else:
            from ..http_bind import get_bound_session

            self._session = get_bound_session()

    @classmethod
    def from_config(cls) -> OpenInboxProvider:
        key = (config.OPENINBOX_API_KEY or config.EMAIL_API_KEY or "").strip()
        preferred = (config.OPENINBOX_DOMAIN or "").strip()
        banned = config.openinbox_banned_domains()
        if preferred and is_banned_domain(preferred, banned):
            logger.warning(
                "OPENINBOX_DOMAIN=%s is banned; ignoring preferred domain",
                preferred,
            )
            preferred = ""
        return cls(
            api_key=key,
            base_url=config.OPENINBOX_BASE_URL,
            domain=preferred,
            banned_domains=banned,
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
        body_snip = (response.text or "")[:500]
        if response.status_code == 401:
            raise EmailProviderError(
                f"OpenInbox auth failed (401): check OPENINBOX_API_KEY "
                f"and that the plan includes API access. {body_snip[:300]}"
            )
        if response.status_code == 403:
            if looks_like_inbox_limit(body_snip):
                raise EmailProviderError(
                    f"OpenInbox inbox limit (403): {body_snip[:300]}"
                )
            raise EmailProviderError(
                f"OpenInbox auth failed (403): check OPENINBOX_API_KEY "
                f"and that the plan includes API access. {body_snip[:300]}"
            )
        if response.status_code >= 400:
            raise EmailProviderError(
                f"OpenInbox {method.upper()} {path} → {response.status_code}: "
                f"{body_snip}"
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

    def list_inboxes(self) -> list[dict[str, Any]]:
        """Return all account inboxes (``GET /v1/inboxes``)."""
        raw = self._request("GET", "/v1/inboxes")
        data = _unwrap_data(raw)
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("inboxes", "items", "data"):
                val = data.get(key)
                if isinstance(val, list):
                    return [row for row in val if isinstance(row, dict)]
        return []

    def delete_inbox(self, inbox_id: str) -> None:
        """Delete one inbox by id (``DELETE /v1/inboxes/:id``)."""
        iid = (inbox_id or "").strip()
        if not iid:
            raise EmailProviderError("OpenInbox delete_inbox requires inbox id")
        self._request("DELETE", f"/v1/inboxes/{iid}")
        logger.info("OpenInbox deleted inbox id=%s", iid)

    def free_one_oldest_inbox(self) -> dict[str, Any] | None:
        """Delete exactly the oldest inbox so one create slot opens.

        Keeps newer inboxes for late/misdelivered mail after account creation.
        Returns the deleted row, or None if nothing to delete.
        """
        rows = self.list_inboxes()
        if not rows:
            logger.info("OpenInbox free_one_oldest: no inboxes to delete")
            return None

        def _created_key(row: dict[str, Any]) -> str:
            return str(row.get("createdAt") or row.get("created_at") or "")

        ordered = sorted(rows, key=_created_key)
        oldest = ordered[0]
        inbox_id = str(oldest.get("id") or oldest.get("inboxId") or oldest.get("inbox_id") or "")
        email = str(oldest.get("email") or oldest.get("address") or "")
        if not inbox_id:
            raise EmailProviderError(f"OpenInbox oldest inbox missing id: {oldest}")
        logger.info(
            "OpenInbox pruning oldest inbox id=%s email=%s created=%s (count_was=%s)",
            inbox_id,
            email,
            _created_key(oldest) or "?",
            len(rows),
        )
        self.delete_inbox(inbox_id)
        return oldest

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        """Create account-owned inbox via authenticated v1 API.

        ``prefix`` is sent as OpenInbox ``prefix`` (e.g. ``john.smith`` →
        ``john.smith@…``). On conflict, retries with a numeric suffix.

        Domains in ``banned_domains`` (e.g. teminbox.click) are deleted and
        recreated until a non-banned host is returned.

        On concurrent-inbox limit: free **one oldest** inbox (if enabled) and
        retry the same create once — never bulk-delete; never delete after enroll.
        """
        import random as _random

        base_prefix = (prefix or "").strip().lower()
        base_prefix = re.sub(r"[^a-z0-9._-]", "", base_prefix).strip("._-")
        preferred_domain = self.domain.strip()
        if preferred_domain and is_banned_domain(preferred_domain, self.banned_domains):
            logger.warning(
                "OpenInbox preferred domain %s is banned; using random domain",
                preferred_domain,
            )
            preferred_domain = ""

        last_error: Exception | None = None
        pruned_once = False
        # Extra attempts so ban-list discards do not exhaust name-collision budget.
        for attempt in range(10):
            payload: dict[str, Any] = {}
            if preferred_domain:
                payload["domain"] = preferred_domain
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
                if looks_like_inbox_limit(str(error)):
                    prune_on = bool(
                        getattr(config, "REGBOT_OPENINBOX_PRUNE_OLDEST", True)
                    )
                    if prune_on and not pruned_once:
                        try:
                            freed = self.free_one_oldest_inbox()
                        except EmailProviderError as prune_err:
                            raise EmailProviderError(
                                f"OpenInbox inbox limit and failed to free oldest: {prune_err}"
                            ) from prune_err
                        pruned_once = True
                        if freed is None:
                            raise EmailProviderError(
                                "OpenInbox inbox limit: no existing inbox to free. "
                                "Upgrade plan or wait for natural expiry."
                            ) from error
                        logger.info(
                            "OpenInbox retrying create after freeing oldest (prefix=%s)",
                            payload.get("prefix") or "",
                        )
                        try:
                            raw = self._request(
                                "POST", "/v1/inboxes", json_body=payload or {}
                            )
                        except EmailProviderError as error2:
                            last_error = error2
                            if looks_like_inbox_limit(str(error2)):
                                raise EmailProviderError(
                                    "OpenInbox inbox limit: freed one oldest inbox and "
                                    "still at capacity. Upgrade plan or wait for natural "
                                    f"inbox expiry. ({error2})"
                                ) from error2
                            # Non-limit failure after prune (e.g. name taken)
                            logger.info(
                                "OpenInbox create after prune failed (retry name): %s",
                                error2,
                            )
                            continue
                    else:
                        raise EmailProviderError(
                            "OpenInbox inbox limit: concurrent inbox capacity full "
                            f"(prune_oldest={'off' if not prune_on else 'already tried'}). "
                            f"{error}"
                        ) from error
                elif "auth failed" in str(error).lower():
                    raise
                else:
                    # name taken / validation — retry with digits only as fallback
                    logger.info(
                        "OpenInbox create retry attempt=%s: %s", attempt + 1, error
                    )
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

            if is_banned_domain(str(address), self.banned_domains):
                dom = email_domain(str(address))
                logger.warning(
                    "OpenInbox banned domain %s for %s — deleting and retrying",
                    dom,
                    address,
                )
                try:
                    self.delete_inbox(str(inbox_id))
                except EmailProviderError as del_err:
                    logger.warning(
                        "OpenInbox failed to delete banned inbox %s: %s",
                        inbox_id,
                        del_err,
                    )
                last_error = EmailProviderError(
                    f"OpenInbox assigned banned domain {dom} (address={address})"
                )
                # Drop preferred domain for further tries if it led here somehow
                if preferred_domain and email_domain(preferred_domain) == dom:
                    preferred_domain = ""
                continue

            logger.info(
                "OpenInbox inbox ready email=%s id=%s prefix=%s pruned_oldest=%s",
                address,
                inbox_id,
                payload.get("prefix") or "",
                pruned_once,
            )
            return Inbox(
                address=str(address),
                external_id=str(inbox_id),
                meta={
                    "provider": "openinbox",
                    "raw": data,
                    "prefix": payload.get("prefix"),
                    "pruned_oldest": pruned_once,
                },
            )
        banned = ",".join(sorted(self.banned_domains)) or "(none)"
        raise EmailProviderError(
            f"OpenInbox create_inbox failed after retries "
            f"(banned_domains={banned}): {last_error}"
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
