"""FreeCustom.Email disposable inbox client for SAS OTP.

API: https://www.freecustom.email/api  (OpenAPI: /openapi.yaml)
Base: https://api2.freecustom.email

Auth: Authorization: Bearer fce_…

Preferred free path:
  POST /v1/inboxes/generate  → email + public otp_url (fceotp_ token)
  GET  /v1/otp/public?token=…&parseCode=true  (no paid OTP plan required)

Fallback:
  POST /v1/inboxes  + GET messages + GET message detail, local OTP regex.

Traffic is **direct** (not through SAS Oxylabs proxy).
"""

from __future__ import annotations

import logging
import random
import re
import time
from html import unescape
from typing import Any
from urllib.parse import quote, urlparse, parse_qs

import requests

from .. import config
from ..profile import OTP_RE
from .base import DEFAULT_OTP_PATTERN, EmailProviderError, Inbox

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_LOCAL_PART_RE = re.compile(r"[^a-z0-9._-]")


def _strip_html(text: str) -> str:
    plain = _HTML_TAG_RE.sub(" ", text)
    return unescape(re.sub(r"\s+", " ", plain)).strip()


def extract_otp(blob: str, pattern: re.Pattern[str] | None = None) -> str | None:
    otp_re = pattern or DEFAULT_OTP_PATTERN
    for candidate in (blob, _strip_html(blob)):
        match = otp_re.search(candidate)
        if not match:
            continue
        code = match.group(1) if match.lastindex else match.group(0)
        if OTP_RE.match(code):
            return code
    return None


def _sanitize_local_part(prefix: str) -> str:
    base = (prefix or "").strip().lower()
    base = _LOCAL_PART_RE.sub("", base).strip("._-")
    return base[:48]


def _inbox_path(address: str) -> str:
    return quote(address, safe="")


class FreeCustomProvider:
    """Create FreeCustom.Email inboxes and wait for SAS OTP codes."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://api2.freecustom.email",
        domain: str = "ditapi.info",
        banned_domains: frozenset[str] | set[str] | None = None,
        timeout: float = 30,
        session: requests.Session | None = None,
    ) -> None:
        if not api_key.strip():
            raise EmailProviderError(
                "FreeCustom API key is required (set FREECUSTOM_API_KEY or FCE_API_KEY). "
                "Free plan: sign in at https://www.freecustom.email/api → dashboard."
            )
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.banned_domains = frozenset(
            banned_domains
            if banned_domains is not None
            else config.freecustom_banned_domains()
        )
        preferred = (domain or "ditapi.info").strip().lstrip("@").lower()
        if preferred and preferred in self.banned_domains:
            logger.warning(
                "FREECUSTOM_DOMAIN=%s is banned; ignoring preferred domain",
                preferred,
            )
            preferred = ""
        self.domain = preferred
        self.timeout = timeout
        if session is not None:
            self._session = session
        else:
            from ..http_bind import get_bound_session

            self._session = get_bound_session()

    @classmethod
    def from_config(cls) -> FreeCustomProvider:
        key = (config.FREECUSTOM_API_KEY or "").strip()
        banned = config.freecustom_banned_domains()
        preferred = (config.FREECUSTOM_DOMAIN or "ditapi.info").strip().lstrip("@")
        return cls(
            api_key=key,
            base_url=config.FREECUSTOM_BASE_URL,
            domain=preferred,
            banned_domains=banned,
        )

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> Any:
        url = f"{self.base_url}{path}" if path.startswith("/") else f"{self.base_url}/{path}"
        headers = (
            self._headers(json_body=json_body is not None)
            if auth
            else {
                "Accept": "application/json",
                **({"Content-Type": "application/json"} if json_body is not None else {}),
            }
        )
        try:
            response = self._session.request(
                method.upper(),
                url,
                params=params,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as error:
            raise EmailProviderError(f"FreeCustom request failed: {error}") from error

        body_snip = (response.text or "")[:500]
        if response.status_code == 401:
            raise EmailProviderError(
                f"FreeCustom auth failed (401): check FREECUSTOM_API_KEY. {body_snip[:300]}"
            )
        if response.status_code == 403:
            raise EmailProviderError(f"FreeCustom forbidden (403): {body_snip[:300]}")
        if response.status_code == 429:
            # Free plan is ~1 req/s — caller may retry; surface retryAfter when present.
            retry_after = response.headers.get("Retry-After") or ""
            try:
                data_tmp = response.json()
                if isinstance(data_tmp, dict) and data_tmp.get("retryAfter") is not None:
                    retry_after = str(data_tmp.get("retryAfter"))
            except ValueError:
                pass
            raise EmailProviderError(
                f"FreeCustom rate limited (429) retryAfter={retry_after or '?'}: "
                f"{body_snip[:300]}"
            )
        if response.status_code >= 400:
            raise EmailProviderError(
                f"FreeCustom {method.upper()} {path} → {response.status_code}: {body_snip}"
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as error:
            raise EmailProviderError(
                f"FreeCustom non-JSON response: {body_snip[:300]}"
            ) from error

    def _request_with_retry(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        auth: bool = True,
        max_retries: int = 4,
    ) -> Any:
        """HTTP with short backoff on free-tier 429 (1 req/s)."""
        last: Exception | None = None
        for i in range(max_retries):
            try:
                return self._request(
                    method, path, params=params, json_body=json_body, auth=auth
                )
            except EmailProviderError as error:
                last = error
                if "rate limited" not in str(error).lower() or i + 1 >= max_retries:
                    raise
                wait = 1.2 + i * 0.5
                # parse retryAfter=N if present
                msg = str(error)
                if "retryAfter=" in msg:
                    try:
                        part = msg.split("retryAfter=", 1)[1].split(":", 1)[0].strip()
                        wait = max(wait, float(part) + 0.2)
                    except ValueError:
                        pass
                logger.info("FreeCustom 429 backoff %.1fs (%s)", wait, path)
                time.sleep(wait)
        raise EmailProviderError(f"FreeCustom retries exhausted: {last}") from last

    def list_domains(self) -> list[dict[str, Any]]:
        raw = self._request_with_retry("GET", "/v1/domains")
        data = raw.get("data") if isinstance(raw, dict) else None
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []

    def free_domains(self) -> list[str]:
        """Return free-tier platform domains, excluding banned hosts."""
        try:
            rows = self.list_domains()
        except EmailProviderError as error:
            logger.warning("FreeCustom list domains failed: %s", error)
            fallback = self.domain if self.domain and self.domain not in self.banned_domains else ""
            return [fallback] if fallback else []
        free = [
            str(r.get("domain") or "").strip().lstrip("@").lower()
            for r in rows
            if str(r.get("tier") or "").lower() == "free" and r.get("domain")
        ]
        seen: set[str] = set()
        out: list[str] = []
        for d in free:
            if not d or d in seen:
                continue
            if d in self.banned_domains:
                logger.debug("FreeCustom skipping banned domain %s", d)
                continue
            seen.add(d)
            out.append(d)
        if not out:
            # last resort: preferred if not banned
            if self.domain and self.domain not in self.banned_domains:
                return [self.domain]
            raise EmailProviderError(
                "FreeCustom has no usable free domains after ban filter "
                f"(banned={','.join(sorted(self.banned_domains)) or 'none'})"
            )
        return out

    def _domain_pool(self) -> list[str]:
        """Shuffled free domains — maximize variety across registrations."""
        pool = self.free_domains()
        if not pool:
            raise EmailProviderError("FreeCustom free domain pool is empty")
        random.shuffle(pool)
        return pool

    def _pick_domain(self) -> str:
        """Pick a random free domain (not sticky)."""
        return self._domain_pool()[0]

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        """Create/register a FreeCustom inbox on a varied free domain.

        Prefer generate (public OTP token) with a random free domain each time.
        Fall back to explicit register, rotating domains on failure.
        """
        pool = self._domain_pool()
        base_prefix = _sanitize_local_part(prefix or "")
        last_error: Exception | None = None

        # Free plan: POST /v1/inboxes only (bulk /generate is Developer+).
        # Shuffle free domains for max variety (18 free hosts as of pilot).
        for attempt in range(8):
            domain = pool[attempt % len(pool)]
            if base_prefix:
                local = (
                    base_prefix
                    if attempt < len(pool)
                    else f"{base_prefix}{random.randint(1, 99999)}"
                )
            else:
                local = f"user{random.randint(100000, 999999)}"
            address = f"{local[:48]}@{domain}"
            try:
                raw = self._request_with_retry(
                    "POST", "/v1/inboxes", json_body={"inbox": address}
                )
            except EmailProviderError as error:
                last_error = error
                logger.info(
                    "FreeCustom register retry attempt=%s domain=%s: %s",
                    attempt + 1,
                    domain,
                    error,
                )
                continue
            email = str(
                (raw.get("inbox") if isinstance(raw, dict) else None) or address
            )
            used_domain = email.rsplit("@", 1)[-1].lower() if "@" in email else domain
            logger.info(
                "FreeCustom inbox registered email=%s domain=%s", email, used_domain
            )
            return Inbox(
                address=email,
                external_id=email,
                meta={
                    "provider": "freecustom",
                    "domain": used_domain,
                    "via": "register",
                    "raw": raw if isinstance(raw, dict) else {},
                },
            )

        raise EmailProviderError(
            f"FreeCustom create_inbox failed: {last_error}"
        ) from last_error

    def _list_messages(self, inbox: Inbox) -> list[dict[str, Any]]:
        address = inbox.address
        raw = self._request_with_retry(
            "GET",
            f"/v1/inboxes/{_inbox_path(address)}/messages",
            params={"limit": 20},
        )
        data = raw.get("data") if isinstance(raw, dict) else None
        if isinstance(data, dict):
            msgs = data.get("messages")
            if isinstance(msgs, list):
                return [m for m in msgs if isinstance(m, dict)]
        if isinstance(data, list):
            return [m for m in data if isinstance(m, dict)]
        return []

    def _get_message(self, inbox: Inbox, msg_id: str) -> dict[str, Any]:
        raw = self._request_with_retry(
            "GET",
            f"/v1/inboxes/{_inbox_path(inbox.address)}/messages/{quote(msg_id, safe='')}",
        )
        data = raw.get("data") if isinstance(raw, dict) else raw
        return data if isinstance(data, dict) else {}

    def _poll_public_otp(self, inbox: Inbox) -> str | None:
        token = (inbox.token or "").strip()
        otp_url = str((inbox.meta or {}).get("otp_url") or "")
        params: dict[str, Any] = {"parseCode": "true"}
        if token:
            params["token"] = token
        elif otp_url:
            parsed = urlparse(otp_url)
            q = parse_qs(parsed.query)
            if q.get("token"):
                params["token"] = q["token"][0]
            if q.get("since"):
                params["since"] = q["since"][0]
            if q.get("parseCode"):
                params["parseCode"] = q["parseCode"][0]
        else:
            return None
        if not params.get("token"):
            return None
        # Public endpoint — still send key if we have it (harmless)
        try:
            raw = self._request_with_retry(
                "GET",
                "/v1/otp/public",
                params=params,
                auth=False,
            )
        except EmailProviderError:
            try:
                raw = self._request_with_retry(
                    "GET", "/v1/otp/public", params=params, auth=True
                )
            except EmailProviderError as error:
                logger.debug("FreeCustom public OTP poll: %s", error)
                return None
        data = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(data, dict):
            return None
        otp = data.get("otp")
        if otp and OTP_RE.match(str(otp).strip()):
            return str(otp).strip()
        return None

    def _poll_otp_endpoint(self, inbox: Inbox) -> str | None:
        try:
            raw = self._request_with_retry(
                "GET",
                f"/v1/inboxes/{_inbox_path(inbox.address)}/otp",
                params={"parseCode": "true"},
            )
        except EmailProviderError as error:
            logger.debug("FreeCustom /otp: %s", error)
            return None
        data = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(data, dict):
            return None
        otp = data.get("otp")
        if otp and str(otp) not in {"__DETECTED__", "null", "None"}:
            if OTP_RE.match(str(otp).strip()):
                return str(otp).strip()
        return None

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
            # 1) Public pre-signed OTP URL (best free path)
            code = self._poll_public_otp(inbox)
            if code:
                logger.info(
                    "FreeCustom OTP via public token email=%s", inbox.address
                )
                return code

            # 2) Authenticated OTP endpoint (may work with parseCode on free)
            code = self._poll_otp_endpoint(inbox)
            if code:
                logger.info(
                    "FreeCustom OTP via /otp email=%s", inbox.address
                )
                return code

            # 3) Message list + full body extract
            try:
                messages = self._list_messages(inbox)
            except EmailProviderError as error:
                logger.warning("FreeCustom poll error: %s", error)
                time.sleep(poll)
                continue

            logger.info(
                "FreeCustom poll #%s email=%s messages=%s",
                poll_i,
                inbox.address,
                len(messages),
            )
            for msg in messages:
                msg_id = str(msg.get("id") or "")
                # summary may already have otp
                otp_field = msg.get("otp")
                if (
                    otp_field
                    and str(otp_field) not in {"__DETECTED__", "null", "None"}
                    and OTP_RE.match(str(otp_field).strip())
                ):
                    return str(otp_field).strip()

                blob_parts = [str(msg.get("subject") or "")]
                if msg_id and msg_id not in seen_ids:
                    seen_ids.add(msg_id)
                    try:
                        full = self._get_message(inbox, msg_id)
                    except EmailProviderError as error:
                        logger.debug("FreeCustom get message %s: %s", msg_id, error)
                        full = {}
                    for key in ("subject", "text", "html", "body"):
                        if full.get(key):
                            blob_parts.append(str(full[key]))
                    fotp = full.get("otp")
                    if (
                        fotp
                        and str(fotp) not in {"__DETECTED__", "null", "None"}
                        and OTP_RE.match(str(fotp).strip())
                    ):
                        return str(fotp).strip()
                else:
                    blob_parts.append(str(msg.get("subject") or ""))

                code = extract_otp(" ".join(blob_parts), pattern)
                if code:
                    logger.info(
                        "FreeCustom OTP from message body email=%s msg=%s",
                        inbox.address,
                        msg_id or "?",
                    )
                    return code

            time.sleep(poll)

        raise EmailProviderError(f"OTP timeout after {timeout}s for {inbox.address}")
