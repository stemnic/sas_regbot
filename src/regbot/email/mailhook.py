"""Mailhook disposable email client for SAS OTP.

API docs: https://app.mailhook.co/llms.txt
Base: https://app.mailhook.co/api/v1

Auth: X-Agent-ID + X-API-Key

Flow:
  POST /agents/register          (optional auto-bootstrap)
  POST /domains                  (shared *.tail.me)
  POST /email_addresses          (local_part) or /email_addresses/random
  GET  /email_addresses/:id/inbound_emails

Traffic is **direct** (not through SAS Oxylabs proxy).
"""

from __future__ import annotations

import json
import logging
import random
import re
import secrets
import time
from html import unescape
from pathlib import Path
from typing import Any

import requests

from .. import config
from ..profile import OTP_RE
from .base import DEFAULT_OTP_PATTERN, EmailProviderError, Inbox

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_LOCAL_PART_RE = re.compile(r"[^a-z0-9._-]")

# Single random word for shared subdomains (no project/tool names).
_SLUG_WORDS = (
    "amber",
    "coral",
    "delta",
    "ember",
    "frost",
    "harbor",
    "ivory",
    "jade",
    "lotus",
    "maple",
    "north",
    "olive",
    "pine",
    "quartz",
    "river",
    "sage",
    "tide",
    "willow",
    "anchor",
    "bridge",
    "canyon",
    "falcon",
    "garden",
    "island",
    "meadow",
    "orchid",
    "pebble",
    "summit",
    "cedar",
    "flint",
    "grove",
    "hazel",
    "linen",
    "mirth",
    "nimbus",
    "opal",
)


def _random_tailme_slug() -> str:
    """One random word for the Mailhook shared subdomain."""
    return secrets.choice(_SLUG_WORDS)


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


def looks_like_address_limit(message: str) -> bool:
    """True when Mailhook rejected create due to email-address capacity."""
    low = (message or "").lower()
    markers = (
        "email address limit",
        "address limit",
        "limit reached",
        "too many email",
        "maximum email",
        "max email",
        "only 1 email",
        "1 email address",
        "quota",
        "plan allows",
        "upgrade",
    )
    if any(m in low for m in markers) and (
        "email" in low or "address" in low or "limit" in low or "quota" in low
    ):
        return True
    if "422" in low and "email" in low:
        return True
    return False


def _attrs(resource: dict[str, Any]) -> dict[str, Any]:
    """Flatten JSON:API-style {id, attributes} into a single dict."""
    if not isinstance(resource, dict):
        return {}
    out: dict[str, Any] = dict(resource)
    attrs = resource.get("attributes")
    if isinstance(attrs, dict):
        for k, v in attrs.items():
            out.setdefault(k, v)
    return out


def _unwrap_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _email_blob(msg: dict[str, Any]) -> str:
    flat = _attrs(msg)
    parts: list[str] = []
    for key in (
        "subject",
        "text_body",
        "html_body",
        "textBody",
        "htmlBody",
        "text",
        "html",
        "body",
        "content",
        "preview",
        "snippet",
    ):
        val = flat.get(key)
        if val:
            parts.append(str(val))
    return " ".join(parts)


def _sanitize_local_part(prefix: str) -> str:
    base = (prefix or "").strip().lower()
    base = _LOCAL_PART_RE.sub("", base).strip("._-")
    return base[:48]


class MailhookProvider:
    """Create Mailhook temp mailboxes and poll for SAS OTP codes."""

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: str,
        base_url: str = "https://app.mailhook.co/api/v1",
        domain_id: str = "",
        tailme_slug: str = "",
        max_emails_per_domain: int | None = None,
        timeout: float = 30,
        session: requests.Session | None = None,
        auto_ensure_domain: bool = True,
    ) -> None:
        if not agent_id.strip() or not api_key.strip():
            raise EmailProviderError(
                "Mailhook requires MAILHOOK_AGENT_ID and MAILHOOK_API_KEY "
                "(or MAILHOOK_AUTO_REGISTER=true for first-run bootstrap). "
                "See https://app.mailhook.co/llms.txt"
            )
        self.agent_id = agent_id.strip()
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.domain_id = (domain_id or "").strip()
        self.tailme_slug = (tailme_slug or "").strip()
        self.timeout = timeout
        self._auto_ensure_domain = auto_ensure_domain
        self.max_emails_per_domain = max(
            1,
            int(
                max_emails_per_domain
                if max_emails_per_domain is not None
                else getattr(config, "MAILHOOK_MAX_EMAILS_PER_DOMAIN", 2)
            ),
        )
        if session is not None:
            self._session = session
        else:
            from ..http_bind import get_bound_session

            self._session = get_bound_session()

    @classmethod
    def from_config(cls) -> MailhookProvider:
        agent_id, api_key, domain_id, slug = resolve_mailhook_credentials()
        return cls(
            agent_id=agent_id,
            api_key=api_key,
            base_url=config.MAILHOOK_BASE_URL,
            domain_id=domain_id or config.MAILHOOK_DOMAIN_ID,
            tailme_slug=slug or config.MAILHOOK_TAILME_SLUG,
            max_emails_per_domain=getattr(config, "MAILHOOK_MAX_EMAILS_PER_DOMAIN", 2),
        )

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "X-Agent-ID": self.agent_id,
            "X-API-Key": self.api_key,
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
            raise EmailProviderError(f"Mailhook request failed: {error}") from error

        body_snip = (response.text or "")[:500]
        if response.status_code == 401:
            raise EmailProviderError(
                f"Mailhook auth failed (401): check MAILHOOK_AGENT_ID / MAILHOOK_API_KEY. "
                f"{body_snip[:300]}"
            )
        if response.status_code == 403:
            raise EmailProviderError(
                f"Mailhook forbidden (403): {body_snip[:300]}"
            )
        if response.status_code >= 400:
            raise EmailProviderError(
                f"Mailhook {method.upper()} {path} → {response.status_code}: {body_snip}"
            )
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as error:
            raise EmailProviderError(
                f"Mailhook non-JSON response: {body_snip[:300]}"
            ) from error
        return data

    def list_domains(self) -> list[dict[str, Any]]:
        raw = self._request("GET", "/domains")
        data = _unwrap_data(raw)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("domains", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    return [r for r in val if isinstance(r, dict)]
        return []

    def list_email_addresses(self) -> list[dict[str, Any]]:
        raw = self._request("GET", "/email_addresses")
        data = _unwrap_data(raw)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("email_addresses", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    return [r for r in val if isinstance(r, dict)]
        return []

    def email_counts_by_domain(self) -> dict[str, int]:
        """Active address counts keyed by domain_id string."""
        counts: dict[str, int] = {}
        for row in self.list_email_addresses():
            flat = _attrs(row)
            did = flat.get("domain_id")
            if did is None or did == "":
                # Fall back to domain host → match later if needed
                continue
            key = str(did)
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _domain_ready(flat: dict[str, Any]) -> bool:
        ready = flat.get("ready")
        status = str(
            flat.get("verification_status") or flat.get("status") or ""
        ).lower()
        if ready is True:
            return True
        if ready is False:
            return False
        return status in {"verified", "ready", "active", "provisioned", ""}

    def create_shared_domain(self, *, prefer_slug: str = "") -> str:
        """Create a shared *.tail.me domain with a random single-word slug."""
        last_error: Exception | None = None
        fixed_slug = (prefer_slug or self.tailme_slug or "").strip()
        for attempt in range(8):
            if attempt == 0 and fixed_slug:
                slug = fixed_slug
            else:
                slug = _random_tailme_slug()
            payload: dict[str, Any] = {"domain_type": "shared", "tailme_slug": slug}
            logger.info("Mailhook creating shared domain slug=%s", slug)
            try:
                raw = self._request("POST", "/domains", json_body=payload)
            except EmailProviderError as error:
                last_error = error
                logger.info("Mailhook domain slug %s failed, retrying: %s", slug, error)
                continue
            created = _unwrap_data(raw)
            if not isinstance(created, dict):
                last_error = EmailProviderError(
                    f"Mailhook create domain unexpected: {raw}"
                )
                continue
            flat = _attrs(created)
            rid = str(flat.get("id") or created.get("id") or "")
            if not rid:
                last_error = EmailProviderError(
                    f"Mailhook create domain missing id: {raw}"
                )
                continue
            self.domain_id = rid
            self.tailme_slug = str(flat.get("name") or slug)
            _persist_domain_id(rid)
            logger.info(
                "Mailhook domain ready id=%s name=%s",
                rid,
                flat.get("name") or slug,
            )
            return rid
        raise EmailProviderError(
            f"Mailhook create domain failed after retries: {last_error}. "
            "Plan may limit shared domains — upgrade or free capacity."
        ) from last_error

    def pick_domain_for_inbox(self) -> str:
        """Pick a domain with fewer than max emails, else create a new subdomain.

        Cap (default 2) avoids reusing the same *.tail.me subdomain too heavily.
        """
        max_n = self.max_emails_per_domain
        counts = self.email_counts_by_domain()
        rows = self.list_domains()

        candidates: list[tuple[int, str, str]] = []  # (count, id, name)
        for row in rows:
            flat = _attrs(row)
            rid = str(flat.get("id") or row.get("id") or "")
            name = str(flat.get("name") or flat.get("full_domain") or "").lower()
            if not rid:
                continue
            if "regbot" in name:
                logger.info("Mailhook skipping branded domain id=%s name=%s", rid, name)
                continue
            if not self._domain_ready(flat):
                continue
            count = counts.get(rid, counts.get(str(int(rid)) if rid.isdigit() else rid, 0))
            # Domain attribute fallback when list is empty/partial
            if count == 0 and rid not in counts:
                attr_count = flat.get("email_addresses_count")
                if attr_count is not None:
                    try:
                        count = int(attr_count)
                    except (TypeError, ValueError):
                        count = 0
            if count < max_n:
                candidates.append((count, rid, name))

        preferred = (self.domain_id or "").strip()
        if preferred:
            for count, rid, name in candidates:
                if rid == preferred or (
                    preferred.isdigit() and rid == preferred
                ):
                    logger.info(
                        "Mailhook reusing preferred domain id=%s name=%s count=%s/%s",
                        rid,
                        name,
                        count,
                        max_n,
                    )
                    self.domain_id = rid
                    _persist_domain_id(rid)
                    return rid
            pref_count = counts.get(preferred, 0)
            if pref_count >= max_n:
                logger.info(
                    "Mailhook preferred domain id=%s at cap (%s/%s) — rotating subdomain",
                    preferred,
                    pref_count,
                    max_n,
                )

        if candidates:
            # Fill domains that already have 1 address before opening empty ones,
            # then lowest id for stability.
            candidates.sort(key=lambda t: (-t[0], t[1]))
            count, rid, name = candidates[0]
            logger.info(
                "Mailhook selected domain id=%s name=%s count=%s/%s",
                rid,
                name,
                count,
                max_n,
            )
            self.domain_id = rid
            _persist_domain_id(rid)
            return rid

        logger.info(
            "Mailhook all domains at cap (%s emails) — creating new subdomain",
            max_n,
        )
        return self.create_shared_domain()

    def ensure_domain(self) -> str:
        """Return a domain under the per-subdomain email cap (create if needed)."""
        return self.pick_domain_for_inbox()

    def delete_email_address(self, email_id: str) -> None:
        eid = (email_id or "").strip()
        if not eid:
            raise EmailProviderError("Mailhook delete requires email address id")
        self._request("DELETE", f"/email_addresses/{eid}")
        logger.info("Mailhook deleted email_address id=%s", eid)

    def free_one_oldest_address(self) -> dict[str, Any] | None:
        rows = self.list_email_addresses()
        if not rows:
            logger.info("Mailhook free_one_oldest: no addresses to delete")
            return None

        def sort_key(row: dict[str, Any]) -> str:
            flat = _attrs(row)
            return str(
                flat.get("created_at")
                or flat.get("createdAt")
                or flat.get("id")
                or ""
            )

        oldest = sorted(rows, key=sort_key)[0]
        flat = _attrs(oldest)
        eid = str(flat.get("id") or oldest.get("id") or "")
        if not eid:
            raise EmailProviderError(f"Mailhook oldest address missing id: {oldest}")
        logger.info(
            "Mailhook pruning oldest address id=%s email=%s",
            eid,
            flat.get("email") or "",
        )
        self.delete_email_address(eid)
        return oldest

    def create_inbox(self, *, prefix: str | None = None) -> Inbox:
        """Create a disposable Mailhook address.

        Prefer ``local_part`` from profile prefix (``john.smith``). Rotates
        ``*.tail.me`` subdomain after ``max_emails_per_domain`` (default 2)
        addresses. On free-tier capacity errors, free the oldest address once
        and retry.
        """
        if self._auto_ensure_domain:
            domain_id = self.pick_domain_for_inbox()
        else:
            domain_id = self.domain_id
            if not domain_id:
                raise EmailProviderError("Mailhook domain_id is required")

        base_prefix = _sanitize_local_part(prefix or "")
        last_error: Exception | None = None
        pruned_once = False

        for attempt in range(5):
            use_local = bool(base_prefix)
            if use_local:
                if attempt == 0:
                    local_part = base_prefix
                else:
                    local_part = f"{base_prefix}{random.randint(1, 99999)}"[:48]
                path = "/email_addresses"
                body: dict[str, Any] = {
                    "domain_id": domain_id,
                    "local_part": local_part,
                    "metadata": {"task": "sas-registration", "prefix": local_part},
                }
            else:
                path = "/email_addresses/random"
                body = {
                    "domain_id": domain_id,
                    "metadata": {"task": "sas-registration"},
                }

            try:
                raw = self._request("POST", path, json_body=body)
            except EmailProviderError as error:
                last_error = error
                err_s = str(error)
                if looks_like_address_limit(err_s) or response_looks_like_limit(err_s):
                    prune_on = bool(
                        getattr(config, "REGBOT_MAILHOOK_PRUNE_OLDEST", True)
                    )
                    if prune_on and not pruned_once:
                        try:
                            freed = self.free_one_oldest_address()
                        except EmailProviderError as prune_err:
                            raise EmailProviderError(
                                f"Mailhook address limit and failed to free oldest: {prune_err}"
                            ) from prune_err
                        pruned_once = True
                        if freed is None:
                            raise EmailProviderError(
                                "Mailhook address limit: no existing address to free. "
                                "Upgrade plan or wait for retention expiry."
                            ) from error
                        logger.info("Mailhook retrying create after free oldest")
                        continue
                    raise EmailProviderError(
                        f"Mailhook address limit: {error}"
                    ) from error
                if "auth failed" in err_s.lower():
                    raise
                # name collision / validation — retry with digits or random
                logger.info("Mailhook create retry attempt=%s: %s", attempt + 1, error)
                if attempt >= 2:
                    base_prefix = ""  # fall through to random
                continue

            data = _unwrap_data(raw)
            if not isinstance(data, dict):
                last_error = EmailProviderError(f"Mailhook create unexpected: {raw}")
                continue
            flat = _attrs(data)
            address = (
                flat.get("email")
                or flat.get("address")
                or flat.get("mail")
                or data.get("email")
            )
            inbox_id = str(flat.get("id") or data.get("id") or "")
            if not address:
                last_error = EmailProviderError(f"Mailhook create missing email: {raw}")
                continue
            if not inbox_id:
                last_error = EmailProviderError(f"Mailhook create missing id: {raw}")
                continue

            logger.info(
                "Mailhook inbox ready email=%s id=%s pruned=%s",
                address,
                inbox_id,
                pruned_once,
            )
            return Inbox(
                address=str(address),
                external_id=inbox_id,
                meta={
                    "provider": "mailhook",
                    "domain_id": domain_id,
                    "raw": data,
                    "pruned_oldest": pruned_once,
                },
            )

        raise EmailProviderError(
            f"Mailhook create_inbox failed after retries: {last_error}"
        ) from last_error

    def _list_inbound(self, inbox: Inbox) -> list[dict[str, Any]]:
        if not inbox.external_id:
            raise EmailProviderError("Mailhook inbox missing external_id")
        raw = self._request(
            "GET", f"/email_addresses/{inbox.external_id}/inbound_emails"
        )
        data = _unwrap_data(raw)
        if isinstance(data, list):
            return [m for m in data if isinstance(m, dict)]
        if isinstance(data, dict):
            for key in ("inbound_emails", "emails", "messages", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    return [m for m in val if isinstance(m, dict)]
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
        deadline = time.time() + timeout
        seen_ids: set[str] = set()
        poll_i = 0

        while time.time() < deadline:
            poll_i += 1
            try:
                messages = self._list_inbound(inbox)
            except EmailProviderError as error:
                logger.warning("Mailhook poll error: %s", error)
                time.sleep(poll)
                continue

            logger.info(
                "Mailhook poll #%s email=%s id=%s messages=%s",
                poll_i,
                inbox.address,
                inbox.external_id or "?",
                len(messages),
            )
            for msg in messages:
                flat = _attrs(msg)
                msg_id = str(flat.get("id") or msg.get("id") or "")
                if msg_id and msg_id in seen_ids:
                    continue
                if msg_id:
                    seen_ids.add(msg_id)
                blob = _email_blob(msg)
                code = extract_otp(blob, pattern)
                if code:
                    logger.info(
                        "Mailhook OTP found email=%s msg_id=%s",
                        inbox.address,
                        msg_id or "?",
                    )
                    return code
            time.sleep(poll)

        raise EmailProviderError(f"OTP timeout after {timeout}s for {inbox.address}")


def response_looks_like_limit(message: str) -> bool:
    """Broader capacity heuristics for free-tier single-address plans."""
    low = (message or "").lower()
    if "429" in low:
        return True
    if "cannot create" in low and "email" in low:
        return True
    if "already have" in low and "email" in low:
        return True
    return looks_like_address_limit(message)


def _credentials_path() -> Path:
    return Path(config.MAILHOOK_CREDENTIALS_PATH or "data/mailhook_credentials.json")


def _load_credentials_file() -> dict[str, Any]:
    path = _credentials_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        logger.warning("Mailhook credentials load failed: %s", error)
        return {}


def _save_credentials_file(data: dict[str, Any]) -> None:
    path = _credentials_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        logger.info("Mailhook credentials saved to %s", path)
    except OSError as error:
        logger.warning("Mailhook credentials save failed: %s", error)


def _persist_domain_id(domain_id: str) -> None:
    if not domain_id:
        return
    data = _load_credentials_file()
    if data.get("domain_id") == domain_id:
        return
    data["domain_id"] = domain_id
    # Keep existing agent fields if present
    if "agent_id" not in data and config.MAILHOOK_AGENT_ID:
        data["agent_id"] = config.MAILHOOK_AGENT_ID
    if "api_key" not in data and config.MAILHOOK_API_KEY:
        data["api_key"] = config.MAILHOOK_API_KEY
    if data.get("agent_id") and data.get("api_key"):
        _save_credentials_file(data)


def resolve_mailhook_credentials() -> tuple[str, str, str, str]:
    """Resolve (agent_id, api_key, domain_id, slug), auto-registering if allowed.

    Order: env → credentials file → POST /agents/register (when enabled).
    """
    agent_id = (config.MAILHOOK_AGENT_ID or "").strip()
    api_key = (config.MAILHOOK_API_KEY or "").strip()
    domain_id = (config.MAILHOOK_DOMAIN_ID or "").strip()
    slug = (config.MAILHOOK_TAILME_SLUG or "").strip()

    file_data = _load_credentials_file()
    if not agent_id:
        agent_id = str(file_data.get("agent_id") or "").strip()
    if not api_key:
        api_key = str(file_data.get("api_key") or "").strip()
    if not domain_id:
        domain_id = str(file_data.get("domain_id") or "").strip()
    if not slug:
        slug = str(file_data.get("tailme_slug") or "").strip()

    if agent_id and api_key:
        return agent_id, api_key, domain_id, slug

    if not config.MAILHOOK_AUTO_REGISTER:
        raise EmailProviderError(
            "Mailhook credentials missing and MAILHOOK_AUTO_REGISTER is false. "
            "Set MAILHOOK_AGENT_ID + MAILHOOK_API_KEY."
        )

    logger.info("Mailhook auto-registering free-tier agent")
    from ..http_bind import get_bound_session

    session = get_bound_session()
    base = config.MAILHOOK_BASE_URL.rstrip("/")
    try:
        response = session.post(
            f"{base}/agents/register",
            json={"name": f"agent-{secrets.token_hex(4)}"},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
    except requests.RequestException as error:
        raise EmailProviderError(f"Mailhook agent register failed: {error}") from error

    if response.status_code >= 400:
        raise EmailProviderError(
            f"Mailhook agent register → {response.status_code}: {response.text[:400]}"
        )
    try:
        payload = response.json()
    except ValueError as error:
        raise EmailProviderError(
            f"Mailhook agent register non-JSON: {response.text[:300]}"
        ) from error

    data = _unwrap_data(payload)
    if not isinstance(data, dict):
        raise EmailProviderError(f"Mailhook agent register unexpected: {payload}")
    agent_id = str(
        data.get("agent_id") or data.get("id") or _attrs(data).get("agent_id") or ""
    ).strip()
    api_key = str(data.get("api_key") or _attrs(data).get("api_key") or "").strip()
    if not agent_id or not api_key:
        raise EmailProviderError(
            f"Mailhook agent register missing agent_id/api_key: {payload}"
        )

    save = {
        "agent_id": agent_id,
        "api_key": api_key,
        "tier": data.get("tier") or _attrs(data).get("tier"),
        "registered_at": time.time(),
    }
    if domain_id:
        save["domain_id"] = domain_id
    if slug:
        save["tailme_slug"] = slug
    _save_credentials_file(save)
    logger.info("Mailhook agent registered id=%s", agent_id)
    return agent_id, api_key, domain_id, slug
