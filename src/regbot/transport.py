"""curl_cffi transport that forces all SAS traffic through a sticky proxy."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from curl_cffi import requests as cffi_requests

from . import config
from .proxy import StickyProxy

logger = logging.getLogger(__name__)

# Hosts that must never leave the machine without the sticky proxy.
_SAS_HOST_SUFFIXES = (
    "flysas.com",
    "sas.no",
    "sas.se",
    "sas.dk",
)

_BLOCK_STATUSES = {403, 429, 503}
_BLOCK_MARKERS = (
    "access denied",
    "you are blocked",
    "rate limited",
    "just a moment",
    "cf-chl",
    "challenge-platform",
    "error 1015",
    "error 1020",
    "denied boarding",
)


class TransportError(RuntimeError):
    """Base transport failure."""


class ProxyRequiredError(TransportError):
    """Raised when a SAS request would not use a proxy."""


class BlockedError(TransportError):
    """Cloudflare / WAF style block; rotate sticky session."""

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class SasHttpError(TransportError):
    """Non-block HTTP failure from SAS APIs."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: str = "",
        payload: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body
        self.payload = payload


def is_sas_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == suffix or host.endswith("." + suffix) for suffix in _SAS_HOST_SUFFIXES)


def block_reason(status: int, headers: Mapping[str, Any], body: str) -> str | None:
    if status in _BLOCK_STATUSES:
        return f"http-{status}"
    normalized = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    if normalized.get("cf-mitigated") == "challenge":
        return "cf-mitigated"
    lowered = body[:250_000].lower()
    for marker in _BLOCK_MARKERS:
        if marker in lowered:
            return f"body-{marker.replace(' ', '-')}"
    return None


class ProxiedSession:
    """One curl_cffi session bound to a sticky proxy for the whole attempt."""

    def __init__(
        self,
        proxy: StickyProxy,
        *,
        impersonate: str | None = None,
        timeout: float | None = None,
        session_factory: Any = cffi_requests.Session,
    ) -> None:
        if not proxy.proxies():
            raise ProxyRequiredError("Sticky proxy has empty proxies dict")
        self.proxy = proxy
        self.impersonate = impersonate or config.REGBOT_IMPERSONATE
        self.timeout = timeout if timeout is not None else config.REGBOT_REQUEST_TIMEOUT_S
        self._session_factory = session_factory
        self._session = session_factory(
            impersonate=self.impersonate,
            proxies=proxy.proxies(),
        )
        self._assert_proxied()

    def _assert_proxied(self) -> None:
        proxies = getattr(self._session, "proxies", None) or {}
        if not proxies.get("http") and not proxies.get("https"):
            raise ProxyRequiredError("curl_cffi session has no proxy configured")

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            logger.warning("Could not close proxied session cleanly")

    def __enter__(self) -> ProxiedSession:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        allow_non_sas: bool = False,
        expect_json: bool = True,
        user_agent: str | None = None,
        cookies: str | None = None,
    ) -> Any:
        """Issue a request. SAS URLs always require the sticky proxy (enforced)."""
        if is_sas_url(url) or not allow_non_sas:
            if is_sas_url(url) or urlparse(url).hostname:
                # Default: treat unknown hosts on this session as proxy-only too
                # for ipify/warm helpers. CapSolver control plane uses plain requests.
                self._assert_proxied()
            if is_sas_url(url) and not (getattr(self._session, "proxies", None) or {}):
                raise ProxyRequiredError(f"Refusing direct SAS request to {url}")

        req_headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": config.REGBOT_ORIGIN,
            "Referer": f"{config.REGBOT_ORIGIN}/",
            "Content-Type": "application/json",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": user_agent or config.REGBOT_USER_AGENT,
        }
        if cookies:
            req_headers["Cookie"] = cookies
        if headers:
            req_headers.update(headers)

        response = self._session.request(
            method.upper(),
            url,
            json=json_body,
            headers=req_headers,
            timeout=self.timeout,
        )
        status = int(response.status_code)
        text = str(response.text or "")
        resp_headers = getattr(response, "headers", {}) or {}

        if status in {401, 407}:
            raise TransportError(f"Proxy authentication failed ({status})")

        # Prefer application JSON errors over CF "block" classification (e.g. 403 + errorInfo)
        app_payload = None
        if expect_json or (text[:1] == "{" and "errorInfo" in text[:500]):
            try:
                app_payload = response.json()
            except Exception:
                app_payload = None
        if (
            status >= 400
            and isinstance(app_payload, dict)
            and (app_payload.get("errorInfo") is not None or app_payload.get("error"))
        ):
            raise SasHttpError(
                f"SAS HTTP {status} for {method.upper()} {url}",
                status=status,
                body=text[:4000],
                payload=app_payload,
            )

        reason = block_reason(status, resp_headers, text)
        if reason:
            raise BlockedError(
                f"Blocked via proxy {self.proxy.label}: {reason}",
                status=status,
                body=text[:2000],
            )

        if status >= 400:
            payload = app_payload
            if payload is None and expect_json:
                try:
                    payload = response.json()
                except Exception:
                    payload = None
            raise SasHttpError(
                f"SAS HTTP {status} for {method.upper()} {url}",
                status=status,
                body=text[:4000],
                payload=payload,
            )

        if not expect_json:
            return response

        if not text.strip():
            return {}
        try:
            return response.json()
        except json.JSONDecodeError as error:
            raise SasHttpError(
                f"Non-JSON response for {method.upper()} {url}",
                status=status,
                body=text[:2000],
            ) from error

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.request("POST", url, **kwargs)

    def sibling(
        self,
        *,
        impersonate: str,
    ) -> "ProxiedSession":
        """New session on the **same** sticky proxy with a different TLS profile.

        Used after CapSolver so enroll TLS matches solution.userAgent (often Chrome).
        """
        return ProxiedSession(
            self.proxy,
            impersonate=impersonate,
            timeout=self.timeout,
            session_factory=self._session_factory,
        )

    def get_proxy_ip(self) -> str:
        """Return egress IP as seen through the sticky proxy (ipify)."""
        data = self.request(
            "GET",
            "https://api.ipify.org/?format=json",
            headers={"Accept": "application/json"},
            allow_non_sas=True,
            expect_json=True,
        )
        ip = str(data.get("ip") or "").strip()
        if not ip:
            raise TransportError(f"ipify returned no IP: {data}")
        return ip
