"""requests Session bound to a local source address (Mullvad WG IP).

Used for CapSolver control plane, OpenInbox, Forward Email, direct Google
fetches, and other host-originated HTTPS that should not leave via bare eth0.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_bind_ip: str | None = None
_session: requests.Session | None = None


class SourceAddressAdapter(HTTPAdapter):
    """HTTPAdapter that binds outbound sockets to a fixed local IPv4."""

    def __init__(self, source_address: str | None = None, **kwargs: Any) -> None:
        self._source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        if self._source_address:
            kwargs["source_address"] = (self._source_address, 0)
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        if self._source_address:
            kwargs["source_address"] = (self._source_address, 0)
        return super().proxy_manager_for(*args, **kwargs)


def configure_bind(bind_ip: str | None) -> None:
    """Set process-wide bind IP and rebuild the shared session."""
    global _bind_ip, _session
    with _lock:
        _bind_ip = (bind_ip or "").strip() or None
        if _session is not None:
            try:
                _session.close()
            except Exception:
                pass
            _session = None
        if _bind_ip:
            logger.debug("HTTP bind source address set to %s", _bind_ip)
        else:
            logger.debug("HTTP bind source address cleared (OS default route)")


def get_bind_ip() -> str | None:
    return _bind_ip


def make_bound_session(bind_ip: str | None = None) -> requests.Session:
    """Create a new Session optionally bound to ``bind_ip`` (or current global)."""
    ip = bind_ip if bind_ip is not None else _bind_ip
    session = requests.Session()
    if ip:
        adapter = SourceAddressAdapter(source_address=ip, max_retries=0)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    return session


def get_bound_session() -> requests.Session:
    """Return a process-wide Session using the configured Mullvad bind IP."""
    global _session
    with _lock:
        if _session is None:
            _session = make_bound_session(_bind_ip)
        return _session


def post(url: str, **kwargs: Any) -> requests.Response:
    return get_bound_session().post(url, **kwargs)


def get(url: str, **kwargs: Any) -> requests.Response:
    return get_bound_session().get(url, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> requests.Response:
    return get_bound_session().request(method, url, **kwargs)
