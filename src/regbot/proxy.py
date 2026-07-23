"""Sticky proxy leases for SAS registration (Oxylabs DC or Bright Data)."""

from __future__ import annotations

import itertools
import random
import re
import string
import threading
from dataclasses import dataclass
from urllib.parse import quote

from . import config

_SESSION_PATTERN = re.compile(r"-session-[A-Za-z0-9]+")
_oxy_port_cycle: itertools.cycle[str] | None = None
_oxy_lock = threading.Lock()


class ProxyError(RuntimeError):
    """Raised when proxy configuration is missing or invalid."""


def _random_session_id(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _session_username(base_username: str, session_id: str) -> str:
    """Add or replace the Bright Data session option in a proxy username."""
    replacement = f"-session-{session_id}"
    if _SESSION_PATTERN.search(base_username):
        return _SESSION_PATTERN.sub(replacement, base_username, count=1)
    return f"{base_username}{replacement}"


def _oxylabs_username(raw: str) -> str:
    """Oxylabs DC expects user-USERNAME (idempotent if already prefixed)."""
    name = raw.strip()
    if not name:
        return name
    if name.startswith("user-"):
        return name
    return f"user-{name}"


def _next_oxylabs_port() -> str:
    global _oxy_port_cycle
    ports = config.oxylabs_ports()
    if len(ports) == 1:
        return ports[0]
    with _oxy_lock:
        if _oxy_port_cycle is None:
            # shuffle once so parallel-ish runs don't all start on 8001
            shuffled = list(ports)
            random.shuffle(shuffled)
            _oxy_port_cycle = itertools.cycle(shuffled)
        return next(_oxy_port_cycle)


@dataclass(frozen=True)
class StickyProxy:
    """One sticky proxy lease for a registration attempt (SAS + CapSolver worker)."""

    session_id: str
    host: str  # host:port
    username: str
    password: str
    provider: str = "oxylabs"

    @property
    def label(self) -> str:
        if self.provider == "oxylabs":
            _, port = self.host_port()
            return f"oxy-{port}"
        return f"bd-{self.session_id[:8]}"

    def host_port(self) -> tuple[str, str]:
        host, port = self.host, "8001"
        if ":" in self.host:
            host, port = self.host.rsplit(":", 1)
        return host, port

    def proxies(self) -> dict[str, str]:
        credentials = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}"
        url = f"http://{credentials}@{self.host}"
        return {"http": url, "https": url}

    def playwright_proxy(self) -> dict[str, str]:
        host, port = self.host_port()
        return {
            "server": f"http://{host}:{port}",
            "username": self.username,
            "password": self.password,
        }

    def capsolver_proxy_string(self, *, style: str = "http_colon") -> str:
        """CapSolver docs: ``http:ip:port:user:pass``."""
        host, port = self.host_port()
        if style == "legacy":
            return f"{host}:{port}:{self.username}:{self.password}"
        return f"http:{host}:{port}:{self.username}:{self.password}"


def new_sticky_proxy(session_id: str | None = None) -> StickyProxy:
    """Create one sticky lease for the configured provider."""
    config.require_proxy_credentials()
    provider = (config.PROXY_PROVIDER or "oxylabs").strip().lower()

    if provider in {"oxylabs", "oxy", "dc.oxylabs"}:
        port = session_id if session_id and session_id.isdigit() else _next_oxylabs_port()
        host_base = config.PROXY_HOST.split(":")[0] if config.PROXY_HOST else "dc.oxylabs.io"
        return StickyProxy(
            session_id=f"p{port}",
            host=f"{host_base}:{port}",
            username=_oxylabs_username(config.PROXY_USERNAME),
            password=config.PROXY_PASSWORD,
            provider="oxylabs",
        )

    # Bright Data (legacy)
    actual = session_id or _random_session_id()
    username = _session_username(config.PROXY_USERNAME, actual)
    host = config.PROXY_HOST or "brd.superproxy.io:33335"
    return StickyProxy(
        session_id=actual,
        host=host,
        username=username,
        password=config.PROXY_PASSWORD,
        provider="brightdata",
    )
