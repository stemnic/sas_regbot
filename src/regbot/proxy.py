"""Sticky proxy leases for SAS registration (Oxylabs DC or Bright Data)."""

from __future__ import annotations

import json
import logging
import os
import random
import re
import string
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from . import config

logger = logging.getLogger(__name__)

_SESSION_PATTERN = re.compile(r"-session-[A-Za-z0-9]+")
_oxy_lock = threading.Lock()


def reset_oxylabs_port_cycle() -> None:
    """Clear persisted port state (tests)."""
    path = _state_path()
    with _oxy_lock:
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            pass


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


def _oxylabs_username(raw: str, *, country: str | None = None) -> str:
    """Build Oxylabs DC username: ``user-USERNAME`` + optional ``-country-XX``.

    Country selection:
    https://developers.oxylabs.io/products/proxies/datacenter-proxies/select-country
    e.g. ``user-scraper2-country-US`` for United States.
    """
    name = raw.strip()
    if not name:
        return name
    # Strip existing user- / country- so we can re-apply cleanly
    if name.startswith("user-"):
        name = name[5:]
    # Drop any prior country-* segments at the end (or mid)
    name = re.sub(r"-country-[A-Za-z]{2}\b", "", name, flags=re.I)
    name = name.strip("-")
    user = f"user-{name}" if name else "user-"

    cc = (country if country is not None else getattr(config, "OXYLABS_COUNTRY", "") or "").strip()
    if not cc:
        return user
    # Accept "US" or "country-US"
    if cc.lower().startswith("country-"):
        cc = cc.split("-", 1)[-1]
    cc = cc.upper()
    if len(cc) != 2 or not cc.isalpha():
        logger.warning("Ignoring invalid OXYLABS_COUNTRY=%r (need 2-letter code)", country)
        return user
    return f"{user}-country-{cc}"


def _state_path() -> Path:
    raw = getattr(config, "REGBOT_PROXY_STATE_PATH", "data/oxy_port_state.json")
    return Path(raw or "data/oxy_port_state.json")


def _load_state() -> dict:
    path = _state_path()
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError) as error:
        logger.debug("proxy state load failed: %s", error)
    return {}


def _save_state(state: dict) -> None:
    path = _state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as error:
        logger.warning("proxy state save failed: %s", error)


def _next_oxylabs_port() -> str:
    """Pick Oxylabs DC sticky session port for this registration attempt.

    **Pay-per-traffic (default):** random port in ``[OXYLABS_PORT_MIN, OXYLABS_PORT_MAX]``
    (docs: 8001–63000). Same port for the whole attempt ⇒ sticky IP; new port ⇒ new IP.

    **Pin:** ``OXYLABS_PORT`` forces one port.

    **Legacy list:** ``OXYLABS_USE_PORT_LIST=true`` + ``OXYLABS_PORTS`` +
    ``REGBOT_PROXY_ROTATE=roundrobin|random``.
    """
    pin = (getattr(config, "OXYLABS_PORT", None) or "").strip()
    if pin:
        return pin

    use_list = bool(getattr(config, "OXYLABS_USE_PORT_LIST", False))
    mode = (getattr(config, "REGBOT_PROXY_ROTATE", "ppt") or "ppt").strip().lower()

    # Default / ppt: pay-per-traffic random sticky port
    if not use_list and mode not in {"roundrobin", "list"}:
        lo, hi = config.oxylabs_port_range()
        with _oxy_lock:
            state = _load_state()
            last = str(state.get("last_port") or "")
            port = random.randint(lo, hi)
            # Avoid immediate reuse of last session port when range is wide
            if hi > lo and last.isdigit():
                for _ in range(8):
                    if str(port) != last:
                        break
                    port = random.randint(lo, hi)
            state = {
                "last_port": str(port),
                "mode": "ppt",
                "min": lo,
                "max": hi,
            }
            _save_state(state)
        logger.info(
            "Oxylabs pay-per-traffic session port=%s (range %s–%s, last=%s)",
            port,
            lo,
            hi,
            last or "-",
        )
        return str(port)

    # Legacy fixed port list
    ports = config.oxylabs_ports()
    if not ports:
        return "8001"
    if len(ports) == 1:
        return ports[0]

    pool = [str(p) for p in ports]
    with _oxy_lock:
        state = _load_state()
        last = str(state.get("last_port") or "")

        if mode in {"random", "shuffle", "rand", "rnd"}:
            candidates = [p for p in pool if p != last] or list(pool)
            port = random.choice(candidates)
            state = {"last_port": port, "mode": "random", "pool": pool}
            _save_state(state)
            logger.info(
                "Oxylabs list port pick=%s last=%s mode=random pool=%s",
                port,
                last or "-",
                pool,
            )
            return port

        order = state.get("order")
        if not isinstance(order, list) or sorted(str(x) for x in order) != sorted(pool):
            order = list(pool)
            random.shuffle(order)
            cursor = 0
        else:
            order = [str(x) for x in order]
            try:
                cursor = int(state.get("cursor") or 0)
            except (TypeError, ValueError):
                cursor = 0
            if cursor < 0:
                cursor = 0

        port = order[cursor % len(order)]
        next_cursor = (cursor + 1) % len(order)
        state = {
            "last_port": port,
            "cursor": next_cursor,
            "order": order,
            "mode": "roundrobin",
            "pool": pool,
        }
        _save_state(state)
        logger.info(
            "Oxylabs list port pick=%s last=%s mode=roundrobin cursor=%s→%s",
            port,
            last or "-",
            cursor,
            next_cursor,
        )
        return port


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
        country = getattr(config, "OXYLABS_COUNTRY", "US") or ""
        username = _oxylabs_username(config.PROXY_USERNAME, country=country or None)
        proxy = StickyProxy(
            session_id=f"p{port}",
            host=f"{host_base}:{port}",
            username=username,
            password=config.PROXY_PASSWORD,
            provider="oxylabs",
        )
        lo, hi = config.oxylabs_port_range()
        logger.info(
            "Oxylabs sticky lease %s (user=%s host=%s country=%s ppt_range=%s-%s)",
            proxy.label,
            proxy.username,
            proxy.host,
            country or "any",
            lo,
            hi,
        )
        return proxy

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
