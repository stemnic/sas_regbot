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
    """Clear persisted rotation state (tests)."""
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


def _oxylabs_username(raw: str) -> str:
    """Oxylabs DC expects user-USERNAME (idempotent if already prefixed)."""
    name = raw.strip()
    if not name:
        return name
    if name.startswith("user-"):
        return name
    return f"user-{name}"


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
    """Pick next Oxylabs DC port — sticky within one attempt, rotated across CLI runs.

    State is persisted to disk so each ``uv run regbot`` continues the cycle instead
    of always landing on the same port (in-memory rotation is useless for --count 1).

    - ``roundrobin`` (default): walk a shuffled pool, cursor saved on disk.
    - ``random``: pick uniformly among ports other than last-used.
    """
    ports = config.oxylabs_ports()
    if not ports:
        return "8001"
    if len(ports) == 1:
        return ports[0]

    mode = (getattr(config, "REGBOT_PROXY_ROTATE", "roundrobin") or "roundrobin").strip().lower()
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
                "Oxylabs port pick=%s last=%s mode=random pool=%s",
                port,
                last or "-",
                pool,
            )
            return port

        # roundrobin with persisted shuffled order
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
            "Oxylabs port pick=%s last=%s mode=roundrobin cursor=%s→%s order=%s",
            port,
            last or "-",
            cursor,
            next_cursor,
            order,
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
        proxy = StickyProxy(
            session_id=f"p{port}",
            host=f"{host_base}:{port}",
            username=_oxylabs_username(config.PROXY_USERNAME),
            password=config.PROXY_PASSWORD,
            provider="oxylabs",
        )
        logger.info(
            "Oxylabs sticky lease %s (rotate=%s pool=%s)",
            proxy.label,
            getattr(config, "REGBOT_PROXY_ROTATE", "roundrobin"),
            config.oxylabs_ports(),
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
