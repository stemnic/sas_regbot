"""Mullvad preflight and host bind resolution.

Ensures registration runs only when Mullvad is Connected, and exposes the
WireGuard bind IP for host-originated HTTPS (CapSolver, OpenInbox, alerts,
direct Google).

SAS product egress remains Oxylabs. Local sockets to Oxylabs follow the OS
default route (already Mullvad when Connected + kill switch); we do not force
curl_cffi ``interface=`` on CONNECT by default (that caused flaky timeouts).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from . import config

logger = logging.getLogger(__name__)

_PREFERRED_IFACES = ("wg0-mullvad",)
_IFACE_NAME_RE = re.compile(r"^(wg0-mullvad|mullvad[\w-]*)$", re.I)


class MullvadNotConnectedError(RuntimeError):
    """Raised when Mullvad is required but not Connected / interface missing."""


@dataclass(frozen=True)
class MullvadBind:
    """Resolved Mullvad bind state after preflight."""

    connected: bool
    interface: str | None
    bind_ip: str | None
    status_raw: str = ""
    exit_ip: str | None = None
    skipped: bool = False
    probe_ok: bool | None = None

    def as_log(self) -> str:
        if self.skipped:
            return "mullvad=skipped (REGBOT_REQUIRE_MULLVAD=false)"
        bits = [
            f"mullvad={'Connected' if self.connected else 'not-connected'}",
            f"iface={self.interface or '?'}",
            f"bind={self.bind_ip or '?'}",
        ]
        if self.exit_ip:
            bits.append(f"exit={self.exit_ip}")
        if self.probe_ok is not None:
            bits.append(f"probe_ok={self.probe_ok}")
        return " ".join(bits)


# Process-wide state set by require_mullvad / preflight
_state: MullvadBind | None = None


def get_bind_state() -> MullvadBind | None:
    return _state


def get_bind_ip() -> str | None:
    st = _state
    if st is None or st.skipped:
        return None
    return st.bind_ip


def get_curl_interface() -> str | None:
    """Optional curl_cffi ``interface=`` value (only when REGBOT_CURL_BIND_INTERFACE)."""
    if not getattr(config, "REGBOT_CURL_BIND_INTERFACE", False):
        return None
    st = _state
    if st is None or st.skipped:
        return None
    # Prefer bind IP over iface name (more reliable with policy routing)
    return st.bind_ip or st.interface


def clear_mullvad_cache() -> None:
    """Reset process-wide preflight cache (tests / reconnect)."""
    global _state
    _state = None


def _run_mullvad_status(bin_path: str) -> str:
    try:
        proc = subprocess.run(
            [bin_path, "status"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError as error:
        raise MullvadNotConnectedError(
            f"Mullvad CLI not found ({bin_path!r}). Install mullvad or set REGBOT_MULLVAD_BIN."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise MullvadNotConnectedError("mullvad status timed out") from error
    out = (proc.stdout or "") + (proc.stderr or "")
    return out.strip()


def parse_mullvad_connected(status_text: str) -> bool:
    """True if ``mullvad status`` output indicates Connected."""
    text = (status_text or "").strip()
    if not text:
        return False
    # First line is usually "Connected" or "Disconnected"
    first = text.splitlines()[0].strip().lower()
    if first.startswith("connected"):
        return True
    if first.startswith("disconnected") or first.startswith("disconnecting"):
        return False
    # Fallback: any strong Connected token
    if re.search(r"(?m)^Connected\b", text):
        return True
    if re.search(r"(?mi)\bDisconnected\b", text) and not re.search(
        r"(?m)^Connected\b", text
    ):
        return False
    return "connected" in first and "disconnected" not in first


def _list_ipv4_ifaces() -> list[tuple[str, str]]:
    """Return (iface, ipv4) pairs from ``ip -4 -o addr show``."""
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    pairs: list[tuple[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        # 12: wg0-mullvad    inet 10.143.193.0/32 ...
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        iface = parts[1].rstrip(":")
        addr = parts[3].split("/")[0]
        if addr and iface:
            pairs.append((iface, addr))
    return pairs


def resolve_interface_and_ip(
    preferred: str | None = None,
) -> tuple[str, str]:
    """Pick Mullvad interface and its primary IPv4.

    Order: REGBOT_BIND_INTERFACE / preferred if UP with IPv4, then wg0-mullvad,
    then any mullvad-* iface.
    """
    pairs = _list_ipv4_ifaces()
    by_name = {name: ip for name, ip in pairs}

    candidates: list[str] = []
    if preferred and preferred.strip():
        candidates.append(preferred.strip())
    for name in _PREFERRED_IFACES:
        if name not in candidates:
            candidates.append(name)
    for name, _ip in pairs:
        if _IFACE_NAME_RE.match(name) and name not in candidates:
            candidates.append(name)

    for name in candidates:
        if name in by_name:
            return name, by_name[name]

    raise MullvadNotConnectedError(
        "No Mullvad WireGuard interface with IPv4 found "
        f"(looked for {candidates or list(_PREFERRED_IFACES)}; "
        f"present={list(by_name)}). Is Mullvad Connected?"
    )


def _optional_exit_probe() -> tuple[str | None, bool | None]:
    """Best-effort exit IP via default route (no interface=). Short timeout."""
    try:
        from curl_cffi import requests as cffi_requests

        timeout = float(getattr(config, "REGBOT_MULLVAD_PROBE_TIMEOUT_S", 3.0) or 3.0)
        resp = cffi_requests.get(
            "https://am.i.mullvad.net/json",
            timeout=max(1.0, timeout),
        )
        data: Any = resp.json() if resp.status_code == 200 else {}
        ip = str(data.get("ip") or "") or None
        is_mullvad = bool(data.get("mullvad_exit_ip"))
        return ip, is_mullvad if ip else None
    except Exception as error:
        logger.debug("Mullvad exit probe skipped/failed (non-fatal): %s", error)
        return None, None


def require_mullvad(
    *,
    force: bool | None = None,
    probe_exit: bool | None = None,
    use_cache: bool = True,
) -> MullvadBind:
    """Require Mullvad Connected + resolve bind, configure HTTP bind, store state.

    When ``REGBOT_REQUIRE_MULLVAD`` is false (or force=False), skip checks and
    clear bind so host uses OS default routing.

    Cached for the process after the first successful Connected preflight so
    ``daily`` + ``register_once`` do not double-probe / double-stall.
    """
    global _state

    require = config.REGBOT_REQUIRE_MULLVAD if force is None else bool(force)
    if not require:
        bind = MullvadBind(
            connected=False,
            interface=None,
            bind_ip=None,
            skipped=True,
        )
        _state = bind
        from . import http_bind

        http_bind.configure_bind(None)
        logger.warning("Mullvad preflight skipped (REGBOT_REQUIRE_MULLVAD=false)")
        return bind

    # Reuse prior Connected bind (skip slow exit probe / iface re-resolve)
    if (
        use_cache
        and _state is not None
        and _state.connected
        and not _state.skipped
        and _state.bind_ip
    ):
        logger.debug("Mullvad preflight cache hit: %s", _state.as_log())
        return _state

    do_probe = (
        bool(getattr(config, "REGBOT_MULLVAD_PROBE_EXIT", False))
        if probe_exit is None
        else bool(probe_exit)
    )

    bin_path = (config.REGBOT_MULLVAD_BIN or "mullvad").strip() or "mullvad"
    if not shutil.which(bin_path) and bin_path == "mullvad":
        for candidate in ("/usr/bin/mullvad", "/usr/local/bin/mullvad"):
            if shutil.which(candidate) or __import__("pathlib").Path(candidate).is_file():
                bin_path = candidate
                break

    status_raw = _run_mullvad_status(bin_path)
    connected = parse_mullvad_connected(status_raw)
    if not connected:
        _state = None
        raise MullvadNotConnectedError(
            "Mullvad is not Connected. Connect with `mullvad connect` before running regbot.\n"
            f"status:\n{status_raw or '(empty)'}"
        )

    preferred = (config.REGBOT_BIND_INTERFACE or "").strip() or None
    interface, bind_ip = resolve_interface_and_ip(preferred)

    exit_ip: str | None = None
    probe_ok: bool | None = None
    if do_probe:
        exit_ip, probe_ok = _optional_exit_probe()

    bind = MullvadBind(
        connected=True,
        interface=interface,
        bind_ip=bind_ip,
        status_raw=status_raw,
        exit_ip=exit_ip,
        skipped=False,
        probe_ok=probe_ok,
    )
    _state = bind

    from . import http_bind

    http_bind.configure_bind(bind_ip)

    logger.info("Mullvad preflight ok: %s", bind.as_log())
    if probe_ok is False:
        logger.warning(
            "Exit probe did not report mullvad_exit_ip=true (exit=%s) — "
            "continuing (OS default route + kill switch still apply)",
            exit_ip,
        )
    return bind


def check_mullvad(*, probe_exit: bool | None = True) -> MullvadBind:
    """Ops helper: fresh preflight (no cache); optional exit probe for check-mullvad."""
    clear_mullvad_cache()
    return require_mullvad(probe_exit=probe_exit, use_cache=False)
