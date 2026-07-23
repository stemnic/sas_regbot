"""Prepare the CapSolver browser extension for Playwright (reCAPTCHA)."""

from __future__ import annotations

import json
import logging
import pathlib
import re
import shutil
import tempfile
from typing import Any

from ..proxy import StickyProxy

logger = logging.getLogger(__name__)

def _resolve_default_extension() -> pathlib.Path:
    """Prefer config override, then repo tools/, then saseb_bot checkout."""
    from .. import config

    candidates = [
        pathlib.Path(config.REGBOT_EXTENSION_DIR),
        pathlib.Path(__file__).resolve().parents[3] / "tools" / "capsolver-extension",
        pathlib.Path.home() / "saseb_bot" / "tools" / "capsolver-extension",
    ]
    for path in candidates:
        if (path / "assets" / "config.js").is_file():
            return path.resolve()
    return candidates[1].resolve()


_DEFAULT_EXT = None  # resolved lazily
CONFIG_REL = pathlib.Path("assets/config.js")


class CapsolverExtensionError(RuntimeError):
    """Extension packaging / config failure."""


def default_extension_path() -> pathlib.Path:
    return _resolve_default_extension()


def extension_launch_args(extension_dir: pathlib.Path) -> list[str]:
    resolved = str(extension_dir.resolve())
    return [
        f"--disable-extensions-except={resolved}",
        f"--load-extension={resolved}",
        "--lang=en-US",
        "--disable-blink-features=AutomationControlled",
    ]


def _js_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    return json.dumps(value, ensure_ascii=True)


def _set_config_value(text: str, key: str, value: Any) -> str:
    replacement = _js_value(value)
    pattern = rf"({re.escape(key)}:\s*)([^,\n]+)"
    updated, count = re.subn(pattern, rf"\g<1>{replacement}", text, count=1)
    if count == 0:
        raise CapsolverExtensionError(f"Could not patch CapSolver config key: {key}")
    return updated


def build_extension_config(
    template: str,
    *,
    api_key: str,
    proxy: StickyProxy | None = None,
    use_proxy: bool = True,
    manual_solving: bool = False,
    recaptcha_mode: str = "token",
) -> str:
    """Patch assets/config.js for automatic reCAPTCHA solving.

    ``recaptcha_mode``: ``token`` (CapSolver API + inject) or ``click`` (in-page images).
    """
    if not api_key.strip():
        raise CapsolverExtensionError("CAPSOLVER_API_KEY is required")

    mode = (recaptcha_mode or "token").strip().lower()
    if mode not in {"token", "click"}:
        mode = "token"

    text = template
    text = _set_config_value(text, "apiKey", api_key.strip())
    text = _set_config_value(text, "useCapsolver", True)
    text = _set_config_value(text, "manualSolving", manual_solving)
    text = _set_config_value(text, "solvedCallback", "captchaSolvedCallback")
    text = _set_config_value(text, "enabledForRecaptcha", True)
    text = _set_config_value(text, "enabledForCloudflare", True)
    for key, value in (
        ("reCaptchaMode", mode),
        ("cloudflareMode", "click"),
        ("reCaptchaDelayTime", 1000),
    ):
        if f"{key}:" in text:
            try:
                text = _set_config_value(text, key, value)
            except CapsolverExtensionError:
                pass

    want_proxy = bool(use_proxy and proxy is not None)
    text = _set_config_value(text, "useProxy", want_proxy)
    if want_proxy and proxy is not None:
        host, port = proxy.host_port()
        text = _set_config_value(text, "proxyType", "http")
        text = _set_config_value(text, "hostOrIp", host)
        text = _set_config_value(text, "port", port)
        text = _set_config_value(text, "proxyLogin", proxy.username)
        text = _set_config_value(text, "proxyPassword", proxy.password)
    return text


def prepare_extension_runtime(
    *,
    api_key: str,
    proxy: StickyProxy | None = None,
    source_dir: pathlib.Path | None = None,
    runtime_dir: pathlib.Path | None = None,
    recaptcha_mode: str | None = None,
) -> pathlib.Path:
    """Copy extension tree and write a session-specific config.js."""
    from .. import config as app_config

    source = (source_dir or default_extension_path()).resolve()
    config_src = source / CONFIG_REL
    if not config_src.is_file():
        raise CapsolverExtensionError(f"CapSolver extension config missing: {config_src}")

    if runtime_dir is None:
        runtime_root = pathlib.Path(tempfile.mkdtemp(prefix="regbot-capsolver-ext-"))
    else:
        runtime_root = runtime_dir.resolve()
        if runtime_root.exists():
            shutil.rmtree(runtime_root)
        runtime_root.mkdir(parents=True, exist_ok=True)

    mode = recaptcha_mode or getattr(app_config, "REGBOT_EXTENSION_RECAPTCHA_MODE", "token")
    shutil.copytree(source, runtime_root, dirs_exist_ok=True)
    patched = build_extension_config(
        config_src.read_text(encoding="utf-8"),
        api_key=api_key,
        proxy=proxy,
        use_proxy=proxy is not None,
        manual_solving=False,
        recaptcha_mode=str(mode),
    )
    (runtime_root / CONFIG_REL).write_text(patched, encoding="utf-8")
    logger.info(
        "CapSolver extension ready at %s (proxy=%s reCaptchaMode=%s apiKey=set len=%s)",
        runtime_root,
        proxy.label if proxy else "none",
        mode,
        len(api_key.strip()),
    )
    return runtime_root
