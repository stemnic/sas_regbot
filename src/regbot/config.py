"""Configuration loaded from environment and optional ~/.bashrc exports."""

from __future__ import annotations

import os
import re
from pathlib import Path

_BASHRC_PREFIXES = ("PROXY_", "OXYLABS_", "CAPSOLVER_", "EMAIL_", "REGBOT_")


def _load_shell_exports_from_bashrc(prefixes: tuple[str, ...]) -> None:
    """Load export lines from ~/.bashrc when the shell is non-interactive."""
    bashrc = Path.home() / ".bashrc"
    if not bashrc.is_file():
        return
    keys = "|".join(re.escape(prefix) for prefix in prefixes)
    pattern = re.compile(
        rf"^\s*export\s+(({keys})[A-Z0-9_]*)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))\s*$"
    )
    for line in bashrc.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = pattern.match(line)
        if not match:
            continue
        key = match.group(1)
        value = match.group(3) or match.group(4) or match.group(5) or ""
        os.environ.setdefault(key, value)


_load_shell_exports_from_bashrc(_BASHRC_PREFIXES)

# Proxy: oxylabs (default) or brightdata
PROXY_PROVIDER = os.environ.get("PROXY_PROVIDER", "oxylabs").strip().lower()
PROXY_USERNAME = os.environ.get("PROXY_USERNAME", "") or os.environ.get("OXYLABS_USERNAME", "")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "") or os.environ.get("OXYLABS_PASSWORD", "")
# Oxylabs: host only (dc.oxylabs.io). Bright Data: host:port (brd.superproxy.io:33335)
PROXY_HOST = os.environ.get("PROXY_HOST", "") or os.environ.get(
    "OXYLABS_HOST",
    "dc.oxylabs.io" if PROXY_PROVIDER.startswith("oxy") else "brd.superproxy.io:33335",
)
# Prefer US datacenter pool (username suffix country-US). Empty = no country filter.
# https://developers.oxylabs.io/products/proxies/datacenter-proxies/select-country
OXYLABS_COUNTRY = os.environ.get("OXYLABS_COUNTRY", "US").strip().upper()
# Pay-per-traffic DC: sticky session = random port in [MIN, MAX] (Oxylabs docs: 8001–63000).
OXYLABS_PORT_MIN = int(os.environ.get("OXYLABS_PORT_MIN", "8001"))
OXYLABS_PORT_MAX = int(os.environ.get("OXYLABS_PORT_MAX", "63000"))
# Optional pin for debug (forces a single sticky port for every attempt).
OXYLABS_PORT = os.environ.get("OXYLABS_PORT", "").strip()
# Legacy fixed port list (only if OXYLABS_USE_PORT_LIST=true)
OXYLABS_PORTS = os.environ.get("OXYLABS_PORTS", "8001,8002,8003,8004,8005")
OXYLABS_USE_PORT_LIST = os.environ.get("OXYLABS_USE_PORT_LIST", "false").lower() in {
    "1",
    "true",
    "yes",
}
# ppt (default, pay-per-traffic random port) | random | roundrobin (legacy list modes)
REGBOT_PROXY_ROTATE = os.environ.get("REGBOT_PROXY_ROTATE", "ppt").strip().lower()
# Persist last_port (avoid immediate reuse) / legacy list cursor
REGBOT_PROXY_STATE_PATH = os.environ.get(
    "REGBOT_PROXY_STATE_PATH", "data/oxy_port_state.json"
)


def oxylabs_port_range() -> tuple[int, int]:
    lo, hi = OXYLABS_PORT_MIN, OXYLABS_PORT_MAX
    if lo < 1:
        lo = 8001
    if hi < lo:
        hi = lo
    return lo, hi


def oxylabs_ports() -> list[str]:
    """Legacy explicit port list (only used when OXYLABS_USE_PORT_LIST is set)."""
    if OXYLABS_PORT:
        return [OXYLABS_PORT]
    ports = [p.strip() for p in OXYLABS_PORTS.split(",") if p.strip()]
    return ports or ["8001"]

# CapSolver
CAPSOLVER_API_KEY = os.environ.get("CAPSOLVER_API_KEY", "")

# Email provider (OTP path is direct — not proxied). Default: OpenInbox.
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "openinbox").strip().lower()
EMAIL_API_KEY = os.environ.get("EMAIL_API_KEY", "")
EMAIL_API_BASE = os.environ.get("EMAIL_API_BASE", "").rstrip("/")
EMAIL_DOMAIN = os.environ.get("EMAIL_DOMAIN", "")

# OpenInbox (https://openinbox.io/api-docs) — preferred automatic OTP source
OPENINBOX_API_KEY = os.environ.get("OPENINBOX_API_KEY", "") or EMAIL_API_KEY
OPENINBOX_BASE_URL = os.environ.get(
    "OPENINBOX_BASE_URL", "https://api.openinbox.io/api"
).rstrip("/")
OPENINBOX_DOMAIN = os.environ.get("OPENINBOX_DOMAIN", EMAIL_DOMAIN)

# AnyMessage (https://anymessage.shop/en/docs) — optional fallback
ANYMESSAGE_TOKEN = os.environ.get("ANYMESSAGE_TOKEN", "") or EMAIL_API_KEY
ANYMESSAGE_SITE = os.environ.get("ANYMESSAGE_SITE", "flysas.com")
ANYMESSAGE_DOMAIN = os.environ.get("ANYMESSAGE_DOMAIN", EMAIL_DOMAIN)
ANYMESSAGE_BASE_URL = os.environ.get(
    "ANYMESSAGE_BASE_URL", "https://api.anymessage.shop"
).rstrip("/")
ANYMESSAGE_ORDER_REGEX = os.environ.get("ANYMESSAGE_ORDER_REGEX", "")
ANYMESSAGE_ORDER_SUBJECT = os.environ.get("ANYMESSAGE_ORDER_SUBJECT", "")

# Registration behaviour
# Prefer a modern Firefox profile that still works with curl_cffi on this host
REGBOT_IMPERSONATE = os.environ.get("REGBOT_IMPERSONATE", "firefox147")
REGBOT_USER_AGENT = os.environ.get(
    "REGBOT_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
)
REGBOT_PROXY_RETRIES = int(os.environ.get("REGBOT_PROXY_RETRIES", "8"))
REGBOT_OTP_TIMEOUT_S = float(os.environ.get("REGBOT_OTP_TIMEOUT_S", "180"))
REGBOT_OTP_POLL_S = float(os.environ.get("REGBOT_OTP_POLL_S", "3"))
REGBOT_CAPTCHA_TIMEOUT_S = int(os.environ.get("REGBOT_CAPTCHA_TIMEOUT_S", "120"))
# CapSolver HTTP tokens rejected by SAS for this sitekey; oxylabs default = in-browser solve.
# proxy | proxyless | manual | playwright | auto
_default_captcha_mode = "playwright" if PROXY_PROVIDER.startswith("oxy") else "proxy"
REGBOT_CAPTCHA_MODE = os.environ.get(
    "REGBOT_CAPTCHA_MODE", _default_captcha_mode
).strip().lower()
REGBOT_CAPTCHA_RETRIES = int(os.environ.get("REGBOT_CAPTCHA_RETRIES", "3"))
# CapSolver v2: set true to request recaptcha-ca-* session cookies in solution
REGBOT_CAPTCHA_IS_SESSION = os.environ.get("REGBOT_CAPTCHA_IS_SESSION", "false").lower() in {
    "1",
    "true",
    "yes",
}
# Force CapSolver task.userAgent to a curl_cffi-known Chrome (avoid Chrome/149 vs chrome146 TLS skew).
# Must match a profile in fingerprint._CHROME_CANDIDATES (chrome146 preferred).
REGBOT_CAPTCHA_USER_AGENT = os.environ.get(
    "REGBOT_CAPTCHA_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36",
).strip()
REGBOT_PLAYWRIGHT_TIMEOUT_S = float(os.environ.get("REGBOT_PLAYWRIGHT_TIMEOUT_S", "120"))
# False: load flysas HTML direct (avoids BD "Denied boarding"); CapSolver ext still uses BD
REGBOT_PLAYWRIGHT_BROWSER_PROXY = os.environ.get(
    "REGBOT_PLAYWRIGHT_BROWSER_PROXY", "true"
).lower() in {"1", "true", "yes"}
# Skip real SPA; serve synthetic reCAPTCHA host at flysas URL (WAF bypass for automation)
REGBOT_PLAYWRIGHT_SYNTHETIC_FIRST = os.environ.get(
    "REGBOT_PLAYWRIGHT_SYNTHETIC_FIRST", "true"
).lower() in {"1", "true", "yes"}
# Fetch Google/reCAPTCHA assets without proxy (oxy DC often flaky for gstatic)
REGBOT_PLAYWRIGHT_DIRECT_GOOGLE = os.environ.get(
    "REGBOT_PLAYWRIGHT_DIRECT_GOOGLE", "true"
).lower() in {"1", "true", "yes"}
# Do not click the reCAPTCHA checkbox ourselves (lets CapSolver drive; default off)
REGBOT_PLAYWRIGHT_CLICK_CHECKBOX = os.environ.get(
    "REGBOT_PLAYWRIGHT_CLICK_CHECKBOX", "false"
).lower() in {"1", "true", "yes"}
# If extension times out, CapSolver HTTP API + inject token into page
REGBOT_PLAYWRIGHT_API_INJECT_FALLBACK = os.environ.get(
    "REGBOT_PLAYWRIGHT_API_INJECT_FALLBACK", "true"
).lower() in {"1", "true", "yes"}
# CapSolver extension's own useProxy (usually false — CapSolver reaches Google better)
REGBOT_EXTENSION_USE_PROXY = os.environ.get(
    "REGBOT_EXTENSION_USE_PROXY", "false"
).lower() in {"1", "true", "yes"}
# Extension reCaptchaMode: token (API+inject, reliable) | click (image grid in page)
REGBOT_EXTENSION_RECAPTCHA_MODE = os.environ.get(
    "REGBOT_EXTENSION_RECAPTCHA_MODE", "token"
).strip().lower()
# Enroll transport for playwright mode: page (Layer C browser) | curl | auto (page then curl)
REGBOT_ENROLL_VIA = os.environ.get("REGBOT_ENROLL_VIA", "page").strip().lower()
REGBOT_PLAYWRIGHT_PROFILE_DIR = os.environ.get(
    "REGBOT_PLAYWRIGHT_PROFILE_DIR", "data/playwright_captcha"
)
REGBOT_EXTENSION_DIR = os.environ.get("REGBOT_EXTENSION_DIR", "tools/capsolver-extension")
# Refresh enrollment JWT before every captcha+enroll. Default false: use validateOtp
# JWT on attempt 1; refresh only on retry after failed enroll (SAS may burn JWT on 1015001).
REGBOT_REFRESH_TOKEN_EACH_ENROLL = os.environ.get(
    "REGBOT_REFRESH_TOKEN_EACH_ENROLL", "false"
).lower() in {"1", "true", "yes"}
REGBOT_REQUEST_TIMEOUT_S = float(os.environ.get("REGBOT_REQUEST_TIMEOUT_S", "45"))
REGBOT_ACCOUNTS_DIR = os.environ.get("REGBOT_ACCOUNTS_DIR", "data/accounts")
REGBOT_RUNS_DIR = os.environ.get("REGBOT_RUNS_DIR", "data/runs")
# HTML warm hits Cloudflare challenge-platform; disabled by default. API warm uses agreement.
REGBOT_SKIP_HTML_WARM = os.environ.get("REGBOT_SKIP_HTML_WARM", "true").lower() in {
    "1",
    "true",
    "yes",
}
REGBOT_WARM_URL = os.environ.get("REGBOT_WARM_URL", "https://www.flysas.com/en/register/")
REGBOT_API_WARM = os.environ.get("REGBOT_API_WARM", "true").lower() in {"1", "true", "yes"}
REGBOT_ORIGIN = os.environ.get("REGBOT_ORIGIN", "https://www.flysas.com")

# Fixed SAS enrollment constants (from HAR)
RECAPTCHA_SITEKEY = os.environ.get(
    "REGBOT_RECAPTCHA_SITEKEY",
    "6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6",
)
RECAPTCHA_PAGE_URL = os.environ.get(
    "REGBOT_RECAPTCHA_PAGE_URL",
    "https://www.flysas.com/en/register/password/",
)
API2_BASE = os.environ.get("REGBOT_API2_BASE", "https://api2.flysas.com/customer")


def require_proxy_credentials() -> None:
    if not PROXY_USERNAME or not PROXY_PASSWORD:
        raise RuntimeError(
            "PROXY_USERNAME and PROXY_PASSWORD are required "
            f"(provider={PROXY_PROVIDER}). Refusing direct SAS egress."
        )


def require_capsolver() -> None:
    if not CAPSOLVER_API_KEY.strip():
        raise RuntimeError("CAPSOLVER_API_KEY is required for reCAPTCHA v2 enrollment")
