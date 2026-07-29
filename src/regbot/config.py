"""Configuration loaded from environment, project ``.env``, and optional ~/.bashrc."""

from __future__ import annotations

import os
import re
from pathlib import Path

_ENV_PREFIXES = (
    "PROXY_",
    "OXYLABS_",
    "CAPSOLVER_",
    "EMAIL_",
    "REGBOT_",
    "OPENINBOX_",
    "ANYMESSAGE_",
    "MAILHOOK_",
    "FORWARDEMAIL_",
    "REG_ALERT_",
)


def _parse_env_assignment(line: str) -> tuple[str, str] | None:
    """Parse KEY=VALUE or export KEY=VALUE (optional quotes)."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("export "):
        raw = raw[7:].strip()
    if "=" not in raw:
        return None
    key, _, value = raw.partition("=")
    key = key.strip()
    if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return key, value


def _load_dotenv_file(path: Path) -> None:
    """Load KEY=VALUE from a .env file into os.environ (does not override existing)."""
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        parsed = _parse_env_assignment(line)
        if not parsed:
            continue
        key, value = parsed
        os.environ.setdefault(key, value)


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


def _bootstrap_env() -> None:
    """Load project .env then bashrc exports (existing process env wins)."""
    # Prefer package/repo root, then cwd (for `uv run` from project dir)
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / ".env",  # src/regbot/config.py → repo root
        Path.cwd() / ".env",
    ]
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        _load_dotenv_file(resolved)
    _load_shell_exports_from_bashrc(_ENV_PREFIXES)


_bootstrap_env()

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

# Email provider (OTP path is direct — not proxied).
# openinbox | mailhook | anymessage | rotate | manual | fake | http
# rotate = weighted pick (default openinbox:5,mailhook:1 → Mailhook ~1/6)
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "rotate").strip().lower()
EMAIL_API_KEY = os.environ.get("EMAIL_API_KEY", "")
EMAIL_API_BASE = os.environ.get("EMAIL_API_BASE", "").rstrip("/")
EMAIL_DOMAIN = os.environ.get("EMAIL_DOMAIN", "")
# Weighted rotation, e.g. openinbox:5,mailhook:1  (empty → default when rotate)
EMAIL_PROVIDER_WEIGHTS = os.environ.get(
    "EMAIL_PROVIDER_WEIGHTS", "openinbox:5,mailhook:1"
).strip()

# OpenInbox (https://openinbox.io/api-docs) — preferred automatic OTP source
OPENINBOX_API_KEY = os.environ.get("OPENINBOX_API_KEY", "") or EMAIL_API_KEY
OPENINBOX_BASE_URL = os.environ.get(
    "OPENINBOX_BASE_URL", "https://api.openinbox.io/api"
).rstrip("/")
OPENINBOX_DOMAIN = os.environ.get("OPENINBOX_DOMAIN", EMAIL_DOMAIN)
# Domains SAS rejects — discard + recreate if OpenInbox assigns one.
# Default when env unset; set OPENINBOX_BANNED_DOMAINS= to disable.
_DEFAULT_OPENINBOX_BANNED = "teminbox.click,myfamilysync.app"
OPENINBOX_BANNED_DOMAINS_RAW = os.environ.get(
    "OPENINBOX_BANNED_DOMAINS", _DEFAULT_OPENINBOX_BANNED
)
# On concurrent-inbox limit: delete only the oldest inbox once, then retry create.
# Keep other inboxes for late/misdelivered mail after account creation.
REGBOT_OPENINBOX_PRUNE_OLDEST = os.environ.get(
    "REGBOT_OPENINBOX_PRUNE_OLDEST", "true"
).lower() in {"1", "true", "yes"}


def openinbox_banned_domains(raw: str | None = None) -> frozenset[str]:
    """Parse comma-separated OpenInbox ban list (lowercased hostnames)."""
    text = OPENINBOX_BANNED_DOMAINS_RAW if raw is None else raw
    if text is None:
        return frozenset()
    return frozenset(
        part.strip().lower().lstrip("@")
        for part in str(text).split(",")
        if part.strip()
    )

# AnyMessage (https://anymessage.shop/en/docs) — optional fallback
ANYMESSAGE_TOKEN = os.environ.get("ANYMESSAGE_TOKEN", "") or EMAIL_API_KEY
ANYMESSAGE_SITE = os.environ.get("ANYMESSAGE_SITE", "flysas.com")
ANYMESSAGE_DOMAIN = os.environ.get("ANYMESSAGE_DOMAIN", EMAIL_DOMAIN)
ANYMESSAGE_BASE_URL = os.environ.get(
    "ANYMESSAGE_BASE_URL", "https://api.anymessage.shop"
).rstrip("/")
ANYMESSAGE_ORDER_REGEX = os.environ.get("ANYMESSAGE_ORDER_REGEX", "")
ANYMESSAGE_ORDER_SUBJECT = os.environ.get("ANYMESSAGE_ORDER_SUBJECT", "")

# Mailhook (https://app.mailhook.co/llms.txt) — temp mail, ~1/6 via rotate
MAILHOOK_AGENT_ID = os.environ.get("MAILHOOK_AGENT_ID", "").strip()
MAILHOOK_API_KEY = os.environ.get("MAILHOOK_API_KEY", "").strip()
MAILHOOK_BASE_URL = os.environ.get(
    "MAILHOOK_BASE_URL", "https://app.mailhook.co/api/v1"
).rstrip("/")
MAILHOOK_DOMAIN_ID = os.environ.get("MAILHOOK_DOMAIN_ID", "").strip()
MAILHOOK_TAILME_SLUG = os.environ.get("MAILHOOK_TAILME_SLUG", "").strip()
MAILHOOK_CREDENTIALS_PATH = os.environ.get(
    "MAILHOOK_CREDENTIALS_PATH", "data/mailhook_credentials.json"
)
MAILHOOK_AUTO_REGISTER = os.environ.get("MAILHOOK_AUTO_REGISTER", "true").lower() in {
    "1",
    "true",
    "yes",
}
# On free-tier 1-address limit: delete oldest address once, then retry create
REGBOT_MAILHOOK_PRUNE_OLDEST = os.environ.get(
    "REGBOT_MAILHOOK_PRUNE_OLDEST", "true"
).lower() in {"1", "true", "yes"}


def parse_email_provider_weights(
    raw: str | None = None,
) -> list[tuple[str, float]]:
    """Parse ``openinbox:5,mailhook:1`` into ``[(name, weight), ...]``.

    Empty / invalid entries are skipped. If nothing parses, returns the default
    openinbox:5 + mailhook:1 rotation (Mailhook ~1/6).
    """
    text = (raw if raw is not None else EMAIL_PROVIDER_WEIGHTS or "").strip()
    out: list[tuple[str, float]] = []
    if text:
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                name, _, w = part.partition(":")
                name = name.strip().lower()
                try:
                    weight = float(w.strip())
                except ValueError:
                    continue
            else:
                name = part.lower()
                weight = 1.0
            if name and weight > 0:
                out.append((name, weight))
    if not out:
        out = [("openinbox", 5.0), ("mailhook", 1.0)]
    return out

# Registration behaviour
# Prefer a modern Firefox profile that still works with curl_cffi on this host
REGBOT_IMPERSONATE = os.environ.get("REGBOT_IMPERSONATE", "firefox147")
REGBOT_USER_AGENT = os.environ.get(
    "REGBOT_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
)
# Max new-proxy attempts per account (captcha/proxy fail). Keep low for automation.
REGBOT_PROXY_RETRIES = int(os.environ.get("REGBOT_PROXY_RETRIES", "3"))
REGBOT_OTP_TIMEOUT_S = float(os.environ.get("REGBOT_OTP_TIMEOUT_S", "180"))
REGBOT_OTP_POLL_S = float(os.environ.get("REGBOT_OTP_POLL_S", "3"))
REGBOT_CAPTCHA_TIMEOUT_S = int(os.environ.get("REGBOT_CAPTCHA_TIMEOUT_S", "120"))
# CapSolver HTTP tokens rejected by SAS for this sitekey; oxylabs default = in-browser solve.
# proxy | proxyless | manual | playwright | auto
_default_captcha_mode = "playwright" if PROXY_PROVIDER.startswith("oxy") else "proxy"
REGBOT_CAPTCHA_MODE = os.environ.get(
    "REGBOT_CAPTCHA_MODE", _default_captcha_mode
).strip().lower()
# Inner captcha loops per proxy lease (playwright: 1 → total attempts ≈ PROXY_RETRIES)
REGBOT_CAPTCHA_RETRIES = int(os.environ.get("REGBOT_CAPTCHA_RETRIES", "1"))

# Mullvad: require Connected + bind host outbound sockets to WG interface (default on)
REGBOT_REQUIRE_MULLVAD = os.environ.get("REGBOT_REQUIRE_MULLVAD", "true").lower() in {
    "1",
    "true",
    "yes",
}
# Empty = auto-detect (wg0-mullvad preferred)
REGBOT_BIND_INTERFACE = os.environ.get("REGBOT_BIND_INTERFACE", "wg0-mullvad").strip()
REGBOT_MULLVAD_BIN = os.environ.get("REGBOT_MULLVAD_BIN", "mullvad").strip() or "mullvad"
# Optional am.i.mullvad exit probe (slow/flaky); default off — Connected CLI + iface is enough
REGBOT_MULLVAD_PROBE_EXIT = os.environ.get("REGBOT_MULLVAD_PROBE_EXIT", "false").lower() in {
    "1",
    "true",
    "yes",
}
REGBOT_MULLVAD_PROBE_TIMEOUT_S = float(os.environ.get("REGBOT_MULLVAD_PROBE_TIMEOUT_S", "3"))
# Force curl_cffi interface= on Oxylabs CONNECT (usually unnecessary; can hang)
REGBOT_CURL_BIND_INTERFACE = os.environ.get("REGBOT_CURL_BIND_INTERFACE", "false").lower() in {
    "1",
    "true",
    "yes",
}
# Fail-fast proxy egress check (ipify via sticky) before warm/OTP
REGBOT_PROXY_IP_TIMEOUT_S = float(os.environ.get("REGBOT_PROXY_IP_TIMEOUT_S", "15"))

# Daily automation — space attempts across the day via cron (one account per run by default)
REGBOT_DAILY_TARGET = int(os.environ.get("REGBOT_DAILY_TARGET", "5"))
# Max accounts to attempt in a single `regbot daily` invocation (not a burst of 5)
REGBOT_DAILY_BATCH = int(os.environ.get("REGBOT_DAILY_BATCH", "1"))
# Only used if batch > 1 (prefer cron spacing over in-process delay)
REGBOT_ACCOUNT_DELAY_S = float(os.environ.get("REGBOT_ACCOUNT_DELAY_S", "900"))
REGBOT_CIRCUIT_CONSEC_FAIL = int(os.environ.get("REGBOT_CIRCUIT_CONSEC_FAIL", "3"))
REGBOT_DAILY_STATE_PATH = os.environ.get("REGBOT_DAILY_STATE_PATH", "data/daily_state.json")
REGBOT_FORCE_CONTINUE = os.environ.get("REGBOT_FORCE_CONTINUE", "false").lower() in {
    "1",
    "true",
    "yes",
}

# Forward Email alerts (circuit open / awaiting review)
# https://forwardemail.net/en/email-api — POST /v1/emails
FORWARDEMAIL_API_KEY = os.environ.get("FORWARDEMAIL_API_KEY", "") or os.environ.get(
    "REG_ALERT_API_KEY", ""
)
FORWARDEMAIL_API_BASE = os.environ.get(
    "FORWARDEMAIL_API_BASE", "https://api.forwardemail.net"
).rstrip("/")
REG_ALERT_FROM = os.environ.get("REG_ALERT_FROM", "reg-infra@polarawards.com")
REG_ALERT_TO = os.environ.get("REG_ALERT_TO", "reg-alerts@polarawards.com")
REG_ALERT_ENABLED = os.environ.get("REG_ALERT_ENABLED", "true").lower() in {
    "1",
    "true",
    "yes",
}
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
