"""Playwright + CapSolver extension: solve reCAPTCHA on flysas.com via sticky proxy."""

from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..http_bind import get_bound_session

from .. import config
from ..proxy import StickyProxy
from .api import CapsolverError, CaptchaSolution, solve_recaptcha_v2
from .extension import CapsolverExtensionError, extension_launch_args, prepare_extension_runtime

logger = logging.getLogger(__name__)


@dataclass
class BrowserEnrollResult:
    """Captcha + enrollment performed in one Playwright session."""

    solution: CaptchaSolution
    enroll_status: int
    enroll_body: str
    enroll_payload: dict[str, Any] | None
    enroll_via: str  # page_request | page_fetch

_MIN_TOKEN_LEN = 500
_DIRECT_HOST_MARKERS = (
    "google.com",
    "gstatic.com",
    "recaptcha.net",
    "googleapis.com",
)


def _is_oxylabs(proxy: StickyProxy) -> bool:
    return (proxy.provider or "").lower().startswith("oxy")


def _browser_user_agent() -> str:
    return (config.REGBOT_CAPTCHA_USER_AGENT or config.REGBOT_USER_AGENT or "").strip()


def _synthetic_host_html(sitekey: str) -> str:
    """Minimal flysas-origin page that hosts reCAPTCHA v2 for CapSolver extension."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SAS Register</title>
  <script>
    window.__regbotCaptchaSolved = false;
    window.captchaSolvedCallback = function () {{
      window.__regbotCaptchaSolved = true;
    }};
    window.captchaSolvedFailedCallback = function () {{
      window.__regbotCaptchaFailed = true;
    }};
  </script>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <style>
    body {{ font-family: system-ui, sans-serif; padding: 2rem; background: #fff; }}
    #regbot-recaptcha {{ margin-top: 1rem; }}
  </style>
</head>
<body>
  <h1>EuroBonus registration</h1>
  <p>Complete the security check to continue.</p>
  <div id="regbot-recaptcha" class="g-recaptcha"
       data-sitekey="{sitekey}"
       data-callback="captchaSolvedCallback"></div>
</body>
</html>"""


def _install_direct_google_routes(context: object, *, user_agent: str) -> None:
    """Serve Google/reCAPTCHA assets via direct HTTP (bypass DC proxy)."""

    def handler(route: object) -> None:
        req = route.request
        url = req.url
        if not any(m in url for m in _DIRECT_HOST_MARKERS):
            route.continue_()
            return
        try:
            if req.method.upper() not in {"GET", "HEAD"}:
                route.continue_()
                return
            resp = get_bound_session().get(
                url,
                timeout=45,
                headers={"User-Agent": user_agent},
            )
            headers = {"content-type": resp.headers.get("content-type", "application/javascript")}
            route.fulfill(status=resp.status_code, body=resp.content, headers=headers)
            logger.debug("direct-fulfilled %s (%s)", url[:90], resp.status_code)
        except Exception as error:
            logger.warning("direct route fail %s: %s", url[:90], error)
            try:
                route.continue_()
            except Exception:
                route.abort()

    context.route("**/*", handler)


def _install_synthetic_flysas_document_route(page: object, *, sitekey: str) -> None:
    html = _synthetic_host_html(sitekey)

    def handler(route: object) -> None:
        req = route.request
        url = (req.url or "").lower()
        rtype = getattr(req, "resource_type", None) or ""
        if "flysas.com" in url and rtype in {"document", "other", ""}:
            if rtype == "document" or "/register" in url or "/signup" in url or url.rstrip("/").endswith(
                ("flysas.com", "password", "en")
            ):
                logger.info("Synthetic fulfill document %s", req.url[:100])
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
                return
        route.continue_()

    page.route("**/*flysas.com/**", handler)
    page.route("**/www.flysas.com/**", handler)


class BrowserCaptchaError(CapsolverError):
    """Playwright / extension captcha failure (often retryable with new proxy)."""


def _profile_dir(proxy: StickyProxy) -> Path:
    root = Path(config.REGBOT_PLAYWRIGHT_PROFILE_DIR)
    return root / proxy.session_id


def _read_token(page: object) -> str:
    token = page.evaluate(
        """() => {
          const areas = [
            ...document.querySelectorAll('textarea[name="g-recaptcha-response"]'),
            ...document.querySelectorAll('#g-recaptcha-response'),
          ];
          for (const el of areas) {
            const v = (el.value || '').trim();
            if (v.length > 50) return v;
          }
          try {
            if (window.grecaptcha && typeof window.grecaptcha.getResponse === 'function') {
              const r = window.grecaptcha.getResponse();
              if (r && r.length > 50) return r;
            }
          } catch (e) {}
          return '';
        }"""
    )
    return str(token or "").strip()


def _inject_token(page: object, token: str) -> None:
    """Fill g-recaptcha-response from CapSolver HTTP fallback."""
    page.evaluate(
        """(token) => {
          const areas = [
            ...document.querySelectorAll('textarea[name="g-recaptcha-response"]'),
            ...document.querySelectorAll('#g-recaptcha-response'),
          ];
          for (const el of areas) {
            el.value = token;
            el.innerHTML = token;
            el.style.display = 'block';
          }
          try {
            if (window.grecaptcha) {
              window.grecaptcha.getResponse = () => token;
            }
          } catch (e) {}
          if (typeof window.captchaSolvedCallback === 'function') {
            try { window.captchaSolvedCallback(); } catch (e) {}
          }
          window.__regbotCaptchaSolved = true;
        }""",
        token,
    )


def _page_user_agent(page: object) -> str | None:
    try:
        ua = page.evaluate("() => navigator.userAgent")
        return str(ua).strip() if ua else None
    except Exception:
        return None


def _ensure_recaptcha_widget(page: object, sitekey: str) -> None:
    page.evaluate(
        """async (sitekey) => {
          const existing = document.querySelector('.g-recaptcha, iframe[src*="recaptcha"]');
          if (existing) return 'present';

          let box = document.getElementById('regbot-recaptcha');
          if (!box) {
            box = document.createElement('div');
            box.id = 'regbot-recaptcha';
            box.className = 'g-recaptcha';
            box.setAttribute('data-sitekey', sitekey);
            box.setAttribute('data-callback', 'captchaSolvedCallback');
            box.style.cssText = 'position:fixed;z-index:2147483647;top:20px;left:20px;background:#fff;padding:12px;';
            document.body.appendChild(box);
          }

          const loadScript = () => new Promise((resolve, reject) => {
            if (window.grecaptcha && window.grecaptcha.render) return resolve();
            const s = document.createElement('script');
            s.src = 'https://www.google.com/recaptcha/api.js?render=explicit';
            s.async = true;
            s.onload = () => resolve();
            s.onerror = () => reject(new Error('recaptcha script load failed'));
            document.head.appendChild(s);
          });

          await loadScript();
          await new Promise((resolve) => {
            const start = Date.now();
            const tick = () => {
              if (window.grecaptcha && window.grecaptcha.render) return resolve();
              if (Date.now() - start > 15000) return resolve();
              setTimeout(tick, 200);
            };
            if (window.grecaptcha && window.grecaptcha.ready) {
              window.grecaptcha.ready(resolve);
            } else {
              tick();
            }
          });

          try {
            if (box.getAttribute('data-rendered') !== '1' && window.grecaptcha && window.grecaptcha.render) {
              window.grecaptcha.render(box, {
                sitekey,
                theme: 'light',
                size: 'normal',
                callback: function () {
                  if (window.captchaSolvedCallback) window.captchaSolvedCallback();
                },
              });
              box.setAttribute('data-rendered', '1');
            }
          } catch (e) {}
          return 'injected';
        }""",
        sitekey,
    )


def _page_title(page: object) -> str:
    try:
        return (page.title() or "").strip()
    except Exception:
        return ""


def _page_looks_like_cf(page: object) -> bool:
    title = _page_title(page).lower()
    try:
        url = (page.url or "").lower()
    except Exception:
        url = ""
    if "just a moment" in title or "attention required" in title:
        return True
    if "challenges.cloudflare.com" in url:
        return True
    try:
        if page.locator("#challenge-running, #challenge-stage, .cf-browser-verification").count() > 0:
            return True
    except Exception:
        pass
    return False


def _page_hard_blocked(page: object) -> bool:
    title = _page_title(page).lower()
    if "denied boarding" in title or "not allowed to board" in title:
        return True
    try:
        body = (page.inner_text("body") or "").lower()
        if "not allowed to board" in body or "access restricted" in body:
            return True
    except Exception:
        pass
    return False


def _save_debug(page: object, debug_path: Path | None, name: str) -> None:
    if not debug_path:
        return
    try:
        debug_path.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(debug_path / f"{name}.png"), full_page=True)
        (debug_path / f"{name}.html").write_text(
            page.content(), encoding="utf-8", errors="replace"
        )
    except Exception as error:
        logger.warning("debug capture %s failed: %s", name, error)


def _attach_console(page: object) -> None:
    def on_console(msg: object) -> None:
        try:
            text = str(getattr(msg, "text", lambda: msg)() if callable(getattr(msg, "text", None)) else msg.text)
            typ = str(getattr(msg, "type", lambda: "log")() if callable(getattr(msg, "type", None)) else msg.type)
        except Exception:
            return
        low = text.lower()
        if any(k in low for k in ("capsolver", "recaptcha", "error", "fail", "solve")):
            logger.info("browser console [%s]: %s", typ, text[:200])

    def on_page_error(exc: object) -> None:
        logger.warning("browser pageerror: %s", str(exc)[:200])

    try:
        page.on("console", on_console)
        page.on("pageerror", on_page_error)
    except Exception:
        pass


def _click_recaptcha_checkbox(page: object) -> None:
    try:
        anchor = page.frame_locator('iframe[src*="recaptcha"][src*="anchor"]').first
        anchor.locator("#recaptcha-anchor, .recaptcha-checkbox").click(timeout=5000)
        logger.info("Clicked reCAPTCHA checkbox")
    except Exception as error:
        logger.info("Checkbox click skipped: %s", error)


def _wait_for_token(
    page: object,
    *,
    sitekey: str,
    started: float,
    timeout_s: float,
    proxy_label: str,
    browser_ua: str,
    debug_path: Path | None,
    click_if_stuck: bool = False,
) -> CaptchaSolution:
    deadline = started + timeout_s
    last_log = 0.0
    last_shot = started
    did_late_click = False
    while time.time() < deadline:
        token = _read_token(page)
        if len(token) >= _MIN_TOKEN_LEN:
            page_ua = _page_user_agent(page) or browser_ua
            elapsed = time.time() - started
            logger.info(
                "Playwright CapSolver token ok (len=%s elapsed=%.1fs proxy=%s ua=%s)",
                len(token),
                elapsed,
                proxy_label,
                (page_ua or "")[:72],
            )
            return CaptchaSolution(
                token=token,
                user_agent=page_ua,
                create_time=int(time.time() * 1000),
                task_type="playwright",
            )
        now = time.time()
        if now - last_log > 15:
            try:
                n_iframes = page.locator('iframe[src*="recaptcha"]').count()
            except Exception:
                n_iframes = -1
            solved = False
            try:
                solved = bool(page.evaluate("() => !!window.__regbotCaptchaSolved"))
            except Exception:
                pass
            logger.info(
                "Waiting for captcha token… (%.0fs left, iframes=%s solved_flag=%s title=%r)",
                deadline - now,
                n_iframes,
                solved,
                _page_title(page)[:60],
            )
            last_log = now
        if debug_path and now - last_shot >= 30:
            _save_debug(page, debug_path, f"captcha-wait-{int(now - started)}")
            last_shot = now
        # Late optional click if extension token mode stalled with only anchor
        if (
            click_if_stuck
            and not did_late_click
            and now - started > 25
            and config.REGBOT_PLAYWRIGHT_CLICK_CHECKBOX
        ):
            _click_recaptcha_checkbox(page)
            did_late_click = True
        page.wait_for_timeout(1500)
        try:
            has_iframe = page.locator('iframe[src*="recaptcha"]').count() > 0
            if not has_iframe:
                _ensure_recaptcha_widget(page, sitekey)
        except Exception:
            pass

    _save_debug(page, debug_path, "captcha-timeout")
    raise BrowserCaptchaError(
        f"Timed out after {timeout_s:.0f}s waiting for reCAPTCHA token ({proxy_label})"
    )


def _api_inject_fallback(
    page: object,
    *,
    proxy: StickyProxy,
    api_key: str,
    page_url: str,
    sitekey: str,
    browser_ua: str,
) -> CaptchaSolution:
    """CapSolver HTTP solve + inject into page (last resort for a filled token)."""
    logger.warning(
        "Extension timeout — CapSolver HTTP inject fallback via %s",
        proxy.label,
    )
    sol = solve_recaptcha_v2(
        api_key=api_key,
        website_url=page_url,
        website_key=sitekey,
        proxy=proxy,
        mode="proxy",
        poll_timeout_s=min(90, int(config.REGBOT_CAPTCHA_TIMEOUT_S)),
        is_invisible=False,
        user_agent=browser_ua or None,
        proxy_formats=["http_colon"],
    )
    _inject_token(page, sol.token)
    page.wait_for_timeout(500)
    page_ua = _page_user_agent(page) or browser_ua or sol.user_agent
    got = _read_token(page)
    if len(got) < _MIN_TOKEN_LEN:
        # Still return API token for enroll even if page inject flaky
        got = sol.token
    logger.info("API inject fallback token len=%s", len(got))
    return CaptchaSolution(
        token=got,
        user_agent=page_ua,
        create_time=sol.create_time or int(time.time() * 1000),
        task_type="playwright+api_inject",
        recaptcha_ca_e=sol.recaptcha_ca_e,
        recaptcha_ca_t=sol.recaptcha_ca_t,
        sec_ch_ua=sol.sec_ch_ua,
    )


def _open_synthetic_origin(
    page: object,
    *,
    page_url: str,
    sitekey: str,
) -> None:
    logger.info("Opening synthetic reCAPTCHA host at %s", page_url)
    _install_synthetic_flysas_document_route(page, sitekey=sitekey)
    page.goto(page_url, wait_until="domcontentloaded", timeout=90_000)
    page.wait_for_timeout(2000)
    logger.info("synthetic page title=%r url=%s", _page_title(page), page.url)
    try:
        if page.locator('iframe[src*="recaptcha"]').count() == 0:
            _ensure_recaptcha_widget(page, sitekey)
    except Exception as error:
        logger.warning("synthetic widget ensure: %s", error)
        _ensure_recaptcha_widget(page, sitekey)
    page.wait_for_timeout(1500)
    if config.REGBOT_PLAYWRIGHT_CLICK_CHECKBOX:
        _click_recaptcha_checkbox(page)
    else:
        logger.info("Skipping checkbox click (REGBOT_PLAYWRIGHT_CLICK_CHECKBOX=false); CapSolver drives")


def solve_recaptcha_playwright(
    *,
    proxy: StickyProxy,
    api_key: str,
    page_url: str | None = None,
    sitekey: str | None = None,
    timeout_s: float | None = None,
    debug_dir: Path | str | None = None,
    browser_via_proxy: bool | None = None,
) -> CaptchaSolution:
    """Solve flysas reCAPTCHA v2 in Chromium + CapSolver extension.

    Default path: synthetic origin page + extension ``token`` mode (API inject).
    On Denied boarding of real SPA, switches to synthetic. Optional HTTP inject fallback.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise BrowserCaptchaError(
            "Playwright not installed. Run: uv sync --extra browser && uv run playwright install chromium"
        ) from error

    page_url = page_url or config.RECAPTCHA_PAGE_URL
    sitekey = sitekey or config.RECAPTCHA_SITEKEY
    timeout_s = timeout_s if timeout_s is not None else config.REGBOT_PLAYWRIGHT_TIMEOUT_S
    debug_path = Path(debug_dir) if debug_dir else None
    oxy = _is_oxylabs(proxy)
    synthetic_first = bool(config.REGBOT_PLAYWRIGHT_SYNTHETIC_FIRST)
    recaptcha_mode = (config.REGBOT_EXTENSION_RECAPTCHA_MODE or "token").strip().lower()

    if browser_via_proxy is None:
        browser_via_proxy = True if oxy else config.REGBOT_PLAYWRIGHT_BROWSER_PROXY

    browser_ua = _browser_user_agent()
    ext_proxy = proxy if config.REGBOT_EXTENSION_USE_PROXY else None
    ext_dir = prepare_extension_runtime(
        api_key=api_key,
        proxy=ext_proxy,
        recaptcha_mode=recaptcha_mode,
    )
    profile = _profile_dir(proxy)
    if profile.exists():
        shutil.rmtree(profile, ignore_errors=True)
    profile.mkdir(parents=True, exist_ok=True)

    started = time.time()
    context = None
    launch_kwargs: dict = {
        "user_data_dir": str(profile),
        "headless": False,
        "args": extension_launch_args(ext_dir),
        "viewport": {"width": 1280, "height": 900},
        "locale": "en-US",
        "user_agent": browser_ua,
        "ignore_https_errors": True,
    }

    if browser_via_proxy:
        launch_kwargs["proxy"] = proxy.playwright_proxy()
        logger.info(
            "Playwright browser via proxy %s provider=%s ua=%s ext_mode=%s",
            proxy.label,
            proxy.provider,
            browser_ua[:72],
            recaptcha_mode,
        )
    else:
        logger.info("Playwright browser direct; ext_mode=%s", recaptcha_mode)

    try:
        with sync_playwright() as p:
            try:
                context = p.chromium.launch_persistent_context(
                    **{**launch_kwargs, "channel": "chrome"}
                )
                logger.info("Playwright using channel=chrome")
            except Exception as error:
                logger.info("Chrome channel unavailable (%s); using Chromium", error)
                context = p.chromium.launch_persistent_context(**launch_kwargs)

            # Direct Google: default on for oxy/synthetic; always for BD
            use_direct_google = bool(config.REGBOT_PLAYWRIGHT_DIRECT_GOOGLE) or (
                browser_via_proxy and not oxy
            )
            if use_direct_google:
                _install_direct_google_routes(context, user_agent=browser_ua)
                logger.info("Installed direct Google routes")

            page = context.pages[0] if context.pages else context.new_page()
            _attach_console(page)

            page.add_init_script(
                """
                window.__regbotCaptchaSolved = false;
                window.__regbotCaptchaFailed = false;
                window.captchaSolvedCallback = function() {
                  window.__regbotCaptchaSolved = true;
                };
                window.captchaSolvedFailedCallback = function() {
                  window.__regbotCaptchaFailed = true;
                };
                """
            )

            # Give extension service worker a moment
            page.wait_for_timeout(2500)

            def run_wait() -> CaptchaSolution:
                return _wait_for_token(
                    page,
                    sitekey=sitekey,
                    started=started,
                    timeout_s=timeout_s,
                    proxy_label=proxy.label,
                    browser_ua=browser_ua,
                    debug_path=debug_path,
                    click_if_stuck=(recaptcha_mode == "click"),
                )

            if synthetic_first:
                _open_synthetic_origin(page, page_url=page_url, sitekey=sitekey)
                try:
                    return run_wait()
                except BrowserCaptchaError:
                    if config.REGBOT_PLAYWRIGHT_API_INJECT_FALLBACK:
                        return _api_inject_fallback(
                            page,
                            proxy=proxy,
                            api_key=api_key,
                            page_url=page_url,
                            sitekey=sitekey,
                            browser_ua=browser_ua,
                        )
                    raise

            # Real page first
            loaded = False
            hard_blocked = False
            for url in (page_url, config.REGBOT_ORIGIN + "/en/", config.REGBOT_ORIGIN + "/"):
                logger.info(
                    "Playwright captcha: goto %s (browser_proxy=%s, oxy=%s)",
                    url,
                    browser_via_proxy,
                    oxy,
                )
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=90_000)
                    loaded = True
                except Exception as error:
                    logger.warning("goto %s: %s", url, error)
                    continue
                page.wait_for_timeout(2000)
                logger.info("page title=%r url=%s", _page_title(page), page.url)

                if _page_looks_like_cf(page):
                    logger.info("Cloudflare interstitial — waiting for extension")
                    deadline_cf = time.time() + min(45.0, timeout_s)
                    while time.time() < deadline_cf and _page_looks_like_cf(page):
                        page.wait_for_timeout(1500)

                if _page_hard_blocked(page):
                    hard_blocked = True
                    logger.warning(
                        "SAS Denied boarding on %s — switching to synthetic origin page",
                        proxy.label,
                    )
                    _save_debug(page, debug_path, "denied-boarding")
                    break
                break

            if hard_blocked or not loaded:
                if not loaded:
                    logger.warning("Could not load real flysas HTML — synthetic origin")
                _open_synthetic_origin(page, page_url=page_url, sitekey=sitekey)
            else:
                try:
                    _ensure_recaptcha_widget(page, sitekey)
                except Exception as error:
                    logger.warning("reCAPTCHA ensure failed: %s", error)
                    page.wait_for_timeout(1000)
                    _ensure_recaptcha_widget(page, sitekey)
                page.wait_for_timeout(2000)
                if config.REGBOT_PLAYWRIGHT_CLICK_CHECKBOX:
                    _click_recaptcha_checkbox(page)
                page.wait_for_timeout(3000)
                try:
                    n = page.locator('iframe[src*="recaptcha"]').count()
                except Exception:
                    n = 0
                if n == 0 or _page_hard_blocked(page):
                    logger.warning("No reCAPTCHA on real page — synthetic origin")
                    _save_debug(page, debug_path, "no-recaptcha-widget")
                    _open_synthetic_origin(page, page_url=page_url, sitekey=sitekey)

            try:
                return run_wait()
            except BrowserCaptchaError:
                if config.REGBOT_PLAYWRIGHT_API_INJECT_FALLBACK:
                    return _api_inject_fallback(
                        page,
                        proxy=proxy,
                        api_key=api_key,
                        page_url=page_url,
                        sitekey=sitekey,
                        browser_ua=browser_ua,
                    )
                raise
    except CapsolverExtensionError as error:
        raise BrowserCaptchaError(str(error)) from error
    except BrowserCaptchaError:
        raise
    except Exception as error:
        raise BrowserCaptchaError(f"Playwright captcha failed: {error}") from error
    finally:
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            shutil.rmtree(ext_dir, ignore_errors=True)
        except Exception:
            pass


def _enroll_from_page(
    page: object,
    *,
    enroll_url: str,
    body: dict[str, Any],
    page_url: str,
) -> tuple[int, str, dict[str, Any] | None, str]:
    """POST enrollment using Chromium network stack (same session as captcha).

    Prefers Playwright APIRequestContext (shared cookies/proxy); falls back to
    page ``fetch`` if needed.
    """
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/plain, */*",
        "origin": config.REGBOT_ORIGIN,
        "referer": page_url,
    }
    # 1) page.request — browser TLS + storage, avoids many CORS pitfalls
    try:
        resp = page.request.post(
            enroll_url,
            data=json.dumps(body),
            headers=headers,
            timeout=60_000,
        )
        status = int(resp.status)
        text = resp.text()
        payload = None
        try:
            payload = resp.json()
        except Exception:
            if text and text[:1] == "{":
                try:
                    payload = json.loads(text)
                except Exception:
                    payload = None
        logger.info(
            "Browser enroll via page.request status=%s body_len=%s",
            status,
            len(text or ""),
        )
        return status, text or "", payload if isinstance(payload, dict) else None, "page_request"
    except Exception as error:
        logger.warning("page.request enroll failed (%s); trying page.fetch", error)

    # 2) in-page fetch (true document context)
    result = page.evaluate(
        """async ({ url, body, headers }) => {
          try {
            const r = await fetch(url, {
              method: 'POST',
              credentials: 'include',
              headers,
              body: JSON.stringify(body),
            });
            const text = await r.text();
            return { status: r.status, body: text, ok: r.ok };
          } catch (e) {
            return { status: 0, body: String(e && e.message ? e.message : e), ok: false };
          }
        }""",
        {"url": enroll_url, "body": body, "headers": headers},
    )
    status = int((result or {}).get("status") or 0)
    text = str((result or {}).get("body") or "")
    payload = None
    try:
        payload = json.loads(text) if text[:1] == "{" else None
    except Exception:
        payload = None
    logger.info("Browser enroll via page.fetch status=%s body_len=%s", status, len(text))
    return status, text, payload if isinstance(payload, dict) else None, "page_fetch"


def playwright_solve_and_enroll(
    *,
    proxy: StickyProxy,
    api_key: str,
    enrollment_body: dict[str, Any],
    enroll_url: str | None = None,
    page_url: str | None = None,
    sitekey: str | None = None,
    timeout_s: float | None = None,
    debug_dir: Path | str | None = None,
    browser_via_proxy: bool | None = None,
) -> BrowserEnrollResult:
    """Solve reCAPTCHA in Playwright then POST enrollment from the same browser.

    Layer C: captcha + enroll share Chromium/proxy/cookies (manual success path).
    ``enrollment_body`` must match SAS enroll JSON except ``captcha`` (filled here).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise BrowserCaptchaError(
            "Playwright not installed. Run: uv sync --extra browser && uv run playwright install chromium"
        ) from error

    page_url = page_url or config.RECAPTCHA_PAGE_URL
    sitekey = sitekey or config.RECAPTCHA_SITEKEY
    timeout_s = timeout_s if timeout_s is not None else config.REGBOT_PLAYWRIGHT_TIMEOUT_S
    debug_path = Path(debug_dir) if debug_dir else None
    enroll_url = enroll_url or f"{config.API2_BASE.rstrip('/')}/v2/enrollment"
    oxy = _is_oxylabs(proxy)
    synthetic_first = bool(config.REGBOT_PLAYWRIGHT_SYNTHETIC_FIRST)
    recaptcha_mode = (config.REGBOT_EXTENSION_RECAPTCHA_MODE or "token").strip().lower()

    if browser_via_proxy is None:
        browser_via_proxy = True if oxy else config.REGBOT_PLAYWRIGHT_BROWSER_PROXY

    browser_ua = _browser_user_agent()
    ext_proxy = proxy if config.REGBOT_EXTENSION_USE_PROXY else None
    ext_dir = prepare_extension_runtime(
        api_key=api_key,
        proxy=ext_proxy,
        recaptcha_mode=recaptcha_mode,
    )
    profile = _profile_dir(proxy)
    if profile.exists():
        shutil.rmtree(profile, ignore_errors=True)
    profile.mkdir(parents=True, exist_ok=True)

    started = time.time()
    context = None
    launch_kwargs: dict = {
        "user_data_dir": str(profile),
        "headless": False,
        "args": extension_launch_args(ext_dir),
        "viewport": {"width": 1280, "height": 900},
        "locale": "en-US",
        "user_agent": browser_ua,
        "ignore_https_errors": True,
    }
    if browser_via_proxy:
        launch_kwargs["proxy"] = proxy.playwright_proxy()
        logger.info(
            "Playwright solve+enroll via proxy %s ext_mode=%s",
            proxy.label,
            recaptcha_mode,
        )

    try:
        with sync_playwright() as p:
            try:
                context = p.chromium.launch_persistent_context(
                    **{**launch_kwargs, "channel": "chrome"}
                )
            except Exception:
                context = p.chromium.launch_persistent_context(**launch_kwargs)

            use_direct_google = bool(config.REGBOT_PLAYWRIGHT_DIRECT_GOOGLE) or (
                browser_via_proxy and not oxy
            )
            if use_direct_google:
                _install_direct_google_routes(context, user_agent=browser_ua)

            page = context.pages[0] if context.pages else context.new_page()
            _attach_console(page)
            page.add_init_script(
                """
                window.__regbotCaptchaSolved = false;
                window.captchaSolvedCallback = function() {
                  window.__regbotCaptchaSolved = true;
                };
                """
            )
            page.wait_for_timeout(2500)

            def obtain_token() -> CaptchaSolution:
                if synthetic_first:
                    _open_synthetic_origin(page, page_url=page_url, sitekey=sitekey)
                else:
                    loaded = False
                    hard_blocked = False
                    for url in (page_url, config.REGBOT_ORIGIN + "/en/"):
                        try:
                            page.goto(url, wait_until="domcontentloaded", timeout=90_000)
                            loaded = True
                        except Exception as error:
                            logger.warning("goto %s: %s", url, error)
                            continue
                        page.wait_for_timeout(2000)
                        if _page_hard_blocked(page):
                            hard_blocked = True
                            _save_debug(page, debug_path, "denied-boarding")
                            break
                        break
                    if hard_blocked or not loaded:
                        _open_synthetic_origin(page, page_url=page_url, sitekey=sitekey)
                    else:
                        _ensure_recaptcha_widget(page, sitekey)
                        if config.REGBOT_PLAYWRIGHT_CLICK_CHECKBOX:
                            _click_recaptcha_checkbox(page)
                try:
                    return _wait_for_token(
                        page,
                        sitekey=sitekey,
                        started=started,
                        timeout_s=timeout_s,
                        proxy_label=proxy.label,
                        browser_ua=browser_ua,
                        debug_path=debug_path,
                        click_if_stuck=(recaptcha_mode == "click"),
                    )
                except BrowserCaptchaError:
                    if config.REGBOT_PLAYWRIGHT_API_INJECT_FALLBACK:
                        return _api_inject_fallback(
                            page,
                            proxy=proxy,
                            api_key=api_key,
                            page_url=page_url,
                            sitekey=sitekey,
                            browser_ua=browser_ua,
                        )
                    raise

            solution = obtain_token()
            body = dict(enrollment_body)
            body["captcha"] = solution.token

            status, text, payload, via = _enroll_from_page(
                page,
                enroll_url=enroll_url,
                body=body,
                page_url=page_url,
            )
            if debug_path:
                debug_path.mkdir(parents=True, exist_ok=True)
                (debug_path / "enrollment_browser.json").write_text(
                    json.dumps(
                        {
                            "status": status,
                            "via": via,
                            "body": text[:8000],
                            "payload": payload,
                            "captcha_len": len(solution.token),
                            "task_type": solution.task_type,
                            "enroll_url": enroll_url,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            logger.info(
                "Layer C enroll done via=%s status=%s captcha_len=%s task=%s",
                via,
                status,
                len(solution.token),
                solution.task_type,
            )
            return BrowserEnrollResult(
                solution=solution,
                enroll_status=status,
                enroll_body=text,
                enroll_payload=payload,
                enroll_via=via,
            )
    except CapsolverExtensionError as error:
        raise BrowserCaptchaError(str(error)) from error
    except BrowserCaptchaError:
        raise
    except Exception as error:
        raise BrowserCaptchaError(f"Playwright solve+enroll failed: {error}") from error
    finally:
        try:
            if context is not None:
                context.close()
        except Exception:
            pass
        try:
            shutil.rmtree(ext_dir, ignore_errors=True)
        except Exception:
            pass
