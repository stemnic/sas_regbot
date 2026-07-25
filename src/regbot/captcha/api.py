"""CapSolver HTTP API — reCAPTCHA v2 (docs-aligned).

Docs:
  https://docs.capsolver.com/en/guide/captcha/ReCaptchaV2/
  https://docs.capsolver.com/en/guide/captcha/ReCaptchaV3/

Flysas register uses v2 checkbox (HAR: api2/anchor size=normal), not v3.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Literal

import requests

from .. import config
from ..http_bind import get_bound_session
from ..proxy import StickyProxy

logger = logging.getLogger(__name__)

CAPSOLVER_CREATE_TASK_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_GET_RESULT_URL = "https://api.capsolver.com/getTaskResult"

CaptchaMode = Literal["proxy", "proxyless"]
ProxyFormat = Literal["http_colon", "fields", "legacy"]


class CapsolverError(RuntimeError):
    """Raised when CapSolver cannot return a reCAPTCHA token."""


@dataclass(frozen=True)
class CaptchaSolution:
    """Full CapSolver solution — token alone is not enough for some sites."""

    token: str
    user_agent: str | None = None
    sec_ch_ua: str | None = None
    recaptcha_ca_e: str | None = None
    recaptcha_ca_t: str | None = None
    create_time: int | None = None
    task_type: str = "ReCaptchaV2Task"

    def cookie_header(self) -> str | None:
        parts: list[str] = []
        if self.recaptcha_ca_e:
            parts.append(f"recaptcha-ca-e={self.recaptcha_ca_e}")
        if self.recaptcha_ca_t:
            parts.append(f"recaptcha-ca-t={self.recaptcha_ca_t}")
        return "; ".join(parts) if parts else None


def _parse_solution(data: dict[str, Any], *, task_type: str) -> CaptchaSolution:
    solution = data.get("solution") or {}
    token = solution.get("gRecaptchaResponse") or solution.get("token")
    if not token:
        raise CapsolverError(f"CapSolver ready without token: {data}")
    create_time = solution.get("createTime")
    try:
        create_time_i = int(create_time) if create_time is not None else None
    except (TypeError, ValueError):
        create_time_i = None
    return CaptchaSolution(
        token=str(token),
        user_agent=(str(solution["userAgent"]) if solution.get("userAgent") else None),
        sec_ch_ua=(str(solution["secChUa"]) if solution.get("secChUa") else None),
        recaptcha_ca_e=(
            str(solution["recaptcha-ca-e"]) if solution.get("recaptcha-ca-e") else None
        ),
        recaptcha_ca_t=(
            str(solution["recaptcha-ca-t"]) if solution.get("recaptcha-ca-t") else None
        ),
        create_time=create_time_i,
        task_type=task_type,
    )


def _poll_solution(
    *,
    api_key: str,
    task_id: str,
    poll_timeout_s: int,
    task_type: str,
    log_via: str,
) -> CaptchaSolution:
    deadline = time.time() + poll_timeout_s
    while time.time() < deadline:
        time.sleep(1)  # docs: results typically 1–10s
        try:
            result_response = get_bound_session().post(
                CAPSOLVER_GET_RESULT_URL,
                json={"clientKey": api_key.strip(), "taskId": task_id},
                timeout=30,
            )
            result_response.raise_for_status()
            result_data = result_response.json()
        except requests.RequestException as error:
            raise CapsolverError(f"CapSolver getTaskResult failed: {error}") from error

        if result_data.get("errorId"):
            raise CapsolverError(f"CapSolver task error: {result_data.get('errorDescription')}")

        status = result_data.get("status")
        if status == "ready":
            sol = _parse_solution(result_data, task_type=task_type)
            logger.info(
                "CapSolver ready type=%s len=%s ua=%s ca_e=%s via=%s",
                task_type,
                len(sol.token),
                bool(sol.user_agent),
                bool(sol.recaptcha_ca_e),
                log_via,
            )
            return sol
        if status == "failed":
            raise CapsolverError(f"CapSolver task failed: {result_data}")

    raise CapsolverError(f"CapSolver reCAPTCHA timed out after {poll_timeout_s}s")


def _build_v2_task(
    *,
    website_url: str,
    website_key: str,
    mode: CaptchaMode,
    proxy: StickyProxy | None,
    proxy_format: ProxyFormat,
    is_invisible: bool,
    is_session: bool,
    user_agent: str | None,
) -> dict[str, Any]:
    # Docs: v2 checkbox → isInvisible false; full page URL preferred
    if mode == "proxyless":
        task_type = "ReCaptchaV2TaskProxyLess"
    else:
        task_type = "ReCaptchaV2Task"

    task: dict[str, Any] = {
        "type": task_type,
        "websiteURL": website_url,
        "websiteKey": website_key,
        "isInvisible": bool(is_invisible),
    }
    if is_session:
        task["isSession"] = True
    if user_agent:
        task["userAgent"] = user_agent

    if mode == "proxy":
        if proxy is None:
            raise CapsolverError("ReCaptchaV2Task requires proxy")
        if proxy_format == "fields":
            host, port = proxy.host_port()
            task.update(
                {
                    "proxyType": "http",
                    "proxyAddress": host,
                    "proxyPort": int(port),
                    "proxyLogin": proxy.username,
                    "proxyPassword": proxy.password,
                }
            )
        elif proxy_format == "legacy":
            task["proxy"] = proxy.capsolver_proxy_string(style="legacy")
        else:
            # Docs example: "http:ip:port:user:pass"
            task["proxy"] = proxy.capsolver_proxy_string(style="http_colon")
    return task


def solve_recaptcha_manual(*, website_url: str, website_key: str) -> CaptchaSolution:
    print(
        "\n=== reCAPTCHA v2 (manual) ===\n"
        f"1. Open: {website_url}\n"
        f"2. Sitekey: {website_key}\n"
        "3. Solve checkbox and paste g-recaptcha-response\n",
        flush=True,
    )
    while True:
        token = input("Paste reCAPTCHA token: ").strip()
        if len(token) >= 100:
            return CaptchaSolution(token=token, task_type="manual")
        print(f"Token too short ({len(token)}). Try again.", flush=True)


def solve_recaptcha_v2(
    *,
    api_key: str,
    website_url: str,
    website_key: str,
    proxy: StickyProxy | None = None,
    mode: CaptchaMode | str = "proxy",
    poll_timeout_s: int = 120,
    is_invisible: bool = False,
    is_session: bool | None = None,
    proxy_formats: list[ProxyFormat] | None = None,
    user_agent: str | None = None,
) -> CaptchaSolution:
    """Solve reCAPTCHA v2 per CapSolver docs; returns full solution (token + UA/cookies)."""
    if not website_key.strip():
        raise CapsolverError("reCAPTCHA sitekey is required")

    if mode in {"manual", "stdin"}:
        return solve_recaptcha_manual(website_url=website_url, website_key=website_key)

    if not api_key.strip():
        raise CapsolverError("CAPSOLVER_API_KEY is required")

    if is_session is None:
        is_session = config.REGBOT_CAPTCHA_IS_SESSION

    mode_n: CaptchaMode = "proxyless" if mode == "proxyless" else "proxy"
    formats: list[ProxyFormat] = (
        ["http_colon"]
        if mode_n == "proxyless"
        else (proxy_formats or ["http_colon", "fields", "legacy"])
    )

    last_error: Exception | None = None
    for fmt in formats:
        task = _build_v2_task(
            website_url=website_url,
            website_key=website_key,
            mode=mode_n,
            proxy=proxy,
            proxy_format=fmt,
            is_invisible=is_invisible,
            is_session=bool(is_session),
            user_agent=user_agent,
        )
        try:
            return _create_and_poll(
                api_key=api_key,
                task=task,
                poll_timeout_s=poll_timeout_s,
                log_via=f"{proxy.label if proxy else 'direct'}/{fmt}",
            )
        except CapsolverError as error:
            last_error = error
            if mode_n == "proxyless":
                raise
            logger.warning("CapSolver format %s failed: %s", fmt, error)
            continue
    raise CapsolverError(f"All CapSolver proxy formats failed: {last_error}") from last_error


def _proxy_log_bits(task: dict[str, Any]) -> str:
    """Redacted proxy identity for logs (no password)."""
    if task.get("proxyAddress") and task.get("proxyPort") is not None:
        return f"{task.get('proxyAddress')}:{task.get('proxyPort')}"
    raw = task.get("proxy")
    if isinstance(raw, str) and raw:
        # http:host:port:user:pass or host:port:user:pass — drop credentials after port
        parts = raw.split(":")
        if len(parts) >= 3 and parts[0] in {"http", "https", "socks5", "socks4"}:
            return f"{parts[0]}:{parts[1]}:{parts[2]}"
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
        return raw[:40]
    return "none"


def _create_and_poll(
    *,
    api_key: str,
    task: dict[str, Any],
    poll_timeout_s: int,
    log_via: str,
) -> CaptchaSolution:
    create_payload = {"clientKey": api_key.strip(), "task": task}
    try:
        create_response = get_bound_session().post(
            CAPSOLVER_CREATE_TASK_URL, json=create_payload, timeout=30
        )
        create_response.raise_for_status()
        create_data = create_response.json()
    except requests.RequestException as error:
        raise CapsolverError(f"CapSolver createTask failed: {error}") from error

    if create_data.get("errorId"):
        raise CapsolverError(f"CapSolver createTask error: {create_data.get('errorDescription')}")

    task_id = create_data.get("taskId")
    if not task_id:
        raise CapsolverError(f"CapSolver createTask returned no taskId: {create_data}")

    forced_ua = task.get("userAgent") or ""
    logger.info(
        "CapSolver createTask id=%s type=%s isInvisible=%s isSession=%s proxy=%s "
        "forced_ua=%s via=%s",
        task_id,
        task.get("type"),
        task.get("isInvisible"),
        task.get("isSession"),
        _proxy_log_bits(task),
        (forced_ua[:72] + "…") if len(forced_ua) > 72 else (forced_ua or "none"),
        log_via,
    )
    return _poll_solution(
        api_key=api_key,
        task_id=str(task_id),
        poll_timeout_s=poll_timeout_s,
        task_type=str(task.get("type") or ""),
        log_via=log_via,
    )


def solve_recaptcha_v2_with_proxy(
    *,
    api_key: str,
    website_url: str,
    website_key: str,
    proxy: StickyProxy,
    poll_timeout_s: int = 120,
    is_invisible: bool = False,
) -> CaptchaSolution:
    return solve_recaptcha_v2(
        api_key=api_key,
        website_url=website_url,
        website_key=website_key,
        proxy=proxy,
        mode="proxy",
        poll_timeout_s=poll_timeout_s,
        is_invisible=is_invisible,
    )
