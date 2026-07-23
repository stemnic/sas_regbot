"""SAS EuroBonus registration orchestrator (curl_cffi + CapSolver + email OTP)."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import config
from .captcha import CaptchaSolution, CapsolverError, solve_captcha
from .captcha.browser import BrowserCaptchaError, BrowserEnrollResult, playwright_solve_and_enroll
from .email.base import EmailProvider, EmailProviderError, Inbox
from .fingerprint import impersonate_for_user_agent
from .profile import UsProfile, generate_us_profile, validate_email
from .proxy import StickyProxy, new_sticky_proxy
from .store import RegisteredAccount, save_account
from .transport import BlockedError, ProxiedSession, SasHttpError, TransportError

logger = logging.getLogger(__name__)

def _default_ua() -> str:
    return config.REGBOT_USER_AGENT


class RegistrationError(RuntimeError):
    """Unrecoverable or final registration failure."""

    def __init__(self, message: str, *, stage: str | None = None) -> None:
        super().__init__(message)
        self.stage = stage


@dataclass
class EnrollmentResume:
    """Continue enrollment after email is already verified (OTP done)."""

    email: str
    enrollment_token: str
    profile: UsProfile


class EnrollmentRetryError(RegistrationError):
    """Enroll/captcha failed after OTP — retry with new proxy, keep enrollment token."""

    def __init__(self, message: str, *, resume: EnrollmentResume) -> None:
        super().__init__(message, stage="enroll")
        self.resume = resume


@dataclass
class AttemptReport:
    proxy_session_id: str = ""
    proxy_label: str = ""
    proxy_ip: str | None = None
    stage: str = "init"
    email: str | None = None
    result: str = "unknown"
    error: str | None = None
    stages: list[dict[str, Any]] = field(default_factory=list)
    run_dir: str | None = None

    def mark(self, stage: str, **extra: Any) -> None:
        self.stage = stage
        entry = {"stage": stage, "ts": time.time(), **extra}
        self.stages.append(entry)
        logger.info("stage=%s %s", stage, {k: v for k, v in extra.items() if k != "body"})

    def to_dict(self) -> dict[str, Any]:
        return {
            "proxy_session_id": self.proxy_session_id,
            "proxy_label": self.proxy_label,
            "proxy_ip": self.proxy_ip,
            "stage": self.stage,
            "email": self.email,
            "result": self.result,
            "error": self.error,
            "stages": self.stages,
            "run_dir": self.run_dir,
        }


class SasRegisterClient:
    """Thin wrapper around api2.flysas.com enrollment endpoints."""

    def __init__(self, session: ProxiedSession, *, ua: str | None = None) -> None:
        self.session = session
        self.ua = ua or _default_ua()
        self.origin = config.REGBOT_ORIGIN
        self.base = config.API2_BASE.rstrip("/")

    def warm_html(self) -> str:
        """Optional www HTML hit. Cloudflare challenge is expected; never fatal."""
        url = (config.REGBOT_WARM_URL or "").strip()
        if not url or config.REGBOT_SKIP_HTML_WARM:
            return "skipped"
        try:
            self.session.request("GET", url, expect_json=False, headers={"Accept": "text/html"})
            return "ok"
        except BlockedError as error:
            logger.warning("HTML warm CF/block (ignored, api2 does not need it): %s", error)
            return "soft_fail_blocked"
        except Exception as error:
            logger.warning("HTML warm failed (ignored): %s", error)
            return "soft_fail_error"

    def warm_api(self) -> str:
        """Open TLS/session against api2 via agreement (validated live; no CF HTML)."""
        if not config.REGBOT_API_WARM:
            return "skipped"
        try:
            self.agreement("EB")
            return "ok"
        except BlockedError:
            raise
        except Exception as error:
            logger.warning("API warm (agreement) failed (continuing): %s", error)
            return "soft_fail_error"

    def request_otp(self, email: str, *, user_ip: str = "") -> dict[str, Any]:
        body = {
            "email": email,
            "origin": self.origin,
            "ua": self.ua,
            "userIpAddress": user_ip or "",
        }
        return self.session.post(f"{self.base}/emailVerify/requestOtp", json_body=body)

    @staticmethod
    def classify_otp_response(payload: dict[str, Any]) -> tuple[str, str | None]:
        """Classify requestOtp JSON.

        Returns:
          (\"sent\", None) — mail sent, need user OTP
          (\"verified\", enrollment_token) — email already verified, continue enroll
          (\"error\", message) — hard business failure
        """
        if not isinstance(payload, dict):
            return "error", "non-object response"
        send = str(payload.get("emailSendStatus") or "").lower()
        reg = str(payload.get("registrationStatus") or "").upper()
        status = str(payload.get("status") or "").lower()
        token = payload.get("enrollmentToken")

        if token and (reg == "VERIFIED" or status == "verified" or payload.get("emailStatus") == "verified"):
            return "verified", str(token)
        if send == "success" or reg in {"EMAIL_SENT", "SUCCESS"}:
            return "sent", None

        err = payload.get("error") or payload.get("message") or payload.get("status") or reg
        if not err:
            return "error", f"unexpected requestOtp response: {payload}"
        parts = [str(err)]
        if payload.get("retryEarliestAtUtc") is not None:
            parts.append(f"retryEarliestAtUtc={payload.get('retryEarliestAtUtc')}")
        if payload.get("secondsLeft") is not None:
            parts.append(f"secondsLeft={payload.get('secondsLeft')}")
        if reg:
            parts.append(f"registrationStatus={reg}")
        return "error", "; ".join(parts)

    @staticmethod
    def otp_request_error(payload: dict[str, Any]) -> str | None:
        """Legacy helper: error message or None if sent/verified."""
        kind, detail = SasRegisterClient.classify_otp_response(payload)
        if kind == "error":
            return detail
        return None

    def validate_otp(self, email: str, otp_code: str | int, *, user_ip: str = "") -> dict[str, Any]:
        body = {
            "email": email,
            "otpCode": int(otp_code),
            "origin": self.origin,
            "ua": self.ua,
            "userIpAddress": user_ip or "",
        }
        return self.session.post(f"{self.base}/emailVerify/validateOtp", json_body=body)

    def agreement(self, profile_type: str = "EB") -> dict[str, Any]:
        return self.session.get(f"{self.base}/agreement?profileType={profile_type}")

    @staticmethod
    def enrollment_body(
        *,
        email: str,
        profile: UsProfile,
        enrollment_token: str,
        captcha: str = "",
        terms_version: int,
    ) -> dict[str, Any]:
        """JSON body for POST /v2/enrollment (captcha may be filled later)."""
        return {
            "userName": email,
            "password": profile.password,
            "enrollmentToken": enrollment_token,
            "captcha": captcha,
            "firstName": profile.first_name,
            "lastName": profile.last_name,
            "directMarketingConsent": False,
            "termsConsent": True,
            "profilingConsent": False,
            "gender": profile.gender,
            "dateOfBirth": profile.date_of_birth,
            "termsVersion": terms_version,
            "channel": "WEB",
            "address": profile.enrollment_address(email),
            "enrollmentType": "FULL",
        }

    def enroll(
        self,
        *,
        email: str,
        profile: UsProfile,
        enrollment_token: str,
        captcha: str,
        terms_version: int,
        user_agent: str | None = None,
        cookie_header: str | None = None,
        sec_ch_ua: str | None = None,
    ) -> dict[str, Any]:
        body = self.enrollment_body(
            email=email,
            profile=profile,
            enrollment_token=enrollment_token,
            captcha=captcha,
            terms_version=terms_version,
        )
        extra_headers: dict[str, str] = {}
        if sec_ch_ua:
            extra_headers["Sec-CH-UA"] = sec_ch_ua
        return self.session.post(
            f"{self.base}/v2/enrollment",
            json_body=body,
            headers=extra_headers or None,
            user_agent=user_agent,
            cookies=cookie_header,
        )

    def refresh_enrollment_token(self, email: str, *, user_ip: str = "") -> str:
        """Get a fresh enrollment JWT (works when email is already VERIFIED)."""
        resp = self.request_otp(email, user_ip=user_ip)
        kind, detail = self.classify_otp_response(resp)
        if kind == "verified" and detail:
            return detail
        if kind == "sent":
            raise RegistrationError(
                "Expected VERIFIED enrollmentToken but SAS re-sent OTP; complete OTP first",
                stage="request_otp",
            )
        raise RegistrationError(
            f"Could not refresh enrollmentToken: {detail} | raw={resp}",
            stage="request_otp",
        )


def _jwt_jti(token: str) -> str | None:
    try:
        import base64

        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return str(data.get("jti") or "") or None
    except Exception:
        return None


def _write_run_report(report: AttemptReport) -> Path | None:
    if not report.run_dir:
        return None
    path = Path(report.run_dir)
    path.mkdir(parents=True, exist_ok=True)
    out = path / "report.json"
    out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return out


def _save_json(run_dir: Path | None, name: str, payload: Any) -> str | None:
    if run_dir is None:
        return None
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / name
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def _is_retryable(error: BaseException) -> bool:
    if isinstance(
        error,
        (BlockedError, CapsolverError, BrowserCaptchaError, TransportError, EnrollmentRetryError),
    ):
        return True
    if isinstance(error, SasHttpError):
        msg = str(error).lower()
        body = (error.body or "").lower()
        if "captcha" in msg or "captcha" in body:
            return True
        if error.status in {403, 429, 503, 502, 500}:
            return True
    return False


def _captcha_modes() -> list[str]:
    mode = (config.REGBOT_CAPTCHA_MODE or "proxy").strip().lower()
    if mode in {"manual", "stdin"}:
        return ["manual"]
    if mode in {"playwright", "browser", "extension"}:
        return ["playwright"]
    if mode in {"proxyless", "proxy_less", "noproxy"}:
        return ["proxyless"]
    if mode in {"auto", "both"}:
        # Browser captcha first (SAS accepts); CapSolver HTTP last-resort only
        return ["playwright", "proxy"]
    return ["proxy"]


def register_once(
    *,
    email_provider: EmailProvider,
    profile: UsProfile | None = None,
    debug: bool = False,
    fetch_proxy_ip: bool = True,
    skip_request_otp: bool = False,
    resume: EnrollmentResume | None = None,
) -> RegisteredAccount:
    """Run one registration attempt (single sticky proxy session).

    ``resume``: email already verified — reuse ``enrollmentToken``, skip OTP.
    """
    config.require_proxy_credentials()
    captcha_mode = (config.REGBOT_CAPTCHA_MODE or "proxy").strip().lower()
    if captcha_mode not in {"manual", "stdin"}:
        config.require_capsolver()

    proxy = new_sticky_proxy()
    report = AttemptReport(
        proxy_session_id=proxy.session_id,
        proxy_label=proxy.label,
    )
    if debug:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        report.run_dir = str(Path(config.REGBOT_RUNS_DIR) / f"run-{stamp}-{proxy.session_id[:8]}")
    run_dir = Path(report.run_dir) if report.run_dir else None

    enrollment_token: str | None = resume.enrollment_token if resume else None
    # Profile may be filled after email is known (name inferred from local-part).
    profile = resume.profile if resume else profile
    logger.info(
        "regbot: provider=%s proxy=%s captcha=%s browser_proxy=%s synthetic_first=%s",
        config.PROXY_PROVIDER,
        proxy.label,
        captcha_mode,
        config.REGBOT_PLAYWRIGHT_BROWSER_PROXY,
        getattr(config, "REGBOT_PLAYWRIGHT_SYNTHETIC_FIRST", False),
    )
    if captcha_mode in {"proxy", "proxyless"}:
        logger.warning(
            "captcha_mode=%s uses CapSolver HTTP tokens — known rejected by SAS enroll (1015001). "
            "Prefer --captcha-mode playwright",
            captcha_mode,
        )
    report.mark("proxy_init", label=proxy.label)

    try:
        with ProxiedSession(proxy) as session:
            client = SasRegisterClient(session)
            user_ip = ""
            if fetch_proxy_ip:
                try:
                    user_ip = session.get_proxy_ip()
                    report.proxy_ip = user_ip
                    report.mark("proxy_ip", ip=user_ip)
                except Exception as error:
                    logger.warning("Could not resolve proxy IP: %s", error)

            html_warm = client.warm_html()
            report.mark("warm_html", result=html_warm)
            api_warm = client.warm_api()
            report.mark("warm_api", result=api_warm)

            if resume:
                email = resume.email
                report.email = email
                report.mark("resume_verified", email=email, token_present=True)
                if profile is None:
                    profile = generate_us_profile(email=email)
            else:
                report.mark("email_create")
                inbox = email_provider.create_inbox()
                if not validate_email(inbox.address):
                    raise RegistrationError(
                        f"Email fails SAS client regex: {inbox.address}",
                        stage="email_create",
                    )
                email = inbox.address
                report.email = email
                report.mark("email_ready", email=email)
                if profile is None:
                    profile = generate_us_profile(email=email)
                    report.mark(
                        "profile",
                        first_name=profile.first_name,
                        last_name=profile.last_name,
                        gender=profile.gender,
                        dob=profile.date_of_birth,
                    )

                if skip_request_otp:
                    report.mark("request_otp_skipped")
                    report.mark("wait_otp")
                    otp = email_provider.wait_for_otp(inbox)
                    report.mark("otp_received")
                    report.mark("validate_otp")
                    val_resp = client.validate_otp(email, otp, user_ip=user_ip)
                    _save_json(run_dir, "validate_otp.json", val_resp)
                    token = val_resp.get("enrollmentToken")
                    if not token:
                        raise RegistrationError(
                            f"validateOtp missing enrollmentToken: {val_resp}",
                            stage="validate_otp",
                        )
                    enrollment_token = str(token)
                    report.mark("validate_otp_ok")
                else:
                    report.mark("request_otp")
                    otp_resp = client.request_otp(email, user_ip=user_ip)
                    _save_json(run_dir, "request_otp.json", otp_resp)
                    kind, detail = client.classify_otp_response(otp_resp)
                    if kind == "error":
                        raise RegistrationError(
                            f"requestOtp rejected by SAS: {detail} | raw={otp_resp}",
                            stage="request_otp",
                        )
                    if kind == "verified":
                        enrollment_token = str(detail)
                        report.mark(
                            "request_otp_already_verified",
                            registration_status="VERIFIED",
                        )
                        logger.info(
                            "Email already verified — reusing enrollmentToken (skip OTP prompt)"
                        )
                    else:
                        report.mark("request_otp_ok", registration_status="EMAIL_SENT")
                        report.mark("wait_otp")
                        otp = email_provider.wait_for_otp(inbox)
                        report.mark("otp_received")
                        report.mark("validate_otp")
                        val_resp = client.validate_otp(email, otp, user_ip=user_ip)
                        _save_json(run_dir, "validate_otp.json", val_resp)
                        token = val_resp.get("enrollmentToken")
                        if not token:
                            raise RegistrationError(
                                f"validateOtp missing enrollmentToken: {val_resp}",
                                stage="validate_otp",
                            )
                        enrollment_token = str(token)
                        report.mark("validate_otp_ok")

            if not enrollment_token:
                raise RegistrationError("Missing enrollmentToken", stage="validate_otp")

            resume_state = EnrollmentResume(
                email=email,
                enrollment_token=enrollment_token,
                profile=profile,
            )

            report.mark("agreement")
            agreement = client.agreement("EB")
            terms_version = int(agreement.get("version") or 3)
            report.mark("agreement_ok", terms_version=terms_version)

            modes = _captcha_modes()
            captcha_tries = max(1, config.REGBOT_CAPTCHA_RETRIES)
            last_enroll_error: BaseException | None = None

            forced_captcha_ua = (config.REGBOT_CAPTCHA_USER_AGENT or "").strip() or None

            for mode in modes:
                for attempt_i in range(1, captcha_tries + 1):
                    # Attempt 1 after validateOtp: keep JWT. Refresh only on retry / each-enroll flag.
                    should_refresh = (
                        config.REGBOT_REFRESH_TOKEN_EACH_ENROLL
                        or attempt_i > 1
                        or mode != modes[0]
                    )
                    if should_refresh:
                        try:
                            report.mark("refresh_token", mode=mode, attempt=attempt_i)
                            enrollment_token = client.refresh_enrollment_token(
                                email, user_ip=user_ip
                            )
                            resume_state = EnrollmentResume(
                                email=email,
                                enrollment_token=enrollment_token,
                                profile=profile,
                            )
                            report.mark(
                                "refresh_token_ok",
                                jti=_jwt_jti(enrollment_token),
                            )
                        except RegistrationError as error:
                            # First attempt may already have a good token
                            if not enrollment_token:
                                raise
                            logger.warning("Token refresh failed, reusing prior JWT: %s", error)
                    else:
                        report.mark(
                            "refresh_token_skipped",
                            mode=mode,
                            attempt=attempt_i,
                            jti=_jwt_jti(enrollment_token),
                            reason="use_validate_otp_jwt",
                        )

                    report.mark("captcha", mode=mode, attempt=attempt_i)
                    enroll_via = (config.REGBOT_ENROLL_VIA or "page").strip().lower()
                    use_browser_enroll = mode in {
                        "playwright",
                        "browser",
                        "extension",
                    } and enroll_via in {"page", "auto", "browser"}

                    enroll_resp: dict[str, Any] | None = None
                    solution: CaptchaSolution | None = None
                    captcha = ""
                    enroll_ua = forced_captcha_ua
                    enroll_impersonate = "chrome146"

                    if use_browser_enroll:
                        # Layer C: captcha + enroll in one Playwright session
                        base_body = SasRegisterClient.enrollment_body(
                            email=email,
                            profile=profile,
                            enrollment_token=enrollment_token,
                            captcha="",
                            terms_version=terms_version,
                        )
                        try:
                            browser_result: BrowserEnrollResult = playwright_solve_and_enroll(
                                proxy=proxy,
                                api_key=config.CAPSOLVER_API_KEY,
                                enrollment_body=base_body,
                                page_url=config.RECAPTCHA_PAGE_URL,
                                sitekey=config.RECAPTCHA_SITEKEY,
                                debug_dir=str(run_dir) if run_dir else None,
                            )
                        except (CapsolverError, BrowserCaptchaError) as error:
                            last_enroll_error = error
                            logger.warning("Playwright solve+enroll failed: %s", error)
                            _write_run_report(report)
                            continue
                        solution = browser_result.solution
                        captcha = solution.token
                        enroll_ua = solution.user_agent or forced_captcha_ua
                        enroll_impersonate = impersonate_for_user_agent(
                            enroll_ua, default="chrome146"
                        )
                        report.mark(
                            "captcha_ok",
                            mode=mode,
                            token_len=len(captcha),
                            task_type=solution.task_type,
                            has_ua=bool(enroll_ua),
                            enroll_impersonate=enroll_impersonate,
                            enroll_ua_prefix=(enroll_ua or "")[:80] or None,
                        )
                        report.mark(
                            "enroll",
                            mode=mode,
                            attempt=attempt_i,
                            jti=_jwt_jti(enrollment_token),
                            captcha_len=len(captcha),
                            enroll_via=browser_result.enroll_via,
                            status=browser_result.enroll_status,
                        )
                        status = browser_result.enroll_status
                        payload = browser_result.enroll_payload
                        body_text = browser_result.enroll_body
                        _save_json(
                            run_dir,
                            f"enrollment_browser_{attempt_i}.json",
                            {
                                "status": status,
                                "via": browser_result.enroll_via,
                                "body": body_text[:8000],
                                "payload": payload,
                                "task_type": solution.task_type,
                            },
                        )
                        if status >= 400 or (
                            isinstance(payload, dict) and payload.get("errorInfo")
                        ):
                            last_enroll_error = SasHttpError(
                                f"Browser enroll HTTP {status} via={browser_result.enroll_via}",
                                status=status,
                                body=body_text[:4000],
                                payload=payload,
                            )
                            logger.warning(
                                "Enrollment HTTP %s mode=%s via=%s jti=%s: %s",
                                status,
                                mode,
                                browser_result.enroll_via,
                                _jwt_jti(enrollment_token),
                                (body_text or "")[:500],
                            )
                            _save_json(
                                run_dir,
                                f"enrollment_error_{mode}_{attempt_i}.json",
                                {
                                    "status": status,
                                    "body": body_text,
                                    "payload": payload,
                                    "enroll_via": browser_result.enroll_via,
                                    "request": {
                                        "userName": email,
                                        "password": "***",
                                        "enrollmentToken_jti": _jwt_jti(enrollment_token),
                                        "captcha_len": len(captcha),
                                        "captcha_mode": mode,
                                        "enroll_via": browser_result.enroll_via,
                                        "proxy_label": proxy.label,
                                        "proxy_ip": report.proxy_ip,
                                        "task_type": solution.task_type,
                                    },
                                },
                            )
                            # auto: fall through to curl enroll with same token
                            if enroll_via == "auto":
                                logger.info(
                                    "Browser enroll failed; trying curl enroll with same captcha"
                                )
                            else:
                                _write_run_report(report)
                                continue
                        else:
                            enroll_resp = payload if isinstance(payload, dict) else {}
                            if not enroll_resp and body_text:
                                try:
                                    enroll_resp = json.loads(body_text)
                                except Exception:
                                    enroll_resp = {"raw": body_text}

                    if enroll_resp is None:
                        # curl_cffi enroll (proxy mode, or auto fallback after page fail)
                        if solution is None:
                            try:
                                solution = solve_captcha(
                                    mode=mode,
                                    proxy=proxy,
                                    api_key=config.CAPSOLVER_API_KEY,
                                    page_url=config.RECAPTCHA_PAGE_URL,
                                    sitekey=config.RECAPTCHA_SITEKEY,
                                    debug_dir=str(run_dir) if run_dir else None,
                                    user_agent=forced_captcha_ua,
                                )
                            except (CapsolverError, BrowserCaptchaError) as error:
                                last_enroll_error = error
                                logger.warning("Captcha mode=%s failed: %s", mode, error)
                                _write_run_report(report)
                                continue
                            captcha = solution.token
                            enroll_ua = solution.user_agent or forced_captcha_ua
                            if (
                                forced_captcha_ua
                                and solution.user_agent
                                and solution.user_agent.strip() != forced_captcha_ua
                                and mode not in {"playwright", "browser", "extension"}
                            ):
                                logger.warning(
                                    "CapSolver returned different UA than forced; "
                                    "enrolling with CapSolver returned UA. forced=%r returned=%r",
                                    forced_captcha_ua[:80],
                                    solution.user_agent[:80],
                                )
                                enroll_ua = solution.user_agent
                            enroll_impersonate = impersonate_for_user_agent(
                                enroll_ua,
                                default=(
                                    "chrome146"
                                    if "playwright" in (solution.task_type or "")
                                    else config.REGBOT_IMPERSONATE
                                ),
                            )
                            report.mark(
                                "captcha_ok",
                                mode=mode,
                                token_len=len(captcha),
                                task_type=solution.task_type,
                                has_ua=bool(enroll_ua),
                                has_ca_e=bool(solution.recaptcha_ca_e),
                                enroll_impersonate=enroll_impersonate,
                                enroll_ua_prefix=(enroll_ua or "")[:80] or None,
                            )
                        report.mark(
                            "enroll",
                            mode=mode,
                            attempt=attempt_i,
                            jti=_jwt_jti(enrollment_token),
                            captcha_len=len(captcha),
                            impersonate=enroll_impersonate,
                            enroll_via="curl",
                            enroll_ua_prefix=(enroll_ua or "")[:80] or None,
                        )
                        enroll_session = session.sibling(impersonate=enroll_impersonate)
                        try:
                            enroll_client = SasRegisterClient(
                                enroll_session,
                                ua=enroll_ua or client.ua,
                            )
                            try:
                                enroll_resp = enroll_client.enroll(
                                    email=email,
                                    profile=profile,
                                    enrollment_token=enrollment_token,
                                    captcha=captcha,
                                    terms_version=terms_version,
                                    user_agent=enroll_ua,
                                    cookie_header=solution.cookie_header() if solution else None,
                                    sec_ch_ua=solution.sec_ch_ua if solution else None,
                                )
                            except SasHttpError as error:
                                last_enroll_error = error
                                body_snip = (error.body or "")[:500]
                                logger.warning(
                                    "Enrollment HTTP %s mode=%s jti=%s imp=%s: %s",
                                    error.status,
                                    mode,
                                    _jwt_jti(enrollment_token),
                                    enroll_impersonate,
                                    body_snip,
                                )
                                _save_json(
                                    run_dir,
                                    f"enrollment_error_{mode}_{attempt_i}.json",
                                    {
                                        "status": error.status,
                                        "body": error.body,
                                        "payload": error.payload,
                                        "request": {
                                            "userName": email,
                                            "password": "***",
                                            "enrollmentToken_jti": _jwt_jti(enrollment_token),
                                            "captcha_len": len(captcha),
                                            "captcha_mode": mode,
                                            "enroll_via": "curl",
                                            "enroll_impersonate": enroll_impersonate,
                                            "proxy_label": proxy.label,
                                            "proxy_ip": report.proxy_ip,
                                        },
                                    },
                                )
                                _write_run_report(report)
                                continue
                        finally:
                            enroll_session.close()

                    raw_path = _save_json(run_dir, "enrollment.json", enroll_resp)
                    eb = None
                    try:
                        eb = enroll_resp["engagements"]["euroBonus"]["ebNumber"]
                    except (KeyError, TypeError):
                        pass
                    crm = enroll_resp.get("crmReference")
                    if not eb and enroll_resp.get("errorInfo"):
                        last_enroll_error = RegistrationError(
                            f"enrollment error: {enroll_resp.get('errorInfo')}",
                            stage="enroll",
                        )
                        logger.warning("%s", last_enroll_error)
                        continue

                    account = RegisteredAccount(
                        email=email,
                        password=profile.password,
                        eb_number=str(eb) if eb else None,
                        crm_reference=str(crm) if crm else None,
                        first_name=profile.first_name,
                        last_name=profile.last_name,
                        phone=profile.phone,
                        country=profile.country_code,
                        gender=profile.gender,
                        date_of_birth=profile.date_of_birth,
                        proxy_session_id=proxy.session_id,
                        proxy_label=proxy.label,
                        proxy_ip=report.proxy_ip,
                        enrollment_raw_path=raw_path,
                    )
                    path = save_account(account)
                    report.result = "success"
                    report.mark("saved", path=str(path), eb_number=account.eb_number)
                    _write_run_report(report)
                    logger.info(
                        "Registered %s EB=%s proxy=%s path=%s",
                        account.email,
                        account.eb_number,
                        proxy.label,
                        path,
                    )
                    return account

            raise EnrollmentRetryError(
                f"Enrollment failed after captcha modes={modes}: {last_enroll_error}",
                resume=resume_state,
            )
    except EnrollmentRetryError:
        report.result = "failure"
        report.error = "enrollment_retry"
        report.stage = "enroll"
        _write_run_report(report)
        raise
    except Exception as error:
        report.result = "failure"
        report.error = str(error)
        if isinstance(error, RegistrationError) and error.stage:
            report.stage = error.stage
        _write_run_report(report)
        raise


def register_with_retries(
    *,
    email_provider: EmailProvider,
    profile: UsProfile | None = None,
    max_attempts: int | None = None,
    debug: bool = False,
    fetch_proxy_ip: bool = True,
    skip_request_otp: bool = False,
) -> RegisteredAccount:
    """Retry with a new sticky proxy on block/captcha/transport failures.

    After email OTP succeeds, keeps ``enrollmentToken`` across proxy rotations
    so a failed captcha does not require a new OTP.
    """
    attempts = max_attempts if max_attempts is not None else config.REGBOT_PROXY_RETRIES
    last: BaseException | None = None
    resume: EnrollmentResume | None = None
    for attempt in range(1, attempts + 1):
        try:
            logger.info(
                "Registration attempt %s/%s%s",
                attempt,
                attempts,
                " (resume verified email)" if resume else "",
            )
            return register_once(
                email_provider=email_provider,
                profile=profile,
                debug=debug,
                fetch_proxy_ip=fetch_proxy_ip,
                skip_request_otp=skip_request_otp,
                resume=resume,
            )
        except EnrollmentRetryError as error:
            last = error
            resume = error.resume
            if attempt >= attempts:
                raise
            logger.warning(
                "Enroll/captcha failed; keeping enrollmentToken for %s — new proxy (%s/%s): %s",
                resume.email,
                attempt,
                attempts,
                error,
            )
            time.sleep(min(2 * attempt, 10))
        except (RegistrationError, EmailProviderError) as error:
            last = error
            if isinstance(error, RegistrationError) and error.stage == "request_otp":
                msg = str(error).lower()
                if any(
                    marker in msg
                    for marker in (
                        "otptemporaryblocked",
                        "retrylater",
                        "abused",
                        "verification_failed",
                        "rejected by sas",
                    )
                ):
                    raise
            if attempt >= attempts:
                raise
            logger.warning("Attempt %s failed (%s): %s", attempt, type(error).__name__, error)
            time.sleep(min(2 * attempt, 10))
        except Exception as error:
            last = error
            if not _is_retryable(error) or attempt >= attempts:
                raise
            logger.warning(
                "Retryable failure on attempt %s/%s: %s",
                attempt,
                attempts,
                error,
            )
            time.sleep(min(2 * attempt, 10))
    raise RegistrationError(f"Exhausted {attempts} attempts: {last}") from last


def verify_proxy_egress() -> dict[str, Any]:
    """Confirm sticky proxy works and masks direct IP."""
    config.require_proxy_credentials()
    import requests

    direct_ip = None
    try:
        direct_ip = requests.get("https://api.ipify.org/?format=json", timeout=15).json().get("ip")
    except Exception as error:
        logger.warning("Direct ipify failed: %s", error)

    proxy = new_sticky_proxy()
    with ProxiedSession(proxy) as session:
        proxy_ip = session.get_proxy_ip()

    result = {
        "proxy_label": proxy.label,
        "proxy_session_id": proxy.session_id,
        "proxy_ip": proxy_ip,
        "direct_ip": direct_ip,
        "masked": bool(direct_ip and proxy_ip and direct_ip != proxy_ip),
    }
    if direct_ip and proxy_ip == direct_ip:
        raise ProxyLeakError(
            f"Proxy IP equals direct IP ({proxy_ip}). SAS traffic would leak. Aborting."
        )
    return result


class ProxyLeakError(RuntimeError):
    """Direct IP equals proxy egress — configuration broken."""
