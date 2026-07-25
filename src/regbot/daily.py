"""Daily registration quota, circuit breaker, and await-review state."""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import config
from .alerts import AlertError, send_circuit_open_alert
from .email.base import EmailProvider, EmailProviderError, get_email_provider
from .sas_register import RegistrationError, register_with_retries
from .store import RegisteredAccount

logger = logging.getLogger(__name__)

# Error substrings that trip the circuit immediately (systemic / do not thrash)
_SYSTEMIC_MARKERS = (
    "capsolver",
    "api key",
    "unauthorized",
    "401",
    "403",
    "407",
    "ip_forbidden",
    "proxy authentication",
    "brightdata",
    "looks like bright data",
    "otptemporaryblocked",
    "retrylater",
    "abused",
    "verification_failed",
    "no balance",
    "insufficient",
    "rate limit",
    "plan allows",
    "openinbox auth",
    "forward email",
    "mullvad",
    "not connected",
)


@dataclass
class DailyState:
    date: str  # YYYY-MM-DD UTC
    success: int = 0
    failures: int = 0
    consec_fail: int = 0
    circuit_open: bool = False
    status: str = "ok"  # ok | awaiting_review | quota_met
    stop_reason: str | None = None
    alert_sent_at: float | None = None
    last_errors: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)  # emails registered today

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DailyState:
        return cls(
            date=str(data.get("date") or ""),
            success=int(data.get("success") or 0),
            failures=int(data.get("failures") or 0),
            consec_fail=int(data.get("consec_fail") or 0),
            circuit_open=bool(data.get("circuit_open")),
            status=str(data.get("status") or "ok"),
            stop_reason=data.get("stop_reason"),
            alert_sent_at=data.get("alert_sent_at"),
            last_errors=list(data.get("last_errors") or []),
            accounts=list(data.get("accounts") or []),
        )


def utc_today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _state_path() -> Path:
    return Path(config.REGBOT_DAILY_STATE_PATH or "data/daily_state.json")


def load_daily_state(*, date: str | None = None) -> DailyState:
    day = date or utc_today()
    path = _state_path()
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and str(raw.get("date")) == day:
                return DailyState.from_dict(raw)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            logger.warning("daily state load failed: %s", error)
    return DailyState(date=day)


def save_daily_state(state: DailyState) -> Path:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    # Also keep a dated snapshot
    snap_dir = Path(config.REGBOT_RUNS_DIR).parent / "daily"
    snap_dir.mkdir(parents=True, exist_ok=True)
    (snap_dir / f"{state.date}.json").write_text(
        json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    return path


def clear_circuit(state: DailyState | None = None) -> DailyState:
    st = state or load_daily_state()
    st.circuit_open = False
    st.status = "ok" if st.success < config.REGBOT_DAILY_TARGET else "quota_met"
    st.stop_reason = None
    st.consec_fail = 0
    save_daily_state(st)
    logger.info("Circuit cleared for %s (status=%s)", st.date, st.status)
    return st


def is_systemic_error(error: BaseException) -> bool:
    msg = str(error).lower()
    return any(m in msg for m in _SYSTEMIC_MARKERS)


def open_circuit(
    state: DailyState,
    *,
    reason: str,
    send_alert: bool = True,
) -> DailyState:
    state.circuit_open = True
    state.status = "awaiting_review"
    state.stop_reason = reason
    logger.error(
        "CIRCUIT OPEN — registration stopped, awaiting review: %s",
        reason,
    )
    if send_alert and not state.alert_sent_at:
        try:
            send_circuit_open_alert(
                date=state.date,
                stop_reason=reason,
                success=state.success,
                failures=state.failures,
                consec_fail=state.consec_fail,
                last_errors=state.last_errors,
            )
            state.alert_sent_at = time.time()
        except AlertError as error:
            logger.error("Failed to send circuit alert email: %s", error)
    save_daily_state(state)
    return state


@dataclass
class DailyRunResult:
    state: DailyState
    exit_code: int
    message: str


def run_daily(
    *,
    target: int | None = None,
    batch: int | None = None,
    max_proxy_attempts: int | None = None,
    delay_s: float | None = None,
    debug: bool = True,
    email_provider: EmailProvider | None = None,
    force_continue: bool | None = None,
) -> DailyRunResult:
    """Register a small batch toward the daily quota (default: 1 account per run).

    Space registrations across the day with cron (e.g. 5 invocations), not one burst.
    """
    from .netguard import MullvadNotConnectedError, require_mullvad

    try:
        require_mullvad()
    except MullvadNotConnectedError as error:
        logger.error("Mullvad preflight failed: %s", error)
        raise

    day = utc_today()
    state = load_daily_state(date=day)
    target_n = target if target is not None else config.REGBOT_DAILY_TARGET
    batch_n = batch if batch is not None else config.REGBOT_DAILY_BATCH
    batch_n = max(1, int(batch_n))
    retries = (
        max_proxy_attempts
        if max_proxy_attempts is not None
        else config.REGBOT_PROXY_RETRIES
    )
    delay = delay_s if delay_s is not None else config.REGBOT_ACCOUNT_DELAY_S
    force = (
        force_continue
        if force_continue is not None
        else config.REGBOT_FORCE_CONTINUE
    )

    if state.circuit_open and not force:
        msg = (
            f"Circuit open for {day} — awaiting review "
            f"(reason={state.stop_reason!r}). "
            "Use --clear-circuit or REGBOT_FORCE_CONTINUE=1 to continue."
        )
        logger.error("%s", msg)
        return DailyRunResult(state=state, exit_code=2, message=msg)

    if force and state.circuit_open:
        logger.warning("FORCE_CONTINUE: ignoring open circuit for %s", day)
        state.circuit_open = False
        state.status = "ok"
        state.stop_reason = None

    remaining = max(0, target_n - state.success)
    to_run = min(remaining, batch_n)
    logger.info(
        "daily: date=%s success_so_far=%s target=%s remaining=%s "
        "this_run_batch=%s proxy_retries_per_account=%s circuit=%s",
        day,
        state.success,
        target_n,
        remaining,
        to_run,
        retries,
        "open" if state.circuit_open else "closed",
    )
    if remaining <= 0:
        state.status = "quota_met"
        save_daily_state(state)
        return DailyRunResult(
            state=state,
            exit_code=0,
            message=f"Quota already met for {day} ({state.success}/{target_n})",
        )

    provider = email_provider or get_email_provider()

    for i in range(to_run):
        if state.circuit_open:
            break
        logger.info(
            "=== daily account slot %s/%s this run (day remaining was %s, max %s proxy tries) ===",
            i + 1,
            to_run,
            remaining,
            retries,
        )
        try:
            account: RegisteredAccount = register_with_retries(
                email_provider=provider,
                profile=None,
                max_attempts=retries,
                debug=debug,
                fetch_proxy_ip=True,
            )
            state.success += 1
            state.consec_fail = 0
            state.accounts.append(account.email)
            logger.info(
                "daily: registered %s EB=%s proxy=%s (%s/%s today)",
                account.email,
                account.eb_number,
                account.proxy_label,
                state.success,
                target_n,
            )
        except Exception as error:
            state.failures += 1
            state.consec_fail += 1
            err_s = f"{type(error).__name__}: {error}"
            state.last_errors.append(err_s[:500])
            state.last_errors = state.last_errors[-20:]
            logger.error("daily: account failed: %s", err_s)

            if is_systemic_error(error):
                open_circuit(
                    state,
                    reason=f"systemic: {err_s[:300]}",
                    send_alert=True,
                )
                break

            if state.consec_fail >= config.REGBOT_CIRCUIT_CONSEC_FAIL:
                open_circuit(
                    state,
                    reason=(
                        f"consecutive_failures={state.consec_fail} "
                        f"(threshold={config.REGBOT_CIRCUIT_CONSEC_FAIL}): {err_s[:200]}"
                    ),
                    send_alert=True,
                )
                break

            if isinstance(error, (RegistrationError, EmailProviderError)):
                # already counted; continue to next account only if circuit closed
                pass

        save_daily_state(state)

        # Only relevant if batch > 1; prefer cron spacing for multi-account days
        if i + 1 < to_run and not state.circuit_open and delay > 0:
            jitter = random.uniform(0, min(60.0, delay * 0.1))
            sleep_for = delay + jitter
            logger.info("daily: sleeping %.0fs before next account in batch", sleep_for)
            time.sleep(sleep_for)

    if state.success >= target_n:
        state.status = "quota_met"
    elif not state.circuit_open:
        state.status = "ok"
    save_daily_state(state)

    if state.circuit_open:
        return DailyRunResult(
            state=state,
            exit_code=2,
            message=f"Stopped awaiting review: {state.stop_reason}",
        )
    return DailyRunResult(
        state=state,
        exit_code=0 if state.success > 0 or remaining == 0 else 1,
        message=(
            f"Done date={day} success={state.success}/{target_n} "
            f"failures={state.failures} status={state.status}"
        ),
    )
