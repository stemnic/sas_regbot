"""Outbound alert email via Forward Email API.

Docs: https://forwardemail.net/en/email-api
Send: POST /v1/emails with Basic Auth (API token as username, empty password).
"""

from __future__ import annotations

import logging
import socket
from typing import Any

import requests

from . import config

logger = logging.getLogger(__name__)


class AlertError(RuntimeError):
    """Failed to send alert email."""


def send_alert_email(
    *,
    subject: str,
    text: str,
    to: str | None = None,
    from_addr: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Send a plain-text alert via Forward Email outbound API."""
    key = (api_key if api_key is not None else config.FORWARDEMAIL_API_KEY).strip()
    if not key:
        raise AlertError(
            "FORWARDEMAIL_API_KEY (or REG_ALERT_API_KEY) is required to send alerts"
        )
    sender = (from_addr or config.REG_ALERT_FROM).strip()
    recipient = (to or config.REG_ALERT_TO).strip()
    if not sender or not recipient:
        raise AlertError("REG_ALERT_FROM and REG_ALERT_TO are required")

    url = f"{config.FORWARDEMAIL_API_BASE}/v1/emails"
    try:
        response = requests.post(
            url,
            auth=(key, ""),
            data={
                "from": sender,
                "to": recipient,
                "subject": subject,
                "text": text,
            },
            timeout=45,
        )
    except requests.RequestException as error:
        raise AlertError(f"Forward Email request failed: {error}") from error

    if response.status_code >= 400:
        raise AlertError(
            f"Forward Email HTTP {response.status_code}: {response.text[:500]}"
        )
    try:
        payload = response.json()
    except Exception:
        payload = {"raw": response.text[:500]}
    logger.info(
        "Alert email queued to=%s subject=%r id=%s",
        recipient,
        subject[:80],
        payload.get("id") or payload.get("messageId"),
    )
    return payload if isinstance(payload, dict) else {"data": payload}


def send_circuit_open_alert(
    *,
    date: str,
    stop_reason: str,
    success: int,
    failures: int,
    consec_fail: int,
    last_errors: list[str],
    host: str | None = None,
) -> dict[str, Any] | None:
    """Notify operators that daily registration stopped and awaits review."""
    if not config.REG_ALERT_ENABLED:
        logger.warning("REG_ALERT_ENABLED=false — skipping circuit alert email")
        return None
    hostname = host or socket.gethostname()
    subject = f"[regbot] CIRCUIT OPEN — registration paused ({hostname} {date})"
    err_block = "\n".join(f"  - {e}" for e in last_errors[-10:]) or "  (none)"
    text = (
        f"regbot daily registration has STOPPED and is AWAITING REVIEW.\n\n"
        f"Host: {hostname}\n"
        f"Date (UTC): {date}\n"
        f"Stop reason: {stop_reason}\n"
        f"Successes today (this run cumulative): {success}\n"
        f"Failures: {failures}\n"
        f"Consecutive failures: {consec_fail}\n\n"
        f"Recent errors:\n{err_block}\n\n"
        f"No further accounts will be created until:\n"
        f"  • the next UTC calendar day, or\n"
        f"  • you clear the circuit (regbot daily --clear-circuit)\n\n"
        f"— regbot / reg-infra@polarawards.com\n"
    )
    return send_alert_email(subject=subject, text=text)
