"""Persist registered accounts to disk."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import config


@dataclass
class RegisteredAccount:
    email: str
    password: str
    eb_number: str | None = None
    crm_reference: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    country: str = "US"
    gender: str | None = None
    date_of_birth: str | None = None
    proxy_session_id: str | None = None
    proxy_label: str | None = None
    proxy_ip: str | None = None
    created_at: float = field(default_factory=time.time)
    enrollment_raw_path: str | None = None
    # True when SAS enroll returned 1015004 (email already exists) — treat as success
    already_existed: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["created_at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created_at))
        return data


def _safe_filename(email: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._@+-]+", "_", email.strip())
    return cleaned[:120] or "account"


def save_account(account: RegisteredAccount, directory: str | Path | None = None) -> Path:
    root = Path(directory or config.REGBOT_ACCOUNTS_DIR)
    root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    path = root / f"{stamp}-{_safe_filename(account.email)}.json"
    payload = json.dumps(account.to_dict(), indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(dir=root, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    index = root / "accounts.jsonl"
    with index.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(account.to_dict(), ensure_ascii=False) + "\n")
    return path
