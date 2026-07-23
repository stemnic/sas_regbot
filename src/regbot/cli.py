"""CLI for regbot."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from . import config
from .email.base import get_email_provider
from .profile import build_us_profile
from .sas_register import ProxyLeakError, register_with_retries, verify_proxy_egress


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_verify_proxy(_args: argparse.Namespace) -> int:
    try:
        result = verify_proxy_egress()
    except ProxyLeakError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        msg = str(error)
        print(f"ERROR: {msg}", file=sys.stderr)
        if "407" in msg or "ip_forbidden" in msg.lower():
            print(
                "Hint: Bright Data returned proxy auth failure (407 / ip_forbidden). "
                "Allowlist this machine's IP on the zone, or run from a permitted network.",
                file=sys.stderr,
            )
        return 1
    print(json.dumps(result, indent=2))
    if result.get("masked"):
        print("OK: sticky proxy masks direct IP")
        return 0
    print("WARN: could not compare to direct IP (proxy still returned an address)")
    return 0


def cmd_email_stock(args: argparse.Namespace) -> int:
    """Preflight AnyMessage stock for the configured site."""
    try:
        provider = get_email_provider(args.email_provider or "anymessage")
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    quantity = getattr(provider, "quantity", None)
    if not callable(quantity):
        print("ERROR: selected provider does not support stock checks", file=sys.stderr)
        return 1
    try:
        data = quantity()
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(data if not isinstance(data, str) else {"raw": data}, indent=2, default=str))
    return 0


def _profile_from_args(args: argparse.Namespace):
    overrides = {
        "first_name": args.first_name,
        "last_name": args.last_name,
        "gender": args.gender,
        "date_of_birth": args.dob,
        "phone": args.phone,
        "password": args.password,
        "email": args.email,
    }
    # If only email is set (manual flow), still return None so orchestrator builds
    # after inbox is known — but if any explicit profile field is set, build now.
    explicit = {
        k: v
        for k, v in overrides.items()
        if k != "email" and v is not None
    }
    if not explicit:
        return None
    return build_us_profile(**overrides)


def cmd_register(args: argparse.Namespace) -> int:
    if args.otp and not args.email:
        print("ERROR: --otp requires --email", file=sys.stderr)
        return 2
    if args.skip_request_otp and not args.otp:
        print(
            "ERROR: --skip-request-otp requires --otp "
            "(only for rare cases where the code was already requested outside the bot)",
            file=sys.stderr,
        )
        return 2
    if args.email and args.count != 1:
        print("ERROR: manual --email flow only supports --count 1", file=sys.stderr)
        return 2

    # Default manual path: requestOtp → prompt user for code.
    # Only skip requestOtp when user explicitly opts in (code already obtained).
    skip_request_otp = bool(args.skip_request_otp)
    if args.otp and not args.skip_request_otp:
        print(
            "NOTE: --otp without --skip-request-otp still calls requestOtp first; "
            "the code you pass may be stale. Prefer omitting --otp so the bot asks "
            "you after the email is sent.",
            file=sys.stderr,
        )

    try:
        # Manual --email: always prompt for OTP after requestOtp unless replaying.
        fixed_otp = args.otp if (args.email and skip_request_otp) else None
        provider = get_email_provider(
            args.email_provider,
            fixed_email=args.email,
            fixed_otp=fixed_otp,
        )
        profile = _profile_from_args(args)
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if args.captcha_mode:
        config.REGBOT_CAPTCHA_MODE = args.captcha_mode

    logging.getLogger(__name__).info(
        "effective: captcha_mode=%s oxy_ports=%s provider=%s",
        config.REGBOT_CAPTCHA_MODE,
        config.oxylabs_ports() if config.PROXY_PROVIDER.startswith("oxy") else "n/a",
        config.PROXY_PROVIDER,
    )
    if (config.REGBOT_CAPTCHA_MODE or "").strip().lower() in {"proxy", "proxyless"}:
        logging.getLogger(__name__).warning(
            "CapSolver HTTP mode is known-bad for SAS enroll; use --captcha-mode playwright"
        )

    success = 0
    failures = 0
    for i in range(args.count):
        if args.count > 1:
            logging.getLogger(__name__).info("=== account %s/%s ===", i + 1, args.count)
        try:
            account = register_with_retries(
                email_provider=provider,
                profile=profile,
                max_attempts=args.retries,
                debug=args.debug,
                fetch_proxy_ip=not args.skip_proxy_ip,
                skip_request_otp=skip_request_otp,
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "email": account.email,
                        "eb_number": account.eb_number,
                        "password": account.password,
                        "proxy_label": account.proxy_label,
                    },
                    indent=2,
                )
            )
            success += 1
        except Exception as error:
            failures += 1
            logging.getLogger(__name__).error("Registration failed: %s", error)
            print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
            if args.fail_fast:
                return 1
        if i + 1 < args.count and args.delay > 0:
            time.sleep(args.delay)
    logging.getLogger(__name__).info("Done success=%s failures=%s", success, failures)
    return 0 if failures == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="regbot",
        description="SAS EuroBonus registration via curl_cffi + CapSolver (proxy-enforced SAS traffic)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_verbose(p: argparse.ArgumentParser) -> None:
        p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    p_verify = sub.add_parser("verify-proxy", help="Check sticky Bright Data egress vs direct IP")
    _add_verbose(p_verify)
    p_verify.set_defaults(func=cmd_verify_proxy)

    p_stock = sub.add_parser("email-stock", help="Check AnyMessage stock for ANYMESSAGE_SITE")
    _add_verbose(p_stock)
    p_stock.add_argument(
        "--email-provider",
        default=None,
        help="Override EMAIL_PROVIDER (default anymessage)",
    )
    p_stock.set_defaults(func=cmd_email_stock)

    p_reg = sub.add_parser(
        "register",
        help="Register EuroBonus account(s)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Fully automated (AnyMessage orders email + reads OTP)
  export ANYMESSAGE_TOKEN=...
  uv run regbot register --debug -v

  # Manual: bot requests OTP to YOUR email, then ASKS you to type the code
  uv run regbot register --email you@gmx.com --debug -v

  # Fully interactive (asks for email, then later for OTP)
  EMAIL_PROVIDER=manual uv run regbot register --debug -v

  # Optional profile overrides (OTP still prompted interactively)
  uv run regbot register --email you@gmx.com \\
    --first-name Harry --last-name Barrier --gender m \\
    --dob 1983-05-13 --phone +13026187675 --password 'YourPass1!' \\
    --debug -v

notes:
  Disconnect personal VPNs (e.g. Mullvad) — Bright Data returns 407/ip_forbidden.
  HTML warm of www.flysas.com is skipped by default (Cloudflare); api2 is used instead.
""",
    )
    _add_verbose(p_reg)
    p_reg.add_argument("--count", type=int, default=1, help="Number of accounts (auto mode only)")
    p_reg.add_argument(
        "--retries",
        type=int,
        default=None,
        help=f"Proxy rotation attempts (default {config.REGBOT_PROXY_RETRIES})",
    )
    p_reg.add_argument(
        "--email-provider",
        default=None,
        help="Override EMAIL_PROVIDER (anymessage|manual|fake|http)",
    )
    p_reg.add_argument(
        "--email",
        default=None,
        help="Manual flow: use this address; bot requests OTP then prompts you to type it",
    )
    p_reg.add_argument(
        "--otp",
        default=None,
        help="Advanced: pre-known OTP (only used with --skip-request-otp)",
    )
    p_reg.add_argument(
        "--skip-request-otp",
        action="store_true",
        help="Advanced: do not call requestOtp (requires --otp already received outside the bot)",
    )
    p_reg.add_argument("--first-name", default=None)
    p_reg.add_argument("--last-name", default=None)
    p_reg.add_argument("--gender", default=None, help="m or f")
    p_reg.add_argument("--dob", default=None, help="YYYY-MM-DD")
    p_reg.add_argument("--phone", default=None, help="E.164 e.g. +13026187675")
    p_reg.add_argument("--password", default=None, help="Must meet SAS password rules")
    p_reg.add_argument("--debug", action="store_true", help="Write per-run artifacts under data/runs")
    p_reg.add_argument("--skip-proxy-ip", action="store_true", help="Skip ipify lookup for userIpAddress")
    p_reg.add_argument("--delay", type=float, default=5.0, help="Seconds between multi-account runs")
    p_reg.add_argument("--fail-fast", action="store_true")
    p_reg.add_argument(
        "--captcha-mode",
        default=None,
        choices=["playwright", "proxy", "proxyless", "auto", "manual"],
        help="Captcha backend (default playwright = Chromium+CapSolver extension)",
    )
    p_reg.set_defaults(func=cmd_register)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = bool(getattr(args, "verbose", False))
    _setup_logging(verbose)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
