# regbot

Automated / semi-automated **SAS EuroBonus** account registration against  
`https://www.flysas.com/en/register` using pure HTTP (`curl_cffi` + CapSolver).

## Design principles

1. **All SAS traffic goes through a sticky Bright Data proxy** — hard-fail if `PROXY_*` is missing.
2. **reCAPTCHA v2** is solved with CapSolver **`ReCaptchaV2Task`** using the **same** sticky proxy (token IP must match enrollment egress).
3. **Email OTP** uses a pluggable provider API and does **not** need to go through the proxy.
4. Flow is reconstructed from a real browser HAR (`api2.flysas.com`), not browser automation.

Inspired by patterns in `~/saseb_bot` (`sas_curl`, sticky sessions, CapSolver proxy string).

## Registration pipeline

```
sticky proxy → create email inbox (direct)
  → warm flysas (proxy) → requestOtp (proxy)
  → wait for 6-digit OTP (direct email API / manual paste)
  → validateOtp → enrollmentToken
  → agreement termsVersion
  → CapSolver reCAPTCHA v2 (worker via same proxy)
  → POST v2/enrollment
  → save credentials under data/accounts/
```

## Setup

```bash
cd ~/regbot
uv sync --group dev
```

Copy env template and fill secrets (or export from `~/.bashrc` like saseb):

```bash
cp .env.example .env
# PROXY_USERNAME / PROXY_PASSWORD / CAPSOLVER_API_KEY required
```

### Email providers

| `EMAIL_PROVIDER` | Behaviour |
|------------------|-----------|
| `anymessage` (**default**) | [AnyMessage](https://anymessage.shop/en/docs) order + poll OTP |
| `manual` | Interactive: type email + paste OTP |
| `fake` | Test only (`test.user@example.com` / `123456`) |
| `http` | Generic REST adapter |

#### AnyMessage setup

1. Create an account at https://anymessage.shop/  
2. Copy API token from the dashboard  
3. Export:

```bash
export EMAIL_PROVIDER=anymessage
export ANYMESSAGE_TOKEN="your-token"
export ANYMESSAGE_SITE=flysas.com   # adjust if stock uses another site key
# export ANYMESSAGE_DOMAIN=gmx.com  # optional preferred domain
```

Preflight stock:

```bash
uv run regbot email-stock
```

API (direct, not proxied): `GET https://api.anymessage.shop/email/order` and `/email/getmessage`.

## Usage

```bash
# Prove Bright Data masks your IP (and proxy auth works)
uv run regbot verify-proxy

# Fully automated (AnyMessage + CapSolver)
export ANYMESSAGE_TOKEN=...
export CAPSOLVER_API_KEY=...
uv run regbot register --debug -v

# Batch
uv run regbot register --count 3 --delay 10 --debug
```

### Manual custom flow (your email — bot asks for OTP)

You cannot know the OTP before SAS sends it. The bot always:

1. Calls `requestOtp` for your address
2. **Prompts you** to type the 6-digit code when the mail arrives
3. Continues with captcha + enrollment

```bash
# You provide the mailbox; bot requests OTP then asks you to paste it
uv run regbot register --email you@gmx.com --debug -v

# Fully interactive (asks for email, then later for OTP)
EMAIL_PROVIDER=manual uv run regbot register --debug -v

# Optional profile overrides (OTP still prompted interactively)
uv run regbot register --email you@gmx.com \
  --first-name Harry --last-name Barrier --gender m \
  --dob 1983-05-13 --phone +13026187675 --password 'YourPass1!' \
  --debug -v
```

Advanced only: `--email … --otp … --skip-request-otp` reuses a code already obtained outside the bot.

Accounts are written to `data/accounts/<timestamp>-email.json` and appended to `data/accounts/accounts.jsonl`.  
Debug runs write `data/runs/run-.../report.json` plus API snapshots.

## Proxy rules (important)

| Traffic | Path |
|---------|------|
| `www.flysas.com`, `api2.flysas.com` | **Must** use sticky Bright Data session |
| CapSolver **worker** (reCAPTCHA solve) | Same sticky proxy string in task payload |
| CapSolver **API** (`api.capsolver.com`) | Direct (control plane only) |
| Email provider API | Direct |

Each registration attempt uses a **new** `-session-{id}` username. Blocks / captcha failures rotate the session.


## Captcha backends

| Mode | How |
|------|-----|
| `playwright` (default) | Headed Chromium + CapSolver **extension**, same sticky BD for enroll |
| `proxy` | CapSolver HTTP `ReCaptchaV2Task` via BD |
| `proxyless` | CapSolver HTTP without BD worker |
| `manual` | You paste `g-recaptcha-response` |
| `auto` | playwright → proxy |

```bash
uv sync --extra browser
uv run playwright install chromium

# Servers without a display:
xvfb-run -a uv run regbot register -v --email you@example.com --debug --captcha-mode playwright
```

Notes:
- Bright Data often returns **Denied boarding** for flysas HTML; the browser still injects reCAPTCHA on that origin and loads Google assets **direct** (BD blocks Google).
- CapSolver extension solves in-page; enroll still uses `curl_cffi` + sticky BD.
- Do **not** use personal Mullvad for CapSolver cloud workers.

## reCAPTCHA / CapSolver modes

CapSolver **control plane** is always direct. Worker mode is configurable:

| `REGBOT_CAPTCHA_MODE` | Behaviour |
|----------------------|-----------|
| `auto` (default) | Try **proxy** (token IP = Bright Data), then **proxyless** if enroll fails |
| `proxy` | Only `ReCaptchaV2Task` with sticky BD proxy |
| `proxyless` | Only `ReCaptchaV2TaskProxyLess` (no BD → Google) |

If Bright Data cannot reach Google well, use `REGBOT_CAPTCHA_MODE=proxyless` or leave `auto`.

After OTP succeeds, a failed captcha/enroll **reuses the enrollment token** (no second OTP). If `requestOtp` returns `VERIFIED` + token, the bot continues without asking for a code.

## reCAPTCHA

Sitekey (from live register page / HAR):

`6LeTFOEUAAAAAKMhMH_hzLHbBo4_S_JVv_CYaoF6`

Task type: **`ReCaptchaV2Task`** (not proxyless).

## Password / profile rules

- Password: 8–50 chars, upper + lower + digit + special, no spaces  
- US profile: empty street/city/zip (matches successful HAR enrollment)  
- Phone: `+1` NANP-style (no SMS verification in the captured flow)

## Tests

```bash
uv run pytest
```

Live proxy check (optional):

```bash
uv run pytest -m live
```

## Non-goals (v1)

- Playwright / CapSolver browser extension  
- Auth0 login / SkyTeam session provisioning  
- Non-US countries  
- High concurrency without rate-limit data  

## Legal / ToS note

Automating registration may violate SAS terms. Use only with accounts and infrastructure you are allowed to operate.
