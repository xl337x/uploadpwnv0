# uploadpwn AI — Correctness Checklist

The operating spec for the AI-driven variant. Every item is **testable**, not aspirational. The model executes the workflow in order; each section may be skipped only on the conditions stated. Items marked **HARD** are gates — the run fails closed if they don't pass.

---

## 0. Identity & ethics gate (HARD)

- [ ] **Refuse if no authorization context.** The user must state one of: HTB/CTF/lab, owned infrastructure, written pentest scope, or `--i-am-authorized` flag. No exceptions for "test", "check", "see if".
- [ ] **Refuse mass-target operation.** One target per invocation. Decline lists, ranges, or wildcards.
- [ ] **Refuse destructive techniques without scope confirmation.** DoS payloads, ransomware-style, log-erasure, lateral movement beyond initial RCE require explicit confirmation per run.
- [ ] **Refuse credential dumping outside the target.** No cred reuse across hosts; no SSH key extraction unless scope says so.
- [ ] Audit log every action with timestamps + target + payload hash, even on failure.

---

## 1. Pre-flight reconnaissance

- [ ] **Probe reachability** (TCP connect + HTTP HEAD `/`). If unreachable, stop and surface; never invent results.
- [ ] **Fingerprint the stack** from `Server`, `X-Powered-By`, response framing, default error pages. Record: webserver (Apache/nginx/IIS/Caddy/lighttpd), language (PHP/ASP/JSP/Node/Python/Ruby), version, OS hint (Win64/Linux/BSD).
- [ ] **Skip irrelevant payloads** based on fingerprint:
  - PHP target → drop ASP/ASPX/JSP shells from matrix
  - Linux target → use `id`/`uname`, not `whoami;ver`
  - Windows target → use `whoami && hostname && ver`, not `id`
  - nginx target → drop `.htaccess` module (no per-dir config)
  - Apache target → keep `.htaccess` AND `.user.ini` (PHP-FPM uses .user.ini)
- [ ] **Detect known CVEs by version** and record (not exploit unless asked):
  - Apache 2.4.49 / 2.4.50 → CVE-2021-41773/42013
  - PHP 8.0.x–8.3.x on Windows-CGI → CVE-2024-4577
  - Tomcat ≤ 7.0.79 → CVE-2017-12617 JSP-PUT
  - IIS 6 / older → CVE-2017-7269 PROPFIND
- [ ] **Robots / sitemap / OpenAPI** read once, cache for the run.

## 2. Endpoint discovery

- [ ] **Discover ALL upload endpoints, not the first.** Run every source:
  - brute-force common path list
  - same-host BFS crawl, depth ≥ 2, max-pages ≥ 20
  - JS bundle regex scrape (`fetch`, `axios.*`, `XMLHttpRequest`, named constants, URL strings in JS comments)
  - robots.txt `Disallow`/`Allow`/`Sitemap`
  - sitemap.xml `<loc>`
  - swagger/openapi `requestBody.content.multipart/form-data.*.binary` (extract field name)
  - OPTIONS Allow → WebDAV PUT/MKCOL
  - GraphQL multipart upload (Apollo spec)
- [ ] **One Endpoint per `<input type=file>`**, not per form. Forms with multiple file inputs (cover_image + gallery_pick) yield multiple endpoints.
- [ ] **Detect orphan file inputs** outside any `<form>` (drag-drop SPAs). Pair with JS-scraped POST URL.
- [ ] **Score and rank** by source confidence; merge scores when same URL appears in multiple sources.
- [ ] **Sanity-check the top candidate before attacking.** GET it; if 0 bytes or 4xx, that's a soft-fail signal — log it.
- [ ] **Per-endpoint method dispatch**: POST/PATCH → multipart; PUT → raw body with `Content-Type`. Never POST a WebDAV PUT-only endpoint.

## 3. Auto-harvest required form fields (HARD)

- [ ] **Parse every input/select/textarea in the parent `<form>`.** Build a dict of `{name: value}` with defaults from the rendered form.
- [ ] **Auto-fill plausible values** for unset fields:
  - `*email*` → `qa@example.test`
  - `*name*` → `John Doe`
  - `*phone*` → `5555550100`
  - `<select>` → first non-empty option's value
  - `submit`/`btn` → that input's `value=` attribute (e.g. `Purchase`, `Save`)
- [ ] **Always include the named submit button.** A surprising number of PHP backends gate on `isset($_POST['submit'])`. Silent HTTP 200 + 0 bytes is the canonical symptom.
- [ ] **Honor hidden fields verbatim** (`csrf_token`, `__VIEWSTATE`, `authenticity_token`, `_token`, nonces, ASP.NET event-validation). Re-fetch on rotation.
- [ ] **CAPTCHA detected** → surface to operator with `--captcha-prompt`; do not invent answers.

## 4. Authentication

- [ ] **Classify response as `ok | otp | fail`** with both body regex AND URL movement. Never default to "ok" on ambiguity.
- [ ] **Never report `True` for `login()` on:**
  - HTTP 4xx
  - Body containing `invalid|incorrect|wrong (password|credential)|denied|failed`
  - Redirect target still under the login URL prefix
- [ ] **Handle the full auth catalogue** automatically per `--basic-auth`/`--digest-auth`/`--ntlm-auth`/`--bearer`/`--api-key`/`--cert`/`--json-login`+`--token-path`+`--csrf-path`/multi-step wizard/`--otp-totp-secret`/`--otp-prompt`/`--otp-value`.
- [ ] **OTP detection requires BOTH** body pattern AND a code-shaped field (`name=code|otp|2fa|token|pin`). Single-signal triggers infinite-loop false positives.
- [ ] **Rotating CSRF**: re-extract on every response (JSON `csrf|next_csrf|_token`, meta tag, hidden field). Header name is whichever the page used.
- [ ] **Session-expiry guardian**: if any request after login redirects to login or returns 401, re-run the login flow and retry once. After 3 retries, abort.
- [ ] **Cookie scoping**: every `set_cookie` carries `domain=` (target host) + `path=/`. No globally-scoped cookies.

## 5. Bypass strategy (ordering + budget)

- [ ] **Stop on first confirmed RCE.** Never continue the matrix after a verified shell.
- [ ] **Ordering** (cheap → expensive):
  1. discovery + form-harvest + auto-detect
  2. `.htaccess` / `.user.ini` (32 tricks) — cheapest, highest hit-rate on Apache/PHP-FPM
  3. real polyglots (PNG-tEXt, JPEG-COM/EXIF/ICC, GIF, PDF, ZIP, SVG, Phar-JPEG, WebP, AVIF)
  4. parser-confusion (RFC 5987, RFC 2231, double-CD, NTFS ADS, U+FF0E, %00, double-ext)
  5. nginx/FPM/Tomcat/Jetty tricks
  6. IIS web.config (8 variants)
  7. full matrix (PHP-ext × shell × CT × inject-char)
  8. zip-slip / race / DoS / SVG XXE
- [ ] **Budget cap**: maximum 5,000 HTTP requests per target by default; abort with summary if reached. Configurable via `--request-budget`.
- [ ] **Skip ASP/JSP shells on PHP servers**, and vice versa.
- [ ] **Throttle**: respect `--delay`, `--jitter`, `--rate-limit`. Back off on 429/5xx with `Retry-After`. Detect WAF fingerprints (Cloudflare/ModSec/Sucuri/Imperva) and pause.

## 6. Payload selection

- [ ] **Polyglots must be REAL** — image polyglots pass `PIL.verify()`. Magic-byte-prefix + `<?php` is not a polyglot; reject from the catalogue.
- [ ] **Filename mutation matrix** must include double-ext (`shell.php.jpg`), reverse (`shell.jpg.php`), case (`shell.Php`), trailing dot/space (`shell.php.`/`shell.php<sp>`), null byte (`shell.php\x00.jpg`), NTFS ADS (`shell.php::$DATA`), unicode dot (`shell．php`), short-name (`shellxx~1.php`).
- [ ] **Content-Type spoofing**: try `image/jpeg`, `image/jpg`, `image/png`, `image/gif`, `image/svg+xml`, `multipart/form-data`, `application/octet-stream`, casing (`IMAGE/JPEG`), parameter pollution (`image/jpeg; charset=utf-8`).
- [ ] **`.htaccess` payloads end with `\n`**. No BOM. CRLF only when Apache 2.4. Pin in tests.
- [ ] **Honor `--extra-field NAME=VALUE`** on every upload, merged into multipart body.

## 7. Verification — ZERO false positives (HARD)

- [ ] **Nonce-wrap every RCE check**: `echo NONCE; <cmd>; echo NONCE` where NONCE is a fresh 16-byte UUID hex. Confirm response contains the nonce TWICE with content between.
- [ ] **Never accept "uid=" / "root" / "/bin" / "GIF89a" alone as proof.** They appear in unrelated pages.
- [ ] **OS-aware probe**: try `id` (Linux), fall back to `whoami` (works on both), to `cmd /c ver` (Windows). Confirm by nonce, not by command output.
- [ ] **Storage-path discovery**: prefer paths LEARNED from upload responses (`Location:`, JSON `path|url|file|src`, HTML `src=/href=`) over the 17-dir brute list.
- [ ] **Silent-200 detection**: if response is HTTP 200 with `Content-Length: 0` AND no discoverable path AND no redirect, treat as soft-fail. Surface to operator: "form likely incomplete — harvest hidden fields with --extra-field".
- [ ] **Soft-success markers** (e.g. "You will shortly receive payment link"): mark upload as "accepted-pending-verification"; never claim RCE until verified.

## 8. Multi-endpoint behavior

- [ ] **`--attack-all` iterates EVERY discovered endpoint**, not just the top one. Each endpoint gets:
  - its own field name
  - its own method (POST vs PUT vs PATCH)
  - the same payload suite (htaccess / polyglots / parser-confusion / matrix)
- [ ] **Aggregate report**: per-endpoint status, per-endpoint bypass that worked, per-endpoint discovered storage path.
- [ ] **Stop iteration on first confirmed RCE** unless `--exhaust` is set.

## 9. Reporting (HARD — honesty bar)

- [ ] **Distinguish four states in the report**:
  - `RCE_CONFIRMED` — nonce verifier returned True
  - `UPLOAD_ACCEPTED` — file landed; execution unverified
  - `FILTER_BYPASSED` — known filter signal disappeared; no upload yet
  - `FAILED` — explicit rejection or network failure
- [ ] **Never claim `RCE_CONFIRMED` without a logged nonce match.** Log: command sent, nonce, response excerpt containing both nonce occurrences.
- [ ] **Cite the exact bypass chain**: which `.htaccess` trick name, which filename, which content-type, which storage URL, which verifier command. A junior pentester should be able to reproduce by reading the report alone.
- [ ] **Surface QA gaps**: any module that could not run (missing dep, network failure, WAF block) must be listed under "did not exercise".
- [ ] **`uploadpwn_report.json`** is the source of truth — every assertion above appears as a structured field, not just printed.

## 10. Anti-patterns (NEVER DO)

- [ ] **Never** invent endpoints, paths, or output. If discovery returned nothing, say so.
- [ ] **Never** assume an unauthenticated 200 means success. Always GET the upload back or run nonce verifier.
- [ ] **Never** swallow exceptions with bare `except:`. Log + reraise or log + continue with reason.
- [ ] **Never** report RCE based on substring match alone.
- [ ] **Never** follow redirects to external domains carrying the session cookie or `Authorization` header.
- [ ] **Never** mutate the target beyond what's required for the test (no rm, no `del`, no DROP).
- [ ] **Never** skip the `.htaccess` cleanup at end of run when `--cleanup` is set — delete uploaded `.htaccess`/`.user.ini`/`web.config` artifacts.
- [ ] **Never** claim coverage you can't point at a passing test for. New techniques land with new tests.

## 11. Tool extensibility

- [ ] **New bypass = new entry in the catalogue + new pytest case.** Both, same PR.
- [ ] **Catalogue size pinned by tests** (≥30 htaccess, ≥8 webconfig, ≥12 nginx, ≥18 parser-confusion, ≥14 polyglots). Regression-guarded.
- [ ] **Every Endpoint source has a dedicated test** against the discovery mock. Don't merge a new source without one.

## 12. Operator UX

- [ ] **One-flag autopilot**: `--all` runs every module sensibly given the fingerprint. `--discover-only` runs reconnaissance and exits.
- [ ] **Burp `-r REQUEST_FILE`** is the source of truth when given; CLI flags override individual fields.
- [ ] **`--interactive` post-RCE** drops into a webshell REPL with built-ins: `!read`, `!ls`, `!find`, `!revshell IP PORT`, `!loot`.
- [ ] **Exit codes**: `0` = RCE confirmed; `1` = some upload accepted, RCE unverified; `2` = auth or discovery failed; `3` = network/target unreachable; `4` = budget exhausted.

---

### Definition of done for an "awesome" run

A run is **awesome** when, on a target with a working upload bypass, the tool:

1. Discovers the endpoint without operator hints,
2. Harvests required form fields automatically,
3. Picks the cheapest bypass that works,
4. Verifies RCE with a fresh nonce,
5. Reports the exact reproduction recipe (filename + CT + extra-fields + storage URL + command),
6. Has every step backed by a passing pytest case in the suite,
7. Does **not** report success for any step it did not verify.

If any of these is missing, the run is incomplete — even if a shell happens to land.
