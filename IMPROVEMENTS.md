# uploadpwn — Field-Trial Improvement Checklist

Derived from a live run against **Apache/2.4.48 (Win64) PHP/8.0.7** at
192.168.134.187 (HTB-style "Access The Event" box). The tool **worked**:
RCE confirmed in 12 audit events, 1 of 32 `.htaccess` tricks landed, the
storage path `/uploads/` was learned from the upload response, and the
nonce verifier matched first try.

Items below are what's worth tightening next, in priority order.

---

## A. High-impact — fix next

- [ ] **Artifact URLs are display strings, not real URLs.** Today the
      `.htaccess` artifact is recorded as
      `http://target/Ticket.php (.htaccess)` (literal parenthetical).
      `cleanup_artifacts` can't DELETE that. Record the **served path**
      learned from `extract_upload_path()` when available, and fall back
      to `target + dir + filename` for every `--shell-dirs` entry.

- [ ] **`--cleanup` cannot DELETE because the test was wrong.** Most
      stock Apache/IIS installs return 405 on DELETE. Add a `cleanup_via`
      strategy:
      1. Try HTTP DELETE on every learned served URL.
      2. If that 405s, *and* RCE is confirmed, issue `rm`/`del` via the
         live webshell — we already hold one.
      3. If neither works, surface the artifact paths in the report's
         "did not exercise" section.

- [ ] **Form harvesting is not yet enforced for `.htaccess` runs.**
      The live target accepted the `.htaccess` upload without the named
      submit button (`submit=Purchase`), the select default
      (`ticket-type=`), or the `your-name`/`your-email` fields. Lucky.
      Other PHP backends gate on `isset($_POST['submit'])` and silently
      drop the file with HTTP 200 + 0 bytes. Make `--field`-only runs
      still call `find_upload_field()`'s form-harvest to populate
      `default_extra_fields` automatically — operators forget.

- [ ] **Filter-probe leaks data about itself.** The `PROBE: .phtml
      accepted → blacklist is incomplete` line is printed before the
      operator knows what the probe even sent. Add a `--quiet-probe`
      mode that records to the report but suppresses chatty stdout, so
      live demos and CI logs are readable.

- [ ] **`extract_upload_path` only learns one path per upload.** On
      this box the response was a plain HTML page that quietly redirected
      to `/uploads/shell.jpg`; the verifier found it via the
      DEFAULT_SHELL_DIRS brute list, not from the response. Strengthen
      `extract_upload_path` to also follow the `Refresh:` header, parse
      `<meta http-equiv=refresh>`, and pull `window.location.href = "..."`
      from inline JS. These are common upload-confirmation patterns.

---

## B. Mid-impact — quality of life

- [ ] **Banner says v4.0**; this file is now feature-complete past
      that. Bump to v5.0 once the items in §A land, and stamp the
      version into `Discovery.save()` JSON for forensic traceability.

- [ ] **Report's "INFO" rows render as green "FOUND"** because
      `print_report` does `s['status'].upper()` without remapping to the
      DISCOVERED/BYPASSED/INFO label set used in the live log. Cosmetic
      but confusing: line 9 of the run output reads
      `FOUND probe SVG allowed → XXE/XSS surface` when it should be
      `DISCOVERED`. Use the same `tag` lookup that `Discovery.log()` uses.

- [ ] **Suggestions are unconditional.** The "Null byte works — server
      likely PHP <5.3.4" suggestion fired against PHP 8.0.7 — the null-byte
      acceptance there was due to extension-filter weakness, not the old
      < 5.3.4 bug. Gate suggestions on the fingerprint already in
      `EndpointDiscovery`. (We have Server: Apache 2.4.48, OpenSSL 1.1.1k,
      PHP 8.0.7 in scope — use it.)

- [ ] **CVE-2024-4577 (PHP-CGI on Windows) was not auto-detected.**
      The fingerprint string `PHP/8.0.7` + `Win64` matches the
      precondition. Module 1.5 (pre-flight reconnaissance) should record
      the CVE in `Discovery.suggestions` even when not exploited.

- [ ] **`--exhaust` only changes the outer `--attack-all` loop break.**
      The matrix, polyglots, parser-confusion, and nginx-tricks modules
      all return early on the first RCE per-endpoint. With `--exhaust`,
      they should fall through and keep mapping every viable bypass
      chain — useful for writing remediation reports.

- [ ] **Discovery scoring loses to brute-force on naïve targets.**
      Live result: form-found endpoint scored **1080** but two
      brute-found `/uploads` paths still appeared in the top-3 list.
      Drop brute candidates whose score is ≤ 5% of the form-found top
      to keep the operator's eye on the real target.

---

## C. Hardening & posture

- [ ] **`--i-am-authorized` is currently advisory.** The tool warns on
      absence but still proceeds. Either keep this (and document it in
      README), or move to "hard-refuse unless flag set OR `--target`
      resolves to RFC1918/loopback OR an `HTB_AUTHORIZED=1` env var is
      set". Pick one and pin it in a test.

- [ ] **WAF pause is per-request.** If the WAF flips a whole class of
      requests to 403, we sleep 3s × N — and burn the request budget on
      sleeps. Track consecutive WAF hits; after 3 in a row, bail with
      exit code 5 (new) and a clear "WAF locked us out, raise --delay
      or switch IP" message.

- [ ] **`--rate-limit` is min-spacing, not token-bucket.** Bursts that
      stay under the rate are punished the same as sustained traffic.
      Acceptable today, but document the limitation in `--help`.

- [ ] **No structured payload-trace log.** `payload_sha256` lives in
      `Discovery.steps` but the payload bodies themselves aren't kept.
      For repro, add `--save-payloads DIR` so each `record_upload_accepted`
      drops the bytes to `DIR/<sha256>.bin`. Bounded by `--request-budget`
      so we don't fill disk.

- [ ] **No second-stage credential carry-over.** Once RCE lands, the
      webshell REPL reads files but doesn't try `LaZagne`, `mimikatz`-
      lite, `/etc/shadow` dump, or AWS metadata. That's by design (the
      §0 anti-pattern bars cred-dumping without scope), but a
      `--post-rce-loot LEVEL` flag (none/conservative/aggressive) with
      explicit consent would be more honest than a hard no.

---

## D. UX — operator told us so

- [ ] **`--endpoint` now accepts five shapes** via `smart_endpoint`
      (path, bare filename, absolute http(s), schemeless host+path,
      protocol-relative). **Done** — pinned by 9 parametrized cases in
      `tests/test_checklist_v2.py::test_smart_endpoint_shapes`. Next:
      print the resolved URL + effective target in the banner so the
      operator can sanity-check before traffic flies.

- [ ] **`-t` alone is enough for HTB-style boxes.** On 192.168.134.187
      the tool found `/Ticket.php` + `the_file` purely from form-scrape
      — no `-e`/`--field` needed. Document this prominently in
      `--help` and README ("just point it at the URL").

- [ ] **`--all` is the wrong default** when the operator hasn't asked.
      Currently a flag-less run falls into the matrix (3 192-line
      filename combinations × shells × CTs) which can easily blow the
      budget. Add a `[*]  No modules selected — running --htaccess +
      --polyglots + --matrix (cheapest first)` notice so the operator
      knows what they're getting.

- [ ] **Burp `-r` should detect host:port mismatch with `-t`** and
      warn before the run. Today it silently retargets, which is right
      most of the time but bites the one time it isn't.

---

## E. Coverage gaps observed on this run

- [ ] **No HTTP/2 or HTTP/3 path.** requests is HTTP/1.1 only. Modern
      WAFs (Cloudflare Turnstile, AWS WAFv2) sometimes treat HTTP/1.1
      and HTTP/2 differently. Out of scope today, but record it as a
      known limitation in README.

- [ ] **Polyglot module skipped on this target** (it ran `.htaccess`
      first and exited on RCE — correct ordering). Confirm polyglot
      coverage on a target with a strict image-only filter by adding a
      `tests/scenarios/strict_imagemagick.py` fixture target.

- [ ] **Multi-file `<input type=file multiple>` is not exercised.**
      The discovery code splits on per-input, but the matrix issues
      one file per request. Add a `--multipart-burst N` flag and pin
      a test fixture that requires the burst to bypass per-file
      validation but allow the Nth file through.

---

## F. Done in this pass (for diff context)

- [x] `--i-am-authorized`, `--captcha-prompt`, `--request-budget`,
      `--rate-limit`, `--exhaust`, `--cleanup`, `--waf-pause` CLI flags
- [x] 4-state report (`RCE_CONFIRMED / UPLOAD_ACCEPTED /
      FILTER_BYPASSED / FAILED`) with per-state counters
- [x] Payload SHA-256 in audit log (`payload_sha256` per step)
- [x] WAF auto-pause via `detect_waf` → `time.sleep(waf_pause)`
- [x] Artifact tracking + best-effort `--cleanup` DELETE pass
- [x] Exit codes 0/1/2/3/4 (RCE / no-RCE / auth-fail / unreachable / budget)
- [x] 17-dir `DEFAULT_SHELL_DIRS`
- [x] Bare `except:` → `except Exception:`
- [x] `smart_endpoint()` accepts 5 endpoint shapes
- [x] 82/82 tests pass (60 original + 13 new + 9 endpoint shapes)
