"""
Hard-scenario tests — exercise EVERY auth type, transport quirk, and
session-state pitfall the QA agents flagged. Each test pins one capability.
"""
import os, time, pytest, pyotp
from uploadpwn import (
    SessionManager, BurpRequest, TransportConfig, AuthAdapter,
    extract_upload_path, NonceVerifier, join_url,
)


# ── HTTP Basic ─────────────────────────────────────────────────────────────
def test_http_basic_auth(hard):
    sm = SessionManager(target=hard, transport=TransportConfig())
    sm.set_auth(AuthAdapter.basic("admin", "hunter2"))
    r = sm.upload(join_url(hard, "/basic-zone/upload"),
                  field="file", filename="a.txt",
                  content=b"x", content_type="text/plain")
    assert r.status_code == 200


# ── Bearer / JWT login + use ──────────────────────────────────────────────
def test_bearer_jwt_flow(hard):
    sm = SessionManager(target=hard, transport=TransportConfig())
    tok = sm.login_json(join_url(hard, "/bearer/login"),
                        body={"username": "admin", "password": "hunter2"},
                        token_path="access_token")
    assert tok and "." in tok
    sm.set_auth(AuthAdapter.bearer(tok))
    r = sm.upload(join_url(hard, "/bearer/upload"),
                  field="file", filename="a.txt",
                  content=b"x", content_type="text/plain")
    assert r.status_code == 200
    # path discovery from JSON
    path = extract_upload_path(r)
    assert path and path.startswith("/hash/files/")


# ── JSON-body SPA login + rotating CSRF ────────────────────────────────────
def test_spa_json_login_with_rotating_csrf(hard):
    sm = SessionManager(target=hard, transport=TransportConfig())
    sm.login_json(join_url(hard, "/spa/login"),
                  body={"username": "admin", "password": "hunter2"},
                  csrf_path="csrf",
                  csrf_header="X-CSRF-Token")
    # first upload — must rotate token for the next call
    r1 = sm.upload(join_url(hard, "/spa/upload"),
                   field="file", filename="a.txt",
                   content=b"x", content_type="text/plain")
    assert r1.status_code == 200
    # session manager must have refreshed CSRF from response
    r2 = sm.upload(join_url(hard, "/spa/upload"),
                   field="file", filename="b.txt",
                   content=b"y", content_type="text/plain")
    assert r2.status_code == 200, "rotating CSRF must be re-extracted between uploads"


# ── Multi-step wizard ──────────────────────────────────────────────────────
def test_multi_step_wizard(hard):
    sm = SessionManager(target=hard, transport=TransportConfig(),
                        otp_totp_secret="JBSWY3DPEHPK3PXP")
    sm.run_steps([
        {"url": "/wizard/step1", "data": {"username": "admin"}, "next": "json"},
        {"url": "/wizard/step2", "data": {"password": "hunter2"}, "next": "json"},
        {"url": "/wizard/step3", "data": {"code": "{otp}"}, "next": None},
    ])
    r = sm.upload(join_url(hard, "/wizard/upload"),
                  field="file", filename="a.txt",
                  content=b"x", content_type="text/plain")
    assert r.status_code == 200


# ── Rate-limit handling: every 7th req returns 429 ────────────────────────
def test_retry_on_429(hard):
    sm = SessionManager(target=hard,
                        transport=TransportConfig(retries=3, backoff=0.1))
    ok = 0
    for _ in range(10):
        r = sm.upload(join_url(hard, "/flaky/upload"),
                      field="file", filename="x", content=b"x",
                      content_type="text/plain")
        if r.status_code == 200:
            ok += 1
    assert ok == 10, "retry-on-429 must transparently recover all 10 uploads"


# ── WAF detection — payloads with <?php should be recognized as blocked ──
def test_waf_detection(hard):
    sm = SessionManager(target=hard, transport=TransportConfig())
    r = sm.upload(join_url(hard, "/waf/upload"),
                  field="file", filename="shell.php",
                  content=b"<?php system($_GET[0]); ?>",
                  content_type="application/x-php")
    assert sm.detect_waf(r) is True


# ── Session-expiry mid-scan: auto re-login when redirected to /login ──────
def test_session_expiry_auto_relogin(hard):
    sm = SessionManager(
        target=hard, transport=TransportConfig(),
        login_url=join_url(hard, "/expiring/login"),
        creds={"username": "admin", "password": "hunter2"},
        relogin_on_expiry=True,
    )
    # initial login
    sm.session.post(join_url(hard, "/expiring/login"),
                    data={"username": "admin", "password": "hunter2"})
    # 5 succeed, 6th would 302 → tool must re-login and retry
    successes = 0
    for _ in range(8):
        r = sm.upload(join_url(hard, "/expiring/upload"),
                      field="file", filename="x", content=b"x",
                      content_type="text/plain")
        if r.status_code == 200:
            successes += 1
    assert successes == 8, "expired-session uploads must be auto re-logged"


# ── Path discovery from JSON response ─────────────────────────────────────
def test_path_discovery_json(hard):
    sm = SessionManager(target=hard, transport=TransportConfig())
    r = sm.upload(join_url(hard, "/hash/upload"),
                  field="file", filename="shell.txt",
                  content=b"hello", content_type="text/plain")
    path = extract_upload_path(r)
    assert path == "/hash/files/aaf4c61ddcc5e8a2.bin"  # sha1("hello")[:16]


# ── Nonce-based RCE verification eliminates false positives ───────────────
def test_nonce_verifier_rejects_false_positive():
    nv = NonceVerifier()
    cmd, nonce = nv.make("id")
    # the cmd must contain markers AND id
    assert nonce in cmd and "id" in cmd
    assert nv.confirm(f"prefix {nonce} uid=33(www-data) {nonce} suffix", nonce) is True
    assert nv.confirm("uid=33(www-data)", nonce) is False, \
        "page that mentions uid= without the nonce must NOT be flagged as RCE"


# ── -r Burp request parsing ───────────────────────────────────────────────
def test_burp_request_parse(tmp_path, hard):
    raw = (
        b"POST /raw/upload HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"X-Raw-Token: secret\r\n"
        b"Content-Type: multipart/form-data; boundary=----X\r\n"
        b"\r\n"
        b"------X\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"hello\r\n"
        b"------X--\r\n"
    )
    p = tmp_path / "req.txt"
    p.write_bytes(raw)

    br = BurpRequest.from_file(str(p))
    assert br.method == "POST"
    assert br.path == "/raw/upload"
    assert br.headers["X-Raw-Token"] == "secret"
    assert br.upload_field == "file"
    assert br.upload_filename == "a.txt"

    # retarget to live mock + replay
    br.retarget(hard)
    r = br.replay_with_payload(filename="shell.php",
                               content=b"<?php phpinfo(); ?>",
                               content_type="application/x-php")
    assert r.status_code == 200


# ── Cookie scoping: cross-host cookies must NOT leak ─────────────────────
def test_cookie_scoping():
    sm = SessionManager(target="http://app.example.com",
                        transport=TransportConfig(),
                        extra_cookies=["SESS=abc"])
    cookies = list(sm.session.cookies)
    assert any(c.domain in ("app.example.com", ".example.com")
               for c in cookies if c.name == "SESS"), \
        "manually-injected cookies must be scoped to target host"


# ── TransportConfig wires proxy/insecure/timeout/user-agent ──────────────
def test_transport_config():
    t = TransportConfig(proxy="http://127.0.0.1:8080",
                        insecure=True, timeout=7, user_agent="UPWN/5")
    sm = SessionManager(target="http://x", transport=t)
    assert sm.session.proxies.get("http") == "http://127.0.0.1:8080"
    assert sm.session.verify is False
    assert sm.session.headers["User-Agent"] == "UPWN/5"


# ── Classifier no longer false-positives on /email-verify-success ────────
def test_classifier_no_otp_false_positive():
    from uploadpwn import classify_response
    class Fake:
        text = "<html><body>Email verify success! Welcome dashboard.</body></html>"
        url  = "https://target/email-verify-success"
    # body has 'welcome' / 'dashboard' — must classify ok, not otp
    assert classify_response(Fake(), login_url="https://target/login") == "ok"


# ── BurpRequest body remains bytes (binary-safe) ─────────────────────────
def test_burp_request_binary_body(tmp_path):
    raw = (
        b"POST /x HTTP/1.1\r\nHost: t\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 5\r\n\r\n\x00\x01\x02\xff\xfe"
    )
    p = tmp_path / "bin.txt"
    p.write_bytes(raw)
    br = BurpRequest.from_file(str(p))
    assert br.body == b"\x00\x01\x02\xff\xfe"
