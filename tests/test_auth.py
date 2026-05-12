"""
Failure tests for uploadpwn.SessionManager.

Each test pins down ONE real-world auth bug. They are written to PASS once the
fixes land — run them against the current code first and watch them burn.
"""
import pytest, pyotp, requests
from uploadpwn import SessionManager


# ── 1. Wrong creds must NOT report success ──────────────────────────────────
def test_bad_credentials_return_false(target):
    sm = SessionManager(target=target,
                        login_url=target + "/login-simple",
                        creds={"username": "admin", "password": "WRONG"})
    assert sm.login_requests() is False, \
        "Login with bad creds must return False (today it returns True)"


def test_good_credentials_return_true(target):
    sm = SessionManager(target=target,
                        login_url=target + "/login-simple",
                        creds={"username": "admin", "password": "hunter2"})
    assert sm.login_requests() is True
    assert sm.session.cookies.get("authed") == "yes"


# ── 2. Meta-tag CSRF must be sent as X-CSRF-Token header ───────────────────
def test_meta_csrf_header_is_sent(target):
    sm = SessionManager(target=target,
                        login_url=target + "/login-csrf",
                        creds={"username": "admin", "password": "hunter2"})
    assert sm.login_requests() is True, \
        "Meta-tag CSRF token must be injected as X-CSRF-Token header"
    assert sm.session.cookies.get("authed") == "yes"


# ── 3. OTP / 2FA must be detected and handled ──────────────────────────────
def test_otp_detected_without_handler_returns_false(target):
    """When OTP is required and no handler is configured, login must fail."""
    sm = SessionManager(target=target,
                        login_url=target + "/login-otp",
                        creds={"username": "admin", "password": "hunter2"})
    assert sm.login_requests() is False, \
        "Reaching the OTP page is NOT a successful login"


def test_otp_with_totp_secret(target):
    sm = SessionManager(target=target,
                        login_url=target + "/login-otp",
                        creds={"username": "admin", "password": "hunter2"},
                        otp_totp_secret="JBSWY3DPEHPK3PXP")
    assert sm.login_requests() is True
    assert sm.session.cookies.get("authed") == "yes"


def test_otp_with_static_value(target):
    code = pyotp.TOTP("JBSWY3DPEHPK3PXP").now()
    sm = SessionManager(target=target,
                        login_url=target + "/login-otp",
                        creds={"username": "admin", "password": "hunter2"},
                        otp_value=code)
    assert sm.login_requests() is True


# ── 4. Malformed --header must not crash the tool ──────────────────────────
def test_malformed_header_is_skipped_not_crash(target):
    SessionManager(target=target, extra_headers=["BrokenNoColon", "X-Ok: yes"])
    # If we got here, it didn't ValueError. Good.


def test_malformed_cookie_is_skipped_not_crash(target):
    SessionManager(target=target, extra_cookies=["nopair", "k=v"])


# ── 5. Endpoint join must use urljoin, not raw concat ──────────────────────
def test_endpoint_without_leading_slash_joins_correctly():
    from uploadpwn import join_url
    assert join_url("http://t:8080", "upload.php")  == "http://t:8080/upload.php"
    assert join_url("http://t:8080", "/upload.php") == "http://t:8080/upload.php"
    assert join_url("http://t:8080/", "upload.php") == "http://t:8080/upload.php"
    assert join_url("http://t:8080", "http://other/x") == "http://other/x"
