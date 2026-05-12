"""
Checklist v2 — pin the new features required by AI_CHECKLIST.md:
  • RequestBudgetExceeded fires at the configured cap
  • Discovery.outcomes increments per state
  • payload_hash is deterministic SHA-256
  • record_artifact appends to Discovery.artifacts
  • cleanup_artifacts deletes via session.delete
  • CAPTCHA_PATTERNS catches common providers
  • DEFAULT_SHELL_DIRS has at least 17 entries
"""
import pytest
import requests
from unittest.mock import MagicMock
from uploadpwn import (
    SessionManager, TransportConfig, Discovery, RequestBudgetExceeded,
    payload_hash, CAPTCHA_PATTERNS, DEFAULT_SHELL_DIRS, cleanup_artifacts,
    smart_endpoint,
    STATE_RCE_CONFIRMED, STATE_UPLOAD_ACCEPTED, STATE_FILTER_BYPASSED, STATE_FAILED,
)


# ─── --endpoint shape resolution (smart_endpoint) ────────────────────────────
@pytest.mark.parametrize("target,endpoint,want_url,want_target", [
    # plain path-only — most common
    ("http://10.0.0.1",       "/upload.php",
     "http://10.0.0.1/upload.php",            "http://10.0.0.1"),
    # path with leading slash on a target that has a trailing slash already
    ("http://10.0.0.1/",      "/api/upload",
     "http://10.0.0.1/api/upload",            "http://10.0.0.1"),
    # bare relative filename — joined to target
    ("http://10.0.0.1",       "upload.php",
     "http://10.0.0.1/upload.php",            "http://10.0.0.1"),
    # absolute URL on a different host — effective target swaps
    ("http://10.0.0.1",       "http://other.tld/u.php",
     "http://other.tld/u.php",                "http://other.tld"),
    # absolute https URL on a different host
    ("http://10.0.0.1",       "https://other.tld:8443/u.php",
     "https://other.tld:8443/u.php",          "https://other.tld:8443"),
    # schemeless host+path — inherits scheme from target
    ("http://10.0.0.1",       "other.tld/u.php",
     "http://other.tld/u.php",                "http://other.tld"),
    # schemeless host:port+path
    ("https://10.0.0.1",      "other.tld:9000/u.php",
     "https://other.tld:9000/u.php",          "https://other.tld:9000"),
    # protocol-relative URL
    ("https://10.0.0.1",      "//other.tld/u.php",
     "https://other.tld/u.php",               "https://other.tld"),
    # endpoint is empty → target as-is
    ("http://10.0.0.1",       "",
     "http://10.0.0.1",                       "http://10.0.0.1"),
])
def test_smart_endpoint_shapes(target, endpoint, want_url, want_target):
    full, eff = smart_endpoint(target, endpoint)
    assert full == want_url
    assert eff == want_target


def test_default_shell_dirs_has_17_entries():
    assert len(DEFAULT_SHELL_DIRS) >= 17


def test_payload_hash_is_deterministic():
    assert payload_hash(b"hello") == payload_hash(b"hello")
    assert payload_hash(b"hello") != payload_hash(b"world")
    assert len(payload_hash(b"x")) == 64
    assert payload_hash(None) is None


def test_payload_hash_accepts_str_and_bytes():
    assert payload_hash("abc") == payload_hash(b"abc")


def test_captcha_patterns_catches_recaptcha_and_hcaptcha():
    assert CAPTCHA_PATTERNS.search('<script src="https://www.google.com/recaptcha/api.js"></script>')
    assert CAPTCHA_PATTERNS.search('<div class="h-captcha" data-sitekey="x"></div>')
    assert CAPTCHA_PATTERNS.search('<input name="g-recaptcha-response" value="">')
    assert not CAPTCHA_PATTERNS.search("<html><body>hello</body></html>")


def test_discovery_outcomes_state_counters():
    d = Discovery("http://t")
    d.log("upload", "found", "ok", state=STATE_UPLOAD_ACCEPTED)
    d.log("upload", "found", "ok", state=STATE_UPLOAD_ACCEPTED)
    d.log("filter", "bypassed", "ok", state=STATE_FILTER_BYPASSED)
    d.log("upload", "failed", "nope", state=STATE_FAILED)
    assert d.outcomes[STATE_UPLOAD_ACCEPTED] == 2
    assert d.outcomes[STATE_FILTER_BYPASSED] == 1
    assert d.outcomes[STATE_FAILED] == 1
    assert d.outcomes[STATE_RCE_CONFIRMED] == 0


def test_discovery_record_rce_sets_state_and_target():
    d = Discovery("http://t")
    d.record_rce("shell.php", "http://t/shell.php", "uid=0(root)", "standard", "image/jpeg")
    assert d.outcomes[STATE_RCE_CONFIRMED] == 1
    last = d.steps[-1]
    assert last["state"] == STATE_RCE_CONFIRMED
    assert last["target"] == "http://t/shell.php"


def test_record_upload_accepted_includes_payload_hash():
    d = Discovery("http://t")
    d.record_upload_accepted("a.jpg", "http://t/u", "image/jpeg", payload=b"GIF89a")
    last = d.steps[-1]
    assert last["state"] == STATE_UPLOAD_ACCEPTED
    assert last["payload_sha256"] == payload_hash(b"GIF89a")


def test_record_artifact_appends():
    d = Discovery("http://t")
    d.record_artifact("http://t/u", ".htaccess", kind="htaccess")
    d.record_artifact("http://t/u", "web.config", kind="web_config")
    assert len(d.artifacts) == 2
    assert d.artifacts[0]["filename"] == ".htaccess"
    assert d.artifacts[1]["type"] == "web_config"


def test_cleanup_artifacts_calls_delete_and_drains_on_success():
    d = Discovery("http://t")
    d.record_artifact("http://t/upload", "shell.php", kind="shell")
    session = MagicMock()
    session.delete.return_value = MagicMock(status_code=204)
    deleted, remaining = cleanup_artifacts(d, session, "http://t")
    assert deleted == 1
    assert remaining == 0
    assert d.artifacts == []
    assert session.delete.called


def test_cleanup_artifacts_keeps_failures():
    d = Discovery("http://t")
    d.record_artifact("http://t/upload", "shell.php", kind="shell")
    session = MagicMock()
    session.delete.return_value = MagicMock(status_code=500)
    deleted, remaining = cleanup_artifacts(d, session, "http://t")
    assert deleted == 0
    assert remaining == 1
    assert len(d.artifacts) == 1


def test_request_budget_raises_when_exhausted(monkeypatch):
    tc = TransportConfig(request_budget=2, waf_pause=0)
    sm = SessionManager(target="http://t", transport=tc)
    # Stub out the real network call so we exercise only the budget guard.
    monkeypatch.setattr(sm.session, "request",
                        lambda *a, **kw: MagicMock(status_code=200, text="",
                                                   headers={}, url="http://t/"))
    sm._request("GET", "http://t/a")
    sm._request("GET", "http://t/b")
    with pytest.raises(RequestBudgetExceeded):
        sm._request("GET", "http://t/c")
    assert tc.requests_sent == 2


def test_request_budget_zero_means_unlimited(monkeypatch):
    tc = TransportConfig(request_budget=0, waf_pause=0)
    sm = SessionManager(target="http://t", transport=tc)
    monkeypatch.setattr(sm.session, "request",
                        lambda *a, **kw: MagicMock(status_code=200, text="",
                                                   headers={}, url="http://t/"))
    for _ in range(10):
        sm._request("GET", "http://t/")
    assert tc.requests_sent == 10


def test_rate_limit_spaces_requests(monkeypatch):
    import time as _time
    tc = TransportConfig(rate_limit=10, waf_pause=0)  # 10 RPS → ≥0.1s gap
    sm = SessionManager(target="http://t", transport=tc)
    monkeypatch.setattr(sm.session, "request",
                        lambda *a, **kw: MagicMock(status_code=200, text="",
                                                   headers={}, url="http://t/"))
    start = _time.time()
    sm._request("GET", "http://t/")
    sm._request("GET", "http://t/")
    sm._request("GET", "http://t/")
    elapsed = _time.time() - start
    # 3 requests at 10 RPS → at least ~0.2s of forced spacing between them
    assert elapsed >= 0.18, f"rate-limit spacing too tight: {elapsed:.3f}s"
