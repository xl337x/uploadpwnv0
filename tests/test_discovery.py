"""
Endpoint-discovery tests. Each pins one source-of-truth that the tool
must mine: HTML crawl, JS bundle, robots.txt, sitemap.xml, swagger,
OPTIONS/WebDAV, GraphQL. The mock hides the upload behind ALL of these.
"""
import pytest, requests
from uploadpwn import EndpointDiscovery, TransportConfig


def _disc(target):
    return EndpointDiscovery(target=target, transport=TransportConfig(timeout=5))


# ── 1. HTML crawl: form lives on /profile/edit, not / ────────────────
def test_finds_endpoint_via_crawl(disco):
    d = _disc(disco)
    eps = d.discover()
    found = [e for e in eps if e.url.endswith("/api/v2/upload")]
    assert found, f"crawl must find /api/v2/upload via /profile/edit; got {[e.url for e in eps]}"
    e = found[0]
    assert e.method == "POST"
    assert e.field  == "attachment"


# ── 2. JS bundle mining: fetch("/api/v2/upload") in app.js ──────────
def test_js_bundle_yields_candidates(disco):
    d = _disc(disco)
    urls = d._scan_js(disco + "/static/app.js")
    assert "/api/v2/upload" in urls
    # legacy mentioned in JS comment must also be picked up
    assert any("/legacy/upload.php" in u for u in urls)


# ── 3. robots.txt ────────────────────────────────────────────────────
def test_robots_txt_disallow(disco):
    d = _disc(disco)
    urls = d._scan_robots()
    assert "/secret-upload" in urls
    assert "/admin/" in urls


# ── 4. sitemap.xml ──────────────────────────────────────────────────
def test_sitemap_xml(disco):
    d = _disc(disco)
    urls = d._scan_sitemap()
    assert "/admin/files"   in urls
    assert "/api/v3/files"  in urls


# ── 5. OpenAPI / swagger.json ───────────────────────────────────────
def test_swagger_openapi_multipart(disco):
    d = _disc(disco)
    found = d._scan_openapi()
    paths = {e["path"]: e for e in found}
    assert "/api/v3/files" in paths
    assert paths["/api/v3/files"]["field"] == "binary"
    assert paths["/api/v3/files"]["method"] == "POST"


# ── 6. OPTIONS / WebDAV: PUT discoverable via Allow header ─────────
def test_options_webdav_put(disco):
    d = _disc(disco)
    allowed = d._scan_options(disco + "/webdav/")
    assert "PUT" in allowed
    assert "PROPFIND" in allowed


def test_webdav_detected_as_endpoint(disco):
    d = _disc(disco)
    eps = d.discover()
    webdav = [e for e in eps if e.method == "PUT" and "/webdav/" in e.url]
    assert webdav, "PUT-capable WebDAV path must be reported"


# ── 7. GraphQL multipart upload detection ───────────────────────────
def test_graphql_detected(disco):
    d = _disc(disco)
    eps = d.discover()
    gql = [e for e in eps if e.url.endswith("/graphql")]
    assert gql, "/graphql must be reported as a possible upload endpoint"


# ── 8. Ranking: every endpoint must be POST-or-PUT verified live ──
def test_endpoints_are_live_and_ranked(disco):
    d = _disc(disco)
    eps = d.discover()
    assert len(eps) >= 3
    # ranked: those with a known field name + 2xx-on-empty-probe go first
    for e in eps[:3]:
        assert e.score > 0


# ── 9. Brute force of common paths catches /legacy/upload.php ──────
def test_brute_force_common_paths(disco):
    d = _disc(disco)
    # The probe should at least try /upload.php, /upload, /api/upload, etc.
    tried = d._brute_common(disco)
    common = {"/upload.php", "/upload", "/api/upload", "/files/upload",
              "/api/v1/upload", "/wp-admin/async-upload.php"}
    assert common.issubset(set(tried)), f"missing common paths: {common - set(tried)}"


# ── 10. End-to-end: discover + replay a small upload to top result ─
def test_end_to_end_discover_and_upload(disco):
    d = _disc(disco)
    eps = d.discover()
    multipart_eps = [e for e in eps if e.method == "POST" and e.field]
    assert multipart_eps, "no multipart POST endpoint discovered"
    top = multipart_eps[0]
    r = requests.post(top.url, files={top.field: ("x.txt", b"hi", "text/plain")})
    assert r.status_code == 200
