"""
Multi-endpoint coverage tests. A real site rarely has just one upload page.
These tests pin: discovery finds ALL pages, multi-input forms yield multiple
endpoints, PUT-only endpoints are attacked correctly, and --attack-all
iterates every one of them.
"""
import requests, pytest
from uploadpwn import EndpointDiscovery, TransportConfig, MultiEndpointAttacker


def _disc(target):
    return EndpointDiscovery(target=target, transport=TransportConfig(timeout=5),
                             depth=2, max_pages=30)


# ── 1. All five distinct upload pages must be found ────────────────
def test_discovers_all_five_upload_pages(multi):
    eps = _disc(multi).discover()
    urls = {e.url for e in eps}
    # the five primary ones
    for must in ("/profile/avatar", "/profile/cover", "/docs/upload",
                 "/api/v2/files", "/admin/upload"):
        assert any(u.endswith(must) for u in urls), \
            f"discovery missed {must}; found {urls}"
    # plus the SPA endpoint from JS scrape
    assert any(u.endswith("/spa/api/files") for u in urls), \
        "SPA endpoint from JS bundle not discovered"
    # plus PUT-only WebDAV
    assert any(e.method == "PUT" and "/webdav/" in e.url for e in eps), \
        "WebDAV PUT endpoint not reported"


# ── 2. Form with TWO file inputs yields TWO endpoints ─────────────
def test_multi_file_input_form_yields_multiple_endpoints(multi):
    eps = _disc(multi).discover()
    cover_eps = [e for e in eps if e.url.endswith("/profile/cover")]
    fields = {e.field for e in cover_eps}
    assert "cover_image" in fields, f"missed cover_image; fields={fields}"
    assert "gallery_pick" in fields, "hidden display:none file input must still be reported"


# ── 3. Per-endpoint method dispatch — PUT vs POST ─────────────────
def test_put_endpoint_has_put_method(multi):
    eps = _disc(multi).discover()
    put_eps = [e for e in eps if e.method == "PUT"]
    assert put_eps, "no PUT endpoints discovered"
    for e in put_eps:
        assert "webdav" in e.url.lower() or "dav" in e.url.lower()


# ── 4. Each endpoint has distinct field name ──────────────────────
def test_field_names_are_distinct_per_endpoint(multi):
    eps = _disc(multi).discover()
    # collect endpoints with known fields
    by_url = {}
    for e in eps:
        if e.field:
            by_url.setdefault(e.url, set()).add(e.field)
    distinct_fields = set()
    for f in by_url.values():
        distinct_fields |= f
    # at least 4 different field names from {avatar, cover_image, gallery_pick, document, file}
    assert len(distinct_fields & {"avatar", "cover_image", "gallery_pick",
                                  "document", "file"}) >= 4, \
        f"only got {distinct_fields}"


# ── 5. SPA hidden input + JS endpoint detection ───────────────────
def test_spa_drag_drop_endpoint_via_js(multi):
    d = _disc(multi)
    urls = d._scan_js(multi + "/spa/app.js")
    assert "/spa/api/files" in urls


# ── 6. MultiEndpointAttacker dispatches across every endpoint ─────
def test_multi_endpoint_attacker_iterates_all(multi):
    eps = _disc(multi).discover()
    # Filter to multipart-POST endpoints with known fields (avatar/cover/docs/api/spa)
    targets = [e for e in eps if e.method == "POST" and e.field]
    assert len(targets) >= 4

    mea = MultiEndpointAttacker(endpoints=targets,
                                transport=TransportConfig(timeout=5))
    # benign upload to each — proves attacker actually drives every one
    results = mea.probe_each(content=b"hello",
                             filename="probe.txt",
                             content_type="image/jpeg")  # avatar will 415 → fine
    # Every target must have been probed
    assert len(results) == len(targets), \
        f"only probed {len(results)} of {len(targets)} endpoints"
    # At least 2 must have returned a 2xx (avatar 415 is fine, docs/api/cover should pass)
    twos = [r for r in results if r["status"] // 100 == 2]
    assert len(twos) >= 3, f"expected 3+ 2xx, got {[r['status'] for r in results]}"


# ── 7. MultiEndpointAttacker per-endpoint method routing ─────────
def test_multi_endpoint_attacker_routes_put_to_put_endpoint(multi):
    eps = _disc(multi).discover()
    put_ep = next(e for e in eps if e.method == "PUT")
    mea = MultiEndpointAttacker(endpoints=[put_ep],
                                transport=TransportConfig(timeout=5))
    res = mea.probe_each(content=b"raw-bytes", filename="x.bin",
                         content_type="application/octet-stream")
    assert res[0]["status"] in (200, 201), \
        f"PUT endpoint not driven correctly: {res}"
    assert res[0]["method"] == "PUT"


# ── 8. Aggregate report sums per-endpoint outcomes ───────────────
def test_multi_endpoint_attacker_summary(multi):
    eps = _disc(multi).discover()
    targets = [e for e in eps if e.method in ("POST", "PUT")][:5]
    mea = MultiEndpointAttacker(endpoints=targets,
                                transport=TransportConfig(timeout=5))
    mea.probe_each(content=b"x", filename="x.txt", content_type="text/plain")
    summary = mea.summary()
    assert summary["total"]  == len(targets)
    assert summary["ok"]     >= 1
    assert "by_endpoint" in summary
    assert len(summary["by_endpoint"]) == len(targets)
