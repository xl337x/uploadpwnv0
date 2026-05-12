"""
Mock target with FIVE distinct upload endpoints, each with its own quirk.

  /profile/avatar    — POST multipart, field "avatar", filter: must be image/* CT
  /profile/cover     — POST multipart, field "cover_image" — SAME form has TWO file inputs
                       (one is the cover, one is a hidden gallery picker)
  /docs/upload       — POST multipart, field "document", different page
  /api/v2/files      — POST multipart, field "file" — JSON success response
  /webdav/<name>     — PUT raw bytes (no form anywhere); OPTIONS Allow: PUT
  /admin/upload      — POST multipart, field "file", requires cookie role=admin
  /spa/upload        — drag-and-drop SPA, the input is <input type=file hidden> with
                       no enclosing form action — endpoint is in JS only:
                       fetch("/spa/api/files", {method:"POST"})

Every endpoint has DIFFERENT field names and DIFFERENT acceptance rules.
"""
import os
from flask import Flask, request, jsonify, make_response, Response

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploadpwn_multi_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _save(req, field):
    f = req.files.get(field)
    if not f:
        return None
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return f.filename


# ── 1. Avatar (image-CT only) ────────────────────────────────────────
@app.route("/profile/avatar", methods=["GET", "POST"])
def avatar():
    if request.method == "POST":
        f = request.files.get("avatar")
        if not f: return "missing avatar", 400
        if not (f.mimetype or "").startswith("image/"):
            return "must be image", 415
        _save(request, "avatar")
        return "ok", 200
    return ('<html><body><form action="/profile/avatar" method=post enctype=multipart/form-data>'
            '<input type=file name=avatar><button>Save</button></form></body></html>')


# ── 2. Cover image (form has TWO file inputs) ────────────────────────
@app.route("/profile/cover", methods=["GET", "POST"])
def cover():
    if request.method == "POST":
        _save(request, "cover_image")
        return "ok", 200
    return ('<html><body><form action="/profile/cover" method=post enctype=multipart/form-data>'
            '<input type=file name=cover_image>'
            # second input — hidden style, but still <input type=file>
            '<input type=file name=gallery_pick style="display:none">'
            '<button>Save</button></form></body></html>')


# ── 3. Document upload (different page, different field) ────────────
@app.route("/docs/upload", methods=["GET", "POST"])
def docs():
    if request.method == "POST":
        _save(request, "document")
        return "ok", 200
    return ('<html><body><form action="/docs/upload" method=post enctype=multipart/form-data>'
            '<input type=file name=document><button>Upload</button></form></body></html>')


# ── 4. JSON API endpoint ─────────────────────────────────────────────
@app.route("/api/v2/files", methods=["POST"])
def api():
    fn = _save(request, "file")
    if not fn: return jsonify({"error": "no file"}), 400
    return jsonify({"path": f"/api/v2/files/{fn}", "id": "x123"}), 200


# ── 5. WebDAV PUT ────────────────────────────────────────────────────
@app.route("/webdav/", methods=["OPTIONS"])
@app.route("/webdav/<path:fn>", methods=["OPTIONS", "PUT"])
def webdav(fn=None):
    if request.method == "OPTIONS":
        r = make_response("")
        r.headers["Allow"] = "GET, PUT, DELETE, OPTIONS, PROPFIND, MKCOL"
        r.headers["DAV"]   = "1, 2"
        return r
    open(os.path.join(UPLOAD_DIR, os.path.basename(fn)), "wb").write(request.get_data())
    return "", 201


# ── 6. Admin-gated upload ───────────────────────────────────────────
@app.route("/admin/upload", methods=["GET", "POST"])
def admin_upload():
    if request.cookies.get("role") != "admin":
        return "forbidden", 403
    if request.method == "POST":
        _save(request, "file")
        return "ok", 200
    return ('<html><body><form action="/admin/upload" method=post enctype=multipart/form-data>'
            '<input type=file name=file><button>Go</button></form></body></html>')


# ── 7. SPA drag-and-drop — file input has NO enclosing form action ──
@app.route("/spa/", methods=["GET"])
def spa():
    return ('<html><body><div id=drop>Drop files here</div>'
            '<input type=file name=files hidden>'   # no <form>!
            '<script src="/spa/app.js"></script></body></html>')


@app.route("/spa/app.js")
def spa_js():
    return Response(
        'document.querySelector("#drop").addEventListener("drop", e => {\n'
        '  const fd = new FormData(); fd.append("payload", e.dataTransfer.files[0]);\n'
        '  fetch("/spa/api/files", {method:"POST", body: fd});\n'
        '});\n', mimetype="application/javascript")


@app.route("/spa/api/files", methods=["POST"])
def spa_api():
    fn = _save(request, "payload")
    return jsonify({"path": f"/spa/files/{fn}"}), 200


# ── Landing page linking to several upload pages so crawl finds them ──
@app.route("/")
def root():
    return ('<html><body>'
            '<a href="/profile/avatar">avatar</a> '
            '<a href="/profile/cover">cover</a> '
            '<a href="/docs/upload">docs</a> '
            '<a href="/admin/upload">admin</a> '
            '<a href="/spa/">spa drop</a>'
            '</body></html>')


def run(port):
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
