"""
Mock target where the upload endpoint is hidden by EVERY known mechanism.

  /                       → landing page; HTML has NO file input
                            but has a link to /profile/edit and a <script src=/static/app.js>
  /static/app.js          → mentions fetch("/api/v2/upload") and axios.post('/api/v2/upload')
  /profile/edit           → contains the actual <form action=/api/v2/upload enctype=multipart>
  /api/v2/upload          → POST multipart accepted (field name "attachment")
  /robots.txt             → "Disallow: /secret-upload"
  /sitemap.xml            → lists /admin/files
  /admin/files            → another upload form
  /swagger.json           → OpenAPI spec mentioning /api/v3/files
  /api/v3/files           → POST multipart (field "binary")
  /webdav/                → OPTIONS returns Allow: PUT, PROPFIND, GET (no form anywhere)
  /webdav/<name>          → PUT accepted
  /graphql                → POST with operations multipart-spec accepted

The challenge for the tool: with only a `--target` URL, find them all.
"""
import os
from flask import Flask, request, jsonify, Response, make_response

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploadpwn_disco_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route("/")
def root():
    return (
        '<html><body>'
        '<h1>Hello</h1>'
        '<a href="/profile/edit">edit profile</a> · '
        '<a href="/admin/files">admin</a>'
        '<script src="/static/app.js"></script>'
        '</body></html>'
    )


@app.route("/static/app.js")
def js():
    return Response(
        'const URL_UPLOAD = "/api/v2/upload";\n'
        'fetch(URL_UPLOAD, {method:"POST", body: new FormData(form)});\n'
        'axios.post("/api/v2/upload", fd, {headers:{"Content-Type":"multipart/form-data"}});\n'
        '// debug: XMLHttpRequest fallback /legacy/upload.php\n',
        mimetype="application/javascript")


@app.route("/profile/edit")
def profile_edit():
    return (
        '<html><body>'
        '<form action="/api/v2/upload" method="post" enctype="multipart/form-data">'
        '  <input type="file" name="attachment">'
        '  <button>Save</button>'
        '</form></body></html>'
    )


@app.route("/api/v2/upload", methods=["POST"])
def api_v2_upload():
    f = request.files.get("attachment")
    if not f:
        return "missing field 'attachment'", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return jsonify({"path": f"/api/v2/files/{f.filename}"}), 200


@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Disallow: /secret-upload\n"
        "Disallow: /admin/\n"
        "Sitemap: /sitemap.xml\n",
        mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return Response(
        '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>/admin/files</loc></url>'
        '<url><loc>/api/v3/files</loc></url>'
        '</urlset>', mimetype="application/xml")


@app.route("/admin/files", methods=["GET", "POST"])
def admin_files():
    if request.method == "POST":
        f = request.files.get("file") or request.files.get("upload")
        if not f:
            return "no file", 400
        f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
        return "ok", 200
    return (
        '<html><body><form method=post enctype=multipart/form-data>'
        '<input type=file name=upload><button>go</button></form></body></html>'
    )


@app.route("/swagger.json")
def swagger():
    return jsonify({
        "openapi": "3.0.0",
        "paths": {
            "/api/v3/files": {
                "post": {
                    "summary": "upload binary",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {"properties": {
                                    "binary": {"type": "string", "format": "binary"}
                                }}
                            }
                        }
                    }
                }
            }
        }
    })


@app.route("/api/v3/files", methods=["POST"])
def api_v3_files():
    f = request.files.get("binary")
    if not f:
        return "no binary", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return jsonify({"id": "abc123"}), 200


# WebDAV-style — no HTML form, only OPTIONS+PUT
@app.route("/webdav/", methods=["OPTIONS"])
@app.route("/webdav/<path:fn>", methods=["OPTIONS"])
def webdav_options(fn=None):
    r = make_response("")
    r.headers["Allow"] = "GET, PUT, DELETE, PROPFIND, MKCOL, OPTIONS"
    r.headers["DAV"]   = "1, 2"
    return r


@app.route("/webdav/<path:fn>", methods=["PUT"])
def webdav_put(fn):
    open(os.path.join(UPLOAD_DIR, os.path.basename(fn)), "wb").write(request.get_data())
    return "", 201


# GraphQL multipart upload (Apollo spec)
@app.route("/graphql", methods=["POST", "OPTIONS"])
def graphql():
    if request.method == "OPTIONS":
        return make_response("", 200, {"Allow": "POST, OPTIONS"})
    if request.content_type and "multipart/form-data" in request.content_type:
        ops = request.form.get("operations", "")
        if "upload" in ops.lower() or "file" in ops.lower():
            f = next(iter(request.files.values()), None)
            if f:
                f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
                return jsonify({"data": {"upload": {"path": "/files/" + f.filename}}})
    return jsonify({"errors": [{"message": "expected multipart upload"}]}), 400


def run(port):
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
