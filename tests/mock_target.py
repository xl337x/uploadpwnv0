"""
Mock vulnerable target exercising real-world auth pitfalls:
  /login-simple   — plain user/pass form, *responds 200 with "Invalid credentials" on failure*
  /login-csrf     — requires X-CSRF-Token header (token published only in a <meta> tag)
  /login-otp      — password POST → 302 to /verify-otp; OTP page validates TOTP
  /upload         — accepts files only when ?authed cookie is set
  /uploads/<f>    — serves uploaded files (so RCE / XXE retrieval works)
"""
import os, secrets, pyotp
from flask import Flask, request, session, redirect, url_for, make_response, send_from_directory

TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USER, PASS  = "admin", "hunter2"
UPLOAD_DIR  = "/tmp/uploadpwn_mock_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ── simple login ────────────────────────────────────────────────────────────
@app.route("/login-simple", methods=["GET", "POST"])
def login_simple():
    if request.method == "POST":
        if request.form.get("username") == USER and request.form.get("password") == PASS:
            r = make_response(redirect("/dashboard"))
            r.set_cookie("authed", "yes")
            return r
        # ⚠ stays on same URL, 200, with a failure message — the trap
        return "<html><body><h1>Invalid credentials</h1>"\
               "<form method=post><input name=username><input name=password type=password>"\
               "<button>Login</button></form></body></html>", 200
    return "<html><body><form method=post>"\
           "<input name=username><input name=password type=password>"\
           "<button>Login</button></form></body></html>"

# ── CSRF login (meta tag + header) ──────────────────────────────────────────
@app.route("/login-csrf", methods=["GET", "POST"])
def login_csrf():
    if request.method == "POST":
        if request.headers.get("X-CSRF-Token") != session.get("csrf"):
            return "CSRF token missing or invalid", 403
        if request.form.get("username") == USER and request.form.get("password") == PASS:
            r = make_response(redirect("/dashboard"))
            r.set_cookie("authed", "yes")
            return r
        return "Invalid credentials", 200
    token = secrets.token_hex(8)
    session["csrf"] = token
    return f'<html><head><meta name="csrf-token" content="{token}"></head>'\
           f'<body><form method=post>'\
           f'<input name=username><input name=password type=password>'\
           f'<button>Login</button></form></body></html>'

# ── OTP / 2FA login ─────────────────────────────────────────────────────────
@app.route("/login-otp", methods=["GET", "POST"])
def login_otp():
    if request.method == "POST":
        if request.form.get("username") == USER and request.form.get("password") == PASS:
            session["otp_pending"] = True
            return redirect("/verify-otp")
        return "Invalid credentials", 200
    return "<html><body><form method=post>"\
           "<input name=username><input name=password type=password>"\
           "<button>Login</button></form></body></html>"

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("otp_pending"):
        return redirect("/login-otp")
    if request.method == "POST":
        code = request.form.get("code", "")
        if pyotp.TOTP(TOTP_SECRET).verify(code, valid_window=1):
            session.pop("otp_pending")
            r = make_response(redirect("/dashboard"))
            r.set_cookie("authed", "yes")
            return r
        return "Wrong OTP code", 200
    return '<html><body><h1>Enter 2FA code</h1>'\
           '<form method=post><input name=code>'\
           '<button>Verify</button></form></body></html>'

# ── dashboard (proof of full auth) ──────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if request.cookies.get("authed") != "yes":
        return redirect("/login-simple")
    return "<html><body><h1>Welcome admin</h1><a href=/logout>logout</a>"\
           '<form method=post action=/upload enctype=multipart/form-data>'\
           '<input type=file name=avatar><button>Upload</button></form></body></html>'

# ── upload endpoint ─────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    if request.cookies.get("authed") != "yes":
        return "forbidden", 403
    f = request.files.get("avatar")
    if not f:
        return "no file", 400
    path = os.path.join(UPLOAD_DIR, os.path.basename(f.filename))
    f.save(path)
    return f"uploaded to /uploads/{os.path.basename(f.filename)}", 200

@app.route("/uploads/<path:fn>")
def serve_upload(fn):
    return send_from_directory(UPLOAD_DIR, fn)


def run(port):
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
