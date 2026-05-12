"""
Hard scenario mock target — combines EVERY auth/transport pitfall in one app.

Endpoints:
  /basic-zone/*       — HTTP Basic-protected upload (Authorization: Basic ...)
  /bearer/login       — POST JSON {user,pass} → {access_token: JWT}; uploads need Bearer
  /bearer/upload      — needs Authorization: Bearer <token>
  /spa/login          — JSON-body login, returns Set-Cookie + rotating CSRF in body
  /spa/upload         — needs cookie + X-CSRF-Token (rotates per response)
  /wizard/step1       — POST username → step2 path in JSON
  /wizard/step2       — POST password → step3 path
  /wizard/step3       — POST OTP → cookie
  /wizard/upload      — needs the wizard cookie
  /flaky/upload       — every 7th request returns 429 with Retry-After: 1
  /waf/upload         — detects "<?php" in body and returns 406 "Mod_Security blocked"
  /expiring/login     — sets cookie that expires after 5 requests
  /expiring/upload    — 302 → /expiring/login when cookie dead
  /hash/upload        — stores file at /hash/files/<sha1-of-content>.bin and returns
                        JSON {"path": "/hash/files/abc.bin"} so brute-force fails
  /raw/upload         — only accepts multipart with header X-Raw-Token: secret
                        (proves -r request file replay)
"""
import os, secrets, hashlib, time, base64
from collections import defaultdict
import pyotp
from flask import Flask, request, session, redirect, make_response, jsonify, abort, send_from_directory

TOTP_SECRET = "JBSWY3DPEHPK3PXP"
USER, PASS  = "admin", "hunter2"
JWT_KEY     = "elite_secret"
RAW_TOKEN   = "secret"
UPLOAD_DIR  = "/tmp/uploadpwn_hard_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# request counters keyed by remote_addr for flaky/expiring behaviour
_req_count = defaultdict(int)
_exp_cookies = {}   # token -> hits remaining

def _mint_jwt(sub):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    body   = base64.urlsafe_b64encode(f'{{"sub":"{sub}","iat":{int(time.time())}}}'.encode()).rstrip(b"=")
    sig    = hashlib.sha256(JWT_KEY.encode()+header+b"."+body).hexdigest().encode()
    return (header+b"."+body+b"."+sig).decode()

# ─── HTTP Basic ────────────────────────────────────────────────────────────
@app.route("/basic-zone/upload", methods=["POST"])
def basic_zone_upload():
    a = request.authorization
    if not a or a.username != USER or a.password != PASS:
        resp = make_response("auth required", 401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="elite"'
        return resp
    f = request.files.get("file")
    if not f: return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return "ok", 200

# ─── Bearer / JWT ──────────────────────────────────────────────────────────
@app.route("/bearer/login", methods=["POST"])
def bearer_login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == USER and data.get("password") == PASS:
        return jsonify({"access_token": _mint_jwt(USER), "token_type": "Bearer"})
    return jsonify({"error": "bad creds"}), 401

@app.route("/bearer/upload", methods=["POST"])
def bearer_upload():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "): return "no token", 401
    tok = h.split(None, 1)[1]
    parts = tok.split(".")
    if len(parts) != 3: return "bad token", 401
    expect = hashlib.sha256(JWT_KEY.encode()+parts[0].encode()+b"."+parts[1].encode()).hexdigest()
    if parts[2] != expect: return "bad sig", 401
    f = request.files.get("file")
    if not f: return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return jsonify({"path": f"/hash/files/{os.path.basename(f.filename)}"}), 200

# ─── SPA: JSON login + rotating CSRF ───────────────────────────────────────
@app.route("/spa/login", methods=["POST"])
def spa_login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == USER and data.get("password") == PASS:
        session["csrf"] = secrets.token_hex(8)
        session["spa_authed"] = True
        return jsonify({"csrf": session["csrf"], "ok": True})
    return jsonify({"ok": False}), 401

@app.route("/spa/upload", methods=["POST"])
def spa_upload():
    if not session.get("spa_authed"): return "no session", 401
    expected = session.get("csrf")
    if request.headers.get("X-CSRF-Token") != expected:
        return "bad csrf", 419
    # rotate CSRF every successful request
    session["csrf"] = secrets.token_hex(8)
    f = request.files.get("file")
    if not f: return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return jsonify({"path": f"/spa/files/{f.filename}", "next_csrf": session["csrf"]}), 200

# ─── Multi-step wizard ─────────────────────────────────────────────────────
@app.route("/wizard/step1", methods=["POST"])
def wizard_s1():
    if request.form.get("username") == USER:
        session["w1"] = True
        return jsonify({"next": "/wizard/step2"})
    return "no", 401

@app.route("/wizard/step2", methods=["POST"])
def wizard_s2():
    if not session.get("w1"): return "skip", 403
    if request.form.get("password") == PASS:
        session["w2"] = True
        return jsonify({"next": "/wizard/step3"})
    return "no", 401

@app.route("/wizard/step3", methods=["POST"])
def wizard_s3():
    if not session.get("w2"): return "skip", 403
    code = request.form.get("code", "")
    if pyotp.TOTP(TOTP_SECRET).verify(code, valid_window=1):
        r = make_response(jsonify({"ok": True}))
        r.set_cookie("wizard_auth", "yes")
        return r
    return "bad otp", 401

@app.route("/wizard/upload", methods=["POST"])
def wizard_upload():
    if request.cookies.get("wizard_auth") != "yes": return "no auth", 401
    f = request.files.get("file")
    if not f: return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return "ok", 200

# ─── Rate-limited endpoint ─────────────────────────────────────────────────
@app.route("/flaky/upload", methods=["POST"])
def flaky_upload():
    _req_count["flaky"] += 1
    if _req_count["flaky"] % 7 == 0:
        r = make_response("rate limited", 429)
        r.headers["Retry-After"] = "1"
        return r
    return "ok", 200

# ─── WAF endpoint ─────────────────────────────────────────────────────────
@app.route("/waf/upload", methods=["POST"])
def waf_upload():
    f = request.files.get("file")
    if f:
        body = f.stream.read()
        if b"<?php" in body or b"<?=" in body:
            r = make_response("Mod_Security: payload blocked", 406)
            r.headers["Server"] = "cloudflare"
            return r
    return "ok", 200

# ─── Session expiry every N requests ───────────────────────────────────────
@app.route("/expiring/login", methods=["POST"])
def expiring_login():
    if request.form.get("username") == USER and request.form.get("password") == PASS:
        tok = secrets.token_hex(8)
        _exp_cookies[tok] = 5
        r = make_response("ok")
        r.set_cookie("EXPSESS", tok)
        return r
    return "no", 401

@app.route("/expiring/upload", methods=["POST"])
def expiring_upload():
    tok = request.cookies.get("EXPSESS", "")
    if tok not in _exp_cookies or _exp_cookies[tok] <= 0:
        # session dead → redirect to login
        return redirect("/expiring/login-form")
    _exp_cookies[tok] -= 1
    return "ok", 200

@app.route("/expiring/login-form")
def expiring_form():
    return "<html><body>Please login</body></html>", 200

# ─── Hash-renaming upload (path discovery needed) ──────────────────────────
@app.route("/hash/upload", methods=["POST"])
def hash_upload():
    f = request.files.get("file")
    if not f: return "no file", 400
    content = f.stream.read()
    h = hashlib.sha1(content).hexdigest()[:16]
    path = os.path.join(UPLOAD_DIR, h + ".bin")
    open(path, "wb").write(content)
    return jsonify({"path": f"/hash/files/{h}.bin"}), 200

@app.route("/hash/files/<path:fn>")
def hash_serve(fn):
    return send_from_directory(UPLOAD_DIR, fn)

# ─── Raw-token upload (-r replay) ─────────────────────────────────────────
@app.route("/raw/upload", methods=["POST"])
def raw_upload():
    if request.headers.get("X-Raw-Token") != RAW_TOKEN:
        return "missing raw token header", 403
    f = request.files.get("file")
    if not f: return "no file", 400
    f.save(os.path.join(UPLOAD_DIR, os.path.basename(f.filename)))
    return "ok", 200


def run(port):
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
