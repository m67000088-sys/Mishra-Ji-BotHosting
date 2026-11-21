import os, io, time, re, base64, zipfile, hmac as _hmac
from collections import OrderedDict
from threading import Lock
from flask import Flask, request, jsonify, send_from_directory, make_response, Response
import requests as _rq
from werkzeug.middleware.proxy_fix import ProxyFix

import store, auth, security, runner

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.json.sort_keys = False
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
PUBLIC_DIR = os.path.join(os.path.dirname(__file__), "public")
SECURE_COOKIE = os.environ.get("INSECURE_COOKIES") != "1"

# ---------------- bounded in-memory rate limiter ----------------
_hits = OrderedDict()
_hits_lock = Lock()
_MAX_RATE_LIMIT_KEYS = 10000


def limited(key, n, per):
    now = time.monotonic()
    with _hits_lock:
        times = _hits.get(key)
        if times is None:
            if len(_hits) >= _MAX_RATE_LIMIT_KEYS:
                _hits.popitem(last=False)
            times = []
            _hits[key] = times
        else:
            _hits.move_to_end(key)
        times[:] = [t for t in times if now - t < per]
        if len(times) >= n:
            return True
        times.append(now)
        return False


def ip():
    # ProxyFix trusts exactly one ingress proxy; use its normalized client address.
    return request.remote_addr or "?"


def env_status():
    missing = []
    if not (os.environ.get("UPSTASH_REDIS_REST_URL") and os.environ.get("UPSTASH_REDIS_REST_TOKEN")):
        missing.append("UPSTASH_REDIS_REST_URL/TOKEN")
    if not ADMIN_PASSWORD:
        missing.append("ADMIN_PASSWORD")
    if not os.environ.get("SESSION_SECRET", "").strip():
        missing.append("SESSION_SECRET")
    return {"redis": isinstance(store.store, store.UpstashStore), "adminPassword": bool(ADMIN_PASSWORD), "missing": missing}


@app.after_request
def sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------------- static pages ----------------
@app.get("/")
def home():
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.get("/admin")
def admin_page():
    return send_from_directory(PUBLIC_DIR, "admin.html")


@app.get("/health")
def health():
    return jsonify({"ok": True})


# ---------------- auth helpers ----------------
def current_user():
    tok = request.cookies.get(auth.COOKIE_USER)
    u = auth.read_session(tok, "user") if tok else None
    if not u:
        return None
    d = store.get_user(u)
    if not d or d.get("banned"):
        return None
    return u


def current_admin():
    tok = request.cookies.get(auth.COOKIE_ADMIN)
    return bool(ADMIN_PASSWORD) and auth.read_session(tok, "admin") == "admin"


def set_cookie(resp, name, value, max_age):
    resp.set_cookie(name, value, max_age=max_age, httponly=True, samesite="Strict", secure=SECURE_COOKIE, path="/")


def need_login():
    u = current_user()
    return (u, None) if u else (None, (jsonify({"error": "Pehle login karo"}), 401))


# ---------------- public config ----------------
@app.get("/api/config")
def api_config():
    s = store.get_settings()
    links = []
    for line in (s.get("links") or "").splitlines():
        if "|" in line:
            t, u = line.split("|", 1)
            if u.strip().startswith(("http://", "https://")):
                links.append({"title": t.strip()[:40], "url": u.strip()})
    return jsonify({
        "name": s["name"], "logo": s["logo"], "tagline": s["tagline"], "announcement": s["announcement"], "links": links,
        "signupOpen": s["signupOpen"], "maintenance": s["maintenance"], "maintenanceMsg": s["maintenanceMsg"],
        "maxBotsPerUser": s["maxBotsPerUser"], "maxFileKB": s["maxFileKB"], "maxEnvVars": s["maxEnvVars"],
        "nodeSupported": runner.HAS_NODE,
    })


# ---------------- user auth ----------------
@app.get("/api/auth")
def api_auth_get():
    return jsonify({"user": current_user()})


@app.post("/api/auth")
def api_auth_post():
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    if action == "logout":
        resp = make_response(jsonify({"ok": True}))
        set_cookie(resp, auth.COOKIE_USER, "", 0)
        return resp
    if limited(("auth", ip()), 12, 600):
        return jsonify({"error": "Bahut zyada koshish. 10 minute baad try karo."}), 429
    username = str(body.get("username", "")).lower().strip()
    password = str(body.get("password", ""))
    if not auth.USERNAME_RE.match(username):
        return jsonify({"error": "Username 3-20 chars (a-z, 0-9, _)"}), 400
    if len(password) > 256:
        return jsonify({"error": "Password 256 characters se chhota hona chahiye"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password kam se kam 8 characters ka ho"}), 400
    settings = store.get_settings()
    if settings["maintenance"]:
        return jsonify({"error": settings["maintenanceMsg"]}), 503
    if action == "signup":
        if not settings["signupOpen"]:
            return jsonify({"error": "Signup abhi band hai"}), 403
        if store.get_user(username):
            return jsonify({"error": "Ye username le liya gaya hai"}), 409
        store.set_user(username, {"pass": auth.hash_pw(password), "banned": False, "created": time.time()})
        store.log_event(f"Naya user: {username}")
    elif action == "login":
        d = store.get_user(username)
        if not d or not auth.check_pw(password, d["pass"]):
            return jsonify({"error": "Username ya password galat hai"}), 401
        if d.get("banned"):
            return jsonify({"error": "Aapka account ban hai"}), 403
    else:
        return jsonify({"error": "Bad action"}), 400
    resp = make_response(jsonify({"ok": True, "user": username}))
    set_cookie(resp, auth.COOKIE_USER, auth.make_session(username, "user"), 86400)
    return resp


# ---------------- bot serialisation ----------------
def public_bot(b, with_usage=True):
    item = {k: v for k, v in b.items() if k not in ("uid",)}
    name = b["name"]
    # live state process se, record se nahi
    if runner.is_running(name):
        item["status"] = "running"
        item["uptime"] = runner.uptime(name)
        if with_usage:
            u = runner.usage(name)
            if u:
                item["cpu"], item["mem"] = u
    elif runner.is_installing(name):
        item["status"] = "installing"
    elif b.get("status") in ("running", "installing"):
        item["status"] = "stopped"
    item["envCount"] = len(runner.get_env(name))
    return item


def own_bot(u, name):
    d = store.get_bot(name)
    return d if d and d.get("owner") == u else None


# ---------------- user bots ----------------
@app.get("/api/bots")
def api_bots_list():
    u, err = need_login()
    if err:
        return err
    settings = store.get_settings()
    limit = (store.get_user(u) or {}).get("botLimit") or settings["maxBotsPerUser"]
    return jsonify({"bots": [public_bot(b) for b in store.list_bots(owner=u)], "limit": limit})


def _zip_from_request(settings):
    """Raw body: .zip ya single .py/.js file (filename query se). Returns zip bytes."""
    data = request.get_data()
    if not data:
        raise security.ScriptRejected("File khali hai")
    if len(data) > settings["maxFileKB"] * 1024:
        raise security.ScriptRejected(f"File {settings['maxFileKB']}KB se badi hai")
    fname = (request.args.get("filename") or "bot.zip").lower()
    if data[:2] == b"PK":
        return data
    if fname.endswith(".py"):
        arc = "bot.py"
    elif fname.endswith((".js", ".mjs")):
        arc = "index.js"
    else:
        raise security.ScriptRejected("Sirf .zip (bot.py + requirements.txt) ya single .py / .js file upload karo")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(arc, data)
        if arc == "index.js":
            z.writestr("package.json", '{"name":"bot","version":"1.0.0","main":"index.js"}')
    return buf.getvalue()


@app.post("/api/bots")
def api_bots_upload():
    u, err = need_login()
    if err:
        return err
    settings = store.get_settings()
    if settings["maintenance"]:
        return jsonify({"error": settings["maintenanceMsg"]}), 503
    if limited(("upload", u), 10, 600):
        return jsonify({"error": "Thoda ruko, bahut uploads ho gaye."}), 429
    name = str(request.args.get("name", "")).lower().strip()
    if not re.match(store.NAME_RE_SRC, name):
        return jsonify({"error": "Bot naam 3-30 chars ka ho (a-z, 0-9, -)"}), 400
    if name in store.RESERVED_NAMES:
        return jsonify({"error": "Ye naam allowed nahi hai"}), 400
    existing = store.get_bot(name)
    if existing and existing.get("owner") != u:
        return jsonify({"error": "Ye naam kisi aur ne le liya hai"}), 409
    if not existing:
        limit = (store.get_user(u) or {}).get("botLimit") or settings["maxBotsPerUser"]
        if len(store.list_bots(owner=u)) >= limit:
            return jsonify({"error": f"Aapki limit {limit} bots ki hai"}), 400
    try:
        zbytes = _zip_from_request(settings)
        info = runner.inspect_zip(zbytes, settings)
    except security.ScriptRejected as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Upload process nahi hua: {e}"}), 400
    if info["runtime"] == "node" and not runner.HAS_NODE:
        return jsonify({"error": "Is server par Node.js nahi hai. Admin ko Docker deploy karna hoga."}), 400

    if existing:
        runner.stop(name)
    is_update = bool(existing)
    needs_approval = settings["approvalRequired"] and not is_update
    status = "pending_approval" if needs_approval else "stopped"
    store.set_zip_b64(name, base64.b64encode(zbytes).decode())
    store.set_bot(name, {
        "owner": u, "created": existing["created"] if is_update else time.time(), "updated": time.time(),
        "status": status, "desired": "stopped", "runtime": info["runtime"], "entry": info["entry"],
        "files": info["files"], "zipHash": info["hash"], "zipSize": len(zbytes),
        "memLimitMB": settings["maxMemoryMB"], "autoRestart": True,
        "restarts": 0, "uid": (existing or {}).get("uid"),
    })
    runner.extract(name, zbytes)
    store.log_event(f"{u} ne bot {'update' if is_update else 'upload'} kiya: {name} ({info['runtime']})")
    return jsonify({"ok": True, "name": name, "status": status, "runtime": info["runtime"], "entry": info["entry"]})


@app.delete("/api/bots/<name>")
def api_bots_delete(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    runner.stop(name)
    store.delete_bot(name)
    import shutil
    shutil.rmtree(runner.bot_dir(name), ignore_errors=True)
    store.log_event(f"{u} ne bot delete kiya: {name}")
    return jsonify({"ok": True})


@app.post("/api/bots/<name>/start")
def api_bots_start(name):
    u, err = need_login()
    if err:
        return err
    d = own_bot(u, name)
    if not d:
        return jsonify({"error": "Bot nahi mila"}), 404
    if d.get("status") == "pending_approval":
        return jsonify({"error": "Ye bot abhi admin approval ka wait kar raha hai"}), 403
    ok, info = runner.start_async(name)
    if not ok:
        return jsonify({"error": str(info)}), 400
    return jsonify({"ok": True})


@app.post("/api/bots/<name>/stop")
def api_bots_stop(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    runner.stop(name)
    store.log_event(f"{u} ne bot stop kiya: {name}")
    return jsonify({"ok": True})


@app.post("/api/bots/<name>/restart")
def api_bots_restart(name):
    u, err = need_login()
    if err:
        return err
    d = own_bot(u, name)
    if not d:
        return jsonify({"error": "Bot nahi mila"}), 404
    if d.get("status") == "pending_approval":
        return jsonify({"error": "Approval pending hai"}), 403
    runner.stop(name)
    ok, info = runner.start_async(name)
    return (jsonify({"ok": True}) if ok else (jsonify({"error": str(info)}), 400))


@app.get("/api/bots/<name>/logs")
def api_bots_logs(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    return jsonify({"log": runner.tail_log(name, 200)})


@app.get("/api/bots/<name>/logs/download")
def api_bots_logs_dl(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    return Response(runner.tail_log(name, 5000), mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename={name}.log"})


@app.post("/api/bots/<name>/logs/clear")
def api_bots_logs_clear(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    runner.clear_log(name)
    return jsonify({"ok": True})


@app.post("/api/bots/<name>/settings")
def api_bots_settings(name):
    u, err = need_login()
    if err:
        return err
    d = own_bot(u, name)
    if not d:
        return jsonify({"error": "Bot nahi mila"}), 404
    body = request.get_json(silent=True) or {}
    if "autoRestart" in body:
        d["autoRestart"] = bool(body["autoRestart"])
    store.set_bot(name, d)
    return jsonify({"ok": True})


# ---------------- env variables (per bot) ----------------
def mask(v):
    return "•" * 8 if len(v) <= 6 else v[:2] + "•" * 8 + v[-2:]


@app.get("/api/bots/<name>/env")
def api_env_get(name):
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    env = runner.get_env(name)
    return jsonify({"env": [{"key": k, "masked": mask(v), "isToken": bool(runner.TOKEN_RE.match(v))} for k, v in sorted(env.items())],
                    "max": store.get_settings()["maxEnvVars"]})


@app.post("/api/bots/<name>/env")
def api_env_set(name):
    """body: {"set": {"KEY":"value"}, "delete": ["KEY"], "dotenv": "A=1\nB=2"}"""
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    body = request.get_json(silent=True) or {}
    env = runner.get_env(name)
    pairs = dict(body.get("set") or {})
    if body.get("dotenv"):
        pairs.update(runner.parse_dotenv(str(body["dotenv"])))
    for k in body.get("delete") or []:
        env.pop(str(k), None)
    clean, e = runner.clean_env_pairs(pairs, 10 ** 6)
    if e:
        return jsonify({"error": e}), 400
    env.update({k: v for k, v in clean.items() if v != ""})
    chk, e = runner.clean_env_pairs(env, store.get_settings()["maxEnvVars"])
    if e:
        return jsonify({"error": e}), 400
    runner.set_env(name, env)
    return jsonify({"ok": True, "count": len(env), "running": runner.is_running(name)})


@app.post("/api/bots/<name>/telegram-check")
def api_tg_check(name):
    """Env mein Telegram token dhoondh ke getMe se verify karta hai."""
    u, err = need_login()
    if err:
        return err
    if not own_bot(u, name):
        return jsonify({"error": "Bot nahi mila"}), 404
    if limited(("tg", u), 10, 300):
        return jsonify({"error": "Thoda ruko"}), 429
    body = request.get_json(silent=True) or {}
    env = runner.get_env(name)
    key = body.get("key")
    token = env.get(key) if key else next((v for v in env.values() if runner.TOKEN_RE.match(v)), None)
    if not token:
        return jsonify({"error": "Env mein Telegram bot token nahi mila (jaise BOT_TOKEN = 123456:ABC...)"}), 400
    try:
        r = _rq.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10).json()
    except Exception as e:
        return jsonify({"error": f"Telegram se connect nahi hua: {e}"}), 502
    if not r.get("ok"):
        return jsonify({"error": "Token galat hai ya revoke ho chuka hai"}), 400
    res = r["result"]
    clash = runner.token_conflict(name, env)
    return jsonify({"ok": True, "username": res.get("username"), "name": res.get("first_name"),
                    "warning": f"Ye token bot '{clash}' mein bhi hai (409 Conflict aayega)" if clash else None})


# ---------------- admin ----------------
@app.get("/api/admin/login")
def admin_login_get():
    return jsonify({"admin": current_admin(), "env": env_status()})


@app.post("/api/admin/login")
def admin_login_post():
    body = request.get_json(silent=True) or {}
    if body.get("action") == "logout":
        resp = make_response(jsonify({"ok": True}))
        set_cookie(resp, auth.COOKIE_ADMIN, "", 0)
        return resp
    if limited(("admin", ip()), 8, 600):
        return jsonify({"error": "Bahut zyada koshish. 10 minute baad try karo."}), 429
    if not ADMIN_PASSWORD:
        return jsonify({"error": "ADMIN_PASSWORD env set nahi hai. Render > Environment mein daalo, phir redeploy."}), 500
    password = str(body.get("password", ""))
    if len(password) > 256:
        return jsonify({"error": "Password galat hai"}), 401
    if not _hmac.compare_digest(password, ADMIN_PASSWORD):
        store.log_event("Galat admin password try hua")
        return jsonify({"error": "Password galat hai"}), 401
    resp = make_response(jsonify({"ok": True}))
    set_cookie(resp, auth.COOKIE_ADMIN, auth.make_session("admin", "admin", 12), 43200)
    store.log_event("Admin login hua")
    return resp


@app.get("/api/admin/data")
def admin_data():
    if not current_admin():
        return jsonify({"error": "Login karo"}), 401
    all_bots = store.list_bots()
    by_owner = {}
    for b in all_bots:
        by_owner[b["owner"]] = by_owner.get(b["owner"], 0) + 1
    users = []
    for u in store.list_users():
        d = store.get_user(u) or {}
        users.append({"u": u, "created": d.get("created", 0), "banned": bool(d.get("banned")),
                      "botLimit": d.get("botLimit", 0), "bots": by_owner.get(u, 0)})
    bots = [public_bot(b) for b in all_bots]
    for b in bots:
        b["pid"] = runner.pid_of(b["name"])
    running = sum(1 for b in bots if b.get("status") == "running")
    return jsonify({
        "settings": store.get_settings(), "users": sorted(users, key=lambda x: -x["created"]),
        "bots": bots, "logs": store.get_logs(),
        "totals": {"users": len(users), "bots": len(bots), "running": running,
                   "banned": sum(1 for u in users if u["banned"]),
                   "node": sum(1 for b in bots if b.get("runtime") == "node"),
                   "python": sum(1 for b in bots if b.get("runtime") == "python")},
        "server": runner.server_info(), "env": env_status(),
    })


@app.post("/api/admin/action")
def admin_action():
    if not current_admin():
        return jsonify({"error": "Login karo"}), 401
    body = request.get_json(silent=True) or {}
    a = body.get("a")
    name = body.get("name")
    try:
        if a in ("ban", "unban"):
            u = body.get("u")
            d = store.get_user(u)
            if not d:
                return jsonify({"error": "User nahi mila"}), 404
            d["banned"] = a == "ban"
            store.set_user(u, d)
            if a == "ban":
                for b in store.list_bots(owner=u):
                    runner.stop(b["name"])
            store.log_event(f"{'Ban' if a == 'ban' else 'Unban'}: {u}")
        elif a == "deluser":
            u = body.get("u")
            import shutil
            for b in store.list_bots(owner=u):
                runner.stop(b["name"])
                store.delete_bot(b["name"])
                shutil.rmtree(runner.bot_dir(b["name"]), ignore_errors=True)
            store.delete_user(u)
            store.log_event(f"User delete: {u}")
        elif a == "setlimit":
            u = body.get("u")
            d = store.get_user(u)
            if not d:
                return jsonify({"error": "User nahi mila"}), 404
            d["botLimit"] = int(body.get("value") or 0) or None
            store.set_user(u, d)
        elif a == "approve":
            d = store.get_bot(name)
            if not d:
                return jsonify({"error": "Bot nahi mila"}), 404
            d["status"] = "stopped"
            store.set_bot(name, d)
            store.log_event(f"Bot approve hua: {name}")
        elif a in ("reject", "delbot"):
            import shutil
            runner.stop(name)
            store.delete_bot(name)
            shutil.rmtree(runner.bot_dir(name), ignore_errors=True)
            store.log_event(f"Admin ne bot delete kiya: {name}")
        elif a == "stopbot":
            runner.stop(name)
            store.log_event(f"Admin ne bot stop kiya: {name}")
        elif a == "startbot":
            if not store.get_bot(name):
                return jsonify({"error": "Bot nahi mila"}), 404
            ok, info = runner.start_async(name, by="admin")
            if not ok:
                return jsonify({"error": str(info)}), 400
        elif a == "savesettings":
            store.set_settings(body.get("settings") or {})
            store.log_event("Settings save hui")
        elif a == "clearlog":
            store.store.delete("log")
        else:
            return jsonify({"error": "Bad action"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.get("/api/admin/bots/<name>/logs")
def admin_bot_logs(name):
    if not current_admin():
        return jsonify({"error": "Login karo"}), 401
    return jsonify({"log": runner.tail_log(name, 200)})


@app.get("/api/admin/bots/<name>/env")
def admin_bot_env(name):
    """Admin ko sirf env ke NAAM dikhte hain, values nahi."""
    if not current_admin():
        return jsonify({"error": "Login karo"}), 401
    return jsonify({"keys": sorted(runner.get_env(name).keys())})


runner.start_monitor()
runner.restore_after_boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
