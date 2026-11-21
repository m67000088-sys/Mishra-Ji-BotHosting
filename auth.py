"""Signup/login with scrypt-hashed passwords and signed, HttpOnly session cookies."""
import os, hmac, hashlib, base64, json, time, re

SECRET = os.environ.get("SESSION_SECRET", "").strip() or hashlib.sha256(
    (os.environ.get("UPSTASH_REDIS_REST_TOKEN", "") + "|bot-hosting").encode()
).hexdigest()

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")


def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16).hex()
    h = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32)
    return f"{salt}:{h.hex()}"


def check_pw(pw, stored):
    try:
        salt, _ = stored.split(":", 1)
    except Exception:
        return False
    return hmac.compare_digest(hash_pw(pw, salt), stored)


def _sign(payload: str, role: str) -> str:
    return hmac.new((SECRET + role).encode(), payload.encode(), hashlib.sha256).hexdigest()


def make_session(subject: str, role: str, hours=24) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"s": subject, "r": role, "exp": time.time() + hours * 3600}).encode()
    ).decode()
    return f"{payload}.{_sign(payload, role)}"


def read_session(cookie_val: str, role: str):
    if not cookie_val or "." not in cookie_val:
        return None
    payload, sig = cookie_val.rsplit(".", 1)
    if not hmac.compare_digest(_sign(payload, role), sig):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception:
        return None
    if data.get("exp", 0) < time.time() or data.get("r") != role:
        return None
    return data.get("s")


def get_cookie(request, name):
    return request.cookies.get(name)


COOKIE_USER = "bh_u"
COOKIE_ADMIN = "bh_a"
