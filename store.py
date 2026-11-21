"""Upstash Redis REST-backed storage, in-memory fallback for local/dev testing."""
import os, json, time, threading
import requests

UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "").strip()


class InMemoryStore:
    def __init__(self):
        self._kv = {}
        self._lock = threading.Lock()

    def get_raw(self, key):
        with self._lock:
            return self._kv.get(key)

    def set_raw(self, key, value):
        with self._lock:
            self._kv[key] = value

    def get(self, key):
        v = self.get_raw(key)
        return json.loads(v) if v else None

    def set(self, key, value):
        self.set_raw(key, json.dumps(value))

    def delete(self, key):
        with self._lock:
            self._kv.pop(key, None)

    def incr(self, key):
        with self._lock:
            v = int(self._kv.get(key) or 0) + 1
            self._kv[key] = str(v)
            return v

    def sadd(self, key, member):
        with self._lock:
            self._kv.setdefault(key, set()).add(member)

    def srem(self, key, member):
        with self._lock:
            s = self._kv.get(key)
            if s:
                s.discard(member)

    def smembers(self, key):
        with self._lock:
            return set(self._kv.get(key, set()))

    def lpush(self, key, value):
        with self._lock:
            self._kv.setdefault(key, [])
            self._kv[key].insert(0, json.dumps(value))
            self._kv[key] = self._kv[key][:200]

    def lrange(self, key):
        with self._lock:
            return [json.loads(v) for v in self._kv.get(key, [])]


class UpstashStore:
    def __init__(self, url, token):
        self.url = url
        self.headers = {"Authorization": f"Bearer {token}"}
        self.s = requests.Session()

    def _cmd(self, *parts):
        r = self.s.post(self.url, headers=self.headers, json=list(parts), timeout=15)
        r.raise_for_status()
        j = r.json()
        if "error" in j:
            raise RuntimeError(j["error"])
        return j.get("result")

    def get_raw(self, key):
        return self._cmd("GET", key)

    def set_raw(self, key, value):
        self._cmd("SET", key, value)

    def get(self, key):
        v = self.get_raw(key)
        return json.loads(v) if v else None

    def set(self, key, value):
        self.set_raw(key, json.dumps(value))

    def delete(self, key):
        self._cmd("DEL", key)

    def incr(self, key):
        return int(self._cmd("INCR", key))

    def sadd(self, key, member):
        self._cmd("SADD", key, member)

    def srem(self, key, member):
        self._cmd("SREM", key, member)

    def smembers(self, key):
        return set(self._cmd("SMEMBERS", key) or [])

    def lpush(self, key, value):
        self._cmd("LPUSH", key, json.dumps(value))
        self._cmd("LTRIM", key, 0, 199)

    def lrange(self, key):
        vals = self._cmd("LRANGE", key, 0, 199) or []
        return [json.loads(v) for v in vals]


def make_store():
    if UPSTASH_URL and UPSTASH_TOKEN:
        return UpstashStore(UPSTASH_URL, UPSTASH_TOKEN)
    return InMemoryStore()


store = make_store()
NAME_RE_SRC = r"^[a-z0-9-]{3,30}$"
RESERVED_NAMES = {"admin", "api", "health", "static"}


# ---------------- users ----------------
def user_key(u):
    return f"user:{u}"


def get_user(u):
    return store.get(user_key(u))


def set_user(u, data):
    store.set(user_key(u), data)
    store.sadd("users:all", u)


def list_users():
    return sorted(store.smembers("users:all"))


def delete_user(u):
    store.delete(user_key(u))
    store.srem("users:all", u)


# ---------------- bots ----------------
def bot_key(name):
    return f"bot:{name}"


def get_bot(name):
    return store.get(bot_key(name))


def set_bot(name, data):
    store.set(bot_key(name), data)
    store.sadd("bots:all", name)


def delete_bot(name):
    for k in (bot_key(name), f"zip:{name}", f"env:{name}"):
        store.delete(k)
    store.srem("bots:all", name)


def list_bots(owner=None):
    out = []
    for n in store.smembers("bots:all"):
        d = get_bot(n)
        if d and (owner is None or d.get("owner") == owner):
            out.append({"name": n, **d})
    return sorted(out, key=lambda x: -x.get("created", 0))


def get_zip_b64(name):
    return store.get_raw(f"zip:{name}")


def set_zip_b64(name, b64):
    store.set_raw(f"zip:{name}", b64)


def get_env_blob(name):
    return store.get_raw(f"env:{name}") or ""


def set_env_blob(name, blob):
    store.set_raw(f"env:{name}", blob)


# ---------------- settings ----------------
DEFAULTS = {
    "approvalRequired": True,
    "signupOpen": True,
    "maintenance": False,
    "maintenanceMsg": "Site maintenance mein hai, thodi der baad aao.",
    "maxBotsPerUser": 3,
    "maxFileKB": 2048,          # ZIP size
    "maxUnzippedMB": 25,
    "maxFiles": 400,
    "maxEnvVars": 40,
    "maxMemoryMB": 150,
    "maxCpuSeconds": 0,         # 0 = unlimited (lifetime CPU)
    "autoRestart": True,
    "installTimeoutSec": 420,
    "blockedImports": "subprocess,ctypes,pty,multiprocessing",
    "name": "Mishra Ji Bot Hosting",
    "logo": "🤖",
    "tagline": "Mishra Ji ki Bot Hosting — apne Telegram bots manage karo",
    "announcement": "",
    "links": "",               # har line: Title|https://link
}


def get_settings():
    s = store.get("settings") or {}
    return {**DEFAULTS, **s}


def set_settings(partial):
    cur = get_settings()
    for k, v in partial.items():
        if k in DEFAULTS:
            cur[k] = v
    store.set("settings", cur)
    return cur


def log_event(msg):
    try:
        store.lpush("log", {"t": time.time(), "msg": str(msg)[:300]})
    except Exception:
        pass


def get_logs():
    return store.lrange("log")
