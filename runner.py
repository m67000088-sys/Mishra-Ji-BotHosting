"""
Bot runner: ZIP extract -> dependency install -> process start -> monitor/auto-restart.

Isolation (honest version):
  * Bot ko CLEAN environment milta hai (host ke secrets: ADMIN_PASSWORD, Upstash token wagaira nahi dikhte).
  * Agar server root se chal raha hai (Docker), har bot apne ALAG unprivileged Linux user (uid) se chalta hai,
    uski directory 0700 hoti hai -> doosre bots ki files / host ke /proc/<pid>/environ nahi padh sakta.
  * Agar root nahi hai, sab bots same user se chalenge (weak isolation) — admin panel mein dikhta hai.
  * Memory: RSS monitor (kill if over limit). CPU: optional lifetime RLIMIT_CPU. Nahi hai: network/CPU-share sandbox.
"""
import os, re, sys, json, base64, hashlib, shutil, signal, subprocess, threading, time, zipfile, io
from pathlib import Path

import psutil
import store, security, vault

BASE_DIR = Path(__file__).parent.absolute()
BOTS_DIR = BASE_DIR / "bot_files"
BOTS_DIR.mkdir(exist_ok=True)
try:
    os.chmod(BOTS_DIR, 0o711)
except Exception:
    pass

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
HAS_NODE = bool(shutil.which("node") and shutil.which("npm"))

_procs = {}        # name -> Popen
_meta = {}         # name -> {"started": ts, "restarts": [ts...], "installing": bool}
_lock = threading.RLock()
_rec_lock = threading.Lock()
_install_sem = threading.Semaphore(1)
_stopping = set()  # manual stop ke dauran auto-restart roko

TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
BLOCKED_ENV = {"PATH", "HOME", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "NODE_OPTIONS",
               "NODE_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "SHELL", "USER", "LOGNAME", "PWD",
               "PYTHONUNBUFFERED", "NODE_ENV", "NPM_CONFIG_PREFIX", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"}
REQ_LINE_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?"
    r"(\s*(===|==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+(\s*,\s*(===|==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+)*)?"
    r"(\s*;\s*[^#]+)?$")


# ---------------- paths ----------------
def bot_dir(name):
    d = BOTS_DIR / name
    d.mkdir(exist_ok=True)
    return d


def app_dir(name):
    return bot_dir(name) / "app"


def deps_dir(name):
    return bot_dir(name) / ".deps"


def log_path(name):
    return bot_dir(name) / "run.log"


def _log(name, msg):
    try:
        with open(log_path(name), "a", encoding="utf-8") as f:
            f.write(f"[host {time.strftime('%H:%M:%S')}] {msg}\n")
    except Exception:
        pass


# ---------------- records ----------------
def _update_rec(name, **kw):
    with _rec_lock:
        d = store.get_bot(name)
        if not d:
            return None
        d.update(kw)
        store.set_bot(name, d)
        return d


def get_env(name):
    return vault.decrypt_dict(store.get_env_blob(name))


def set_env(name, env: dict):
    store.set_env_blob(name, vault.encrypt_dict(env))


def clean_env_pairs(pairs, max_vars):
    """pairs: dict. Returns (clean_dict, error)."""
    out = {}
    for k, v in pairs.items():
        k = str(k).strip()
        v = str(v)
        if not ENV_KEY_RE.match(k):
            return None, f"Env naam galat hai: '{k}' (A-Z, 0-9, _ ; number se shuru nahi)"
        if k.upper() in BLOCKED_ENV:
            return None, f"'{k}' naam allowed nahi hai (system reserved)"
        if "\x00" in v or len(v) > 4096:
            return None, f"'{k}' ki value galat ya bahut badi hai"
        out[k] = v
    if len(out) > max_vars:
        return None, f"Max {max_vars} env variables allowed hain"
    return out, None


def parse_dotenv(text):
    pairs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        pairs[k] = v
    return pairs


# ---------------- zip -> disk ----------------
def validate_requirements(text):
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-") or "://" in line or "@" in line.split(";")[0] or not REQ_LINE_RE.match(line):
            raise security.ScriptRejected(
                f"requirements.txt mein ye line allowed nahi: '{line[:60]}' (sirf PyPI packages, jaise python-telegram-bot==21.6)")


def inspect_zip(zip_bytes, settings):
    """Validate zip + scan. Returns dict(runtime, entry, files, hash). Raises ScriptRejected."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise security.ScriptRejected("Ye valid ZIP file nahi hai.")
    members = security.safe_members(zf, settings["maxUnzippedMB"] * 1024 * 1024, settings["maxFiles"])
    paths = [p for _, p in members]
    runtime, entry = security.detect_runtime(paths)
    blocked = [m for m in settings["blockedImports"].split(",")]
    top = {p for p in paths if "/" not in p}
    if runtime == "python" and "requirements.txt" in top:
        info = next(i for i, p in members if p == "requirements.txt")
        validate_requirements(zf.read(info).decode("utf-8", errors="replace"))
    if runtime == "node":
        if "package.json" not in top:
            raise security.ScriptRejected("Node.js bot ke liye package.json zaroori hai.")
        info = next(i for i, p in members if p == "package.json")
        try:
            json.loads(zf.read(info).decode("utf-8", errors="replace"))
        except ValueError:
            raise security.ScriptRejected("package.json valid JSON nahi hai.")
    for info, p in members:
        if info.file_size > 2 * 1024 * 1024:
            continue
        if runtime == "python" and p.endswith(".py"):
            code = zf.read(info).decode("utf-8", errors="replace")
            try:
                compile(code, p, "exec")
            except SyntaxError as e:
                raise security.ScriptRejected(f"Python syntax error ({p}): {e}")
            security.scan_python(code, blocked, p)
        elif runtime == "node" and p.endswith((".js", ".mjs", ".cjs")) and not p.startswith("node_modules/"):
            security.scan_js(zf.read(info).decode("utf-8", errors="replace"), p)
    files = [[p, i.file_size] for i, p in members if not p.startswith("node_modules/")][:150]
    return {"runtime": runtime, "entry": entry, "files": files,
            "hash": hashlib.sha256(zip_bytes).hexdigest()[:16]}


def _chown_tree(path, uid):
    if not IS_ROOT or uid is None:
        return
    try:
        for root, dirs, files in os.walk(path):
            os.chown(root, uid, uid)
            for f in files:
                try:
                    os.chown(os.path.join(root, f), uid, uid, follow_symlinks=False)
                except Exception:
                    pass
        os.chmod(path, 0o700)
    except Exception:
        pass


def _bot_uid(name):
    """Har bot ko apna unique uid (sirf root mode mein)."""
    if not IS_ROOT:
        return None
    d = store.get_bot(name) or {}
    if d.get("uid"):
        return d["uid"]
    uid = 20000 + store.store.incr("uidseq")
    _update_rec(name, uid=uid)
    return uid


def extract(name, zip_bytes=None):
    """Zip ko disk par kholta hai (purani app dir saaf)."""
    if zip_bytes is None:
        b64 = store.get_zip_b64(name)
        if not b64:
            raise RuntimeError("Bot ka zip store mein nahi mila")
        zip_bytes = base64.b64decode(b64)
    settings = store.get_settings()
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    members = security.safe_members(zf, settings["maxUnzippedMB"] * 1024 * 1024, settings["maxFiles"])
    ad = app_dir(name)
    if ad.exists():
        shutil.rmtree(ad, ignore_errors=True)
    ad.mkdir(parents=True, exist_ok=True)
    for info, rel in members:
        target = (ad / rel).resolve()
        if not str(target).startswith(str(ad.resolve()) + os.sep):
            raise security.ScriptRejected(f"Unsafe path: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
    uid = _bot_uid(name)
    _chown_tree(bot_dir(name), uid)


# ---------------- env for process ----------------
def _base_env(name, runtime, mem_mb):
    e = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(bot_dir(name)),
        "LANG": "C.UTF-8",
        "TZ": os.environ.get("TZ", "UTC"),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if runtime == "python":
        e["PYTHONPATH"] = f"{app_dir(name)}{os.pathsep}{deps_dir(name)}"
    else:
        e["NODE_ENV"] = "production"
        e["NODE_OPTIONS"] = f"--max-old-space-size={max(64, int(mem_mb * 0.7))}"
    return e


def _spawn_kwargs(name):
    kw = {"start_new_session": True}
    uid = (store.get_bot(name) or {}).get("uid")
    if IS_ROOT and uid:
        kw.update(user=uid, group=uid, extra_groups=[])
    return kw


def _apply_limits(proc, settings):
    try:
        import resource
        resource.prlimit(proc.pid, resource.RLIMIT_NOFILE, (1024, 1024))
        resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, (200 * 1024 * 1024,) * 2)
        resource.prlimit(proc.pid, resource.RLIMIT_CORE, (0, 0))
        if IS_ROOT:
            resource.prlimit(proc.pid, resource.RLIMIT_NPROC, (256, 256))
        cpu = int(settings.get("maxCpuSeconds") or 0)
        if cpu > 0:
            resource.prlimit(proc.pid, resource.RLIMIT_CPU, (cpu, cpu))
    except Exception:
        pass


# ---------------- dependency install ----------------
def _run_install(name, cmd, env, cwd, timeout):
    lf = open(log_path(name), "a", encoding="utf-8")
    lf.write(f"\n--- install {time.strftime('%Y-%m-%d %H:%M:%S')} : {' '.join(cmd[:6])} ---\n")
    lf.flush()
    try:
        p = subprocess.Popen(cmd, cwd=str(cwd), env=env, stdout=lf, stderr=lf, **_spawn_kwargs(name))
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(p, signal.SIGKILL)
            lf.write("\n[install] timeout ho gaya, rok diya.\n")
            return False
        return rc == 0
    except Exception as e:
        lf.write(f"\n[install] error: {e}\n")
        return False
    finally:
        lf.close()


def ensure_deps(name, d, settings):
    ad = app_dir(name)
    runtime = d["runtime"]
    marker = bot_dir(name) / ".deps_ok"
    timeout = int(settings.get("installTimeoutSec") or 420)
    env = _base_env(name, runtime, settings["maxMemoryMB"])
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INPUT"] = "1"
    env["npm_config_cache"] = str(bot_dir(name) / ".npm")
    if runtime == "python":
        req = ad / "requirements.txt"
        if not req.exists():
            return True
        h = hashlib.sha256(req.read_bytes()).hexdigest()
        if marker.exists() and marker.read_text() == h and deps_dir(name).exists():
            return True
        shutil.rmtree(deps_dir(name), ignore_errors=True)
        deps_dir(name).mkdir(exist_ok=True)
        _chown_tree(bot_dir(name), d.get("uid"))
        ok = _run_install(name, [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--target",
                                 str(deps_dir(name)), "-r", "requirements.txt"], env, ad, timeout)
    else:
        pj = ad / "package.json"
        h = hashlib.sha256(pj.read_bytes()).hexdigest()
        if marker.exists() and marker.read_text() == h and (ad / "node_modules").exists():
            return True
        ok = _run_install(name, ["npm", "install", "--omit=dev", "--no-audit", "--no-fund", "--ignore-scripts"],
                          env, ad, timeout)
    if ok:
        marker.write_text(h)
        _chown_tree(bot_dir(name), d.get("uid"))
    return ok


# ---------------- start / stop ----------------
def _entry_cmd(name, d):
    ad = app_dir(name)
    entry = d.get("entry")
    if d["runtime"] == "python":
        return [sys.executable, "-u", str(ad / entry)]
    return ["node", str(ad / entry)]


def token_conflict(name, env):
    mine = {v for v in env.values() if TOKEN_RE.match(v)}
    if not mine:
        return None
    for b in store.list_bots():
        other = b["name"]
        if other == name or not is_running(other):
            continue
        if mine & {v for v in get_env(other).values() if TOKEN_RE.match(v)}:
            return other
    return None


def _launch(name):
    """Process start (deps pehle se ready hone chahiye). Returns (ok, info)."""
    d = store.get_bot(name)
    if not d:
        return False, "Bot nahi mila"
    settings = store.get_settings()
    env_user = get_env(name)
    clash = token_conflict(name, env_user)
    if clash:
        return False, (f"Is bot ka Telegram token bot '{clash}' mein bhi hai jo chal raha hai. "
                       f"Ek token do jagah chalega to 409 Conflict aayega. Naya token BotFather se banao.")
    mem = d.get("memLimitMB") or settings["maxMemoryMB"]
    env = _base_env(name, d["runtime"], mem)
    env.update(env_user)
    lf = open(log_path(name), "ab")
    lf.write(f"\n--- start {time.strftime('%Y-%m-%d %H:%M:%S')} ({d['runtime']} : {d['entry']}) ---\n".encode())
    lf.flush()
    try:
        proc = subprocess.Popen(_entry_cmd(name, d), cwd=str(app_dir(name)), env=env, stdout=lf, stderr=lf,
                                stdin=subprocess.DEVNULL, **_spawn_kwargs(name))
    except Exception as e:
        lf.close()
        return False, f"Start nahi hua: {e}"
    lf.close()
    _apply_limits(proc, settings)
    with _lock:
        _procs[name] = proc
        m = _meta.setdefault(name, {"restarts": []})
        m["started"] = time.time()
    return True, proc.pid


def start_async(name, by="user"):
    """Background mein: files -> deps -> launch. Status Redis record mein update hota hai."""
    with _lock:
        m = _meta.setdefault(name, {"restarts": []})
        if m.get("installing") or is_running(name):
            return False, "Pehle se chal raha hai ya taiyari ho rahi hai"
        m["installing"] = True
        _stopping.discard(name)
    _update_rec(name, status="installing", desired="running", exitCode=None)

    def work():
        try:
            d = store.get_bot(name)
            if not d:
                return
            if d["runtime"] == "node" and not HAS_NODE:
                _log(name, "Server par Node.js install nahi hai. Docker deploy use karo (README dekho).")
                _update_rec(name, status="crashed", exitCode="no-node", desired="stopped")
                return
            if not app_dir(name).exists() or not (app_dir(name) / d["entry"]).exists():
                _log(name, "Files disk par nahi mili, store se wapas khol raha hu...")
                extract(name)
                d = store.get_bot(name)
            with _install_sem:
                ok = ensure_deps(name, d, store.get_settings())
            if not ok:
                _log(name, "Dependencies install fail. Upar ka log dekho, requirements.txt/package.json theek karo.")
                _update_rec(name, status="crashed", exitCode="install-failed", desired="stopped")
                store.log_event(f"Bot '{name}' dependencies install fail")
                return
            # stop() and launch are serialized so a stop during dependency installation
            # cannot be followed by a late process start.
            with _lock:
                if name in _stopping or not store.get_bot(name):
                    return
                ok, info = _launch(name)
            if not ok:
                _log(name, str(info))
                _update_rec(name, status="crashed", exitCode="start-failed", desired="stopped")
                return
            _update_rec(name, status="running", startedAt=time.time())
            store.log_event(f"Bot '{name}' start hua ({by})")
        except Exception as e:
            _log(name, f"Start error: {e}")
            _update_rec(name, status="crashed", exitCode="error", desired="stopped")
        finally:
            with _lock:
                _meta.setdefault(name, {"restarts": []})["installing"] = False

    threading.Thread(target=work, daemon=True).start()
    return True, "starting"


def _kill_tree(proc, sig=signal.SIGTERM):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except Exception:
        try:
            proc.send_signal(sig)
        except Exception:
            pass


def stop(name, final_status="stopped"):
    with _lock:
        _stopping.add(name)
        proc = _procs.get(name)
    if proc and proc.poll() is None:
        _kill_tree(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=6)
        except Exception:
            _kill_tree(proc, signal.SIGKILL)
    with _lock:
        _procs.pop(name, None)
    _update_rec(name, status=final_status, desired="stopped")
    return True, "Stopped"


def is_running(name):
    p = _procs.get(name)
    return bool(p and p.poll() is None)


def is_installing(name):
    return bool(_meta.get(name, {}).get("installing"))


def pid_of(name):
    p = _procs.get(name)
    return p.pid if p and p.poll() is None else None


def uptime(name):
    m = _meta.get(name) or {}
    return int(time.time() - m["started"]) if is_running(name) and m.get("started") else None


def usage(name):
    """(cpu%, rss MB) including children."""
    p = _procs.get(name)
    if not p or p.poll() is not None:
        return None
    try:
        root = psutil.Process(p.pid)
        procs = [root] + root.children(recursive=True)
        mem = sum(x.memory_info().rss for x in procs if x.is_running()) / (1024 * 1024)
        cpu = sum(x.cpu_percent(interval=None) for x in procs if x.is_running())
        return round(cpu, 1), round(mem, 1)
    except Exception:
        return None


# ---------------- logs ----------------
def tail_log(name, lines=150):
    path = log_path(name)
    if not path.exists():
        return ""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 64 * 1024))
        data = f.read()
    return "\n".join(data.decode("utf-8", errors="replace").splitlines()[-lines:])


def clear_log(name):
    try:
        open(log_path(name), "w").close()
    except Exception:
        pass


# ---------------- monitor ----------------
_limit_cache = {"t": 0, "v": 150}


def _cached_limit():
    if time.time() - _limit_cache["t"] > 30:
        _limit_cache.update(t=time.time(), v=store.get_settings()["maxMemoryMB"])
    return _limit_cache["v"]


def _handle_exit(name, code):
    with _lock:
        _procs.pop(name, None)
    if name in _stopping:
        return
    d = store.get_bot(name)
    if not d or d.get("desired") != "running":
        return
    settings = store.get_settings()
    m = _meta.setdefault(name, {"restarts": []})
    now = time.time()
    m["restarts"] = [t for t in m["restarts"] if now - t < 600]
    store.log_event(f"Bot '{name}' band ho gaya (exit {code}).")
    if settings.get("autoRestart") and d.get("autoRestart", True) and len(m["restarts"]) < 6:
        delay = min(60, 2 ** len(m["restarts"]))
        m["restarts"].append(now)
        _log(name, f"Process exit {code}. {delay}s baad auto-restart ({len(m['restarts'])}/6)...")
        _update_rec(name, status="installing", exitCode=code, restarts=d.get("restarts", 0) + 1)

        def later():
            time.sleep(delay)
            with _lock:
                if name in _stopping or not store.get_bot(name):
                    return
                ok, info = _launch(name)
            if ok:
                _update_rec(name, status="running", startedAt=time.time())
            else:
                _log(name, str(info))
                _update_rec(name, status="crashed", exitCode="restart-failed", desired="stopped")
        threading.Thread(target=later, daemon=True).start()
    else:
        _update_rec(name, status="crashed" if code != 0 else "stopped", exitCode=code, desired="stopped")
        if len(m["restarts"]) >= 6:
            _log(name, "10 minute mein 6 baar crash hua, auto-restart band. Code/env check karke Start dabao.")


def _monitor_loop(interval=3):
    tick = 0
    while True:
        time.sleep(interval)
        tick += 1
        with _lock:
            names = list(_procs.keys())
        for name in names:
            proc = _procs.get(name)
            if not proc:
                continue
            code = proc.poll()
            if code is not None:
                try:
                    _handle_exit(name, code)
                except Exception:
                    pass
                continue
            u = usage(name)
            if u:
                d = store.get_bot(name) if tick % 5 == 0 else None
                limit = ((d or {}).get("memLimitMB")) or _cached_limit()
                if u[1] > limit * 1.1:
                    stop(name, final_status="killed")
                    _update_rec(name, exitCode="mem-limit")
                    _log(name, f"Memory limit ({limit}MB) cross hui ({round(u[1])}MB). Bot kill kiya.")
                    store.log_event(f"Bot '{name}' memory limit cross, kill.")
            if tick % 20 == 0:
                try:
                    lp = log_path(name)
                    if lp.exists() and lp.stat().st_size > 2 * 1024 * 1024:
                        os.truncate(lp, 512 * 1024)
                except Exception:
                    pass


def start_monitor():
    threading.Thread(target=_monitor_loop, daemon=True).start()


def kill_orphans():
    """Gunicorn worker restart ke baad purane bot processes (jo yaad nahi) band karo, warna duplicate/409 aata hai."""
    base = str(BOTS_DIR) + os.sep
    me = os.getpid()
    for p in psutil.process_iter(["pid", "cwd"]):
        try:
            cwd = p.info.get("cwd") or ""
            if p.info["pid"] != me and cwd.startswith(base):
                p.kill()
        except Exception:
            pass


def restore_after_boot():
    """Server restart / sleep ke baad: jo bots 'running' the unhe wapas chalu karo (ek-ek karke)."""
    def work():
        kill_orphans()
        for b in store.list_bots():
            if b.get("status") == "pending_approval":
                continue
            if b.get("desired") == "running" or b.get("status") in ("running", "installing"):
                start_async(b["name"], by="auto-restore")
                for _ in range(150):
                    time.sleep(2)
                    if not is_installing(b["name"]):
                        break
    threading.Thread(target=work, daemon=True).start()


# ---------------- server info ----------------
def server_info():
    vm = psutil.virtual_memory()
    try:
        du = shutil.disk_usage(str(BOTS_DIR))
        disk = {"total": du.total, "used": du.used}
    except Exception:
        disk = {"total": 0, "used": 0}

    def ver(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            return None
    return {
        "ramTotalMB": round(vm.total / 1048576), "ramUsedMB": round((vm.total - vm.available) / 1048576),
        "cpuPercent": psutil.cpu_percent(interval=None), "disk": disk,
        "python": sys.version.split()[0], "node": ver(["node", "--version"]) if HAS_NODE else None,
        "isolation": "per-bot Linux user" if IS_ROOT else "shared user (weak)",
        "uptimeSec": int(time.time() - psutil.boot_time()),
    }
