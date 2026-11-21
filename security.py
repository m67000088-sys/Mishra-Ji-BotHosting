"""Uploaded bot ke liye safety checks: zip-slip, zip-bomb, dangerous code scan.
Ye asli sandbox nahi hai — README mein honest limits likhe hain."""
import re, io, zipfile, posixpath

DEFAULT_BLOCKED_MODULES = ["subprocess", "ctypes", "pty", "multiprocessing"]

PY_CALLS = [
    (r"\bos\.(system|popen|remove|unlink|rmdir|rename|chmod|chown|execv|execve|fork|kill|killpg)\s*\(", "dangerous os.* call"),
    (r"\b__import__\s*\(", "dynamic __import__"),
    (r"\beval\s*\(", "eval()"),
    (r"\bexec\s*\(", "exec()"),
    (r"/proc/", "/proc access"),
]
JS_CALLS = [
    (r"require\(\s*['\"](node:)?child_process['\"]\s*\)", "child_process"),
    (r"from\s+['\"](node:)?child_process['\"]", "child_process"),
    (r"\bprocess\.binding\s*\(", "process.binding"),
    (r"require\(\s*['\"](node:)?(cluster|worker_threads|vm)['\"]\s*\)", "cluster/worker_threads/vm"),
    (r"/proc/", "/proc access"),
]

ENTRY_PY = ["bot.py", "main.py", "app.py", "run.py", "index.py"]
ENTRY_JS = ["bot.js", "index.js", "main.js", "app.js", "server.js", "bot.mjs", "index.mjs"]


class ScriptRejected(Exception):
    pass


def scan_python(code: str, blocked, fname=""):
    for mod in blocked:
        mod = mod.strip()
        if not mod:
            continue
        if re.search(rf"^\s*import\s+{re.escape(mod)}\b", code, re.M) or re.search(rf"^\s*from\s+{re.escape(mod)}\b", code, re.M):
            raise ScriptRejected(f"{fname}: '{mod}' import allowed nahi hai (safety ke liye block).")
    for pat, label in PY_CALLS:
        if re.search(pat, code):
            raise ScriptRejected(f"{fname}: '{label}' allowed nahi hai (safety ke liye block).")


def scan_js(code: str, fname=""):
    for pat, label in JS_CALLS:
        if re.search(pat, code):
            raise ScriptRejected(f"{fname}: '{label}' allowed nahi hai (safety ke liye block).")


def safe_members(zf: zipfile.ZipFile, max_total: int, max_files: int):
    """Returns list of (info, clean_relpath). Raises ScriptRejected on unsafe zip."""
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > max_files:
        raise ScriptRejected(f"Zip mein {max_files} se zyada files hain.")
    total = 0
    out = []
    for i in infos:
        name = i.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/") or re.match(r"^[a-zA-Z]:", name):
            raise ScriptRejected(f"Zip mein unsafe path hai: {name}")
        if (i.external_attr >> 16) & 0o170000 == 0o120000:
            raise ScriptRejected(f"Zip mein symlink allowed nahi: {name}")
        total += i.file_size
        if total > max_total:
            raise ScriptRejected(f"Zip khulne par {max_total // (1024 * 1024)}MB se bada ho jata hai.")
        out.append((i, posixpath.normpath(name)))
    # agar sab kuch ek hi folder ke andar hai to us folder ko hata do
    parts = [p.split("/") for _, p in out]
    if parts and all(len(p) > 1 for p in parts) and len({p[0] for p in parts}) == 1:
        out = [(i, "/".join(p.split("/")[1:])) for i, p in out]
    return [(i, p) for i, p in out if not p.startswith("__MACOSX") and not p.endswith(".DS_Store")]


def detect_runtime(paths):
    pset = set(paths)
    top = {p for p in pset if "/" not in p}
    if "package.json" in top and not any(e in top for e in ENTRY_PY):
        rt = "node"
    elif any(e in top for e in ENTRY_PY):
        rt = "python"
    elif any(e in top for e in ENTRY_JS):
        rt = "node"
    elif any(p.endswith(".py") for p in top):
        rt = "python"
    elif any(p.endswith((".js", ".mjs")) for p in top):
        rt = "node"
    else:
        raise ScriptRejected("Zip mein bot.py (Python) ya index.js/bot.js + package.json (Node.js) chahiye.")
    entries = ENTRY_PY if rt == "python" else ENTRY_JS
    entry = next((e for e in entries if e in top), None)
    if not entry:
        ext = (".py",) if rt == "python" else (".js", ".mjs")
        cands = sorted(p for p in top if p.endswith(ext))
        entry = cands[0] if cands else None
    if not entry:
        raise ScriptRejected("Entry file nahi mili (bot.py / index.js jaisi file top-level par rakho).")
    return rt, entry
