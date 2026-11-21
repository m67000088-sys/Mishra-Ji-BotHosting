# 🤖 Mishra Ji Bot Hosting

User website + Admin panel. User **ZIP upload** karta hai (`bot.py` + `requirements.txt`, ya Node.js ke liye `index.js` + `package.json`), bot ke **env variables** website se add karta hai, **Start** dabata hai — bot chalu.

## ✨ Features
**User side**
- 📦 ZIP upload (ya single `.py` / `.js` file)
- 🐍 Python **aur** 🟢 Node.js bots
- 📚 Libraries khud install: `requirements.txt` → pip, `package.json` → npm
- 🔐 Per-bot **Environment Variables** (encrypted store). `.env` paste karke bulk import bhi
- ✈️ **Telegram token test** button (getMe se bot ka @username dikhata hai)
- ⚠️ Same token do bots mein chalane se pehle rok (409 Conflict se bachata hai)
- ♻️ **Auto-restart** on crash (exponential backoff, 10 min mein max 6 baar)
- 📜 Live logs (auto-refresh), download, clear
- 📊 Status, uptime, CPU/RAM, restart count
- ⬆️ Update ZIP (env save rehta hai)

**Admin panel (`/admin`)**
- Overview: server RAM/CPU/disk, Python/Node version, isolation mode, runtime counts
- Bots: force start/stop/delete, logs, env variable **naam** (values admin ko nahi dikhte)
- Users: ban/unban, per-user bot limit, delete
- Settings: approval mode, limits, auto-restart, blocked imports, branding, announcement banner, community links
- Activity log

## 📁 ZIP kaisa hona chahiye
```
🐍 Python                 🟢 Node.js
bot.py                    index.js
requirements.txt          package.json
```
Files seedha top-level par, ya ek folder ke andar (folder khud hat jata hai). Entry file ka naam: Python → `bot.py`, `main.py`, `app.py`; Node → `index.js`, `bot.js`, `main.js`.

**Token code mein mat likho.** Website par **⚙️ Env** mein `BOT_TOKEN` add karo:
```python
TOKEN = os.environ["BOT_TOKEN"]        # Python
```
```js
const TOKEN = process.env.BOT_TOKEN;   // Node.js
```
`examples/python_bot.zip` aur `examples/node_bot.zip` ready samples hain (upload karke test karo).

`requirements.txt` mein **sirf PyPI packages** allowed hain (`python-telegram-bot==21.6`). Git/URL links, `-r`, `--index-url` jaise options reject hote hain.

## 🚀 Deploy (Render, Docker)
Node.js bots ke liye server par Node chahiye, isliye **Docker** use hota hai (`Dockerfile` ready hai).

1. **Upstash**: upstash.com → Create Database (Redis) → REST API se `REST URL` + `REST TOKEN`.
2. **GitHub**: is folder ki saari files naye repo mein daalo.
3. **Render** → New → Web Service → repo → **Language: Docker** (Dockerfile khud detect hota hai) → Plan: Free.
4. **Environment Variables** daalo:

| Key | Value |
|---|---|
| `ADMIN_PASSWORD` | admin panel ka password |
| `UPSTASH_REDIS_REST_URL` | Upstash URL |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash token |
| `SESSION_SECRET` | koi lamba random string (32+ chars) |

5. Deploy → `/health` par sirf service health (`{ "ok": true }`) check karo → `/admin` par login. Public health endpoint environment variables ya deployment configuration expose nahi karta.
6. Fresh setup mein **approval mode ON** hota hai. Admin login karke Settings mein signup/approval options apni zaroorat ke mutabik set karo. Is project ko sirf apne ya bharosemand logon ke liye rakho; public signup enable mat karo.

⚠️ **`SESSION_SECRET` ko configured aur stable rakho.** Bot env variables isi se encrypt hote hain. Render Blueprint ise generate karta hai; ise rotate/reset karne par saved env variables decrypt nahi honge aur users ko dobara login karna padega.

⚠️ `--workers 1` hi rakhna (bots ek process ke andar track hote hain).

## 🔒 Safety — honest version
✅ **Hai**
- Bot ko **clean environment** milta hai: tumhare `ADMIN_PASSWORD`, Upstash token wagaira bot ko nahi dikhte.
- Docker (root) mein har bot **alag Linux user (uid)** se chalta hai, uski directory `0700`: doosre bots ki files aur host process ka `/proc/<pid>/environ` nahi padh sakta. (Admin panel mein "Isolation: per-bot Linux user" dikhta hai.)
- ZIP checks: zip-slip, symlink, zip-bomb (size/file limit), syntax check, dangerous code scan (`subprocess`, `os.system`, `eval`, `exec`, `child_process` wagaira block).
- Libraries bhi bot ke apne user se install hoti hain, root se nahi. npm `--ignore-scripts` ke saath.
- RAM limit (RSS monitor, limit cross karne par kill), file-size aur process limits.
- Env variables Fernet se encrypted; admin ko sirf naam dikhte hain.
- Login/upload/admin par bounded in-memory rate limit. Render ingress ka ek proxy hop trust hota hai; app ko kisi additional proxy chain ke peeche rakhne par trusted-hop configuration verify karo.

❌ **Nahi hai**
- Asli container/VM sandbox nahi hai. **Network** open hai (bot kuch bhi connect kar sakta hai) aur **CPU share** limit nahi hai (RAM ke jaisa).
- Static scan sirf common cheezein pakadta hai, kuch bhi chhupa ke bypass ho sakta hai.
- Agar server **root se nahi chalta** (Docker ke bina), sab bots same user se chalenge (weak isolation).
👉 **Isliye abhi sirf apne ya trusted logon ko use karne do. Pura public kholne se pehle approval mode ON rakho.**

## ⚠️ Render free plan
- **15 min** koi request na aaye to service **sleep** ho jati hai aur saare bots ruk jate hain. Apne uptime monitor se `https://tumhari-site.onrender.com/health` har 5 min ping karo.
- Disk **temporary** hai: restart/sleep ke baad files Redis se wapas khulti hain aur **libraries dobara install hoti hain** (1-2 min). Bots `desired=running` the to khud wapas chalu hote hain, ek-ek karke.
- RAM sirf **512 MB** hai. Default 150 MB per bot → 2-3 chhote bots. Zyada ke liye paid plan.
- ZIP Redis mein save hota hai (default max 2 MB). Upstash free ki limits (500k commands/month) ka dhyan rakho.

## 🧪 Local run
```bash
pip install -r requirements.txt
ADMIN_PASSWORD=test SESSION_SECRET=$(openssl rand -hex 16) INSECURE_COOKIES=1 python app.py
# bina Upstash ke in-memory store use hota hai (restart par data jata hai)
```

## 🛠 Problems
| Problem | Matlab / Fix |
|---|---|
| Status "Crashed", exit `install-failed` | Logs dekho. `requirements.txt` ka naam/version galat hai ya package install nahi ho raha |
| "409 Conflict" bot ke logs mein | Wahi token kahin aur bhi chal raha hai (doosra bot / phone / purani hosting). BotFather se `/revoke` karke naya token |
| "Killed (RAM limit)" | Bot limit se zyada RAM le raha hai. Admin → Settings mein limit badhao ya code halka karo |
| Node bot start nahi hota | Docker deploy karo (native Python runtime mein Node nahi hota) |
| Env badal ke bhi purana chal raha | Env change ke baad **Restart** zaroori hai |

Brand: **Mishra Ji**


## ⚠️ Deployment se pehle zaroor padhein
Ye app uploaded Python/Node.js code ko host machine par subprocess ke roop mein chalata hai. Static code scanning ya alag Linux UID ek real security sandbox nahi hai. Isliye is ZIP ko public multi-user code-hosting service ke roop mein launch karna surakshit nahi maana ja sakta. Approval mode ON rakhein aur sirf apne/trusted code ko chalayein. Production-level public hosting ke liye har bot ko alag, tightly restricted container/VM, CPU/RAM/disk/network quotas aur abuse monitoring mein chalana hoga.
