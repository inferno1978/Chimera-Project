#!/usr/bin/env python3
"""Живой смоук-тест HTTP-слоя triple_panel_web (без root, temp-каталоги).

Поднимает сервер в потоке с фейковыми хранилищами и прогоняет:
static → login → session → /api/users → POST/PUT/DELETE → /sub/:token (UA)
+ SSE /api/events (сырой сокет), ротация пароля, rename email,
       смена портов naive/mieru, каскад, WARP, /api/logs/:service.
+ /api/stats/users (accounting-фолбэк), /api/settings/hy2 (статус
       + 501 на мутации), /api/diagnostics, /api/panel/stub (roundtrip),
       /api/status — контракт апстрима ПОЛНОСТЬЮ (services/system/panel).
"""
import base64
import json
import socket
import sys
import tempfile
import threading
import time
import types
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from chimera.modules import triple_panel as tp
from chimera.modules import triple_panel_web as web

# ── temp-окружение ──────────────────────────────────────────────────────────
tmp = tempfile.mkdtemp(prefix="triple-smoke-")
www = Path(tmp) / "www"
(www / "locales").mkdir(parents=True)
(www / "index.html").write_text(
    '<html><head><title>smoke</title></head>'
    '<body><script src="app.js"></script></body></html>')
(www / "app.js").write_text("console.log('smoke');")
(www / "locales" / "ru.json").write_text('{"lang":"ru"}')
# шим вживляется установщиком — проверяем и раздачу
assert tp._inject_sse_shim(www), "shim inject failed"

state_file = Path(tmp) / "state.json"
state = {
    "installed": True, "web_port": 9760, "admin_user": "admin",
    "front_version": "1.11.2", "language": "ru",
}
tp._set_admin_password(state, "smoke-pass-123")
state_file.write_text(json.dumps(state))

web._STATE_FILE = state_file
web._WWW_DIR = www
# детерминизм: сервисы «активны», egress не ходит в сеть
web._svc_active = lambda name: True
web._egress_ip = lambda timeout=6: "203.0.113.9"

# детерминизм новых эндпоинтов (stub/hy2/diagnostics/status
# в tmp, процессы не спавним — смоук должен быть одинаков везде)
web._STUB_FILE = Path(tmp) / "panel-stub" / "index.html"
web._local_ip = lambda: "127.0.0.1"
web._run_cmd = lambda cmd, timeout=6: ""
web._HY2_UNIT = Path(tmp) / "hysteria-server.service"
web._HY2_CONFIG = Path(tmp) / "hysteria" / "config.yaml"
web._HY2_STATE = Path(tmp) / "core-state.json"
web._CADDYFILE = Path(tmp) / "Caddyfile"
ta = types.ModuleType("chimera.modules.traffic_accounting")
ta.get_all_accumulated = lambda u: (
    {"mieru": 5 * 1048576, "naiveproxy": 3 * 1048576}
    if u == "smoke" else {})
sys.modules["chimera.modules.traffic_accounting"] = ta

# ── фейковые хранилища ─────────────────────────────────────────────────────
USERS = [{"email": "smoke@x.com", "uuid": "uuid-smoke-1", "name": "smoke",
          "portal_password": "p", "created": "2026-01-01"}]

ra = types.ModuleType("chimera.modules.rest_api")
ra._get_users = lambda: list(USERS)
ra._save_users = lambda users: USERS.clear() or USERS.extend(users)
ra._sync_users_from_config = lambda: 0
ra._sync_ensure_user = lambda name, user=None: {"naiveproxy": True}
ra._sync_remove_user = lambda name, user=None: {}
ra._sync_rename_user = lambda old, new, old_user=None, new_user=None: None
sys.modules["chimera.modules.rest_api"] = ra

import chimera.modules.proto_common as pc
naive_st = {"users": [{"username": "smoke", "password": "nvpw"}],
            "domain": "smoke.example", "port": 443, "upstream": ""}
naive_mod = types.ModuleType("chimera.modules.naiveproxy")
naive_mod._MODULE_STATE = Path(tmp) / "naive.json"
pc.proto_save_state(naive_mod._MODULE_STATE, naive_st)


def _naive_set_pw(user, password=None):
    st = pc.proto_load_state(naive_mod._MODULE_STATE)
    new_pw = password or "gen-naive-pw"
    for u in st.get("users", []):
        if u.get("username") == (user.get("email", "") or "").split("@")[0]:
            u["password"] = new_pw
    pc.proto_save_state(naive_mod._MODULE_STATE, st)
    return new_pw


naive_mod.is_active = lambda: True
naive_mod.ensure_user_full = lambda u: True
naive_mod.remove_user_full = lambda u: True
naive_mod.set_password_full = _naive_set_pw
naive_mod._apply_config = lambda d, p, u, f, ps, up="": None
sys.modules["chimera.modules.naiveproxy"] = naive_mod

mieru_st = {"users": [{"username": "smoke", "password": "mrpw"}],
            "port_start": 2012, "port_end": 2022, "protocol": "TCP"}
mieru_mod = types.ModuleType("chimera.modules.mieru")
mieru_mod._MODULE_STATE = Path(tmp) / "mieru.json"
pc.proto_save_state(mieru_mod._MODULE_STATE, mieru_st)


def _mieru_set_pw(user, password=None):
    st = pc.proto_load_state(mieru_mod._MODULE_STATE)
    new_pw = password or "gen-mieru-pw"
    for u in st.get("users", []):
        if u.get("username") == (user.get("email", "") or "").split("@")[0]:
            u["password"] = new_pw
    pc.proto_save_state(mieru_mod._MODULE_STATE, st)
    return new_pw


mieru_mod.is_active = lambda: True
mieru_mod.ensure_user_full = lambda u: True
mieru_mod.remove_user_full = lambda u: True
mieru_mod.set_password_full = _mieru_set_pw
mieru_mod._MIERU_TRAFFIC_PRESETS = {}
mieru_mod._build_server_config = lambda users, ps, pe, proto, \
    traffic_pattern=None: {"ports": (ps, pe)}
mieru_mod._apply_server_config = lambda cfg: None
sys.modules["chimera.modules.mieru"] = mieru_mod

sub = types.ModuleType("chimera.modules.subscription")
sub._load_sub_conf = lambda: {}
sub._ensure_pepper = lambda cfg: "pepper"
sub._find_user_by_token = lambda t, p: (
    USERS[0] if t == "smoketoken" else None)
sub._resolve_format = lambda requested, ua: requested or (
    "singbox" if "nekobox" in (ua or "").lower() else
    "clash" if "clash" in (ua or "").lower() else
    "base64_safe" if "karing" in (ua or "").lower() else "base64")
sub.build_subscription_body = lambda u: base64.b64encode(
    b"naive+https://smoke:nvpw@smoke.example:443\nmierus://smoke2")
sub.build_subscription_singbox_config = lambda u: '{"outbounds":[{"type":"direct","tag":"direct"}]}'
sub._filter_safe_links = lambda links: [
    l for l in links if not l.startswith("naive+https://")
    and not l.startswith("mierus://")]
sub._build_userinfo_header = lambda u: "upload=0; download=0; total=1073741824"
sub._get_server_ip = lambda t="4": "127.0.0.1"
sub._load_traffic_limits = lambda: LIM
sys.modules["chimera.modules.subscription"] = sub

mn = types.ModuleType("chimera.modules.subscription_multinode")
mn.build_mihomo_config = lambda u: "proxies: [smoke]"
sys.modules["chimera.modules.subscription_multinode"] = mn

ttl = types.ModuleType("chimera.modules.ttl_users")
TTL = {}
ttl._ttl_load = lambda: TTL
ttl._ttl_set = lambda e, d: TTL.update({e: {"expires_at": "2099-01-01", "days": d}})
ttl._ttl_remove = lambda e: TTL.pop(e, None)
sys.modules["chimera.modules.ttl_users"] = ttl

ul = types.ModuleType("chimera.modules.user_lifecycle")
LIM = {}
ul._set_traffic_limit = lambda e, gb: LIM.update({e: {"limit_gb": gb}})
ul._remove_traffic_limit = lambda e: LIM.pop(e, None)
sys.modules["chimera.modules.user_lifecycle"] = ul

core = types.ModuleType("chimera._core")
core.gen_uuid = lambda: "uuid-generated"
core._users_apply_to_config = lambda users: True
sys.modules["chimera._core"] = core

# фейковые port_registry + warp
REG = []
CONFLICTS = {"ports": set()}
pr = types.ModuleType("chimera.modules.port_registry")
pr.SERVICE_NAIVEPROXY = "naiveproxy"
pr.SERVICE_MIERU = "mieru"
pr.port_get_conflicts = lambda port, proto="tcp", exclude_service=None: (
    [{"type": "registry", "detail": "занят: тест", "service": "x"}]
    if port in CONFLICTS["ports"] else [])
pr.port_check_system = lambda port, proto="tcp": []
pr.port_register = lambda tag, port, proto="tcp", comment="", force=False: (
    REG.append(("reg", tag, port)) or (True, "ok"))
pr.port_unregister = lambda tag, port=None, proto=None: (
    REG.append(("unreg", tag, port)) or True)
pr.port_register_range = lambda tag, ps, pe, proto="tcp", comment="": (
    REG.append(("reg-range", tag, ps, pe)) or (True, "ok"))
pr.port_unregister_range = lambda tag, ps, pe, proto=None: (
    REG.append(("unreg-range", tag, ps, pe)) or True)
pr.ufw_open_port = lambda port, proto, tag, comment=None: REG.append(
    ("ufw-open", port))
pr.ufw_close_port = lambda port, proto, tag, legacy_comments=None: REG.append(
    ("ufw-close", port))
pr.ufw_open_port_range = lambda ps, pe, proto, tag, comment=None: REG.append(
    ("ufw-open-range", ps, pe))
pr.ufw_close_port_range = lambda ps, pe, proto, tag, legacy=None: REG.append(
    ("ufw-close-range", ps, pe))
sys.modules["chimera.modules.port_registry"] = pr

WARP = {"state": {"WARP_CONNECTED": False, "WARP_MODE": "runet",
                  "WARP_SSH_CLIENT_IP": ""}, "calls": [], "uninstalled": 0}
warp = types.ModuleType("chimera.modules.warp")
warp._state_get = lambda name, default=None: WARP["state"].get(name, default)
warp._state_set = lambda name, value: WARP["state"].update({name: value})
warp.configure_warp = lambda mode, ssh, custom_ips=None, custom_domains=None: (
    WARP["state"].update({"WARP_CONNECTED": True})
    or WARP["calls"].append((mode, ssh)) or True)
warp.uninstall_warp = lambda: (
    WARP["state"].update({"WARP_CONNECTED": False})
    or WARP.__setattr__("uninstalled", WARP["uninstalled"] + 1) or True)
warp.WG_SERVICE = "wg-quick@wgcf"
sys.modules["chimera.modules.warp"] = warp

# ── запуск сервера в потоке ────────────────────────────────────────────────
PORT = 18960
server = None
def _run():
    global server
    server = web.ThreadingHTTPServer(("127.0.0.1", PORT), web._TripleHandler)
    server.serve_forever()

t = threading.Thread(target=_run, daemon=True)
t.start()
time.sleep(0.6)

BASE = f"http://127.0.0.1:{PORT}"
PASS, FAIL = [], []

def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✓' if cond else '✗'} {name} {extra}")

def req(path, method="GET", data=None, headers=None, cookies=None):
    r = urllib.request.Request(BASE + path, method=method)
    if data is not None:
        r.data = json.dumps(data).encode()
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookies:
        r.add_header("Cookie", "; ".join(cookies))
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

print("── Triple Panel web smoke ──")

# 1. Статика (+ SSE-шим)
st, _, body = req("/")
check("GET / → 200 + index.html", st == 200 and b"smoke" in body)
st, _, body = req("/app.js")
check("GET /app.js → 200", st == 200 and b"smoke" in body)
st, _, body = req("/triple-sse.js")
check("GET /triple-sse.js → 200 (SSE-шим)", st == 200 and b"EventSource" in body)
st, _, body = req("/locales/ru.json")
check("GET /locales/ru.json → 200", st == 200)
st, _, _ = req("/../../etc/passwd")
check("traversal → 200 index fallback (SPA), не passwd", st == 200)
st, _, _ = req("/nonexistent-route")
check("SPA-фолбэк → 200", st == 200)

# 2. Auth
st, _, body = req("/api/me")
check("GET /api/me без сессии → 401", st == 401)
st, _, body = req("/api/login", "POST",
                   {"username": "admin", "password": "wrong"})
check("login wrong → 401", st == 401)
st, hdr, body = req("/api/login", "POST",
                    {"username": "admin", "password": "smoke-pass-123"})
cookie = (hdr.get("Set-Cookie") or "").split(";")[0]
check("login ok → 200 + cookie", st == 200 and cookie.startswith("tp_session="))

# 3. Сессия
st, _, body = req("/api/me", cookies=[cookie])
check("GET /api/me с сессией → 200",
      st == 200 and json.loads(body)["username"] == "admin")

# 4. Пользователи
st, _, body = req("/api/users", cookies=[cookie])
rows = json.loads(body)
check("GET /api/users → 200, 1 юзер", st == 200 and len(rows) == 1)
row = rows[0] if rows else {}
check("unified-ряд: protocols [naive,mieru]",
      sorted(row.get("protocols", [])) == ["mieru", "naive"])
check("unified-ряд: username=smoke, id=email",
      row.get("username") == "smoke" and row.get("id") == "smoke@x.com")

st, _, body = req("/api/users", "POST", {"email": "new@x.com",
                                          "expiry": "2099-01-01",
                                          "quotaMB": 2048}, cookies=[cookie])
check("POST /api/users → 201", st == 201)
check("TTL поставлен", "new@x.com" in TTL)
check("квота поставлена (2 GiB)", LIM.get("new@x.com", {}).get("limit_gb") == 2)

st, _, body = req("/api/users/new%40x.com", "PUT", {"quotaMB": 5120},
                  cookies=[cookie])
check("PUT /api/users/:id → 200, квота 5 GiB",
      st == 200 and LIM["new@x.com"]["limit_gb"] == 5)

# ротация пароля (до удаления — на юзере new@x.com фейков нет аккаунтов →
# проверяем на smoke@x.com после удаления new)
st, _, body = req("/api/users/new%40x.com", "DELETE", cookies=[cookie])
check("DELETE /api/users/:id → 200", st == 200)
check("юзера нет в списке",
      all(u["email"] != "new@x.com" for u in USERS))

# ротация пароля — один пароль в оба протокола
st, _, body = req("/api/users/smoke%40x.com", "PUT",
                  {"password": "rotated-pw-123"}, cookies=[cookie])
resp = json.loads(body) if st == 200 else {}
check("PUT password → 200 + changed", st == 200 and "password" in resp.get("changed", []))
st, _, body = req("/api/users/smoke%40x.com/naive-link", cookies=[cookie])
d = json.loads(body)
check("naive-link отражает новый пароль",
      st == 200 and "rotated-pw-123" in d.get("link", ""))
st, _, _ = req("/api/users/smoke%40x.com", "PUT", {"password": "short"},
               cookies=[cookie])
check("PUT короткий пароль → 400", st == 400)

# rename email (uuid сохраняется, TTL переносится)
TTL["smoke@x.com"] = {"expires_at": "2099-01-01", "days": 30}
st, _, body = req("/api/users/smoke%40x.com", "PUT",
                  {"email": "renamed@x.com"}, cookies=[cookie])
check("PUT email → 200 + id=renamed", st == 200 and
      json.loads(body).get("id") == "renamed@x.com")
check("rename: юзер переехал в USERS",
      any(u["email"] == "renamed@x.com" and u["uuid"] == "uuid-smoke-1"
          for u in USERS))
check("rename: TTL перенесён", "renamed@x.com" in TTL
      and "smoke@x.com" not in TTL)
# вернуть для остальных проверок
req("/api/users/renamed%40x.com", "PUT", {"email": "smoke@x.com"},
    cookies=[cookie])

# 5. Ссылки юзера
st, _, body = req("/api/users/smoke%40x.com/naive-link", cookies=[cookie])
d = json.loads(body)
check("naive-link → naive+https:// с паролем",
      st == 200 and d.get("link", "").startswith("naive+https://smoke:"))
st, _, body = req("/api/users/smoke%40x.com/universal-config", cookies=[cookie])
check("universal-config → base64-список", st == 200)

# 6. /sub/:token с UA-детектом
st, hdr, body = req("/sub/smoketoken")
check("/sub base64 default → 200 + userinfo",
      st == 200 and "Subscription-Userinfo" in hdr)
st, hdr, body = req("/sub/smoketoken", headers={"User-Agent": "NekoBox/1.2"})
check("/sub UA NekoBox → singbox JSON", st == 200 and b"outbounds" in body)
st, hdr, body = req("/sub/smoketoken", headers={"User-Agent": "ClashMeta/1.18"})
check("/sub UA Clash → mihomo YAML", st == 200 and b"proxies" in body)
st, hdr, body = req("/sub/smoketoken", headers={"User-Agent": "Karing/1.0"})
dec = base64.b64decode(body).decode()
check("/sub UA Karing → base64_safe (без naive/mierus)",
      st == 200 and "naive+https://" not in dec and "mierus://" not in dec)
st, _, _ = req("/sub/badtoken")
check("/sub плохой токен → 404", st == 404)
st, _, _ = req("/sub/smoketoken?format=singbox")
check("/sub ?format=singbox → приоритет параметра", st == 200)

# 7. SSE /api/events
st, _, _ = req("/api/events")
check("SSE без сессии → 401", st == 401)

def _sse_open(cookie_str):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=8)
    req_raw = (f"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
               f"Cookie: {cookie_str}\r\n"
               f"Accept: text/event-stream\r\nConnection: close\r\n\r\n")
    s.sendall(req_raw.encode())
    return s

def _read_until(s, token, timeout=8.0):
    s.settimeout(timeout)
    data = b""
    deadline = time.time() + timeout
    while token not in data and time.time() < deadline:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data

sock = _sse_open(cookie)
d1 = _read_until(sock, b"retry: 3000")
check("SSE: стрим открылся (retry: 3000)", b"retry: 3000" in d1)
web._sse_publish("metrics", {"type": "metrics", "cpu": 7.5,
                             "ramUsedMB": 100, "ramTotalMB": 1000,
                             "naive": True, "mieru": True})
d2 = _read_until(sock, b"event: metrics")
sock.close()
check("SSE: событие metrics доставлено (контракт WS апстрима)",
      b"event: metrics" in d2 and b"cpu" in d2)

# 8. порты протоколов
st, _, body = req("/api/settings/naive-port", "POST", {"port": 8443},
                  cookies=[cookie])
check("POST naive-port 8443 → 200", st == 200 and json.loads(body).get("ok"))
st, _, body = req("/api/config", cookies=[cookie])
check("/api/config видит новый naivePort",
      json.loads(body).get("naivePort") == 8443)
st, _, _ = req("/api/settings/naive-port", "POST", {"port": 99999},
               cookies=[cookie])
check("POST naive-port невалидный → 400", st == 400)
CONFLICTS["ports"].add(9443)
st, _, _ = req("/api/settings/naive-port", "POST", {"port": 9443},
               cookies=[cookie])
CONFLICTS["ports"].discard(9443)
check("POST naive-port конфликт → 409", st == 409)

st, _, body = req("/api/settings/mieru-ports", "POST",
                  {"portStart": 3000, "portEnd": 3010}, cookies=[cookie])
check("POST mieru-ports 3000-3010 → 200",
      st == 200 and json.loads(body).get("ok"))
st, _, body = req("/api/config", cookies=[cookie])
check("/api/config видит новые mieruPorts",
      json.loads(body).get("mieruPorts", {}).get("start") == 3000)
st, _, _ = req("/api/settings/mieru-ports", "POST",
               {"portStart": 3000, "portEnd": 2999}, cookies=[cookie])
check("POST mieru-ports невалидный диапазон → 400", st == 400)

# 9. каскад
st, _, body = req("/api/settings/cascade", cookies=[cookie])
check("GET cascade → 200, выключен",
      st == 200 and not json.loads(body).get("cascadeEnabled"))
st, _, body = req("/api/settings/cascade", "POST", {
    "cascadeEnabled": True,
    "cascadeNaiveUpstream": "naive+https://u:p@exit.example:443#tag"},
    cookies=[cookie])
check("POST cascade enable → 200", st == 200 and json.loads(body).get("ok"))
st, _, body = req("/api/settings/cascade", cookies=[cookie])
view = json.loads(body)
check("GET cascade видит upstream (нормализован)",
      view.get("cascadeEnabled") and
      view.get("cascadeNaiveUpstream") == "https://u:p@exit.example:443")
st, _, body = req("/api/settings/cascade/status", cookies=[cookie])
check("GET cascade/status → 200 + output",
      st == 200 and "upstream" in json.loads(body).get("output", ""))
st, _, body = req("/api/settings/cascade/reset", "POST", cookies=[cookie])
check("POST cascade/reset → 200 + сброшен",
      st == 200 and not web._cascade_view()["cascadeEnabled"])

# 10. WARP
st, _, body = req("/api/settings/warp", cookies=[cookie])
check("GET warp → 200 shape", st == 200 and "ramMB" in json.loads(body))
st, _, body = req("/api/settings/warp", "POST", {"warpEnabled": True},
                  cookies=[cookie])
resp = json.loads(body)
check("POST warp enable → 200 + режим runet",
      st == 200 and resp.get("ok") and "runet" in resp.get("message", ""))
check("warp.py: configure_warp вызван", WARP["calls"] == [("runet", "")])
st, _, body = req("/api/settings/warp/status", cookies=[cookie])
check("GET warp/status → 200 + egress IP",
      st == 200 and "203.0.113.9" in json.loads(body).get("output", ""))
st, _, body = req("/api/settings/warp", "POST", {"warpEnabled": False},
                  cookies=[cookie])
check("POST warp disable → 200", st == 200 and
      not json.loads(body).get("warpEnabled"))

# 11. логи
st, _, body = req("/api/logs/naive", cookies=[cookie])
check("GET /api/logs/naive → 200 {logs}", st == 200 and
      "logs" in json.loads(body))
st, _, body = req("/api/logs/panel", cookies=[cookie])
check("GET /api/logs/panel → 200 (кольцо)", st == 200)
st, _, _ = req("/api/logs/bogus", cookies=[cookie])
check("GET /api/logs/bogus → 400", st == 400)

# 12. Разное
st, _, body = req("/api/password/generate", cookies=[cookie])
check("/api/password/generate → 200", st == 200)

# 13. недостающие эндпоинты (4 ошибки со скринов юзера)
st, _, body = req("/api/stats/users", cookies=[cookie])
stats = json.loads(body) if st == 200 else {}
u = (stats.get("users") or [{}])[0]
check("GET /api/stats/users → 200, контракт апстрима",
      st == 200 and sorted(stats) ==
      ["naivePerUser", "naiveServerTotalMB", "users"])
check("stats: mieru/naive из accounting-фолбэка",
      u.get("mieruMB") == 5.0 and u.get("naiveMB") == 3.0)
check("stats: naive целиком в download, used = сумма (квоты нет)",
      u.get("uploadMB") == 0 and u.get("downloadMB") == 8.0 and
      u.get("usedMB") == 8.0)
check("stats: hy2MB=0 (per-exit-node), lastSeen None",
      u.get("hy2MB") == 0 and u.get("lastSeen") is None)

st, _, body = req("/api/settings/hy2", cookies=[cookie])
hy2 = json.loads(body) if st == 200 else {}
check("GET /api/settings/hy2 → 200 + статус",
      st == 200 and hy2.get("installed") is False and
      hy2.get("port") == 443 and "hy2UserCount" in hy2 and
      hy2.get("stack", {}).get("naive") is True)
st, _, _ = req("/api/settings/hy2/install", "POST", {"port": 443},
                cookies=[cookie])
check("POST hy2/install → 501 с указанием TUI", st == 501)

st, _, body = req("/api/diagnostics", cookies=[cookie])
diag = json.loads(body) if st == 200 else {}
check("GET /api/diagnostics → 200, ключи контракта",
      st == 200 and all(k in diag for k in
      ("ports", "naiveVersionOk", "caddyfileUsers", "probeMode",
       "timeSynced", "mitaStateFile", "mitaStatus", "mitaConfig")))
check("diagnostics: probeMode bare (нет probe_secret)",
      diag.get("probeMode") == "bare" and
      diag.get("ports", {}).get("hy2Installed") is False)

st, _, body = req("/api/panel/stub", cookies=[cookie])
stub = json.loads(body) if st == 200 else {}
check("GET /api/panel/stub → 200 {path, html}",
      st == 200 and "path" in stub and stub.get("html") == "")
st, _, body = req("/api/panel/stub", "POST",
                   {"html": "<html>stub</html>"}, cookies=[cookie])
r = json.loads(body) if st == 200 else {}
check("POST /api/panel/stub → 200 ok + bytes",
      st == 200 and r.get("ok") and r.get("bytes") == 17)
st, _, body = req("/api/panel/stub", cookies=[cookie])
check("stub roundtrip", json.loads(body).get("html") ==
      "<html>stub</html>")
st, _, _ = req("/api/panel/stub", "POST", {"html": "   "},
                cookies=[cookie])
check("POST stub пустой → 400", st == 400)

st, _, body = req("/api/status", cookies=[cookie])
s = json.loads(body) if st == 200 else {}
check("status: services.naive.active (контракт апстрима)",
      st == 200 and s.get("services", {}).get("naive", {}).get("active")
      is True)
check("status: system.cpu/ram/disk/uptime/os",
      isinstance(s.get("system", {}).get("cpuPercent"), int) and
      "ramUsedMB" in s.get("system", {}) and
      "diskTotalGB" in s.get("system", {}) and
      "uptime" in s.get("system", {}) and s.get("system", {}).get("os"))
check("status: panel.userCount=1, version фронта",
      s.get("panel", {}).get("userCount") == 1 and
      s.get("panel", {}).get("version") == "1.11.2")
check("status: domain из naive state + serverIp",
      s.get("domain") == "smoke.example" and s.get("serverIp") ==
      "127.0.0.1")

st, _, body = req("/api/config", cookies=[cookie])
cfg = json.loads(body)
check("/api/config → 200 + плоские поля ",
      st == 200 and "webPort" in cfg and "mieruPortStart" in cfg and
      "probeMode" in cfg and "serverIp" in cfg)
st, _, _ = req("/api/logout", "POST", cookies=[cookie])
check("logout → 200", st == 200)

server.shutdown()
print(f"\nИТОГ: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("ПРОВАЛЫ:", FAIL)
    sys.exit(1)
