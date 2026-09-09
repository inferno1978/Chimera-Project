#!/usr/bin/env python3
"""
chimera/modules/triple_panel_web.py
───────────────────────────────────────────────────────────────────────────────
Веб-бэкенд Triple Panel — реализация API-контракта панели
Panel-Naive-Mieru-by-RIXXX поверх нативных примитивов Chimera.

Запуск (systemd triple-web.service):
    python3 -c "from chimera.modules.triple_panel_web import start_server; start_server()"

СТЕК (как у rest_api.py): stdlib ThreadingHTTPServer + BaseHTTPRequestHandler.
Ноль внешних зависимостей. Слушает ТОЛЬКО 127.0.0.1 (порт из
triple_panel_state.json) — наружу панель экспонируется nginx-фронтом
(panel_nginx_front, эталон b4) с TLS.

КОНТРАКТ (подмножество апстрима, необходимое фронтенду):
    POST   /api/login                — сессия (cookie tp_session, 24ч)
    POST   /api/logout               — сброс сессии
    GET    /api/me                   — кто в сессии
    GET    /api/users                — unified-таблица юзеров
    POST   /api/users                — создать (VLESS + sync contract v4.25)
    PUT    /api/users/:id            — v82: password (ротация протоколов) +
                                        email/username (rename через мост) +
                                        expiry/quota/protocols
    DELETE /api/users/:id            — удалить (везде: VLESS+naive+mieru+TTL+лимит)
    GET    /api/config               — панельные настройки (без секретов)
    POST   /api/config               — language
    GET    /api/status               — v83.4: контракт апстрима ПОЛНОСТЬЮ
                                        (services.{naive,mieru,hy2,panel},
                                        system.{cpu,ram,disk,uptime,os,arch},
                                        panel.{userCount,version}, domain,
                                        serverIp, language) — дашборд и
                                        мониторинг фронта читают эти поля
    GET    /api/apply-status         — исход последнего apply (фронт поллит)
    GET    /api/password/generate    — генератор пароля
    GET    /api/stats/users          — v83.4: трафик по юзерам (апстрим-контракт:
                                        users[{uploadMB,downloadMB,usedMB,
                                        naiveMB,mieruMB,hy2MB,lastSeen}],
                                        naiveServerTotalMB, naivePerUser);
                                        источники: `mita get users` (30-дневные
                                        live-цифры, как у апстрима) → фолбэк
                                        traffic_accounting (накопительный
                                        per-user mieru/naive); usedMB —
                                        квотосчётчик traffic_limits;
                                        серверный итог Naive — systemd
                                        IPAccounting caddy-naive
    GET    /api/settings/hy2         — v83.4: статус Hysteria2 (installed/
                                        active/port/stack/hy2UserCount);
                                        управление Hy2 — TUI Химеры (из UI —
                                        честный 501 с указанием пути)
    GET    /api/diagnostics          — v83.4: порты слушаются (ss), версия
                                        caddy-naive, Caddyfile-юзеры,
                                        mita status/describe, синхронизация
                                        времени, probe_secret
    GET/POST /api/panel/stub         — v83.4: заглушка-страница (файл
                                        /var/www/panel-stub/index.html,
                                        атомарная запись, лимит 256 KiB) —
                                        контракт апстрима; раздача —
                                        nginx-фронт/v2 (webBasePath)
    GET    /api/users/:id/naive-link | mieru-link | universal-config
    GET    /sub/:token               — умная подписка: UA-детект (делегация
                                        subscription.py: base64 / base64_safe /
                                        singbox / clash) + Subscription-Userinfo

v82 (SSE + настройки сервера):
    GET    /api/events               — SSE-стрим live-событий: metrics (контракт
                                        WS апстрима), users, status, log.
                                        Шим triple-sse.js (вживляется во фронт
                                        при установке) подменяет WebSocket
                                        апстрима на EventSource — app.js не
                                        меняется, WS-«точка» живой.
    GET    /api/logs/:service        — журналы: naive|caddy, mieru, hy2|hysteria
                                        (journalctl), panel (кольцо лога)
    POST   /api/settings/naive-port  — смена порта caddy-naive (port_registry:
                                        конфликт-чек + перерегистрация + ufw;
                                        rebuild + restart + откат при ошибке)
    POST   /api/settings/mieru-ports — смена диапазона портов mita
    GET/POST /api/settings/cascade{,/status,/reset} — каскад Naive-leg
                                        (upstream в Caddyfile, формат
                                        https://user:pass@host:port);
                                        Mieru-relay (Variant B) в Chimera не
                                        применяется — честно отражено в ответе
    GET/POST /api/settings/warp{,/status,/reset}    — WARP через warp.py
                                        (full/selective/runet; режим из TUI
                                        сохраняется; WARP<->каскад
                                        взаимоисключающи — как BUG-150 апстрима)

НЕ реализовано (фронт получит 501 с внятным текстом): федерация, backup
import/export, управление hy2 из UI (per-user Hy2 — отдельный проект; статус —
GET работает), external-access/webBasePath из UI (nginx-фронт — TUI-пункт 4),
WS (заменён SSE-шимом).

ДЕЛЕГИРУЕМЫЕ ПРИМИТИВЫ:
    rest_api.py        — _get_users/_save_users/_sync_* (юзер-мост v4.25)
    naiveproxy.py      — state users, _build_naive_link
    mieru.py           — state users
    ttl_users.py       — expiry
    user_lifecycle.py  — квоты (traffic_limits.json)
    subscription.py    — единая подписка + UA-детект + токены (pepper)
    traffic_accounting.py — v83.4: накопительный per-user трафик
                            (mieru — journalctl mita, naiveproxy — access.log)
"""
from __future__ import annotations

import base64
import hmac
import json
import platform
import queue
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

# ── Пути (синхронизированы с triple_panel.py) ────────────────────────────────
STATE_DIR   = Path("/var/lib/xray-installer")
_STATE_FILE = STATE_DIR / "triple_panel_state.json"
_WWW_DIR    = STATE_DIR / "triple_panel_www"
_LOG_FILE   = Path("/var/log/chimera.log")

_SESSION_COOKIE = "tp_session"
_SESSION_TTL    = 86400  # 24 часа — как у апстрима (maxAge 86400000 мс)
_BODY_LIMIT     = 1_048_576  # 1 МБ

# Юзеры без лимита/даты — что отдавать фронтенду:
_NO_QUOTA_MB = 0
_NO_EXPIRY = None

# ── v83.4: бинари/пути для stats/hy2/diagnostics/stub (синхронизированы
#    с naiveproxy.py / mieru.py / hysteria2_common.py) ────────────────────────
_MITA_BIN     = Path("/usr/local/bin/mita")
_CADDY_BIN    = Path("/usr/local/bin/caddy-naive")
_HY2_BIN      = Path("/usr/local/bin/hysteria")
_CADDYFILE    = Path("/etc/caddy-naive/Caddyfile")
_HY2_SERVICE  = "hysteria-server"
_HY2_UNIT     = Path("/etc/systemd/system/hysteria-server.service")
_HY2_CONFIG   = Path("/etc/hysteria/config.yaml")
_HY2_STATE    = Path("/var/lib/xray-installer/state.json")
_MIERU_STATE  = Path("/var/lib/xray-installer/mieru.json")
_STUB_FILE    = Path("/var/www/panel-stub/index.html")
_STUB_LIMIT   = 256 * 1024  # как у апстрима

# ══════════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}

_SSE_LOG_RING: list = []       # v82: последние строки лога (для /api/logs/panel)
_SSE_LOG_RING_MAX = 200

def _log(level: str, msg: str) -> None:
    line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"[TRIPLE-WEB][{level}] {msg}")
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    # v82: кольцо для /api/logs/panel + live-событие 'log' (SSE)
    try:
        _SSE_LOG_RING.append(line)
        if len(_SSE_LOG_RING) > _SSE_LOG_RING_MAX:
            del _SSE_LOG_RING[:-_SSE_LOG_RING_MAX]
        _sse_publish("log", {"line": line})
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
#  СЕССИИ (in-memory, сброс при рестарте — как у апстрима express-session)
# ══════════════════════════════════════════════════════════════════════════════
_SESSIONS: dict = {}

def _session_create(username: str) -> str:
    token = secrets.token_hex(16)
    _SESSIONS[token] = {"user": username, "exp": time.time() + _SESSION_TTL}
    # Подчистка протухших (лениво, без отдельного потока).
    now = time.time()
    for t in [t for t, s in _SESSIONS.items() if s["exp"] < now]:
        _SESSIONS.pop(t, None)
    return token

def _session_user(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    s = _SESSIONS.get(token)
    if not s:
        return None
    if s["exp"] < time.time():
        _SESSIONS.pop(token, None)
        return None
    return s["user"]

def _session_drop(token: Optional[str]) -> None:
    if token:
        _SESSIONS.pop(token, None)

def _check_credentials(state: dict, username: str, password: str) -> bool:
    """SHA-256(соль+пароль) — constant-time compare."""
    salt = state.get("admin_pass_salt", "")
    digest = state.get("admin_pass_sha256", "")
    if not salt or not digest:
        return False
    import hashlib
    candidate = hashlib.sha256((salt + (password or "")).encode()).hexdigest()
    return hmac.compare_digest(candidate, digest)

# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED-ЮЗЕРЫ (view поверх users.json + proto states + TTL + limits + token)
# ══════════════════════════════════════════════════════════════════════════════
def _naive_state() -> dict:
    from chimera.modules.proto_common import proto_load_state
    from chimera.modules.naiveproxy import _MODULE_STATE
    return proto_load_state(Path(_MODULE_STATE), {"users": []})

def _mieru_state() -> dict:
    from chimera.modules.proto_common import proto_load_state
    from chimera.modules.mieru import _MODULE_STATE
    return proto_load_state(Path(_MODULE_STATE), {"users": []})

def _ttl_data() -> dict:
    try:
        from chimera.modules.ttl_users import _ttl_load
        return _ttl_load() or {}
    except Exception:
        return {}

def _traffic_limits() -> dict:
    try:
        from chimera.modules.subscription import _load_traffic_limits
        return _load_traffic_limits() or {}
    except Exception:
        return {}

def _sub_token_for_user(user: dict) -> str:
    """Токен единой подписки (то же pepper-пространство, что у /sub апстрима
    Химеры — один токен на юзера во всех раздачах)."""
    try:
        from chimera.modules import subscription as sub
        cfg = sub._load_sub_conf()
        pepper = sub._ensure_pepper(cfg)
        return sub._token_for(user.get("uuid", ""), pepper)
    except Exception:
        return ""

def _panel_user_row(user: dict, naive_users: list, mieru_users: list,
                    ttl: dict, limits: dict) -> dict:
    """Собирает строку юзера в форме контракта панели.

    user — запись users.json (email/uuid/name/created); naive/mieru_users —
    списки {username,password} из module state; ttl — ttl_users.json;
    limits — traffic_limits.json.
    """
    email = user.get("email", "")
    username = (user.get("name") or email.split("@")[0]) if email else ""
    prefix = email.split("@")[0] if email else ""

    protocols = []
    if any(u.get("username") == prefix for u in naive_users):
        protocols.append("naive")
    if any(u.get("username") == prefix for u in mieru_users):
        protocols.append("mieru")

    expiry = _NO_EXPIRY
    ttl_row = ttl.get(email) or {}
    if ttl_row.get("expires_at"):
        expiry = ttl_row["expires_at"]

    lim = limits.get(email) or {}
    quota_mb = int(lim.get("limit_gb", 0)) * 1024 if lim.get("limit_gb") else _NO_QUOTA_MB
    used_mb = round(int(lim.get("used_bytes", 0)) / (1024 * 1024), 2)

    disabled = bool(lim.get("disabled")) or bool(user.get("disabled"))

    return {
        "id": email,
        "email": email,
        "username": username,
        "protocols": protocols,
        "expiry": expiry,
        "quotaMB": quota_mb,
        "usedMB": used_mb,
        "createdAt": user.get("created", ""),
        "updatedAt": user.get("created", ""),
        "lastSeen": None,
        "subToken": _sub_token_for_user(user),
        "active": not disabled,
    }

def _assemble_panel_users() -> list:
    """Unified-таблица юзеров панели (панельный view над хранилищами Химеры)."""
    try:
        from chimera.modules.rest_api import _get_users
        vless_users = _get_users()
    except Exception as e:
        _log("ERR", f"_get_users: {e}")
        vless_users = []
    naive_users = _naive_state().get("users", [])
    mieru_users = _mieru_state().get("users", [])
    ttl = _ttl_data()
    limits = _traffic_limits()
    return [_panel_user_row(u, naive_users, mieru_users, ttl, limits)
            for u in vless_users]

# ══════════════════════════════════════════════════════════════════════════════
#  USER CRUD (делегация юзер-мосту v4.25 — тот же флоу, что у rest_api)
# ══════════════════════════════════════════════════════════════════════════════
_EMAIL_RE = re.compile(r"^[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

def _expiry_to_days(expiry: Optional[str]) -> Optional[int]:
    """ISO-дата → целые дни от сегодня (минимум 1). None/'' → None."""
    if not expiry:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", str(expiry).strip())
    if not m:
        return None
    import datetime
    try:
        target = datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    days = (target - datetime.date.today()).days + 1
    return max(1, days)

def _quota_to_gb(quota_mb, quota_gb) -> int:
    """quotaMB/quotaGb панели → limit_gb (GiB, округление вверх)."""
    try:
        if quota_gb:
            return int(quota_gb)
        if quota_mb:
            return max(1, -(-int(quota_mb) // 1024))  # ceil
    except (TypeError, ValueError):
        pass
    return 0

def _create_panel_user(payload: dict) -> "tuple[int, dict]":
    """POST /api/users: VLESS-юзер + автосинк протоколов + TTL + квота.

    Возвращает (http_status, response_json).
    """
    email = (payload.get("email") or "").strip()
    name = (payload.get("username") or "").strip() or (
        email.split("@")[0] if email else "")
    if not email or not _EMAIL_RE.match(email):
        return 400, {"error": "valid email required"}
    if "@" not in name and name == email.split("@")[0]:
        pass  # имя = префикс — валидно

    protocols = payload.get("protocols") or ["naive", "mieru"]
    if not isinstance(protocols, list):
        protocols = list(protocols)

    from chimera.modules import rest_api as ra
    core = None
    try:
        from chimera.modules.triple_panel import _core_module
        core = _core_module()
    except Exception:
        pass

    # Мёрж (не затереть юзеров, живущих только в config.json)
    try:
        ra._sync_users_from_config()
    except Exception:
        pass
    users = ra._get_users()
    if any(u.get("email") == email for u in users):
        return 409, {"error": "user already exists"}

    new_uuid = core.gen_uuid() if core else secrets.token_hex(16)
    portal_password = secrets.token_urlsafe(12)
    from datetime import datetime
    users.append({
        "uuid": new_uuid,
        "email": email,
        "name": name,
        "portal_password": portal_password,
        "created": datetime.now().isoformat(),
    })
    ra._save_users(users)
    try:
        if core:
            core._users_apply_to_config(users)
    except Exception as e:
        _log("WARN", f"_users_apply_to_config: {e}")

    user_dict = {"uuid": new_uuid, "email": email, "name": name}
    # Автосинк на ВСЕ активные протоколы (sync contract v4.25)
    protocol_sync = {}
    try:
        protocol_sync = ra._sync_ensure_user(name, user=user_dict)
    except Exception as e:
        _log("WARN", f"_sync_ensure_user: {e}")
        protocol_sync = {}

    # Чекбоксы протоколов: выключенные — снять (remove_user_full идемпотентен)
    try:
        if "naive" not in protocols:
            from chimera.modules.naiveproxy import remove_user_full as _nr
            _nr(user_dict)
        if "mieru" not in protocols:
            from chimera.modules.mieru import remove_user_full as _mr
            _mr(user_dict)
    except Exception as e:
        _log("WARN", f"protocol opt-out: {e}")

    # TTL (expiry)
    days = _expiry_to_days(payload.get("expiry"))
    if days:
        try:
            from chimera.modules.ttl_users import _ttl_set
            _ttl_set(email, days)
        except Exception as e:
            _log("WARN", f"_ttl_set: {e}")

    # Квота
    limit_gb = _quota_to_gb(payload.get("quotaMB"), payload.get("quotaGb"))
    if limit_gb:
        try:
            from chimera.modules.user_lifecycle import _set_traffic_limit
            _set_traffic_limit(email, limit_gb)
        except Exception as e:
            _log("WARN", f"_set_traffic_limit: {e}")

    _log("INFO", f"user created: {email} (protocols sync: {protocol_sync})")
    return 201, {
        "status": "created",
        "id": email,
        "email": email,
        "uuid": new_uuid,
        "portal_login": name or email,
        "portal_password": portal_password,
        "protocol_sync": protocol_sync,
    }

def _delete_panel_user(email: str) -> "tuple[int, dict]":
    """DELETE /api/users/:id — удаляет юзера из всех хранилищ."""
    from chimera.modules import rest_api as ra
    try:
        ra._sync_users_from_config()
    except Exception:
        pass
    users = ra._get_users()
    target = next((u for u in users if u.get("email") == email), None)
    if not target:
        return 404, {"error": "user not found"}
    users = [u for u in users if u.get("email") != email]
    ra._save_users(users)
    try:
        from chimera.modules.triple_panel import _core_module
        core = _core_module()
        core._users_apply_to_config(users)
    except Exception as e:
        _log("WARN", f"_users_apply_to_config: {e}")
    user_dict = {"uuid": target.get("uuid", ""), "email": email,
                 "name": target.get("name", "")}
    try:
        ra._sync_remove_user(target.get("name") or email, user=user_dict)
    except Exception as e:
        _log("WARN", f"_sync_remove_user: {e}")
    try:
        from chimera.modules.ttl_users import _ttl_remove
        _ttl_remove(email)
    except Exception:
        pass
    try:
        from chimera.modules.user_lifecycle import _remove_traffic_limit
        _remove_traffic_limit(email)
    except Exception:
        pass
    _log("INFO", f"user deleted: {email}")
    return 200, {"status": "deleted", "id": email}

def _update_panel_user(email: str, payload: dict) -> "tuple[int, dict]":
    """PUT /api/users/:id — v82: password (ротация протоколов), email/username
    (rename через юзер-мост v4.25), expiry / квота / чекбоксы протоколов.

    Один пароль юзера применяется в оба протокола (модель апстрима);
    при создании пароль генерит мост — здесь только ротация. uuid не
    меняется, поэтому подписка/токен переживают смену email.
    """
    from chimera.modules import rest_api as ra
    try:
        ra._sync_users_from_config()
    except Exception:
        pass
    users = ra._get_users()
    target = next((u for u in users if u.get("email") == email), None)
    if not target:
        return 404, {"error": "user not found"}
    user_dict = {"uuid": target.get("uuid", ""), "email": email,
                 "name": target.get("name", "")}
    changed = []

    # 1) Ротация пароля протоколов (naive + mieru, один пароль на юзера)
    new_password = payload.get("password")
    if isinstance(new_password, str) and new_password.strip():
        pw = new_password.strip()
        if len(pw) < 8:
            return 400, {"error": "password must be at least 8 chars"}
        applied = []
        try:
            from chimera.modules.naiveproxy import set_password_full as _ns
            if _ns(user_dict, pw):
                applied.append("naive")
        except Exception as e:
            _log("WARN", f"naive set_password: {e}")
        try:
            from chimera.modules.mieru import set_password_full as _ms
            if _ms(user_dict, pw):
                applied.append("mieru")
        except Exception as e:
            _log("WARN", f"mieru set_password: {e}")
        if not applied:
            return 409, {"error": "no protocol accounts to rotate"}
        changed.append("password")

    # 2) Смена email/username — rename через мост (TTL и квоты переносятся
    #    на новый email, uuid не меняется — подписка/токен остаются)
    new_email = (payload.get("email") or "").strip()
    new_name = (payload.get("username") or "").strip()
    old_email, old_name = email, (target.get("name") or "")
    email_renamed = bool(new_email) and new_email != old_email
    name_renamed = bool(new_name) and new_name != old_name
    if email_renamed or name_renamed:
        if email_renamed:
            if not _EMAIL_RE.match(new_email):
                return 400, {"error": "valid email required"}
            if any(u.get("email") == new_email and u is not target
                   for u in users):
                return 409, {"error": "Email already in use"}
        final_email = new_email or old_email
        final_name = new_name or (
            final_email.split("@")[0] if "@" in final_email else final_email)
        old_user = dict(user_dict)
        new_user = {"uuid": target.get("uuid", ""), "email": final_email,
                    "name": final_name}
        for u in users:
            if u is target:
                u["email"] = final_email
                u["name"] = final_name
        ra._save_users(users)
        try:
            from chimera.modules.triple_panel import _core_module
            core = _core_module()
            core._users_apply_to_config(users)
        except Exception as e:
            _log("WARN", f"_users_apply_to_config: {e}")
        try:
            ra._sync_rename_user(old_name or old_email, final_name,
                                 old_user, new_user)
        except Exception as e:
            _log("WARN", f"_sync_rename_user: {e}")
        # TTL/квоты ключуются по email — переносим за юзером
        try:
            from chimera.modules.ttl_users import (
                _ttl_load, _ttl_set, _ttl_remove)
            row = (_ttl_load() or {}).get(old_email)
            if row:
                _ttl_remove(old_email)
                _ttl_set(final_email, max(1, int(row.get("days", 1) or 1)))
        except Exception as e:
            _log("WARN", f"ttl transfer: {e}")
        try:
            from chimera.modules.subscription import _load_traffic_limits
            from chimera.modules.user_lifecycle import (
                _set_traffic_limit, _remove_traffic_limit)
            row = (_load_traffic_limits() or {}).get(old_email)
            if row:
                _remove_traffic_limit(old_email)
                _set_traffic_limit(final_email,
                                   int(row.get("limit_gb", 0) or 0))
        except Exception as e:
            _log("WARN", f"limits transfer: {e}")
        email = final_email
        user_dict = new_user
        if email_renamed:
            changed.append("email")
        if name_renamed:
            changed.append("username")

    # 3) expiry
    if "expiry" in payload:
        days = _expiry_to_days(payload.get("expiry"))
        if days:
            try:
                from chimera.modules.ttl_users import _ttl_set
                _ttl_set(email, days)
                changed.append("expiry")
            except Exception as e:
                _log("WARN", f"_ttl_set: {e}")
        else:
            try:
                from chimera.modules.ttl_users import _ttl_remove
                _ttl_remove(email)
                changed.append("expiry")
            except Exception:
                pass

    # 4) quotaMB
    if "quotaMB" in payload or "quotaGb" in payload:
        limit_gb = _quota_to_gb(payload.get("quotaMB"), payload.get("quotaGb"))
        try:
            if limit_gb:
                from chimera.modules.user_lifecycle import _set_traffic_limit
                _set_traffic_limit(email, limit_gb)
            else:
                from chimera.modules.user_lifecycle import _remove_traffic_limit
                _remove_traffic_limit(email)
            changed.append("quota")
        except Exception as e:
            _log("WARN", f"quota: {e}")

    # 5) protocols
    protocols = payload.get("protocols")
    if isinstance(protocols, list):
        try:
            if "naive" in protocols:
                from chimera.modules.naiveproxy import ensure_user_full
                ensure_user_full(user_dict)
            else:
                from chimera.modules.naiveproxy import remove_user_full
                remove_user_full(user_dict)
            if "mieru" in protocols:
                from chimera.modules.mieru import ensure_user_full
                ensure_user_full(user_dict)
            else:
                from chimera.modules.mieru import remove_user_full
                remove_user_full(user_dict)
            changed.append("protocols")
        except Exception as e:
            _log("WARN", f"protocols: {e}")

    _log("INFO", f"user updated: {email} ({changed})")
    return 200, {"ok": True, "status": "updated", "id": email,
                 "changed": changed, "servicesReloading": True}

# ══════════════════════════════════════════════════════════════════════════════
#  v82: SSE LIVE-ОБНОВЛЕНИЯ + НАСТРОЙКИ СЕРВЕРА (порты/каскад/WARP/логи)
#  Апстримный фронт общается с бэкендом по WS (только метрики).
#  Chimera-бэкенд — stdlib: вместо WS — /api/events (SSE). Шим
#  triple-sse.js (вживляется во фронт при установке) подменяет
#  window.WebSocket классом поверх EventSource, поэтому контракт
#  сообщений (msg.type == 'metrics') сохранён без правок app.js.
# ══════════════════════════════════════════════════════════════════════════════

# ── SSE-шина ────────────────────────────────────────────────────────────────
_SSE_CLIENTS: list = []
_SSE_LOCK = threading.Lock()

def _sse_subscribe() -> "queue.Queue":
    q: "queue.Queue" = queue.Queue(maxsize=256)
    with _SSE_LOCK:
        _SSE_CLIENTS.append(q)
    return q

def _sse_unsubscribe(q: "queue.Queue") -> None:
    with _SSE_LOCK:
        try:
            _SSE_CLIENTS.remove(q)
        except ValueError:
            pass

def _sse_publish(event: str, data) -> None:
    """Событие всем SSE-клиентам. data — dict (→json) или готовая строка."""
    if not isinstance(data, str):
        data = json.dumps(data, ensure_ascii=False)
    with _SSE_LOCK:
        clients = list(_SSE_CLIENTS)
    for q in clients:
        try:
            q.put_nowait((event, data))
        except queue.Full:
            pass  # медленный клиент — дроп, рассылку не блокируем

# ── метрики (контракт msg WS апстрима: cpu/ram/naive/mieru) ───────────────────
_CPU_TICKS: dict = {"prev": None}

def _read_cpu_percent() -> float:
    """Загрузка CPU между вызовами (первый вызов — 0.0)."""
    try:
        parts = open("/proc/stat").readline().split()[1:]
        idle = int(parts[3]) + int(parts[4])
        total = sum(int(p) for p in parts)
        prev = _CPU_TICKS["prev"]
        _CPU_TICKS["prev"] = (idle, total)
        if not prev:
            return 0.0
        d_idle, d_total = idle - prev[0], total - prev[1]
        if d_total <= 0:
            return 0.0
        return round(max(0.0, 100.0 * (1.0 - d_idle / d_total)), 1)
    except Exception:
        return 0.0

def _read_ram_mb() -> "tuple[int, int]":
    """(usedMB, totalMB) из /proc/meminfo."""
    try:
        info = {}
        for line in open("/proc/meminfo"):
            k, _, v = line.partition(":")
            info[k.strip()] = int(v.strip().split()[0])  # kB
        total = info.get("MemTotal", 0) // 1024
        avail = info.get("MemAvailable", 0) // 1024
        return max(0, total - avail), total
    except Exception:
        return 0, 0

def _svc_active(name: str) -> bool:
    import subprocess
    try:
        r = subprocess.run(["systemctl", "is-active", name],
                           capture_output=True, check=False, timeout=5)
        return r.returncode == 0 and r.stdout.decode().strip() == "active"
    except Exception:
        return False

# ── watcher: diff живого состояния → события ────────────────────────────
_SSE_POLL_SEC = 3.0
_SSE_METRICS_SEC = 5.0
_WATCHER: dict = {"users_fp": None, "services": None, "metrics_ts": 0.0}

def _watcher_tick() -> None:
    users = _assemble_panel_users()
    fp = json.dumps(users, sort_keys=True, default=str)
    if fp != _WATCHER["users_fp"]:
        _WATCHER["users_fp"] = fp
        _sse_publish("users", users)
    services = {svc: _svc_active(svc)
                for svc in ("caddy-naive", "mita", "hysteria-server", "xray")}
    if services != _WATCHER["services"]:
        _WATCHER["services"] = services
        _sse_publish("status", services)
    if time.time() - _WATCHER["metrics_ts"] >= _SSE_METRICS_SEC:
        _WATCHER["metrics_ts"] = time.time()
        ram_used, ram_total = _read_ram_mb()
        _sse_publish("metrics", {
            "type": "metrics",
            "cpu": _read_cpu_percent(),
            "ramUsedMB": ram_used,
            "ramTotalMB": ram_total,
            "naive": services.get("caddy-naive", False),
            "mieru": services.get("mita", False),
        })

def _sse_watcher() -> None:
    """Демон-поток: живые события для открытых SSE-клиентов."""
    while True:
        try:
            _watcher_tick()
        except Exception as e:
            _log("WARN", f"sse watcher: {e}")
        time.sleep(_SSE_POLL_SEC)

# ── egress IP (для warp/cascade-ответов; кэш 30с, чтобы не долбить ipify) ────
_EGRESS_CACHE: dict = {"ts": 0.0, "ip": ""}

def _egress_ip(timeout: int = 6) -> str:
    if _EGRESS_CACHE["ip"] and time.time() - _EGRESS_CACHE["ts"] < 30:
        return _EGRESS_CACHE["ip"]
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org",
                                    timeout=timeout) as r:
            ip = r.read(64).decode(errors="replace").strip()
        if ip:
            _EGRESS_CACHE.update(ts=time.time(), ip=ip)
            return ip
    except Exception:
        pass
    return ""

# ── логи сервисов (journalctl / кольцо лога панели) ─────────────────────────
_LOG_SERVICES = {
    "naive": "caddy-naive", "caddy": "caddy-naive",
    "mieru": "mita",
    "hy2": "hysteria-server", "hysteria": "hysteria-server",
}

def _journal_tail(unit: str, lines: int) -> str:
    import subprocess
    try:
        r = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"],
            capture_output=True, check=False, timeout=6)
        out = r.stdout.decode(errors="replace").strip()
        return out or "(no logs available)"
    except Exception:
        return "(no logs available)"

def _logs_response(service: str, lines: int) -> "tuple[int, dict]":
    try:
        lines = max(1, min(int(lines), 1000))
    except (TypeError, ValueError):
        lines = 100
    if service in ("panel", "triple", "triple-web"):
        text = "\n".join(_SSE_LOG_RING[-lines:]) or "(no logs available)"
        return 200, {"logs": text}
    unit = _LOG_SERVICES.get(service)
    if not unit:
        return 400, {"error": "Unknown service"}
    return 200, {"logs": _journal_tail(unit, lines)}

# ══════════════════════════════════════════════════════════════════════════════
#  v83.4: /api/stats/users + /api/settings/hy2 + /api/diagnostics + /api/panel/stub
#  (все источники изолированы — один умерший источник НЕ зануляет остальные,
#   паттерн BUG-160 апстрима)
# ══════════════════════════════════════════════════════════════════════════════

def _run_cmd(cmd: list, timeout: int = 6) -> str:
    """subprocess-обёртка: любой провал → '' (никогда не бросает)."""
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, check=False,
                           timeout=timeout)
        return r.stdout.decode(errors="replace").strip()
    except Exception:
        return ""

_SIZE_RE = re.compile(r"^([\d.]+)\s*([KMGT]?I?B)$", re.I)

def _to_mb(v: float, unit: str) -> float:
    """Размер+единица → МБ (IEC и десятичные написания, как toMB апстрима)."""
    u = (unit or "").upper()
    if u == "B":
        return v / 1048576
    if u in ("KB", "KIB"):
        return v / 1024
    if u in ("GB", "GIB"):
        return v * 1024
    if u in ("TB", "TIB"):
        return v * 1048576
    return v  # MB / MiB

def _mita_live_users() -> dict:
    """`mita get users` → {username: {uploadMB, downloadMB, usedMB, lastSeen}}.

    Таблица mita (Bug 78 апстрима): User LastActive 1DayDown 1DayUp
    30DaysDown 30DaysUpload — берём 30-дневные колонки (последние 4 = размеры).
    Бинаря нет / пустой вывод / мусор → {} (вызывающий фолбэчится на
    traffic_accounting).
    """
    try:
        if not _MITA_BIN.exists():
            return {}
    except OSError:
        return {}
    raw = _run_cmd([str(_MITA_BIN), "get", "users"], timeout=8)
    out: dict = {}
    for raw_line in (raw or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # заголовок и разделители пропускаем
        if re.match(r"^user\b", line, re.I) or re.match(r"^[-=\s]+$", line):
            continue
        cols = line.split()
        if len(cols) < 6:
            continue
        username, last_active = cols[0], cols[1]
        vals = []
        for c in cols[-4:]:
            m = _SIZE_RE.match(c)
            if not m:
                vals = None
                break
            vals.append(_to_mb(float(m.group(1)), m.group(2)))
        if not vals:
            continue
        _d1, _u1, d30, u30 = vals
        out[username] = {
            "uploadMB": round(u30, 2),
            "downloadMB": round(d30, 2),
            "usedMB": round(u30 + d30, 2),
            "lastSeen": last_active
            if re.match(r"^\d{4}-\d{2}-\d{2}T", last_active) else None,
        }
    return out

def _accounting_user_bytes(username: str) -> dict:
    """traffic_accounting: {protocol: bytes} по юзеру (mieru/naiveproxy/…)."""
    if not username:
        return {}
    try:
        from chimera.modules.traffic_accounting import get_all_accumulated
        return get_all_accumulated(username) or {}
    except Exception:
        return {}

def _naive_server_total_mb() -> float:
    """Серверный итог Naive (МБ) из systemd IPAccounting caddy-naive.

    Единственный надёжный источник по Naive: forward_proxy захватывает
    CONNECT-туннели и access.log их не пишет (BUG-163 апстрима).
    """
    out = _run_cmd(["systemctl", "show", "caddy-naive",
                    "-p", "IPIngressBytes", "-p", "IPEgressBytes"],
                   timeout=5)
    total = 0
    for line in out.splitlines():
        k, _, v = line.partition("=")
        if k.strip() in ("IPIngressBytes", "IPEgressBytes"):
            try:
                total += int(v.strip() or 0)
            except ValueError:
                pass
    return round(total / 1048576, 2)

def _stats_users_payload() -> dict:
    """GET /api/stats/users — контракт апстрима {users, naiveServerTotalMB,
    naivePerUser}.

    Источники (каждый изолирован): `mita get users` (30-дневные live-цифры,
    как у апстрима) → фолбэк traffic_accounting (накопительный per-user);
    naive per-user — access.log-аккаунтинг Химеры (best-effort: CONNECT не
    пишется, up/down нет → в download, конвенция Subscription-Userinfo);
    usedMB — квотосчётчик traffic_limits (авторитет для полосы квоты),
    при отсутствии записи — сумма up+down; hy2 — per-exit-node в Chimera,
    per-user Hy2 отложен → честный 0.
    """
    rows = _assemble_panel_users()
    limits = _traffic_limits()
    live = _mita_live_users()
    users = []
    for row in rows:
        email = row.get("email", "")
        prefix = (row.get("username")
                  or (email.split("@")[0] if email else "")) or ""
        acc = _accounting_user_bytes(prefix)
        naive_mb = round((acc.get("naiveproxy") or 0) / 1048576, 2)
        lv = live.get(prefix) or {}
        if lv:
            mieru_mb = round((lv.get("uploadMB") or 0)
                             + (lv.get("downloadMB") or 0), 2)
            up = lv.get("uploadMB") or 0.0
            down = lv.get("downloadMB") or 0.0
            last_seen = lv.get("lastSeen")
        else:
            mieru_mb = round((acc.get("mieru") or 0) / 1048576, 2)
            up, down, last_seen = 0.0, mieru_mb, None
        # naive: раздельного up/down нет → весь объём в download
        down += naive_mb
        hy2_mb = 0.0
        lim = limits.get(email) or {}
        used = row.get("usedMB") or 0.0
        if not (lim.get("used_bytes") or lim.get("limit_gb")):
            used = round(up + down, 2)
        users.append({
            "username": row.get("username"),
            "email": email,
            "expiry": row.get("expiry"),
            "protocols": row.get("protocols") or [],
            "quotaMB": row.get("quotaMB") or 0,
            "usedMB": round(used, 2),
            "uploadMB": round(up, 2),
            "downloadMB": round(down, 2),
            "naiveMB": naive_mb,
            "mieruMB": mieru_mb,
            "hy2MB": hy2_mb,
            "lastSeen": last_seen,
        })
    return {"users": users,
            "naiveServerTotalMB": _naive_server_total_mb(),
            "naivePerUser": False}

# ── v83.4: Hysteria2 статус ──────────────────────────────────────────────

def _hy2_installed() -> bool:
    """Юнит есть / конфиг есть / секция state включена."""
    try:
        if _HY2_UNIT.exists():
            return True
    except OSError:
        pass
    try:
        if _HY2_CONFIG.exists():
            return True
    except OSError:
        pass
    try:
        st = json.loads(_HY2_STATE.read_text())
        return bool((st.get("hysteria2") or {}).get("enabled"))
    except Exception:
        return False

def _hy2_port() -> int:
    """listen-порт из /etc/hysteria/config.yaml → state → 443.

    Форматы: `listen: :443`, `listen: 0.0.0.0:443`, `listen: 8443`.
    Порт — ПОСЛЕДНЕЕ число строки (иначе 0.0.0.0:443 отдал бы первый «0»).
    """
    try:
        for line in _HY2_CONFIG.read_text(errors="replace").splitlines():
            if not re.match(r"^listen:", line.strip()):
                continue
            nums = re.findall(r"\d+", line.split("#", 1)[0])
            if nums:
                return int(nums[-1])
    except Exception:
        pass
    try:
        st = json.loads(_HY2_STATE.read_text())
        ports = (st.get("hysteria2") or {}).get(
            "firewall", {}).get("udp_ports") or []
        if ports:
            return int(ports[0])
    except Exception:
        pass
    return 443

def _hy2_view() -> dict:
    installed = _hy2_installed()
    return {
        "installed": installed,
        "active": installed and _svc_active(_HY2_SERVICE),
        "port": _hy2_port(),
        "stack": {
            "naive": bool(_naive_state().get("users")),
            "mieru": bool(_mieru_state().get("users")),
            "hy2": installed,
        },
        # per-user Hy2 в Chimera нет (Hy2 — per-exit-node, решено юзером);
        # честный 0 вместо выдуманных цифр
        "hy2UserCount": 0,
        "chimeraNote": "Управление Hysteria2 — меню Химеры; per-user Hy2 не "
                       "поддерживается (exit-node архитектура)",
    }

# ── v83.4: системные метрики для /api/status (контракт апстрима) ─────────

def _os_pretty() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return ""

def _uptime_sec() -> int:
    try:
        return int(float(open("/proc/uptime").read().split()[0]))
    except Exception:
        return 0

def _disk_gb() -> "tuple[int, int]":
    try:
        import shutil
        u = shutil.disk_usage("/")
        return round(u.used / 1073741824), round(u.total / 1073741824)
    except Exception:
        return 0, 0

def _local_ip() -> str:
    """Локальный IP без сетевого трафика (UDP connect пакет не шлёт)."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return ""

_VERSION_CACHE: dict = {"ts": 0.0, "naive": "", "mieru": "", "hy2": ""}

def _cached_versions() -> dict:
    """Версии бинарей (60с кэш — не спавним процессы на каждый поллинг)."""
    if time.time() - _VERSION_CACHE["ts"] < 60:
        return _VERSION_CACHE
    def _first_line(p: Path) -> str:
        out = _run_cmd([str(p), "version"], timeout=6)
        return (out.splitlines() or [""])[0].strip() if out else ""
    vals = {"ts": time.time(), "naive": "", "mieru": "", "hy2": ""}
    try:
        if _CADDY_BIN.exists():
            vals["naive"] = _first_line(_CADDY_BIN)
    except OSError:
        pass
    try:
        if _MITA_BIN.exists():
            vals["mieru"] = _first_line(_MITA_BIN)
    except OSError:
        pass
    try:
        if _HY2_BIN.exists() and _hy2_installed():
            vals["hy2"] = _first_line(_HY2_BIN)
    except OSError:
        pass
    _VERSION_CACHE.update(vals)
    return _VERSION_CACHE

def _status_view_payload() -> dict:
    """GET /api/status — контракт апстрима (loadDashboard/refreshStats)."""
    state = _load_state()
    from chimera.modules.triple_panel import _PORT_FRONT_VERSION
    naive = _naive_state()
    mieru = _mieru_state()
    hy2_inst = _hy2_installed()
    ver = _cached_versions()
    ram_used, ram_total = _read_ram_mb()
    disk_used, disk_total = _disk_gb()
    try:
        core_domain = (getattr(_core_module_cached(), "PARAM_DOMAIN", "")
                       or "")
    except Exception:
        core_domain = ""
    domain = core_domain or (naive.get("domain") or "")
    try:
        user_count = len(_assemble_panel_users())
    except Exception:
        user_count = 0
    return {
        "services": {
            "naive": {"active": _svc_active("caddy-naive"),
                      "version": ver["naive"]},
            "mieru": {"active": _svc_active("mita"),
                      "version": ver["mieru"]},
            "hy2": {"installed": hy2_inst,
                    "active": hy2_inst and _svc_active(_HY2_SERVICE),
                    "version": ver["hy2"] if hy2_inst else "",
                    "port": _hy2_port()},
            "panel": {"active": True},
        },
        "system": {
            "cpuPercent": round(_read_cpu_percent()),
            "ramUsedMB": ram_used,
            "ramTotalMB": ram_total,
            "diskUsedGB": disk_used,
            "diskTotalGB": disk_total,
            "uptime": _uptime_sec(),
            "os": _os_pretty(),
            "arch": platform.machine(),
        },
        "panel": {
            "userCount": user_count,
            "version": state.get("front_version", "") or _PORT_FRONT_VERSION,
        },
        "domain": domain,
        "serverIp": _local_ip(),
        "language": state.get("language", "ru"),
    }

# ── v83.4: /api/diagnostics ──────────────────────────────────────────────

def _port_listening(port: int) -> bool:
    """Слушается ли порт (TCP/UDP) — ss, как у апстрима."""
    if not port:
        return False
    out = _run_cmd(["ss", "-H", "-tlnup", f"sport = :{int(port)}"],
                   timeout=3)
    return bool(out) and f":{int(port)}" in out

def _time_synced() -> bool:
    out = _run_cmd(["timedatectl", "show", "-p", "NTPSynchronized",
                    "--value"], timeout=4)
    return out.strip().lower() == "yes"

def _caddyfile_user_count() -> int:
    """Число basic_auth-директив в Caddyfile (юзеры Naive)."""
    try:
        text = _CADDYFILE.read_text(errors="replace")
    except Exception:
        return 0
    return len(re.findall(r"^\s*basic_auth\s+\S+\s+\S+", text, re.M))

def _diagnostics_payload() -> dict:
    naive = _naive_state()
    mieru = _mieru_state()
    naive_port = int(naive.get("port", 443) or 443)
    mieru_start = int(mieru.get("port_start", 2012) or 2012)
    mieru_end = int(mieru.get("port_end", 2022) or 2022)
    hy2_inst = _hy2_installed()
    hy2_port = _hy2_port()
    ver = _cached_versions()
    try:
        caddy_exists = _CADDYFILE.exists()
    except OSError:
        caddy_exists = False
    probe = (naive.get("probe_secret") or "").strip()
    mieru_ports_listening = [p for p in (mieru_start, mieru_end)
                             if _port_listening(p)]
    return {
        "ports": {
            "naive": _port_listening(naive_port),
            "mieru": _port_listening(mieru_start),
            "mieruPorts": mieru_ports_listening,
            # Hy2 — UDP; ss -tlnup покрывает и его
            "hy2": hy2_inst and _port_listening(hy2_port),
            "hy2Port": hy2_port,
            "hy2Installed": hy2_inst,
        },
        "naiveVersionOk": bool(ver["naive"]),
        "naiveVersion": ver["naive"],
        "naiveConfigExists": caddy_exists,
        # htpasswd убран апстримом в v1.2.3 (юзеры в Caddyfile) — совместимость
        "htpasswdExists": False,
        "htpasswdUsers": 0,
        "caddyfileExists": caddy_exists,
        "caddyfileUsers": _caddyfile_user_count(),
        "mitaStatus": _run_cmd([str(_MITA_BIN), "status"], timeout=8)
        if _MITA_BIN.exists() else "",
        "mitaConfig": _run_cmd([str(_MITA_BIN), "describe", "config"],
                               timeout=8) if _MITA_BIN.exists() else "",
        "timeSynced": _time_synced(),
        "mitaStateFile": str(_MIERU_STATE),
        "probeSecretSet": bool(probe),
        "probeMode": "secret" if probe else "bare",
    }

# ── v83.4: /api/panel/stub (заглушка-страница) ────────────────────────────

def _stub_get() -> dict:
    html = ""
    try:
        html = _STUB_FILE.read_text(errors="replace")
    except Exception:
        pass
    return {"path": str(_STUB_FILE), "html": html}

def _stub_set(html) -> "tuple[int, dict]":
    """POST /api/panel/stub — атомарная запись (tmp + replace), 256 KiB."""
    if not isinstance(html, str):
        html = ""
    # артефакт буфера обмена и BOM — как у апстрима
    html = html.lstrip("\ufeff")
    html = re.sub(r"^Copy(?=\s*<)", "", html)
    if not html.strip():
        return 400, {"error": "Stub HTML must not be empty"}
    data = html.encode("utf-8")
    if len(data) > _STUB_LIMIT:
        return 400, {"error": "Stub HTML too large (max 256 KiB)"}
    try:
        _STUB_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STUB_FILE.with_name(_STUB_FILE.name + ".new")
        tmp.write_text(html, encoding="utf-8")
        tmp.chmod(0o644)
        tmp.replace(_STUB_FILE)  # атомарно — нет полу-записанной заглушки
    except Exception as e:
        return 500, {"error": f"Failed to write stub file: {e}"}
    return 200, {"ok": True, "path": str(_STUB_FILE), "bytes": len(data)}

# ── смена портов протоколов (port_registry + rebuild + откат) ─────────────

def _conflict_detail(conflicts: list) -> str:
    parts = []
    for c in conflicts[:5]:
        parts.append(str(c.get("detail", c)) if isinstance(c, dict) else str(c))
    return "; ".join(p for p in parts if p)

def _set_naive_port(payload: dict) -> "tuple[int, dict]":
    """POST /api/settings/naive-port — контракт апстрима (Bug 52)."""
    try:
        port = int(payload.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if port < 1 or port > 65535:
        return 400, {"error": "Invalid port (1-65535)"}
    try:
        from chimera.modules import naiveproxy as nv
        from chimera.modules.proto_common import proto_load_state, proto_save_state
        state = proto_load_state(nv._MODULE_STATE)
    except Exception:
        return 503, {"error": "naiveproxy module unavailable"}
    old = int(state.get("port", 443) or 443)
    if port == old:
        return 200, {"ok": True,
                     "message": f"NaiveProxy уже слушает порт {port}."}
    try:
        from chimera.modules import port_registry as pr
        conflicts = pr.port_get_conflicts(port, proto="tcp",
                                          exclude_service=pr.SERVICE_NAIVEPROXY)
        conflicts += pr.port_check_system(port, proto="tcp")
    except Exception:
        conflicts = []
    if conflicts:
        return 409, {"error": f"порт занят: {_conflict_detail(conflicts)}"}
    users = state.get("users", [])
    state["port"] = port
    try:
        proto_save_state(nv._MODULE_STATE, state)
    except Exception:
        return 500, {"error": "не удалось сохранить state naiveproxy"}

    def _apply(p: int):
        return nv._apply_config(
            state.get("domain", ""), p, users,
            state.get("fake_url", ""), state.get("probe_secret", ""),
            state.get("upstream", ""))

    err = _apply(port)
    if err:
        state["port"] = old
        try:
            proto_save_state(nv._MODULE_STATE, state)
            _apply(old)
        except Exception:
            pass
        return 500, {"ok": False, "error": str(err)}
    # смена порт-биндинга — полный restart (не reload), как у апстрима
    import subprocess
    try:
        subprocess.run(["systemctl", "restart", "caddy-naive"],
                       capture_output=True, check=False, timeout=25)
    except Exception:
        pass
    try:
        from chimera.modules import port_registry as pr
        pr.port_unregister(pr.SERVICE_NAIVEPROXY, port=old, proto="tcp")
        pr.port_register(pr.SERVICE_NAIVEPROXY, port, "tcp",
                         comment="NaiveProxy (Triple Panel)", force=True)
        # 443 может быть общим с другими сервисами — чужие правила не трогаем,
        # своё снимаем только при уходе с нестандартного порта
        if old != 443:
            pr.ufw_close_port(old, "tcp", pr.SERVICE_NAIVEPROXY,
                              legacy_comments=["NaiveProxy"])
        pr.ufw_open_port(port, "tcp", pr.SERVICE_NAIVEPROXY,
                         comment="Triple Panel")
    except Exception as e:
        _log("WARN", f"port_registry naive: {e}")
    if not _svc_active("caddy-naive"):
        return 500, {"ok": False,
                     "error": "caddy-naive failed to start after port change — "
                              "run: journalctl -u caddy-naive -n 30"}
    return 200, {"ok": True,
                 "message": f"NaiveProxy port changed to {port}. "
                            "Clients must download new configs."}

def _set_mieru_ports(payload: dict) -> "tuple[int, dict]":
    """POST /api/settings/mieru-ports — контракт апстрима (Bug 7)."""
    try:
        s = int(payload.get("portStart") or 0)
        e = int(payload.get("portEnd") or 0)
    except (TypeError, ValueError):
        return 400, {"error": "Invalid port range (1025-65535, end >= start)"}
    if not s or not e or s < 1025 or e > 65535 or e < s:
        return 400, {"error": "Invalid port range (1025-65535, end >= start)"}
    try:
        from chimera.modules import mieru as mr
        from chimera.modules.proto_common import proto_load_state, proto_save_state
        state = proto_load_state(mr._MODULE_STATE)
    except Exception:
        return 503, {"error": "mieru module unavailable"}
    old_s = int(state.get("port_start", 2012) or 2012)
    old_e = int(state.get("port_end", 2022) or 2022)
    if (s, e) == (old_s, old_e):
        return 200, {"ok": True, "message": f"Mieru уже слушает {s}-{e}."}
    try:
        from chimera.modules import port_registry as pr
        conflicts = []
        for p in range(s, e + 1):
            if old_s <= p <= old_e:
                continue
            conflicts += pr.port_get_conflicts(
                p, proto="tcp", exclude_service=pr.SERVICE_MIERU)
        conflicts += pr.port_check_system(s, proto="tcp")
        conflicts += pr.port_check_system(e, proto="tcp")
    except Exception:
        conflicts = []
    conflicts = [c for c in conflicts if c]
    if conflicts:
        return 409, {"error": f"порты заняты: {_conflict_detail(conflicts)}"}
    users = state.get("users", [])
    state["port_start"], state["port_end"] = s, e
    try:
        proto_save_state(mr._MODULE_STATE, state)
    except Exception:
        return 500, {"error": "не удалось сохранить state mieru"}

    def _apply(ps: int, pe: int):
        tp = mr._MIERU_TRAFFIC_PRESETS.get(
            state.get("traffic_preset", "basic"), {}).get("config")
        return mr._apply_server_config(mr._build_server_config(
            users, ps, pe, state.get("protocol", "TCP"), traffic_pattern=tp))

    err = _apply(s, e)
    if err:
        state["port_start"], state["port_end"] = old_s, old_e
        try:
            proto_save_state(mr._MODULE_STATE, state)
            _apply(old_s, old_e)
        except Exception:
            pass
        return 500, {"ok": False, "error": str(err)}
    import subprocess
    try:
        subprocess.run(["systemctl", "reload-or-restart", "mita"],
                       capture_output=True, check=False, timeout=25)
    except Exception:
        pass
    try:
        from chimera.modules import port_registry as pr
        pr.port_unregister_range(pr.SERVICE_MIERU, old_s, old_e, proto="tcp")
        pr.port_register_range(pr.SERVICE_MIERU, s, e, "tcp",
                               comment="Mieru (Triple Panel)")
        pr.ufw_close_port_range(old_s, old_e, "tcp", pr.SERVICE_MIERU)
        pr.ufw_open_port_range(s, e, "tcp", pr.SERVICE_MIERU,
                               comment="Triple Panel")
    except Exception as ex:
        _log("WARN", f"port_registry mieru: {ex}")
    return 200, {"ok": True,
                 "message": f"Mieru ports changed to {s}-{e}. Service restarted. "
                            "Clients must download new configs."}

# ── каскад (Naive-leg: upstream в Caddyfile; Mieru-relay в Chimera нет) ─────

def _cascade_view() -> dict:
    try:
        from chimera.modules.proto_common import proto_load_state
        from chimera.modules.naiveproxy import _MODULE_STATE as _NS
        nst = proto_load_state(_NS)
    except Exception:
        nst = {}
    try:
        from chimera.modules.proto_common import proto_load_state
        from chimera.modules.mieru import _MODULE_STATE as _MS
        mst = proto_load_state(_MS)
    except Exception:
        mst = {}
    upstream = nst.get("upstream", "") or ""
    return {
        "cascadeEnabled": bool(upstream),
        "cascadeNaiveUpstream": upstream,
        "cascadeMieru": {
            "host": "",
            "portStart": int(mst.get("port_start", 2012) or 2012),
            "portEnd": int(mst.get("port_end", 2022) or 2022),
            "user": "",
            "mtu": 1400,
            # exit-нода в Chimera-модели каскада отсутствует (relay не
            # применяется) — пароля нет, UI показывает пустое поле.
            "hasPass": False,
        },
    }

def _normalize_upstream(raw: str) -> str:
    """'naive+https://u:p@h:443#tag' → 'https://u:p@h:443' (формат Caddyfile).

    В отличие от normalizeUpstream апстрима креды СОХРАНЯЮТСЯ: директива
    upstream в caddy-forwardproxy-naive Химеры принимает полный URL с
    basic_auth (см. _cascade_menu в naiveproxy.py).
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    if raw.startswith("naive+"):
        raw = raw[len("naive+"):]
    raw = raw.split("#", 1)[0].strip().rstrip("/")
    if not raw:
        return ""
    if not raw.startswith(("https://", "http://")):
        raw = "https://" + raw.lstrip("/")
    if not re.match(r"^https?://([^/@\s]+@)?[^/@\s:]+(:\d+)?$", raw):
        return ""
    return raw

def _cascade_status_view() -> dict:
    view = _cascade_view()
    upstream = view["cascadeNaiveUpstream"]
    lines = [
        "=== NAIVE CASCADE (Entry→Exit) ===",
        f"caddy-naive: {'active' if _svc_active('caddy-naive') else 'inactive'}",
        f"upstream: {upstream or '(direct — каскад выключен)'}",
        "",
        "=== MIERU CASCADE (Variant B) ===",
        "не применяется в Chimera — mita работает напрямую (см. TUI 10/11).",
    ]
    return {"ok": bool(upstream) and _svc_active("caddy-naive"),
            "output": "\n".join(lines)}

def _cascade_apply(payload: dict) -> "tuple[int, dict]":
    """POST /api/settings/cascade — Naive-leg + взаимоисключение с WARP.

    Mieru-relay (Variant B: redsocks/mieru-client) в Chimera не существует —
    поле cascadeMieru принимается, но честно игнорируется (в ответе сказано).
    """
    enabled = bool(payload.get("cascadeEnabled"))
    try:
        from chimera.modules import naiveproxy as nv
        from chimera.modules.proto_common import proto_load_state, proto_save_state
        state = proto_load_state(nv._MODULE_STATE)
    except Exception:
        return 503, {"error": "naiveproxy module unavailable"}
    raw = payload.get("cascadeNaiveUpstream")
    upstream = state.get("upstream", "") or ""
    if raw is not None:
        upstream = _normalize_upstream(str(raw))
    if not enabled:
        upstream = ""
    elif not upstream:
        return 400, {"error": "cascadeEnabled требует cascadeNaiveUpstream"}
    # BUG-150 (апстрим): включение каскада снимает WARP
    warp_torn = False
    if enabled:
        try:
            from chimera.modules import warp
            if warp._state_get("WARP_CONNECTED", False):
                warp.uninstall_warp()
                warp_torn = True
                _log("INFO", "warp torn down by cascade enable")
        except Exception as e:
            _log("WARN", f"warp teardown: {e}")
    state["upstream"] = upstream
    try:
        proto_save_state(nv._MODULE_STATE, state)
    except Exception:
        return 500, {"error": "не удалось сохранить state naiveproxy"}
    err = nv._apply_config(
        state.get("domain", ""), int(state.get("port", 443) or 443),
        state.get("users", []), state.get("fake_url", ""),
        state.get("probe_secret", ""), upstream)
    caddy_ok = not err
    msg = (f"Cascade enabled. Naive upstream applied: {upstream}."
           if enabled else "Cascade disabled. Naive direct egress.")
    if enabled and isinstance(payload.get("cascadeMieru"), dict):
        m = payload.get("cascadeMieru") or {}
        if m.get("host") or m.get("user"):
            msg += (" Mieru-relay (Variant B) в Chimera не применяется — "
                    "настройки exit-ноды проигнорированы.")
    if warp_torn:
        msg += " WARP был автоматически отключён (взаимоисключение)."
    return 200, {
        "ok": caddy_ok, "caddyOk": caddy_ok, "mitaOk": True,
        "cascadeOk": caddy_ok, "caddyError": err or "",
        "cascadeOutput": ("Mieru-relay (Variant B) в Chimera не применяется — "
                          "mita работает напрямую."),
        "message": msg,
    }

def _cascade_reset() -> "tuple[int, dict]":
    status, payload = _cascade_apply({"cascadeEnabled": False})
    payload["teardownOk"] = True
    payload["nativeEgress"] = _egress_ip(8) or "(unknown)"
    payload["message"] = ("Каскад полностью сброшен: Caddyfile без upstream, "
                          "возврат к прямому egress.")
    return status, payload

# ── WARP (warp.py: full/selective/runet; WARP ↔ каскад взаимоисключающи) ────

def _warp_module():
    from chimera.modules import warp
    return warp

def _warp_connected() -> bool:
    try:
        return bool(_warp_module()._state_get("WARP_CONNECTED", False))
    except Exception:
        return False

def _warp_view() -> dict:
    ram = _read_ram_mb()[1]
    low = 0 < ram <= 1024
    return {
        "warpEnabled": _warp_connected(),
        # Chimera поддерживает WARP автономно (state.json + cron-синк) —
        # persist отражает фактическое поведение, а не отдельную опцию.
        "warpPersist": _warp_connected(),
        "cascadeEnabled": bool(_cascade_view()["cascadeNaiveUpstream"]),
        "ramMB": ram,
        "lowRam": low,
        "lowRamWarning": (
            "На VPS с ≤1 ГБ RAM дополнительный сетевой слой WARP (WireGuard) "
            "нагружает память — включайте только при необходимости."
            if low else ""),
    }

def _warp_status_view() -> dict:
    lines = ["=== WARP (chimera warp.py) ==="]
    try:
        w = _warp_module()
        lines.append(f"connected: {w._state_get('WARP_CONNECTED', False)}")
        lines.append(f"mode: {w._state_get('WARP_MODE', '') or '(n/a)'}")
        try:
            svc = w.WG_SERVICE
        except Exception:
            svc = "wg-quick@wgcf"
        lines.append(f"service {svc}: "
                     f"{'active' if _svc_active(svc) else 'inactive'}")
    except Exception as e:
        lines.append(f"(warp module unavailable: {e})")
    lines.append(f"egress IP: {_egress_ip() or '(unknown)'}")
    return {"ok": _warp_connected(), "enabled": _warp_connected(),
            "output": "\n".join(lines)}

def _warp_disable_cascade() -> bool:
    """BUG-150 (апстрим): включение WARP снимает каскад (naive upstream)."""
    try:
        from chimera.modules import naiveproxy as nv
        from chimera.modules.proto_common import proto_load_state, proto_save_state
        state = proto_load_state(nv._MODULE_STATE)
        if not (state.get("upstream", "") or ""):
            return False
        state["upstream"] = ""
        proto_save_state(nv._MODULE_STATE, state)
        nv._apply_config(
            state.get("domain", ""), int(state.get("port", 443) or 443),
            state.get("users", []), state.get("fake_url", ""),
            state.get("probe_secret", ""), "")
        return True
    except Exception as e:
        _log("WARN", f"cascade teardown: {e}")
        return False

def _set_warp(payload: dict) -> "tuple[int, dict]":
    """POST /api/settings/warp — режим warp.py сохраняется; full без SSH-IP
    деградирует до runet (защита от потери доступа из веба)."""
    enabled = bool((payload or {}).get("warpEnabled"))
    try:
        w = _warp_module()
    except Exception:
        return 503, {"error": "warp module unavailable"}
    if not enabled:
        try:
            w.uninstall_warp()
        except Exception as e:
            _log("WARN", f"uninstall_warp: {e}")
        egress = _egress_ip(8)
        msg = "WARP выключен. Возврат к родному IP сервера."
        return 200, {"ok": True, "warpEnabled": False, "warpPersist": False,
                     "egressIP": egress or "(unknown)", "output": "",
                     "warpResult": {"severity": "success", "code": "disabled",
                                    "message": msg},
                     "message": msg}
    # включение: каскад сначала снимается (взаимоисключение)
    cascade_cleared = _warp_disable_cascade()
    mode = w._state_get("WARP_MODE", "") or "runet"
    ssh_ip = w._state_get("WARP_SSH_CLIENT_IP", "") or ""
    degraded = ""
    if mode == "full" and not ssh_ip:
        mode = "runet"
        degraded = (" full без SSH-IP из веба не включается (риск потери "
                    "доступа) — использован runet; задайте SSH-IP в TUI (WARP).")
    ok = False
    try:
        ok = bool(w.configure_warp(mode, ssh_ip))
    except Exception as e:
        _log("WARN", f"configure_warp: {e}")
        ok = False
    egress = _egress_ip(10)
    if ok:
        msg = (f"WARP включён в режиме '{mode}' — egress через Cloudflare "
               f"(IP {egress or '?'}). SSH и панель доступны напрямую."
               + (" Каскад был автоматически отключён." if cascade_cleared else "")
               + degraded)
        wresult = {"severity": "success", "code": "ok",
                   "egressIP": egress or "(unknown)", "message": msg}
    else:
        msg = ("WARP включить не удалось. Всё откачено, доступ к серверу "
               "сохранён. Подробности: TUI Химеры → WARP; journalctl -u "
               "wg-quick@*")
        wresult = {"severity": "warning", "code": "unknown", "message": msg}
    return 200, {"ok": ok, "warpEnabled": ok, "warpPersist": ok,
                 "egressIP": egress or "(unknown)", "output": "",
                 "warpResult": wresult, "message": msg}

def _warp_reset() -> "tuple[int, dict]":
    try:
        w = _warp_module()
        w.uninstall_warp()
    except Exception as e:
        _log("WARN", f"uninstall_warp: {e}")
    egress = _egress_ip(8)
    return 200, {"ok": True, "warpEnabled": False,
                 "nativeEgress": egress or "(unknown)", "output": "",
                 "message": "WARP полностью снят: интерфейс/маршруты удалены, "
                            "возврат к родному IP."}

# ══════════════════════════════════════════════════════════════════════════════
#  ПОДПИСКА /sub/:token (UA-детект — полная делегация subscription.py)
# ══════════════════════════════════════════════════════════════════════════════
def _sub_response(token: str, requested_format: str,
                  user_agent: str) -> "tuple[int, dict, Optional[bytes]]":
    """Возвращает (status, headers, body) для GET /sub/:token.

    Форматы: base64 (default) / base64_safe / singbox / clash.
    Заголовок Subscription-Userinfo — только если лимит задан (как у
    апстрима: total=0 некоторые клиенты трактуют как «исчерпано»).
    """
    try:
        from chimera.modules import subscription as sub
        cfg = sub._load_sub_conf()
        pepper = sub._ensure_pepper(cfg)
        user = sub._find_user_by_token(token, pepper)
        if not user:
            return 404, {"Content-Type": "text/plain"}, b"not found\n"
        fmt = sub._resolve_format(requested_format, user_agent)
        if fmt == "singbox":
            body = sub.build_subscription_singbox_config(user).encode()
            ctype = "application/json; charset=utf-8"
        elif fmt == "clash":
            try:
                from chimera.modules.subscription_multinode import (
                    build_mihomo_config)
                body = build_mihomo_config(user).encode()
            except Exception as e:
                _log("WARN", f"clash builder: {e}")
                return 501, {"Content-Type": "application/json"}, (
                    json.dumps({"error": "clash format unavailable"}).encode())
            ctype = "text/yaml; charset=utf-8"
        else:
            body = sub.build_subscription_body(user)
            if fmt == "base64_safe":
                links = base64.b64decode(body).decode().splitlines()
                links = sub._filter_safe_links(links)
                body = base64.b64encode("\n".join(links).encode())
            ctype = "text/plain; charset=utf-8"
        headers = {"Content-Type": ctype}
        userinfo = sub._build_userinfo_header(user)
        if userinfo:
            headers["Subscription-Userinfo"] = userinfo
        headers["Profile-Update-Interval"] = "24"
        return 200, headers, body
    except Exception as e:
        _log("ERR", f"/sub: {e}")
        return 500, {"Content-Type": "text/plain"}, b"internal error\n"

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТИКА (path traversal guard)
# ══════════════════════════════════════════════════════════════════════════════
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js":    "application/javascript; charset=utf-8",
    ".css":   "text/css; charset=utf-8",
    ".json":  "application/json; charset=utf-8",
    ".svg":   "image/svg+xml",
    ".png":   "image/png",
    ".ico":   "image/x-icon",
    ".woff2": "font/woff2",
    ".txt":   "text/plain; charset=utf-8",
}

def _safe_join(www_dir: Path, rel_path: str) -> Optional[Path]:
    """Безопасное сопоставление URL-пути в файл внутри www_dir.

    Отбрасывает '..' и абсолютные пути; каталог — не отдаём.
    """
    if not www_dir.exists():
        return None
    rel = urllib.parse.unquote(rel_path).lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    candidate = www_dir.joinpath(*parts)
    try:
        candidate.resolve().relative_to(www_dir.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP-HANDLER
# ══════════════════════════════════════════════════════════════════════════════
class _TripleHandler(BaseHTTPRequestHandler):
    server_version = "ChimeraTriplePanel/1.0"

    # ── утилиты ──────────────────────────────────────────────────────────────
    def _send_json(self, obj, status: int = 200, extra: dict = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body: bytes, ctype: str, status: int = 200,
                    extra: dict = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _cookie_token(self) -> Optional[str]:
        raw = self.headers.get("Cookie", "") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == _SESSION_COOKIE:
                return v
        return None

    def _require_auth(self) -> Optional[str]:
        """None = авторизован (юзер возвращён отдельно). Иначе отправлен 401."""
        user = _session_user(self._cookie_token())
        if user:
            return user
        if self.path.startswith("/api/"):
            self._send_json({"error": "Unauthorized"}, 401)
        else:
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        return None

    def _read_body(self) -> Optional[dict]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > _BODY_LIMIT:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _handle_sse(self) -> None:
        """GET /api/events — text/event-stream (вместо WS апстрима).

        События: metrics (контракт WS апстрима), users, status, log.
        Keepalive ': ping' каждые 20с — nginx-фронт не рвёт read-timeout,
        X-Accel-Buffering: no — отключает прокси-буферизацию.
        """
        q = _sse_subscribe()
        try:
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                try:
                    event, data = q.get(timeout=20)
                    chunk = f"event: {event}\ndata: {data}\n\n".encode(
                        "utf-8")
                except queue.Empty:
                    chunk = b": ping\n\n"
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            _sse_unsubscribe(q)
            self.close_connection = True

    def log_message(self, fmt, *args):  # systemd пишет stdout в журнал
        _log("HTTP", f"{self.client_address[0]} {fmt % args}")

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # /sub/:token — публичный роут (до авторизации!)
        m = re.match(r"^/sub/([A-Za-z0-9]+)$", path)
        if m:
            status, headers, body = _sub_response(
                m.group(1),
                (query.get("format") or [""])[0],
                self.headers.get("User-Agent", "") or "",
            )
            self._send_bytes(body or b"", headers.get("Content-Type",
                            "text/plain"), status,
                            {k: v for k, v in headers.items()
                             if k != "Content-Type"})
            return

        # Статика фронта (без авторизации: login-страница часть фронта).
        if not path.startswith("/api/"):
            rel = path.lstrip("/") or "index.html"
            f = _safe_join(_WWW_DIR, rel)
            if not f:
                # SPA-фолбэк: всё неизвестное → index.html
                f = _safe_join(_WWW_DIR, "index.html")
            if f:
                ctype = _CONTENT_TYPES.get(f.suffix.lower(),
                                           "application/octet-stream")
                body = f.read_bytes()
                self._send_bytes(body, ctype, 200,
                                 {"Cache-Control": "no-cache"})
            else:
                self._send_bytes(b"Triple Panel: frontend not installed\n",
                                 "text/plain; charset=utf-8", 503)
            return

        # ── API ─────────────────────────────────────────────────────────────
        if path == "/api/login" or path == "/api/logout":
            self._send_json({"error": "use POST"}, 405)
            return

        user = self._require_auth()
        if user is None:
            return

        if path == "/api/me":
            self._send_json({"username": user, "authenticated": True})
            return

        if path == "/api/users":
            self._send_json(_assemble_panel_users())
            return

        if path == "/api/config":
            self._send_json(self._config_view())
            return

        if path == "/api/status":
            self._send_json(_status_view_payload())
            return

        if path == "/api/apply-status":
            self._send_json({"ok": True, "ts": int(time.time()),
                             "servicesReloading": False})
            return

        if path == "/api/password/generate":
            from chimera.modules.proto_common import proto_gen_password
            self._send_json({"password": proto_gen_password()})
            return

        # v83.4: трафик по юзерам (вкладки Пользователи/Мониторинг)
        if path == "/api/stats/users":
            self._send_json(_stats_users_payload())
            return

        # v83.4: статус Hysteria2 (вкладка Настройки)
        if path == "/api/settings/hy2":
            self._send_json(_hy2_view())
            return

        # v83.4: диагностика (вкладка Диагностика)
        if path == "/api/diagnostics":
            self._send_json(_diagnostics_payload())
            return

        # v83.4: заглушка-страница (вкладка Настройки)
        if path == "/api/panel/stub":
            self._send_json(_stub_get())
            return

        # v83.4: генерация webBasePath — фронт вызывает перед Apply;
        # раздача base-path — v2, но генератор честный
        if path == "/api/panel/webbasepath/generate":
            import secrets as _secrets
            self._send_json({"webBasePath": _secrets.token_urlsafe(8)})
            return

        # v82: SSE-стрим live-событий (вместо WS апстрима)
        if path == "/api/events":
            self._handle_sse()
            return

        # v82: настройки сервера (GET-часть)
        if path == "/api/settings/cascade":
            self._send_json(_cascade_view())
            return
        if path == "/api/settings/cascade/status":
            self._send_json(_cascade_status_view())
            return
        if path == "/api/settings/warp":
            self._send_json(_warp_view())
            return
        if path == "/api/settings/warp/status":
            self._send_json(_warp_status_view())
            return

        # v82: журналы сервисов
        m = re.match(r"^/api/logs/([a-z0-9\-]+)$", path)
        if m:
            try:
                lines = int((query.get("lines") or ["100"])[0])
            except ValueError:
                lines = 100
            status, payload = _logs_response(m.group(1), lines)
            self._send_json(payload, status)
            return

        # /api/users/:id/naive-link | mieru-link | universal-config
        m = re.match(r"^/api/users/([^/]+)/(naive-link|mieru-link|universal-config)$", path)
        if m:
            email = urllib.parse.unquote(m.group(1))
            kind = m.group(2)
            status, payload = self._user_link(email, kind)
            self._send_json(payload, status)
            return

        self._send_json({"error": f"not implemented by Chimera port: {path}"},
                        501)

    # ── POST ─────────────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        if path == "/api/login":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not username or not password:
                self._send_json({"error": "Missing credentials"}, 400)
                return
            if _check_credentials(_load_state(), username, password):
                token = _session_create(username)
                cookie = (f"{_SESSION_COOKIE}={token}; Path=/; Max-Age={_SESSION_TTL}; "
                          f"HttpOnly; SameSite=Lax")
                self._send_json({"ok": True, "username": username}, 200,
                                {"Set-Cookie": cookie})
                _log("INFO", f"login ok: {username}")
            else:
                self._send_json({"error": "Invalid credentials"}, 401)
                _log("WARN", f"login failed: {username}")
            return

        user = self._require_auth()
        if user is None:
            return

        if path == "/api/logout":
            _session_drop(self._cookie_token())
            cookie = f"{_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly"
            self._send_json({"ok": True}, 200, {"Set-Cookie": cookie})
            return

        if path == "/api/users":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _create_panel_user(body)
            self._send_json(payload, status)
            return

        if path == "/api/config":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            state = _load_state()
            if "language" in body and body["language"] in ("ru", "en"):
                state["language"] = body["language"]
                _STATE_FILE.write_text(json.dumps(state, indent=2))
            self._send_json({"ok": True})
            return

        # v82: настройки сервера (мутации)
        if path == "/api/settings/naive-port":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _set_naive_port(body or {})
            self._send_json(payload, status)
            return

        if path == "/api/settings/mieru-ports":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _set_mieru_ports(body or {})
            self._send_json(payload, status)
            return

        if path == "/api/settings/cascade":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _cascade_apply(body or {})
            self._send_json(payload, status)
            return

        if path == "/api/settings/cascade/reset":
            status, payload = _cascade_reset()
            self._send_json(payload, status)
            return

        if path == "/api/settings/warp":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _set_warp(body or {})
            self._send_json(payload, status)
            return

        if path == "/api/settings/warp/reset":
            status, payload = _warp_reset()
            self._send_json(payload, status)
            return

        # v83.4: заглушка-страница — атомарная запись
        if path == "/api/panel/stub":
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            status, payload = _stub_set((body or {}).get("html"))
            self._send_json(payload, status)
            return

        # v83.4: мутации Hy2 из UI — честный отказ с указанием пути в TUI
        if path in ("/api/settings/hy2/install", "/api/settings/hy2-port",
                    "/api/settings/hy2/enroll-all"):
            self._send_json({
                "error": "Управление Hysteria2 в Chimera — через TUI "
                         "(меню Hysteria2). Панель показывает статус; "
                         "per-user Hy2 не поддерживается.",
            }, 501)
            return

        self._send_json({"error": f"not implemented by Chimera port: {path}"},
                        501)

    # ── PUT / DELETE ─────────────────────────────────────────────────────────
    def do_PUT(self):
        user = self._require_auth()
        if user is None:
            return
        m = re.match(r"^/api/users/([^/]+)$", urllib.parse.urlsplit(self.path).path)
        if not m:
            self._send_json({"error": "not implemented by Chimera port"}, 501)
            return
        body = self._read_body()
        if body is None:
            self._send_json({"error": "Payload Too Large"}, 413)
            return
        status, payload = _update_panel_user(urllib.parse.unquote(m.group(1)), body)
        self._send_json(payload, status)

    def do_DELETE(self):
        user = self._require_auth()
        if user is None:
            return
        m = re.match(r"^/api/users/([^/]+)$", urllib.parse.urlsplit(self.path).path)
        if not m:
            self._send_json({"error": "not implemented by Chimera port"}, 501)
            return
        status, payload = _delete_panel_user(urllib.parse.unquote(m.group(1)))
        self._send_json(payload, status)

    # ── view-сборщики ────────────────────────────────────────────────────────
    def _config_view(self) -> dict:
        state = _load_state()
        from chimera.modules.triple_panel import _PORT_FRONT_VERSION
        naive = _naive_state()
        mieru = _mieru_state()
        core_domain = ""
        try:
            core = _core_module_cached()
            core_domain = getattr(core, "PARAM_DOMAIN", "") or ""
        except Exception:
            pass
        domain = core_domain or (naive.get("domain") or "")
        probe = (naive.get("probe_secret") or "").strip()
        try:
            cascade_enabled = bool(_cascade_view().get("enabled"))
        except Exception:
            cascade_enabled = False
        try:
            warp_enabled = bool(_warp_view().get("enabled"))
        except Exception:
            warp_enabled = False
        return {
            "version": state.get("front_version", "") or _PORT_FRONT_VERSION,
            "portVersion": _PORT_FRONT_VERSION,
            "language": state.get("language", "ru"),
            "domain": domain,
            "serverIp": _local_ip(),
            # v83.4: плоские поля апстрима (loadSettings читает их без
            # вложенности) + вложенный mieruPorts (наш v81) для обратной
            # совместимости
            "naivePort": naive.get("port", 443),
            "mieruPortStart": mieru.get("port_start", 2012),
            "mieruPortEnd": mieru.get("port_end", 2022),
            "mieruPorts": {
                "start": mieru.get("port_start", 2012),
                "end": mieru.get("port_end", 2022),
            },
            # probe_resistance Naive (маска в форме настроек апстрима)
            "probeSecret": probe,
            "probeMode": "secret" if probe else "bare",
            "fakeSiteUrl": naive.get("fake_url", ""),
            "cascadeEnabled": cascade_enabled,
            "warpEnabled": warp_enabled,
            "protocols": {
                "naive": bool(naive.get("users")),
                "mieru": bool(mieru.get("users")),
                "hy2": _hy2_installed() and _svc_active(_HY2_SERVICE),
            },
            "webPort": int(state.get("web_port", 9760)),
            "adminUser": state.get("admin_user", "admin"),
            "upstreamRepo": "cwash797-cmd/Panel-Naive-Mieru-by-RIXXX",
        }

    def _user_link(self, email: str, kind: str) -> "tuple[int, dict]":
        from chimera.modules import rest_api as ra
        try:
            ra._sync_users_from_config()
        except Exception:
            pass
        users = ra._get_users()
        target = next((u for u in users if u.get("email") == email), None)
        if not target:
            return 404, {"error": "user not found"}
        prefix = email.split("@")[0]
        if kind == "naive-link":
            naive = _naive_state()
            row = next((u for u in naive.get("users", [])
                        if u.get("username") == prefix), None)
            if not row:
                return 404, {"error": "naive account not found"}
            domain = naive.get("domain", "") or "server-ip"
            port = int(naive.get("port", 443))
            link = (f"naive+https://{row['username']}:{row['password']}"
                    f"@{domain}:{port}#{prefix}")
            return 200, {"link": link, "username": row["username"],
                         "password": row["password"]}
        if kind == "mieru-link":
            try:
                from chimera.modules import subscription as sub
                ipv4 = sub._get_server_ip("4")
                uris = sub._build_mieru_uris(target, ipv4 or "")
                if uris:
                    return 200, {"link": uris[0], "count": len(uris)}
            except Exception as e:
                _log("WARN", f"mieru-link: {e}")
            return 404, {"error": "mieru link unavailable"}
        # universal-config
        try:
            from chimera.modules import subscription as sub
            body = sub.build_subscription_body(target)
            links = base64.b64decode(body).decode().splitlines()
            return 200, {"links": links, "b64": body.decode()}
        except Exception as e:
            _log("WARN", f"universal: {e}")
            return 500, {"error": str(e)}

_core_cache = None
def _core_module_cached():
    global _core_cache
    if _core_cache is None:
        from chimera.modules.triple_panel import _core_module
        _core_cache = _core_module()
    return _core_cache

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def start_server() -> None:
    state = _load_state()
    port = int(state.get("web_port", 9760))
    host = "127.0.0.1"  # наружу — только через nginx front (эталон b4)
    watcher = threading.Thread(target=_sse_watcher, daemon=True,
                               name="triple-sse-watcher")
    watcher.start()
    server = ThreadingHTTPServer((host, port), _TripleHandler)
    print(f"[Triple Panel] Сервер запущен на {host}:{port} (ThreadingHTTPServer)")
    _log("INFO", f"started on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    if "--serve" in sys.argv:
        start_server()
    else:
        print("Usage: python3 triple_panel_web.py --serve")
