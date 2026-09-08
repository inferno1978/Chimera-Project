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
    PUT    /api/users/:id            — expiry/quota/protocols
    DELETE /api/users/:id            — удалить (везде: VLESS+naive+mieru+TTL+лимит)
    GET    /api/config               — панельные настройки (без секретов)
    POST   /api/config               — language (остальное — v2)
    GET    /api/status               — версии + статус сервисов тройки
    GET    /api/apply-status         — исход последнего apply (фронт поллит)
    GET    /api/password/generate    — генератор пароля
    GET    /api/users/:id/naive-link | mieru-link | universal-config
    GET    /sub/:token               — умная подписка: UA-детект (делегация
                                        subscription.py: base64 / base64_safe /
                                        singbox / clash) + Subscription-Userinfo

НЕ реализовано в v1 (фронт получит 501 с внятным текстом): смена портов
протоколов из UI, cascade/warp-настройки, федерация, backup import/export,
WS live-обновления (фронт деградирует на REST-поллинг, reconnect безвреден).
Все эти операции остаются в TUI-модулях Химеры (10/11/7, раздел 1 W 8).

ДЕЛЕГИРУЕМЫЕ ПРИМИТИВЫ:
    rest_api.py        — _get_users/_save_users/_sync_* (юзер-мост v4.25)
    naiveproxy.py      — state users, _build_naive_link
    mieru.py           — state users
    ttl_users.py       — expiry
    user_lifecycle.py  — квоты (traffic_limits.json)
    subscription.py    — единая подписка + UA-детект + токены (pepper)
"""
from __future__ import annotations

import base64
import hmac
import json
import re
import secrets
import sys
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

# ══════════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}

def _log(level: str, msg: str) -> None:
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"[TRIPLE-WEB][{level}] {msg}\n")
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
    """PUT /api/users/:id — expiry / квота / чекбоксы протоколов.

    Пароль протоколов в v1 не редактируется (генерируется sync-контрактом;
    ротация = v2 через отдельный эндпоинт).
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

    # expiry
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

    # quotaMB
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

    # protocols
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
    return 200, {"status": "updated", "id": email, "changed": changed}

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
            self._send_json(self._status_view())
            return

        if path == "/api/apply-status":
            self._send_json({"ok": True, "ts": int(time.time()),
                             "servicesReloading": False})
            return

        if path == "/api/password/generate":
            from chimera.modules.proto_common import proto_gen_password
            self._send_json({"password": proto_gen_password()})
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
        return {
            "version": state.get("front_version", "") or _PORT_FRONT_VERSION,
            "portVersion": _PORT_FRONT_VERSION,
            "language": state.get("language", "ru"),
            "domain": core_domain,
            "naivePort": naive.get("port", 443),
            "mieruPorts": {
                "start": mieru.get("port_start", 2012),
                "end": mieru.get("port_end", 2022),
            },
            "protocols": {
                "naive": bool(naive.get("users")),
                "mieru": bool(mieru.get("users")),
                "hy2": self._hy2_active(),
            },
            "webPort": int(state.get("web_port", 9760)),
            "adminUser": state.get("admin_user", "admin"),
            "upstreamRepo": "cwash797-cmd/Panel-Naive-Mieru-by-RIXXX",
        }

    def _hy2_active(self) -> bool:
        import subprocess
        try:
            r = subprocess.run(["systemctl", "is-active", "hysteria-server"],
                               capture_output=True, check=False)
            return r.returncode == 0 and r.stdout.decode().strip() == "active"
        except Exception:
            return False

    def _status_view(self) -> dict:
        import subprocess
        from chimera.modules.triple_panel import _PORT_FRONT_VERSION
        state = _load_state()
        services = {}
        for svc in ("caddy-naive", "mita", "hysteria-server", "xray"):
            try:
                r = subprocess.run(["systemctl", "is-active", svc],
                                   capture_output=True, check=False)
                services[svc] = r.returncode == 0 and r.stdout.decode().strip() == "active"
            except Exception:
                services[svc] = False
        return {
            "version": state.get("front_version", ""),
            "portVersion": _PORT_FRONT_VERSION,
            "services": services,
            "webPort": int(state.get("web_port", 9760)),
            "uptimeSec": int(time.time()),
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
