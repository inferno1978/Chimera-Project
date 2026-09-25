#!/usr/bin/env python3
"""
chimera/modules/wpp_panel_web.py
────────────────────────────────────────────────────────────────────────────────
Backend WPP Web Panel — Python stdlib HTTP-сервер для управления
VPN-подключениями (VLESS/Hysteria2/AWG/MTProto/OpenFlux).

АРХИТЕКТУРА:
  • ThreadingHTTPServer + BaseHTTPRequestHandler (как Triple Panel)
  • Читает web_port/admin_user/admin_pass_salt/admin_pass_sha256 из
    wpp_state.load_state()
  • Сессии — in-memory dict, cookie 'wpp_session', HMAC-signed token
  • CSRF-токен в каждой форме (как panel.py оригинала WPP)
  • Логин: SHA-256(salt + password), hmac.compare_digest

ADAPTERS к Chimera state (заменяют оригинальные ctl/ctl_subscription/
load/save/traffic/subscription_registry из WPP):
  • _chimera_state()           → chimera's state.json
  • _chimera_users()           → chimera's users_manager.list_users()
  • _chimera_traffic()         → chimera's traffic_accounting state
  • _chimera_subscription_list → chimera's subscription.py
  • _chimera_proxy_link(...)   → chimera's client_config_export

Запуск (systemd):
  python3 -c "from chimera.modules.wpp_panel_web import start_server; start_server()"
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

# Bootstrap корня проекта (для прямого запуска / systemd ExecStart)
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.wpp_state import load_state, save_state  # noqa: E402

# ─── КОНСТАНТЫ ───────────────────────────────────────────────────────────────

STATE_DIR         = Path("/var/lib/xray-installer")
WWW_DIR           = STATE_DIR / "wpp_panel_www"        # vendored фронт
LOGIN_WINDOW      = 300   # 5 минут — окно для rate-limit
LOGIN_MAX_ATTEMPTS = 5    # 5 неудачных попыток в окне → 429
SESSION_TTL       = 86400  # 24 часа
PANEL_PATH        = os.environ.get("WEBPROXY_PANEL_PATH", "/panel")
# Если PANEL_PATH пустой — fallback на "/panel" (см. ниже в _panel_path).

# ─── ЛОКАЛЬНЫЕ HELPERS ──────────────────────────────────────────────────────

def _panel_path() -> str:
    """Возвращает path-префикс панели (не пустой)."""
    p = PANEL_PATH or "/panel"
    return p.rstrip("/") or ""  # пустая строка = корень


def _esc(value) -> str:
    """HTML escape для безопасного вывода пользовательских данных."""
    return html.escape(str(value), quote=True)


def _size(value) -> str:
    """Человекочитаемый размер."""
    if value is None:
        return "—"
    value = max(0, float(value))
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if value < 1024 or unit == "ТБ":
            return ("%.0f" if unit == "Б" else "%.1f") % value + " " + unit
        value /= 1024


def _duration(value) -> str:
    """Человекочитаемая длительность (секунды → дни/часы/минуты)."""
    if value is None:
        return "—"
    value = max(0, int(value))
    if value >= 86400:
        return f"{value // 86400} д. {value % 86400 // 3600} ч."
    if value >= 3600:
        return f"{value // 3600} ч. {value % 3600 // 60} мин."
    return f"{value // 60} мин."


# ─── ИКОНКИ (SVG) ───────────────────────────────────────────────────────────
# (Портировано из wpp_ui.py — SVG path data inline для визуальной навигации.)

_ICON_PATHS = {
    "grid":     '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "users":    '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3M17 4a3 3 0 0 1 0 6m1 4a5 5 0 0 1 3 4v3"/>',
    "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
    "nodes":    '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
    "logout":   '<path d="M10 4H4v16h6m4-12 4 4-4 4m-6-4h10"/>',
    "sun":      '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1"/>',
    "refresh":  '<path d="M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6"/>',
    "chart":    '<path d="M3 3v18h18M6 15l4-5 4 3 6-8"/>',
    "link":     '<path d="m10 13 4-4m-6 5-2 2a3 3 0 0 0 4 4l3-3m-2-10 3-3a3 3 0 0 1 4 4l-2 2"/>',
    "qr":       '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3m4 0v4m0-7h3"/>',
    "shield":   '<path d="M12 2 4 5v6c0 5 3 9 8 11 5-2 8-6 8-11V5z"/>',
    "copy":     '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    "edit":     '<path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
    "delete":   '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>',
    "add":      '<path d="M12 5v14m-7-7h14"/>',
    "menu":     '<path d="M3 6h18M3 12h18M3 18h18"/>',
    "eye":      '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "lock":     '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
}


def _icon(name: str) -> str:
    """Возвращает SVG-иконку с заданным path id."""
    path = _ICON_PATHS.get(name, "")
    if not path:
        return ""
    return f'<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{path}</svg>'


# ─── СЕССИИ ─────────────────────────────────────────────────────────────────

# In-memory dict: token -> {expires, client_ip}
# Cookie name: wpp_session (НЕ tp_session — конфликт с Triple Panel)
_SESSIONS: dict[str, dict] = {}
_SESSIONS_LOCK = threading.Lock()
_SESSION_KEY = secrets.token_hex(32)  # для HMAC-подписи токенов

# Login rate-limiting: client_id -> deque of failure timestamps
_LOGIN_FAILS: dict[str, deque] = defaultdict(deque)
_LOGIN_FAILS_LOCK = threading.Lock()


def _client_id(handler) -> str:
    """Идентификатор клиента для rate-limiting (X-Forwarded-For или remote IP)."""
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Берём последний IP из цепочки (ближайший к серверу)
        candidate = forwarded.split(",")[-1].strip()
        if candidate:
            return candidate
    return handler.client_address[0] if handler.client_address else "unknown"


def _sign(token: str) -> str:
    """Подписывает токен HMAC-SHA256 — 'token.signature' (как panel.py:113)."""
    sig = hmac.new(_SESSION_KEY.encode(), token.encode(), hashlib.sha256).hexdigest()
    return f"{token}.{sig}"


def _verify_signed(signed_token: str) -> bool:
    """Проверяет подпись токена. True если подпись валидна."""
    if "." not in signed_token:
        return False
    token, sig = signed_token.rsplit(".", 1)
    expected = hmac.new(_SESSION_KEY.encode(), token.encode(),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def _session_cookie(value: str, max_age: int = SESSION_TTL) -> str:
    """Создаёт Set-Cookie header value."""
    secure = " Secure" if False else ""  # HTTPS-only если за TLS-terminator
    path = _panel_path() or "/"
    return (f"wpp_session={value}; Path={path}; Max-Age={max_age};"
            f" HttpOnly{secure}; SameSite=Lax")


def _login_blocked(client_id: str) -> bool:
    """True если клиент превысил LOGIN_MAX_ATTEMPTS в LOGIN_WINDOW секунд."""
    now = time.time()
    with _LOGIN_FAILS_LOCK:
        dq = _LOGIN_FAILS[client_id]
        # Чистим старые
        while dq and now - dq[0] > LOGIN_WINDOW:
            dq.popleft()
        return len(dq) >= LOGIN_MAX_ATTEMPTS


def _login_failed(client_id: str) -> None:
    with _LOGIN_FAILS_LOCK:
        _LOGIN_FAILS[client_id].append(time.time())


def _login_succeeded(client_id: str) -> None:
    with _LOGIN_FAILS_LOCK:
        _LOGIN_FAILS.pop(client_id, None)


def _hash_password(password: str, salt_hex: str) -> str:
    """SHA-256(salt + password) → hex."""
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return ""
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def _check_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    actual = _hash_password(password, salt_hex)
    return bool(actual) and hmac.compare_digest(actual, expected_hash)


# ─── CSRF ────────────────────────────────────────────────────────────────────

_CSRF_TOKENS: dict[str, float] = {}  # token -> created_at
_CSRF_LOCK = threading.Lock()
_CSRF_TTL = 3600  # 1 час


def _new_csrf_token() -> str:
    token = secrets.token_hex(16)
    with _CSRF_LOCK:
        _CSRF_TOKENS[token] = time.time()
        # Чистим старые
        cutoff = time.time() - _CSRF_TTL
        for k in list(_CSRF_TOKENS.keys()):
            if _CSRF_TOKENS[k] < cutoff:
                del _CSRF_TOKENS[k]
    return token


def _verify_csrf(token: str) -> bool:
    if not token:
        return False
    with _CSRF_LOCK:
        created = _CSRF_TOKENS.get(token)
        if not created:
            return False
        if time.time() - created > _CSRF_TTL:
            del _CSRF_TOKENS[token]
            return False
    return True


# ─── ADAPTERS к Chimera state ───────────────────────────────────────────────
# Оригинал WPP использует ctl() subprocess к /opt/tproxy-panel/manager.py.
# В Chimera заменяем на прямые вызовы к существующим модулям.

CHIMERA_STATE_FILE = Path("/var/lib/xray-installer/state.json")


def _chimera_state() -> dict:
    """Читает главный state.json Chimera (для domain/xray_port/итд)."""
    try:
        if CHIMERA_STATE_FILE.exists():
            return json.loads(CHIMERA_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _chimera_users_file() -> Path:
    """Путь к users.json Chimera."""
    return Path("/var/lib/xray-installer/users.json")


def _chimera_users() -> list[dict]:
    """Список пользователей Chimera (из users.json).
    Schema: list of {uuid, name, protocol, enabled, traffic_up, traffic_down, ...}
    """
    try:
        f = _chimera_users_file()
        if not f.exists():
            return []
        data = json.loads(f.read_text())
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "users" in data:
            return data["users"]
    except Exception:
        pass
    return []


def _chimera_traffic() -> dict:
    """Словарь трафика по user_id: {uuid: {up: bytes, down: bytes, total: bytes}}."""
    users = _chimera_users()
    out: dict[str, dict] = {}
    for u in users:
        uid = str(u.get("uuid") or u.get("id") or "")
        if not uid:
            continue
        out[uid] = {
            "up":      int(u.get("traffic_up",   0) or 0),
            "down":    int(u.get("traffic_down", 0) or 0),
            "total":   int(u.get("traffic_up",   0) or 0)
                     + int(u.get("traffic_down", 0) or 0),
            "enabled": bool(u.get("enabled", True)),
        }
    return out


def _chimera_subscription_link(uid: str, name: str = "") -> str:
    """Генерирует ссылку подписки для пользователя Chimera (как в subscription.py).
    URL: https://<domain>/sub/<uid>  (или с портом если не 443)."""
    state = _chimera_state()
    domain = state.get("domain") or state.get("DOMAIN") or ""
    if not domain:
        return ""
    # Если xray на 443 — стандартный URL. Иначе — :port.
    port = state.get("xray_port") or state.get("vless_port") or 443
    if port == 443:
        return f"https://{domain}/sub/{uid}"
    return f"https://{domain}:{port}/sub/{uid}"


def _chimera_proxy_link(protocol: str, secret: str, port: int,
                        name: str = "", username: str = "") -> str:
    """Генерирует клиентскую ссылку (vless://, hysteria://, и т.д.).
    Делегирует в chimera.modules.client_config_export если доступен."""
    try:
        from chimera.modules.client_config_export import build_link
        return build_link(protocol=protocol, secret=secret, port=port,
                          name=name, username=username)
    except Exception:
        # Fallback: минимальный VLESS-формат
        state = _chimera_state()
        domain = state.get("domain") or "<server>"
        return f"vless://{secret}@{domain}:{port}?type=tcp&security=reality#{name}"


# ─── ADAPTERS к chimera linkqr_lib / subscription / openflux ────────────────
# Phase 2: QR codes, subscriptions list, OpenFlux state, landing presets.

def _chimera_links_for_user(user_dict: dict) -> dict[str, str]:
    """
    Возвращает все доступные client-links для пользователя через
    chimera.modules.linkqr_lib.build_all_links_for_user(). Pattern:
      {"vless": "vless://...", "awg": "awg://...", "subscription": "https://.../sub/...",
       "hysteria2": "hysteria://...", "mieru": "mieru://...", "naive": "naive+https://..."}
    Пустой dict если linkqr_lib недоступен или user невалиден.
    """
    try:
        from chimera.modules import linkqr_lib
        return linkqr_lib.build_all_links_for_user(user_dict) or {}
    except Exception:
        return {}


def _chimera_subscription_info(user_dict: dict | None = None) -> dict:
    """
    Возвращает инфо о подписке для пользователя. Если user_dict=None —
    возвращает admin overview всех подписок.
    Pattern: chimera.modules.subscription.get_portal_subscription_info(user)
    или get_admin_subscription_info() если user=None.
    """
    try:
        from chimera.modules import subscription
        if user_dict is None:
            return subscription.get_admin_subscription_info() or {}
        return subscription.get_portal_subscription_info(user_dict) or {}
    except Exception:
        return {}


def _generate_qr_png_bytes(text: str) -> bytes | None:
    """
    Генерирует QR-код как PNG bytes (через chimera.modules.linkqr_lib).
    Возвращает None при ошибке.
    """
    try:
        from chimera.modules import linkqr_lib
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            tmp_path = Path(f.name)
        try:
            ok = linkqr_lib.generate_qr_png(text, tmp_path)
            if not ok:
                return None
            return tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)
    except Exception:
        return None


# ─── OPENFLUX STATE (single-profile — chimera's openflux.py не имеет multi) ──

_OPENFLUX_STATE_FILE = Path("/var/lib/xray-installer/openflux.json")


def _chimera_openflux_state() -> dict:
    """
    Возвращает masked-state OpenFlux (без secret-полей типа transport_key).
    Single-profile — chimera.modules.openflux.py пока не имеет multi-profile API.
    """
    try:
        if not _OPENFLUX_STATE_FILE.exists():
            return {"installed": False, "enabled": False, "bridge_active": False}
        data = json.loads(_OPENFLUX_STATE_FILE.read_text())
        # Убираем секреты
        safe = {
            "installed":     bool(data.get("installed_at")),
            "transport":     data.get("transport", ""),
            "enabled":       False,  # вычисляем ниже
            "bridge_active": bool(data.get("bridge_active", False)),
            "bridge_port":   data.get("bridge_port"),
            "bridge_bind":   data.get("bridge_bind", "127.0.0.1"),
            "installed_at":  data.get("installed_at", ""),
            "doc_url_masked": _mask_doc_url(data.get("doc_url", "")),
        }
        # Проверяем активность сервиса
        try:
            r = subprocess.run(["systemctl", "is-active", "--quiet", "openflux"],
                               capture_output=True, timeout=5)
            safe["enabled"] = (r.returncode == 0)
        except Exception:
            pass
        return safe
    except Exception:
        return {"installed": False, "enabled": False, "bridge_active": False}


def _mask_doc_url(url: str) -> str:
    """Маскирует doc_url — оставляет только host + path без query (?sk=...)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return "<masked>"


def _openflux_set_enabled(enable: bool) -> tuple[bool, str]:
    """Включает/выключает OpenFlux сервис."""
    try:
        if enable:
            r = subprocess.run(["systemctl", "enable", "--now", "openflux"],
                               capture_output=True, text=True, timeout=30)
        else:
            r = subprocess.run(["systemctl", "disable", "--now", "openflux"],
                               capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()[:500]
        return True, f"OpenFlux {'enabled' if enable else 'disabled'}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _openflux_rotate_key() -> tuple[bool, str]:
    """Перегенерирует transport key (rotate). Делегирует в chimera.modules.openflux._rotate_key."""
    try:
        from chimera.modules import openflux as of
        # NB: _rotate_key() — интерактивная функция (TUI). Запускаем с empty input.
        # Это запишет новый ключ в /etc/openflux/transport.key и перезапустит openflux.service.
        # TODO: когда в chimera добавят non-interactive rotate_key(name, no_input=True),
        #       переключиться на него. Пока — напрямую через API.
        new_key = of._gen_transport_key()
        if not new_key:
            return False, "Не удалось сгенерировать ключ"
        # Записываем ключ
        key_file = Path("/etc/openflux/transport.key")
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(new_key)
        key_file.chmod(0o600)
        # Перезапуск
        subprocess.run(["systemctl", "restart", "openflux"],
                       capture_output=True, timeout=30)
        return True, f"Ключ rotated ({new_key[:8]}...)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


# ─── LANDING PAGE STUB / PRESETS ────────────────────────────────────────────
# Pattern: triple_panel_web._stub_set / _stub_get (atomic, 256 KiB cap).

_STUB_FILE    = Path("/var/www/panel-stub/index.html")
_STUB_DRAFT   = Path("/var/lib/xray-installer/wpp_panel_stub.draft.html")
_STUB_PRESETS_FILE = Path("/var/lib/xray-installer/wpp_panel_presets.json")
_STUB_LIMIT   = 256 * 1024  # 256 KiB — apstrim contract как в Triple Panel

# Built-in presets (3 базовых страницы для старта).
_BUILTIN_PRESETS = {
    "empty": {
        "name":        "Пустая страница",
        "description": "Минимальный HTML5 с meta-charset",
        "html":        "<!doctype html>\n<html lang=\"ru\"><head>\n"
                       "<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
                       "<title></title>\n</head><body></body></html>\n",
    },
    "coming-soon": {
        "name":        "Скоро открытие",
        "description": "Лендинг «coming soon» с email-формой",
        "html":        "<!doctype html>\n<html lang=\"ru\"><head>\n"
                       "<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
                       "<title>Скоро открытие</title>\n<style>body{margin:0;min-height:100vh;display:grid;"
                       "place-items:center;background:#0d1520;color:#fff;font:16px system-ui}"
                       ".b{text-align:center;padding:48px}h1{font-size:28px;margin:0 0 12px}"
                       "p{color:#9ab;margin:0 0 24px}input{padding:12px 16px;border:1px solid #1c2b40;"
                       "border-radius:8px;background:#0a121d;color:#fff;font:inherit;width:300px;max-width:90vw}"
                       "button{padding:12px 20px;border:0;border-radius:8px;background:#2563eb;color:#fff;"
                       "font:inherit;font-weight:600;cursor:pointer;margin-left:8px}</style></head>\n"
                       "<body><div class=\"b\"><h1>Скоро открытие</h1>"
                       "<p>Мы скоро запустимся. Оставьте email — сообщим первыми.</p>"
                       "<form><input type=\"email\" placeholder=\"you@example.com\" required>"
                       "<button type=\"submit\">Подписаться</button></form></div></body></html>\n",
    },
    "404": {
        "name":        "404 — не найдено",
        "description": "Заглушка 404 страницы",
        "html":        "<!doctype html>\n<html lang=\"ru\"><head>\n<meta charset=\"utf-8\">"
                       "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                       "<title>404 — Не найдено</title>\n"
                       "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;"
                       "background:#0d1520;color:#fff;font:16px system-ui;text-align:center}"
                       "h1{font-size:96px;margin:0;font-weight:200}p{color:#9ab;margin:8px 0 0}</style></head>"
                       "<body><div><h1>404</h1><p>Страница не найдена</p></div></body></html>\n",
    },
}


def _stub_strip(source: str) -> str:
    """Preprocessing: strip BOM + leading 'Copy' clipboard artifact."""
    # Pattern: triple_panel_web._stub_set L1246-1248
    source = source.lstrip("\ufeff")
    import re
    source = re.sub(r"^Copy(?=\s*<)", "", source)
    return source


def _stub_get_live() -> str:
    """Возвращает текущий live HTML из _STUB_FILE (или пустую строку)."""
    try:
        if _STUB_FILE.exists():
            return _STUB_FILE.read_text(encoding="utf-8")
    except Exception:
        pass
    return ""


def _stub_set_live(html: str) -> tuple[bool, str]:
    """Атомарно публикует HTML в _STUB_FILE. 256 KiB cap. Возвращает (ok, msg)."""
    try:
        source = _stub_strip(html)
        if len(source.encode("utf-8")) > _STUB_LIMIT:
            return False, f"HTML слишком большой (>{_STUB_LIMIT} байт)"
        _STUB_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STUB_FILE.with_name(_STUB_FILE.name + ".new")
        tmp.write_text(source, encoding="utf-8")
        tmp.chmod(0o644)
        tmp.replace(_STUB_FILE)
        return True, f"Опубликовано ({len(source.encode('utf-8'))} байт)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _stub_get_draft() -> str:
    try:
        if _STUB_DRAFT.exists():
            return _STUB_DRAFT.read_text(encoding="utf-8")
    except Exception:
        pass
    return ""


def _stub_save_draft(html: str) -> tuple[bool, str]:
    try:
        source = _stub_strip(html)
        if len(source.encode("utf-8")) > _STUB_LIMIT:
            return False, f"HTML слишком большой (>{_STUB_LIMIT} байт)"
        _STUB_DRAFT.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STUB_DRAFT.with_name(_STUB_DRAFT.name + ".new")
        tmp.write_text(source, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(_STUB_DRAFT)
        return True, f"Draft сохранён ({len(source.encode('utf-8'))} байт)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _stub_discard_draft() -> None:
    try:
        if _STUB_DRAFT.exists():
            _STUB_DRAFT.unlink()
    except Exception:
        pass


def _stub_list_presets() -> list[dict]:
    """Объединяет built-in + custom presets, возвращает [{id, name, description, custom, bytes}]."""
    out: list[dict] = []
    for pid, p in _BUILTIN_PRESETS.items():
        out.append({
            "id":          pid,
            "name":        p["name"],
            "description": p["description"],
            "custom":      False,
            "bytes":       len(p["html"].encode("utf-8")),
        })
    # Custom presets
    try:
        if _STUB_PRESETS_FILE.exists():
            data = json.loads(_STUB_PRESETS_FILE.read_text())
            if isinstance(data, list):
                for p in data:
                    out.append({
                        "id":          p.get("id", ""),
                        "name":        p.get("name", ""),
                        "description": p.get("description", ""),
                        "custom":      True,
                        "bytes":       len((p.get("html", "") or "").encode("utf-8")),
                    })
    except Exception:
        pass
    return out


def _stub_get_preset(pid: str) -> dict | None:
    """Возвращает preset по id (built-in или custom)."""
    if pid in _BUILTIN_PRESETS:
        p = _BUILTIN_PRESETS[pid]
        return {**p, "id": pid, "custom": False}
    # Custom
    try:
        if _STUB_PRESETS_FILE.exists():
            data = json.loads(_STUB_PRESETS_FILE.read_text())
            if isinstance(data, list):
                for p in data:
                    if p.get("id") == pid:
                        return {**p, "custom": True}
    except Exception:
        pass
    return None


def _stub_save_preset(name: str, html: str, description: str = "") -> tuple[bool, str]:
    """Сохраняет custom preset (макс 20 штук)."""
    try:
        name = name.strip()
        if not 1 <= len(name) <= 80:
            return False, "Имя должно быть 1-80 символов"
        if len(description) > 180:
            return False, "Описание ≤ 180 символов"
        source = _stub_strip(html)
        if len(source.encode("utf-8")) > _STUB_LIMIT:
            return False, f"HTML слишком большой (>{_STUB_LIMIT} байт)"
        # Load existing
        data = []
        if _STUB_PRESETS_FILE.exists():
            data = json.loads(_STUB_PRESETS_FILE.read_text())
            if not isinstance(data, list):
                data = []
        if len(data) >= 20:
            return False, "Максимум 20 custom presets"
        new_id = "custom-" + secrets.token_hex(8)
        data.append({
            "id":          new_id,
            "name":        name,
            "description": description or "Пользовательская заглушка",
            "html":        source,
        })
        _STUB_PRESETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STUB_PRESETS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _STUB_PRESETS_FILE.chmod(0o600)
        return True, f"Preset '{name}' сохранён (id={new_id})"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _stub_delete_preset(pid: str) -> tuple[bool, str]:
    """Удаляет custom preset по id (built-in нельзя)."""
    try:
        if not pid.startswith("custom-"):
            return False, "Built-in preset нельзя удалить"
        if not _STUB_PRESETS_FILE.exists():
            return False, "Preset не найден"
        data = json.loads(_STUB_PRESETS_FILE.read_text())
        if not isinstance(data, list):
            return False, "Список presets повреждён"
        retained = [p for p in data if p.get("id") != pid]
        if len(retained) == len(data):
            return False, "Preset не найден"
        _STUB_PRESETS_FILE.write_text(json.dumps(retained, indent=2, ensure_ascii=False))
        return True, "Preset удалён"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"




class _WppHandler(BaseHTTPRequestHandler):
    """
    Главный HTTP handler. Реализует:
      • do_GET: раздаёт статику из WWW_DIR + отдаёт HTML-страницы
      • do_POST: обрабатывает формы (login, create-user, delete, и т.д.)
      • serve_subscription: отдаёт подписку по /sub/<token>

    Auth flow:
      1. Cookie wpp_session → verify_signed → session exists → auth OK
      2. Если cookie нет/невалиден → redirect на /login
    """

    server_version = "ChimeraWPP/1.0"

    # ── HELPERS ───────────────────────────────────────────────────────────

    def log_message(self, fmt, *args):
        """Перенаправляем логи в stderr (как в nginx logs / journalctl)."""
        print(f"[WPP-WEB] {self.address_string()} - {fmt % args}",
              file=sys.stderr, flush=True)

    def _send(self, body: bytes, status: int = 200,
              content_type: str = "text/html; charset=utf-8",
              headers: Optional[dict] = None) -> None:
        """Отправляет response с заданным content-type и headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_html(self, body: str, status: int = 200,
                  headers: Optional[dict] = None) -> None:
        self._send(body.encode("utf-8"), status=status,
                   content_type="text/html; charset=utf-8",
                   headers=headers)

    def send_json(self, obj: dict, status: int = 200,
                 headers: Optional[dict] = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(body, status=status,
                   content_type="application/json; charset=utf-8",
                   headers=headers)

    def send_data(self, body: str | bytes, status: int = 200,
                  content_type: str = "text/plain; charset=utf-8",
                  headers: Optional[dict] = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._send(body, status=status, content_type=content_type,
                   headers=headers)

    def redirect(self, location: str) -> None:
        path = location if location.startswith("/") else f"/{location}"
        # Префикс панели если локейшен относительный и не начинается с префикса
        prefix = _panel_path()
        if prefix and not path.startswith(prefix):
            path = prefix + path
        self.send_response(303)
        self.send_header("Location", path)
        self.end_headers()

    def form(self, max_size: int = 1024 * 1024) -> dict:
        """Парсит application/x-www-form-urlencoded. Raises ValueError на больших payload."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > max_size:
            raise ValueError(f"Form data too large: {length} > {max_size}")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnicodeDecodeError("utf-8", raw, 0, length, str(exc)) from None
        return {k: v[0] if v else "" for k, v in parse_qs(text, keep_blank_values=True).items()}

    def json_request(self, max_size: int = 1024 * 1024) -> dict:
        """Парсит JSON body. Raises ValueError на больших payload."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > max_size:
            raise ValueError(f"JSON body too large: {length} > {max_size}")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def session_cookie_value(self) -> str:
        """Достаёт значение wpp_session cookie из заголовков."""
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return ""
        try:
            c = cookies.SimpleCookie()
            c.load(cookie_header)
            morsel = c.get("wpp_session")
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def auth(self) -> bool:
        """Проверяет сессию. True если валидна."""
        signed = self.session_cookie_value()
        if not signed or not _verify_signed(signed):
            return False
        with _SESSIONS_LOCK:
            session = _SESSIONS.get(signed)
            if not session:
                return False
            if time.time() > session.get("expires", 0):
                _SESSIONS.pop(signed, None)
                return False
            return True

    def csrf(self) -> str:
        """Возвращает CSRF-токен для текущей сессии (создаётся при auth)."""
        signed = self.session_cookie_value()
        with _SESSIONS_LOCK:
            session = _SESSIONS.get(signed)
            if not session:
                return _new_csrf_token()
            if "csrf" not in session:
                session["csrf"] = _new_csrf_token()
            return session["csrf"]

    def valid_csrf(self, form: dict) -> bool:
        return _verify_csrf(form.get("csrf", ""))

    # ─── GET ────────────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            prefix = _panel_path()

            # ── Health check (без auth) ──
            if path == prefix + "/__health" or path == "/__health":
                self.send_data("OK", status=200,
                               content_type="text/plain; charset=utf-8")
                return

            # ── Static files (без auth) — для логин-страницы ──
            # /panel/static/* → /var/lib/xray-installer/wpp_panel_www/static/*
            if path.startswith(prefix + "/static/"):
                self._serve_static(path)
                return

            # ── Login page (без auth) ──
            if path == prefix + "/login" or path == "/login":
                self.send_html(self._login_page())
                return

            # ── Logout ──
            if path == prefix + "/logout" or path == "/logout":
                signed = self.session_cookie_value()
                with _SESSIONS_LOCK:
                    _SESSIONS.pop(signed, None)
                self.send_response(303)
                self.send_header("Set-Cookie", _session_cookie("", 0))
                self.send_header("Location", (prefix or "") + "/login")
                self.end_headers()
                return

            # ── Корневой путь панели → редирект на dashboard или login ──
            if path == prefix or path == prefix + "/" or path == "/":
                if self.auth():
                    self.redirect("/dashboard")
                else:
                    self.redirect("/login")
                return

            # ── Все остальные пути требуют auth ──
            if not self.auth():
                self.redirect("/login")
                return

            # ── Диспетчер маршрутов ──
            if path == prefix + "/dashboard":
                self.send_html(self._dashboard_page())
                return
            if path == prefix + "/users":
                self.send_html(self._users_page())
                return
            if path == prefix + "/nodes":
                self.send_html(self._nodes_page())
                return
            if path == prefix + "/settings":
                self.send_html(self._settings_page())
                return
            if path == prefix + "/openflux":
                self.send_html(self._openflux_page())
                return
            if path == prefix + "/landing":
                self.send_html(self._landing_page())
                return

            # ── API endpoints (JSON) ──
            if path == prefix + "/api/stub":
                # GET: вернуть текущий live HTML
                self.send_json({"html": _stub_get_live(), "path": str(_STUB_FILE)})
                return
            if path == prefix + "/api/stub/draft":
                self.send_json({"html": _stub_get_draft()})
                return
            if path == prefix + "/api/stub/presets":
                self.send_json({"presets": _stub_list_presets()})
                return
            if path == prefix + "/api/openflux":
                self.send_json(_chimera_openflux_state())
                return
            if path == prefix + "/api/subscription":
                self.send_json(_chimera_subscription_info())
                return
            if path == prefix + "/api/version":
                state = load_state()
                self.send_json({
                    "front_version": state.get("front_version", ""),
                    "upstream_cache": state.get("upstream_cache", {}),
                })
                return

            # ── QR codes: /qr/user/<uid>/<protocol> ──
            # /qr/user/<uid>/<protocol> → PNG QR code
            import re as _re
            qr_match = _re.fullmatch(
                re.escape(prefix) + r"/qr/user/([a-f0-9-]{1,64})/([a-z0-9_]+)",
                path,
            )
            if qr_match:
                uid = qr_match.group(1)
                protocol = qr_match.group(2)
                # Находим user
                user = next((u for u in _chimera_users()
                             if str(u.get("uuid") or u.get("id") or "") == uid), None)
                if not user:
                    self.send_data("User not found", status=404,
                                   content_type="text/plain; charset=utf-8")
                    return
                # Получаем links
                links = _chimera_links_for_user(user)
                link = links.get(protocol) or links.get("vless")
                if not link:
                    self.send_data("No link for protocol", status=404,
                                   content_type="text/plain; charset=utf-8")
                    return
                png_bytes = _generate_qr_png_bytes(link)
                if png_bytes is None:
                    self.send_data("QR generation failed", status=503,
                                   content_type="text/plain; charset=utf-8")
                    return
                self.send_data(png_bytes, content_type="image/png",
                               headers={"Cache-Control": "private, max-age=60"})
                return

            # ── Subscription endpoint: /sub/<token> ──
            # Делегирует в chimera.modules.subscription (если запущен отдельный
            # подписочный сервер на 8443, этот path НЕ дойдёт сюда — nginx
            # разрулит первым. Это fallback если nginx front выключен.)
            sub_match = _re.fullmatch(
                re.escape(prefix) + r"/sub/([0-9a-f]{24})",
                path,
            )
            if sub_match:
                # NB: WPP не реализует собственный подписочный сервер —
                # это прерогатива chimera.modules.subscription. Просто
                # отдаём 410 Gone с подсказкой.
                self.send_data(
                    "Subscription endpoint is served by chimera subscription "
                    "module on port 8443 — use that URL instead.",
                    status=410,
                    content_type="text/plain; charset=utf-8",
                )
                return

            # ── 404 ──
            self.send_html("Not found", status=404)

        except Exception as exc:
            self.log_message("do_GET failed: %s: %s", type(exc).__name__, exc)
            self.send_html("Internal Server Error", status=500)

    # ─── POST ───────────────────────────────────────────────────────────────

    def do_POST(self) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            prefix = _panel_path()

            # ── Login не требует auth ──
            if path == prefix + "/login" or path == "/login":
                self._handle_login()
                return

            # ── Logout ──
            if path == prefix + "/logout" or path == "/logout":
                signed = self.session_cookie_value()
                with _SESSIONS_LOCK:
                    _SESSIONS.pop(signed, None)
                self.send_response(303)
                self.send_header("Set-Cookie", _session_cookie("", 0))
                self.send_header("Location", (prefix or "") + "/login")
                self.end_headers()
                return

            # ── Всё остальное требует auth ──
            if not self.auth():
                self.redirect("/login")
                return

            try:
                form = self.form()
            except (ValueError, UnicodeDecodeError) as exc:
                self.send_html(_esc(str(exc)), status=400)
                return

            if not self.valid_csrf(form):
                self.send_html("Недействительный запрос (CSRF). "
                               "Обновите страницу.", status=403)
                return

            if path == prefix + "/logout" or path == "/logout":
                # уже обработали выше
                return

            # ── create-account (form) ──
            if path == prefix + "/create-account":
                self._handle_create_account(form)
                return

            # ── delete-user ──
            if path == prefix + "/delete-user":
                self._handle_delete_user(form)
                return

            # ── change password ──
            if path == prefix + "/password":
                self._handle_change_password(form)
                return

            # ── Landing page stub: publish ──
            if path == prefix + "/stub/publish":
                html = form.get("html", "")
                ok, msg = _stub_set_live(html)
                if ok:
                    self.redirect("/landing")
                else:
                    self.send_html(f"Ошибка публикации: {_esc(msg)}", status=400)
                return

            # ── Landing: apply preset ──
            if path == prefix + "/stub/apply-preset":
                preset_id = form.get("preset", "")
                preset = _stub_get_preset(preset_id)
                if not preset:
                    self.send_html("Preset не найден", status=400)
                    return
                ok, msg = _stub_set_live(preset.get("html", ""))
                if ok:
                    self.redirect("/landing")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=400)
                return

            # ── Landing: save draft ──
            if path == prefix + "/stub/save-draft":
                ok, msg = _stub_save_draft(form.get("html", ""))
                if ok:
                    self.redirect("/landing")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=400)
                return

            # ── Landing: discard draft ──
            if path == prefix + "/stub/discard-draft":
                _stub_discard_draft()
                self.redirect("/landing")
                return

            # ── Landing: save custom preset ──
            if path == prefix + "/stub/save-preset":
                ok, msg = _stub_save_preset(
                    name=form.get("name", ""),
                    html=form.get("html", ""),
                    description=form.get("description", ""),
                )
                if ok:
                    self.redirect("/landing")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=400)
                return

            # ── Landing: delete custom preset ──
            if path == prefix + "/stub/delete-preset":
                ok, msg = _stub_delete_preset(form.get("preset", ""))
                if ok:
                    self.redirect("/landing")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=400)
                return

            # ── OpenFlux: enable/disable/rotate ──
            if path == prefix + "/openflux/enable":
                ok, msg = _openflux_set_enabled(True)
                if ok:
                    self.redirect("/openflux")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=503)
                return
            if path == prefix + "/openflux/disable":
                ok, msg = _openflux_set_enabled(False)
                if ok:
                    self.redirect("/openflux")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=503)
                return
            if path == prefix + "/openflux/rotate":
                ok, msg = _openflux_rotate_key()
                if ok:
                    self.redirect("/openflux")
                else:
                    self.send_html(f"Ошибка: {_esc(msg)}", status=503)
                return

            # ── Auto-update toggle ──
            if path == prefix + "/autoupdate/toggle":
                enable = form.get("enable", "") == "1"
                try:
                    from chimera.modules.wpp_autoupdate import wpp_autoupdate_toggle
                    ok, msg = wpp_autoupdate_toggle(enable)
                    if ok:
                        self.redirect("/settings")
                    else:
                        self.send_html(f"Ошибка: {_esc(msg)}", status=503)
                except Exception as exc:
                    self.send_html(f"Ошибка: {_esc(str(exc))}", status=500)
                return

            # ── 404 ──
            self.send_html("Not found", status=404)

        except Exception as exc:
            self.log_message("do_POST failed: %s: %s", type(exc).__name__, exc)
            self.send_html("Internal Server Error", status=500)

    # ─── LOGIN ──────────────────────────────────────────────────────────────

    def _handle_login(self) -> None:
        client = _client_id(self)
        if _login_blocked(client):
            body = "Слишком много попыток входа. Повторите позже.".encode("utf-8")
            self.send_response(429)
            self.send_header("Retry-After", str(LOGIN_WINDOW))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        try:
            form = self.form(8192)
        except (ValueError, UnicodeDecodeError):
            self.send_html("Некорректный запрос.", status=400)
            return

        state = load_state()
        admin = state.get("admin_user", "admin")
        salt_hex = state.get("admin_pass_salt", "")
        expected_hash = state.get("admin_pass_sha256", "")

        username = form.get("user", "")
        password = form.get("password", "")

        if (username == admin
                and _check_password(password, salt_hex, expected_hash)):
            token = f"{int(time.time())}-{secrets.token_hex(16)}"
            signed = _sign(token)
            with _SESSIONS_LOCK:
                _SESSIONS[signed] = {
                    "expires": time.time() + SESSION_TTL,
                    "client":  client,
                    "csrf":    _new_csrf_token(),
                }
            _login_succeeded(client)
            self.send_response(303)
            self.send_header("Set-Cookie", _session_cookie(signed, SESSION_TTL))
            self.send_header("Location", (_panel_path() or "") + "/dashboard")
            self.end_headers()
        else:
            _login_failed(client)
            self.send_html(
                '<!doctype html><meta charset=utf-8>'
                '<meta name=viewport content="width=device-width,initial-scale=1">'
                '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;'
                'background:#060910;color:#fff;font:15px system-ui}'
                '.b{width:min(420px,90vw);padding:28px;border:1px solid #223148;'
                'border-radius:22px;background:#0d1520}a{color:#8edcff}</style>'
                '<div class=b><h2>Неверный логин или пароль</h2>'
                '<p>Попробуйте войти ещё раз.</p>'
                '<a href="/login">Вернуться</a></div>',
                status=401,
            )

    # ─── CREATE ACCOUNT ─────────────────────────────────────────────────────

    def _handle_create_account(self, form: dict) -> None:
        name = (form.get("name", "") or "").strip()
        protocol = (form.get("protocol", "vless") or "vless").strip().lower()

        if not name or len(name) > 80:
            self.send_html("Имя пользователя обязательно (1-80 символов).",
                           status=400)
            return

        if protocol not in ("vless", "hysteria", "mtproto", "awg20", "awg31"):
            self.send_html("Неизвестный протокол.", status=400)
            return

        # Делегируем в chimera CLI (как WPP делегирует в manager.py).
        # Pattern: subprocess.run(['python3', '<chimera_root>/main.py',
        #                          '--user-add', protocol, name])
        try:
            chimera_root = str(Path(__file__).resolve().parent.parent.parent)
            cmd = [
                sys.executable, f"{chimera_root}/main.py",
                "--user-add", protocol, name,
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip()[:500]
                self.send_html(f"Не удалось создать: {_esc(err)}", status=503)
                return
            self.redirect("/users")
        except subprocess.TimeoutExpired:
            self.send_html("Создание превысило таймаут (30s).", status=503)
        except Exception as exc:
            self.log_message("create_account failed: %s: %s",
                             type(exc).__name__, exc)
            self.send_html("Не удалось создать пользователя.", status=503)

    # ─── DELETE USER ────────────────────────────────────────────────────────

    def _handle_delete_user(self, form: dict) -> None:
        uid = (form.get("id", "") or "").strip()
        if not re.fullmatch(r"[a-f0-9-]{1,64}", uid):
            self.send_html("Некорректный ID пользователя.", status=400)
            return
        try:
            chimera_root = str(Path(__file__).resolve().parent.parent.parent)
            cmd = [
                sys.executable, f"{chimera_root}/main.py",
                "--user-delete", uid,
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip()[:500]
                self.send_html(f"Не удалось удалить: {_esc(err)}", status=503)
                return
            self.redirect("/users")
        except subprocess.TimeoutExpired:
            self.send_html("Удаление превысило таймаут.", status=503)
        except Exception as exc:
            self.log_message("delete_user failed: %s: %s",
                             type(exc).__name__, exc)
            self.send_html("Не удалось удалить.", status=503)

    # ─── CHANGE PASSWORD ────────────────────────────────────────────────────

    def _handle_change_password(self, form: dict) -> None:
        new_pass = form.get("a", "")
        if len(new_pass) < 3:
            self.send_html("Пароль должен содержать минимум 3 символа.",
                           status=400)
            return
        state = load_state()
        # Re-hash + rotate session key (аннулируем все сессии)
        salt = secrets.token_bytes(16).hex()
        h = hashlib.sha256(bytes.fromhex(salt) + new_pass.encode("utf-8")).hexdigest()
        state["admin_pass_salt"] = salt
        state["admin_pass_sha256"] = h
        save_state(state)
        # Rotate session key — все текущие сессии станут невалидны
        global _SESSION_KEY
        _SESSION_KEY = secrets.token_hex(32)
        with _SESSIONS_LOCK:
            _SESSIONS.clear()
        self.send_response(303)
        self.send_header("Set-Cookie", _session_cookie("", 0))
        self.send_header("Location", (_panel_path() or "") + "/login")
        self.end_headers()

    # ─── STATIC FILES ────────────────────────────────────────────────────────

    def _serve_static(self, path: str) -> None:
        """Раздаёт статику из WWW_DIR/static/."""
        prefix = _panel_path()
        rel = path[len((prefix or "") + "/static/"):]
        # Защита от path traversal
        target = (WWW_DIR / "static" / rel).resolve()
        try:
            target.relative_to((WWW_DIR / "static").resolve())
        except ValueError:
            self.send_data("Forbidden", status=403)
            return
        if not target.exists() or not target.is_file():
            self.send_data("Not found", status=404)
            return
        # MIME-типы (базовый набор)
        ext = target.suffix.lower()
        mime = {
            ".html": "text/html; charset=utf-8",
            ".css":  "text/css; charset=utf-8",
            ".js":   "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg":  "image/svg+xml",
            ".png":  "image/png",
            ".jpg":  "image/jpeg",
            ".jpeg": "image/jpeg",
            ".ico":  "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
        }.get(ext, "application/octet-stream")
        try:
            body = target.read_bytes()
            self.send_data(body, content_type=mime)
        except Exception as exc:
            self.log_message("static %s: %s", target, exc)
            self.send_data("Internal error", status=500)

    # ─── HTML PAGES (упрощённые; полный UI — отдельный подпроект) ───────────

    def _login_page(self) -> str:
        """HTML страница логина (минимальный inline CSS, без зависимостей)."""
        prefix = _panel_path()
        return f"""<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP Web Panel — вход</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;
background:#060910;color:#fff;font:15px system-ui,-apple-system,sans-serif}}
.b{{width:min(420px,90vw);padding:28px;border:1px solid #223148;
border-radius:22px;background:#0d1520;box-shadow:0 8px 32px rgba(0,0,0,.45)}}
h1{{font-size:18px;margin:0 0 4px 0;font-weight:600}}
.sub{{color:#8edcff;margin:0 0 24px 0;font-size:13px}}
label{{display:block;margin:14px 0 6px;color:#9ab;font-size:13px}}
input{{width:100%;box-sizing:border-box;padding:11px 14px;
border:1px solid #1c2b40;border-radius:10px;background:#0a121d;color:#fff;font:inherit}}
input:focus{{outline:none;border-color:#3b6ea5}}
button{{width:100%;padding:11px;margin-top:18px;border:0;border-radius:10px;
background:#2563eb;color:#fff;font:inherit;font-weight:600;cursor:pointer}}
button:hover{{background:#1d4ed8}}
.err{{color:#f87171;margin:14px 0 0 0;font-size:13px}}
</style></head><body>
<div class="b">
<h1>{_icon('shield')} WPP Web Panel</h1>
<p class="sub">Войдите для управления VPN-подключениями</p>
<form method="post" action="{prefix}/login">
<label for="user">Логин</label>
<input id="user" name="user" type="text" required autocomplete="username" autofocus>
<label for="password">Пароль</label>
<input id="password" name="password" type="password" required autocomplete="current-password">
<button type="submit">Войти</button>
</form>
</div></body></html>"""

    def _dashboard_page(self) -> str:
        """Главная страница панели — дашборд с метриками."""
        prefix = _panel_path()
        csrf = self.csrf()
        users = _chimera_users()
        traffic = _chimera_traffic()
        total_up = sum(t.get("up", 0) for t in traffic.values())
        total_down = sum(t.get("down", 0) for t in traffic.values())
        active = sum(1 for t in traffic.values() if t.get("enabled", True))
        state = _chimera_state()
        domain = state.get("domain", "—")

        return f"""<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Дашборд</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
gap:16px;padding:24px;max-width:1280px;margin:0 auto}}
.card{{padding:20px;border:1px solid #1c2b40;border-radius:14px;background:#0d1520}}
.card h3{{margin:0 0 8px 0;font-size:13px;color:#9ab;font-weight:500}}
.card .v{{font-size:24px;font-weight:700}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('grid')} WPP Web Panel</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div>
</div>
<div class="cards">
<div class="card"><h3>Сервер</h3><div class="v">{_esc(domain)}</div></div>
<div class="card"><h3>Пользователей</h3><div class="v">{len(users)}</div></div>
<div class="card"><h3>Активных</h3><div class="v">{active}</div></div>
<div class="card"><h3>Входящий трафик</h3><div class="v">{_size(total_up)}</div></div>
<div class="card"><h3>Исходящий трафик</h3><div class="v">{_size(total_down)}</div></div>
</div>
</body></html>"""

    def _users_page(self) -> str:
        """Список пользователей с возможностью удаления/смены статуса."""
        prefix = _panel_path()
        csrf = self.csrf()
        users = _chimera_users()
        traffic = _chimera_traffic()

        rows_html = []
        for u in users:
            uid = str(u.get("uuid") or u.get("id") or "")
            name = _esc(u.get("name", "") or "")
            protocol = _esc(u.get("protocol", "") or "")
            enabled = bool(u.get("enabled", True))
            state_html = ("🟢" if enabled else "🔴")
            tr = traffic.get(uid, {})
            up = _size(tr.get("up", 0))
            down = _size(tr.get("down", 0))
            rows_html.append(
                f"<tr><td>{state_html}</td><td>{name}</td><td>{protocol}</td>"
                f"<td>{up}</td><td>{down}</td>"
                f"<td><form method='post' action='{prefix}/delete-user' "
                f"style='display:inline'>"
                f"<input type='hidden' name='csrf' value='{csrf}'>"
                f"<input type='hidden' name='id' value='{_esc(uid)}'>"
                f"<button type='submit' style='background:#dc2626'>"
                f"{_icon('delete')} Удалить</button></form></td></tr>"
            )

        rows = "\n".join(rows_html) if rows_html else (
            "<tr><td colspan='6' style='text-align:center;color:#9ab'>"
            "Пользователей нет — создайте первого ↓</td></tr>"
        )

        return f"""<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Подключения</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.table-wrap{{padding:24px;max-width:1280px;margin:0 auto}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #1c2b40}}
th{{color:#9ab;font-weight:500;font-size:12px;text-transform:uppercase}}
button{{padding:6px 10px;border:0;border-radius:6px;color:#fff;font:inherit;
font-weight:500;cursor:pointer}}
.create-form{{margin:24px 0;padding:18px;border:1px solid #1c2b40;
border-radius:12px;background:#0d1520;display:flex;gap:10px;flex-wrap:wrap}}
.create-form input,.create-form select{{padding:8px 12px;border:1px solid #1c2b40;
border-radius:8px;background:#0a121d;color:#fff;font:inherit}}
.create-form button{{background:#2563eb;padding:8px 14px}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('users')} Подключения</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div>
</div>
<div class="table-wrap">
<form class="create-form" method="post" action="{prefix}/create-account">
<input type="hidden" name="csrf" value="{csrf}">
<input type="text" name="name" placeholder="Имя пользователя" required
 maxlength="80" autocomplete="off">
<select name="protocol">
<option value="vless">VLESS REALITY</option>
<option value="hysteria">Hysteria2</option>
<option value="mtproto">MTProto</option>
<option value="awg20">AmneziaWG 2.0</option>
<option value="awg31">AmneziaWG 3.1</option>
</select>
<button type="submit">{_icon('add')} Создать</button>
</form>
<table>
<thead><tr><th>Статус</th><th>Имя</th><th>Протокол</th>
<th>↑ Входящий</th><th>↓ Исходящий</th><th>Действия</th></tr></thead>
<tbody>
{rows}
</tbody></table>
</div>
</body></html>"""

    def _nodes_page(self) -> str:
        """Страница нод каскада (read-only на первом этапе)."""
        prefix = _panel_path()
        state = _chimera_state()
        nodes = state.get("chain_nodes", []) or []
        if not nodes:
            body = ('<div style="padding:48px;text-align:center;color:#9ab">'
                    'Ноды каскада не настроены. Используйте раздел '
                    '"Установка и Система → Каскад нод" в chimera CLI.</div>')
        else:
            rows = []
            for n in nodes:
                host = _esc(n.get("host", ""))
                port = _esc(str(n.get("port", "")))
                role = _esc(n.get("role", ""))
                rows.append(f"<tr><td>{host}</td><td>{port}</td>"
                            f"<td>{role}</td></tr>")
            body = (f"<table><thead><tr><th>Host</th><th>Port</th>"
                    f"<th>Role</th></tr></thead><tbody>"
                    + "\n".join(rows) + "</tbody></table>")
        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Ноды</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.wrap{{padding:24px;max-width:1280px;margin:0 auto}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #1c2b40}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('nodes')} Ноды каскада</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div></div>
<div class="wrap">{body}</div>
</body></html>"""

    def _settings_page(self) -> str:
        """Настройки — смена пароля + инфо о сервере."""
        prefix = _panel_path()
        csrf = self.csrf()
        state = _chimera_state()
        domain = _esc(state.get("domain", "—"))
        xray_port = state.get("xray_port", "—")
        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Настройки</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.wrap{{padding:24px;max-width:800px;margin:0 auto}}
.card{{margin-bottom:18px;padding:18px;border:1px solid #1c2b40;
border-radius:12px;background:#0d1520}}
.card h2{{margin:0 0 12px 0;font-size:16px;font-weight:600}}
.card label{{display:block;margin:10px 0 4px;color:#9ab;font-size:13px}}
.card input{{width:100%;box-sizing:border-box;padding:9px 12px;
border:1px solid #1c2b40;border-radius:8px;background:#0a121d;color:#fff;font:inherit}}
.card button{{margin-top:12px;padding:9px 16px;border:0;border-radius:8px;
background:#2563eb;color:#fff;font:inherit;font-weight:500;cursor:pointer}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('settings')} Настройки</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div></div>
<div class="wrap">
<div class="card"><h2>Сервер</h2>
<p>Domain: <code>{domain}</code></p>
<p>Xray порт: <code>{xray_port}</code></p>
</div>
<div class="card"><h2>Смена пароля</h2>
<form method="post" action="{prefix}/password">
<input type="hidden" name="csrf" value="{csrf}">
<label for="adminNewPassword">Новый пароль</label>
<input id="adminNewPassword" type="password" name="a" minlength="3"
 required autocomplete="new-password">
<button type="submit">Сохранить пароль</button>
<small style="display:block;margin-top:8px;color:#9ab">
Смена пароля завершит все сессии панели.</small>
</form></div>
<div class="card"><h2>Авто-обновление фронта</h2>"""

        # Auto-update state
        try:
            from chimera.modules.wpp_autoupdate import _get_auto_update_enabled, load_state as _load_au_state
            au_enabled = _get_auto_update_enabled()
            cron_installed = (_load_au_state() or {}).get("auto_update", {}).get("cron_installed", False)
        except Exception:
            au_enabled = False
            cron_installed = False

        csrf_field = f'<input type="hidden" name="csrf" value="{csrf}">'
        if au_enabled:
            au_state_html = (f'<p>Статус: <b>🟢 Включено</b> (cron в /etc/cron.d/wpp-autoupdate)</p>'
                             f'<form method="post" action="{prefix}/autoupdate/toggle">'
                             f'{csrf_field}<input type="hidden" name="enable" value="0">'
                             f'<button type="submit" style="background:#dc2626">Выключить</button></form>')
        else:
            au_state_html = (f'<p>Статус: <b>🔴 Выключено</b></p>'
                             f'<form method="post" action="{prefix}/autoupdate/toggle">'
                             f'{csrf_field}<input type="hidden" name="enable" value="1">'
                             f'<button type="submit">Включить</button></form>')
        if not cron_installed and au_enabled:
            au_state_html += '<p style="color:#fbbf24">⚠️ Cron файл не найден — пере-включите авто-обновление.</p>'

        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Настройки</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.wrap{{padding:24px;max-width:800px;margin:0 auto}}
.card{{margin-bottom:18px;padding:18px;border:1px solid #1c2b40;
border-radius:12px;background:#0d1520}}
.card h2{{margin:0 0 12px 0;font-size:16px;font-weight:600}}
.card label{{display:block;margin:10px 0 4px;color:#9ab;font-size:13px}}
.card input{{width:100%;box-sizing:border-box;padding:9px 12px;
border:1px solid #1c2b40;border-radius:8px;background:#0a121d;color:#fff;font:inherit}}
.card button{{margin-top:12px;padding:9px 16px;border:0;border-radius:8px;
background:#2563eb;color:#fff;font:inherit;font-weight:500;cursor:pointer}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('settings')} Настройки</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/openflux">OpenFlux</a>
<a href="{prefix}/landing">Лендинг</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div></div>
<div class="wrap">
<div class="card"><h2>Сервер</h2>
<p>Domain: <code>{domain}</code></p>
<p>Xray порт: <code>{xray_port}</code></p>
</div>
<div class="card"><h2>Смена пароля</h2>
<form method="post" action="{prefix}/password">
<input type="hidden" name="csrf" value="{csrf}">
<label for="adminNewPassword">Новый пароль</label>
<input id="adminNewPassword" type="password" name="a" minlength="3"
 required autocomplete="new-password">
<button type="submit">Сохранить пароль</button>
<small style="display:block;margin-top:8px;color:#9ab">
Смена пароля завершит все сессии панели.</small>
</form></div>
<div class="card"><h2>Авто-обновление фронта</h2>
{au_state_html}
<small style="display:block;margin-top:8px;color:#9ab">
Cron: 30 3 * * * root /usr/bin/python3 /opt/chimera/main.py --wpp-autoupdate
</small>
</div>
</div></body></html>"""

    def _openflux_page(self) -> str:
        """OpenFlux management page (single-profile — chimera's openflux.py)."""
        prefix = _panel_path()
        csrf = self.csrf()
        state = _chimera_openflux_state()
        installed = state.get("installed", False)
        enabled = state.get("enabled", False)

        if not installed:
            body = ('<div style="padding:48px;text-align:center;color:#9ab">'
                    'OpenFlux не установлен. Используйте chimera CLI → '
                    'раздел "OpenFlux" → установка.</div>')
        else:
            transport = _esc(state.get("transport", ""))
            bridge_active = state.get("bridge_active", False)
            bridge_port = state.get("bridge_port")
            bridge_bind = _esc(state.get("bridge_bind", "127.0.0.1"))
            doc_url = _esc(state.get("doc_url_masked", ""))
            installed_at = _esc(state.get("installed_at", ""))

            state_html = ("🟢 Активен" if enabled else "🔴 Остановлен")
            bridge_html = ("🟢 Активен" if bridge_active else "🔴 Выключен")

            actions = []
            if enabled:
                actions.append(f'<form method="post" action="{prefix}/openflux/disable" style="display:inline">'
                               f'<input type="hidden" name="csrf" value="{csrf}">'
                               f'<button type="submit" style="background:#dc2626">Остановить</button></form>')
            else:
                actions.append(f'<form method="post" action="{prefix}/openflux/enable" style="display:inline">'
                               f'<input type="hidden" name="csrf" value="{csrf}">'
                               f'<button type="submit">Запустить</button></form>')
            actions.append(f'<form method="post" action="{prefix}/openflux/rotate" style="display:inline">'
                           f'<input type="hidden" name="csrf" value="{csrf}">'
                           f'<button type="submit" style="background:#7c3aed">Rotate key</button></form>')
            actions_html = " ".join(actions)

            body = f"""
<table style="width:100%;border-collapse:collapse">
<tr><th style="text-align:left;padding:8px 0;color:#9ab">Транспорт</th><td>{transport}</td></tr>
<tr><th style="text-align:left;padding:8px 0;color:#9ab">Сервис</th><td>{state_html}</td></tr>
<tr><th style="text-align:left;padding:8px 0;color:#9ab">Bridge</th><td>{bridge_html} ({bridge_bind}:{bridge_port or '—'})</td></tr>
<tr><th style="text-align:left;padding:8px 0;color:#9ab">Doc URL</th><td><code>{doc_url}</code> <small style="color:#9ab">(secret скрыт)</small></td></tr>
<tr><th style="text-align:left;padding:8px 0;color:#9ab">Установлен</th><td>{installed_at}</td></tr>
</table>
<div style="margin-top:18px">{actions_html}</div>
"""
        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — OpenFlux</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.wrap{{padding:24px;max-width:800px;margin:0 auto}}
.card{{padding:18px;border:1px solid #1c2b40;border-radius:12px;background:#0d1520}}
.card h2{{margin:0 0 12px 0;font-size:16px;font-weight:600}}
table th,table td{{padding:6px 0}}
button{{padding:8px 14px;border:0;border-radius:8px;color:#fff;font:inherit;
font-weight:500;cursor:pointer}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('shield')} OpenFlux</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/openflux">OpenFlux</a>
<a href="{prefix}/landing">Лендинг</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div></div>
<div class="wrap"><div class="card">
<h2>OpenFlux (single-profile)</h2>
{body}
</div></div></body></html>"""

    def _landing_page(self) -> str:
        """Landing page editor — HTML editor + presets + draft."""
        prefix = _panel_path()
        csrf = self.csrf()
        live_html = _stub_get_live()
        draft_html = _stub_get_draft()
        has_draft = bool(draft_html)
        # Если есть draft — показываем его в редакторе, иначе live
        editor_content = _esc(draft_html or live_html)
        presets_list = _stub_list_presets()

        # Preset select options
        preset_options = []
        for p in presets_list:
            label = f"{_esc(p['name'])}" + (f" ({p['bytes']} байт)" if p.get("bytes") else "")
            preset_options.append(f'<option value="{_esc(p["id"])}">{label}</option>')
        preset_options_html = "\n".join(preset_options)

        # Custom presets delete buttons
        custom_presets = [p for p in presets_list if p.get("custom")]
        custom_html = ""
        if custom_presets:
            custom_items = []
            for p in custom_presets:
                custom_items.append(
                    f'<li>{_esc(p["name"])} — {_esc(p.get("description",""))} '
                    f'({p.get("bytes", 0)} байт) '
                    f'<form method="post" action="{prefix}/stub/delete-preset" style="display:inline">'
                    f'<input type="hidden" name="csrf" value="{csrf}">'
                    f'<input type="hidden" name="preset" value="{_esc(p["id"])}">'
                    f'<button type="submit" style="background:#dc2626">Удалить</button></form></li>'
                )
            custom_html = (f'<div class="card"><h2>Свои пресеты ({len(custom_presets)}/20)</h2>'
                          f'<ul style="list-style:none;padding:0">'
                          + "\n".join(custom_items) + '</ul></div>')

        draft_indicator = ('<p style="color:#fbbf24">📝 Есть несохранённый draft</p>'
                           if has_draft else '')

        return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WPP — Лендинг</title>
<style>
body{{margin:0;background:#060910;color:#fff;font:15px system-ui,sans-serif}}
.head{{display:flex;justify-content:space-between;align-items:center;
padding:16px 24px;border-bottom:1px solid #1c2b40;background:#0d1520}}
.brand{{font-weight:700;font-size:17px}}
.nav a{{color:#9ab;margin-left:14px;text-decoration:none;font-size:13px}}
.nav a:hover{{color:#fff}}
.wrap{{padding:24px;max-width:1200px;margin:0 auto}}
.card{{margin-bottom:18px;padding:18px;border:1px solid #1c2b40;
border-radius:12px;background:#0d1520}}
.card h2{{margin:0 0 12px 0;font-size:16px;font-weight:600}}
textarea{{width:100%;min-height:300px;box-sizing:border-box;padding:12px;
border:1px solid #1c2b40;border-radius:8px;background:#0a121d;color:#fff;
font-family:ui-monospace,monospace;font-size:13px}}
button{{padding:8px 16px;border:0;border-radius:8px;color:#fff;font:inherit;
font-weight:500;cursor:pointer;margin-right:8px;margin-top:12px}}
button.primary{{background:#2563eb}}button.danger{{background:#dc2626}}
button.warn{{background:#f59e0b;color:#000}}
select,input{{padding:8px 12px;border:1px solid #1c2b40;border-radius:8px;
background:#0a121d;color:#fff;font:inherit}}
small{{color:#9ab}}
</style></head><body>
<div class="head">
<div class="brand">{_icon('edit')} Лендинг / HTML editor</div>
<div class="nav">
<a href="{prefix}/dashboard">Дашборд</a>
<a href="{prefix}/users">Подключения</a>
<a href="{prefix}/nodes">Ноды</a>
<a href="{prefix}/settings">Настройки</a>
<a href="{prefix}/openflux">OpenFlux</a>
<a href="{prefix}/landing">Лендинг</a>
<a href="{prefix}/logout">{_icon('logout')} Выход</a>
</div></div>
<div class="wrap">
<div class="card">
<h2>HTML редактор лендинга</h2>
{draft_indicator}
<small>Лимит: 256 KiB. Публикуется в /var/www/panel-stub/index.html</small>
<form method="post" action="{prefix}/stub/publish">
<input type="hidden" name="csrf" value="{csrf}">
<textarea name="html" placeholder="<!doctype html>...">{editor_content}</textarea>
<button type="submit" class="primary">Опубликовать</button>
</form>
</div>
<div class="card">
<h2>Draft</h2>
<form method="post" action="{prefix}/stub/save-draft">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit" class="warn">Сохранить текущий textarea как draft</button>
</form>
<form method="post" action="{prefix}/stub/discard-draft" style="display:inline">
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit" class="danger">Удалить draft</button>
</form>
</div>
<div class="card">
<h2>Готовые пресеты</h2>
<form method="post" action="{prefix}/stub/apply-preset" style="display:inline">
<input type="hidden" name="csrf" value="{csrf}">
<select name="preset">{preset_options_html}</select>
<button type="submit">Применить</button>
</form>
</div>
<div class="card">
<h2>Сохранить как свой preset</h2>
<form method="post" action="{prefix}/stub/save-preset">
<input type="hidden" name="csrf" value="{csrf}">
<input type="text" name="name" placeholder="Имя (1-80)" maxlength="80" required>
<input type="text" name="description" placeholder="Описание (опц.)" maxlength="180">
<textarea name="html" placeholder="<!doctype html>..." style="min-height:100px"></textarea>
<button type="submit" class="primary">Сохранить preset</button>
</form>
</div>
{custom_html}
</div></body></html>"""


# ─── START SERVER ────────────────────────────────────────────────────────────

def start_server() -> None:
    """Точка входа для systemd ExecStart."""
    state = load_state()
    port = int(state.get("web_port", 9701) or 9701)
    if not port:
        print("[WPP-WEB] web_port not set in state — using 9701", file=sys.stderr)
        port = 9701
    host = "127.0.0.1"  # loopback-only — доступ через SSH-tunnel или Nginx Front
    print(f"[WPP-WEB] starting on {host}:{port} (panel_path={_panel_path()!r})",
          file=sys.stderr, flush=True)
    ThreadingHTTPServer((host, port), _WppHandler).serve_forever()


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--serve":
        start_server()
    else:
        print("Usage: python3 wpp_panel_web.py --serve",
              file=sys.stderr)
        sys.exit(1)
