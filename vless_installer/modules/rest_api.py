"""
vless_installer/modules/rest_api.py
───────────────────────────────────────────────────────────────────────────────
REST API + Admin Panel + User Portal — единый HTTP-сервер.

Запуск: отдельный systemd-сервис vless-web.service.
Порт: из state.json (ключ web_port, по умолчанию 8443).
Авторизация: Basic Auth (admin — логин/пароль из state.json;
             user — логин/пароль из users.json).

Endpoints:
  REST API (admin):
    GET    /api/health              — статус сервисов, SSL, RAM, Disk
    GET    /api/users               — список пользователей
    POST   /api/users               — создать пользователя
    DELETE /api/users/{email}       — удалить пользователя
    GET    /api/users/{email}/traffic — трафик пользователя
    POST   /api/rotate/uuid         — ротация UUID
    POST   /api/rotate/reality       — ротация REALITY-ключей
    GET    /api/geoip/rules          — текущие GeoIP-правила
    POST   /api/geoip/rules          — добавить правило
    DELETE /api/geoip/rules          — удалить все правила
    POST   /api/backup               — создать бэкап
    GET    /api/backup/list          — список бэкапов

  Web UI:
    GET  /admin/    — Admin Panel (HTML)
    GET  /portal/   — User Portal (HTML)
    GET  /portal/{token} — User Portal с авто-логином

Дизайн: glassmorphism, серо-голубые тона, анимации.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  КОНФИГУРАЦИЯ
# ============================================================================

WEB_CONFIG_FILE = Path("/var/lib/xray-installer/web_config.json")
WEB_SERVICE_FILE = Path("/etc/systemd/system/vless-web.service")
DEFAULT_WEB_PORT = 8443
# По умолчанию панель слушает только loopback — доступ через SSH-туннель
# (ssh -L 8443:127.0.0.1:8443 user@server). Внешний доступ включается явно
# через do_manage_web_panel() пункт 5, с предупреждением о HTTP без TLS.
DEFAULT_WEB_HOST = "127.0.0.1"

# Cap на размер тела JSON-запроса — защита от memory-exhaustion.
MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB

# In-memory sliding-window rate-limit для auth-попыток (общий для всех потоков
# ThreadingHTTPServer). Не персистентный — сброс при рестарте сервиса, этого
# достаточно для отсечения brute-force на этом масштабе.
_AUTH_FAIL_LOG: dict[str, list[float]] = {}
_AUTH_FAIL_LOCK = threading.Lock()
AUTH_FAIL_WINDOW = 60     # секунд — окно подсчёта неудачных попыток
AUTH_FAIL_MAX = 10        # попыток в окне до включения троттлинга
AUTH_FAIL_REJECT = 30     # секунд — 429 Retry-After


def _web_config_load() -> dict:
    """Загружает конфиг веб-панели (порт, admin логин/пароль)."""
    try:
        if WEB_CONFIG_FILE.exists():
            return json.loads(WEB_CONFIG_FILE.read_text())
    except Exception:
        pass
    return {}


def _web_config_save(cfg: dict) -> None:
    """Сохраняет конфиг веб-панели."""
    try:
        WEB_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        WEB_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        WEB_CONFIG_FILE.chmod(0o600)
    except Exception:
        pass


def _web_config_init(port: int = None, admin_user: str = None,
                     admin_pass: str = None, host: str = None) -> dict:
    """Инициализирует конфиг веб-панели при первой установке.
    host=None — оставить существующее значение (или поставить default при первой установке)."""
    cfg = _web_config_load()
    if port:
        cfg["port"] = port
    elif "port" not in cfg:
        cfg["port"] = DEFAULT_WEB_PORT
    if host:
        cfg["host"] = host
    elif "host" not in cfg:
        cfg["host"] = DEFAULT_WEB_HOST
    if admin_user:
        cfg["admin_user"] = admin_user
    elif "admin_user" not in cfg:
        cfg["admin_user"] = "admin"
    if admin_pass:
        cfg["admin_pass"] = admin_pass
    elif "admin_pass" not in cfg:
        cfg["admin_pass"] = secrets.token_urlsafe(16)
    cfg["enabled"] = True
    _web_config_save(cfg)
    return cfg


# ============================================================================
#  ВСПОМОГАТЕЛЬНЫЕ — получение данных из ядра
# ============================================================================

def _get_state() -> dict:
    """Читает state.json."""
    core = _core_module()
    try:
        if core.STATE_FILE.exists():
            return json.loads(core.STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _get_users() -> list[dict]:
    """Загружает список пользователей."""
    core = _core_module()
    users_file = core.USERS_FILE
    if not users_file.exists():
        return []
    try:
        return json.loads(users_file.read_text())
    except Exception:
        return []


def _save_users(users: list[dict]) -> None:
    """Сохраняет список пользователей."""
    core = _core_module()
    users_file = core.USERS_FILE
    users_file.parent.mkdir(parents=True, exist_ok=True)
    users_file.write_text(json.dumps(users, indent=2, ensure_ascii=False))
    core._set_config_owner(users_file)


def _get_user_traffic(email: str) -> dict:
    """Возвращает трафик пользователя (uplink + downlink)."""
    core = _core_module()
    try:
        # Пытаемся через Stats API
        from vless_installer.modules.traffic_tracking import _query_user_traffic_bytes
        total = _query_user_traffic_bytes(email)
        return {"email": email, "total_bytes": total,
                "total_gb": round(total / 1024**3, 2)}
    except Exception:
        return {"email": email, "total_bytes": 0, "total_gb": 0}


def _get_ttl_info(email: str) -> dict:
    """Возвращает TTL-информацию о пользователе."""
    try:
        from vless_installer.modules.ttl_users import _ttl_load, _ttl_expires_str, _ttl_is_expired
        ttl = _ttl_load()
        if email in ttl:
            entry = ttl[email]
            expires = entry.get("expires_at", "")
            return {
                "has_ttl": True,
                "expires_at": expires,
                "expires_str": _ttl_expires_str(expires),
                "expired": _ttl_is_expired(expires),
                "days": entry.get("days", 0),
            }
    except Exception:
        pass
    return {"has_ttl": False}


def _get_health() -> dict:
    """Собирает health-статус системы."""
    core = _core_module()
    _run = core._run

    result = {}

    # Xray
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    result["xray"] = r.stdout.strip() if r.returncode == 0 else "inactive"

    # Nginx
    r = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
    result["nginx"] = r.stdout.strip() if r.returncode == 0 else "inactive"

    # DNSCrypt
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    result["dnscrypt"] = r.stdout.strip() if r.returncode == 0 else "inactive"

    # SSL
    state = _get_state()
    domain = state.get("domain", "")
    if domain:
        cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if cert.exists():
            try:
                r = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
                         capture=True, check=False)
                expiry = r.stdout.strip().split("=", 1)[-1]
                r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                days = (int(r2.stdout.strip()) - int(time.time())) // 86400
                result["ssl_days_left"] = days
                result["ssl_domain"] = domain
            except Exception:
                result["ssl_days_left"] = -1
                result["ssl_domain"] = domain

    # RAM
    try:
        meminfo = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            meminfo[k.strip()] = int(v.strip().split()[0])
        total_mb = meminfo.get("MemTotal", 0) // 1024
        avail_mb = meminfo.get("MemAvailable", 0) // 1024
        result["ram_total_mb"] = total_mb
        result["ram_used_mb"] = total_mb - avail_mb
        result["ram_pct"] = round((total_mb - avail_mb) * 100 / max(total_mb, 1), 1)
    except Exception:
        pass

    # Disk
    try:
        r = _run(["df", "-h", "/"], capture=True, check=False)
        parts = r.stdout.splitlines()[-1].split()
        result["disk_used"] = parts[2]
        result["disk_total"] = parts[1]
        result["disk_pct"] = float(parts[4].replace("%", ""))
    except Exception:
        pass

    # CPU
    try:
        r = _run(["nproc"], capture=True, check=False)
        result["cpu_cores"] = int(r.stdout.strip())
    except Exception:
        result["cpu_cores"] = 1

    # Uptime
    try:
        up_s = float(Path("/proc/uptime").read_text().split()[0])
        result["uptime_hours"] = round(up_s / 3600, 1)
    except Exception:
        pass

    # Xray connections
    try:
        r = _run(["ss", "-tnp"], capture=True, check=False)
        result["xray_connections"] = sum(1 for l in r.stdout.splitlines() if "xray" in l)
    except Exception:
        result["xray_connections"] = 0

    # Server info
    result["domain"] = domain
    result["server_port"] = state.get("server_port", 443)
    result["protocol_mode"] = state.get("protocol_mode", "reality")
    result["install_mode"] = state.get("install_mode", "A")
    result["timestamp"] = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    return result


def _generate_vless_links(user: dict) -> list[dict]:
    """Генерирует VLESS-ссылки для пользователя."""
    core = _core_module()
    state = _get_state()

    domain = state.get("domain", "")
    port = state.get("server_port", 443)
    uuid_val = user.get("uuid", "")
    pub_key = state.get("public_key", "")
    short_id = state.get("short_id", "")
    fp = state.get("fingerprint", "chrome")
    proto = state.get("protocol_mode", "reality")
    xhttp_path = state.get("xhttp_path", "/")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    # SNI: Mode B + AWG → reality_dest, else domain
    install_mode = state.get("install_mode", "A")
    awg_exit = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    if proto == "reality" and awg_exit and reality_dest:
        sni = reality_dest
    elif proto == "reality":
        sni = domain
    else:
        sni = domain

    links = []

    # IPv4 / Domain link
    if proto == "reality":
        link = (f"vless://{uuid_val}@{domain}:{port}"
                f"?encryption=none&flow={xtls_flow}"
                f"&security=reality&sni={sni}"
                f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                f"&type=tcp#VLESS-Reality")
    else:
        from urllib.parse import quote
        xhttp_path_enc = quote(xhttp_path, safe="")
        link = (f"vless://{uuid_val}@{domain}:{port}"
                f"?encryption=none&security=tls&sni={domain}"
                f"&fp={fp}&type=http&path={xhttp_path_enc}#VLESS-xHTTP")
    links.append({"label": "IPv4 / Domain", "link": link, "protocol": proto})

    # IPv6 link (если доступен)
    ipv6 = state.get("ipv6", "")
    if ipv6:
        if proto == "reality":
            link6 = (f"vless://{uuid_val}@[{ipv6}]:{port}"
                     f"?encryption=none&flow={xtls_flow}"
                     f"&security=reality&sni={sni}"
                     f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                     f"&type=tcp#VLESS-Reality-IPv6")
        else:
            from urllib.parse import quote
            xhttp_path_enc = quote(xhttp_path, safe="")
            link6 = (f"vless://{uuid_val}@[{ipv6}]:{port}"
                     f"?encryption=none&security=tls&sni={domain}"
                     f"&fp={fp}&type=http&path={xhttp_path_enc}#VLESS-xHTTP-IPv6")
        links.append({"label": "IPv6", "link": link6, "protocol": proto})

    # Hysteria2 (если включён)
    if state.get("h2_exit_enabled", False):
        h2_host = state.get("awg_exit_host", domain)
        h2_port = state.get("h2_port", 443)
        h2_pass = state.get("h2_password", "")
        h2_link = f"hysteria2://{h2_pass}@{h2_host}:{h2_port}?insecure=1&sni={domain}#Hysteria2"
        links.append({"label": "Hysteria2", "link": h2_link, "protocol": "hysteria2"})

    # MTProto (если установлен)
    try:
        from vless_installer.modules.mtproto import _load_state as _mtproto_load
        mt_state = _mtproto_load(Path("/var/lib/xray-installer/mtproto_state.json"))
        if mt_state.get("port"):
            mt_port = mt_state["port"]
            mt_secret = mt_state.get("secret", "")
            mt_link = f"https://t.me/proxy?server={domain}&port={mt_port}&secret={mt_secret}"
            links.append({"label": "MTProto", "link": mt_link, "protocol": "mtproto"})
    except Exception:
        pass

    return links


def _generate_clash_config(user: dict) -> str:
    """Генерирует Clash Meta YAML для пользователя."""
    links = _generate_vless_links(user)
    if not links:
        return ""

    first = links[0]
    state = _get_state()
    domain = state.get("domain", "")
    port = state.get("server_port", 443)
    uuid_val = user.get("uuid", "")
    pub_key = state.get("public_key", "")
    short_id = state.get("short_id", "")
    fp = state.get("fingerprint", "chrome")
    proto = state.get("protocol_mode", "reality")
    sni = domain
    xhttp_path = state.get("xhttp_path", "/")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    if proto == "reality":
        clash = f"""proxies:
  - name: VLESS-Reality
    type: vless
    server: {domain}
    port: {port}
    uuid: {uuid_val}
    network: tcp
    tls: true
    udp: true
    flow: {xtls_flow}
    reality-opts:
      public-key: {pub_key}
      short-id: {short_id}
    client-fingerprint: {fp}
    servername: {sni}

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - VLESS-Reality

rules:
  - MATCH,Proxy
"""
    else:
        clash = f"""proxies:
  - name: VLESS-xHTTP
    type: vless
    server: {domain}
    port: {port}
    uuid: {uuid_val}
    network: http
    tls: true
    udp: false
    http-opts:
      path: [{xhttp_path}]
    client-fingerprint: {fp}
    servername: {domain}

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - VLESS-xHTTP

rules:
  - MATCH,Proxy
"""
    return clash


def _generate_singbox_config(user: dict) -> str:
    """Генерирует Sing-box JSON для пользователя."""
    state = _get_state()
    domain = state.get("domain", "")
    port = state.get("server_port", 443)
    uuid_val = user.get("uuid", "")
    pub_key = state.get("public_key", "")
    short_id = state.get("short_id", "")
    fp = state.get("fingerprint", "chrome")
    proto = state.get("protocol_mode", "reality")
    sni = domain
    xhttp_path = state.get("xhttp_path", "/")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    if proto == "reality":
        config = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": uuid_val,
                **({"flow": xtls_flow} if xtls_flow else {}),
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "utls": {"enabled": True, "fingerprint": fp},
                    "reality": {
                        "enabled": True,
                        "public_key": pub_key,
                        "short_id": short_id,
                    }
                }
            }]
        }
    else:
        config = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": uuid_val,
                "transport": {"type": "http", "path": xhttp_path},
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "utls": {"enabled": True, "fingerprint": fp},
                }
            }]
        }
    return json.dumps(config, indent=2, ensure_ascii=False)


# ============================================================================
#  HTTP HANDLER
# ============================================================================

class _VLESSHandler(BaseHTTPRequestHandler):
    """HTTP request handler для REST API + Admin + Portal."""

    # HTTP/1.1 вместо дефолтного HTTP/1.0 — современные браузеры лучше работают
    # с Basic Auth + fetch() по HTTP/1.1 (keep-alive, корректная передача кредов).
    # HTTP/1.0 мог вызывать проблемы с JS-запросами из admin_panel/user_portal.
    protocol_version = "HTTP/1.1"

    # Per-connection timeout (seconds). Каждый запрос синхронный и быстрый
    # (медленные — geoip/backup — укладываются в 30с). Без этого таймаута
    # (= None по умолчанию в stdlib) клиент может держать соединение бесконечно.
    timeout = 30

    def log_message(self, fmt, *args):
        pass  # тихий лог

    # ── Rate-limit (in-memory sliding window, общий для всех потоков) ───────

    def _client_ip(self) -> str:
        try:
            return self.client_address[0] if self.client_address else "?"
        except Exception:
            return "?"

    def _is_rate_limited(self) -> bool:
        """True если IP превысил AUTH_FAIL_MAX попыток за AUTH_FAIL_WINDOW
        и всё ещё находится в окне AUTH_FAIL_REJECT с момента последней неудачи."""
        ip = self._client_ip()
        now = time.time()
        with _AUTH_FAIL_LOCK:
            ts = [t for t in _AUTH_FAIL_LOG.get(ip, [])
                  if t > now - AUTH_FAIL_WINDOW]
            _AUTH_FAIL_LOG[ip] = ts
            if len(ts) >= AUTH_FAIL_MAX and (now - ts[-1]) < AUTH_FAIL_REJECT:
                return True
        return False

    def _record_auth_failure(self) -> None:
        ip = self._client_ip()
        now = time.time()
        with _AUTH_FAIL_LOCK:
            _AUTH_FAIL_LOG.setdefault(ip, []).append(now)
            _AUTH_FAIL_LOG[ip] = [t for t in _AUTH_FAIL_LOG[ip]
                                  if t > now - AUTH_FAIL_WINDOW]

    # ── Авторизация ──────────────────────────────────────────────────────────

    def _check_admin_auth(self) -> bool:
        """Проверяет креды админа. БЕЗ сайд-эффектов (401/429 не отправляет).
        Использует secrets.compare_digest для постоянного времени сравнения."""
        cfg = _web_config_load()
        expected_user = cfg.get("admin_user", "admin")
        expected_pass = cfg.get("admin_pass", "")
        if not expected_pass:
            # Конфиг не инициализирован — отказываем (не пускаем по пустому паролю).
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            user, _, passwd = decoded.partition(":")
            return (secrets.compare_digest(user, expected_user) and
                    secrets.compare_digest(passwd, expected_pass))
        except Exception:
            return False

    def _check_user_auth(self) -> Optional[dict]:
        """Проверяет креды пользователя. БЕЗ сайд-эффектов.
        portal_password обязателен. Fallback на uuid убран намеренно:
        uuid — это публичная часть vless:// ссылки (в QR-коде клиента),
        любой, кто видел ссылку подключения, не должен уметь залогиниться."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            user_or_email, _, password = decoded.partition(":")
            users = _get_users()
            for u in users:
                if (u.get("name", "") == user_or_email or
                    u.get("email", "") == user_or_email):
                    stored = u.get("portal_password", "")
                    # Без portal_password вход запрещён. compare_digest даёт
                    # constant-time сравнение, но вызываем только при непустом stored
                    # (compare_digest с пустой строкой тоже работает, но семантически
                    # empty stored = пользователь ещё не установлен пароль).
                    if stored and secrets.compare_digest(stored, password):
                        return u
                    return None  # пользователь найден, пароль не совпал / не задан
        except Exception:
            return None
        return None

    def _require_admin(self, realm: str = "Admin") -> bool:
        """Возвращает True если админ-авторизация пройдена.
        Иначе сам отправляет 401 (с записью в rate-limit) или 429 и возвращает False.
        Вызывающему коду нужно только `if not self._require_admin(): return`."""
        if self._is_rate_limited():
            self._send_429()
            return False
        if not self._check_admin_auth():
            self._record_auth_failure()
            self._send_401(realm)
            return False
        return True

    def _require_user(self) -> Optional[dict]:
        """Возвращает user dict если авторизация пройдена, иначе None
        (и сам отправляет 401/429)."""
        if self._is_rate_limited():
            self._send_429()
            return None
        u = self._check_user_auth()
        if u is None:
            self._record_auth_failure()
            self._send_401("User Portal")
            return None
        return u

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_401(self, realm: str = "Admin") -> None:
        body = b'{"error": "Unauthorized"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", f'Basic realm="{realm}"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_429(self) -> None:
        body = b'{"error": "Too Many Requests"}'
        self.send_response(429)
        self.send_header("Retry-After", str(AUTH_FAIL_REJECT))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_404(self) -> None:
        self._send_json({"error": "Not found"}, 404)

    def _read_body(self) -> Optional[dict]:
        """Читает и парсит JSON-тело. Возвращает dict (возможно пустой).
        Возвращает None если тело превышает MAX_BODY_BYTES — вызывающий код
        должен в этом случае отправить 413 Payload Too Large."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return {}
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return {}

    # ── Routing ──────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # Health (без авторизации — для мониторинга)
        if path == "/api/health":
            self._send_json(_get_health())
            return

        # Admin Panel HTML
        if path == "/admin" or path == "/admin/":
            if not self._require_admin("Admin Panel"):
                return
            from vless_installer.modules.admin_panel import get_admin_html
            self._send_html(get_admin_html())
            return

        # User Portal HTML
        if path == "/portal" or path == "/portal/":
            user = self._require_user()
            if user is None:
                return
            from vless_installer.modules.user_portal import get_portal_html
            self._send_html(get_portal_html(user))
            return

        # ── REST API (admin only) ────────────────────────────────────────────

        if path == "/api/users":
            if not self._require_admin():
                return
            users = _get_users()
            # Не отдаём пароли
            safe = [{k: v for k, v in u.items()
                     if k not in ("portal_password",)} for u in users]
            self._send_json({"users": safe, "count": len(safe)})
            return

        # GET /api/users/{email}/traffic
        m = re.match(r"^/api/users/(.+)/traffic$", path)
        if m:
            if not self._require_admin():
                return
            # unquote — см. комментарий в do_DELETE. Браузер кодирует @ как %40.
            email = unquote(m.group(1))
            traffic = _get_user_traffic(email)
            ttl = _get_ttl_info(email)
            self._send_json({**traffic, **ttl})
            return

        # GET /api/geoip/rules
        if path == "/api/geoip/rules":
            if not self._require_admin():
                return
            try:
                from vless_installer.modules.geoip_block import _geoip_block_get_rules
                rules = _geoip_block_get_rules()
                self._send_json({"rules": rules, "count": len(rules)})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/backup/list
        if path == "/api/backup/list":
            if not self._require_admin():
                return
            core = _core_module()
            backups = []
            if core.BACKUP_DIR.exists():
                for d in sorted(core.BACKUP_DIR.iterdir(), reverse=True):
                    if d.is_dir() and d.name.startswith("config_"):
                        backups.append({"name": d.name, "path": str(d)})
            self._send_json({"backups": backups, "count": len(backups)})
            return

        self._send_404()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # ── REST API (admin only) ────────────────────────────────────────────

        if path == "/api/users":
            if not self._require_admin():
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            email = body.get("email", "").strip()
            name = body.get("name", "").strip() or email.split("@")[0]
            if not email:
                self._send_json({"error": "email required"}, 400)
                return

            core = _core_module()
            new_uuid = core.gen_uuid()
            # portal_password генерируется отдельно от uuid и возвращается ОДИН раз
            # в ответе POST /api/users. В дальнейшем посмотреть нельзя, только сменить
            # через POST /api/portal/password. Fallback на uuid как пароль убран —
            # uuid это публичная часть vless:// ссылки и не может быть паролем.
            portal_password = secrets.token_urlsafe(12)
            users = _get_users()
            users.append({
                "uuid": new_uuid,
                "email": email,
                "name": name,
                "portal_password": portal_password,
                "created": datetime.now().isoformat(),
            })
            _save_users(users)

            # Применяем к конфигу
            try:
                core._users_apply_to_config(users)
            except Exception:
                pass

            self._send_json({
                "status": "created",
                "uuid": new_uuid,
                "email": email,
                "portal_login": name or email,
                "portal_password": portal_password,
            }, 201)
            return

        if path == "/api/rotate/uuid":
            if not self._require_admin():
                return
            try:
                from vless_installer.modules.credential_rotation import _uuid_rotate_now
                new_uuid = _uuid_rotate_now()
                if new_uuid:
                    self._send_json({"status": "rotated", "new_uuid": new_uuid})
                else:
                    self._send_json({"error": "rotation failed"}, 500)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/api/rotate/reality":
            if not self._require_admin():
                return
            try:
                from vless_installer.modules.credential_rotation import _rotate_reality_keys
                new_keys = _rotate_reality_keys()
                if new_keys:
                    self._send_json({"status": "rotated", **new_keys})
                else:
                    self._send_json({"error": "rotation failed"}, 500)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/api/geoip/rules":
            if not self._require_admin():
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            codes = body.get("codes", [])
            mode = body.get("mode", "block")  # block / allow
            try:
                from vless_installer.modules.geoip_block import (
                    _geoip_set_allowlist, _geoip_add_country_block
                )
                if mode == "allow":
                    _geoip_set_allowlist(codes)
                else:
                    _geoip_add_country_block(codes)
                self._send_json({"status": "applied", "codes": codes, "mode": mode})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/api/backup":
            if not self._require_admin():
                return
            try:
                from vless_installer.modules.backup_rollback import create_backup
                create_backup()
                self._send_json({"status": "backup_created"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # ── User Portal API ──────────────────────────────────────────────────

        if path == "/api/portal/links":
            user = self._require_user()
            if user is None:
                return
            links = _generate_vless_links(user)
            self._send_json({"links": links, "count": len(links)})
            return

        if path == "/api/portal/traffic":
            user = self._require_user()
            if user is None:
                return
            email = user.get("email", "")
            traffic = _get_user_traffic(email)
            ttl = _get_ttl_info(email)
            self._send_json({**traffic, **ttl})
            return

        if path == "/api/portal/health":
            user = self._require_user()
            if user is None:
                return
            health = _get_health()
            # Ограниченный набор для юзера
            safe = {
                "domain": health.get("domain", ""),
                "server_port": health.get("server_port", 443),
                "protocol_mode": health.get("protocol_mode", "reality"),
                "xray": health.get("xray", "unknown"),
                "ssl_days_left": health.get("ssl_days_left", -1),
                "uptime_hours": health.get("uptime_hours", 0),
                "timestamp": health.get("timestamp", ""),
            }
            self._send_json(safe)
            return

        if path == "/api/portal/clash":
            user = self._require_user()
            if user is None:
                return
            clash = _generate_clash_config(user)
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="clash-meta.yaml"')
            self.send_header("Content-Length", str(len(clash.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(clash.encode("utf-8"))
            return

        if path == "/api/portal/singbox":
            user = self._require_user()
            if user is None:
                return
            singbox = _generate_singbox_config(user)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="sing-box.json"')
            self.send_header("Content-Length", str(len(singbox.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(singbox.encode("utf-8"))
            return

        if path == "/api/portal/password":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            new_pass = body.get("new_password", "").strip()
            if len(new_pass) < 8:
                self._send_json({"error": "Пароль минимум 8 символов"}, 400)
                return
            email = user.get("email", "")
            users = _get_users()
            for u in users:
                if u.get("email") == email:
                    u["portal_password"] = new_pass
                    _save_users(users)
                    self._send_json({"status": "changed"})
                    return
            self._send_json({"error": "user not found"}, 404)
            return

        self._send_404()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # DELETE /api/users/{email}
        m = re.match(r"^/api/users/(.+)$", path)
        if m:
            if not self._require_admin():
                return
            # unquote — декодирует %40 → @, %2B → +, и т.д.
            # Браузер кодирует email через encodeURIComponent(), и сервер
            # получает test%40local вместо test@local. Без unquote — user
            # не находится в users.json → 404 → "Ошибка удаления" в admin panel.
            email = unquote(m.group(1))
            users = _get_users()
            new_users = [u for u in users if u.get("email") != email]
            if len(new_users) == len(users):
                self._send_json({"error": "user not found"}, 404)
                return
            _save_users(new_users)
            try:
                core = _core_module()
                core._users_apply_to_config(new_users)
            except Exception:
                pass
            self._send_json({"status": "deleted", "email": email})
            return

        # DELETE /api/geoip/rules
        if path == "/api/geoip/rules":
            if not self._require_admin():
                return
            try:
                from vless_installer.modules.geoip_block import _geoip_remove_all
                _geoip_remove_all()
                self._send_json({"status": "all_rules_removed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        self._send_404()

    def do_OPTIONS(self):
        # CORS отключён — панель работает same-origin. Если нужен cross-origin
        # доступ (например, отдельный frontend), настройте reverse-proxy с
        # явным Access-Control-Allow-Origin для конкретных доменов.
        self.send_response(204)
        self.end_headers()


# ============================================================================
#  SERVER
# ============================================================================

def start_server(port: int = None, host: str = None) -> None:
    """Запускает HTTP-сервер (блокирующий вызов).
    По умолчанию bind 127.0.0.1 (читается из web_config.json) — доступ только
    через SSH-туннель: ssh -L 8443:127.0.0.1:8443 user@server.
    Для внешнего доступа включите пункт 5 в do_manage_web_panel() —
    будет напечатано предупреждение о HTTP без TLS."""
    cfg = _web_config_load()
    if port is None:
        port = cfg.get("port", DEFAULT_WEB_PORT)
    if host is None:
        host = cfg.get("host", DEFAULT_WEB_HOST)

    # ThreadingHTTPServer: каждый запрос в отдельном потоке, иначе
    # single-threaded HTTPServer + медленный клиент = тривиальный DoS.
    server = ThreadingHTTPServer((host, port), _VLESSHandler)
    # Per-connection timeout задаётся классом _VLESSHandler.timeout (30с).
    # serve_forever() не требует server.timeout.
    print(f"[VLESS Web] Сервер запущен на {host}:{port} (ThreadingHTTPServer)")
    if host == "0.0.0.0":
        print("[VLESS Web] ⚠️  ВНИМАНИЕ: HTTP без TLS на 0.0.0.0!")
        print("[VLESS Web] ⚠️  Basic Auth = base64, НЕ шифрование.")
        print("[VLESS Web] ⚠️  Используйте reverse-proxy (nginx) с TLS или SSH-туннель.")
    else:
        print(f"[VLESS Web] Локальный bind. Доступ через SSH-туннель:")
        print(f"[VLESS Web]   ssh -L {port}:127.0.0.1:{port} user@<server>")
    print(f"[VLESS Web] Admin:  http://<IP>:{port}/admin/")
    print(f"[VLESS Web] Portal: http://<IP>:{port}/portal/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[VLESS Web] Остановлен.")
        server.server_close()


def _run_in_thread(port: int = None) -> threading.Thread:
    """Запускает сервер в отдельном потоке (для тестов)."""
    t = threading.Thread(target=start_server, args=(port,), daemon=True)
    t.start()
    return t


# ============================================================================
#  SYSTEMD SERVICE
# ============================================================================

def install_web_service(port: int = None, admin_user: str = None,
                        admin_pass: str = None,
                        expose: Optional[bool] = None) -> dict:
    """Устанавливает systemd-сервис для веб-панели.
    По умолчанию bind 127.0.0.1 — ufw НЕ открывается (доступ через SSH-туннель).
    expose=True  — bind 0.0.0.0 + открытие порта в ufw + предупреждение о HTTP.
    expose=False — принудительно 127.0.0.1 (даже если в конфиге было 0.0.0.0).
    expose=None  — оставить текущий host в конфиге как есть."""
    host_arg = None
    if expose is True:
        host_arg = "0.0.0.0"
    elif expose is False:
        host_arg = "127.0.0.1"
    cfg = _web_config_init(port=port, admin_user=admin_user,
                           admin_pass=admin_pass, host=host_arg)
    port = cfg["port"]
    current_host = cfg.get("host", DEFAULT_WEB_HOST)

    core = _core_module()
    _run = core._run

    # Открываем порт в ufw ТОЛЬКО при явном внешнем доступе (host=0.0.0.0).
    # По умолчанию (127.0.0.1) — не открываем, доступ через SSH-туннель.
    if current_host == "0.0.0.0" and shutil.which("ufw"):
        _run(["ufw", "allow", str(port), "tcp",
              "comment", "VLESS Web Panel (exposed, no TLS)"],
             check=False, quiet=True)
        warn_msg = (
            f"ВНИМАНИЕ: веб-панель открыта наружу на 0.0.0.0:{port} без TLS! "
            "Basic Auth = base64, НЕ шифрование. "
            "Используйте reverse-proxy (nginx) с TLS или SSH-туннель."
        )
        try:
            core.warn(warn_msg)
        except Exception:
            print("[VLESS Web] " + warn_msg)

    # systemd unit — start_server() читает host из cfg
    main_py = Path(sys.argv[0]).resolve() if sys.argv[0] else Path("/opt/vless-ultimate/main.py")
    project_root = main_py.parent

    unit = f"""[Unit]
Description=VLESS Ultimate Web Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "from vless_installer.modules.rest_api import start_server; start_server()"
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    WEB_SERVICE_FILE.write_text(unit)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "--now", "vless-web"], check=False, quiet=True)

    return cfg


def uninstall_web_service() -> None:
    """Останавливает и удаляет systemd-сервис."""
    core = _core_module()
    _run = core._run
    _run(["systemctl", "disable", "--now", "vless-web"], check=False, quiet=True)
    WEB_SERVICE_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    cfg = _web_config_load()
    cfg["enabled"] = False
    _web_config_save(cfg)


def is_web_running() -> bool:
    """Проверяет, запущен ли сервис."""
    core = _core_module()
    r = core._run(["systemctl", "is-active", "vless-web"], capture=True, check=False)
    return r.returncode == 0


# ============================================================================
#  МЕНЮ УПРАВЛЕНИЯ
# ============================================================================

def do_manage_web_panel() -> None:
    """Меню управления веб-панелью."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_ok = core._box_ok
    _box_warn = core._box_warn
    _box_info = core._box_info
    info = core.info
    warn = core.warn
    success = core.success
    CYAN, NC, GREEN, YELLOW, RED, BLUE, BOLD, DIM = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.RED, core.BLUE,
        core.BOLD, core.DIM
    )

    import builtins
    _input = builtins.input

    while True:
        import os as _os
        _os.system("clear")
        print()
        _box_top("🌐  Веб-панель управления")

        cfg = _web_config_load()
        running = is_web_running()
        port = cfg.get("port", DEFAULT_WEB_PORT)
        admin_user = cfg.get("admin_user", "admin")
        host = cfg.get("host", DEFAULT_WEB_HOST)
        exposed = (host == "0.0.0.0")
        # Проверяем — установлен ли systemd-unit веб-панели.
        # Если нет (например, после fresh install без вызова install_web_service),
        # "Запустить сервис" молча ничего не делает. В этом случае пункт 1
        # меняется на "Установить веб-панель" — логичнее, чем неработающий старт.
        _installed = WEB_SERVICE_FILE.exists()

        if not _installed:
            _box_row(f"  {YELLOW}⚠️  Веб-панель НЕ установлена!{NC}")
            _box_row(f"  {DIM}Используйте пункт 1 для установки.{NC}")
            _box_row()

        _box_row(f"  Сервис:       {GREEN+'активен'+NC if running else YELLOW+'остановлен'+NC}")
        _box_row(f"  Хост:         {CYAN}{host}{NC} {YELLOW+'(открыто наружу, без TLS!)'+NC if exposed else '(локально, SSH-туннель)'}")
        _box_row(f"  Порт:         {CYAN}{port}{NC}")
        _box_row(f"  Admin:        {CYAN}http://<IP>:{port}/admin/{NC}")
        _box_row(f"  Portal:       {CYAN}http://<IP>:{port}/portal/{NC}")
        _box_row(f"  Admin логин:  {CYAN}{admin_user}{NC}")

        # IP адреса
        try:
            ipv4 = core.get_server_ip("4")
            if ipv4:
                _box_row(f"  IPv4:         {CYAN}{ipv4}{NC}")
        except Exception:
            pass

        _box_sep()
        if not _installed:
            _box_item("1", "Установить веб-панель")
        else:
            _box_item("1", f"{'Остановить' if running else 'Запустить'} сервис")
        _box_item("2", "Изменить порт")
        _box_item("3", "Изменить admin-пароль")
        _box_item("4", "Переустановить (сброс конфига)")
        _box_item("5", f"{'Закрыть доступ снаружи' if exposed else 'Открыть доступ снаружи (ВНИМАНИЕ: без TLS!)'}")
        _box_item("Q", "Назад")
        _box_bottom()

        try:
            ch = _input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if ch == "1":
            if not _installed:
                # Установка веб-панели: создаёт web_config.json, systemd-unit,
                # запускает сервис. Пароль генерируется и показывается ОДИН раз.
                info("Установка веб-панели...")
                cfg = install_web_service()
                success(f"Веб-панель установлена. Порт: {cfg['port']}, логин: {cfg['admin_user']}")
                _box_row(f"  {YELLOW}Пароль: {cfg['admin_pass']}{NC}")
                warn("  ⚠️  Сохраните пароль — он показан только один раз!")
                _box_row(f"  {DIM}Доступ через SSH-туннель: ssh -L {cfg['port']}:127.0.0.1:{cfg['port']} user@<server>{NC}")
            elif running:
                core._run(["systemctl", "stop", "vless-web"], check=False, quiet=True)
                success("Сервис остановлен")
            else:
                core._run(["systemctl", "start", "vless-web"], check=False, quiet=True)
                success("Сервис запущен")
            _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            raw = _input(f"  Новый порт [{port}]: ").strip()
            if raw.isdigit() and 1024 <= int(raw) <= 65535:
                new_port = int(raw)
                cfg["port"] = new_port
                _web_config_save(cfg)
                # Переустанавливаем сервис с новым портом
                install_web_service(port=new_port)
                success(f"Порт изменён на {new_port}, сервис перезапущен")
            else:
                warn("Некорректный порт")
            _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            new_pass = _input("  Новый admin-пароль: ").strip()
            if len(new_pass) >= 8:
                cfg["admin_pass"] = new_pass
                _web_config_save(cfg)
                success("Пароль изменён")
            else:
                warn("Минимум 8 символов")
            _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            confirm = _input(f"  {RED}Переустановить? (сброс пароля/порта) [y/N]:{NC} ").strip().lower()
            if confirm == "y":
                cfg = _web_config_init(
                    port=DEFAULT_WEB_PORT,
                    admin_user="admin",
                    admin_pass=secrets.token_urlsafe(16)
                )
                install_web_service(port=cfg["port"])
                success(f"Переустановлено. Порт: {cfg['port']}, логин: admin")
                _box_row(f"  {YELLOW}Новый пароль: {cfg['admin_pass']}{NC}")
            _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            # Переключатель: 127.0.0.1 (по умолчанию, доступ через SSH-туннель)
            # ↔ 0.0.0.0 (открыто наружу, БЕЗ TLS — осознанный риск администратора).
            if exposed:
                confirm = _input(
                    f"  Закрыть доступ снаружи (только 127.0.0.1)? [y/N]: "
                ).strip().lower()
                if confirm == "y":
                    install_web_service(port=cfg["port"], expose=False)
                    success("Доступ закрыт. Только 127.0.0.1 (SSH-туннель).")
            else:
                warn("  ВНИМАНИЕ: HTTP без TLS! Basic Auth = base64, НЕ шифрование.")
                warn("  Любой, кто перехватит трафик, увидит пароль в открытом виде.")
                warn("  Рекомендуется reverse-proxy (nginx) с TLS вместо прямого открытия.")
                confirm = _input(
                    f"  {RED}Открыть панель наружу (0.0.0.0:{port})? [y/N]:{NC} "
                ).strip().lower()
                if confirm == "y":
                    install_web_service(port=cfg["port"], expose=True)
                    success(f"Открыто на 0.0.0.0:{port} (без TLS!)")
            _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
