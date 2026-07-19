"""
chimera/modules/rest_api.py
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
    POST   /api/users/{email}/password — задать пароль портала
    POST   /api/users/{email}/toggle   — заблокировать/разблокировать
    POST   /api/users/{email}/rename   — переименовать (login портала)
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
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


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


def _sync_users_from_config() -> int:
    """Синхронизирует users.json с config.json Xray.

    Проблема: при первичной установке юзер создаётся только в config.json
    (через _users_apply_to_config), минуя users.json. Когда admin panel
    создаёт нового юзера через _save_users() + _users_apply_to_config(),
    старый юзер (которого нет в users.json) затирается в config.json.

    Фикс: перед созданием нового юзера подтянуть существующих клиентов из
    config.json в users.json (если их там нет). portal_password для
    импортированных юзеров пустой — они должны установить его через админку
    или скрипт (uuid-fallback убран в security-фиксе).

    Возвращает количество добавленных юзеров (0 если ничего не изменилось).
    """
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    cfg_path = CONFIG_DIR / "config.json"
    if not cfg_path.exists():
        return 0
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        return 0
    # Собираем всех clients из всех VLESS inbounds
    config_clients = []
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") == "vless":
            for c in inb.get("settings", {}).get("clients", []):
                cid = c.get("id", "")
                if cid and cid != "00000000-0000-0000-0000-000000000000":
                    config_clients.append({
                        "uuid": cid,
                        "email": c.get("email", ""),
                    })
    if not config_clients:
        return 0
    # Читаем текущий users.json
    users = _get_users()
    existing_uuids = {u.get("uuid", "") for u in users}
    # Дата изменения config.json — приблизительная дата создания юзера
    # (для юзеров, созданных при установке — реальная дата неизвестна).
    try:
        import time as _time
        _created_ts = _time.time()
        try:
            _created_ts = cfg_path.stat().st_mtime
        except Exception:
            pass
        from datetime import datetime as _dt
        _created_iso = _dt.fromtimestamp(_created_ts).isoformat()
    except Exception:
        _created_iso = ""
    # Добавляем тех, кого нет в users.json
    added = 0
    for c in config_clients:
        if c["uuid"] not in existing_uuids:
            email = c.get("email", "") or f"user-{c['uuid'][:8]}"
            users.append({
                "uuid": c["uuid"],
                "email": email,
                "name": email.split("@")[0] if "@" in email else email,
                "portal_password": "",  # пустой — юзер должен установить
                "created": _created_iso,
            })
            existing_uuids.add(c["uuid"])
            added += 1
    if added:
        _save_users(users)
        print(f"[VLESS Web] Синхронизация: добавлено {added} юзеров из config.json в users.json")
    return added


# ── Обобщённая автосинхронизация VLESS → независимые протоколы ──────────────
#
# Реестр протоколов, которые участвуют в автосинхронизации. Каждый протокол
# в списке — это полный modulepath к Python-модулю, который экспортирует
# 4 функции контракта:
#   • is_active() -> bool — протокол установлен и активен
#   • ensure_user(name) -> bool — создать аккаунт если нет
#   • remove_user(name) -> bool — удалить аккаунт
#   • rename_user(old, new) -> bool — переименовать с сохранением секрета/порта
#
# Все 4 функции НИКОГДА не бросают исключение наружу — ловят всё внутри
# и возвращают bool. Это позволяет реестру диспетчеризовать вызовы безопасно,
# не падая при сбое одного из протоколов.
#
# Добавление нового протокола в синхронизацию = ОДНА строка в этом списке.
# Не нужно писать новые _<proto>_ensure_user функции в rest_api.py —
# логика инкапсулирована в самом протокол-модуле.
#
# Протоколы в списке:
#   • mtproto (Telemt) — MTProto-прокси, общий [access.users] в /etc/telemt/telemt.toml
#   • snell (Snell v4) — per-user systemd template, /etc/snell/<user>.conf
#
# Внутренняя политика каждого протокола (валидация имён, лимиты портов,
# "нельзя удалить последнего" и т.п.) — полностью инкапсулирована в модуле.
# Реестр про это ничего не знает, он просто вызывает 4 функции контракта.
_SYNCABLE_PROTOCOLS = [
    "chimera.modules.mtproto",
    "chimera.modules.snell",
]


def _sync_dispatch(method: str, *args) -> dict:
    """Вызывает method (ensure_user/remove_user/rename_user) на каждом
    активном syncable-протоколе.

    Возвращает {proto_short_name: bool|None}:
      • True/False — результат вызова method на протоколе
      • None — протокол недоступен (ImportError) или не активен (is_active()
        вернул False), либо method бросил исключение

    None означает "протокол пропущен, не считается ошибкой" — например,
    если Snell не установлен, синхронизация для него просто не делается,
    но Telemt при этом нормально синхронизируется.
    """
    import importlib
    results: dict = {}
    for modpath in _SYNCABLE_PROTOCOLS:
        # proto — короткое имя для ключа в ответе (mtproto, snell).
        proto = modpath.rsplit(".", 1)[-1]
        try:
            mod = importlib.import_module(modpath)
        except Exception:
            # Модуль не импортируется (старая инсталляция без этого протокола,
            # или синтаксическая ошибка после кривого update) — пропускаем.
            results[proto] = None
            continue
        try:
            # is_active() — тоже часть контракта, не бросает исключение.
            if not mod.is_active():
                results[proto] = None
                continue
            fn = getattr(mod, method)
            results[proto] = fn(*args)
        except Exception:
            # Любой сбой внутри method — протокол пропускаем, не роняем
            # всю синхронизацию. Остальные протоколы в реестре продолжают.
            results[proto] = None
    return results


def _sync_ensure_user(name: str) -> dict:
    """Создаёт аккаунт `name` во всех активных syncable-протоколах.

    Возвращает {proto: bool|None}. См. _sync_dispatch для значений.
    """
    return _sync_dispatch("ensure_user", name)


def _sync_remove_user(name: str) -> dict:
    """Удаляет аккаунт `name` во всех активных syncable-протоколах."""
    return _sync_dispatch("remove_user", name)


def _sync_rename_user(old: str, new: str) -> dict:
    """Переименовывает old → new во всех активных syncable-протоколах."""
    return _sync_dispatch("rename_user", old, new)


def _sync_all_from_vless(users: list[dict]) -> dict:
    """Массовая синхронизация: для каждого syncable-протокола вызывает
    ensure_user на всех валидных VLESS-именах.

    Возвращает {proto: {"created": N, "skipped": N}} — статистика по
    каждому протоколу. skipped = сумма всех причин пропуска (невалидное
    имя, нет ресурсов и т.п.) — детализация причин внутри протокола,
    реестр не различает.

    Протоколы, у которых is_active() вернул False — в ответе со значением
    {"created": 0, "skipped": 0} (no-op, не считается ошибкой).
    """
    import importlib
    # Собираем уникальные VLESS-имена (не disabled). Этот шаг общий для
    # всех протоколов — нет смысла дублировать в каждом модуле.
    vless_names: set[str] = set()
    for u in users:
        name = u.get("name", "") or ""
        if not u.get("disabled", False) and name:
            vless_names.add(name)
    stats: dict = {}
    for modpath in _SYNCABLE_PROTOCOLS:
        proto = modpath.rsplit(".", 1)[-1]
        stats[proto] = {"created": 0, "skipped": 0}
        try:
            mod = importlib.import_module(modpath)
        except Exception:
            continue  # протокол недоступен — stats остаётся {0, 0}
        try:
            if not mod.is_active():
                continue  # не активен — no-op
            for name in vless_names:
                ok = mod.ensure_user(name)
                if ok:
                    stats[proto]["created"] += 1
                else:
                    stats[proto]["skipped"] += 1
        except Exception:
            # Любой сбой — протокол пропускаем, не роняем sync.
            continue
    return stats


def _get_user_traffic(email: str) -> dict:
    """Возвращает трафик пользователя (uplink + downlink)."""
    core = _core_module()
    try:
        # Пытаемся через Stats API
        from chimera.modules.traffic_tracking import _query_user_traffic_bytes
        total = _query_user_traffic_bytes(email)
        return {"email": email, "total_bytes": total,
                "total_gb": round(total / 1024**3, 2)}
    except Exception:
        return {"email": email, "total_bytes": 0, "total_gb": 0}


def _get_ttl_info(email: str) -> dict:
    """Возвращает TTL-информацию о пользователе."""
    try:
        from chimera.modules.ttl_users import _ttl_load, _ttl_expires_str, _ttl_is_expired
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

    # ── Tag (после # в URL) ──────────────────────────────────────────────
    # В TUI (_unified_show_links в users_manager.py) тэг формируется как
    # "<флаг страны> <имя юзера>". Web-панель раньше хардкодила "VLESS-Reality"
    # / "VLESS-xHTTP" — без флага и без имени юзера. Это было неудобно: в
    # клиенте (v2rayN, NekoBox, и т.п.) несколько узлов отображались как
    # одинаковые "VLESS Reality", без возможности отличить.
    #
    # Теперь web-панель использует тот же формат что и TUI:
    #   "<флаг> <имя_юзера>"  (если флаг есть и не "🌐")
    #   "<имя_юзера>"         (если флаг недоступен)
    # Имя юзера берётся из user["name"], fallback на email, потом на "user".
    # Это совпадает с TUI-логикой в _unified_show_links().
    #
    # Флаг страны кешируется через get_server_country_cached() — один curl
    # к ip-api.com за всё время работы процесса. Если ip-api недоступен —
    # возвращается "🌐", тогда prefix пустой (без флага).
    from urllib.parse import quote as _url_quote
    try:
        _, _, _flag = core.get_server_country_cached()
    except Exception:
        _flag = "🌐"
    _flag_prefix = f"{_flag} " if _flag and _flag != "🌐" else ""
    # label = user name (или email, или "user") — как в TUI.
    _user_label = (user.get("name", "") or user.get("email", "")
                   or "user").replace(" ", "_").replace("/", "_")
    _tag_user = _flag_prefix + _url_quote(_user_label)
    # Для IPv6 добавляем суффикс "IPv6" чтобы отличить от IPv4 в клиенте.
    _tag_user_v6 = _flag_prefix + _url_quote(_user_label + "-IPv6")

    links = []

    # IPv4 / Domain link
    if proto == "reality":
        link = (f"vless://{uuid_val}@{domain}:{port}"
                f"?encryption=none&flow={xtls_flow}"
                f"&security=reality&sni={sni}"
                f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                f"&type=tcp#{_tag_user}")
    else:
        xhttp_path_enc = _url_quote(xhttp_path, safe="")
        link = (f"vless://{uuid_val}@{domain}:{port}"
                f"?encryption=none&security=tls&sni={domain}"
                f"&fp={fp}&type=http&path={xhttp_path_enc}#{_tag_user}")
    links.append({"label": "IPv4 / Domain", "link": link, "protocol": proto})

    # IPv6 link (если доступен)
    ipv6 = state.get("ipv6", "")
    if ipv6:
        if proto == "reality":
            link6 = (f"vless://{uuid_val}@[{ipv6}]:{port}"
                     f"?encryption=none&flow={xtls_flow}"
                     f"&security=reality&sni={sni}"
                     f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                     f"&type=tcp#{_tag_user_v6}")
        else:
            xhttp_path_enc = _url_quote(xhttp_path, safe="")
            link6 = (f"vless://{uuid_val}@[{ipv6}]:{port}"
                     f"?encryption=none&security=tls&sni={domain}"
                     f"&fp={fp}&type=http&path={xhttp_path_enc}#{_tag_user_v6}")
        links.append({"label": "IPv6", "link": link6, "protocol": proto})

    # Hysteria2 (если включён И реально настроен И сервис активен)
    # Проверяем не только флаг h2_exit_enabled, но и:
    #   1. Наличие h2_password/host — иначе генерируется кастрированная ссылка
    #      hysteria2://@:443 без пароля.
    #   2. Что H2-сервис реально запущен (systemctl is-active) — чтобы не
    #      отдавать ссылки на несуществующие сервисы.
    if state.get("h2_exit_enabled", False):
        h2_host = state.get("h2_exit_host", "") or state.get("awg_exit_host", "")
        h2_port = state.get("h2_port", 443)
        h2_pass = state.get("h2_password", "")
        # Проверяем что H2-сервис активен на entry-сервере.
        _h2_active = False
        try:
            core = _core_module()
            r = core._run(["systemctl", "is-active", "hysteria-server"],
                          capture=True, check=False)
            _h2_active = (r.returncode == 0 and r.stdout.strip() == "active")
        except Exception:
            pass
        # Только если есть host+password И сервис активен — иначе ссылка битая.
        if h2_host and h2_pass and _h2_active:
            h2_link = f"hysteria2://{h2_pass}@{h2_host}:{h2_port}?insecure=1&sni={domain}#Hysteria2"
            links.append({"label": "Hysteria2", "link": h2_link, "protocol": "hysteria2"})

    # MTProto (Telemt) — персональная ссылка для юзера портала.
    #
    # Корневая причина прошлой реализации: код обращался к _load_state и файлу
    # /var/lib/xray-installer/mtproto_state.json, которых не существует в
    # chimera/modules/mtproto.py (модуль Telemt хранит конфиг иначе — см. ниже).
    # Из-за `except Exception: pass` импорт падал молча, и ссылка просто не
    # появлялась в /api/portal/links без ошибок в логах.
    #
    # Реальная структура конфига Telemt (см. chimera/modules/mtproto.py):
    #   • CONFIG_FILE = /etc/telemt/telemt.toml
    #   • [server].port                 → _get_port()
    #   • [censorship].tls_domain       → _get_domain()
    #     (если непустой — TLS-режим; секрет обёрнут через _make_tls_secret)
    #   • [access.users]: name = "hex32" → _load_users() dict {имя: secret}
    #
    # Логика:
    #   1. Сервис telemt должен быть активен (systemctl is-active telemt) —
    #      по аналогии с проверкой hysteria-server выше. Иначе не отдаём
    #      ссылку на неработающий сервис.
    #   2. Ссылка персональная: сопоставляем user["name"] / user["email"] /
    #      локальную часть email с ключом в _load_users(). Если совпадения
    #      нет — не показываем ссылку (не отдаём чужой/первый-попавшийся секрет).
    #   3. TLS-режим (tls_domain непустой) → секрет через _make_tls_secret
    #      (формат "ee<secret_hex><tls_domain_hex>"). Иначе — голый секрет.
    try:
        from chimera.modules.mtproto import (
            _load_users as _telemt_load_users,
            _get_port as _telemt_get_port,
            _get_domain as _telemt_get_domain,
            _make_tls_secret as _telemt_make_tls_secret,
            SERVICE_NAME as _TELEMT_SERVICE_NAME,
        )
        # 1) Проверяем что служба telemt активна.
        _telemt_active = False
        try:
            core = _core_module()
            r = core._run(["systemctl", "is-active", _TELEMT_SERVICE_NAME],
                          capture=True, check=False)
            _telemt_active = (r.returncode == 0 and r.stdout.strip() == "active")
        except Exception:
            pass
        # 2) Только если сервис активен — ищем персональный секрет юзера.
        if _telemt_active:
            telemt_users = _telemt_load_users() or {}
            user_name = user.get("name", "") or ""
            user_email = user.get("email", "") or ""
            # email часто имеет вид "user@domain" — пробуем и локальную часть
            # как fallback, потому что в Telemt имена пользователей это обычно
            # короткие логины без @ (см. _validate_username в mtproto.py).
            user_email_local = user_email.split("@", 1)[0] if user_email else ""
            mt_secret_raw = ""
            if user_name and user_name in telemt_users:
                mt_secret_raw = telemt_users[user_name]
            elif user_email and user_email in telemt_users:
                mt_secret_raw = telemt_users[user_email]
            elif user_email_local and user_email_local in telemt_users:
                mt_secret_raw = telemt_users[user_email_local]
            # 3) Секрет найден — собираем ссылку (с учётом TLS-режима).
            if mt_secret_raw:
                mt_port = _telemt_get_port()
                mt_tls_domain = _telemt_get_domain()
                if mt_tls_domain:
                    mt_secret = _telemt_make_tls_secret(mt_secret_raw, mt_tls_domain)
                else:
                    mt_secret = mt_secret_raw
                mt_link = (f"https://t.me/proxy?server={domain}"
                           f"&port={mt_port}&secret={mt_secret}")
                links.append({"label": "MTProto", "link": mt_link,
                              "protocol": "mtproto"})
    except Exception:
        pass

    # Snell v4 (если установлен и есть активный инстанс для этого юзера).
    # Per-user модель: каждый юзер имеет свой порт+PSK, ссылка генерируется
    # только если snell-server@<user> активен. Сопоставление по user["name"]
    # / email / email-local-part (как в MTProto-блоке выше).
    try:
        from chimera.modules.snell import (
            get_user_link as _snell_get_user_link,
            is_any_active as _snell_is_any_active,
        )
        if _snell_is_any_active():
            # Сопоставление: пробуем user["name"], user["email"], локальную
            # часть email — Snell-юзеры имеют имена в формате [a-zA-Z][a-zA-Z0-9_-]{2,15}.
            user_name = user.get("name", "") or ""
            user_email = user.get("email", "") or ""
            user_email_local = user_email.split("@", 1)[0] if user_email else ""
            snell_link = None
            for candidate in (user_name, user_email, user_email_local):
                if candidate:
                    snell_link = _snell_get_user_link(candidate, server_ip=domain)
                    if snell_link:
                        break
            if snell_link:
                links.append({"label": "Snell v4", "link": snell_link,
                              "protocol": "snell"})
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

    # Snell v4 — добавляем как альтернативный proxy если установлен и
    # есть активный инстанс для этого юзера. Per-user matching по name/email.
    snell_proxy_yaml = ""
    snell_name = ""
    try:
        from chimera.modules.snell import (
            get_user_clash_proxy as _snell_get_clash_proxy,
            is_any_active as _snell_is_any_active,
        )
        if _snell_is_any_active():
            user_name = user.get("name", "") or ""
            user_email = user.get("email", "") or ""
            user_email_local = user_email.split("@", 1)[0] if user_email else ""
            for candidate in (user_name, user_email, user_email_local):
                if candidate:
                    px = _snell_get_clash_proxy(candidate, server_ip=domain)
                    if px:
                        snell_name = px.get("name", "Snell")
                        obfs = px.get("obfs-opts", {})
                        obfs_mode = obfs.get("mode", "off")
                        obfs_host = obfs.get("host", "")
                        # Ручная YAML-сериализация (без привлечения yaml-модуля).
                        snell_proxy_yaml = (
                            f"  - name: {snell_name}\n"
                            f"    type: snell\n"
                            f"    server: {px['server']}\n"
                            f"    port: {px['port']}\n"
                            f"    psk: {px['psk']}\n"
                            f"    obfs-opts:\n"
                            f"      mode: {obfs_mode}\n"
                        )
                        if obfs_host:
                            snell_proxy_yaml += f"      host: {obfs_host}\n"
                        break
    except Exception:
        pass

    # Имена proxy-узлов в группе — VLESS первым, Snell вторым (если есть).
    group_proxies = ["VLESS-Reality" if proto == "reality" else "VLESS-xHTTP"]
    if snell_proxy_yaml:
        group_proxies.append(snell_name)

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
{snell_proxy_yaml}
proxy-groups:
  - name: Proxy
    type: select
    proxies:
"""
        for p in group_proxies:
            clash += f"      - {p}\n"
        clash += """
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
{snell_proxy_yaml}
proxy-groups:
  - name: Proxy
    type: select
    proxies:
"""
        for p in group_proxies:
            clash += f"      - {p}\n"
        clash += """
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

    # Snell v4 — добавляем как второй outbound если установлен и есть
    # активный инстанс. ВАЖНО: официальный sing-box НЕ поддерживает Snell —
    # outbound работает только в сторонних форках (Dress, sss-box-shadow).
    # Если у юзера официальный sing-box, он увидит в логах unknown outbound
    # type — это нормально, просто игнорируется.
    #
    # Если Snell-outbound реально добавлен — добавляем информационное поле
    # верхнего уровня "_snell_compat_note" с пояснением на русском, чтобы
    # админ/юзер открыв конфиг видел причину "unknown outbound type".
    # Ведущее подчёркивание — чтобы не путать с реальными полями sing-box.
    snell_added = False
    try:
        from chimera.modules.snell import (
            get_user_singbox_outbound as _snell_get_singbox_outbound,
            is_any_active as _snell_is_any_active,
        )
        if _snell_is_any_active():
            user_name = user.get("name", "") or ""
            user_email = user.get("email", "") or ""
            user_email_local = user_email.split("@", 1)[0] if user_email else ""
            for candidate in (user_name, user_email, user_email_local):
                if candidate:
                    ob = _snell_get_singbox_outbound(candidate, server_ip=domain)
                    if ob:
                        config["outbounds"].append(ob)
                        snell_added = True
                        break
    except Exception:
        pass

    # Информационное поле о совместимости Snell — только если Snell-outbound
    # реально попал в конфиг. На официальном sing-box этот outbound будет
    # молча проигнорирован ("unknown outbound type" в логах), но остальные
    # outbounds/конфиг работать продолжат. Пользователям официального
    # sing-box следует использовать Clash Meta или snell:// ссылку напрямую.
    if snell_added:
        config["_snell_compat_note"] = (
            "Внимание: outbound с type=snell в этом конфиге совместим только "
            "со сторонними форками sing-box (Dress, sss-box-shadow и подобные), "
            "имеющими патч поддержки протокола Snell v4. Официальная сборка "
            "sing-box не поддерживает Snell как нативный outbound и молча "
            "проигнорирует его (в логах — 'unknown outbound type'), при этом "
            "остальные outbounds (VLESS/Reality/xHTTP) продолжат работать "
            "без изменений. Если вы используете официальный sing-box — "
            "импортируйте Snell через snell:// ссылку (раздел «Подключение» "
            "на главной странице портала) или используйте Clash Meta конфиг "
            "из этого же раздела «Скачать конфиги»."
        )

    return json.dumps(config, indent=2, ensure_ascii=False)


def _generate_hiddify_config(user: dict) -> str:
    """Генерирует Hiddify JSON конфиг для пользователя.

    Hiddify (https://github.com/hiddify/hiddify-app) — популярный
    мультиплатформенный клиент. Импортирует VLESS-ссылку, но полнофункциональный
    конфиг удобнее — включает все параметры REALITY одним файлом.
    Формат: JSON с outbound (VLESS + REALITY), как в sing-box, но с
    дополнительными полями для Hiddify-совместимости.
    """
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

    # SNI: Mode B + AWG → reality_dest, else domain (как в _generate_vless_links)
    install_mode = state.get("install_mode", "A")
    awg_exit = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    if proto == "reality" and awg_exit and reality_dest:
        sni = reality_dest
    elif proto == "reality":
        sni = domain

    if proto == "reality":
        config = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": uuid_val,
                "flow": xtls_flow,
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
            }],
            "routing": {
                "rules": [
                    {"type": "default", "outbound": "vless-out"}
                ]
            }
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
            }],
            "routing": {
                "rules": [
                    {"type": "default", "outbound": "vless-out"}
                ]
            }
        }
    return json.dumps(config, indent=2, ensure_ascii=False)


def _generate_vless_link_plain(user: dict) -> str:
    """Возвращает VLESS-ссылку как plain text (для скачивания файлом).

    Многие юзеры не понимают что длинная ссылка в QR — это и есть конфиг.
    Скачать файлом с понятным именем (vless-link.txt) проще.
    Берёт первую ссылку из _generate_vless_links (IPv4/Domain).
    """
    links = _generate_vless_links(user)
    if not links:
        return ""
    return links[0]["link"]


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
            from chimera.modules.admin_panel import get_admin_html
            self._send_html(get_admin_html())
            return

        # User Portal HTML
        if path == "/portal" or path == "/portal/":
            user = self._require_user()
            if user is None:
                return
            from chimera.modules.user_portal import get_portal_html
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
                from chimera.modules.geoip_block import _geoip_block_get_rules
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

        # ── User Portal API (GET) ──────────────────────────────────────────────
        # links / traffic / health / clash / singbox — это GET-запросы (browser
        # шлёт fetch(path) без method). password — POST (меняет состояние).
        # Раньше все portal endpoints были в do_POST — это баг, browser получал
        # 404 на каждый GET-запрос из user_portal.js.

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

        if path == "/api/portal/hiddify":
            user = self._require_user()
            if user is None:
                return
            hiddify = _generate_hiddify_config(user)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="hiddify.json"')
            self.send_header("Content-Length", str(len(hiddify.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(hiddify.encode("utf-8"))
            return

        if path == "/api/portal/vless-link":
            user = self._require_user()
            if user is None:
                return
            vless_link = _generate_vless_link_plain(user)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="vless-link.txt"')
            self.send_header("Content-Length", str(len(vless_link.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(vless_link.encode("utf-8"))
            return

        # ── AmneziaWG standalone API (/api/awg/*) ─────────────────────────────
        # Делегирует в awg_rest_api.py. Авторизация проверяется внутри хендлеров
        # (admin endpoints → _require_admin, user endpoints → _require_user).
        # Все /api/awg/* отдают 404 если AWG не установлен (не 500).
        if path.startswith("/api/awg/"):
            from chimera.modules import awg_rest_api
            parsed_query = parse_qs(parsed.query)
            handled = awg_rest_api.awg_handle_get(self, path, parsed_query)
            if handled:
                return
            # если не обработано — fall through к 404

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
            # Синхронизируем users.json с config.json — подтягиваем юзеров, которые
            # были созданы при установке (только в config.json), чтобы не затереть
            # их при _users_apply_to_config() ниже.
            _sync_users_from_config()
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

            # Автосинхронизация со всеми syncable-протоколами (Telemt,
            # Snell, и любые будущие через реестр _SYNCABLE_PROTOCOLS).
            # Создаёт аккаунт с тем же name в каждом активном протоколе,
            # чтобы соответствующая ссылка появилась в User Portal без
            # ручного шага в TUI. Возвращает {proto: bool|None}.
            protocol_sync = _sync_ensure_user(name)

            self._send_json({
                "status": "created",
                "uuid": new_uuid,
                "email": email,
                "portal_login": name or email,
                "portal_password": portal_password,
                "protocol_sync": protocol_sync,
            }, 201)
            return

        # POST /api/users/{email}/password — админ задаёт portal_password юзеру
        # (нужно для юзеров, созданных при установке — у них portal_password пустой).
        m = re.match(r"^/api/users/(.+)/password$", path)
        if m:
            if not self._require_admin():
                return
            email = unquote(m.group(1))
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            new_pass = body.get("new_password", "").strip()
            if len(new_pass) < 8:
                self._send_json({"error": "Пароль минимум 8 символов"}, 400)
                return
            users = _get_users()
            for u in users:
                if u.get("email") == email:
                    u["portal_password"] = new_pass
                    _save_users(users)
                    self._send_json({"status": "changed", "email": email})
                    return
            self._send_json({"error": "user not found"}, 404)
            return

        # POST /api/users/{email}/toggle — заблокировать/разблокировать юзера.
        # Блокировка = disabled=True → юзер убирается из config.json (не может
        # подключиться). Разблокировка = disabled=False → юзер возвращается.
        m = re.match(r"^/api/users/(.+)/toggle$", path)
        if m:
            if not self._require_admin():
                return
            email = unquote(m.group(1))
            users = _get_users()
            for u in users:
                if u.get("email") == email:
                    u["disabled"] = not u.get("disabled", False)
                    if u["disabled"]:
                        from datetime import datetime as _dt
                        u["disabled_at"] = _dt.now().isoformat()
                    else:
                        u.pop("disabled_at", None)
                    _save_users(users)
                    # Применяем к config.json — отключённые убираются из clients
                    try:
                        core = _core_module()
                        core._users_apply_to_config(users)
                    except Exception:
                        pass
                    _new_state = "disabled" if u["disabled"] else "enabled"
                    self._send_json({"status": _new_state, "email": email})
                    return
            self._send_json({"error": "user not found"}, 404)
            return

        # POST /api/users/{email}/rename — переименовать юзера (изменить name,
        # login для портала). Email остаётся прежним — он используется как
        # ключ в users.json и как clients[].email в config.json Xray.
        # Backend дополнительно синхронизирует все syncable-протоколы через
        # _sync_rename_user() — каждый протокол переименовывает аккаунт с
        # сохранением своих данных (Telemt — секрет, Snell — PSK+порт).
        m = re.match(r"^/api/users/(.+)/rename$", path)
        if m:
            if not self._require_admin():
                return
            email = unquote(m.group(1))
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            new_name = (body.get("new_name", "") or "").strip()
            if not new_name:
                self._send_json({"error": "new_name required"}, 400)
                return
            if len(new_name) < 3 or len(new_name) > 32:
                self._send_json({"error": "Имя должно быть 3-32 символа"}, 400)
                return
            users = _get_users()
            target = None
            for u in users:
                if u.get("email") == email:
                    target = u
                    break
            if target is None:
                self._send_json({"error": "user not found"}, 404)
                return
            old_name = target.get("name", "") or target.get("email", "").split("@")[0]
            target["name"] = new_name
            _save_users(users)
            # config.json Xray не нужно трогать — там используется email,
            # а не name. _users_apply_to_config не требуется.
            # Автосинхронизация со всеми syncable-протоколами (Telemt, Snell,
            # и любые будущие через реестр _SYNCABLE_PROTOCOLS). Каждый
            # протокол переименовывает аккаунт с сохранением своих данных
            # (Telemt — секрет, Snell — PSK+порт). Если протокол не активен
            # или имя не подходит под его спеку — это не ошибка, VLESS всё
            # равно переименован. Возвращаем protocol_sync = {proto: bool|None}
            # для информативного toast в админ-панели.
            protocol_sync = _sync_rename_user(old_name, new_name)
            self._send_json({
                "status": "renamed",
                "email": email,
                "old_name": old_name,
                "new_name": new_name,
                "protocol_sync": protocol_sync,
            })
            return

        if path == "/api/rotate/uuid":
            if not self._require_admin():
                return
            try:
                from chimera.modules.credential_rotation import _uuid_rotate_now
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
                from chimera.modules.credential_rotation import _rotate_reality_keys
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
                from chimera.modules.geoip_block import (
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
                from chimera.modules.backup_rollback import create_backup
                create_backup()
                self._send_json({"status": "backup_created"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/users/sync — синхронизация users.json с config.json Xray.
        # Подтягивает юзеров, созданных через TUI (они есть в config.json,
        # но отсутствуют в users.json) в users.json. Нужно чтобы:
        #   1. Эти юзеры появились в списке админ-панели
        #   2. Им можно было задать portal_password (для входа в User Portal)
        #   3. При следующем создании юзера через админку они не затёрлись
        #      (раньше _save_users затирал config.json clients, потеря TUI-юзеров)
        if path == "/api/users/sync":
            if not self._require_admin():
                return
            try:
                added = _sync_users_from_config()
                # Полная синхронизация VLESS → все syncable-протоколы
                # (Telemt, Snell, и любые будущие через реестр
                # _SYNCABLE_PROTOCOLS). Создаёт недостающие аккаунты для
                # всех валидных VLESS-имён, чтобы соответствующие ссылки
                # появились в User Portal для всех сразу.
                # Возвращает {proto: {"created": N, "skipped": N}}.
                protocol_stats = _sync_all_from_vless(_get_users())
                msg_parts = []
                if added:
                    msg_parts.append(f"Синхронизировано {added} новых юзеров из config.json")
                else:
                    msg_parts.append("Новых юзеров в config.json не найдено — users.json уже актуален")
                # Перебираем все протоколы из реестра — фронт не хардкодит
                # конкретные имена, формирует текст toast универсально.
                for proto, st in protocol_stats.items():
                    created = st.get("created", 0)
                    skipped = st.get("skipped", 0)
                    if created:
                        msg_parts.append(f"создано {created} {proto}-аккаунтов")
                    if skipped:
                        msg_parts.append(f"{skipped} имён не подходят для {proto} (нужен формат [a-zA-Z][a-zA-Z0-9_-]{{2,15}} или нет ресурсов)")
                self._send_json({
                    "status": "synced",
                    "added": added,
                    "protocol_stats": protocol_stats,
                    "message": "; ".join(msg_parts),
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # ── User Portal API (POST) ─────────────────────────────────────────────
        # Только /api/portal/password — меняет состояние (нужен body).
        # Остальные portal endpoints (links/traffic/health/clash/singbox) — GET,
        # см. do_GET выше. Раньше они были тут (в do_POST) — это был баг.

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

        # ── AmneziaWG standalone API — POST ───────────────────────────────────
        if path.startswith("/api/awg/"):
            from chimera.modules import awg_rest_api
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            handled = awg_rest_api.awg_handle_post(self, path, body)
            if handled:
                return
            # если не обработано — fall through к 404

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
            # Ищем удаляемого юзера ДО того как отфильтруем список —
            # нужно знать его name для синхронизации с Telemt.
            deleted_user = None
            for u in users:
                if u.get("email") == email:
                    deleted_user = u
                    break
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
            # Автосинхронизация со всеми syncable-протоколами (Telemt,
            # Snell, и любые будущие через реестр _SYNCABLE_PROTOCOLS).
            # Удаляет аккаунт в каждом активном протоколе, чтобы не
            # оставлять "висящие" аккаунты для удалённого VLESS-юзера.
            # Возвращает {proto: bool|None}.
            protocol_sync = {}
            if deleted_user is not None:
                protocol_sync = _sync_remove_user(
                    deleted_user.get("name", "") or
                    deleted_user.get("email", "").split("@")[0]
                )
            self._send_json({
                "status": "deleted", "email": email,
                "protocol_sync": protocol_sync,
            })
            return

        # DELETE /api/geoip/rules
        if path == "/api/geoip/rules":
            if not self._require_admin():
                return
            try:
                from chimera.modules.geoip_block import _geoip_remove_all
                _geoip_remove_all()
                self._send_json({"status": "all_rules_removed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # ── AmneziaWG standalone API — DELETE ─────────────────────────────────
        if path.startswith("/api/awg/"):
            from chimera.modules import awg_rest_api
            handled = awg_rest_api.awg_handle_delete(self, path)
            if handled:
                return
            # если не обработано — fall through к 404

        self._send_404()

    def do_PATCH(self):
        """PATCH — частичное обновление ресурса (RFC 5789).
        Используется для /api/awg/peers/{name} (изменение параметров пира).
        Делегирует в awg_rest_api.py."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # ── AmneziaWG standalone API — PATCH ──────────────────────────────────
        if path.startswith("/api/awg/"):
            from chimera.modules import awg_rest_api
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            handled = awg_rest_api.awg_handle_patch(self, path, body)
            if handled:
                return
            # если не обработано — fall through к 404

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
    main_py = Path(sys.argv[0]).resolve() if sys.argv[0] else Path("/opt/chimera/main.py")
    project_root = main_py.parent

    unit = f"""[Unit]
Description=VLESS Ultimate Web Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "from chimera.modules.rest_api import start_server; start_server()"
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
