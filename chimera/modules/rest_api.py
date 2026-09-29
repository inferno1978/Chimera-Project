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
#
# Внутренняя политика каждого протокола (валидация имён, лимиты портов,
# "нельзя удалить последнего" и т.п.) — полностью инкапсулирована в модуле.
# Реестр про это ничего не знает, он просто вызывает 4 функции контракта.
#
# КОНТРАКТ модуля (каждый syncable-протокол экспортирует):
#   is_active() -> bool
#       True если сервис установлен И запущен (systemctl is-active == active).
#       Синхронизация пропускается если False.
#
#   ensure_user(name: str) -> bool           # legacy contract — только name
#   ensure_user_full(user: dict) -> bool     # extended contract — full user dict
#       Создаёт аккаунт. Если есть ensure_user_full — dispatcher предпочитает её
#       (даёт доступ к email, uuid, device_label — нужно для trusttunnel/singbox).
#       Возвращает True если создан или уже существует. Никогда не бросает исключение.
#
#   remove_user(name: str) -> bool
#   remove_user_full(user: dict) -> bool     # extended
#       Аналогично — удаляет аккаунт.
#
#   rename_user(old: str, new: str) -> bool
#   rename_user_full(old_user: dict, new_user: dict) -> bool   # extended
#       Переименовывает. Legacy: только имена. Extended: full dicts.
#
# Идемпотентность: все функции безопасны при повторном вызове (no-op если
# уже в нужном состоянии). Это позволяет вызывать sync при каждом install/
# add/remove без побочных эффектов.
#
# Текущий реестр (v4.25): все 9 спутниковых протоколов —
#   • mtproto (Telemt) — MTProto-прокси, [access.users] в /etc/telemt/telemt.toml
#   • naiveproxy       — Caddy + forwardproxy-naive, /var/lib/xray-installer/naiveproxy.json
#   • mieru            — mita server, /var/lib/xray-installer/mieru.json
#   • trusttunnel      — AdGuard VPN ref impl, /opt/trusttunnel/credentials.toml
#   • singbox          — sing-box inbounds (ShadowTLS/AnyTLS/TUIC/Trojan), singbox_state.json
#   • wdtt             — qWDTT WireGuard-over-TURN, /etc/wdtt/passwords.json (парольная модель)
#   • fptn             — FPTN server, /etc/fptn/users.list
#   • awg_peers        — AmneziaWG standalone, /var/lib/xray-installer/awg_standalone_state.json
#   • hysteria2_sync   — Hysteria2 transport (shared password, NO per-user)
#
# VLESS НЕ в реестре (это canonical source, не satellite — синхронизация
# идёт ОТ него, не К нему). Hysteria2 — shared-password модель, контракт
# NO-OP (см. chimera/modules/hysteria2_sync.py).
_SYNCABLE_PROTOCOLS = [
    "chimera.modules.mtproto",
    "chimera.modules.naiveproxy",
    "chimera.modules.mieru",
    "chimera.modules.trusttunnel",
    "chimera.modules.singbox_users",
    "chimera.modules.wdtt",
    "chimera.modules.fptn",
    "chimera.modules.csqtt",
    "chimera.modules.awg_peers",
    "chimera.modules.hysteria2_sync",
]


def _sync_dispatch(method: str, *args, user: dict = None) -> dict:
    """Вызывает method (ensure_user/remove_user/rename_user) на каждом
    активном syncable-протоколе.

    Если передан `user` (dict с email, uuid, name, device_label) —
    dispatcher предпочитает `{method}_full(user)` если модуль её экспортирует
    (extended contract — нужен для trusttunnel/singbox которые требуют UUID).
    Иначе fallback на legacy `{method}(*args)` (только name).

    Возвращает {proto_short_name: bool|None}:
      • True/False — результат вызова method на протоколе
      • None — протокол недоступен (ImportError) или не активен (is_active()
        вернул False), либо method бросил исключение

    None означает "протокол пропущен, не считается ошибкой" — например,
    если протокол не установлен, синхронизация для него просто не делается,
    но Telemt при этом нормально синхронизируется.
    """
    import importlib
    results: dict = {}
    for modpath in _SYNCABLE_PROTOCOLS:
        # proto — короткое имя для ключа в ответе (mtproto, naiveproxy, etc).
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
            # Если передан full user dict и модуль поддерживает extended contract —
            # предпочитаем _full вариант (доступ к email/uuid/device_label).
            if user is not None:
                full_method = f"{method}_full"
                fn = getattr(mod, full_method, None)
                if fn is not None:
                    results[proto] = fn(user)
                    continue
            # Fallback: legacy contract — method(*args) только с name.
            fn = getattr(mod, method)
            results[proto] = fn(*args)
        except Exception:
            # Любой сбой внутри method — протокол пропускаем, не роняем
            # всю синхронизацию. Остальные протоколы в реестре продолжают.
            results[proto] = None
    return results


def _sync_ensure_user(name: str, user: dict = None) -> dict:
    """Создаёт аккаунт `name` во всех активных syncable-протоколах.

    Если передан `user` (dict с email/uuid/name/device_label) — используется
    extended contract (ensure_user_full) для протоколов которым нужен UUID
    (singbox, trusttunnel). Иначе fallback на legacy ensure_user(name).

    Возвращает {proto: bool|None}. См. _sync_dispatch для значений.
    """
    return _sync_dispatch("ensure_user", name, user=user)


def _sync_remove_user(name: str, user: dict = None) -> dict:
    """Удаляет аккаунт `name` во всех активных syncable-протоколах."""
    return _sync_dispatch("remove_user", name, user=user)


def _sync_rename_user(old: str, new: str,
                      old_user: dict = None, new_user: dict = None) -> dict:
    """Переименовывает old → new во всех активных syncable-протоколах.

    Если переданы old_user/new_user dicts — используется extended contract
    (rename_user_full) для протоколов с UUID-зависимостью.
    """
    # Для rename_full передаём пару (old_user, new_user) как один tuple-arg.
    if old_user is not None and new_user is not None:
        return _sync_dispatch("rename_user", old, new,
                              user={"old": old_user, "new": new_user})
    return _sync_dispatch("rename_user", old, new)


def _sync_all_from_vless(users: list[dict]) -> dict:
    """Массовая синхронизация: для каждого syncable-протокола вызывает
    ensure_user_full(user) на всех активных VLESS-пользователях.

    Возвращает {proto: {"created": N, "skipped": N}} — статистика по
    каждому протоколу. skipped = сумма всех причин пропуска (невалидное
    имя, нет ресурсов и т.п.) — детализация причин внутри протокола,
    реестр не различает.

    Протоколы, у которых is_active() вернул False — в ответе со значением
    {"created": 0, "skipped": 0} (no-op, не считается ошибкой).

    v4.25: передаёт ПОЛНЫЙ user dict (с email, uuid, name, device_label)
    вместо просто name. Это позволяет singbox использовать UUID, trusttunnel
    — email+UUID для derive пароля. Legacy fallback на ensure_user(name)
    сохранён для протоколов без _full варианта.
    """
    import importlib
    # Собираем активных VLESS-пользователей (не disabled). Передаём full dict.
    active_users: list[dict] = []
    for u in users:
        if not u.get("disabled", False) and (u.get("name") or u.get("email")):
            active_users.append(u)
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
            # Предпочитаем ensure_user_full если есть, иначе legacy ensure_user(name).
            full_fn = getattr(mod, "ensure_user_full", None)
            legacy_fn = getattr(mod, "ensure_user", None)
            for u in active_users:
                ok = False
                try:
                    if full_fn is not None:
                        ok = bool(full_fn(u))
                    elif legacy_fn is not None:
                        # Legacy: передаём name (или email если name пусто).
                        name = u.get("name") or u.get("email", "")
                        ok = bool(legacy_fn(name))
                except Exception:
                    ok = False
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
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    # SNI: Mode B + AWG → reality_dest, else domain.
    # xhttp_reality использует ключи REALITY — те же правила SNI, что и
    # classic reality (ветка xhttp-reality, план XHTTP_REALITY_PLAN.md).
    install_mode = state.get("install_mode", "A")
    awg_exit = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    if proto in ("reality", "xhttp_reality") and awg_exit and reality_dest:
        sni = reality_dest
    elif proto in ("reality", "xhttp_reality"):
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
    elif proto == "xhttp_reality":
        # xHTTP+REALITY: транспорт xhttp + маскировка REALITY.
        # security=reality (не tls), type=xhttp, БЕЗ flow — xhttp-транспорт
        # не поддерживает xtls-rprx-vision. mode= обязателен: клиентам на
        # xray-core нужен режим транспорта (в старой xhttp-ветке ниже mode
        # не добавляется — там он не обязателен, здесь без него никак).
        xhttp_path_enc = _url_quote(xhttp_path, safe="")
        link = (f"vless://{uuid_val}@{domain}:{port}"
                f"?encryption=none&security=reality&sni={sni}"
                f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                f"&type=xhttp&path={xhttp_path_enc}"
                f"&mode={xhttp_mode}#{_tag_user}")
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
        elif proto == "xhttp_reality":
            # xHTTP+REALITY для IPv6: те же параметры, что и в IPv4-ветке
            # выше (type=xhttp, security=reality, без flow, с mode=).
            xhttp_path_enc = _url_quote(xhttp_path, safe="")
            link6 = (f"vless://{uuid_val}@[{ipv6}]:{port}"
                     f"?encryption=none&security=reality&sni={sni}"
                     f"&fp={fp}&pbk={pub_key}&sid={short_id}"
                     f"&type=xhttp&path={xhttp_path_enc}"
                     f"&mode={xhttp_mode}#{_tag_user_v6}")
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

    return links


def _generate_clash_config(user: dict) -> str:
    """Генерирует Clash Meta YAML для пользователя."""
    links = _generate_vless_links(user)
    if not links:
        return ""

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

    # Имя ноды (proxies + proxy-groups должны совпадать). Для xhttp_reality —
    # имя с суффиксом "-fallback": mihomo не поддерживает xHTTP-транспорт,
    # конфиг ниже — фолбэк на tcp+reality (юзер предупреждён при установке).
    if proto == "reality":
        node_name = "VLESS-Reality"
    elif proto == "xhttp_reality":
        node_name = "VLESS-xHTTP-REALITY-fallback"
    else:
        node_name = "VLESS-xHTTP"
    group_proxies = [node_name]

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
"""
        for p in group_proxies:
            clash += f"      - {p}\n"
        clash += """
rules:
  - MATCH,Proxy
"""
    elif proto == "xhttp_reality":
        # xHTTP+REALITY → mihomo fallback на tcp+reality: mihomo не умеет
        # network:http вместе с reality-opts (юзер предупреждён при установке,
        # что mihomo не поддерживается).
        # support-x25519mlkem768 (внутри reality-opts): Xray-core 26.9.8+
        # требует keyShare X25519MLKEM768 в ClientHello; в mihomo он есть
        # только у HelloChrome_Auto, опция запрещает его вырезание. Поэтому
        # client-fingerprint фиксирован на chrome, а не из state.json
        # (как в reality-ветке client_config_export.py).
        clash = f"""# xHTTP+REALITY node — mihomo fallback to tcp+reality (mihomo не поддерживает xHTTP)
proxies:
  - name: {node_name}
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
      support-x25519mlkem768: true
    client-fingerprint: chrome
    servername: {sni}

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
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    # SNI: Mode B + AWG → reality_dest, else domain (как в
    # _generate_vless_links). xhttp_reality использует ключи REALITY —
    # те же правила SNI, что и classic reality.
    install_mode = state.get("install_mode", "A")
    awg_exit = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    if proto in ("reality", "xhttp_reality") and awg_exit and reality_dest:
        sni = reality_dest
    else:
        sni = domain

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
    elif proto == "xhttp_reality":
        # xHTTP+REALITY: транспорт xhttp (mode+path) + REALITY TLS, БЕЗ flow
        # (xhttp-транспорт не поддерживает xtls-rprx-vision). Старую
        # xhttp-ветку ниже (transport type "http") не трогаем — она для
        # legacy-режима xHTTP+TLS с LE-сертификатом.
        config = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": uuid_val,
                "transport": {
                    "type": "xhttp",
                    "mode": xhttp_mode,
                    "path": xhttp_path,
                },
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

    # singbox_client_rulesets: опциональная инъекция route.rule_set + rules
    # с готовыми .srs-списками для Podkop/OpenWrt (РФ-домены → direct и т.д.).
    # По умолчанию ВЫКЛЮЧЕНО — обратная совместимость 100%.
    # См. chimera/modules/singbox_client_rulesets.py
    try:
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        inject_route_rulesets(config, "vless-out")
    except Exception as _e:
        # Никогда не должен ронять генерацию конфига — фича опциональна.
        # Логируем и продолжаем с config без ruleset'ов.
        try:
            core = _core_module()
            if hasattr(core, "log_to_file"):
                core.log_to_file("WARN", f"singbox_client_rulesets.inject failed: {_e}")
        except Exception:
            pass

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
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    xtls_flow = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"

    # SNI: Mode B + AWG → reality_dest, else domain (как в _generate_vless_links).
    # xhttp_reality использует ключи REALITY — те же правила SNI.
    install_mode = state.get("install_mode", "A")
    awg_exit = state.get("awg_exit_enabled", False) and install_mode == "B"
    reality_dest = state.get("reality_dest", "")
    if proto in ("reality", "xhttp_reality") and awg_exit and reality_dest:
        sni = reality_dest
    elif proto in ("reality", "xhttp_reality"):
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
    elif proto == "xhttp_reality":
        # xHTTP+REALITY: копия структуры reality-ветки (REALITY TLS +
        # routing), но транспорт xhttp (mode+path) и БЕЗ flow — xhttp
        # не поддерживает xtls-rprx-vision.
        config = {
            "outbounds": [{
                "type": "vless",
                "tag": "vless-out",
                "server": domain,
                "server_port": port,
                "uuid": uuid_val,
                "transport": {
                    "type": "xhttp",
                    "mode": xhttp_mode,
                    "path": xhttp_path,
                },
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
        """Возвращает реальный IP клиента.

         изначально возвращал self.client_address[0] напрямую —
        обоснование было «rest_api слушает напрямую (без nginx)».

         nginx_front_portal.py поставил nginx перед User Portal
        с proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for.
        Теперь client_address[0] — это 127.0.0.1 (loopback от nginx),
        а реальный IP клиента — в X-Forwarded-For.

         доверяем X-Forwarded-For, ТОЛЬКО если TCP-соединение
        пришло с loopback (значит — от локально работающего nginx-фронта).
        Если direct_ip НЕ loopback — запрос пришёл напрямую (rest_api
        открыт наружу без nginx, host="0.0.0.0") — тогда X-Forwarded-For
        может быть подделан клиентом, игнорируем заголовок полностью.
        """
        try:
            direct_ip = self.client_address[0] if self.client_address else "?"
        except Exception:
            return "?"

        # Доверяем X-Forwarded-For ТОЛЬКО если запрос пришёл с loopback
        # (от локального nginx-фронта, см. nginx_front_portal.py).
        if direct_ip in ("127.0.0.1", "::1", "localhost"):
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                # Берём ПЕРВЫЙ адрес в цепочке (реальный клиент;
                # $proxy_add_x_forwarded_for в nginx добавляет в конец,
                # оригинальный клиентский IP — всегда первый).
                candidate = xff.split(",")[0].strip()
                if candidate:
                    return candidate
        return direct_ip

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

        # GET /api/subscription/info — сводка подписки для Admin Panel:
        # статус сервиса, базовый URL, per-user ссылки всех форматов,
        # статус мульти-нод фичи и список нод (Mode B).
        if path == "/api/subscription/info":
            if not self._require_admin():
                return
            try:
                from chimera.modules.subscription import get_admin_subscription_info
                self._send_json(get_admin_subscription_info())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/sat/info — все привязки сателлитов + все доступные логины
        # (для Admin Panel).
        if path == "/api/sat/info":
            if not self._require_admin():
                return
            try:
                from chimera.modules.satellite_bindings import get_admin_satellites_info
                self._send_json(get_admin_satellites_info())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/b4/info — полный статус b4 для Admin Panel.
        if path == "/api/b4/info":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import get_admin_info
                self._send_json(get_admin_info())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/b4/health — health check YouTube (работает ли?).
        if path == "/api/b4/health":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import health_check_youtube
                self._send_json(health_check_youtube())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
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

        # GET /api/portal/sub-info — сводка подписки текущего юзера:
        # URL'ы всех форматов (base64/ios/singbox/clash) + статус мульти-нод
        # фичи и список нод (Mode B). Используется карточкой «Моя подписка».
        if path == "/api/portal/sub-info":
            user = self._require_user()
            if user is None:
                return
            try:
                from chimera.modules.subscription import get_portal_subscription_info
                self._send_json(get_portal_subscription_info(user))
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/portal/sat-info — привязки сателлитных протоколов
        # текущего юзера (Mieru/NaiveProxy/Telemt/TrustTunnel/sing-box).
        # Используется карточкой «🛰 Сателлиты» в User Portal.
        if path == "/api/portal/sat-info":
            user = self._require_user()
            if user is None:
                return
            try:
                from chimera.modules.satellite_bindings import get_user_satellites_info
                self._send_json({"satellites": get_user_satellites_info(user)})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/portal/sat-suggest — предложения привязки для юзера
        # (авто-сканирование логинов всех сателлитов, matches по имени/uuid).
        # Используется кнопкой «Авто-привязка» в User Portal.
        if path == "/api/portal/sat-suggest":
            user = self._require_user()
            if user is None:
                return
            try:
                from chimera.modules.satellite_bindings import suggest_for_user
                self._send_json({"suggestions": suggest_for_user(user)})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/portal/b4-info — краткий статус b4 (DPI bypass YouTube)
        # для User Portal. Не требует admin-прав — юзер видит только
        # «включено/выключено», без технических деталей.
        if path == "/api/portal/b4-info":
            user = self._require_user()
            if user is None:
                return
            try:
                from chimera.modules.youtube_b4 import get_portal_info
                self._send_json(get_portal_info())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # GET /api/portal/sub-clash — полный мульти-нодовый mihomo YAML
        # (группы Выбор/Auto/Fallback/Balance + правила). Отличие от
        # /api/portal/clash: тот — минимальный single-proxy, этот — полный
        # конфиг из подписки (тот же, что ?format=clash).
        if path == "/api/portal/sub-clash":
            user = self._require_user()
            if user is None:
                return
            body = ""
            try:
                from chimera.modules import subscription_multinode as _mn
                body = _mn.build_mihomo_config(user)
            except Exception:
                pass
            if not body:
                body = _generate_clash_config(user)
            if not body:
                self._send_json({"error": "clash config unavailable"}, 503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="chimera-mihomo.yaml"')
            self.send_header("Content-Length", str(len(body.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        # GET /api/portal/sub-singbox — полный мульти-нодовый sing-box JSON
        # (selector «🎯 Chimera» + urltest «auto» + все ноды).
        if path == "/api/portal/sub-singbox":
            user = self._require_user()
            if user is None:
                return
            body = ""
            try:
                from chimera.modules import subscription_multinode as _mn
                body = _mn.build_singbox_config(user)
            except Exception:
                pass
            if not body:
                body = _generate_singbox_config(user)
            if not body:
                self._send_json({"error": "singbox config unavailable"}, 503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="chimera-singbox.json"')
            self.send_header("Content-Length", str(len(body.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
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

        # GET /api/portal/ips — список allowed_ips текущего пользователя.
        # Возвращает:
        #   { "ips": [{"ip": "5.167.98.20", "added_at": "...", "pinned": false}, ...],
        #     "max": 20, "detected_ip": "<текущий IP клиента>" }
        #  detailed формат с added_at и pinned.
        # detected_ip — IP, с которого клиент пришёл СЕЙЧАС. НЕ доверяем X-Forwarded-For.
        if path == "/api/portal/ips":
            user = self._require_user()
            if user is None:
                return
            try:
                from chimera.modules.user_ip_whitelist import (
                    get_user_ips_detailed, MAX_IPS_PER_USER,
                )
                email = user.get("email", "")
                ips_detailed = get_user_ips_detailed(email)
                detected = self._client_ip()
                #  _client_ip() уже извлекает реальный IP из
                # X-Forwarded-For (если запрос через nginx-фронт). Если
                # всё равно loopback — значит nginx не проставил XFF
                # (конфиг сломан), или клиент правда localhost (SSH tunnel).
                if detected in ("127.0.0.1", "::1", "localhost", "?"):
                    detected = ""
                self._send_json({
                    "ips": ips_detailed,
                    "max": MAX_IPS_PER_USER,
                    "detected_ip": detected,
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
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

            # v4.25: Автосинхронизация со всеми syncable-протоколами (NaiveProxy,
            # Mieru, TrustTunnel, sing-box, Telemt). Создаёт аккаунт с тем же
            # email/UUID в каждом активном протоколе, чтобы соответствующая
            # ссылка появилась в User Portal без ручного шага в TUI.
            # Передаём full user dict чтобы singbox/trusttunnel могли использовать
            # UUID для derive пароля. Возвращает {proto: bool|None}.
            _new_user_dict = {
                "uuid": new_uuid, "email": email, "name": name,
            }
            protocol_sync = _sync_ensure_user(name, user=_new_user_dict)

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
        # v4.25: toggle теперь синхронизируется со всеми спутниковыми протоколами
        # (NaiveProxy, Mieru, TrustTunnel, sing-box, Telemt) через
        # _sync_remove_user (на disable) / _sync_ensure_user (на enable).
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
                    # v4.25: синхронизируем toggle со спутниковыми протоколами.
                    if u["disabled"]:
                        _sync_remove_user(u.get("name", ""), user=u)
                    else:
                        _sync_ensure_user(u.get("name", ""), user=u)
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
        # сохранением своих данных (Telemt — секрет).
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
            # Сохраняем old_user dict для full rename sync (нужно для sing-box
            # и trusttunnel которые используют UUID, не name).
            _old_user_dict = dict(target)
            target["name"] = new_name
            _save_users(users)
            # config.json Xray не нужно трогать — там используется email,
            # а не name. _users_apply_to_config не требуется.
            # v4.25: Автосинхронизация со всеми syncable-протоколами (NaiveProxy,
            # Mieru, TrustTunnel, sing-box, Telemt). Каждый протокол переименовывает
            # аккаунт с сохранением своих данных (Telemt — секрет, sing-box —
            # UUID+password, TrustTunnel — derived password). Если протокол не
            # активен или имя не подходит под его спеку — это не ошибка, VLESS
            # всё равно переименован. Возвращаем protocol_sync = {proto: bool|None}
            # для информативного toast в админ-панели.
            _new_user_dict = dict(target)
            protocol_sync = _sync_rename_user(
                old_name, new_name,
                old_user=_old_user_dict, new_user=_new_user_dict,
            )
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
                # (Telemt, и любые будущие через реестр
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

        # ── Satellite bindings (admin CRUD) ───────────────────────────────
        # POST /api/sat/bind — привязать логин сателлита к UUID юзера.
        # Body: {satellite, login, owner_uuid, owner_email?}
        if path == "/api/sat/bind":
            if not self._require_admin():
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            try:
                from chimera.modules.satellite_bindings import set_binding
                ok = set_binding(
                    satellite=body.get("satellite", ""),
                    login=body.get("login", ""),
                    owner_uuid=body.get("owner_uuid", ""),
                    owner_email=body.get("owner_email", ""),
                )
                if ok:
                    self._send_json({"status": "bound"})
                else:
                    self._send_json({"error": "invalid arguments"}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/sat/unbind — отвязать сателлит от UUID юзера.
        # Body: {satellite, owner_uuid}
        if path == "/api/sat/unbind":
            if not self._require_admin():
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            try:
                from chimera.modules.satellite_bindings import remove_binding
                ok = remove_binding(
                    satellite=body.get("satellite", ""),
                    owner_uuid=body.get("owner_uuid", ""),
                )
                self._send_json({"status": "unbound" if ok else "not_found"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # ── b4 management (admin) ────────────────────────────────────────
        # POST /api/b4/install — установить b4 (скачать + конфиг + systemd + iptables).
        if path == "/api/b4/install":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import install_b4
                ok = install_b4()
                self._send_json({"status": "installed" if ok else "failed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/b4/uninstall — удалить b4 полностью.
        if path == "/api/b4/uninstall":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import uninstall_b4
                uninstall_b4()
                self._send_json({"status": "uninstalled"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/b4/enable — запустить b4.
        if path == "/api/b4/enable":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import enable
                ok = enable()
                self._send_json({"status": "enabled" if ok else "failed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/b4/disable — остановить b4 (без удаления).
        if path == "/api/b4/disable":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import disable
                disable()
                self._send_json({"status": "disabled"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/b4/preset — переключить preset.
        # Body: {preset: "default"|"aggressive"|"light"}
        if path == "/api/b4/preset":
            if not self._require_admin():
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            try:
                from chimera.modules.youtube_b4 import switch_preset
                ok = switch_preset(body.get("preset", ""))
                self._send_json({"status": "switched" if ok else "failed"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/b4/discovery — запустить Discovery (автоподбор сета).
        if path == "/api/b4/discovery":
            if not self._require_admin():
                return
            try:
                from chimera.modules.youtube_b4 import run_discovery
                result = run_discovery(timeout_sec=60)
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # ── User-side satellite auto-bind (Portal → bindings.json) ────────
        # POST /api/portal/sat-bind — юзер сам привязывает предложенный
        # логин (auto-suggest) или手动 указывает. Body: {satellite, login}
        if path == "/api/portal/sat-bind":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            satellite = body.get("satellite", "").strip()
            login = body.get("login", "").strip()
            if not satellite or not login:
                self._send_json({"error": "satellite и login обязательны"}, 400)
                return
            try:
                from chimera.modules.satellite_bindings import (
                    set_binding, scan_all_satellites, SATELLITES,
                )
                # Валидация: login должен существовать в сателлите
                # (защита от привязки произвольного логина).
                scan = scan_all_satellites()
                sat_key = None
                for s in SATELLITES:
                    if s == satellite.lower() or s.startswith(satellite.lower()):
                        sat_key = s
                        break
                if not sat_key:
                    self._send_json({"error": f"unknown satellite: {satellite}"}, 400)
                    return
                available_logins = [l.get("login") for l in scan.get(sat_key, [])]
                if login not in available_logins:
                    self._send_json({"error": f"login '{login}' не найден в {sat_key}"}, 400)
                    return
                set_binding(
                    satellite=sat_key,
                    login=login,
                    owner_uuid=user.get("uuid", ""),
                    owner_email=user.get("email", ""),
                )
                self._send_json({"status": "bound", "satellite": sat_key, "login": login})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/portal/sat-unbind — юзер отвязывает свой сателлит.
        # Body: {satellite}
        if path == "/api/portal/sat-unbind":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            satellite = body.get("satellite", "").strip()
            if not satellite:
                self._send_json({"error": "satellite обязателен"}, 400)
                return
            try:
                from chimera.modules.satellite_bindings import remove_binding
                ok = remove_binding(
                    satellite=satellite,
                    owner_uuid=user.get("uuid", ""),
                )
                self._send_json({"status": "unbound" if ok else "not_found"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # POST /api/portal/ips — добавить IP в whitelist текущего пользователя.
        # Body: {"ip": "5.167.98.20"} или {"ip": "5.167.98.0/24"}.
        # Специальное значение: {"ip": "auto"} — использовать IP клиента из
        # client_address (НЕ из X-Forwarded-For, см. Q2 в user_ip_whitelist.py).
        # Returns: {"status": "added", "ip": "<normalized>"} или {"error": "..."}.
        if path == "/api/portal/ips":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            ip_input = (body.get("ip") or "").strip()
            if not ip_input:
                self._send_json({"error": "ip required"}, 400)
                return
            # "auto" → берём IP через _client_ip() ( с поддержкой
            # X-Forwarded-For если запрос через nginx-фронт).
            # Если всё равно loopback — значит nginx не проставил XFF
            # (конфиг сломан), или клиент правда localhost (SSH tunnel).
            if ip_input.lower() == "auto":
                ip_input = self._client_ip()
                if ip_input in ("127.0.0.1", "::1", "localhost", "?"):
                    self._send_json({
                        "error": "auto-detect невозможен (вы за localhost/SSH tunnel). "
                                 "Укажите IP вручную.",
                    }, 400)
                    return
            email = user.get("email", "")
            try:
                from chimera.modules.user_ip_whitelist import add_ip_to_user
                ok, msg = add_ip_to_user(email, ip_input)
                if ok:
                    self._send_json({"status": "added", "message": msg})
                else:
                    self._send_json({"error": msg}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        #  POST /api/portal/ips/replace-all — заменить все IP на один новый.
        # Body: {"ip": "5.167.98.20"} или {"ip": "auto"} или {"ip": "auto", "keep_pinned": false}
        if path == "/api/portal/ips/replace-all":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            ip_input = (body.get("ip") or "").strip()
            if not ip_input:
                self._send_json({"error": "ip required"}, 400)
                return
            if ip_input.lower() == "auto":
                #  _client_ip() с поддержкой X-Forwarded-For.
                ip_input = self._client_ip()
                if ip_input in ("127.0.0.1", "::1", "localhost", "?"):
                    self._send_json({
                        "error": "auto-detect невозможен (вы за localhost/SSH tunnel). "
                                 "Укажите IP вручную.",
                    }, 400)
                    return
            keep_pinned = body.get("keep_pinned", True)
            email = user.get("email", "")
            try:
                from chimera.modules.user_ip_whitelist import replace_all_ips
                ok, msg = replace_all_ips(email, ip_input, keep_pinned=keep_pinned)
                if ok:
                    self._send_json({"status": "replaced", "message": msg})
                else:
                    self._send_json({"error": msg}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        #  POST /api/portal/ips/pin — закрепить IP.
        # Body: {"ip": "5.167.98.20"}
        if path == "/api/portal/ips/pin":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            ip_input = (body.get("ip") or "").strip()
            if not ip_input:
                self._send_json({"error": "ip required"}, 400)
                return
            email = user.get("email", "")
            try:
                from chimera.modules.user_ip_whitelist import pin_ip_to_user
                ok, msg = pin_ip_to_user(email, ip_input)
                if ok:
                    self._send_json({"status": "pinned", "message": msg})
                else:
                    self._send_json({"error": msg}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        #  POST /api/portal/ips/unpin — открепить IP.
        # Body: {"ip": "5.167.98.20"}
        if path == "/api/portal/ips/unpin":
            user = self._require_user()
            if user is None:
                return
            body = self._read_body()
            if body is None:
                self._send_json({"error": "Payload Too Large"}, 413)
                return
            ip_input = (body.get("ip") or "").strip()
            if not ip_input:
                self._send_json({"error": "ip required"}, 400)
                return
            email = user.get("email", "")
            try:
                from chimera.modules.user_ip_whitelist import unpin_ip_from_user
                ok, msg = unpin_ip_from_user(email, ip_input)
                if ok:
                    self._send_json({"status": "unpinned", "message": msg})
                else:
                    self._send_json({"error": msg}, 400)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
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
            # v4.25: Автосинхронизация со всеми syncable-протоколами (NaiveProxy,
            # Mieru, TrustTunnel, sing-box, Telemt). Удаляет аккаунт в каждом
            # активном протоколе, чтобы не оставлять "висящие" аккаунты для
            # удалённого VLESS-юзера. Передаём full user dict чтобы singbox/
            # trusttunnel могли найти аккаунт по UUID (не только по name/email).
            # Возвращает {proto: bool|None}.
            protocol_sync = {}
            if deleted_user is not None:
                protocol_sync = _sync_remove_user(
                    deleted_user.get("name", "") or
                    deleted_user.get("email", "").split("@")[0],
                    user=deleted_user,
                )
            # v5: также снимаем все привязки сателлитов из side-table
            # satellite_bindings.json — иначе в Admin Panel в секции
            # «Сателлиты» остаются висящие записи с несуществующим UUID.
            if deleted_user is not None:
                try:
                    from chimera.modules.satellite_bindings import remove_user as _sb_remove_user
                    _sb_remove_user(deleted_user.get("uuid", ""))
                except Exception:
                    pass
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

        # DELETE /api/portal/ips?ip=<ip> — удалить IP из whitelist текущего
        # пользователя. ip передаётся в query string (URL-encoded).
        # Пример: DELETE /api/portal/ips?ip=5.167.98.20
        #         DELETE /api/portal/ips?ip=5.167.98.0%2F24
        if path == "/api/portal/ips":
            user = self._require_user()
            if user is None:
                return
            parsed_query = parse_qs(parsed.query)
            ip_to_delete = ""
            if "ip" in parsed_query and parsed_query["ip"]:
                ip_to_delete = unquote(parsed_query["ip"][0]).strip()
            if not ip_to_delete:
                self._send_json({"error": "ip query parameter required"}, 400)
                return
            email = user.get("email", "")
            try:
                from chimera.modules.user_ip_whitelist import remove_ip_from_user
                ok, msg = remove_ip_from_user(email, ip_to_delete)
                if ok:
                    self._send_json({"status": "deleted", "message": msg})
                else:
                    self._send_json({"error": msg}, 400)
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

def _ufw_web_panel_close(port: int) -> None:
    """Закрывает ufw-правило для веб-панели по комментарию и порту.

     миграция на port_registry (с legacy comment backward compat).
    Сначала пробует port_registry.ufw_close_port (ищет chimera-web_panel
    и legacy "VLESS Web Panel"), затем fallback на ручной парсинг ufw status.
    """
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_WEB_PANEL,
        )
        ufw_close_port(port, "tcp", SERVICE_WEB_PANEL,
                       legacy_comments=["VLESS Web Panel (exposed, no TLS)",
                                        "VLESS Web Panel"])
        port_unregister(SERVICE_WEB_PANEL, port, "tcp")
    except Exception:
        pass
    # Fallback: ручной парсинг ufw status (для правил без comment или
    # если port_registry недоступен).
    if not shutil.which("ufw"):
        return
    core = _core_module()
    _run = core._run
    r = _run(["ufw", "status", "numbered"], capture=True, check=False, quiet=True)
    if r.returncode != 0 or not r.stdout:
        return
    # Парсим строки вида:
    # [ 3] 8443/tcp                   ALLOW IN    Anywhere                   # VLESS Web Panel (exposed, no TLS)
    lines_to_delete: list[int] = []
    for line in r.stdout.splitlines():
        # Ищем номер правила в квадратных скобках.
        m = re.match(r'^\s*\[\s*(\d+)\s*\]\s*(.+)', line)
        if not m:
            continue
        rule_num = int(m.group(1))
        rest = m.group(2)
        # Проверяем: содержит ли правило наш порт и наш комментарий.
        if str(port) in rest and "VLESS Web Panel" in rest:
            lines_to_delete.append(rule_num)
    # Удаляем с конца (старшие номера первыми) — чтобы не сбить нумерацию.
    for num in sorted(lines_to_delete, reverse=True):
        _run(["ufw", "delete", str(num)],
             check=False, quiet=True,
             input_text="y\n")


def install_web_service(port: int = None, admin_user: str = None,
                        admin_pass: str = None,
                        expose: Optional[bool] = None) -> dict:
    """Устанавливает systemd-сервис для веб-панели.
    По умолчанию bind 127.0.0.1 — ufw НЕ открывается (доступ через SSH-туннель).
    expose=True  — bind 0.0.0.0 + открытие порта в ufw + предупреждение о HTTP.
    expose=False — принудительно 127.0.0.1 (даже если в конфиге было 0.0.0.0)
                  + закрытие старого ufw-правила если было открыто.
    expose=None  — оставить текущий host в конфиге как есть."""
    # Читаем СТАРЫЙ конфиг ДО перезаписи — нужно знать старый host/port
    # для закрытия ufw-правила при переключении с 0.0.0.0 на 127.0.0.1.
    old_cfg = _web_config_load()
    old_host = old_cfg.get("host", DEFAULT_WEB_HOST)
    old_port = old_cfg.get("port", DEFAULT_WEB_PORT)

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

    # Если переключаемся С 0.0.0.0 на что-то другое (127.0.0.1 или смена порта) —
    # закрыть СТАРЫЙ ufw-порт.
    if old_host == "0.0.0.0" and current_host != "0.0.0.0":
        _ufw_web_panel_close(old_port)
    # Если меняем порт при сохранении 0.0.0.0 — закрыть старый, открыть новый.
    if old_host == "0.0.0.0" and current_host == "0.0.0.0" and old_port != port:
        _ufw_web_panel_close(old_port)

    # Открываем порт в ufw ТОЛЬКО при явном внешнем доступе (host=0.0.0.0).
    # По умолчанию (127.0.0.1) — не открываем, доступ через SSH-туннель.
    #  миграция на port_registry (с backward compat fallback).
    # port_register — ВСЕГДА (и loopback): конфликт-детекция должна
    # видеть панель (webdav_tunnel тоже дефолтит на 8443). UFW — только
    # при 0.0.0.0.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_WEB_PANEL,
        )
        _reg_comment = ("VLESS Web Panel (exposed, no TLS)"
                        if current_host == "0.0.0.0"
                        else "VLESS Web Panel (loopback)")
        port_register(SERVICE_WEB_PANEL, port, "tcp",
                      comment=_reg_comment, force=True)
    except Exception:
        pass
    if current_host == "0.0.0.0" and shutil.which("ufw"):
        _web_panel_ufw_opened = False
        try:
            from chimera.modules.port_registry import (
                ufw_open_port, SERVICE_WEB_PANEL,
            )
            ok, msg = ufw_open_port(port, "tcp", SERVICE_WEB_PANEL,
                                    comment="VLESS Web Panel (exposed, no TLS)")
            if ok:
                _web_panel_ufw_opened = True
        except Exception:
            pass
        if not _web_panel_ufw_opened:
            # Fallback: прямой ufw allow.
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
    # FIX: использовать __file__ вместо sys.argv[0] для определения project_root.
    # sys.argv[0] может быть /tmp/script.py при вызове install_web_service()
    # из скрипта — тогда project_root=/tmp и PYTHONPATH=/tmp → ModuleNotFoundError.
    # __file__ всегда указывает на rest_api.py внутри chimera/modules/ —
    # parent.parent = chimera project root (/opt/chimera).
    main_py = Path(__file__).resolve().parent.parent.parent / "main.py"
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
    """Останавливает и удаляет systemd-сервис + закрывает ufw-порт.

    Проблема с Restart=on-failure: при systemctl stop процесс убивается,
    но systemd перезапускает его (т.к. юнит-файл ещё на диске).
    Решение: mask → stop → удалить юнит → daemon-reload → reset-failed →
    kill по порту если процесс всё ещё жив (fallback).

     также удаляет nginx front для User Portal (если был установлен).
    nginx_front_portal.NGINX_FRONT_STATE_FILE указывает на наличие фронта.
    """
    core = _core_module()
    _run = core._run
    #  сначала удаляем nginx front (если был) — он зависит от rest_api.
    try:
        from chimera.modules.nginx_front_portal import nginx_front_remove, nginx_front_status
        if nginx_front_status().get("enabled"):
            core.info("Удаляю nginx front для User Portal...")
            nginx_front_remove()
    except Exception as _e:
        try:
            core.warn(f"nginx_front_remove: {_e}")
        except Exception:
            pass
    # Читаем конфиг ДО остановки — нужно знать host/port для ufw и kill.
    cfg = _web_config_load()
    old_host = cfg.get("host", DEFAULT_WEB_HOST)
    old_port = cfg.get("port", DEFAULT_WEB_PORT)
    # Если панель была открыта наружу — закрыть ufw-порт.
    if old_host == "0.0.0.0":
        _ufw_web_panel_close(old_port)
    # 1. Mask — предотвращает перезапуск после stop (systemd больше не
    #    читает юнит-файл для этого сервиса, /etc/systemd/system/vless-web.service
    #    заменяется symlink на /dev/null).
    _run(["systemctl", "mask", "vless-web"], check=False, quiet=True)
    # 2. Stop — теперь процесс не перезапустится (mask блокирует Restart=).
    _run(["systemctl", "stop", "vless-web"], check=False, quiet=True)
    # 3. Disable — убирает из автозагрузки.
    _run(["systemctl", "disable", "vless-web"], check=False, quiet=True)
    # 4. Удаляем юнит-файл (и symlink от mask, если остался).
    WEB_SERVICE_FILE.unlink(missing_ok=True)
    # mask создаёт symlink /etc/systemd/system/vless-web.service → /dev/null
    # — его тоже нужно убрать, иначе при следующей установке сервис не стартует.
    mask_link = Path("/etc/systemd/system/vless-web.service")
    if mask_link.is_symlink():
        try:
            mask_link.unlink()
        except Exception:
            pass
    # 5. Daemon-reload — systemd забывает про сервис.
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    # 6. Reset-failed — очищает состояние "failed" (иначе при следующей
    #    установке systemd может ругаться на "start-limit-hit").
    _run(["systemctl", "reset-failed", "vless-web"], check=False, quiet=True)
    # 7. Fallback: если процесс всё ещё слушает порт (mask не сработал
    #    на старых systemd, или процесс был запущен вручную а не через
    #    systemd) — найти PID через ss и убить через kill -9.
    try:
        r = _run(["ss", "-tlnp"], capture=True, check=False, quiet=True)
        if r.stdout and f":{old_port}" in r.stdout:
            # Парсим PID из вывода ss: users:(("python3",pid=4966,fd=3))
            import re as _re
            m = _re.search(r'pid=(\d+)', r.stdout)
            if m:
                pid = int(m.group(1))
                _run(["kill", "-9", str(pid)], check=False, quiet=True)
    except Exception:
        pass
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

        # IPv4 (один раз — используется в нескольких блоках ниже)
        try:
            ipv4 = core.get_server_ip("4")
        except Exception:
            ipv4 = ""

        # Домен (из state.json — VLESS install)
        try:
            _domain = getattr(core, "PARAM_DOMAIN", "") or ""
            if not _domain:
                import json as _json
                _st = Path("/var/lib/xray-installer/state.json")
                if _st.exists():
                    _domain = (_json.loads(_st.read_text()).get("domain") or "").lower()
        except Exception:
            _domain = ""

        # ── БЛОК 1: Chimera default web-panel (vless-web, port 8443) ────────
        if not _installed:
            _box_row(f"  {YELLOW}⚠️  Веб-панель НЕ установлена!{NC}")
            _box_row(f"  {DIM}Используйте пункт 1 для установки.{NC}")
            _box_row()

        _box_row(f"  {BOLD}Chimera default panel (vless-web, :8443){NC}")
        _box_row(f"  Сервис:       {GREEN+'активен'+NC if running else YELLOW+'остановлен'+NC}")
        _box_row(f"  Хост:         {CYAN}{host}{NC} {YELLOW+'(открыто наружу, без TLS!)'+NC if exposed else '(локально, SSH-туннель)'}")
        _box_row(f"  Порт:         {CYAN}{port}{NC}")
        _box_row(f"  Admin:        {CYAN}http://<IP>:{port}/admin/{NC}")
        _box_row(f"  Portal:       {CYAN}http://<IP>:{port}/portal/{NC}")
        _box_row(f"  Admin логин:  {CYAN}{admin_user}{NC}")
        if ipv4:
            _box_row(f"  IPv4:         {CYAN}{ipv4}{NC}")

        #  nginx front status (для Chimera default)
        _nginx_front_enabled = False
        _nginx_front_port = 0
        _nginx_front_domain = ""
        try:
            from chimera.modules.nginx_front_portal import nginx_front_status
            _nfp_status = nginx_front_status()
            _nginx_front_enabled = _nfp_status.get("enabled", False)
            _nginx_front_port = _nfp_status.get("port", 0)
            _nginx_front_domain = _nfp_status.get("domain", "")
        except Exception:
            pass

        # ── БЛОК 2: WPP Web Panel (если установлен) ──────────────────────────
        _wpp_installed = False
        _wpp_running = False
        _wpp_port = 0
        _wpp_nginx_enabled = False
        _wpp_nginx_port = 0
        _wpp_nginx_domain = ""
        try:
            from chimera.modules import wpp_state
            _wpp_state_data = wpp_state.load_state()
            _wpp_installed = bool(_wpp_state_data.get("installed"))
            _wpp_port = int(_wpp_state_data.get("web_port", 0) or 0)
            # Проверяем активность сервиса
            if _wpp_installed:
                import subprocess as _sp
                _r = _sp.run(["systemctl", "is-active", "--quiet", "wpp-web"],
                              capture_output=True, timeout=5)
                _wpp_running = (_r.returncode == 0)
            # Читаем WPP nginx front state
            _wpp_nginx_state_file = Path("/var/lib/xray-installer/wpp_panel_nginx.json")
            if _wpp_nginx_state_file.exists():
                import json as _json
                _wng = _json.loads(_wpp_nginx_state_file.read_text())
                _wpp_nginx_enabled = bool(_wng.get("enabled"))
                _wpp_nginx_port = int(_wng.get("port", 0) or 0)
                _wpp_nginx_domain = _wng.get("domain", "") or _domain
        except Exception:
            pass

        if _wpp_installed:
            _box_sep()
            _box_row(f"  {BOLD}🌐 WPP Web Panel (POLESNIESOVETI12 порт){NC}")
            _box_row(f"  Сервис:       {GREEN+'активен'+NC if _wpp_running else YELLOW+'остановлен'+NC}")
            _box_row(f"  Backend:      {CYAN}127.0.0.1:{_wpp_port}{NC} (loopback)")
            if _wpp_nginx_enabled:
                _box_row(f"  Nginx Front:  {GREEN}включён{NC} — {CYAN}https://{_wpp_nginx_domain}:{_wpp_nginx_port}{NC}")
                _box_row(f"  Публичный URL:{CYAN}https://{_wpp_nginx_domain}:{_wpp_nginx_port}/panel/{NC}")
            else:
                _box_row(f"  Nginx Front:  {DIM}выключен (доступ через SSH-туннель){NC}")
                if ipv4:
                    _box_row(f"  SSH-туннель:  {CYAN}ssh -L {_wpp_port}:127.0.0.1:{_wpp_port} root@{ipv4}{NC}")
                    _box_row(f"  Затем браузер:{CYAN}http://localhost:{_wpp_port}/panel/{NC}")

        # ── БЛОК 3: Triple Panel (если установлен) ──────────────────────────
        _triple_installed = False
        _triple_running = False
        _triple_port = 0
        _triple_nginx_enabled = False
        _triple_nginx_port = 0
        _triple_nginx_domain = ""
        try:
            _triple_state_file = Path("/var/lib/xray-installer/triple_panel_state.json")
            if _triple_state_file.exists():
                import json as _json
                _tsd = _json.loads(_triple_state_file.read_text())
                _triple_installed = bool(_tsd.get("installed"))
                _triple_port = int(_tsd.get("web_port", 0) or 0)
                if _triple_installed:
                    import subprocess as _sp
                    _r = _sp.run(["systemctl", "is-active", "--quiet", "triple-web"],
                                  capture_output=True, timeout=5)
                    _triple_running = (_r.returncode == 0)
                _triple_nginx_state_file = Path("/var/lib/xray-installer/triple_panel_nginx.json")
                if _triple_nginx_state_file.exists():
                    _tng = _json.loads(_triple_nginx_state_file.read_text())
                    _triple_nginx_enabled = bool(_tng.get("enabled"))
                    _triple_nginx_port = int(_tng.get("port", 0) or 0)
                    _triple_nginx_domain = _tng.get("domain", "") or _domain
        except Exception:
            pass

        if _triple_installed:
            _box_sep()
            _box_row(f"  {BOLD}🧩 Triple Panel (Naive+Mieru+H2, RIXXX порт){NC}")
            _box_row(f"  Сервис:       {GREEN+'активен'+NC if _triple_running else YELLOW+'остановлен'+NC}")
            _box_row(f"  Backend:      {CYAN}127.0.0.1:{_triple_port}{NC} (loopback)")
            if _triple_nginx_enabled:
                _box_row(f"  Nginx Front:  {GREEN}включён{NC} — {CYAN}https://{_triple_nginx_domain}:{_triple_nginx_port}{NC}")
            else:
                _box_row(f"  Nginx Front:  {DIM}выключен (доступ через SSH-туннель){NC}")
                if ipv4:
                    _box_row(f"  SSH-туннель:  {CYAN}ssh -L {_triple_port}:127.0.0.1:{_triple_port} root@{ipv4}{NC}")

        # ── БЛОК 4: nginx front статус (общий — для Chimera default) ─────────
        _box_sep()
        if _nginx_front_enabled:
            _box_row(f"  Chimera nginx front:  {GREEN}включён{NC} — https://{_nginx_front_domain}:{_nginx_front_port}")
        else:
            _box_row(f"  Chimera nginx front:  {DIM}выключен (доступ через SSH-туннель или без TLS){NC}")

        _box_sep()
        if not _installed:
            _box_item("1", "Установить веб-панель")
        else:
            _box_item("1", f"{'Остановить' if running else 'Запустить'} сервис")
        _box_item("2", "Изменить порт")
        _box_item("3", "Изменить admin-пароль")
        _box_item("4", "Переустановить (сброс конфига)")
        _box_item("5", f"{'Закрыть доступ снаружи' if exposed else 'Открыть доступ снаружи (ВНИМАНИЕ: без TLS!)'}")
        _box_item("6", f"🌐 nginx front (TLS) — {'выключен' if not _nginx_front_enabled else 'настройки'}")
        _box_item("7", f"🧩 Triple Panel (Naive+Mieru+H2)  {DIM}(порт RIXXX-панели: установка/обновления/доступ){NC}")
        _box_item("8", f"🌐 WPP Web Panel  {DIM}(порт POLESNIESOVETI12/web-panel-proxy: VLESS/H2/AWG/MTProto/OpenFlux){NC}")
        _box_item("0", f"{RED}🗑️  Удалить полностью{NC}")
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
                # Останавливаем сервис. Если панель была открыта наружу (0.0.0.0) —
                # закрываем ufw-порт, чтобы не оставлять дыру при остановленном сервисе.
                if exposed:
                    _ufw_web_panel_close(port)
                # Mask перед stop — предотвращает перезапуск из-за Restart=on-failure.
                core._run(["systemctl", "mask", "vless-web"], check=False, quiet=True)
                core._run(["systemctl", "stop", "vless-web"], check=False, quiet=True)
                success("Сервис остановлен")
            else:
                # Запускаем сервис. Сначала unmask (если был замаскирован при остановке).
                # Если панель была открыта наружу (0.0.0.0) —
                # переоткрываем ufw-порт через install_web_service (а не голый
                # systemctl start, который порт не откроет).
                core._run(["systemctl", "unmask", "vless-web"], check=False, quiet=True)
                if exposed:
                    install_web_service(port=port, expose=True)
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
                    # install_web_service(expose=False) уже закроет старый ufw-порт
                    # через логику old_host=="0.0.0.0" → _ufw_web_panel_close.
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

        elif ch == "6":
            #  nginx front (TLS) для User Portal.
            try:
                from chimera.modules.nginx_front_portal import do_manage_nginx_front
                do_manage_nginx_front()
            except Exception as e:
                warn(f"Не удалось открыть меню nginx front: {e}")
                _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "7":
            #  Triple Panel — порт веб-панели Panel-Naive-Mieru-by-RIXXX
            #  (Naive+Mieru+H2) в архитектуру Chimera. Свой сервис/порт/версии.
            try:
                from chimera.modules.triple_panel import do_triple_panel_menu
                do_triple_panel_menu()
            except Exception as e:
                warn(f"Не удалось открыть меню Triple Panel: {e}")
                _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "8":
            #  WPP Web Panel — порт POLESNIESOVETI12/web-panel-proxy
            #  (VLESS/Hysteria2/AWG/MTProto/OpenFlux). Свой сервис/порт/версии.
            #  По образцу Triple Panel: полностью автономный модуль с lazy
            #  доступом к chimera._core, не требует изменений в _core.py.
            try:
                from chimera.modules.wpp_panel import do_wpp_panel_menu
                do_wpp_panel_menu()
            except Exception as e:
                warn(f"Не удалось открыть меню WPP Web Panel: {e}")
                _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "0":
            #  Полное удаление веб-панели (systemd unit + web_config.json + ufw).
            #  Вынесено в конец как [0] — логичнее: безопасные действия вверху,
            #  деструктивное — в самом конце, требует отдельного нажатия '0'.
            if not _installed:
                warn("Веб-панель не установлена — нечего удалять.")
                _input(f"{BLUE}Нажмите Enter...{NC}")
            else:
                _box_row(f"  {RED}Будет удалено:{NC}")
                _box_row(f"  {DIM}  • systemd-unit vless-web.service{NC}")
                _box_row(f"  {DIM}  • web_config.json (admin/portal конфиг){NC}")
                _box_row(f"  {DIM}  • ufw-правило (если было открыто){NC}")
                if _nginx_front_enabled:
                    _box_row(f"  {DIM}  • nginx front для User Portal (если установлен){NC}")
                _box_row(f"  {DIM}  state.json и пользователи VLESS НЕ затрагиваются.{NC}")
                _box_row()
                confirm = _input(
                    f"  {RED}Полностью удалить веб-панель? [y/N]:{NC} "
                ).strip().lower()
                if confirm == "y":
                    uninstall_web_service()
                    success("Веб-панель полностью удалена.")
                else:
                    info("Отменено.")
                _input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
