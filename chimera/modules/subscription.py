"""
chimera/modules/subscription.py
───────────────────────────────────────────────────────────────────────────────
Единая подписка (subscription link) на все активные клиентские транспорты.

АРХИТЕКТУРНОЕ РЕШЕНИЕ (и почему):
  У пользователя не бывает нескольких ПАРАЛЛЕЛЬНЫХ клиентских протоколов
  на выбор. AWG и Hysteria2 в этом проекте — транспорт цепочки Entry→Exit
  (см. smart_balancer._sb_patch_xray_active_node, hysteria2_exit_mgr) —
  свитч exit-ноды балансировщиком меняет ТОЛЬКО серверный outbound,
  клиентская vless:// ссылка никогда не содержит exit-IP и не протухает.

  Реально независимый клиентский эндпоинт — только Telemt/MTProto
  (tg://proxy?server=...), с собственными пользователями в telemt.toml
  ([access.users]), не связанными с UUID из users.json напрямую.

  Поэтому подписка на юзера — это агрегат:
    1) vless:// (Reality/xHTTP) — по UUID пользователя + общим server-side
       параметрам (pbk/sid/sni/fp/port) из state.json
    2) tg://proxy — если найден telemt-юзер с совпадающим именем/label

  Никакого кеша: хендлер читает users.json / state.json / telemt.toml
  прямо в момент запроса. Любое изменение топологии (новый UUID, ротация
  Reality-ключей, новый telemt-юзер, смена домена) видно клиенту при
  следующем автообновлении подписки — вручную рассылать ссылки не нужно.

  Формат тела ответа — Base64(join("\n", uri_list)) — универсальный
  subscription-формат, который понимают Happ, NekoBox/Nekoray, v2rayN,
  v2rayNG «из коробки» без доп. настроек. Как и config_edit_mode="api" —
  формат HARDCODED, без пользовательского выбора (меньше площадь отказа).

  Транспорт: собственный HTTPS-хендлер на 127.0.0.1:<порт>, слушающий
  напрямую (без внешней зависимости от nginx — топология веб-морды перед
  Reality на 443 у каждого инсталла своя и её лучше не трогать вслепую).
  Если нужен проброс через уже существующий nginx — см. NGINX_SNIPPET
  ниже, добавляется одной строкой `include`.

  ВАЖНО: _core.py НЕ изменяется. Функциональность полностью в этом файле.
  Точка входа НЕ зашита в общее меню — вызывается отдельно:
      python3 -m chimera.modules.subscription menu
      python3 -m chimera.modules.subscription serve   (из systemd)
  Прицепить пункт меню в _core.py — по желанию, одна строка импорта.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

# ── Цвета (та же схема, что и в остальных модулях проекта) ────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ── Единый box-рендерер проекта (та же система, что и во всех остальных меню) ──
from chimera.modules.box_renderer import (
    _box_top, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn as _box_warn_line, _box_ok as _box_ok_line,
)

# ── Мульти-нодовые конфиги (Mode B): mihomo YAML + sing-box selector ──────
# Импорт мягкий: при отсутствии модуля подписка продолжает работать
# как раньше (100% обратная совместимость).
try:
    from chimera.modules import subscription_multinode as _mn
except Exception as _mn_err:  # pragma: no cover
    _mn = None
    _MN_IMPORT_ERR = str(_mn_err)

# ── Логирование (единый формат с остальными модулями) ──────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [SUBSCRIPTION] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str) -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg: str)   -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str) -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str)  -> None: print(f"{RED}[ERR]{NC}   {msg}"); _log("ERROR", msg)

def _print_qr(data: str, label: str = "") -> None:
    if not shutil.which("qrencode"):
        print(f"  {YELLOW}⚠{NC}  qrencode не установлен: apt install qrencode")
        return
    if label:
        print(f"  {CYAN}→{NC}  QR: {YELLOW}{label}{NC}")
    print()
    try:
        subprocess.run(["qrencode", "-t", "UTF8", "-m", "1", data], check=True)
    except Exception as e:
        print(f"  {RED}✗{NC}  QR ошибка: {e}")
    print()

# ── Делегирование в _core.py (без circular import, без дублирования) ──────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    return importlib.import_module("chimera._core")

def _core_call(func_name: str, *args, **kwargs):
    core = _core_module()
    return getattr(core, func_name)(*args, **kwargs)

def _gen_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                     proto="reality", xhttp_path="/", xhttp_mode="stream-up",
                     port=443) -> str:
    return _core_call(
        "_gen_vless_link",
        host, uuid_str, pbk, sid, domain, fp, proto, xhttp_path, xhttp_mode, port,
    )

def _load_all_users() -> list[dict]:
    """UUID + email/name/device_label/disabled — единый мёрж users.json + xray config.json."""
    try:
        return _core_call("_unified_load_users")
    except Exception as e:
        _warn(f"Не удалось получить список пользователей из _core: {e}")
        return []

def _get_server_ip(ip_type: str = "4") -> str:
    try:
        return _core_call("get_server_ip", ip_type)
    except Exception:
        return ""

# ── Пути ─────────────────────────────────────────────────────────────────
_STATE_FILE   = Path("/var/lib/xray-installer/state.json")
_TELEMT_TOML  = Path("/etc/telemt/telemt.toml")
_MIERU_STATE  = Path("/var/lib/xray-installer/mieru.json")
_NAIVE_STATE  = Path("/var/lib/xray-installer/naiveproxy.json")
_FPTN_STATE   = Path("/var/lib/xray-installer/fptn.json")
_FPTN_USERS_FILE = Path("/etc/fptn/users.list")
_FPTN_CERT_FILE  = Path("/etc/fptn/server.crt")
_HYBRID_STATE = Path("/var/lib/xray-installer/hybrid_mieru_state.json")
_MITA_HYBRID_CFG = Path("/etc/mita/hybrid_server_config.json")
_SUB_CONF    = Path("/var/lib/xray-installer/subscription.json")
_TRAFFIC_LIMITS_FILE = Path("/var/lib/xray-installer/traffic_limits.json")
_UNIT_PATH   = Path("/etc/systemd/system/vless-subscription.service")
_NGINX_SNIP  = Path("/etc/nginx/snippets/vless-subscription.conf")

# ── nginx front (прямой доступ по домену/IP с TLS) ──────────────────────────
# По аналогии с rest_api.nginx_front_portal и telemt_panel._telemt_setup_direct_access.
# Когда nginx front включён — backend слушает 127.0.0.1 (loopback), а nginx
# терминирует TLS на отдельном порту (default 9444) и проксирует на backend.
# Когда выключён — backend возвращается на 0.0.0.0 (старый режим, обратная
# совместимость: существующие URL https://<домен>:8443/sub/<token> продолжают работать).
_SUB_NGINX_SITE_NAME   = "chimera-subscription-nginx"
_SUB_NGINX_STATE_FILE  = Path("/var/lib/xray-installer/subscription_nginx_front.json")
DEFAULT_SUB_NGINX_PORT = 9444  # не конфликтует с 8443 (backend), 9443 (User Portal nginx)

SERVICE_NAME  = "vless-subscription"
DEFAULT_PORT  = 8443

# ══════════════════════════════════════════════════════════════════════════
# КОНФИГ ПОДПИСКИ (pepper для токенов, порт, тайминги)
# ══════════════════════════════════════════════════════════════════════════

def _load_sub_conf() -> dict:
    if _SUB_CONF.exists():
        try:
            return json.loads(_SUB_CONF.read_text())
        except Exception:
            pass
    return {}

def _save_sub_conf(cfg: dict) -> None:
    _SUB_CONF.parent.mkdir(parents=True, exist_ok=True)
    _SUB_CONF.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _SUB_CONF.chmod(0o600)

def _ensure_pepper(cfg: dict) -> str:
    pepper = cfg.get("pepper")
    if not pepper:
        pepper = secrets.token_hex(32)
        cfg["pepper"] = pepper
        _save_sub_conf(cfg)
    return pepper

def _token_for(uuid_str: str, pepper: str) -> str:
    """Токен в URL — НЕ сам UUID (чтобы не светить его напрямую в ссылке)."""
    return hmac.new(pepper.encode(), uuid_str.encode(), hashlib.sha256).hexdigest()[:24]

# ══════════════════════════════════════════════════════════════════════════
# STATE.JSON — общие server-side параметры Reality/xHTTP
# ══════════════════════════════════════════════════════════════════════════

def _load_state() -> Optional[dict]:
    if not _STATE_FILE.exists():
        return None
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"state.json повреждён: {e}")
        return None

def _resolve_sni(state: dict) -> str:
    proto        = state.get("protocol_mode", "reality")
    domain       = state.get("domain", "")
    reality_dest = state.get("reality_dest", "")
    awg_exit     = state.get("awg_exit_enabled", False)
    install_mode = state.get("install_mode", "A")
    # xhttp_reality наследует SNI-правило REALITY (те же ключи/dest)
    if proto in ("reality", "xhttp_reality") and awg_exit and install_mode == "B" and reality_dest:
        return reality_dest.split(":")[0]
    return domain

def _build_vless_uri(user: dict, state: dict) -> Optional[str]:
    domain     = state.get("domain", "")
    if not domain:
        return None
    proto      = state.get("protocol_mode", "reality")
    port       = int(state.get("server_port", 443))
    # pbk/sid/spx — с fallback на живой config.json. При частично
    # повреждённом state.json (domain/uuid на месте, ключи потеряны)
    # ссылки получали pbk=&sid= и молча ломались. Источник истины для
    # выданных ссылок — realitySettings текущего конфига.
    try:
        pub_key, short_id, spiderx_fallback = _core_call(
            "_reality_transport_params_from_state", state)
    except Exception:
        pub_key    = state.get("public_key", "")
        short_id   = state.get("short_id", "")
        spiderx_fallback = ""
    fp         = state.get("fingerprint", "chrome") or "chrome"
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    sni        = _resolve_sni(state)
    host       = domain  # у клиента подписки должен быть стабильный host, IP — по желанию юзера отдельно

    uuid_str = user.get("uuid", "")
    if not uuid_str:
        return None
    if proto in ("reality", "xhttp_reality") and not (pub_key and short_id):
        _warn(f"REALITY-параметры неполны (pbk={'да' if pub_key else 'НЕТ'}, "
              f"sid={'да' if short_id else 'НЕТ'}) — ссылка для "
              f"{user.get('email','?')} может не работать; проверьте state.json")
    try:
        return _gen_vless_link(host, uuid_str, pub_key, short_id, sni, fp,
                                proto, xhttp_path, xhttp_mode, port)
    except Exception as e:
        _warn(f"Не удалось собрать vless-ссылку для {user.get('email','?')}: {e}")
        return None

# ══════════════════════════════════════════════════════════════════════════
# TELEMT.TOML — читаем только для чтения (свой формат, писатель — mtproto.py)
# ══════════════════════════════════════════════════════════════════════════

def _parse_telemt_toml() -> Optional[dict]:
    """
    Минимальный read-only парсер под фиксированный формат, который пишет
    mtproto.py (_write_telemt_toml и т.п.): секции [server]/[censorship]/
    [access.users]. Полноценный TOML-парсер не тянем как зависимость —
    формат контролируется этим же проектом и стабилен.
    """
    if not _TELEMT_TOML.exists():
        return None
    try:
        text = _TELEMT_TOML.read_text()
    except Exception:
        return None

    port_m   = re.search(r'^\s*port\s*=\s*(\d+)', text, re.MULTILINE)
    domain_m = re.search(r'^\s*tls_domain\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not port_m or not domain_m:
        return None

    users: dict[str, str] = {}
    in_users = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[access.users]":
            in_users = True
            continue
        if in_users:
            if stripped.startswith("["):
                break
            m = re.match(r'^([^=\s]+)\s*=\s*"([^"]+)"\s*$', stripped)
            if m:
                users[m.group(1)] = m.group(2)

    return {"port": int(port_m.group(1)), "tls_domain": domain_m.group(1), "users": users}

def _make_tls_secret(base_secret: str, domain: str) -> str:
    """Идентично mtproto._make_tls_secret — намеренное точечное дублирование
    (2 строки), чтобы не тащить зависимость на внутренние функции mtproto.py."""
    return f"ee{base_secret}{domain.encode().hex()}"

# ── Сопоставление UUID-пользователя с "чужими" неймспейсами (Telemt/Mieru/
#    NaiveProxy у каждого свой список users, никак не привязанный к UUID) ──
def _candidate_names(user: dict) -> set[str]:
    names = {
        (user.get("device_label") or "").strip().lower(),
        (user.get("name") or "").strip().lower(),
        (user.get("email") or "").split("@")[0].strip().lower(),
    }
    names.discard("")
    return names

def _identity_overrides() -> dict:
    """Ручные переопределения из subscription.json:
    {"identity_map": {"<uuid>": {"mieru": "username", "naive": "...", "telemt": "...", "fptn": "..."}}}
    Заполняется через do_subscription_menu → пункт 5, если автоматическое
    сопоставление по имени не сработало (например у сателлитных протоколов
    юзеры создавались вручную под другими логинами)."""
    return _load_sub_conf().get("identity_map", {})

def _match_by_name(user: dict, satellite: str, pool_keys) -> Optional[str]:
    """Возвращает ключ (имя/логин) в pool_keys, соответствующий этому
    UUID-пользователю.

    Приоритет:
      1. subscription.json → identity_map[uuid][satellite]  (manual override)
      2. satellite_bindings.json → find_login(uuid, satellite)  (CRUD, canon)
      3. Эвристика по имени (старый fallback, 100% backward compat)

    Шаг 2 — канонический путь, добавленный в v5 вместе с модулем
    satellite_bindings. Шаги 1 и 3 сохранены как escape-hatch и для
    инсталляций без side-table."""
    uuid_str = user.get("uuid", "")
    # 1. identity_map (manual override).
    override = _identity_overrides().get(uuid_str, {}).get(satellite)
    if override and override in pool_keys:
        return override
    # 2. satellite_bindings (canon).
    try:
        from chimera.modules import satellite_bindings as _sb
        bound = _sb.resolve_login(user, satellite, pool_keys)
        if bound and bound in pool_keys:
            return bound
    except ImportError:
        pass
    # 3. Heuristics by name.
    candidates = _candidate_names(user)
    for key in pool_keys:
        if key.strip().lower() in candidates:
            return key
    return None

def _build_telemt_uri(user: dict, server_ip: str) -> Optional[str]:
    tcfg = _parse_telemt_toml()
    if not tcfg:
        return None
    match_name = _match_by_name(user, "telemt", tcfg["users"].keys())
    if not match_name:
        return None
    secret = tcfg["users"][match_name]
    sec = _make_tls_secret(secret, tcfg["tls_domain"])
    return f"tg://proxy?server={server_ip}&port={tcfg['port']}&secret={sec}"

# ══════════════════════════════════════════════════════════════════════════
# MIERU (standalone-аддон ИЛИ hybrid_addon — внешний inbound вместо VLESS)
# ══════════════════════════════════════════════════════════════════════════

def _gen_mieru_share_link(server_ip: str, port: int, protocol: str,
                           username: str, password: str) -> str:
    """Точная копия формулы mieru._gen_client_share_link (без port_end —
    используем один порт: для standalone это port_start==port_end в
    типичной установке, для hybrid — единственный tcp_port/udp_port)."""
    return (
        f"mierus://{username}:{password}@{server_ip}"
        f"?port={port}&protocol={protocol.upper()}&profile=default"
        f"&mtu=1400&multiplexing=MULTIPLEXING_HIGH"
    )

def is_hybrid_mieru_active() -> bool:
    """True, если hybrid_addon.py переключил внешний VLESS-inbound на
    SOCKS-петлю 127.0.0.1 — в этом случае vless:// снаружи недоступен."""
    return _HYBRID_STATE.exists()

def _build_mieru_uris(user: dict, server_ip: str) -> list[str]:
    links: list[str] = []
    for ep in _mieru_client_endpoints(user, server_ip):
        links.append(_gen_mieru_share_link(
            ep["addr"], ep["port"], ep["proto"], ep["username"], ep["password"],
        ))
    return links


def _mieru_client_endpoints(user: dict, server_ip: str) -> list[dict]:
    """единый источник mieru-точек для ссылок и singbox-outbound'ов.

    Возвращает список {addr, port, proto, username, password, client_dns,
    pattern_b64}: hybrid (порт на транспорт; tcp и udp — ОТДЕЛЬНЫЕ точки)
    + standalone (протоколы из state, BOTH → TCP и UDP). addr — домен из
    client_server_addr важнее переданного server_ip: ссылки и
    конфиги переживают смену IP сервера. pattern_b64 — client-side
    traffic-pattern ('' — не задан, ссылкам не нужен).
    """
    endpoints: list[dict] = []

    # ── hybrid_addon: Mieru — единственный внешний вход ────────────────
    if _HYBRID_STATE.exists() and _MITA_HYBRID_CFG.exists():
        try:
            hybrid_st = json.loads(_HYBRID_STATE.read_text())
            mita_cfg  = json.loads(_MITA_HYBRID_CFG.read_text())
            users_by_name = {u["name"]: u["password"] for u in mita_cfg.get("users", [])}
            match = _match_by_name(user, "mieru", users_by_name.keys())
            if match:
                addr = (hybrid_st.get("client_server_addr") or "").strip() or server_ip
                client_dns = (hybrid_st.get("client_dns") or "").strip()
                pattern_b64 = (hybrid_st.get("traffic_pattern_blob") or "").strip()
                # tcp/udp может быть включён по отдельности — берём то, что есть
                for proto_key, port_key in (("tcp", "tcp_port"), ("udp", "udp_port")):
                    port = hybrid_st.get(port_key)
                    if port:
                        endpoints.append({
                            "addr": addr, "port": int(port), "proto": proto_key.upper(),
                            "username": match, "password": users_by_name[match],
                            "client_dns": client_dns, "pattern_b64": pattern_b64,
                        })
        except Exception as e:
            _warn(f"Не удалось прочитать hybrid_mieru_state: {e}")

    # ── standalone mieru.py-аддон (параллельно с обычным VLESS) ────────
    if _MIERU_STATE.exists():
        try:
            st = json.loads(_MIERU_STATE.read_text())
            if st.get("installed"):
                users_by_name = {u["username"]: u["password"] for u in st.get("users", [])}
                match = _match_by_name(user, "mieru", users_by_name.keys())
                if match:
                    addr = (st.get("client_server_addr") or "").strip() or server_ip
                    client_dns = (st.get("client_dns") or "").strip()
                    # BOTH — отдельная точка на каждый транспорт
                    proto = (st.get("protocol") or "TCP").upper()
                    protos = ("TCP", "UDP") if proto == "BOTH" else (proto,)
                    pattern_b64 = ""
                    if st.get("traffic_preset"):
                        try:
                            from chimera.modules.mieru_traffic_presets import get_preset_base64
                            pattern_b64 = get_preset_base64(st.get("traffic_preset"))
                        except Exception:
                            pass
                    for p in protos:
                        endpoints.append({
                            "addr": addr, "port": int(st.get("port_start", 0)), "proto": p,
                            "username": match, "password": users_by_name[match],
                            "client_dns": client_dns, "pattern_b64": pattern_b64,
                        })
        except Exception as e:
            _warn(f"Не удалось прочитать mieru.json: {e}")

    return endpoints


def _collect_mieru_json_outbounds(user: dict, server_ip: str) -> tuple:
    """mieru-outbound'ы для singbox-подписки (nyamebox/nekobox/sing-box).

    Возвращает (outbounds, meta). outbounds — по одному на транспорт
    (hybrid both и standalone BOTH → и TCP, и UDP); tag уникален
    (суффикс -tcp/-udp при коллизии); addr — домен из state;
    traffic_pattern — blob/preset, если известен. meta = {client_dns,
    server_domain, first_tag} — для dns-секции конфига подписки."""
    meta = {"client_dns": "", "server_domain": "", "first_tag": ""}
    try:
        from chimera.modules.mieru import _gen_singbox_outbound, _dns_host_is_domain
    except ImportError:
        return [], meta
    endpoints = _mieru_client_endpoints(user, server_ip)
    if not endpoints:
        return [], meta

    used_tags: set = set()
    outbounds: list[dict] = []
    for ep in endpoints:
        ob = _gen_singbox_outbound(ep["addr"], ep["port"], ep["port"], ep["proto"],
                                    ep["username"], ep["password"])
        # теги sing-box обязаны быть уникальными: при двух транспортах
        # (или двух источниках) суффиксуем протоколом
        tag = ob["tag"]
        if tag in used_tags:
            tag = f"{tag}-{ep['proto'].lower()}"
            n = 2
            while tag in used_tags:
                tag = f"{ob['tag']}-{ep['proto'].lower()}-{n}"
                n += 1
        ob["tag"] = tag
        used_tags.add(tag)
        if ep["pattern_b64"]:
            ob["traffic_pattern"] = ep["pattern_b64"]
        if _dns_host_is_domain(ep["addr"]):
            ob["domain_resolver"] = "local"
        outbounds.append(ob)

    first = endpoints[0]
    meta["client_dns"] = next((e["client_dns"] for e in endpoints if e.get("client_dns")), "")
    meta["server_domain"] = first["addr"] if _dns_host_is_domain(first["addr"]) else ""
    meta["first_tag"] = outbounds[0]["tag"]
    return outbounds, meta

# ══════════════════════════════════════════════════════════════════════════
# NAIVEPROXY (тоже независимый клиентский протокол, свой users)
# ══════════════════════════════════════════════════════════════════════════

def _build_naive_uris(user: dict) -> list[str]:
    if not _NAIVE_STATE.exists():
        return []
    try:
        st = json.loads(_NAIVE_STATE.read_text())
        if not st.get("installed"):
            return []
        users_by_name = {u["username"]: u["password"] for u in st.get("users", [])}
        match = _match_by_name(user, "naive", users_by_name.keys())
        if not match:
            return []
        domain = st.get("domain", "")
        port = int(st.get("port", 443))
        password = users_by_name[match]
        import urllib.parse as _up
        return [f"naive+https://{_up.quote(match, safe='')}:{_up.quote(password, safe='')}@{domain}:{port}/"]
    except Exception as e:
        _warn(f"Не удалось прочитать naiveproxy.json: {e}")
        return []

# ══════════════════════════════════════════════════════════════════════════
# FPTN (самостоятельный L3 VPN, свой users.list — не Xray-inbound)
# ══════════════════════════════════════════════════════════════════════════

def _fptn_cert_md5_fingerprint() -> str:
    """Копия fptn._cert_md5_fingerprint() — не импортируем модуль целиком
    (у него своя интерактивная CLI и systemctl-вызовы), только эта чистая
    команда openssl нужна для сборки токена."""
    if not _FPTN_CERT_FILE.exists():
        return ""
    r = subprocess.run(
        ["openssl", "x509", "-noout", "-fingerprint", "-md5",
         "-in", str(_FPTN_CERT_FILE)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    out = (r.stdout or "").strip()
    if r.returncode != 0 or "=" not in out:
        return ""
    return out.split("=", 1)[1].replace(":", "").lower()

def _gen_fptn_token(username: str, password: str, server_ip: str,
                     service_name: str, port: int) -> str:
    md5_fp = _fptn_cert_md5_fingerprint()
    token_data = {
        "version": 1,
        "service_name": service_name,
        "username": username,
        "password": password,
        "servers": [{
            "name": service_name, "host": server_ip,
            "md5_fingerprint": md5_fp, "port": port,
        }],
        "censored_zone_servers": [],
    }
    json_str = json.dumps(token_data, separators=(",", ":"))
    b64 = base64.b64encode(json_str.encode("utf-8")).decode("utf-8").rstrip("=")
    return f"fptn:{b64}"

def _build_fptn_uris(user: dict, server_ip: str) -> list[str]:
    if not _FPTN_STATE.exists():
        return []
    try:
        st = json.loads(_FPTN_STATE.read_text())
        if not st.get("installed"):
            return []
        users_by_name = {u["username"]: u for u in st.get("users", [])}
        match = _match_by_name(user, "fptn", users_by_name.keys())
        if not match:
            return []
        u = users_by_name[match]
        port = int(st.get("port", 443))
        service_name = st.get("service_name", "MyFptnServer")
        host = st.get("server_ip") or server_ip
        return [_gen_fptn_token(match, u["password"], host, service_name, port)]
    except Exception as e:
        _warn(f"Не удалось прочитать fptn.json: {e}")
        return []

# ══════════════════════════════════════════════════════════════════════════
# СБОРКА ТЕЛА ПОДПИСКИ
# ══════════════════════════════════════════════════════════════════════════

def _find_user_by_token(token: str, pepper: str) -> Optional[dict]:
    for u in _load_all_users():
        if u.get("disabled"):
            continue
        uid = u.get("uuid", "")
        if uid and hmac.compare_digest(_token_for(uid, pepper), token):
            return u
    return None

# ══════════════════════════════════════════════════════════════════════════
# Subscription-Userinfo — остаток трафика в клиенте (v2rayNG/Clash/Happ/
# NekoBox читают этот заголовок и показывают юзеру расход/лимит прямо в
# приложении, без захода в свою учётку).
# ══════════════════════════════════════════════════════════════════════════

def _load_traffic_limits() -> dict:
    if not _TRAFFIC_LIMITS_FILE.exists():
        return {}
    try:
        return json.loads(_TRAFFIC_LIMITS_FILE.read_text())
    except Exception:
        return {}

def _build_userinfo_header(user: dict) -> Optional[str]:
    """Источник данных — traffic_limits.json, который уже ведёт _core.py
    (do_manage_traffic_limits / _check_traffic_limits_once, cron раз в 15
    мин). Здесь НИЧЕГО заново не запрашивается у Xray Stats API — только
    читается уже посчитанное значение, чтобы не гонять `xray api
    statsquery` на каждый HTTP-запрос подписки (клиенты дёргают её сами
    каждые Profile-Update-Interval часов, но открытых клиентов может быть
    много одновременно).

    traffic_limits.json хранит только суммарный used_bytes (up+down вместе,
    см. _query_user_traffic_bytes в _core.py) — раздельного up/down там нет,
    поэтому весь объём указывается как download, upload=0. Для того, как
    v2rayNG/Clash считают процент использования (upload+download к total),
    этого достаточно.

    Если лимит для пользователя не задан — возвращает None, а не
    total=0: часть клиентов трактует total=0 как "лимит исчерпан", это был
    бы неверный сигнал для пользователя без лимита вообще."""
    email = user.get("email", "")
    if not email:
        return None
    lim = _load_traffic_limits().get(email)
    if not lim or not lim.get("limit_gb"):
        return None
    used_bytes  = int(lim.get("used_bytes", 0))
    total_bytes = int(lim.get("limit_gb", 0)) * 1024 ** 3
    return f"upload=0; download={used_bytes}; total={total_bytes}"

# ── Реестр сателлитных протоколов для единой подписки ──────────────────────
#
# Протоколы, которые экспортируют get_subscription_uris(user: dict) -> list[str].
# Добавление нового протокола в подписку = ОДНА строка в этом списке.
# Модуль должен импортироваться без side effects и иметь функцию
# get_subscription_uris, которая никогда не бросает исключение.
#
# v4.25: реестр расширен с 2 до 5 протоколов. Теперь подписка включает
# ВСЕ синхронизируемые спутниковые протоколы (кроме тех что уже hardcoded
# ниже: Telemt/Mieru/NaiveProxy/FPTN — они в build_subscription_body
# напрямую через _build_*_uris функции).
#
# Hardcoded в build_subscription_body (НЕ в этом реестре):
#   • VLESS (всегда, через _build_vless_uri)
#   • Telemt/MTProto (через _build_telemt_uri)
#   • Mieru (через _build_mieru_uris)
#   • NaiveProxy (через _build_naive_uris)
#   • FPTN (через _build_fptn_uris)
#
# В реестре (v4.25):
#   • trusttunnel      — tt:// deep-link
#   • singbox_menu     — trojan://, anytls://, tuic://, vless:// (WS-CDN)
#   • wdtt             — qwdtt:// (WireGuard-over-TURN, по owner_email)
#   • awg_peers        — vpn:// (Amnezia VPN deep-link, по owner_email)
#   • hysteria2_sync   — hysteria2:// (shared password, одинакова для всех)
_SUBSCRIBABLE_PROTOCOLS = [
    "chimera.modules.trusttunnel",
    "chimera.modules.singbox_menu",
    "chimera.modules.wdtt",
    "chimera.modules.csqtt",
    "chimera.modules.awg_peers",
    "chimera.modules.hysteria2_sync",
]


def _collect_registry_uris(user: dict) -> list[str]:
    """Вызывает get_subscription_uris(user) на каждом модуле из реестра.

    Возвращает плоский список URI. Если модуль недоступен (ImportError)
    или его функция бросает исключение — логирует и продолжает, не роняя
    остальные протоколы.
    """
    import importlib
    links: list[str] = []
    for modpath in _SUBSCRIBABLE_PROTOCOLS:
        try:
            mod = importlib.import_module(modpath)
            uris = mod.get_subscription_uris(user)
            if uris:
                links.extend(uris)
        except ImportError:
            pass  # модуль не установлен — нормально
        except Exception as e:
            _log("WARN", f"{modpath} недоступен для подписки: {e}")
    return links


# ── Content negotiation: ?format= / User-Agent → формат подписки ────────────
#
# Поддерживаемые форматы:
#   "base64" (default) — текущее поведение: Base64-список share-links.
#   "singbox"           — полный sing-box JSON config с outbounds
#                         (мульти-нодовый в Mode B: selector + urltest).
#   "clash"             — полный mihomo/Clash Meta YAML (мульти-нодовый:
#                         группы Выбор/Auto/Fallback/Balance + правила).
#   "base64_safe"       — Base64-список БЕЗ naive+https:// и mierus://
#                         (для клиентов, которые не умеют их парсить).
#
# Определение формата:
#   1. Явный ?format=singbox в URL — высший приоритет.
#   2. Эвристика по User-Agent (словарь, легко расширяется).
#   3. Дефолт: "base64" (100% обратная совместимость).
#
# User-Agent сигнатуры (подстрока в lowercased UA → формат):
_UA_FORMAT_MAP = {
    "nekobox": "singbox",
    "nyamebox": "singbox",
    "sing-box": "singbox",
    "karing": "base64_safe",
    "clash": "clash",
    "mihomo": "clash",
    "flclash": "clash",
    "stash": "clash",
    "clashx": "clash",
}


def _resolve_format(requested: str, user_agent: str) -> str:
    """Определяет формат подписки: ?format= > User-Agent > 'base64'.

    Parameters:
      requested — значение query-параметра ?format= (может быть пустым).
      user_agent — заголовок User-Agent (может быть пустым).

    Returns: 'base64' | 'singbox' | 'clash' | 'base64_safe'
    """
    # 1. Явный параметр — высший приоритет.
    if requested:
        fmt = requested.lower().strip()
        if fmt in ("singbox", "sing-box", "json"):
            return "singbox"
        if fmt in ("clash", "mihomo", "meta", "clashmeta", "yaml"):
            return "clash"
        if fmt in ("safe", "base64_safe", "base64safe"):
            return "base64_safe"
        if fmt in ("auto", "default", "base64"):
            return "base64"
    # 2. Эвристика по User-Agent.
    ua = (user_agent or "").lower()
    for ua_substring, fmt in _UA_FORMAT_MAP.items():
        if ua_substring in ua:
            return fmt
    # 3. Дефолт.
    return "base64"


def _collect_registry_json_outbounds(user: dict) -> list[dict]:
    """Вызывает get_subscription_json_outbound(user) на каждом модуле из реестра.

    Каждый модуль может (опционально) экспортировать функцию
    get_subscription_json_outbound(user: dict) -> Optional[dict | list[dict]]
    — возвращает sing-box outbound JSON (dict) или список outbound'ов.
    Если функция отсутствует или возвращает None — протокол пропускается.

    Возвращает плоский список outbound-объектов.
    """
    import importlib
    outbounds: list[dict] = []
    for modpath in _SUBSCRIBABLE_PROTOCOLS:
        try:
            mod = importlib.import_module(modpath)
            fn = getattr(mod, "get_subscription_json_outbound", None)
            if fn is None:
                continue
            result = fn(user)
            if result is None:
                continue
            if isinstance(result, list):
                outbounds.extend(result)
            elif isinstance(result, dict):
                outbounds.append(result)
        except ImportError:
            pass
        except Exception as e:
            _log("WARN", f"{modpath}.get_subscription_json_outbound: {e}")
    return outbounds


def build_subscription_singbox_config(user: dict) -> str:
    """Собирает полный sing-box JSON config для пользователя.

    Включает:
      - VLESS outbound (Reality/xHTTP) — из rest_api._generate_singbox_config
      - Все sing-box протоколы (ShadowTLS/AnyTLS/TUIC/VLESS-WS-CDN) —
        через _collect_registry_json_outbounds
      - TrustTunnel outbound — через реестр
      - direct + block outbounds
      - Базовый route с final на первый outbound

    Возвращает JSON-строку (indent=2, ensure_ascii=False).
    """
    import json as _json

    outbounds: list[dict] = []

    # 1. VLESS outbound — переиспользуем логику из rest_api.
    # в hybrid-режиме внешний вход ушёл с VLESS на Mieru (SOCKS-петля
    # 127.0.0.1) — такой outbound снаружи мёртв. Исключаем, паритет с
    # base64-подпиской (is_hybrid_mieru_active там делает то же самое).
    vless_outbounds: list[dict] = []
    if not is_hybrid_mieru_active():
        try:
            from chimera.modules.rest_api import _generate_singbox_config
            vless_json = _generate_singbox_config(user)
            if vless_json:
                vless_cfg = _json.loads(vless_json)
                for ob in vless_cfg.get("outbounds", []):
                    vless_outbounds.append(ob)
        except Exception as e:
            _log("WARN", f"VLESS singbox outbound: {e}")
    outbounds.extend(vless_outbounds)

    # 2. Сателлитные протоколы через реестр.
    registry_outbounds = _collect_registry_json_outbounds(user)
    outbounds.extend(registry_outbounds)

    # 2.5 mieru-outbound'ы (TCP и UDP — отдельными нодами) — раньше
    # mierus:// жил только в base64-формате, а nyamebox/nekobox/sing-box
    # (format=singbox) mieru не получали вовсе. Адрес — домен из state,
    # traffic-pattern — blob/preset, домен резолвится через domain_resolver.
    _st = _load_state() or {}
    _srv = _get_server_ip("4") or _st.get("domain", "")
    mieru_outbounds, mieru_meta = _collect_mieru_json_outbounds(user, _srv)
    outbounds.extend(mieru_outbounds)

    # 3. Direct + block (базовые outbounds).
    if outbounds:
        outbounds.append({"type": "direct", "tag": "direct"})
        outbounds.append({"type": "block", "tag": "block"})
    else:
        # Нет ни одного outbound — возвращаем минимальный direct-only.
        outbounds.append({"type": "direct", "tag": "direct"})

    config = {
        "log": {"level": "warn"},
        "outbounds": outbounds,
        "route": {
            "final": outbounds[0].get("tag", "direct"),
        },
    }

    # 3.5 DNS-секция — ТОЛЬКО когда mieru есть, client_dns задан
    # и других прокси-outbound'ов нет. В смешанной конфигурации (VLESS+mieru
    # в standalone) DNS через mieru создавал бы зависимость: mieru упал —
    # и VLESS-домен перестал бы резолвиться. Чистый hybrid-профиль (mieru —
    # единственный вход) получает свой AGH через туннель, как в Karing-JSON.
    if mieru_outbounds and mieru_meta["client_dns"] \
            and not (vless_outbounds or registry_outbounds):
        try:
            from chimera.modules.mieru import _build_karing_dns_block
            config["dns"] = _build_karing_dns_block(
                mieru_meta["client_dns"], mieru_meta["first_tag"],
                mieru_meta["server_domain"])
        except Exception as e:
            _log("WARN", f"mieru dns block: {e}")

    # singbox_client_rulesets: опциональная инъекция route.rule_set + rules
    # с готовыми .srs-списками для Podkop/OpenWrt (РФ-домены → direct,
    # заблокированные → proxy). По умолчанию ВЫКЛЮЧЕНО — обратная совместимость
    # 100%: без этой опции конфиг остаётся таким же, как до патча.
    # См. chimera/modules/singbox_client_rulesets.py
    try:
        from chimera.modules.singbox_client_rulesets import inject_route_rulesets
        inject_route_rulesets(config, outbounds[0].get("tag", "vless-out"))
    except Exception as _e:
        _log("WARN", f"singbox_client_rulesets.inject failed: {_e}")

    # mieru_dpi (режим «Mieru + B4»): route-правила доменов b4-сетов →
    # mieru-outbound. Вставляются ПОВЕРХ правил inject_route_rulesets
    # (prepend): domain_suffix-правила кастомных ресурсов закреплены
    # админом и приоритетнее geosite-категорий rulesets.
    if mieru_outbounds:
        try:
            from chimera.modules import mieru_dpi
            if mieru_dpi.is_mieru_dpi_active():
                _md_rules = mieru_dpi.build_mieru_route_rules(
                    [ob["tag"] for ob in mieru_outbounds],
                    mieru_dpi.get_route_domains())
                if _md_rules:
                    _route = config.setdefault("route", {})
                    _existing = _route.get("rules") or []
                    _route["rules"] = _md_rules + _existing
        except Exception as _e:
            _log("WARN", f"mieru_dpi route rules: {_e}")

    return _json.dumps(config, indent=2, ensure_ascii=False)


def _filter_safe_links(links: list[str]) -> list[str]:
    """Убирает из списка ссылок те, что не распознаются большинством клиентов.

    naive+https://, mierus://, qwdtt://, vpn:// — нестандартные share-link
    форматы, которые Karing и некоторые другие клиенты не умеют парсить.
    При format=base64_safe они исключаются.

    vless://, trojan://, anytls://, tuic://, tt://, hysteria2:// —
    поддерживаются (стандартные или широко имплементированные).
    """
    filtered = []
    for link in links:
        if link.startswith("naive+https://"):
            continue
        if link.startswith("mierus://"):
            continue
        if link.startswith("qwdtt://"):
            continue  # qWDTT — только Android APK, не стандартный share-link
        if link.startswith("csqtt://"):
            continue  # CSQTT — только Android APK, не стандартный share-link
        if link.startswith("vpn://"):
            continue  # Amnezia VPN deep-link — только Amnezia Client
        filtered.append(link)
    return filtered


def build_subscription_body(user: dict) -> bytes:
    state = _load_state() or {}
    ipv4  = _get_server_ip("4")

    links: list[str] = []

    # vless:// — только если hybrid_addon не увёл внешний inbound на Mieru
    if not is_hybrid_mieru_active():
        vless = _build_vless_uri(user, state)
        if vless:
            links.append(vless)
    else:
        _log("INFO", "hybrid_mieru активен — vless:// исключён из подписки")

    # Мульти-нодовые exit-ноды (Mode B): vless:// каждой exit со своим
    # chain-UUID — клиенты (v2rayNG/Happ/NekoBox) сами сгруппируют и дадут
    # выбор/авто-переключение. См. subscription_multinode.get_multinode_uris.
    if _mn is not None:
        try:
            links += _mn.get_multinode_uris(user)
        except Exception as e:
            _log("WARN", f"multinode uris: {e}")

    links += _build_mieru_uris(user, ipv4 or state.get("domain", ""))
    links += _build_naive_uris(user)
    links += _build_fptn_uris(user, ipv4 or state.get("domain", ""))

    telemt = _build_telemt_uri(user, ipv4 or state.get("domain", ""))
    if telemt:
        links.append(telemt)

    # Реестр сателлитных протоколов: TrustTunnel, sing-box (ShadowTLS,
    # AnyTLS, TUIC, VLESS-WS-CDN) и любые будущие через единый интерфейс
    # get_subscription_uris(user) -> list[str].
    links += _collect_registry_uris(user)

    # Резервные entry-ноды (см. entry_mirrors.py) — опционально, для
    # клиент-сайд auto-failover если основной entry заблокируют/забанят.
    uuid_str = user.get("uuid", "")
    if uuid_str:
        try:
            from chimera.modules.entry_mirrors import get_mirror_uris
            links += get_mirror_uris(uuid_str, only_healthy=True)
        except Exception as e:
            _log("WARN", f"entry_mirrors недоступен: {e}")

    payload = "\n".join(links)
    return base64.b64encode(payload.encode())


def build_subscription_body_ios(user: dict) -> bytes:
    """iOS/Karing-совместимый вариант тела подписки.

    Копия структуры build_subscription_body(), но:
      • vless:// строится на shadow-UUID (через
        _users_get_or_create_ios_shadow), НЕ на user["uuid"]. Это та же
        защита от рассинхрона, что в do_user_show_link_ios_by_uuid
        (патч №3): email берётся напрямую из clients[] по user["uuid"],
        и если он не совпадает с тем, что в users.json — shadow всё
        равно создаётся/переиспользуется правильно.
      • Mirror-URI (entry_mirrors) ИСКЛЮЧАЮТСЯ из iOS-подписки ЦЕЛИКОМ.
        Mirror-серверы — это отдельные инстансы того же инсталлятора на
        других VPS, чьи clients[] этот модуль не редактирует. Заводить
        там shadow программно нельзя — только руками на каждом mirror.
        Постпроцессор на клиентской строке mirror-ссылки без shadow на
        СЕРВЕРЕ mirror'а даст тот же разрыв хендшейка, который мы чиним
        весь этот раунд.
      • Сателлитные протоколы (mieru/naive/fptn/telemt) НЕ трогаются —
        в их ссылках нет ни `&flow=xtls-rprx-vision`, ни эмодзи-флага в
        начале fragment.

    Существующая build_subscription_body() НЕ трогается — старый
    маршрут /sub/{token} возвращает побайтово тот же base64, что и до
    патча (защищено отдельным регрессионным тестом).
    """
    from chimera.modules.ios_link_variant import to_ios_karing_link

    state = _load_state() or {}
    ipv4  = _get_server_ip("4")

    links: list[str] = []

    # ── vless:// на shadow-UUID ───────────────────────────────────────────
    # _build_vless_uri(user, state) берёт user["uuid"] напрямую — это
    # оригинальный UUID, для которого серверная clients[] хранит
    # "flow": "xtls-rprx-vision". Создаём shadow (без flow) и подменяем
    # user dict перед вызовом, чтобы ссылка строилась на shadow UUID.
    # Та же логика, что в do_user_show_link_ios_by_uuid (патч №3).
    if not is_hybrid_mieru_active():
        proto = state.get("protocol_mode", "reality")
        if proto == "reality":
            # Резолвим shadow — email из живого clients[], не из user dict.
            shadow_user = _resolve_ios_shadow_user(user)
            vless = _build_vless_uri(shadow_user, state)
        elif proto == "xhttp_reality":
            # xHTTP+REALITY — серверные clients[] БЕЗ flow (xhttp-транспорт
            # не поддерживает vision), shadow не нужен: ссылка строится
            # на оригинальном UUID, трансформация to_ios_karing_link()
            # вырезания flow не заметит (его нет в ссылке).
            vless = _build_vless_uri(user, state)
        else:
            # xHTTP — flow не используется, shadow не нужен.
            vless = _build_vless_uri(user, state)
        if vless:
            links.append(to_ios_karing_link(vless))
    else:
        _log("INFO", "hybrid_mieru активен — vless:// исключён из iOS-подписки")

    # Сателлитные протоколы — БЕЗ трансформации (фиксируется тестом).
    links += _build_mieru_uris(user, ipv4 or state.get("domain", ""))
    links += _build_naive_uris(user)
    links += _build_fptn_uris(user, ipv4 or state.get("domain", ""))

    telemt = _build_telemt_uri(user, ipv4 or state.get("domain", ""))
    if telemt:
        links.append(telemt)

    # Реестр сателлитных протоколов (TrustTunnel, sing-box протоколы).
    links += _collect_registry_uris(user)

    # ── Mirror-URI ИСКЛЮЧАЮТСЯ из iOS-подписки ────────────────────────────
    # Mirror-серверы — отдельные инстансы, их clients[] мы не контролируем.
    # На каждом mirror админ должен отдельно выполнить
    # do_unified_user_manager → 1 → K для нужных пользователей, иначе
    # постпроцессор отрежет flow, а сервер mirror'а его ждёт — разрыв.
    # Логируем количество исключённых, чтобы админ видел, сколько mirror
    # требует ручной настройки.
    uuid_str = user.get("uuid", "")
    excluded_mirrors = 0
    if uuid_str:
        try:
            from chimera.modules.entry_mirrors import get_mirror_uris
            mirror_uris = get_mirror_uris(uuid_str, only_healthy=True)
            excluded_mirrors = len(mirror_uris)
            if excluded_mirrors > 0:
                _log("WARN",
                     f"iOS-подписка: {excluded_mirrors} mirror-ссылок исключены — "
                     "требуют ручной настройки shadow-клиента на каждом mirror "
                     "(do_unified_user_manager → 1 → K)")
        except Exception as e:
            _log("WARN", f"entry_mirrors недоступен: {e}")

    # ── Мульти-нодовые exit-URI ИСКЛЮЧАЮТСЯ из iOS-подписки ────────
    # Exit-ноды — отдельные серверы со своими chain-UUID; заводить там
    # shadow-клиенты программно нельзя (та же причина, что и для mirrors:
    # clients[] на exit-серверах этот модуль не редактирует). Ссылка без
    # shadow с постпроцессором Karing дала бы разрыв хендшейка.
    if _mn is not None:
        try:
            _excluded_mn = len(_mn.get_multinode_uris(user))
            if _excluded_mn > 0:
                _log("WARN",
                     f"iOS-подписка: {_excluded_mn} exit-нод исключены — прямые "
                     "ссылки требуют shadow-клиента на каждом exit; в iOS-"
                     "подписке доступен только каскад через entry")
        except Exception as e:
            _log("WARN", f"multinode ios check: {e}")

    payload = "\n".join(links)
    return base64.b64encode(payload.encode())


def _resolve_ios_shadow_user(user: dict) -> dict:
    """Возвращает копию user dict с подменённым uuid/email на shadow-значения.

    Логика та же, что в do_user_show_link_ios_by_uuid (патч №3):
      1. Найти client в config.json по user["uuid"].
      2. Взять email напрямую из clients[] (защита от рассинхрона
         с users.json — там может быть устаревший email).
      3. Вызвать _users_get_or_create_ios_shadow(cfg, email).
      4. Если shadow создан — вернуть {**user, "uuid": shadow_uuid,
         "email": shadow_email}.
      5. Если что-то пошло не так — вернуть user без изменений (fallback).
         Ссылка будет с оригинальным UUID и flow — постпроцессор отрежет
         flow, но это всё ещё может работать на iOS, если баг Karing#1158
         не воспроизводится. Лучше так, чем уронить подписку.

    Не использует _core_module() напрямую — импортирует users_manager
    по требованию (как и остальной код subscription.py).
    """
    try:
        from chimera.modules.users_manager import (
            _users_get_config, _users_get_or_create_ios_shadow,
        )
        cfg_path = _users_get_config()
        with cfg_path.open() as f:
            c = json.load(f)
        clients = (c.get("inbounds", [{}])[0]
                   .get("settings", {}).get("clients", []))
        orig_uuid = user.get("uuid", "")
        base = next((cl for cl in clients if cl.get("id", "") == orig_uuid), None)
        if not base or not base.get("email"):
            _log("WARN", f"iOS-подписка: UUID '{orig_uuid[:8]}…' не найден в "
                 "clients[] или нет email — используется оригинальный UUID")
            return user
        shadow = _users_get_or_create_ios_shadow(cfg_path, base["email"])
        if shadow is None:
            return user
        shadow_uuid, shadow_email = shadow
        return {**user, "uuid": shadow_uuid, "email": shadow_email}
    except Exception as e:
        _log("WARN", f"iOS-подписка: не удалось создать shadow для "
             f"{user.get('email', '?')}: {e} — используется оригинальный UUID")
        return user

# ══════════════════════════════════════════════════════════════════════════
# HTTP(S)-ХЕНДЛЕР
# ══════════════════════════════════════════════════════════════════════════

class _SubHandler(BaseHTTPRequestHandler):
    server_version = "chimera-sub/1.0"

    def log_message(self, fmt, *args):  # тише в journalctl, пишем в свой лог
        _log("ACCESS", f"{self.client_address[0]} {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        user_agent = self.headers.get("User-Agent", "")

        # iOS/Karing-маршрут — проверяем ПЕРВЫМ. Существующий regex
        # ^/sub/([0-9a-f]{24})/?$ физически не матчит `/sub/{token}/ios`
        # (там после 24 hex идёт `/ios`, а `$` требует конца), так что
        # даже если бы мы поставили старую проверку первой, конфликтов
        # не было бы — но логичнее держать более специфичный маршрут
        # выше. Существующая ветка ниже — не тронута.
        m_ios = re.match(r"^/sub/([0-9a-f]{24})/ios/?$", path)
        if m_ios:
            cfg = _load_sub_conf()
            pepper = cfg.get("pepper", "")
            if not pepper:
                self.send_response(503)
                self.end_headers()
                return
            token = m_ios.group(1)
            user = _find_user_by_token(token, pepper)
            if not user:
                self.send_response(404)
                self.end_headers()
                return
            body = build_subscription_body_ios(user)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Profile-Update-Interval", "6")
            self.send_header("Profile-Title", "Chimera-iOS")
            userinfo = _build_userinfo_header(user)
            if userinfo:
                self.send_header("Subscription-Userinfo", userinfo)
            self.end_headers()
            self.wfile.write(body)
            return

        # Существующая ветка — с content negotiation.
        m = re.match(r"^/sub/([0-9a-f]{24})/?$", path)
        if not m:
            self.send_response(404)
            self.end_headers()
            return

        cfg = _load_sub_conf()
        pepper = cfg.get("pepper", "")
        if not pepper:
            self.send_response(503)
            self.end_headers()
            return

        token = m.group(1)
        user = _find_user_by_token(token, pepper)
        if not user:
            self.send_response(404)
            self.end_headers()
            return

        # Content negotiation: ?format= > User-Agent > base64 (default).
        fmt_param = (query.get("format", [""])[0] or "").strip()
        fmt = _resolve_format(fmt_param, user_agent)

        if fmt == "singbox":
            # Полный sing-box JSON config. В Mode B (мульти-нод активна) —
            # все ноды + selector «🎯 Chimera» + urltest «auto»; иначе —
            # старый single-outbound конфиг (100% обратная совместимость).
            body_str = ""
            if _mn is not None and _mn.is_multinode_active():
                try:
                    body_str = _mn.build_singbox_config(
                        user, extra_outbounds=_collect_registry_json_outbounds(user))
                except Exception as e:
                    _log("WARN", f"multinode singbox build: {e}")
            if not body_str:
                body_str = build_subscription_singbox_config(user)
            body = body_str.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Profile-Update-Interval", "6")
            self.send_header("Profile-Title", "Chimera-singbox")
            userinfo = _build_userinfo_header(user)
            if userinfo:
                self.send_header("Subscription-Userinfo", userinfo)
            self.end_headers()
            self.wfile.write(body)
            return

        if fmt == "clash":
            # Полный mihomo/Clash Meta YAML (мульти-нодовый в Mode B:
            # группы Выбор/Auto/Fallback/Balance + правила по эталону).
            # Fallback на single-proxy YAML из rest_api — если нод нет.
            clash_body = ""
            if _mn is not None:
                try:
                    clash_body = _mn.build_mihomo_config(user)
                except Exception as e:
                    _log("WARN", f"multinode clash build: {e}")
            if not clash_body:
                try:
                    from chimera.modules.rest_api import _generate_clash_config
                    clash_body = _generate_clash_config(user)
                except Exception as e:
                    _log("WARN", f"clash fallback build: {e}")
            if not clash_body:
                self.send_response(503)
                self.end_headers()
                return
            body = clash_body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Profile-Update-Interval", "6")
            self.send_header("Profile-Title", "Chimera-mihomo")
            userinfo = _build_userinfo_header(user)
            if userinfo:
                self.send_header("Subscription-Userinfo", userinfo)
            self.end_headers()
            self.wfile.write(body)
            return

        # base64 или base64_safe — текущее поведение (возможно с фильтром).
        body = build_subscription_body(user)
        if fmt == "base64_safe":
            # Декодируем, фильтруем, кодируем обратно.
            import base64 as _b64
            decoded = body.decode("utf-8")
            links = decoded.split("\n")
            links = _filter_safe_links(links)
            body = _b64.b64encode("\n".join(links).encode())
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Стандартный заголовок для авто-обновления подписки в клиентах
        # (Happ/NekoBox/v2rayN его читают) — раз в 6 часов достаточно,
        # т.к. тело и так генерируется на лету без кеша.
        self.send_header("Profile-Update-Interval", "6")
        self.send_header("Profile-Title", "Chimera")
        userinfo = _build_userinfo_header(user)
        if userinfo:
            # v2rayNG/Clash/Happ/NekoBox читают это и показывают остаток
            # трафика прямо в приложении — см. _build_userinfo_header().
            self.send_header("Subscription-Userinfo", userinfo)
        self.end_headers()
        self.wfile.write(body)


def _find_cert_pair(domain: str) -> tuple[Optional[str], Optional[str]]:
    """Пытаемся переиспользовать уже выпущенный на этот домен сертификат —
    сначала Let's Encrypt (certbot), потом сертификат Hysteria2 из state.json.
    Отдельный сертификат подписка не выпускает."""
    le_dir = Path(f"/etc/letsencrypt/live/{domain}")
    if (le_dir / "fullchain.pem").exists() and (le_dir / "privkey.pem").exists():
        return str(le_dir / "fullchain.pem"), str(le_dir / "privkey.pem")

    state = _load_state() or {}
    h2 = state.get("hysteria2", {}) or {}
    cert = h2.get("cert", {}) or {}
    crt, key = cert.get("crt"), cert.get("key")
    if crt and key and Path(crt).exists() and Path(key).exists():
        return crt, key

    return None, None


def serve(port: int = DEFAULT_PORT) -> None:
    cfg = _load_sub_conf()
    if not cfg.get("enabled"):
        _err("Подписка выключена в конфиге — включите через `menu`.")
        sys.exit(1)
    _ensure_pepper(cfg)

    state = _load_state() or {}
    domain = state.get("domain", "")
    certfile, keyfile = _find_cert_pair(domain)

    # SUB_LISTEN_HOST из окружения — для переключения 0.0.0.0 ↔ 127.0.0.1
    # без правки кода. Когда nginx front включён (через _sub_backend_bind_loopback),
    # unit-файл прокидывает SUB_LISTEN_HOST=127.0.0.1 — backend слушает loopback,
    # а наружу торчит только nginx с TLS. Когда выключён — переменной нет, дефолт 0.0.0.0.
    listen_host = os.environ.get("SUB_LISTEN_HOST", "0.0.0.0")

    httpd = ThreadingHTTPServer((listen_host, port), _SubHandler)
    if certfile and keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        _ok(f"TLS: {certfile}")
    else:
        _warn("Сертификат не найден — подписка отдаётся по HTTP (без TLS). "
              "Поставьте сертификат Let's Encrypt на домен или проксируйте через nginx с TLS.")

    _ok(f"Слушаю {listen_host}:{port} …")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


# ══════════════════════════════════════════════════════════════════════════
# SYSTEMD UNIT
# ══════════════════════════════════════════════════════════════════════════

def _unit_text(python_bin: str, module_path: str, port: int) -> str:
    return (
        "[Unit]\n"
        "Description=Chimera unified subscription endpoint\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        f"ExecStart={python_bin} -m chimera.modules.subscription serve {port}\n"
        f"WorkingDirectory={module_path}\n"
        "Restart=always\n"
        "RestartSec=3\n"
        "StartLimitBurst=10\n"
        "StartLimitIntervalSec=60\n"
        "User=root\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "PrivateTmp=true\n"
        "ReadWritePaths=/var/lib/xray-installer /var/log\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

_NGINX_SNIPPET_TEMPLATE = (
    "# vless-subscription — включить одной строкой внутри существующего\n"
    "# `server {{ listen 443 ssl; ... }}` для домена:\n"
    "#   include /etc/nginx/snippets/vless-subscription.conf;\n"
    "location /sub/ {{\n"
    "    proxy_pass https://127.0.0.1:{port};\n"
    "    proxy_ssl_verify off;\n"
    "    proxy_set_header Host $host;\n"
    "}}\n"
)

def _nginx_snippet_text(port: int) -> str:
    """Build the nginx snippet for the given port (was hardcoded to 8443)."""
    return _NGINX_SNIPPET_TEMPLATE.format(port=port)

def _fw_open_tcp(port: int) -> str:
    """Открывает TCP-порт подписки в файрволе. ufw, если активен (как
    делает основной инсталлятор в _core.py) — иначе raw iptables fallback.
    Возвращает использованный инструмент ('ufw' / 'iptables' / '' при неудаче).

     миграция на port_registry (с backward compat fallback).
    """
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_SUBSCRIPTION,
        )
        port_register(SERVICE_SUBSCRIPTION, port, "tcp",
                      comment="vless-subscription", force=True)
        ok, msg = ufw_open_port(port, "tcp", SERVICE_SUBSCRIPTION,
                                comment="vless-subscription")
        if ok:
            return "ufw"
        # ufw_open_port вернул False — продолжаем fallback ниже.
    except Exception:
        pass
    if shutil.which("ufw"):
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=False)
        if "Status: active" in (r.stdout or ""):
            already = re.search(rf'^{port}/tcp\b.*ALLOW', r.stdout or "", re.MULTILINE)
            if not already:
                subprocess.run(
                    ["ufw", "allow", f"{port}/tcp", "comment", "vless-subscription"],
                    check=False,
                )
            return "ufw"
    if shutil.which("iptables"):
        chk = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
            capture_output=True, check=False,
        )
        if chk.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                check=False,
            )
        return "iptables"
    return ""


def _fw_close_tcp(port: int) -> None:
    """Закрывает TCP-порт, ранее открытый _fw_open_tcp.

    Идемпотентно: если правило уже удалено (или никогда не существовало),
    ufw пишет в stderr 'Could not delete non-existent rule' — мы глушим
    stderr/stdout чтобы не пугать пользователя. Это нормально для сценариев
    вроде stop[4] → uninstall[6]: stop уже закрыл порт, uninstall пытается
    закрыть его снова.

     миграция на port_registry (с legacy comment backward compat).
    """
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister, SERVICE_SUBSCRIPTION,
        )
        ufw_close_port(port, "tcp", SERVICE_SUBSCRIPTION,
                       legacy_comments=["vless-subscription"])
        port_unregister(SERVICE_SUBSCRIPTION, port, "tcp")
    except Exception:
        pass
    if shutil.which("ufw"):
        # ufw delete allow <port>/tcp — неинтерактивный (правило задано явно).
        # stderr подавляем: 'Could not delete non-existent rule' — это шум,
        # не ошибка. stdout тоже — 'Rule deleted' уже после stop неинформативно.
        subprocess.run(
            ["ufw", "delete", "allow", f"{port}/tcp"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if shutil.which("iptables"):
        for _ in range(5):
            chk = subprocess.run(
                ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                capture_output=True, check=False,
            )
            if chk.returncode != 0:
                break
            subprocess.run(
                ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                check=False,
            )


def _install_service(port: int) -> bool:
    try:
        python_bin = sys.executable
        repo_root  = str(Path(__file__).resolve().parents[2])
        _UNIT_PATH.write_text(_unit_text(python_bin, repo_root, port))
        _NGINX_SNIP.parent.mkdir(parents=True, exist_ok=True)
        _NGINX_SNIP.write_text(_nginx_snippet_text(port))
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        # Clear any prior start-limit-hit failure so `restart` is not refused.
        # Without this, `enable --now` (or `start`) is silently rejected by
        # systemd when the unit is in failed state — which is why menu [1]
        # alone couldn't recover from a port-bind crash (e.g. TrustTunnel on
        # the same port). The user had to run [4] (stop/disable) first to
        # clear the failed state, then [1]. Now [1] is self-healing.
        #
        # stderr подавляем: на свеже-установленной системе (unit никогда не
        # был загружен) `reset-failed` падает с 'Unit ... not loaded.' — это
        # шум, не ошибка. После `daemon-reload` выше unit загружается в
        # память systemd, но если он никогда не был в failed-состоянии,
        # `reset-failed` всё равно пишет это сообщение. Глушим.
        subprocess.run(
            ["systemctl", "reset-failed", SERVICE_NAME],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Unmask before enable — item [4] (Выключить сервис) может
        # замаскировать unit (если mask succeed). Если юзер потом запускает
        # [1] без unmask, `systemctl enable` молча игнорирует (unit symlink
        # to /dev/null). Та же логика что в rest_api.do_manage_web_panel()
        # item '1' run branch.
        subprocess.run(["systemctl", "unmask", SERVICE_NAME], check=False)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], check=True)
        # `restart` (not `start`) so a unit-file change (new port, new cert)
        # takes effect even if the service is already running on the old port.
        subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True)
        return True
    except Exception as e:
        _err(f"Не удалось установить сервис: {e}")
        return False


def _kill_port_holder(port: int) -> bool:
    """Fallback: если systemd-управление не убило процесс (старый systemd,
    процесс запущен вручную через `python3 -m chimera.modules.subscription
    serve`, mask не сработал и т.п.) — найти PID через `ss -tlnp` и убить
    через `kill -9`.

    Возвращает True если процесс был найден и убит, иначе False.
    Та же логика что и в rest_api.uninstall_web_service() — см. commit
    e830f28 'fix(rest_api): mask+stop+kill for reliable web panel uninstall'.

    ВАЖНО: парсим ТОЛЬКО строку с `:port` — `re.finditer(r'pid=(\\d+)',
    весь_вывод)` матчит ВСЕ pid= в выводе ss (включая sshd, xray и т.д.),
    что убило бы посторонние процессы. Ищем строку вида
    `0.0.0.0:8443 ... users:((\"python3\",pid=4966,fd=3))` и достаём PID
    только из неё.
    """
    try:
        r = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0 or not r.stdout:
            return False
        # Ищем СТРОКУ с нашим портом. На одной строке — Local Address:Port
        # и (опционально) users:((...pid=N...)). Бывает несколько строк с
        # одним портом (IPv4 + IPv6) — обрабатываем все.
        port_str = f":{port}"
        killed = False
        for line in r.stdout.splitlines():
            if port_str not in line:
                continue
            # В этой строке ищем pid=N. Может быть несколько processes
            # (multi-process bind — редко, но возможно).
            for m in re.finditer(r'pid=(\d+)', line):
                pid = int(m.group(1))
                if pid <= 1:
                    continue  # не убиваем init
                subprocess.run(["kill", "-9", str(pid)], check=False)
                _info(f"Убит процесс PID={pid} (держал порт :{port})")
                killed = True
        return killed
    except Exception as e:
        _warn(f"Не удалось убить процесс на порту {port}: {e}")
        return False


def _stop_service_reliable() -> None:
    """Останавливает сервис vless-subscription НАДЁЖНО — без перезапуска.

    ВАЖНО о mask: первоначальный фикс (mirror rest_api commit e830f28)
    использовал `systemctl mask` перед stop, но mask ПАДАЕТ с 'Failed to
    mask unit: File ... already exists.' на новом systemd (≥252), если
    unit-файл — обычный файл, а не symlink. Mask задуман как создание
    symlink → /dev/null, но не перезаписывает существующий файл без --force.

    Оказалось, что mask вообще НЕ НУЖЕН для временной остановки (item [4]):
    согласно systemd.service(5), `systemctl stop` ЯВНО игнорирует Restart=:
      > If a service is stopped via systemctl stop, the Restart= setting
      > is ignored and the service is not restarted.
    Restart= срабатывает только когда процесс падает САМ (crash, OOM, signal
    от ядрa) — но НЕ когда systemd его останавливает по явной команде stop.

    Поэтому правильная последовательность для [4]:
      1. systemctl stop — процесс уходит, Restart= НЕ триггерится.
      2. _kill_port_holder(port) — fallback: если stop не успел за
         TimeoutStopSec (процесс игнорит SIGTERM), добить по PID.

    Для uninstall[6] — другая ситуация (см. uninstall_subscription_service):
    там мы удаляем unit-файл ДО mask, чтобы mask succeeded (создал symlink
    → /dev/null какbelt-and-suspenders — на случай если stop по какой-то
    причине не отработает и Restart= всё-таки триггернётся).
    """
    # 1. Stop — process exits, Restart= is ignored per systemd docs.
    #    stderr глушим: если сервис уже остановлен, systemctl stop пишет
    #    ничего страшного, но иногда там мусор.
    subprocess.run(
        ["systemctl", "stop", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 2. Fallback: kill by port if systemd didn't release it in time.
    cfg = _load_sub_conf()
    port = cfg.get("listen_port", DEFAULT_PORT)
    _kill_port_holder(port)


def uninstall_subscription_service() -> None:
    """Полное удаление сервиса vless-subscription: systemd-unit + ufw-порт +
    процесс. mirror rest_api.uninstall_web_service() (commit e830f28),
    но с правильным порядком mask/delete (см. ниже).

    КРИТИЧНЫЙ баг в первоначальном фиксе: `systemctl mask` ПАДАЕТ с
    'Failed to mask unit: File ... already exists.' на новом systemd (≥252),
    если unit-файл — обычный файл. Mask создаёт symlink → /dev/null, но
    отказывается перезаписывать существующий файл (нужен --force, которого
    нет на старом systemd). Результат: mask не сработал, stop вызвался
    следом, но Restart=always мог перезапустить процесс.

    Правильный порядок: сначала удалить unit-файл (чтобы mask succeeded и
    создал symlink → /dev/null), потом mask, потом stop. Тогда даже если
    stop почему-то триггернет Restart= (чего по docs быть не должно, но
    belt-and-suspenders), masked unit не даст процессу воскреснуть.

    Полная последовательность:
      1. _fw_close_tcp(port) — закрыть ufw-порт (идемпотентно, stderr
         глушится — правило могло быть уже удалено через stop[4]).
      2. systemctl disable — убрать из автозагрузки (Wants symlink).
      3. Удалить unit-файл — теперь `systemctl mask` сможет создать
         symlink → /dev/null.
      4. systemctl mask — symlink → /dev/null, Restart= заблокирован.
      5. systemctl stop — процесс уходит, не перезапускается (masked +
         systemd docs: stop игнорирует Restart=).
      6. systemctl unmask — убрать symlink → /dev/null (cleanup).
      7. systemctl daemon-reload — systemd забывает юнит.
      8. systemctl reset-failed — очистить failed-состояние.
         stderr глушим: после удаления unit-файла systemd пишет
         'Unit ... not loaded.' — это шум, не ошибка.
      9. Fallback: _kill_port_holder(port) — добить процесс если что-то
         пошло не так (старый systemd, процесс запущен вручную через
         `python3 -m chimera.modules.subscription serve`).

    Конфиг subscription.json (pepper, identity_map) НЕ трогается —
    это намеренно: при повторной установке старые ссылки должны
    продолжить работать (pepper не инвалидируется). Если нужно
    полный сброс — пункт меню 'Сгенерировать pepper заново'.
    """
    cfg = _load_sub_conf()
    port = cfg.get("listen_port", DEFAULT_PORT)
    # 1. Закрыть ufw-порт (идемпотентно — stderr глушится).
    _fw_close_tcp(port)
    # 2. Disable — убрать из автозагрузки (Wants symlink).
    #    stderr глушим: 'Removed .../multi-user.target.wants/...' — это
    #    info, не error, но пугает пользователя в контексте полного удаления.
    subprocess.run(
        ["systemctl", "disable", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 3. Удалить unit-файл ДО mask — иначе mask падает с
    #    'Failed to mask unit: File ... already exists.' (systemd ≥252).
    try:
        _UNIT_PATH.unlink(missing_ok=True)
    except Exception:
        pass
    # 4. Mask — теперь создаёт symlink → /dev/null (файла нет).
    #    stderr глушим: на старом systemd mask может выдать предупреждение,
    #    не влияющее на работу.
    subprocess.run(
        ["systemctl", "mask", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 5. Stop — процесс уходит, не перезапускается (masked + systemd stop
    #    semantics игнорируют Restart=).
    subprocess.run(
        ["systemctl", "stop", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 6. Unmask — убрать symlink → /dev/null (cleanup, мы хотим полностью
    #    удалить unit, не оставить замаскированный symlink).
    subprocess.run(
        ["systemctl", "unmask", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 7. На всякий случай убираем symlink/file если unmask не справился.
    if _UNIT_PATH.is_symlink() or _UNIT_PATH.exists():
        try:
            _UNIT_PATH.unlink()
        except Exception:
            pass
    # 8. Daemon-reload — systemd забывает юнит.
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    # 9. Reset-failed — очищает failed-состояние (иначе при следующей
    #    установке systemd может ругаться на 'start-limit-hit').
    #    stderr глушим: после удаления unit-файла systemd пишет
    #    'Unit ... not loaded.' — это шум (нечего очищать), не ошибка.
    subprocess.run(
        ["systemctl", "reset-failed", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # 10. Fallback: убить процесс по порту если systemd не справился.
    _kill_port_holder(port)
    # Помечаем как выключенный в конфиге — но НЕ удаляем pepper/port,
    # чтобы при повторной установке старые ссылки продолжили работать.
    cfg["enabled"] = False
    _save_sub_conf(cfg)

    # Также снимаем nginx front если был включён — иначе остаётся висеть
    # orphaned vhost + открытый порт, и подписка всё равно не отвечает
    # (backend мёртв, nginx проксирует в никуда).
    try:
        _sub_nginx_remove()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
#  NGINX FRONT (прямой доступ по домену/IP с TLS)
# ──────────────────────────────────────────────────────────────────────────
# По аналогии с rest_api.nginx_front_portal и telemt_panel._telemt_setup_direct_access.
# Делегирует в chimera.modules.panel_nginx_front — единая точка логики.
#
# Поведение:
#   nginx front ON  → backend слушает 127.0.0.1:8443 (loopback), nginx терминирует
#                     TLS на порту 9444 (или настраиваемом) и проксирует на backend.
#                     UFW открывает порт 9444, порт 8443 НЕ открывается наружу.
#   nginx front OFF → backend слушает 0.0.0.0:8443 (старый режим, обратная совместимость).
#                     UFW открывает порт 8443. Старые URL продолжают работать.
# ══════════════════════════════════════════════════════════════════════════

def _sub_nginx_status() -> dict:
    """Возвращает состояние nginx front для подписки."""
    if not _SUB_NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(_SUB_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}


def _sub_backend_bind_loopback() -> None:
    """Переключает backend-сервис подписки на 127.0.0.1 (loopback).

    Вызывается при включении nginx front — наружу торчит только nginx.
    Атомарно: обновляет unit-файл + перезапускает сервис. UFW-порт 8443
    при этом закрывается (он больше не нужен снаружи).
    """
    cfg = _load_sub_conf()
    port = cfg.get("listen_port", DEFAULT_PORT)

    # Закрываем старый порт 8443 в UFW (через port_registry, идемпотентно).
    _fw_close_tcp(port)

    # Меняем unit-файл так, чтобы backend слушал 127.0.0.1.
    # Это делается через служебную переменную окружения SUB_LISTEN_HOST
    # которую читает serve() — см. ниже.
    if _UNIT_PATH.exists():
        try:
            content = _UNIT_PATH.read_text()
            # Если уже есть SUB_LISTEN_HOST=127.0.0.1 — ничего не делаем.
            if "SUB_LISTEN_HOST=127.0.0.1" not in content:
                # Добавляем Environment=SUB_LISTEN_HOST=127.0.0.1 в [Service].
                if "Environment=" in content and "SUB_LISTEN_HOST" not in content:
                    content = content.replace(
                        "Environment=",
                        "Environment=SUB_LISTEN_HOST=127.0.0.1\nEnvironment=",
                        1,
                    )
                elif "[Service]" in content:
                    content = content.replace(
                        "[Service]",
                        "[Service]\nEnvironment=SUB_LISTEN_HOST=127.0.0.1",
                        1,
                    )
                _UNIT_PATH.write_text(content)
                subprocess.run(["systemctl", "daemon-reload"], check=False)
                subprocess.run(["systemctl", "restart", SERVICE_NAME], check=False)
        except Exception:
            pass


def _sub_backend_bind_public() -> None:
    """Возвращает backend на 0.0.0.0 (старый режим, без nginx front).

    Удаляет SUB_LISTEN_HOST из unit-файла, открывает порт 8443 в UFW.
    """
    cfg = _load_sub_conf()
    port = cfg.get("listen_port", DEFAULT_PORT)

    if _UNIT_PATH.exists():
        try:
            content = _UNIT_PATH.read_text()
            changed = False
            # Удаляем строку Environment=SUB_LISTEN_HOST=127.0.0.1
            if "SUB_LISTEN_HOST=127.0.0.1" in content:
                lines = content.splitlines()
                new_lines = [l for l in lines if "SUB_LISTEN_HOST=127.0.0.1" not in l]
                content = "\n".join(new_lines) + "\n"
                changed = True
            if changed:
                _UNIT_PATH.write_text(content)
                subprocess.run(["systemctl", "daemon-reload"], check=False)
                subprocess.run(["systemctl", "restart", SERVICE_NAME], check=False)
        except Exception:
            pass

    # Открываем порт 8443 (если сервис включён).
    if cfg.get("enabled"):
        _fw_open_tcp(port)


def _sub_nginx_install(port: int, use_self_signed: bool, domain: "Optional[str]") -> "tuple[bool, str]":
    """Устанавливает nginx front с TLS для подписки.

    Делегирует в chimera.modules.panel_nginx_front.
    """
    from chimera.modules.panel_nginx_front import panel_nginx_front_install
    from chimera.modules.port_registry import SERVICE_SUBSCRIPTION_NGINX

    backend_port = _load_sub_conf().get("listen_port", DEFAULT_PORT)

    ok, msg = panel_nginx_front_install(
        service_tag=SERVICE_SUBSCRIPTION_NGINX,
        port=port,
        backend_port=backend_port,
        site_name=_SUB_NGINX_SITE_NAME,
        state_file=_SUB_NGINX_STATE_FILE,
        title="Подписка",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="https",  # backend сам имеет TLS от LE-сертификата
        cert_name_slug="chimera-subscription",
    )
    return ok, msg


def _sub_nginx_remove() -> "tuple[bool, str]":
    """Удаляет nginx front + закрывает порт + возвращает backend на 0.0.0.0."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove
    from chimera.modules.port_registry import SERVICE_SUBSCRIPTION_NGINX

    if not _sub_nginx_status().get("enabled"):
        return True, "nginx front уже выключен"

    panel_nginx_front_remove(
        service_tag=SERVICE_SUBSCRIPTION_NGINX,
        site_name=_SUB_NGINX_SITE_NAME,
        state_file=_SUB_NGINX_STATE_FILE,
        title="Подписка",
    )
    # Возвращаем backend на 0.0.0.0 — старые URL должны снова заработать.
    _sub_backend_bind_public()
    return True, "nginx front удалён"


def _sub_nginx_get_url(token: str) -> "Optional[str]":
    """Возвращает URL подписки через nginx front (если включён).

    Если nginx front выключен — возвращает None (caller использует старый URL).
    """
    st = _sub_nginx_status()
    if not st.get("enabled"):
        return None
    port = st.get("port", DEFAULT_SUB_NGINX_PORT)
    domain = st.get("domain")
    if not domain:
        # Self-signed — используем public IP из state файла.
        return None  # fallback — backend URL будет показан
    return f"https://{domain}:{port}/sub/{token}"


# ══════════════════════════════════════════════════════════════════════════
#  ПОМОЩНИКИ ДЛЯ REST API / ПАНЕЛЕЙ (User Portal, Admin Panel)
# ══════════════════════════════════════════════════════════════════════════

def get_subscription_base_url() -> str:
    """Внешний базовый URL подписки: https://<host>:<port>/sub.

    Учитывает nginx front (если включён — его домен/порт), иначе —
    домен + listen_port backend'а. Используется User/Admin панелями
    для показа ссылок юзеру."""
    cfg = _load_sub_conf()
    state = _load_state() or {}
    ng = _sub_nginx_status()
    if ng.get("enabled"):
        port = ng.get("port", DEFAULT_SUB_NGINX_PORT)
        host = ng.get("domain") or state.get("domain", "") or _get_server_ip("4")
    else:
        port = cfg.get("listen_port", DEFAULT_PORT)
        host = state.get("domain", "") or _get_server_ip("4")
    return f"https://{host}:{port}/sub"


def get_portal_subscription_info(user: dict) -> dict:
    """Сводка подписки для User Portal (GET /api/portal/sub-info).

    Возвращает URL'ы всех форматов + статус мульти-нод фичи и список нод.
    Не бросает исключений — панель должна работать даже без подписки."""
    try:
        cfg = _load_sub_conf()
        service_enabled = bool(cfg.get("enabled"))
        base = get_subscription_base_url()
        info: dict = {
            "service_enabled": service_enabled,
            "base_url": base,
            "urls": {},
            "multinode": {"enabled": False, "nodes": []},
        }
        uuid_str = user.get("uuid", "")
        pepper = cfg.get("pepper", "")
        if service_enabled and uuid_str and pepper:
            token = _token_for(uuid_str, pepper)
            info["urls"] = {
                "base64":  f"{base}/{token}",
                "ios":     f"{base}/{token}/ios",
                "singbox": f"{base}/{token}?format=singbox",
                "clash":   f"{base}/{token}?format=clash",
            }
        if _mn is not None:
            try:
                st = _mn.multinode_status()
                info["multinode"] = {
                    "enabled": bool(st.get("enabled")),
                    "nodes": _mn.summarize_nodes(user),
                }
            except Exception as e:
                _log("WARN", f"portal multinode info: {e}")
        return info
    except Exception as e:
        _log("WARN", f"get_portal_subscription_info: {e}")
        return {"service_enabled": False, "base_url": "", "urls": {},
                "multinode": {"enabled": False, "nodes": []}}


def get_admin_subscription_info() -> dict:
    """Сводка для Admin Panel (GET /api/subscription/info): статус сервиса
    + URL всех форматов на каждого активного пользователя."""
    try:
        cfg = _load_sub_conf()
        base = get_subscription_base_url()
        pepper = cfg.get("pepper", "")
        users_out: list[dict] = []
        if cfg.get("enabled") and pepper:
            for u in _load_all_users():
                if u.get("disabled") or not u.get("uuid"):
                    continue
                token = _token_for(u["uuid"], pepper)
                users_out.append({
                    "email": u.get("email", u.get("name", "?")),
                    "url":       f"{base}/{token}",
                    "url_ios":   f"{base}/{token}/ios",
                    "url_singbox": f"{base}/{token}?format=singbox",
                    "url_clash": f"{base}/{token}?format=clash",
                })
        mn: dict = {"enabled": False, "nodes": []}
        if _mn is not None:
            try:
                st = _mn.multinode_status()
                mn = {"enabled": bool(st.get("enabled")),
                      "reason": st.get("reason", ""),
                      "nodes": _mn.summarize_nodes()}
            except Exception as e:
                _log("WARN", f"admin multinode info: {e}")
        return {
            "service_enabled": bool(cfg.get("enabled")),
            "listen_port": cfg.get("listen_port", DEFAULT_PORT),
            "base_url": base,
            "users": users_out,
            "multinode": mn,
        }
    except Exception as e:
        _log("WARN", f"get_admin_subscription_info: {e}")
        return {"service_enabled": False, "listen_port": DEFAULT_PORT,
                "base_url": "", "users": [],
                "multinode": {"enabled": False, "nodes": []}}


# ══════════════════════════════════════════════════════════════════════════
# CLI / МЕНЮ (вызывается отдельно, НЕ вшито в _core.py)
# ══════════════════════════════════════════════════════════════════════════

def do_subscription_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        cfg = _load_sub_conf()
        enabled = cfg.get("enabled", False)
        status = f"{GREEN}включена{NC}" if enabled else f"{DIM}выключена{NC}"

        # Проверяем состояние nginx front — для отображения в меню.
        nginx_front = _sub_nginx_status()
        nginx_front_enabled = nginx_front.get("enabled", False)
        nginx_front_port = nginx_front.get("port", DEFAULT_SUB_NGINX_PORT)
        nginx_front_domain = nginx_front.get("domain") or state.get("domain", "")
        nginx_front_self_signed = nginx_front.get("self_signed", False)

        _box_top(f"🔁  ЕДИНАЯ ПОДПИСКА  {DIM}({NC}{status}{DIM}){NC}")
        _box_row()
        if not state or not state.get("domain"):
            _box_warn_line("state.json не найден — сначала установите сервер (раздел 1).")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"\n{CYAN}Enter…{NC}")
            return

        if nginx_front_enabled:
            mode = "self-signed (по IP)" if nginx_front_self_signed else f"Let's Encrypt ({nginx_front_domain})"
            _box_row(f"  {GREEN}🌐 nginx front (TLS):{NC} {CYAN}{mode}{NC}  {DIM}→ порт {nginx_front_port}{NC}")
            _box_row(f"  {DIM}backend слушает 127.0.0.1:{cfg.get('listen_port', DEFAULT_PORT)} (loopback){NC}")
            _box_row()
        else:
            _box_row(f"  {DIM}nginx front: выключен — backend на 0.0.0.0:{cfg.get('listen_port', DEFAULT_PORT)} (свой TLS){NC}")
            _box_row()

        _box_item("1", "🚀 Включить / переустановить сервис")
        _box_item("2", "🔗 Показать ссылки подписки для всех пользователей")
        _box_item("3", f"🔄 Сгенерировать pepper заново  {DIM}(инвалидирует все ссылки){NC}")
        _box_item("4", "🛑 Выключить сервис")
        _box_item("5", f"🧩 Привязка сателлитов к UUID  {DIM}(Mieru/Naive/Telemt/TrustTunnel/sing-box, авто-скан){NC}")
        _box_item("6", f"{RED}🗑️  Удалить полностью{NC}")
        if nginx_front_enabled:
            _box_item("7", f"🌐 nginx front (TLS) — {YELLOW}выключить{NC}  {DIM}(вернуть на 0.0.0.0:{cfg.get('listen_port', DEFAULT_PORT)}){NC}")
        else:
            _box_item("7", f"🌐 nginx front (TLS) — {DIM}включить прямой доступ по домену/IP{NC}")
        if _mn is not None:
            try:
                _mn_st = _mn.multinode_status()
                _mn_label = "вкл" if _mn_st["enabled"] else "выкл"
                _box_item("8", f"🌐 Мульти-нод конфиги (Mode B) — {_mn_label}  {DIM}(mihomo/sing-box/exit-URI){NC}")
            except Exception:
                _box_item("8", f"🌐 Мульти-нод конфиги (Mode B)  {DIM}(mihomo/sing-box/exit-URI){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            return

        if ch == "1":
            old_port = cfg.get("listen_port", DEFAULT_PORT)
            port = old_port
            try:
                port = int(input(f"Порт [{port}]: ").strip() or port)
            except ValueError:
                pass
            # Port-conflict check: prevent binding a port already taken by
            # another protocol (TrustTunnel defaults to 8443, sing-box
            # ShadowTLS/AnyTLS/TUIC use 8442-8444). Without this, the
            # ThreadingHTTPServer constructor raises OSError: Address
            # already in use → systemd start-limit-hit → subscription
            # silently dies and [1] can't recover (until Fix B above).
            try:
                core = _core_module()
                if hasattr(core, "check_port_used_by_other_protocol"):
                    conflict = core.check_port_used_by_other_protocol(
                        port, exclude_module="subscription",
                    )
                    if conflict:
                        _err(f"Порт {port} занят другим протоколом:")
                        _err(conflict)
                        _warn("Выберите другой порт (например 8445, 8446, 9443).")
                        input(f"\n{BOLD}Enter…{NC}")
                        continue
            except Exception as _e:
                _warn(f"Не удалось проверить конфликт портов: {_e}")
            cfg["enabled"] = True
            cfg["listen_port"] = port
            _ensure_pepper(cfg)
            _save_sub_conf(cfg)
            if old_port != port:
                _fw_close_tcp(old_port)
            fw_tool = _fw_open_tcp(port)
            if _install_service(port):
                _ok(f"Сервис {SERVICE_NAME} запущен на :{port}")
                if fw_tool:
                    _ok(f"{fw_tool}: TCP {port} открыт")
                else:
                    _warn(f"Не найден ufw/iptables — откройте {port}/tcp вручную.")
                _info(f"nginx (опционально): подключите {_NGINX_SNIP}")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "2":
            pepper = _ensure_pepper(cfg)
            domain = state.get("domain", "")
            port = cfg.get("listen_port", DEFAULT_PORT)
            os.system("clear")

            # Если nginx front включён — показываем URL'ы через него.
            # Если нет — старые URL'ы через backend на 0.0.0.0:port.
            ng_st = _sub_nginx_status()
            use_nginx = ng_st.get("enabled", False)
            if use_nginx:
                ng_port = ng_st.get("port", DEFAULT_SUB_NGINX_PORT)
                ng_domain = ng_st.get("domain") or domain
                ng_self_signed = ng_st.get("self_signed", False)
                # Для self-signed domain может быть пустым — fallback на public IP.
                host_label = ng_domain if ng_domain else "<IP сервера>"
                host_for_url = ng_domain if ng_domain else state.get("server_ip", host_label)
                url_base = f"https://{host_for_url}:{ng_port}/sub"
                scheme_note = (f"self-signed TLS (по IP {host_label})" if ng_self_signed
                                else f"Let's Encrypt ({ng_domain})")
            else:
                url_base = f"https://{domain}:{port}/sub"
                scheme_note = f"собственный TLS (backend 0.0.0.0:{port})"

            rows = []
            for u in _load_all_users():
                if u.get("disabled") or not u.get("uuid"):
                    continue
                token = _token_for(u["uuid"], pepper)
                url = f"{url_base}/{token}"
                url_ios = f"{url_base}/{token}/ios"
                url_sb = f"{url_base}/{token}?format=singbox"
                url_cl = f"{url_base}/{token}?format=clash"
                label = u.get("email", u.get("name", "?"))
                rows.append((label, url, url_ios, url_sb, url_cl))

            _box_top("🔗  ССЫЛКИ ПОДПИСКИ")
            _box_row()
            _box_row(f"  {DIM}Режим:{NC} {scheme_note}")
            _box_row()
            if not rows:
                _box_warn_line("Нет активных пользователей.")
            for label, url, url_ios, url_sb, url_cl in rows:
                _box_row(f"  {WHITE}{label}{NC}")
                _box_row(f"  {GREEN}{url}{NC}")
                _box_row(f"  {DIM}iOS/Karing:{NC} {CYAN}{url_ios}{NC}")
                _box_row(f"  {DIM}sing-box JSON:{NC} {CYAN}{url_sb}{NC}")
                _box_row(f"  {DIM}mihomo/Clash YAML:{NC} {CYAN}{url_cl}{NC}")
                _box_row()
            _box_back()
            _box_bottom()

            # QR — вне рамки, qrencode рисует свою фиксированную ASCII-сетку,
            # внутри box она ломает выравнивание.
            for label, url, url_ios, url_sb, url_cl in rows:
                print()
                _print_qr(url, f"{label} (основной)")
                _print_qr(url_ios, f"{label} (iOS/Karing)")

            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "3":
            confirm = input(f"{YELLOW}Все выданные ссылки перестанут работать. Продолжить? (y/N):{NC} ")
            if confirm.lower() == "y":
                cfg["pepper"] = secrets.token_hex(32)
                _save_sub_conf(cfg)
                _ok("Pepper обновлён.")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "4":
            # Надёжная остановка: mask → stop → kill-by-port fallback.
            # Обычный `systemctl disable --now` НЕ работает — в unit-файле
            # стоит Restart=always, и systemd сразу перезапускает процесс
            # после stop (юнит-файл ещё на диске). Результат: порт остаётся
            # занятым, пользователь думает что сервис остановлен.
            # Та же проблема/фикс как в rest_api.do_manage_web_panel() item '1'
            # stop branch — см. commit e830f28.
            cfg["enabled"] = False
            _save_sub_conf(cfg)
            old_port = cfg.get("listen_port", DEFAULT_PORT)
            _fw_close_tcp(old_port)
            _stop_service_reliable()
            _ok("Сервис остановлен, порт освобождён.")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "5":
            _do_identity_map_menu(cfg)

        elif ch == "6":
            # Полное удаление (mirror rest_api.uninstall_web_service):
            # systemd-unit + ufw-порт + процесс. pepper/port в конфиге
            # НЕ удаляем — при повторной установке [1] старые ссылки
            # продолжат работать. Для инвалидации ссылок есть пункт [3].
            if not _UNIT_PATH.exists():
                _warn("Сервис не установлен — нечего удалять.")
                input(f"\n{BOLD}Enter…{NC}")
            else:
                _box_row(f"  {RED}Будет удалено:{NC}")
                _box_row(f"  {DIM}  • systemd-unit {SERVICE_NAME}.service{NC}")
                _box_row(f"  {DIM}  • ufw-правило (если было открыто){NC}")
                _box_row(f"  {DIM}  • процесс python3 на порту подписки{NC}")
                _box_row(f"  {DIM}  subscription.json (pepper, identity_map) НЕ затрагивается —{NC}")
                _box_row(f"  {DIM}  при повторной установке [1] старые ссылки продолжат работать.{NC}")
                _box_row()
                confirm = input(
                    f"  {RED}Полностью удалить сервис подписки? [y/N]:{NC} "
                ).strip().lower()
                if confirm == "y":
                    uninstall_subscription_service()
                    _ok("Сервис подписки полностью удалён, порт свободен.")
                else:
                    _info("Отменено.")
                input(f"\n{BOLD}Enter…{NC}")

        elif ch == "7":
            # nginx front (TLS) — прямой доступ по домену/IP.
            ng_st = _sub_nginx_status()
            if ng_st.get("enabled"):
                # Выключение.
                _box_top("🌐  NGINX FRONT — ВЫКЛЮЧЕНИЕ")
                _box_row()
                _box_row(f"  {DIM}Будет удалён nginx vhost + закрыт порт {ng_st.get('port', DEFAULT_SUB_NGINX_PORT)}.{NC}")
                _box_row(f"  {DIM}Backend вернётся на 0.0.0.0:{cfg.get('listen_port', DEFAULT_PORT)} — старые URL снова заработают.{NC}")
                _box_row()
                _box_back()
                _box_bottom()
                confirm = input(f"  {YELLOW}Выключить nginx front? [y/N]:{NC} ").strip().lower()
                if confirm == "y":
                    ok, msg = _sub_nginx_remove()
                    if ok:
                        _ok(msg)
                    else:
                        _err(msg)
                else:
                    _info("Отменено.")
                input(f"\n{BOLD}Enter…{NC}")
            else:
                # Включение.
                if not cfg.get("enabled"):
                    _warn("Сначала включите сервис подписки (пункт 1).")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                # Спрашиваем порт.
                try:
                    port_str = input(f"  Порт для nginx front [Enter={DEFAULT_SUB_NGINX_PORT}]: ").strip()
                    ng_port = int(port_str) if port_str else DEFAULT_SUB_NGINX_PORT
                except (ValueError, EOFError, KeyboardInterrupt):
                    ng_port = DEFAULT_SUB_NGINX_PORT
                # Спрашиваем режим TLS.
                try:
                    from chimera.modules.panel_nginx_front import ask_tls_mode, ask_domain
                except ImportError:
                    _err("panel_nginx_front недоступен — не могу установить nginx front.")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                use_self_signed, _ = ask_tls_mode("подписку")
                domain = None
                if not use_self_signed:
                    domain = ask_domain(default=state.get("domain", ""))
                    if not domain:
                        _warn("Домен не указан — отмена. Используйте self-signed режим.")
                        input(f"\n{BOLD}Enter…{NC}")
                        continue
                # Сначала ставим nginx front (это открывает порт 9444),
                # потом переключаем backend на loopback.
                ok, msg = _sub_nginx_install(ng_port, use_self_signed, domain)
                if not ok:
                    _err(f"Не удалось установить nginx front: {msg}")
                    input(f"\n{BOLD}Enter…{NC}")
                    continue
                # Переключаем backend на 127.0.0.1 (loopback).
                _sub_backend_bind_loopback()
                _ok(f"nginx front включён на порту {ng_port}.")
                _info(f"Backend переведён на 127.0.0.1:{cfg.get('listen_port', DEFAULT_PORT)} (loopback).")
                _info(f"Старый URL https://{state.get('domain', '<домен>')}:{cfg.get('listen_port', DEFAULT_PORT)}/sub/... больше не работает.")
                _info(f"Новый URL: https://{domain or '<IP сервера>'}:{ng_port}/sub/<token>")
                input(f"\n{BOLD}Enter…{NC}")

        elif ch == "8":
            # Мульти-нод конфиги (Mode B): mihomo ?format=clash + sing-box
            # selector + exit-URI в base64. Управление вкл/выкл/авто.
            if _mn is None:
                _err(f"Модуль subscription_multinode недоступен: {_MN_IMPORT_ERR}")
                input(f"\n{BOLD}Enter…{NC}")
                continue
            st = _mn.multinode_status()
            state_ = st["enabled"]
            os.system("clear")
            _box_top("🌐  МУЛЬТИ-НОД КОНФИГИ (MODE B)")
            _box_row()
            if state_:
                _box_ok_line(f"Состояние: включена ({st['reason']})")
            else:
                _box_warn_line(f"Состояние: выключена ({st['reason']})")
            _box_row()
            nodes = _mn.summarize_nodes()
            if nodes:
                _box_row(f"  {DIM}Ноды в конфигах ({len(nodes)}):{NC}")
                for n in nodes:
                    kind_label = {"exit": "exit", "entry": "entry",
                                  "entry_cascade": "каскад",
                                  "mirror": "mirror"}.get(n["kind"], n["kind"])
                    _box_row(f"    {WHITE}{n['name']}{NC}  {DIM}[{kind_label}] → {n['host']}:{n['port']}{NC}")
            else:
                _box_warn_line("Нод не найдено — добавьте exit-ноды (Chain/Nodes, Mode B).")
            _box_row()
            _box_row(f"  {DIM}?format=clash   — mihomo/Clash Meta YAML (группы Выбор/Auto/Balance){NC}")
            _box_row(f"  {DIM}?format=singbox — sing-box JSON (selector «🎯 Chimera» + auto){NC}")
            _box_row(f"  {DIM}base64           — vless:// каждой exit-ноды дополнительно{NC}")
            _box_row()
            _box_item("1", f"{'🔴 Выключить принудительно' if state_ else '🟢 Включить принудительно'}")
            _box_item("2", "⚙ Авто (по Mode B: вкл при наличии exit-нод)")
            _box_row()
            _box_back()
            _box_bottom()
            try:
                sub_ch = input(f"{CYAN}Выбор:{NC} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if sub_ch == "1":
                _mn.set_multinode_enabled("off" if state_ else "on")
                _ok(f"Мульти-нод конфиги: {'выключены' if state_ else 'включены'}.")
            elif sub_ch == "2":
                _mn.set_multinode_enabled("auto")
                _ok("Режим авто: активна при install_mode=B и наличии exit-нод.")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "" or ch.lower() == "q" or ch == "0":
            return
        else:
            _warn("Неверный выбор.")


def _do_identity_map_menu(cfg: dict) -> None:
    """Пункт 5: привязка сателлитных логинов к UUID пользователя.

    Новая реализация (v5): использует satellite_bindings.json (canon CRUD).
    Старый identity_map в subscription.json остаётся как escape-hatch
    (приоритет выше), но новая секция показывает оба источника и
    предлагает авто-привязку по совпадению имени/UUID.

    UX:
      1. Выбор пользователя из списка.
      2. Авто-сканирование всех 5 сателлитов + предложения привязки
         (matched_login по email-local-part / name / UUID).
      3. Per-satellite меню: принять предложение / выбрать из списка /
         снять привязку.
    """
    try:
        from chimera.modules import satellite_bindings as _sb
    except ImportError as _e:
        _err(f"Модуль satellite_bindings недоступен: {_e}")
        input(f"\n{BOLD}Enter…{NC}")
        return

    users = [u for u in _load_all_users() if u.get("uuid")]
    os.system("clear")
    _box_top("🧩  ПРИВЯЗКА САТЕЛЛИТОВ К ПОЛЬЗОВАТЕЛЯМ")
    _box_row()
    _box_row(f"  {DIM}Per-user привязка Mieru/NaiveProxy/Telemt/TrustTunnel/sing-box.{NC}")
    _box_row(f"  {DIM}Канонический путь — satellite_bindings.json.{NC}")
    _box_row(f"  {DIM}Identity map (legacy) остаётся как escape-hatch (приоритет выше).{NC}")
    _box_row()
    if not users:
        _box_warn_line("Нет пользователей.")
        _box_back()
        _box_bottom()
        input(f"\n{BOLD}Enter…{NC}")
        return

    for i, u in enumerate(users, 1):
        n_bind = len(_sb.list_for_user(u["uuid"]))
        bind_label = f"{GREEN}({n_bind} привязок){NC}" if n_bind else f"{DIM}(нет привязок){NC}"
        _box_row(f"  {DIM}{i}.{NC} {WHITE}{u.get('email', u.get('name','?'))}{NC}  "
                  f"{DIM}[{u['uuid'][:8]}…]{NC}  {bind_label}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        idx = int(input(f"{CYAN}Номер пользователя:{NC} ").strip()) - 1
        target = users[idx]
    except (ValueError, IndexError, KeyboardInterrupt, EOFError):
        _warn("Отменено.")
        input(f"\n{BOLD}Enter…{NC}")
        return

    # Авто-предложения привязок.
    suggestions = _sb.suggest_for_user(target)
    os.system("clear")
    _box_top(f"🧩  {target.get('email', target.get('name','?'))}")
    _box_row()
    _box_row(f"  {DIM}UUID: {target['uuid']}{NC}")
    _box_row()

    # ── Показ предложений и текущих привязок ─────────────────────────
    _box_row(f"  {BOLD}Сателлит         Текущая привязка    Предложение{NC}")
    _box_row()
    for sug in suggestions:
        sat = sug["satellite"]
        label = sug["satellite_label"][:24]
        cur = sug.get("current_binding") or f"{DIM}—{NC}"
        matched = sug.get("matched_login")
        if matched:
            prop = f"{GREEN}{matched}{NC}"
        elif sug.get("available_logins"):
            prop = f"{YELLOW}(выбрать из {len(sug['available_logins'])}){NC}"
        else:
            prop = f"{DIM}нет логинов{NC}"
        _box_row(f"  {label:<16}  {cur:<20}  →  {prop}")
    _box_row()
    _box_row(f"  {DIM}Действия:{NC}")
    _box_item("1", "✅ Принять все предложения (авто-привязка)")
    _box_item("2", "✏️  Выбрать привязки вручную (per-satellite)")
    _box_item("3", "🧹 Снять все привязки этого пользователя")
    _box_item("4", "📋 Показать identity_map (legacy escape-hatch)")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        sub_ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except (KeyboardInterrupt, EOFError):
        return

    if sub_ch == "1":
        # Авто-привязка всех matched.
        bound = 0
        for sug in suggestions:
            if sug.get("matched_login"):
                if _sb.set_binding(
                    satellite=sug["satellite"],
                    login=sug["matched_login"],
                    owner_uuid=target["uuid"],
                    owner_email=target.get("email", ""),
                ):
                    bound += 1
        _ok(f"Привязано {bound} сателлитов.")
        input(f"\n{BOLD}Enter…{NC}")

    elif sub_ch == "2":
        # Per-satellite ручной выбор.
        for sug in suggestions:
            sat = sug["satellite"]
            label = sug["satellite_label"]
            logins = sug.get("available_logins") or []
            cur = sug.get("current_binding")
            if not logins:
                _warn(f"{label}: нет установленных логинов — пропускаю.")
                continue
            print()
            print(f"  {BOLD}{label}{NC} {DIM}([Enter] = оставить «{cur or '—'}», 0 = снять, ? = список){NC}")
            for j, lg in enumerate(logins[:10], 1):
                marker = f" {GREEN}← текущая{NC}" if lg == cur else ""
                print(f"    {DIM}{j}.{NC} {lg}{marker}")
            try:
                v = input(f"  {CYAN}Выбор:{NC} ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if v == "" or v.lower() == "?":
                continue
            if v == "0":
                _sb.remove_binding(sat, target["uuid"])
                _ok(f"{label}: привязка снята.")
                continue
            try:
                idx_l = int(v) - 1
                if 0 <= idx_l < len(logins):
                    _sb.set_binding(sat, logins[idx_l],
                                    target["uuid"], target.get("email", ""))
                    _ok(f"{label}: привязан «{logins[idx_l]}».")
                else:
                    _warn("Неверный номер.")
            except ValueError:
                _warn("Неверный ввод.")
        input(f"\n{BOLD}Enter…{NC}")

    elif sub_ch == "3":
        confirm = input(f"  {YELLOW}Снять все привязки пользователя? (y/N):{NC} ").strip().lower()
        if confirm == "y":
            n = _sb.remove_user(target["uuid"])
            _ok(f"Снято {n} привязок.")
        input(f"\n{BOLD}Enter…{NC}")

    elif sub_ch == "4":
        # Показать legacy identity_map.
        os.system("clear")
        _box_top(f"🧩  IDENTITY_MAP (LEGACY) — {target.get('email','?')}")
        _box_row()
        idmap = cfg.get("identity_map", {}).get(target["uuid"], {})
        if not idmap:
            _box_warn_line("Identity map пуст — все привязки идут через satellite_bindings.json.")
        else:
            for sat, login in idmap.items():
                _box_row(f"  {sat:<14} → {login}")
        _box_row()
        _box_row(f"  {DIM}Identity map имеет ПРИОРИТЕТ над satellite_bindings.{NC}")
        _box_row(f"  {DIM}Используется только как escape-hatch для edge cases.{NC}")
        _box_row()
        _box_back()
        _box_bottom()
        input(f"\n{BOLD}Enter…{NC}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        p = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
        serve(p)
    else:
        do_subscription_menu()
