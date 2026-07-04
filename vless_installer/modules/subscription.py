"""
vless_installer/modules/subscription.py
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
      python3 -m vless_installer.modules.subscription menu
      python3 -m vless_installer.modules.subscription serve   (из systemd)
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
from urllib.parse import urlparse

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
from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn as _box_warn_line, _box_ok as _box_ok_line,
)

# ── Логирование (единый формат с остальными модулями) ──────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

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
def _core_call(func_name: str, *args, **kwargs):
    core = importlib.import_module("vless_installer._core")
    return getattr(core, func_name)(*args, **kwargs)

def _gen_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                     proto="reality", xhttp_path="/", xhttp_mode="streamup",
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
_HYBRID_STATE = Path("/var/lib/xray-installer/hybrid_mieru_state.json")
_MITA_HYBRID_CFG = Path("/etc/mita/hybrid_server_config.json")
_SUB_CONF    = Path("/var/lib/xray-installer/subscription.json")
_TRAFFIC_LIMITS_FILE = Path("/var/lib/xray-installer/traffic_limits.json")
_UNIT_PATH   = Path("/etc/systemd/system/vless-subscription.service")
_NGINX_SNIP  = Path("/etc/nginx/snippets/vless-subscription.conf")

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
    if proto == "reality" and awg_exit and install_mode == "B" and reality_dest:
        return reality_dest.split(":")[0]
    return domain

def _build_vless_uri(user: dict, state: dict) -> Optional[str]:
    domain     = state.get("domain", "")
    if not domain:
        return None
    proto      = state.get("protocol_mode", "reality")
    port       = int(state.get("server_port", 443))
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    fp         = state.get("fingerprint", "chrome") or "chrome"
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "streamup")
    sni        = _resolve_sni(state)
    host       = domain  # у клиента подписки должен быть стабильный host, IP — по желанию юзера отдельно

    uuid_str = user.get("uuid", "")
    if not uuid_str:
        return None
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
    {"identity_map": {"<uuid>": {"mieru": "username", "naive": "...", "telemt": "..."}}}
    Заполняется через do_subscription_menu → пункт 5, если автоматическое
    сопоставление по имени не сработало (например у сателлитных протоколов
    юзеры создавались вручную под другими логинами)."""
    return _load_sub_conf().get("identity_map", {})

def _match_by_name(user: dict, satellite: str, pool_keys) -> Optional[str]:
    """Возвращает ключ (имя/логин) в pool_keys, соответствующий этому
    UUID-пользователю: сначала ручной override, потом эвристика по имени."""
    override = _identity_overrides().get(user.get("uuid", ""), {}).get(satellite)
    if override and override in pool_keys:
        return override
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

    # ── hybrid_addon: Mieru — единственный внешний вход ────────────────
    if _HYBRID_STATE.exists() and _MITA_HYBRID_CFG.exists():
        try:
            hybrid_st = json.loads(_HYBRID_STATE.read_text())
            mita_cfg  = json.loads(_MITA_HYBRID_CFG.read_text())
            users_by_name = {u["name"]: u["password"] for u in mita_cfg.get("users", [])}
            match = _match_by_name(user, "mieru", users_by_name.keys())
            if match:
                # tcp/udp может быть включён по отдельности — берём то, что есть
                for proto_key, port_key in (("tcp", "tcp_port"), ("udp", "udp_port")):
                    port = hybrid_st.get(port_key)
                    if port:
                        links.append(_gen_mieru_share_link(
                            server_ip, int(port), proto_key, match, users_by_name[match],
                        ))
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
                    links.append(_gen_mieru_share_link(
                        server_ip, int(st.get("port_start", 0)), st.get("protocol", "TCP"),
                        match, users_by_name[match],
                    ))
        except Exception as e:
            _warn(f"Не удалось прочитать mieru.json: {e}")

    return links

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

    links += _build_mieru_uris(user, ipv4 or state.get("domain", ""))
    links += _build_naive_uris(user)

    telemt = _build_telemt_uri(user, ipv4 or state.get("domain", ""))
    if telemt:
        links.append(telemt)

    # Резервные entry-ноды (см. entry_mirrors.py) — опционально, для
    # клиент-сайд auto-failover если основной entry заблокируют/забанят.
    uuid_str = user.get("uuid", "")
    if uuid_str:
        try:
            from vless_installer.modules.entry_mirrors import get_mirror_uris
            links += get_mirror_uris(uuid_str, only_healthy=True)
        except Exception as e:
            _log("WARN", f"entry_mirrors недоступен: {e}")

    payload = "\n".join(links)
    return base64.b64encode(payload.encode())

# ══════════════════════════════════════════════════════════════════════════
# HTTP(S)-ХЕНДЛЕР
# ══════════════════════════════════════════════════════════════════════════

class _SubHandler(BaseHTTPRequestHandler):
    server_version = "chimera-sub/1.0"

    def log_message(self, fmt, *args):  # тише в journalctl, пишем в свой лог
        _log("ACCESS", f"{self.client_address[0]} {fmt % args}")

    def do_GET(self):
        path = urlparse(self.path).path
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

        body = build_subscription_body(user)
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

    httpd = ThreadingHTTPServer(("0.0.0.0", port), _SubHandler)
    if certfile and keyfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        _ok(f"TLS: {certfile}")
    else:
        _warn("Сертификат не найден — подписка отдаётся по HTTP (без TLS). "
              "Поставьте сертификат Let's Encrypt на домен или проксируйте через nginx с TLS.")

    _ok(f"Слушаю :{port} …")
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
        "After=network.target\n"
        "\n"
        "[Service]\n"
        f"ExecStart={python_bin} -m vless_installer.modules.subscription serve {port}\n"
        f"WorkingDirectory={module_path}\n"
        "Restart=always\n"
        "RestartSec=3\n"
        "User=root\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "PrivateTmp=true\n"
        "ReadWritePaths=/var/lib/xray-installer /var/log\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

_NGINX_SNIPPET_TEXT = (
    "# vless-subscription — включить одной строкой внутри существующего\n"
    "# `server { listen 443 ssl; ... }` для домена:\n"
    "#   include /etc/nginx/snippets/vless-subscription.conf;\n"
    "location /sub/ {\n"
    "    proxy_pass https://127.0.0.1:8443;\n"
    "    proxy_ssl_verify off;\n"
    "    proxy_set_header Host $host;\n"
    "}\n"
)

def _fw_open_tcp(port: int) -> str:
    """Открывает TCP-порт подписки в файрволе. ufw, если активен (как
    делает основной инсталлятор в _core.py) — иначе raw iptables fallback.
    Возвращает использованный инструмент ('ufw' / 'iptables' / '' при неудаче)."""
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
    """Закрывает TCP-порт, ранее открытый _fw_open_tcp (при смене порта
    подписки старое правило иначе остаётся висеть в файрволе)."""
    if shutil.which("ufw"):
        subprocess.run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
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
        _NGINX_SNIP.write_text(_NGINX_SNIPPET_TEXT)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], check=True)
        return True
    except Exception as e:
        _err(f"Не удалось установить сервис: {e}")
        return False

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

        _box_top(f"🔁  ЕДИНАЯ ПОДПИСКА  {DIM}({NC}{status}{DIM}){NC}")
        _box_row()
        if not state or not state.get("domain"):
            _box_warn_line("state.json не найден — сначала установите сервер (раздел 1).")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"\n{CYAN}Enter…{NC}")
            return

        _box_item("1", "🚀 Включить / переустановить сервис")
        _box_item("2", "🔗 Показать ссылки подписки для всех пользователей")
        _box_item("3", f"🔄 Сгенерировать pepper заново  {DIM}(инвалидирует все ссылки){NC}")
        _box_item("4", "🛑 Выключить сервис")
        _box_item("5", f"🧩 Привязать Mieru/NaiveProxy/Telemt к UUID  {DIM}(вручную){NC}")
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

            rows = []
            for u in _load_all_users():
                if u.get("disabled") or not u.get("uuid"):
                    continue
                token = _token_for(u["uuid"], pepper)
                url = f"https://{domain}:{port}/sub/{token}"
                label = u.get("email", u.get("name", "?"))
                rows.append((label, url))

            _box_top("🔗  ССЫЛКИ ПОДПИСКИ")
            _box_row()
            if not rows:
                _box_warn_line("Нет активных пользователей.")
            for label, url in rows:
                _box_row(f"  {WHITE}{label}{NC}")
                _box_row(f"  {GREEN}{url}{NC}")
                _box_row()
            _box_back()
            _box_bottom()

            # QR — вне рамки, qrencode рисует свою фиксированную ASCII-сетку,
            # внутри box она ломает выравнивание.
            for label, url in rows:
                print()
                _print_qr(url, label)

            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "3":
            confirm = input(f"{YELLOW}Все выданные ссылки перестанут работать. Продолжить? (y/N):{NC} ")
            if confirm.lower() == "y":
                cfg["pepper"] = secrets.token_hex(32)
                _save_sub_conf(cfg)
                _ok("Pepper обновлён.")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "4":
            cfg["enabled"] = False
            _save_sub_conf(cfg)
            subprocess.run(["systemctl", "disable", "--now", SERVICE_NAME], check=False)
            _fw_close_tcp(cfg.get("listen_port", DEFAULT_PORT))
            _ok("Сервис остановлен, порт закрыт.")
            input(f"\n{BOLD}Enter…{NC}")

        elif ch == "5":
            _do_identity_map_menu(cfg)

        elif ch == "" or ch.lower() == "q" or ch == "0":
            return
        else:
            _warn("Неверный выбор.")


def _do_identity_map_menu(cfg: dict) -> None:
    users = [u for u in _load_all_users() if u.get("uuid")]
    os.system("clear")
    _box_top("🧩  ПРИВЯЗКА САТЕЛЛИТНЫХ ЛОГИНОВ К UUID")
    _box_row()
    if not users:
        _box_warn_line("Нет пользователей.")
        _box_back()
        _box_bottom()
        input(f"\n{BOLD}Enter…{NC}")
        return

    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC} {WHITE}{u.get('email', u.get('name','?'))}{NC}  "
                  f"{DIM}[{u['uuid'][:8]}…]{NC}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        idx = int(input("Номер пользователя: ").strip()) - 1
        target = users[idx]
    except (ValueError, IndexError):
        _warn("Неверный номер.")
        input(f"\n{BOLD}Enter…{NC}")
        return

    mieru_pool = set()
    if _MIERU_STATE.exists():
        mieru_pool |= {u["username"] for u in json.loads(_MIERU_STATE.read_text()).get("users", [])}
    if _MITA_HYBRID_CFG.exists():
        mieru_pool |= {u["name"] for u in json.loads(_MITA_HYBRID_CFG.read_text()).get("users", [])}
    naive_pool = set()
    if _NAIVE_STATE.exists():
        naive_pool |= {u["username"] for u in json.loads(_NAIVE_STATE.read_text()).get("users", [])}
    telemt_cfg = _parse_telemt_toml()
    telemt_pool = set(telemt_cfg["users"].keys()) if telemt_cfg else set()

    os.system("clear")
    _box_top(f"🧩  {target.get('email', target.get('name','?'))}")
    _box_row()
    _box_row(f"  Mieru доступные:      {', '.join(sorted(mieru_pool)) or '—'}")
    _box_row(f"  NaiveProxy доступные: {', '.join(sorted(naive_pool)) or '—'}")
    _box_row(f"  Telemt доступные:     {', '.join(sorted(telemt_pool)) or '—'}")
    _box_row()
    _box_bottom()

    m = input("Mieru логин (Enter — пропустить): ").strip()
    n = input("NaiveProxy логин (Enter — пропустить): ").strip()
    t = input("Telemt логин (Enter — пропустить): ").strip()

    idmap = cfg.setdefault("identity_map", {})
    entry = idmap.setdefault(target["uuid"], {})
    if m: entry["mieru"] = m
    if n: entry["naive"] = n
    if t: entry["telemt"] = t
    _save_sub_conf(cfg)
    _ok("Привязка сохранена.")
    input(f"\n{BOLD}Enter…{NC}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        p = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
        serve(p)
    else:
        do_subscription_menu()
