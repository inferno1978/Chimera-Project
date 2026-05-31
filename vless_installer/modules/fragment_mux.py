"""
vless_installer/modules/fragment_mux.py
───────────────────────────────────────────────────────────────────────────────
Mux (мультиплексирование) — несколько соединений через один TCP-туннель.

Вместо открытия нового TCP-соединения на каждый запрос, все запросы
идут через одно долгоживущее соединение. DPI видит один длинный
«непонятный» поток вместо множества коротких паттернов.

Работает в связке с фрагментацией: fragment скрывает начало соединения,
mux снижает количество новых соединений (а значит и поводов для анализа).

Xray mux (outbound.mux):
    "mux": {
        "enabled": true,
        "concurrency": 8,       # параллельных потоков в одном соединении
        "xudpConcurrency": 16,  # для UDP
        "xudpProxyUDP443": "reject"
    }

Sing-box multiplex:
    "multiplex": {
        "enabled": true,
        "protocol": "h2mux",    # h2mux / smux / yamux
        "max_connections": 4,
        "min_streams": 4,
        "padding": true
    }

ВАЖНО: серверный /etc/xray/config.json не затрагивается.

Публичное API:
    build_mux_outbound_patch(concurrency)  → dict для вставки в outbound
    build_singbox_multiplex(protocol)      → dict для вставки в outbound
    do_fragment_mux_menu()                 → Меню 4 → F7
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [MUX] [{level}] {_re.sub(chr(27)+'[0-9;]*m','',msg)}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)

# ── Импорты ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)
from vless_installer.modules.fragment_config import build_fragment_sockopt

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/state.json")
_OUT_DIR    = Path("/var/lib/xray-installer/fragment_configs")

_MUX_PRESETS = {
    "light":  {"concurrency": 4,  "xudp": 8,
               "desc": "Лёгкий  — 4 потока  (минимальный оверхед)"},
    "medium": {"concurrency": 8,  "xudp": 16,
               "desc": "Средний — 8 потоков (рекомендуется)"},
    "heavy":  {"concurrency": 16, "xudp": 32,
               "desc": "Мощный  — 16 потоков (высокая нагрузка)"},
}

_SINGBOX_PROTOCOLS = {
    "h2mux": "h2mux — HTTP/2 мультиплексирование (рекомендуется)",
    "smux":  "smux  — простой, минимальный оверхед",
    "yamux": "yamux — надёжный, совместимый",
}

# ── Публичное API ──────────────────────────────────────────────────────────

def build_mux_outbound_patch(concurrency: int = 8, xudp: int = 16) -> dict:
    """
    Возвращает dict mux для вставки в outbound Xray.
    Пример: outbound["mux"] = build_mux_outbound_patch()
    """
    return {
        "enabled":          True,
        "concurrency":      concurrency,
        "xudpConcurrency":  xudp,
        "xudpProxyUDP443":  "reject",
    }


def build_singbox_multiplex(protocol: str = "h2mux",
                             max_connections: int = 4,
                             min_streams: int = 4) -> dict:
    """
    Возвращает dict multiplex для outbound sing-box.
    Пример: outbound["multiplex"] = build_singbox_multiplex()
    """
    return {
        "enabled":         True,
        "protocol":        protocol,
        "max_connections": max_connections,
        "min_streams":     min_streams,
        "padding":         True,
    }


def _load_state() -> Optional[dict]:
    if not _STATE_FILE.exists():
        _warn("state.json не найден — сначала установите VLESS-сервер")
        return None
    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"Не удалось прочитать state.json: {e}")
        return None
    if not state.get("domain") or not state.get("uuid"):
        _warn("В state.json нет domain/uuid")
        return None
    return state


def _resolve_sni(state: dict) -> str:
    proto        = state.get("protocol_mode", "reality")
    reality_dest = state.get("reality_dest", "")
    if (proto == "reality" and state.get("awg_exit_enabled")
            and state.get("install_mode") == "B" and reality_dest):
        return reality_dest.split(":")[0]
    return state.get("domain", "")


def _build_xray_mux_json(state: dict, frag_packets: str, frag_length: str,
                          frag_interval: str, concurrency: int,
                          xudp: int) -> dict:
    """Xray JSON с fragment + mux."""
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    xtls_flow  = state.get("xtls_flow", "xtls-rprx-vision")
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "streamup")
    fp         = state.get("fingerprint", "chrome") or "chrome"
    sni        = _resolve_sni(state)

    sockopt = build_fragment_sockopt(frag_packets, frag_length, frag_interval)
    mux     = build_mux_outbound_patch(concurrency, xudp)

    # Mux несовместим с xtls-rprx-vision — при mux flow убираем
    flow = xtls_flow if (xtls_flow and proto != "reality") else None

    if proto == "xhttp":
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": domain, "port": port,
                "users": [{"id": uuid_val, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "xhttp", "security": "tls", "sockopt": sockopt,
                "tlsSettings": {"serverName": sni, "allowInsecure": False,
                                "fingerprint": fp},
                "xhttpSettings": {"path": xhttp_path, "mode": xhttp_mode},
            },
            "mux": mux,
        }
    else:
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": domain, "port": port,
                "users": [{"id": uuid_val, "encryption": "none",
                           **({"flow": flow} if flow else {})}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality", "sockopt": sockopt,
                "realitySettings": {
                    "show": False, "fingerprint": fp,
                    "serverName": sni, "publicKey": pub_key,
                    "shortId": short_id, "spiderX": "/",
                },
            },
            "mux": mux,
        }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "protocol": "socks", "listen": "127.0.0.1",
             "port": 10808, "settings": {"auth": "noauth", "udp": True}},
            {"tag": "http",  "protocol": "http",  "listen": "127.0.0.1",
             "port": 10809, "settings": {}},
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom",   "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip":     ["geoip:private"],   "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            ],
        },
    }


def _build_singbox_mux_json(state: dict, frag_packets: str, frag_length: str,
                              frag_interval: str, sb_protocol: str) -> dict:
    """Sing-box JSON с fragment + multiplex."""
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    xtls_flow  = state.get("xtls_flow", "xtls-rprx-vision")
    xhttp_path = state.get("xhttp_path", "/")
    fp         = state.get("fingerprint", "chrome") or "chrome"
    sni        = _resolve_sni(state)

    dial = {
        "tcp_fast_open": True,
        "fragment": {"enabled": True, "size": frag_length, "sleep": frag_interval},
    }
    multiplex = build_singbox_multiplex(sb_protocol)

    if proto == "reality":
        outbound = {
            "type": "vless", "tag": "vless-out",
            "server": domain, "server_port": port, "uuid": uuid_val,
            **({"flow": xtls_flow} if xtls_flow else {}),
            "tls": {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {"enabled": True, "public_key": pub_key,
                            "short_id": short_id},
            },
            "multiplex": multiplex,
            **dial,
        }
    else:
        outbound = {
            "type": "vless", "tag": "vless-out",
            "server": domain, "server_port": port, "uuid": uuid_val,
            "transport": {"type": "http", "path": xhttp_path},
            "tls": {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
            },
            "multiplex": multiplex,
            **dial,
        }

    return {
        "outbounds": [outbound],
        "inbounds": [
            {"type": "socks", "tag": "socks-in",
             "listen": "127.0.0.1", "listen_port": 10808},
            {"type": "http",  "tag": "http-in",
             "listen": "127.0.0.1", "listen_port": 10809},
        ],
        "route": {
            "rules": [
                {"ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": "direct"},
                {"geoip":   ["private"],                 "outbound": "direct"},
            ],
            "auto_detect_interface": True,
        },
    }


def do_fragment_mux_menu() -> None:
    """
    Генерация конфигов с фрагментацией + Mux.
    Вызывается из _menu_diagnostics() (пункт F7).
    """
    os.system("clear")
    print()
    _box_top("🔀  ФРАГМЕНТАЦИЯ + MUX (МУЛЬТИПЛЕКСИРОВАНИЕ)")
    _box_desc(
        "Mux объединяет несколько соединений в один TCP-туннель. "
        "DPI видит один долгий поток вместо множества коротких — "
        "сложнее классифицировать и заблокировать."
    )
    _box_sep()
    _box_info("Xray: mux несовместим с xtls-rprx-vision (flow будет отключён)")
    _box_info("Sing-box: поддерживается h2mux / smux / yamux")
    _box_warn("Серверный /etc/xray/config.json не затрагивается")
    _box_bottom()

    state = _load_state()
    if state is None:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # Шаг 1: пресет фрагментации
    print()
    _box_top("Шаг 1 из 3: пресет фрагментации")
    _box_item("1", f"⚡ Агрессивная  {DIM}length=1-3б{NC}")
    _box_item("2", f"✅ Сбалансированная  {DIM}length=3-7б{NC}")
    _box_item("3", f"🔆 Лёгкая  {DIM}length=5-15б{NC}")
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор [1-3]:{NC} ").strip()
    except KeyboardInterrupt:
        return
    frag_map = {"1": ("1-3","1-3","5-10"),
                "2": ("1-3","3-7","10-20"),
                "3": ("1-2","5-15","20-50")}
    if ch not in frag_map:
        return
    fp, fl, fi = frag_map[ch]

    # Шаг 2: пресет mux
    print()
    _box_top("Шаг 2 из 3: мультиплексирование (Xray)")
    for k, (key, p) in enumerate(_MUX_PRESETS.items(), 1):
        _box_item(str(k), p["desc"])
    _box_bottom()
    try:
        ch2 = input(f"{CYAN}Выбор [1-3]:{NC} ").strip()
    except KeyboardInterrupt:
        return
    mux_list = list(_MUX_PRESETS.values())
    if ch2 not in ("1","2","3"):
        return
    mux_cfg  = mux_list[int(ch2)-1]

    # Шаг 3: протокол sing-box
    print()
    _box_top("Шаг 3 из 3: протокол Sing-box")
    for k, (proto, desc) in enumerate(_SINGBOX_PROTOCOLS.items(), 1):
        _box_item(str(k), desc)
    _box_bottom()
    try:
        ch3 = input(f"{CYAN}Выбор [1-3]:{NC} ").strip()
    except KeyboardInterrupt:
        return
    sb_protos = list(_SINGBOX_PROTOCOLS.keys())
    if ch3 not in ("1","2","3"):
        return
    sb_proto = sb_protos[int(ch3)-1]

    # Генерация
    print()
    _info("Генерирую конфиги с fragment + mux...")
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    suffix    = f"frag_{fl.replace('-','_')}b_mux_{mux_cfg['concurrency']}x"
    xray_path = _OUT_DIR / f"xray-{suffix}.json"
    sb_path   = _OUT_DIR / f"singbox-{suffix}.json"

    try:
        xray_cfg = _build_xray_mux_json(
            state, fp, fl, fi, mux_cfg["concurrency"], mux_cfg["xudp"])
        xray_path.write_text(json.dumps(xray_cfg, ensure_ascii=False, indent=2))
        xray_path.chmod(0o600)

        sb_cfg = _build_singbox_mux_json(state, fp, fl, fi, sb_proto)
        sb_path.write_text(json.dumps(sb_cfg, ensure_ascii=False, indent=2))
        sb_path.chmod(0o600)
    except Exception as e:
        _warn(f"Ошибка записи: {e}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _ok(f"Xray:     {xray_path}")
    _ok(f"Sing-box: {sb_path}")
    _log("INFO", f"Mux configs: {xray_path} {sb_path}")

    print()
    _box_top("📋  Как использовать")
    _box_row(f"  scp root@{state.get('domain','')}:{xray_path} .")
    _box_row(f"  xray run -config {xray_path.name}")
    _box_row()
    _box_row(f"  scp root@{state.get('domain','')}:{sb_path} .")
    _box_row(f"  Sing-box: импорт через «Добавить конфиг → из файла»")
    _box_bottom()

    input(f"\n{BLUE}Нажмите Enter...{NC}")
