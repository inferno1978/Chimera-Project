"""
vless_installer/modules/fragment_noise.py
───────────────────────────────────────────────────────────────────────────────
Noise (шум) — случайные пакеты перед TLS ClientHello.

Noise дополняет фрагментацию: если DPI научился распознавать фрагментированные
паттерны, noise добавляет случайные байты перед реальным соединением — DPI
видит «мусор» и не может классифицировать трафик.

Xray sockopt.noise (v1.8.4+):
    "noise": [{"type": "rand", "packet": "10-20", "delay": "5-10"}]
    type:   "rand" (случайные байты) или "str" (фиксированная строка hex)
    packet: диапазон размера шумового пакета в байтах
    delay:  задержка перед шумом в мс

Sing-box dial_fields.noise (v1.9+):
    "noise": {"enabled": true, "type": "rand", "packet": "10-20", "delay": "5-10"}

ВАЖНО: серверный /etc/xray/config.json не затрагивается.

Публичное API:
    build_noise_sockopt(packets, length, interval, noise_packet, noise_delay)
        → dict sockopt с fragment + noise
    do_fragment_noise_menu()
        → интерактивное меню (Меню 4 → F6)
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
            f.write(f"[{ts}] [NOISE] [{level}] {_re.sub(chr(27)+'[0-9;]*m','',msg)}\n")
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
from vless_installer.modules.fragment_config import (
    build_fragment_sockopt, _validate_range_str, _FRAGMENT_PRESETS,
)

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/state.json")
_OUT_DIR    = Path("/var/lib/xray-installer/fragment_configs")

# Пресеты noise
_NOISE_PRESETS = {
    "light":      {"packet": "10-20",  "delay": "5-10",
                   "desc": "Лёгкий  — 10–20 байт, 5–10 мс"},
    "medium":     {"packet": "20-50",  "delay": "10-20",
                   "desc": "Средний — 20–50 байт, 10–20 мс"},
    "aggressive": {"packet": "50-100", "delay": "15-30",
                   "desc": "Агрессивный — 50–100 байт, 15–30 мс"},
}

# ── Публичное API ──────────────────────────────────────────────────────────

def build_noise_sockopt(
    packets: str = "1-3",
    length: str  = "3-7",
    interval: str = "10-20",
    noise_packet: str = "20-50",
    noise_delay: str  = "10-20",
) -> dict:
    """
    Возвращает sockopt с fragment + noise.
    Используется fragment_link.py, fragment_presets.py.

    noise_packet: диапазон размера шумового пакета в байтах ("20-50")
    noise_delay:  задержка перед шумом в мс ("10-20")
    """
    sockopt = build_fragment_sockopt(packets, length, interval)
    sockopt["noise"] = [
        {
            "type":   "rand",
            "packet": noise_packet,
            "delay":  noise_delay,
        }
    ]
    return sockopt


def build_singbox_noise_dial(
    packets: str = "1-3",
    length: str  = "3-7",
    interval: str = "10-20",
    noise_packet: str = "20-50",
    noise_delay: str  = "10-20",
) -> dict:
    """
    Возвращает dial_fields для sing-box с fragment + noise.
    Используется fragment_link.py при генерации Sing-box конфига.
    """
    return {
        "tcp_fast_open": True,
        "fragment": {
            "enabled": True,
            "size":    length,
            "sleep":   interval,
        },
        "noise": {
            "enabled": True,
            "type":    "rand",
            "packet":  noise_packet,
            "delay":   noise_delay,
        },
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
    domain       = state.get("domain", "")
    reality_dest = state.get("reality_dest", "")
    if (proto == "reality" and state.get("awg_exit_enabled")
            and state.get("install_mode") == "B" and reality_dest):
        return reality_dest.split(":")[0]
    return domain


def _build_xray_noise_json(
    state: dict,
    frag_packets: str, frag_length: str, frag_interval: str,
    noise_packet: str, noise_delay: str,
) -> dict:
    """Полный клиентский Xray JSON с fragment + noise."""
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

    sockopt = build_noise_sockopt(
        frag_packets, frag_length, frag_interval, noise_packet, noise_delay
    )

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
        }
    else:
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": domain, "port": port,
                "users": [{"id": uuid_val, "encryption": "none",
                           **({"flow": xtls_flow} if xtls_flow else {})}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality", "sockopt": sockopt,
                "realitySettings": {
                    "show": False, "fingerprint": fp,
                    "serverName": sni, "publicKey": pub_key,
                    "shortId": short_id, "spiderX": "/",
                },
            },
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


def _build_singbox_noise_json(
    state: dict,
    frag_packets: str, frag_length: str, frag_interval: str,
    noise_packet: str, noise_delay: str,
) -> dict:
    """Sing-box JSON с fragment + noise."""
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

    dial = build_singbox_noise_dial(
        frag_packets, frag_length, frag_interval, noise_packet, noise_delay
    )

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


def do_fragment_noise_menu() -> None:
    """
    Генерация конфигов с фрагментацией + noise.
    Вызывается из _menu_diagnostics() в _core.py (пункт F6).
    """
    os.system("clear")
    print()
    _box_top("🔊  ФРАГМЕНТАЦИЯ + NOISE (ШУМ)")
    _box_desc(
        "Noise добавляет случайные пакеты перед TLS ClientHello. "
        "Если DPI научился распознавать фрагментацию — "
        "noise делает трафик полностью непредсказуемым."
    )
    _box_sep()
    _box_info("Требуется Xray v1.8.4+ на клиенте")
    _box_info("Sing-box: версия 1.9+")
    _box_warn("Серверный /etc/xray/config.json не затрагивается")
    _box_bottom()

    state = _load_state()
    if state is None:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    # ── Выбор пресета фрагментации ─────────────────────────────────────
    print()
    _box_top("Шаг 1 из 2: пресет фрагментации")
    _box_item("1", f"⚡ Агрессивная  {DIM}packets=1-3 length=1-3б{NC}")
    _box_item("2", f"✅ Сбалансированная  {DIM}packets=1-3 length=3-7б{NC}")
    _box_item("3", f"🔆 Лёгкая  {DIM}packets=1-2 length=5-15б{NC}")
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор [1-3]:{NC} ").strip()
    except KeyboardInterrupt:
        return

    frag_map = {
        "1": ("1-3", "1-3",  "5-10"),
        "2": ("1-3", "3-7",  "10-20"),
        "3": ("1-2", "5-15", "20-50"),
    }
    if ch not in frag_map:
        return
    frag_packets, frag_length, frag_interval = frag_map[ch]

    # ── Выбор пресета noise ────────────────────────────────────────────
    print()
    _box_top("Шаг 2 из 2: интенсивность шума (noise)")
    _box_item("1", f"🔅 {_NOISE_PRESETS['light']['desc']}")
    _box_item("2", f"🔆 {_NOISE_PRESETS['medium']['desc']}")
    _box_item("3", f"🔊 {_NOISE_PRESETS['aggressive']['desc']}")
    _box_bottom()

    try:
        ch2 = input(f"{CYAN}Выбор [1-3]:{NC} ").strip()
    except KeyboardInterrupt:
        return

    noise_map = {
        "1": _NOISE_PRESETS["light"],
        "2": _NOISE_PRESETS["medium"],
        "3": _NOISE_PRESETS["aggressive"],
    }
    if ch2 not in noise_map:
        return
    noise_cfg = noise_map[ch2]
    noise_packet = noise_cfg["packet"]
    noise_delay  = noise_cfg["delay"]

    # ── Генерация ──────────────────────────────────────────────────────
    print()
    _info("Генерирую конфиги с fragment + noise...")

    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    suffix      = f"frag_{frag_length.replace('-','_')}b_noise_{noise_packet.replace('-','_')}b"
    xray_path   = _OUT_DIR / f"xray-{suffix}.json"
    sb_path     = _OUT_DIR / f"singbox-{suffix}.json"

    try:
        xray_cfg = _build_xray_noise_json(
            state, frag_packets, frag_length, frag_interval,
            noise_packet, noise_delay,
        )
        xray_path.write_text(json.dumps(xray_cfg, ensure_ascii=False, indent=2))
        xray_path.chmod(0o600)

        sb_cfg = _build_singbox_noise_json(
            state, frag_packets, frag_length, frag_interval,
            noise_packet, noise_delay,
        )
        sb_path.write_text(json.dumps(sb_cfg, ensure_ascii=False, indent=2))
        sb_path.chmod(0o600)
    except Exception as e:
        _warn(f"Ошибка записи файлов: {e}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _ok(f"Xray:     {xray_path}")
    _ok(f"Sing-box: {sb_path}")
    _log("INFO", f"Noise configs: {xray_path} {sb_path}")

    print()
    _box_top("📋  Как использовать")
    _box_row(f"  {BOLD}Xray (Linux/macOS/Windows):{NC}")
    _box_row(f"    scp root@{state.get('domain','')}:{xray_path} .")
    _box_row(f"    xray run -config {xray_path.name}")
    _box_row()
    _box_row(f"  {BOLD}Sing-box (Android/iOS/Desktop):{NC}")
    _box_row(f"    scp root@{state.get('domain','')}:{sb_path} .")
    _box_row(f"    Импорт через «Добавить конфиг → из файла»")
    _box_row()
    _box_info("Хapp, Incy — noise поддерживается через &noise= в URI")
    _box_info("v2rayNG — импортируйте JSON-файл")
    _box_bottom()

    input(f"\n{BLUE}Нажмите Enter...{NC}")
