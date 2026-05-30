"""
vless_installer/modules/fragment_link.py
───────────────────────────────────────────────────────────────────────────────
Генерация клиентских ссылок, QR-кодов и конфигов с фрагментацией.

Поддерживаемые клиенты и форматы fragment в URI (из официальной документации):

  Клиент          Формат параметра в vless://               «Просто QR»
  ─────────────── ──────────────────────────────────────── ─────────────
  Happ            &fragment=length,interval,packets          ✅ да
  Incy            &fragmentLength=L&fragmentInterval=I       ✅ да
  Nekoray/Nekobox &fragment=packets,length,interval          ✅ да
  NyameBox (ПК)   не поддерживается в URI                   ❌ нет
  v2rayNG         не поддерживается в URI                   ❌ нет
  Hiddify         не поддерживается в URI                   ❌ нет

  Для клиентов без поддержки URI:
    → Xray JSON-конфиг (xray-client-*.json) через scp + импорт из файла
    → Sing-box JSON  (singbox-client-*.json) через scp + импорт из файла

ИСТОЧНИКИ:
  Happ:    https://www.happ.su/main/dev-docs/examples-of-links-and-parameters
  Incy:    https://incy.gitbook.io/docs/docs-en/developer-documentation/config-parameters
  Nekobox: собственный расширенный формат URI (sing-box core)

ВАЖНО: функция _gen_vless_link из _core.py НЕ изменяется.
  Каждый клиент — отдельная функция генерации только внутри этого файла.

ВАЖНО: серверный /etc/xray/config.json не затрагивается.

Точка входа из _core.py:
    from vless_installer.modules.fragment_link import do_fragment_link_menu
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
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', MAGENTA='\033[0;35m',
                BOLD='\033[1m', DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', MAGENTA='\033[0;35m',
                BOLD='\033[1m', DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in (
        'RED','GREEN','YELLOW','CYAN','BLUE','MAGENTA','BOLD','DIM','WHITE','NC'
    )}

_C = _detect_colors()
RED     = _C['RED'];   GREEN   = _C['GREEN'];   YELLOW  = _C['YELLOW']
CYAN    = _C['CYAN'];  BLUE    = _C['BLUE'];    MAGENTA = _C['MAGENTA']
BOLD    = _C['BOLD'];  DIM     = _C['DIM'];     WHITE   = _C['WHITE']
NC      = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [FRAG_LINK] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)  -> None: print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def _ok(msg: str)    -> None: print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str)  -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)

# ── Импорты из модулей проекта ────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_ok, _box_desc, _box_link, _get_box_width,
)
from vless_installer.modules.fragment_config import (
    build_fragment_sockopt,
    _FRAGMENT_PRESETS,
    _validate_range_str,
)

# ── Делегирование в _core.py (без circular import, без дублирования) ──────
def _core_call(func_name: str, *args, **kwargs):
    _core = importlib.import_module("vless_installer._core")
    return getattr(_core, func_name)(*args, **kwargs)

def _show_qr(link: str, label: str, png_path: str) -> None:
    _core_call("_show_qr", link, label, png_path)

def _gen_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                    proto="reality", xhttp_path="/", xhttp_mode="streamup",
                    port=443) -> str:
    """Стандартная ссылка без fragment — делегируем в _core.py без изменений."""
    return _core_call(
        "_gen_vless_link",
        host, uuid_str, pbk, sid, domain, fp, proto, xhttp_path, xhttp_mode, port,
    )

def _get_server_ip(ip_type: str = "4") -> str:
    return _core_call("get_server_ip", ip_type)

def _get_server_country_cached():
    return _core_call("get_server_country_cached")

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/state.json")
_OUT_DIR    = Path("/root/xray-client-configs")

# ── Вычисление SNI ────────────────────────────────────────────────────────
def _resolve_sni(state: dict) -> str:
    proto        = state.get("protocol_mode", "reality")
    domain       = state.get("domain", "")
    reality_dest = state.get("reality_dest", "")
    awg_exit     = state.get("awg_exit_enabled", False)
    install_mode = state.get("install_mode", "A")
    if proto == "reality" and awg_exit and install_mode == "B" and reality_dest:
        return reality_dest.split(":")[0]
    return domain

# ── Получение флага и префикса страны ────────────────────────────────────
def _flag_prefix() -> str:
    try:
        _, _, flag = _get_server_country_cached()
        return f"{flag} " if flag and flag != "🌐" else ""
    except Exception:
        return ""

# ── Базовые части URI (без параметров fragment) ───────────────────────────
def _base_uri_params(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    fp: str, proto: str, xhttp_path: str, xhttp_mode: str, port: int,
) -> str:
    """Возвращает vless://uuid@host:port?<базовые параметры> без fragment и без #label."""
    import urllib.parse
    if proto == "xhttp":
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=xhttp&security=tls&sni={sni}"
            f"&path={path_enc}&mode={xhttp_mode}&fp={fp}"
        )
    else:
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}&flow=xtls-rprx-vision"
        )

# ══════════════════════════════════════════════════════════════════════════
# ГЕНЕРАТОРЫ ССЫЛОК — по одной функции на каждый клиент
# ══════════════════════════════════════════════════════════════════════════

def _gen_happ_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "streamup", port: int = 443,
) -> str:
    """
    Happ (iOS/Android/Desktop, Xray-core).
    Документация: https://www.happ.su/main/dev-docs/examples-of-links-and-parameters
    Формат: &fragment=length,interval,packets
    Пример: &fragment=3-7,10-20,1-3
    """
    import urllib.parse
    base   = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto, xhttp_path, xhttp_mode, port)
    frag   = urllib.parse.quote(f"{length},{interval},{packets}")
    label  = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Happ"
    return f"{base}&fragment={frag}#{label}"


def _gen_incy_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "streamup", port: int = 443,
) -> str:
    """
    Incy (iOS/Android/Desktop/TV, Xray-core).
    Документация: https://incy.gitbook.io/docs/docs-en/developer-documentation/config-parameters
    Формат: &fragmentLength=length&fragmentInterval=interval
    Пример: &fragmentLength=3-7&fragmentInterval=10-20
    Примечание: packets в URI Incy не передаётся — клиент использует
    дефолтный пакет tlshello автоматически при tls/reality.
    """
    import urllib.parse
    base  = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto, xhttp_path, xhttp_mode, port)
    label = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Incy"
    return f"{base}&fragmentLength={length}&fragmentInterval={interval}#{label}"


def _gen_nekoray_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "streamup", port: int = 443,
) -> str:
    """
    Nekoray / Nekobox (Desktop, sing-box core).
    Формат: &fragment=packets,length,interval
    Пример: &fragment=1-3,3-7,10-20
    Примечание: NyameBox (qr243vbi/nekobox) — тот же формат, но
    поддержка fragment в URI нестабильна, рекомендуется JSON-файл.
    """
    import urllib.parse
    base   = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto, xhttp_path, xhttp_mode, port)
    frag   = urllib.parse.quote(f"{packets},{length},{interval}")
    label  = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Neko"
    return f"{base}&fragment={frag}#{label}"

# ══════════════════════════════════════════════════════════════════════════
# ГЕНЕРАЦИЯ JSON-КОНФИГОВ
# ══════════════════════════════════════════════════════════════════════════

def _build_xray_client_json(state: dict, packets: str, length: str,
                             interval: str) -> dict:
    """Полный клиентский Xray config.json с fragment в sockopt."""
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

    sockopt = (
        build_fragment_sockopt(packets, length, interval)
        if packets and length and interval
        else {
            "tcpFastOpen": True,
            "tcpKeepAliveInterval": 15,
            "tcpKeepAliveIdle": 60,
            "tcpUserTimeout": 10000,
            "tcpCongestion": "bbr",
        }
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
            {"tag": "http", "protocol": "http", "listen": "127.0.0.1",
             "port": 10809, "settings": {}},
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip":     ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            ],
        },
    }


def _build_singbox_json(state: dict, packets: str, length: str,
                        interval: str) -> dict:
    """Sing-box outbound с нативным fragment."""
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

    dial_fields: dict = {}
    if packets and length and interval:
        dial_fields["tcp_fast_open"] = True
        dial_fields["fragment"] = {"enabled": True, "size": length, "sleep": interval}

    if proto == "reality":
        outbound = {
            "type": "vless", "tag": "vless-out",
            "server": domain, "server_port": port, "uuid": uuid_val,
            **({"flow": xtls_flow} if xtls_flow else {}),
            "tls": {
                "enabled": True, "server_name": sni,
                "utls": {"enabled": True, "fingerprint": fp},
                "reality": {"enabled": True, "public_key": pub_key, "short_id": short_id},
            },
            **dial_fields,
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
            **dial_fields,
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
                {"geoip": ["private"], "outbound": "direct"},
            ],
            "auto_detect_interface": True,
        },
    }

# ══════════════════════════════════════════════════════════════════════════
# ВЫБОР ПРЕСЕТА
# ══════════════════════════════════════════════════════════════════════════

def _pick_fragment_preset() -> Optional[tuple[str, str, str]]:
    """Возвращает (packets, length, interval) или None при отмене."""
    print()
    _box_top("🔀  Выберите пресет фрагментации")
    _box_row()
    _box_item("1", f"⚡ Агрессивная    {DIM}packets=1-3  length=1-3б   interval=5-10мс{NC}")
    _box_item("2", f"✅ Сбалансированная  {DIM}packets=1-3  length=3-7б   interval=10-20мс{NC}")
    _box_item("3", f"🔆 Лёгкая         {DIM}packets=1-2  length=5-15б  interval=20-50мс{NC}")
    _box_item("4", f"⚙️  Своя           {DIM}ввести параметры вручную{NC}")
    _box_sep()
    _box_item("0", f"Без фрагментации  {DIM}стандартная ссылка + QR{NC}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip()
    except KeyboardInterrupt:
        return None

    preset_map = {
        "1": ("1-3", "1-3",  "5-10"),
        "2": ("1-3", "3-7",  "10-20"),
        "3": ("1-2", "5-15", "20-50"),
    }

    if ch == "0":
        return ("", "", "")

    if ch in preset_map:
        packets, length, interval = preset_map[ch]
        name = {"1": "aggressive", "2": "balanced", "3": "light"}[ch]
        _info(f"Пресет: {_FRAGMENT_PRESETS[name]['desc']}")
        return (packets, length, interval)

    if ch == "4":
        print()
        _info("Введите параметры (диапазон: N или N-M, например 3-7):")
        print()
        try:
            raw_packets  = input(f"  {CYAN}packets {DIM}(сегменты, напр. 1-3){NC}:  ").strip() or "1-3"
            raw_length   = input(f"  {CYAN}length  {DIM}(байты,    напр. 3-7){NC}:  ").strip() or "3-7"
            raw_interval = input(f"  {CYAN}interval{DIM}(мс,       напр. 10-20){NC}: ").strip() or "10-20"
        except KeyboardInterrupt:
            return None
        ok = (
            _validate_range_str(raw_packets,  "packets")
            and _validate_range_str(raw_length,   "length")
            and _validate_range_str(raw_interval, "interval")
        )
        if not ok:
            time.sleep(2)
            return None
        return (raw_packets, raw_length, raw_interval)

    if ch.lower() in ("q", ""):
        return None

    _warn("Неверный выбор.")
    return None

# ══════════════════════════════════════════════════════════════════════════
# ПОКАЗ ССЫЛОК И QR
# ══════════════════════════════════════════════════════════════════════════

def _show_links_and_qr(state: dict, packets: str, length: str,
                        interval: str) -> None:
    """Выводит ссылки всех форматов и QR-коды."""
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    fp         = state.get("fingerprint", "chrome") or "chrome"
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "streamup")
    sni        = _resolve_sni(state)
    ipv4       = _get_server_ip("4")

    has_fragment = bool(packets and length and interval)

    def _show_for_host(host: str, host_label: str) -> None:
        if has_fragment:
            # Happ
            happ = _gen_happ_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {GREEN}🔵 Happ {DIM}({host_label}){NC}  {DIM}← QR достаточно{NC}")
            _box_link(happ)
            print()
            _show_qr(happ, f"Happ {host_label}", f"/root/vless_qr_happ_{host_label.lower()}.png")

            # Incy
            incy = _gen_incy_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {CYAN}🔵 Incy {DIM}({host_label}){NC}  {DIM}← QR достаточно{NC}")
            _box_link(incy)
            print()
            _show_qr(incy, f"Incy {host_label}", f"/root/vless_qr_incy_{host_label.lower()}.png")

            # Nekoray / Nekobox
            neko = _gen_nekoray_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {MAGENTA}🔵 Nekoray/Nekobox {DIM}({host_label}){NC}  {DIM}← QR достаточно{NC}")
            _box_link(neko)
            print()
            _show_qr(neko, f"Nekoray {host_label}", f"/root/vless_qr_neko_{host_label.lower()}.png")

            # Универсальная (без fragment)
            std = _gen_vless_link(
                host, uuid_val, pub_key, short_id, sni, fp,
                proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {YELLOW}📱 Универсальная {DIM}({host_label}) — v2rayNG, NyameBox, Hiddify{NC}")
            print(f"     {DIM}Фрагментацию нужно включить вручную в настройках клиента.{NC}")
            _box_link(std)
        else:
            std = _gen_vless_link(
                host, uuid_val, pub_key, short_id, sni, fp,
                proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {GREEN}📡 Стандартная ссылка {DIM}({host_label}){NC}")
            _box_link(std)
            print()
            _show_qr(std, f"Стандартная {host_label}", f"/root/vless_qr_{host_label.lower()}.png")

    frag_label = f"fragment {length}б/{interval}мс" if has_fragment else "без фрагментации"
    print()
    _box_top(f"🔗  ССЫЛКИ  ({frag_label})")

    if ipv4:
        _box_sep()
        _box_row(f"  {BOLD}IPv4: {ipv4}{NC}")
        _box_sep()
        _show_for_host(ipv4, "IPv4")

    _box_sep()
    _box_row(f"  {BOLD}Domain: {domain}{NC}")
    _box_sep()
    _show_for_host(domain, "Domain")

    _box_bottom()

# ══════════════════════════════════════════════════════════════════════════
# МИНИ-ГАЙД
# ══════════════════════════════════════════════════════════════════════════

def _print_client_guide(has_fragment: bool, domain: str,
                        xray_path: Path, singbox_path: Path,
                        frag_suffix: str) -> None:
    """
    Мини-гайд: кому что делать в зависимости от клиента.
    Основан на официальной документации каждого клиента.
    """
    w = _get_box_width()
    line = "─" * min(w - 4, 54)

    print()
    print(f"  {BOLD}{CYAN}══  КАК ПОДКЛЮЧИТЬСЯ  ══{NC}")
    print()

    if has_fragment:

        # ── Группа 1: клиенты с поддержкой fragment в URI (просто QR) ─────
        print(f"  {GREEN}{BOLD}✅  QR/ссылка — фрагментация включается автоматически:{NC}")
        print(f"  {line}")
        print()

        print(f"  {GREEN}•{NC} {BOLD}Happ{NC}  {DIM}(iOS / Android / macOS / Windows / Linux / TV){NC}")
        print(f"    Отсканируйте QR «Happ» или скопируйте ссылку с меткой 🔵Happ.")
        print(f"    {DIM}Формат fragment: length,interval,packets — официальный стандарт Happ.{NC}")
        print()

        print(f"  {GREEN}•{NC} {BOLD}Incy{NC}  {DIM}(iOS / Android / macOS / Windows / Linux / TV){NC}")
        print(f"    Отсканируйте QR «Incy» или скопируйте ссылку с меткой 🔵Incy.")
        print(f"    {DIM}Формат: fragmentLength + fragmentInterval — официальный стандарт Incy.{NC}")
        print()

        print(f"  {GREEN}•{NC} {BOLD}Nekoray / Nekobox{NC}  {DIM}(Desktop: Windows / Linux / macOS){NC}")
        print(f"    Отсканируйте QR «Nekoray» или скопируйте ссылку с меткой 🔵Neko.")
        print(f"    {DIM}Формат: fragment=packets,length,interval (sing-box URI extension).{NC}")
        print()

        # ── Группа 2: клиенты без поддержки fragment в URI ────────────────
        print(f"  {YELLOW}{BOLD}⚠️   Нужен JSON-файл — QR только для подключения, без фрагментации:{NC}")
        print(f"  {line}")
        print()

        print(f"  {YELLOW}•{NC} {BOLD}NyameBox (ПК){NC}  {DIM}(qr243vbi/nekobox — Desktop){NC}")
        print(f"    Fragment в URI нестабилен в этом форке.")
        print(f"    {DIM}→ Импортируйте Sing-box JSON:{NC}")
        print(f"    {DIM}  scp root@{domain}:{singbox_path} ./{NC}")
        print(f"    {DIM}  «Добавить сервер» → «Импорт из файла» → {singbox_path.name}{NC}")
        print()

        print(f"  {YELLOW}•{NC} {BOLD}v2rayNG{NC}  {DIM}(Android){NC}")
        print(f"    Импортируйте Xray JSON-конфиг:")
        print(f"    {DIM}  scp root@{domain}:{xray_path} ./{NC}")
        print(f"    {DIM}  ⊕ → «Импорт конфигурации из файла» → {xray_path.name}{NC}")
        print(f"    {DIM}  Либо: отсканируйте «Универсальную» ссылку, затем включите{NC}")
        print(f"    {DIM}  фрагментацию вручную в настройках подключения.{NC}")
        print()

        print(f"  {YELLOW}•{NC} {BOLD}Hiddify{NC}  {DIM}(Android / iOS / Desktop){NC}")
        print(f"    Импортируйте Sing-box JSON:")
        print(f"    {DIM}  scp root@{domain}:{singbox_path} ./{NC}")
        print(f"    {DIM}  «Добавить» → «Из файла» → {singbox_path.name}{NC}")
        print()

        print(f"  {CYAN}•{NC} {BOLD}Xray на Linux / macOS / Windows{NC}")
        print(f"    {DIM}  scp root@{domain}:{xray_path} ./{NC}")
        print(f"    {DIM}  xray run -config {xray_path.name}{NC}")
        print(f"    {DIM}  → socks5://127.0.0.1:10808   http://127.0.0.1:10809{NC}")
        print()

    else:
        print(f"  {GREEN}{BOLD}Любой клиент:{NC}")
        print(f"  {line}")
        print(f"  Отсканируйте QR-код или скопируйте ссылку выше.")
        print(f"  Фрагментация не применяется.")
        print()

    print(f"  {DIM}Файлы JSON на сервере:{NC}")
    print(f"    {DIM}{xray_path}   — Xray{NC}")
    print(f"    {DIM}{singbox_path}   — Sing-box{NC}")
    print(f"  {DIM}Скачать всё: scp root@{domain}:{_OUT_DIR}/*{frag_suffix}* ./{NC}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# ЗАГРУЗКА STATE
# ══════════════════════════════════════════════════════════════════════════

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
        _warn("В state.json нет domain/uuid — завершите установку сервера")
        return None
    return state

# ══════════════════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════

def do_fragment_link_menu() -> None:
    """
    Генерация ссылок и конфигов с фрагментацией.
    Вызывается из _menu_users() в _core.py (пункт F).
    """
    os.system("clear")
    print()
    _box_top("🔀  ССЫЛКИ И КОНФИГИ С ФРАГМЕНТАЦИЕЙ")
    _box_desc(
        "Генерирует ссылки для Happ, Incy, Nekoray (QR = готово) "
        "и JSON-конфиги для v2rayNG, NyameBox, Hiddify, Xray."
    )
    _box_row()
    _box_info("Серверный конфиг /etc/xray/config.json не затрагивается.")
    _box_bottom()

    state = _load_state()
    if state is None:
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    result = _pick_fragment_preset()
    if result is None:
        return

    packets, length, interval = result
    has_fragment = bool(packets and length and interval)

    safe = lambda s: s.replace("-", "_")
    frag_suffix = f"fragment_{safe(length)}b_{safe(interval)}ms" if has_fragment else "no_fragment"

    # Генерируем JSON-конфиги
    print()
    _info("Генерирую JSON-конфиги...")
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    xray_path    = _OUT_DIR / f"xray-client-{frag_suffix}.json"
    singbox_path = _OUT_DIR / f"singbox-client-{frag_suffix}.json"

    try:
        xray_path.write_text(
            json.dumps(_build_xray_client_json(state, packets, length, interval),
                       ensure_ascii=False, indent=2)
        )
        xray_path.chmod(0o600)
        singbox_path.write_text(
            json.dumps(_build_singbox_json(state, packets, length, interval),
                       ensure_ascii=False, indent=2)
        )
        singbox_path.chmod(0o600)
        _ok(f"Xray JSON:  {xray_path}")
        _ok(f"Sing-box:   {singbox_path}")
    except Exception as e:
        _warn(f"Ошибка записи файлов: {e}")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    _log("INFO", (
        f"Fragment configs generated: {xray_path}, {singbox_path} "
        f"[packets={packets} length={length} interval={interval}]"
    ))

    # Ссылки и QR
    _show_links_and_qr(state, packets, length, interval)

    # Мини-гайд
    _print_client_guide(
        has_fragment,
        state.get("domain", ""),
        xray_path,
        singbox_path,
        frag_suffix,
    )

    input(f"{BLUE}Нажмите Enter...{NC}")
