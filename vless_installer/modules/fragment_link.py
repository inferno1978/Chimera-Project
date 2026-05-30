"""
vless_installer/modules/fragment_link.py
───────────────────────────────────────────────────────────────────────────────
Генерация клиентских ссылок, QR-кодов и конфигов с фрагментацией.

Что делает этот модуль:
  1. Берёт параметры из state.json (domain, uuid, public_key, …)
  2. Предлагает выбрать пресет фрагментации (или ввести свои)
  3. Генерирует ДВА варианта ссылки:
       A) Nekoray/Nekobox — расширенный vless:// URI с параметрами fragment
          в query string (&fragment=packets,length,interval).
          Импортируется одним QR или копированием — фрагментация работает сразу.
       B) Универсальная vless:// без fragment — для v2rayNG, Hiddify и прочих.
          Фрагментацию придётся включить вручную в настройках клиента.
  4. Генерирует полный клиентский Xray JSON-конфиг с fragment в sockopt
  5. Генерирует Sing-box JSON с нативным fragment (sing-box поддерживает)
  6. Выводит мини-гайд: кому что использовать

ФОРМАТ fragment в Nekoray/Nekobox URI:
  Nekobox (sing-box core) принимает дополнительные параметры в vless:// URI:
    &fragment=<packets>,<length>,<interval>
  Пример:
    vless://uuid@host:443?type=tcp&security=reality&...&fragment=1-3,3-7,10-20#label
  Это нестандартное расширение — работает только в Nekoray / Nekobox.
  Другие клиенты игнорируют неизвестные параметры (не ломаются, просто
  фрагментация не применяется).

ВАЖНО: функция _gen_vless_link из _core.py НЕ модифицируется.
  Nekoray-ссылка генерируется отдельной функцией _gen_nekoray_link()
  только внутри этого файла, не затрагивая никакой существующий код.

ВАЖНО: серверный /etc/xray/config.json не затрагивается ни при каких условиях.

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
    """Вызов функции из _core.py через importlib — не дублируем логику."""
    _core = importlib.import_module("vless_installer._core")
    return getattr(_core, func_name)(*args, **kwargs)

def _show_qr(link: str, label: str, png_path: str) -> None:
    _core_call("_show_qr", link, label, png_path)

def _gen_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                    proto="reality", xhttp_path="/", xhttp_mode="streamup",
                    port=443) -> str:
    """Стандартная ссылка — делегируем в _core.py без изменений."""
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

# ── Чтение state.json ─────────────────────────────────────────────────────
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

# ── Вычисление SNI из state ───────────────────────────────────────────────
def _resolve_sni(state: dict) -> str:
    """
    Определяет правильный SNI по тем же правилам что и do_generate_client_config.
    Mode B + AWG → reality_dest; иначе → domain.
    """
    proto        = state.get("protocol_mode", "reality")
    domain       = state.get("domain", "")
    reality_dest = state.get("reality_dest", "")
    awg_exit     = state.get("awg_exit_enabled", False)
    install_mode = state.get("install_mode", "A")
    if proto == "reality" and awg_exit and install_mode == "B" and reality_dest:
        return reality_dest.split(":")[0]
    return domain

# ── Генерация Nekoray/Nekobox-ссылки с fragment ───────────────────────────
def _gen_nekoray_link(
    host: str,
    uuid_str: str,
    pbk: str,
    sid: str,
    domain: str,
    packets: str,
    length: str,
    interval: str,
    fp: str = "chrome",
    proto: str = "reality",
    xhttp_path: str = "/",
    xhttp_mode: str = "streamup",
    port: int = 443,
) -> str:
    """
    Генерирует vless:// URI с параметром &fragment=<packets>,<length>,<interval>
    в формате Nekoray / Nekobox (sing-box core).

    Формат fragment-параметра: packets,length,interval
    Пример: 1-3,3-7,10-20

    Эта функция НЕ изменяет и НЕ вызывает _gen_vless_link из _core.py —
    полностью независимая реализация только для Nekoray/Nekobox.
    Существующая генерация ссылок в проекте не затрагивается.
    """
    import urllib.parse

    try:
        _, _, _flag = _get_server_country_cached()
        _flag_prefix = f"{_flag} " if _flag and _flag != "🌐" else ""
    except Exception:
        _flag_prefix = ""

    label = _flag_prefix + urllib.parse.quote(domain) + "%20%F0%9F%94%80frag"

    frag_param = f"{packets},{length},{interval}"

    if proto == "xhttp":
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=xhttp&security=tls&sni={domain}"
            f"&path={path_enc}&mode={xhttp_mode}"
            f"&fp={fp}"
            f"&fragment={urllib.parse.quote(frag_param)}"
            f"#{label}"
        )
    else:
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={domain}&sid={sid}"
            f"&flow=xtls-rprx-vision"
            f"&fragment={urllib.parse.quote(frag_param)}"
            f"#{label}"
        )

# ── Выбор пресета ─────────────────────────────────────────────────────────
def _pick_fragment_preset() -> Optional[tuple[str, str, str]]:
    """
    Возвращает (packets, length, interval) или None при отмене.
    Пустые строки означают «без фрагментации».
    """
    print()
    _box_top("🔀  Выберите пресет фрагментации")
    _box_row()
    _box_item("1", f"⚡ Агрессивная    {DIM}packets=1-3  length=1-3б   interval=5-10мс{NC}")
    _box_item("2", f"✅ Сбалансированная  {DIM}packets=1-3  length=3-7б   interval=10-20мс{NC}")
    _box_item("3", f"🔆 Лёгкая         {DIM}packets=1-2  length=5-15б  interval=20-50мс{NC}")
    _box_item("4", f"⚙️  Своя           {DIM}ввести параметры вручную{NC}")
    _box_sep()
    _box_item("0", f"Без фрагментации  {DIM}стандартная ссылка{NC}")
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

# ── Генерация Xray JSON-конфига ───────────────────────────────────────────
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

# ── Генерация Sing-box JSON ───────────────────────────────────────────────
def _build_singbox_json(state: dict, packets: str, length: str,
                        interval: str) -> dict:
    """Sing-box outbound с нативным fragment (sing-box >= 1.8)."""
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
        dial_fields["fragment"] = {
            "enabled": True,
            "size":    length,
            "sleep":   interval,
        }

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

# ── Мини-гайд для пользователя ────────────────────────────────────────────
def _print_client_guide(has_fragment: bool, domain: str,
                        xray_path: Path, singbox_path: Path,
                        frag_label: str) -> None:
    """
    Выводит понятный мини-гайд: кому что делать в зависимости от клиента.
    Вызывается после показа ссылок и QR-кодов.
    """
    w = _get_box_width()
    line = "─" * (w - 2)

    print()
    print(f"  {BOLD}{CYAN}{'─'*((w-28)//2)}  КАК ИСПОЛЬЗОВАТЬ ЭТОТ КОНФИГ  {'─'*((w-28)//2)}{NC}")
    print()

    if has_fragment:
        # ── Блок 1: Nekoray / Nekobox ──────────────────────────────────────
        print(f"  {GREEN}{BOLD}┌─ Nekoray / Nekobox{NC}  {GREEN}← фрагментация работает из коробки{NC}")
        print(f"  {GREEN}│{NC}")
        print(f"  {GREEN}│{NC}  Отсканируйте QR «Nekoray» выше ИЛИ скопируйте ссылку")
        print(f"  {GREEN}│{NC}  с пометкой 🔀frag и добавьте в Nekoray/Nekobox.")
        print(f"  {GREEN}│{NC}  Фрагментация включится автоматически — ничего больше")
        print(f"  {GREEN}│{NC}  делать не нужно.")
        print(f"  {GREEN}└──────────────────────────────────────────────────{NC}")
        print()

        # ── Блок 2: v2rayNG ────────────────────────────────────────────────
        print(f"  {YELLOW}{BOLD}┌─ v2rayNG (Android){NC}  {YELLOW}← нужен JSON-файл{NC}")
        print(f"  {YELLOW}│{NC}")
        print(f"  {YELLOW}│{NC}  1. Скачайте файл с сервера на телефон:")
        print(f"  {YELLOW}│{NC}       {DIM}scp root@{domain}:{xray_path} ./{xray_path.name}{NC}")
        print(f"  {YELLOW}│{NC}  2. В v2rayNG: ⊕ → «Импорт конфигурации из файла»")
        print(f"  {YELLOW}│{NC}  3. Выберите скачанный {xray_path.name}")
        print(f"  {YELLOW}│{NC}")
        print(f"  {YELLOW}│{NC}  {DIM}Либо: отсканируйте обычный QR (без fragment),{NC}")
        print(f"  {YELLOW}│{NC}  {DIM}затем в настройках подключения включите Fragment вручную.{NC}")
        print(f"  {YELLOW}└──────────────────────────────────────────────────{NC}")
        print()

        # ── Блок 3: Hiddify ────────────────────────────────────────────────
        print(f"  {MAGENTA}{BOLD}┌─ Hiddify (Android/iOS/Desktop){NC}  {MAGENTA}← нужен JSON-файл{NC}")
        print(f"  {MAGENTA}│{NC}")
        print(f"  {MAGENTA}│{NC}  1. Скачайте Sing-box конфиг:")
        print(f"  {MAGENTA}│{NC}       {DIM}scp root@{domain}:{singbox_path} ./{singbox_path.name}{NC}")
        print(f"  {MAGENTA}│{NC}  2. В Hiddify: «Добавить» → «Из файла» → выберите файл")
        print(f"  {MAGENTA}└──────────────────────────────────────────────────{NC}")
        print()

        # ── Блок 4: Xray на десктопе ───────────────────────────────────────
        print(f"  {CYAN}{BOLD}┌─ Xray / v2ray на Linux / macOS / Windows{NC}")
        print(f"  {CYAN}│{NC}")
        print(f"  {CYAN}│{NC}  scp root@{domain}:{xray_path} .")
        print(f"  {CYAN}│{NC}  xray run -config {xray_path.name}")
        print(f"  {CYAN}│{NC}  → socks5://127.0.0.1:10808  http://127.0.0.1:10809")
        print(f"  {CYAN}└──────────────────────────────────────────────────{NC}")

    else:
        # Без фрагментации — простой гайд
        print(f"  {GREEN}{BOLD}┌─ Любой клиент (v2rayNG, Nekoray, Hiddify, Xray…){NC}")
        print(f"  {GREEN}│{NC}")
        print(f"  {GREEN}│{NC}  Отсканируйте QR-код выше или скопируйте ссылку.")
        print(f"  {GREEN}│{NC}  Фрагментация не применяется.")
        print(f"  {GREEN}└──────────────────────────────────────────────────{NC}")

    print()
    print(f"  {DIM}Файлы на сервере:{NC}")
    print(f"    {DIM}{xray_path}{NC}   — Xray JSON")
    print(f"    {DIM}{singbox_path}{NC}   — Sing-box JSON")
    print(f"  {DIM}Скачать всё: scp root@{domain}:{_OUT_DIR}/*{frag_label}* ./{NC}")
    print()

# ── Показ ссылок и QR-кодов ───────────────────────────────────────────────
def _show_links_and_qr(state: dict, packets: str, length: str,
                        interval: str) -> None:
    """
    Выводит все ссылки и QR. Вызывается из do_fragment_link_menu.
    Стандартная ссылка → через _gen_vless_link (_core.py, без изменений).
    Nekoray-ссылка    → через _gen_nekoray_link (только этот файл).
    """
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

    has_fragment = bool(packets and length and interval)
    ipv4 = _get_server_ip("4")

    if has_fragment:
        frag_label = f"fragment {length}б / {interval}мс"
        print()
        _box_top(f"🔗  ССЫЛКИ С ФРАГМЕНТАЦИЕЙ  ({frag_label})")

        # ── Nekoray/Nekobox-ссылка ─────────────────────────────────────────
        print()
        print(f"{GREEN}🔀 Nekoray / Nekobox (с fragment){NC}  "
              f"{DIM}← отсканируйте QR, фрагментация включена{NC}")
        if ipv4:
            neko_link4 = _gen_nekoray_link(
                ipv4, uuid_val, pub_key, short_id, sni,
                packets, length, interval,
                fp, proto, xhttp_path, xhttp_mode, port,
            )
            print(f"  {DIM}IPv4:{NC}")
            _box_link(neko_link4)
            print()
            _show_qr(neko_link4, f"Nekoray IPv4 ({frag_label})",
                     "/root/vless_qr_neko_fragment_ipv4.png")

        neko_link_ds = _gen_nekoray_link(
            domain, uuid_val, pub_key, short_id, sni,
            packets, length, interval,
            fp, proto, xhttp_path, xhttp_mode, port,
        )
        print()
        print(f"  {DIM}Domain:{NC}")
        _box_link(neko_link_ds)
        print()
        _show_qr(neko_link_ds, f"Nekoray Domain ({frag_label})",
                 "/root/vless_qr_neko_fragment.png")

        # ── Универсальная ссылка (без fragment — для прочих клиентов) ──────
        print()
        _box_sep()
        print(f"{YELLOW}📱 Универсальная ссылка (без fragment){NC}  "
              f"{DIM}← v2rayNG, Hiddify, прочие{NC}")
        print(f"  {DIM}Fragment потребуется включить вручную в настройках клиента.{NC}")
        if ipv4:
            std_link4 = _gen_vless_link(
                ipv4, uuid_val, pub_key, short_id, sni, fp,
                proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"  {DIM}IPv4:{NC}")
            _box_link(std_link4)
            print()
            _show_qr(std_link4, "Универсальная IPv4",
                     "/root/vless_qr_universal_ipv4.png")

        std_link_ds = _gen_vless_link(
            domain, uuid_val, pub_key, short_id, sni, fp,
            proto, xhttp_path, xhttp_mode, port,
        )
        print()
        print(f"  {DIM}Domain:{NC}")
        _box_link(std_link_ds)
        print()
        _show_qr(std_link_ds, "Универсальная Domain",
                 "/root/vless_qr_universal.png")

        _box_bottom()

    else:
        # Без фрагментации — только стандартная ссылка
        print()
        _box_top("🔗  СТАНДАРТНАЯ ССЫЛКА (без фрагментации)")
        if ipv4:
            std_link4 = _gen_vless_link(
                ipv4, uuid_val, pub_key, short_id, sni, fp,
                proto, xhttp_path, xhttp_mode, port,
            )
            print()
            print(f"{GREEN}📡 IPv4:{NC}")
            _box_link(std_link4)
            print()
            _show_qr(std_link4, "IPv4", "/root/vless_qr_ipv4.png")

        std_link_ds = _gen_vless_link(
            domain, uuid_val, pub_key, short_id, sni, fp,
            proto, xhttp_path, xhttp_mode, port,
        )
        print()
        print(f"{MAGENTA}🔄 Domain:{NC}")
        _box_link(std_link_ds)
        print()
        _show_qr(std_link_ds, "Domain", "/root/vless_qr.png")
        _box_bottom()

# ── Главное меню ──────────────────────────────────────────────────────────
def do_fragment_link_menu() -> None:
    """
    Генерация ссылок и конфигов с фрагментацией.
    Вызывается из _menu_users() в _core.py (пункт F).

    Что генерируется:
      • Nekoray/Nekobox ссылка + QR  (с fragment в URI)
      • Универсальная ссылка + QR    (без fragment, для v2rayNG и др.)
      • Xray client JSON             (с fragment в sockopt)
      • Sing-box JSON                (с нативным fragment)
      • Мини-гайд: кому что делать
    """
    os.system("clear")
    print()
    _box_top("🔀  ССЫЛКИ И КОНФИГИ С ФРАГМЕНТАЦИЕЙ")
    _box_desc(
        "Генерирует ссылки для всех популярных клиентов. "
        "Nekoray/Nekobox — фрагментация из QR-кода. "
        "Остальные — через JSON-файл."
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

    if has_fragment:
        safe = lambda s: s.replace("-", "_")
        frag_suffix = f"fragment_{safe(length)}b_{safe(interval)}ms"
    else:
        frag_suffix = "no_fragment"

    # Генерируем и сохраняем JSON-конфиги
    print()
    _info("Генерирую конфиги...")

    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    xray_path    = _OUT_DIR / f"xray-client-{frag_suffix}.json"
    singbox_path = _OUT_DIR / f"singbox-client-{frag_suffix}.json"

    xray_cfg    = _build_xray_client_json(state, packets, length, interval)
    singbox_cfg = _build_singbox_json(state, packets, length, interval)

    try:
        xray_path.write_text(json.dumps(xray_cfg, ensure_ascii=False, indent=2))
        xray_path.chmod(0o600)
        singbox_path.write_text(json.dumps(singbox_cfg, ensure_ascii=False, indent=2))
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

    # Показываем ссылки и QR
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
