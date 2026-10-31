"""
chimera/modules/fragment_link.py
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
    from chimera.modules.fragment_link import do_fragment_link_menu
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
_LOG_FILE = Path("/var/log/chimera.log")

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
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_ok, _box_desc, _box_link, _get_box_width,
)
from chimera.modules.fragment_config import (
    apply_stream_finalmask,
    build_fragment_outbound,
    build_fragment_sockopt,
    _FRAGMENT_PRESETS,
    _validate_range_str,
)
from chimera.modules.fingerprint_manager import (
    XRAY_FP_LIST, REALITY_INCOMPATIBLE_FP, reality_fp_warning,
    resolve_client_fp, save_default_fingerprint,
)

# ── Делегирование в _core.py (без circular import, без дублирования) ──────
def _core_call(func_name: str, *args, **kwargs):
    _core = importlib.import_module("chimera._core")
    return getattr(_core, func_name)(*args, **kwargs)

def _show_qr(link: str, label: str, png_path: str) -> None:
    _core_call("_show_qr", link, label, png_path)

def _gen_vless_link(host, uuid_str, pbk, sid, domain, fp="chrome",
                    proto="reality", xhttp_path="/", xhttp_mode="stream-up",
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
    if proto in ("reality", "xhttp_reality") and awg_exit and install_mode == "B" and reality_dest:
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
    flow: str = "xtls-rprx-vision",
) -> str:
    """Возвращает vless://uuid@host:port?<базовые параметры> без fragment и без #label.

    v4.31: flow берётся из state (xtls_flow), а не прибит гвоздями —
    все генераторы ссылок пробрасывают его сюда.
    """
    import urllib.parse
    if proto == "xhttp":
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=xhttp&security=tls&sni={sni}"
            f"&path={path_enc}&mode={xhttp_mode}&fp={fp}"
        )
    elif proto == "xhttp_reality":
        # xHTTP + REALITY: type=xhttp + security=reality, БЕЗ flow
        # (xhttp-транспорт не поддерживает xtls-rprx-vision).
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=xhttp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}"
            f"&path={path_enc}&mode={xhttp_mode}"
        )
    else:
        return (
            f"vless://{uuid_str}@{host}:{port}"
            f"?type=tcp&security=reality&pbk={pbk}"
            f"&fp={fp}&sni={sni}&sid={sid}&flow={flow}"
        )

# ══════════════════════════════════════════════════════════════════════════
# ГЕНЕРАТОРЫ ССЫЛОК — по одной функции на каждый клиент
# ══════════════════════════════════════════════════════════════════════════

def _gen_happ_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "stream-up", port: int = 443,
    flow: str = "xtls-rprx-vision",
) -> str:
    """
    Happ (iOS/Android/Desktop, Xray-core).
    Документация: https://www.happ.su/main/dev-docs/examples-of-links-and-parameters
    Формат: &fragment=length,interval,packets
    Пример: &fragment=3-7,10-20,1-3
    """
    import urllib.parse
    base   = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto,
                              xhttp_path, xhttp_mode, port, flow)
    frag   = urllib.parse.quote(f"{length},{interval},{packets}")
    label  = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Happ"
    return f"{base}&fragment={frag}#{label}"


def _gen_incy_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "stream-up", port: int = 443,
    flow: str = "xtls-rprx-vision",
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
    base  = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto,
                             xhttp_path, xhttp_mode, port, flow)
    label = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Incy"
    return f"{base}&fragmentLength={length}&fragmentInterval={interval}#{label}"


def _gen_nekoray_link(
    host: str, uuid_str: str, pbk: str, sid: str, sni: str,
    packets: str, length: str, interval: str,
    fp: str = "chrome", proto: str = "reality",
    xhttp_path: str = "/", xhttp_mode: str = "stream-up", port: int = 443,
    flow: str = "xtls-rprx-vision",
) -> str:
    """
    Nekoray / Nekobox (Desktop, sing-box core).
    Формат: &fragment=packets,length,interval
    Пример: &fragment=1-3,3-7,10-20
    Примечание: NyameBox (qr243vbi/nekobox) — тот же формат, но
    поддержка fragment в URI нестабильна, рекомендуется JSON-файл.
    """
    import urllib.parse
    base   = _base_uri_params(host, uuid_str, pbk, sid, sni, fp, proto,
                              xhttp_path, xhttp_mode, port, flow)
    frag   = urllib.parse.quote(f"{packets},{length},{interval}")
    label  = _flag_prefix() + urllib.parse.quote(sni) + "%20%F0%9F%94%B5Neko"
    return f"{base}&fragment={frag}#{label}"


def build_fragment_link_variants(base_link: str, packets: str,
                                 length: str, interval: str) -> list:
    """Три fragment-варианта (Happ/Incy/Neko) ГОТОВОЙ vless://-ссылки.

    Каноническую ссылку собирает ЛЮБОЙ генератор проекта
    (users_manager._gen_vless_link, subscription._build_vless_uri,
    subscription_multinode.get_multinode_uris) — со всеми параметрами
    (CDN host=, xhttp path/mode и т.д.). Здесь параметры НЕ пересобираются,
    а только ДОБАВЛЯЮТСЯ клиент-специфичные fragment-параметры —
    рассинхрон форматов исключён по построению.

    Матрица клиентов (см. шапку модуля):
      Happ     &fragment=length,interval,packets
      Incy     &fragmentLength=length&fragmentInterval=interval
               (packets в URI Incy не кодируется — клиент сам использует
               tlshello на tls/reality)
      Nekoray  &fragment=packets,length,interval

    Happ и Nekoray читают ОДНО имя параметра fragment= с РАЗНЫМ порядком
    значений — поэтому вариантов ТРИ, а не один: каждый клиент импортирует
    ссылку, помеченную его именем (метка #…🔵Happ / 🔵Incy / 🔵Neko).

    Метка варианта = метка base_link (часть после '#') + суффикс клиента;
    если метки нет — суффикс становится меткой целиком.

    Возвращает [] (молча) если base_link пуст/не vless:///уже содержит
    fragment-параметры (идемпотентность: двойное добавление исключено).
    """
    import urllib.parse
    raw = (base_link or "").strip()
    if not raw or not raw.startswith("vless://"):
        return []
    base, _, old_label = raw.partition("#")
    if not base:
        return []
    # Уже фрагментированная ссылка — не дублируем параметры.
    if ("fragment=" in base or "fragmentLength=" in base
            or "fragmentInterval=" in base):
        return []
    p, l, i = str(packets), str(length), str(interval)
    happ_frag = urllib.parse.quote(f"{l},{i},{p}", safe="")
    neko_frag = urllib.parse.quote(f"{p},{l},{i}", safe="")
    incy_l    = urllib.parse.quote(l, safe="")
    incy_i    = urllib.parse.quote(i, safe="")
    _sep      = "%20" if old_label else ""
    # Минимальная ссылка vless://uuid@host:port без query — первый
    # добавляемый параметр стартует с '?', а не '&'.
    _q = "&" if "?" in base else "?"
    return [
        f"{base}{_q}fragment={happ_frag}#{old_label}{_sep}%F0%9F%94%B5Happ",
        f"{base}{_q}fragmentLength={incy_l}&fragmentInterval={incy_i}"
        f"#{old_label}{_sep}%F0%9F%94%B5Incy",
        f"{base}{_q}fragment={neko_frag}#{old_label}{_sep}%F0%9F%94%B5Neko",
    ]

# ══════════════════════════════════════════════════════════════════════════
# ГЕНЕРАЦИЯ JSON-КОНФИГОВ
# ══════════════════════════════════════════════════════════════════════════

def _build_xray_client_json(state: dict, packets: str, length: str,
                             interval: str,
                             noise_packet: Optional[str] = None,
                             noise_delay: Optional[str] = None,
                             fp_override: Optional[str] = None) -> dict:
    """Полный клиентский Xray config.json: fragment (+ опц. noise) в freedom-outbound,
    основной outbound цепляется через sockopt.dialerProxy (валидная схема Xray-core).

    v4.31: fp_override — FP этой генерации; None → дефолт ноды (state.fingerprint).
    """
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    xtls_flow  = state.get("xtls_flow", "xtls-rprx-vision")
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    fp         = resolve_client_fp(state, fp_override)  # v4.31: настраиваемый FP
    sni        = _resolve_sni(state)

    # Валидная схема Xray-core: fragment(+опц. noises) живут в settings
    # freedom-outbound, основной outbound цепляется через sockopt.dialerProxy
    # (прежде fragment/noise клали прямо в sockopt — ядро молча игнорировало
    # эти поля, фрагментация не работала). Без fragment-параметров — обычный
    # sockopt без dialerProxy.
    from chimera.modules.tfo_settings import tfo_sockopt
    if packets and length and interval:
        fragment_outbound = build_fragment_outbound(
            packets, length, interval, noise_packet, noise_delay)
        sockopt = build_fragment_sockopt(packets, length, interval)
    else:
        fragment_outbound = None
        sockopt = {
            **tfo_sockopt(),
            "tcpKeepAliveInterval": 15,
            "tcpKeepAliveIdle": 60,
            "tcpUserTimeout": 30000,
            "tcpCongestion": "bbr",
        }

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
    elif proto == "xhttp_reality":
        # xHTTP + REALITY: транспорт xhttp + REALITY TLS, БЕЗ flow
        # (в отличие от tcp+reality — users без flow, xhttpSettings
        # + realitySettings в одном streamSettings).
        outbound = {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": domain, "port": port,
                "users": [{"id": uuid_val, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "xhttp", "security": "reality", "sockopt": sockopt,
                "xhttpSettings": {"path": xhttp_path, "mode": xhttp_mode},
                "realitySettings": {
                    "show": False, "fingerprint": fp,
                    "serverName": sni, "publicKey": pub_key,
                    "shortId": short_id, "spiderX": "/",
                },
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

    # DUAL-схема (31.10.2026): + finalmask вдобавок к legacy-паре
    # (freedom.fragment+dialerProxy) — миграция Xray 26.10.29
    # (freedom.fragment deprecated → streamSettings.finalmask.tcp).
    apply_stream_finalmask(outbound, packets, length, interval)

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
            *([fragment_outbound] if fragment_outbound else []),
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
                        interval: str,
                        noise_packet: Optional[str] = None,
                        noise_delay: Optional[str] = None,
                        fp_override: Optional[str] = None) -> dict:
    """Sing-box outbound с нативным fragment (+ опц. noise).

    v4.31: fp_override — FP этой генерации; None → дефолт ноды.
    """
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    xtls_flow  = state.get("xtls_flow", "xtls-rprx-vision")
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    fp         = resolve_client_fp(state, fp_override)  # v4.31: настраиваемый FP
    sni        = _resolve_sni(state)

    # TFO — только по настройке tfo_settings (дефолт ВЫКЛ).
    # Комбо fragment+noise — build_singbox_noise_dial (ленивый импорт,
    # см. _build_xray_client_json).
    from chimera.modules.tfo_settings import tfo_dial
    dial_fields: dict = {}
    if noise_packet and noise_delay:
        from chimera.modules.fragment_noise import build_singbox_noise_dial
        dial_fields = build_singbox_noise_dial(packets, length, interval,
                                               noise_packet, noise_delay)
    elif packets and length and interval:
        dial_fields.update(tfo_dial())
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
    elif proto == "xhttp_reality":
        # xHTTP + REALITY (sing-box/NekoBox): transport xhttp + REALITY,
        # БЕЗ flow (фрагментация работает — она на уровне TCP/TLS).
        outbound = {
            "type": "vless", "tag": "vless-out",
            "server": domain, "server_port": port, "uuid": uuid_val,
            "transport": {"type": "xhttp", "mode": xhttp_mode,
                          "path": xhttp_path},
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
    _box_item("4", f"🧩 tlshello-рецепт  {DIM}packets=tlshello length=10-20б "
                   f"interval=10-20мс (DPI/CHECKER){NC}")
    _box_item("5", f"⚙️  Своя           {DIM}ввести параметры вручную (packets: N/N-M/tlshello){NC}")
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
        "4": ("tlshello", "10-20", "10-20"),
    }

    if ch in ("0", "Q", "q", ""):
        return ("", "", "")

    if ch in preset_map:
        packets, length, interval = preset_map[ch]
        name = {"1": "aggressive", "2": "balanced", "3": "light",
                "4": "tlshello"}[ch]
        if name == "tlshello":
            _info("tlshello-рецепт: дробим все сегменты до конца TLS "
                  "ClientHello (спец-значение sockopt Xray-core)")
        else:
            _info(f"Пресет: {_FRAGMENT_PRESETS[name]['desc']}")
        return (packets, length, interval)

    if ch == "5":
        print()
        _info("Введите параметры (packets: N, N-M или tlshello):")
        print()
        try:
            raw_packets  = input(f"  {CYAN}packets {DIM}(сегменты, напр. 1-3 или tlshello){NC}:  ").strip() or "1-3"
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
                        interval: str,
                        fp_override: Optional[str] = None) -> None:
    """Выводит ссылки всех форматов и QR-коды.

    v4.31: fp_override — FP этой генерации (None → дефолт ноды);
    flow пробрасывается из state (xtls_flow), не прибит гвоздями.
    """
    proto      = state.get("protocol_mode", "reality")
    domain     = state.get("domain", "")
    port       = int(state.get("server_port", 443))
    uuid_val   = state.get("uuid", "")
    pub_key    = state.get("public_key", "")
    short_id   = state.get("short_id", "")
    fp         = resolve_client_fp(state, fp_override)  # v4.31
    flow       = state.get("xtls_flow", "xtls-rprx-vision") or "xtls-rprx-vision"
    xhttp_path = state.get("xhttp_path", "/")
    xhttp_mode = state.get("xhttp_mode", "stream-up")
    sni        = _resolve_sni(state)
    ipv4       = _get_server_ip("4")

    has_fragment = bool(packets and length and interval)

    def _show_for_host(host: str, host_label: str) -> None:
        if has_fragment:
            # Happ
            happ = _gen_happ_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port, flow,
            )
            print()
            print(f"  {GREEN}🔵 Happ {DIM}({host_label}){NC}  {DIM}← QR достаточно{NC}")
            _box_link(happ)
            print()
            _show_qr(happ, f"Happ {host_label}", f"/root/vless_qr_happ_{host_label.lower()}.png")

            # Incy
            incy = _gen_incy_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port, flow,
            )
            print()
            print(f"  {CYAN}🔵 Incy {DIM}({host_label}){NC}  {DIM}← QR достаточно{NC}")
            _box_link(incy)
            print()
            _show_qr(incy, f"Incy {host_label}", f"/root/vless_qr_incy_{host_label.lower()}.png")

            # Nekoray / Nekobox
            neko = _gen_nekoray_link(
                host, uuid_val, pub_key, short_id, sni,
                packets, length, interval, fp, proto, xhttp_path, xhttp_mode, port, flow,
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
# ВЫБОР FINGERPRINT (v4.31 — «Fragment & FP Customizer»)
# ══════════════════════════════════════════════════════════════════════════

def _pick_fingerprint_step(state: dict) -> Optional[str]:
    """
    Шаг «Fingerprint» меню генерации ссылок/конфигов.

    Возвращает:
      None   — оставить дефолт ноды (state.fingerprint);
      str    — выбранный FP (валидный, live 26.10.29) для ЭТОЙ генерации;
               при согласии пользователя — сразу сохраняется как дефолт
               ноды (state.json → все будущие генерации/экспорт);
      ""     — Ctrl+C: отмена ВСЕЙ генерации (меню завершается).

    Список — LIVE-валидированный (ядро 26.10.29 отвергает неизвестные
    имена при парсинге конфига): 11 FP из XRAY_FP_LIST.
    REALITY-guard: randomized-семейство (random/randomized/
    randomizednoalpn) с REALITY несовместимо — предупреждаем.
    """
    eff = resolve_client_fp(state)
    print()
    _box_top("🔑  FINGERPRINT (TLS/uTLS)")
    _box_desc(
        "FP имитирует ClientHello браузера в REALITY-хендшейке. "
        "Влияет на ссылки (&fp=) и JSON-конфиги этой генерации."
    )
    _box_sep()
    _box_row(f"  Текущий (дефолт ноды): {BOLD}{eff}{NC}")
    _box_row()
    for i, name in enumerate(XRAY_FP_LIST, 1):
        mark = f" {GREEN}← текущий{NC}" if name == eff else ""
        dim = f" {YELLOW}(REALITY: несовместим){NC}" if name in REALITY_INCOMPATIBLE_FP else ""
        _box_item(str(i), f"{name}{mark}{dim}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        raw = input(f"{CYAN}FP (номер/имя, Enter = {eff}):{NC} ").strip().lower()
    except KeyboardInterrupt:
        return ""
    if not raw:
        return None

    chosen = ""
    if raw.isdigit() and 1 <= int(raw) <= len(XRAY_FP_LIST):
        chosen = XRAY_FP_LIST[int(raw) - 1]
    elif raw in XRAY_FP_LIST:
        chosen = raw
    if not chosen:
        _warn(f"Неизвестный FP: {raw!r} — ядро 26.10.29 отвергает "
              "неизвестные имена при парсинге (unknown fingerprint).")
        time.sleep(1)
        return None

    w = reality_fp_warning(chosen)
    if w:
        _warn(w)
    _info(f"FP этой генерации: {chosen}")

    try:
        keep = input(f"{CYAN}Сохранить как дефолт ноды (state.json)? "
                     f"[y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        keep = ""
    if keep in ("y", "yes", "д", "да"):
        if save_default_fingerprint(chosen):
            state["fingerprint"] = chosen
            _ok(f"Сохранено — дефолт ноды теперь {chosen} "
                "(все будущие генерации/экспорт)")
    return chosen


def _pick_noise_custom() -> Optional[tuple[str, str]]:
    """Кастомный noise (v4.31): ручной ввод packet/delay. None = отмена."""
    print()
    _info("Свой noise: введите параметры (диапазон N или N-M).")
    print()
    try:
        raw_packet = input(f"  {CYAN}packet {DIM}(байты, напр. 30-80){NC}: ").strip() or "30-80"
        raw_delay  = input(f"  {CYAN}delay  {DIM}(мс,    напр. 10-40){NC}: ").strip() or "10-40"
    except KeyboardInterrupt:
        return None
    if not (_validate_range_str(raw_packet, "packet")
            and _validate_range_str(raw_delay, "delay")):
        time.sleep(2)
        return None
    return (raw_packet, raw_delay)


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
    # Anti-Empty Identity Guard для ссылок — при частично битом
    # state.json (domain/uuid есть, public_key/short_id потеряны) ссылки
    # получали pbk=&sid= и молча ломались. Добираем параметры доступа
    # из ЖИВОГО /etc/xray/config.json (realitySettings) — он и есть
    # источник истины для выданных пользователям ссылок.
    try:
        import importlib as _il
        _core_mod = _il.import_module("chimera._core")
        _pub, _sid, _spx = _core_mod._reality_transport_params_from_state(state)
        if _pub and not state.get("public_key"):
            state["public_key"] = _pub
        if _sid and not state.get("short_id"):
            state["short_id"] = _sid
        if _spx and not state.get("spiderx"):
            state["spiderx"] = _spx
        if state.get("protocol_mode", "reality") == "reality" \
                and not (state.get("public_key") and state.get("short_id")):
            _warn("REALITY-параметры неполны (pbk/sid) даже после восстановления "
                  "из config.json — ссылки могут не работать")
    except Exception:
        pass  # fallback: работаем с тем, что есть в state
    return state

# ══════════════════════════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════

def do_fragment_link_menu() -> None:
    """
    Генерация ссылок и конфигов с фрагментацией.
    Вызывается из _menu_users() в _core.py (пункт F).

    v4.31 «Fragment & FP Customizer»:
      шаг 0 — FP (11 live-валидированных имён, REALITY-guard, опция
               «сохранить как дефолт ноды»);
      шаг 1 — пресет фрагментации (агрессивная/сбалансированная/лёгкая/
               tlshello/своя);
      шаг 2 — опциональный noise (3 пресета + СВОИ параметры);
      генерация — все JSON/ссылки несут выбранный FP и flow из state.
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

    # ── Шаг 0: Fingerprint (v4.31) ─────────────────────────────────────
    fp_pick = _pick_fingerprint_step(state)
    if fp_pick == "":
        return  # Ctrl+C — отмена всей генерации
    fp_override: Optional[str] = fp_pick  # None = дефолт ноды

    result = _pick_fragment_preset()
    if result is None:
        return

    packets, length, interval = result
    has_fragment = bool(packets and length and interval)

    # ── Опциональный noise (комбо fragment+noise одной генерацией) ────
    # Дефолт — N (Enter): прежнее поведение. Noise идёт ТОЛЬКО в
    # JSON-конфиги (URI-форматы Happ/Incy/Neko noise не несут).
    # v4.31: + пункт «своя» — ручной ввод packet/delay.
    noise_packet: Optional[str] = None
    noise_delay:  Optional[str] = None
    if has_fragment:
        try:
            _ans = input(f"{CYAN}Добавить noise (шум перед ClientHello)? "
                         f"{DIM}[y/N]{NC}: ").strip().lower()
        except KeyboardInterrupt:
            _ans = ""
        if _ans in ("y", "yes", "д", "да"):
            print()
            _box_top("Интенсивность шума (noise)")
            _box_item("1", "🔅 Лёгкий      10–20 байт, 5–10 мс")
            _box_item("2", "🔆 Средний     20–50 байт, 10–20 мс")
            _box_item("3", "🔊 Агрессивный 50–100 байт, 15–30 мс")
            _box_item("4", "⚙️  Своя        ввести packet/delay вручную")
            _box_bottom()
            try:
                _nch = input(f"{CYAN}Выбор [1-4]:{NC} ").strip()
            except KeyboardInterrupt:
                _nch = ""
            _nmap = {
                "1": ("10-20",  "5-10"),
                "2": ("20-50",  "10-20"),
                "3": ("50-100", "15-30"),
            }
            if _nch in _nmap:
                noise_packet, noise_delay = _nmap[_nch]
            elif _nch == "4":
                custom = _pick_noise_custom()
                if custom:
                    noise_packet, noise_delay = custom
            if noise_packet and noise_delay:
                _info(f"Noise: packet={noise_packet}б delay={noise_delay}мс "
                      f"(только в JSON-конфигах)")

    safe = lambda s: s.replace("-", "_")
    frag_suffix = f"fragment_{safe(length)}b_{safe(interval)}ms" if has_fragment else "no_fragment"
    if noise_packet and noise_delay:
        frag_suffix += f"_noise_{safe(noise_packet)}b"

    # Генерируем JSON-конфиги (v4.31: с выбранным FP)
    print()
    _info("Генерирую JSON-конфиги...")
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    xray_path    = _OUT_DIR / f"xray-client-{frag_suffix}.json"
    singbox_path = _OUT_DIR / f"singbox-client-{frag_suffix}.json"

    try:
        xray_path.write_text(
            json.dumps(_build_xray_client_json(state, packets, length, interval,
                                                noise_packet, noise_delay,
                                                fp_override=fp_override),
                       ensure_ascii=False, indent=2)
        )
        xray_path.chmod(0o600)
        singbox_path.write_text(
            json.dumps(_build_singbox_json(state, packets, length, interval,
                                           noise_packet, noise_delay,
                                           fp_override=fp_override),
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
        f"[packets={packets} length={length} interval={interval}"
        f" fp={resolve_client_fp(state, fp_override)}"
        + (f" noise_packet={noise_packet} noise_delay={noise_delay}]"
           if noise_packet and noise_delay else "]")
    ))

    # Ссылки и QR (v4.31: с выбранным FP)
    _show_links_and_qr(state, packets, length, interval, fp_override=fp_override)

    # Мини-гайд
    _print_client_guide(
        has_fragment,
        state.get("domain", ""),
        xray_path,
        singbox_path,
        frag_suffix,
    )

    input(f"{BLUE}Нажмите Enter...{NC}")
