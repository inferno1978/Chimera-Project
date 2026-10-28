"""
chimera/modules/fragment_config.py
───────────────────────────────────────────────────────────────────────────────
Генератор конфигов с TCP-фрагментацией ClientHello.

Фрагментация работает на уровне TCP-сегментов исходящего соединения:
Xray разбивает первые N байт TLS ClientHello на мелкие куски, что
препятствует DPI-анализу провайдера.

Схема Xray-core (единственно валидная — infra/conf/freedom.go): fragment и
noises живут в settings freedom-outbound, основной outbound набирает своё
соединение ЧЕРЕЗ него (streamSettings.sockopt.dialerProxy, transport_sockopt.go):
  • packets  — "1-3" / "tlshello"  (первые 1–3 TCP-сегмента / весь ClientHello)
  • length   — "1-5"          (размер каждого фрагмента в байтах)
  • interval — "10-20"        (задержка между фрагментами, мс)

Поля fragment/noise ВНУТРИ sockopt ядром НЕ поддерживаются и молча
игнорировались (плацебо до фикса 2026-10-28).

ВАЖНО: фрагментация применяется ТОЛЬКО к исходящим соединениям (outbounds),
и ТОЛЬКО в клиентском конфиге (не в серверном xray/config.json на VPS).
Серверный config.json этим модулем не затрагивается ни при каких условиях.

Точка входа из _core.py / fragment_fuzzer.py:
    from chimera.modules.fragment_config import (
        build_fragment_outbound,
        build_fragment_sockopt,
        generate_fragment_client_config,
        do_fragment_config_menu,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета (самодостаточные, как во всех других модулях) ────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        import re as _re
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = _re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [FRAGMENT] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)

# ── Импорт box-рендерера ──────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_ok, _box_desc, _get_box_width,
)

# ── Константы ─────────────────────────────────────────────────────────────
_STATE_FILE       = Path("/var/lib/xray-installer/state.json")
_FRAGMENT_DIR     = Path("/var/lib/xray-installer/fragment_configs")
_FRAGMENT_PRESETS = {
    "aggressive": {
        "packets":  "1-3",
        "length":   "1-3",
        "interval": "5-10",
        "desc":     "Агрессивная (1–3 байта) — максимальный обход DPI, медленнее",
    },
    "balanced": {
        "packets":  "1-3",
        "length":   "3-7",
        "interval": "10-20",
        "desc":     "Сбалансированная (3–7 байт) — рекомендуется для большинства провайдеров",
    },
    "light": {
        "packets":  "1-2",
        "length":   "5-15",
        "interval": "20-50",
        "desc":     "Лёгкая (5–15 байт) — минимальный оверхед, базовая защита",
    },
    "custom": {
        "packets":  "",
        "length":   "",
        "interval": "",
        "desc":     "Пользовательская — ввести параметры вручную",
    },
}

# ── Публичные функции ──────────────────────────────────────────────────────

FRAGMENT_OUTBOUND_TAG = "fragment"


def _base_tcp_sockopt() -> dict:
    """Базовый TCP-тюнинг sockopt (TFO — только если включён в tfo_settings;
    дефолт ВЫКЛ — инцидент 28.08.2026: DPI резал data-in-SYN)."""
    from chimera.modules.tfo_settings import tfo_sockopt
    return {
        **tfo_sockopt(),
        "tcpKeepAliveInterval": 15,
        "tcpKeepAliveIdle":   60,
        "tcpUserTimeout":     30000,
        "tcpCongestion":      "bbr",
    }


def build_fragment_outbound(
    packets: str = "1-3",
    length: str = "3-7",
    interval: str = "10-20",
    noise_packet: Optional[str] = None,
    noise_delay: Optional[str] = None,
    tag: str = FRAGMENT_OUTBOUND_TAG,
) -> dict:
    """
    freedom-outbound с settings.fragment (+ опц. noises) — ЕДИНСТВЕННО
    валидное место fragment/noise в схеме Xray-core (infra/conf/freedom.go:
    Fragment *Fragment `json:"fragment"` / Noises []*Noise `json:"noises"`;
    сингулярный "noise" из Xray-core удалён — только массив noises).

    Цепочка: основной outbound получает streamSettings.sockopt.dialerProxy
    = tag (см. build_fragment_sockopt) — его TCP-соединение набирается через
    этот freedom-outbound, который дробит записи (fragment) и/или шлёт шум
    (noises). TCP-тюнинг продублирован здесь: фактический dial выполняет
    именно freedom-outbound.
    """
    settings: dict = {
        "fragment": {
            "packets":  packets,
            "length":   length,
            "interval": interval,
        }
    }
    if noise_packet and noise_delay:
        settings["noises"] = [
            {
                "type":   "rand",
                "packet": noise_packet,
                "delay":  noise_delay,
            }
        ]
    return {
        "tag":            tag,
        "protocol":       "freedom",
        "settings":       settings,
        "streamSettings": {"sockopt": _base_tcp_sockopt()},
    }


def build_fragment_sockopt(
    packets: str = "1-3",
    length: str = "3-7",
    interval: str = "10-20",
) -> dict:
    """
    sockopt ОСНОВНОГО (proxy) outbound: TCP-тюнинг + dialerProxy.

    Валидная схема Xray-core: фрагментацию выполняет freedom-outbound
    (build_fragment_outbound), основной outbound набирает соединение ЧЕРЕЗ
    него — sockopt.dialerProxy (поле есть в infra/conf/transport_sockopt.go).
    Прежняя схема — fragment прямо в sockopt — была невалидна: sockopt
    такого поля не имеет, ядро молча его игнорировало (плацебо).

    Параметры packets/length/interval сохранены для совместимости сигнатуры
    (вызовы в fragment_link / fragment_mux / fragment_fuzzer); значения
    фрагментации читает build_fragment_outbound().

    Пример результата (TFO выключен — базовый случай):
        {
            "tcpKeepAliveInterval": 15,
            ... ,
            "dialerProxy": "fragment"
        }
    """
    return {
        **_base_tcp_sockopt(),
        "dialerProxy": FRAGMENT_OUTBOUND_TAG,
    }


def generate_fragment_client_config(
    packets: str = "1-3",
    length: str = "3-7",
    interval: str = "10-20",
    label: str = "fragment",
    noise_packet: Optional[str] = None,
    noise_delay: Optional[str] = None,
) -> Optional[Path]:
    """
    Генерирует клиентский конфиг Xray с фрагментацией и сохраняет его
    в /var/lib/xray-installer/fragment_configs/<label>.json.

    noise_packet/noise_delay (опционально, обе или ни одной): добавляют
    noises в settings freedom-outbound — комбо «fragment + noise»
    одной генерацией (шум перед ClientHello: если DPI научился
    распознавать фрагменты).

    Конфиг является КЛИЕНТСКИМ — он работает на устройстве пользователя
    и проксирует трафик через VPS. Серверный /etc/xray/config.json
    этой функцией не затрагивается.

    Возвращает Path к созданному файлу или None при ошибке.
    """
    # Читаем параметры сервера из state.json
    if not _STATE_FILE.exists():
        _warn("state.json не найден — сначала установите VLESS-сервер")
        return None

    try:
        state = json.loads(_STATE_FILE.read_text())
    except Exception as e:
        _warn(f"Не удалось прочитать state.json: {e}")
        return None

    protocol_mode = state.get("protocol_mode", "reality")
    server_host   = state.get("domain", "")
    server_port   = state.get("server_port", 443)
    uuid_val      = state.get("uuid", "")
    pub_key       = state.get("public_key", "")
    short_id      = state.get("short_id", "")
    reality_dest  = state.get("reality_dest", "")
    xtls_flow     = state.get("xtls_flow", "xtls-rprx-vision")

    if not server_host or not uuid_val:
        _warn("В state.json нет domain/uuid — конфиг не может быть сгенерирован")
        return None

    # Валидная схема Xray-core: fragment(+опц. noises) — в settings
    # freedom-outbound, основной outbound цепляется через sockopt.dialerProxy
    # (комбо «fragment + noise» — одной генерацией: noises на том же outbound).
    fragment_outbound = build_fragment_outbound(
        packets, length, interval, noise_packet, noise_delay)
    sockopt = build_fragment_sockopt(packets, length, interval)

    # ── Строим outbound в зависимости от протокола ─────────────────────────
    if protocol_mode == "xhttp":
        xhttp_path = state.get("xhttp_path", "/")
        xhttp_mode = state.get("xhttp_mode", "stream-up")
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{"id": uuid_val, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network":  "xhttp",
                "security": "tls",
                "sockopt":  sockopt,
                "tlsSettings": {
                    "serverName":    server_host,
                    "allowInsecure": False,
                },
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                },
            },
        }
    elif protocol_mode == "xhttp_reality":
        # xHTTP + REALITY: транспорт xhttp + REALITY TLS, БЕЗ flow
        # (xhttp несовместим с xtls-rprx-vision — users без flow,
        # xhttpSettings + realitySettings в одном streamSettings;
        # фрагментация совместима — она на уровне TCP/TLS ClientHello).
        xhttp_path = state.get("xhttp_path", "/")
        xhttp_mode = state.get("xhttp_mode", "stream-up")
        fp         = state.get("fingerprint", "chrome") or "chrome"
        # SNI по канону xhttp_reality (как _resolve_sni в fragment_link.py):
        # Mode B + AWG-exit → reality_dest (совпадает с serverNames сервера),
        # иначе — domain. Легаси-ветку reality ниже не трогаем.
        awg_dest = state.get("reality_dest", "")
        if (state.get("awg_exit_enabled") and state.get("install_mode") == "B"
                and awg_dest):
            sni = awg_dest.split(":")[0]
        else:
            sni = server_host
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{"id": uuid_val, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network":  "xhttp",
                "security": "reality",
                "sockopt":  sockopt,
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                },
                "realitySettings": {
                    "show":        False,
                    "fingerprint": fp,
                    "serverName":  sni,
                    "publicKey":   pub_key,
                    "shortId":     short_id,
                    "spiderX":     "/",
                },
            },
        }
    else:
        # REALITY — канонический SNI-рул (sni_hygiene.client_sni_for_state):
        # Mode B + AWG-exit + reality_dest → reality_dest (совпадает с
        # serverNames сервера), иначе — domain (свой домен). Прежний
        # безусловный reality_dest с фолбэком www.cloudflare.com ломал Mode A
        # (SNI не совпадал с serverNames=[domain]) и светил известный домен.
        from chimera.modules.sni_hygiene import client_sni_for_state
        sni = client_sni_for_state(state) or server_host
        outbound = {
            "tag":      "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port":    server_port,
                    "users":   [{
                        "id":         uuid_val,
                        "encryption": "none",
                        **({"flow": xtls_flow} if xtls_flow else {}),
                    }],
                }],
            },
            "streamSettings": {
                "network":  "tcp",
                "security": "reality",
                "sockopt":  sockopt,
                "realitySettings": {
                    "show":        False,
                    "fingerprint": "chrome",
                    "serverName":  sni,
                    "publicKey":   pub_key,
                    "shortId":     short_id,
                    "spiderX":     "/",
                },
            },
        }

    client_cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag":      "socks",
                "protocol": "socks",
                "listen":   "127.0.0.1",
                "port":     10808,
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag":      "http",
                "protocol": "http",
                "listen":   "127.0.0.1",
                "port":     10809,
                "settings": {},
            },
        ],
        "outbounds": [
            outbound,
            fragment_outbound,
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

    # ── Сохраняем файл ─────────────────────────────────────────────────────
    _FRAGMENT_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = "".join(c for c in label if c.isalnum() or c in "-_")
    out_path = _FRAGMENT_DIR / f"{safe_label}.json"
    try:
        out_path.write_text(json.dumps(client_cfg, ensure_ascii=False, indent=2))
        _log("INFO", f"Клиентский конфиг с фрагментацией сохранён: {out_path}")
        return out_path
    except Exception as e:
        _warn(f"Не удалось сохранить конфиг: {e}")
        return None


def _validate_range_str(value: str, what: str) -> bool:
    """Проверяет, что строка имеет вид 'N' или 'N-M' с целыми числами > 0.

    Спец-значение для what='packets': 'tlshello' — дробить TLS ClientHello
    на отдельные handshake-сообщения (Xray-core freedom.settings.fragment
    .packets, case "tlshello" в infra/conf/freedom.go).
    Рецепт волны DPI/CHECKER (окт-2026): packets=tlshello length=10-20
    interval=10-20.
    """
    # freedom.settings.fragment.packets допускает спец-строку "tlshello"
    # вместо числового диапазона — валидна ТОЛЬКО для поля packets.
    if what == "packets" and value.strip().lower() == "tlshello":
        return True
    parts = value.strip().split("-")
    if len(parts) not in (1, 2):
        _warn(f"{what}: ожидается формат 'N' или 'N-M', например '3-7'")
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        _warn(f"{what}: значения должны быть целыми числами")
        return False
    if any(n <= 0 for n in nums):
        _warn(f"{what}: значения должны быть > 0")
        return False
    if len(nums) == 2 and nums[0] > nums[1]:
        _warn(f"{what}: нижняя граница должна быть ≤ верхней")
        return False
    return True


# ── Fragment в дефолтном экспорте клиентских конфигов (тумблер) ────────────
#
# state.json → "client_fragment":
#     {"enabled": true, "packets": "1-3", "length": "10-20", "interval": "10-20"}
#
# ВКЛ: do_generate_client_config (client_config_export.py) ДОПОЛНИТЕЛЬНО
# кладёт в /root/xray-client-configs/ (аддитивно, существующие файлы
# экспорта не меняются):
#   xray-client-fragment.json    — v2rayN/v2rayNG/Nekoray(Xray)/xray CLI
#   singbox-client-fragment.json — Hiddify/NekoBox (только reality-ветка:
#                                   xhttp-транспорт sing-box не поддерживает)
#   vless-links-fragment.txt     — Happ/Incy/Nekoray (fragment прямо в URI)
#
# ВЫКЛ (ключа нет / enabled=false — дефолт): поведение дефолтного экспорта
# байт-в-байт прежнее. Управление — пункт 5 меню do_fragment_config_menu
# (Меню 4 «Диагностика и мониторинг» → F1).

def get_client_fragment_settings(state: dict) -> Optional[dict]:
    """Настройки fragment-аддона дефолтного экспорта.

    Возвращает {"packets", "length", "interval"} или None = выключено
    (в т.ч. при неполных параметрах — честный экспорт не врёт).
    """
    cf = state.get("client_fragment") if isinstance(state, dict) else None
    if not isinstance(cf, dict) or not cf.get("enabled"):
        return None
    packets  = str(cf.get("packets", "") or "").strip()
    length   = str(cf.get("length", "") or "").strip()
    interval = str(cf.get("interval", "") or "").strip()
    if not (packets and length and interval):
        return None
    return {"packets": packets, "length": length, "interval": interval}


def _save_client_fragment_state(cf: dict) -> bool:
    """Записывает блок client_fragment в state.json (сохраняя остальное)."""
    st: dict = {}
    if _STATE_FILE.exists():
        try:
            st = json.loads(_STATE_FILE.read_text())
        except Exception:
            st = {}
        if not isinstance(st, dict):
            st = {}
    st["client_fragment"] = cf
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        return True
    except Exception as e:
        _warn(f"Не удалось записать state.json: {e}")
        return False


def do_export_fragment_toggle_menu() -> None:
    """
    Тумблер «fragment в дефолтном экспорте клиентских конфигов».

    ВКЛ: do_generate_client_config (меню экспорта) дополнительно
    генерирует fragment-варианты конфигов — Xray JSON (v2rayNG/v2rayN),
    Sing-box JSON (Hiddify/NekoBox) и ссылки Happ/Incy/Nekoray с
    fragment в URI. Серверный /etc/xray/config.json не затрагивается.

    Вызывается пунктом 5 меню do_fragment_config_menu (Меню 4 «Диагностика
    и мониторинг» → F1 → пункт 5).
    """
    # Текущее состояние
    state: dict = {}
    if _STATE_FILE.exists():
        try:
            state = json.loads(_STATE_FILE.read_text())
        except Exception:
            state = {}
    cur = get_client_fragment_settings(state)

    os.system("clear")
    print()
    _box_top("📦  FRAGMENT В ДЕФОЛТНОМ ЭКСПОРТЕ")
    _box_desc(
        "Когда ВКЛ: экспорт клиентских конфигов дополнительно кладёт "
        "fragment-варианты — Xray JSON (v2rayNG/v2rayN), Sing-box JSON "
        "(Hiddify/NekoBox) и ссылки Happ/Incy/Nekoray с fragment в URI. "
        "Существующие файлы экспорта не меняются."
    )
    _box_sep()
    if cur:
        _box_row(f"  {GREEN}● ВКЛЮЧЕНО{NC}: packets={cur['packets']}  "
                 f"length={cur['length']}б  interval={cur['interval']}мс")
    else:
        _box_row(f"  {DIM}○ ВЫКЛЮЧЕНО (дефолт){NC}")
    _box_sep()
    _box_item("1", f"Включить — агрессивная  {DIM}packets=1-3 length=1-3б interval=5-10мс{NC}")
    _box_item("2", f"Включить — сбалансированная  {DIM}packets=1-3 length=3-7б interval=10-20мс{NC}")
    _box_item("3", f"Включить — лёгкая  {DIM}packets=1-2 length=5-15б interval=20-50мс{NC}")
    _box_item("4", f"Включить — tlshello-рецепт  {DIM}packets=tlshello length=10-20б "
                   f"interval=10-20мс (DPI/CHECKER){NC}")
    _box_item("5", f"Включить — своя  {DIM}ввести packets/length/interval вручную{NC}")
    _box_sep()
    _box_item("0", f"{RED}Выключить{NC}  {DIM}(вернуть дефолтный экспорт без fragment){NC}")
    _box_row()
    _box_back()
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    preset_map = {
        "1": {"packets": "1-3", "length": "1-3",  "interval": "5-10"},
        "2": {"packets": "1-3", "length": "3-7",  "interval": "10-20"},
        "3": {"packets": "1-2", "length": "5-15", "interval": "20-50"},
        "4": {"packets": "tlshello", "length": "10-20", "interval": "10-20"},
    }

    if ch in ("q", ""):
        return

    if ch == "0":
        if _save_client_fragment_state({"enabled": False}):
            _success("Fragment-аддон экспорта ВЫКЛЮЧЕН")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    if ch in preset_map:
        cf = {"enabled": True, **preset_map[ch]}
    elif ch == "5":
        print()
        _info("Введите параметры (packets: N, N-M или tlshello):")
        print()
        try:
            raw_packets  = input(f"  {CYAN}packets {DIM}(напр. 1-3 или tlshello){NC}:  ").strip() or "1-3"
            raw_length   = input(f"  {CYAN}length  {DIM}(байты,    напр. 10-20){NC}:  ").strip() or "10-20"
            raw_interval = input(f"  {CYAN}interval{DIM}(мс,       напр. 10-20){NC}: ").strip() or "10-20"
        except KeyboardInterrupt:
            return
        ok = (
            _validate_range_str(raw_packets,  "packets")
            and _validate_range_str(raw_length,   "length")
            and _validate_range_str(raw_interval, "interval")
        )
        if not ok:
            time.sleep(2)
            return
        cf = {"enabled": True, "packets": raw_packets,
              "length": raw_length, "interval": raw_interval}
    else:
        _warn("Неверный выбор.")
        time.sleep(1)
        return

    if _save_client_fragment_state(cf):
        _success(f"Fragment-аддон экспорта ВКЛЮЧЁН: packets={cf['packets']} "
                 f"length={cf['length']}б interval={cf['interval']}мс")
        _info("Применится при следующей генерации клиентских конфигов "
              "(экспорт/share) — дополнительными файлами "
              "*-fragment.json + vless-links-fragment.txt")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def do_fragment_config_menu() -> None:
    """
    Интерактивное меню генератора клиентских конфигов с фрагментацией.
    Вызывается из _menu_diagnostics() в _core.py.
    """
    while True:
        os.system("clear")
        print()
        _box_top("🔀  ГЕНЕРАТОР КОНФИГОВ С ФРАГМЕНТАЦИЕЙ")
        _box_desc(
            "Фрагментация разбивает TLS ClientHello на мелкие TCP-сегменты, "
            "обходя DPI провайдера. Применяется в клиентском конфиге Xray."
        )
        _box_sep()
        _box_row()
        _box_item("1", f"⚡ Агрессивная  {DIM}(1–3 байта, макс. обход DPI){NC}")
        _box_item("2", f"✅ Сбалансированная  {DIM}(3–7 байт, рекомендуется){NC}")
        _box_item("3", f"🔆 Лёгкая  {DIM}(5–15 байт, минимальный оверхед){NC}")
        _box_item("4", f"⚙️  Пользовательская  {DIM}(ввести length / interval / packets){NC}")
        _box_item("5", f"📦 Fragment в дефолтном экспорте  {DIM}(тумблер: доп. файлы "
                       f"v2rayNG/Hiddify/Happ){NC}")
        _box_sep()
        _box_item("L", f"📂 Показать сохранённые конфиги")
        _box_row(f"       {DIM}{_FRAGMENT_DIR}{NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "q" or ch == "":
            break

        # ── Выбор пресета ─────────────────────────────────────────────────
        preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
        if ch in preset_map:
            key = preset_map[ch]
            p = _FRAGMENT_PRESETS[key]
            _info(f"Пресет: {p['desc']}")
            _info(f"  packets={p['packets']}  length={p['length']}  interval={p['interval']} мс")
            print()
            path = generate_fragment_client_config(
                packets=p["packets"],
                length=p["length"],
                interval=p["interval"],
                label=f"fragment_{key}",
            )
            if path:
                _success(f"Конфиг сохранён: {path}")
                _info("Скопируйте на клиентское устройство и подключите в Xray/v2rayNG/Nekoray")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            # Пользовательский ввод
            print()
            _info("Введите параметры фрагментации (диапазон: N или N-M, например 3-7):")
            print()

            try:
                raw_packets  = input(f"  {CYAN}packets {DIM}(сегменты, напр. 1-3){NC}: ").strip() or "1-3"
                raw_length   = input(f"  {CYAN}length  {DIM}(байты,    напр. 3-7){NC}: ").strip() or "3-7"
                raw_interval = input(f"  {CYAN}interval{DIM}(мс,       напр. 10-20){NC}: ").strip() or "10-20"
            except KeyboardInterrupt:
                continue

            ok = (
                _validate_range_str(raw_packets,  "packets")
                and _validate_range_str(raw_length,   "length")
                and _validate_range_str(raw_interval, "interval")
            )
            if not ok:
                time.sleep(2)
                continue

            print()
            path = generate_fragment_client_config(
                packets=raw_packets,
                length=raw_length,
                interval=raw_interval,
                label="fragment_custom",
            )
            if path:
                _success(f"Конфиг сохранён: {path}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            do_export_fragment_toggle_menu()

        elif ch == "l":
            # Список сохранённых конфигов
            print()
            _box_top("📂  Сохранённые конфиги")
            if not _FRAGMENT_DIR.exists() or not list(_FRAGMENT_DIR.glob("*.json")):
                _box_info("Конфигов пока нет — создайте через пункты 1–4")
            else:
                for f in sorted(_FRAGMENT_DIR.glob("*.json")):
                    try:
                        data = json.loads(f.read_text())
                        # Извлекаем параметры fragment из freedom-outbound
                        frag = {}
                        for _ob in data.get("outbounds", []):
                            _fr = (_ob.get("settings", {}) or {}).get("fragment")
                            if isinstance(_fr, dict):
                                frag = _fr
                                break
                        tag = (f"packets={frag.get('packets','-')} "
                               f"length={frag.get('length','-')} "
                               f"interval={frag.get('interval','-')}")
                        _box_row(f"  {GREEN}•{NC} {f.name}  {DIM}{tag}{NC}")
                    except Exception:
                        _box_row(f"  {DIM}• {f.name}{NC}")
            _box_bottom()
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор.")
            time.sleep(1)
