"""
chimera/modules/status_panel.py
─────────────────────────────────────────────────────────────────────────────
Сводная панель "Состояние" над главным меню (main_menu() в _core.py).

Единственная точка сопряжения с _core.py — функция render(), которую
main_menu() вызывает перед отрисовкой своего собственного _box_top().
Панель ничего не знает о структуре главного меню и не лезет в его глобали —
все данные читает сама: либо напрямую из state.json/state-файлов других
модулей, либо через уже существующие публичные/приватные функции этих же
модулей (см. таблицы PROTOCOLS/SECURITY ниже). Каждая отдельная проверка
обёрнута в try/except: если какой-то модуль переименуют/сломают, это
роняет только одну строку в счётчике, а не всю панель.

Кэш на диск (/var/lib/xray-installer/status_panel_cache.json, TTL 20 сек):
"тяжёлая" часть (systemctl/subprocess-проверки по ~15 модулям + запрос
IP/страны) считается не при каждой отрисовке меню, а не чаще раза в 20
секунд. На практике при обычной навигации по меню (main_menu — это
while True с перерисовкой при каждом возврате из подменю) это означает
одну заметную задержку примерно раз в 15-30 секунд активной работы, а не
на каждое нажатие.

ВАЖНО — сделанные допущения, требуют твоей проверки:
  • Hysteria2 считается "активным", если включена chain-exit роль
    (`h2_exit_enabled` в state.json) — отдельного стейта для entry-only
    установки в state.json не нашлось. Если у тебя H2 может стоять только
    как entry без exit — поправь _check_h2() ниже.
  • "VK Turn Tunnel" считается активным, если установлен хотя бы один из
    двух вариантов (FreeTurn/turntunnel.py ИЛИ WireTurn/turnable.py) — в
    главном меню это тоже один пункт (8), так что 1:1 с ним.
  • Ручной `ipban.py` (точечный бан конкретных IP по запросу) сознательно
    НЕ включён в "Безопасность" — это утилита разового действия, а не
    постоянно работающий защитный слой, в отличие от fail2ban/honeypot/
    ingress_geoip/autoban.
  • "Пользователи" считает active/total как not-disabled/all через
    _unified_load_users() из _core.py — то же самое, что уже использует
    subscription.py.
─────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom,
    RED, GREEN, BLUE, CYAN, YELLOW, DIM, NC,
)

STATE_FILE = Path("/var/lib/xray-installer/state.json")
CACHE_FILE = Path("/var/lib/xray-installer/status_panel_cache.json")
CACHE_TTL  = 20  # секунд — см. пояснение в шапке файла


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def _run_ok(cmd: list[str], timeout: float = 3.0) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


# =============================================================================
#  ПРОТОКОЛЫ
# =============================================================================
def _check_awg(state: dict) -> bool:
    return bool(state.get("awg_exit_enabled") or state.get("awg_installed"))

def _check_h2(state: dict) -> bool:
    return bool(state.get("h2_exit_enabled"))

def _check_telemt() -> bool:
    from chimera.modules.mtproto import BIN_PATH
    return BIN_PATH.exists()

def _check_vkturn() -> bool:
    installed = False
    try:
        from chimera.modules.turntunnel import _is_installed as _t1
        installed = installed or _t1()
    except Exception:
        pass
    try:
        from chimera.modules.turnable import _is_installed as _t2
        installed = installed or _t2()
    except Exception:
        pass
    return installed

def _check_slipgate() -> bool:
    from chimera.modules.slipgate import _is_installed
    return _is_installed()

def _check_wdtt() -> bool:
    from chimera.modules.wdtt import _is_installed
    return _is_installed()

def _check_naiveproxy() -> bool:
    from chimera.modules.naiveproxy import _is_installed
    return _is_installed()

def _check_mieru() -> bool:
    from chimera.modules.mieru import _is_installed
    return _is_installed()

def _check_snell() -> bool:
    """Snell v4 — установлен если есть бинарник + template unit + CONFIG_DIR."""
    try:
        from chimera.modules.snell import _is_installed
        return _is_installed()
    except Exception:
        return False

def _check_olcrtc() -> bool:
    from chimera.modules.olcrtc import _olcrtc_installed
    return _olcrtc_installed()

def _check_webdav() -> bool:
    from chimera.modules.webdav_tunnel import _is_installed
    return _is_installed()

def _protocol_checks(state: dict) -> list[tuple[str, bool]]:
    """VLESS+REALITY — ядро проекта: считается активным, пока существует
    state.json (само его наличие означает, что установка проведена)."""
    checks: list[tuple[str, Callable[[], bool]]] = [
        ("VLESS + REALITY",   lambda: STATE_FILE.exists()),
        ("AWG (AmneziaWG)",   lambda: _check_awg(state)),
        ("Hysteria2",         lambda: _check_h2(state)),
        ("Telemt / MTProto",  _check_telemt),
        ("VK Turn Tunnel",    _check_vkturn),
        ("SlipGate/SlipNet",  _check_slipgate),
        ("qWDTT",             _check_wdtt),
        ("NaiveProxy",        _check_naiveproxy),
        ("Mieru",             _check_mieru),
        ("Snell v4",          _check_snell),
        ("olcRTC",            _check_olcrtc),
        ("WebDAV Tunnel",     _check_webdav),
    ]
    out: list[tuple[str, bool]] = []
    for name, fn in checks:
        try:
            out.append((name, bool(fn())))
        except Exception:
            out.append((name, False))
    return out


# =============================================================================
#  СЕТЕВЫЕ СЛУЖБЫ — WARP, DNSCrypt
# =============================================================================
def _check_warp() -> bool:
    from chimera.modules.warp import _warp_is_installed
    return _warp_is_installed()

def _check_dnscrypt(state: dict) -> bool:
    if not state.get("use_dnscrypt"):
        return False
    return _run_ok(["systemctl", "is-active", "--quiet", "dnscrypt-proxy"])

def _network_checks(state: dict) -> list[tuple[str, bool]]:
    checks: list[tuple[str, Callable[[], bool]]] = [
        ("WARP",     lambda: _check_warp()),
        ("DNSCrypt", lambda: _check_dnscrypt(state)),
    ]
    out: list[tuple[str, bool]] = []
    for name, fn in checks:
        try:
            out.append((name, bool(fn())))
        except Exception:
            out.append((name, False))
    return out


# =============================================================================
#  БЕЗОПАСНОСТЬ — fail2ban, honeypot, ingress-GeoIP, auto-ban по TLS-ошибкам
# =============================================================================
def _check_fail2ban() -> bool:
    from chimera.modules.fail2ban_manager import _f2b_installed, _f2b_active
    return _f2b_installed() and _f2b_active()

def _check_honeypot() -> bool:
    from chimera.modules.honeypot import _honeypot_state_load
    return bool(_honeypot_state_load().get("enabled"))

def _check_ingress_geoip() -> bool:
    from chimera.modules.ingress_geoip import _ingress_state_load
    return bool(_ingress_state_load().get("enabled"))

def _check_autoban() -> bool:
    return Path("/etc/cron.d/xray-autoban").exists()

def _security_checks() -> list[tuple[str, bool]]:
    checks: list[tuple[str, Callable[[], bool]]] = [
        ("fail2ban",      _check_fail2ban),
        ("Honeypot",      _check_honeypot),
        ("Ingress GeoIP", _check_ingress_geoip),
        ("Auto-ban TLS",  _check_autoban),
    ]
    out: list[tuple[str, bool]] = []
    for name, fn in checks:
        try:
            out.append((name, bool(fn())))
        except Exception:
            out.append((name, False))
    return out


# =============================================================================
#  ПОЛЬЗОВАТЕЛИ
# =============================================================================
def _users_counts() -> tuple[int, int]:
    try:
        users = _core_module()._unified_load_users()
        # Исключаем iOS-shadow-клиентов (служебные записи без flow, создаются
        # через _users_get_or_create_ios_shadow). Они не реальные пользователи,
        # а серверная пара для REALITY-юзера, чья iOS-ссылка идёт без Vision flow.
        # Без фильтра счётчик задваивался бы — shadow имеют уникальный UUID и
        # попадали бы в total как отдельный юзер.
        real_users = [u for u in users if not u.get("is_ios_shadow")]
        total = len(real_users)
        active = sum(1 for u in real_users if not u.get("disabled"))
        return active, total
    except Exception:
        return 0, 0


# =============================================================================
#  СИСТЕМНЫЕ МЕТРИКИ (без внешних зависимостей — /proc напрямую)
# =============================================================================
def _system_metrics() -> dict:
    metrics = {
        "load": "?, ?",
        "ram_pct": 0, "ram_used": "?", "ram_total": "?",
        "disk_pct": 0, "disk_used": "?", "disk_total": "?",
        "uptime": "?",
    }
    try:
        l1, l5, _l15 = os.getloadavg()
        metrics["load"] = f"{l1:.2f}, {l5:.2f}"
    except Exception:
        pass
    try:
        total, used, _free = shutil.disk_usage("/")
        metrics["disk_pct"]   = round(used / total * 100) if total else 0
        metrics["disk_used"]  = f"{used / 1024**3:.2f} GB"
        metrics["disk_total"] = f"{total / 1024**3:.2f} GB"
    except Exception:
        pass
    try:
        vals: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            vals[k.strip()] = int(v.strip().split()[0])  # в kB
        total_kb = vals.get("MemTotal", 0)
        avail_kb = vals.get("MemAvailable", 0)
        used_kb  = max(total_kb - avail_kb, 0)
        if total_kb:
            metrics["ram_pct"]   = round(used_kb / total_kb * 100)
            metrics["ram_used"]  = f"{used_kb / 1024:.1f} MB"
            metrics["ram_total"] = f"{total_kb / 1024:.1f} MB"
    except Exception:
        pass
    try:
        uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
        days, rem  = divmod(int(uptime_sec), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _s = divmod(rem, 60)
        metrics["uptime"] = f"{days}д {hours:02d}:{minutes:02d}"
    except Exception:
        pass
    return metrics


# =============================================================================
#  ВЕРСИЯ ЯДРА, IP+СТРАНА, DNSCRYPT-ПРОВАЙДЕРЫ
# =============================================================================
def _core_version() -> str:
    try:
        return _core_module()._xray_current_version() or "?"
    except Exception:
        return "?"

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def _ip_and_country() -> str:
    """get_server_ip() при сетевом сбое (например, временный DNS-затык до
    ipify) возвращает ТЕКСТ ОШИБКИ, а не исключение — если не проверять
    формат, эта строка целиком вклеится в панель и сломает рамку box_renderer.
    Поэтому валидируем, что вернулось что-то похожее на IPv4, а не текст."""
    try:
        core = _core_module()
        ip = (core.get_server_ip("4") or "").strip()
        if not _IPV4_RE.match(ip):
            return "?"
        cc, _name, flag = core.get_server_country_cached()
        return f"{ip}  {flag} {cc}".strip() if cc else ip
    except Exception:
        return "?"

def _dnscrypt_providers(state: dict) -> str:
    if not state.get("use_dnscrypt"):
        return "выключен"
    try:
        from chimera.modules.dnscrypt_selector import _get_current_server_names
        names = _get_current_server_names()
        return ", ".join(names) if names else "?"
    except Exception:
        return "?"


# =============================================================================
#  СБОРКА СНАПШОТА + КЭШ
# =============================================================================
def _build_snapshot() -> dict:
    state     = _load_state()
    protocols = _protocol_checks(state)
    network   = _network_checks(state)
    security  = _security_checks()
    users_active, users_total = _users_counts()

    return {
        "ts": time.time(),
        "core_version":     _core_version(),
        "protocols_active": sum(1 for _n, ok in protocols if ok),
        "protocols_total":  len(protocols),
        "network_active":   sum(1 for _n, ok in network if ok),
        "network_total":    len(network),
        "security_active":  sum(1 for _n, ok in security if ok),
        "security_total":   len(security),
        "users_active": users_active,
        "users_total":  users_total,
        "metrics":    _system_metrics(),
        "ip_country": _ip_and_country(),
        "dns":        _dnscrypt_providers(state),
    }

def _load_cache() -> Optional[dict]:
    try:
        data = json.loads(CACHE_FILE.read_text())
        if time.time() - data.get("ts", 0) < CACHE_TTL:
            return data
    except Exception:
        pass
    return None

def _save_cache(data: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False))
    except Exception:
        pass

def get_snapshot(force: bool = False) -> dict:
    """Публичная точка входа для получения данных без рендера — например,
    для будущего использования в других местах (TUI-статус в SSH MOTD и т.п.)."""
    if not force:
        cached = _load_cache()
        if cached:
            return cached
    data = _build_snapshot()
    _save_cache(data)
    return data


# =============================================================================
#  РЕНДЕР — единственное, что вызывает main_menu() в _core.py
# =============================================================================
def render() -> None:
    """Печатает панель «Состояние». Если сборка снапшота полностью
    провалилась (что не должно случаться благодаря try/except в каждой
    отдельной проверке, но на всякий случай) — молча ничего не рисует,
    чтобы сломанная панель не мешала попасть в само главное меню."""
    try:
        snap = get_snapshot()
    except Exception:
        return

    m = snap["metrics"]
    _box_top("Состояние")
    _box_row()
    _box_row(f"  {DIM}Ядро (Xray-core):{NC}  {GREEN}✓{NC}  {snap['core_version']}")
    _box_row(f"  {DIM}Протоколы:{NC}         {snap['protocols_active']}/{snap['protocols_total']} активны")
    _box_row(f"  {DIM}Сетевые службы:{NC}    {snap['network_active']}/{snap['network_total']} активны")
    _box_row(f"  {DIM}Безопасность:{NC}      {snap['security_active']}/{snap['security_total']} активны")
    _box_row(f"  {DIM}Пользователи:{NC}      {snap['users_active']} из {snap['users_total']}")
    _box_row(f"  {DIM}Load Avg:{NC}          {m['load']}")
    _box_row(f"  {DIM}RAM:{NC}               {m['ram_pct']}%  ({m['ram_used']} / {m['ram_total']})")
    _box_row(f"  {DIM}Диск:{NC}              {m['disk_pct']}%  ({m['disk_used']} / {m['disk_total']})")
    _box_row(f"  {DIM}Uptime:{NC}            {m['uptime']}")
    _box_row(f"  {DIM}IP (Public):{NC}       {CYAN}{snap['ip_country']}{NC}")
    _box_row(f"  {DIM}DNS:{NC}               {snap['dns']}")
    _box_bottom()


if __name__ == "__main__":
    import sys
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))
    render()
