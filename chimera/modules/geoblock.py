"""
chimera/modules/geoblock.py
───────────────────────────────────────────────────────────────────────────────
Гео-блокировка по странам для Telemt (MTProto) — iptables/ipset DROP.

Блокирует входящие соединения на порт Telemt с IP-диапазонов указанных стран.
Работает на уровне iptables (ДО бинарника Telemt), а не на уровне Xray routing.

Переиспользует паттерн из ingress_geoip.py (ipset hash:net + iptables DROP),
но в режиме block-list (DROP конкретных стран), а не allow-list.

Источник данных: ipdeny.com — aggregated country zone files.
  IPv4: https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone
  IPv6: https://www.ipdeny.com/ipblocks/data/aggregated/ip6t/{cc}-aggregated.zone

Персистентность: через ipset_save() + systemd-юнит восстановления (как в
ingress_geoip.py). State в JSON — какие страны заблокированы на каком порту.

Точки входа:
    from chimera.modules.geoblock import (
        geoblock_add_country, geoblock_remove_country,
        geoblock_list, geoblock_menu_telemt,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import shutil
import urllib.request
from pathlib import Path
from typing import Optional

# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ───────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/geoblock_telemt.json")
_IPDENY_V4_BASE = "https://www.ipdeny.com/ipblocks/data/aggregated"
_IPDENY_V6_BASE = "https://www.ipdeny.com/ipblocks/data/aggregated/ip6t"

# Имена ipset-сетов — уникальные, не конфликтуют с ingress_geoip (xray_ru_block)
_IPSET_V4_PREFIX = "telemt_geoblock_v4_"
_IPSET_V6_PREFIX = "telemt_geoblock_v6_"

# Комментарий для iptables-правил
_IPT_COMMENT = "telemt-geoblock"


# ── State ────────────────────────────────────────────────────────────────────

def _state_load() -> dict:
    """Загружает state: {port: [country_code, ...], ...}"""
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}


def _state_save(data: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    _STATE_FILE.chmod(0o640)


# ── Скачивание CIDR-списка страны ────────────────────────────────────────────

def _fetch_country_cidrs(cc: str) -> "tuple[list[str], list[str]]":
    """Скачивает aggregated CIDR-список страны с ipdeny.com.
    
    Возвращает (v4_cidrs, v6_cidrs).
    """
    cc = cc.lower().strip()
    v4_url = f"{_IPDENY_V4_BASE}/{cc}-aggregated.zone"
    v6_url = f"{_IPDENY_V6_BASE}/{cc}-aggregated.zone"
    
    v4_cidrs = []
    v6_cidrs = []
    
    # IPv4
    try:
        req = urllib.request.Request(v4_url, headers={"User-Agent": "Chimera-Project"})
        with urllib.request.urlopen(req, timeout=30) as r:
            for line in r.read().decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    v4_cidrs.append(line)
    except Exception as e:
        try:
            _core_module().warn(f"Не удалось скачать IPv4 CIDR для {cc.upper()}: {e}")
        except Exception:
            pass
    
    # IPv6
    try:
        req = urllib.request.Request(v6_url, headers={"User-Agent": "Chimera-Project"})
        with urllib.request.urlopen(req, timeout=30) as r:
            for line in r.read().decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    v6_cidrs.append(line)
    except Exception:
        pass  # IPv6 может отсутствовать для некоторых стран — не критично
    
    return v4_cidrs, v6_cidrs


# ── Применение ipset+iptables ────────────────────────────────────────────────

def _run(cmd: list, **kw):
    """Делегирует в core._run."""
    return _core_module()._run(cmd, **kw)


def _apply_country_block(port: int, cc: str, v4: list, v6: list) -> bool:
    """Создаёт ipset-сеты и iptables-правила для блокировки страны на порту."""
    cc = cc.lower().strip()
    ipset_v4 = f"{_IPSET_V4_PREFIX}{cc}"
    ipset_v6 = f"{_IPSET_V6_PREFIX}{cc}"
    
    # IPv4
    if v4:
        _run(["ipset", "create", ipset_v4, "hash:net", "family", "inet",
              "maxelem", "100000", "-exist"], check=False, quiet=True)
        _run(["ipset", "flush", ipset_v4], check=False, quiet=True)
        
        # Batch-добавление через restore
        restore_text = "\n".join(f"add {ipset_v4} {cidr}" for cidr in v4)
        tmp = Path(f"/tmp/geoblock_{cc}_v4.ipset")
        tmp.write_text(restore_text)
        _run(["ipset", "restore", "-!", "-f", str(tmp)], check=False, quiet=True)
        tmp.unlink(missing_ok=True)
        
        # iptables DROP
        _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", ipset_v4, "src", "-j", "DROP",
              "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
             check=False, quiet=True)
        _run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", ipset_v4, "src", "-j", "DROP",
              "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
             check=False, quiet=True)
    
    # IPv6
    if v6:
        _run(["ipset", "create", ipset_v6, "hash:net", "family", "inet6",
              "maxelem", "50000", "-exist"], check=False, quiet=True)
        _run(["ipset", "flush", ipset_v6], check=False, quiet=True)
        
        restore_text = "\n".join(f"add {ipset_v6} {cidr}" for cidr in v6)
        tmp = Path(f"/tmp/geoblock_{cc}_v6.ipset")
        tmp.write_text(restore_text)
        _run(["ipset", "restore", "-!", "-f", str(tmp)], check=False, quiet=True)
        tmp.unlink(missing_ok=True)
        
        _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", ipset_v6, "src", "-j", "DROP",
              "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
             check=False, quiet=True)
        _run(["ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", ipset_v6, "src", "-j", "DROP",
              "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
             check=False, quiet=True)
    
    # Persist ipset
    try:
        from chimera.modules.ipset_persist import ipset_save
        ipset_save()
    except Exception:
        pass
    
    return True


def _remove_country_block(port: int, cc: str) -> bool:
    """Удаляет ipset-сеты и iptables-правила для страны."""
    cc = cc.lower().strip()
    ipset_v4 = f"{_IPSET_V4_PREFIX}{cc}"
    ipset_v6 = f"{_IPSET_V6_PREFIX}{cc}"
    
    # Удаляем iptables-правила
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "--match-set", ipset_v4, "src", "-j", "DROP",
          "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
         check=False, quiet=True)
    _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "--match-set", ipset_v6, "src", "-j", "DROP",
          "-m", "comment", "--comment", f"{_IPT_COMMENT}-{cc}"],
         check=False, quiet=True)
    
    # Удаляем ipset-сеты
    _run(["ipset", "destroy", ipset_v4], check=False, quiet=True)
    _run(["ipset", "destroy", ipset_v6], check=False, quiet=True)
    
    # Persist
    try:
        from chimera.modules.ipset_persist import ipset_save
        ipset_save()
    except Exception:
        pass
    
    return True


# ── Публичный API ─────────────────────────────────────────────────────────────

def geoblock_add_country(port: int, country_code: str) -> bool:
    """Блокирует входящие соединения на порт с IP-диапазонов указанной страны.
    
    Args:
      port: TCP-порт Telemt
      country_code: ISO 3166-1 alpha-2 (ir, cn, ru, us и т.п.)
    
    Возвращает True если блокировка применена.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    success = core.success
    
    cc = country_code.lower().strip()
    if not cc or len(cc) != 2:
        warn(f"Неверный код страны: {country_code!r} (нужно 2 буквы, например 'ir')")
        return False
    
    if not shutil.which("ipset"):
        warn("ipset не установлен: apt install ipset")
        return False
    
    info(f"Скачиваю CIDR-список для {cc.upper()}...")
    v4, v6 = _fetch_country_cidrs(cc)
    if not v4 and not v6:
        warn(f"Не удалось получить CIDR-список для {cc.upper()}")
        return False
    
    info(f"Применяем блокировку: {cc.upper()} ({len(v4)} IPv4 + {len(v6)} IPv6 CIDR) → DROP :{port}")
    if not _apply_country_block(port, cc, v4, v6):
        warn(f"Не удалось применить блокировку для {cc.upper()}")
        return False
    
    # Сохраняем в state
    state = _state_load()
    port_key = str(port)
    if port_key not in state:
        state[port_key] = []
    if cc not in state[port_key]:
        state[port_key].append(cc)
    _state_save(state)
    
    success(f"Заблокирована страна {cc.upper()} на порту {port} "
            f"({len(v4)} IPv4 + {len(v6)} IPv6 CIDR)")
    return True


def geoblock_remove_country(port: int, country_code: str) -> bool:
    """Удаляет блокировку страны с порта."""
    core = _core_module()
    success = core.success
    warn = core.warn
    
    cc = country_code.lower().strip()
    
    _remove_country_block(port, cc)
    
    # Обновляем state
    state = _state_load()
    port_key = str(port)
    if port_key in state and cc in state[port_key]:
        state[port_key].remove(cc)
        if not state[port_key]:
            del state[port_key]
        _state_save(state)
    
    success(f"Разблокирована страна {cc.upper()} на порту {port}")
    return True


def geoblock_list(port: int) -> list:
    """Возвращает список заблокированных стран на порту."""
    state = _state_load()
    return state.get(str(port), [])


def geoblock_restore_all() -> None:
    """Восстанавливает все блокировки из state после ребута.
    
    Вызывается из systemd-юнита или cron.
    """
    state = _state_load()
    if not state:
        return
    
    core = _core_module()
    info = core.info
    
    for port_str, countries in state.items():
        try:
            port = int(port_str)
        except ValueError:
            continue
        for cc in countries:
            info(f"geoblock: восстанавливаю {cc.upper()} на порту {port}...")
            v4, v6 = _fetch_country_cidrs(cc)
            if v4 or v6:
                _apply_country_block(port, cc, v4, v6)


# ── TUI ──────────────────────────────────────────────────────────────────────

def geoblock_menu_telemt(port: int) -> None:
    """TUI-меню гео-блокировки для Telemt."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_info = core._box_info
    _box_warn = core._box_warn
    CYAN = core.CYAN
    NC = core.NC
    GREEN = core.GREEN
    YELLOW = core.YELLOW
    RED = core.RED
    DIM = core.DIM
    BLUE = core.BLUE
    BOLD = core.BOLD
    info = core.info
    warn = core.warn
    success = core.success
    
    while True:
        os.system("clear")
        print()
        blocked = geoblock_list(port)
        
        _box_top(f"🌍  Гео-блокировка  •  Telemt  (порт {port})")
        _box_row()
        if blocked:
            _box_row(f"  Заблокированные страны: {GREEN}{', '.join(c.upper() for c in blocked)}{NC}")
        else:
            _box_row(f"  {DIM}Нет заблокированных стран{NC}")
        _box_row()
        _box_row(f"  {DIM}Блокировка работает на уровне iptables/ipset —{NC}")
        _box_row(f"  {DIM}соединения отбрасываются ДО достижения бинарника Telemt.{NC}")
        _box_row(f"  {DIM}Источник данных: ipdeny.com (aggregated country zones).{NC}")
        _box_row(f"  {DIM}Персистентность: ipset save + systemd restore при ребуте.{NC}")
        _box_sep()
        _box_item("1", "🚫  Заблокировать страну")
        _box_item("2", "✅  Разблокировать страну")
        _box_item("3", "📋  Список заблокированных")
        _box_sep()
        _box_item("Q", f"{DIM}Назад{NC}")
        _box_bottom()
        print()
        
        try:
            ch = input(f"{CYAN}  Выбор [1/2/3/Q]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return
        
        if ch == "1":
            try:
                cc = input(f"  {CYAN}Код страны (2 буквы, например ir, cn, ru):{NC} ").strip().lower()
            except KeyboardInterrupt:
                print(); continue
            if not cc or len(cc) != 2:
                _box_warn("  Нужно 2 буквы (ISO 3166-1 alpha-2).")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                continue
            if cc in blocked:
                _box_warn(f"  {cc.upper()} уже заблокирована.")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                continue
            if geoblock_add_country(port, cc):
                _box_info(f"  Страна {cc.upper()} заблокирована.")
            else:
                _box_warn("  Не удалось — проверьте вывод выше.")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")
        
        elif ch == "2":
            if not blocked:
                _box_warn("  Нет заблокированных стран.")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                continue
            try:
                cc = input(f"  {CYAN}Код страны для разблокировки:{NC} ").strip().lower()
            except KeyboardInterrupt:
                print(); continue
            if cc not in blocked:
                _box_warn(f"  {cc.upper()} не заблокирована.")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")
                continue
            if geoblock_remove_country(port, cc):
                _box_info(f"  Страна {cc.upper()} разблокирована.")
            else:
                _box_warn("  Не удалось — проверьте вывод выше.")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")
        
        elif ch == "3":
            print()
            if blocked:
                _box_top(f"Заблокированные страны (порт {port})")
                for cc in blocked:
                    _box_row(f"  {GREEN}●{NC} {cc.upper()}")
                _box_bottom()
            else:
                _box_warn("  Нет заблокированных стран.")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")
        
        elif ch in ("q", ""):
            return
