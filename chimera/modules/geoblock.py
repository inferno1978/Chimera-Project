"""
chimera/modules/geoblock.py
───────────────────────────────────────────────────────────────────────────────
Гео-блокировка по странам для Telemt (MTProto) — nftables DROP.

Блокирует входящие соединения на порт Telemt с IP-диапазонов указанных стран.
Работает на уровне nftables (ДО бинарника Telemt), а не на уровне Xray routing.

МИГРАЦИЯ (этап 1.2):
  Раньше использовался связка `ipset hash:net` + `iptables/ip6tables -m set
  --match-set` для каждой страны. Теперь всё живет в единой таблице
  `inet chimera` (covers both IPv4 + IPv6 без дублирования) и использует
  централизованные примитивы из `chimera/modules/nft_common.py`:

    • `nft_set_create(name, ..., flags=["interval"], maxelem=N)` — замена
      `ipset create <name> hash:net family inet maxelem N -exist`.
    • `nft_set_atomic_swap(name, new_elements, ...)` — замена последовательности
      `ipset flush <name>` + `ipset restore -! -f <tmpfile>`. Атомарная
      транзакция `nft -f -` (flush set + add element в одном batch) — лучше
      старого паттерна ipset (между flush и add нет окна видимости).
    • `nft_rule_add(table, chain, rule_spec, family, comment=...)` — замена
      `-D ... -A ... -m set --match-set ... -m comment --comment ...`
      (идемпотентно по comment-tag, не требует ручного -D перед -A).
    • `nft_rule_delete_by_comment(table, chain, comment)` — замена цикла
      `iptables -D INPUT ...` до rc!=0. Один вызов находит все правила с
      указанным comment и удаляет их через `handle` (через `nft -a list chain`).
    • `nft_set_destroy(name, table, family)` — замена `ipset destroy <name>`.
    • `nft_persist()` — замена `ipset save` → /etc/ipset.conf. Теперь единый
      `/etc/nftables.conf` для всех правил Chimera (nft list ruleset).

  Comment-tag `telemt-geoblock-<cc>` сохранён для совместимости с аудитом
  правил в `nft list ruleset` (тот же префикс `telemt-geoblock-` что и раньше).
  Семантика идентична: что блокировалось — то и блокируется.

Переиспользует паттерн из ingress_geoip.py (set + DROP rule),
но в режиме block-list (DROP конкретных стран), а не allow-list.

Источник данных: ipdeny.com — aggregated country zone files.
  IPv4: https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone
  IPv6: https://www.ipdeny.com/ipblocks/data/aggregated/ip6t/{cc}-aggregated.zone

Персистентность: через `nft_persist()` → единый файл /etc/nftables.conf
(заменяет отдельные /etc/ipset.conf + /etc/iptables/rules.v4 + rules.v6).
State в JSON — какие страны заблокированы на каком порту.

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
import urllib.request
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.2 миграции)
from .nft_common import (
    nft_set_create, nft_set_atomic_swap, nft_set_destroy,
    nft_rule_add, nft_rule_delete_by_comment,
    nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    geoblock_set_name, COMMENT_GEOBLOCK_PREFIX,
)

# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ───────────────────────────────────────────────────────────────
_STATE_FILE = Path("/var/lib/xray-installer/geoblock_telemt.json")
_IPDENY_V4_BASE = "https://www.ipdeny.com/ipblocks/data/aggregated"
_IPDENY_V6_BASE = "https://www.ipdeny.com/ipblocks/data/aggregated/ip6t"

# Имена nft sets теперь генерируются через chimera.modules.nft_constants.
# geoblock_set_name(cc, ipv6=False) → "geoblock_<cc>_v4" / "geoblock_<cc>_v6".
# Исторически (до миграции, эпоха ipset) использовались имена вида
# `telemt_geoblock_v4_<cc>` — см. LEGACY_IPSET_NAME_MAP в nft_constants для
# обратной совместимости со старым state.json (если такой попадётся).
_IPSET_V4_PREFIX = "telemt_geoblock_v4_"  # legacy alias (для справки)
_IPSET_V6_PREFIX = "telemt_geoblock_v6_"  # legacy alias (для справки)

# Comment-tag для nft-правил: `telemt-geoblock-<cc>` (префикс из nft_constants).
# Используем централизованный COMMENT_GEOBLOCK_PREFIX чтобы не разойтись
# с реестром comment-тегов Chimera.
_IPT_COMMENT = COMMENT_GEOBLOCK_PREFIX  # "telemt-geoblock-"


def _set_name_v4(cc: str) -> str:
    """Имя nft set для IPv4 geoblock страны cc."""
    return geoblock_set_name(cc, ipv6=False)


def _set_name_v6(cc: str) -> str:
    """Имя nft set для IPv6 geoblock страны cc."""
    return geoblock_set_name(cc, ipv6=True)


def _comment_tag(cc: str) -> str:
    """Comment-tag для nft-правила блокировки страны cc (для аудита и удаления)."""
    return f"{COMMENT_GEOBLOCK_PREFIX}{cc.lower()}"


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


# ── Применение nft set + DROP rule ────────────────────────────────────────────

def _apply_country_block(port: int, cc: str, v4: list, v6: list) -> bool:
    """Создаёт nft set и DROP-правила для блокировки страны на порту.

    Заменяет (миграция этап 1.2):
      ipset create <name> hash:net family inet maxelem 100000 -exist
      ipset flush <name>
      ipset restore -! -f /tmp/geoblock_<cc>_v4.ipset
      iptables -D INPUT -p tcp --dport <port> -m set --match-set <name> src \\
          -j DROP -m comment --comment telemt-geoblock-<cc>
      iptables -A INPUT -p tcp --dport <port> -m set --match-set <name> src \\
          -j DROP -m comment --comment telemt-geoblock-<cc>
      (и зеркально для IPv6 через ipset create family inet6 + ip6tables -A)

    Теперь:
      nft_set_create(name, set_type="ipv4_addr", flags=["interval"], maxelem=N)
      nft_set_atomic_swap(name, v4_cidrs)  # flush+add в одной транзакции
      nft_rule_add(table="chimera", chain="input",
                   rule_spec="tcp dport {port} ip saddr @{name} drop",
                   comment="telemt-geoblock-{cc}")
      (аналогично для IPv6: set_type="ipv6_addr", "ip6 saddr @{name}")
    """
    cc = cc.lower().strip()
    set_v4 = _set_name_v4(cc)
    set_v6 = _set_name_v6(cc)
    comment = _comment_tag(cc)

    # IPv4
    if v4:
        # nft set inet chimera geoblock_<cc>_v4 { type ipv4_addr; flags interval; size 100000; }
        nft_set_create(
            set_v4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
            set_type="ipv4_addr", flags=["interval"], maxelem=100000,
        )
        # Атомарно заменяем содержимое set на v4 (flush+add одной транзакцией).
        # Заменяет `ipset flush` + `ipset restore -! -f <file>`.
        nft_set_atomic_swap(
            set_v4, v4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        )
        # nft add rule inet chimera input tcp dport <port> ip saddr @<set_v4> drop
        # comment "telemt-geoblock-<cc>"
        # Идемпотентно по comment-tag: повторный вызов не дублирует правило.
        nft_rule_add(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec=f"tcp dport {port} ip saddr @{set_v4} drop",
            family=NFT_TABLE_FAMILY, comment=comment, idempotent=True,
        )

    # IPv6
    if v6:
        # nft set inet chimera geoblock_<cc>_v6 { type ipv6_addr; flags interval; size 50000; }
        nft_set_create(
            set_v6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
            set_type="ipv6_addr", flags=["interval"], maxelem=50000,
        )
        nft_set_atomic_swap(
            set_v6, v6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
        )
        # nft add rule inet chimera input tcp dport <port> ip6 saddr @<set_v6> drop
        # comment "telemt-geoblock-<cc>"
        nft_rule_add(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec=f"tcp dport {port} ip6 saddr @{set_v6} drop",
            family=NFT_TABLE_FAMILY, comment=comment, idempotent=True,
        )

    # Persist nft ruleset (заменяет `ipset save` → /etc/ipset.conf).
    try:
        nft_persist()
    except Exception:
        pass

    return True


def _remove_country_block(port: int, cc: str) -> bool:
    """Удаляет nft set и DROP-правила для страны.

    Заменяет (миграция этап 1.2):
      iptables -D INPUT -p tcp --dport <port> -m set --match-set <name> src \\
          -j DROP -m comment --comment telemt-geoblock-<cc>
      ip6tables -D INPUT -p tcp --dport <port> -m set --match-set <name6> src \\
          -j DROP -m comment --comment telemt-geoblock-<cc>
      ipset destroy <name>
      ipset destroy <name6>

    Теперь:
      nft_rule_delete_by_comment(table="chimera", chain="input",
                                  comment="telemt-geoblock-<cc>")
        — один вызов находит ВСЕ правила с этим comment (v4 и v6 вместе,
          потому что у них одинаковый comment-tag) и удаляет через handle.
      nft_set_destroy(<set_v4>, table="chimera", family="inet")
      nft_set_destroy(<set_v6>, table="chimera", family="inet")
    """
    cc = cc.lower().strip()
    set_v4 = _set_name_v4(cc)
    set_v6 = _set_name_v6(cc)
    comment = _comment_tag(cc)

    # Удаляем все nft-правила с comment="telemt-geoblock-<cc>" из input.
    # Заменяет цикл `iptables -D` (там нужно было по одному -D на каждое
    # правило — для IPv4 и IPv6 отдельно). Здесь один вызов покрывает оба.
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=comment, family=NFT_TABLE_FAMILY,
    )

    # Уничтожаем nft sets (set_v4 + set_v6 — это два разных set, их надо
    # удалить оба).
    nft_set_destroy(set_v4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    nft_set_destroy(set_v6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)

    # Persist
    try:
        nft_persist()
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
    
    # Замена `shutil.which("ipset")` на `_nft_available()` из nft_common.
    if not _nft_available():
        warn("nft не установлен: apt install nftables")
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
        _box_row(f"  {DIM}Блокировка работает на уровне nftables —{NC}")
        _box_row(f"  {DIM}соединения отбрасываются ДО достижения бинарника Telemt.{NC}")
        _box_row(f"  {DIM}Источник данных: ipdeny.com (aggregated country zones).{NC}")
        _box_row(f"  {DIM}Персистентность: nft list ruleset → /etc/nftables.conf +{NC}")
        _box_row(f"  {DIM}восстановление через nftables.service при ребуте.{NC}")
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
