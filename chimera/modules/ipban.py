"""
chimera/modules/ipban.py
───────────────────────────────────────────────────────────────────────────────
Ручной бан IP на уровне nftables через nft sets.

Возможности:
  • Бан одного IP                  (192.168.1.1)
  • Бан нескольких IP              (1.2.3.4, 5.6.7.8, ...)
  • Бан диапазона IP               (10.0.0.1-10.0.0.255)
  • Бан подсети (CIDR)             (10.0.0.0/24)
  • Бан целой ASN                  (AS12345 → скачивает префиксы с RIPE Stat)

Реализация (мигрировано с iptables/ipset на nftables, этап 1.1):
  • nft set inet chimera manual_ban_v4  (type ipv4_addr; flags interval;)
  • nft set inet chimera manual_ban_v6  (type ipv6_addr; flags interval;)
  • nft rule inet chimera input ip  saddr @manual_ban_v4 drop comment "xray-manual-ban"
  • nft rule inet chimera input ip6 saddr @manual_ban_v6 drop comment "xray-manual-ban"
  • Состояние бана → /var/lib/xray-installer/ipban.json
  • Персистентность — через nft list ruleset > /etc/nftables.conf
    (единый файл, заменяет /etc/iptables/rules.v4 + /etc/ipset.conf)

Бан НЕ затрагивает:
  • Xray-конфиг (никаких изменений в config.json)
  • GeoIP-блокировку (ingress_block_v4 / ingress_block_v6)
  • AutoBan (xray-autoban)
  • Службы: xray, nginx, telemt и все прочие

Точка входа из _core.py:
    from chimera.modules.ipban import do_manage_ipban
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

# nftables — централизованная обёртка над `nft` CLI (этап 1.1 миграции)
from .nft_common import (
    nft_set_create, nft_set_exists, nft_set_add, nft_set_del,
    nft_set_flush, nft_set_destroy, nft_set_count,
    nft_rule_add, nft_rule_exists, nft_rule_delete_by_comment,
    nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    NFT_SET_MANUAL_BAN_V4, NFT_SET_MANUAL_BAN_V6,
    COMMENT_MANUAL_BAN, NFT_PERSIST_FILE,
)

# ── Цвета (идентично остальным модулям проекта) ───────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN']; YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];  BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE']; NC     = _C['NC']


# ── Константы ─────────────────────────────────────────────────────────────────
_STATE_FILE    = Path("/var/lib/xray-installer/ipban.json")
# Имена nft sets (мигрировано с ipset xray_manual_ban / xray_manual_ban6).
# Сохраняем переменные _IPSET_V4/_IPSET_V6 как aliases для обратной совместимости
# с любыми местами в этом файле, которые ссылаются на старые имена.
_IPSET_V4      = NFT_SET_MANUAL_BAN_V4   # "manual_ban_v4"
_IPSET_V6      = NFT_SET_MANUAL_BAN_V6   # "manual_ban_v6"
_COMMENT       = COMMENT_MANUAL_BAN       # "xray-manual-ban"
# nft persist file (заменяет /etc/ipset.conf + /etc/iptables/rules.v4).
# Один единый файл для всех правил Chimera.
_IPSET_CONF    = Path(NFT_PERSIST_FILE)   # "/etc/nftables.conf"

_RIPE_PREFIXES = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
)


# ── Вспомогательные принтеры ──────────────────────────────────────────────────
def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC} {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}•{NC} {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC} {msg}", file=sys.stderr)


def _run(cmd: list, quiet: bool = False) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if not quiet and r.returncode != 0 and r.stderr:
        _warn(r.stderr.strip()[:200])
    return r


# ── Работа с состоянием ───────────────────────────────────────────────────────
def _state_load() -> dict:
    """Загружает состояние бана из JSON-файла."""
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {"entries": []}


def _state_save(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(
        json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _state_add_entry(
    display: str, cidrs: list, kind: str, comment: str = ""
) -> None:
    """Добавляет запись в state-файл (дедупликация по display)."""
    state = _state_load()
    entries = state.setdefault("entries", [])
    # не дублируем по display-имени
    entries = [e for e in entries if e.get("display") != display]
    entries.append({
        "display":  display,
        "kind":     kind,          # ip | cidr | range | asn
        "cidrs":    cidrs,
        "comment":  comment,
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    state["entries"] = entries
    _state_save(state)


def _state_remove_entry(display: str) -> bool:
    state = _state_load()
    before = len(state.get("entries", []))
    state["entries"] = [
        e for e in state.get("entries", []) if e.get("display") != display
    ]
    _state_save(state)
    return len(state["entries"]) < before


# ── nftables-хелперы (замена ipset/iptables, этап 1.1) ─────────────────────────
def _ipset_available() -> bool:
    """Алиас для обратной совместимости. Теперь проверяет наличие `nft` binary."""
    return _nft_available()


def _set_exists(name: str) -> bool:
    """Проверяет существует ли nft set (в таблице chimera)."""
    return nft_set_exists(name, table=NFT_TABLE_NAME)


def _ensure_sets() -> bool:
    """Создаёт nft sets manual_ban_v4 и manual_ban_v6 если их ещё нет.

    Заменяет: ipset create xray_manual_ban hash:net family inet maxelem 65536 -exist
              ipset create xray_manual_ban6 hash:net family inet6 maxelem 65536 -exist
    """
    if not _nft_available():
        _err("nft не установлен. Установите: apt install nftables")
        return False
    # nft set inet chimera manual_ban_v4 { type ipv4_addr; flags interval; size 65536; }
    nft_set_create(_IPSET_V4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
                   set_type="ipv4_addr", flags=["interval"], maxelem=65536)
    # nft set inet chimera manual_ban_v6 { type ipv6_addr; flags interval; size 65536; }
    nft_set_create(_IPSET_V6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
                   set_type="ipv6_addr", flags=["interval"], maxelem=65536)
    return True


def _ensure_iptables_rules() -> None:
    """
    Добавляет nft-правила DROP для manual_ban sets в цепочку input.

    Заменяет:
      iptables  -A INPUT -m set --match-set xray_manual_ban  src -j DROP \\
                  -m comment --comment xray-manual-ban
      ip6tables -A INPUT -m set --match-set xray_manual_ban6 src -j DROP \\
                  -m comment --comment xray-manual-ban

    Теперь это два правила в одной таблице inet chimera (v4 и v6 одновременно):
      nft add rule inet chimera input ip  saddr @manual_ban_v4 drop \\
          comment "xray-manual-ban"
      nft add rule inet chimera input ip6 saddr @manual_ban_v6 drop \\
          comment "xray-manual-ban"

    Правила идемпотентны через comment-tag — повторный вызов не дублирует.
    """
    # IPv4 — DROP для ip saddr в set
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"ip saddr @{_IPSET_V4} drop",
        family=NFT_TABLE_FAMILY, comment=_COMMENT, idempotent=True
    )
    # IPv6 — DROP для ip6 saddr в set
    nft_rule_add(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"ip6 saddr @{_IPSET_V6} drop",
        family=NFT_TABLE_FAMILY, comment=_COMMENT, idempotent=True
    )


def _remove_iptables_rules() -> None:
    """Удаляет все nft-правила с comment='xray-manual-ban' из input.

    Заменяет цикл `iptables -D INPUT ...` (10 итераций до rc!=0).
    nft_rule_delete_by_comment делает то же самое за один вызов через
    `nft -a list chain` → handles → delete.
    """
    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=_COMMENT, family=NFT_TABLE_FAMILY, max_iterations=20
    )


def _ipset_add_cidrs(cidrs: list) -> Tuple[int, int]:
    """
    Добавляет список CIDR в соответствующие nft sets.

    Заменяет: цикл ipset add xray_manual_ban <cidr> -exist
    Теперь: один batched nft add element inet chimera manual_ban_v4 { cidrs }

    Возвращает (добавлено_v4, добавлено_v6). В nft batch mode отдельный
    подсчёт "сколько добавлено нового" невозможен (nft не различает -exist
    и новый add). Возвращаем len списка как upper bound — это безопасно,
    потому что callers используют return только для display в TUI.
    """
    v4 = [c for c in cidrs if ":" not in c]
    v6 = [c for c in cidrs if ":" in c]

    added_v4 = added_v6 = 0
    if v4:
        # nft add element inet chimera manual_ban_v4 { cidr1, cidr2, ... }
        if nft_set_add(_IPSET_V4, v4, table=NFT_TABLE_NAME,
                       family=NFT_TABLE_FAMILY):
            added_v4 = len(v4)
    if v6:
        if nft_set_add(_IPSET_V6, v6, table=NFT_TABLE_NAME,
                       family=NFT_TABLE_FAMILY):
            added_v6 = len(v6)
    return added_v4, added_v6


def _ipset_del_cidrs(cidrs: list) -> None:
    """Удаляет список CIDR из nft sets (игнорирует ошибки).

    Заменяет цикл ipset del <name> <cidr>.
    Теперь: nft delete element inet chimera <set> { cidr1, cidr2, ... }
    """
    v4 = [c for c in cidrs if ":" not in c]
    v6 = [c for c in cidrs if ":" in c]
    if v4:
        nft_set_del(_IPSET_V4, v4, table=NFT_TABLE_NAME,
                    family=NFT_TABLE_FAMILY)
    if v6:
        nft_set_del(_IPSET_V6, v6, table=NFT_TABLE_NAME,
                    family=NFT_TABLE_FAMILY)


def _ipset_flush_all() -> None:
    """Очищает оба nft sets полностью.

    Заменяет: ipset flush xray_manual_ban / xray_manual_ban6.
    Теперь: nft flush set inet chimera manual_ban_v4 / manual_ban_v6.
    """
    nft_set_flush(_IPSET_V4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    nft_set_flush(_IPSET_V6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)


def _ipset_destroy_all() -> None:
    """Уничтожает оба nft sets.

    Заменяет: ipset destroy xray_manual_ban / xray_manual_ban6.
    Теперь: nft delete set inet chimera manual_ban_v4 / manual_ban_v6.
    """
    nft_set_destroy(_IPSET_V4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    nft_set_destroy(_IPSET_V6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)


def _ipset_count() -> Tuple[int, int]:
    """Возвращает количество записей в (v4, v6) через JSON-парсинг.

    Заменяет: парсинг текстового `ipset list <name>` → секция "Members:".
    Теперь: nft -j list set → JSON → len(elem).
    """
    return (
        nft_set_count(_IPSET_V4, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY),
        nft_set_count(_IPSET_V6, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY),
    )


# ── Сохранение ruleset (персистентность, этап 1.1) ────────────────────────────
def _ipban_persist_save() -> None:
    """
    Сохраняет весь nft ruleset в /etc/nftables.conf.

    Заменяет: ipset save xray_manual_ban* → /etc/ipset.conf (merge mode).
    Теперь: nft list ruleset > /etc/nftables.conf (atomic write через tmp+rename).

    Поскольку nftables хранит ВСЕ правила (включая от ingress_geoip,
    geoblock, user_ip_whitelist, awg_cascade, и т.д.) в одном ruleset,
    этот вызов сохраняет всё разом. Не нужно merge-логики как с ipset.
    """
    if not _nft_available():
        return
    if nft_persist(str(_IPSET_CONF)):
        _info(f"nft ruleset сохранён → {_IPSET_CONF}")
    else:
        _warn(f"Не удалось сохранить nft ruleset → {_IPSET_CONF}")


# ── Парсинг пользовательского ввода ───────────────────────────────────────────
def _parse_ip(raw: str) -> List[str]:
    """Одиночный IP → /32 или /128."""
    net = ipaddress.ip_address(raw)
    bits = 32 if net.version == 4 else 128
    return [f"{net}/{bits}"]


def _parse_cidr(raw: str) -> List[str]:
    """CIDR-подсеть — валидация и нормализация."""
    net = ipaddress.ip_network(raw, strict=False)
    return [str(net)]


def _parse_range(raw: str) -> List[str]:
    """
    Диапазон вида 1.2.3.4-1.2.3.255 → список CIDR.
    Работает только для IPv4 (ipaddress.summarize_address_range).
    """
    parts = raw.split("-", 1)
    if len(parts) != 2:
        raise ValueError(f"Неверный диапазон: {raw!r}")
    start = ipaddress.IPv4Address(parts[0].strip())
    end   = ipaddress.IPv4Address(parts[1].strip())
    if start > end:
        start, end = end, start
    return [str(n) for n in ipaddress.summarize_address_range(start, end)]


def _asn_normalize(raw: str) -> str:
    raw = raw.strip().upper()
    return raw if raw.startswith("AS") else f"AS{raw}"


def _fetch_asn_prefixes(asn: str) -> List[str]:
    """
    Скачивает IPv4+IPv6 префиксы ASN через RIPE Stat.
    Возвращает список CIDR или бросает RuntimeError.
    """
    url = _RIPE_PREFIXES.format(asn=asn)
    _info(f"Запрос префиксов {asn} → RIPE Stat API...")
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "xray-installer/4.12.10",
                              "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as exc:
            if attempt == 3:
                raise RuntimeError(f"RIPE Stat недоступен: {exc}") from exc
            _warn(f"  Попытка {attempt}/3 не удалась, повтор через {2**attempt}с...")
            time.sleep(2 ** attempt)

    try:
        data = json.loads(raw)
    except Exception as exc:
        raise RuntimeError(f"Неверный JSON от RIPE Stat: {exc}") from exc

    prefixes_raw = (
        data.get("data", {}).get("prefixes", [])
    )
    result = []
    for item in prefixes_raw:
        p = item.get("prefix", "")
        try:
            net = ipaddress.ip_network(p, strict=False)
            result.append(str(net))
        except ValueError:
            continue

    if not result:
        raise RuntimeError(f"RIPE Stat вернул 0 префиксов для {asn}")

    v4 = [p for p in result if ":" not in p]
    v6 = [p for p in result if ":" in p]
    _ok(f"{asn}: {len(v4)} IPv4 + {len(v6)} IPv6 префиксов")
    return result


def _detect_input_kind(raw: str) -> str:
    """
    Определяет тип введённых данных:
      'asn'   — AS12345
      'range' — содержит дефис между двумя IP
      'cidr'  — содержит /
      'ip'    — одиночный IP
    """
    raw = raw.strip()
    up = raw.upper()
    if up.startswith("AS") or (raw.isdigit() and len(raw) <= 10):
        return "asn"
    if "/" in raw:
        return "cidr"
    if "-" in raw and ":" not in raw:
        return "range"
    return "ip"


def _resolve_to_cidrs(raw: str) -> Tuple[str, str, List[str]]:
    """
    Главный парсер. raw — пользовательский ввод (один токен).
    Возвращает (display_name, kind, [CIDR, ...]).
    Бросает ValueError/RuntimeError при ошибке.
    """
    raw = raw.strip()
    kind = _detect_input_kind(raw)

    if kind == "asn":
        asn = _asn_normalize(raw)
        cidrs = _fetch_asn_prefixes(asn)
        return asn, "asn", cidrs

    if kind == "range":
        cidrs = _parse_range(raw)
        return raw, "range", cidrs

    if kind == "cidr":
        cidrs = _parse_cidr(raw)
        return str(ipaddress.ip_network(raw, strict=False)), "cidr", cidrs

    # одиночный IP
    cidrs = _parse_ip(raw)
    return str(ipaddress.ip_address(raw)), "ip", cidrs


# ── Публичный API (применение / снятие) ───────────────────────────────────────
def ipban_add(raw: str, comment: str = "") -> bool:
    """
    Банит один IP / CIDR / диапазон / ASN.
    Возвращает True при успехе.
    """
    if not _ensure_sets():
        return False
    try:
        display, kind, cidrs = _resolve_to_cidrs(raw)
    except (ValueError, RuntimeError) as exc:
        _err(str(exc))
        return False

    _ensure_iptables_rules()
    added_v4, added_v6 = _ipset_add_cidrs(cidrs)
    total = added_v4 + added_v6
    if total == 0:
        _warn(f"Ничего не добавлено для {display!r} (уже в списке или ошибка nft)")
    else:
        _ok(f"Заблокировано: {display}  "
            f"[{total} CIDR: {added_v4} IPv4 + {added_v6} IPv6]")

    _state_add_entry(display, cidrs, kind, comment)
    _ipban_persist_save()
    return True


def ipban_remove(display: str) -> bool:
    """
    Снимает бан по display-имени (берёт CIDR из state).
    Возвращает True при успехе.
    """
    state = _state_load()
    entry = next(
        (e for e in state.get("entries", []) if e.get("display") == display),
        None,
    )
    if not entry:
        _err(f"Запись {display!r} не найдена в state")
        return False

    _ipset_del_cidrs(entry.get("cidrs", []))
    _state_remove_entry(display)
    _ipban_persist_save()
    _ok(f"Разбанено: {display}")
    return True


def ipban_flush() -> None:
    """Снимает все баны, удаляет nft-правила и sets."""
    _remove_iptables_rules()
    _ipset_flush_all()
    _ipset_destroy_all()
    _state_save({"entries": []})
    _ipban_persist_save()
    _ok("Все IP-баны сняты, nft sets удалены")


def ipban_restore() -> None:
    """
    Восстанавливает баны из state (например, после reboot если
    nftables.service не включён или /etc/nftables.conf отсутствует).
    """
    state = _state_load()
    entries = state.get("entries", [])
    if not entries:
        _info("Нет записей для восстановления")
        return
    if not _ensure_sets():
        return
    _ensure_iptables_rules()
    total = 0
    for e in entries:
        v4, v6 = _ipset_add_cidrs(e.get("cidrs", []))
        total += v4 + v6
    _ok(f"Восстановлено {total} CIDR из {len(entries)} записей")


# ── Интерактивное меню ────────────────────────────────────────────────────────
def do_manage_ipban() -> None:
    """
    Главное меню управления IP-банами на уровне nftables.
    Вызывается из _core.py → _menu_security().
    """
    from chimera._core import (
        _box_top, _box_row, _box_sep, _box_bottom,
        _box_item, _box_back, _box_info, _box_warn, _box_ok,
        _box_dim, _box_input, DIM as _DIM, NC as _NC,
    )

    while True:
        os.system("clear")
        state    = _state_load()
        entries  = state.get("entries", [])
        cnt_v4, cnt_v6 = _ipset_count()
        sets_ok  = _set_exists(_IPSET_V4) or _set_exists(_IPSET_V6)

        # статус nft-правил (мигрировано с iptables -C → nft_rule_exists)
        # Проверяем наличие DROP-правила с comment="xray-manual-ban"
        chk4 = nft_rule_exists(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            comment=_COMMENT, family=NFT_TABLE_FAMILY
        )
        # В nft один comment-tag для обоих правил (v4 и v6) — chk6 = chk4.
        # Сохраняем отдельную переменную для совместимости с TUI ниже.
        chk6 = chk4

        rules_str = (
            f"{GREEN}активны{NC}"
            if (chk4 or chk6) else f"{DIM}не установлены{NC}"
        )
        entries_str = (
            f"{GREEN}{len(entries)} запис{'ь' if len(entries)==1 else 'и' if 2<=len(entries)<=4 else 'ей'}{NC}"
            if entries else f"{DIM}нет{NC}"
        )
        cidr_str = (
            f"{GREEN}{cnt_v4} IPv4 + {cnt_v6} IPv6{NC}"
            if sets_ok else f"{DIM}nft set не создан{NC}"
        )

        print()
        _box_top("🚫  IP-БАН  (nftables)")
        _box_row(f"  Правила nft:       {rules_str}")
        _box_row(f"  Записей в state:    {entries_str}")
        _box_row(f"  Активных CIDR:      {cidr_str}")
        _box_sep()
        _box_item("1", f"➕  Добавить бан  {DIM}(IP / подсеть / диапазон / ASN){NC}")
        _box_item("2", f"➖  Снять бан{NC}")
        _box_item("3", f"📋  Список активных банов")
        _box_sep()
        _box_item("4", f"🔄  Восстановить из state  {DIM}(после reboot){NC}")
        _box_item("5", f"💾  Сохранить nft ruleset → {_IPSET_CONF}")
        _box_item("X", f"{RED}🗑️   Снять ВСЕ баны{NC}  {DIM}(flush + удаление sets){NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        # ── 1. Добавить бан ───────────────────────────────────────────────────
        if ch == "1":
            os.system("clear")
            print()
            _box_top("🚫  ДОБАВИТЬ БАН")
            _box_row(f"  Форматы ввода (можно несколько через запятую или пробел):")
            _box_row()
            _box_row(f"    {CYAN}1.2.3.4{NC}              — одиночный IP")
            _box_row(f"    {CYAN}10.0.0.0/24{NC}          — подсеть (CIDR)")
            _box_row(f"    {CYAN}10.0.0.1-10.0.0.255{NC}  — диапазон IPv4")
            _box_row(f"    {CYAN}AS12345{NC}               — вся ASN (RIPE Stat)")
            _box_row(f"    {CYAN}2001:db8::/32{NC}         — IPv6 подсеть")
            _box_row()
            _box_row(f"  {DIM}Пример: 1.2.3.4, 10.0.0.0/8, AS1234{NC}")
            _box_bottom()

            try:
                raw_inp = input(f"{CYAN}Введите:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue

            if not raw_inp:
                continue

            try:
                comment_inp = input(f"{CYAN}Комментарий (Enter — пропустить):{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                comment_inp = ""

            # Разбиваем по запятым и пробелам
            tokens = [t.strip() for t in raw_inp.replace(",", " ").split() if t.strip()]
            print()
            _box_top("🚫  ПРИМЕНЯЮ БАН...")
            for token in tokens:
                ipban_add(token, comment=comment_inp)
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 2. Снять бан ──────────────────────────────────────────────────────
        elif ch == "2":
            os.system("clear")
            state   = _state_load()
            entries = state.get("entries", [])
            if not entries:
                print()
                _box_top("🚫  СНЯТЬ БАН")
                _box_row(f"  {YELLOW}Список банов пуст.{NC}")
                _box_bottom()
                input(f"{CYAN}Нажмите Enter...{NC}")
                continue

            print()
            _box_top("🚫  СНЯТЬ БАН — выберите запись")
            for idx, e in enumerate(entries, 1):
                kind_icon = {
                    "ip":    "🔹", "cidr": "🔸",
                    "range": "🔷", "asn":  "🏢",
                }.get(e.get("kind", ""), "•")
                n_cidr = len(e.get("cidrs", []))
                added  = e.get("added_at", "")[:10]
                cmt    = f"  {DIM}{e['comment']}{NC}" if e.get("comment") else ""
                _box_row(
                    f"  {CYAN}{idx:>2}.{NC} {kind_icon}  {BOLD}{e['display']}{NC}"
                    f"  {DIM}[{n_cidr} CIDR, {added}]{NC}{cmt}"
                )
            _box_sep()
            _box_row(f"  {DIM}Введите номер или display-имя{NC}")
            _box_bottom()

            try:
                sel = input(f"{CYAN}Выбор:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue

            if not sel:
                continue

            # по номеру или по имени
            target = None
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(entries):
                    target = entries[idx]["display"]
            else:
                # ищем по display или asn
                for e in entries:
                    if sel.upper() == e["display"].upper():
                        target = e["display"]
                        break

            if not target:
                _warn(f"Запись {sel!r} не найдена")
                time.sleep(1)
                continue

            print()
            _box_top("🚫  СНИМАЮ БАН...")
            ipban_remove(target)
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 3. Список ─────────────────────────────────────────────────────────
        elif ch == "3":
            os.system("clear")
            state   = _state_load()
            entries = state.get("entries", [])
            print()
            _box_top("📋  АКТИВНЫЕ IP-БАНЫ")
            if not entries:
                _box_row(f"  {DIM}Список пуст{NC}")
            else:
                _box_row(
                    f"  {'#':>3}  {'Тип':<6}  {'Запись':<30}  "
                    f"{'CIDR':>5}  {'Добавлен':<10}  Комментарий"
                )
                _box_sep()
                kind_labels = {
                    "ip": "IP", "cidr": "CIDR",
                    "range": "Range", "asn": "ASN",
                }
                for idx, e in enumerate(entries, 1):
                    kind   = kind_labels.get(e.get("kind", ""), "?")
                    n_cidr = len(e.get("cidrs", []))
                    added  = e.get("added_at", "")[:10]
                    cmt    = e.get("comment", "")[:20]
                    disp   = e.get("display", "")[:30]
                    _box_row(
                        f"  {CYAN}{idx:>3}.{NC}  {kind:<6}  {BOLD}{disp:<30}{NC}"
                        f"  {n_cidr:>5}  {DIM}{added:<10}{NC}  {DIM}{cmt}{NC}"
                    )
            _box_sep()
            cnt_v4, cnt_v6 = _ipset_count()
            _box_row(
                f"  Итого в nft sets: {GREEN}{cnt_v4}{NC} IPv4 + {GREEN}{cnt_v6}{NC} IPv6 CIDR"
            )
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 4. Восстановить ───────────────────────────────────────────────────
        elif ch == "4":
            print()
            _box_top("🔄  ВОССТАНОВЛЕНИЕ ИЗ STATE...")
            ipban_restore()
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── 5. Сохранить nft ruleset ─────────────────────────────────────────
        elif ch == "5":
            print()
            _box_top("💾  СОХРАНЕНИЕ NFT RULESET...")
            _ipban_persist_save()
            _box_bottom()
            input(f"{CYAN}Нажмите Enter...{NC}")

        # ── X. Сбросить всё ───────────────────────────────────────────────────
        elif ch == "x":
            print()
            _box_top(f"{RED}🗑️   СБРОС ВСЕХ БАНОВ{NC}")
            _box_row(f"  {YELLOW}Будут удалены ВСЕ nft-правила и nft sets.{NC}")
            _box_row(f"  {YELLOW}State-файл будет очищен.{NC}")
            _box_bottom()
            try:
                confirm = input(
                    f"{RED}Введите{NC} {BOLD}ДА{NC} для подтверждения: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if confirm in ("ДА", "да", "yes", "YES", "y", "Y"):
                print()
                _box_top("🗑️   ОЧИЩАЮ...")
                ipban_flush()
                _box_bottom()
            else:
                _info("Отменено")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
