"""
chimera/modules/user_ip_whitelist.py
───────────────────────────────────────────────────────────────────────────────
Per-user IP whitelist (allowed_ips) для клиентов Chimera.

Решает проблему: ingress_geoip дропает ВСЕ входящие из РФ на SERVER_PORT (443).
Это защищает от ТСПУ-сенсоров, но блокирует и реальных клиентов с российскими IP.

Решение (мигрировано с iptables/ipset на nftables, этап 1.2):
  • В users.json добавляется поле allowed_ips: ["5.167.98.20", ...]
  • Скрипт собирает ВСЕ allowed_ips ВСЕХ пользователей → nft set clients_wl_v4/v6
  • nft rule inet chimera input tcp dport 443 ip saddr @clients_wl_v4 accept
    comment "chimera-clients-wl" — ставится ПЕРЕД правилом DROP РФ
    (clients_wl имеет приоритет над ingress_block_v4 через insert position=1)
  • TUI (пункт [6] в do_manage_users): админ добавляет/удаляет IP для юзера
  • User Portal: клиент сам управляет своими IP через /api/portal/ips
  • Cron каждые 5 минут пересобирает nft set (atomic swap через
    'nft -f -' с flush+add в одной транзакции — лучше чем ipset swap,
    т.к. между flush и add нет окна видимости снаружи)

АРХИТЕКТУРНЫЕ РЕШЕНИЯ (Q1 + Q2):

Q1 (chicken-egg с User Portal):
  User Portal (rest_api.py, порт 8443 по умолчанию) слушает ОТДЕЛЬНО от
  SERVER_PORT (443). ingress_geoip применяет DROP ТОЛЬКО к SERVER_PORT,
  НЕ к порту портала. Поэтому User Portal доступен с любого IP, даже если
  клиент сменил IP и выпал из whitelist. Вариант (a) — без grace-period,
  без временных окон уязвимости.

  Если User Portal expose=True (bind 0.0.0.0) — порт открывается в UFW.
  ingress_geoip при включении дополнительно проверяет: если портал на 0.0.0.0,
  его порт остаётся открытым в UFW (НЕ подпадает под блокировку).

Q2 (X-Forwarded-For trust):
  rest_api.py по умолчанию слушает напрямую (без nginx). _client_ip() уже
  использует self.client_address[0] — это правильно.

  Новый хелпер _client_ip_for_user() в этом модуле НЕ используется для
  определения IP из запроса (это делает rest_api). Этот модуль работает
  с уже определённым IP, переданным как аргумент.

  rest_api.py при добавлении IP пользователем:
    • Берёт self.client_address[0] напрямую (это и есть IP клиента)
    • НЕ доверяет X-Forwarded-For, т.к. запрос приходит напрямую, не через nginx
    • Если в будущем появится nginx перед rest_api — добавить отдельный хелпер
      с проверкой loopback source

Точка входа из TUI:
    from chimera.modules.user_ip_whitelist import (
        do_manage_user_ip_whitelist,
        add_ip_to_user, remove_ip_from_user, get_user_ips,
        rebuild_clients_ipset, install_cron, remove_cron,
        apply_iptables_rule, remove_iptables_rule,
    )

Точка входа из rest_api.py:
    from chimera.modules.user_ip_whitelist import (
        add_ip_to_user, remove_ip_from_user, get_user_ips,
        rebuild_clients_ipset,
    )

Точка входа из ingress_geoip.py:
    from chimera.modules.user_ip_whitelist import (
        apply_iptables_rule, remove_iptables_rule, rebuild_clients_ipset,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.2 миграции)
from .nft_common import (
    nft_set_create, nft_set_exists, nft_set_atomic_swap,
    nft_set_destroy, nft_set_count,
    nft_rule_add, nft_rule_insert, nft_rule_delete_by_comment,
    nft_persist, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    NFT_SET_CLIENTS_WL_V4, NFT_SET_CLIENTS_WL_V6,
    COMMENT_CLIENTS_WL, NFT_PERSIST_FILE,
)


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ────────────────────────────────────────────────────────────────
# Имена nft sets для per-user whitelist (живут в таблице inet chimera).
# В nftables family=inet поддерживает и v4, и v6 правила в одной таблице,
# но type set-а должен быть конкретным: ipv4_addr или ipv6_addr.
# Поэтому два отдельных set-а для v4 и v6 (как раньше в ipset).
IPSET_V4_NAME = NFT_SET_CLIENTS_WL_V4   # "clients_wl_v4"
IPSET_V6_NAME = NFT_SET_CLIENTS_WL_V6   # "clients_wl_v6"

# Comment-tag для идемпотентности nft-правил и безопасного удаления.
# Один tag используется и для v4, и для v6 правила — это упрощает удаление
# (один вызов nft_rule_delete_by_comment удаляет оба правила).
IPTABLES_COMMENT = COMMENT_CLIENTS_WL       # "chimera-clients-wl"
IPTABLES_COMMENT_V6 = COMMENT_CLIENTS_WL   # тот же tag (раньше был отдельный v6)

# Cron: пересобираем ipset каждые 5 минут (быстрая реакция на добавление IP
# через User Portal без ожидания ручного rebuild).
CRON_INTERVAL_MIN = 5

# Cron-файлы (как в ingress_geoip.py — /etc/cron.d/ + /usr/local/bin/ скрипт).
CRON_FILE = Path("/etc/cron.d/chimera-clients-wl")
CRON_SCRIPT = Path("/usr/local/bin/chimera-clients-wl-rebuild.sh")

# Максимальное количество IP на пользователя. Достаточно для мобильных
# операторов (3-5 подсетей) + домашний + рабочий. Больше = злоупотребление.
MAX_IPS_PER_USER = 20

#  Age-based cleanup — IP старше этого количества дней удаляются
# автоматически (cron, раз в сутки). 0 = cleanup отключен.
DEFAULT_CLEANUP_RETENTION_DAYS = 30

# Cron-файлы для age-based cleanup (запускается раз в сутки в 04:00).
CLEANUP_CRON_FILE = Path("/etc/cron.d/chimera-ip-cleanup")
CLEANUP_CRON_SCRIPT = Path("/usr/local/bin/chimera-ip-cleanup.sh")


# ── Валидация IP/CIDR ────────────────────────────────────────────────────────

def _validate_ip_or_cidr(value: str) -> "tuple[bool, str, Optional[str]]":
    """Валидирует IP-адрес или CIDR.

    Возвращает (is_valid, normalized_value, error_message).
    normalized_value — каноническая форма (без leading zeros, без /32 для IPv4).
    error_message — пустая строка если валиден, описание ошибки если нет.

    Запрещает:
      • Локальные/зарезервированные адреса (127.x, 10.x, 192.168.x, 169.254.x, ::1, fc00::/7, ...)
      • Multicast (224.0.0.0/4, ff00::/8)
      • Loopback
      • Link-local

    Разрешает:
      • Глобальные IPv4 (1.0.0.0/8 — 223.0.0.0/8, исключая 127/10/172.16/192.168/169.254)
      • Глобальные IPv6 (2000::/3)
    """
    if not value or not isinstance(value, str):
        return False, "", "Пустое значение"

    value = value.strip()
    if not value:
        return False, "", "Пустое значение"

    try:
        # ipaddress.ip_address / ip_network принимают оба формата.
        # Если есть '/' — это CIDR, иначе — одиночный IP.
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            normalized = str(net)
            addr = net.network_address
        else:
            addr = ipaddress.ip_address(value)
            normalized = str(addr)

        # Проверяем, что это глобальный адрес.
        if addr.is_loopback:
            return False, "", f"Loopback адрес запрещён: {value}"
        if addr.is_private:
            return False, "", f"Приватный адрес запрещён: {value} (нужен публичный IP клиента)"
        if addr.is_link_local:
            return False, "", f"Link-local адрес запрещён: {value}"
        if addr.is_multicast:
            return False, "", f"Multicast адрес запрещён: {value}"
        if addr.is_reserved:
            return False, "", f"Зарезервированный адрес запрещён: {value}"
        if addr.is_unspecified:
            return False, "", f"Unspecified адрес (0.0.0.0/::) запрещён: {value}"

        # Дополнительная проверка для IPv6: только глобальные (2000::/3),
        # не ULA (fc00::/7), не site-local (fec0::/10, deprecated).
        if addr.version == 6:
            if not addr.is_global:
                return False, "", f"Не глобальный IPv6: {value}"

        return True, normalized, ""
    except ValueError as e:
        return False, "", f"Невалидный IP/CIDR: {value} ({e})"


def _is_ipv6(value: str) -> bool:
    """True если value содержит IPv6-адрес/CIDR (двоеточие в адресе)."""
    # CIDR "::/0" или "2001:db8::/32" — двоеточие есть.
    # IPv4 "1.2.3.4" или "1.2.3.0/24" — двоеточия нет.
    # Нормализованные значения от _validate_ip_or_cidr — каноническая форма.
    return ":" in value


# ── Работа с users.json ──────────────────────────────────────────────────────

def _users_load() -> list[dict]:
    """Делегирует в users_manager._users_load (lazy import)."""
    from chimera.modules.users_manager import _users_load as _load
    return _load()


def _users_save(users: list[dict]) -> None:
    """Делегирует в users_manager._users_save."""
    from chimera.modules.users_manager import _users_save as _save
    _save(users)


def _find_user_by_email(users: list[dict], email: str) -> "Optional[dict]":
    """Ищет пользователя по email (case-sensitive, как везде в Chimera)."""
    for u in users:
        if u.get("email") == email:
            return u
    return None


def _find_user_by_uuid(users: list[dict], uuid_val: str) -> "Optional[dict]":
    """Ищет пользователя по UUID."""
    for u in users:
        if u.get("uuid") == uuid_val:
            return u
    return None


def _normalize_user_ips(user: dict) -> list[str]:
    """Возвращает список IP-строк из allowed_ips пользователя.

     поддерживает оба формата:
      - Старый: ["5.167.98.20", ...] (просто строки)
      - Новый: [{"ip": "5.167.98.20", "added_at": "...", "pinned": false}, ...]
    Возвращает всегда list[str] (только IP-строки) для backward compat
    с _collect_all_user_ips и старым кодом.
    """
    ips = user.get("allowed_ips", [])
    if not isinstance(ips, list):
        return []
    result: list[str] = []
    for entry in ips:
        if isinstance(entry, str):
            if entry:
                result.append(entry)
        elif isinstance(entry, dict):
            ip_str = entry.get("ip", "")
            if ip_str:
                result.append(str(ip_str))
    return result


def _normalize_user_ips_detailed(user: dict) -> list[dict]:
    """Возвращает список объектов allowed_ips с метаданными.

     каждый элемент — {"ip": str, "added_at": str, "pinned": bool}.
    Для старого формата (строки) — конвертирует in-memory с added_at="" и pinned=False.
    Не пишет на диск (миграция происходит при следующем save).
    """
    ips = user.get("allowed_ips", [])
    if not isinstance(ips, list):
        return []
    result: list[dict] = []
    for entry in ips:
        if isinstance(entry, str):
            if entry:
                result.append({"ip": entry, "added_at": "", "pinned": False})
        elif isinstance(entry, dict):
            ip_str = entry.get("ip", "")
            if ip_str:
                result.append({
                    "ip": str(ip_str),
                    "added_at": entry.get("added_at", ""),
                    "pinned": bool(entry.get("pinned", False)),
                })
    return result


def _migrate_ips_to_detailed(user: dict) -> list[dict]:
    """Конвертирует allowed_ips в detailed формат (in-memory).
    Возвращает список объектов. Если уже detailed — возвращает как есть.
    """
    detailed = _normalize_user_ips_detailed(user)
    # Если есть entries без added_at — заполняем now (миграция).
    now_iso = datetime.now(timezone.utc).isoformat()
    for entry in detailed:
        if not entry.get("added_at"):
            entry["added_at"] = now_iso
    return detailed


# ── API: add / remove / get ──────────────────────────────────────────────────

def add_ip_to_user(email: str, ip: str, pinned: bool = False) -> "tuple[bool, str]":
    """Добавляет IP/CIDR в allowed_ips пользователя.

    Возвращает (success, message).
    Атомарно: читает users → модифицирует → сохраняет → rebuild ipset.

     
      - Хранит в detailed формате: {"ip", "added_at", "pinned"}
      - FIFO: если лимит достигнут, удаляет самый старый незакреплённый IP
      - Migration: при добавлении конвертирует старый формат (строки) в detailed
    """
    # Валидация IP.
    ok, normalized, err = _validate_ip_or_cidr(ip)
    if not ok:
        return False, err

    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return False, f"Пользователь не найден: {email}"

    # Мигрируем в detailed формат (если старый — строки).
    detailed = _migrate_ips_to_detailed(user)

    # Дедупликация — не добавляем если уже есть.
    existing_ips = [e["ip"] for e in detailed]
    if normalized in existing_ips:
        # IP уже есть — если pinned=True, обновляем pinned статус.
        if pinned:
            for e in detailed:
                if e["ip"] == normalized:
                    e["pinned"] = True
                    break
            user["allowed_ips"] = detailed
            _users_save(users)
            rebuild_clients_ipset()
            return True, f"IP {normalized} уже в whitelist (закреплён)"
        return True, f"IP {normalized} уже в whitelist"

    # FIFO: если лимит достигнут — удаляем самый старый незакреплённый.
    if len(detailed) >= MAX_IPS_PER_USER:
        # Ищем незакреплённые, сортируем по added_at (пустая = самая старая).
        unpinned = [e for e in detailed if not e.get("pinned", False)]
        if not unpinned:
            return False, (f"Превышен лимит IP ({MAX_IPS_PER_USER}), "
                           "все закреплены — удалите вручную")
        # Сортируем по added_at (пустая строка = старая, идёт первой).
        unpinned.sort(key=lambda e: e.get("added_at", ""))
        oldest = unpinned[0]
        detailed.remove(oldest)

    # Добавляем новый IP.
    detailed.append({
        "ip": normalized,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "pinned": pinned,
    })
    user["allowed_ips"] = detailed
    _users_save(users)

    # Пересобираем ipset.
    rebuild_clients_ipset()

    return True, f"IP {normalized} добавлен в whitelist пользователя {email}"


def remove_ip_from_user(email: str, ip: str) -> "tuple[bool, str]":
    """Удаляет IP/CIDR из allowed_ips пользователя.

    Возвращает (success, message).
    Принимает как нормализованную форму (из get_user_ips), так и произвольную
    (пробуем валидировать и нормализовать перед поиском).

     работает с detailed форматом, но принимает IP-строку.
    """
    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return False, f"Пользователь не найден: {email}"

    # Мигрируем в detailed формат.
    detailed = _migrate_ips_to_detailed(user)
    existing_ips = [e["ip"] for e in detailed]

    # Пробуем найти как есть.
    target = ip.strip()
    if target not in existing_ips:
        # Пробуем нормализовать.
        ok, normalized, _ = _validate_ip_or_cidr(ip)
        if ok and normalized in existing_ips:
            target = normalized
        else:
            return False, f"IP {ip} не найден в whitelist пользователя"

    # Удаляем объект с этим IP.
    detailed = [e for e in detailed if e["ip"] != target]
    user["allowed_ips"] = detailed
    _users_save(users)

    rebuild_clients_ipset()

    return True, f"IP {target} удалён из whitelist пользователя {email}"


def get_user_ips(email: str) -> list[str]:
    """Возвращает список allowed_ips пользователя (IP-строки).
    Пустой список если пользователь не найден или нет IP.
    Backward compat — возвращает list[str].
    """
    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return []
    return _normalize_user_ips(user)


def get_user_ips_detailed(email: str) -> list[dict]:
    """Возвращает список allowed_ips с метаданными.

     каждый элемент — {"ip": str, "added_at": str, "pinned": bool}.
    """
    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return []
    return _normalize_user_ips_detailed(user)


def pin_ip_to_user(email: str, ip: str) -> "tuple[bool, str]":
    """Закрепляет IP (не удаляется при age-based cleanup)."""
    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return False, f"Пользователь не найден: {email}"

    detailed = _migrate_ips_to_detailed(user)
    found = False
    for e in detailed:
        if e["ip"] == ip:
            e["pinned"] = True
            found = True
            break
    if not found:
        return False, f"IP {ip} не найден в whitelist пользователя"
    user["allowed_ips"] = detailed
    _users_save(users)
    return True, f"IP {ip} закреплён"


def unpin_ip_from_user(email: str, ip: str) -> "tuple[bool, str]":
    """Открепляет IP (может быть удалён при age-based cleanup)."""
    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return False, f"Пользователь не найден: {email}"

    detailed = _migrate_ips_to_detailed(user)
    found = False
    for e in detailed:
        if e["ip"] == ip:
            e["pinned"] = False
            found = True
            break
    if not found:
        return False, f"IP {ip} не найден в whitelist пользователя"
    user["allowed_ips"] = detailed
    _users_save(users)
    return True, f"IP {ip} откреплён"


def replace_all_ips(email: str, new_ip: str, keep_pinned: bool = True) -> "tuple[bool, str]":
    """Заменяет все IP на один новый. Опционально сохраняет закреплённые.

     для сценария «у меня сменился IP, хочу только новый».
    Если keep_pinned=True — закреплённые IP не удаляются.
    """
    # Валидация нового IP.
    ok, normalized, err = _validate_ip_or_cidr(new_ip)
    if not ok:
        return False, err

    users = _users_load()
    user = _find_user_by_email(users, email)
    if user is None:
        return False, f"Пользователь не найден: {email}"

    detailed = _migrate_ips_to_detailed(user)

    # Оставляем только закреплённые (если keep_pinned).
    if keep_pinned:
        pinned = [e for e in detailed if e.get("pinned", False)]
    else:
        pinned = []

    # Добавляем новый IP.
    new_entry = {
        "ip": normalized,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "pinned": False,
    }

    # Проверяем, нет ли уже этого IP в pinned.
    pinned_ips = [e["ip"] for e in pinned]
    if normalized in pinned_ips:
        # IP уже в pinned — не дублируем.
        user["allowed_ips"] = pinned
        _users_save(users)
        rebuild_clients_ipset()
        return True, f"Все IP заменены на {normalized} (закреплённые сохранены)"

    result = pinned + [new_entry]
    # Проверяем лимит.
    if len(result) > MAX_IPS_PER_USER:
        return False, (f"Превышен лимит IP ({MAX_IPS_PER_USER}) — "
                       "слишком много закреплённых")

    user["allowed_ips"] = result
    _users_save(users)
    rebuild_clients_ipset()

    if keep_pinned and pinned:
        return True, f"Все IP заменены на {normalized} ({len(pinned)} закреплённых сохранено)"
    return True, f"Все IP заменены на {normalized}"


# ── nftables management (замена ipset/iptables, этап 1.2) ─────────────────────

def _run(cmd: list, check: bool = False, quiet: bool = True) -> subprocess.CompletedProcess:
    """Тонкая обёртка над subprocess.run — сохранена для обратной совместимости
    с тестами и со старыми вызовами в этом файле (например, для UFW).

    ВНИМАНИЕ: ВАЖНЫЕ операции с firewall должны идти через nft_common.*,
    не через этот _run. Здесь _run оставлен только для не-firewall команд
    (например, проверка which, системные вызовы).
    """
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _ipset_available() -> bool:
    """Алиас — теперь проверяет наличие `nft` binary (а не ipset)."""
    return _nft_available()


def _iptables_available() -> bool:
    """Алиас — теперь проверяет наличие `nft` binary (а не iptables).

    В nftables нет отдельного iptables — все firewall-операции идут через
    единый `nft` binary. Поэтому для работы apply_iptables_rule/remove_iptables_rule
    достаточно наличия nft.
    """
    return _nft_available()


def _collect_all_user_ips() -> "tuple[list[str], list[str]]":
    """Собирает allowed_ips из ВСЕХ пользователей.
    Возвращает (v4_list, v6_list) — списки уникальных CIDR/IP.
    """
    users = _users_load()
    v4_set: set[str] = set()
    v6_set: set[str] = set()
    for u in users:
        for ip in _normalize_user_ips(u):
            ok, normalized, _ = _validate_ip_or_cidr(ip)
            if not ok:
                continue
            if _is_ipv6(normalized):
                v6_set.add(normalized)
            else:
                v4_set.add(normalized)
    return sorted(v4_set), sorted(v6_set)


def _ipset_create_empty(name: str, family: str = "inet") -> bool:
    """Создаёт пустой nft set (если не существует).

    Заменяет: ipset create <name> hash:net family <inet|inet6> maxelem 100000 -exist
    Теперь:   nft add set inet chimera <name> { type ipv4_addr|ipv6_addr;
              flags interval; size 100000; }
    """
    if not _nft_available():
        return False
    set_type = "ipv6_addr" if family == "inet6" else "ipv4_addr"
    return nft_set_create(name, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY,
                          set_type=set_type, flags=["interval"],
                          maxelem=100000)


def _ipset_swap_and_destroy(tmp_name: str, real_name: str) -> bool:
    """DEPRECATED после миграции на nftables (этап 1.2).

    Раньше: ipset swap <tmp> <real> + ipset destroy <tmp> (atomic swap).
    Теперь: nft_set_atomic_swap(real, new_elements) делает flush+add в одной
    транзакции через `nft -f -` (here-doc). Это даже лучше — между flush и
    add нет окна видимости снаружи.

    Функция сохранена для обратной совместимости с тестами, но теперь НЕ
    должна вызываться из нового кода. Если её вызывают — это noop (real_name
    уже должен содержать правильные данные через nft_set_atomic_swap).
    """
    nft_set_destroy(tmp_name, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    return True


def rebuild_clients_ipset() -> bool:
    """Пересобирает nft sets clients_wl_v4 и clients_wl_v6 из users.json.

    Использует atomic swap (одна nft-транзакция с flush + add) — без
    перерыва в фильтрации. Старые IP продолжают работать до момента flush,
    новые — сразу после add. Между flush и add нет окна видимости снаружи
    (транзакция атомарна в ядре nftables).

    Заменяет: ipset create tmp + ipset restore -! -f <file> + ipset swap
              tmp real + ipset destroy tmp (4 операции + tmp-file на диске)
    Теперь:   nft -f - <<EOF  (одна операция, без tmp-file)
              flush set inet chimera clients_wl_v4
              add element inet chimera clients_wl_v4 { 1.2.3.4, 5.6.7.0/24, ... }
              EOF
    """
    if not _nft_available():
        return False

    v4, v6 = _collect_all_user_ips()

    # Создаём set-ы если их ещё нет (пустые — чтобы atomic swap не упал
    # на "set does not exist").
    _ipset_create_empty(IPSET_V4_NAME, "inet")
    _ipset_create_empty(IPSET_V6_NAME, "inet6")

    # Atomic swap: flush + add в одной nft-транзакции.
    # Если v4/v6 пустой — просто flush (set остаётся пустым, что валидно).
    if not nft_set_atomic_swap(IPSET_V4_NAME, v4,
                                table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY):
        return False
    if not nft_set_atomic_swap(IPSET_V6_NAME, v6,
                                table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY):
        return False

    # Persist для boot-restore — единый nft ruleset.
    try:
        nft_persist(NFT_PERSIST_FILE)
    except Exception:
        pass  # не критично — cron пересоберёт при следующем запуске

    return True


# ── nft rules (заменa iptables rules, этап 1.2) ──────────────────────────────

def apply_iptables_rule(port: int) -> bool:
    """Добавляет ACCEPT-правило для clients_wl перед DROP-правилом ingress_geoip.

    Заменяет:
      iptables  -I INPUT 1 -p tcp --dport <port> -m set --match-set
                  clients_wl_v4 src -j ACCEPT -m comment --comment chimera-clients-wl
      ip6tables -I INPUT 1 -p tcp --dport <port> -m set --match-set
                  clients_wl_v6 src -j ACCEPT -m comment --comment chimera-clients-wl-v6

    Теперь два правила в одной таблице inet chimera (v4 + v6 одновременно),
    оба с одинаковым comment "chimera-clients-wl" для упрощённого удаления:
      nft insert rule inet chimera input tcp dport <port> ip  saddr @clients_wl_v4 \\
          accept comment "chimera-clients-wl"
      nft insert rule inet chimera input tcp dport <port> ip6 saddr @clients_wl_v6 \\
          accept comment "chimera-clients-wl"

    Правила вставляются в начало (insert position=1) — ПЕРЕД всем остальным,
    включая DROP для ingress_block_v4. Это КРИТИЧНО: если поставить через add
    (в конец), то DROP сработает раньше.

    Идемпотентность: nft_rule_insert с comment проверяет существование правила
    с этим comment перед добавлением (через nft -j list chain).

    Вызывается из ingress_geoip._ingress_enable() автоматически.
    """
    if not _nft_available():
        return False

    # Убедимся, что set существует (если users пустые — будет пустой set,
    # правило всё равно нужно ставить — оно просто ничего не пропустит).
    rebuild_clients_ipset()

    # IPv4: insert accept rule for v4 source set
    nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"tcp dport {port} ip saddr @{IPSET_V4_NAME} accept",
        family=NFT_TABLE_FAMILY, comment=IPTABLES_COMMENT, idempotent=True
    )
    # IPv6: insert accept rule for v6 source set (тот же comment для упрощённого удаления)
    nft_rule_insert(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        rule_spec=f"tcp dport {port} ip6 saddr @{IPSET_V6_NAME} accept",
        family=NFT_TABLE_FAMILY, comment=IPTABLES_COMMENT, idempotent=True
    )

    return True


def remove_iptables_rule(port: int) -> None:
    """Удаляет ACCEPT-правила для clients_wl (обa: v4 и v6).

    Заменяет: цикл iptables -D INPUT ... / ip6tables -D INPUT ...
    Теперь: один вызов nft_rule_delete_by_comment — находит все правила с
    comment="chimera-clients-wl" и удаляет через handle (nft -a list chain
    → handles → delete rule ... handle N).

    НЕ удаляет сами nft sets и НЕ трогает users.json — данные сохраняются,
    чтобы при повторном включении ingress_geoip правила восстановились.
    """
    if not _nft_available():
        return

    nft_rule_delete_by_comment(
        table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
        comment=IPTABLES_COMMENT, family=NFT_TABLE_FAMILY, max_iterations=20
    )


def destroy_ipset() -> None:
    """Полностью удаляет nft sets clients_wl_*. Данные в users.json сохраняются.
    Вызывается ТОЛЬКО при полном удалении user_ip_whitelist (через TUI пункт).

    Заменяет: ipset destroy clients_wl_v4 / clients_wl_v6
    Теперь:   nft delete set inet chimera clients_wl_v4 / clients_wl_v6
    """
    if not _nft_available():
        return
    nft_set_destroy(IPSET_V4_NAME, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)
    nft_set_destroy(IPSET_V6_NAME, table=NFT_TABLE_NAME, family=NFT_TABLE_FAMILY)


# ── Cron ─────────────────────────────────────────────────────────────────────

def install_cron() -> bool:
    """Устанавливает cron для пересборки nft set каждые 5 минут.
    Cron-скрипт вызывает rebuild_clients_ipset() — если IP не изменились,
    atomic swap не делает ничего (быстро).
    """
    try:
        core = _core_module()
    except Exception:
        return False

    # Cron-скрипт — простой bash-wrapper, вызывающий Python.
    # Использует тот же Python, что и Chimera (sys.executable).
    python_bin = sys.executable or "/usr/bin/python3"
    CRON_SCRIPT.write_text(
        f"#!/bin/bash\n"
        f"# Авто-пересборка nft set clients_wl_v4/v6 из users.json.\n"
        f"# Вызывается cron каждые {CRON_INTERVAL_MIN} минут.\n"
        f"{python_bin} -c '"
        f"from chimera.modules.user_ip_whitelist import rebuild_clients_ipset; "
        f"rebuild_clients_ipset()' >/dev/null 2>&1\n"
    )
    CRON_SCRIPT.chmod(0o755)

    CRON_FILE.write_text(
        f"# Chimera — per-user IP whitelist nft set rebuild\n"
        f"SHELL=/bin/bash\n"
        f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"*/{CRON_INTERVAL_MIN} * * * * root {CRON_SCRIPT}\n"
    )
    CRON_FILE.chmod(0o644)
    return True


def remove_cron() -> None:
    """Удаляет cron и cron-скрипт. Не трогает nft sets/rules/users.json."""
    CRON_FILE.unlink(missing_ok=True)
    CRON_SCRIPT.unlink(missing_ok=True)


# ── Age-based cleanup  ──────────────────────────────────────────────

def _get_cleanup_retention_days() -> int:
    """Возвращает retention period из state.json (или default)."""
    try:
        core = _core_module()
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
            return int(state.get("ip_cleanup_retention_days",
                                 DEFAULT_CLEANUP_RETENTION_DAYS))
    except Exception:
        pass
    return DEFAULT_CLEANUP_RETENTION_DAYS


def _set_cleanup_retention_days(days: int) -> None:
    """Сохраняет retention period в state.json."""
    try:
        core = _core_module()
        state = {}
        if core.STATE_FILE.exists():
            state = json.loads(core.STATE_FILE.read_text())
        state["ip_cleanup_retention_days"] = days
        core.STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception:
        pass


def _is_cleanup_enabled() -> bool:
    """Возвращает True если age-based cleanup включен (retention > 0)."""
    return _get_cleanup_retention_days() > 0


def cleanup_old_ips(retention_days: "Optional[int]" = None) -> "tuple[int, int]":
    """Удаляет незакреплённые IP старше retention_days.

     age-based cleanup для предотвращения накопления старых IP.
    Закреплённые (pinned=True) IP НЕ удаляются.

    Args:
      retention_days: если None — берётся из state.json (или default 30).

    Returns:
      (deleted_count, total_ips_before) — количество удалённых IP и
      общее количество до очистки.
    """
    if retention_days is None:
        retention_days = _get_cleanup_retention_days()
    if retention_days <= 0:
        return 0, 0  # cleanup отключен

    now = datetime.now(timezone.utc)
    cutoff = now - _td(days=retention_days)

    users = _users_load()
    total_before = 0
    deleted_total = 0
    changed = False

    for user in users:
        detailed = _migrate_ips_to_detailed(user)
        total_before += len(detailed)

        new_detailed = []
        for entry in detailed:
            # Закреплённые — не удаляем.
            if entry.get("pinned", False):
                new_detailed.append(entry)
                continue

            # Проверяем возраст.
            added_at = entry.get("added_at", "")
            if not added_at:
                # Старый формат без timestamp — считаем старым, удаляем.
                # (миграция заполняет added_at=now, но если файл был
                # отредактирован вручную — может быть пусто)
                # Не удаляем — лучше оставить, чем удалить нужный IP.
                new_detailed.append(entry)
                continue

            try:
                added_dt = datetime.fromisoformat(added_at)
                if added_dt.tzinfo is None:
                    added_dt = added_dt.replace(tzinfo=timezone.utc)
                if added_dt < cutoff:
                    # IP старше retention — удаляем.
                    deleted_total += 1
                    changed = True
                    continue
            except Exception:
                # Невалидный timestamp — не удаляем (безопасный fallback).
                pass

            new_detailed.append(entry)

        if len(new_detailed) != len(detailed):
            user["allowed_ips"] = new_detailed

    if changed:
        _users_save(users)
        rebuild_clients_ipset()

    return deleted_total, total_before


def _td(days: int):
    """timedelta helper (избегаем import timedelta вверху)."""
    from datetime import timedelta
    return timedelta(days=days)


def install_cleanup_cron() -> bool:
    """Устанавливает cron для age-based cleanup (раз в сутки в 04:00)."""
    try:
        core = _core_module()
    except Exception:
        return False

    python_bin = sys.executable or "/usr/bin/python3"
    CLEANUP_CRON_SCRIPT.write_text(
        f"#!/bin/bash\n"
        f"# Chimera — age-based cleanup для IP whitelist.\n"
        f"# Запускается cron раз в сутки в 04:00.\n"
        f"# Удаляет незакреплённые IP старше retention_days.\n"
        f"{python_bin} -c '"
        f"from chimera.modules.user_ip_whitelist import cleanup_old_ips; "
        f"cleanup_old_ips()' >/dev/null 2>&1\n"
    )
    CLEANUP_CRON_SCRIPT.chmod(0o755)

    CLEANUP_CRON_FILE.write_text(
        f"# Chimera — IP whitelist age-based cleanup\n"
        f"SHELL=/bin/bash\n"
        f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"0 4 * * * root {CLEANUP_CRON_SCRIPT}\n"
    )
    CLEANUP_CRON_FILE.chmod(0o644)
    return True


def remove_cleanup_cron() -> None:
    """Удаляет cleanup cron и cron-скрипт."""
    CLEANUP_CRON_FILE.unlink(missing_ok=True)
    CLEANUP_CRON_SCRIPT.unlink(missing_ok=True)


# ── TUI ──────────────────────────────────────────────────────────────────────

def do_manage_user_ip_whitelist() -> None:
    """TUI-меню управления per-user IP whitelist.

    Показывает список пользователей → выбор → список IP → add/remove.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    _box_back   = core._box_back
    CYAN   = core.CYAN
    NC     = core.NC
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    BLUE   = core.BLUE
    info    = core.info
    warn    = core.warn
    success = core.success

    while True:
        users = _users_load()
        os_system_clear = core.__dict__.get("_clear_screen", lambda: None)

        # Header
        print()
        _box_top("📋  Per-user IP whitelist")
        _box_row()
        if not users:
            _box_row(f"  {YELLOW}Пользователей нет.{NC}")
        else:
            _box_row(f"  {'#':<4} {'Имя':<20} {'Email':<30} {'IP':<6}")
            _box_row(f"  {'-'*4} {'-'*20} {'-'*30} {'-'*6}")
            for i, u in enumerate(users, 1):
                name = u.get("name", "—")[:20]
                email = u.get("email", "—")[:30]
                ip_count = len(_normalize_user_ips(u))
                ip_str = f"{GREEN}{ip_count}{NC}" if ip_count else f"{DIM}0{NC}"
                _box_row(f"  {i:<4} {name:<20} {email:<30} {ip_str}")
        _box_sep()

        # Status
        ipset_ok = _ipset_available()
        iptables_ok = _iptables_available()
        _box_row(f"  nft:       {GREEN+'доступен'+NC if ipset_ok else YELLOW+'НЕТ (apt install nftables)'+NC}")
        _box_row(f"  rules:    {GREEN+'доступны'+NC if iptables_ok else YELLOW+'НЕТ'+NC}")

        # Cron status
        cron_ok = CRON_FILE.exists()
        _box_row(f"  cron:     {GREEN+'активен'+NC if cron_ok else DIM+'не установлен'+NC}")
        _box_sep()

        _box_item("1", "Управление IP пользователя (выбрать)")
        if cron_ok:
            _box_item("2", f"{YELLOW}Отключить автообновление (cron){NC}")
        else:
            _box_item("2", f"{GREEN}Включить автообновление (cron, каждые {CRON_INTERVAL_MIN} мин){NC}")
        _box_item("3", "Перестроить nft set сейчас (rebuild)")
        _box_item("4", f"{RED}Очистить все IP всех пользователей{NC}")
        _box_row()
        _box_row(f"  {DIM}Для доступа клиентов с РФ-IP к VLESS на сервере с ingress_geoip.{NC}")
        _box_row(f"  {DIM}Без этого правила клиенты с РФ-IP будут DROP'нуты на 443.{NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "q" or ch == "":
            return

        if ch == "1":
            _tui_manage_single_user(core, users)
        elif ch == "2":
            if cron_ok:
                remove_cron()
                success("Cron отключён.")
            else:
                if install_cron():
                    success(f"Cron включён — nft set пересобирается каждые {CRON_INTERVAL_MIN} мин.")
                else:
                    warn("Не удалось установить cron.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            info("Пересобираю nft set...")
            if rebuild_clients_ipset():
                v4, v6 = _collect_all_user_ips()
                success(f"nft set пересобран: {len(v4)} IPv4, {len(v6)} IPv6 записей.")
            else:
                warn("Не удалось пересобрать nft set — проверьте наличие nft binary.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            _tui_clear_all_ips(core, users)


def _tui_manage_single_user(core, users: list[dict]) -> None:
    """Подменю управления IP конкретного пользователя."""
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    CYAN   = core.CYAN
    NC     = core.NC
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    BLUE   = core.BLUE
    info    = core.info
    warn    = core.warn
    success = core.success

    if not users:
        _box_warn("  Пользователей нет.")
        input(f"\n{BLUE}Нажмите Enter...{NC}")
        return

    print()
    _box_top("Выберите пользователя")
    _box_row()
    for i, u in enumerate(users, 1):
        name = u.get("name", "—")
        email = u.get("email", "—")
        ip_count = len(_normalize_user_ips(u))
        _box_row(f"  {GREEN}[{i}]{NC} {name} ({email}) — {ip_count} IP")
    _box_row()
    _box_item("Q", "Назад")
    _box_bottom()

    try:
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return

    if ch == "q" or ch == "":
        return

    try:
        idx = int(ch) - 1
        if not (0 <= idx < len(users)):
            return
    except ValueError:
        return

    user = users[idx]
    email = user.get("email", "")
    name = user.get("name", "")

    # Подменю IP для выбранного пользователя.
    while True:
        # Перечитываем users (могли измениться).
        users = _users_load()
        user = _find_user_by_email(users, email)
        if user is None:
            warn("Пользователь исчез из users.json")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            return
        ips = _normalize_user_ips(user)

        print()
        _box_top(f"IP whitelist: {name}")
        _box_row(f"  {DIM}Email: {email}{NC}")
        _box_row()
        if not ips:
            _box_row(f"  {YELLOW}IP-адресов нет.{NC}")
            _box_row(f"  {DIM}Клиент не сможет подключиться к VLESS если включена{NC}")
            _box_row(f"  {DIM}блокировка входящих из РФ (ingress_geoip).{NC}")
        else:
            _box_row(f"  Текущие IP ({len(ips)}/{MAX_IPS_PER_USER}):")
            for i, ip in enumerate(ips, 1):
                _box_row(f"    {GREEN}[{i}]{NC} {ip}")
        _box_sep()
        _box_item("1", f"{GREEN}Добавить IP/CIDR{NC}")
        if ips:
            _box_item("2", f"{RED}Удалить IP/CIDR{NC}")
        _box_item("3", "Показать текущий IP клиента (curl ifconfig.me)")
        _box_row()
        _box_item("Q", "Назад")
        _box_bottom()

        try:
            ch2 = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch2 == "q" or ch2 == "":
            return

        if ch2 == "1":
            print()
            print(f"{DIM}  Формат: IP (5.167.98.20) или CIDR (5.167.98.0/24).{NC}")
            print(f"{DIM}  Допускается IPv6 (2a03:1ac0:5a7:6214::/64).{NC}")
            print(f"{DIM}  Подсказка: пусть клиент откроет https://2ip.ru с устройства.{NC}")
            try:
                new_ip = input(f"{CYAN}  IP/CIDR:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not new_ip:
                continue
            ok, msg = add_ip_to_user(email, new_ip)
            if ok:
                success(f"  {msg}")
            else:
                warn(f"  {msg}")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch2 == "2" and ips:
            print()
            try:
                del_input = input(f"{CYAN}  Номер IP или сам IP для удаления:{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not del_input:
                continue
            # Если введено число — это номер.
            target_ip = None
            try:
                num = int(del_input)
                if 1 <= num <= len(ips):
                    target_ip = ips[num - 1]
                else:
                    warn(f"  Номер вне диапазона 1..{len(ips)}")
                    input(f"\n{BLUE}  Нажмите Enter...{NC}")
                    continue
            except ValueError:
                target_ip = del_input
            ok, msg = remove_ip_from_user(email, target_ip)
            if ok:
                success(f"  {msg}")
            else:
                warn(f"  {msg}")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch2 == "3":
            # Информация для админа — серверный curl (это IP сервера, не клиента).
            # Реальный IP клиента нужно спросить у него.
            print()
            _box_info("  Чтобы узнать IP клиента:")
            _box_info(f"  {DIM}1. Пусть клиент откроет https://2ip.ru с устройства{NC}")
            _box_info(f"  {DIM}2. Или пусть выполнит с устройства: curl ifconfig.me{NC}")
            _box_info(f"  {DIM}3. Или пусть зайдёт в User Portal (порт 8443) —{NC}")
            _box_info(f"  {DIM}   портал покажет его IP и предложит добавить.{NC}")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")


def _tui_clear_all_ips(core, users: list[dict]) -> None:
    """Очистка всех allowed_ips у всех пользователей."""
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    YELLOW = core.YELLOW
    RED    = core.RED
    NC     = core.NC
    BLUE   = core.BLUE

    total_ips = sum(len(_normalize_user_ips(u)) for u in users)
    if total_ips == 0:
        _box_warn("  Нет IP для очистки.")
        input(f"\n{BLUE}  Нажмите Enter...{NC}")
        return

    print()
    _box_top(f"{RED}Очистка всех IP{NC}")
    _box_row()
    _box_row(f"  {YELLOW}Будут удалены все IP всех пользователей ({total_ips} шт.).{NC}")
    _box_row(f"  {RED}Это действие необратимо!{NC}")
    _box_row(f"  {DIM}users.json останется, поле allowed_ips обнулится.{NC}")
    _box_bottom()

    try:
        confirm = input(f"{BLUE}  Введите DELETE для подтверждения:{NC} ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if confirm != "DELETE":
        print("  Отменено.")
        input(f"\n{BLUE}  Нажмите Enter...{NC}")
        return

    # Очищаем.
    for u in users:
        u["allowed_ips"] = []
    _users_save(users)
    rebuild_clients_ipset()
    print(f"  {GREEN if hasattr(core, 'GREEN') else ''}Очищено.{NC}")
    input(f"\n{BLUE}  Нажмите Enter...{NC}")
