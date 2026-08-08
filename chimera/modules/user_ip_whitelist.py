"""
chimera/modules/user_ip_whitelist.py
───────────────────────────────────────────────────────────────────────────────
Per-user IP whitelist (allowed_ips) для клиентов Chimera.

Решает проблему: ingress_geoip дропает ВСЕ входящие из РФ на SERVER_PORT (443).
Это защищает от ТСПУ-сенсоров, но блокирует и реальных клиентов с российскими IP.

Решение:
  • В users.json добавляется поле allowed_ips: ["5.167.98.20", ...]
  • Скрипт собирает ВСЕ allowed_ips ВСЕХ пользователей → ipset clients_wl
  • iptables: ACCEPT -m set --match-set clients_wl src -p tcp --dport 443
    ставится ПЕРЕД правилом DROP РФ (clients_wl имеет приоритет над xray_ru_block)
  • TUI (пункт [6] в do_manage_users): админ добавляет/удаляет IP для юзера
  • User Portal: клиент сам управляет своими IP через /api/portal/ips
  • Cron каждые 5 минут пересобирает ipset (atomic swap через ipset swap)

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


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ────────────────────────────────────────────────────────────────
# ipset-сеты для per-user whitelist. Раздельно IPv4 и IPv6 — у ipset
# hash:ip/hash:net должен быть фиксированный family (inet или inet6).
IPSET_V4_NAME = "clients_wl_v4"
IPSET_V6_NAME = "clients_wl_v6"

# Комментарий в iptables для поиска правила при remove.
IPTABLES_COMMENT = "chimera-clients-wl"
IPTABLES_COMMENT_V6 = "chimera-clients-wl-v6"

# Cron: пересобираем ipset каждые 5 минут (быстрая реакция на добавление IP
# через User Portal без ожидания ручного rebuild).
CRON_INTERVAL_MIN = 5

# Cron-файлы (как в ingress_geoip.py — /etc/cron.d/ + /usr/local/bin/ скрипт).
CRON_FILE = Path("/etc/cron.d/chimera-clients-wl")
CRON_SCRIPT = Path("/usr/local/bin/chimera-clients-wl-rebuild.sh")

# Максимальное количество IP на пользователя. Достаточно для мобильных
# операторов (3-5 подсетей) + домашний + рабочий. Больше = злоупотребление.
MAX_IPS_PER_USER = 20

# v5.0.20: Age-based cleanup — IP старше этого количества дней удаляются
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

    v5.0.20: поддерживает оба формата:
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

    v5.0.20: каждый элемент — {"ip": str, "added_at": str, "pinned": bool}.
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

    v5.0.20:
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

    v5.0.20: работает с detailed форматом, но принимает IP-строку.
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

    v5.0.20: каждый элемент — {"ip": str, "added_at": str, "pinned": bool}.
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

    v5.0.20: для сценария «у меня сменился IP, хочу только новый».
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


# ── ipset management ─────────────────────────────────────────────────────────

def _run(cmd: list, check: bool = False, quiet: bool = True) -> subprocess.CompletedProcess:
    """Тонкая обёртка над subprocess.run для консистентности с остальным Chimera."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _ipset_available() -> bool:
    return bool(shutil.which("ipset"))


def _iptables_available() -> bool:
    return bool(shutil.which("iptables"))


def _collect_all_user_ips() -> "tuple[list[str], list[str]]":
    """Собирает allowed_ips из ВСЕХ пользователей.
    Возвращает (v4_list, v6_list) — списки уникальных CIDR/IP.
    """
    users = _users_load()
    v4_set: set[str] = set()
    v6_set: set[str] = set()
    for u in users:
        for ip in _normalize_user_ips(u):
            # Все значения в allowed_ips уже валидированы при add, но
            # для устойчивости к ручному редактированию users.json —
            # валидируем ещё раз.
            ok, normalized, _ = _validate_ip_or_cidr(ip)
            if not ok:
                continue
            if _is_ipv6(normalized):
                v6_set.add(normalized)
            else:
                v4_set.add(normalized)
    return sorted(v4_set), sorted(v6_set)


def _ipset_create_empty(name: str, family: str = "inet") -> bool:
    """Создаёт пустой ipset (если не существует)."""
    if not _ipset_available():
        return False
    family_arg = "inet6" if family == "inet6" else "inet"
    # hash:net работает и для одиночных IP (1.2.3.4 → 1.2.3.4/32),
    # и для подсетей (1.2.3.0/24).
    r = _run(["ipset", "create", name, "hash:net",
              "family", family_arg, "maxelem", "100000", "-exist"])
    return r.returncode == 0


def _ipset_swap_and_destroy(tmp_name: str, real_name: str) -> bool:
    """Atomic swap: tmp → real, затем удаляем tmp (теперь он real_name).
    Возвращает True при успехе.
    """
    r = _run(["ipset", "swap", tmp_name, real_name])
    if r.returncode != 0:
        # swap не удался — удаляем tmp, оставляем real как есть.
        _run(["ipset", "destroy", tmp_name])
        return False
    # После swap: tmp_name теперь содержит старое содержимое real_name.
    # Удаляем его (это бывший real).
    _run(["ipset", "destroy", tmp_name])
    return True


def rebuild_clients_ipset() -> bool:
    """Пересобирает ipset clients_wl_v4 и clients_wl_v6 из users.json.

    Использует atomic swap (ipset swap) — без перерыва в фильтрации.
    Старые IP продолжают работать до момента swap, новые — сразу после.
    """
    if not _ipset_available():
        return False

    v4, v6 = _collect_all_user_ips()

    # IPv4: создаём tmp-сет, заполняем, swap.
    if not _ipset_create_empty(IPSET_V4_NAME, "inet"):
        return False
    # tmp-сеты для atomic swap.
    _run(["ipset", "create", IPSET_V4_NAME + "_tmp", "hash:net",
          "family", "inet", "maxelem", "100000", "-exist"])
    if v4:
        restore_lines = "\n".join(
            [f"add {IPSET_V4_NAME}_tmp {cidr}" for cidr in v4]
        ) + "\n"
        tmp_file = Path("/tmp/chimera_clients_wl_v4.ipset")
        tmp_file.write_text(restore_lines)
        _run(["ipset", "restore", "-!", "-f", str(tmp_file)])
        tmp_file.unlink(missing_ok=True)
    _ipset_swap_and_destroy(IPSET_V4_NAME + "_tmp", IPSET_V4_NAME)

    # IPv6 — то же самое.
    if not _ipset_create_empty(IPSET_V6_NAME, "inet6"):
        return False
    _run(["ipset", "create", IPSET_V6_NAME + "_tmp", "hash:net",
          "family", "inet6", "maxelem", "100000", "-exist"])
    if v6:
        restore_lines = "\n".join(
            [f"add {IPSET_V6_NAME}_tmp {cidr}" for cidr in v6]
        ) + "\n"
        tmp_file = Path("/tmp/chimera_clients_wl_v6.ipset")
        tmp_file.write_text(restore_lines)
        _run(["ipset", "restore", "-!", "-f", str(tmp_file)])
        tmp_file.unlink(missing_ok=True)
    _ipset_swap_and_destroy(IPSET_V6_NAME + "_tmp", IPSET_V6_NAME)

    # Persist для boot-restore.
    try:
        from chimera.modules.ipset_persist import ipset_save
        ipset_save()
    except Exception:
        pass  # не критично — cron пересоберёт при следующем запуске

    return True


# ── iptables rules ───────────────────────────────────────────────────────────

def apply_iptables_rule(port: int) -> bool:
    """Добавляет ACCEPT-правило для clients_wl перед DROP-правилом ingress_geoip.

    Правило: ACCEPT -m set --match-set clients_wl_v4 src -p tcp --dport <port>
    Ставится через -I INPUT 1 (в самое начало) — ПЕРЕД всем остальным,
    включая DROP для xray_ru_block.

    Это КРИТИЧНО: если поставить через -A (в конец), то DROP для РФ-подсетей
    сработает раньше (он стоит через -A, но AFTER ESTABLISHED и whitelist ACCEPT).
    -I 1 гарантирует приоритет над любыми правилами.

    Вызывается из ingress_geoip._ingress_enable() автоматически.
    """
    if not _iptables_available():
        return False
    if not _ipset_available():
        return False

    # Убедимся, что ipset существует (если users пустые — будет пустой сет,
    # правило всё равно нужно ставить — оно просто ничего не пропустит).
    rebuild_clients_ipset()

    # IPv4
    # Сначала удаляем старое правило если есть (idempotent).
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "--match-set", IPSET_V4_NAME, "src",
          "-j", "ACCEPT",
          "-m", "comment", "--comment", IPTABLES_COMMENT],
         check=False, quiet=True)
    # Вставляем в начало.
    r = _run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", IPSET_V4_NAME, "src",
              "-j", "ACCEPT",
              "-m", "comment", "--comment", IPTABLES_COMMENT])
    if r.returncode != 0:
        return False

    # IPv6 — то же самое, но в ip6tables.
    if shutil.which("ip6tables"):
        _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", IPSET_V6_NAME, "src",
              "-j", "ACCEPT",
              "-m", "comment", "--comment", IPTABLES_COMMENT_V6],
             check=False, quiet=True)
        _run(["ip6tables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", IPSET_V6_NAME, "src",
              "-j", "ACCEPT",
              "-m", "comment", "--comment", IPTABLES_COMMENT_V6])

    return True


def remove_iptables_rule(port: int) -> None:
    """Удаляет ACCEPT-правило для clients_wl.

    Вызывается из ingress_geoip._ingress_remove() автоматически.
    НЕ удаляет сам ipset и НЕ трогает users.json — данные сохраняются,
    чтобы при повторном включении ingress_geoip правила восстановились.
    """
    if not _iptables_available():
        return

    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
          "-m", "set", "--match-set", IPSET_V4_NAME, "src",
          "-j", "ACCEPT",
          "-m", "comment", "--comment", IPTABLES_COMMENT],
         check=False, quiet=True)

    if shutil.which("ip6tables"):
        _run(["ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", str(port),
              "-m", "set", "--match-set", IPSET_V6_NAME, "src",
              "-j", "ACCEPT",
              "-m", "comment", "--comment", IPTABLES_COMMENT_V6],
             check=False, quiet=True)

    # НЕ удаляем ipset — данные сохраняются для повторного включения.
    # Если хочется полностью очистить — отдельная функция destroy_ipset().


def destroy_ipset() -> None:
    """Полностью удаляет ipset-сеты clients_wl_*. Данные в users.json сохраняются.
    Вызывается ТОЛЬКО при полном удалении user_ip_whitelist (через TUI пункт).
    """
    if not _ipset_available():
        return
    _run(["ipset", "destroy", IPSET_V4_NAME], check=False, quiet=True)
    _run(["ipset", "destroy", IPSET_V6_NAME], check=False, quiet=True)


# ── Cron ─────────────────────────────────────────────────────────────────────

def install_cron() -> bool:
    """Устанавливает cron для пересборки ipset каждые 5 минут.
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
        f"# Авто-пересборка clients_wl ipset из users.json.\n"
        f"# Вызывается cron каждые {CRON_INTERVAL_MIN} минут.\n"
        f"{python_bin} -c '"
        f"from chimera.modules.user_ip_whitelist import rebuild_clients_ipset; "
        f"rebuild_clients_ipset()' >/dev/null 2>&1\n"
    )
    CRON_SCRIPT.chmod(0o755)

    CRON_FILE.write_text(
        f"# Chimera — per-user IP whitelist ipset rebuild\n"
        f"SHELL=/bin/bash\n"
        f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"*/{CRON_INTERVAL_MIN} * * * * root {CRON_SCRIPT}\n"
    )
    CRON_FILE.chmod(0o644)
    return True


def remove_cron() -> None:
    """Удаляет cron и cron-скрипт. Не трогает ipset/iptables/users.json."""
    CRON_FILE.unlink(missing_ok=True)
    CRON_SCRIPT.unlink(missing_ok=True)


# ── Age-based cleanup (v5.0.20) ──────────────────────────────────────────────

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

    v5.0.20: age-based cleanup для предотвращения накопления старых IP.
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
        _box_row(f"  ipset:    {GREEN+'доступен'+NC if ipset_ok else YELLOW+'НЕТ (apt install ipset)'+NC}")
        _box_row(f"  iptables: {GREEN+'доступен'+NC if iptables_ok else YELLOW+'НЕТ'+NC}")

        # Cron status
        cron_ok = CRON_FILE.exists()
        _box_row(f"  cron:     {GREEN+'активен'+NC if cron_ok else DIM+'не установлен'+NC}")
        _box_sep()

        _box_item("1", "Управление IP пользователя (выбрать)")
        if cron_ok:
            _box_item("2", f"{YELLOW}Отключить автообновление (cron){NC}")
        else:
            _box_item("2", f"{GREEN}Включить автообновление (cron, каждые {CRON_INTERVAL_MIN} мин){NC}")
        _box_item("3", "Перестроить ipset сейчас (rebuild)")
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
                    success(f"Cron включён — ipset пересобирается каждые {CRON_INTERVAL_MIN} мин.")
                else:
                    warn("Не удалось установить cron.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            info("Пересобираю ipset...")
            if rebuild_clients_ipset():
                v4, v6 = _collect_all_user_ips()
                success(f"ipset пересобран: {len(v4)} IPv4, {len(v6)} IPv6 записей.")
            else:
                warn("Не удалось пересобрать ipset — проверьте наличие ipset/iptables.")
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
