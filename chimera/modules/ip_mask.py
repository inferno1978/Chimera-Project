"""
chimera/modules/ip_mask.py
───────────────────────────────────────────────────────────────────────────────
IPv4 wildcard-маски (звёздочки в последних октетах) → CIDR.

Запрос фичи: пользователь вводит IP «по маске» — например 176.9.*.* или
152.65.*.* / 189.122.*.* — и хочет, чтобы запись покрывала ВСЕ адреса,
подпадающие под маску. Примеры НЕ захардкожены: маска — общая нотация,
любые значения октетов допустимы (0-255).

Поддерживаемые формы (IPv4, звёздочка = «этот и все следующие октеты
не фиксированы» — только хвостовые звёздочки):
    a.b.c.*   → a.b.c.0/24   (например 176.9.40.* → 176.9.40.0/24)
    a.b.*.*   → a.b.0.0/16   (например 176.9.*.*  → 176.9.0.0/16)
    a.b.*     → a.b.0.0/16   (сокращение: * «до конца адреса»)
    a.*       → a.0.0.0/8    (например 176.*      → 176.0.0.0/8)

НЕ поддерживается (отказ с понятной ошибкой):
    *.*.*.*      — «весь интернет»: запрет (иначе whitelist/ban теряют смысл)
    a.*.b.c      — звёздочка в середине (не хвост): отказ
    *.a.b.c      — ведущая звёздочка: отказ
    a..b.*.*     — пустой октет / двойная точка: отказ (просим исправить ввод)
    IPv6-маски   — не поддерживаются (документировано; IPv6 вводится как
                   точный адрес или CIDR)

Почему нормализация в CIDR: ВСЯ инфраструктура Chimera уже CIDR-native —
ipset hash:net (clients_wl_v4/v6, xray_manual_ban/6), iptables -s,
ipaddress.* в модулях.Wildcard-маска — это лишь НОТАЦИЯ на входе;
хранение и потребление — канонический CIDR. Поэтому каждый октет-маска
даёт ровно один CIDR (хвостовые октеты бинарно выровнены: /8, /16, /24).

Публичный API:
    is_wildcard_mask(value) -> bool
        Быстрый детектор (есть '*' и нет ':').

    mask_to_cidr(value) -> (ok, cidr, error)
        Маска → CIDR. ok=False при нарушении правил выше.

    ip_in_entries(ip, entries) -> bool
        Containment-проверка: точный IP против списка записей
        (IP/CIDR, IPv4+IPv6). Для autoban/scan-логики, где whitelist
        раньше сравнивался по точной строке.

Двойники (SYNC: держать в актуальном состоянии):
    chimera/modules/tg_bot.py        — _normalize_ip_token() в шаблоне бота
                                       (standalone-скрипт, без импортов chimera)
    scripts/chimera-remote-cmd.py    — _mask_to_cidr() (deployed в /usr/local/bin)
    chimera/modules/autoban.py       — inline-парсер CIDR в cron-скрипте
Двойники сознательно урезаны (только mask_to_cidr) и помечены комментарием
«SYNC: ip_mask.py».
"""
from __future__ import annotations

import ipaddress
from typing import List, Tuple

__all__ = [
    "is_wildcard_mask",
    "mask_to_cidr",
    "ip_in_entries",
    "entries_to_networks",
]


def is_wildcard_mask(value: str) -> bool:
    """True если value похоже на wildcard-маску (есть '*', нет ':'/'/')."""
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    return "*" in v and ":" not in v and "/" not in v


def mask_to_cidr(value: str) -> Tuple[bool, str, str]:
    """IPv4 wildcard-маска с хвостовыми звёздочками → (ok, cidr, error).

    Примеры:
        176.9.*.*  → (True, '176.9.0.0/16', '')
        152.65.*.* → (True, '152.65.0.0/16', '')
        189.122.*  → (True, '189.122.0.0/24', '')
        176.*      → (True, '176.0.0.0/8', '')
        *.*.*.*    → (False, '', 'маска *.*.*.* запрещена — это весь интернет')
        176.*.9.1  → (False, '', 'звёздочки допускаются только в ПОСЛЕДНИХ октетах')
        176..9.*.* → (False, '', '...')
    """
    if not value or not isinstance(value, str):
        return False, "", "Пустое значение"
    v = value.strip()
    if not v:
        return False, "", "Пустое значение"
    if ":" in v:
        return False, "", f"IPv6-маски не поддерживаются: {value} (введите точный IPv6 или CIDR)"
    if "/" in v:
        return False, "", f"Это уже CIDR, маска не нужна: {value}"

    parts = v.split(".")
    if len(parts) > 4 or any(p == "" for p in parts):
        return False, "", (
            f"Непонятные октеты в {value} (проверьте точки — например "
            f"176..9.*.* нужно писать как 176.9.*.*)"
        )

    # Первый октет обязателен и обязан быть числом (маска вида *.9.8.7 запрещена).
    if not parts[0].isdigit():
        if parts[0] == "*":
            return False, "", (
                f"Ведущая звёздочка запрещена: {value} "
                f"(звёздочки — только в последних октетах, например 176.9.*.*)"
            )
        return False, "", f"Первый октет не число: {value}"

    # Нормализуем до 4 октетов: 176.9.* → 176.9.*.*.* не нужно; работаем с
    # сокращённой формой как есть, дополняя звёздочками до 4 позиций.
    parts = parts + ["*"] * (4 - len(parts))

    # Разбираем октеты: идём слева направо, пока встречаются числа.
    base: List[int] = []
    for p in parts:
        if p == "*":
            break
        if not p.isdigit():
            return False, "", (
                f"Непонятный октет {p!r} в {value} (проверьте точки — "
                f"например 176..9.*.* нужно писать как 176.9.*.*)"
            )
        n = int(p)
        if n > 255:
            return False, "", f"Октет {p} больше 255: {value}"
        base.append(n)

    # Хвост после первого '*' обязан состоять ТОЛЬКО из '*' (звёздочка
    # «дотягивается» до конца адреса; серединные маски вроде 176.*.9.1
    # неоднозначны и запрещены).
    n_fixed = len(base)  # сколько октетов зафиксировано
    tail = parts[n_fixed:]
    if any(p != "*" for p in tail):
        return False, "", (
            f"Звёздочки допускаются только в ПОСЛЕДНИХ октетах: {value} "
            f"(например 176.9.*.*, но не 176.*.9.1)"
        )

    if n_fixed == 0:
        return False, "", f"Маска *.*.*.* запрещена: {value} (это весь интернет)"
    if n_fixed >= 4:
        return False, "", f"В маске нет звёздочек: {value}"

    cidr = ".".join(str(x) for x in base) + ".0" * (4 - n_fixed)
    prefix = 8 * n_fixed
    return True, f"{cidr}/{prefix}", ""


def entries_to_networks(entries) -> List["ipaddress._BaseNetwork"]:
    """Список строк (IP/CIDR, v4+v6) → список ip_network (битые — пропущены)."""
    nets = []
    for e in entries or []:
        try:
            nets.append(ipaddress.ip_network(str(e).strip(), strict=False))
        except (ValueError, TypeError, AttributeError):
            continue
    return nets


def ip_in_entries(ip: str, entries) -> bool:
    """True если точный ip входит в любую запись entries (IP или CIDR).

    Замена точечного сравнения `ip in whitelist`: запись 176.9.0.0/16
    теперь накрывает 176.9.5.5. Некорректные записи молча пропускаются
    (whitelist в старых конфигах может содержать мусор).
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    for net in entries_to_networks(entries):
        try:
            if addr in net:
                return True
        except TypeError:
            continue  # version mismatch (v4 addr vs v6 net) — не входит
    return False
