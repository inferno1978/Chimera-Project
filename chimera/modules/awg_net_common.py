"""
chimera/modules/awg_net_common.py
───────────────────────────────────────────────────────────────────────────────
Общий сетевой слой для AWG-модулей: NAT/MASQUERADE + sysctl + iptables-idempotency.

Эта прослойка выделена, чтобы избежать регрессии "баг исправлен в одном модуле,
но забыт в другом" между:
  • awg_standalone.awgs_setup_nat_and_routing — runtime-установка iptables
    правил + systemd-юнит awg-nat.service для standalone-сервера (где AWG
    работает локально и клиенты подключаются извне на этот же сервер).
  • awg_transport._awg_server_conf_text — генерация PostUp/PostDown строк для
    awg0.conf на exit-VPS в Mode B chain. Топология разная (RU→exit), но
    NAT-паттерн на exit-VPS идентичен standalone: трафик из awg_subnet →
    WAN MASQUERADE + FORWARD awg0↔WAN.

ВАЖНО про Mode B на RU-VPS: там NAT через MASQUERADE НЕ используется. Вместо
этого применяется policy routing по fwmark (xray-процесс маркируется, ip rule
отправляет marked-трафик через таблицу AWG → awg0 → exit-VPS). Поэтому на RU-VPS
никаких MASQUERADE правил не нужно — там трафик уходит в туннель с исходным
адресом 10.66.66.2, а уже exit-VPS делает MASQUERADE в интернет. Эта функция
(awgs_setup_nat_and_routing в standalone) — уникальна для standalone-режима и
для exit-VPS стороны Mode B (через PostUp); для RU-VPS стороны Mode B NAT
не нужен по причине policy-routing-через-fwmark.

Публичные функции:
  • iptables_ensure(core, args)        — idempotent -A через -C check
  • ip6tables_ensure(core, args)       — то же для ip6tables (IPv6)
  • build_nat_rule_args(...)           — список iptables-правил для NAT (IPv4)
  • build_nat_idempotent_shell(...)    — bash-сниппет для PostUp (с -C check, IPv4)
  • build_nat_cleanup_shell(...)       — bash-сниппет для PostDown (с -D, IPv4)
  • build_nat6_rule_args(...)          — список ip6tables-правил для NAT (IPv6)
  • build_nat6_idempotent_shell(...)   — bash-сниппет для PostUp (с -C check, IPv6)
  • build_nat6_cleanup_shell(...)      — bash-сниппет для PostDown (с -D, IPv6)
  • awg_v6_ula_from_subnet(subnet_v4)  — derived ULA-подсеть из v4-подсети
  • build_sysctl_lines(...)            — строки для /etc/sysctl.d/XX-awg.conf
  • detect_wan_iface(core)             — имя WAN-интерфейса (default route)
  • apply_rp_filter_per_iface(core, awg_iface, wan_iface, value=2)
                                        — runtime sysctl -w для per-interface
  • apply_ipv6_forward(core)           — runtime net.ipv6.conf.all.forwarding=1

MASQUERADE scope (scope_source parameter):
  • scope_source=True (default)  → MASQUERADE только трафика из awg_subnet
    (`-s {subnet} -o {wan} -j MASQUERADE`). Используется в standalone.
  • scope_source=False           → blanket MASQUERADE всего исходящего через WAN
    (`-o {wan} -j MASQUERADE`, без -s). Используется в Mode B exit-VPS для
    сохранения поведения до коммита 47f56d3 (см. docstring _awg_server_conf_text).
  Выбор blanket для exit-VPS — намеренное сохранение обратной совместимости:
  на exit-VPS в chain-режиме кроме AWG-трафика могут быть другие исходящие
  потоки (например системные обновления, monitoring-агенты), которые тоже
  должны маскарадиться через WAN. Сужение до `-s awg_subnet` сломало бы их.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List


# ============================================================================
#  CONSTANTS
# ============================================================================

# rp_filter values:
#   0 = off (no anti-spoofing — НЕ рекомендуется, ослабляет безопасность)
#   1 = strict (блокирует асимметричный роутинг, ломает NAT для туннелей)
#   2 = loose (рекомендуется: допускает асимметричный роутинг, но всё ещё
#              отбрасывает явный spoofing — достаточно для корректной работы
#              NAT между awg0 и WAN)
# Дефолт 2 (loose). Если 2 не решает проблему на конкретном ядре/драйвере —
# вызывай apply_rp_filter_per_iface(..., value=0), но это явный fallback.
RP_FILTER_DEFAULT = 2


# ============================================================================
#  IPTABLES IDEMPOTENT HELPER
# ============================================================================

def iptables_ensure(core, args: list, binary: str = "iptables") -> None:
    """
    Добавляет iptables-правило только если его ещё нет (idempotent).

    Реализация: заменяет "-A" на "-C" в копии args, выполняет check.
    Если check вернул ненулевой код (правила нет) — выполняем исходный -A.
    Если check вернул 0 (правило уже есть) — ничего не делаем.

    Без этой обёртки повторный вызов awgs_setup_nat_and_routing
    (переустановка, --force, повторный запуск после сбоя) дублировал бы
    правила бесконечно.

    Используется как для runtime-установки (awgs_setup_nat_and_routing),
    так и доступен для других модулей, которым нужна идемпотентная
    установка iptables-правил (NAT, mangle, filter).

    v5.5.8: параметр binary ("iptables" | "ip6tables") — та же логика
    для IPv6-правил (ip6tables_ensure — обёртка ниже).
    """
    if "-A" not in args:
        # Защита: args без -A нельзя безопасно конвертировать в -C.
        # В лог пишем WARN и выходим без действия — вызывавший код должен
        # быть обновлён.
        try:
            core.log_to_file(
                "WARN",
                f"awg_net_common.iptables_ensure: args без '-A', пропуск: {args}",
            )
        except Exception:
            pass
        return

    check_args = list(args)
    check_args[check_args.index("-A")] = "-C"
    r = core._run([binary] + check_args, capture=True, check=False)
    if r.returncode != 0:
        # Правила ещё нет — добавляем
        core._run([binary] + args, check=False, quiet=True)


def ip6tables_ensure(core, args: list) -> None:
    """
    v5.5.8: идемпотентное добавление ip6tables-правила (IPv6).

    Обёртка над iptables_ensure с binary="ip6tables" — идентичная логика
    -C/-A, но для стека IPv6. Используется NAT66 (MASQUERADE v6) и
    каскадными v6-правилами (MARK/FORWARD/TCPMSS).
    """
    iptables_ensure(core, args, binary="ip6tables")


# ============================================================================
# IPv6 ULA DERIVATION (v5.5.8)
# ============================================================================

def awg_v6_ula_from_subnet(subnet_v4: str, default: str = "fd66:66:66::/64") -> str:
    """
    v5.5.8: выводит ULA-подсеть IPv6 из v4-подсети туннеля.

    Правило: третий октет v4-базы становится третьим hextet'ом ULA
    (ДЕСЯТИЧНАЯ запись октета — 82 значит hextet '82', НЕ 0x52;
    читается человеком так же, как v4-подсеть):
      10.66.66.0/24   → fd66:66:66::/64   (дефолт — совместимость со старыми
                                            установками, где subnet_v6 был
                                            именно таким)
      172.16.81.0/24  → fd66:66:81::/64
      172.16.82.0/24  → fd66:66:82::/64
      172.16.91.0/24  → fd66:66:91::/64

    ЗАЧЕМ: в мульти-exit каскаде несколько RU-entry работают через один
    exit. Если бы у всех entry была одна и та же v6-подсеть клиентов
    (fd66:66:66::/64), v6-адреса на awg1 entry после NAT66 не конфликтуют,
    но при без-NAT транзите cryptokey-routing exit не смог бы различить
    пиры. Per-node производный префикс делает каждую entry уникальной
    по построению (v4-подсети entry обязаны быть уникальны — иначе каскад
    не работает и в v4).

    Фолбэк: при непарсибельной v4-подсети возвращается default
    (AWGS_DEFAULT_SUBNET_V6).
    """
    try:
        base = (subnet_v4 or "").split("/")[0]
        parts = base.split(".")
        if len(parts) != 4:
            return default
        third = int(parts[2])
        if not (0 < third < 256):
            return default
        # ДЕСЯТИЧНАЯ запись октета как hextet: нам важна не арифметика,
        # а УНИКАЛЬНОСТЬ и ЧИТАЕМОСТЬ — разные октеты → разные hextet-строки
        # → разные подсети. Любые 1-3 цифры валидны как hextet (≤ 0xFFFF).
        return f"fd66:66:{third}::/64"
    except Exception:
        return default


def awg_v6_host_from_v4(client_ip_v4: str, subnet_v6: str) -> str:
    """
    v5.5.8: выводит v6-адрес хоста с host-id из последнего октета v4.

    Примеры (subnet_v6 = fd66:66:82::/64):
      172.16.82.2  → fd66:66:82::2
      172.16.82.17 → fd66:66:82::17

    Правило «v6-адрес зеркалит v4 host-id» даёт два свойства:
      1. Адреса клиентов entry (172.16.82.2 → fd66:66:82::2) читаются
         человеком так же легко, как их v4-зеркала.
      2. В каскаде v6-адрес awg1 на entry (172.16.91.3 → fd66:66:91::3)
         ГАРАНТИРОВАННО совпадает с AllowedIPs пира cascade_entry_* на
         exit-ноде (там тот же принцип) — cryptokey routing сходится без
         ручной синхронизации.

    Возвращает "" если v4-адрес или подсеть непарсибельны.
    """
    try:
        v4 = (client_ip_v4 or "").split("/")[0]
        parts = v4.split(".")
        if len(parts) != 4:
            return ""
        host = int(parts[3])
        base = (subnet_v6 or "").split("::")[0].rstrip(":")
        if not base or not (0 < host < 256):
            return ""
        # Десятичная запись host-id как hextet (::17 — зеркалит .17)
        return f"{base}::{host}"
    except Exception:
        return ""


# ============================================================================
#  NAT RULE BUILDERS (IPv4 — iptables)
# ============================================================================

def build_nat_rule_args(subnet: str, awg_iface: str, wan_iface: str,
                        scope_source: bool = True) -> List[list]:
    """
    Возвращает список из 3 iptables-правил для NAT/FORWARD (как списки аргументов).

    Правила:
      1. MASQUERADE трафика → WAN (nat/POSTROUTING).
         При scope_source=True (default) — только из awg_subnet: `-s {subnet} -o {wan}`
         При scope_source=False — blanket: `-o {wan}` без -s
      2. FORWARD IN from awg_iface (новые соединения от клиентов)
      3. FORWARD OUT to awg_iface (ESTABLISHED,RELATED — обратный трафик)

    Эти правила идентичны для:
      • standalone (runtime через iptables_ensure + awg-nat.service) —
        использует scope_source=True (default), MASQUERADE ограничен подсетью awg0.
      • Mode B exit-VPS (через PostUp в awg0.conf) — использует scope_source=False
        для сохранения поведения до 47f56d3 (blanket MASQUERADE на exit-VPS).
      • cascade (но там 2 интерфейса — awg0↔awg1, этот билдер НЕ применяется)
    """
    if scope_source:
        masq_rule = ["iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", subnet, "-o", wan_iface, "-j", "MASQUERADE"]
    else:
        masq_rule = ["iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-o", wan_iface, "-j", "MASQUERADE"]
    return [
        masq_rule,
        # 2. FORWARD: awg_iface → anywhere (новые соединения от клиентов)
        ["iptables", "-A", "FORWARD",
         "-i", awg_iface, "-j", "ACCEPT"],
        # 3. FORWARD: anywhere → awg_iface (ответы на установленные соединения)
        ["iptables", "-A", "FORWARD",
         "-o", awg_iface, "-m", "state",
         "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]


def build_nat_idempotent_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                               scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostUp в awg0.conf (wg-quick) — IPv4.

    Использует идиому `iptables -C ... || iptables -A ...` для идемпотентности
    (безопасно при повторных `awg-quick up awg0` без промежуточного `down`).

    wan_iface_expr — bash-выражение для подстановки WAN-интерфейса.
    По умолчанию '$WAN' (ожидает что $WAN определена ранее в PostUp).
    Для standalone systemd-юнита awg-nat.service там делается
    `WAN=$(ip route show default | awk '{print $5; exit}')`.

    scope_source=True (default) → MASQUERADE scoped до awg_subnet (`-s {subnet} -o $WAN`).
    scope_source=False          → MASQUERADE blanket (`-o $WAN` без -s).
    """
    if scope_source:
        masq_pair = (
            f"iptables -t nat -C POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || "
            f"iptables -t nat -A POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE"
        )
    else:
        masq_pair = (
            f"iptables -t nat -C POSTROUTING -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || "
            f"iptables -t nat -A POSTROUTING -o {wan_iface_expr} -j MASQUERADE"
        )
    return (
        masq_pair + "; "
        + f"iptables -C FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || "
          f"iptables -A FORWARD -i {awg_iface} -j ACCEPT; "
        + f"iptables -C FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
          f"iptables -A FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT"
    )


def build_nat_cleanup_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                            scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostDown в awg0.conf — безопасное удаление правил (IPv4).
    Каждое удаление обёрнуто в `... 2>/dev/null || true` чтобы PostDown
    не падал даже если какого-то правила уже нет (например после ручной очистки).

    scope_source должен совпадать с тем, что использовался в build_nat_idempotent_shell
    (иначе -D не найдёт правило для удаления — но `|| true` спасёт от падения).
    """
    if scope_source:
        masq_del = (
            f"iptables -t nat -D POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || true"
        )
    else:
        masq_del = (
            f"iptables -t nat -D POSTROUTING -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || true"
        )
    return (
        masq_del + "; "
        + f"iptables -D FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || true; "
        + f"iptables -D FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true"
    )


# ============================================================================
#  NAT RULE BUILDERS (IPv6 — ip6tables)
# ============================================================================
# IPv6 NAT-паттерн идентичен IPv4 по структуре (MASQUERADE + FORWARD in/out),
# отличается только бинарником (ip6tables vs iptables). Вынесен в отдельные
# функции для читаемости и чтобы type-checkers не путались в family-параметре.
#
# subnet для IPv6 обычно = "fd66:66:66::/64" (AWG_SUBNET_V6 из _core.py globals).

def build_nat6_rule_args(subnet: str, awg_iface: str, wan_iface: str,
                         scope_source: bool = True) -> List[list]:
    """
    Возвращает список из 3 ip6tables-правил для NAT/FORWARD (IPv6).
    Аналог build_nat_rule_args, но для ip6tables.
    """
    if scope_source:
        masq_rule = ["ip6tables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", subnet, "-o", wan_iface, "-j", "MASQUERADE"]
    else:
        masq_rule = ["ip6tables", "-t", "nat", "-A", "POSTROUTING",
                     "-o", wan_iface, "-j", "MASQUERADE"]
    return [
        masq_rule,
        ["ip6tables", "-A", "FORWARD",
         "-i", awg_iface, "-j", "ACCEPT"],
        ["ip6tables", "-A", "FORWARD",
         "-o", awg_iface, "-m", "state",
         "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]


def build_nat6_idempotent_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                                scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostUp в awg0.conf (wg-quick) — IPv6, ip6tables.
    Аналог build_nat_idempotent_shell, но для ip6tables.
    """
    if scope_source:
        masq_pair = (
            f"ip6tables -t nat -C POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || "
            f"ip6tables -t nat -A POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE"
        )
    else:
        masq_pair = (
            f"ip6tables -t nat -C POSTROUTING -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || "
            f"ip6tables -t nat -A POSTROUTING -o {wan_iface_expr} -j MASQUERADE"
        )
    return (
        masq_pair + "; "
        + f"ip6tables -C FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || "
          f"ip6tables -A FORWARD -i {awg_iface} -j ACCEPT; "
        + f"ip6tables -C FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
          f"ip6tables -A FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT"
    )


def build_nat6_cleanup_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                             scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostDown в awg0.conf — безопасное удаление правил (IPv6).
    Аналог build_nat_cleanup_shell, но для ip6tables.
    """
    if scope_source:
        masq_del = (
            f"ip6tables -t nat -D POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || true"
        )
    else:
        masq_del = (
            f"ip6tables -t nat -D POSTROUTING -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || true"
        )
    return (
        masq_del + "; "
        + f"ip6tables -D FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || true; "
        + f"ip6tables -D FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true"
    )


# ============================================================================
#  SYSCTL
# ============================================================================

def build_sysctl_lines(awg_iface: str, wan_iface: str,
                       rp_filter_value: int = RP_FILTER_DEFAULT,
                       ipv6_forward: bool = False) -> List[str]:
    """
    Возвращает строки для /etc/sysctl.d/XX-awg.conf.

    ВАЖНО: НЕ сбрасываем rp_filter глобально (all/default). Это ослабляло бы
    anti-spoofing защиту на всей системе, а не только для awg0/WAN.

    Используем per-interface loose mode (2) — обычно достаточен для корректной
    работы NAT между туннелем и WAN, и не отключает защиту полностью.

    Параметры:
      • awg_iface       — имя туннеля (awg0)
      • wan_iface       — имя WAN-интерфейса (eth0, ens3, …)
      • rp_filter_value — 0/1/2 (default 2 = loose mode). 0 только как явный
                          fallback если 2 не решает проблему на конкретном ядре.
      • ipv6_forward    — v5.5.8: добавить net.ipv6.conf.all.forwarding = 1
                          (нужно для NAT66/транзита v6 из туннеля).

    Дополнительно: net.ipv4.ip_forward=1 (без этого NAT-трафик не форвардится).
    """
    if rp_filter_value not in (0, 1, 2):
        rp_filter_value = RP_FILTER_DEFAULT
    lines = [
        "net.ipv4.ip_forward = 1",
        f"net.ipv4.conf.{awg_iface}.rp_filter = {rp_filter_value}",
        f"net.ipv4.conf.{wan_iface}.rp_filter = {rp_filter_value}",
    ]
    if ipv6_forward:
        lines.append("net.ipv6.conf.all.forwarding = 1")
    return lines


def apply_rp_filter_per_iface(core, awg_iface: str, wan_iface: str,
                              value: int = RP_FILTER_DEFAULT) -> None:
    """
    Runtime применение per-interface rp_filter через sysctl -w.

    Не трогает all/default — только конкретные интерфейсы.

    Если текущее значение уже совпадает с целевым — пропускает (idempotent).
    Логирует изменения через core.info().
    """
    if value not in (0, 1, 2):
        value = RP_FILTER_DEFAULT
    for iface in (awg_iface, wan_iface):
        r = core._run(["sysctl", "-n", f"net.ipv4.conf.{iface}.rp_filter"],
                      capture=True, check=False)
        cur = r.stdout.strip() if r.returncode == 0 else ""
        if r.returncode != 0:
            # Интерфейс может ещё не существовать (awg0 до awg-quick up) —
            # это нормально, конфиг будет применён позже через sysctl --system.
            continue
        if cur not in (str(value),):
            core._run(["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter={value}"],
                      check=False, quiet=True)
            try:
                core.info(f"  rp_filter {iface}: {cur} → {value}"
                          f" (loose mode — сохраняет anti-spoofing защиту)")
            except Exception:
                pass


def apply_ip_forward(core) -> None:
    """
    Включает net.ipv4.ip_forward=1 в runtime, если ещё не включён.
    Idempotent: проверяет текущее значение перед sysctl -w.
    """
    r = core._run(["sysctl", "-n", "net.ipv4.ip_forward"],
                  capture=True, check=False)
    if r.returncode == 0 and r.stdout.strip() != "1":
        core._run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                  check=False, quiet=True)
        try:
            core.info("  net.ipv4.ip_forward: 0 → 1")
        except Exception:
            pass
    elif r.returncode == 0:
        try:
            core.info("  net.ipv4.ip_forward: уже 1")
        except Exception:
            pass


def apply_ipv6_forward(core) -> None:
    """
    v5.5.8: включает net.ipv6.conf.all.forwarding=1 в runtime — без этого
    ядро не форвардит IPv6-пакеты из туннеля (NAT66/транзит в каскаде).
    Idempotent: проверяет текущее значение перед sysctl -w.
    """
    r = core._run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"],
                  capture=True, check=False)
    if r.returncode == 0 and r.stdout.strip() != "1":
        core._run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                  check=False, quiet=True)
        try:
            core.info("  net.ipv6.conf.all.forwarding: 0 → 1")
        except Exception:
            pass
    elif r.returncode == 0:
        try:
            core.info("  net.ipv6.conf.all.forwarding: уже 1")
        except Exception:
            pass


def write_sysctl_conf(path: Path, awg_iface: str, wan_iface: str,
                      rp_filter_value: int = RP_FILTER_DEFAULT,
                      extra_lines: list = None,
                      ipv6_forward: bool = False) -> bool:
    """
    Перезаписывает /etc/sysctl.d/XX-awg*.conf с per-interface rp_filter.

    Сохраняет чужие строки из существующего файла (например net.ipv6.conf...),
    но вычищает старые global all/default rp_filter записи (которые были
    ошибочно добавлены предыдущей версией кода).

    v5.5.8: ipv6_forward=True добавляет net.ipv6.conf.all.forwarding = 1
    в управляемые строки (managed_prefixes расширен соответствующе — старая
    строка ipv6.forwarding из файла вычищается и перезаписывается нашей).

    Возвращает True при успехе, False при ошибке записи.
    """
    extra_lines = extra_lines or []
    new_lines = build_sysctl_lines(awg_iface, wan_iface, rp_filter_value,
                                   ipv6_forward=ipv6_forward) + extra_lines

    # Ключи, которые мы управляем — вычищаем их старые вхождения
    managed_prefixes = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        f"net.ipv4.conf.{awg_iface}.rp_filter",
        f"net.ipv4.conf.{wan_iface}.rp_filter",
        "net.ipv6.conf.all.forwarding",
    )

    kept = []
    if path.exists():
        try:
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if any(stripped.startswith(p) for p in managed_prefixes):
                    continue
                kept.append(line)
        except Exception:
            kept = []

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(kept + new_lines) + "\n")
        return True
    except Exception:
        return False


# ============================================================================
#  WAN INTERFACE DETECTION
# ============================================================================

def detect_wan_iface(core) -> str:
    """
    Возвращает имя WAN-интерфейса (через который идёт default route).
    Пустая строка если не удалось определить.
    """
    r = core._run(["ip", "route", "show", "default"],
                  capture=True, check=False)
    if r.returncode == 0:
        m = re.search(r"\bdev\s+(\S+)", r.stdout)
        if m:
            return m.group(1)
    return ""
