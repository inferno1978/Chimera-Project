"""
vless_installer/modules/awg_net_common.py
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
  • build_nat_rule_args(...)           — список iptables-правил для NAT
  • build_nat_idempotent_shell(...)    — bash-сниппет для PostUp (с -C check)
  • build_nat_cleanup_shell(...)       — bash-сниппет для PostDown (с -D)
  • build_sysctl_lines(...)            — строки для /etc/sysctl.d/XX-awg.conf
  • detect_wan_iface(core)             — имя WAN-интерфейса (default route)
  • apply_rp_filter_per_iface(core, awg_iface, wan_iface, value=2)
                                        — runtime sysctl -w для per-interface
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

def iptables_ensure(core, args: list) -> None:
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
    r = core._run(["iptables"] + check_args, capture=True, check=False)
    if r.returncode != 0:
        # Правила ещё нет — добавляем
        core._run(["iptables"] + args, check=False, quiet=True)


# ============================================================================
#  NAT RULE BUILDERS
# ============================================================================

def build_nat_rule_args(subnet: str, awg_iface: str, wan_iface: str) -> List[list]:
    """
    Возвращает список из 3 iptables-правил для NAT/FORWARD (как списки аргументов).

    Правила:
      1. MASQUERADE трафика из awg_subnet → WAN (nat/POSTROUTING)
      2. FORWARD IN from awg_iface (новые соединения от клиентов)
      3. FORWARD OUT to awg_iface (ESTABLISHED,RELATED — обратный трафик)

    Эти правила идентичны для:
      • standalone (runtime через iptables_ensure + awg-nat.service)
      • Mode B exit-VPS (через PostUp в awg0.conf)
      • cascade (но там 2 интерфейса — awg0↔awg1, этот билдер НЕ применяется)
    """
    return [
        # 1. MASQUERADE: трафик из awg_subnet → WAN интерфейс
        ["iptables", "-t", "nat", "-A", "POSTROUTING",
         "-s", subnet, "-o", wan_iface, "-j", "MASQUERADE"],
        # 2. FORWARD: awg_iface → anywhere (новые соединения от клиентов)
        ["iptables", "-A", "FORWARD",
         "-i", awg_iface, "-j", "ACCEPT"],
        # 3. FORWARD: anywhere → awg_iface (ответы на установленные соединения)
        ["iptables", "-A", "FORWARD",
         "-o", awg_iface, "-m", "state",
         "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]


def build_nat_idempotent_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN") -> str:
    """
    Bash-сниппет для PostUp в awg0.conf (wg-quick).

    Использует идиому `iptables -C ... || iptables -A ...` для идемпотентности
    (безопасно при повторных `awg-quick up awg0` без промежуточного `down`).

    wan_iface_expr — bash-выражение для подстановки WAN-интерфейса.
    По умолчанию '$WAN' (ожидает что $WAN определена ранее в PostUp).
    Для standalone systemd-юнита awg-nat.service там делается
    `WAN=$(ip route show default | awk '{print $5; exit}')`.
    """
    return (
        f"iptables -t nat -C POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || "
        f"iptables -t nat -A POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE; "
        f"iptables -C FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || "
        f"iptables -A FORWARD -i {awg_iface} -j ACCEPT; "
        f"iptables -C FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || "
        f"iptables -A FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT"
    )


def build_nat_cleanup_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN") -> str:
    """
    Bash-сниппет для PostDown в awg0.conf — безопасное удаление правил.
    Каждое удаление обёрнуто в `... 2>/dev/null || true` чтобы PostDown
    не падал даже если какого-то правила уже нет (например после ручной очистки).
    """
    return (
        f"iptables -t nat -D POSTROUTING -s {subnet} -o {wan_iface_expr} -j MASQUERADE 2>/dev/null || true; "
        f"iptables -D FORWARD -i {awg_iface} -j ACCEPT 2>/dev/null || true; "
        f"iptables -D FORWARD -o {awg_iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true"
    )


# ============================================================================
#  SYSCTL
# ============================================================================

def build_sysctl_lines(awg_iface: str, wan_iface: str,
                       rp_filter_value: int = RP_FILTER_DEFAULT) -> List[str]:
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

    Дополнительно: net.ipv4.ip_forward=1 (без этого NAT-трафик не форвардится).
    """
    if rp_filter_value not in (0, 1, 2):
        rp_filter_value = RP_FILTER_DEFAULT
    return [
        "net.ipv4.ip_forward = 1",
        f"net.ipv4.conf.{awg_iface}.rp_filter = {rp_filter_value}",
        f"net.ipv4.conf.{wan_iface}.rp_filter = {rp_filter_value}",
    ]


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


def write_sysctl_conf(path: Path, awg_iface: str, wan_iface: str,
                      rp_filter_value: int = RP_FILTER_DEFAULT,
                      extra_lines: list = None) -> bool:
    """
    Перезаписывает /etc/sysctl.d/XX-awg*.conf с per-interface rp_filter.

    Сохраняет чужие строки из существующего файла (например net.ipv6.conf...),
    но вычищает старые global all/default rp_filter записи (которые были
    ошибочно добавлены предыдущей версией кода).

    Возвращает True при успехе, False при ошибке записи.
    """
    extra_lines = extra_lines or []
    new_lines = build_sysctl_lines(awg_iface, wan_iface, rp_filter_value) + extra_lines

    # Ключи, которые мы управляем — вычищаем их старые вхождения
    managed_prefixes = (
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        f"net.ipv4.conf.{awg_iface}.rp_filter",
        f"net.ipv4.conf.{wan_iface}.rp_filter",
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
