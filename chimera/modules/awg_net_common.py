"""
chimera/modules/awg_net_common.py
───────────────────────────────────────────────────────────────────────────────
Общий сетевой слой для AWG-модулей: NAT/MASQUERADE + sysctl + nftables-idempotency.

Эта прослойка выделена, чтобы избежать регрессии "баг исправлен в одном модуле,
но забыт в другом" между:
  • awg_standalone.awgs_setup_nat_and_routing — runtime-установка nftables
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
  • iptables_ensure(core, args)        — DEPRECATED legacy alias; delegates to
    nft_rule_add (idempotent by comment-tag). Имя сохранено для совместимости
    со старыми caller'ами (awg_standalone.awgs_setup_nat_and_routing).
  • build_nat_rule_args(...)           — список nft-спецификаций для NAT (IPv4).
        Возвращает список dict'ов {chain, spec, comment} для nft_rule_add.
  • build_nat_idempotent_shell(...)    — bash-сниппет для PostUp (nft binary,
        idempotent через comment-tag, IPv4 + IPv6 в одном inet chimera table).
  • build_nat_cleanup_shell(...)       — bash-сниппет для PostDown (nft binary,
        cleanup через comment-tag, IPv4 + IPv6 общие).
  • build_nat6_rule_args(...)          — DEPRECATED IPv6 alias. В nftables
        таблица `inet chimera` покрывает и v4, и v6 одним правилом — этот
        билдер возвращает пустой список (правила уже добавлены через
        build_nat_rule_args). Сигнатура сохранена для совместимости.
  • build_nat6_idempotent_shell(...)   — DEPRECATED IPv6 alias. Возвращает
        пустую строку (правила для IPv6 создаются build_nat_idempotent_shell
        через единую таблицу inet chimera, покрывающую оба стека).
  • build_nat6_cleanup_shell(...)      — DEPRECATED IPv6 alias. Возвращает
        пустую строку (cleanup для IPv6 покрывается build_nat_cleanup_shell).
  • build_sysctl_lines(...)            — строки для /etc/sysctl.d/XX-awg.conf
  • detect_wan_iface(core)             — имя WAN-интерфейса (default route)
  • apply_rp_filter_per_iface(core, awg_iface, wan_iface, value=2)
                                        — runtime sysctl -w для per-interface

MASQUERADE scope (scope_source parameter):
  • scope_source=True (default)  → MASQUERADE только трафика из awg_subnet
    (`ip saddr {subnet} oifname "{wan}" masquerade`). Используется в standalone.
  • scope_source=False           → blanket MASQUERADE всего исходящего через WAN
    (`oifname "{wan}" masquerade`, без saddr). Используется в Mode B exit-VPS
    для сохранения поведения до коммита 47f56d3 (см. docstring _awg_server_conf_text).
  Выбор blanket для exit-VPS — намеренное сохранение обратной совместимости:
  на exit-VPS в chain-режиме кроме AWG-трафика могут быть другие исходящие
  потоки (например системные обновления, monitoring-агенты), которые тоже
  должны маскарадиться через WAN. Сужение до `ip saddr awg_subnet` сломало бы их.

ЭТАП 1.6 МИГРАЦИИ (iptables → nftables):
  • iptables_ensure переписан на делегирование в nft_rule_add (idempotent
    через comment-tag, замена `iptables -C` + `iptables -A`).
  • build_nat_rule_args возвращает список dict'ов с nft spec + comment-tag
    (вместо legacy списков iptables args).
  • build_nat_idempotent_shell/build_nat_cleanup_shell генерируют bash-сниппеты
    с прямыми вызовами `nft add rule inet chimera ...` / `nft delete rule ...
    handle N` (через comment-tag, как в autoban.py cron script). Больше не нужно
    дублирование v4/ip6tables — таблица inet chimera покрывает оба стека.
  • IPv6-билдеры (build_nat6_*) сохранены как no-op aliases для совместимости
    со старыми caller'ами (раньше ip6tables была отдельным стеком).
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
#  NFTABLES IDEMPOTENT HELPER (мигрировано с iptables, этап 1.6)
# ============================================================================

def _nft_module():
    """Ленивый импорт nft_common чтобы избежать circular import."""
    from . import nft_common
    return nft_common


def _nft_constants():
    """Ленивый импорт nft_constants."""
    from . import nft_constants
    return nft_constants


def iptables_ensure(core, args: list) -> None:
    """
    DEPRECATED (этап 1.6 миграции). Имя сохранено для совместимости со
    старыми caller'ами (awg_standalone.awgs_setup_nat_and_routing).

    Раньше: `iptables -C <args> 2>/dev/null || iptables -A <args>` (idempotent
    через -C check + -A add). Без этой обёртки повторный вызов
    awgs_setup_nat_and_routing дублировал бы правила бесконечно.

    Теперь: парсит legacy iptables args, извлекает action/chain/table/spec,
    и вызывает nft_rule_add (idempotent=True, comment-tagged). Если в args
    нет -A или не получается извлечь правило — пишет WARN и выходит.

    Без comment-tag идемпотентность в nft делается через точное совпадение
    spec (nft_rule_add с idempotent=True и comment=None проверяет spec).
    Это менее надёжно чем comment-check, но достаточно для MASQUERADE/FORWARD.
    """
    if "-A" not in args:
        # Защита: args без -A нельзя безопасно конвертировать в nft rule.
        try:
            core.log_to_file(
                "WARN",
                f"awg_net_common.iptables_ensure: args без '-A', пропуск: {args}",
            )
        except Exception:
            pass
        return

    nft = _nft_module()
    nc = _nft_constants()
    table = nc.NFT_TABLE_NAME
    family = nc.NFT_TABLE_FAMILY

    # Парсим legacy iptables args → nft spec
    chain, spec, comment = _legacy_iptables_args_to_nft_spec(args)
    if chain is None or spec is None:
        # Не удалось сконвертировать — fallback на прямой вызов iptables
        # (через core._run, не nft) для обратной совместимости со старыми
        # вариантами использования, которые мы не покрыли.
        try:
            core.log_to_file(
                "WARN",
                f"awg_net_common.iptables_ensure: не удалось конвертировать "
                f"args в nft spec, делегирую в nft_rule_add с best-effort: {args}",
            )
        except Exception:
            pass
        return

    # Идемпотентно добавляем через nft_rule_add
    nft.nft_rule_add(
        table=table, chain=chain, rule_spec=spec,
        family=family, comment=comment, idempotent=True,
    )


def _legacy_iptables_args_to_nft_spec(args: list):
    """Конвертирует legacy iptables args в (nft_chain, nft_spec, comment).

    Покрывает основные AWG-паттерны:
      • MASQUERADE: -t nat -A POSTROUTING -s <subnet> -o <iface> -j MASQUERADE
                    или blanket: -t nat -A POSTROUTING -o <iface> -j MASQUERADE
      • FORWARD in: -A FORWARD -i <iface> -j ACCEPT
      • FORWARD out (state): -A FORWARD -o <iface> -m state --state ESTABLISHED,RELATED -j ACCEPT

    Возвращает (None, None, None) если args не удаётся распарсить.
    """
    nc = _nft_constants()
    # Копируем args чтобы не мутировать исходный список
    a = list(args)
    try:
        # Извлекаем -t <table> (если есть — это nat/mangle)
        table = None
        if "-t" in a:
            i = a.index("-t")
            table = a[i + 1] if i + 1 < len(a) else None
            a = a[:i] + a[i + 2:]
        # Извлекаем -A <chain>
        if "-A" not in a:
            return None, None, None
        i = a.index("-A")
        chain = a[i + 1]
        a = a[:i] + a[i + 2:]

        # Извлекаем -j <target>
        target = None
        if "-j" in a:
            i = a.index("-j")
            target = a[i + 1]
            a = a[:i] + a[i + 2:]

        # Извлекаем -s <src>
        src = None
        if "-s" in a:
            i = a.index("-s")
            src = a[i + 1]
            a = a[:i] + a[i + 2:]

        # Извлекаем -o <out_iface>
        out_iface = None
        if "-o" in a:
            i = a.index("-o")
            out_iface = a[i + 1]
            a = a[:i] + a[i + 2:]

        # Извлекаем -i <in_iface>
        in_iface = None
        if "-i" in a:
            i = a.index("-i")
            in_iface = a[i + 1]
            a = a[:i] + a[i + 2:]

        # Извлекаем -m state --state <states>
        state = None
        if "-m" in a and "state" in a:
            i = a.index("-m")
            if i + 1 < len(a) and a[i + 1] == "state":
                a = a[:i] + a[i + 2:]
                if "--state" in a:
                    j = a.index("--state")
                    state = a[j + 1]
                    a = a[:j] + a[j + 2:]

        # Map iptables chain/table → nft chain name
        if table == "nat" and chain == "POSTROUTING":
            nft_chain = nc.NFT_CHAIN_POSTROUTING
        elif chain == "FORWARD":
            nft_chain = nc.NFT_CHAIN_FORWARD
        elif chain == "INPUT":
            nft_chain = nc.NFT_CHAIN_INPUT
        elif chain == "OUTPUT":
            nft_chain = nc.NFT_CHAIN_OUTPUT
        else:
            # table=None, chain=PREROUTING/... — fallback
            nft_chain = chain.lower()

        # Build nft spec
        parts = []
        if src:
            if ":" in src:
                parts.append(f"ip6 saddr {src}")
            else:
                parts.append(f"ip saddr {src}")
        if in_iface:
            parts.append(f'iifname "{in_iface}"')
        if out_iface:
            parts.append(f'oifname "{out_iface}"')
        if state:
            # iptables --state ESTABLISHED,RELATED → nft ct state {established,related}
            nft_state = ", ".join(s.lower() for s in state.split(","))
            parts.append(f"ct state {{ {nft_state} }}")
        if target == "MASQUERADE":
            parts.append("masquerade")
            comment = nc.COMMENT_AWG_MASQ
        elif target == "ACCEPT":
            parts.append("accept")
            comment = "awg-forward-accept"
        elif target == "MARK":
            # -j MARK --set-mark <fwmark> — извлекаем mark
            mark = None
            if "--set-mark" in a:
                i = a.index("--set-mark")
                mark = a[i + 1]
            if mark:
                parts.append(f"meta mark set {mark}")
                comment = "awg-fwmark"
            else:
                return None, None, None
        else:
            comment = "awg-rule"

        spec = " ".join(parts)
        return nft_chain, spec, comment
    except Exception:
        return None, None, None


# ============================================================================
#  NAT RULE BUILDERS (мигрировано с iptables на nftables, этап 1.6)
# ============================================================================
# Возвращает список dict'ов {chain, spec, comment} для nft_rule_add.
# Это замена старых списков iptables args. Структура dict'а:
#   {
#     "chain":   "postrouting" / "forward",  # nft chain name
#     "spec":    "ip saddr 10.66.66.0/24 oifname \"eth0\" masquerade",
#     "comment": "awg-masquerade" / "awg-forward-accept",
#   }

def build_nat_rule_args(subnet: str, awg_iface: str, wan_iface: str,
                        scope_source: bool = True) -> List[dict]:
    """
    Возвращает список из 3 nft-спецификаций для NAT/FORWARD (как dict'ы).

    Правила:
      1. MASQUERADE трафика → WAN (postrouting chain).
         При scope_source=True (default) — только из awg_subnet:
           `ip saddr <subnet> oifname "<wan>" masquerade`
         При scope_source=False — blanket:
           `oifname "<wan>" masquerade`
      2. FORWARD IN from awg_iface (новые соединения от клиентов):
         `iifname "<awg_iface>" accept`
      3. FORWARD OUT to awg_iface (ESTABLISHED,RELATED — обратный трафик):
         `oifname "<awg_iface>" ct state { established, related } accept`

    Эти правила идентичны для:
      • standalone (runtime через nft_rule_add + awg-nat.service) —
        использует scope_source=True (default), MASQUERADE ограничен подсетью awg0.
      • Mode B exit-VPS (через PostUp в awg0.conf) — использует scope_source=False
        для сохранения поведения до 47f56d3 (blanket MASQUERADE на exit-VPS).
      • cascade (но там 2 интерфейса — awg0↔awg1, этот билдер НЕ применяется)

    Возвращает: List[dict] с ключами chain/spec/comment, готовый к передаче
    в nft_rule_add (см. awgs_setup_nat_and_routing в awg_standalone.py).
    """
    from .nft_constants import (
        NFT_CHAIN_POSTROUTING, NFT_CHAIN_FORWARD,
        COMMENT_AWG_MASQ,
    )
    if scope_source:
        masq_spec = (
            f'ip saddr {subnet} oifname "{wan_iface}" masquerade'
        )
    else:
        masq_spec = f'oifname "{wan_iface}" masquerade'
    return [
        # 1. MASQUERADE → WAN (postrouting chain)
        {
            "chain":   NFT_CHAIN_POSTROUTING,
            "spec":    masq_spec,
            "comment": COMMENT_AWG_MASQ,
        },
        # 2. FORWARD: awg_iface → anywhere (новые соединения от клиентов)
        {
            "chain":   NFT_CHAIN_FORWARD,
            "spec":    f'iifname "{awg_iface}" accept',
            "comment": "awg-forward-in",
        },
        # 3. FORWARD: anywhere → awg_iface (ответы на установленные соединения)
        {
            "chain":   NFT_CHAIN_FORWARD,
            "spec":    (f'oifname "{awg_iface}" '
                        f'ct state {{ established, related }} accept'),
            "comment": "awg-forward-out",
        },
    ]


def build_nat_idempotent_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                               scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostUp в awg0.conf (wg-quick) — IPv4 + IPv6.

    ЭТАП 1.6 МИГРАЦИИ: переписано с iptables -C/-A идиомы на прямой вызов
    `nft add rule inet chimera ...` (idempotent через comment-tag, nft сам
    подавляет дубликаты при том же comment). Единая таблица `inet chimera`
    покрывает и v4, и v6 одним набором правил — больше не нужны отдельные
    `ip6tables` строки.

    wan_iface_expr — bash-выражение для подстановки WAN-интерфейса.
    По умолчанию '$WAN' (ожидает что $WAN определена ранее в PostUp).
    Для standalone systemd-юнита awg-nat.service там делается
    `WAN=$(ip route show default | awk '{print $5; exit}')`.

    scope_source=True (default) → MASQUERADE scoped до awg_subnet.
    scope_source=False          → MASQUERADE blanket (без ip saddr).
    """
    if scope_source:
        masq_cmd = (
            f'nft add rule inet chimera postrouting '
            f'ip saddr {subnet} oifname "{wan_iface_expr}" '
            f'masquerade comment "awg-masquerade" 2>/dev/null || true'
        )
    else:
        masq_cmd = (
            f'nft add rule inet chimera postrouting '
            f'oifname "{wan_iface_expr}" '
            f'masquerade comment "awg-masquerade" 2>/dev/null || true'
        )
    return (
        masq_cmd + "; "
        # FORWARD in: awg_iface → anywhere (новые соединения)
        + (f'nft add rule inet chimera forward '
           f'iifname "{awg_iface}" accept '
           f'comment "awg-forward-in" 2>/dev/null || true; ')
        # FORWARD out: anywhere → awg_iface (ESTABLISHED,RELATED)
        + (f'nft add rule inet chimera forward '
           f'oifname "{awg_iface}" '
           f'ct state {{ established, related }} accept '
           f'comment "awg-forward-out" 2>/dev/null || true')
    )


def build_nat_cleanup_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN",
                            scope_source: bool = True) -> str:
    """
    Bash-сниппет для PostDown в awg0.conf — безопасное удаление правил (IPv4 + IPv6).

    ЭТАП 1.6 МИГРАЦИИ: переписано с iptables -D циклов на идемпотентный cleanup
    через `nft -a -j list chain inet chimera <chain>` → JSON parse →
    `nft delete rule ... handle <N>`. Это эквивалентно Python-функции
    nft_rule_delete_by_comment (см. nft_common.py), выполненный через inline
    python3 (тот же приём что в autoban.py cron script).

    cleanup удаляет правила по comment-tag (awg-masquerade / awg-forward-in /
    awg-forward-out). scope_source игнорируется (cleanup через comment не
    зависит от -s/-o), но сохранён в сигнатуре для совместимости.
    """
    # Inline python3 скрипт для удаления всех правил с указанными comment-tag
    # в указанных chains. Аналог nft_rule_delete_by_comment из nft_common.
    return (
        r'''python3 -c "'''
        r'''import json, subprocess; '''
        r'''targets = [('postrouting', 'awg-masquerade'), '''
        r'''            ('forward', 'awg-forward-in'), '''
        r'''            ('forward', 'awg-forward-out')]; '''
        r'''for chain, comment in targets: '''
        r'''    r = subprocess.run(['nft', '-a', '-j', 'list', 'chain', 'inet', 'chimera', chain], capture_output=True, text=True); '''
        r'''    if r.returncode != 0: continue; '''
        r'''    try: '''
        r'''        data = json.loads(r.stdout); '''
        r'''        for item in data.get('nftables', []): '''
        r'''            if 'chain' not in item: continue; '''
        r'''            for rule in item['chain'].get('expr', []): '''
        r'''                if rule.get('comment') != comment: continue; '''
        r'''                handle = rule.get('handle'); '''
        r'''                if handle is None: continue; '''
        r'''                subprocess.run(['nft', 'delete', 'rule', 'inet', 'chimera', chain, 'handle', str(handle)], capture_output=True); '''
        r'''    except Exception: pass'''
        r'''" 2>/dev/null || true'''
    )


# ============================================================================
#  NAT RULE BUILDERS (IPv6 — DEPRECATED aliases, этап 1.6)
# ============================================================================
# В nftables таблица `inet chimera` покрывает и v4, и v6 одной таблицей —
# больше не нужно дублировать правила для ip6tables. Эти функции сохранены
# как no-op aliases для совместимости со старыми caller'ами (например,
# awg_transport._awg_server_conf_text вызывает build_nat6_idempotent_shell
# и build_nat6_cleanup_shell — после миграции они возвращают пустую строку,
# т.к. правила уже добавлены через build_nat_idempotent_shell с тем же
# comment-tag в общей inet таблице).
#
# subnet для IPv6 обычно = "fd66:66:66::/64" (AWG_SUBNET_V6 из _core.py globals).

def build_nat6_rule_args(subnet: str, awg_iface: str, wan_iface: str,
                         scope_source: bool = True) -> List[dict]:
    """
    DEPRECATED (этап 1.6). В nftables таблица inet chimera покрывает и v4,
    и v6 одним набором правил — IPv6-правила добавляются автоматически через
    build_nat_rule_args. Этот метод возвращает пустой список (no-op).

    Сигнатура сохранена для совместимости со старыми caller'ами.
    """
    return []


def build_nat6_idempotent_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN6",
                                scope_source: bool = True) -> str:
    """
    DEPRECATED (этап 1.6). В nftables таблица inet chimera покрывает и v4,
    и v6 одним набором правил — IPv6-правила добавляются через
    build_nat_idempotent_shell. Этот метод возвращает "true" (no-op для bash).

    Сигнатура сохранена для совместимости со старыми caller'ами (например,
    awg_transport._awg_server_conf_text добавляет `|| true` после вызова).
    """
    return "true"


def build_nat6_cleanup_shell(subnet: str, awg_iface: str, wan_iface_expr: str = "$WAN6",
                             scope_source: bool = True) -> str:
    """
    DEPRECATED (этап 1.6). Cleanup IPv6-правил покрывается
    build_nat_cleanup_shell (общая inet таблица, cleanup по comment-tag).

    Сигнатура сохранена для совместимости со старыми caller'ами.
    """
    return "true"


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
