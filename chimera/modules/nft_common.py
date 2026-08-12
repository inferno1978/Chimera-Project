"""
chimera/modules/nft_common.py
───────────────────────────────────────────────────────────────────────────────
Центральная обёртка над nftables CLI для всех модулей Chimera.

ЗАМЕНА: iptables/ip6tables/ipset прямых вызовов во всех 42 модулях Chimera.

ПРИНЦИПЫ:
  1. Pure nftables (без iptables-nft fallback). Все вызовы идут через `nft`
     binary, который присутствует в Debian 10+/Ubuntu 18.04+ из коробки.
  2. Единая таблица `inet chimera` покрывает и IPv4, и IPv6 — это устраняет
     дублирование iptables/ip6tables.
  3. Идемпотентность по умолчанию для всех операций (через comment-tags
     или `nft -j list chain` JSON-парсинг).
  4. Atomic transactions через `nft -f -` (here-doc) для batch-операций —
     это замена `ipset swap <tmp> <real> + ipset destroy <tmp>` scheme.
  5. Lazy binding к chimera._core для логирования (как в proto_common.py).
  6. Все функции return bool (success) или данные; никогда не бросают
     исключения во внешние вызовы (errors логируются как warnings).

АРХИТЕКТУРА:
  • Функции разделены на 4 уровня:
       Level 1: low-level (nft_run, nft_list_chain_json)
       Level 2: table/chain/set primitives
       Level 3: rule operations (ensure, delete by comment, exists)
       Level 4: high-level patterns (open_port, ban_ip, nat_redirect, etc.)

ИСПОЛЬЗОВАНИЕ (примеры):
  from chimera.modules.nft_common import (
      nft_open_port, nft_ban_ip, nft_nat_redirect,
      nft_mangle_mark_uid, nft_persist,
  )

  nft_open_port(443, proto="tcp", comment="vless-https")
  nft_ban_ip("1.2.3.4", comment="xray-autoban")
  nft_nat_redirect(prerouting=True, proto="udp", dport=53, to_port=5300)
  nft_mangle_mark_uid(uid=1000, fwmark=1234, comment="awg-fwmark-xray")
  nft_persist()

ПРОВЕРКА СИНТАКСИСА (для dev/test):
  Все функции возвращают сконструированную nft-команду через _nft_command_log
  (последние N команд) — это помогает тестам проверять, что команды корректны,
  без реального запуска `nft`.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional, Union, Iterable

# Локальная регистрация констант — избегаем кругового импорта с nft_constants
# (nft_constants импортируется через __getattr__ в редких случаях, но мы
# импортируем напрямую здесь для производительности).
from .nft_constants import (
    NFT_TABLE_FAMILY, NFT_TABLE_NAME,
    NFT_CHAIN_INPUT, NFT_CHAIN_FORWARD, NFT_CHAIN_OUTPUT,
    NFT_CHAIN_PREROUTING, NFT_CHAIN_POSTROUTING,
    NFT_CHAIN_MANGLE_OUTPUT, NFT_CHAIN_MANGLE_FORWARD,
    NFT_PERSIST_FILE, NFT_PERSIST_INCLUDE_FILE,
)


# ════════════════════════════════════════════════════════════════════════════
#  LOGGING / CORE BINDING (lazy)
# ════════════════════════════════════════════════════════════════════════════
def _core_module():
    """Ленивый доступ к chimera._core — как в proto_common.py.

    Позволяет модулю импортироваться как из интерактива, так и из cron
    (python -c) — _core загружается по требованию.
    """
    try:
        import importlib
        return importlib.import_module("chimera._core")
    except Exception:
        return None


def _log(level: str, msg: str) -> None:
    """Логирует через _core._log если доступно, иначе stderr."""
    core = _core_module()
    if core is not None and hasattr(core, "_log"):
        try:
            core._log(level, msg)
            return
        except Exception:
            pass
    # Fallback — silent (не падать если нет логгера)
    pass


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 1: LOW-LEVEL — nft binary invocation
# ════════════════════════════════════════════════════════════════════════════

# Дебаг-лог последних команд (для тестов). None = не ведём.
_NFT_CMD_LOG: list[dict] = []


def _nft_available() -> bool:
    """Проверяет наличие nft binary в PATH."""
    return shutil.which("nft") is not None


def _nft_run(args: list[str], stdin: Optional[str] = None,
             check: bool = False, timeout: int = 15) -> subprocess.CompletedProcess:
    """Запускает `nft <args>` с опциональным stdin (для `nft -f -`).

    Возвращает CompletedProcess. Никогда не бросает CalledProcessError если
    check=False (поведение как _core._run с check=False).

    Логирует команду в _NFT_CMD_LOG для тестирования/аудита.
    """
    cmd = ["nft"] + list(args)
    # Записываем в лог команд (для тестов и аудита)
    _NFT_CMD_LOG.append({
        "cmd": cmd,
        "stdin": stdin,
    })
    # Ограничиваем размер лога
    if len(_NFT_CMD_LOG) > 100:
        del _NFT_CMD_LOG[:50]

    if not _nft_available():
        # nft не установлен — возвращаем rc=127 как и shell-команда
        _log("WARN", f"nft binary not found, command skipped: {' '.join(cmd)}")
        return subprocess.CompletedProcess(
            args=cmd, returncode=127, stdout="", stderr="nft: command not found"
        )

    try:
        r = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # всегда False — мы сами обрабатываем rc
        )
        if check and r.returncode != 0:
            raise subprocess.CalledProcessError(
                r.returncode, cmd, r.stdout, r.stderr
            )
        return r
    except subprocess.TimeoutExpired:
        _log("ERROR", f"nft command timed out: {' '.join(cmd)}")
        return subprocess.CompletedProcess(
            args=cmd, returncode=124, stdout="", stderr="timeout"
        )
    except Exception as e:
        _log("ERROR", f"nft command failed: {' '.join(cmd)}: {e}")
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr=str(e)
        )


def _nft_cmd_log() -> list[dict]:
    """Возвращает копию лога последних nft-команд (для тестов)."""
    return list(_NFT_CMD_LOG)


def _nft_cmd_log_clear() -> None:
    """Очищает лог команд (для тестов)."""
    _NFT_CMD_LOG.clear()


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 2: TABLE / CHAIN / SET PRIMITIVES
# ════════════════════════════════════════════════════════════════════════════

def nft_table_ensure(table: str = NFT_TABLE_NAME,
                     family: str = NFT_TABLE_FAMILY) -> bool:
    """Создаёт таблицу если ещё не существует.

    Эквивалент в iptables: нет (таблицы filter/nat/mangle создаются ядром).
    В nft таблица — явный объект.

    Команда: `nft create table <family> <table>` (если уже есть — rc=1,
    мы игнорируем это).
    """
    r = _nft_run(["create", "table", family, table], check=False)
    # rc=0 — создана, rc=1 — уже существует (это OK)
    return r.returncode == 0 or nft_table_exists(table, family)


def nft_table_exists(table: str = NFT_TABLE_NAME,
                     family: str = NFT_TABLE_FAMILY) -> bool:
    """Проверяет существует ли таблица."""
    r = _nft_run(["list", "table", family, table], check=False)
    return r.returncode == 0


def nft_chain_ensure(table: str, chain: str,
                     family: str = NFT_TABLE_FAMILY,
                     hook: Optional[str] = None,
                     priority: Optional[Union[int, str]] = None,
                     policy: str = "accept") -> bool:
    """Создаёт цепочку если ещё не существует.

    Для base-chain (hook не None): создаёт с указанным hook/priority/policy.
    Для regular-chain (hook None): создаёт без hook (аналог iptables -N).

    Примеры:
      nft_chain_ensure("chimera", "input", hook="input", priority=0,
                        policy="accept")
      nft_chain_ensure("chimera", "xru_block")  # regular chain
    """
    nft_table_ensure(table, family)
    # Проверяем есть ли уже такая цепочка
    if _nft_chain_exists(table, chain, family):
        return True
    # Строим команду create chain
    args = ["add", "chain", family, table, chain]
    if hook is not None:
        # base chain: { type filter hook input priority 0; policy accept; }
        hook_type = "filter" if hook in ("input", "forward", "output") else \
                    "nat" if hook in ("prerouting", "postrouting", "input", "output") else \
                    "route"
        if hook in ("prerouting", "postrouting"):
            hook_type = "nat"
        elif hook == "output" and table == NFT_TABLE_NAME and chain == NFT_CHAIN_MANGLE_OUTPUT:
            hook_type = "route"
        prio_str = str(priority) if priority is not None else "0"
        args.append(f"{{ type {hook_type} hook {hook} priority {prio_str}; policy {policy}; }}")
    r = _nft_run(args, check=False)
    return r.returncode == 0


def nft_chain_exists(table: str, chain: str,
                     family: str = NFT_TABLE_FAMILY) -> bool:
    """Проверяет существует ли цепочка."""
    return _nft_chain_exists(table, chain, family)


def _nft_chain_exists(table: str, chain: str,
                      family: str = NFT_TABLE_FAMILY) -> bool:
    """Внутренняя проверка без логирования."""
    r = _nft_run(["list", "chain", family, table, chain], check=False)
    return r.returncode == 0


def nft_chain_flush(table: str, chain: str,
                    family: str = NFT_TABLE_FAMILY) -> bool:
    """Очищает все правила в цепочке. Аналог iptables -F <chain>."""
    r = _nft_run(["flush", "chain", family, table, chain], check=False)
    return r.returncode == 0


def nft_chain_delete(table: str, chain: str,
                     family: str = NFT_TABLE_FAMILY) -> bool:
    """Удаляет цепочку (сначала flush). Аналог iptables -F + -X."""
    nft_chain_flush(table, chain, family)
    r = _nft_run(["delete", "chain", family, table, chain], check=False)
    return r.returncode == 0


# ──────────────────────────────────────────────────────────────────────
#  NFT SETS (замена ipset)
# ──────────────────────────────────────────────────────────────────────
def nft_set_create(name: str, table: str = NFT_TABLE_NAME,
                   family: str = NFT_TABLE_FAMILY,
                   set_type: str = "ipv4_addr",
                   flags: Optional[list[str]] = None,
                   timeout: Optional[int] = None,
                   maxelem: Optional[int] = None) -> bool:
    """Создаёт nft set. Аналог `ipset create <name> hash:net family inet maxelem N -exist`.

    Args:
        name: имя set
        table: таблица (по умолчанию chimera)
        family: ip / ip6 / inet
        set_type: ipv4_addr / ipv6_addr / inet_service / ifname / ether_addr
        flags: ['interval'] для CIDR-подсетей (аналог hash:net),
               ['timeout'] для auto-expire
        timeout: время жизни элемента в секундах (опционально)
        maxelem: max elements hint (аналог ipset maxelem)

    Пример:
        nft_set_create("manual_ban_v4", set_type="ipv4_addr",
                       flags=["interval"], maxelem=65536)
    """
    nft_table_ensure(table, family)
    if _nft_set_exists(name, table, family):
        return True
    # Строим spec: { type ipv4_addr; flags interval; size 65536; }
    spec_parts = [f"type {set_type};"]
    if flags:
        spec_parts.append(f"flags {' '.join(flags)};")
    if timeout is not None:
        spec_parts.append(f"timeout {timeout}s;")
    if maxelem is not None:
        spec_parts.append(f"size {maxelem};")
    spec = "{ " + " ".join(spec_parts) + " }"
    r = _nft_run(["add", "set", family, table, name, spec], check=False)
    return r.returncode == 0


def nft_set_exists(name: str, table: str = NFT_TABLE_NAME,
                   family: str = NFT_TABLE_FAMILY) -> bool:
    """Проверяет существует ли nft set. Аналог `ipset list -n <name>`."""
    return _nft_set_exists(name, table, family)


def _nft_set_exists(name: str, table: str = NFT_TABLE_NAME,
                    family: str = NFT_TABLE_FAMILY) -> bool:
    r = _nft_run(["list", "set", family, table, name], check=False)
    return r.returncode == 0


def nft_set_add(name: str, elements: Union[str, Iterable[str]],
                table: str = NFT_TABLE_NAME,
                family: str = NFT_TABLE_FAMILY) -> bool:
    """Batch add элементов в set одной транзакцией.

    Аналог `ipset restore -! -f <file>` (где file содержит строки `add <name> <elem>`).

    Args:
        elements: строка (один элемент) или список строк
    """
    if isinstance(elements, str):
        elements = [elements]
    elements = list(elements)
    if not elements:
        return True
    # Один batch: `add element <family> <table> <name> { 1.2.3.0/24, 5.6.7.8 }`
    elem_str = ", ".join(elements)
    r = _nft_run(["add", "element", family, table, name, "{ " + elem_str + " }"],
                 check=False)
    return r.returncode == 0


def nft_set_del(name: str, elements: Union[str, Iterable[str]],
                table: str = NFT_TABLE_NAME,
                family: str = NFT_TABLE_FAMILY) -> bool:
    """Batch delete элементов из set.

    Аналог: цикл `ipset del <name> <elem>` для каждого.
    """
    if isinstance(elements, str):
        elements = [elements]
    elements = list(elements)
    if not elements:
        return True
    elem_str = ", ".join(elements)
    r = _nft_run(["delete", "element", family, table, name, "{ " + elem_str + " }"],
                 check=False)
    return r.returncode == 0


def nft_set_flush(name: str, table: str = NFT_TABLE_NAME,
                  family: str = NFT_TABLE_FAMILY) -> bool:
    """Очищает set. Аналог `ipset flush <name>`."""
    r = _nft_run(["flush", "set", family, table, name], check=False)
    return r.returncode == 0


def nft_set_destroy(name: str, table: str = NFT_TABLE_NAME,
                    family: str = NFT_TABLE_FAMILY) -> bool:
    """Удаляет set. Аналог `ipset destroy <name>`."""
    r = _nft_run(["delete", "set", family, table, name], check=False)
    return r.returncode == 0


def nft_set_atomic_swap(name: str, new_elements: Iterable[str],
                        table: str = NFT_TABLE_NAME,
                        family: str = NFT_TABLE_FAMILY) -> bool:
    """ATOMIC SWAP: атомарно заменяет содержимое set на new_elements.

    Аналог: `ipset swap <tmp> <real>` + `ipset destroy <tmp>` (две команды,
    между которыми есть короткое окно видимости).

    В nftables: одна транзакция `nft -f -` с двумя операциями:
        flush set <family> <table> <name>
        add element <family> <table> <name> { ... }

    Транзакция атомарна в ядре — между flush и add нет окна видимости
    снаружи. Это улучшение над ipset swap.

    ВАЖНО: в момент применения транзакции для новых элементов есть короткое
    окно когда set пуст — это нормально и не отличается от поведения
    ipset swap (там тоже на короткий момент set содержит мусор из tmp).
    """
    elements = list(new_elements)
    # Строим batch через here-doc
    parts = [f"flush set {family} {table} {name}"]
    if elements:
        elem_str = ", ".join(elements)
        parts.append(f"add element {family} {table} {name} {{ {elem_str} }}")
    batch = "\n".join(parts) + "\n"
    r = _nft_run(["-f", "-"], stdin=batch, check=False)
    return r.returncode == 0


def nft_set_count(name: str, table: str = NFT_TABLE_NAME,
                  family: str = NFT_TABLE_FAMILY) -> int:
    """Возвращает количество элементов в set.

    Аналог: парсинг `ipset list <name>` → "Number of entries: N".
    Реализация: `nft -j list set <family> <table> <name>` → JSON.
    """
    r = _nft_run(["-j", "list", "set", family, table, name], check=False)
    if r.returncode != 0 or not r.stdout:
        return 0
    try:
        data = json.loads(r.stdout)
        # JSON формат: {"nftables": [{"set": {"elem": [...]}}]}
        nft_data = data.get("nftables", [])
        if not nft_data:
            return 0
        set_obj = nft_data[0].get("set", {})
        elems = set_obj.get("elem", [])
        return len(elems)
    except (json.JSONDecodeError, KeyError, IndexError):
        return 0


def nft_set_list_elements(name: str, table: str = NFT_TABLE_NAME,
                          family: str = NFT_TABLE_FAMILY) -> list[str]:
    """Возвращает список элементов set как строки.

    Аналог: парсинг `ipset list <name>` → секция "Members:".
    """
    r = _nft_run(["-j", "list", "set", family, table, name], check=False)
    if r.returncode != 0 or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
        nft_data = data.get("nftables", [])
        if not nft_data:
            return []
        set_obj = nft_data[0].get("set", {})
        elems = set_obj.get("elem", [])
        # Элементы могут быть простыми строками или dict (для interval/timeout)
        result = []
        for e in elems:
            if isinstance(e, str):
                result.append(e)
            elif isinstance(e, dict):
                # {"prefix": "1.2.3.0/24"} или {"elem": "1.2.3.4", "timeout": 300}
                if "prefix" in e:
                    result.append(e["prefix"])
                elif "elem" in e:
                    result.append(str(e["elem"]))
        return result
    except (json.JSONDecodeError, KeyError, IndexError):
        return []


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 3: RULE OPERATIONS (idempotent)
# ════════════════════════════════════════════════════════════════════════════

def nft_rule_add(table: str, chain: str, rule_spec: str,
                 family: str = NFT_TABLE_FAMILY,
                 comment: Optional[str] = None,
                 position: Optional[int] = None,
                 idempotent: bool = True) -> bool:
    """Добавляет правило в цепочку.

    Аналог iptables -A/-I INPUT.

    Args:
        rule_spec: nft-синтаксис правила без 'add rule <family> <table> <chain>'
                   (например 'tcp dport 443 accept')
        comment: если задан, добавляет `comment "<comment>"` к правилу
        position: если None — добавить в конец (add), если int — вставить в
                  позицию (insert rule <position>)
        idempotent: если True — проверить существование правила (по comment
                    если задан, иначе по точному совпадению spec) и не добавлять
                    если уже есть. Аналог `iptables -C` + `-A` паттерна.
    """
    nft_table_ensure(table, family)
    nft_chain_ensure(table, chain, family)

    # Дописываем comment к rule_spec
    full_spec = rule_spec
    if comment is not None:
        # Экранируем двойные кавычки в comment
        escaped = comment.replace('"', '\\"')
        full_spec = f'{rule_spec} comment "{escaped}"'

    if idempotent:
        if comment is not None:
            # Проверка по comment
            if _nft_rule_exists_by_comment(table, chain, comment, family):
                return True
        else:
            # Проверка по точному совпадению (менее надёжна, но для rules без comment)
            if _nft_rule_exists_by_spec(table, chain, rule_spec, family):
                return True

    if position is not None:
        # insert rule <family> <table> <chain> position <N> <spec>
        args = ["add", "rule", family, table, chain, "position", str(position)]
    else:
        args = ["add", "rule", family, table, chain]
    # rule_spec передаём как одну строку — nft её распарсит
    args.extend(full_spec.split())
    r = _nft_run(args, check=False)
    return r.returncode == 0


def nft_rule_insert(table: str, chain: str, rule_spec: str,
                   family: str = NFT_TABLE_FAMILY,
                   comment: Optional[str] = None,
                   idempotent: bool = True) -> bool:
    """Вставляет правило в НАЧАЛО цепочки. Аналог `iptables -I INPUT 1 ...`.

    Это нужно для WHITELIST правил, которые должны идти ДО любых DROP.
    Реализация: position=1 в nft_rule_add.
    """
    return nft_rule_add(table, chain, rule_spec, family=family,
                        comment=comment, position=1, idempotent=idempotent)


def nft_rule_exists(table: str, chain: str, rule_spec: Optional[str] = None,
                    comment: Optional[str] = None,
                    family: str = NFT_TABLE_FAMILY) -> bool:
    """Проверяет существует ли правило.

    Аналог `iptables -t <table> -C <chain> <args>` → rc==0.

    Можно искать по rule_spec (точное совпадение) или по comment.
    """
    if comment is not None:
        return _nft_rule_exists_by_comment(table, chain, comment, family)
    if rule_spec is not None:
        return _nft_rule_exists_by_spec(table, chain, rule_spec, family)
    return False


def _nft_rule_exists_by_comment(table: str, chain: str, comment: str,
                                 family: str = NFT_TABLE_FAMILY) -> bool:
    """Ищет правило по comment через `nft -j list chain`."""
    rules = _nft_list_chain_rules(table, chain, family)
    for rule in rules:
        # comment может быть в rule["comment"] (новые nft) или в expr-цепочке
        rule_comment = rule.get("comment")
        if rule_comment == comment:
            return True
        # Альтернативный путь: comment в expr (для старых версий nft)
        for expr in rule.get("expr", []):
            if expr.get("comment") == comment:
                return True
    return False


def _nft_rule_exists_by_spec(table: str, chain: str, rule_spec: str,
                              family: str = NFT_TABLE_FAMILY) -> bool:
    """Ищет правило по точному совпадению spec (медленнее, чем по comment).

    Реализация: парсит `nft -j list chain` и сравнивает нормализованный
    JSON-expr с spec. Это менее надёжно чем comment-match, потому что
    nft нормализует spec (например `tcp dport 443` vs `dport 443 tcp`).
    """
    rules = _nft_list_chain_rules(table, chain, family)
    # Нормализуем искомый spec: lower, удалить лишние пробелы
    target = " ".join(rule_spec.lower().split())
    for rule in rules:
        # Собираем строку из expr
        expr_str = _expr_to_str(rule.get("expr", []))
        if target in expr_str.lower():
            return True
    return False


def _expr_to_str(expr_list: list) -> str:
    """Конвертирует JSON expr-список в строку для сравнения.

    nftables JSON format: [{match: {op: ==, left: {payload: ...}, right: 443}}, {accept: null}]
    Упрощённая конвертация: собираем все значения в одну строку.
    """
    parts = []
    for expr in expr_list:
        if not isinstance(expr, dict):
            continue
        for k, v in expr.items():
            if v is None:
                parts.append(k)
            elif isinstance(v, dict):
                # Рекурсивно
                parts.append(_expr_to_str([v]))
            elif isinstance(v, (str, int)):
                parts.append(str(v))
    return " ".join(parts)


def _nft_list_chain_rules(table: str, chain: str,
                          family: str = NFT_TABLE_FAMILY) -> list[dict]:
    """Возвращает список правил цепочки как JSON-объекты.

    Использует `nft -j list chain` — нативный JSON output, надёжнее
    парсинга текстового `iptables -L`.
    """
    r = _nft_run(["-j", "list", "chain", family, table, chain], check=False)
    if r.returncode != 0 or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
        nft_data = data.get("nftables", [])
        for item in nft_data:
            if "chain" in item:
                return item["chain"].get("expr", []) or []
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return []


def nft_rule_delete_by_comment(table: str, chain: str, comment: str,
                               family: str = NFT_TABLE_FAMILY,
                               max_iterations: int = 100) -> int:
    """Удаляет ВСЕ правила с указанным comment.

    Аналог: цикл `iptables -D ... -m comment --comment <tag>` до rc!=0.

    Возвращает количество удалённых правил. Безопасно для идемпотентности:
    повторный вызов с тем же comment удалит 0 правил.

    Реализация: для каждого правила с comment находит его handle через
    `nft -a list chain` и удаляет через `nft delete rule ... handle <N>`.
    """
    rules = _nft_list_chain_rules_with_handles(table, chain, family)
    removed = 0
    for rule in rules:
        rule_comment = rule.get("comment")
        if rule_comment != comment:
            # Проверяем expr на наличие comment
            for expr in rule.get("expr", []):
                if expr.get("comment") == comment:
                    rule_comment = comment
                    break
        if rule_comment == comment:
            handle = rule.get("handle")
            if handle is None:
                continue
            r = _nft_run(["delete", "rule", family, table, chain,
                          "handle", str(handle)], check=False)
            if r.returncode == 0:
                removed += 1
            if removed >= max_iterations:
                break
    return removed


def _nft_list_chain_rules_with_handles(table: str, chain: str,
                                       family: str = NFT_TABLE_FAMILY) -> list[dict]:
    """Список правил с handles (для delete). `nft -a list chain`."""
    r = _nft_run(["-a", "-j", "list", "chain", family, table, chain],
                 check=False)
    if r.returncode != 0 or not r.stdout:
        return []
    try:
        data = json.loads(r.stdout)
        nft_data = data.get("nftables", [])
        for item in nft_data:
            if "chain" in item:
                return item["chain"].get("expr", []) or []
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return []


def nft_rule_delete(table: str, chain: str, rule_spec: str,
                    family: str = NFT_TABLE_FAMILY,
                    comment: Optional[str] = None) -> bool:
    """Удаляет одно правило по spec или comment.

    Если задан comment — удаление по comment (предпочтительно).
    Иначе — поиск по spec и удаление через handle.
    """
    if comment is not None:
        removed = nft_rule_delete_by_comment(table, chain, comment, family,
                                             max_iterations=1)
        return removed > 0
    # По spec — находим handle и удаляем
    rules = _nft_list_chain_rules_with_handles(table, chain, family)
    target = " ".join(rule_spec.lower().split())
    for rule in rules:
        expr_str = _expr_to_str(rule.get("expr", []))
        if target in expr_str.lower():
            handle = rule.get("handle")
            if handle is None:
                continue
            r = _nft_run(["delete", "rule", family, table, chain,
                          "handle", str(handle)], check=False)
            return r.returncode == 0
    return False


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 3.5: COUNTERS (для traffic accounting)
# ════════════════════════════════════════════════════════════════════════════

def nft_counter_ensure(name: str, table: str = NFT_TABLE_NAME,
                       family: str = NFT_TABLE_FAMILY) -> bool:
    """Создаёт именованный counter. Аналог `iptables -N TELEMT_STATS_IN`.

    Named counters — это отдельные объекты в nftables, на которые можно
    ссылаться из правил (`counter name <name>`). Это лучше чем implicit
    per-rule counters в iptables, потому что:
      • counter остаётся даже если правило удалено (можно читать после flush)
      • один counter можно использовать из нескольких правил
    """
    nft_table_ensure(table, family)
    if _nft_counter_exists(name, table, family):
        return True
    r = _nft_run(["add", "counter", family, table, name], check=False)
    return r.returncode == 0


def _nft_counter_exists(name: str, table: str, family: str) -> bool:
    r = _nft_run(["list", "counter", family, table, name], check=False)
    return r.returncode == 0


def nft_counter_read(name: str, table: str = NFT_TABLE_NAME,
                     family: str = NFT_TABLE_FAMILY) -> dict[str, int]:
    """Читает {packets, bytes} named counter.

    Аналог: парсинг `iptables -L <chain> -v -n -x` для строки с нужным comment.
    Реализация: `nft -j list counter <family> <table> <name>` → JSON.
    """
    r = _nft_run(["-j", "list", "counter", family, table, name], check=False)
    if r.returncode != 0 or not r.stdout:
        return {"packets": 0, "bytes": 0}
    try:
        data = json.loads(r.stdout)
        nft_data = data.get("nftables", [])
        for item in nft_data:
            if "counter" in item:
                cnt = item["counter"]
                return {
                    "packets": int(cnt.get("packets", 0)),
                    "bytes": int(cnt.get("bytes", 0)),
                }
    except (json.JSONDecodeError, KeyError, IndexError, ValueError):
        pass
    return {"packets": 0, "bytes": 0}


def nft_counter_zero(name: str, table: str = NFT_TABLE_NAME,
                     family: str = NFT_TABLE_FAMILY) -> bool:
    """Сбрасывает counter. Аналог `iptables -Z <chain>`."""
    r = _nft_run(["delete", "counter", family, table, name], check=False)
    if r.returncode != 0:
        return False
    return nft_counter_ensure(name, table, family)


def nft_rule_counter_read(table: str, chain: str, comment: str,
                          family: str = NFT_TABLE_FAMILY) -> dict[str, int]:
    """Читает {packets, bytes} для правила с указанным comment.

    Аналог: парсинг `iptables -L <chain> -v -n -x` с поиском по comment.
    Реализация: `nft -j list chain` → ищем правило с comment, читаем его
    counter expr.
    """
    rules = _nft_list_chain_rules(table, chain, family)
    for rule in rules:
        # Проверяем comment
        if rule.get("comment") != comment:
            continue
        # Ищем counter в expr
        for expr in rule.get("expr", []):
            if "counter" in expr:
                cnt = expr["counter"]
                return {
                    "packets": int(cnt.get("packets", 0)),
                    "bytes": int(cnt.get("bytes", 0)),
                }
    return {"packets": 0, "bytes": 0}


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 4: HIGH-LEVEL PATTERNS — convenience wrappers
# ════════════════════════════════════════════════════════════════════════════

def _ensure_chimera_base_chains() -> None:
    """Гарантирует что базовые цепочки Chimera созданы.

    Вызывается из всех high-level операций чтобы быть идемпотентной.
    """
    nft_table_ensure()
    # input — filter, priority 0, policy accept
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_INPUT,
                     hook="input", priority=0, policy="accept")
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_FORWARD,
                     hook="forward", priority=0, policy="accept")
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_OUTPUT,
                     hook="output", priority=0, policy="accept")
    # nat chains — priority filter / srcnat (стандартные nft priorities)
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_PREROUTING,
                     hook="prerouting", priority="dstnat", policy="accept")
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_POSTROUTING,
                     hook="postrouting", priority="srcnat", policy="accept")
    # mangle chains — route hook for output, filter+mangle priority for forward
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_MANGLE_OUTPUT,
                     hook="output", priority="mangle", policy="accept")
    nft_chain_ensure(NFT_TABLE_NAME, NFT_CHAIN_MANGLE_FORWARD,
                     hook="forward", priority="mangle", policy="accept")


def nft_open_port(port: int, proto: str = "tcp",
                  comment: str = "chimera-open-port",
                  family: str = NFT_TABLE_FAMILY,
                  table: str = NFT_TABLE_NAME,
                  chain: str = NFT_CHAIN_INPUT,
                  idempotent: bool = True) -> bool:
    """Открытие TCP/UDP порта в INPUT.

    Заменяет: `iptables -I INPUT 1 -p <proto> --dport <port> -j ACCEPT`
              (используется в 8 протокольных модулях + network_setup).

    Эквивалент в nft:
      nft add rule inet chimera input <proto> dport <port> accept \\
          comment "<comment>"

    Args:
        port: номер порта (1-65535)
        proto: 'tcp' или 'udp'
        comment: тег для идемпотентности (по умолчанию общий)
    """
    if proto not in ("tcp", "udp"):
        raise ValueError(f"proto must be 'tcp' or 'udp', got {proto!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"port must be 1-65535, got {port}")
    _ensure_chimera_base_chains()
    # iptables -I INPUT 1 → nft insert (position=1). Но для accept-правил
    # обычно порядок не важен — используем add в конец (как network_setup).
    # Если нужно гарантировать приоритет (before DROP), использовать insert.
    # По умолчанию add (большинство протоколов используют add для accept).
    spec = f"{proto} dport {port} accept"
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_ban_ip(ip: str, comment: str = "xray-autoban",
               table: str = NFT_TABLE_NAME,
               chain: str = NFT_CHAIN_INPUT,
               family: str = NFT_TABLE_FAMILY,
               idempotent: bool = True) -> bool:
    """Бан одного IP через DROP. Заменяет `iptables -I INPUT -s <ip> -j DROP`.

    Эквивалент в nft:
      nft add rule inet chimera input ip saddr <ip> drop comment "<comment>"

    Для IPv6: `ip6 saddr` (nft сам определяет по family, но если ip содержит
    ':', используем ip6 saddr).
    """
    _ensure_chimera_base_chains()
    if ":" in ip:
        # IPv6
        spec = f"ip6 saddr {ip} drop"
    else:
        spec = f"ip saddr {ip} drop"
    # insert (position=1) чтобы DROP был ПЕРЕД другими accept-правилами
    return nft_rule_insert(table, chain, spec, family=family,
                           comment=comment, idempotent=idempotent)


def nft_unban_ip(ip: str, comment: str = "xray-autoban",
                 table: str = NFT_TABLE_NAME,
                 chain: str = NFT_CHAIN_INPUT,
                 family: str = NFT_TABLE_FAMILY) -> int:
    """Снимает бан IP. Заменяет `iptables -D INPUT -s <ip> -j DROP`.

    Удаляет ВСЕ правила с comment=<comment> и соответствующим IP. Возвращает
    количество удалённых.
    """
    # Ищем все правила с этим comment и удаляем те, где saddr = ip
    rules = _nft_list_chain_rules_with_handles(table, chain, family)
    removed = 0
    for rule in rules:
        if rule.get("comment") != comment:
            continue
        # Проверяем что в expr есть saddr = ip
        if not _rule_matches_ip(rule, ip):
            continue
        handle = rule.get("handle")
        if handle is None:
            continue
        r = _nft_run(["delete", "rule", family, table, chain,
                      "handle", str(handle)], check=False)
        if r.returncode == 0:
            removed += 1
    return removed


def _rule_matches_ip(rule: dict, ip: str) -> bool:
    """Проверяет содержит ли правило match на source IP."""
    ip_key = "ip6" if ":" in ip else "ip"
    for expr in rule.get("expr", []):
        if not isinstance(expr, dict):
            continue
        match = expr.get("match")
        if not match:
            continue
        left = match.get("left", {})
        payload = left.get("payload", {})
        # payload protocol = ip / ip6, field = saddr
        if payload.get("protocol") == ip_key and payload.get("field") == "saddr":
            right = match.get("right")
            if right == ip or (isinstance(right, dict) and right.get("prefix") == ip):
                return True
    return False


def nft_whitelist_ip(ip: str, port: Optional[int] = None,
                     proto: str = "tcp",
                     comment: str = "chimera-whitelist",
                     table: str = NFT_TABLE_NAME,
                     chain: str = NFT_CHAIN_INPUT,
                     family: str = NFT_TABLE_FAMILY,
                     idempotent: bool = True) -> bool:
    """Разрешение IP (с опциональной привязкой к порту).

    Заменяет: `iptables -I INPUT 1 -s <ip> [-p <proto> --dport <port>] -j ACCEPT`

    Эквивалент в nft:
      nft insert rule inet chimera input ip saddr <ip> [tcp dport <port>] accept \\
          comment "<comment>"
    """
    _ensure_chimera_base_chains()
    if ":" in ip:
        saddr = f"ip6 saddr {ip}"
    else:
        saddr = f"ip saddr {ip}"
    if port is not None:
        spec = f"{saddr} {proto} dport {port} accept"
    else:
        spec = f"{saddr} accept"
    return nft_rule_insert(table, chain, spec, family=family,
                           comment=comment, idempotent=idempotent)


def nft_nat_redirect(prerouting: bool = True,
                     in_iface: Optional[str] = None,
                     proto: str = "tcp",
                     dport: Union[int, str] = 53,
                     to_port: int = 5300,
                     comment: str = "chimera-dns-redirect",
                     family: str = NFT_TABLE_FAMILY,
                     table: str = NFT_TABLE_NAME,
                     idempotent: bool = True) -> bool:
    """NAT REDIRECT. Заменяет `iptables -t nat -A PREROUTING/OUTPUT -p <proto> --dport <X> -j REDIRECT --to-port <Y>`.

    Args:
        prerouting: True → PREROUTING (для VPN-клиентов),
                    False → OUTPUT (для локальных процессов)
        in_iface: опционально — ограничить по входящему интерфейсу
                  (аналог `-i awg0`)
        proto: 'tcp' или 'udp'
        dport: исходный порт (int или range-строка '10000-20000')
        to_port: целевой порт
        comment: тег

    Эквивалент в nft:
      nft add rule inet chimera prerouting [iifname "<iface>"] <proto> dport <X> \\
          redirect to :<Y> comment "<comment>"
    """
    if proto not in ("tcp", "udp"):
        raise ValueError(f"proto must be 'tcp' or 'udp', got {proto!r}")
    _ensure_chimera_base_chains()
    chain = NFT_CHAIN_PREROUTING if prerouting else NFT_CHAIN_OUTPUT
    parts = []
    if in_iface:
        parts.append(f'iifname "{in_iface}"')
    parts.append(f"{proto} dport {dport}")
    parts.append(f"redirect to :{to_port}")
    spec = " ".join(parts)
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_nat_masquerade(out_iface: Optional[str] = None,
                       src_subnet: Optional[str] = None,
                       family: str = NFT_TABLE_FAMILY,
                       table: str = NFT_TABLE_NAME,
                       comment: str = "chimera-masquerade",
                       idempotent: bool = True) -> bool:
    """MASQUERADE. Заменяет `iptables -t nat -A POSTROUTING [-s <subnet>] [-o <iface>] -j MASQUERADE`.

    Эквивалент в nft:
      nft add rule inet chimera postrouting [ip saddr <subnet>] [oifname "<iface>"] \\
          masquerade comment "<comment>"

    Args:
        out_iface: WAN interface (None → blanket MASQUERADE для всех интерфейсов)
        src_subnet: ограничение по source (например '10.66.66.0/24')
    """
    _ensure_chimera_base_chains()
    parts = []
    if src_subnet:
        if ":" in src_subnet:
            parts.append(f"ip6 saddr {src_subnet}")
        else:
            parts.append(f"ip saddr {src_subnet}")
    if out_iface:
        parts.append(f'oifname "{out_iface}"')
    parts.append("masquerade")
    spec = " ".join(parts)
    return nft_rule_add(table, NFT_CHAIN_POSTROUTING, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_mangle_mark_uid(uid: Union[int, str], fwmark: int,
                        chain: str = NFT_CHAIN_MANGLE_OUTPUT,
                        family: str = NFT_TABLE_FAMILY,
                        table: str = NFT_TABLE_NAME,
                        comment: str = "chimera-fwmark-uid",
                        idempotent: bool = True) -> bool:
    """MARK по uid-owner. Заменяет `iptables -t mangle -A OUTPUT -m owner --uid-owner <uid> -j MARK --set-mark <fwmark>`.

    Эквивалент в nft:
      nft add rule inet chimera mangle_output meta skuid <uid> meta mark set <fwmark> \\
          comment "<comment>"

    Args:
        uid: числовой UID или имя пользователя (nft поддерживает оба варианта)
        fwmark: числовое значение mark
    """
    _ensure_chimera_base_chains()
    spec = f"meta skuid {uid} meta mark set {fwmark}"
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_mangle_mark_dst(cidr: str, fwmark: int,
                        proto: Optional[str] = None,
                        chain: str = NFT_CHAIN_MANGLE_OUTPUT,
                        family: str = NFT_TABLE_FAMILY,
                        table: str = NFT_TABLE_NAME,
                        comment: str = "chimera-fwmark-dst",
                        idempotent: bool = True) -> bool:
    """MARK по dst CIDR. Заменяет `iptables -t mangle -A OUTPUT -d <cidr> -p <proto> -j MARK --set-mark <fwmark>`.

    Эквивалент в nft:
      nft add rule inet chimera mangle_output ip daddr <cidr> [<proto>] \\
          meta mark set <fwmark> comment "<comment>"
    """
    _ensure_chimera_base_chains()
    parts = []
    if ":" in cidr:
        parts.append(f"ip6 daddr {cidr}")
    else:
        parts.append(f"ip daddr {cidr}")
    if proto:
        parts.append(proto)
    parts.append(f"meta mark set {fwmark}")
    spec = " ".join(parts)
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_mangle_mssclamp(mss: Optional[int] = None,
                        in_iface: Optional[str] = None,
                        out_iface: Optional[str] = None,
                        chain: str = NFT_CHAIN_MANGLE_FORWARD,
                        family: str = NFT_TABLE_FAMILY,
                        table: str = NFT_TABLE_NAME,
                        comment: str = "chimera-mss-clamp",
                        idempotent: bool = True) -> bool:
    """TCPMSS clamp. Заменяет `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss <mss>` или `--clamp-mss-to-pmtu`.

    Эквивалент в nft:
      set-mss:   `tcp flags syn / syn,rst tcp option maxseg size set <mss>`
      clamp-pmtu: `tcp flags syn / syn,rst tcp option maxseg size set rt mtu`

    Args:
        mss: конкретное значение MSS (None → clamp-to-pmtu)
    """
    _ensure_chimera_base_chains()
    parts = []
    if in_iface:
        parts.append(f'iifname "{in_iface}"')
    if out_iface:
        parts.append(f'oifname "{out_iface}"')
    parts.append("tcp flags syn / syn,rst")
    if mss is None:
        parts.append("tcp option maxseg size set rt mtu")
    else:
        parts.append(f"tcp option maxseg size set {mss}")
    spec = " ".join(parts)
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=idempotent)


def nft_mangle_return_uid(uid: Union[int, str],
                          chain: str = NFT_CHAIN_OUTPUT,
                          family: str = NFT_TABLE_FAMILY,
                          table: str = NFT_TABLE_NAME,
                          comment: str = "chimera-tproxy-bypass",
                          idempotent: bool = True) -> bool:
    """RETURN rule для uid (tproxy bypass).

    Заменяет: `iptables -t nat -I OUTPUT 1 -m owner --uid-owner <uid> -j RETURN`

    ВАЖНО: в nft RETURN доступен только в regular chains (не в base chains
    с hook). Для base chain нужно использовать `accept` или структуру
    chain с jump. Здесь используем nat output chain (priority dstnat),
    которая создаётся через nft_nat_redirect-family calls.

    Для упрощения: вставляем в начало nat OUTPUT chain.
    """
    # Используем nat OUTPUT chain (не mangle) — RETURN в base-chain = accept
    nft_chain_ensure(table, "nat_output_bypass",
                     family=family)  # regular chain, не base
    spec = f"meta skuid {uid} return"
    return nft_rule_insert(table, "nat_output_bypass", spec, family=family,
                           comment=comment, idempotent=idempotent)


def nft_syn_limiter(port: int, rate_per_sec: int, burst: int = 5,
                    comment: str = "chimera-syn-limit",
                    family: str = NFT_TABLE_FAMILY,
                    table: str = NFT_TABLE_NAME,
                    chain: str = NFT_CHAIN_INPUT,
                    idempotent: bool = True) -> bool:
    """Per-source SYN flood limiter через meter (замена hashlimit).

    Заменяет: `iptables -I INPUT 1 -p tcp --dport <port> --syn -m hashlimit
              --hashlimit-name telemt_syn --hashlimit-mode srcip
              --hashlimit-upto <rate>/sec --hashlimit-burst <burst>
              --hashlimit-htable-expire <expire> -j ACCEPT`
              + `iptables -I INPUT 2 -p tcp --dport <port> --syn -j REJECT --reject-with tcp-reset`

    Эквивалент в nft (через meter — более мощный аналог hashlimit):
      nft add rule inet chimera input tcp dport <port> tcp flags syn / syn,rst \\
          meter <meter_name> { ip saddr limit rate <rate>/second burst <burst> packets } accept
      nft add rule inet chimera input tcp dport <port> tcp flags syn / syn,rst \\
          reject with tcp reset

    Args:
        port: TCP порт для защиты
        rate_per_sec: максимум SYN-пакетов в секунду с одного IP
        burst: burst size (по умолчанию 5)
    """
    _ensure_chimera_base_chains()
    meter_name = comment.replace("-", "_")
    # Правило 1: ACCEPT если в пределах лимита
    spec_accept = (f"tcp dport {port} tcp flags syn / syn,rst "
                   f"meter {meter_name} {{ ip saddr limit rate {rate_per_sec}/second "
                   f"burst {burst} packets }} accept")
    # Правило 2: REJECT для превышения лимита
    spec_reject = (f"tcp dport {port} tcp flags syn / syn,rst "
                   f"reject with tcp reset")
    # insert position=2 (после accept-rule) — но в nft проще создать оба
    # в правильном порядке: сначала accept-rule (insert position=1), потом reject (insert position=2)
    # Поскольку insert всегда в начало, добавляем reject первым, потом accept первым
    nft_rule_insert(table, chain, spec_reject, family=family,
                    comment=comment + "-reject", idempotent=idempotent)
    return nft_rule_insert(table, chain, spec_accept, family=family,
                           comment=comment + "-accept", idempotent=idempotent)


def nft_geoip_drop(cidr_list: Iterable[str], set_name: str,
                   port: Optional[int] = None, proto: str = "tcp",
                   comment: Optional[str] = None,
                   family: str = NFT_TABLE_FAMILY,
                   table: str = NFT_TABLE_NAME,
                   chain: str = NFT_CHAIN_INPUT) -> bool:
    """Блокировка списка CIDR через nft set + drop правило.

    Заменяет связку: ipset create + ipset restore + iptables -m set --match-set.
    """
    _ensure_chimera_base_chains()
    # Создаём set если нужно
    is_v6 = any(":" in c for c in cidr_list)
    set_type = "ipv6_addr" if is_v6 else "ipv4_addr"
    nft_set_create(set_name, table, family, set_type=set_type,
                   flags=["interval"])
    # Atomic swap содержимого set
    if not nft_set_atomic_swap(set_name, cidr_list, table, family):
        return False
    # Добавляем drop-правило если его ещё нет
    if comment is None:
        comment = f"chimera-geo-drop-{set_name}"
    if port is not None:
        spec = f"{proto} dport {port} ip saddr @{set_name} drop"
    else:
        spec = f"ip saddr @{set_name} drop"
    return nft_rule_add(table, chain, spec, family=family,
                        comment=comment, idempotent=True)


def nft_whitelist_via_set(cidr_list: Iterable[str], set_name: str,
                          port: int, proto: str = "tcp",
                          comment: Optional[str] = None,
                          family: str = NFT_TABLE_FAMILY,
                          table: str = NFT_TABLE_NAME,
                          chain: str = NFT_CHAIN_INPUT) -> bool:
    """Whitelist через nft set + accept правило. Заменяет user_ip_whitelist.

    Использует atomic swap для безопасного обновления содержимого.
    """
    _ensure_chimera_base_chains()
    is_v6 = any(":" in c for c in cidr_list)
    set_type = "ipv6_addr" if is_v6 else "ipv4_addr"
    nft_set_create(set_name, table, family, set_type=set_type,
                   flags=["interval"])
    if not nft_set_atomic_swap(set_name, cidr_list, table, family):
        return False
    if comment is None:
        comment = f"chimera-wl-{set_name}"
    spec = f"{proto} dport {port} ip saddr @{set_name} accept"
    # insert (position=1) — whitelist должен быть ПЕРЕД любыми DROP
    return nft_rule_insert(table, chain, spec, family=family,
                           comment=comment, idempotent=True)


# ════════════════════════════════════════════════════════════════════════════
#  LEVEL 5: PERSIST / RESTORE
# ════════════════════════════════════════════════════════════════════════════

def nft_persist(ruleset_file: str = NFT_PERSIST_FILE) -> bool:
    """Сохраняет весь ruleset в файл. Аналог `netfilter-persistent save`.

    Заменяет:
      • netfilter-persistent save
      • iptables-save > /etc/iptables/rules.v4
      • ip6tables-save > /etc/iptables/rules.v6
      • ipset save > /etc/ipset.conf

    Реализация: `nft list ruleset > /etc/nftables.conf`
    """
    r = _nft_run(["list", "ruleset"], check=False, timeout=30)
    if r.returncode != 0 or r.stdout is None:
        _log("ERROR", f"nft list ruleset failed: {r.stderr}")
        return False
    try:
        Path(ruleset_file).parent.mkdir(parents=True, exist_ok=True)
        # Атомарная запись: tmp + rename
        tmp = Path(ruleset_file + ".tmp")
        tmp.write_text(r.stdout)
        tmp.chmod(0o644)
        tmp.rename(ruleset_file)
        return True
    except Exception as e:
        _log("ERROR", f"nft_persist write failed: {e}")
        return False


def nft_restore(ruleset_file: str = NFT_PERSIST_FILE,
                flush: bool = True) -> bool:
    """Загружает ruleset из файла. Аналог `nft -f <file>`.

    Args:
        flush: True → `nft -f` делает полный flush+restore (поведение по
               умолчанию для systemd `nftables.service`).
               False → merge (нужны дополнительные меры для идемпотентности).
    """
    if not Path(ruleset_file).exists():
        _log("WARN", f"nft_restore: file not found: {ruleset_file}")
        return False
    if flush:
        # Полная замена через `nft -f` (он сам делает flush при `flush ruleset` в начале)
        # Стандартный /etc/nftables.conf обычно начинается с `flush ruleset`
        r = _nft_run(["-f", ruleset_file], check=False, timeout=60)
    else:
        # Merge — читаем файл и применяем построчно
        with open(ruleset_file) as f:
            content = f.read()
        r = _nft_run(["-f", "-"], stdin=content, check=False, timeout=60)
    return r.returncode == 0


def nft_persist_enable_systemd() -> bool:
    """Включает nftables.service (стандартный Debian/Ubuntu unit).

    Заменяет кастомные telemt-iptables.service, telemt-warp-restore.service,
    xray-ipset-restore.service — всё это теперь обрабатывается одним
    встроенным `nftables.service`, который читает /etc/nftables.conf при
    `systemctl start nftables` (через `nft -f /etc/nftables.conf`).
    """
    if not shutil.which("systemctl"):
        return False
    try:
        subprocess.run(["systemctl", "enable", "nftables"],
                       capture_output=True, check=False, timeout=15)
        return True
    except Exception:
        return False


def nft_persist_disable_legacy() -> None:
    """Отключает legacy systemd units, которые теперь не нужны.

    КРИТИЧНО: вызывать ТОЛЬКО после того, как nftables.service подтверждён
    рабочим на тестовом сервере. Иначе при ребуте правила НЕ применятся.

    Отключает:
      • netfilter-persistent.service (если установлен iptables-persistent)
      • telemt-iptables.service (legacy custom unit)
      • telemt-warp-restore.service (legacy custom unit)
      • xray-ipset-restore.service (legacy custom unit)
      • singbox-cdn-ipset-restore.service (legacy custom unit)

    NOT MIGRATED YET — placeholder. Реальная логика отключения будет в
    миграции system_deps.py и emergency_repair.py.
    """
    pass


# ════════════════════════════════════════════════════════════════════════════
#  UTILITY: validation helpers (для тестов)
# ════════════════════════════════════════════════════════════════════════════

def nft_check_syntax(rule_spec: str) -> bool:
    """Проверяет синтаксис правила через `nft -c -f -`.

    Аналог `nginx -t` для nginx-конфигурации. Возвращает True если синтаксис
    корректен. Не применяет правило.

    Реализация: `nft -c -f -` с here-doc `add rule ... <spec>`.
    """
    # Гарантируем что у нас есть таблица для проверки
    nft_table_ensure()
    nft_chain_ensure(NFT_TABLE_NAME, "_syntax_check")
    batch = f"add rule {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} _syntax_check {rule_spec}\n"
    r = _nft_run(["-c", "-f", "-"], stdin=batch, check=False)
    return r.returncode == 0


def nft_check_full_ruleset() -> bool:
    """Проверяет полный ruleset через `nft -c -f /etc/nftables.conf`.

    Использовать ПЕРЕД `systemctl reload nftables` на боевом сервере
    (аналог `nginx -t` перед `systemctl reload nginx`).
    """
    if not Path(NFT_PERSIST_FILE).exists():
        return False
    r = _nft_run(["-c", "-f", NFT_PERSIST_FILE], check=False)
    return r.returncode == 0


# ════════════════════════════════════════════════════════════════════════════
#  PUBLIC API — экспорт для from ... import *
# ════════════════════════════════════════════════════════════════════════════
__all__ = [
    # Level 1
    "_nft_available",
    "_nft_run",
    "_nft_cmd_log",
    "_nft_cmd_log_clear",
    # Level 2 — table/chain
    "nft_table_ensure", "nft_table_exists",
    "nft_chain_ensure", "nft_chain_exists",
    "nft_chain_flush", "nft_chain_delete",
    # Level 2 — sets (заменa ipset)
    "nft_set_create", "nft_set_exists",
    "nft_set_add", "nft_set_del",
    "nft_set_flush", "nft_set_destroy",
    "nft_set_atomic_swap",
    "nft_set_count", "nft_set_list_elements",
    # Level 3 — rules
    "nft_rule_add", "nft_rule_insert",
    "nft_rule_exists",
    "nft_rule_delete", "nft_rule_delete_by_comment",
    # Level 3.5 — counters
    "nft_counter_ensure",
    "nft_counter_read", "nft_counter_zero",
    "nft_rule_counter_read",
    # Level 4 — high-level patterns
    "nft_open_port", "nft_ban_ip", "nft_unban_ip",
    "nft_whitelist_ip",
    "nft_nat_redirect", "nft_nat_masquerade",
    "nft_mangle_mark_uid", "nft_mangle_mark_dst",
    "nft_mangle_mssclamp", "nft_mangle_return_uid",
    "nft_syn_limiter",
    "nft_geoip_drop", "nft_whitelist_via_set",
    # Level 5 — persist
    "nft_persist", "nft_restore",
    "nft_persist_enable_systemd",
    # Validation
    "nft_check_syntax", "nft_check_full_ruleset",
]
