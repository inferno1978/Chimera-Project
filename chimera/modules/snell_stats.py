"""
chimera/modules/snell_stats.py
───────────────────────────────────────────────────────────────────────────────
Per-user traffic accounting для Snell v4 через iptables chains.

Архитектура (по аналогии с mtproto_stats.py):
  - Две глобальные цепочки: SNELL_STATS_IN (входящий), SNELL_STATS_OUT (исходящий)
  - Для каждого per-user порта добавляются правила:
      iptables -A SNELL_STATS_IN  -p tcp --dport <port> -m comment --comment "snell-<user>-rx" -j RETURN
      iptables -A SNELL_STATS_OUT -p tcp --sport <port> -m comment --comment "snell-<user>-tx" -j RETURN
  - INPUT  → SNELL_STATS_IN  (для всех tcp-пакетов на per-user порты)
  - OUTPUT → SNELL_STATS_OUT (для всех tcp-пакетов с per-user портов)
  - Чтение: iptables -L SNELL_STATS_IN -v -n -x, парсинг по comment-тегу
  - Cron: ночной сброс счётчиков (00:00) для статистики «за сегодня»

Конкуренция с другими модулями:
  - цепочки SNELL_STATS_* уникальны (TELEMT_STATS_* / MITA_STATS_* не конфликтуют)
  - UFW и iptables-правила из других модулей не трогаем — только добавляем
    свои цепочки в INPUT/OUTPUT (один jump на цепочку, без дублирования)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Optional

# ─── Константы ───────────────────────────────────────────────────────────────
STATS_FILE   = Path("/var/lib/xray-installer/snell_stats.json")
CONFIG_DIR   = Path("/etc/snell")
CRON_FILE    = Path("/etc/cron.d/snell-stats")
CHAIN_IN     = "SNELL_STATS_IN"
CHAIN_OUT    = "SNELL_STATS_OUT"
SERVICE_NAME = "snell"

# Comment-prefix для per-user правил. Формат: "snell-<username>-rx" / "snell-<username>-tx"
# Используется для парсинга: ищем comment-тег, чтобы сопоставить байты с юзером.
COMMENT_PREFIX_RX = "snell-"
COMMENT_SUFFIX_RX = "-rx"
COMMENT_SUFFIX_TX = "-tx"


def _run(cmd: list, capture: bool = False, check: bool = False):
    """Локальный subprocess.run — не зависит от chimera._core (для изоляции).

    Возвращает CompletedProcess с stdout/stderr как строки (text=True).
    """
    kw = {"check": check, "text": True, "capture_output": capture}
    try:
        return subprocess.run(cmd, **kw)
    except FileNotFoundError:
        # Команда не найдена (например, iptables не установлен).
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="")


def _ipt_chain_exists(chain: str) -> bool:
    """Проверяет существует ли цепочка в таблице filter."""
    r = _run(["iptables", "-L", chain, "-n"], capture=True)
    return r.returncode == 0


def _ensure_chains() -> None:
    """Создаёт цепочки SNELL_STATS_IN/OUT если их ещё нет."""
    for chain in (CHAIN_IN, CHAIN_OUT):
        if not _ipt_chain_exists(chain):
            _run(["iptables", "-N", chain])


def _jump_exists(direction: str) -> bool:
    """Проверяет, есть ли уже jump INPUT→CHAIN_IN (или OUTPUT→CHAIN_OUT)."""
    chain = "INPUT" if direction == "in" else "OUTPUT"
    target = CHAIN_IN if direction == "in" else CHAIN_OUT
    r = _run(["iptables", "-C", chain, "-j", target], capture=True)
    return r.returncode == 0


def _ensure_jumps() -> None:
    """Добавляет jump INPUT→CHAIN_IN и OUTPUT→CHAIN_OUT если их ещё нет."""
    if not _jump_exists("in"):
        _run(["iptables", "-I", "INPUT", "1", "-j", CHAIN_IN])
    if not _jump_exists("out"):
        _run(["iptables", "-I", "OUTPUT", "1", "-j", CHAIN_OUT])


def _rule_exists(chain: str, port: int, direction: str, username: str) -> bool:
    """Проверяет, есть ли уже правило для конкретного юзера/порта в цепочке."""
    if direction == "in":
        dport_arg = ["--dport", str(port)]
    else:
        dport_arg = ["--sport", str(port)]
    comment = f"{COMMENT_PREFIX_RX}{username}{COMMENT_SUFFIX_RX if direction == 'in' else COMMENT_SUFFIX_TX}"
    r = _run(
        ["iptables", "-C", chain, "-p", "tcp"] + dport_arg
        + ["-m", "comment", "--comment", comment, "-j", "RETURN"],
        capture=True,
    )
    return r.returncode == 0


def _add_user_rule(chain: str, port: int, direction: str, username: str) -> None:
    """Добавляет правило для одного юзера в цепочку (если его ещё нет)."""
    if _rule_exists(chain, port, direction, username):
        return
    if direction == "in":
        dport_arg = ["--dport", str(port)]
        suffix = COMMENT_SUFFIX_RX
    else:
        dport_arg = ["--sport", str(port)]
        suffix = COMMENT_SUFFIX_TX
    comment = f"{COMMENT_PREFIX_RX}{username}{suffix}"
    _run(
        ["iptables", "-A", chain, "-p", "tcp"] + dport_arg
        + ["-m", "comment", "--comment", comment, "-j", "RETURN"]
    )


def _del_user_rule(chain: str, port: int, direction: str, username: str) -> None:
    """Удаляет ВСЕ правила для конкретного юзера/порта (может быть несколько
    из-за прошлых багов — удаляем в цикле до чистого состояния)."""
    if direction == "in":
        dport_arg = ["--dport", str(port)]
        suffix = COMMENT_SUFFIX_RX
    else:
        dport_arg = ["--sport", str(port)]
        suffix = COMMENT_SUFFIX_TX
    comment = f"{COMMENT_PREFIX_RX}{username}{suffix}"
    rule = (["iptables", "-D", chain, "-p", "tcp"] + dport_arg
            + ["-m", "comment", "--comment", comment, "-j", "RETURN"])
    # Удаляем в цикле — на случай если правило было добавлено несколько раз.
    for _ in range(10):
        r = _run(rule, capture=True)
        if r.returncode != 0:
            break


# ─── Public API ──────────────────────────────────────────────────────────────

def setup_user_accounting(username: str, port: int) -> bool:
    """Регистрирует per-user iptables-правила для учёта трафика.

    Вызывается из snell.py при создании/включении пользователя. Создаёт
    глобальные цепочки если их ещё нет, добавляет jump INPUT/OUTPUT→CHAIN,
    и добавляет per-user правила с comment-тегом.

    Возвращает True если всё прошло OK, False при ошибке iptables.
    """
    try:
        _ensure_chains()
        _ensure_jumps()
        _add_user_rule(CHAIN_IN,  port, "in",  username)
        _add_user_rule(CHAIN_OUT, port, "out", username)
        _setup_cron()
        _persist_accounting_rules()
        return True
    except Exception:
        return False


def teardown_user_accounting(username: str, port: int) -> bool:
    """Удаляет per-user правила при удалении/отключении пользователя.

    Возвращает True даже если правил не было (это не ошибка).
    Возвращает False только при критической ошибке iptables.
    """
    try:
        _del_user_rule(CHAIN_IN,  port, "in",  username)
        _del_user_rule(CHAIN_OUT, port, "out", username)
        _persist_accounting_rules()
        return True
    except Exception:
        return False


def teardown_all_accounting() -> bool:
    """Полный демонтаж цепочек — вызывается при удалении Snell.

    Удаляет jump INPUT/OUTPUT→CHAIN, очищает цепочки, удаляет сами цепочки.
    Возвращает True если хотя бы частично успешно.
    """
    ok = True
    try:
        # Сначала убираем jump (иначе цепочку нельзя удалить).
        if _jump_exists("in"):
            r = _run(["iptables", "-D", "INPUT", "-j", CHAIN_IN], capture=True)
            ok = ok and (r.returncode == 0)
        if _jump_exists("out"):
            r = _run(["iptables", "-D", "OUTPUT", "-j", CHAIN_OUT], capture=True)
            ok = ok and (r.returncode == 0)
        # Очищаем и удаляем цепочки.
        for chain in (CHAIN_IN, CHAIN_OUT):
            if _ipt_chain_exists(chain):
                _run(["iptables", "-F", chain], capture=True)
                r = _run(["iptables", "-X", chain], capture=True)
                ok = ok and (r.returncode == 0)
        # Удаляем cron.
        if CRON_FILE.exists():
            CRON_FILE.unlink()
        _persist_accounting_rules()
    except Exception:
        ok = False
    return ok


def get_user_traffic(username: str) -> dict:
    """Возвращает {bytes_in, bytes_out, total_bytes} для конкретного юзера.

    Парсит вывод `iptables -L SNELL_STATS_IN -v -n -x` по comment-тегу
    snell-<username>-rx (и -tx для OUT). Если юзер не найден — возвращает
    нули (это нормально если учёт ещё не настроен или трафика не было).
    """
    result = {"bytes_in": 0, "bytes_out": 0, "total_bytes": 0}
    try:
        rx_comment = f"{COMMENT_PREFIX_RX}{username}{COMMENT_SUFFIX_RX}"
        tx_comment = f"{COMMENT_PREFIX_RX}{username}{COMMENT_SUFFIX_TX}"
        result["bytes_in"]  = _read_chain_bytes(CHAIN_IN,  rx_comment)
        result["bytes_out"] = _read_chain_bytes(CHAIN_OUT, tx_comment)
        result["total_bytes"] = result["bytes_in"] + result["bytes_out"]
    except Exception:
        pass
    return result


def get_all_users_traffic() -> dict:
    """Возвращает {username: {bytes_in, bytes_out, total}} для всех юзеров.

    Используется для сводной статистики в TUI. Парсит обе цепочки одним
    проходом, группирует по comment-тегу.
    """
    result: dict[str, dict] = {}
    try:
        rx_map = _read_chain_all(CHAIN_IN, COMMENT_SUFFIX_RX)
        tx_map = _read_chain_all(CHAIN_OUT, COMMENT_SUFFIX_TX)
        all_users = set(rx_map) | set(tx_map)
        for u in all_users:
            bi = rx_map.get(u, 0)
            bo = tx_map.get(u, 0)
            result[u] = {
                "bytes_in": bi,
                "bytes_out": bo,
                "total_bytes": bi + bo,
            }
    except Exception:
        pass
    return result


# ─── Внутренние хелперы ──────────────────────────────────────────────────────

def _read_chain_bytes(chain: str, comment: str) -> int:
    """Читает байты по конкретному comment-тегу из цепочки."""
    r = _run(["iptables", "-L", chain, "-v", "-n", "-x"], capture=True)
    if r.returncode != 0 or not r.stdout:
        return 0
    for line in r.stdout.splitlines():
        if comment not in line:
            continue
        parts = line.split()
        # Формат iptables -v -x:
        #  pkts    bytes   target  prot  opt  in  out  source  destination  ...
        #  1234   567890   RETURN  tcp   --   *    *   0.0.0.0/0  0.0.0.0/0  ... comments "snell-user-rx"
        if len(parts) >= 2:
            try:
                # parts[1] — колонка bytes (с -x — без K/M суффиксов, в байтах).
                return int(parts[1])
            except (ValueError, IndexError):
                continue
    return 0


def _read_chain_all(chain: str, suffix: str) -> dict:
    """Парсит ВСЕ правила в цепочке, возвращает {username: bytes}.

    Извлекает username из comment-тега формата snell-<user>-rx/-tx.
    """
    result: dict[str, int] = {}
    r = _run(["iptables", "-L", chain, "-v", "-n", "-x"], capture=True)
    if r.returncode != 0 or not r.stdout:
        return result
    for line in r.stdout.splitlines():
        # Ищем comment-тег. iptables оборачивает его в кавычки: "snell-alice-rx"
        m = re.search(r'/*\s+"?' + re.escape(COMMENT_PREFIX_RX) + r'([^"]+?)' + re.escape(suffix) + r'"?\s*$', line)
        if not m:
            # Альтернативный формат: ... /* snell-alice-rx */
            m = re.search(r'/\*\s*' + re.escape(COMMENT_PREFIX_RX) + r'(\S+?)' + re.escape(suffix) + r'\s*\*/', line)
        if not m:
            continue
        username = m.group(1)
        parts = line.split()
        if len(parts) >= 2:
            try:
                result[username] = result.get(username, 0) + int(parts[1])
            except (ValueError, IndexError):
                continue
    return result


def _setup_cron() -> None:
    """Создаёт cron-файл для ночного сброса счётчиков (00:00).

    Сброс нужен чтобы статистика «за сегодня» корректно обнулялась — иначе
    счётчики монотонно растут до перезагрузки и юзер не видит «сегодняшний»
    трафик отдельно от «за всё время».
    """
    if CRON_FILE.exists():
        return  # уже настроено
    try:
        CRON_FILE.parent.mkdir(parents=True, exist_ok=True)
        CRON_FILE.write_text(
            "# Reset Snell per-user iptables counters nightly (00:00)\n"
            f"0 0 * * * root iptables -Z {CHAIN_IN} && iptables -Z {CHAIN_OUT}"
            f"  # snell-stats\n"
        )
        CRON_FILE.chmod(0o644)
    except (OSError, PermissionError):
        pass


def _persist_accounting_rules() -> None:
    """Сохраняет iptables-правила через netfilter-persistent или iptables-save.

    Использует proto_ipt_persist из proto_common если доступен — он сам
    определяет доступный механизм (netfilter-persistent на Debian/Ubuntu,
    iptables-save на RHEL/CentOS).
    """
    try:
        from chimera.modules.proto_common import proto_ipt_persist
        proto_ipt_persist()
    except Exception:
        # Fallback: прямой вызов iptables-save (без проверки netfilter-persistent).
        _run(["iptables-save"], capture=True)


# ─── Snapshot в JSON-файл (для долгосрочного учёта) ──────────────────────────
# Счётчики iptables живут в памяти ядра и сбрасываются при перезагрузке.
# Для долгосрочной статистики (за неделю/месяц) нужно периодически
# дампать snapshot в JSON-файл — чтобы после сброса накопленные значения
# не потерялись. Этот механизм здесь не реализован (упрощённая версия);
# если нужна долгосрочная статистика — добавить cron-job, который
# дампает get_all_users_traffic() в STATS_FILE с инкрементальным сложением.

def snapshot_to_file() -> bool:
    """Сохраняет текущие значения counters в STATS_FILE.

    Перезаписывает файл (не инкрементно). Для инкрементного учёта нужно
    сначала прочитать старый snapshot, сложить, записать — это упрощённая
    версия, просто для отладки/мониторинга.
    """
    try:
        all_traffic = get_all_users_traffic()
        STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATS_FILE.write_text(json.dumps(all_traffic, indent=2))
        STATS_FILE.chmod(0o640)
        return True
    except Exception:
        return False


def load_snapshot() -> dict:
    """Загружает последний snapshot из STATS_FILE (если есть)."""
    try:
        if STATS_FILE.exists():
            return json.loads(STATS_FILE.read_text())
    except Exception:
        pass
    return {}
