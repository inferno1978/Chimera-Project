"""
chimera/modules/port_knocking.py
───────────────────────────────────────────────────────────────────────────────
Port Knocking — динамический ACL для защиты VPN-портов (443, 9443) от
интернет-сканеров (Censys, Shodan) и пассивного DPI-фингерпринтинга.

Концепция:
  • iptables/ip6tables DROP by default на защищаемом порту (например :443)
  • Каждый SYN-пакет трекается через `recent` iptables-модуль
  • После N SYN за W секунд → IP добавляется в ipset `xray_knocked`
    (или `xray_knocked6` для IPv6) с TTL
  • Если IP в `xray_knocked`/`xray_knocked6` → SYN ACCEPTED → handshake
  • Whitelist IPs в существующем ipset `clients_wl` → обходят knocking
    (приоритет, только IPv4 — whitelist модуль хранит IPv4)
  • Существующие `xray_manual_ban`/`xray_manual_ban6` ipsets → DROP независимо
    от knocking

Порядок правил iptables (приоритет — позиция в INPUT):
  1. INSERT 1: -m set --match-set xray_manual_ban src -j DROP    (бан от ipban.py)
  2. INSERT 2: -m set --match-set clients_wl src     -j ACCEPT  (wl от user_ip_whitelist.py)
  3. INSERT 3: -m set --match-set xray_knocked src    -j ACCEPT  (кто постучался)
  4. APPEND:   --syn -m recent --name KNOCK{port} --set           (трекать SYN)
  5. APPEND:   --syn -m recent --rcheck --seconds W --hitcount N
              -j SET --add-set xray_knocked src                    (повысить до knocked)
  6. APPEND:   --syn -j DROP                                       (default deny)

Аналогично для ip6tables (IPv6):
  1. INSERT 1: -m set --match-set xray_manual_ban6 src -j DROP
  2. INSERT 2: -m set --match-set xray_knocked6 src    -j ACCEPT
  3. APPEND:   --syn -m recent --name KNOCK{port}v6 --set
  4. APPEND:   --syn -m recent --rcheck ... -j SET --add-set xray_knocked6 src
  5. APPEND:   --syn -j DROP

  (нет clients_wl для IPv6 — whitelist модуль хранит только IPv4)

UFW-конфликт:
  При install: ufw delete allow <port>/tcp (убирает ACCEPT :port от UFW,
  чтобы knocking-правила не обходились через UFW chain).
  При remove: ufw allow <port>/tcp comment "chimera-vless VLESS REALITY :<port>"
  (восстанавливает IPv4+IPv6 ACCEPT от UFW).

Точка входа из _core.py:
    from chimera.modules.port_knocking import do_manage_port_knocking
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE',
                            'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Пути и константы ──────────────────────────────────────────────────────────
_PK_STATE_FILE = Path("/var/lib/xray-installer/port_knocking.json")
_PK_LOG_FILE   = Path("/var/log/chimera.log")

# ipset-имена:
#   `xray_knocked`    — СОЗДАЁТСЯ этим модулем (с TTL timeout), IPv4
#   `xray_knocked6`   — СОЗДАЁТСЯ этим модулем (с TTL timeout), IPv6 (family inet6)
#   `clients_wl`      — уже существует (user_ip_whitelist.py) — читаем, не трогаем
#   `xray_manual_ban`  — уже существует (ipban.py) — читаем, не трогаем
#   `xray_manual_ban6` — может существовать (ipban.py для IPv6) — читаем, не трогаем
_PK_KNOCKED_SET       = "xray_knocked"
_PK_KNOCKED_SET_V6    = "xray_knocked6"   # IPv6 ipset name
_PK_MANUAL_BAN_SET    = "xray_manual_ban"
_PK_MANUAL_BAN_SET_V6 = "xray_manual_ban6"  # IPv6 manual ban
_PK_WL_SET            = "clients_wl"

# Comment-маркер для всех iptables/ip6tables-правил модуля — для идемпотентной
# установки и безопасной очистки при remove(): ищем/удаляем только свои правила.
# IPv6 rules use suffixed comments like "chimera-port-knocking:DROP-ban6" —
# grep by tag substring works for both.
_PK_COMMENT_TAG = "chimera-port-knocking"

# ── Дефолты (с объяснениями) ──────────────────────────────────────────────────
# knock_count = 3       — покрывает Linux/macOS/iOS ретраи (обычно 4 ретрая SYN):
#                         1-й и 2-й SYN "стучат", 3-й — повышает до xray_knocked,
#                         4-й — уже ACCEPT по INSERT-правилу #3 → handshake.
# knock_window_sec = 10 — достаточно для exponential backoff ретраев SYN.
# whitelist_ttl_sec = 3600 — 1 час: баланс между безопасностью (TTL истекает,
#                         сканер не сможет повторно использовать открытый порт)
#                         и удобством (клиент не стучит каждые 5 минут).
_DEFAULT_KNOCK_COUNT       = 3
_DEFAULT_KNOCK_WINDOW_SEC  = 10
_DEFAULT_WHITELIST_TTL_SEC = 3600
_DEFAULT_PORTS             = [443]
_DEFAULT_LOG_SUCCESS       = False


def _pk_default_state() -> dict:
    """Возвращает дефолтное состояние модуля."""
    return {
        "enabled":           False,
        "ports":             list(_DEFAULT_PORTS),
        "knock_count":       _DEFAULT_KNOCK_COUNT,
        "knock_window_sec": _DEFAULT_KNOCK_WINDOW_SEC,
        "whitelist_ttl_sec": _DEFAULT_WHITELIST_TTL_SEC,
        "log_success":       _DEFAULT_LOG_SUCCESS,
        "installed_at":      "",
    }


# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    """Пишет в /var/log/chimera.log с префиксом [PK]."""
    try:
        _PK_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _PK_LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] [PK] {clean}\n")
    except Exception:
        pass


def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}   {msg}"); _log("ERR", msg)


# ── TG-уведомления (делегируем в _core через importlib) ───────────────────────
def _tg_notify_event(event: str, detail: str = "") -> None:
    """Лёгкая делегация в _core._tg_notify_event; no-op если _core недоступен."""
    try:
        import importlib
        _core = importlib.import_module("chimera._core")
        _core._tg_notify_event(event, detail)
    except Exception:
        pass  # TG не настроен или _core недоступен


# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int = 30) -> subprocess.CompletedProcess:
    """subprocess.run без исключений (таймаут/отсутствие бинарника → rc!=0)."""
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        return subprocess.run(cmd, **kw, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return subprocess.CompletedProcess(cmd, 126, "", "")


def _cmd_str(cmd: list) -> str:
    """Строковое представление команды для логов (с shlex.quote)."""
    return " ".join(shlex.quote(str(c)) for c in cmd)


# ── STATE ──────────────────────────────────────────────────────────────────────
def _pk_state_load() -> dict:
    """Загружает state из JSON. При ошибке/отсутствии — дефолт.

    Мержит с дефолтами: поля, добавленные в более поздних версиях модуля,
    получают дефолтные значения, если отсутствуют в файле (обратная совместимость).
    """
    try:
        if _PK_STATE_FILE.exists():
            data = json.loads(_PK_STATE_FILE.read_text())
            if isinstance(data, dict):
                merged = _pk_default_state()
                merged.update(data)
                return merged
    except Exception:
        pass
    return _pk_default_state()


def _pk_state_save(state: dict) -> None:
    """Сохраняет state в JSON с chmod 0600."""
    try:
        _PK_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PK_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        _PK_STATE_FILE.chmod(0o600)
    except Exception as e:
        _log("ERR", f"_pk_state_save failed: {e}")


# ── Валидация ──────────────────────────────────────────────────────────────────
def _pk_validate_int(value, lo: int, hi: int, name: str) -> "tuple[bool, str]":
    """Проверка что value — int в диапазоне [lo, hi]. Возвращает (ok, msg)."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return False, f"{name}: должно быть целое число"
    if not (lo <= v <= hi):
        return False, f"{name}: должно быть в диапазоне [{lo}, {hi}]"
    return True, ""


def _pk_validate(state: dict) -> list:
    """Возвращает список ошибок (пустой если state валиден)."""
    errors: list[str] = []
    ok, msg = _pk_validate_int(state.get("knock_count"), 1, 20, "knock_count")
    if not ok:
        errors.append(msg)
    ok, msg = _pk_validate_int(state.get("knock_window_sec"), 1, 300,
                               "knock_window_sec")
    if not ok:
        errors.append(msg)
    ok, msg = _pk_validate_int(state.get("whitelist_ttl_sec"), 60,
                               86400 * 30, "whitelist_ttl_sec")
    if not ok:
        errors.append(msg)
    ports = state.get("ports", [])
    if not isinstance(ports, list):
        errors.append("ports: должно быть списком")
    else:
        for p in ports:
            ok, msg = _pk_validate_int(p, 1, 65535, "port")
            if not ok:
                errors.append(msg)
                break
    return errors


# ── iptables rules ─────────────────────────────────────────────────────────────
def _pk_recent_name(port: int) -> str:
    """Имя recent-таблицы для порта (уникальное per-port, IPv4).

    xt_recent имеет глобальный лимит на размер таблицы (ip_list_tot, default 100).
    Уникальное имя per-port (KNOCK443, KNOCK9443) позволяет независимо трекать
    SYN на разных портах без взаимных коллизий.
    """
    return f"KNOCK{port}"


def _pk_recent_name_v6(port: int) -> str:
    """Имя recent-таблицы для порта (IPv6).

    Должно отличаться от IPv4-имени, т.к. xt_recent использует отдельные таблицы
    для ip6tables (разное пространство имён в /proc/net/xt_recent).
    """
    return f"KNOCK{port}v6"


def _pk_build_iptables_rules(port: int, state: dict) -> list:
    """Строит список iptables rule descriptors для порта (IPv4).

    Возвращает list of dicts:
      {"op": "insert", "pos": 1, "spec": [...]}   # iptables -I INPUT <pos> <spec>
      {"op": "append", "spec": [...]}             # iptables -A INPUT <spec>

    Порядок INSERT (приоритет — позиция в INPUT):
      1 = DROP для xray_manual_ban (бан приоритетнее всего)
      2 = ACCEPT для clients_wl     (whitelist обходит knocking)
      3 = ACCEPT для xray_knocked    (кто успешно постучался)
    Порядок APPEND (выполняются после INSERT, для "упавших сквозь" пакетов):
      4 = recent --set              (записать SYN в recent-таблицу)
      5 = recent --rcheck + add-set (если N SYN за W сек → добавить в xray_knocked)
      6 = --syn -j DROP              (default deny для остальных SYN)

    spec — полный список аргументов после `iptables` и `-I/-A INPUT [pos]`.
    Используется одним и тем же кодом для `-C` check и `-I`/`-A` execution
    (позиция для `-C` не нужна — iptables ищет по spec во всей цепочке).
    """
    knock_count  = int(state["knock_count"])
    knock_window = int(state["knock_window_sec"])
    recent_name  = _pk_recent_name(port)
    port_str     = str(port)

    base    = ["-p", "tcp", "--dport", port_str]
    comment = ["-m", "comment", "--comment", _PK_COMMENT_TAG]

    # ── INSERT rules (priority: ban > wl > knocked) ──────────────────────────
    insert_rules = [
        # 1. DROP для ipset xray_manual_ban (бан от ipban.py — высший приоритет)
        {"op": "insert", "pos": 1,
         "spec": base + ["-m", "set", "--match-set", _PK_MANUAL_BAN_SET, "src",
                         "-j", "DROP"] + comment},
        # 2. ACCEPT для ipset clients_wl (whitelist от user_ip_whitelist.py)
        {"op": "insert", "pos": 2,
         "spec": base + ["-m", "set", "--match-set", _PK_WL_SET, "src",
                         "-j", "ACCEPT"] + comment},
        # 3. ACCEPT для ipset xray_knocked (кто успешно постучался)
        {"op": "insert", "pos": 3,
         "spec": base + ["-m", "set", "--match-set", _PK_KNOCKED_SET, "src",
                         "-j", "ACCEPT"] + comment},
    ]

    # ── APPEND rules (track → promote → drop) ────────────────────────────────
    append_rules = [
        # 4. Записать каждый SYN в recent-таблицу KNOCK{port}
        #    (без -j target: recent match только обновляет таблицу, пакет
        #     продолжает падать ниже по цепочке)
        {"op": "append",
         "spec": base + ["--syn",
                         "-m", "recent", "--name", recent_name, "--set"] + comment},
        # 5. Если N SYN за W секунд → добавить src в xray_knocked (с TTL)
        #    FIX (Bug 5): iptables-nft (nf_tables backend) не поддерживает
        #    `-m set --add-set` — нужно использовать target SET:
        #    `-j SET --add-set xray_knocked src`
        #    (пакет продолжает падать ниже по цепочке → правило 6 его
        #     дропнет; но IP уже в xray_knocked, следующий SYN попадёт
        #     в INSERT #3 и будет ACCEPT)
        {"op": "append",
         "spec": base + ["--syn",
                         "-m", "recent", "--name", recent_name,
                         "--rcheck", "--seconds", str(knock_window),
                         "--hitcount", str(knock_count),
                         "-j", "SET", "--add-set", _PK_KNOCKED_SET,
                         "src"] + comment},
        # 6. Default deny: DROP всех остальных SYN на этом порту
        {"op": "append",
         "spec": base + ["--syn", "-j", "DROP"] + comment},
    ]

    return insert_rules + append_rules


def _pk_build_ip6tables_rules(port: int, state: dict) -> list:
    """Строит список ip6tables rule descriptors для порта (IPv6).

    Аналог _pk_build_iptables_rules, но для IPv6:
      • Использует xray_manual_ban6 / xray_knocked6 ipsets
      • Использует KNOCK{port}v6 recent-имя (отдельное пространство имён)
      • Без clients_wl (whitelist модуль хранит только IPv4)
      • Comment имеет суффикс :...6 для отладки

    Возвращает 5 rules (2 INSERT + 3 APPEND).
    """
    knock_count  = int(state["knock_count"])
    knock_window = int(state["knock_window_sec"])
    recent_name  = _pk_recent_name_v6(port)
    port_str     = str(port)

    base = ["-p", "tcp", "--dport", port_str]

    # ── INSERT rules (priority: ban6 > knocked6; no wl6) ─────────────────────
    insert_rules = [
        # 1. DROP для ipset xray_manual_ban6 (IPv6 бан)
        {"op": "insert", "pos": 1,
         "spec": base + ["-m", "set", "--match-set", _PK_MANUAL_BAN_SET_V6, "src",
                         "-j", "DROP",
                         "-m", "comment", "--comment",
                         f"{_PK_COMMENT_TAG}:DROP-ban6"]},
        # 2. ACCEPT для ipset xray_knocked6 (IPv6 postучавшие)
        {"op": "insert", "pos": 2,
         "spec": base + ["-m", "set", "--match-set", _PK_KNOCKED_SET_V6, "src",
                         "-j", "ACCEPT",
                         "-m", "comment", "--comment",
                         f"{_PK_COMMENT_TAG}:ACCEPT-knocked6"]},
    ]

    # ── APPEND rules (track → promote → drop) ────────────────────────────────
    append_rules = [
        # 3. Записать каждый SYN в recent-таблицу KNOCK{port}v6
        {"op": "append",
         "spec": base + ["--syn",
                         "-m", "recent", "--name", recent_name, "--set",
                         "-m", "comment", "--comment",
                         f"{_PK_COMMENT_TAG}:recent-set6"]},
        # 4. Если N SYN за W секунд → добавить src в xray_knocked6 (с TTL)
        #    FIX (Bug 5): используем -j SET --add-set (iptables-nft совместимо)
        {"op": "append",
         "spec": base + ["--syn",
                         "-m", "recent", "--name", recent_name,
                         "--rcheck", "--seconds", str(knock_window),
                         "--hitcount", str(knock_count),
                         "-j", "SET", "--add-set", _PK_KNOCKED_SET_V6, "src",
                         "-m", "comment", "--comment",
                         f"{_PK_COMMENT_TAG}:recent-check-add6"]},
        # 5. Default deny: DROP всех остальных SYN на этом порту
        {"op": "append",
         "spec": base + ["--syn", "-j", "DROP",
                         "-m", "comment", "--comment",
                         f"{_PK_COMMENT_TAG}:DROP-default6"]},
    ]

    return insert_rules + append_rules


def _pk_build_ipset_create_cmd(state: dict) -> list:
    """Команда создания ipset xray_knocked с TTL timeout (IPv4).

        ipset create xray_knocked hash:ip timeout 3600 -exist

    `-exist` flag — идемпотентность: не падает если set уже есть.
    FIX (Bug 4): используем `-exist` (с dash), не `exist`.
    """
    return ["ipset", "create", _PK_KNOCKED_SET, "hash:ip",
            "timeout", str(int(state["whitelist_ttl_sec"])), "-exist"]


def _pk_build_ipset_create_cmd_v6(state: dict) -> list:
    """Команда создания ipset xray_knocked6 с TTL timeout (IPv6, family inet6).

        ipset create xray_knocked6 hash:ip timeout 3600 family inet6 -exist

    `family inet6` обязателен для IPv6 ipset — должен быть указан при создании,
    после создания изменить нельзя. Поэтому отдельный set от IPv4.
    """
    return ["ipset", "create", _PK_KNOCKED_SET_V6, "hash:ip",
            "timeout", str(int(state["whitelist_ttl_sec"])),
            "family", "inet6", "-exist"]


def _pk_rule_exists(spec: list, table: str = "iptables") -> bool:
    """Проверяет наличие правила через `<table> -C INPUT <spec>`.

    table = "iptables" (IPv4) или "ip6tables" (IPv6).
    """
    cmd = [table, "-C", "INPUT"] + spec
    return _run(cmd, quiet=True).returncode == 0


def _pk_ipset_exists(name: str) -> bool:
    """Существует ли ipset с указанным именем."""
    r = _run(["ipset", "list", name], capture=True)
    return r.returncode == 0


# ── Persistence (best-effort, без падения если tools отсутствуют) ────────────
def _pk_persist() -> None:
    """Сохраняет iptables/ip6tables-правила и ipset, чтобы пережить reboot.

    Best-effort: если netfilter-persistent/iptables-save/ipset save недоступны
    или нет прав на запись — молча пропускаем (правила не переживут reboot,
    но модуль можно повторно активировать через меню).
    """
    # iptables (IPv4)
    try:
        import shutil
        if shutil.which("netfilter-persistent"):
            _run(["netfilter-persistent", "save"], quiet=True)
        else:
            rules_path = Path("/etc/iptables/rules.v4")
            if rules_path.parent.exists():
                r = _run(["iptables-save"], capture=True)
                if r.returncode == 0 and r.stdout:
                    rules_path.write_text(r.stdout)
    except Exception:
        pass
    # ip6tables (IPv6)
    try:
        import shutil
        rules_path = Path("/etc/iptables/rules.v6")
        if rules_path.parent.exists():
            r = _run(["ip6tables-save"], capture=True)
            if r.returncode == 0 and r.stdout:
                rules_path.write_text(r.stdout)
    except Exception:
        pass
    # ipset (both IPv4 + IPv6)
    try:
        ipset_save_path = Path("/etc/iptables/ipsets")
        if ipset_save_path.parent.exists():
            for set_name in (_PK_KNOCKED_SET, _PK_KNOCKED_SET_V6):
                if _pk_ipset_exists(set_name):
                    r = _run(["ipset", "save", set_name], capture=True)
                    if r.returncode == 0 and r.stdout:
                        # append (both sets in same file)
                        with ipset_save_path.open("a") as f:
                            f.write(r.stdout)
    except Exception:
        pass


# ── Install / Remove ───────────────────────────────────────────────────────────
def _pk_find_rule_lines(table: str) -> list:
    """Возвращает номера строк правил с нашим comment-тегом в `<table> -L INPUT`.

    Алгоритм (Bug 1 fix):
      • `<table> -L INPUT --line-numbers -n` → вывод с номерами строк
      • Фильтруем строки с _PK_COMMENT_TAG (substring match — работает и для
        IPv4 cвойствa "chimera-port-knocking", и для IPv6 с суффиксами
        "chimera-port-knocking:DROP-ban6" и т.д.)
      • Извлекаем ведущее число (номер строки)
      • Сортируем по убыванию (bottom-up delete — чтобы номера строк не
        сдвигались при удалении)

    Возвращает list[int] отсортированный по убыванию.
    """
    r = _run([table, "-L", "INPUT", "--line-numbers", "-n"], capture=True)
    if r.returncode != 0:
        return []
    lines: list[int] = []
    for line in (r.stdout or "").splitlines():
        if _PK_COMMENT_TAG not in line:
            continue
        m = re.match(r"\s*(\d+)", line)
        if m:
            lines.append(int(m.group(1)))
    # Сортируем по убыванию — удаляем снизу вверх (номера не сдвигаются)
    return sorted(lines, reverse=True)


def _pk_install(state: dict) -> bool:
    """Устанавливает ipset + iptables + ip6tables-правила для всех портов.

    FIX (Bug 2): сначала вызывает _pk_remove() чтобы удалить ВСЕ старые правила
    (даже если порядок был нарушен), потом ставит свежие правила в правильном
    порядке. Идемпотентно — повторный install полностью пересоздаёт состояние.

    FIX (Bug 3): для каждого порта удаляет UFW-правило `allow <port>/tcp` —
    иначе UFW ACCEPT'ит :port ДО достижения knocking-правил, делая knocking
    бесполезным. При remove UFW восстанавливается.

    Шаги:
      1. Валидация state.
      2. _pk_remove() — очистка всех старых правил + восстановление UFW
         (для старого набора портов).
      3. Создаём ipset xray_knocked (IPv4) — идемпотентно через `-exist`.
      4. Создаём ipset xray_knocked6 (IPv6, family inet6) — идемпотентно.
      5. Для каждого порта:
         a. ufw delete allow <port>/tcp (Bug 3 fix)
         b. iptables-правила IPv4 (3 INSERT + 3 APPEND) — skip clients_wl
            если ipset не существует; идемпотентно через -C check.
         c. ip6tables-правила IPv6 (2 INSERT + 3 APPEND) — skip
            xray_manual_ban6 если ipset не существует; идемпотентно через -C.
      6. Сохраняем state (enabled=True, installed_at=сейчас).
      7. _pk_persist() для survive reboot.
    """
    errors = _pk_validate(state)
    if errors:
        _err(f"State invalid: {errors[0]}")
        return False

    if not state.get("ports"):
        _warn("No ports configured — nothing to install")
        return False

    # 1. Bug 2 fix: clean ALL old rules first (correct order every time).
    #    _pk_remove loads state from disk (old state), removes old rules,
    #    restores UFW for old ports, saves state with enabled=False.
    _pk_remove()

    # 2. Создаём ipset xray_knocked (IPv4, идемпотентно через -exist)
    ipset_cmd = _pk_build_ipset_create_cmd(state)
    r = _run(ipset_cmd, capture=True)
    if r.returncode != 0:
        _err(f"ipset create (IPv4) failed: {(r.stderr or '').strip()[:120]}")
        return False
    _log("INFO", f"ipset {_PK_KNOCKED_SET} ready "
                 f"(timeout={state['whitelist_ttl_sec']}s)")

    # 3. Создаём ipset xray_knocked6 (IPv6, family inet6, идемпотентно)
    ipset_cmd_v6 = _pk_build_ipset_create_cmd_v6(state)
    r = _run(ipset_cmd_v6, capture=True)
    if r.returncode != 0:
        _err(f"ipset create (IPv6) failed: {(r.stderr or '').strip()[:120]}")
        return False
    _log("INFO", f"ipset {_PK_KNOCKED_SET_V6} ready (family inet6, "
                 f"timeout={state['whitelist_ttl_sec']}s)")

    # 4. Bug 3 fix: для каждого порта удаляем UFW-правило allow <port>/tcp.
    #    ufw delete removes BOTH IPv4 and IPv6 rules for that port.
    #    Затем устанавливаем knocking-правила (IPv4 + IPv6).
    installed_rules = 0
    for port in state["ports"]:
        # 4a. Delete UFW allow rule for this port (Bug 3 fix)
        _run(["ufw", "delete", "allow", f"{port}/tcp"], quiet=True)

        # 4b. Install iptables (IPv4) rules — идемпотентно через -C
        for rule in _pk_build_iptables_rules(port, state):
            # Skip xray_manual_ban rule if ipset doesn't exist on this server
            if _PK_MANUAL_BAN_SET in rule["spec"] and \
                    not _pk_ipset_exists(_PK_MANUAL_BAN_SET):
                _info(f"Skipping {_PK_MANUAL_BAN_SET} rule — ipset not "
                      f"found (configure IP ban in ipban TUI to enable)")
                continue
            # Skip clients_wl rule if ipset doesn't exist on this server
            if _PK_WL_SET in rule["spec"] and not _pk_ipset_exists(_PK_WL_SET):
                _info(f"Skipping {_PK_WL_SET} rule — ipset not found "
                      f"(configure whitelist in chimera TUI to enable)")
                continue
            if _pk_rule_exists(rule["spec"], "iptables"):
                continue  # уже есть — пропускаем (идемпотентность)
            if rule["op"] == "insert":
                cmd = ["iptables", "-I", "INPUT", str(rule["pos"])] + rule["spec"]
            else:  # append
                cmd = ["iptables", "-A", "INPUT"] + rule["spec"]
            r = _run(cmd, capture=True)
            if r.returncode != 0:
                _err(f"iptables rule failed ({_cmd_str(cmd)}): "
                     f"{(r.stderr or '').strip()[:120]}")
                # Не откатываем — частичная установка лучше чем ничего,
                # пользователь увидит ошибку в логе и меню статуса
                continue
            installed_rules += 1

        # 4c. Install ip6tables (IPv6) rules — идемпотентно через -C
        for rule in _pk_build_ip6tables_rules(port, state):
            # Skip xray_manual_ban6 rule if ipset doesn't exist on this server
            if _PK_MANUAL_BAN_SET_V6 in rule["spec"] and \
                    not _pk_ipset_exists(_PK_MANUAL_BAN_SET_V6):
                _info(f"Skipping {_PK_MANUAL_BAN_SET_V6} rule — ipset not "
                      f"found (configure IPv6 ban in ipban TUI to enable)")
                continue
            if _pk_rule_exists(rule["spec"], "ip6tables"):
                continue
            if rule["op"] == "insert":
                cmd = ["ip6tables", "-I", "INPUT", str(rule["pos"])] + rule["spec"]
            else:  # append
                cmd = ["ip6tables", "-A", "INPUT"] + rule["spec"]
            r = _run(cmd, capture=True)
            if r.returncode != 0:
                _err(f"ip6tables rule failed ({_cmd_str(cmd)}): "
                     f"{(r.stderr or '').strip()[:120]}")
                continue
            installed_rules += 1

    # 5. Обновляем state
    state["enabled"] = True
    state["installed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _pk_state_save(state)

    # 6. Persist для survive reboot
    _pk_persist()

    _success(f"Port knocking installed: ports={state['ports']}, "
             f"knock={state['knock_count']}/{state['knock_window_sec']}s, "
             f"ttl={state['whitelist_ttl_sec']}s "
             f"({installed_rules} new rules, IPv4+IPv6)")
    _log("INFO", f"installed: ports={state['ports']}, "
                 f"new_rules={installed_rules}, ip6tables=included")

    _tg_notify_event("port_knocking",
        f"<b>Port knocking</b> enabled: ports={state['ports']}, "
        f"knock={state['knock_count']}/{state['knock_window_sec']}s, "
        f"ttl={state['whitelist_ttl_sec']}s (IPv4+IPv6)")
    return True


def _pk_remove() -> bool:
    """Удаляет все iptables/ip6tables-правила с нашим comment-тегом + ipsets.

    Безопасно вызывать многократно: если правил/сет нет — ничего не делает.

    FIX (Bug 1): удаляет правила по НОМЕРУ СТРОКИ (а не по -D с неполным spec,
    который не работает т.к. iptables -D требует точного совпадения всех
    аргументов). Алгоритм:
      1. `<table> -L INPUT --line-numbers -n | grep <tag>` → номера строк
      2. Сортируем по убыванию (bottom-up — чтобы номера не сдвигались)
      3. `<table> -D INPUT <N>` для каждого номера

    FIX (Bug 3): после удаления правил восстанавливает UFW-правило
    `allow <port>/tcp comment "chimera-vless VLESS REALITY :<port>"` —
    это возвращает IPv4+IPv6 ACCEPT от UFW для портов, которые мы ранее
    закрывали knocking-ом. Восстановление делается только если state.enabled
    было True (т.е. install ранее действительно удалил UFW).

    Алгоритм:
      1. _pk_state_load() — узнать был ли модуль включён и список портов.
      2. Для iptables и ip6tables: найти номера строк наших правил, удалить
         снизу вверх по номеру.
      3. Flush + destroy ipset xray_knocked и xray_knocked6 (созданы нами).
      4. Если было включено — восстановить UFW для каждого порта.
      5. Сохранить state (enabled=False, installed_at='').
      6. _pk_persist() чтобы сохранить ОЧИЩЕННОЕ состояние.
    """
    removed_rules = 0

    # 1. State: узнать старый статус и порты (для UFW restore)
    state = _pk_state_load()
    was_enabled = bool(state.get("enabled", False))
    ports = list(state.get("ports", []))

    # 2. Bug 1 fix: удаляем правила по номеру строки в ОБЕИХ таблицах
    for table in ("iptables", "ip6tables"):
        line_nums = _pk_find_rule_lines(table)
        for n in line_nums:  # уже отсортированы по убыванию
            r = _run([table, "-D", "INPUT", str(n)], capture=True)
            if r.returncode == 0:
                removed_rules += 1
            else:
                _log("WARN", f"{table} -D INPUT {n} failed: "
                             f"{(r.stderr or '').strip()[:120]}")

    # 3. Flush + destroy оба ipset (созданы нами — безопасно)
    for set_name in (_PK_KNOCKED_SET, _PK_KNOCKED_SET_V6):
        if _pk_ipset_exists(set_name):
            _run(["ipset", "flush", set_name], quiet=True)
            r = _run(["ipset", "destroy", set_name], capture=True)
            if r.returncode != 0:
                _log("WARN", f"ipset destroy {set_name} failed: "
                             f"{(r.stderr or '').strip()[:120]}")

    # 4. Bug 3 fix: восстанавливаем UFW (IPv4 + IPv6) — только если
    #    модуль был включён (т.е. install ранее удалил UFW).
    if was_enabled:
        for port in ports:
            _run(["ufw", "allow", f"{port}/tcp", "comment",
                  f"chimera-vless VLESS REALITY :{port}"], quiet=True)
            _log("INFO", f"UFW restored: allow {port}/tcp")

    # 5. Обновляем state
    state["enabled"] = False
    state["installed_at"] = ""
    _pk_state_save(state)

    # 6. Persist очищенного состояния
    _pk_persist()

    _success(f"Port knocking removed ({removed_rules} rules deleted, "
             f"ipsets {_PK_KNOCKED_SET}+{_PK_KNOCKED_SET_V6} destroyed"
             + (f", UFW restored for {ports}" if was_enabled else "") + ")")
    _log("INFO", f"removed: deleted_rules={removed_rules}, "
                 f"was_enabled={was_enabled}")

    _tg_notify_event("port_knocking", "<b>Port knocking</b> disabled")
    return True


# ── Status ──────────────────────────────────────────────────────────────────────
def _pk_is_active() -> bool:
    """Активен ли модуль сейчас (есть ли правила с нашим тегом в iptables
    ИЛИ ip6tables).

    Проверяет обе таблицы — даже если правила только в одной, считаем активным.
    """
    for table in ("iptables", "ip6tables"):
        r = _run([table, "-S", "INPUT"], capture=True, quiet=True)
        if r.returncode == 0 and _PK_COMMENT_TAG in (r.stdout or ""):
            return True
    return False


def _pk_ipset_size(name: str) -> int:
    """Число записей в ipset (0 если не существует)."""
    r = _run(["ipset", "list", name], capture=True)
    if r.returncode != 0:
        return 0
    m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
    return int(m.group(1)) if m else 0


def _pk_recent_stats(port: int) -> dict:
    """Статистика recent-таблицы для порта через /proc/net/xt_recent (IPv4).

    Возвращает dict {name, exists, entries}.
    """
    return _pk_recent_stats_by_name(_pk_recent_name(port))


def _pk_recent_stats_v6(port: int) -> dict:
    """Статистика recent-таблицы для порта (IPv6, имя KNOCK{port}v6)."""
    return _pk_recent_stats_by_name(_pk_recent_name_v6(port))


def _pk_recent_stats_by_name(name: str) -> dict:
    """Shared helper: читает /proc/net/xt_recent/<name>."""
    proc_file = Path("/proc/net/xt_recent") / name
    if not proc_file.exists():
        return {"name": name, "exists": False, "entries": 0}
    try:
        lines = proc_file.read_text(errors="replace").splitlines()
        return {"name": name, "exists": True, "entries": len(lines)}
    except Exception:
        return {"name": name, "exists": False, "entries": 0}


def _pk_ipv6_available() -> bool:
    """Доступен ли IPv6 loopback (::1) на этой машине.

    Простая проверка: создаём AF_INET6 socket. Если ядро не поддерживает
    AF_INET6 — исключение → IPv6 не доступен. Если поддерживает, считаем
    что loopback ::1 доступен (стандарт для всех современных Linux/macOS).
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.close()
        return True
    except (OSError, ValueError):
        return False


def _pk_status() -> str:
    """Возвращает форматированный статус-строку (ANSI-color, для терминала).

    Включает: enabled/active, порты, knock-параметры, размеры ipset
    xray_knocked (IPv4) + xray_knocked6 (IPv6), статистику recent-таблиц
    на порт (IPv4 KNOCK{port} + IPv6 KNOCK{port}v6), число правил в
    iptables/ip6tables, installed_at.
    """
    state = _pk_state_load()
    active = _pk_is_active()

    if active and state["enabled"]:
        status_line = f"{GREEN}● active{NC}"
    elif state["enabled"] and not active:
        status_line = f"{YELLOW}⚠ enabled but rules missing{NC}"
    else:
        status_line = f"{DIM}○ inactive{NC}"

    knocked_size_v4 = _pk_ipset_size(_PK_KNOCKED_SET) if active else 0
    knocked_size_v6 = _pk_ipset_size(_PK_KNOCKED_SET_V6) if active else 0
    rules_v4 = len(_pk_find_rule_lines("iptables")) if active else 0
    rules_v6 = len(_pk_find_rule_lines("ip6tables")) if active else 0

    lines = [
        f"<b>Port Knocking</b> {status_line}",
        f"Ports:           {CYAN}{state['ports']}{NC}",
        f"Knock:           {state['knock_count']} SYN / "
        f"{state['knock_window_sec']}s",
        f"Whitelist TTL:   {state['whitelist_ttl_sec']}s",
        f"xray_knocked:    {knocked_size_v4} IPs (IPv4)",
        f"xray_knocked6:   {knocked_size_v6} IPs (IPv6)",
        f"Rules:           iptables={rules_v4}, ip6tables={rules_v6}",
    ]
    if active:
        for port in state["ports"]:
            rs_v4 = _pk_recent_stats(port)
            rs_v6 = _pk_recent_stats_v6(port)
            if rs_v4["exists"]:
                lines.append(f"  recent KNOCK{port}: "
                             f"{rs_v4['entries']} tracked IPs (IPv4)")
            if rs_v6["exists"]:
                lines.append(f"  recent KNOCK{port}v6: "
                             f"{rs_v6['entries']} tracked IPs (IPv6)")
    if state.get("installed_at"):
        lines.append(f"Installed:       {DIM}{state['installed_at']}{NC}")

    return "\n".join(lines)


# ── Test knock ──────────────────────────────────────────────────────────────────
def _get_server_ipv4():
    """Возвращает публичный IPv4 сервера (из hostname -I).
    Нужно для теста knocking — 127.0.0.1 обходит knocking через
    UFW lo-bypass, поэтому тестировать надо с публичного IP.
    """
    r = _run(["hostname", "-I"], capture=True, quiet=True)
    if r.stdout.strip():
        ips = r.stdout.strip().split()
        # Берем первый non-loopback IPv4
        for ip in ips:
            if not ip.startswith("127.") and "." in ip:
                return ip
    return ""


def _get_server_ipv6():
    """Возвращает глобальный IPv6 адрес сервера."""
    r = _run(["ip", "-6", "addr", "show", "dev", "ens3"], capture=True, quiet=True)
    if r.stdout:
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6 ") and "scope global" in line:
                # Извлекаем адрес: "inet6 2a12:bec4:.../64 scope global"
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1].split("/")[0]
                    return addr
    return ""


def _pk_test_knock(port: int) -> dict:
    """Тест: отправляет N SYN на **публичный IP**:port для IPv4 и IPv6,
    проверяет добавление в xray_knocked / xray_knocked6.

    FIX: раньше тестировал с 127.0.0.1 — но UFW имеет правило
    `-A ufw-before-input -i lo -j ACCEPT` которое обходит все
    knocking-правила для localhost. Поэтому 127.0.0.1 всегда
    "connected" но никогда не попадал в xray_knocked.

    Теперь тест использует публичный IP сервера (из hostname -I),
    который идёт через ens3 (не lo) и реально проходит через
    knocking-правила.

    Если IP в xray_ru_block (GeoIP) — тест пропускается (GeoIP
    DROP маскирует knocking, нужно тестить с внешнего IP).

    Шаги:
      1. Получает публичный IPv4/IPv6 сервера
      2. Проверяет что IP не в xray_ru_block
      3. Очищает IP из ipset + recent
      4. Отправляет knock_count SYN на <pub_ip>:port
      5. Проверяет что IP в xray_knocked
    """
    state = _pk_state_load()
    knock_count = int(state["knock_count"])
    recent_name    = _pk_recent_name(port)
    recent_name_v6 = _pk_recent_name_v6(port)

    # ── IPv4 test ─────────────────────────────────────────────────────────────
    pub_v4 = _get_server_ipv4()
    skip_v4 = False
    skip_v4_reason = ""
    sent_v4 = 0
    in_set_v4 = False
    v4_bypass = False  # SYN connected but IP not in xray_knocked → lo-bypass

    if not pub_v4:
        skip_v4 = True
        skip_v4_reason = "Не удалось определить публичный IPv4"
    else:
        # Check if pub_v4 is in xray_ru_block (GeoIP would DROP before knocking)
        r_ru = _run(["ipset", "test", "xray_ru_block", pub_v4], quiet=True)
        if r_ru.returncode == 0:
            skip_v4 = True
            skip_v4_reason = f"IP {pub_v4} в xray_ru_block (GeoIP DROP маскирует knocking)"
        else:
            # 1. Clear pub_v4 from xray_knocked
            _run(["ipset", "del", _PK_KNOCKED_SET, pub_v4], quiet=True)
            # 2. Clear pub_v4 from recent table
            recent_proc = Path("/proc/net/xt_recent") / recent_name
            if recent_proc.exists():
                try:
                    with recent_proc.open("w") as f:
                        f.write(f"-{pub_v4}\n")
                except Exception:
                    pass
            # 3. Send N SYN to pub_v4:port
            # NOTE: Linux routes self-connections through lo (loopback),
            # so UFW's '-A ufw-before-input -i lo -j ACCEPT' will bypass
            # knocking. We detect this: if SYN connected but IP not in
            # xray_knocked → lo-bypass detected → report accordingly.
            connected_v4 = False
            for _ in range(knock_count):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    rc = sock.connect_ex((pub_v4, port))
                    sock.close()
                    sent_v4 += 1
                    if rc == 0:
                        connected_v4 = True
                except Exception:
                    pass
                time.sleep(0.05)
            # 4. Wait for kernel processing
            time.sleep(0.5)
            # 5. Check pub_v4 in xray_knocked
            r = _run(["ipset", "list", _PK_KNOCKED_SET], capture=True)
            in_set_v4 = pub_v4 in (r.stdout or "")
            # 6. Detect lo-bypass: SYN connected but IP not in xray_knocked
            if connected_v4 and not in_set_v4:
                v4_bypass = True

    # ── IPv6 test ────────────────────────────────────────────────────────────
    pub_v6 = _get_server_ipv6()
    ipv6_available = _pk_ipv6_available()
    skip_v6 = False
    skip_v6_reason = ""
    sent_v6 = 0
    in_set_v6 = False

    if not ipv6_available:
        skip_v6 = True
        skip_v6_reason = "IPv6 loopback недоступен"
    elif not pub_v6:
        skip_v6 = True
        skip_v6_reason = "Не удалось определить публичный IPv6"
    else:
        # Check if pub_v6 is in xray_ru_block6
        r_ru6 = _run(["ipset", "test", "xray_ru_block6", pub_v6], quiet=True)
        if r_ru6.returncode == 0:
            skip_v6 = True
            skip_v6_reason = f"IPv6 {pub_v6} в xray_ru_block6 (GeoIP DROP)"
        else:
            # 1. Clear pub_v6 from xray_knocked6
            _run(["ipset", "del", _PK_KNOCKED_SET_V6, pub_v6], quiet=True)
            # 2. Clear pub_v6 from recent v6 table
            recent_proc_v6 = Path("/proc/net/xt_recent") / recent_name_v6
            if recent_proc_v6.exists():
                try:
                    with recent_proc_v6.open("w") as f:
                        f.write(f"-{pub_v6}\n")
                except Exception:
                    pass
            # 3. Send N SYN to [pub_v6]:port
            for _ in range(knock_count):
                try:
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect_ex((pub_v6, port))
                    sock.close()
                    sent_v6 += 1
                except Exception:
                    pass
                time.sleep(0.05)
            # 4. Wait for kernel processing
            time.sleep(0.5)
            # 5. Check pub_v6 in xray_knocked6
            r = _run(["ipset", "list", _PK_KNOCKED_SET_V6], capture=True)
            in_set_v6 = pub_v6 in (r.stdout or "")

    return {
        "port":              port,
        "knock_count":       knock_count,
        # IPv4
        "ipv4_ip":           pub_v4,
        "sent_syns":         sent_v4,
        "in_xray_knocked":   in_set_v4,
        "success":           in_set_v4,
        "ipv4_skip":         skip_v4,
        "ipv4_skip_reason":  skip_v4_reason,
        "ipv4_bypass":       v4_bypass,
        # IPv6
        "ipv6_available":     ipv6_available,
        "ipv6_ip":           pub_v6,
        "ipv6_sent_syns":     sent_v6,
        "in_xray_knocked6":   in_set_v6,
        "ipv6_success":       in_set_v6,
        "ipv6_skip":          skip_v6,
        "ipv6_skip_reason":  skip_v6_reason,
    }



# ── Box renderer (импорт после хелперов — паттерн honeypot/smart_balancer) ────
from chimera.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)


# ── TUI helpers ─────────────────────────────────────────────────────────────────
def _pk_input(prompt: str, default: str = "") -> str:
    """input() с защитой от EOF/Ctrl+C."""
    try:
        val = input(prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        return default


# ── TUI menu ────────────────────────────────────────────────────────────────────
def do_manage_port_knocking() -> None:
    """TUI меню — точка входа из _core.py main_menu [PK].

    Пункты:
      [1] Включить/выключить port knocking
      [2] Настроить параметры (knock_count, window, ttl)
      [3] Добавить/удалить защищаемый порт
      [4] Показать статус (активные правила, ipset, recent)
      [5] Тест knocking (N SYN → публичный IP:port)
      [6] Список knocked IP (ipset list xray_knocked)
      [Q] Назад в главное меню
    """
    while True:
        os.system("clear")
        print()
        state = _pk_state_load()
        active = _pk_is_active()
        knocked = _pk_ipset_size(_PK_KNOCKED_SET) if active else 0

        status_str = (
            f"{GREEN}● активен{NC}" if active and state["enabled"]
            else f"{YELLOW}⚠ включён, правил нет{NC}" if state["enabled"]
            else f"{DIM}○ не активен{NC}"
        )

        _box_top("🚪  PORT KNOCKING  •  DYNAMIC ACL")
        _box_row(f"  {DIM}Защита VPN-портов от сканеров (Censys/Shodan) через{NC}")
        _box_row(f"  {DIM}dynamic ACL: N SYN за W сек → IP в xray_knocked (TTL).{NC}")
        _box_sep()
        _box_row(f"  Статус:        {status_str}")
        _box_row(f"  Порты:         {CYAN}{state['ports']}{NC}")
        _box_row(f"  Knock:         {state['knock_count']} SYN / "
                 f"{state['knock_window_sec']}s")
        _box_row(f"  Whitelist TTL: {state['whitelist_ttl_sec']}s")
        _box_row(f"  Knocked IPs:   {knocked}")
        if state.get("installed_at"):
            _box_row(f"  Установлен:    {DIM}{state['installed_at']}{NC}")
        _box_sep()
        _box_item("1", f"{'Выключить' if state['enabled'] else 'Включить'} "
                       f"port knocking")
        _box_item("2", f"Настроить параметры {DIM}(knock/window/ttl){NC}")
        _box_item("3", f"Управление портами {DIM}({len(state['ports'])} шт.){NC}")
        _box_item("4", "Показать статус")
        _box_item("5", f"Тест knocking {DIM}(N SYN → публичный IP:port){NC}")
        _box_item("6", f"Список knocked IP {DIM}({knocked} шт.){NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор: {NC}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch in ("q", ""):
            break
        elif ch == "1":
            if state["enabled"]:
                _pk_remove()
            else:
                _pk_install(state)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _pk_menu_configure(state)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            _pk_menu_ports(state)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            print()
            _box_top("🚪  PORT KNOCKING — СТАТУС")
            for line in _pk_status().split("\n"):
                _box_row(f"  {line}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            _pk_menu_test(state)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            _pk_menu_list_knocked()
            input(f"{BLUE}Нажмите Enter...{NC}")


def _pk_menu_configure(state: dict) -> None:
    """Подменю настройки knock_count, knock_window_sec, whitelist_ttl_sec."""
    print()
    _box_top("🚪  PORT KNOCKING — ПАРАМЕТРЫ")
    _box_row(f"  knock_count:       {CYAN}{state['knock_count']}{NC} "
             f"{DIM}(1-20){NC}")
    _box_row(f"  knock_window_sec:  {CYAN}{state['knock_window_sec']}{NC} "
             f"{DIM}(1-300){NC}")
    _box_row(f"  whitelist_ttl_sec: {CYAN}{state['whitelist_ttl_sec']}{NC} "
             f"{DIM}(60-2592000){NC}")
    _box_sep()
    _box_row(f"  {DIM}Изменения применятся сразу если модуль активен.{NC}")
    _box_bottom()

    raw = _pk_input(f"  {CYAN}Новый knock_count "
                    f"[{state['knock_count']}]: {NC}")
    if raw:
        ok, msg = _pk_validate_int(raw, 1, 20, "knock_count")
        if ok:
            state["knock_count"] = int(raw)
        else:
            _warn(msg)

    raw = _pk_input(f"  {CYAN}Новый knock_window_sec "
                    f"[{state['knock_window_sec']}]: {NC}")
    if raw:
        ok, msg = _pk_validate_int(raw, 1, 300, "knock_window_sec")
        if ok:
            state["knock_window_sec"] = int(raw)
        else:
            _warn(msg)

    raw = _pk_input(f"  {CYAN}Новый whitelist_ttl_sec "
                    f"[{state['whitelist_ttl_sec']}]: {NC}")
    if raw:
        ok, msg = _pk_validate_int(raw, 60, 86400 * 30,
                                   "whitelist_ttl_sec")
        if ok:
            state["whitelist_ttl_sec"] = int(raw)
        else:
            _warn(msg)

    _pk_state_save(state)
    _success("Параметры сохранены")

    # Если активно — переприменяем правила с новыми параметрами
    if _pk_is_active():
        _info("Переприменяем правила с новыми параметрами...")
        _pk_remove()
        _pk_install(state)


def _pk_menu_ports(state: dict) -> None:
    """Подменю добавления/удаления защищаемых портов."""
    print()
    _box_top("🚪  PORT KNOCKING — ПОРТЫ")
    for i, p in enumerate(state["ports"], 1):
        _box_row(f"  {DIM}[{i}]{NC}  {CYAN}{p}{NC}")
    _box_sep()
    _box_row(f"  {DIM}[+]{NC}  Добавить порт")
    _box_row(f"  {DIM}[-]{NC}  Удалить порт по номеру")
    _box_bottom()

    act = _pk_input(f"  {CYAN}Действие [+/-/Enter]: {NC}")
    if act == "+":
        raw = _pk_input(f"  {CYAN}Порт (1-65535): {NC}")
        if raw.isdigit():
            p = int(raw)
            ok, msg = _pk_validate_int(p, 1, 65535, "port")
            if ok:
                if p in state["ports"]:
                    _warn(f"Порт {p} уже в списке")
                else:
                    state["ports"].append(p)
                    state["enabled"] = _pk_is_active()
                    _pk_state_save(state)
                    _success(f"Порт {p} добавлен")
                    if state["enabled"]:
                        _info("Переприменяем правила...")
                        _pk_remove()
                        _pk_install(state)
            else:
                _warn(msg)
        else:
            _warn("Порт должен быть числом")
    elif act == "-" and state["ports"]:
        raw = _pk_input(f"  {CYAN}Номер для удаления "
                        f"[1-{len(state['ports'])}]: {NC}")
        if raw.isdigit() and 1 <= int(raw) <= len(state["ports"]):
            removed = state["ports"].pop(int(raw) - 1)
            state["enabled"] = _pk_is_active()
            _pk_state_save(state)
            _success(f"Порт {removed} удалён")
            if state["enabled"]:
                _info("Переприменяем правила...")
                _pk_remove()
                _pk_install(state)
        else:
            _warn("Неверный номер")


def _pk_menu_test(state: dict) -> None:
    """Подменю теста knocking для выбранного порта."""
    if not state["ports"]:
        _warn("Нет защищаемых портов — добавьте хотя бы один [3]")
        return
    if not _pk_is_active():
        _warn("Port knocking не активен — сначала включите [1]")
        return

    print()
    _box_top("🚪  PORT KNOCKING — ТЕСТ")
    for i, p in enumerate(state["ports"], 1):
        _box_row(f"  {DIM}[{i}]{NC}  port {CYAN}{p}{NC}")
    _box_bottom()

    raw = _pk_input(f"  {CYAN}Выбор порта "
                    f"[1-{len(state['ports'])}]: {NC}")
    if not (raw.isdigit() and 1 <= int(raw) <= len(state["ports"])):
        _warn("Неверный выбор")
        return

    port = state["ports"][int(raw) - 1]
    _info(f"Отправляем {state['knock_count']} SYN на публичный IP:{port}...")
    result = _pk_test_knock(port)

    print()
    _box_top("🚪  PORT KNOCKING — РЕЗУЛЬТАТ ТЕСТА")
    _box_row(f"  Порт:              {CYAN}{result['port']}{NC}")
    _box_row(f"  IPv4 SYN:          {result['sent_syns']}/"
             f"{result['knock_count']}")
    if result["success"]:
        ip_v4 = result.get('ipv4_ip', '?')
        _box_row(f"  {ip_v4} в xray_knocked: {GREEN}ДА{NC}")
        _box_row(f"  {GREEN}✓ IPv4 knocking работает{NC}")
    elif result.get("ipv4_bypass"):
        ip_v4 = result.get('ipv4_ip', '?')
        _box_row(f"  {ip_v4} в xray_knocked: {YELLOW}НЕТ{NC}")
        _box_row(f"  {YELLOW}⚠ IPv4 тест невозможен с сервера{NC}")
        _box_row(f"  {DIM}Linux маршрутизирует self-connections через lo,{NC}")
        _box_row(f"  {DIM}UFW '-i lo -j ACCEPT' обходит knocking.{NC}")
        _box_row(f"  {DIM}Knocking работает для внешних IP.{NC}")
        _box_row(f"  {DIM}Проверьте: /probe <ip> 443 из TG-бота{NC}")
    elif result.get("ipv4_skip"):
        _box_row(f"  {YELLOW}⚠ {result.get('ipv4_skip_reason', 'skip')}{NC}")
    else:
        ip_v4 = result.get('ipv4_ip', '?')
        _box_row(f"  {ip_v4} в xray_knocked: {RED}НЕТ{NC}")
        _box_row(f"  {RED}✗ IPv4 тест не пройден{NC}")
    if result.get("ipv6_available"):
        _box_row(f"  IPv6 SYN:          {result['ipv6_sent_syns']}/"
                 f"{result['knock_count']}")
        if result.get("ipv6_success"):
            ip_v6 = result.get('ipv6_ip', '?')
            _box_row(f"  {ip_v6} в xray_knocked6: {GREEN}ДА{NC}")
            _box_row(f"  {GREEN}✓ IPv6 knocking работает{NC}")
        elif result.get("ipv6_skip"):
            _box_row(f"  {YELLOW}⚠ {result.get('ipv6_skip_reason', 'skip')}{NC}")
        else:
            ip_v6 = result.get('ipv6_ip', '?')
            _box_row(f"  {ip_v6} в xray_knocked6: {RED}НЕТ{NC}")
            _box_row(f"  {RED}✗ IPv6 тест не пройден{NC}")
    else:
        _box_row(f"  IPv6:               {DIM}недоступен{NC}")
    _box_bottom()


def _pk_menu_list_knocked() -> None:
    """Показывает список IP в xray_knocked (ipset list)."""
    print()
    if not _pk_ipset_exists(_PK_KNOCKED_SET):
        _warn(f"ipset {_PK_KNOCKED_SET} не существует")
        return

    r = _run(["ipset", "list", _PK_KNOCKED_SET], capture=True)
    if r.returncode != 0:
        _warn("Не удалось получить список")
        return

    lines = (r.stdout or "").splitlines()
    # Фильтруем заголовки (Name, Type, ...), оставляем строки с IP
    ip_lines = [l for l in lines
                if re.match(r"^\d+\.\d+\.\d+\.\d+", l.strip())]

    _box_top(f"🚪  XRAY_KNOCKED — {len(ip_lines)} IPs")
    if not ip_lines:
        _box_row(f"  {DIM}Список пуст{NC}")
    else:
        for line in ip_lines[-30:]:  # последние 30
            _box_row(f"  {CYAN}{line.strip()}{NC}")
        if len(ip_lines) > 30:
            _box_row(f"  {DIM}... и ещё {len(ip_lines) - 30}{NC}")
    _box_bottom()


# ── Автономный запуск ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}")
        sys.exit(1)
    try:
        do_manage_port_knocking()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
