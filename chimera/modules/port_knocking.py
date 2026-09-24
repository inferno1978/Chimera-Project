"""
chimera/modules/port_knocking.py
───────────────────────────────────────────────────────────────────────────────
Port Knocking — динамический ACL для защиты VPN-портов (443, 9443) от
интернет-сканеров (Censys, Shodan) и пассивного DPI-фингерпринтинга.

Концепция:
  • iptables DROP by default на защищаемом порту (например :443)
  • Каждый SYN-пакет трекается через `recent` iptables-модуль
  • После N SYN за W секунд → IP добавляется в ipset `xray_knocked` (с TTL)
  • Если IP в `xray_knocked` → SYN ACCEPTED → VLESS REALITY handshake проходит
  • Whitelist IPs в существующем ipset `clients_wl` → обходят knocking (приоритет)
  • Существующий `xray_manual_ban` ipset → DROP независимо от knocking

Порядок правил iptables (приоритет — позиция в INPUT):
  1. INSERT 1: -m set --match-set xray_manual_ban src -j DROP    (бан от ipban.py)
  2. INSERT 2: -m set --match-set clients_wl src     -j ACCEPT  (wl от user_ip_whitelist.py)
  3. INSERT 3: -m set --match-set xray_knocked src    -j ACCEPT  (кто постучался)
  4. APPEND:   --syn -m recent --name KNOCK{port} --set           (трекать SYN)
  5. APPEND:   --syn -m recent --rcheck --seconds W --hitcount N
              -m set --add-set xray_knocked src                    (повысить до knocked)
  6. APPEND:   --syn -j DROP                                       (default deny)

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
#   `xray_knocked`    — СОЗДАЁТСЯ этим модулем (с TTL timeout)
#   `clients_wl`      — уже существует (user_ip_whitelist.py) — читаем, не трогаем
#   `xray_manual_ban` — уже существует (ipban.py) — читаем, не трогаем
_PK_KNOCKED_SET    = "xray_knocked"
_PK_MANUAL_BAN_SET = "xray_manual_ban"
_PK_WL_SET         = "clients_wl"

# Comment-маркер для всех iptables-правил модуля — для идемпотентной установки
# и безопасной очистки при remove(): ищем/удаляем только свои правила.
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
        "knock_window_sec":  _DEFAULT_KNOCK_WINDOW_SEC,
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
    """Имя recent-таблицы для порта (уникальное per-port).

    xt_recent имеет глобальный лимит на размер таблицы (ip_list_tot, default 100).
    Уникальное имя per-port (KNOCK443, KNOCK9443) позволяет независимо трекать
    SYN на разных портах без взаимных коллизий.
    """
    return f"KNOCK{port}"


def _pk_build_iptables_rules(port: int, state: dict) -> list:
    """Строит список iptables rule descriptors для порта.

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
        #    (без -j target: --add-set — side-effect match, пакет продолжает
        #     падать ниже → правило 6 его дропнет; но IP уже в xray_knocked,
        #     следующий SYN попадёт в INSERT #3 и будет ACCEPT)
        {"op": "append",
         "spec": base + ["--syn",
                         "-m", "recent", "--name", recent_name,
                         "--rcheck", "--seconds", str(knock_window),
                         "--hitcount", str(knock_count),
                         "-m", "set", "--add-set", _PK_KNOCKED_SET,
                         "src"] + comment},
        # 6. Default deny: DROP всех остальных SYN на этом порту
        {"op": "append",
         "spec": base + ["--syn", "-j", "DROP"] + comment},
    ]

    return insert_rules + append_rules


def _pk_build_ipset_create_cmd(state: dict) -> list:
    """Команда создания ipset xray_knocked с TTL timeout.

        ipset create xray_knocked hash:ip timeout 3600 exist

    `exist` flag — идемпотентность: не падает если set уже есть.
    """
    return ["ipset", "create", _PK_KNOCKED_SET, "hash:ip",
            "timeout", str(int(state["whitelist_ttl_sec"])), "-exist"]


def _pk_rule_exists(spec: list) -> bool:
    """Проверяет наличие правила через `iptables -C INPUT <spec>`."""
    cmd = ["iptables", "-C", "INPUT"] + spec
    return _run(cmd, quiet=True).returncode == 0


def _pk_ipset_exists(name: str) -> bool:
    """Существует ли ipset с указанным именем."""
    r = _run(["ipset", "list", name], capture=True)
    return r.returncode == 0


# ── Persistence (best-effort, без падения если tools отсутствуют) ────────────
def _pk_persist() -> None:
    """Сохраняет iptables-правила и ipset, чтобы пережить reboot.

    Best-effort: если netfilter-persistent/iptables-save/ipset save недоступны
    или нет прав на запись — молча пропускаем (правила не переживут reboot,
    но модуль можно повторно активировать через меню).
    """
    # iptables
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
    # ipset
    try:
        ipset_save_path = Path("/etc/iptables/ipsets")
        if ipset_save_path.parent.exists() and _pk_ipset_exists(_PK_KNOCKED_SET):
            r = _run(["ipset", "save", _PK_KNOCKED_SET], capture=True)
            if r.returncode == 0 and r.stdout:
                ipset_save_path.write_text(r.stdout)
    except Exception:
        pass


# ── Install / Remove ───────────────────────────────────────────────────────────
def _pk_install(state: dict) -> bool:
    """Устанавливает ipset + iptables-правила для всех портов в state['ports'].

    Идемпотентно:
      • ipset создаётся с флагом `exist` (не падает если уже есть)
      • каждое iptables-правило проверяется через `-C` перед `-I`/`-A`
        (не дублирует уже установленные правила)

    При успехе обновляет state (enabled=True, installed_at=сейчас) и вызывает
    _pk_persist() для сохранения правил через reboot.
    """
    errors = _pk_validate(state)
    if errors:
        _err(f"State invalid: {errors[0]}")
        return False

    if not state.get("ports"):
        _warn("No ports configured — nothing to install")
        return False

    # 1. Создаём ipset xray_knocked (идемпотентно через `exist` flag)
    ipset_cmd = _pk_build_ipset_create_cmd(state)
    r = _run(ipset_cmd, capture=True)
    if r.returncode != 0:
        _err(f"ipset create failed: {(r.stderr or '').strip()[:120]}")
        return False
    _log("INFO", f"ipset {_PK_KNOCKED_SET} ready "
                 f"(timeout={state['whitelist_ttl_sec']}s)")

    # 2. Устанавливаем правила для каждого порта (идемпотентно через -C)
    installed_rules = 0
    for port in state["ports"]:
        rules = _pk_build_iptables_rules(port, state)
        for rule in rules:
            if _pk_rule_exists(rule["spec"]):
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

    # 3. Обновляем state
    state["enabled"] = True
    state["installed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _pk_state_save(state)

    # 4. Persist для survive reboot
    _pk_persist()

    _success(f"Port knocking installed: ports={state['ports']}, "
             f"knock={state['knock_count']}/{state['knock_window_sec']}s, "
             f"ttl={state['whitelist_ttl_sec']}s "
             f"({installed_rules} new rules)")
    _log("INFO", f"installed: ports={state['ports']}, "
                 f"new_rules={installed_rules}")

    _tg_notify_event("port_knocking",
        f"<b>Port knocking</b> enabled: ports={state['ports']}, "
        f"knock={state['knock_count']}/{state['knock_window_sec']}s, "
        f"ttl={state['whitelist_ttl_sec']}s")
    return True


def _pk_remove() -> bool:
    """Удаляет все iptables-правила с нашим comment-тегом + flush/destroy ipset.

    Безопасно вызывать многократно: если правил/сет нет — ничего не делает.

    Алгоритм:
      1. В цикле `iptables -S INPUT` → найти строки с _PK_COMMENT_TAG →
         конвертировать `-A INPUT <spec>` → `-D INPUT <spec>` → выполнить.
         Повторять пока не останется наших правил (защита от бесконечного
         цикла — 60 итераций = 6 правил × 10 портов максимум).
      2. `ipset flush xray_knocked` + `ipset destroy xray_knocked`
         (этот set создан нами — безопасно уничтожать; clients_wl и
         xray_manual_ban не трогаем — они чужие).
      3. Обновляем state (enabled=False, installed_at='').
      4. _pk_persist() чтобы сохранить ОЧИЩЕННОЕ состояние iptables.
    """
    removed_rules = 0

    # 1. Удаляем все iptables-правила с нашим comment-тегом
    for _ in range(60):  # защита от бесконечного цикла
        r = _run(["iptables", "-S", "INPUT"], capture=True)
        lines = [l for l in (r.stdout or "").splitlines()
                 if _PK_COMMENT_TAG in l]
        if not lines:
            break
        line = lines[0]
        if not line.startswith("-A INPUT"):
            break
        # Конвертируем "-A INPUT <spec>" → "-D INPUT <spec>"
        del_args = ["iptables", "-D", "INPUT"] + line.split()[2:]
        r2 = _run(del_args, capture=True)
        if r2.returncode != 0:
            break
        removed_rules += 1

    # 2. Flush + destroy ipset xray_knocked (создан нами — безопасно)
    if _pk_ipset_exists(_PK_KNOCKED_SET):
        _run(["ipset", "flush", _PK_KNOCKED_SET], quiet=True)
        r = _run(["ipset", "destroy", _PK_KNOCKED_SET], capture=True)
        if r.returncode != 0:
            _log("WARN", f"ipset destroy failed: "
                         f"{(r.stderr or '').strip()[:120]}")

    # 3. Обновляем state
    state = _pk_state_load()
    state["enabled"] = False
    state["installed_at"] = ""
    _pk_state_save(state)

    # 4. Persist очищенного состояния
    _pk_persist()

    _success(f"Port knocking removed ({removed_rules} rules deleted, "
             f"ipset {_PK_KNOCKED_SET} destroyed)")
    _log("INFO", f"removed: deleted_rules={removed_rules}")

    _tg_notify_event("port_knocking", "<b>Port knocking</b> disabled")
    return True


# ── Status ──────────────────────────────────────────────────────────────────────
def _pk_is_active() -> bool:
    """Активен ли модуль сейчас (есть ли правила с нашим тегом в iptables)."""
    r = _run(["iptables", "-S", "INPUT"], capture=True)
    return _PK_COMMENT_TAG in (r.stdout or "")


def _pk_ipset_size(name: str) -> int:
    """Число записей в ipset (0 если не существует)."""
    r = _run(["ipset", "list", name], capture=True)
    if r.returncode != 0:
        return 0
    m = re.search(r"Number of entries:\s*(\d+)", r.stdout or "")
    return int(m.group(1)) if m else 0


def _pk_recent_stats(port: int) -> dict:
    """Статистика recent-таблицы для порта через /proc/net/xt_recent.

    Возвращает dict {name, exists, entries}.
    """
    name = _pk_recent_name(port)
    proc_file = Path("/proc/net/xt_recent") / name
    if not proc_file.exists():
        return {"name": name, "exists": False, "entries": 0}
    try:
        lines = proc_file.read_text(errors="replace").splitlines()
        return {"name": name, "exists": True, "entries": len(lines)}
    except Exception:
        return {"name": name, "exists": False, "entries": 0}


def _pk_status() -> str:
    """Возвращает форматированный статус-строку (ANSI-color, для терминала).

    Включает: enabled/active, порты, knock-параметры, размер ipset
    xray_knocked, статистику recent-таблиц на порт, installed_at.
    """
    state = _pk_state_load()
    active = _pk_is_active()

    if active and state["enabled"]:
        status_line = f"{GREEN}● active{NC}"
    elif state["enabled"] and not active:
        status_line = f"{YELLOW}⚠ enabled but rules missing{NC}"
    else:
        status_line = f"{DIM}○ inactive{NC}"

    knocked_size = _pk_ipset_size(_PK_KNOCKED_SET) if active else 0

    lines = [
        f"<b>Port Knocking</b> {status_line}",
        f"Ports:           {CYAN}{state['ports']}{NC}",
        f"Knock:           {state['knock_count']} SYN / "
        f"{state['knock_window_sec']}s",
        f"Whitelist TTL:   {state['whitelist_ttl_sec']}s",
        f"xray_knocked:    {knocked_size} IPs",
    ]
    if active:
        for port in state["ports"]:
            rs = _pk_recent_stats(port)
            if rs["exists"]:
                lines.append(f"  recent KNOCK{port}: {rs['entries']} tracked IPs")
    if state.get("installed_at"):
        lines.append(f"Installed:       {DIM}{state['installed_at']}{NC}")

    return "\n".join(lines)


# ── Test knock ──────────────────────────────────────────────────────────────────
def _pk_test_knock(port: int) -> dict:
    """Тест: отправляет N SYN на localhost:port, проверяет добавление в xray_knocked.

    Шаги:
      1. Очищает 127.0.0.1 из xray_knocked (если уже там)
      2. Очищает 127.0.0.1 из recent-таблицы (через /proc/net/xt_recent/<name>)
      3. Отправляет knock_count SYN на 127.0.0.1:port (connect_ex, короткий timeout)
      4. Ждёт 0.3с для обработки в kernel
      5. Проверяет, что 127.0.0.1 в ipset list xray_knocked

    Возвращает dict: {port, sent_syns, knock_count, in_xray_knocked, success}.
    """
    state = _pk_state_load()
    knock_count = int(state["knock_count"])

    # 1. Очищаем 127.0.0.1 из xray_knocked (если уже там)
    _run(["ipset", "del", _PK_KNOCKED_SET, "127.0.0.1"], quiet=True)

    # 2. Очищаем 127.0.0.1 из recent-таблицы
    #    /proc/net/xt_recent/<name> принимает команды: +IP (add), -IP (remove)
    recent_name = _pk_recent_name(port)
    recent_proc = Path("/proc/net/xt_recent") / recent_name
    if recent_proc.exists():
        try:
            with recent_proc.open("w") as f:
                f.write("-127.0.0.1\n")
        except Exception:
            pass

    # 3. Отправляем N SYN на localhost:port
    #    connect_ex возвращает 0 при успехе (соединение установлено) или
    #    errno при ошибке (ECONNREFUSED/ETIMEDOUT). Нам неважно — мы только
    #    инициируем SYN, который пройдёт через iptables INPUT и обновит recent.
    sent = 0
    for _ in range(knock_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex(("127.0.0.1", port))
            sock.close()
            sent += 1
        except Exception:
            pass
        time.sleep(0.05)  # небольшая пауза между SYN

    # 4. Ждём обработки в kernel (recent --set, --rcheck, --add-set)
    time.sleep(0.3)

    # 5. Проверяем, что 127.0.0.1 в xray_knocked
    r = _run(["ipset", "list", _PK_KNOCKED_SET], capture=True)
    in_set = "127.0.0.1" in (r.stdout or "")

    return {
        "port":            port,
        "sent_syns":       sent,
        "knock_count":     knock_count,
        "in_xray_knocked": in_set,
        "success":         in_set,
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
      [5] Тест knocking (N SYN → localhost:port)
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
        _box_item("5", f"Тест knocking {DIM}(N SYN → localhost:port){NC}")
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
        _box_row(f"  {DIM}[{i}]{NC}  localhost:{CYAN}{p}{NC}")
    _box_bottom()

    raw = _pk_input(f"  {CYAN}Выбор порта "
                    f"[1-{len(state['ports'])}]: {NC}")
    if not (raw.isdigit() and 1 <= int(raw) <= len(state["ports"])):
        _warn("Неверный выбор")
        return

    port = state["ports"][int(raw) - 1]
    _info(f"Отправляем {state['knock_count']} SYN на localhost:{port}...")
    result = _pk_test_knock(port)

    print()
    _box_top("🚪  PORT KNOCKING — РЕЗУЛЬТАТ ТЕСТА")
    _box_row(f"  Порт:              {CYAN}{result['port']}{NC}")
    _box_row(f"  Отправлено SYN:    {result['sent_syns']}/"
             f"{result['knock_count']}")
    if result["success"]:
        _box_row(f"  127.0.0.1 в xray_knocked: {GREEN}ДА{NC}")
        _box_row(f"  {GREEN}✓ Тест пройден — knocking работает{NC}")
    else:
        _box_row(f"  127.0.0.1 в xray_knocked: {RED}НЕТ{NC}")
        _box_row(f"  {RED}✗ Тест не пройден — проверьте правила "
                 f"iptables{NC}")
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
