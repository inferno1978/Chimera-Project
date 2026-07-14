"""
chimera/modules/failover.py
───────────────────────────────────────────────────────────────────────────────
Failover-мониторинг exit-нод + авто-фолбэк (Режим B → A).

Две логические части (объединены, т.к. обе работают с состоянием exit-нод):

1. **Failover watchdog** (cron каждую минуту): проверяет TCP-доступность
   exit-нод, пишет результаты в /var/lib/xray-installer/failover.json и
   алертит в Telegram при падении ноды. Экран статуса — do_failover_status.

2. **Auto-fallback** (cron каждую минуту): если все exit-ноды недоступны —
   переключает Xray в Режим A (прямой выход); при восстановлении хотя бы
   одной ноды — возвращает Режим B. Экран управления —
   do_manage_auto_fallback (пункт [~] в главном меню).

Точки входа из _core.py:
    from chimera.modules.failover import (
        _FAILOVER_LOG, _FAILOVER_SCRIPT, _FAILOVER_CRON, _FAILOVER_STATE,
        _failover_load, _failover_save, _failover_install, do_failover_status,
        _auto_fallback_install, _auto_fallback_set_flag, do_manage_auto_fallback,
    )

Константы _AUTO_FALLBACK_* импортируются из smart_balancer; здесь доступны
через core._AUTO_FALLBACK_* (lazy binding).

Доступ к helpers ядра (success/warn/info, _run, _box_*, цвета, STATE_FILE,
_nodes_from_state, _speed_test_node_latency, switch_mode_ab) — через
importlib (lazy binding), как и в других извлечённых модулях.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Константы (failover-секция) ──────────────────────────────────────────────
_FAILOVER_LOG      = Path("/var/log/xray-failover.log")
_FAILOVER_SCRIPT   = Path("/usr/local/bin/xray-failover-watch.sh")
_FAILOVER_CRON     = Path("/etc/cron.d/xray-failover-watch")
_FAILOVER_STATE    = Path("/var/lib/xray-installer/failover.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  FAILOVER СТАТУС EXIT-НОД
# =============================================================================
def _failover_load() -> dict:
    try:
        if _FAILOVER_STATE.exists():
            return json.loads(_FAILOVER_STATE.read_text())
    except Exception:
        pass
    return {}


def _failover_save(data: dict) -> None:
    try:
        _FAILOVER_STATE.parent.mkdir(parents=True, exist_ok=True)
        _FAILOVER_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        pass


def _failover_install(nodes: list, tg_token: str = "", tg_chat: str = "") -> None:
    """Устанавливает watchdog-скрипт для exit-нод с Telegram-алертом."""
    core = _core_module()
    success = core.success

    # Строим список "host port" для bash
    nodes_str = "\n".join(
        f'  check_node "{nd["host"]}" "{nd.get("port", 443)}"'
        for nd in nodes
    )
    tg_block = ""
    if tg_token and tg_chat:
        tg_block = textwrap.dedent(f"""\
            send_tg() {{
                curl -s -o /dev/null -m 5 \\
                    "https://api.telegram.org/bot{tg_token}/sendMessage" \\
                    -d chat_id="{tg_chat}" -d text="$1" || true
            }}
        """)
    else:
        tg_block = "send_tg() { : ; }"  # no-op

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray Failover Watchdog (VLESS Installer)
        LOG="{_FAILOVER_LOG}"
        STATE="{_FAILOVER_STATE}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')

        {tg_block}

        check_node() {{
            local HOST=$1
            local PORT=$2
            if timeout 5 bash -c ">/dev/tcp/$HOST/$PORT" 2>/dev/null; then
                echo "up"
            else
                echo "down"
            fi
        }}

        update_state() {{
            local HOST=$1 STATUS=$2
            python3 -c "
import json, os, time
p = '$STATE'
d = {{}}
if os.path.exists(p):
    with open(p) as f: d = json.load(f)
key = '$HOST'
prev = d.get(key, {{}})
d[key] = {{'status': '$STATUS', 'last_check': time.time(), 'host': '$HOST'}}
if prev.get('status') != '$STATUS':
    d[key]['changed_at'] = time.time()
with open(p, 'w') as f: json.dump(d, f, indent=2)
sys.exit(0 if prev.get('status') == '$STATUS' else 1)
" 2>/dev/null
            return $?
        }}

{nodes_str.replace('check_node', 'STATUS=$(check_node') }

        # Inline loop — генерируем для каждой ноды
        for ITEM in {' '.join(nd['host']+':'+str(nd.get('port',443)) for nd in nodes)}; do
            HOST=${{ITEM%%:*}}
            PORT=${{ITEM##*:}}
            STATUS=$(check_node "$HOST" "$PORT")
            update_state "$HOST" "$STATUS"
            RET=$?
            if [ "$STATUS" = "down" ]; then
                echo "[$DATE] FAILOVER: $HOST:$PORT DOWN" >> "$LOG"
                if [ "$RET" -ne 0 ]; then
                    send_tg "⚠️ VLESS Exit Node DOWN: $HOST:$PORT"
                fi
            fi
        done
    """)
    _FAILOVER_SCRIPT.write_text(script)
    _FAILOVER_SCRIPT.chmod(0o750)
    _FAILOVER_CRON.write_text(f"* * * * * root {_FAILOVER_SCRIPT}\n")
    _FAILOVER_CRON.chmod(0o644)
    success("Failover watchdog установлен (cron каждую минуту)")


def do_failover_status() -> None:
    """Показывает таблицу uptime exit-нод + управление failover watchdog."""
    core = _core_module()
    success = core.success
    warn    = core.warn
    info    = core.info
    STATE_FILE              = core.STATE_FILE
    _nodes_from_state       = core._nodes_from_state
    _speed_test_node_latency = core._speed_test_node_latency
    _box_top                = core._box_top
    _box_row                = core._box_row
    _box_bottom             = core._box_bottom
    _box_item               = core._box_item
    _box_warn               = core._box_warn
    BLUE = core.BLUE
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, GREEN, YELLOW, RED, DIM, BLUE = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.RED, core.DIM, core.BLUE
    )

    # ── AWG-режим: failover нод не применим ──────────────────────────────────
    try:
        if STATE_FILE.exists():
            _st = json.loads(STATE_FILE.read_text())
            if _st.get("awg_exit_enabled", False) and _st.get("install_mode") == "B":
                print()
                _box_top("Failover Exit-нод")
                _box_warn("В режиме AWG 2.0 нет VLESS exit-нод для failover.")
                _box_row(f"  {DIM}Мониторинг туннеля awg0 выполняется через AWG Watchdog.{NC}")
                _box_row(f"  {DIM}Меню → Безопасность → [W] AWG Tunnel Watchdog{NC}")
                _box_bottom()
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
    except Exception:
        pass

    while True:
        os.system("clear")
        print()
        _box_top(f"Failover Exit-нод")

        cron_active = _FAILOVER_CRON.exists()
        _box_row(f"  Watchdog: {''+GREEN+'активен'+NC if cron_active else ''+YELLOW+'отключён'+NC}")

        # Таблица статусов
        state_data = _failover_load()
        if state_data:
            _box_row(f"  {'Нода':<35} {'Статус':<10} {'Изменился'}")
            _box_row(f"  {'─'*60}")
            for host, info_d in state_data.items():
                st = info_d.get("status", "?")
                colour = GREEN if st == "up" else RED
                changed = info_d.get("changed_at", 0)
                changed_str = (datetime.fromtimestamp(changed).strftime("%d.%m %H:%M")
                               if changed else "—")
                _box_row(f"  {CYAN}{host:<35}{NC} {colour}{st:<10}{NC} {DIM}{changed_str}{NC}")
        else:
            _box_row(f"  {DIM}Нет данных — запустите watchdog или проверку вручную{NC}")

        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} watchdog")
        _box_item("2", f"Проверить все ноды прямо сейчас")
        _box_item("3", f"Показать лог ({_FAILOVER_LOG})")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                _FAILOVER_CRON.unlink(missing_ok=True)
                _FAILOVER_SCRIPT.unlink(missing_ok=True)
                success("Failover watchdog отключён")
            else:
                # Загружаем ноды
                try:
                    nodes = _nodes_from_state(json.loads(STATE_FILE.read_text()))
                except Exception:
                    nodes = []
                if not nodes:
                    warn("Ноды не найдены — установите Режим B")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                tg_token = input("  Telegram Bot Token (Enter = без алертов): ").strip()
                tg_chat  = ""
                if tg_token:
                    tg_chat = input("  Telegram Chat ID: ").strip()
                _failover_install(nodes, tg_token, tg_chat)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            try:
                nodes = _nodes_from_state(json.loads(STATE_FILE.read_text()))
            except Exception:
                nodes = []
            if not nodes:
                warn("Ноды не найдены")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            new_state = {}
            for nd in nodes:
                host = nd["host"]
                port = nd.get("port", 443)
                info(f"  Проверка {host}:{port} ...")
                lat = _speed_test_node_latency(host, port)
                st  = "up" if "мс" in lat else "down"
                colour = GREEN if st == "up" else RED
                print(f"    {CYAN}{host}:{port}{NC} → {colour}{st}{NC}  {lat}")
                new_state[host] = {
                    "status": st, "host": host,
                    "last_check": time.time(), "changed_at": time.time()
                }
            _failover_save(new_state)
            print()
            success("Проверка завершена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if _FAILOVER_LOG.exists():
                lines = _FAILOVER_LOG.read_text().splitlines()[-30:]
                print('\n'.join(lines))
            else:
                warn("Лог пуст")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  AUTO-FALLBACK: Режим B → A при отказе всех exit-нод
# =============================================================================
def _auto_fallback_install(nodes: list, tg_token: str = "", tg_chat: str = "") -> None:
    """
    Устанавливает cron-скрипт авто-фолбэка.
    Каждую минуту проверяет все exit-ноды; если ни одна не отвечает —
    переводит xray в временный Режим A (прямой выход).
    При восстановлении хотя бы одной ноды — возвращает Режим B.
    """
    core = _core_module()
    success           = core.success
    STATE_FILE        = core.STATE_FILE
    _AUTO_FALLBACK_LOGFILE = core._AUTO_FALLBACK_LOGFILE
    _AUTO_FALLBACK_SCRIPT  = core._AUTO_FALLBACK_SCRIPT
    _AUTO_FALLBACK_CRON    = core._AUTO_FALLBACK_CRON

    nodes_list = " ".join(
        f'{nd["host"]}:{nd.get("port", 443)}' for nd in nodes
    )

    tg_block = ""
    if tg_token and tg_chat:
        tg_block = textwrap.dedent(f"""\
            send_tg() {{
                curl -s -o /dev/null -m 5 \\
                    "https://api.telegram.org/bot{tg_token}/sendMessage" \\
                    -d chat_id="{tg_chat}" -d text="$1" || true
            }}
        """)
    else:
        tg_block = "send_tg() { : ; }"

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray Auto-Fallback: Mode B → A при отказе всех exit-нод
        # Установлен VLESS Ultimate Installer
        LOG="{_AUTO_FALLBACK_LOGFILE}"
        STATE_FILE="{STATE_FILE}"
        FAILOVER_STATE="{_FAILOVER_STATE}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        NODES="{nodes_list}"
        SCRIPT="{sys.argv[0]}"

        {tg_block}

        log() {{ echo "[$DATE] $1" >> "$LOG"; }}

        # Читаем флаг auto_fallback_to_direct из state.json
        ENABLED=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE_FILE'))
    print('1' if d.get('auto_fallback_to_direct', False) else '0')
except: print('0')
")
        [ "$ENABLED" = "0" ] && exit 0

        # Текущий install_mode из state.json
        CUR_MODE=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE_FILE'))
    print(d.get('install_mode', 'A'))
except: print('A')
")

        # Флаг «мы сами переключились в A как фолбэк»
        IN_FALLBACK=$(python3 -c "
import json, sys
try:
    d = json.load(open('$STATE_FILE'))
    print('1' if d.get('_fallback_active', False) else '0')
except: print('0')
")

        # Проверяем каждую ноду
        ANY_UP=0
        for ITEM in $NODES; do
            HOST=${{ITEM%%:*}}
            PORT=${{ITEM##*:}}
            if timeout 5 bash -c ">/dev/tcp/$HOST/$PORT" 2>/dev/null; then
                ANY_UP=1
                break
            fi
        done

        if [ "$ANY_UP" = "0" ]; then
            # Все ноды мертвы
            if [ "$CUR_MODE" = "B" ] && [ "$IN_FALLBACK" = "0" ]; then
                log "Все exit-ноды недоступны. Переключение в Режим A (фолбэк)."
                # Помечаем фолбэк в state.json
                python3 -c "
import json
p = '$STATE_FILE'
d = json.load(open(p))
d['_fallback_active'] = True
d['_fallback_original_mode'] = d.get('install_mode', 'B')
open(p, 'w').write(json.dumps(d, indent=2))
"
                python3 "$SCRIPT" --switch-mode-a
                send_tg "⚠️ VLESS: все exit-ноды DOWN. Переключён в Режим A (прямой выход)."
            fi
        else
            # Есть живая нода
            if [ "$IN_FALLBACK" = "1" ]; then
                log "Exit-нода восстановлена. Возврат в Режим B."
                python3 -c "
import json
p = '$STATE_FILE'
d = json.load(open(p))
d['_fallback_active'] = False
open(p, 'w').write(json.dumps(d, indent=2))
"
                python3 "$SCRIPT" --switch-mode-b
                send_tg "✅ VLESS: exit-нода восстановлена. Возврат в Режим B (каскад)."
            fi
        fi

        # Если режим B и pinned активен — проверяем живость закреплённой ноды
        if [ "$CUR_MODE" = "B" ] && [ "$IN_FALLBACK" = "0" ]; then
            python3 "$SCRIPT" --pinned-fallback-check >> "$LOG" 2>&1 || true
        fi
    """)

    _AUTO_FALLBACK_SCRIPT.write_text(script)
    _AUTO_FALLBACK_SCRIPT.chmod(0o750)
    _AUTO_FALLBACK_CRON.write_text(f"* * * * * root {_AUTO_FALLBACK_SCRIPT}\n")
    _AUTO_FALLBACK_CRON.chmod(0o644)
    success("Auto-fallback watchdog установлен (cron каждую минуту).")


def _auto_fallback_set_flag(enabled: bool) -> None:
    """Включает/выключает флаг auto_fallback_to_direct в state.json."""
    core = _core_module()
    success    = core.success
    warn       = core.warn
    STATE_FILE = core.STATE_FILE

    if not STATE_FILE.exists():
        warn("state.json не найден.")
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        state["auto_fallback_to_direct"] = enabled
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        status = "включён" if enabled else "отключён"
        success(f"Флаг auto_fallback_to_direct → {status}.")
    except Exception as e:
        warn(f"Ошибка обновления state.json: {e}")


def do_manage_auto_fallback() -> None:
    """
    Меню управления авто-фолбэком (Режим B → A при отказе всех нод).
    Пункт [~] в главном меню.
    """
    core = _core_module()
    success       = core.success
    warn          = core.warn
    info          = core.info
    STATE_FILE    = core.STATE_FILE
    _nodes_from_state = core._nodes_from_state
    switch_mode_ab    = core.switch_mode_ab
    _AUTO_FALLBACK_CRON    = core._AUTO_FALLBACK_CRON
    _AUTO_FALLBACK_SCRIPT  = core._AUTO_FALLBACK_SCRIPT
    _AUTO_FALLBACK_LOGFILE = core._AUTO_FALLBACK_LOGFILE
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_warn   = core._box_warn
    BLUE = core.BLUE
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    YELLOW = core.YELLOW
    CYAN, NC, GREEN, YELLOW, DIM, BLUE = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM, core.BLUE
    )

    # ── AWG-режим: авто-фолбэк на ноды не применим ──────────────────────────
    try:
        if STATE_FILE.exists():
            _st = json.loads(STATE_FILE.read_text())
            if _st.get("awg_exit_enabled", False) and _st.get("install_mode") == "B":
                print()
                _box_top("Авто-фолбэк: Режим B → A")
                _box_warn("В режиме AWG 2.0 авто-фолбэк по нодам недоступен.")
                _box_row(f"  {DIM}Для мониторинга и восстановления AWG-туннеля используйте:{NC}")
                _box_row(f"  {DIM}Меню → Безопасность → [W] AWG Tunnel Watchdog{NC}")
                _box_bottom()
                input(f"{BLUE}Нажмите Enter...{NC}")
                return
    except Exception:
        pass

    while True:
        os.system("clear")
        _box_top(f"Авто-фолбэк: Режим B → A")

        cron_active = _AUTO_FALLBACK_CRON.exists()

        # Читаем текущий флаг из state
        flag_enabled = False
        fallback_active = False
        try:
            st = json.loads(STATE_FILE.read_text())
            flag_enabled = st.get("auto_fallback_to_direct", False)
            fallback_active = st.get("_fallback_active", False)
            install_mode = st.get("install_mode", "A")
        except Exception:
            install_mode = "A"

        _box_row(f"  Watchdog (cron): "
              f"{''+GREEN+'активен'+NC if cron_active else ''+YELLOW+'отключён'+NC}")
        _box_row(f"  Флаг auto_fallback_to_direct: "
              f"{''+GREEN+'ВКЛ'+NC if flag_enabled else ''+YELLOW+'ВЫКЛ'+NC}")
        _box_row(f"  Текущий режим Xray:  {CYAN}{install_mode}{NC}")
        if fallback_active:
            _box_row(f"  {YELLOW}⚠ Сейчас активен фолбэк (все ноды были недоступны){NC}")

        _box_item("1", f'{"Выключить" if flag_enabled else "Включить"} флаг auto_fallback_to_direct')
        _box_item("2", f"{'Отключить' if cron_active else 'Установить'} watchdog-cron")
        if fallback_active:
            _box_item("3", f"{YELLOW}Принудительно вернуться в Режим B прямо сейчас{NC}")
        _box_item("L", f"Показать лог фолбэка ({_AUTO_FALLBACK_LOGFILE})")
        _box_item("Q", f"Назад")

        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _auto_fallback_set_flag(not flag_enabled)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if cron_active:
                _AUTO_FALLBACK_CRON.unlink(missing_ok=True)
                _AUTO_FALLBACK_SCRIPT.unlink(missing_ok=True)
                success("Auto-fallback watchdog отключён.")
            else:
                if install_mode != "B":
                    warn("Авто-фолбэк актуален только при Режиме B.")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                try:
                    nodes = _nodes_from_state(json.loads(STATE_FILE.read_text()))
                except Exception:
                    nodes = []
                if not nodes:
                    warn("Ноды не найдены — установите Режим B.")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                tg_token = input("  Telegram Bot Token (Enter = без алертов): ").strip()
                tg_chat = ""
                if tg_token:
                    tg_chat = input("  Telegram Chat ID: ").strip()
                _auto_fallback_install(nodes, tg_token, tg_chat)
                # Включаем флаг автоматически при установке watchdog
                _auto_fallback_set_flag(True)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3" and fallback_active:
            info("Принудительный возврат в Режим B...")
            try:
                st2 = json.loads(STATE_FILE.read_text())
                st2["_fallback_active"] = False
                STATE_FILE.write_text(json.dumps(st2, indent=2, ensure_ascii=False))
            except Exception:
                pass
            switch_mode_ab()   # текущий режим A → переключит в B

        elif ch == "l":
            if _AUTO_FALLBACK_LOGFILE.exists():
                lines = _AUTO_FALLBACK_LOGFILE.read_text().splitlines()[-40:]
                print("\n".join(lines))
            else:
                warn("Лог пуст.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)
