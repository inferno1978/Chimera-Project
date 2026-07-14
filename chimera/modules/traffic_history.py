"""
chimera/modules/traffic_history.py
───────────────────────────────────────────────────────────────────────────────
МОДУЛЬ 6: История трафика по дням (ASCII-гистограмма).

Содержит:
  • ``TRAFFIC_HISTORY_FILE`` — путь к /var/lib/xray-installer/traffic_history.json
    (накапливает ежедневные снимки максимального трафика пользователей;
    ротация — 90 дней).
  • ``_traffic_snapshot_save()`` — CLI/cron entry point: читает актуальные
    счётчики Stats API для каждого пользователя, сохраняет максимум за день
    в ``TRAFFIC_HISTORY_FILE`` и подчищает записи старше 90 дней.
  • ``_install_traffic_snapshot_cron()`` — установка cron-задачи (каждые 15
    минут) и bash-обёртки ``/usr/local/bin/xray-traffic-snapshot.sh``
    (heredoc с встроенным Python-скриптом — независим от _core.py).
  • ``do_traffic_history()`` — интерактивное меню: показать гистограмму
    последних 14 дней, включить/выключить сбор снимков, сохранить снимок
    прямо сейчас.

Точки входа из _core.py:
    from chimera.modules.traffic_history import (
        TRAFFIC_HISTORY_FILE,
        _traffic_snapshot_save, _install_traffic_snapshot_cron, do_traffic_history,
    )

Доступ к helpers ядра (``_box_*``, ``_users_load``, ``_query_user_traffic_bytes``,
ANSI-цвета, ``success``/``info``/``warn``) — через importlib (см. _core_module()).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path


# ── Константы ─────────────────────────────────────────────────────────────────
TRAFFIC_HISTORY_FILE = Path("/var/lib/xray-installer/traffic_history.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  МОДУЛЬ 6: ИСТОРИЯ ТРАФИКА ПО ДНЯМ (ASCII-ГИСТОГРАММА)
# =============================================================================
def _traffic_snapshot_save() -> None:
    """Сохраняет текущий снимок максимального трафика пользователей за день."""
    core = _core_module()
    _users_load = core._users_load
    _query_user_traffic_bytes = core._query_user_traffic_bytes

    users = _users_load()
    if not users:
        return
    now_date = datetime.now().strftime("%Y-%m-%d")
    try:
        history = json.loads(TRAFFIC_HISTORY_FILE.read_text()) if TRAFFIC_HISTORY_FILE.exists() else {}
    except Exception:
        history = {}
    day_data = history.setdefault(now_date, {})
    for u in users:
        email = u.get("email", "")
        if not email:
            continue
        used_bytes = _query_user_traffic_bytes(email)
        # Сохраняем максимум — счётчики Stats API накопительные с момента запуска
        key = f"{email}_max"
        day_data[key] = max(day_data.get(key, 0), used_bytes)
    # Удаляем данные старше 90 дней
    cutoff = time.time() - 90 * 86400
    history = {
        date: data for date, data in history.items()
        if datetime.strptime(date, "%Y-%m-%d").timestamp() >= cutoff
    }
    TRAFFIC_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False))
    TRAFFIC_HISTORY_FILE.chmod(0o600)


def _install_traffic_snapshot_cron() -> None:
    core = _core_module()
    success = core.success

    sh = Path("/usr/local/bin/xray-traffic-snapshot.sh")
    # Используем heredoc вместо python3 -c "..." чтобы избежать проблем
    # с экранированием кавычек и невалидным shebang на Debian 13 / dash.
    script_lines = [
        "#!/bin/bash",
        "python3 - <<'PYEOF'",
        "import json, re, subprocess, sys, time",
        "from pathlib import Path",
        "from datetime import datetime",
        "XRAY_BIN = Path('/usr/local/bin/xray')",
        "XRAY_STATS_API_PORT = 10085",
        "USERS_FILE = Path('/etc/xray/users.json')",
        "TRAFFIC_HISTORY_FILE = Path('/var/lib/xray-installer/traffic_history.json')",
        "",
        "def _run(args):",
        "    return subprocess.run(args, capture_output=True, text=True)",
        "",
        "def _users_load():",
        "    try: return json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else []",
        "    except: return []",
        "",
        "def qbytes(email):",
        "    total = 0",
        "    for d in ('uplink', 'downlink'):",
        "        r = _run([str(XRAY_BIN), 'api', 'statsquery',",
        "            f'--server=127.0.0.1:{XRAY_STATS_API_PORT}',",
        "            f'--pattern=user>>>{email}>>>{d}'])",
        "        for line in r.stdout.splitlines():",
        '            m = re.search(r\'"value"\\s*:\\s*"?(\\d+)"?\', line)',
        "            if m: total += int(m.group(1))",
        "    return total",
        "",
        "users = _users_load()",
        "if not users: sys.exit(0)",
        "now_date = datetime.now().strftime('%Y-%m-%d')",
        "try:",
        "    history = json.loads(TRAFFIC_HISTORY_FILE.read_text()) if TRAFFIC_HISTORY_FILE.exists() else {}",
        "except: history = {}",
        "day_data = history.setdefault(now_date, {})",
        "for u in users:",
        "    email = u.get('email', '')",
        "    if not email: continue",
        "    used = qbytes(email)",
        "    key = f'{email}_max'",
        "    day_data[key] = max(day_data.get(key, 0), used)",
        "cutoff = time.time() - 90 * 86400",
        "history = {d: v for d, v in history.items()",
        "    if datetime.strptime(d, '%Y-%m-%d').timestamp() >= cutoff}",
        "TRAFFIC_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)",
        "TRAFFIC_HISTORY_FILE.write_text(json.dumps(history, indent=2))",
        "PYEOF",
    ]
    sh.write_text("\n".join(script_lines) + "\n")
    sh.chmod(0o750)
    cron_p = Path("/etc/cron.d/xray-traffic-snapshot")
    cron_p.write_text(f"*/15 * * * * root {sh} >> /var/log/xray-traffic-snapshot.log 2>&1\n")
    cron_p.chmod(0o644)
    success("Cron снимков трафика установлен (каждые 15 мин)")




def do_traffic_history() -> None:
    """Показывает ASCII-гистограмму трафика по дням (последние 14 дней)."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    _box_warn   = core._box_warn
    _users_load = core._users_load
    success = core.success
    info    = core.info
    warn    = core.warn
    GREEN  = core.GREEN
    NC     = core.NC
    YELLOW = core.YELLOW
    DIM    = core.DIM
    CYAN   = core.CYAN
    BLUE   = core.BLUE
    BOLD   = core.BOLD
    MAGENTA = core.MAGENTA

    while True:
        os.system("clear")
        print()
        _box_top(f"История трафика по дням")

        cron_active = Path("/etc/cron.d/xray-traffic-snapshot").exists()
        _box_row(f"  Сбор снимков: {''+GREEN+'ВКЛЮЧЁН (15 мин)'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")

        if not TRAFFIC_HISTORY_FILE.exists():
            _box_row(f"  {DIM}Данных пока нет. Включите сбор снимков [1] и подождите.{NC}")
        else:
            try:
                history = json.loads(TRAFFIC_HISTORY_FILE.read_text())
                users   = _users_load()
                all_emails = list(dict.fromkeys(
                    u.get("email", "") for u in users if u.get("email")
                ))

                if not all_emails:
                    _box_row(f"  {DIM}Пользователей нет{NC}")
                else:
                    sorted_dates = sorted(history.keys())[-14:]
                    max_bytes = max(
                        (history.get(d, {}).get(f"{email}_max", 0)
                         for d in sorted_dates for email in all_emails),
                        default=1
                    )
                    bar_width = 28
                    scale = max_bytes / bar_width if max_bytes else 1

                    def fmt_bytes(b: int) -> str:
                        if b >= 1024**3: return f"{b/1024**3:.2f} ГБ"
                        if b >= 1024**2: return f"{b/1024**2:.1f} МБ"
                        if b >= 1024:    return f"{b/1024:.0f} КБ"
                        return f"{b} Б"

                    colours = [CYAN, GREEN, MAGENTA, YELLOW, BLUE]
                    _box_row(f"  {BOLD}{'Дата':<12} {'Трафик':<{bar_width+2}} {'Итого'}{NC}")
                    _box_row(f"  {'─'*12} {'─'*bar_width} {'─'*12}")
                    for date in sorted_dates:
                        day_total = 0
                        bar_parts = []
                        for idx, email in enumerate(all_emails[:5]):
                            val   = history.get(date, {}).get(f"{email}_max", 0)
                            day_total += val
                            filled = int(val / scale) if scale else 0
                            col = colours[idx % len(colours)]
                            bar_parts.append(f"{col}{'▓' * filled}{NC}")
                        bar_str   = "".join(bar_parts)
                        total_str = fmt_bytes(day_total)
                        _box_row(f"  {date:<12} {bar_str:<{bar_width+30}} {DIM}{total_str}{NC}")

                    for idx, email in enumerate(all_emails[:5]):
                        col = colours[idx % len(colours)]
                        _box_row(f"  {col}#{NC} {email}")

            except Exception as e:
                _box_warn(f"Ошибка чтения истории: {e}")

        _box_row()
        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} сбор снимков (cron 15 мин)")
        _box_item("2", f"Сохранить снимок прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                Path("/etc/cron.d/xray-traffic-snapshot").unlink(missing_ok=True)
                Path("/usr/local/bin/xray-traffic-snapshot.sh").unlink(missing_ok=True)
                success("Сбор снимков отключён")
            else:
                _install_traffic_snapshot_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            info("Сохранение снимка...")
            _traffic_snapshot_save()
            success("Снимок сохранён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
