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
    """Сохраняет текущий снимок максимального трафика пользователей за день.

    ДО этого фикса перебирала ТОЛЬКО core._users_load() (VLESS-only из
    users.json) — про telemt/mieru/naiveproxy/awg пользователей не знала
    вообще. В результате в traffic_history.json (и в TUI "По дням")
    отсутствовали все не-VLESS протоколы, даже если их per-user трафик
    корректно собирался в соответствующих stats-модулях.

    Теперь перебирает пользователей ВСЕХ протоколов, у которых есть
    per-user трафик:
      • VLESS (xray) — core._users_load() → email
      • Telemt (mtproto) — mtproto._load_users() → username
      • Mieru — mieru state.users → username
      • NaiveProxy — naiveproxy._load_users() → username
      • AWG Standalone — awgs_state.peers → owner_email

    TrustTunnel намеренно НЕ включён — у него aggregate-only трафик
    (нет per-user breakdown, см. SUPPORTED_PROTOCOLS в
    traffic_accounting.py).

    Ключи в history.json разные для разных протоколов, чтобы избежать
    коллизий: {email}_max для VLESS, mtproto::{username}_max для Telemt,
    и т.д. Это обратно совместимо со старыми данными {email}_max.
    """
    core = _core_module()
    _users_load = core._users_load

    # Lazy-импорт диспетчера (создан в traffic_tracking.py)
    try:
        from chimera.modules.traffic_tracking import query_user_traffic_bytes
    except Exception as _e:
        # Fallback на старый путь (VLESS-only) если диспетчер недоступен
        try:
            core.log_to_file("WARN",
                f"_traffic_snapshot_save: dispatcher unavailable ({_e}), "
                f"VLESS-only fallback")
        except Exception:
            pass
        query_user_traffic_bytes = None

    now_date = datetime.now().strftime("%Y-%m-%d")
    try:
        history = json.loads(TRAFFIC_HISTORY_FILE.read_text()) if TRAFFIC_HISTORY_FILE.exists() else {}
    except Exception:
        history = {}
    day_data = history.setdefault(now_date, {})

    # ── VLESS (через dispatcher или legacy _query_user_traffic_bytes) ────────
    users = _users_load()
    for u in users:
        email = u.get("email", "")
        if not email:
            continue
        if query_user_traffic_bytes is not None:
            used_bytes = query_user_traffic_bytes(email, "xray")
        else:
            used_bytes = core._query_user_traffic_bytes(email)
        # Сохраняем максимум — счётчики Stats API накопительные с момента запуска
        key = f"{email}_max"
        day_data[key] = max(day_data.get(key, 0), used_bytes)

    # ── Telemt (mtproto) — per-user username ─────────────────────────────────
    if query_user_traffic_bytes is not None:
        try:
            from chimera.modules.mtproto import _load_users as _mtproto_load_users
            mtproto_users = _mtproto_load_users() or {}
            for username in mtproto_users:
                used_bytes = query_user_traffic_bytes(username, "mtproto")
                key = f"mtproto::{username}_max"
                day_data[key] = max(day_data.get(key, 0), used_bytes)
        except Exception as _e:
            try:
                core.log_to_file("DEBUG",
                    f"_traffic_snapshot_save: mtproto users skipped ({_e})")
            except Exception:
                pass

        # ── Mieru — per-user username ────────────────────────────────────────
        try:
            from chimera.modules.proto_common import proto_load_state
            from chimera.modules.mieru import _MODULE_STATE as _mieru_state
            mieru_state = proto_load_state(_mieru_state) or {}
            for u in mieru_state.get("users", []):
                username = u.get("username", "") or u.get("email", "")
                if not username:
                    continue
                used_bytes = query_user_traffic_bytes(username, "mieru")
                key = f"mieru::{username}_max"
                day_data[key] = max(day_data.get(key, 0), used_bytes)
        except Exception as _e:
            try:
                core.log_to_file("DEBUG",
                    f"_traffic_snapshot_save: mieru users skipped ({_e})")
            except Exception:
                pass

        # ── NaiveProxy — per-user username ───────────────────────────────────
        try:
            from chimera.modules.naiveproxy import _load_users as _naive_load_users
            naive_users = _naive_load_users() or []
            for u in naive_users:
                username = u.get("username", "") or u.get("email", "")
                if not username:
                    continue
                used_bytes = query_user_traffic_bytes(username, "naiveproxy")
                key = f"naiveproxy::{username}_max"
                day_data[key] = max(day_data.get(key, 0), used_bytes)
        except Exception as _e:
            try:
                core.log_to_file("DEBUG",
                    f"_traffic_snapshot_save: naiveproxy users skipped ({_e})")
            except Exception:
                pass

        # ── AWG Standalone — per-peer owner_email ────────────────────────────
        try:
            from chimera.modules.awg_state import awgs_state_load
            awgs_state = awgs_state_load() or {}
            for peer in awgs_state.get("peers", []):
                owner_email = peer.get("owner_email", "")
                if not owner_email:
                    continue
                used_bytes = query_user_traffic_bytes(owner_email, "awg")
                key = f"awg::{owner_email}_max"
                day_data[key] = max(day_data.get(key, 0), used_bytes)
        except Exception as _e:
            try:
                core.log_to_file("DEBUG",
                    f"_traffic_snapshot_save: awg peers skipped ({_e})")
            except Exception:
                pass

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
    # Cron-скрипт раньше содержал инлайн-реализацию опроса Xray Stats API —
    # жёстко VLESS-only. Теперь делегирует в проектную функцию
    # _traffic_snapshot_save(), которая перебирает ВСЕ протоколы
    # (VLESS/Telemt/Mieru/NaiveProxy/AWG) через единый диспетчер
    # query_user_traffic_bytes(). Это убирает дублирование и автоматически
    # подключает все протоколы в дневной снэпшот.
    #
    # /opt/chimera — canonical install path (см. trusttunnel.py:149,
    # _PROJECT_ROOT = Path("/opt/chimera")). Fallback на cwd если
    # запускают из другого места.
    script_lines = [
        "#!/bin/bash",
        "# Auto-generated by chimera.modules.traffic_history._install_traffic_snapshot_cron",
        "# Calls project function _traffic_snapshot_save() — multi-protocol.",
        "set -e",
        "export PYTHONPATH=/opt/chimera:${PYTHONPATH:-}",
        "cd /opt/chimera 2>/dev/null || true",
        "python3 - <<'PYEOF'",
        "import sys",
        "try:",
        "    from chimera.modules.traffic_history import _traffic_snapshot_save",
        "    _traffic_snapshot_save()",
        "except Exception as e:",
        "    print(f'snapshot failed: {e}', file=sys.stderr)",
        "    sys.exit(1)",
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

                # ── Мультипротокольный список пользователей ──────────────────
                # Раньше тут были только VLESS-emails из _users_load(). Теперь
                # берём также пользователей mtproto/mieru/naiveproxy/awg, чьи
                # ключи в history.json имеют вид "<proto>::<id>_max".
                # Ключ VLESS остаётся "<email>_max" для обратной совместимости
                # со старыми снимками.
                all_user_keys: list[tuple[str, str]] = []  # (display_label, history_key_prefix)
                for u in users:
                    email = u.get("email", "")
                    if email:
                        all_user_keys.append((email, f"{email}_max"))

                # Подгружаем ключи из history.json для остальных протоколов.
                # Берём все ключи вида "<proto>::<id>_max" из всех дней.
                seen_keys: set[str] = set()
                for day_data in history.values():
                    for k in day_data.keys():
                        if "::" in k and k.endswith("_max") and k not in seen_keys:
                            seen_keys.add(k)
                            # display_label = "proto::id" (без _max)
                            all_user_keys.append((k[:-4], k))

                if not all_user_keys:
                    _box_row(f"  {DIM}Пользователей нет{NC}")
                else:
                    sorted_dates = sorted(history.keys())[-14:]
                    max_bytes = max(
                        (history.get(d, {}).get(key, 0)
                         for d in sorted_dates for _, key in all_user_keys),
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
                    # Берём топ-5 пользователей по суммарному трафику за период,
                    # чтобы график не перегружался (>5 цветов нет).
                    totals_per_user = [
                        (label, key, sum(history.get(d, {}).get(key, 0) for d in sorted_dates))
                        for label, key in all_user_keys
                    ]
                    totals_per_user.sort(key=lambda t: t[2], reverse=True)
                    top5 = totals_per_user[:5]

                    for date in sorted_dates:
                        day_total = 0
                        bar_parts = []
                        for idx, (_label, key, _total) in enumerate(top5):
                            val   = history.get(date, {}).get(key, 0)
                            day_total += val
                            filled = int(val / scale) if scale else 0
                            col = colours[idx % len(colours)]
                            bar_parts.append(f"{col}{'▓' * filled}{NC}")
                        bar_str   = "".join(bar_parts)
                        total_str = fmt_bytes(day_total)
                        _box_row(f"  {date:<12} {bar_str:<{bar_width+30}} {DIM}{total_str}{NC}")

                    for idx, (label, _key, _total) in enumerate(top5):
                        col = colours[idx % len(colours)]
                        _box_row(f"  {col}#{NC} {label}")

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
