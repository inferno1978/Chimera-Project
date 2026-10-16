"""
chimera/modules/mieru_cascade_monitor.py
───────────────────────────────────────────────────────────────────────────────
TG-монитор mieru-каскада — реплика бот-паттерна VLESS для Mieru.

Аналогии (что уже работало для VLESS и чего не было для Mieru):
  • node_health_monitor.py — cron-проверка exit-нод VLESS-каскада с
    TG-алертом при СМЕНЕ состояния (анти-спам по построению);
  • xray-tg-monitor.sh v2 — events-фильтр telegram.json + {H}-заголовок
    [host | ip];
  • certmon v2 — суточные штампы вместо повторов.

Здесь то же самое для mieru-каскада (Entry→Exit, health-тик */1 мин):

  mieru_cascade.json (пишет health-тик каждую минуту)
        │  читаем БЕЗ проб (пробы уже делает тик — не дублируем сеть)
        ▼
  check_cascade_once():
      • stall:   данные старше STALE_AFTER (5 пропущенных тиков)
                 → mieru_stalled (таймер/сервис health-тика умер)
      • mita:    systemctl is-active mita
                 → mieru_down / mieru_up
      • Exit-ы:  healthy из state (fail_streak ≥ 2 — тот же порог,
                 что в health_tick: 2 подряд E2E-фейла)
                 → mieru_exit_down / mieru_exit_up (по каждому Exit-у)
      • кризис:  активных Exit-ов 0 при включённых > 0
                 → mieru_no_exits (каскад мёртв, трафик встал)
      • hop/redsocks-юниты: is-active — только в ЛОГ (self-healing
        health-тика + exit-проба ловят реальные отказы; отдельные
        алерты по юнитам спамили бы при рестартах)

  Анти-спам: алерт ТОЛЬКО при смене состояния; первое наблюдение
  (нет сохранённого) — молча. Состояние — отдельный файл
  mieru-cascade-monitor-state.json (не путать с mieru_cascade.json).

  Каждый алерт проверяет events.<event> в telegram.json (как v2
  мониторы); отсутствующий ключ = включено (default True).

Публичный API:
    check_cascade_once()               → list[dict] — разовая проверка
    install_cascade_monitor(interval)  → (bool, str) — cron + wrapper
    uninstall_cascade_monitor()        → (bool, str)
    is_monitor_installed()             → bool
    do_cascade_monitor_menu()          → None — TUI-меню
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ── Пути (все — модульные константы: тесты патчат их в tmp) ──────────────────
TG_CONFIG      = Path("/var/lib/xray-installer/telegram.json")
CASCADE_STATE  = Path("/var/lib/xray-installer/mieru_cascade.json")
MONITOR_STATE  = Path("/var/lib/xray-installer/mieru-cascade-monitor-state.json")
MONITOR_LOG    = Path("/var/log/mieru-cascade-monitor.log")
CRON_FILE      = Path("/etc/cron.d/mieru-cascade-monitor")
CHECK_SCRIPT   = Path("/usr/local/bin/mieru-cascade-monitor.sh")

# ── Параметры ─────────────────────────────────────────────────────────────────
DEFAULT_INTERVAL = 5        # минут (как xray-tg-monitor)
STALE_AFTER      = 300      # сек: 5 пропущенных тиков (тик = 1 мин)
TG_TIMEOUT       = 10       # сек

# ── События (метки для меню tg_bot; порядок синхронизирован) ─────────────────
EVENT_KEYS = [
    "mieru_down", "mieru_up", "mieru_exit_down", "mieru_exit_up",
    "mieru_no_exits", "mieru_stalled",
]
EVENT_LABELS = {
    "mieru_down":     "Mieru: mita упал",
    "mieru_up":       "Mieru: mita восстановился",
    "mieru_exit_down": "Mieru: Exit недоступен (2+ фейла)",
    "mieru_exit_up":  "Mieru: Exit восстановился",
    "mieru_no_exits": "Mieru: все Exit-ы недоступны",
    "mieru_stalled":  "Mieru: health-tick не обновляется",
}


# ── Вспомогательные ───────────────────────────────────────────────────────────

def _run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _log(msg: str) -> None:
    try:
        MONITOR_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(MONITOR_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _hostname() -> str:
    try:
        return _run(["hostname", "-s"]).stdout.strip() or "server"
    except Exception:
        return "server"


def _systemd_is_active(unit: str) -> str:
    """'active' | 'inactive' | ... — обёртка для тестов."""
    try:
        r = _run(["systemctl", "is-active", unit], timeout=10)
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


def _tg_send(msg: str, event: str = "") -> bool:
    """Отправка в TG с проверкой events.<event> (паттерн v2-мониторов).

    Отсутствующий ключ events = включено (default True) — новые
    mieru-события работают сразу, без правки telegram.json.
    """
    try:
        if not TG_CONFIG.exists():
            return False
        cfg = json.loads(TG_CONFIG.read_text(encoding="utf-8"))
        token, chat = cfg.get("token", ""), cfg.get("chat_id", "")
        if not token or not chat:
            return False
        if event and not cfg.get("events", {}).get(event, True):
            return False
        # {H}-заголовок как в xray-tg-monitor v2: [host | ip]
        host = _hostname()
        ip = cfg.get("server_ip", "")
        header = f"[{host} | {ip}]" if ip else f"[{host}]"
        text = msg.replace("{H}", header)
        _cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-m", str(TG_TIMEOUT)]
        _px = str(cfg.get("proxy") or "").strip()
        if _px:
            _cmd += ["-x", _px]
        _cmd += [
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat}",
            "-d", f"text={text}",
            "-d", "parse_mode=HTML",
        ]
        r = _run(_cmd)
        return (r.stdout or "").strip() == "200"
    except Exception:
        return False


def _load_monitor_state() -> dict:
    try:
        if MONITOR_STATE.exists():
            return json.loads(MONITOR_STATE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_monitor_state(st: dict) -> None:
    try:
        MONITOR_STATE.parent.mkdir(parents=True, exist_ok=True)
        MONITOR_STATE.write_text(
            json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _newest_exit_check(exits: list) -> float | None:
    """Самый свежий last_check среди Exit-ов (epoch) — для stall-детекции."""
    newest: float | None = None
    for e in exits:
        v = e.get("last_check", "")
        if not v:
            continue
        try:
            ts = datetime.strptime(str(v), "%Y-%m-%d %H:%M:%S").timestamp()
        except Exception:
            continue
        if newest is None or ts > newest:
            newest = ts
    return newest


# ── Ядро: разовая проверка ────────────────────────────────────────────────────

def check_cascade_once() -> list[dict]:
    """Разовая проверка mieru-каскада. TG-алерты только при смене состояния.

    Возвращает список результатов (для меню):
      [{'id','label','host','healthy','fail_streak','latency_ms','unit_hop',
        'unit_redsocks','changed'}, ...] + служебные записи mita/stall.
    """
    results: list[dict] = []
    alerts: list[tuple[str, str]] = []          # (event, msg) — собираем, шлём

    if not CASCADE_STATE.exists():
        _log("нет mieru_cascade.json — каскад не настроен, выходим")
        return results

    try:
        st = json.loads(CASCADE_STATE.read_text(encoding="utf-8"))
    except Exception as exc:
        _log(f"mieru_cascade.json не читается: {exc}")
        return results
    if st.get("role") != "entry":
        return results

    exits = [e for e in st.get("exits", []) if e.get("enabled", True)]
    prev = _load_monitor_state()
    prev_exits: dict = prev.get("exits", {})
    new_exits: dict = {}
    ts = time.strftime("%d.%m.%Y %H:%M")
    host_hdr = "{H}"

    # ── 1. stall: health-тик не обновляет данные ───────────────────────────
    stalled_now = False
    if exits:
        newest = _newest_exit_check(exits)
        try:
            f_mtime = CASCADE_STATE.stat().st_mtime
        except Exception:
            f_mtime = 0.0
        ref = max(newest or 0.0, f_mtime)
        stalled_now = (time.time() - ref) > STALE_AFTER
    prev_stalled = bool(prev.get("stalled"))
    if stalled_now and not prev_stalled:
        alerts.append(("mieru_stalled",
            "⚠️ <b>{H}</b> Mieru health-tick не обновляется "
            f"(&gt;{STALE_AFTER // 60} мин)\n"
            "Проверь <code>systemctl status mieru-cascade-health.timer</code>\n"
            f"<i>{ts}</i>"))
        _log("STALL: health-tick не обновляет mieru_cascade.json")
    elif not stalled_now and prev_stalled:
        alerts.append(("mieru_stalled",
            "🟢 <b>{H}</b> Mieru health-tick обновляется\n"
            f"<i>{ts}</i>"))
        _log("STALL восстановлен")

    # ── 2. mita: сервис жив? ────────────────────────────────────────────────
    mita_active = _systemd_is_active("mita") == "active"
    prev_mita = prev.get("mita", {}).get("active")
    if prev_mita is True and not mita_active:
        alerts.append(("mieru_down",
            "🔴 <b>{H}</b> Mieru (mita) не запущен!\n"
            f"<i>{ts}</i>"))
        _log("MITA DOWN")
    elif prev_mita is False and mita_active:
        alerts.append(("mieru_up",
            "🟢 <b>{H}</b> Mieru (mita) восстановился.\n"
            f"<i>{ts}</i>"))
        _log("MITA UP")
    results.append({"id": "mita", "label": "mita", "host": "local",
                    "healthy": mita_active, "changed": False,
                    "service": "mita"})

    # ── 3. Exit-ы: healthy из state (порог fail_streak ≥ 2 — как в тике) ───
    for e in exits:
        eid = e.get("id") or e.get("label") or "?"
        label = e.get("label") or eid
        healthy = bool(e.get("healthy", False))
        streak = int(e.get("fail_streak", 0))
        latency = e.get("latency_ms")
        host = e.get("host", "?")

        pe = prev_exits.get(eid, {})
        prev_h = pe.get("healthy")
        first_seen = prev_h is None
        changed = (prev_h is not None) and (prev_h != healthy)
        new_exits[eid] = {
            "healthy": healthy, "last_change": time.time() if changed else
            pe.get("last_change", time.time()),
        }

        unit_hop = _systemd_is_active(f"mieru-hop@{eid}")
        unit_reds = _systemd_is_active(f"mieru-cascade-redsocks@{eid}")
        if unit_hop != "active":
            _log(f"unit mieru-hop@{eid}: {unit_hop} (self-healing тика)")
        if unit_reds != "active":
            _log(f"unit mieru-cascade-redsocks@{eid}: {unit_reds} (self-healing тика)")

        results.append({
            "id": eid, "label": label, "host": host,
            "healthy": healthy, "fail_streak": streak,
            "latency_ms": latency, "changed": changed,
            "unit_hop": unit_hop, "unit_redsocks": unit_reds,
        })

        if changed and not first_seen:
            if not healthy:
                alerts.append(("mieru_exit_down",
                    "🔴 <b>{H}</b> Mieru Exit недоступен\n"
                    f"✗ <code>{label}</code> ({host}) — "
                    f"fail_streak {streak}\n"
                    f"<i>{ts}</i>"))
                _log(f"EXIT DOWN: {eid} (streak {streak})")
            else:
                ms = f" — {latency:.0f} мс" if isinstance(latency, (int, float)) else ""
                alerts.append(("mieru_exit_up",
                    "🟢 <b>{H}</b> Mieru Exit восстановлен\n"
                    f"✓ <code>{label}</code> ({host}){ms}\n"
                    f"<i>{ts}</i>"))
                _log(f"EXIT UP: {eid}")

    # ── 4. кризис: живых Exit-ов 0 при включённых > 0 ───────────────────────
    no_exits_now = bool(exits) and not any(x["healthy"] for x in exits)
    prev_no = bool(prev.get("no_exits"))
    if no_exits_now and not prev_no:
        alerts.append(("mieru_no_exits",
            "🚨 <b>{H}</b> Mieru каскад: все Exit-ы недоступны\n"
            f"Трафик каскада мёртв ({len(exits)} шт. unhealthy)\n"
            f"<i>{ts}</i>"))
        _log("NO EXITS: все unhealthy")
    elif not no_exits_now and prev_no:
        n_ok = sum(1 for x in exits if x["healthy"])
        alerts.append(("mieru_no_exits",
            "🟢 <b>{H}</b> Mieru каскад восстановлен: "
            f"{n_ok}/{len(exits)} Exit-ов здоровы\n"
            f"<i>{ts}</i>"))
        _log(f"NO EXITS снят: {n_ok}/{len(exits)}")

    # ── отправка (после всех вычислений — atomic по смыслу) ─────────────────
    for event, msg in alerts:
        ok = _tg_send(msg, event)
        _log(f"TG[{event}] {'sent' if ok else 'SKIPPED/off'}: "
             + msg.replace("\n", " ")[:90])

    _save_monitor_state({
        "exits": new_exits,
        "mita": {"active": mita_active,
                 "last_change": time.time()},
        "stalled": stalled_now,
        "no_exits": no_exits_now,
        "last_check": time.time(),
    })
    return results


# ── Установка / удаление cron ────────────────────────────────────────────────

def is_monitor_installed() -> bool:
    return CRON_FILE.exists() and CHECK_SCRIPT.exists()


def _get_installed_interval() -> int:
    try:
        if CRON_FILE.exists():
            for line in CRON_FILE.read_text().splitlines():
                if line.startswith("*/"):
                    return int(line.split()[0].replace("*/", ""))
    except Exception:
        pass
    return DEFAULT_INTERVAL


def _find_installer_path() -> str:
    """Как в node_health_monitor: путь установки пакета chimera."""
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    return "/opt/chimera"


def _find_python() -> str:
    for p in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if Path(p).exists():
            return p
    return "python3"


def install_cascade_monitor(interval: int = DEFAULT_INTERVAL) -> tuple[bool, str]:
    """cron /etc/cron.d/mieru-cascade-monitor + wrapper-скрипт.

    Wrapper — тот же паттерн, что xray-node-health-check.sh и
    mieru-cascade-health.sh: PYTHONPATH безопасен, импорт модуля,
    вызов check_cascade_once().
    """
    try:
        interval = max(1, min(60, int(interval)))
        installer_path = _find_installer_path()
        python = _find_python()
        CHECK_SCRIPT.write_text(
            f"""#!/bin/bash
# mieru-cascade-monitor.sh — TG-монитор mieru-каскада (Chimera)
# Читает mieru_cascade.json (health-тик */1 мин) + systemd; алерты
# при СМЕНЕ состояния (анти-спам), события events.<event> в telegram.json.
export PYTHONPATH="{installer_path}:$PYTHONPATH"
{python} -c "
import sys
sys.path.insert(0, '{installer_path}')
from chimera.modules.mieru_cascade_monitor import check_cascade_once
check_cascade_once()
" 2>>/var/log/mieru-cascade-monitor.log
""", encoding="utf-8")
        CHECK_SCRIPT.chmod(0o755)

        CRON_FILE.write_text(
            f"""# mieru-cascade-monitor — TG-монитор mieru-каскада каждые {interval} мин
*/{interval} * * * * root {CHECK_SCRIPT} >/dev/null 2>&1
""", encoding="utf-8")
        CRON_FILE.chmod(0o644)
        _log(f"установлен cron */{interval} (wrapper {CHECK_SCRIPT})")
        return True, f"Mieru cascade monitor установлен (интервал: {interval} мин)"
    except Exception as e:
        return False, f"Ошибка установки: {e}"


def uninstall_cascade_monitor() -> tuple[bool, str]:
    try:
        CRON_FILE.unlink(missing_ok=True)
        CHECK_SCRIPT.unlink(missing_ok=True)
        MONITOR_STATE.unlink(missing_ok=True)
        _log("удалён (cron + wrapper + state)")
        return True, "Mieru cascade monitor удалён (cron+скрипт+state)"
    except Exception as e:
        return False, f"Ошибка удаления: {e}"


# ── TUI-меню (паттерн node_health_monitor.do_health_monitor_menu) ────────────

def do_cascade_monitor_menu() -> None:
    import os
    from chimera.modules import mieru_cascade as mcs

    m = mcs._mieru()
    while True:
        os.system("clear")
        installed = is_monitor_installed()
        interval = _get_installed_interval() if installed else DEFAULT_INTERVAL

        try:
            st = json.loads(CASCADE_STATE.read_text(encoding="utf-8"))
        except Exception:
            st = {}
        exits = [e for e in st.get("exits", []) if e.get("enabled", True)]
        ms = _load_monitor_state()

        m._box_top("🧅  TG-МОНИТОР MIERU-КАСКАДА")
        m._box_row("  Алерты в Telegram при смене состояния каскада:")
        m._box_row("  mita up/down, Exit-ы, health-tick, «все Exit-ы down».")
        m._box_row("  Анти-спам: только изменения; events.<event> в telegram.json.")
        m._box_sep()
        status = f"{m.GREEN}активен{m.NC}" if installed else f"{m.YELLOW}не активен{m.NC}"
        m._box_kv("Статус:", status)
        if installed:
            m._box_kv("Интервал:", f"{m.BOLD}{interval} мин{m.NC}")
        if st:
            mita_on = ms.get("mita", {}).get("active")
            mita_str = ("—" if mita_on is None else
                        f"{m.GREEN}active{m.NC}" if mita_on else f"{m.RED}down{m.NC}")
            m._box_kv("mita:", mita_str)
            stalled = bool(ms.get("stalled"))
            m._box_kv("health-tick:",
                      f"{m.RED}stalled{m.NC}" if stalled else f"{m.GREEN}живой{m.NC}")
        m._box_sep()

        if exits:
            m._box_row(f"  {'Exit':<28} {'Статус':<10} {'RTT':>7}  streak")
            m._box_sep()
            for e in exits:
                eid = e.get("id") or e.get("label") or "?"
                label = e.get("label") or eid
                healthy = bool(e.get("healthy", False))
                lat = e.get("latency_ms")
                st_str = f"{m.GREEN}UP{m.NC}" if healthy else f"{m.RED}DOWN{m.NC}"
                lat_str = f"{lat:.0f}мс" if isinstance(lat, (int, float)) else "—"
                m._box_row(f"  {label:<28} {st_str:<10} {lat_str:>7}  "
                           f"{e.get('fail_streak', 0)}")
        else:
            m._box_row(f"  {m.DIM}Каскад не настроен (роль entry без Exit-ов){m.NC}")
        m._box_sep()
        m._box_item("C", "Проверить сейчас")
        if not installed:
            m._box_item("I", f"Установить (интервал {DEFAULT_INTERVAL} мин)")
            m._box_item("I10", "Установить — каждые 10 мин")
            m._box_item("I30", "Установить — каждые 30 мин")
        else:
            m._box_item("U", "Удалить")
        m._box_item("Q", "← Назад в меню каскада")
        m._box_bot()
        print()

        try:
            ch = m.proto_ask(f"{m.CYAN}Выбор: {m.NC}", c=True).strip().upper()
        except Exception:
            return
        if ch in ("0", "Q", ""):
            return
        elif ch == "C":
            rs = check_cascade_once()
            if not rs:
                m._box_warn("Каскад не настроен — проверять нечего")
            else:
                for r in rs:
                    if r.get("service") == "mita":
                        continue
                    icon = f"{m.GREEN}✓{m.NC}" if r["healthy"] else f"{m.RED}✗{m.NC}"
                    lat = r.get("latency_ms")
                    lat_s = f"{lat:.0f} мс" if isinstance(lat, (int, float)) else "—"
                    m._box_row(f"  {icon} {r['label']} ({r['host']}) — "
                               f"{'UP ' + lat_s if r['healthy'] else 'DOWN'}"
                               + (" [изменился]" if r.get("changed") else ""))
            input(f"{m.CYAN}Нажмите Enter...{m.NC}")
        elif ch in ("I", "I5"):
            ok, msg = install_cascade_monitor(DEFAULT_INTERVAL)
            m._box_ok(msg) if ok else m._box_warn(msg)
            input(f"{m.CYAN}Нажмите Enter...{m.NC}")
        elif ch == "I10":
            ok, msg = install_cascade_monitor(10)
            m._box_ok(msg) if ok else m._box_warn(msg)
            input(f"{m.CYAN}Нажмите Enter...{m.NC}")
        elif ch == "I30":
            ok, msg = install_cascade_monitor(30)
            m._box_ok(msg) if ok else m._box_warn(msg)
            input(f"{m.CYAN}Нажмите Enter...{m.NC}")
        elif ch == "U" and installed:
            ok, msg = uninstall_cascade_monitor()
            m._box_ok(msg) if ok else m._box_warn(msg)
            input(f"{m.CYAN}Нажмите Enter...{m.NC}")
