"""
chimera/modules/quick_status.py
───────────────────────────────────────────────────────────────────────────────
Быстрый статус + тест качества соединения (TTFB).

Содержит (логически объединены: используются одним CLI-флоу ``--status``):
  • ``_STATS_SORT_KEYS`` — словарь опций сортировки статистики пользователей
    (используется ``_do_user_stats_sorted`` в _core.py).
  • ``_TTFB_TARGETS`` — список URL для теста TTFB.
  • ``do_quick_status()`` — CLI entry point для ``--status``: показывает
    сервисы / конфигурацию / активные соединения / SSL / трафик за сегодня /
    ресурсы / автобан / AS-маршруты одной командой без входа в меню.
  • ``do_connection_quality_test()`` — TTFB-тест к Cloudflare/Google/Яндекс/
    GitHub с усреднением и оценкой качества.

Точки входа из _core.py:
    from chimera.modules.quick_status import (
        _STATS_SORT_KEYS, _TTFB_TARGETS,
        do_quick_status, do_connection_quality_test,
    )

Доступ к helpers ядра (``_box_*``, ``_run``, ANSI-цвета, ``STATE_FILE``,
``TRAFFIC_HISTORY_FILE``, ``_users_load``, ``_device_icon``, ``_fmt_bytes_ru``,
``_autoban_load``, ``_as_direct_list_load``, ``_as_action_label``,
``log_to_file``) — через importlib (см. _core_module()).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path


# ── Константы ─────────────────────────────────────────────────────────────────
_STATS_SORT_KEYS = {
    "1": ("traffic", "По трафику ↓"),
    "2": ("last",    "По последнему визиту"),
    "3": ("name",    "По имени"),
    "4": ("label",   "По метке устройства"),
}

_TTFB_TARGETS = [
    ("Cloudflare",  "https://1.1.1.1/cdn-cgi/trace"),
    ("Google",      "https://www.google.com/generate_204"),
    ("Яндекс",      "https://ya.ru"),
    ("GitHub",      "https://github.com"),
]


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ФИЧА 3: БЫСТРЫЙ СТАТУС --status (CLI без интерактива)
# =============================================================================
def do_quick_status() -> None:
    """
    Быстрый статус одной командой: python3 install.py --status
    Показывает всё самое важное за ~2 секунды без входа в меню.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    _run = core._run
    log_to_file = core.log_to_file
    STATE_FILE = core.STATE_FILE
    TRAFFIC_HISTORY_FILE = core.TRAFFIC_HISTORY_FILE
    _users_load    = core._users_load
    _device_icon   = core._device_icon
    _fmt_bytes_ru  = core._fmt_bytes_ru
    _autoban_load  = core._autoban_load
    _as_direct_list_load = core._as_direct_list_load
    _as_action_label     = core._as_action_label
    DIM   = core.DIM
    NC    = core.NC
    BOLD  = core.BOLD
    GREEN = core.GREEN
    RED   = core.RED
    CYAN  = core.CYAN
    YELLOW = core.YELLOW

    print()
    _box_top("VLESS Quick Status")
    ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    _box_row(f"  {DIM}{ts}{NC}")

    # ── Сервисы ─────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Сервисы:{NC}")
    for svc in ("xray", "nginx", "dnscrypt-proxy"):
        r = _run(["systemctl", "is-active", svc], capture=True, check=False)
        st = r.stdout.strip()
        if st == "active":
            _box_row(f"  {GREEN}●{NC} {svc:<22} {GREEN}активен{NC}")
        elif st == "inactive":
            _box_row(f"  {DIM}○{NC} {svc:<22} {DIM}не запущен{NC}")
        else:
            _box_row(f"  {RED}✗{NC} {svc:<22} {RED}{st}{NC}")

    # ── Конфигурация ─────────────────────────────────────────────────────────
    try:
        if STATE_FILE.exists():
            _qs    = json.loads(STATE_FILE.read_text())
            _proto = _qs.get("protocol_mode", "reality")
            _dom   = _qs.get("domain", "")
            _port  = _qs.get("server_port", 443)
            _flow  = _qs.get("xtls_flow", "xtls-rprx-vision")
            if _proto == "reality":
                _proto_label = f"VLESS+REALITY  flow={_flow or 'none'}"
            elif _proto == "xhttp_reality":
                _proto_label = "VLESS+xHTTP+REALITY"
            else:
                _proto_label = "VLESS+xHTTP+TLS"
            _box_row(f"  {BOLD}Конфиг:{NC}")
            _box_row(f"  {CYAN}⚙{NC}  {'Протокол:':<22} {_proto_label}")
            if _dom:
                _box_row(f"  {CYAN}🌐{NC} {'Домен/порт:':<22} {_dom}:{_port}")
            # ── AWG-туннель ──────────────────────────────────────────────────
            if _qs.get("awg_exit_enabled") and _qs.get("install_mode") == "B":
                _awg_host = _qs.get("awg_exit_host", "")
                _awg_port = _qs.get("awg_exit_port", 51820)
                _box_row(f"  {CYAN}🔌{NC} {'AWG exit-VPS:':<22} {_awg_host}:{_awg_port}/udp")
                _r_if = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
                _awg_col = GREEN if _r_if.returncode == 0 else RED
                _awg_status = "активен" if _r_if.returncode == 0 else "НЕ ПОДНЯТ"
                _box_row(f"  {_awg_col}🔌{NC} {'awg0:':<22} {_awg_col}{_awg_status}{NC}")
            _box_row()
    except Exception:
        pass

    # ── Активные соединения ─────────────────────────────────────────────────
    try:
        port = 443
        if STATE_FILE.exists():
            port = json.loads(STATE_FILE.read_text()).get("server_port", 443)
        r = _run(["ss", "-tn", "state", "established"], capture=True, check=False)
        conns = [l for l in r.stdout.splitlines() if f":{port}" in l]
        _box_row(f"  {GREEN}⇄{NC} {'Соединений:':<22} {CYAN}{len(conns)}{NC} на порту {port}")
    except Exception:
        pass

    _box_row()

    # ── SSL ──────────────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}SSL:{NC}")
    domain = ""
    try:
        if STATE_FILE.exists():
            domain = json.loads(STATE_FILE.read_text()).get("domain", "")
    except Exception:
        pass
    if domain:
        cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        if cert.exists():
            try:
                r  = _run(["openssl", "x509", "-in", str(cert),
                           "-noout", "-enddate"], capture=True, check=False)
                ex = r.stdout.strip().split("=", 1)[1]
                r2 = _run(["date", "-d", ex, "+%s"], capture=True, check=False)
                days = (int(r2.stdout.strip()) - int(time.time())) // 86400
                col = GREEN if days > 30 else YELLOW if days > 14 else RED
                _box_row(f"  {col}🔒{NC} {domain:<30} {col}{days} дн.{NC}")
            except Exception:
                _box_row(f"  {DIM}  {domain:<30} (не удалось проверить){NC}")
        else:
            _box_row(f"  {RED}✗{NC} {domain:<30} {RED}сертификат не найден{NC}")
    else:
        _box_row(f"  {DIM}  домен не задан{NC}")


    # ── Трафик за сегодня (из истории) ──────────────────────────────────────
    _box_row(f"  {BOLD}Трафик сегодня:{NC}")
    today = datetime.now().strftime("%Y-%m-%d")
    try:
        if TRAFFIC_HISTORY_FILE.exists():
            hist    = json.loads(TRAFFIC_HISTORY_FILE.read_text())
            day     = hist.get(today, {})
            users   = _users_load()
            total_b = 0
            for u in users:
                email = u.get("email", "")
                val   = day.get(f"{email}_max", 0)
                total_b += val
                if val > 0:
                    icon  = _device_icon(u.get("device_label", ""))
                    label = u.get("device_label") or u.get("name", email)
                    _box_row(f"  {icon} {label:<24} {CYAN}{_fmt_bytes_ru(val)}{NC}")
            if not users or total_b == 0:
                _box_row(f"  {DIM}нет данных (включите сбор снимков: > → 1){NC}")
        else:
            _box_row(f"  {DIM}история не ведётся (включите: > → 1){NC}")
    except Exception:
        _box_row(f"  {DIM}не удалось прочитать{NC}")


    # ── Диск и RAM ──────────────────────────────────────────────────────────
    _box_row(f"  {BOLD}Ресурсы:{NC}")
    try:
        r = _run(["df", "-h", "/"], capture=True, check=False)
        p = r.stdout.splitlines()[-1].split()
        pct = float(p[4].replace("%", ""))
        col = GREEN if pct < 80 else YELLOW if pct < 90 else RED
        _box_row(f"  {col}💾{NC} {'Диск /:':<22} {p[2]}/{p[1]} ({col}{pct:.0f}%{NC})")
    except Exception:
        pass
    try:
        mi = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            mi[k.strip()] = int(v.strip().split()[0])
        total_mb = mi.get("MemTotal", 0) // 1024
        used_mb  = total_mb - mi.get("MemAvailable", 0) // 1024
        pct      = used_mb * 100 // max(total_mb, 1)
        col = GREEN if pct < 80 else YELLOW if pct < 90 else RED
        _box_row(f"  {col}🧠{NC} {'RAM:':<22} {used_mb}/{total_mb} МБ ({col}{pct}%{NC})")
    except Exception:
        pass

    _box_row()

    # ── Автобан ──────────────────────────────────────────────────────────────
    try:
        ban_cfg = _autoban_load()
        n_banned = len(ban_cfg.get("banned", {}))
        if n_banned:
            _box_row(f"  {RED}🚫{NC} Забанено IP:           {RED}{n_banned}{NC}")
    except Exception:
        pass

    # ── AS-маршруты (патч: задача #5) ────────────────────────────────────────
    try:
        _as_qs_entries = _as_direct_list_load()
        if _as_qs_entries:
            _box_row()
            _box_row(f"  {BOLD}AS-маршруты ({len(_as_qs_entries)}):{NC}")
            for _ase in _as_qs_entries:
                _box_row(f"  {CYAN}⇢{NC}  {BOLD}{_ase['asn']}{NC}  [{_as_action_label(_ase.get('action', 'direct'))}]")
    except Exception:
        pass

    _box_bottom()


# =============================================================================
#  ФИЧА 7: ТЕСТ КАЧЕСТВА СОЕДИНЕНИЯ ЧЕРЕЗ EXIT-НОДУ (TTFB)
# =============================================================================
def do_connection_quality_test() -> None:
    """
    Тест качества соединения: TTFB (время до первого байта) к нескольким сайтам.
    Запускается без прокси (прямое соединение с сервера) — показывает реальную
    задержку для пользователей при split-tunnel или после выхода через exit-ноду.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_info   = core._box_info
    _box_bottom = core._box_bottom
    _run = core._run
    log_to_file = core.log_to_file
    DIM   = core.DIM
    NC    = core.NC
    BOLD  = core.BOLD
    GREEN = core.GREEN
    RED   = core.RED
    YELLOW = core.YELLOW
    BLUE  = core.BLUE

    os.system("clear")
    print()
    _box_top(f"Тест качества соединения (TTFB)")
    _box_row(f"  {DIM}Измеряет время до первого байта с сервера (реальная задержка для клиентов){NC}")

    results = []
    for name, url in _TTFB_TARGETS:
        _box_info(f"  Тест {name}...")
        ttfb_ms = None
        http_code = "—"
        try:
            r = _run([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_starttransfer}|%{http_code}|%{time_connect}|%{time_namelookup}",
                "--max-time", "10",
                "--connect-timeout", "5",
                url,
            ], capture=True, check=False)
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.strip().split("|")
                ttfb_ms   = int(float(parts[0]) * 1000)
                http_code = parts[1]
                connect_ms = int(float(parts[2]) * 1000)
                dns_ms    = int(float(parts[3]) * 1000)
                results.append((name, url, ttfb_ms, http_code, connect_ms, dns_ms))
            else:
                results.append((name, url, None, "err", 0, 0))
        except Exception as e:
            results.append((name, url, None, "err", 0, 0))

    _box_row()
    _box_row(f"  {BOLD}{'Сайт':<14} {'TTFB':>8} {'Подключение':>12} {'DNS':>8} {'HTTP':>6}{NC}")
    _box_row(f"  {'─'*14} {'─'*8} {'─'*12} {'─'*8} {'─'*6}")

    for name, url, ttfb, code, conn, dns in results:
        if ttfb is None:
            _box_row(f"  {name:<14} {RED}{'недост.':>8}{NC} {'—':>12} {'—':>8} {RED}{code:>6}{NC}")
        else:
            t_col = GREEN if ttfb < 200 else YELLOW if ttfb < 500 else RED
            c_col = GREEN if conn < 100 else YELLOW if conn < 300 else RED
            _box_row(f"  {name:<14} "
                  f"{t_col}{ttfb:>6} мс{NC} "
                  f"{c_col}{conn:>10} мс{NC} "
                  f"{DIM}{dns:>6} мс{NC} "
                  f"{GREEN if code in ('200','204') else YELLOW}{code:>6}{NC}")

    # Итог
    valid = [r for r in results if r[2] is not None]
    if valid:
        avg_ttfb = sum(r[2] for r in valid) // len(valid)
        _box_row()
        col = GREEN if avg_ttfb < 200 else YELLOW if avg_ttfb < 500 else RED
        _box_row(f"  {BOLD}Средний TTFB: {NC}{col}{avg_ttfb} ms{NC}")
        if avg_ttfb < 150:
            _box_row(f"  {GREEN}✓ Отличное качество соединения{NC}")
        elif avg_ttfb < 300:
            _box_row(f"  {YELLOW}~ Хорошее качество, небольшая задержка{NC}")
        elif avg_ttfb < 600:
            _box_row(f"  {YELLOW}⚠ Повышенная задержка — проверьте нагрузку сервера{NC}")
        else:
            _box_row(f"  {RED}✗ Высокая задержка — возможны проблемы{NC}")
        _box_row()
        _box_bottom()

    log_to_file("INFO", f"TTFB test: avg={avg_ttfb if valid else 'n/a'} ms")
    input(f"{BLUE}Нажмите Enter...{NC}")
