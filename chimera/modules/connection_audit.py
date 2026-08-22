"""
chimera/modules/connection_audit.py
───────────────────────────────────────────────────────────────────────────────
Аудит подключений Xray (access.log + error.log + active sockets).

Содержит интерактивный экран «Аудит подключений» и helpers для парсинга и
агрегации данных:

  • do_connection_audit()        — главное меню (сводка / хронология /
                                    подозрительная активность / активные сейчас)
  • _parse_access_log()          — парсит /var/log/xray/access.log → list[dict]
  • _audit_user_summary()        — сводка по пользователям (email / IP / время)
  • _audit_recent_connections(n) — последние N подключений в хронологии
  • _audit_suspicious()          — топ-IP по ошибкам + последние строки error.log
  • _audit_active_now()          — `ss -tnp` established соединения с процессом xray

Точки входа из _core.py:
    from chimera.modules.connection_audit import (
        do_connection_audit,
        _parse_access_log,
        _audit_user_summary,
        _audit_recent_connections,
        _audit_suspicious,
        _audit_active_now,
    )

Доступ к helpers ядра (_box_*, _run, цвета, info/warn/success, ASN lookup
helpers) — через importlib (lazy binding), как и в других извлечённых модулях
(standalone_screens.py, asn_cache.py, warp.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  ГЛАВНОЕ МЕНЮ: АУДИТ ПОДКЛЮЧЕНИЙ
# ============================================================================
def do_connection_audit() -> None:
    """Аудит access.log: кто подключался, когда, сколько, откуда."""
    core = _core_module()
    _box_top    = core._box_top
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    warn        = core.warn
    CYAN, NC, BLUE = core.CYAN, core.NC, core.BLUE

    while True:
        os.system("clear")
        print()
        _box_top(f"Аудит подключений")
        _box_item("1", f"Сводка по пользователям")
        _box_item("2", f"Последние 50 подключений (хронология)")
        _box_item("3", f"Подозрительная активность")
        _box_item("4", f"Активные соединения прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _audit_user_summary()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _audit_recent_connections(50)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            _audit_suspicious()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            _audit_active_now()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _parse_access_log() -> list:
    """Парсит /var/log/xray/access.log в список dict."""
    core = _core_module()
    warn = core.warn

    log_path = Path("/var/log/xray/access.log")
    if not log_path.exists():
        warn(f"access.log не найден: {log_path}")
        return []

    entries = []
    # Формат Xray: 2024/01/15 12:34:56 accepted tcp:1.2.3.4:1234 ... email:user@domain
    pattern = re.compile(
        r'(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+'
        r'(?:from\s+(?P<from_ip>[^:]+):\d+\s+)?'
        r'(?P<action>\w+)\s+(?P<proto>\w+):(?P<dst_ip>[^:]+):(?P<src_port>\d+)'
        r'(?:\s+(?P<dst>\S+))?(?:\s+\[(?P<tag>[^\]]*)\])?'
        r'(?:.*?email:\s*(?P<email>\S+))?'
    )
    try:
        lines = log_path.read_text(errors="replace").splitlines()
        for line in lines[-10000:]:
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            dt_str  = ""
            dt      = None
            action  = ""
            src_ip  = ""
            email   = ""
            if m:
                dt_str = f"{m.group('date')} {m.group('time')}"
                try:
                    dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
                except Exception:
                    pass
                action = m.group("action") or ""
                src_ip = m.group("from_ip") or m.group("dst_ip") or ""
                email  = m.group("email")  or ""
            else:
                m2 = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\w+)', line)
                if m2:
                    dt_str = f"{m2.group(1)} {m2.group(2)}"
                    try:
                        dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
                    except Exception:
                        pass
                    action = m2.group(3)
                    ip_m   = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):\d+', line)
                    src_ip = ip_m.group(1) if ip_m else ""
                    em_m   = re.search(r'email:(\S+)', line)
                    email  = em_m.group(1) if em_m else ""
                else:
                    continue
            entries.append({
                "dt": dt, "dt_str": dt_str, "action": action,
                "src_ip": src_ip, "email": email, "raw": line,
                "dst": m.group("dst") if m else "",
            })
    except Exception as e:
        warn(f"Ошибка чтения access.log: {e}")
    return entries


def _audit_user_summary() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    info        = core.info
    warn        = core.warn
    BOLD, NC, CYAN, DIM = core.BOLD, core.NC, core.CYAN, core.DIM

    print()
    info("Анализ access.log...")
    all_entries = _parse_access_log()
    entries = [e for e in all_entries if e.get("action", "").lower() == "accepted"]
    if not entries:
        log_path = Path("/var/log/xray/access.log")
        if not log_path.exists():
            warn("access.log не найден — xray не запущен или путь не задан в config.json")
        elif log_path.stat().st_size == 0:
            warn("access.log пустой — xray запущен с loglevel=warning")
            info("Для аудита подключений нужен loglevel=info в config.json → перезапустите xray")
        elif not all_entries:
            warn("access.log есть, но записи не распознаны — нестандартный формат")
        else:
            warn("access.log есть, но записи 'accepted' не найдены")
            info("Причина: loglevel=warning — xray не пишет подключения при таком уровне")
            info("Для аудита: config.json → log.loglevel = 'info', затем перезапустите xray")
        return

    from collections import defaultdict
    stats: dict = defaultdict(lambda: {"connections": 0, "ips": set(), "first": None, "last": None})

    for e in entries:
        key    = e.get("email") or "[без email]"
        src_ip = e.get("src_ip", "")
        dt     = e.get("dt")
        s      = stats[key]
        s["connections"] += 1
        if src_ip:
            s["ips"].add(src_ip)
        if dt:
            if s["first"] is None or dt < s["first"]: s["first"] = dt
            if s["last"]  is None or dt > s["last"]:  s["last"]  = dt

    _box_top("Сводка по пользователям")
    _box_row(f"  {BOLD}{'Пользователь':<30} {'Соед.':<8} {'IP':<8} {'Первое':<18} {'Последнее'}{NC}")
    _box_sep()
    for email, s in sorted(stats.items(), key=lambda x: -x[1]["connections"]):
        first_str = s["first"].strftime("%d.%m %H:%M") if s["first"] else "—"
        last_str  = s["last"].strftime("%d.%m %H:%M")  if s["last"]  else "—"
        col = CYAN if email != "[без email]" else DIM
        _box_row(f"  {col}{email:<30}{NC} {s['connections']:<8} {len(s['ips']):<8} {first_str:<18} {last_str}")
    _box_sep()
    _box_row(f"  {DIM}Всего записей: {len(entries)}{NC}")
    _box_row()
    _box_bottom()


def _audit_recent_connections(n: int = 50) -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    info        = core.info
    warn        = core.warn
    BOLD, NC, GREEN, RED, DIM = core.BOLD, core.NC, core.GREEN, core.RED, core.DIM

    print()
    info(f"Последние {n} записей access.log:")
    entries = _parse_access_log()
    if not entries:
        warn("Нет данных")
        return
    _box_top(f"Последние {n} подключений")
    _box_row(f"  {BOLD}{'Время':<20} {'Действие':<10} {'IP-клиента':<18} {'Email'}{NC}")
    _box_sep()
    for e in entries[-n:]:
        action = e.get("action", "")
        col = GREEN if action == "accepted" else RED if "reject" in action.lower() else DIM
        _box_row(
            f"  {e['dt_str']:<20} "
            f"{col}{action:<10}{NC} "
            f"{e['src_ip']:<18} "
            f"{(e['email'] or '—')}"
        )
    _box_row()
    _box_bottom()


def _audit_suspicious() -> None:
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    info        = core.info
    success     = core.success
    BOLD, RED, NC, YELLOW, DIM = core.BOLD, core.RED, core.NC, core.YELLOW, core.DIM

    print()
    info("Анализ подозрительной активности...")
    entries = _parse_access_log()
    suspicious = [
        e for e in entries
        if any(kw in (e.get("action","") + e.get("raw","")).lower()
               for kw in ("reject", "error", "failed", "denied",
                          "invalid", "timeout", "handshake"))
    ]

    error_log = Path("/var/log/xray/error.log")
    error_lines = []
    if error_log.exists():
        error_lines = error_log.read_text(errors="replace").splitlines()[-100:]

    if not suspicious and not error_lines:
        success("Подозрительных событий не обнаружено")
        return

    _box_top("Подозрительная активность")
    if suspicious:
        from collections import Counter
        ip_counter = Counter(e.get("src_ip","") for e in suspicious if e.get("src_ip"))
        _box_row(f"  {BOLD}{RED}Подозрительные события в access.log: {len(suspicious)}{NC}")
        _box_row()
        _box_row(f"  {BOLD}Топ IP по числу ошибок:{NC}")
        for ip, cnt in ip_counter.most_common(10):
            col = RED if cnt >= 5 else YELLOW
            _box_row(f"    {col}{ip:<22}{NC} {cnt} событий")
        _box_sep()
        _box_row(f"  {BOLD}Последние подозрительные строки:{NC}")
        for e in suspicious[-15:]:
            _box_row(f"  {DIM}{e['dt_str']:<20}{NC} {RED}{e['action']:<10}{NC} {e['src_ip']:<18} {e['raw'][:50]}")

    if error_lines:
        _box_sep()
        _box_row(f"  {BOLD}Последние строки error.log:{NC}")
        for line in error_lines[-10:]:
            _box_row(f"  {DIM}{line[:100]}{NC}")
    _box_row()
    _box_bottom()


def _audit_active_now() -> None:
    """Показывает активные TCP-соединения процесса xray с привязкой к VLESS-юзерам.

    Алгоритм:
      1. ss -tnpH state established → все TCP-соединения в состоянии ESTABLISHED.
      2. Фильтр по процессу xray (по users:(("xray",...)) ).
      3. Парсинг через regex — надёжно работает на всех версиях iproute2
         (старые с 1 числовым столбцом Recv-Q, новые с Recv-Q + Send-Q).
      4. Для каждого соединения: если локальный порт = 443 (или другой VLESS
         inbound), то удалённый адрес = клиентский IP.
      5. Через _parse_access_log() строим map: client_IP → email (по последним
         записям access.log). Сопоставляем — получаем email юзера для каждого
         активного соединения.
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _run        = core._run
    info        = core.info
    warn        = core.warn
    BOLD, CYAN, NC, GREEN, DIM, YELLOW = (
        core.BOLD, core.CYAN, core.NC, core.GREEN, core.DIM, core.YELLOW
    )

    print()
    info("Активные соединения Xray:")
    try:
        # -H = без заголовка, -n = числовые адреса, -p = процесс
        r = _run(["ss", "-tnpH", "state", "established"], capture=True, check=False)
        lines = [l for l in r.stdout.splitlines() if "xray" in l]
        if not lines:
            info("Нет активных соединений с процессом xray")
            return

        # Парсинг через regex — надёжно работает на всех версиях ss.
        # Формат (iproute2 5.x+): tcp ESTAB 0 0 local:port peer:port users:(("xray",pid=N,fd=N))
        # Формат (старые): tcp ESTAB 0 local:port peer:port users:(...)
        # IPv6-адреса в квадратных скобках: [::ffff:1.2.3.4]:55164
        # (?:\d+\s+){1,2} — 1 или 2 числовых столбца (Recv-Q, опционально Send-Q)
        pat = re.compile(
            r'^\S+\s+\S+\s+(?:\d+\s+){1,2}'
            r'(?P<local>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'(?P<peer>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'users:\(\("(?P<proc>[^"]+)"'
        )

        # Построим map: client_IP → email через access.log
        ip_to_email: dict[str, str] = {}
        try:
            entries = _parse_access_log()
            for e in entries:
                ip = e.get("src_ip", "")
                em = e.get("email", "")
                if ip and em:
                    # Нормализуем IPv4-mapped IPv6: ::ffff:1.2.3.4 → 1.2.3.4
                    if ip.startswith("::ffff:"):
                        ip = ip[7:]
                    ip_to_email[ip] = em
        except Exception:
            pass

        # Внешний IP VPS (чтобы отличать входящие от исходящих)
        try:
            from chimera._core import get_server_ip
            vps_ip = get_server_ip("4") or ""
        except Exception:
            vps_ip = ""

        _box_top("Активные соединения Xray")
        _box_row(f"  {BOLD}{'Локал. адрес':<28} {'Удал. адрес':<28} {'VLESS юзер':<28}{NC}")
        _box_sep()
        shown = 0
        no_email_count = 0
        for line in lines[:50]:
            m = pat.match(line.strip())
            if not m:
                continue
            local = m.group("local")
            peer  = m.group("peer")

            # Извлекаем IP из peer (без порта, без IPv6-скобок)
            peer_ip = peer
            if peer_ip.startswith("["):
                peer_ip = peer_ip[1:].split("]")[0]
            else:
                peer_ip = peer_ip.rsplit(":", 1)[0]
            if peer_ip.startswith("::ffff:"):
                peer_ip = peer_ip[7:]

            # Если локальный адрес = VPS IP — значит это входящее соединение
            # от клиента (peer = клиентский IP). Иначе — исходящее от Xray.
            local_ip = local
            if local_ip.startswith("["):
                local_ip = local_ip[1:].split("]")[0]
            else:
                local_ip = local_ip.rsplit(":", 1)[0]
            if local_ip.startswith("::ffff:"):
                local_ip = local_ip[7:]

            # Определяем email юзера по клиентскому IP
            email = ""
            if vps_ip and local_ip == vps_ip:
                # Входящее соединение: peer = клиент
                email = ip_to_email.get(peer_ip, "")
            else:
                # Исходящее соединение: local = клиент (Xray к exit-ноде)
                email = ip_to_email.get(local_ip, "")

            if not email:
                no_email_count += 1
                email_display = f"{DIM}(не сопоставлен){NC}"
            else:
                email_display = f"{YELLOW}{email[:26]}{NC}"

            _box_row(
                f"  {CYAN}{local:<28}{NC} {GREEN}{peer:<28}{NC} {email_display}"
            )
            shown += 1

        if shown == 0:
            _box_row(f"  {DIM}Не удалось распарсить ни одной строки ss{NC}")
            _box_row(f"  {DIM}(проверьте формат вывода `ss -tnpH`){NC}")
        _box_sep()
        _box_row(f"  {DIM}Всего: {len(lines)} соединений (показано {shown}){NC}")
        if no_email_count > 0:
            _box_row(f"  {DIM}Без email: {no_email_count} (нет в access.log или loglevel < info){NC}")
        if not ip_to_email:
            _box_row()
            _box_row(f"  {YELLOW}⚠ access.log пуст или loglevel < info — email не сопоставлены{NC}")
            _box_row(f"  {DIM}  Для включения: config.json → log.loglevel = 'info', restart xray{NC}")
        _box_row()
        _box_bottom()
    except Exception as e:
        warn(f"Ошибка ss: {e}")
