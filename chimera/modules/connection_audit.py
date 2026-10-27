"""
chimera/modules/connection_audit.py
───────────────────────────────────────────────────────────────────────────────
Аудит подключений Xray (access.log + error.log + active sockets).

Содержит интерактивный экран «Аудит подключений» и helpers для парсинга и
агрегации данных:

  • do_connection_audit()        — главное меню (сводка / хронология /
                                    подозрительная активность / активные сейчас)
  • _parse_access_log()          — парсит /var/log/xray/access.log → list[dict]
                                    (include_rotated=True: + access.log.1 и
                                    access.log.{2..14}.gz — daily-ротация;
                                    IP клиента — ТОЛЬКО из `from <IP>:<port>`,
                                    строки observatory/outbound игнорируются)
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

import gzip
import os
import re
import time
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Пути access-логов (модуль-level константы — патчатся в тестах) ───────────
_ACCESS_LOG = Path("/var/log/xray/access.log")
_ACCESS_LOG_ROTATIONS = 14   # синхронно с setup_logrotate() в _core.py: rotate 14


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


def _rotated_access_log_paths() -> list:
    """Ротированные access.log.* в порядке старшинства (старые → новые).

    logrotate (setup_logrotate(), _core.py) с rotate 14 + delaycompress создаёт:
      access.log.1        — свежий ротированный, НЕ сжат (delaycompress)
      access.log.2.gz … access.log.14.gz — сжатые, чем больше N, тем старше
    Порядок выхода: .14.gz → … → .2.gz → .1 — хронологический (старые → новые),
    поэтому "последний выигрывает"-маппинги (ip_to_email) остаются корректными:
    самая свежая запись для IP перезапишет устаревшую.
    """
    out: list = []
    base = _ACCESS_LOG.parent
    for n in range(_ACCESS_LOG_ROTATIONS, 1, -1):
        p = base / f"access.log.{n}.gz"
        if p.exists():
            out.append(p)
    p1 = base / "access.log.1"
    if p1.exists():
        out.append(p1)
    return out


def _access_log_sources(include_rotated: bool = False) -> list:
    """Все источники access-лога: [ротированные (старые → новые)…, текущий]."""
    sources: list = []
    if include_rotated:
        sources.extend(_rotated_access_log_paths())
    sources.append(_ACCESS_LOG)
    return sources


def _read_log_lines(path: Path) -> list:
    """Строки лог-файла: plain или .gz (stdlib gzip — без внешнего zgrep).

    Бинарник zgrep в системе может отсутствовать (минимальные образы),
    gzip из stdlib есть всегда. Ошибка чтения отдельного файла (битый архив,
    права) не валит весь аудит: файл пропускается, остальные читаются.
    """
    try:
        if str(path).endswith(".gz"):
            with gzip.open(path, "rt", errors="replace") as fh:
                return fh.read().splitlines()
        return path.read_text(errors="replace").splitlines()
    except Exception:
        return []


# ── Правила парсинга access-лога (фикс «чужих IP в аудите») ──────────────────

# Служебные строки xray, которые НЕ являются клиентскими соединениями:
#   • observatory (app/observatory, burst observatory) — health-check'ы
#     цепочек: адреса в них — цели проверок, а не клиенты;
#   • outbound (app/proxyman/outbound, proxy/*/outbound) — диспетчер
#     исходящего трафика: адреса в них — destination'ы.
# Без фильтра такие строки попадали в аудит и приписывали юзерам ЧУЖИЕ IP
# (кейс: destination-адрес показывался как «IP клиента» юзера).
# Теги outbound'ов Chimera (direct / chain-exit-N / hop-fi / xray-stats-api)
# слов-маркеров не содержат — фильтр их не задевает.
_SKIP_LINE_MARKERS = ("observatory", "outbound")

# Голова строки access-лога Xray (реальный формат нод Chimera):
#   2026/10/27 03:53:45.890235 from 192.0.2.20:52359 accepted tcp:... email: u@d
#   2026/10/27 14:07:32.429924 from [2001:db8:...]:63698 accepted tcp:...
#   2026/10/27 03:53:46.138124 from DNS accepted udp:127.0.0.1:53 [xray.system...]
#   2026/10/25 09:12:33 accepted tcp:198.51.100.7:49775 dst:... (легаси без from)
_ACCESS_LINE_HEAD = re.compile(
    r'^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+'
    r'(?:from\s+(?P<from_tok>\S+)\s+)?'
    r'(?P<action>\w+)'
)

# from-токен как адрес клиента: IPv4:port | [IPv6]:port.
_FROM_ADDR = re.compile(
    r'^(?:\[(?P<v6>[0-9a-fA-F:.]+)\]|(?P<v4>\d{1,3}(?:\.\d{1,3}){3})):(?P<port>\d+)$'
)

_EMAIL_FIELD = re.compile(r'email:\s*(\S+)')

# Destination из `tcp:<dest>:<port>` / `udp:<dest>:<port>` (информационно).
_DST_FIELD = re.compile(r'\b(?:tcp|udp):(?P<dst>\[[0-9a-fA-F:.]+\]|[^\s:]+):\d+')


def _client_ip_from_token(tok: str) -> str:
    """IP клиента из from-токена; '' — если токен не адрес (напр. 'DNS').

    '[2001:db8:...]:63698'   → '2001:db8:...'
    '[::ffff:1.2.3.4]:443'    → '1.2.3.4'      (IPv4-mapped нормализуется)
    '192.0.2.20:52359'       → '192.0.2.20'
    'DNS'                     → ''
    """
    m = _FROM_ADDR.match(tok)
    if not m:
        return ""
    ip = m.group("v6") or m.group("v4") or ""
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


def _parse_access_log(include_rotated: bool = False) -> list:
    """Парсит /var/log/xray/access.log в список dict.

    include_rotated=True — дополнительно читает ротированные логи
    (access.log.1 … access.log.14.gz — daily-ротация из setup_logrotate()):
    файлы идут от старых к новым, поэтому записи в списке остаются
    в хронологическом порядке, а словари вида "последний выигрывает"
    (ip_to_email в _audit_active_now) корректны.

    Окно ограничено: последние 10000 строк НА КАЖДЫЙ файл (не суммарно) —
    память bounded (≤ 15 × 10000 записей), а история после ротации
    не теряется (кейс: юзер подключался до среза — записи ушли в .1/.gz).

    Правила извлечения IP клиента (фикс «чужих IP в аудите»):
      • IP клиента берётся ТОЛЬКО из префикса `from <IP>:<port>` — IPv4
        или [IPv6] (IPv4-mapped [::ffff:x.x.x.x] нормализуется до IPv4);
      • строки observatory/outbound (health-check'ы цепочек, диспетчер
        исходящего трафика) игнорируются целиком — их адреса не клиентские;
      • строки `from <не-адрес>` — внутренние события xray (например
        «from DNS … udp:127.0.0.1:53» — диспетчер DNS) — пропускаются;
      • строка без `from` (легаси-формат) сохраняется (action/email/dst),
        но src_ip остаётся пустым: destination из `tcp:<addr>:<port>`
        как IP клиента больше НЕ используется (раньше это приписывало
        юзерам адреса назначений — чужие IP в сводке/активных соединениях).
    """
    core = _core_module()
    warn = core.warn

    sources = [p for p in _access_log_sources(include_rotated) if p.exists()]
    if not sources:
        warn(f"access.log не найден: {_ACCESS_LOG}")
        return []

    entries = []
    try:
        for path in sources:
            lines = _read_log_lines(path)
            for line in lines[-10000:]:
                line = line.strip()
                if not line:
                    continue
                # 1) Служебные строки (observatory/outbound) — не клиентские.
                low = line.lower()
                if any(marker in low for marker in _SKIP_LINE_MARKERS):
                    continue
                # 2) Голова строки: дата/время, опц. from-токен, действие.
                m = _ACCESS_LINE_HEAD.match(line)
                if not m:
                    continue
                dt_str = f"{m.group('date')} {m.group('time')}"
                try:
                    dt = datetime.strptime(dt_str, "%Y/%m/%d %H:%M:%S")
                except Exception:
                    dt = None
                action = m.group("action") or ""
                # 3) IP клиента — ТОЛЬКО из from-токена.
                from_tok = m.group("from_tok")
                if from_tok is not None:
                    src_ip = _client_ip_from_token(from_tok)
                    if not src_ip:
                        # `from <не-адрес>` — внутреннее событие xray
                        # (например «from DNS …»): не клиентское соединение.
                        continue
                else:
                    # Легаси-формат без from: IP клиента неизвестен —
                    # НЕ выдумываем его из destination.
                    src_ip = ""
                em = _EMAIL_FIELD.search(line)
                email = em.group(1) if em else ""
                dm = _DST_FIELD.search(line)
                dst = dm.group("dst") if dm else ""
                entries.append({
                    "dt": dt, "dt_str": dt_str, "action": action,
                    "src_ip": src_ip, "email": email, "raw": line,
                    "dst": dst,
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
    info("Анализ access.log (текущий + ротированные)...")
    # Кейс: daily-ротация (setup_logrotate) переносит историю подключений
    # в access.log.1/.gz — сводка по ОДНОМУ текущему файлу «теряла» юзеров,
    # не заходивших после ночного среза. Читаем всю доступную историю.
    all_entries = _parse_access_log(include_rotated=True)
    entries = [e for e in all_entries if e.get("action", "").lower() == "accepted"]
    if not entries:
        rotated = _rotated_access_log_paths()
        if not _ACCESS_LOG.exists() and not rotated:
            warn("access.log не найден — xray не запущен или путь не задан в config.json")
        elif _ACCESS_LOG.exists() and _ACCESS_LOG.stat().st_size == 0 and not rotated:
            warn("access.log пустой — xray запущен с loglevel=warning")
            info("Для аудита подключений нужен loglevel=info в config.json → перезапустите xray")
        elif not all_entries:
            warn("access.log есть, но записи не распознаны — нестандартный формат")
        else:
            warn("записи 'accepted' не найдены (текущий лог + ротированные)")
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
    # Строка источников и периода: юзер видит, каким окном данных он владеет
    # (сколько логов прочитано и за какой период), — иначе «пропавшие» юзеры
    # выглядели как баг данных, хотя это просто окно чтения.
    n_rot = len(_rotated_access_log_paths())
    src_note = f"текущий лог + {n_rot} ротир." if n_rot else "текущий лог (ротации нет)"
    _box_row(f"  {DIM}Всего принятых: {len(entries)} · источники: {src_note}{NC}")
    dts = [e["dt"] for e in entries if e.get("dt")]
    if dts:
        period = f"{min(dts).strftime('%d.%m %H:%M')} — {max(dts).strftime('%d.%m %H:%M')}"
        _box_row(f"  {DIM}Период данных: {period}{NC}")
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

        # Парсинг через regex — надёжно работает на всех версиях ss / iproute2.
        #
        # Форматы вывода ss -tnpH state established (только ESTABLISHED, с -H без заголовка):
        #   • iproute2 6.x (новые): "0 0 local:port peer:port users:(("xray",pid=N,fd=N))"
        #     — БЕЗ префикса "tcp ESTAB" (state filter убирает колонку State и Proto).
        #   • iproute2 6.x без state filter: "ESTAB 0 0 local:port peer:port users:..."
        #     — только State (1 слово, без "tcp").
        #   • Старые iproute2 (5.x и ниже): "tcp ESTAB 0 0 local:port peer:port users:..."
        #     — с префиксом tcp ESTAB (2 слова).
        #   • Совсем старые: "tcp ESTAB 0 local:port peer:port users:..." (1 число Recv-Q).
        # IPv6-адреса в квадратных скобках: [::ffff:1.2.3.4]:55164
        #
        # `(?:\S+\s+){0,2}` — опционально 0-2 слова в начале (tcp, ESTAB, или ничего)
        # `(?:\d+\s+){1,2}` — 1-2 числовых столбца (Recv-Q, опционально Send-Q)
        pat = re.compile(
            r'^(?:\S+\s+){0,2}'
            r'(?:\d+\s+){1,2}'
            r'(?P<local>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'(?P<peer>\[[^\]]+\]:\d+|[^\s:]+:\d+)\s+'
            r'users:\(\("(?P<proc>[^"]+)"'
        )

        # Построим map: client_IP → email через access.log.
        # include_rotated=True: long-lived туннели устанавливаются ДО ночной
        # ротации — их записей уже нет в текущем access.log, и IP показывался
        # бы «(не сопоставлен)». Ротированные логи восстанавливают карту.
        # Порядок записей хронологический (старые → новые), поэтому для
        # каждого IP остаётся самая свежая привязка («последний выигрывает»).
        ip_to_email: dict[str, str] = {}
        try:
            entries = _parse_access_log(include_rotated=True)
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

        def _norm_addr_for_display(addr: str) -> str:
            """Нормализация адреса для display в таблице:
               [::ffff:1.2.3.4]:443 → 1.2.3.4:443
               [2001:db8::1]:443     → [2001:db8::1]:443  (настоящий IPv6 оставляем в скобках)
               1.2.3.4:443           → 1.2.3.4:443       (IPv4 без изменений)
            Это сокращает длину IPv4-mapped IPv6 адресов с 28 до 19 символов,
            чтобы строка помещалась в box width 66 и email не переносился
            на следующую строку (UX баг: таблица ломалась при IPv6 выводе).
            """
            if addr.startswith("["):
                inner = addr[1:].split("]", 1)[0]
                port_part = addr.rsplit(":", 1)[1] if ":" in addr.split("]", 1)[1] else ""
                if inner.startswith("::ffff:"):
                    # IPv4-mapped IPv6 → показываем как обычный IPv4
                    return f"{inner[7:]}:{port_part}" if port_part else inner[7:]
                # Настоящий IPv6 — оставляем в скобках для однозначности
                return addr
            return addr

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

            # Нормализуем для display — убираем IPv4-mapped IPv6 overhead
            # чтобы строка помещалась в box width 66.
            local_disp = _norm_addr_for_display(local)
            peer_disp  = _norm_addr_for_display(peer)

            # Динамическое обрезание email — чтобы вся строка помещалась в box.
            # Раньше использовался padding {local:<28}, который делал короткие IPv4
            # адреса (19 chars) padded до 28 chars — суммарная длина строки получалась
            # 86 chars и не помещалась в box width 66 → email уезжал на новую строку.
            # Теперь: убираем padding, считаем доступное место под email динамически.
            # Layout: 2 leading + local + 1 sep + peer + 1 sep + email ≤ 66
            local_w = len(local_disp)
            peer_w = len(peer_disp)
            max_email = max(8, 62 - local_w - peer_w)  # минимум 8, иначе будет пусто
            max_email = min(max_email, 26)              # не больше 26
            if not email:
                email_short = "(не сопоставлен)"
            elif len(email) > max_email:
                email_short = email[:max_email - 1] + "…"
            else:
                email_short = email
            email_display = f"{YELLOW}{email_short}{NC}" if email else f"{DIM}{email_short}{NC}"

            _box_row(
                f"  {CYAN}{local_disp}{NC} {GREEN}{peer_disp}{NC} {email_display}"
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
