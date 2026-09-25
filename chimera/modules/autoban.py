"""
chimera/modules/autoban.py
───────────────────────────────────────────────────────────────────────────────
Авто-бан IP по ошибкам TLS handshake (без Fail2ban).

Содержит интерактивный экран «Авто-бан IP (TLS handshake ошибки)» и helpers
для сканирования error.log, блокировки/разблокировки IP через UFW/iptables,
ротации читаемого отчёта и установки cron-задачи:

  • _ban_report_rotate()           — удаление отчёта старше 7 дней
  • _ban_report_append(...)        — запись одного бана в текстовый отчёт
  • _ban_report_show_in_box()      — вывод отчёта в рамке под таблицей истории
  • _autoban_load()/_save(data)    — чтение/запись state autoban.json
  • _autoban_get_chain_ips()       — IP нод каскада для автоматического whitelist
  • _fw_ban/_fw_unban (private)    — блокировка/разблокировка через ufw/iptables
  • _autoban_run_once()            — CLI entry point для --autoban
  • _autoban_install_cron(t, w)    — установка cron-задачи (5 мин)
  • do_manage_autoban()            — интерактивное меню управления

Точки входа из _core.py:
    from chimera.modules.autoban import (
        _XRAY_BAN_STATE, _XRAY_BAN_CRON, _XRAY_BAN_SCRIPT, _XRAY_BAN_LOG,
        _XRAY_BAN_REPORT, _BAN_THRESHOLD_DEFAULT, _BAN_WINDOW_MINUTES,
        _BAN_WHITELIST_DEFAULT, _BAN_REPORT_TTL_DAYS,
        _ban_report_rotate, _ban_report_append, _ban_report_show_in_box,
        _autoban_load, _autoban_save, _autoban_get_chain_ips,
        _autoban_run_once, _autoban_install_cron, do_manage_autoban,
    )

Доступ к helpers ядра (_box_*, _run, цвета, info/warn/success, log_to_file,
_tg_notify_event, _lookup_asn, _fmt_asn_short, STATE_FILE) — через importlib
(lazy binding), как и в других извлечённых модулях (standalone_screens.py,
asn_cache.py, connection_audit.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
#  ФИЧА 1: АВТО-БАН IP ПО ОШИБКАМ TLS HANDSHAKE (без Fail2ban)
# =============================================================================
_XRAY_BAN_STATE   = Path("/var/lib/xray-installer/autoban.json")
_XRAY_BAN_CRON    = Path("/etc/cron.d/xray-autoban")
_XRAY_BAN_SCRIPT  = Path("/usr/local/bin/xray-autoban.sh")
_XRAY_BAN_LOG     = Path("/var/log/xray-autoban.log")
_XRAY_BAN_REPORT  = Path("/var/log/xray-ban-report.txt")   # читаемый отчёт (7 дней)

# Пороги по умолчанию (сохраняются в state autoban.json)
_BAN_THRESHOLD_DEFAULT   = 10   # ошибок за период
_BAN_WINDOW_MINUTES      = 10   # минут для подсчёта
_BAN_WHITELIST_DEFAULT   = ["127.0.0.1", "::1"]

# (_asn_cache / _lookup_asn / _fmt_asn_short вынесены в
#  chimera.modules.asn_cache; импорт — в верхней секции _core.py.)


# ---------------------------------------------------------------------------
#  BAN REPORT FILE — /var/log/xray-ban-report.txt
#  Накапливает читаемый отчёт в течение 7 дней, затем ротируется.
# ---------------------------------------------------------------------------
_BAN_REPORT_TTL_DAYS = 7


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("chimera._core")


def _ban_report_rotate() -> None:
    """Если файл старше 7 дней — удаляем (создастся заново при следующей записи)."""
    try:
        if _XRAY_BAN_REPORT.exists():
            age_days = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
            if age_days >= _BAN_REPORT_TTL_DAYS:
                _XRAY_BAN_REPORT.unlink()
    except Exception:
        pass


def _ban_report_append(ip: str, count: int, reason: str, asn_info: dict) -> None:
    """
    Дописывает одну запись о бане в текстовый отчёт.
    Сначала проверяет ротацию (7-дневный TTL).
    Формат блока:
    ────────────────────────────────────────────────────────────
    [2026-05-04 02:15:00]  ЗАБЛОКИРОВАН: 203.0.113.137
      Ошибок:    6  (DPI [HTTP на TLS-порту])
      ASN:       AS7922 · Comcast Cable Communications
      Провайдер: Comcast Cable Communications, LLC
      Организация: Comcast Cable Communications, LLC
    ────────────────────────────────────────────────────────────
    """
    _ban_report_rotate()
    try:
        _XRAY_BAN_REPORT.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep = "─" * 64
        asn_raw = asn_info.get("asn", "—")
        isp     = asn_info.get("isp", "—")
        org     = asn_info.get("org", "—")
        # Форматируем ASN: убираем дублирование если asn == org
        asn_num = asn_raw.split()[0] if asn_raw and asn_raw != "—" else "—"
        block = (
            f"\n{sep}\n"
            f"[{ts}]  ЗАБЛОКИРОВАН: {ip}\n"
            f"  Ошибок:      {count}  ({reason})\n"
            f"  ASN:         {asn_num}\n"
            f"  Провайдер:   {isp}\n"
            f"  Организация: {org}\n"
        )
        with _XRAY_BAN_REPORT.open("a", encoding="utf-8") as f:
            f.write(block)
    except Exception:
        pass


def _ban_report_show_in_box() -> None:
    """
    Читает _XRAY_BAN_REPORT и выводит его содержимое под таблицей истории банов.
    Если файла нет — ничего не выводит.
    Длинные строки переносятся по ширине рамки.
    """
    core = _core_module()
    _box_line_top = core._box_line_top
    _box_line_sep = core._box_line_sep
    _box_row      = core._box_row
    _box_bottom   = core._box_bottom
    _wcslen       = core._wcslen
    _BOX_W        = core._BOX_W
    CYAN, NC, BOLD, WHITE, DIM = core.CYAN, core.NC, core.BOLD, core.WHITE, core.DIM

    if not _XRAY_BAN_REPORT.exists():
        return
    try:
        text = _XRAY_BAN_REPORT.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    if not text.strip():
        return

    _ban_report_rotate()  # проверяем TTL перед показом
    if not _XRAY_BAN_REPORT.exists():
        return

    try:
        age_days = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
        age_str = f"{age_days:.1f} дн."
        file_size = _XRAY_BAN_REPORT.stat().st_size
        size_str = (f"{file_size // 1024} КБ" if file_size >= 1024
                    else f"{file_size} Б")
    except Exception:
        age_str = "?"
        size_str = "?"

    print()
    # Заголовок секции
    _box_line_top()
    _hdr = f"📋 Детальный отчёт о банах (файл, 7 дней)"
    _pl  = _wcslen(_hdr)
    _lp  = (_BOX_W - _pl) // 2
    _rp  = _BOX_W - _pl - _lp
    print(f"{CYAN}║{NC}{' ' * _lp}{BOLD}{WHITE}{_hdr}{NC}{' ' * _rp}{CYAN}║{NC}")
    _box_line_sep()
    _meta = f"  Файл: {_XRAY_BAN_REPORT}  │  Размер: {size_str}  │  Возраст: {age_str}"
    _box_row(f"{DIM}{_meta}{NC}")
    _meta2 = f"  Ротация: автоматически через {_BAN_REPORT_TTL_DAYS} дней с момента создания"
    _box_row(f"{DIM}{_meta2}{NC}")
    _box_line_sep()

    # Печатаем строки файла, перенося длинные
    max_w = _BOX_W - 2
    for raw_line in text.splitlines():
        # Убираем символы рамки из самого файла (─) — они пройдут как есть
        if len(raw_line) > max_w:
            # Жёсткий перенос по max_w
            while raw_line:
                chunk = raw_line[:max_w]
                raw_line = raw_line[max_w:]
                _box_row(f" {chunk}")
        else:
            _box_row(f" {raw_line}")

    _box_bottom()


def _autoban_load() -> dict:
    try:
        if _XRAY_BAN_STATE.exists():
            cfg = json.loads(_XRAY_BAN_STATE.read_text())
            #  FIX: миграция ban_history — ранее cron-скрипт не писал
            # записи в ban_history (только в banned-словарь). Из-за этого
            # у существующих инсталляций с десятками банов пункт меню [6]
            # «История банов» показывал «История пуста».
            # Если ban_history пуст, но в banned есть записи — переносим
            # их в историю (один раз, при первом открытии после фикса).
            # FIX (кейс vds14808, 2026-09-21): миграция была НЕ одноразовой —
            # пересоздавала историю при каждом load, у которого banned
            # непуст, а история пуста. После «Очистить историю» [C]
            # cron успевал перебанить пару IP → banned непуст → на
            # следующей итерации меню история «воскресала» с теми же
            # записями. Флаг history_migrated (ставится при первой
            # миграции ИЛИ при явной очистке [C]) закрывает навсегда.
            banned = cfg.get("banned", {})
            hist   = cfg.get("ban_history", [])
            if not cfg.get("history_migrated") and banned and not hist:
                cfg["ban_history"] = [
                    {
                        "ip":          ip,
                        "banned_at":   meta.get("banned_at", datetime.now().isoformat()),
                        "unbanned_at": None,
                        "count":       meta.get("count", 0),
                        "reason":      meta.get("reason", "migrated from banned dict"),
                    }
                    for ip, meta in banned.items()
                ]
                cfg["history_migrated"] = True   # миграция выполнена —
                _autoban_save(cfg)               # больше не воскресаем
                #  FIX: также пишем мигрированные баны в файл отчёта
                # (/var/log/xray-ban-report.txt) — иначе пункт [6] показывает
                # историю, а файл отчёта остаётся пустым со статусом
                # «не создан (появится после первого бана)». Это несостыковка,
                # которую пользователи видят как баг.
                try:
                    core = _core_module()
                    _lookup_asn = core._lookup_asn
                    for ip, meta in banned.items():
                        _count = meta.get("count", 0)
                        _reason = meta.get("reason", "migrated from banned dict")
                        _asn = _lookup_asn(ip) if _lookup_asn else {}
                        _ban_report_append(ip, _count, _reason, _asn)
                except Exception:
                    pass
            return cfg
    except Exception:
        pass
    return {"enabled": False, "threshold": _BAN_THRESHOLD_DEFAULT,
            "window_min": _BAN_WINDOW_MINUTES, "whitelist": list(_BAN_WHITELIST_DEFAULT),
            "banned": {}}


def _autoban_save(data: dict) -> None:
    _XRAY_BAN_STATE.parent.mkdir(parents=True, exist_ok=True)
    # Гарантируем наличие секции ban_history
    if "ban_history" not in data:
        data["ban_history"] = []
    _XRAY_BAN_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _XRAY_BAN_STATE.chmod(0o600)


def _get_server_own_ips() -> list[str]:
    """
    Возвращает список всех IP-адресов этого сервера (public + все интерфейсы),
    чтобы автобан не забанил сам себя.

    Источники:
      1. ip route get 8.8.8.8  → primary public IPv4 (src=...)
      2. ip -4 addr show       → все IPv4 на всех интерфейсах
      3. ip -6 addr show       → все IPv6 (глобальные, не link-local)

    Исключаются:
      - 127.x.x.x (loopback)
      - ::1 (IPv6 loopback)
      - 10.66.66.x (AWG tunnel subnet — это не публичные IP)
      - 172.16.x.x–172.31.x.x (private, но добавляем на случай сложной маршрутизации)
      - 192.168.x.x (private, но добавляем — могут быть клиенты через NAT)
      - fe80::/10 (link-local IPv6)

    Функция НЕ использует сеть (curl к ipify) — только локальные команды,
    поэтому работает даже без интернета. Это критично: если сервер временно
    без сети, автобан всё равно должен знать свой собственный IP.
    """
    ips: list[str] = []
    try:
        import subprocess as _sp

        # 1. Primary public IPv4 через ip route get
        try:
            r = _sp.run(["ip", "route", "get", "8.8.8.8"],
                        capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                # Формат: "8.8.8.8 via 1.2.3.1 dev eth0 src 1.2.3.4 uid 0"
                parts = r.stdout.split()
                if "src" in parts:
                    idx = parts.index("src")
                    if idx + 1 < len(parts):
                        candidate = parts[idx + 1]
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', candidate):
                            if candidate not in ips:
                                ips.append(candidate)
        except Exception:
            pass

        # 2. Все IPv4 на всех интерфейсах
        try:
            r = _sp.run(["ip", "-4", "addr", "show"],
                        capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                # Парсим строки вида: "    inet 1.2.3.4/24 brd ..."
                for line in r.stdout.splitlines():
                    m = re.search(r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if m:
                        ip = m.group(1)
                        # Исключаем loopback и AWG tunnel subnet
                        if ip.startswith("127."):
                            continue
                        if ip not in ips:
                            ips.append(ip)
        except Exception:
            pass

        # 3. Глобальные IPv6 (не link-local)
        try:
            r = _sp.run(["ip", "-6", "addr", "show"],
                        capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    m = re.search(r'inet6\s+([0-9a-fA-F:]+)', line)
                    if m:
                        ip6 = m.group(1)
                        # Исключаем ::1 и fe80:: (link-local)
                        if ip6 == "::1" or ip6.startswith("fe80:"):
                            continue
                        if ip6 not in ips:
                            ips.append(ip6)
        except Exception:
            pass

    except Exception:
        pass
    return ips


def _autoban_get_chain_ips() -> list[str]:
    """Возвращает список IP всех нод из state.json (entry + exit) + собственные IP сервера
    для автоматического whitelist.
    При AWG 2.0 включает IP exit-VPS туннеля.
    Также включает собственные IP сервера (public + interfaces) — чтобы автобан
    не забанил сам сервер при TLS-handshake ошибках от loopback/health-check соединений."""
    core = _core_module()
    STATE_FILE = core.STATE_FILE

    ips: list[str] = []

    # Собственные IP сервера — добавляем ПЕРВЫМИ, чтобы они всегда были в whitelist.
    # Это предотвращает само-бан: сервер не должен банить свой собственный IP
    # при TLS-ошибках от health-check, loopback-соединений, или когда exit-нода
    # каскада подключается обратно к entry-ноде.
    for own_ip in _get_server_own_ips():
        if own_ip not in ips:
            ips.append(own_ip)

    try:
        if not STATE_FILE.exists():
            return ips
        state = json.loads(STATE_FILE.read_text())

        # Хелпер: резолв домена → IPv4 через DoH + fallback.
        # КРИТИЧНО для autoban: если в whitelist окажется устаревший IP
        # exit-ноды (из локального DNS-кэша), то нода на НОВОМ IP рискует
        # попасть в автобан при TLS-handshake ошибках — и трафик встанет.
        def _resolve(host: str) -> str:
            try:
                from chimera.modules.chain_nodes import _resolve_host_fresh
                ip = _resolve_host_fresh(host)
                if ip:
                    return ip
            except Exception:
                pass
            try:
                import socket as _sock
                return _sock.gethostbyname(host)
            except Exception:
                return ""

        # Exit-ноды каскада (Режим B, VLESS)
        for node in state.get("chain_nodes", []):
            host = node.get("host", "")
            if host and not host.replace(".", "").replace(":", "").isalnum() is False:
                # Если host выглядит как IP — добавляем напрямую
                import re as _re
                if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    ips.append(host)
                else:
                    # Резолвим домен через DoH + fallback
                    resolved = _resolve(host)
                    if resolved:
                        ips.append(resolved)
        # Legacy одиночная нода
        legacy_host = state.get("chain_exit_host", "")
        if legacy_host:
            import re as _re
            if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', legacy_host):
                if legacy_host not in ips:
                    ips.append(legacy_host)
            else:
                resolved = _resolve(legacy_host)
                if resolved and resolved not in ips:
                    ips.append(resolved)
        # AWG 2.0: добавляем IP exit-VPS в whitelist чтобы он не получил автобан
        if state.get("awg_exit_enabled") and state.get("install_mode") == "B":
            awg_host = state.get("awg_exit_host", "")
            if awg_host:
                import re as _re
                if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', awg_host):
                    if awg_host not in ips:
                        ips.append(awg_host)
                else:
                    resolved = _resolve(awg_host)
                    if resolved and resolved not in ips:
                        ips.append(resolved)
    except Exception:
        pass
    return ips


def _fw_ban(ip: str) -> bool:
    """Банит IP через ufw если доступен, иначе через iptables. Возвращает True при успехе.

    (кейс AS25369): ufw ОБЯЗАН ставить deny ПЕРВОЙ пользовательской
    строкой (ufw insert 1) — обычный `ufw deny` добавляется в КОНЕЦ
    ufw-user-input, ПОСЛЕ allow-правил портов (configure_firewall →
    ufw allow 22/80/SERVER_PORT) → first-match-wins пропускал
    нарушителя на открытые порты, бан был декоративным.
    """
    core = _core_module()
    _run = core._run

    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "insert", "1", "deny", "from", ip, "to", "any",
                  "comment", "xray-autoban"],
                 check=False, quiet=True)
        return r.returncode == 0
    # Fallback: iptables (Debian 13 / nftables системы без ufw)
    r = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


def _fw_unban(ip: str) -> bool:
    """Разбанивает IP через ufw или iptables.

    ufw ищет правило на delete по ПОЛНОМУ синтаксису: новые баны
    создаются с comment (см. _fw_ban), старые — без. Пробуем оба
    варианта, чтобы разбан работал для правил любого поколения.
    """
    core = _core_module()
    _run = core._run

    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "delete", "deny", "from", ip, "to", "any"],
                 check=False, quiet=True)
        if r.returncode == 0:
            return True
        # правило могло быть создано с comment (ufw матчит по полному
        # синтаксису) — пробуем и такой вариант
        r = _run(["ufw", "delete", "deny", "from", ip, "to", "any",
                  "comment", "xray-autoban"], check=False, quiet=True)
        return r.returncode == 0
    r = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


# ufw хранит пользовательские правила в iptables-save-формате;
# deny-from-бан выглядит так (comment может отсутствовать или стоять
# до/после -j — порядок у разных версий ufw разный):
#   -A ufw-user-input -s 1.2.3.4/32 -j DROP [-m comment --comment xray-autoban]
_UFW_USER_RULES = Path("/etc/ufw/user.rules")
_RE_UFW_INPUT_RULE = re.compile(r'^-A\s+ufw-user-input\b')
_RE_SRC_IPV4       = re.compile(r'(?:^|\s)-s\s+(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?(?:\s|$)')
_RE_J_DROP         = re.compile(r'(?:^|\s)-j\s+DROP(?:\s|$)')


def _ufw_write_rules_atomic(new_lines) -> bool:
    """Бэкап + атомарная запись user.rules (tmp + os.replace, режим
    файла сохраняется). Перед правкой — copy2 в .chimera-bak. При
    неудаче записи — попытка откатить файл из бэкапа и вернуть False."""
    path = _UFW_USER_RULES
    import shutil as _shutil
    bak = Path(str(path) + ".chimera-bak")
    tmp = Path(str(path) + ".chimera-tmp")
    try:
        _shutil.copy2(path, bak)
        tmp.write_text("\n".join(new_lines) + "\n")
        os.chmod(tmp, path.stat().st_mode & 0o7777)
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
            if bak.exists():
                _shutil.copy2(bak, path)
        except Exception:
            pass
        return False


def _ufw_restore_backup() -> bool:
    """Откат user.rules из .chimera-bak (после неудачного reload и т.п.)."""
    import shutil as _shutil
    path = _UFW_USER_RULES
    bak = Path(str(path) + ".chimera-bak")
    try:
        if bak.exists():
            _shutil.copy2(bak, path)
            return True
    except Exception:
        pass
    return False


def _ufw_status_active(runner) -> str:
    """Статус ufw: 'active' / 'inactive' / 'error' (не смог прочитать)."""
    try:
        rs = runner(["ufw", "status"], check=False, quiet=True)
    except Exception:
        return "error"
    if rs.returncode != 0:
        return "error"
    return "inactive" if "inactive" in (rs.stdout or "") else "active"


def _ufw_reload(runner) -> bool:
    """Один `ufw reload`; True при успехе."""
    r = runner(["ufw", "reload"], check=False, quiet=True)
    return r.returncode == 0


def _ufw_reorder_rules_file(banned: dict, runner):
    """Быстрый (батч) путь миграции порядка ufw-правил: одна правка
    /etc/ufw/user.rules + один `ufw reload`.

    Почему не ufw CLI на каждый IP (кейс vds14808, 2026-09-21): каждый
    вызов `ufw delete/insert` ре-апплит ВЕСЬ ruleset через
    iptables-restore — 1-3 с на вызов; 199 IP x 2 вызова = ~10-20 минут
    «зависания» без единой строки прогресса. Файловый путь: парсинг и
    запись — миллисекунды, один reload ~1-3 с, итого секунды.

    deny-from-правила (автобан + любые ручные source-DROP) переносятся
    в начало цепочки ufw-user-input — ДО allow-правил портов
    (first-match-wins). Относительный порядок deny-правил сохраняется.

    Возвращает:
      int  — сколько deny-правил переставлено (0 — если их нет; столько
             же — если уже стоят сверху: идемпотентно, файл и reload
             не трогаются)
      None — быстрый путь не удался (файла нет / структура непонятна /
             reload упал) → вызывающий код откатывается на CLI-режим
    """
    path = _UFW_USER_RULES
    try:
        if not path.exists():
            return None
        lines = path.read_text().splitlines()
    except Exception:
        return None

    def _is_ban_rule(ln: str) -> bool:
        return (bool(_RE_UFW_INPUT_RULE.match(ln))
                and bool(_RE_SRC_IPV4.search(ln))
                and bool(_RE_J_DROP.search(ln)))

    ban_idx = [i for i, ln in enumerate(lines) if _is_ban_rule(ln)]
    if not ban_idx:
        return 0

    first_input = next(
        (i for i, ln in enumerate(lines) if _RE_UFW_INPUT_RULE.match(ln)),
        None)
    if first_input is None:      # ban-строки сами совпадают с шаблоном
        return None              # → ветка недостижима, но не падаем

    # Идемпотентность: deny-блок уже стоит сплошняком с первой строки
    # ufw-user-input → ничего не делаем (повторный [F] мгновенен)
    if ban_idx[0] == first_input and all(
            b == first_input + k for k, b in enumerate(ban_idx)):
        return len(ban_idx)

    new_lines = [ln for i, ln in enumerate(lines) if i not in set(ban_idx)]
    for k, i in enumerate(ban_idx):
        new_lines.insert(first_input + k, lines[i])

    if not _ufw_write_rules_atomic(new_lines):
        return None

    st = _ufw_status_active(runner)
    if st == "error":             # ufw не смог прочитать файл
        _ufw_restore_backup()     # → откат и CLI-фолбэк
        return None
    if st == "inactive":          # файл поправлен, применится при enable
        return len(ban_idx)

    # ОДИН reload вместо 2xN CLI-вызовов; при неудаче — откат из бэкапа
    if not _ufw_reload(runner):
        _ufw_restore_backup()
        _ufw_reload(runner)
        return None

    # Лёгкая верификация: первая строка цепочки должна быть deny-правилом.
    # Отрицательный результат (строка есть и она НЕ deny) → откат+фолбэк;
    # пустой вывод (нечем проверить) → доверяем reload'у
    try:
        rv = runner(["iptables", "-S", "ufw-user-input"],
                    check=False, quiet=True)
        if rv.returncode == 0:
            first = next((ln for ln in (rv.stdout or "").splitlines()
                          if ln.startswith("-A ufw-user-input")), "")
            if first and not (_RE_SRC_IPV4.search(first)
                              and _RE_J_DROP.search(first)):
                _ufw_restore_backup()
                _ufw_reload(runner)
                return None
    except Exception:
        pass
    return len(ban_idx)


def _ufw_remove_rules_file(ips, runner):
    """Батч-удаление deny-правил заданных IP из user.rules + один reload.

    Кейс vds14808 (2026-09-21): «Разбанить IP → all» на 199 IP висел
    ~5 минут — по-IP ufw delete, каждый вызов ре-апплит весь ruleset.
    Здесь: парсинг/удаление строк — миллисекунды, ОДИН `ufw reload`.
    Удаляются ВСЕ deny-строки с -s <ip> для каждого IP (в т.ч. дубли
    от старых багов). Allow-правила и чужие deny не трогаются.

    Возвращает:
      int  — сколько строк удалено (0 — целевых правил не было)
      None — быстрый путь не удался → CLI-фолбэк (откат уже сделан)
    """
    path = _UFW_USER_RULES
    try:
        if not path.exists():
            return None
        lines = path.read_text().splitlines()
    except Exception:
        return None

    targets = set(ips)

    def _src_ip(ln: str):
        m = _RE_SRC_IPV4.search(ln)
        return m.group(1) if m else None

    remove_idx = [
        i for i, ln in enumerate(lines)
        if _RE_UFW_INPUT_RULE.match(ln) and _RE_J_DROP.search(ln)
        and _src_ip(ln) in targets
    ]
    if not remove_idx:
        return 0

    new_lines = [ln for i, ln in enumerate(lines) if i not in set(remove_idx)]
    if not _ufw_write_rules_atomic(new_lines):
        return None

    st = _ufw_status_active(runner)
    if st == "error":
        _ufw_restore_backup()
        return None
    if st == "inactive":
        return len(remove_idx)

    if not _ufw_reload(runner):
        _ufw_restore_backup()
        _ufw_reload(runner)
        return None

    # Верификация: в живой цепочке не должно остаться целевых IP
    # (точное сравнение -s <ip>, не подстрокой — иначе 1.2.3.4 совпадёт
    # с 1.2.3.40); пустой вывод → доверяем reload'у
    try:
        rv = runner(["iptables", "-S", "ufw-user-input"],
                    check=False, quiet=True)
        if rv.returncode == 0:
            for ln in (rv.stdout or "").splitlines():
                m = _RE_SRC_IPV4.search(ln)
                if m and m.group(1) in targets and _RE_J_DROP.search(ln):
                    _ufw_restore_backup()
                    _ufw_reload(runner)
                    return None
    except Exception:
        pass
    return len(remove_idx)


def _fw_unban_cli_batch(ips) -> int:
    """CLI-фолбэк разбана: по-IP через _fw_unban, прогресс каждые 20 IP."""
    core = _core_module()
    info = core.info
    ok = 0
    total = len(ips)
    for done, ip in enumerate(ips, 1):
        if _fw_unban(ip):
            ok += 1
        if done % 20 == 0 and done < total:
            info(f"  … {done}/{total} (CLI-фолбэк: каждый вызов ufw "
                 f"ре-апплит весь ruleset — это медленно)")
    return ok


def _fw_unban_batch(ips) -> int:
    """Батч-разбан: снимает deny-правила для списка IP.

    Один IP → ufw CLI delete (1-2 вызова — достаточно быстро).
    Несколько → батч: правка /etc/ufw/user.rules + ОДИН reload (кейс
    vds14808: 199 IP по-одному = ~5 минут, каждый ufw-вызов ре-апплит
    ruleset). ufw нет → iptables-режим по-IP (kernel-only, быстро).
    Возвращает число снятых FW-правил (0 — правил не было).
    """
    ips = list(dict.fromkeys(ips))
    if not ips:
        return 0
    if len(ips) == 1:
        return 1 if _fw_unban(ips[0]) else 0

    core = _core_module()
    _run = core._run
    import shutil as _shutil
    if not _shutil.which("ufw"):
        return sum(1 for ip in ips if _fw_unban(ip))

    n = _ufw_remove_rules_file(ips, _run)
    if n is not None:
        return n
    return _fw_unban_cli_batch(ips)


def _fw_repair_order_cli(banned: dict, _run) -> int:
    """Фолбэк-миграция порядка правил через ufw CLI (по одному IP).

    Медленно — каждый вызов ufw ре-апплит весь ruleset — поэтому печатает
    прогресс каждые 20 IP. Используется только если файловый батч-путь
    не удался (нет/не распарсился user.rules, упал reload).
    """
    core = _core_module()
    info = core.info
    fixed = 0
    total = len(banned)
    for done, ip in enumerate(list(banned.keys()), 1):
        # удалить старое правило (любое положение) — «not found» молча
        # игнорируем; правило могло быть с comment или без — оба варианта
        r = _run(["ufw", "delete", "deny", "from", ip, "to", "any"],
                 check=False, quiet=True)
        if r.returncode != 0:
            _run(["ufw", "delete", "deny", "from", ip, "to", "any",
                  "comment", "xray-autoban"], check=False, quiet=True)
        r = _run(["ufw", "insert", "1", "deny", "from", ip, "to", "any",
                  "comment", "xray-autoban"], check=False, quiet=True)
        if r.returncode == 0:
            fixed += 1
        if done % 20 == 0 and done < total:
            info(f"  … {done}/{total} (CLI-фолбэк: каждый вызов ufw "
                 f"ре-апплит весь ruleset — это медленно)")
    return fixed


def _fw_repair_order(banned: dict):
    """Миграция порядка ufw-правил для уже существующих банов.

    (кейс AS25369): старый _fw_ban добавлял `ufw deny from X` в КОНЕЦ
    ufw-user-input — ПОСЛЕ allow-правил портов (ufw allow 22/80/SERVER_PORT
    из configure_firewall) → first-match-wins пропускал нарушителей на
    открытые порты: баны росли в state, трафик продолжал течь.

    (кейс vds14808, 2026-09-21): прежняя миграция делала 2 ufw-вызова на
    IP, каждый ре-апплит весь ruleset → 199 IP висели 10-20 минут. Теперь:
    батч-правка /etc/ufw/user.rules + ОДИН `ufw reload` (секунды);
    CLI по-IP — только фолбэк с прогрессом.

    Возвращает число переставленных правил или None, если ufw нет
    (iptables-режим всегда ставил правила первой строкой).
    """
    core = _core_module()
    _run = core._run

    import shutil as _shutil
    if not _shutil.which("ufw"):
        return None

    n = _ufw_reorder_rules_file(banned, _run)
    if n is not None:
        return n
    return _fw_repair_order_cli(banned, _run)


def _autoban_run_once() -> int:
    """
    Сканирует error.log за последние N минут, считает TLS-ошибки по IP.
    При превышении порога добавляет UFW deny. Возвращает число новых банов.
    """
    core = _core_module()
    log_to_file      = core.log_to_file
    _tg_notify_event = core._tg_notify_event
    _lookup_asn      = core._lookup_asn

    cfg       = _autoban_load()
    threshold = cfg.get("threshold", _BAN_THRESHOLD_DEFAULT)
    window    = cfg.get("window_min", _BAN_WINDOW_MINUTES)
    whitelist = set(cfg.get("whitelist", _BAN_WHITELIST_DEFAULT))
    # Автоматически исключаем IP нод из цепочки — они появляются в error.log
    # как источники TLS-соединений и НЕ должны баниться
    for chain_ip in _autoban_get_chain_ips():
        whitelist.add(chain_ip)
    banned    = cfg.get("banned", {})

    error_log = Path("/var/log/xray/error.log")
    if not error_log.exists():
        return 0

    cutoff = time.time() - window * 60
    ip_errors: dict = {}

    # Паттерны TLS-ошибок в error.log Xray
    tls_patterns = re.compile(
        r'(tls: (?:handshake|no supported versions|no cipher)'
        r'|failed to read'
        r'|invalid header'
        r'|connection reset'
        r'|broken pipe)',
        re.IGNORECASE
    )
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    try:
        lines = error_log.read_text(errors="replace").splitlines()[-5000:]
        for line in lines:
            # Фильтруем по времени — Xray пишет: 2024/04/22 18:45:01
            dt_m = re.match(r'(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})', line)
            if dt_m:
                try:
                    ts = datetime.strptime(
                        f"{dt_m.group(1)} {dt_m.group(2)}", "%Y/%m/%d %H:%M:%S"
                    ).timestamp()
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
            if not tls_patterns.search(line):
                continue
            ip_m = ip_pattern.search(line)
            if not ip_m:
                continue
            ip = ip_m.group(1)
            if ip in whitelist:
                continue
            ip_errors[ip] = ip_errors.get(ip, 0) + 1
    except Exception:
        return 0

    new_bans = 0
    for ip, count in ip_errors.items():
        if count >= threshold and ip not in banned:
            # Баним через UFW
            if _fw_ban(ip):
                _ban_ts = datetime.now().isoformat()
                _reason = f"{count} TLS errors in {window}min"
                # ASN-инфо: в запись истории и в отчёт (кейс vds14808 —
                # Провайдер/Организация в «Истории банов»)
                try:
                    _asn = _lookup_asn(ip)
                except Exception:
                    _asn = {}
                banned[ip] = {
                    "count":     count,
                    "banned_at": _ban_ts,
                    "reason":    _reason,
                }
                # Записываем в историю (запись не удаляется при разбане)
                cfg.setdefault("ban_history", []).append({
                    "ip":          ip,
                    "banned_at":   _ban_ts,
                    "unbanned_at": None,
                    "count":       count,
                    "reason":      _reason,
                    "asn":         _asn.get("asn", ""),
                    "isp":         _asn.get("isp", ""),
                    "org":         _asn.get("org", ""),
                })
                if len(cfg["ban_history"]) > 500:
                    cfg["ban_history"] = cfg["ban_history"][-500:]
                new_bans += 1
                log_to_file("INFO", f"AutoBan: {ip} banned ({count} errors)")
                _tg_notify_event("autoban",
                    f"IP <b>{ip}</b> забанен автоматически: {count} TLS-ошибок за {window} мин")
                try:
                    _XRAY_BAN_LOG.parent.mkdir(parents=True, exist_ok=True)
                    with _XRAY_BAN_LOG.open("a") as f:
                        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] BAN {ip}: {count} errors\n")
                except Exception:
                    pass
                # Записываем в читаемый отчёт с ASN-данными
                try:
                    _ban_report_append(ip, count, _reason, _asn)
                except Exception:
                    pass

    cfg["banned"] = banned
    _autoban_save(cfg)
    return new_bans


def _autoban_install_cron(threshold: int, window: int) -> None:
    """Устанавливает cron каждые 5 минут."""
    core = _core_module()
    success = core.success

    sh = _XRAY_BAN_SCRIPT
    # Используем heredoc + iptables-fallback для совместимости с Debian 13
    # (нет ufw по умолчанию, textwrap.dedent ломает shebang)
    py_body = f"""import json, re, subprocess, sys, time, shutil
from pathlib import Path
from datetime import datetime

BAN_STATE  = Path('/var/lib/xray-installer/autoban.json')
BAN_LOG    = Path('/var/log/xray-autoban.log')
TG_CONFIG  = Path('/var/lib/xray-installer/telegram.json')

def tg(msg):
    try:
        c = json.loads(TG_CONFIG.read_text()) if TG_CONFIG.exists() else {{}}
        t, ch = c.get('token'), c.get('chat_id')
        # FIX: добавляем hostname + server_ip в начало сообщения,
        # чтобы было видно на каком сервере сработал autoban.
        # FIX-2 (2026-09-25): добавляем эмодзи 🚫 (No Entry, U+1F6AB)
        # в начало — чтобы уведомление о бане визуально выделялось в чате.
        import socket as _sock
        _host = _sock.gethostname().split('.')[0]
        _sip  = c.get('server_ip', '')
        _header = '\U0001f6ab [' + _host + ('] ' if not _sip else ' | ' + _sip + '] ')
        if t and ch:
            subprocess.run(['curl','-s','-o','/dev/null','-m','10',
                f'https://api.telegram.org/bot{{t}}/sendMessage',
                '-d',f'chat_id={{ch}}',
                '-d',f'text={{_header}}{{msg}}',
                '-d','parse_mode=HTML'],capture_output=True)
    except: pass

def fw_ban(ip):
    #  FIX (кейс AS25369): deny ПЕРВОЙ строкой ufw-user-input — обычный
    # `ufw deny` добавляется в конец, ПОСЛЕ allow-правил портов,
    # и не срабатывает для открытых портов (first-match-wins).
    if shutil.which('ufw'):
        return subprocess.run(['ufw','insert','1','deny','from',ip,'to','any','comment','xray-autoban'],
            capture_output=True).returncode == 0
    return subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP',
        '-m','comment','--comment','xray-autoban'],
        capture_output=True).returncode == 0

#  FIX (кейс vds14808, 2026-09-20): ASN/Провайдер/Организация в истории
#  банов и отчёте. Cron-скрипт не может импортировать
#  chimera.modules.asn_cache — поэтому lookup дублирует его логику
#  (ip-api.com, тот же endpoint/UA) + файл-кеш
#  /var/lib/xray-installer/autoban_asn_cache.json (TTL 7 дней,
#  лимит 2000 записей) — повторы не дёргают API зря.
ASN_CACHE_F   = Path('/var/lib/xray-installer/autoban_asn_cache.json')
ASN_CACHE_TTL = 7 * 86400
_asn_mem = {{}}

def lookup_asn(ip):
    if ip in _asn_mem:
        return _asn_mem[ip]
    data = {{}}
    try:
        if ASN_CACHE_F.exists():
            data = json.loads(ASN_CACHE_F.read_text())
    except Exception:
        data = {{}}
    hit = data.get(ip)
    if hit and (time.time() - hit.get('ts', 0)) < ASN_CACHE_TTL:
        _asn_mem[ip] = hit
        return hit
    info = {{'asn': '', 'isp': '', 'org': ''}}
    try:
        import urllib.request as _ur
        _url = f'http://ip-api.com/json/{{ip}}?fields=as,org,isp,status'
        _req = _ur.Request(_url, headers={{'User-Agent': 'xray-installer/3.99'}})
        with _ur.urlopen(_req, timeout=4) as _resp:
            _d = json.loads(_resp.read().decode())
        if _d.get('status') == 'success':
            info = {{'asn': _d.get('as',''), 'isp': _d.get('isp',''), 'org': _d.get('org','')}}
    except Exception:
        pass
    info['ts'] = time.time()
    _asn_mem[ip] = info
    try:
        data[ip] = info
        if len(data) > 2000:
            _keep = sorted(data.items(), key=lambda kv: kv[1].get('ts', 0))[-2000:]
            data = dict(_keep)
        ASN_CACHE_F.parent.mkdir(parents=True, exist_ok=True)
        ASN_CACHE_F.write_text(json.dumps(data))
    except Exception:
        pass
    return info

#  DoH-resolver: резолв домена exit-ноды → IPv4 через публичные
# DoH-резолверы (Cloudflare 1.1.1.1 + Google 8.8.8.8 JSON API), минуя
# локальный DNS-кэш (/etc/hosts, systemd-resolved, nscd, dnsmasq).
# КРИТИЧНО для autoban: если в whitelist окажется устаревший IP exit-ноды,
# то нода на НОВОМ IP рискует попасть в автобан при TLS-handshake ошибках.
def _resolve_fresh(host):
    import socket as _s
    try:
        _s.inet_aton(host)
        return host
    except OSError:
        pass
    for url, hdr in [
        (f'https://1.1.1.1/dns-query?name={{host}}&type=A', 'Accept: application/dns-json'),
        (f'https://8.8.8.8/resolve?name={{host}}&type=A', None),
    ]:
        try:
            cmd = ['curl','-s','--max-time','3']
            if hdr: cmd += ['-H', hdr]
            cmd.append(url)
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0 or not r.stdout.strip():
                continue
            data = json.loads(r.stdout.decode())
            if data.get('Status', 0) != 0:
                continue
            for ans in data.get('Answer', []):
                if ans.get('type') == 1:
                    ip = ans.get('data','')
                    try:
                        _s.inet_aton(ip)
                        return ip
                    except OSError:
                        continue
        except Exception:
            continue
    try:
        return _s.gethostbyname(host)
    except Exception:
        return ''

cfg = {{}}
try:
    if BAN_STATE.exists(): cfg = json.loads(BAN_STATE.read_text())
except: pass
threshold = cfg.get('threshold', {threshold})
window    = cfg.get('window_min', {window})
#  FIX: persist whitelist back to cfg, otherwise cron-скрипт
# перезаписывал autoban.json без 'whitelist' (если поле отсутствовало
# в файле) — и пользовательские IP терялись при следующем запуске.
# Раньше: whitelist = set(cfg.get('whitelist', ['127.0.0.1','::1']))
# → локальная переменная, в cfg не записывалась → json.dumps(cfg)
# → файл без 'whitelist' → _autoban_load() возвращает дефолт.
# Теперь: инициализируем cfg['whitelist'] явно, а whitelist берём из него.
if 'whitelist' not in cfg or not isinstance(cfg.get('whitelist'), list):
    cfg['whitelist'] = ['127.0.0.1', '::1']
whitelist = set(cfg['whitelist'])
#  FIX (кейс <node-2>, 2026-09-21): авто-IP НЕ сливаем с пользовательским
# whitelist. Резолвы доменов каскада (DoH, ниже) и собственные IP сервера
# держим в отдельном рантайм-сете auto_wl: он защищает ровно один прогон и
# пересчитывается заново каждые 5 минут. Раньше каждый резолв персистился
# в cfg['whitelist'] навсегда: домен без A-записи на DNS регистратора
# (ns*.reg.ru) отвечал парковочным кластером round-robin (ParkingCrew,
# 194.67.71.0/24) — за месяцы cron накидал в «Пользовательский whitelist»
# ~80 чужих IP; DDNS-ротация нод оседала там же всей историей адресов.
# cfg['whitelist'] навсегда = только ручные записи из меню [5].
auto_wl = set()
try:
    import socket as _sock
    _state_f = Path('/var/lib/xray-installer/state.json')
    if _state_f.exists():
        _st = json.loads(_state_f.read_text())
        for _nd in _st.get('chain_nodes', []):
            _h = _nd.get('host','')
            if not _h: continue
            import re as _re
            if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _h):
                auto_wl.add(_h)
            else:
                _r = _resolve_fresh(_h)
                if _r: auto_wl.add(_r)
        _lh = _st.get('chain_exit_host','')
        if _lh:
            if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _lh):
                auto_wl.add(_lh)
            else:
                _r = _resolve_fresh(_lh)
                if _r: auto_wl.add(_r)
except: pass

#  FIX: добавляем собственные IP сервера в whitelist — чтобы автобан
# не забанил сам себя при TLS-ошибках от loopback/health-check или
# когда exit-нода каскада подключается обратно к entry-ноде.
# Используем только локальные команды (ip route, ip addr) — без сети.
try:
    import subprocess as _sp2
    # 1. Primary public IPv4 через ip route get
    _r_route = _sp2.run(['ip', 'route', 'get', '8.8.8.8'],
                        capture_output=True, text=True, timeout=5)
    if _r_route.returncode == 0:
        _parts = _r_route.stdout.split()
        if 'src' in _parts:
            _idx = _parts.index('src')
            if _idx + 1 < len(_parts):
                _candidate = _parts[_idx + 1]
                if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _candidate):
                    auto_wl.add(_candidate)
    # 2. Все IPv4 на всех интерфейсах
    _r_addr = _sp2.run(['ip', '-4', 'addr', 'show'],
                       capture_output=True, text=True, timeout=5)
    if _r_addr.returncode == 0:
        for _line in _r_addr.stdout.splitlines():
            _m = _re.search(r'inet\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})', _line)
            if _m:
                _ip = _m.group(1)
                if not _ip.startswith('127.'):
                    auto_wl.add(_ip)
except: pass

banned = cfg.get('banned', {{}})

error_log = Path('/var/log/xray/error.log')
if not error_log.exists(): sys.exit(0)

cutoff = time.time() - window * 60
ip_errors = {{}}
tls_re = re.compile(r'tls.*handshake|failed to read|invalid header|connection reset|broken pipe', re.I)
ip_re  = re.compile(r'(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})')
for line in error_log.read_text(errors='replace').splitlines()[-5000:]:
    m = re.match(r'(\\d{{4}}/\\d{{2}}/\\d{{2}})\\s+(\\d{{2}}:\\d{{2}}:\\d{{2}})', line)
    if m:
        try:
            ts = datetime.strptime(f'{{m.group(1)}} {{m.group(2)}}','%Y/%m/%d %H:%M:%S').timestamp()
            if ts < cutoff: continue
        except: pass
    if not tls_re.search(line): continue
    im = ip_re.search(line)
    if not im or im.group(1) in whitelist or im.group(1) in auto_wl: continue
    ip_errors[im.group(1)] = ip_errors.get(im.group(1), 0) + 1

for ip, cnt in ip_errors.items():
    if cnt >= threshold and ip not in banned:
        if fw_ban(ip):
            _ban_ts = datetime.now().isoformat()
            _ban_reason = f'{{cnt}} TLS errors in {{window}}min'
            #  FIX (кейс vds14808): ASN/Провайдер/Организация прямо в запись
            #  истории (lookup_asn — ip-api.com + файл-кеш, см. выше).
            _asn = lookup_asn(ip)
            banned[ip] = {{'count':cnt,'banned_at':_ban_ts,'reason':_ban_reason}}
            BAN_LOG.parent.mkdir(parents=True,exist_ok=True)
            with open(BAN_LOG,'a') as f:
                f.write(f'[{{datetime.now():%Y-%m-%d %H:%M:%S}}] BAN {{ip}}: {{cnt}} errors\\n')
            tg(f'AutoBan: <b>{{ip}}</b> banned ({{cnt}} TLS errors in {{window}}min)')
            #  FIX: добавляем запись в ban_history — иначе пункт меню [6]
            # «История банов» оставался пустым, хотя banned-список рос.
            # Раньше cron только инициализировал пустой ban_history если
            # поля не было, но никогда не добавлял новые баны.
            if 'ban_history' not in cfg or not isinstance(cfg.get('ban_history'), list):
                cfg['ban_history'] = []
            cfg['ban_history'].append({{
                'ip':          ip,
                'banned_at':   _ban_ts,
                'unbanned_at': None,
                'count':       cnt,
                'reason':      _ban_reason,
                'asn':         _asn.get('asn', ''),
                'isp':         _asn.get('isp', ''),
                'org':         _asn.get('org', ''),
            }})
            if len(cfg['ban_history']) > 500:
                cfg['ban_history'] = cfg['ban_history'][-500:]
            #  FIX: пишем в читаемый отчёт /var/log/xray-ban-report.txt —
            # иначе пункт [6] показывает историю, а файл отчёта пустой.
            #  FIX (кейс vds14808): ASN/Провайдер/Организация из lookup_asn
            # (ip-api.com + файл-кеш) — вместо прочерков «без ASN-lookup».
            try:
                _report_f = Path('/var/log/xray-ban-report.txt')
                _report_f.parent.mkdir(parents=True, exist_ok=True)
                _sep = '─' * 64
                _ts_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                _asn_v = _asn.get('asn') or '—'
                _isp_v = _asn.get('isp') or '—'
                _org_v = _asn.get('org') or '—'
                _block = (
                    f'\\n{{_sep}}\\n'
                    f'[{{_ts_str}}]  ЗАБЛОКИРОВАН: {{ip}}\\n'
                    f'  Ошибок:      {{cnt}}  ({{_ban_reason}})\\n'
                    f'  ASN:         {{_asn_v}}\\n'
                    f'  Провайдер:   {{_isp_v}}\\n'
                    f'  Организация: {{_org_v}}\\n'
                )
                with open(_report_f, 'a', encoding='utf-8') as _rf:
                    _rf.write(_block)
            except Exception:
                pass

cfg['banned'] = banned
#  FIX: persist whitelist и гарантировать наличие 'ban_history' — иначе
# cron-скрипт затирал эти поля, и пункт меню [6] История банов оставался
# пустым. whitelist здесь = только пользовательские записи (см. FIX
# кейса <node-2> выше): авто-резолвы живут в auto_wl один прогон и
# в файл не попадают.
cfg['whitelist'] = sorted(whitelist)
if 'ban_history' not in cfg:
    cfg['ban_history'] = []
if 'enabled' not in cfg:
    cfg['enabled'] = True
BAN_STATE.parent.mkdir(parents=True,exist_ok=True)
BAN_STATE.write_text(json.dumps(cfg,indent=2,ensure_ascii=False))
BAN_STATE.chmod(0o600)
"""
    lines = ["#!/bin/bash", "python3 - <<'PYEOF'"] + py_body.splitlines() + ["PYEOF"]
    sh.write_text("\n".join(lines) + "\n")
    sh.chmod(0o750)
    _XRAY_BAN_CRON.write_text(
        f"*/5 * * * * root {sh} >> /var/log/xray-autoban.log 2>&1\n"
    )
    _XRAY_BAN_CRON.chmod(0o644)
    success(f"AutoBan cron установлен (каждые 5 мин, порог: {threshold} ошибок за {window} мин)")




def _parse_selection_targets(raw: str, items: list,
                              known: "set | None" = None) -> "tuple[list, list]":
    """Разбор выбора из нумерованного списка: '3' | '1,3,5' | '2-6' |
    'all'/'все'/'*' | точное значение (IP).

    Единый парсер для меню [3] «Разбанить IP» и [5] «Управление whitelist»
    (кейс <node-2>: вычищать 90 записей whitelist по одной — чокнуться
    можно). items — список в порядке нумерации меню (1-based).
    known — допустимые точные значения (по умолчанию set(items)).
    Возвращает (targets, warnings) — без дублей, порядок как в items.
    """
    targets: list = []
    warnings: list = []
    r = (raw or "").strip().lower()
    if not r:
        return targets, warnings
    if known is None:
        known = set(items)

    def _add(value) -> None:
        if value not in targets:
            targets.append(value)

    if r in ("all", "все", "*"):
        return list(items), warnings

    # Перечисление через запятую: '1,3,5' или '1.2.3.4,5.6.7.8'
    if "," in r:
        for token in r.split(","):
            token = token.strip()
            if not token:
                continue
            sub, sub_warns = _parse_selection_targets(token, items, known)
            warnings.extend(sub_warns)
            for v in sub:
                _add(v)
        return targets, warnings

    # Одиночный номер: '3'
    if r.isdigit():
        idx = int(r)
        if 1 <= idx <= len(items):
            _add(items[idx - 1])
        else:
            warnings.append(f"Номер {idx} вне диапазона (1..{len(items)})")
        return targets, warnings

    # Диапазон номеров: '2-6' (IP содержит точки; здесь — чистые цифры)
    if "-" in r and not r.startswith("-"):
        parts = r.split("-", 1)
        if parts[0].strip().isdigit() and parts[1].strip().isdigit():
            lo, hi = int(parts[0]), int(parts[1])
            lo, hi = min(lo, hi), max(lo, hi)
            for i in range(lo, hi + 1):
                if 1 <= i <= len(items):
                    _add(items[i - 1])
            return targets, warnings
        warnings.append("Неверный диапазон. Формат: 2-6")
        return targets, warnings

    # Точное значение (IP)
    if r in known:
        _add(r)
    else:
        warnings.append(f"'{raw}' не найден")
    return targets, warnings


def _whitelist_add_many(wl: list, raw: str) -> "tuple[list, list]":
    """Добавляет в whitelist несколько IP (запятая/пробелы).

    Валидация точных IP (IPv4/IPv6) — подсети/CIDR НЕ поддерживаются:
    whitelist автобана сравнивает точные строки (кейс <node-2> —
    «203.0.113.141/24» молча не срабатывает никогда).
    Мутирует wl по месту. Возвращает (added, warnings).
    """
    import ipaddress
    added: list = []
    warnings: list = []
    tokens = [t.strip() for t in re.split(r"[,\s]+", raw or "") if t.strip()]
    if not tokens:
        warnings.append("Пустой ввод")
        return added, warnings
    for token in tokens:
        if "/" in token:
            warnings.append(f"{token}: подсети не поддерживаются — только точные "
                            f"IP (сравнение по строке)")
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            warnings.append(f"{token}: не похоже на IP — пропущен")
            continue
        if token in wl:
            warnings.append(f"{token}: уже в whitelist")
            continue
        wl.append(token)
        added.append(token)
    return added, warnings


def do_manage_autoban() -> None:
    """Меню автоматического бана IP по TLS-ошибкам."""
    core = _core_module()
    _box_top        = core._box_top
    _box_row        = core._box_row
    _box_bottom     = core._box_bottom
    _box_item       = core._box_item
    _box_sep        = core._box_sep
    _BOX_W          = core._BOX_W
    _lookup_asn     = core._lookup_asn
    _fmt_asn_short  = core._fmt_asn_short
    info            = core.info
    warn            = core.warn
    success         = core.success
    BLUE = core.BLUE
    BOLD = core.BOLD
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    WHITE = core.WHITE
    YELLOW = core.YELLOW
    CYAN, NC, GREEN, YELLOW, RED, DIM, BOLD, BLUE, WHITE = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.RED,
        core.DIM, core.BOLD, core.BLUE, core.WHITE,
    )

    while True:
        os.system("clear")
        cfg    = _autoban_load()
        banned = cfg.get("banned", {})
        cron_active = _XRAY_BAN_CRON.exists()

        print()
        _box_top(f"Авто-бан IP (TLS handshake ошибки)")
        _box_row(f"  Cron (5 мин):  {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        _box_row(f"  Порог:         {CYAN}{cfg.get('threshold', _BAN_THRESHOLD_DEFAULT)}{NC} ошибок "
              f"за {CYAN}{cfg.get('window_min', _BAN_WINDOW_MINUTES)}{NC} мин")
        _box_row(f"  Забанено IP:   {RED if banned else DIM}{len(banned)}{NC}")

        if banned:
            _box_row(f"  {BOLD}Забаненные IP:{NC}")
            for ip, meta in list(banned.items())[-10:]:
                ts  = meta.get("banned_at", "?")[:16].replace("T", " ")
                cnt = meta.get("count", "?")
                # Первая строка: IP + количество ошибок + дата
                line1 = f"    {RED}✗{NC} {ip:<18} {YELLOW}{cnt}{NC} ошибок  {DIM}{ts}{NC}"
                _box_row(line1)
                # Вторая строка: ASN + провайдер (запрашиваем без блокировки)
                asn_info = _lookup_asn(ip)
                asn_str  = _fmt_asn_short(asn_info)
                if asn_str:
                    # Обрезаем если слишком длинно
                    max_asn = _BOX_W - 8
                    if len(asn_str) > max_asn:
                        asn_str = asn_str[:max_asn - 1] + "…"
                    _box_row(f"      {DIM}{asn_str}{NC}")
            if len(banned) > 10:
                _box_row(f"    {DIM}... и ещё {len(banned)-10} IP{NC}")

        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} авто-бан")
        _box_item("2", f"Изменить порог / окно")
        _box_item("3", f"Разбанить IP")
        _box_item("4", f"Запустить проверку прямо сейчас")
        _box_item("5", f"Управление whitelist")
        _box_item("6", f"📜 История банов")
        _box_item("F", f"🔧 FW-порядок банов  {DIM}(переставить deny выше allow — миграция){NC}")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                _XRAY_BAN_CRON.unlink(missing_ok=True)
                _XRAY_BAN_SCRIPT.unlink(missing_ok=True)
                cfg["enabled"] = False
                _autoban_save(cfg)
                success("Авто-бан отключён")
            else:
                t = cfg.get("threshold", _BAN_THRESHOLD_DEFAULT)
                w = cfg.get("window_min", _BAN_WINDOW_MINUTES)
                _autoban_install_cron(t, w)
                cfg["enabled"] = True
                _autoban_save(cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw_t = input(f"  Порог ошибок [{cfg.get('threshold', _BAN_THRESHOLD_DEFAULT)}]: ").strip()
            raw_w = input(f"  Окно (мин)   [{cfg.get('window_min', _BAN_WINDOW_MINUTES)}]: ").strip()
            if raw_t.isdigit(): cfg["threshold"]  = int(raw_t)
            if raw_w.isdigit(): cfg["window_min"] = int(raw_w)
            _autoban_save(cfg)
            # Переустанавливаем cron с новыми параметрами если был активен
            if cron_active:
                _autoban_install_cron(cfg["threshold"], cfg["window_min"])
            success("Настройки сохранены")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            if not banned:
                warn("Нет забаненных IP")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            print()
            ban_list = list(banned.keys())
            _box_top("Забаненные IP — выберите для разбана")
            for i, ip in enumerate(ban_list, 1):
                meta  = banned[ip]
                ts    = meta.get("banned_at", "?")[:16].replace("T", " ")
                cnt   = meta.get("count", "?")
                _box_row(f"  {CYAN}{i:>3}{NC}  {ip:<18} {YELLOW}{cnt}{NC} ошибок  {DIM}{ts}{NC}")
            _box_row()
            _box_row(f"  {DIM}Примеры ввода:{NC}")
            _box_row(f"  {DIM}  3        — разбанить один IP по номеру{NC}")
            _box_row(f"  {DIM}  1,3,5    — разбанить несколько через запятую{NC}")
            _box_row(f"  {DIM}  2-6      — разбанить диапазон номеров{NC}")
            _box_row(f"  {DIM}  all      — разбанить всех{NC}")
            _box_row(f"  {DIM}  1.2.3.4  — разбанить по IP напрямую{NC}")
            _box_bottom()
            raw = input(f"  {CYAN}Ввод:{NC} ").strip().lower()

            # ── Разбираем ввод → список целевых IP ────────────────────────────
            # Единый парсер (общий с меню [5] whitelist): '3' | '1,3,5' | '2-6'
            # | 'all'/'все'/'*' | точный IP.
            targets, _sel_warns = _parse_selection_targets(raw, ban_list,
                                                            known=set(banned))
            for _w in _sel_warns:
                warn(_w)

            # ── Выполняем разбан ──────────────────────────────────────────────
            if targets:
                _unban_ts = datetime.now().isoformat()
                # Батч: FW-правила снимаются ОДНОЙ правкой user.rules +
                # одним reload — не по-IP через ufw CLI (кейс vds14808:
                # 199 IP висели ~5 минут)
                if len(targets) > 1:
                    info(f"Снижаю deny-правила UFW батчем "
                         f"({len(targets)} IP, один reload)...")
                _t0 = time.monotonic()
                _fw_n = _fw_unban_batch(targets)
                _dt = time.monotonic() - _t0
                ok_count  = 0
                for target in targets:
                    banned.pop(target, None)
                    for _hrec in reversed(cfg.get("ban_history", [])):
                        if _hrec.get("ip") == target and _hrec.get("unbanned_at") is None:
                            _hrec["unbanned_at"] = _unban_ts
                            break
                    ok_count += 1
                cfg["banned"] = banned
                _autoban_save(cfg)
                if ok_count == 1:
                    success(f"IP {targets[0]} разбанен")
                else:
                    success(f"Разбанено IP: {ok_count} за {_dt:.1f}с")
                    if _fw_n < len(targets):
                        warn(f"FW-правил снято: {_fw_n} из {len(targets)} "
                             f"(остальные не имели ufw deny-правил)")

            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            print()
            info("Запуск проверки...")
            n = _autoban_run_once()
            if n:
                success(f"Забанено новых IP: {n}")
            else:
                success("Новых нарушителей не обнаружено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "f":
            # Миграция порядка FW-правил: deny-правила существующих банов
            # переставляются ПЕРВОЙ строкой ufw-user-input (старые баны
            # добавлялись в конец — после allow портов — и не работали).
            # Батч-режим: правка user.rules + ОДИН reload (кейс vds14808:
            # 199 IP через CLI-вызовы висели 10-20 минут).
            print()
            if not banned:
                info("Активных банов нет — переставлять нечего")
            else:
                info(f"Переставляю deny-правила первой строкой UFW "
                     f"({len(banned)} IP, батч: правка user.rules + "
                     f"один reload)...")
                _t0 = time.monotonic()
                _n = _fw_repair_order(banned)
                _dt = time.monotonic() - _t0
                if _n is None:
                    warn("ufw не найден — порядок правил не требует миграции "
                         "(iptables-режим ставит правила первой строкой)")
                else:
                    if _n >= len(banned):
                        success(f"Готово: переставлено {_n} из {len(banned)} "
                                f"правил за {_dt:.1f}с")
                    else:
                        success(f"Готово: переставлено {_n} deny-правил "
                                f"за {_dt:.1f}с")
                        warn(f"Внимание: {len(banned) - _n} банов без ufw "
                             f"deny-правил (iptables-режим или уже удалены)")
                    warn("Проверка: iptables -L ufw-user-input -n --line-numbers | head")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "6":
            # История банов
            history = cfg.get("ban_history", [])
            os.system("clear")
            print()
            _box_top("📜 История банов (последние 50)")
            if not history:
                _box_row(f"  {DIM}История пуста{NC}")
            else:
                # Заголовок таблицы — две строки чтобы уместиться
                _box_row(f"  {BOLD}{'IP':<18} {'Забанен':<16} {'Разбанен':<16} {'Ош':>3} Причина{NC}")
                _box_row(f"  {'─'*18}  {'─'*16}  {'─'*16}  {'─'*3}  {'─'*15}")
                for rec in reversed(history[-50:]):
                    _ip   = rec.get("ip", "?")
                    _bat  = rec.get("banned_at", "?")[:16].replace("T", " ")
                    _uat  = rec.get("unbanned_at")
                    _uat_s = (_uat[:16].replace("T", " ") if _uat
                              else f"{DIM}активен{NC}")
                    _cnt  = str(rec.get("count", "?"))
                    _rsn  = rec.get("reason", "")
                    # Обрезаем причину чтобы строка влезала
                    # Формула: 2 + 18 + 2 + 16 + 2 + 16 + 2 + 3 + 2 = 63 символа без причины
                    # оставляем на причину _BOX_W - 65 символов
                    _rsn_max = max(_BOX_W - 65, 8)
                    if len(_rsn) > _rsn_max:
                        _rsn = _rsn[:_rsn_max - 1] + "…"
                    _col = DIM if _uat else RED
                    # Строка 1: IP | даты | ошибки | причина
                    _box_row(
                        f"  {_col}{_ip:<18}{NC} {_bat:<16} {_uat_s:<16} "
                        f"{_cnt:>3}  {DIM}{_rsn}{NC}"
                    )
                    # Строка 2: ASN + провайдер. Приоритет — значения,
                    # сохранённые в записи (cron/TUI пишут с фикса vds14808);
                    # для старых записей — lookup на лету.
                    if rec.get("asn") or rec.get("isp") or rec.get("org"):
                        asn_info = {
                            "asn": rec.get("asn", ""),
                            "isp": rec.get("isp", ""),
                            "org": rec.get("org", ""),
                        }
                    else:
                        asn_info = _lookup_asn(_ip)
                    asn_str = _fmt_asn_short(asn_info)
                    if asn_str:
                        _asn_max = _BOX_W - 6
                        if len(asn_str) > _asn_max:
                            asn_str = asn_str[:_asn_max - 1] + "…"
                        _box_row(f"    {DIM}↳ {asn_str}{NC}")
            _box_item("C", "Очистить историю")
            _box_bottom()
            # Путь к файлу полного отчёта — вне рамки, всегда виден
            print()
            _report_exists = _XRAY_BAN_REPORT.exists()
            _report_status = (f"{GREEN}существует{NC}" if _report_exists
                              else f"{YELLOW}не создан (появится после первого бана){NC}")
            print(f"  {DIM}Полный лог:{NC} {CYAN}{_XRAY_BAN_REPORT}{NC}  [{_report_status}]")
            if _report_exists:
                try:
                    _rsz   = _XRAY_BAN_REPORT.stat().st_size
                    _rage  = (time.time() - _XRAY_BAN_REPORT.stat().st_mtime) / 86400
                    _rsz_s = f"{_rsz // 1024} КБ" if _rsz >= 1024 else f"{_rsz} Б"
                    _rot_in = max(0.0, _BAN_REPORT_TTL_DAYS - _rage)
                    print(f"  {DIM}Размер: {_rsz_s}  │  Ротация через: {_rot_in:.1f} дн.{NC}")
                except Exception:
                    pass
            print()
            # Вывод детального отчёта из файла (если есть)
            _ban_report_show_in_box()
            _hch = input(f"{CYAN}Выбор [Enter — назад]:{NC} ").strip().lower()
            if _hch == "c":
                ans = input(f"  {RED}Удалить всю историю банов (таблицу + "
                            f"файл отчёта)? [y/N]:{NC} ").strip().lower()
                if ans == "y":
                    # FIX (кейс vds14808, 2026-09-21): очистка «не работала»:
                    # 1) _autoban_load() воскрешал ban_history миграцией из
                    #    banned при следующей итерации меню (cron перебанивал
                    #    пару IP за 5 минут → banned непуст → история
                    #    «оставалась на месте»). Флаг history_migrated
                    #    выключает авто-миграцию навсегда.
                    cfg["ban_history"] = []
                    cfg["history_migrated"] = True
                    _autoban_save(cfg)
                    # 2) файл отчёта — тоже часть «Истории банов» на экране [6]:
                    #    показывался под таблицей и выглядел как «не очистилось»
                    try:
                        _XRAY_BAN_REPORT.unlink(missing_ok=True)
                    except Exception:
                        pass
                    success("История очищена. Новые баны по-прежнему будут "
                            "записываться, пока работает авто-бан")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            wl = cfg.get("whitelist", list(_BAN_WHITELIST_DEFAULT))
            chain_ips = _autoban_get_chain_ips()
            # Разделяем: собственные IP сервера vs IP нод каскада
            own_ips = _get_server_own_ips()
            chain_only = [ip for ip in chain_ips if ip not in own_ips]
            print()
            _box_top("Whitelist (эти IP никогда не баним)")
            _box_row(f"  {BOLD}Пользовательский whitelist:{NC}")
            for i, ip in enumerate(wl, 1):
                _box_item(f"{i}", f"{ip}")
            if own_ips:
                _box_sep()
                _box_row(f"  {DIM}Автозащита — собственные IP сервера (всегда в whitelist):{NC}")
                for ip in own_ips:
                    in_wl = "  (уже в whitelist)" if ip in wl else ""
                    _box_row(f"    {DIM}• {ip}{in_wl}{NC}")
            if chain_only:
                _box_sep()
                _box_row(f"  {DIM}Автозащита — IP нод каскада (всегда в whitelist):{NC}")
                for ip in chain_only:
                    in_wl = "  (уже в whitelist)" if ip in wl else ""
                    _box_row(f"    {DIM}• {ip}{in_wl}{NC}")
            _box_sep()
            _box_item("+", f"Добавить IP  {DIM}(один или список через запятую){NC}")
            _box_item("-", f"Удалить  {DIM}N | N,M | N-M | all | IP{NC}")
            _box_bottom()
            act = input("  Действие [+/-/Enter]: ").strip()
            if act == "+":
                #  FEAT (кейс <node-2>): пакетное добавление — список IP через
                # запятую (например, пул IP мониторинга: 3 адреса одним вводом).
                raw_ips = input("  IP (или список через запятую): ").strip()
                added, add_warns = _whitelist_add_many(wl, raw_ips)
                if added or add_warns:
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                if added:
                    success(f"Добавлено ({len(added)}): {', '.join(added)}")
                for msg in add_warns:
                    warn(msg)
            elif act == "-":
                #  FEAT (кейс <node-2>): пакетное удаление — по номерам
                # ('3', '1,3,5', '2-25'), 'all' или по IP напрямую — тем же
                # синтаксисом, что и разбан в меню [3].
                raw_n = input("  Удалить (N / N,M / N-M / all / IP): ").strip().lower()
                targets, _sel_warns = _parse_selection_targets(raw_n, wl)
                for _w in _sel_warns:
                    warn(_w)
                if targets and raw_n in ("all", "все", "*"):
                    if input(f"  {YELLOW}Удалить ВСЕ {len(targets)} записей? [y/N]: {NC}") \
                            .strip().lower() in ("y", "yes", "д", "да"):
                        for t in targets:
                            wl.remove(t)
                        cfg["whitelist"] = wl
                        _autoban_save(cfg)
                        success(f"Whitelist очищен (удалено {len(targets)})")
                elif targets:
                    for t in targets:
                        wl.remove(t)  # по значению — безопасно при нескольких
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                    success(f"Удалено ({len(targets)}): {', '.join(targets)}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
