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
    [2026-05-04 02:15:00]  ЗАБЛОКИРОВАН: 66.132.172.140
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
            return json.loads(_XRAY_BAN_STATE.read_text())
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


def _autoban_get_chain_ips() -> list[str]:
    """Возвращает список IP всех нод из state.json (entry + exit) для автоматического whitelist.
    При AWG 2.0 включает IP exit-VPS туннеля."""
    core = _core_module()
    STATE_FILE = core.STATE_FILE

    ips: list[str] = []
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
    """Банит IP через ufw если доступен, иначе через iptables. Возвращает True при успехе."""
    core = _core_module()
    _run = core._run

    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "deny", "from", ip, "to", "any", "comment", "xray-autoban"],
                 check=False, quiet=True)
        return r.returncode == 0
    # Fallback: iptables (Debian 13 / nftables системы без ufw)
    r = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


def _fw_unban(ip: str) -> bool:
    """Разбанивает IP через ufw или iptables."""
    core = _core_module()
    _run = core._run

    import shutil as _shutil
    if _shutil.which("ufw"):
        r = _run(["ufw", "delete", "deny", "from", ip, "to", "any"],
                 check=False, quiet=True)
        return r.returncode == 0
    r = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
              "-m", "comment", "--comment", "xray-autoban"],
             check=False, quiet=True)
    return r.returncode == 0


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
                banned[ip] = {
                    "count":     count,
                    "banned_at": _ban_ts,
                    "reason":    f"{count} TLS errors in {window}min",
                }
                # Записываем в историю (запись не удаляется при разбане)
                cfg.setdefault("ban_history", []).append({
                    "ip":          ip,
                    "banned_at":   _ban_ts,
                    "unbanned_at": None,
                    "count":       count,
                    "reason":      f"{count} TLS errors in {window}min",
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
                    _asn = _lookup_asn(ip)
                    _ban_report_append(ip, count, f"{count} TLS errors in {window}min", _asn)
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
        if t and ch:
            subprocess.run(['curl','-s','-o','/dev/null','-m','10',
                f'https://api.telegram.org/bot{{t}}/sendMessage',
                '-d',f'chat_id={{ch}}','-d',f'text={{msg}}'],capture_output=True)
    except: pass

def fw_ban(ip):
    if shutil.which('ufw'):
        return subprocess.run(['ufw','deny','from',ip,'to','any','comment','xray-autoban'],
            capture_output=True).returncode == 0
    return subprocess.run(['iptables','-I','INPUT','-s',ip,'-j','DROP',
        '-m','comment','--comment','xray-autoban'],
        capture_output=True).returncode == 0

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
                whitelist.add(_h)
            else:
                _r = _resolve_fresh(_h)
                if _r: whitelist.add(_r)
        _lh = _st.get('chain_exit_host','')
        if _lh:
            if _re.match(r'^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$', _lh):
                whitelist.add(_lh)
            else:
                _r = _resolve_fresh(_lh)
                if _r: whitelist.add(_r)
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
    if not im or im.group(1) in whitelist: continue
    ip_errors[im.group(1)] = ip_errors.get(im.group(1), 0) + 1

for ip, cnt in ip_errors.items():
    if cnt >= threshold and ip not in banned:
        if fw_ban(ip):
            banned[ip] = {{'count':cnt,'banned_at':datetime.now().isoformat()}}
            BAN_LOG.parent.mkdir(parents=True,exist_ok=True)
            with open(BAN_LOG,'a') as f:
                f.write(f'[{{datetime.now():%Y-%m-%d %H:%M:%S}}] BAN {{ip}}: {{cnt}} errors\\n')
            tg(f'AutoBan: {{ip}} banned ({{cnt}} TLS errors in {{window}}min)')

cfg['banned'] = banned
#  FIX: persist whitelist (включая добавленные chain IPs) и
# гарантировать наличие 'ban_history' — иначе cron-скрипт затирал
# эти поля, и пункт меню [6] История банов оставался пустым.
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
            targets: list[str] = []

            if raw in ("all", "все", "*"):
                targets = list(ban_list)

            elif "-" in raw and not raw.startswith("-") and not raw.replace(".", "").replace("-", "").isdigit() is False:
                # Диапазон номеров: "2-6"
                parts = raw.split("-", 1)
                if parts[0].isdigit() and parts[1].isdigit():
                    lo, hi = int(parts[0]), int(parts[1])
                    lo, hi = min(lo, hi), max(lo, hi)
                    targets = [ban_list[i-1] for i in range(lo, hi+1)
                               if 1 <= i <= len(ban_list)]
                else:
                    warn("Неверный диапазон. Формат: 2-6")

            elif "," in raw:
                # Перечисление: "1,3,5" или "1.2.3.4,5.6.7.8"
                for token in raw.split(","):
                    token = token.strip()
                    if token.isdigit():
                        idx = int(token)
                        if 1 <= idx <= len(ban_list):
                            targets.append(ban_list[idx-1])
                        else:
                            warn(f"Номер {idx} вне диапазона — пропущен")
                    elif token in banned:
                        targets.append(token)
                    else:
                        warn(f"'{token}' не найден — пропущен")

            elif raw.isdigit():
                idx = int(raw)
                if 1 <= idx <= len(ban_list):
                    targets = [ban_list[idx-1]]
                else:
                    warn(f"Номер {idx} вне диапазона")

            elif raw in banned:
                targets = [raw]

            else:
                warn("Не удалось распознать ввод")

            # ── Выполняем разбан ──────────────────────────────────────────────
            if targets:
                _unban_ts = datetime.now().isoformat()
                ok_count  = 0
                for target in targets:
                    _fw_unban(target)
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
                    success(f"Разбанено IP: {ok_count}")

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
                    # Строка 2: ASN + провайдер
                    asn_info = _lookup_asn(_ip)
                    asn_str  = _fmt_asn_short(asn_info)
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
                ans = input(f"  {RED}Удалить всю историю банов? [y/N]:{NC} ").strip().lower()
                if ans == "y":
                    cfg["ban_history"] = []
                    _autoban_save(cfg)
                    success("История очищена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            wl = cfg.get("whitelist", list(_BAN_WHITELIST_DEFAULT))
            chain_ips = _autoban_get_chain_ips()
            print()
            _box_top("Whitelist (эти IP никогда не баним)")
            for i, ip in enumerate(wl, 1):
                _box_item(f"{i}", f"{ip}")
            if chain_ips:
                _box_sep()
                _box_row(f"  {DIM}Автозащита — IP нод каскада (всегда в whitelist):{NC}")
                for ip in chain_ips:
                    in_wl = "  (уже в whitelist)" if ip in wl else ""
                    _box_row(f"    {DIM}• {ip}{in_wl}{NC}")
            _box_sep()
            _box_item("+", f"Добавить IP")
            _box_item("-", f"Удалить IP")
            _box_bottom()
            act = input("  Действие [+/-/Enter]: ").strip()
            if act == "+":
                new_ip = input("  IP для whitelist: ").strip()
                if new_ip and new_ip not in wl:
                    wl.append(new_ip)
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                    success(f"Добавлен в whitelist: {new_ip}")
            elif act == "-":
                raw_n = input("  Номер для удаления: ").strip()
                if raw_n.isdigit() and 1 <= int(raw_n) <= len(wl):
                    removed = wl.pop(int(raw_n)-1)
                    cfg["whitelist"] = wl
                    _autoban_save(cfg)
                    success(f"Удалён из whitelist: {removed}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
