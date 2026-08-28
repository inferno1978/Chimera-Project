"""
chimera/modules/health_report.py
───────────────────────────────────────────────────────────────────────────────
Ежедневный health-отчёт: сбор состояния Xray/Nginx/SSL/диска/RAM/geo-файлов,
опциональная отправка в Telegram, интерактивное меню и cron-скрипт на 08:00.
Содержит 3 функции, вынесенных из _core.py (Tier-2 рефакторинг):

  • do_health_report(send_tg_flag=True)  — собирает отчёт (Xray/Nginx/SSL/
                                            диск/RAM/geo-файлы), опционально
                                            шлёт в Telegram, возвращает текст
  • _health_report_install_cron()        — устанавливает cron на 08:00
                                            (содержит встроенный stringified
                                            Python-скрипт в bash-heredoc)
  • do_manage_health_report()            — интерактивное меню: вкл/выкл cron,
                                            запустить сейчас, показать лог

Точки входа из _core.py:
    from chimera.modules.health_report import (
        do_health_report, _health_report_install_cron, do_manage_health_report,
    )

Доступ к helpers ядра (_run, log_to_file, STATE_FILE, GEOSITE_DAT, GEOIP_DAT,
_tg_load, tg_send, _box_*, info/warn/success, цвета) — через importlib
(lazy binding), как и в других извлечённых модулях (credential_rotation.py,
standalone_screens.py, traffic_tracking.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  МОДУЛЬ 4: ЕЖЕДНЕВНЫЙ HEALTH-ОТЧЁТ (CRON 08:00)
# =============================================================================
def do_health_report(send_tg_flag: bool = True) -> str:
    """Собирает ежедневный health-отчёт, опционально шлёт в Telegram."""
    core = _core_module()
    _run        = core._run
    log_to_file = core.log_to_file
    STATE_FILE  = core.STATE_FILE
    GEOSITE_DAT = core.GEOSITE_DAT
    GEOIP_DAT   = core.GEOIP_DAT
    _tg_load    = core._tg_load
    tg_send     = core.tg_send

    lines = []
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True, check=False).stdout.strip()
    except Exception:
        pass

    lines.append(f"📋 <b>Daily Health Report [{hostname}]</b>  {ts}")
    lines.append("")

    # Xray
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    xray_ok = r.stdout.strip() == "active"
    lines.append(f"{'✅' if xray_ok else '❌'} Xray: {'активен' if xray_ok else 'НЕ АКТИВЕН'}")

    # Nginx
    r = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
    nginx_ok = r.stdout.strip() == "active"
    lines.append(f"{'✅' if nginx_ok else '❌'} Nginx: {'активен' if nginx_ok else 'НЕ АКТИВЕН'}")

    # v62: фактический DNS-путь Xray — config.json + живой DNS-стек.
    # Одна строка закрывает «через что идут DNS-запросы»: конфиг «через
    # AGH» + мёртвый AGH = запросы молча в fallback, фильтры обходятся.
    try:
        from chimera.modules.agh_probe import xray_dns_path_report
        dns_rep = xray_dns_path_report(run=_run)
        lines.append(f"{dns_rep['icon']} {dns_rep['line']}")
    except Exception:
        lines.append("⚠️ DNS-путь: не удалось проверить")

    # SSL
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
                r  = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
                          capture=True, check=False)
                expiry = r.stdout.strip().split("=", 1)[1]
                r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
                cert_days = (int(r2.stdout.strip()) - int(time.time())) // 86400
                icon = "✅" if cert_days > 30 else "⚠️"
                lines.append(f"{icon} SSL ({domain}): {cert_days} дн. до истечения")
            except Exception:
                lines.append("⚠️ SSL: не удалось проверить")
        else:
            lines.append("❌ SSL: сертификат не найден")
    else:
        lines.append("ℹ️  SSL: домен не задан")

    # Диск
    try:
        r = _run(["df", "-h", "/"], capture=True, check=False)
        parts = r.stdout.splitlines()[-1].split()
        disk_pct = float(parts[4].replace("%", ""))
        icon = "✅" if disk_pct < 80 else "⚠️" if disk_pct < 90 else "❌"
        lines.append(f"{icon} Диск: {parts[2]}/{parts[1]} ({disk_pct:.0f}%)")
    except Exception:
        lines.append("⚠️ Диск: не удалось проверить")

    # RAM
    try:
        meminfo = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            meminfo[k.strip()] = int(v.strip().split()[0])
        total_mb = meminfo.get("MemTotal", 0) // 1024
        avail_mb = meminfo.get("MemAvailable", 0) // 1024
        used_mb  = total_mb - avail_mb
        pct = used_mb * 100 // max(total_mb, 1)
        icon = "✅" if pct < 80 else "⚠️" if pct < 90 else "❌"
        lines.append(f"{icon} RAM: {used_mb}/{total_mb} МБ ({pct}%)")
    except Exception:
        lines.append("⚠️ RAM: не удалось проверить")

    # Geo-файлы
    for dat in (GEOSITE_DAT, GEOIP_DAT):
        if dat.exists():
            age = (time.time() - dat.stat().st_mtime) / 86400
            icon = "✅" if age < 14 else "⚠️"
            lines.append(f"{icon} {dat.name}: возраст {age:.0f} дн.")
        else:
            lines.append(f"❌ {dat.name}: не найден")

    text = "\n".join(lines)
    log_to_file("INFO", f"Health report generated")

    if send_tg_flag:
        cfg = _tg_load()
        if (cfg.get("token") and cfg.get("chat_id")
                and cfg.get("events", {}).get("health_report", True)):
            tg_send(text, cfg["token"], cfg["chat_id"])

    return text


def _health_report_install_cron() -> None:
    """Устанавливает cron на 08:00 для ежедневного health-отчёта."""
    core = _core_module()
    success = core.success

    sh = Path("/usr/local/bin/xray-health-report.sh")
    sh.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        python3 -c "
import json, re, subprocess, sys, time
from pathlib import Path
from datetime import datetime
STATE_FILE = Path('/var/lib/xray-installer/state.json')
TG_CONFIG_FILE = Path('/var/lib/xray-installer/telegram.json')
GEOSITE_DAT = Path('/etc/xray/geosite.dat')
GEOIP_DAT   = Path('/etc/xray/geoip.dat')

def _run(args):
    return subprocess.run(args, capture_output=True, text=True)

def tg_send(msg, token, chat_id):
    subprocess.run(['curl','-s','-o','/dev/null','-m','10',
        f'https://api.telegram.org/bot{{token}}/sendMessage',
        '-d',f'chat_id={{chat_id}}','-d',f'text={{msg}}','-d','parse_mode=HTML'],
        capture_output=True)

cfg = {{}}
try:
    if TG_CONFIG_FILE.exists():
        cfg = json.loads(TG_CONFIG_FILE.read_text())
except: pass
token   = cfg.get('token','')
chat_id = cfg.get('chat_id','')
if not (token and chat_id and cfg.get('events',{{}}).get('health_report',True)):
    sys.exit(0)

hostname = _run(['hostname','-s']).stdout.strip()
ts = datetime.now().strftime('%d.%m.%Y %H:%M')
lines = [f'Daily Health Report [{{hostname}}]  {{ts}}', '']
for svc in ('xray','nginx'):
    ok = _run(['systemctl','is-active',svc]).stdout.strip() == 'active'
    _icon = chr(9989) if ok else chr(10060)
    _status = 'активен' if ok else 'НЕ АКТИВЕН'
    lines.append(f'{{_icon}} {{svc}}: {{_status}}')
domain = ''
try:
    if STATE_FILE.exists():
        domain = json.loads(STATE_FILE.read_text()).get('domain','')
except: pass
if domain:
    cert = Path(f'/etc/letsencrypt/live/{{domain}}/fullchain.pem')
    if cert.exists():
        try:
            r = _run(['openssl','x509','-in',str(cert),'-noout','-enddate'])
            exp = r.stdout.strip().split('=',1)[1]
            epoch = int(_run(['date','-d',exp,'+%s']).stdout.strip())
            days = (epoch - int(time.time())) // 86400
            lines.append(f'{{chr(9989) if days>30 else chr(9888)}} SSL: {{days}} дн. до истечения')
        except: lines.append('SSL: ошибка проверки')
try:
    r = _run(['df','-h','/'])
    p = r.stdout.splitlines()[-1].split()
    pct = float(p[4].replace('%',''))
    lines.append(f'{{chr(9989) if pct<80 else chr(9888)}} Диск: {{p[2]}}/{{p[1]}} ({{pct:.0f}}%)')
except: pass
# v62: фактический DNS-путь Xray (config.json + живой DNS-стек)
try:
    _servers = []
    for _cp in ('/etc/xray/config.json','/usr/local/etc/xray/config.json'):
        _p = Path(_cp)
        if _p.exists():
            try:
                _servers = (json.loads(_p.read_text()).get('dns') or {{}}).get('servers') or []
                if _servers: break
            except: pass
    if _servers:
        _s0 = _servers[0] or {{}}
        _a = str(_s0.get('address','')); _po = _s0.get('port', 53)
        if _a == '127.0.0.1' and _po == 53:
            _agh = _run(['systemctl','is-active','AdGuardHome']).stdout.strip() == 'active'
            if _agh:
                _ss = _run(['ss','-ulnp']).stdout or ''
                _agh = any('adguardhome' in _l.lower()
                           and re.search(r'127[.]0[.]0[.]1:53(?![0-9])', _l)
                           for _l in _ss.splitlines())
            lines.append((chr(9989) if _agh else chr(9888))
                + ' DNS: Xray → AGH:53 → DNSCrypt:5300'
                + ('' if _agh else ' (AGH не активен — запросы через fallback)'))
        elif _a == '127.0.0.1':
            _dc = _run(['systemctl','is-active','dnscrypt-proxy']).stdout.strip() == 'active'
            lines.append((chr(9989) if _dc else chr(9888))
                + f' DNS: Xray → DNSCrypt:{{_po}}'
                + ('' if _dc else ' (dnscrypt не активен)'))
        else:
            lines.append(chr(8505) + f' DNS: Xray → {{_a}}:{{_po}} (публичный)')
except: pass
for dat_name in ('geosite.dat','geoip.dat'):
    dat = Path(f'/etc/xray/{{dat_name}}')
    if dat.exists():
        age = (time.time() - dat.stat().st_mtime) / 86400
        lines.append(f'{{chr(9989) if age<14 else chr(9888)}} {{dat_name}}: возраст {{age:.0f}} дн.')
    else:
        lines.append(f'{{chr(10060)}} {{dat_name}}: не найден')
tg_send(chr(10).join(lines), token, chat_id)
" 2>>/var/log/xray-health-report.log
    """))
    sh.chmod(0o750)
    cron_p = Path("/etc/cron.d/xray-health-report")
    cron_p.write_text(f"0 8 * * * root {sh} >> /var/log/xray-health-report.log 2>&1\n")
    cron_p.chmod(0o644)
    success("Health-отчёт cron установлен (ежедневно 08:00)")


def do_manage_health_report() -> None:
    """Меню управления ежедневным health-отчётом."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    info        = core.info
    warn        = core.warn
    success     = core.success
    CYAN, NC, GREEN, YELLOW, BLUE = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.BLUE

    while True:
        os.system("clear")
        cron_active = Path("/etc/cron.d/xray-health-report").exists()
        print()
        _box_top(f"Ежедневный Health-отчёт")
        _box_row(f"  Cron (08:00): {''+GREEN+'ВКЛЮЧЁН'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЁН'+NC}")
        _box_item("1", f"{'Отключить' if cron_active else 'Включить'} ежедневный отчёт (cron 08:00)")
        _box_item("2", f"Запустить отчёт прямо сейчас")
        _box_item("3", f"Показать лог отчётов")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            if cron_active:
                Path("/etc/cron.d/xray-health-report").unlink(missing_ok=True)
                Path("/usr/local/bin/xray-health-report.sh").unlink(missing_ok=True)
                success("Health-отчёт cron отключён")
            else:
                _health_report_install_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            info("Генерация отчёта...")
            report = do_health_report(send_tg_flag=True)
            clean  = re.sub(r'<[^>]+>', '', report)
            print()
            print(clean)
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            lp = Path("/var/log/xray-health-report.log")
            if lp.exists():
                lines = lp.read_text().splitlines()[-30:]
                print()
                print('\n'.join(lines))
            else:
                warn("Лог не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
