"""
vless_installer/modules/traffic_tracking.py
───────────────────────────────────────────────────────────────────────────────
Лимиты трафика пользователей: чтение/запись limits.json, опрос Xray Stats API,
разовая проверка лимитов с отключением превышенных клиентов, интерактивное
меню управления и cron-скрипт. Содержит 6 функций, вынесенных из _core.py
(Tier-2 рефакторинг):

  • _limits_load()                  — чтение /var/lib/xray-installer/traffic_limits.json
  • _limits_save(data)              — запись traffic_limits.json (chmod 0o600)
  • _query_user_traffic_bytes(...)  — опрос Xray Stats API (uplink+downlink) по email
  • _stats_api_is_configured()      — проверка наличия секций stats/api/policy/inbound
                                      в config.json (без неё запросы вернут 0)
  • _check_traffic_limits_once()    — разовая проверка: при превышении лимита
                                      клиент удаляется из users.json, лимит
                                      помечается disabled, шлётся TG-уведомление
  • do_manage_traffic_limits()      — интерактивное меню: задать/снять лимит,
                                      сбросить счётчики, вкл/выкл cron, проверить
                                      сейчас. Содержит встроенный cron-скрипт
                                      (stringified Python в bash-heredoc).

Точки входа из _core.py:
    from vless_installer.modules.traffic_tracking import (
        TRAFFIC_LIMITS_FILE,
        _limits_load, _limits_save, _query_user_traffic_bytes,
        _stats_api_is_configured, _check_traffic_limits_once,
        do_manage_traffic_limits,
    )

Доступ к helpers ядра (_run, log_to_file, STATE_FILE, CONFIG_DIR, XRAY_BIN,
XRAY_STATS_API_PORT, _users_load, _users_save, _users_apply_to_config,
_xray_safe_apply_config, _tg_notify_event, _box_*, info/warn/success, цвета) —
через importlib (lazy binding), как и в других извлечённых модулях
(credential_rotation.py, standalone_screens.py, smart_balancer.py и т.д.).
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

# ── Константы ─────────────────────────────────────────────────────────────────
TRAFFIC_LIMITS_FILE = Path("/var/lib/xray-installer/traffic_limits.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  ЛИМИТЫ ТРАФИКА ПОЛЬЗОВАТЕЛЕЙ
# =============================================================================
def _limits_load() -> dict:
    try:
        if TRAFFIC_LIMITS_FILE.exists():
            return json.loads(TRAFFIC_LIMITS_FILE.read_text())
    except Exception:
        pass
    return {}


def _limits_save(data: dict) -> None:
    TRAFFIC_LIMITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_LIMITS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    TRAFFIC_LIMITS_FILE.chmod(0o600)


def _query_user_traffic_bytes(email: str) -> int:
    """Возвращает суммарный трафик пользователя (up+down) в байтах через Stats API."""
    core = _core_module()
    _run = core._run
    XRAY_BIN = core.XRAY_BIN
    XRAY_STATS_API_PORT = core.XRAY_STATS_API_PORT

    total = 0
    for direction in ("uplink", "downlink"):
        try:
            r = _run([
                str(XRAY_BIN), "api", "statsquery",
                f"--server=127.0.0.1:{XRAY_STATS_API_PORT}",
                f"--pattern=user>>>{email}>>>{direction}",
            ], capture=True, check=False)
            for line in r.stdout.splitlines():
                m = re.search(r'"value"\s*:\s*"?(\d+)"?', line)
                if m:
                    total += int(m.group(1))
        except Exception:
            pass
    return total


def _stats_api_is_configured() -> bool:
    """
    Проверяет что Stats API реально включён в config.json
    (секции stats + api + policy + inbound xray-stats-api присутствуют).
    Без этого _query_user_traffic_bytes всегда вернёт 0 и лимиты никогда не сработают.
    """
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR

    for cfg_path in (Path("/usr/local/etc/xray/config.json"), CONFIG_DIR / "config.json"):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            has_stats  = "stats" in cfg
            has_api    = any(ob.get("tag") == "xray-stats-api"
                             for ob in cfg.get("outbounds", []))
            has_policy = "policy" in cfg
            has_inb    = any(ib.get("tag") == "xray-stats-api"
                             for ib in cfg.get("inbounds", []))
            return has_stats and has_api and has_policy and has_inb
        except Exception:
            pass
    return False


def _check_traffic_limits_once() -> None:
    """Проверяет лимиты трафика. При превышении удаляет клиента из конфига."""
    core = _core_module()
    log_to_file              = core.log_to_file
    _users_load              = core._users_load
    _users_save              = core._users_save
    _users_apply_to_config   = core._users_apply_to_config
    _tg_notify_event         = core._tg_notify_event
    XRAY_BIN                 = core.XRAY_BIN
    XRAY_STATS_API_PORT      = core.XRAY_STATS_API_PORT

    # Ранняя проверка: Stats API должен быть включён, иначе запросы вернут 0
    # и лимиты никогда не сработают — молча пропускаем, логируем один раз.
    if not _stats_api_is_configured():
        log_to_file("WARN",
            "traffic_limits: Stats API не настроен в config.json — "
            "лимиты не могут быть применены. Используйте 'Патч Stats API' в меню диагностики.")
        return

    limits = _limits_load()
    if not limits:
        return
    users = _users_load()
    changed = False
    for email, limit_cfg in limits.items():
        limit_bytes = limit_cfg.get("limit_gb", 0) * 1024 ** 3
        if not limit_bytes or limit_cfg.get("disabled"):
            continue
        used_bytes = _query_user_traffic_bytes(email)
        limit_cfg["used_bytes"] = used_bytes
        if used_bytes >= limit_bytes:
            users_new = [u for u in users if u.get("email") != email]
            if len(users_new) < len(users):
                _users_save(users_new)
                _users_apply_to_config(users_new)
                limit_cfg["disabled"] = True
                limit_cfg["disabled_at"] = datetime.now().isoformat()
                changed = True
                log_to_file("INFO",
                    f"Traffic limit: {email} disabled "
                    f"({used_bytes/1024**3:.2f} GB / {limit_cfg['limit_gb']} GB)")
                _tg_notify_event(
                    "traffic_limit",
                    f"Пользователь <b>{email}</b> отключён: "
                    f"использовано {used_bytes/1024**3:.2f} ГБ из {limit_cfg['limit_gb']} ГБ"
                )
    if changed:
        _limits_save(limits)


def do_manage_traffic_limits() -> None:
    """Меню управления лимитами трафика пользователей."""
    core = _core_module()
    _box_top                = core._box_top
    _box_row                = core._box_row
    _box_item               = core._box_item
    _box_bottom             = core._box_bottom
    info                    = core.info
    warn                    = core.warn
    success                 = core.success
    _run                    = core._run
    log_to_file             = core.log_to_file
    STATE_FILE              = core.STATE_FILE
    XRAY_BIN                = core.XRAY_BIN
    XRAY_STATS_API_PORT     = core.XRAY_STATS_API_PORT
    _users_load             = core._users_load
    _users_save             = core._users_save
    _users_apply_to_config  = core._users_apply_to_config
    _xray_safe_apply_config = core._xray_safe_apply_config
    _tg_notify_event        = core._tg_notify_event
    _BOX_W                  = core._BOX_W
    BLUE = core.BLUE
    CYAN = core.CYAN
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    RED = core.RED
    YELLOW = core.YELLOW
    CYAN, NC, RED, YELLOW, GREEN, BLUE, DIM = (
        core.CYAN, core.NC, core.RED, core.YELLOW, core.GREEN, core.BLUE, core.DIM,
    )

    while True:
        os.system("clear")
        limits = _limits_load()
        users  = _users_load()

        print()
        _box_top(f"Лимиты трафика пользователей")

        cron_active = Path("/etc/cron.d/xray-traffic-limits").exists()
        _box_row(f"  Cron-проверка: {''+GREEN+'ВКЛЮЧЕНА (каждые 15 мин)'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЕНА'+NC}")

        if not users:
            _box_row(f"  {DIM}Пользователей нет{NC}")
        else:
            _EM_W = max(16, _BOX_W - 2 - 4 - 12 - 20 - 10 - 4)
            _box_row(f"  {'#':<4} {'Email':<{_EM_W}} {'Лимит':<12} {'Использовано':<20} {'Статус'}")
            _box_row(f"  {'─'*4} {'─'*_EM_W} {'─'*12} {'─'*20} {'─'*10}")
            for i, u in enumerate(users, 1):
                email = u.get("email", "")
                lim   = limits.get(email, {})
                limit_gb   = lim.get("limit_gb", 0)
                used_bytes = lim.get("used_bytes", 0)
                used_gb    = used_bytes / 1024 ** 3
                disabled   = lim.get("disabled", False)
                email_disp = email if len(email) <= _EM_W else email[:_EM_W - 1] + "…"
                if limit_gb:
                    pct = min(100, used_gb / limit_gb * 100)
                    col = RED if pct >= 90 else YELLOW if pct >= 70 else GREEN
                    lim_str  = f"{limit_gb} ГБ"
                    used_str = f"{col}{used_gb:.2f} ГБ ({pct:.0f}%){NC}"
                    st_str   = f"{RED}ОТКЛЮЧЁН{NC}" if disabled else f"{GREEN}активен{NC}"
                else:
                    lim_str  = f"{DIM}нет{NC}"
                    used_str = f"{DIM}—{NC}"
                    st_str   = f"{GREEN}активен{NC}"
                _box_row(f"  {i:<4} {email_disp:<{_EM_W}} {lim_str:<12} {used_str:<20} {st_str}")
        _box_item("1", f"Задать/изменить лимит пользователя")
        _box_item("2", f"Снять лимит и восстановить пользователя")
        _box_item("3", f"Сбросить счётчики (новый месяц)")
        _box_item("4", f"{'Отключить' if cron_active else 'Включить'} авто-проверку (cron 15 мин)")
        _box_item("5", f"Проверить лимиты прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            if not users:
                warn("Нет пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _box_top("Выберите пользователя")
            for i, u in enumerate(users, 1):
                _box_item(f"{i}", f"{u.get('email','?')}")
            _box_bottom()
            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(users)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            u = users[int(raw)-1]
            email = u.get("email", "")
            raw_gb = input(f"  Лимит трафика в ГБ (0 = без лимита): ").strip()
            if not raw_gb.isdigit():
                warn("Введите число")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            limit_gb = int(raw_gb)
            if email not in limits:
                limits[email] = {}
            limits[email]["limit_gb"] = limit_gb
            limits[email].pop("disabled", None)
            limits[email].pop("disabled_at", None)
            _limits_save(limits)
            success(f"Лимит {limit_gb} ГБ задан для {email}" if limit_gb else f"Лимит снят для {email}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            print()
            raw = input("  Номер пользователя для восстановления: ").strip()
            target_email = ""
            if raw.isdigit() and 1 <= int(raw) <= len(users):
                target_email = users[int(raw)-1].get("email", "")
            else:
                target_email = raw
            if target_email in limits and limits[target_email].get("disabled"):
                limits[target_email].pop("disabled", None)
                limits[target_email].pop("disabled_at", None)
                _limits_save(limits)
                _users_apply_to_config(users)
                success(f"Пользователь {target_email} восстановлен")
            else:
                warn("Пользователь не найден или не был отключён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ans = input(f"  {YELLOW}Сбросить счётчики для всех? [y/N]:{NC} ").strip().lower()
            if ans == "y":
                for email in limits:
                    limits[email]["used_bytes"] = 0
                    limits[email].pop("disabled", None)
                    limits[email].pop("disabled_at", None)
                _limits_save(limits)
                _run(["systemctl", "restart", "xray"], check=False, quiet=True)
                time.sleep(2)
                success("Счётчики сброшены, Xray перезапущен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            cron_p = Path("/etc/cron.d/xray-traffic-limits")
            sh     = Path("/usr/local/bin/xray-traffic-limits.sh")
            if cron_active:
                cron_p.unlink(missing_ok=True)
                sh.unlink(missing_ok=True)
                success("Авто-проверка лимитов отключена")
            else:
                sh.write_text(textwrap.dedent(f"""\
                    #!/bin/bash
                    python3 -c "
import json, re, subprocess, sys, time
from pathlib import Path
from datetime import datetime
XRAY_BIN = Path('/usr/local/bin/xray')
XRAY_STATS_API_PORT = 10085
USERS_FILE = Path('/etc/xray/users.json')
TRAFFIC_LIMITS_FILE = Path('/var/lib/xray-installer/traffic_limits.json')
TG_CONFIG_FILE = Path('/var/lib/xray-installer/telegram.json')

def _run(args):
    return subprocess.run(args, capture_output=True, text=True)

def _users_load():
    try: return json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else []
    except: return []

def _users_save(users):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))

def _users_apply(users):
    for cfg_path in (Path('/etc/xray/config.json'),Path('/usr/local/etc/xray/config.json')):
        if not cfg_path.exists(): continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for inb in cfg.get('inbounds',[]):
                s = inb.get('settings',{{}})
                if 'clients' not in s: continue
                use_flow = 'realitySettings' in inb.get('streamSettings',{{}})
                s['clients'] = [dict(id=u['uuid'],email=u.get('email',''),**({{'flow':'xtls-rprx-vision'}} if use_flow else {{}})) for u in users]
            cfg_path.write_text(json.dumps(cfg,indent=2))
            import os; os.chmod(str(cfg_path),0o640)
        except: pass
    subprocess.run(['systemctl','restart','xray'],capture_output=True)

def tg_send(msg):
    try:
        cfg=json.loads(TG_CONFIG_FILE.read_text()) if TG_CONFIG_FILE.exists() else {{}}
        t,c=cfg.get('token'),cfg.get('chat_id')
        if t and c:
            subprocess.run(['curl','-s','-o','/dev/null','-m','10',
                f'https://api.telegram.org/bot{{t}}/sendMessage',
                '-d',f'chat_id={{c}}','-d',f'text={{msg}}','-d','parse_mode=HTML'],capture_output=True)
    except: pass

def qbytes(email):
    total=0
    for d in ('uplink','downlink'):
        r=_run([str(XRAY_BIN),'api','statsquery',f'--server=127.0.0.1:{{XRAY_STATS_API_PORT}}',f'--pattern=user>>>{{email}}>>>{{d}}'])
        for line in r.stdout.splitlines():
            m=re.search(r'\"value\"\\s*:\\s*\"?(\\d+)\"?',line)
            if m: total+=int(m.group(1))
    return total

limits=json.loads(TRAFFIC_LIMITS_FILE.read_text()) if TRAFFIC_LIMITS_FILE.exists() else {{}}
users=_users_load()
changed=False
for email,lim in limits.items():
    gb=lim.get('limit_gb',0)
    if not gb or lim.get('disabled'): continue
    used=qbytes(email)
    lim['used_bytes']=used
    if used>=gb*1024**3:
        un=[u for u in users if u.get('email')!=email]
        if len(un)<len(users):
            _users_save(un); _users_apply(un)
            lim['disabled']=True; changed=True
            tg_send(f'Warning user {{email}} disabled: {{used/1024**3:.2f}} GB of {{gb}} GB')
if changed:
    TRAFFIC_LIMITS_FILE.write_text(json.dumps(limits,indent=2))
" 2>>/var/log/xray-traffic-limits.log
                """))
                sh.chmod(0o750)
                cron_p.write_text(f"*/15 * * * * root {sh} >> /var/log/xray-traffic-limits.log 2>&1\n")
                cron_p.chmod(0o644)
                success("Авто-проверка лимитов включена (каждые 15 мин)")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            print()
            info("Проверка лимитов трафика...")
            _check_traffic_limits_once()
            success("Проверка завершена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
