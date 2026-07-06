"""
vless_installer/modules/credential_rotation.py
───────────────────────────────────────────────────────────────────────────────
Ротация учётных данных: UUID-ротация по расписанию и REALITY-ключей
(x25519 + ShortID). Содержит 6 функций, вынесенных из _core.py
(Tier-2 рефакторинг):

  • _uuid_rotate_now()           — генерация нового UUID, патч config.json /
                                    state.json / users.json
  • _uuid_install_cron(...)      — установка cron-скрипта еженедельной ротации UUID
  • do_manage_uuid_rotation()    — интерактивное меню ротации UUID
  • _rotate_reality_keys()       — генерация новой пары x25519 + ShortID,
                                    патч config.json / state.json / vless_link.txt
  • do_manage_reality_keys()     — интерактивное меню ротации REALITY-ключей
  • _menu_rotation()             — объединённое подменю ротации UUID /
                                    Fingerprint / REALITY-ключей

Точки входа из _core.py:
    from vless_installer.modules.credential_rotation import (
        _UUID_CRON_TAG, _UUID_CRON_SCRIPT,
        _uuid_rotate_now, _uuid_install_cron, do_manage_uuid_rotation,
        _rotate_reality_keys, do_manage_reality_keys, _menu_rotation,
    )

Доступ к helpers ядра (warn, info, success, _run, _box_*, цвета, log_to_file,
XRAY_BIN, STATE_FILE, CONFIG_DIR, USERS_FILE, _tg_notify_event,
ROLLBACK_AVAILABLE, perform_rollback, do_manage_fingerprint) — через importlib
(lazy binding), как и в других извлечённых модулях (warp.py, smart_balancer.py,
standalone_screens.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import textwrap
import time
import uuid
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
_UUID_CRON_TAG    = "xray-uuid-rotate"
_UUID_CRON_SCRIPT = Path("/usr/local/bin/xray-uuid-rotate.sh")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво, как в warp.py)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  UUID РОТАЦИЯ ПО РАСПИСАНИЮ
# =============================================================================
def _uuid_rotate_now() -> str:
    """Генерирует новый UUID, патчит config.json, state.json, users.json. Возвращает новый UUID."""
    core = _core_module()
    warn       = core.warn
    CONFIG_DIR = core.CONFIG_DIR
    STATE_FILE = core.STATE_FILE
    USERS_FILE = core.USERS_FILE

    new_uuid = str(uuid.uuid4())

    # Патч Xray config.json
    for cfg_path in (Path("/usr/local/etc/xray/config.json"), CONFIG_DIR / "config.json"):
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            for ib in cfg.get("inbounds", []):
                clients = ib.get("settings", {}).get("clients", [])
                # Меняем только первого (основного) пользователя
                if clients:
                    clients[0]["id"] = new_uuid
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            cfg_path.chmod(0o640)
        except Exception as e:
            warn(f"Ошибка патча UUID в {cfg_path}: {e}")
            return ""

    # Патч state.json
    try:
        if STATE_FILE.exists():
            state = json.loads(STATE_FILE.read_text())
            state["uuid"] = new_uuid
            STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"Ошибка патча state.json: {e}")

    # Патч users.json (основной пользователь — index 0)
    try:
        if USERS_FILE.exists():
            users = json.loads(USERS_FILE.read_text())
            if isinstance(users, list) and users:
                users[0]["uuid"] = new_uuid
            elif isinstance(users, dict):
                for k in users:
                    if isinstance(users[k], dict) and "uuid" in users[k]:
                        users[k]["uuid"] = new_uuid
                        break
            USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"Ошибка патча users.json: {e}")

    return new_uuid


def _uuid_install_cron(interval_days: int) -> None:
    """Устанавливает cron-скрипт для еженедельной ротации UUID."""
    core = _core_module()
    success = core.success

    script = textwrap.dedent("""\
        #!/bin/bash
        # Авто-ротация UUID для Xray (установлено VLESS Installer)
        NEW_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
        LOG="/var/log/xray-uuid-rotate.log"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] Новый UUID: $NEW_UUID" >> "$LOG"

        for CONF in /usr/local/etc/xray/config.json /etc/xray/config.json; do
            [ -f "$CONF" ] || continue
            python3 -c "
import json, sys
nu = sys.argv[1]
with open('$CONF') as f: c = json.load(f)
for ib in c.get('inbounds', []):
    clients = ib.get('settings', {}).get('clients', [])
    if clients:
        clients[0]['id'] = nu
with open('$CONF', 'w') as f: json.dump(c, f, indent=2, ensure_ascii=False)
print('Обновлён: $CONF')
" "$NEW_UUID" >> "$LOG" 2>&1
        done

        # state.json
        python3 -c "
import json, sys
nu = sys.argv[1]
p = '/var/lib/xray-installer/state.json'
import os;
if os.path.exists(p):
    with open(p) as f: s = json.load(f)
    s['uuid'] = nu
    with open(p, 'w') as f: json.dump(s, f, indent=2, ensure_ascii=False)
" "$NEW_UUID" >> "$LOG" 2>&1

        if /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json >> "$LOG" 2>&1; then
            # Xray 26.x не поддерживает горячий reload через SIGHUP — используем restart.
            if systemctl is-active --quiet xray 2>/dev/null; then
                systemctl restart xray >> "$LOG" 2>&1 \\
                    && echo "[$DATE] Xray перезапущен (uuid=$NEW_UUID)" >> "$LOG" \\
                    || echo "[$DATE] ОШИБКА перезапуска Xray" >> "$LOG"
            else
                systemctl start xray >> "$LOG" 2>&1 \\
                    && echo "[$DATE] Xray запущен (uuid=$NEW_UUID)" >> "$LOG" \\
                    || echo "[$DATE] ОШИБКА запуска Xray" >> "$LOG"
            fi
        else
            echo "[$DATE] Конфиг невалиден — UUID не применён!" >> "$LOG"
        fi
    """)
    _UUID_CRON_SCRIPT.write_text(script)
    _UUID_CRON_SCRIPT.chmod(0o750)
    cron_path = Path(f"/etc/cron.d/{_UUID_CRON_TAG}")
    # Каждые N дней в 03:00
    cron_path.write_text(f"0 3 */{interval_days} * * root {_UUID_CRON_SCRIPT}\n")
    cron_path.chmod(0o644)
    success(f"UUID ротация: каждые {interval_days} дн. → {_UUID_CRON_SCRIPT}")


def do_manage_uuid_rotation() -> None:
    """Меню ротации UUID."""
    core = _core_module()
    info        = core.info
    warn        = core.warn
    success     = core.success
    _run        = core._run
    log_to_file = core.log_to_file
    STATE_FILE  = core.STATE_FILE
    XRAY_BIN    = core.XRAY_BIN
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    CYAN, NC, GREEN, YELLOW, BLUE = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.BLUE

    cron_path = Path(f"/etc/cron.d/{_UUID_CRON_TAG}")

    while True:
        os.system("clear")
        cron_active = cron_path.exists()

        # Текущий UUID из state
        cur_uuid = "?"
        try:
            if STATE_FILE.exists():
                cur_uuid = json.loads(STATE_FILE.read_text()).get("uuid", "?")
        except Exception:
            pass

        print()
        _box_top(f"Ротация UUID")
        _box_row(f"  Текущий UUID:   {CYAN}{cur_uuid}{NC}")
        _box_row(f"  Авто-ротация:   {''+GREEN+'ВКЛЮЧЕНА'+NC if cron_active else ''+YELLOW+'ОТКЛЮЧЕНА'+NC}")
        _box_item("1", f"Сгенерировать новый UUID прямо сейчас")
        _box_item("2", f"{'Отключить' if cron_active else 'Включить'} авто-ротацию по расписанию")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            print()
            ans = input(f"  {YELLOW}Смена UUID отключит всех клиентов до обновления конфига!{NC}\n  Продолжить? [y/N]: ").strip().lower()
            if ans != "y":
                continue
            new_uuid = _uuid_rotate_now()
            if not new_uuid:
                warn("Ошибка при смене UUID")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            val = _run([str(XRAY_BIN), "-test", "-config",
                        "/usr/local/etc/xray/config.json"],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                warn("Конфиг невалиден — UUID не применён")
            else:
                _run(["systemctl", "restart", "xray"], check=False, quiet=True)
                time.sleep(2)
                success(f"Новый UUID: {new_uuid}")
            log_to_file("INFO", f"UUID rotate manual → {new_uuid}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if cron_active:
                cron_path.unlink(missing_ok=True)
                _UUID_CRON_SCRIPT.unlink(missing_ok=True)
                success("Авто-ротация UUID отключена")
            else:
                print()
                _box_top("Интервал авто-ротации UUID")
                _box_item("1", f"Каждые 7 дней {GREEN}(рекомендуется){NC}")
                _box_item("2", f"Каждые 14 дней")
                _box_item("3", f"Каждые 30 дней")
                _box_bottom()
                iv = input("  Выбор [1]: ").strip() or "1"
                days_map = {"1": 7, "2": 14, "3": 30}
                _uuid_install_cron(days_map.get(iv, 7))
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  РОТАЦИЯ REALITY-КЛЮЧЕЙ
# =============================================================================
def _rotate_reality_keys() -> dict:
    """
    Генерирует новую пару x25519 + shortId через `xray x25519`,
    патчит config.json (оба пути), state.json, регенерирует vless_link.txt.
    Возвращает dict с новыми ключами, или {} при ошибке.
    """
    core = _core_module()
    warn             = core.warn
    _run             = core._run
    CONFIG_DIR       = core.CONFIG_DIR
    STATE_FILE       = core.STATE_FILE
    log_to_file      = core.log_to_file
    _tg_notify_event = core._tg_notify_event
    XRAY_BIN         = core.XRAY_BIN

    # Генерируем новую пару ключей
    r = _run([str(XRAY_BIN), "x25519"], capture=True, check=False)
    if r.returncode != 0 or not r.stdout.strip():
        warn("xray x25519 вернул ошибку")
        return {}

    new_priv = new_pub = ""
    for line in r.stdout.splitlines():
        if "Private key" in line:
            new_priv = line.split(":", 1)[-1].strip()
        elif "Public key" in line:
            new_pub  = line.split(":", 1)[-1].strip()

    if not new_priv or not new_pub:
        warn("Не удалось распарсить ключи из вывода xray x25519")
        return {}

    # Новый shortId — 8 случайных hex-байт
    import secrets
    new_sid = secrets.token_hex(8)

    # Патч config.json (оба возможных пути)
    cfg_paths = [
        Path("/usr/local/etc/xray/config.json"),
        CONFIG_DIR / "config.json",
    ]
    patched_any = False
    for cfg_path in cfg_paths:
        if not cfg_path.exists():
            continue
        try:
            cfg = json.loads(cfg_path.read_text())
            changed = False
            for ib in cfg.get("inbounds", []):
                ss = ib.get("streamSettings", {})
                rs = ss.get("realitySettings", {})
                if not rs:
                    continue
                rs["privateKey"] = new_priv
                rs["publicKey"]  = new_pub
                rs["shortIds"]   = [new_sid]
                changed = True
            if changed:
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
                patched_any = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")
            return {}

    if not patched_any:
        warn("REALITY-inbound не найден ни в одном config.json")
        return {}

    # Патч state.json
    try:
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
        old_priv = state.get("private_key", "?")
        state["private_key"] = new_priv
        state["public_key"]  = new_pub
        state["short_id"]    = new_sid
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"Ошибка патча state.json: {e}")
        return {}

    # Обновляем vless_link.txt — заменяем pbk= и sid=
    for link_path in (Path("/root/vless_link.txt"),):
        if not link_path.exists():
            continue
        try:
            txt = link_path.read_text()
            txt = re.sub(r'pbk=[^&\s]+', f'pbk={new_pub}', txt)
            txt = re.sub(r'sid=[^&\s]+', f'sid={new_sid}', txt)
            link_path.write_text(txt)
        except Exception:
            pass

    log_to_file("INFO",
        f"REALITY keys rotated: pub={new_pub[:12]}… sid={new_sid} "
        f"(old priv prefix={old_priv[:8]}…)")
    _tg_notify_event("xray_up",
        f"🔑 REALITY ключи сменены.\n"
        f"<b>Public key:</b> <code>{new_pub}</code>\n"
        f"<b>ShortID:</b> <code>{new_sid}</code>\n"
        f"Обновите клиентские конфиги!")

    return {"private_key": new_priv, "public_key": new_pub, "short_id": new_sid}


def do_manage_reality_keys() -> None:
    """Меню ротации REALITY x25519-ключей и ShortID."""
    core = _core_module()
    info               = core.info
    warn               = core.warn
    success            = core.success
    _run               = core._run
    STATE_FILE         = core.STATE_FILE
    XRAY_BIN           = core.XRAY_BIN
    ROLLBACK_AVAILABLE = getattr(core, "ROLLBACK_AVAILABLE", False)
    perform_rollback   = core.perform_rollback
    _box_top           = core._box_top
    _box_row           = core._box_row
    _box_sep           = core._box_sep
    _box_back          = core._box_back
    _box_item          = core._box_item
    _box_bottom        = core._box_bottom
    CYAN, NC, GREEN, YELLOW, BLUE, RED, DIM = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.BLUE, core.RED, core.DIM,
    )

    while True:
        os.system("clear")
        print()

        # Текущие ключи из state
        cur_pub = cur_sid = cur_priv_hint = "?"
        try:
            if STATE_FILE.exists():
                st = json.loads(STATE_FILE.read_text())
                cur_pub       = st.get("public_key",  "?")
                cur_sid       = st.get("short_id",    "?")
                priv          = st.get("private_key", "")
                cur_priv_hint = (priv[:8] + "…") if len(priv) > 8 else priv
        except Exception:
            pass

        proto = "?"
        try:
            if STATE_FILE.exists():
                proto = json.loads(STATE_FILE.read_text()).get("protocol_mode", "?")
        except Exception:
            pass

        _box_top("🔑  РОТАЦИЯ REALITY-КЛЮЧЕЙ")
        _box_row(f"  {DIM}Смена x25519 keypair + ShortID. Всем клиентам нужно обновить конфиг.{NC}")
        _box_row()
        _box_row(f"  Протокол:    {CYAN}{proto}{NC}")
        _box_row(f"  Public Key:  {CYAN}{cur_pub[:52]}{'…' if len(cur_pub) > 52 else ''}{NC}")
        _box_row(f"  ShortID:     {CYAN}{cur_sid}{NC}")
        _box_row(f"  Private Key: {DIM}{cur_priv_hint} (скрыт){NC}")
        _box_sep()

        if proto != "reality":
            _box_row(f"  {YELLOW}⚠  Протокол не REALITY — ротация ключей неприменима{NC}")
            _box_row()
            _box_back()
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")
            return

        _box_item("1", f"🔄 Сгенерировать новые ключи (x25519 + ShortID)")
        _box_item("2", f"📋 Показать актуальные клиентские ссылки")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            print()
            _box_row(f"  {RED}⚠  ВНИМАНИЕ:{NC} после смены ключей все клиенты перестанут подключаться")
            _box_row(f"  {YELLOW}   до обновления Public Key и ShortID в их конфигах!{NC}")
            print()
            ans = input(f"  Продолжить? [y/N]: ").strip().lower()
            if ans != "y":
                warn("Отменено")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            info("Генерация новых ключей…")
            new_keys = _rotate_reality_keys()
            if not new_keys:
                warn("Ошибка при ротации ключей — конфиг не изменён")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Валидация и перезапуск
            val = _run([str(XRAY_BIN), "-test", "-config",
                        "/usr/local/etc/xray/config.json"],
                       capture=True, check=False, quiet=True)
            if val.returncode != 0:
                warn("Конфиг невалиден после ротации — откатываем!")
                warn(val.stderr[:300] if val.stderr else "(нет stderr)")
                # Откат через perform_rollback если доступен
                if ROLLBACK_AVAILABLE:
                    perform_rollback()
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _run(["systemctl", "restart", "xray"], check=False, quiet=True)
            time.sleep(2)

            print()
            _box_top("✅ Новые REALITY-ключи")
            _box_row(f"  {GREEN}Public Key:{NC}  {new_keys['public_key']}")
            _box_row(f"  {GREEN}ShortID:   {NC}  {new_keys['short_id']}")
            _box_row()
            _box_row(f"  {YELLOW}Обновите Public Key и ShortID во всех клиентских конфигах!{NC}")
            _box_bottom()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            link_path = Path("/root/vless_link.txt")
            if link_path.exists():
                print()
                _box_top("Клиентские ссылки")
                for line in link_path.read_text().splitlines():
                    if line.strip():
                        _box_row(f"  {CYAN}{line.strip()}{NC}")
                _box_bottom()
            else:
                warn("vless_link.txt не найден")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


# =============================================================================
#  ОБЪЕДИНЁННОЕ ПОДМЕНЮ РОТАЦИИ
# =============================================================================
def _menu_rotation() -> None:
    """Объединённое подменю ротации UUID и Fingerprint."""
    core = _core_module()
    warn                  = core.warn
    _box_top              = core._box_top
    _box_row              = core._box_row
    _box_item             = core._box_item
    _box_back             = core._box_back
    _box_bottom           = core._box_bottom
    CYAN, NC              = core.CYAN, core.NC
    do_manage_fingerprint = core.do_manage_fingerprint

    while True:
        os.system("clear")
        print()
        _box_top("🔑  РОТАЦИЯ UUID И FINGERPRINT")
        _box_row()
        _box_item("1", "🔑 Ротация UUID по расписанию")
        _box_item("2", "🎭 Авто-смена TLS Fingerprint")
        _box_item("3", "🔐 Ротация REALITY-ключей (x25519 + ShortID)")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except KeyboardInterrupt:
            break
        if ch == "1":
            do_manage_uuid_rotation()
        elif ch == "2":
            do_manage_fingerprint()
        elif ch == "3":
            do_manage_reality_keys()
        elif ch.lower() == "q" or ch == "":
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)
