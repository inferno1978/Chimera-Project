"""
vless_installer/modules/ttl_users.py
───────────────────────────────────────────────────────────────────────────────
Временные пользователи (TTL) + база заблокированных пользователей.

Хранилище:
  • TTL-база      — /var/lib/xray-installer/ttl_users.json
  • Blocked-база  — /var/lib/xray-installer/blocked_users.json
  • Cron-агент    — /usr/local/bin/xray-ttl-check.sh
  • Cron-файл     — /etc/cron.d/xray-ttl-check  (каждые 30 мин)
  • Лог           — /var/log/xray-ttl.log

Формат записи TTL:
    {
      "email": "guest@xray",
      "expires_at": "2025-12-31T23:59:59+00:00",   # ISO-8601 UTC
      "days": 7,                                     # исходный TTL
      "notified_24h": false                          # флаг — алерт за 24ч отправлен
    }

Точки входа из _core.py:
    from vless_installer.modules.ttl_users import (
        TTL_FILE, TTL_CRON_SCRIPT, TTL_CRON_FILE, TTL_LOG, BLOCKED_FILE,
        _ttl_load, _ttl_save, _ttl_expires_str, _ttl_is_expired,
        _ttl_expires_within_hours, _ttl_set, _ttl_remove,
        _blocked_load, _blocked_save, _ttl_block_user, _ttl_unblock_user,
        _ttl_is_blocked, _ttl_check_and_expire, _ttl_install_cron,
        _ttl_remove_cron, _ttl_cron_active, do_manage_ttl_users,
    )

Доступ к helpers ядра (info/warn/success/log_to_file/_users_load/...)
— через importlib (см. _core_module()), как и в других извлечённых модулях
(standalone_screens.py, asn_cache.py, warp.py, smart_balancer.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


# ── Константы ─────────────────────────────────────────────────────────────────
TTL_FILE        = Path("/var/lib/xray-installer/ttl_users.json")
TTL_CRON_SCRIPT = Path("/usr/local/bin/xray-ttl-check.sh")
TTL_CRON_FILE   = Path("/etc/cron.d/xray-ttl-check")
TTL_LOG         = Path("/var/log/xray-ttl.log")
BLOCKED_FILE    = Path("/var/lib/xray-installer/blocked_users.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво.

    Все функции ниже обращаются к helpers ядра (info/warn/success,
    log_to_file, _users_load, _users_save, _users_apply_to_config,
    _tg_notify_event, _box_*, colors, STATE_FILE, ...) через `core = _core_module()`
    в начале тела — это позволяет избежать циклического импорта.
    """
    import importlib
    return importlib.import_module("vless_installer._core")


# ── helpers ──────────────────────────────────────────────────────────────────

def _ttl_load() -> dict:
    """Загружает TTL-базу. Ключ — email пользователя."""
    try:
        if TTL_FILE.exists():
            return json.loads(TTL_FILE.read_text())
    except Exception:
        pass
    return {}


def _ttl_save(data: dict) -> None:
    TTL_FILE.parent.mkdir(parents=True, exist_ok=True)
    TTL_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    TTL_FILE.chmod(0o600)


def _ttl_expires_str(iso: str) -> str:
    """Возвращает строку вида '3д 14ч' до истечения или 'ИСТЁК'."""
    try:
        exp = datetime.fromisoformat(iso)
        now = datetime.now(timezone.utc)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - now
        total = int(delta.total_seconds())
        if total <= 0:
            return "ИСТЁК"
        days  = total // 86400
        hours = (total % 86400) // 3600
        mins  = (total % 3600)  // 60
        if days > 0:
            return f"{days}д {hours}ч"
        if hours > 0:
            return f"{hours}ч {mins}м"
        return f"{mins}м"
    except Exception:
        return "?"


def _ttl_is_expired(iso: str) -> bool:
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp
    except Exception:
        return False


def _ttl_expires_within_hours(iso: str, hours: int) -> bool:
    """True если пользователь истечёт в течение `hours` часов."""
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (exp - now).total_seconds()
        return 0 < delta <= hours * 3600
    except Exception:
        return False


# ── добавление TTL к пользователю ────────────────────────────────────────────

def _ttl_set(email: str, days: int) -> None:
    """
    Устанавливает TTL для существующего пользователя.
    Если запись уже есть — перезаписывает (продление / сокращение).
    """
    core = _core_module()
    log_to_file = core.log_to_file
    data = _ttl_load()
    expires_at = (
        datetime.now(timezone.utc).replace(microsecond=0)
        + __import__("datetime").timedelta(days=days)
    ).isoformat()
    data[email] = {
        "email":        email,
        "expires_at":   expires_at,
        "days":         days,
        "notified_24h": False,
    }
    _ttl_save(data)
    log_to_file("INFO", f"TTL set: {email} expires {expires_at} ({days}d)")


def _ttl_remove(email: str) -> None:
    """Снимает TTL-ограничение с пользователя (делает постоянным)."""
    core = _core_module()
    log_to_file = core.log_to_file
    data = _ttl_load()
    if email in data:
        del data[email]
        _ttl_save(data)
        log_to_file("INFO", f"TTL removed: {email}")


# ── блокировка / разблокировка ───────────────────────────────────────────────

def _blocked_load() -> dict:
    """Загружает базу заблокированных. Ключ — email, значение — запись."""
    try:
        if BLOCKED_FILE.exists():
            return json.loads(BLOCKED_FILE.read_text())
    except Exception:
        pass
    return {}


def _blocked_save(data: dict) -> None:
    BLOCKED_FILE.parent.mkdir(parents=True, exist_ok=True)
    BLOCKED_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    BLOCKED_FILE.chmod(0o600)


def _ttl_block_user(email: str, reason: str = "ttl_expired") -> bool:
    """
    Блокирует пользователя: убирает его UUID из конфига Xray и перезапускает
    сервис, но сохраняет запись в users.json с флагом blocked=true.
    Это позволяет разблокировать / продлить срок без повторного добавления.

    Возвращает True если пользователь найден и заблокирован.
    """
    core = _core_module()
    _users_load = core._users_load
    _users_save = core._users_save
    _users_apply_to_config = core._users_apply_to_config
    log_to_file = core.log_to_file
    users = _users_load()
    target = next(
        (u for u in users if u.get("email") == email or u.get("uuid") == email),
        None,
    )
    if not target:
        log_to_file("WARN", f"_ttl_block_user: {email} not found in users.json")
        return False

    # Помечаем заблокированным в users.json
    target["blocked"]    = True
    target["blocked_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    target["block_reason"] = reason
    _users_save(users)

    # Сохраняем в отдельную базу заблокированных (для быстрого просмотра)
    blocked = _blocked_load()
    blocked[email] = {
        "email":       email,
        "uuid":        target.get("uuid", ""),
        "name":        target.get("name", ""),
        "blocked_at":  target["blocked_at"],
        "reason":      reason,
    }
    _blocked_save(blocked)

    # Применяем в Xray только НЕзаблокированных пользователей
    active_users = [u for u in users if not u.get("blocked")]
    _users_apply_to_config(active_users)

    log_to_file("INFO", f"User blocked: {email} (reason={reason})")
    return True


def _ttl_unblock_user(email: str) -> bool:
    """
    Снимает блокировку: возвращает UUID пользователя в конфиг Xray.
    Возвращает True если разблокировка прошла успешно.
    """
    core = _core_module()
    _users_load = core._users_load
    _users_save = core._users_save
    _users_apply_to_config = core._users_apply_to_config
    log_to_file = core.log_to_file
    users = _users_load()
    target = next(
        (u for u in users if u.get("email") == email or u.get("uuid") == email),
        None,
    )
    if not target:
        log_to_file("WARN", f"_ttl_unblock_user: {email} not found in users.json")
        return False

    # Снимаем флаги блокировки
    target.pop("blocked",      None)
    target.pop("blocked_at",   None)
    target.pop("block_reason", None)
    _users_save(users)

    # Убираем из базы заблокированных
    blocked = _blocked_load()
    if email in blocked:
        del blocked[email]
        _blocked_save(blocked)

    # Применяем всех незаблокированных (включая только что разблокированного)
    active_users = [u for u in users if not u.get("blocked")]
    _users_apply_to_config(active_users)

    log_to_file("INFO", f"User unblocked: {email}")
    return True


def _ttl_is_blocked(email: str) -> bool:
    """True если пользователь с данным email в настоящее время заблокирован."""
    core = _core_module()
    _users_load = core._users_load
    users = _users_load()
    target = next(
        (u for u in users if u.get("email") == email or u.get("uuid") == email),
        None,
    )
    return bool(target and target.get("blocked"))


# ── проверка и блокировка истёкших ───────────────────────────────────────────

def _ttl_check_and_expire() -> int:
    """
    Проверяет все TTL-записи:
      • за 24 ч до истечения — отправляет TG-предупреждение
      • при истечении — БЛОКИРУЕТ пользователя (убирает из Xray, но не удаляет
        из users.json), помечает запись TTL как заблокированную.
        Это позволяет продлить срок и разблокировать без повторного добавления.

    Возвращает количество заблокированных пользователей.

    ДЕЛЕГИРУЕТ в vless_installer.modules.user_lifecycle.check_ttl_expired()
    для централизованной multi-protocol блокировки (VLESS + AWG + sing-box + ...).
    Сохраняет обратную совместимость: те же TG-нотификации, тот же TTL-state.
    """
    try:
        from vless_installer.modules.user_lifecycle import check_ttl_expired
        return check_ttl_expired()
    except Exception as e:
        # Fallback: оригинальная реализация (на случай если user_lifecycle недоступен)
        try:
            core = _core_module()
            core.log_to_file("WARN", f"_ttl_check_and_expire: user_lifecycle failed ({e}), using legacy path")
        except Exception:
            pass
        return _ttl_check_and_expire_legacy()


def _ttl_check_and_expire_legacy() -> int:
    """Legacy-реализация — fallback если user_lifecycle недоступен."""
    core = _core_module()
    log_to_file = core.log_to_file
    _tg_notify_event = core._tg_notify_event
    data    = _ttl_load()
    blocked = 0
    changed = False

    for email, rec in list(data.items()):
        iso = rec.get("expires_at", "")

        # ── алерт за 24 часа ──
        if not rec.get("notified_24h") and _ttl_expires_within_hours(iso, 24):
            left = _ttl_expires_str(iso)
            _tg_notify_event(
                "ttl_expiring",
                f"⏳ Пользователь <b>{email}</b> истекает через <b>{left}</b>",
            )
            log_to_file("INFO", f"TTL 24h warning sent: {email}")
            rec["notified_24h"] = True
            changed = True

        # ── истёк: блокируем (не удаляем) ──
        if _ttl_is_expired(iso) and not rec.get("blocked"):
            ok = _ttl_block_user(email, reason="ttl_expired")
            if ok:
                rec["blocked"] = True
                _tg_notify_event(
                    "ttl_expired",
                    f"🔒 Пользователь <b>{email}</b> заблокирован — срок действия истёк",
                )
                log_to_file("INFO", f"TTL expired: {email} blocked in Xray")
                blocked += 1
            changed = True

    if changed:
        _ttl_save(data)

    return blocked


# ── cron-агент ───────────────────────────────────────────────────────────────

def _ttl_install_cron() -> None:
    """
    Устанавливает cron-агент, вызывающий этот скрипт с флагом --ttl-check.
    Запускается каждые 30 минут от root.
    """
    core = _core_module()
    success = core.success
    textwrap = core.textwrap
    script = textwrap.dedent(f"""\
        #!/bin/bash
        # Xray TTL User Expiry Check (VLESS Installer)
        LOG="{TTL_LOG}"
        DATE=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$DATE] TTL check start" >> "$LOG"
        python3 {Path(__file__).resolve()} --ttl-check >> "$LOG" 2>&1
        echo "[$DATE] TTL check done" >> "$LOG"
    """)
    TTL_CRON_SCRIPT.write_text(script)
    TTL_CRON_SCRIPT.chmod(0o750)

    TTL_CRON_FILE.write_text(
        f"*/30 * * * * root {TTL_CRON_SCRIPT} >> {TTL_LOG} 2>&1\n"
    )
    TTL_CRON_FILE.chmod(0o644)
    success(f"Cron-агент TTL установлен (каждые 30 мин) → {TTL_CRON_SCRIPT}")
    success(f"Лог: {TTL_LOG}")


def _ttl_remove_cron() -> None:
    core = _core_module()
    success = core.success
    TTL_CRON_FILE.unlink(missing_ok=True)
    TTL_CRON_SCRIPT.unlink(missing_ok=True)
    success("Cron-агент TTL удалён")


def _ttl_cron_active() -> bool:
    return TTL_CRON_FILE.exists()


# ── меню управления ───────────────────────────────────────────────────────────

def do_manage_ttl_users() -> None:
    """
    Меню управления временными пользователями (TTL).
    Интегрируется в подменю пользователей.
    """
    core = _core_module()
    _users_load = core._users_load
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_item   = core._box_item
    _box_back   = core._box_back
    _box_bottom = core._box_bottom
    info    = core.info
    warn    = core.warn
    success = core.success
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    CYAN   = core.CYAN
    BLUE   = core.BLUE
    BOLD   = core.BOLD
    DIM    = core.DIM
    NC     = core.NC
    while True:
        os.system("clear")
        print()
        data  = _ttl_load()
        users = _users_load()

        _box_top("⏱  ВРЕМЕННЫЕ ПОЛЬЗОВАТЕЛИ (TTL)")
        _box_row()

        # ── статус cron ──
        cron_ok = _ttl_cron_active()
        cron_str = f"{GREEN}ВКЛЮЧЁН (каждые 30 мин){NC}" if cron_ok \
                   else f"{YELLOW}ОТКЛЮЧЁН{NC}"
        _box_row(f"  Авто-проверка: {cron_str}")
        _box_sep()

        # ── список TTL-пользователей ──
        if not data:
            _box_row(f"  {DIM}Временных пользователей нет{NC}")
        else:
            _box_row(
                f"  {'#':<4} {'Email':<26} {'Истекает':<18} {'Осталось':<10} {'Статус'}"
            )
            _box_row(
                f"  {'─'*4} {'─'*26} {'─'*18} {'─'*10} {'─'*14}"
            )
            for i, (email, rec) in enumerate(data.items(), 1):
                iso      = rec.get("expires_at", "")
                left     = _ttl_expires_str(iso)
                expired  = _ttl_is_expired(iso)
                warn24   = _ttl_expires_within_hours(iso, 24) and not expired
                is_blocked_now = _ttl_is_blocked(email)

                # Форматируем дату без секунд
                try:
                    exp_dt   = datetime.fromisoformat(iso)
                    exp_show = exp_dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    exp_show = iso[:16]

                if is_blocked_now:
                    status = f"{RED}ЗАБЛОКИРОВАН{NC}"
                    left_c = f"{RED}{left}{NC}"
                elif expired:
                    status = f"{RED}ИСТЁК{NC}"
                    left_c = f"{RED}{left}{NC}"
                elif warn24:
                    status = f"{YELLOW}скоро{NC}"
                    left_c = f"{YELLOW}{left}{NC}"
                else:
                    status = f"{GREEN}активен{NC}"
                    left_c = f"{GREEN}{left}{NC}"

                # Проверяем существует ли юзер в users.json
                in_users = any(
                    u.get("email") == email or u.get("uuid") == email
                    for u in users
                )
                if not in_users:
                    status = f"{DIM}нет в базе{NC}"

                _box_row(
                    f"  {i:<4} {email:<26} {exp_show:<18} {left_c:<10} {status}"
                )

        _box_sep()
        _box_row()
        _box_item("1", f"Назначить TTL пользователю")
        _box_item("2", f"Продлить / изменить срок  {DIM}(автоматически разблокирует){NC}")
        _box_item("3", f"Сделать пользователя постоянным (снять TTL)")
        _box_item("4", f"Проверить истёкших прямо сейчас")
        _box_item("5",
            f"{'Отключить' if cron_ok else 'Включить'} авто-проверку (cron 30 мин)"
        )
        _box_item("6", f"🔒 Заблокировать пользователя вручную")
        _box_item("7", f"🔓 Разблокировать пользователя")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        # ── 1: Назначить TTL ──────────────────────────────────────────────
        if ch == "1":
            print()
            if not users:
                warn("Нет пользователей. Сначала добавьте через менеджер пользователей.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            # Показываем только тех, у кого нет TTL
            no_ttl = [u for u in users if u.get("email") not in data]
            if not no_ttl:
                warn("У всех пользователей уже есть TTL.")
                info("Используйте [2] для продления или [3] чтобы снять ограничение.")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Выбор пользователя")
            for i, u in enumerate(no_ttl, 1):
                _box_row(
                    f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}"
                    f"  {u.get('name', u.get('email', '—')):<20}"
                    f"  {DIM}{u.get('email','')}{NC}"
                )
            _box_bottom()
            raw = input(f"  Номер: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(no_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            target = no_ttl[int(raw) - 1]
            email  = target.get("email", "")

            print()
            presets = {"1": 1, "2": 3, "3": 7, "4": 14, "5": 30, "6": 90}
            _box_top(f"Установить срок действия для: {email}")
            for k, v in presets.items():
                _box_item(k, f"{v} дней")
            _box_item("7", "Ввести своё количество дней")
            _box_bottom()
            raw2 = input(f"  Выбор: ").strip()

            if raw2 in presets:
                days = presets[raw2]
            elif raw2 == "7":
                d = input("  Количество дней (1–3650): ").strip()
                if not (d.isdigit() and 1 <= int(d) <= 3650):
                    warn("Неверное значение")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                days = int(d)
            else:
                warn("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _ttl_set(email, days)

            # Устанавливаем cron если не был
            if not cron_ok:
                info("Cron-агент ещё не установлен — устанавливаю автоматически...")
                _ttl_install_cron()

            exp = _ttl_expires_str(data.get(email, {}).get("expires_at", ""))
            # Перечитываем после _ttl_set
            data = _ttl_load()
            exp  = _ttl_expires_str(data.get(email, {}).get("expires_at", ""))
            success(
                f"TTL назначен: {email} → {days} дней (осталось: {exp})"
            )
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 2: Продлить / изменить ────────────────────────────────────────
        elif ch == "2":
            print()
            if not data:
                warn("Нет TTL-пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            emails = list(data.keys())
            _box_top("Выбор пользователя")
            for i, e in enumerate(emails, 1):
                rec  = data[e]
                left = _ttl_expires_str(rec.get("expires_at", ""))
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {e:<30}  осталось: {left}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(emails)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = emails[int(raw) - 1]

            print()
            presets = {"1": 1, "2": 3, "3": 7, "4": 14, "5": 30, "6": 90}
            _box_top(f"Новый срок от текущего момента: {email}")
            for k, v in presets.items():
                _box_item(k, f"{v} дней с сейчас")
            _box_item("7", "Ввести количество дней")
            _box_bottom()
            raw2 = input("  Выбор: ").strip()

            if raw2 in presets:
                days = presets[raw2]
            elif raw2 == "7":
                d = input("  Дней (1–3650): ").strip()
                if not (d.isdigit() and 1 <= int(d) <= 3650):
                    warn("Неверное значение")
                    input(f"{BLUE}Нажмите Enter...{NC}")
                    continue
                days = int(d)
            else:
                warn("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _ttl_set(email, days)
            # Если пользователь был заблокирован — снимаем блокировку
            if _ttl_is_blocked(email):
                _ttl_unblock_user(email)
                success(f"Блокировка снята, срок продлён: {email} → {days} дней")
            else:
                data = _ttl_load()
                exp  = _ttl_expires_str(data.get(email, {}).get("expires_at", ""))
                success(f"Срок обновлён: {email} → {days} дней (осталось: {exp})")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 3: Снять TTL ──────────────────────────────────────────────────
        elif ch == "3":
            print()
            if not data:
                warn("Нет TTL-пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            emails = list(data.keys())
            _box_top("Выбор пользователя")
            for i, e in enumerate(emails, 1):
                left = _ttl_expires_str(data[e].get("expires_at", ""))
                blk  = f"  {RED}[заблокирован]{NC}" if _ttl_is_blocked(e) else ""
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {e:<30}  осталось: {left}{blk}")
            _box_row()
            _box_bottom()

            raw = input("  Номер: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(emails)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = emails[int(raw) - 1]

            ans = input(
                f"  {YELLOW}Сделать '{email}' постоянным (TTL будет снят, блокировка снята)? [y/N]:{NC} "
            ).strip().lower()
            if ans == "y":
                # Снимаем блокировку если была
                if _ttl_is_blocked(email):
                    _ttl_unblock_user(email)
                _ttl_remove(email)
                success(f"TTL снят: {email} теперь постоянный пользователь")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 4: Проверить прямо сейчас ─────────────────────────────────────
        elif ch == "4":
            print()
            info("Проверка истёкших TTL-пользователей...")
            n = _ttl_check_and_expire()
            if n:
                success(f"Заблокировано {n} пользователей с истёкшим сроком")
            else:
                info("Истёкших пользователей не найдено")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 5: Cron вкл/выкл ─────────────────────────────────────────────
        elif ch == "5":
            print()
            if cron_ok:
                ans = input(
                    f"  {YELLOW}Отключить авто-проверку TTL? [y/N]:{NC} "
                ).strip().lower()
                if ans == "y":
                    _ttl_remove_cron()
            else:
                _ttl_install_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 6: Заблокировать вручную ──────────────────────────────────────
        elif ch == "6":
            print()
            # Показываем незаблокированных TTL-пользователей
            active_ttl = [
                e for e in data
                if not _ttl_is_blocked(e)
            ]
            if not active_ttl:
                warn("Нет активных TTL-пользователей для блокировки")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Заблокировать пользователя")
            for i, e in enumerate(active_ttl, 1):
                left = _ttl_expires_str(data[e].get("expires_at", ""))
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {e:<30}  осталось: {left}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(active_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = active_ttl[int(raw) - 1]

            ans = input(
                f"  {YELLOW}Заблокировать '{email}'? Xray откажет ему в соединении. [y/N]:{NC} "
            ).strip().lower()
            if ans == "y":
                ok = _ttl_block_user(email, reason="manual")
                if ok:
                    success(f"Пользователь {email} заблокирован. Продлите TTL [2] чтобы разблокировать.")
                else:
                    warn(f"Не удалось заблокировать: {email} не найден в базе пользователей")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── 7: Разблокировать ─────────────────────────────────────────────
        elif ch == "7":
            print()
            blocked_ttl = [
                e for e in data
                if _ttl_is_blocked(e)
            ]
            if not blocked_ttl:
                info("Нет заблокированных пользователей")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _box_top("Разблокировать пользователя")
            for i, e in enumerate(blocked_ttl, 1):
                rec  = data[e]
                iso  = rec.get("expires_at", "")
                exp_expired = _ttl_is_expired(iso)
                left = _ttl_expires_str(iso)
                left_c = f"{RED}{left}{NC}" if exp_expired else f"{YELLOW}{left}{NC}"
                note = f"  {RED}срок истёк — рекомендуется продлить [2]{NC}" if exp_expired else ""
                _box_row(f"  {DIM}[{NC}{BOLD}{i}{NC}{DIM}]{NC}  {e:<30}  {left_c}{note}")
            _box_row()
            _box_bottom()

            raw = input("  Номер пользователя: ").strip()
            if not (raw.isdigit() and 1 <= int(raw) <= len(blocked_ttl)):
                warn("Неверный номер")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            email = blocked_ttl[int(raw) - 1]

            # Предупреждаем если срок уже истёк
            rec = data.get(email, {})
            if _ttl_is_expired(rec.get("expires_at", "")):
                warn(f"Срок действия {email} уже истёк. После разблокировки он снова")
                warn("заблокируется при следующей проверке cron (каждые 30 мин).")
                warn("Рекомендуется продлить срок через [2] или снять TTL через [3].")
                ans = input(
                    f"  {YELLOW}Всё равно разблокировать временно? [y/N]:{NC} "
                ).strip().lower()
            else:
                ans = input(
                    f"  {YELLOW}Разблокировать '{email}'? [y/N]:{NC} "
                ).strip().lower()

            if ans == "y":
                # Сбрасываем флаг blocked в TTL-записи
                if email in data:
                    data[email].pop("blocked", None)
                    _ttl_save(data)
                ok = _ttl_unblock_user(email)
                if ok:
                    success(f"Пользователь {email} разблокирован")
                else:
                    warn(f"Не удалось разблокировать: {email} не найден в базе")
            else:
                info("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)
