"""
vless_installer/modules/turntunnel_links.py
───────────────────────────────────────────────────────────────────────────────
Менеджер пула ссылок VK Turn Tunnel.

Зачем:
  vk-turn-proxy получает TURN-credentials из ссылки на ВК-звонок.
  Одну ссылку можно использовать для неограниченного числа клиентов —
  но тогда при компрометации ссылки пострадают все.
  Этот модуль позволяет:
    • Хранить пул ссылок (каждая привязана к конкретному пользователю)
    • Выдавать каждому пользователю уникальную ссылку
    • Контролировать какие ссылки живые, какие отозваны
    • Генерировать инструкцию для WireTurn под конкретного пользователя

Почему нет автосоздания ссылок:
  Создание ВК-звонка требует авторизованный аккаунт ВКонтакте +
  прохождение капчи. Это нестабильный процесс завязанный на внутреннее
  API ВК которое меняется без предупреждения. Ручное добавление ссылок —
  надёжнее и предсказуемее для продакшена.

Как получить ссылку:
  1. Зайти на vk.com → Звонки → Новый звонок
  2. Скопировать ссылку приглашения (vk.com/call/join/...)
  3. Добавить в пул через этот модуль
  Ссылка действует вечно пока не нажать «Завершить звонок для всех».

Хранение:
  /var/lib/xray-installer/turntunnel_links.json
  Формат: список записей {id, link, label, assigned_to, created_at, active}
  Не трогает state.json, turntunnel.json и конфиги xray.

Точка входа из turntunnel.py или _core.py:
    from vless_installer.modules.turntunnel_links import do_links_menu
    do_links_menu()

Интеграция в turntunnel.py:
  В do_turntunnel_menu() добавить пункт меню:
    _box_item("L", "🔗  Менеджер ссылок ВК-звонков")
  И обработчик:
    elif ch == "l" and st["installed"]:
        try:
            from vless_installer.modules.turntunnel_links import do_links_menu
            do_links_menu()
        except ImportError:
            _warn("Модуль turntunnel_links не найден.")
            _pause()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_LINKS_FILE       = Path("/var/lib/xray-installer/turntunnel_links.json")
_TURNTUNNEL_FILE  = Path("/var/lib/xray-installer/turntunnel.json")

# Паттерн валидной ссылки ВК-звонка
_VK_LINK_RE = re.compile(
    r'^https?://(vk\.com|m\.vk\.com)/call/join/[A-Za-z0-9_\-]+/?$'
)

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width = 0
    chars = list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text)
        cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i
                break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    """Пользователь нажал Ctrl+C — возврат в вызывающее меню."""

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c: raise _Cancelled()
        return default

def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def _short_id() -> str:
    """Короткий читаемый ID записи."""
    return str(uuid.uuid4())[:8]

# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ ССЫЛОК
# ══════════════════════════════════════════════════════════════════════════════
def _load_links() -> list:
    """Загружает пул ссылок. Возвращает [] если файл не существует."""
    if not _LINKS_FILE.exists():
        return []
    try:
        data = json.loads(_LINKS_FILE.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_links(links: list) -> None:
    """Сохраняет пул ссылок."""
    try:
        _LINKS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LINKS_FILE.write_text(json.dumps(links, indent=2, ensure_ascii=False))
        _LINKS_FILE.chmod(0o600)
    except Exception as e:
        print(f"  {RED}✗{NC}  Не удалось сохранить ссылки: {e}")

def _find_link(links: list, link_id: str) -> Optional[dict]:
    """Находит запись по id."""
    return next((e for e in links if e.get("id") == link_id), None)

def _validate_vk_link(link: str) -> bool:
    """Проверяет что ссылка похожа на приглашение в ВК-звонок."""
    return bool(_VK_LINK_RE.match(link.strip()))

# ══════════════════════════════════════════════════════════════════════════════
#  TURNTUNNEL STATE — только чтение
# ══════════════════════════════════════════════════════════════════════════════
def _load_turntunnel_state() -> dict:
    if not _TURNTUNNEL_FILE.exists():
        return {}
    try:
        return json.loads(_TURNTUNNEL_FILE.read_text())
    except Exception:
        return {}

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    return "ВАШ_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТИСТИКА ПУЛА
# ══════════════════════════════════════════════════════════════════════════════
def _pool_stats(links: list) -> dict:
    total    = len(links)
    active   = sum(1 for e in links if e.get("active", True))
    assigned = sum(1 for e in links if e.get("assigned_to"))
    free     = sum(1 for e in links if e.get("active", True) and not e.get("assigned_to"))
    return {"total": total, "active": active, "assigned": assigned, "free": free}

# ══════════════════════════════════════════════════════════════════════════════
#  ДОБАВЛЕНИЕ ССЫЛКИ
# ══════════════════════════════════════════════════════════════════════════════
def _add_link() -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ССЫЛКУ ВК-ЗВОНКА")
    _box_row()
    _box_info("Создайте звонок ВКонтакте:")
    _box_info("vk.com → Звонки → Новый звонок → Скопировать ссылку")
    _box_row()
    _box_info("Формат: https://vk.com/call/join/XXXXXXXXX")
    _box_row()
    _box_warn("Ссылка действует вечно пока не завершить звонок.")
    _box_bot(); print()

    try:
        raw_link = _ask(
            f"  {CYAN}Ссылка (Enter = отмена): {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if not raw_link:
        return

    if not _validate_vk_link(raw_link):
        print()
        print(f"  {RED}✗{NC}  Ссылка не похожа на vk.com/call/join/...")
        print(f"  {DIM}Проверьте формат и попробуйте ещё раз.{NC}")
        _pause(); return

    # Метка — для удобства администратора
    try:
        label = _ask(
            f"  {CYAN}Метка (имя пользователя или описание, Enter = без метки): {NC}",
            default="",
            c=True,
        ).strip()
    except _Cancelled:
        return

    links = _load_links()

    # Проверка на дубликат
    if any(e.get("link") == raw_link for e in links):
        print(f"\n  {YELLOW}⚠{NC}  Эта ссылка уже есть в пуле.")
        _pause(); return

    entry = {
        "id":          _short_id(),
        "link":        raw_link,
        "label":       label or "",
        "assigned_to": "",
        "created_at":  _now_str(),
        "active":      True,
    }
    links.append(entry)
    _save_links(links)

    print()
    print(f"  {GREEN}✓{NC}  Ссылка добавлена. ID: {CYAN}{entry['id']}{NC}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СПИСОК ССЫЛОК
# ══════════════════════════════════════════════════════════════════════════════
def _list_links() -> None:
    os.system("clear")
    links = _load_links()
    stats = _pool_stats(links)

    _box_top("📋  ПУЛ ССЫЛОК ВК-ЗВОНКОВ")
    _box_row()
    _box_kv("Всего:",      str(stats["total"]))
    _box_kv("Активных:",   f"{GREEN}{stats['active']}{NC}")
    _box_kv("Назначено:",  f"{YELLOW}{stats['assigned']}{NC}")
    _box_kv("Свободных:",  f"{GREEN}{stats['free']}{NC}")
    _box_row()

    if not links:
        _box_warn("Пул пуст. Добавьте ссылки через пункт [1].")
        _box_bot(); _pause(); return

    _box_sep()
    # Заголовок таблицы
    _box_row(
        f"  {BOLD}{CYAN}{'ID':<8}{'Метка':<16}{'Назначена':<16}{'Создана':<14}{'Статус'}{NC}"
    )
    _box_sep()

    for e in links:
        eid      = e.get("id", "?")[:8]
        label    = (e.get("label") or "—")[:14]
        assigned = (e.get("assigned_to") or "свободна")[:14]
        created  = (e.get("created_at") or "")[:13]
        active   = e.get("active", True)
        status   = f"{GREEN}✓ активна{NC}" if active else f"{RED}✗ отозвана{NC}"
        asgn_col = YELLOW if e.get("assigned_to") else DIM
        _box_row(
            f"  {CYAN}{eid:<8}{NC}"
            f"{label:<16}"
            f"{asgn_col}{assigned:<16}{NC}"
            f"{DIM}{created:<14}{NC}"
            f"{status}"
        )

    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  НАЗНАЧЕНИЕ ССЫЛКИ ПОЛЬЗОВАТЕЛЮ
# ══════════════════════════════════════════════════════════════════════════════
def _assign_link() -> None:
    os.system("clear")
    links = _load_links()
    free  = [e for e in links if e.get("active", True) and not e.get("assigned_to")]

    _box_top("📱  НАЗНАЧИТЬ ССЫЛКУ ПОЛЬЗОВАТЕЛЮ")
    _box_row()

    if not free:
        _box_warn("Нет свободных активных ссылок.")
        _box_info("Добавьте новые ссылки через пункт [1].")
        _box_bot(); _pause(); return

    _box_info(f"Свободных ссылок: {GREEN}{len(free)}{NC}")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{CYAN}{'№':<4}{'ID':<10}{'Метка':<18}{'Создана'}{NC}")
    _box_sep()

    for i, e in enumerate(free, 1):
        eid     = e.get("id", "?")[:8]
        label   = (e.get("label") or "—")[:16]
        created = (e.get("created_at") or "")[:13]
        _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{eid:<10}{NC}{label:<18}{DIM}{created}{NC}")

    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        num_raw = _ask(
            f"  {CYAN}Номер ссылки [1-{len(free)}]: {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if num_raw.lower() == "q" or not num_raw:
        return

    try:
        idx = int(num_raw) - 1
        if not (0 <= idx < len(free)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    chosen = free[idx]

    try:
        username = _ask(
            f"  {CYAN}Имя пользователя (для кого ссылка): {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if not username:
        print(f"  {YELLOW}⚠{NC}  Имя не указано — назначение отменено."); _pause(); return

    # Обновляем запись
    for e in links:
        if e.get("id") == chosen["id"]:
            e["assigned_to"] = username
            e["label"]       = e["label"] or username
            break

    _save_links(links)

    # Показываем инструкцию для этого пользователя
    _show_user_instruction(chosen["link"], username)

# ══════════════════════════════════════════════════════════════════════════════
#  ИНСТРУКЦИЯ ДЛЯ ПОЛЬЗОВАТЕЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _show_user_instruction(vk_link: str, username: str) -> None:
    """Выводит готовую инструкцию для конкретного пользователя."""
    tt_state    = _load_turntunnel_state()
    listen_port = tt_state.get("listen_port", 56000)
    vless_uuid  = tt_state.get("vless_uuid", "")
    server_ip   = _get_server_ip()

    vless_link = (
        f"vless://{vless_uuid}@127.0.0.1:9000"
        f"?encryption=none&security=none&type=tcp"
        f"#{username}"
    ) if vless_uuid else "(установите VK Turn Tunnel сначала)"

    os.system("clear")
    _box_top(f"📱  ИНСТРУКЦИЯ ДЛЯ: {username}")
    _box_row()
    _box_info("Установите WireTurn: github.com/spkprsnts/WireTurn")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Вкладка Клиент:{NC}")
    _box_row()
    _box_kv("  Сервер:",         f"{YELLOW}{server_ip}:{listen_port}{NC}")
    _box_kv("  Ссылка звонка:",  f"{YELLOW}{vk_link}{NC}")
    _box_kv("  Локальный адрес:", f"{DIM}127.0.0.1:9000{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Вкладка Xray — VLESS-ссылка:{NC}")
    _box_row()
    _box_row(f"  {YELLOW}{vless_link}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Порядок запуска:{NC}")
    _box_row()
    _box_info("1. Вставьте ссылку ВК-звонка в WireTurn")
    _box_info("2. Нажмите кнопку запуска → дождитесь DTLS connected")
    _box_info("3. Включите Xray → включите VPN Mode")
    _box_row()
    _box_warn("Не завершайте ВК-звонок — иначе ссылка перестанет работать.")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОКАЗ ИНСТРУКЦИИ ПО ID
# ══════════════════════════════════════════════════════════════════════════════
def _show_instruction_by_id() -> None:
    os.system("clear")
    links = _load_links()

    if not links:
        _box_top("📱  ИНСТРУКЦИЯ ДЛЯ ПОЛЬЗОВАТЕЛЯ")
        _box_row()
        _box_warn("Пул пуст."); _box_bot(); _pause(); return

    _box_top("📱  ИНСТРУКЦИЯ ДЛЯ ПОЛЬЗОВАТЕЛЯ")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{CYAN}{'№':<4}{'ID':<10}{'Назначена':<18}{'Метка'}{NC}")
    _box_sep()

    for i, e in enumerate(links, 1):
        eid      = e.get("id", "?")[:8]
        assigned = (e.get("assigned_to") or "—")[:16]
        label    = (e.get("label") or "—")[:16]
        active   = e.get("active", True)
        col      = NC if active else DIM
        _box_row(f"  {col}{DIM}{i:<4}{NC}{CYAN}{eid:<10}{NC}{col}{assigned:<18}{label}{NC}")

    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        num_raw = _ask(
            f"  {CYAN}Номер записи [1-{len(links)}]: {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if num_raw.lower() == "q" or not num_raw:
        return

    try:
        idx = int(num_raw) - 1
        if not (0 <= idx < len(links)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    e = links[idx]
    _show_user_instruction(
        e.get("link", ""),
        e.get("assigned_to") or e.get("label") or f"id:{e.get('id','?')}",
    )

# ══════════════════════════════════════════════════════════════════════════════
#  ОТЗЫВ / АКТИВАЦИЯ ССЫЛКИ
# ══════════════════════════════════════════════════════════════════════════════
def _toggle_link() -> None:
    """Отзывает активную ссылку или активирует отозванную."""
    os.system("clear")
    links = _load_links()

    if not links:
        _box_top("🔁  ОТОЗВАТЬ / АКТИВИРОВАТЬ")
        _box_row()
        _box_warn("Пул пуст."); _box_bot(); _pause(); return

    _box_top("🔁  ОТОЗВАТЬ / АКТИВИРОВАТЬ ССЫЛКУ")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{CYAN}{'№':<4}{'ID':<10}{'Метка':<16}{'Назначена':<16}{'Статус'}{NC}")
    _box_sep()

    for i, e in enumerate(links, 1):
        eid      = e.get("id", "?")[:8]
        label    = (e.get("label") or "—")[:14]
        assigned = (e.get("assigned_to") or "—")[:14]
        active   = e.get("active", True)
        status   = f"{GREEN}активна{NC}" if active else f"{RED}отозвана{NC}"
        _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{eid:<10}{NC}{label:<16}{assigned:<16}{status}")

    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        num_raw = _ask(
            f"  {CYAN}Номер [1-{len(links)}]: {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if num_raw.lower() == "q" or not num_raw:
        return

    try:
        idx = int(num_raw) - 1
        if not (0 <= idx < len(links)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    e      = links[idx]
    was    = e.get("active", True)
    action = "отозвана" if was else "активирована"

    for entry in links:
        if entry.get("id") == e["id"]:
            entry["active"] = not was
            break

    _save_links(links)
    col = RED if was else GREEN
    print(f"\n  {col}✓{NC}  Ссылка {e.get('id','')} {action}.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ ССЫЛКИ
# ══════════════════════════════════════════════════════════════════════════════
def _delete_link() -> None:
    os.system("clear")
    links = _load_links()

    if not links:
        _box_top("🗑️  УДАЛИТЬ ССЫЛКУ")
        _box_row()
        _box_warn("Пул пуст."); _box_bot(); _pause(); return

    _box_top("🗑️  УДАЛИТЬ ССЫЛКУ ИЗ ПУЛА")
    _box_row()
    _box_warn("Удаление необратимо. Ссылка исчезнет из пула.")
    _box_warn("Сам ВК-звонок не затрагивается.")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{CYAN}{'№':<4}{'ID':<10}{'Метка':<18}{'Назначена'}{NC}")
    _box_sep()

    for i, e in enumerate(links, 1):
        eid      = e.get("id", "?")[:8]
        label    = (e.get("label") or "—")[:16]
        assigned = (e.get("assigned_to") or "—")[:16]
        _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{eid:<10}{NC}{label:<18}{assigned}")

    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        num_raw = _ask(
            f"  {CYAN}Номер для удаления [1-{len(links)}]: {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if num_raw.lower() == "q" or not num_raw:
        return

    try:
        idx = int(num_raw) - 1
        if not (0 <= idx < len(links)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    e = links[idx]
    label_str = e.get("label") or e.get("id", "?")

    try:
        confirm = _ask(
            f"  {YELLOW}Удалить «{label_str}»? [y/N]: {NC}",
            default="n",
            c=True,
        ).strip().lower()
    except _Cancelled:
        return

    if confirm != "y":
        print(f"  {DIM}Отменено.{NC}"); _pause(); return

    links.pop(idx)
    _save_links(links)
    print(f"\n  {GREEN}✓{NC}  Ссылка удалена из пула.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СНЯТИЕ НАЗНАЧЕНИЯ
# ══════════════════════════════════════════════════════════════════════════════
def _unassign_link() -> None:
    """Снимает назначение пользователя — ссылка снова становится свободной."""
    os.system("clear")
    links    = _load_links()
    assigned = [e for e in links if e.get("assigned_to")]

    if not assigned:
        _box_top("🔓  СНЯТЬ НАЗНАЧЕНИЕ")
        _box_row()
        _box_info("Нет назначенных ссылок."); _box_bot(); _pause(); return

    _box_top("🔓  СНЯТЬ НАЗНАЧЕНИЕ ПОЛЬЗОВАТЕЛЯ")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{CYAN}{'№':<4}{'ID':<10}{'Назначена':<18}{'Метка'}{NC}")
    _box_sep()

    for i, e in enumerate(assigned, 1):
        eid      = e.get("id", "?")[:8]
        assigned_to = (e.get("assigned_to") or "")[:16]
        label    = (e.get("label") or "—")[:16]
        _box_row(f"  {DIM}{i:<4}{NC}{CYAN}{eid:<10}{NC}{YELLOW}{assigned_to:<18}{NC}{label}")

    _box_sep()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        num_raw = _ask(
            f"  {CYAN}Номер [1-{len(assigned)}]: {NC}",
            c=True,
        ).strip()
    except _Cancelled:
        return

    if num_raw.lower() == "q" or not num_raw:
        return

    try:
        idx = int(num_raw) - 1
        if not (0 <= idx < len(assigned)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    e = assigned[idx]
    old_user = e.get("assigned_to", "")

    for entry in links:
        if entry.get("id") == e["id"]:
            entry["assigned_to"] = ""
            break

    _save_links(links)
    print(f"\n  {GREEN}✓{NC}  Назначение снято (пользователь: {old_user}). Ссылка свободна.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_links_menu() -> None:
    """
    Точка входа из turntunnel.py или _core.py.
    Ctrl+C → возврат в вызывающее меню.
    """
    while True:
        os.system("clear")
        links = _load_links()
        stats = _pool_stats(links)
        tt    = _load_turntunnel_state()

        _box_top("🔗  МЕНЕДЖЕР ССЫЛОК  •  VK TURN TUNNEL")
        _box_row()

        # Статус turntunnel
        if tt.get("installed"):
            _box_kv("Turn Tunnel:", f"{GREEN}✓ установлен{NC}")
        else:
            _box_kv("Turn Tunnel:", f"{YELLOW}⚠ не установлен{NC}")
            _box_warn("Установите VK Turn Tunnel (пункт 1 главного меню)")
            _box_warn("перед настройкой ссылок.")

        _box_row()
        _box_kv("Ссылок в пуле:",  str(stats["total"]))
        _box_kv("Свободных:",
                f"{GREEN}{stats['free']}{NC}" if stats["free"] else f"{YELLOW}0{NC}")
        _box_kv("Назначено:",      f"{YELLOW}{stats['assigned']}{NC}")
        _box_row(); _box_sep()

        _box_item("1", "➕  Добавить ссылку ВК-звонка")
        _box_item("2", "📋  Список всех ссылок")
        _box_item("3", f"📱  Назначить ссылку пользователю  "
                       f"{DIM}(свободных: {stats['free']}){NC}")
        _box_item("4", "📄  Показать инструкцию для пользователя")
        _box_item("5", "🔓  Снять назначение")
        _box_item("6", "🔁  Отозвать / активировать ссылку")
        _box_item("7", f"{RED}🗑️   Удалить ссылку из пула{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                _add_link()
            except _Cancelled:
                pass

        elif ch == "2":
            _list_links()

        elif ch == "3":
            try:
                _assign_link()
            except _Cancelled:
                pass

        elif ch == "4":
            try:
                _show_instruction_by_id()
            except _Cancelled:
                pass

        elif ch == "5":
            try:
                _unassign_link()
            except _Cancelled:
                pass

        elif ch == "6":
            try:
                _toggle_link()
            except _Cancelled:
                pass

        elif ch == "7":
            try:
                _delete_link()
            except _Cancelled:
                pass

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (для отладки)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        do_links_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
