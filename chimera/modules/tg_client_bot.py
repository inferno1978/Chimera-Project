"""
chimera/modules/tg_client_bot.py
───────────────────────────────────────────────────────────────────────────────
КЛИЕНТСКИЙ Telegram-бот для self-service доступа пользователей.

Это ОТДЕЛЬНЫЙ бот от admin-бота (chimera/modules/tg_bot.py):
  • отдельный токен (другой бот в @BotFather)
  • отдельный systemd-сервис xray-tg-client
  • отдельный конфиг /var/lib/xray-installer/tg_client_bot.json
  • отдельный файл привязок /var/lib/xray-installer/tg_client_bot_map.json

Принципы:
  • READ-ONLY: бот не умеет добавлять/удалять/банить пользователей.
  • Привязка: TG user_id -> UUID пользователя через deep-link токен
    (админ выдаёт токен при создании учётки, пользователь пишет
    /start <token> один раз — связка сохраняется навсегда).
  • Секреты: приватные ключи сервера, PSK, серверные пароли НИКОГДА не
    попадают в текст ответов. Только то, что нужно клиенту для подключения.
  • Rate-limit: 1 команда / 2 сек на пользователя (защита от спама QR).

Команды бота:
  /start [token]  — приветствие + привязка аккаунта (один раз)
  /config         — список ссылок для всех активных протоколов + inline-кнопки
  /qr <protocol>  — QR-код для конкретного протокола
  /status         — трафик + прогресс-бар + TTL + лимит
  /help           — справка

Архитектура: внешний модуль + генерируемый inner-скрипт (как в tg_bot.py).
Inner-скрипт самодостаточен (stdlib only), не требует chimera.* на
PYTHONPATH. Логика генерации ссылок/QR — общая, через linkqr_lib.py, вызывается
из inner-скрипта через subprocess-вызов helper'а.

Публичное API:
    do_tg_client_bot_menu()    — TUI-меню управления (пункт "TC" в main_menu)
    install_client_bot_service() — установка systemd-сервиса
    stop_client_bot_service()    — остановка и удаление сервиса
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Константы ─────────────────────────────────────────────────────────────────
_NOTIF_FILE       = Path("/var/lib/xray-installer/telegram.json")
_CLIENT_BOT_FILE  = Path("/var/lib/xray-installer/tg_client_bot.json")
_CLIENT_MAP_FILE  = Path("/var/lib/xray-installer/tg_client_bot_map.json")
_STATE_FILE       = Path("/var/lib/xray-installer/state.json")
_USERS_FILE       = Path("/etc/xray/users.json")
_TTL_FILE         = Path("/var/lib/xray-installer/ttl_users.json")
_LIMITS_FILE      = Path("/var/lib/xray-installer/traffic_limits.json")
_BLOCKED_FILE     = Path("/var/lib/xray-installer/blocked_users.json")
_LOG_FILE         = Path("/var/log/chimera.log")
_CLIENT_BOT_SVC   = Path("/etc/systemd/system/xray-tg-client.service")
_CLIENT_BOT_SCRIPT = Path("/usr/local/bin/xray-tg-client-bot.py")
_QR_TMP_DIR       = Path("/tmp/tg-client-bot-qr")

# ── box_renderer ─────────────────────────────────────────────────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)


# ── Логирование ────────────────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [TG-CLIENT] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str):  print(f"{CYAN}[INFO]{NC}  {msg}");   _log("INFO",    msg)
def _ok(msg: str):    print(f"{GREEN}[OK]{NC}    {msg}");  _log("SUCCESS", msg)
def _warn(msg: str):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _err(msg: str):   print(f"{RED}[ERR]{NC}   {msg}");    _log("ERROR",   msg)

def _run(cmd: list, capture: bool = False, quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


# =============================================================================
#  КОНФИГ / КАРТА ПРИВЯЗОК
# =============================================================================
def client_bot_load() -> dict:
    """Читает конфиг клиентского бота."""
    try:
        if _CLIENT_BOT_FILE.exists():
            return json.loads(_CLIENT_BOT_FILE.read_text())
    except Exception:
        pass
    return {}


def client_bot_save(cfg: dict) -> None:
    """Сохраняет конфиг клиентского бота (chmod 0o600 — внутри токен)."""
    _CLIENT_BOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CLIENT_BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _CLIENT_BOT_FILE.chmod(0o600)


def client_map_load() -> dict:
    """
    Читает карту привязок TG user_id -> {uuid, email, bound_at}.

    Структура:
        {
          "111111111": {
            "uuid": "abc-def-...",
            "email": "alice@xray",
            "bound_at": "2025-09-01T12:00:00+00:00"
          },
          ...
        }
    """
    try:
        if _CLIENT_MAP_FILE.exists():
            return json.loads(_CLIENT_MAP_FILE.read_text())
    except Exception:
        pass
    return {}


def client_map_save(data: dict) -> None:
    """Сохраняет карту привязок (chmod 0o600)."""
    _CLIENT_MAP_FILE.parent.mkdir(parents=True, exist_ok=True)
    _CLIENT_MAP_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _CLIENT_MAP_FILE.chmod(0o600)


def client_bot_running() -> bool:
    """Проверяет, запущен ли systemd-сервис xray-tg-client."""
    r = _run(["systemctl", "is-active", "--quiet", "xray-tg-client"], quiet=False)
    return r.returncode == 0


# =============================================================================
#  HELPERS: поиск пользователя, проверка блокировки / TTL / лимита
# =============================================================================
def _read_users() -> list:
    try:
        if _USERS_FILE.exists():
            data = json.loads(_USERS_FILE.read_text())
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _find_user_by_uuid(uuid_str: str) -> Optional[dict]:
    for u in _read_users():
        if u.get("uuid", "") == uuid_str:
            return u
    return None


def _find_user_by_email(email: str) -> Optional[dict]:
    for u in _read_users():
        if u.get("email", "") == email:
            return u
    return None


def _read_json(path: Path) -> dict:
    try:
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _ttl_is_expired(iso: str) -> bool:
    """True если ISO-строка TTL уже в прошлом. Пустая/невалидная → False."""
    if not iso:
        return False
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp
    except Exception:
        return False


def _ttl_expires_str(iso: str) -> str:
    """Возвращает '3д 14ч' / 'ИСТЁК' / '?' для ISO-строки TTL."""
    if not iso:
        return "бессрочно"
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - datetime.now(timezone.utc)
        total = int(delta.total_seconds())
        if total <= 0:
            return "ИСТЁК"
        days  = total // 86400
        hours = (total % 86400) // 3600
        mins  = (total % 3600) // 60
        if days > 0:
            return f"{days}д {hours}ч"
        if hours > 0:
            return f"{hours}ч {mins}м"
        return f"{mins}м"
    except Exception:
        return "?"


def _is_user_blocked(email: str) -> tuple[bool, str]:
    """
    Проверяет, заблокирован ли пользователь.
    Возвращает (blocked: bool, reason: str).
    reason — одна из: 'disabled', 'blocked', 'ttl_expired', 'traffic_limit', ''
    """
    user = _find_user_by_email(email)
    if not user:
        return True, "no_user"
    if user.get("disabled"):
        return True, "disabled"
    if user.get("blocked"):
        return True, "blocked"
    # TTL check
    ttl = _read_json(_TTL_FILE).get(email, {})
    exp = ttl.get("expires_at", "")
    if exp and _ttl_is_expired(exp):
        return True, "ttl_expired"
    # Traffic limit check
    limits = _read_json(_LIMITS_FILE).get(email, {})
    if limits.get("disabled"):
        return True, "traffic_limit"
    # Blocked_users.json
    blocked_db = _read_json(_BLOCKED_FILE)
    if email in blocked_db:
        return True, blocked_db[email].get("reason", "blocked")
    return False, ""


def _get_user_traffic_info(email: str) -> dict:
    """
    Возвращает {used_bytes, limit_bytes, limit_gb, pct, available} для пользователя.
    used_bytes — текущее потребление (из кеша traffic_limits.json, либо 0).
    limit_bytes — лимит в байтах (0 = безлимит).
    pct — процент использования (0-100), None если безлимит.
    """
    limits = _read_json(_LIMITS_FILE).get(email, {})
    limit_gb = limits.get("limit_gb", 0)
    used_bytes = limits.get("used_bytes", 0)
    limit_bytes = limit_gb * 1024**3 if limit_gb else 0
    pct = None
    if limit_bytes > 0:
        pct = min(100, int(used_bytes * 100 / limit_bytes))
    return {
        "used_bytes": used_bytes,
        "limit_bytes": limit_bytes,
        "limit_gb": limit_gb,
        "pct": pct,
    }


def _format_bytes(n: int) -> str:
    """Человекочитаемый размер: 1234567 -> '1.17 MiB'."""
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n/1024:.1f} KiB"
    if n < 1024**3:
        return f"{n/1024**2:.2f} MiB"
    return f"{n/1024**3:.2f} GiB"


def _progress_bar(pct: int, width: int = 10) -> str:
    """Текстовый прогресс-бар: [████████--] 80%."""
    pct = max(0, min(100, pct))
    filled = width * pct // 100
    return f"[{'█' * filled}{'-' * (width - filled)}] {pct}%"


# =============================================================================
#  TOKEN / DEEP-LINK: выдача админом, валидация при /start
# =============================================================================
def issue_invite_token(email: str, admin_id: str = "") -> str:
    """
    Создаёт одноразовый invite-токен для пользователя с указанным email.
    Токен сохраняется в tg_client_bot.json -> invite_tokens и удаляется
    после первого использования.
    """
    cfg = client_bot_load()
    invites = cfg.get("invite_tokens", {})
    tok = secrets.token_urlsafe(12)
    invites[tok] = {
        "email": email,
        "created": datetime.now(timezone.utc).isoformat(),
        "by": admin_id or "admin_menu",
        "used": False,
    }
    cfg["invite_tokens"] = invites
    client_bot_save(cfg)
    return tok


def _consume_invite_token(token: str) -> Optional[str]:
    """
    Возвращает email пользователя, к которому привязан токен, и помечает
    токен использованным. Возвращает None если токен не найден или уже использован.
    """
    cfg = client_bot_load()
    invites = cfg.get("invite_tokens", {})
    info = invites.get(token)
    if not info:
        return None
    if info.get("used"):
        return None
    email = info.get("email", "")
    if not email:
        return None
    info["used"] = True
    info["used_at"] = datetime.now(timezone.utc).isoformat()
    invites[token] = info
    cfg["invite_tokens"] = invites
    client_bot_save(cfg)
    return email


def bind_telegram_user(tg_user_id: int, email: str) -> Optional[dict]:
    """
    Привязывает Telegram user_id к пользователю по email.
    Возвращает dict пользователя или None если email не найден в users.json.
    Запрещает привязку нескольких TG-аккаунтов к одному email (one-to-one).
    Разрешает перепривязку TG-аккаунта на новый email (старая связка удаляется).
    """
    user = _find_user_by_email(email)
    if not user:
        return None
    data = client_map_load()
    tg_id_str = str(tg_user_id)
    # Если этот email уже привязан к другому TG-аккаунту — запрещаем
    for k, v in data.items():
        if v.get("email") == email and k != tg_id_str:
            return None  # уже занят другим TG-аккаунтом
    # Привязываем (перезаписываем старую связку этого TG-аккаунта)
    data[tg_id_str] = {
        "uuid": user.get("uuid", ""),
        "email": email,
        "bound_at": datetime.now(timezone.utc).isoformat(),
    }
    client_map_save(data)
    return user


def lookup_user_by_tg_id(tg_user_id: int) -> Optional[dict]:
    """
    Возвращает dict пользователя VLESS, привязанного к данному TG user_id,
    или None если привязки нет.
    """
    data = client_map_load()
    info = data.get(str(tg_user_id))
    if not info:
        return None
    uuid = info.get("uuid", "")
    if not uuid:
        return None
    return _find_user_by_uuid(uuid)


# =============================================================================
#  ФОРМИРОВАНИЕ ОТВЕТОВ КОМАНД (использует linkqr_lib)
# =============================================================================
def _safe_html(s: str) -> str:
    """Экранирует HTML-спецсимволы для Telegram parse_mode=HTML."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def format_status_message(tg_user_id: int) -> str:
    """
    Формирует HTML-ответ на /status для конкретного TG user_id.

    Возможные состояния:
      • нет привязки → "вы не зарегистрированы"
      • нет подписки (нет user) → "ваша учётка удалена"
      • заблокирован по disabled / blocked / TTL / traffic_limit → причина
      • активен → трафик (с прогресс-баром) + TTL + лимит
    """
    user = lookup_user_by_tg_id(tg_user_id)
    if not user:
        return (
            "❌ <b>Вы не зарегистрированы.</b>\n\n"
            "Обратитесь к администратору для получения invite-ссылки.\n"
            "Команда <code>/start &lt;token&gt;</code> активирует ваш аккаунт."
        )
    email = user.get("email", "")
    name  = user.get("name", "") or email.split("@")[0]
    blocked, reason = _is_user_blocked(email)

    lines = [
        f"📊 <b>Статус подписки</b> — <code>{_safe_html(name)}</code>",
        "",
    ]

    if blocked:
        reason_text = {
            "disabled":      "⛔ Учётная запись отключена администратором.",
            "blocked":       "⛔ Учётная запись заблокирована.",
            "ttl_expired":   "⏰ Срок действия подписки истёк.",
            "traffic_limit": "📦 Исчерпан лимит трафика.",
            "no_user":       "❌ Учётная запись не найдена.",
        }.get(reason, f"⛔ Заблокировано: {reason}")
        lines.append(reason_text)
        lines.append("")
        if reason == "ttl_expired":
            ttl = _read_json(_TTL_FILE).get(email, {})
            exp = ttl.get("expires_at", "")
            if exp:
                lines.append(f"📅 Дата истечения: <code>{_safe_html(exp)}</code>")
            lines.append("Обратитесь к администратору для продления.")
        elif reason == "traffic_limit":
            tr = _get_user_traffic_info(email)
            lines.append(f"📦 Лимит: <code>{tr['limit_gb']} GiB</code>")
            lines.append("Обратитесь к администратору для увеличения лимита.")
        return "\n".join(lines)

    # Активен — показываем трафик + TTL
    lines.append("🟢 <b>Подписка активна</b>")
    lines.append("")

    # Трафик
    tr = _get_user_traffic_info(email)
    if tr["limit_bytes"] > 0:
        pct = tr["pct"] or 0
        bar = _progress_bar(pct)
        used_h = _format_bytes(tr["used_bytes"])
        limit_h = _format_bytes(tr["limit_bytes"])
        lines.append(f"📦 Трафик: <code>{used_h} / {limit_h}</code>")
        lines.append(f"   <code>{bar}</code>")
    else:
        used_h = _format_bytes(tr["used_bytes"])
        lines.append(f"📦 Трафик: <code>{used_h}</code> (безлимит)")
    lines.append("")

    # TTL
    ttl = _read_json(_TTL_FILE).get(email, {})
    exp = ttl.get("expires_at", "")
    if exp:
        lines.append(f"📅 Срок действия: <code>{_safe_html(exp)}</code>")
        lines.append(f"   Осталось: <b>{_safe_html(_ttl_expires_str(exp))}</b>")
    else:
        lines.append("📅 Срок действия: <b>бессрочно</b>")

    return "\n".join(lines)


def format_config_message(tg_user_id: int) -> tuple[str, list[str]]:
    """
    Формирует HTML-ответ на /config.
    Возвращает (text, list_of_protocol_keys) — список ключей протоколов,
    которые активны у пользователя (для inline-кнопок /qr <protocol>).

    Если подписка заблокирована — text содержит причину, list пустой.
    """
    user = lookup_user_by_tg_id(tg_user_id)
    if not user:
        return (
            "❌ <b>Вы не зарегистрированы.</b>\n\n"
            "Обратитесь к администратору для получения invite-ссылки.",
            []
        )
    email = user.get("email", "")
    blocked, reason = _is_user_blocked(email)
    if blocked:
        return (format_status_message(tg_user_id), [])

    # Импортируем linkqr_lib лениво (внутри функции — для тестability)
    from chimera.modules import linkqr_lib
    links = linkqr_lib.build_all_links_for_user(user)

    if not links:
        return (
            "⚠️ <b>Нет активных протоколов.</b>\n\n"
            "Ваша учётная запись не настроена ни на один протокол. "
            "Обратитесь к администратору.",
            []
        )

    proto_labels = {
        "vless":              "VLESS / REALITY",
        "awg":                "AmneziaWG (vpn://)",
        "hysteria2":          "Hysteria2",
        "mieru":              "Mieru (Karing)",
        "naive":              "NaiveProxy",
        "singbox_shadowtls":  "sing-box: ShadowTLS",
        "singbox_anytls":     "sing-box: AnyTLS",
        "singbox_tuic":       "sing-box: TUIC",
        "singbox_trojan":     "sing-box: Trojan",
        "singbox_vless_ws_cdn": "sing-box: VLESS-WS-CDN",
        "trusttunnel":        "TrustTunnel (tt://)",
        "subscription":       "Subscription URL (агато)",
    }
    lines = [
        "📋 <b>Ваши конфигурации</b>",
        "",
        "Нажмите кнопку ниже для QR-кода конкретного протокола,",
        "или используйте <code>/qr &lt;протокол&gt;</code>.",
        "",
    ]
    keys = []
    for key in links:
        label = proto_labels.get(key, key)
        lines.append(f"🔹 <b>{_safe_html(label)}</b>")
        lines.append(f"   <code>{_safe_html(links[key])}</code>")
        lines.append("")
        keys.append(key)
    return ("\n".join(lines), keys)


def format_qr_payload(tg_user_id: int, protocol: str) -> tuple[str, Optional[Path]]:
    """
    Возвращает (link_text, png_path) для указанного протокола.
    png_path — путь к сохранённому QR PNG, или None если не удалось.
    """
    user = lookup_user_by_tg_id(tg_user_id)
    if not user:
        return ("❌ Вы не зарегистрированы.", None)
    email = user.get("email", "")
    blocked, _ = _is_user_blocked(email)
    if blocked:
        return (format_status_message(tg_user_id), None)

    from chimera.modules import linkqr_lib
    links = linkqr_lib.build_all_links_for_user(user)
    link = links.get(protocol)
    if not link:
        return (f"❌ Протокол <code>{_safe_html(protocol)}</code> не активен.", None)

    # Генерируем QR PNG
    try:
        _QR_TMP_DIR.mkdir(parents=True, exist_ok=True)
        png_path = _QR_TMP_DIR / f"{tg_user_id}_{protocol}.png"
        ok = linkqr_lib.generate_qr_png(link, png_path)
        if not ok:
            return (f"❌ Не удалось сгенерировать QR для <code>{_safe_html(protocol)}</code>.", None)
        # Ссылку возвращаем как подпись к картинке
        return (link, png_path)
    except Exception as e:
        _log("ERROR", f"format_qr_payload: {e}")
        return (f"❌ Ошибка генерации QR: {_safe_html(str(e))}", None)


# =============================================================================
#  ГЕНЕРАЦИЯ INNER-СКРИПТА (самодостаточный бот для systemd)
# =============================================================================
def _generate_client_bot_script(bot_cfg: dict) -> str:
    """
    Генерирует Python-скрипт клиентского бота (long-polling, stdlib only).

    Скрипт запускается как systemd-сервис xray-tg-client. Не требует
    chimera.* на PYTHONPATH — все пути захардкожены.

    Bot API вызывается через urllib.request. QR-генерация — через subprocess
    к qrencode / python3 -c 'import qrcode'.
    """
    token        = json.dumps(bot_cfg.get("token", ""), ensure_ascii=False)
    admin_id     = json.dumps(str(bot_cfg.get("admin_id", "")), ensure_ascii=False)
    rate_limit_s = int(bot_cfg.get("rate_limit_seconds", 2))
    bot_file     = str(_CLIENT_BOT_FILE)
    map_file     = str(_CLIENT_MAP_FILE)
    users_file   = str(_USERS_FILE)
    state_file   = str(_STATE_FILE)
    ttl_file     = str(_TTL_FILE)
    limits_file  = str(_LIMITS_FILE)
    blocked_file = str(_BLOCKED_FILE)
    qr_dir       = str(_QR_TMP_DIR)

    # ── ПРОБЛЕМА: inner-скрипт запускается как отдельный systemd-процесс и
    #    не имеет chimera.* на PYTHONPATH. Ему нужно как-то найти
    #    linkqr_lib.py для построения AWG/Mieru/NaiveProxy/sing-box/subscription
    #    ссылок.
    #
    # РЕШЕНИЕ: вычисляем PROJECT_ROOT В МОМЕНТ ГЕНЕРАЦИИ скрипта — здесь мы
    #    гарантированно находимся внутри правильно установленного пакета
    #    chimera.modules.tg_client_bot (этот файл = .../chimera/
    #    modules/tg_client_bot.py), поэтому parents[2] = корень проекта,
    #    содержащий папку chimera/. Зашиваем путь как литерал в
    #    inner-скрипт. Никакого угадывания с диска во время выполнения.
    #
    #    Важно: не используем Path(__file__) ВНУТРИ inner-скрипта, потому что
    #    он лежит в /usr/local/bin/, а не в проекте — это и было источником
    #    бага. Только внешний Path(__file__) здесь, в момент генерации.
    _here = Path(__file__).resolve()
    # _here = .../chimera/modules/tg_client_bot.py
    # parents[0] = .../chimera/modules/
    # parents[1] = .../chimera/
    # parents[2] = .../  (корень проекта, где лежит main.py)
    _project_root = str(_here.parents[2])
    project_root_literal = json.dumps(_project_root, ensure_ascii=False)

    # ВНИМАНИЕ: все фигурные скобки внутри f-string-скрипта удвоены,
    # чтобы пережить f-string-интерполяцию на нашей стороне.
    script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# xray-tg-client-bot — auto-generated by vless-installer
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерируется из меню установщика
#
# Самодостаточный клиентский бот: stdlib only, никаких chimera.*.
# Логика: /start <token> -> привязка TG user_id к VLESS-пользователю,
# /config -> список ссылок + inline-кнопки, /qr <proto> -> QR PNG,
# /status -> трафик + TTL.

import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, urllib.error, base64, hashlib, hmac, secrets
from pathlib import Path
from datetime import datetime, timezone

TOKEN        = {token}
ADMIN_ID     = {admin_id}
RATE_LIMIT_S = {rate_limit_s}
# Корень проекта — вычислен В МОМЕНТ ГЕНЕРАЦИИ скрипта (а не во время
# выполнения) через Path(__file__).resolve().parents[2] от расположения
# chimera/modules/tg_client_bot.py. Гарантированно указывает на
# каталог, содержащий chimera/modules/linkqr_lib.py — нужен для
# subprocess-вызовов linkqr_lib из inner-скрипта (см. _call_linkqr_helper).
# Если проект перемещён после установки — fallback в _call_linkqr_helper
# попробует канонические пути (/opt/chimera и legacy-варианты).
PROJECT_ROOT = {project_root_literal}
BOT_FILE     = Path("{bot_file}")
MAP_FILE     = Path("{map_file}")
USERS_FILE   = Path("{users_file}")
STATE_FILE   = Path("{state_file}")
TTL_FILE     = Path("{ttl_file}")
LIMITS_FILE  = Path("{limits_file}")
BLOCKED_FILE = Path("{blocked_file}")
QR_DIR       = Path("{qr_dir}")
LOG_FILE     = Path("/var/log/chimera.log")
OFFSET       = 0

# ── Rate-limiting ────────────────────────────────────────────────────────────
_LAST_CMD = {{}}  # tg_user_id -> timestamp last command

def _rl_allow(uid):
    """True если команда разрешена (с прошлого вызова прошло >= RATE_LIMIT_S)."""
    now = time.time()
    last = _LAST_CMD.get(uid, 0)
    if now - last < RATE_LIMIT_S:
        return False
    _LAST_CMD[uid] = now
    return True

# ── Логирование ────────────────────────────────────────────────────────────────
def _log(msg):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(f"[{{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}] [TG-CLIENT-BOT] {{msg}}\\n")
    except Exception:
        pass

# ── JSON helpers ────────────────────────────────────────────────────────────
def _read_json(path):
    try:
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {{}}

def _read_users():
    try:
        if USERS_FILE.exists():
            data = json.loads(USERS_FILE.read_text())
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []

def _find_user_by_uuid(uuid_str):
    for u in _read_users():
        if u.get("uuid", "") == uuid_str:
            return u
    return None

def _find_user_by_email(email):
    for u in _read_users():
        if u.get("email", "") == email:
            return u
    return None

def _bot_load():
    return _read_json(BOT_FILE)

def _bot_save(cfg):
    BOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    BOT_FILE.chmod(0o600)

def _map_load():
    return _read_json(MAP_FILE)

def _map_save(data):
    MAP_FILE.parent.mkdir(parents=True, exist_ok=True)
    MAP_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    MAP_FILE.chmod(0o600)

def _state():
    return _read_json(STATE_FILE)

# ── TTL / блокировки ──────────────────────────────────────────────────────────
def _ttl_is_expired(iso):
    if not iso:
        return False
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp
    except Exception:
        return False

def _ttl_expires_str(iso):
    if not iso:
        return "бессрочно"
    try:
        exp = datetime.fromisoformat(iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - datetime.now(timezone.utc)
        total = int(delta.total_seconds())
        if total <= 0:
            return "ИСТЁК"
        days  = total // 86400
        hours = (total % 86400) // 3600
        mins  = (total % 3600) // 60
        if days > 0:
            return f"{{days}}д {{hours}}ч"
        if hours > 0:
            return f"{{hours}}ч {{mins}}м"
        return f"{{mins}}м"
    except Exception:
        return "?"

def _is_user_blocked(email):
    user = _find_user_by_email(email)
    if not user:
        return True, "no_user"
    if user.get("disabled"):
        return True, "disabled"
    if user.get("blocked"):
        return True, "blocked"
    ttl = _read_json(TTL_FILE).get(email, {{}})
    exp = ttl.get("expires_at", "")
    if exp and _ttl_is_expired(exp):
        return True, "ttl_expired"
    limits = _read_json(LIMITS_FILE).get(email, {{}})
    if limits.get("disabled"):
        return True, "traffic_limit"
    blocked_db = _read_json(BLOCKED_FILE)
    if email in blocked_db:
        return True, blocked_db[email].get("reason", "blocked")
    return False, ""

def _get_user_traffic_info(email):
    limits = _read_json(LIMITS_FILE).get(email, {{}})
    limit_gb = limits.get("limit_gb", 0)
    used_bytes = limits.get("used_bytes", 0)
    limit_bytes = limit_gb * 1024**3 if limit_gb else 0
    pct = None
    if limit_bytes > 0:
        pct = min(100, int(used_bytes * 100 / limit_bytes))
    return {{"used_bytes": used_bytes, "limit_bytes": limit_bytes, "limit_gb": limit_gb, "pct": pct}}

def _format_bytes(n):
    if n < 1024:
        return f"{{n}} B"
    if n < 1024**2:
        return f"{{n/1024:.1f}} KiB"
    if n < 1024**3:
        return f"{{n/1024**2:.2f}} MiB"
    return f"{{n/1024**3:.2f}} GiB"

def _progress_bar(pct, width=10):
    pct = max(0, min(100, pct))
    filled = width * pct // 100
    return f"[{{'█' * filled}}{{'-' * (width - filled)}}] {{pct}}%"

def _safe_html(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ── Привязка TG user_id к VLESS-пользователю ──────────────────────────────────
def _consume_invite_token(token):
    cfg = _bot_load()
    invites = cfg.get("invite_tokens", {{}})
    info = invites.get(token)
    if not info:
        return None
    if info.get("used"):
        return None
    email = info.get("email", "")
    if not email:
        return None
    info["used"] = True
    info["used_at"] = datetime.now(timezone.utc).isoformat()
    invites[token] = info
    cfg["invite_tokens"] = invites
    _bot_save(cfg)
    return email

def _bind_tg_user(tg_user_id, email):
    user = _find_user_by_email(email)
    if not user:
        return None
    data = _map_load()
    tg_id_str = str(tg_user_id)
    for k, v in data.items():
        if v.get("email") == email and k != tg_id_str:
            return None
    data[tg_id_str] = {{
        "uuid": user.get("uuid", ""),
        "email": email,
        "bound_at": datetime.now(timezone.utc).isoformat(),
    }}
    _map_save(data)
    return user

def _lookup_user(tg_user_id):
    data = _map_load()
    info = data.get(str(tg_user_id))
    if not info:
        return None
    uuid = info.get("uuid", "")
    if not uuid:
        return None
    return _find_user_by_uuid(uuid)

# ── Генерация ссылок (аналог linkqr_lib, но stdlib-only) ──────────────────────
def _build_vless_link(uuid_val):
    st = _state()
    domain = st.get("domain", "")
    port = st.get("server_port", 443)
    uuid_val = uuid_val or st.get("uuid", "")
    proto = st.get("protocol_mode", "reality")
    pub_key = st.get("public_key", "")
    short_id = st.get("short_id", "")
    fp = st.get("fingerprint", "chrome") or "chrome"
    xtls_flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path = st.get("xhttp_path", "/")
    install_mode = st.get("install_mode", "A")
    awg_exit = st.get("awg_exit_enabled", False)
    sni = domain
    if proto == "reality" and awg_exit and install_mode == "B":
        sni = (st.get("reality_dest", domain) or domain).split(":")[0]
    if not domain or not uuid_val:
        return ""
    if proto == "xhttp":
        return f"vless://{{uuid_val}}@{{domain}}:{{port}}?type=xhttp&security=tls&path={{xhttp_path}}&sni={{sni}}&fp={{fp}}#VLESS-xHTTP"
    flow_part = f"&flow={{xtls_flow}}" if xtls_flow else ""
    return f"vless://{{uuid_val}}@{{domain}}:{{port}}?type=tcp&security=reality&pbk={{pub_key}}&sid={{short_id}}&sni={{sni}}&fp={{fp}}{{flow_part}}#VLESS-REALITY"

def _build_hysteria2_link():
    st = _state()
    h2 = st.get("hysteria2", {{}})
    if not h2.get("enabled"):
        return ""
    nodes = h2.get("exit_nodes", []) or []
    node = next((n for n in nodes if n.get("status") == "active"), None)
    if not node:
        return ""
    host = h2.get("_active_node_ip") or node.get("ip", "")
    if not host:
        return ""
    port = (node.get("ports", [443]) or [443])[0]
    password = node.get("auth", "")
    sni = st.get("domain", "") or host
    if not password:
        return ""
    return f"hysteria2://{{urllib.parse.quote(password, safe='')}}@{{host}}:{{port}}?insecure=1&sni={{sni}}#Hysteria2"

def _build_awg_link(email):
    """Строит vpn:// URI для пира AWG, привязанного к email."""
    try:
        # Читаем awg state напрямую (без импорта awg_state)
        awg_state_file = Path("/var/lib/xray-installer/awg_standalone_state.json")
        if not awg_state_file.exists():
            return ""
        awg_state = json.loads(awg_state_file.read_text())
        if not awg_state.get("installed"):
            return ""
        peer = None
        for p in awg_state.get("peers", []):
            if p.get("owner_email") == email:
                peer = p
                break
        if not peer:
            return ""
        expires_at = peer.get("expires_at", "")
        if expires_at and _ttl_is_expired(expires_at):
            return ""
        # Делегируем в linkqr_lib через subprocess
        # (чтобы не дублировать сложную логику сборки vpn:// URI)
        return _call_linkqr_helper("awg_link", email=email)
    except Exception as e:
        _log(f"_build_awg_link error: {{e}}")
        return ""

def _build_singbox_links(uuid_val):
    """Возвращает list[(proto_name, link)] — через linkqr_lib helper."""
    return _call_linkqr_helper("singbox_links", uuid=uuid_val) or []

def _build_mieru_link(email):
    return _call_linkqr_helper("mieru_link", email=email) or ""

def _build_naive_link(email):
    return _call_linkqr_helper("naive_link", email=email) or ""

def _build_subscription_url(user):
    return _call_linkqr_helper("subscription_url", user=user) or ""

def _call_linkqr_helper(action, **kwargs):
    """
    Вызывает chimera.modules.linkqr_lib через subprocess-вызов
    python3 -c '...'. Это НЕ дублирует код ссылок, а переиспользует его.
    Возвращает распарсенный JSON-ответ или None.

    Поиск корня проекта:
      1. PROJECT_ROOT — зашитый в момент генерации путь (главный, надёжный).
         Вычислен через Path(__file__).resolve().parents[2] от расположения
         chimera/modules/tg_client_bot.py — это канонический путь
         установки (например /opt/chimera по bootstrap.sh).
      2. Fallback на случай нестандартной установки/переустановки:
         проверяем канонические пути из bootstrap.sh, ВКЛЮЧАЯ правильный
         /opt/chimera (legacy /opt/vless-ultimate и /opt/VLESS-Ultimate-Installer
         оставлены только для обратной совместимости со старыми установками).
      3. Если ничего не найдено — возвращаем None, вызывающий код должен
         ЯВНО сообщить пользователю о невозможности построить ссылку.
    """
    def _has_linkqr(p):
        """Безопасная проверка что по пути p лежит linkqr_lib.py.
        Path.exists() может поднять PermissionError (например для
        /root/chimera если бот запущен не от root) —
        ловим и считаем что пути нет."""
        try:
            return Path(p).exists() and (Path(p) / "chimera" / "modules" / "linkqr_lib.py").exists()
        except (OSError, PermissionError):
            return False

    project_root = None
    # 1) Зашитый в момент генерации путь
    if PROJECT_ROOT and _has_linkqr(PROJECT_ROOT):
        project_root = PROJECT_ROOT
    # 2) Fallback: канонические пути в порядке приоритета.
    #    ВАЖНО: домашние директории НЕ проверяем — только системные пути.
    if not project_root:
        for p in (
            "/opt/chimera",                          # канонический (bootstrap.sh:INSTALL_DIR, Chimera Project v5.0+)
            "/opt/vless-ultimate",                   # legacy (VLESS Ultimate Installer v4.x)
            "/opt/VLESS-Ultimate-Installer",         # legacy регистр (ранние версии bootstrap)
        ):
            if _has_linkqr(p):
                project_root = p
                break
    if not project_root:
        _log(f"linkqr_lib not found (PROJECT_ROOT={{PROJECT_ROOT!r}}), cannot build link for action={{action}}")
        return None
    env = dict(os.environ)
    env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")
    payload = json.dumps({{"action": action, **kwargs}})
    # ВАЖНО: код ниже исполняется как отдельная строка через `python3 -c`.
    # Использовать `; elif` НЕЛЬЗЯ — Python это не парсит (SyntaxError).
    # Поэтому if/elif разложены через полноценные переводы строк (\\n).
    # Каждая строка заканчивается \\n (после f-string-интерполяции станет
    # реальным \\n в строке-аргументе `python3 -c`).
    code = (
        "import json, sys\\n"
        "from chimera.modules import linkqr_lib\\n"
        "args = json.loads(sys.stdin.read())\\n"
        "action = args.pop('action')\\n"
        "r = None\\n"
        "if action == 'awg_link':\\n"
        "    r = linkqr_lib.build_awg_link_for_user(args.get('email', ''))\\n"
        "elif action == 'mieru_link':\\n"
        "    r = linkqr_lib.build_mieru_link_for_user(args.get('email', ''))\\n"
        "elif action == 'naive_link':\\n"
        "    r = linkqr_lib.build_naive_link_for_user(args.get('email', ''))\\n"
        "elif action == 'singbox_links':\\n"
        "    r = linkqr_lib.build_singbox_links_for_user(args.get('uuid', ''))\\n"
        "elif action == 'subscription_url':\\n"
        "    r = linkqr_lib.build_subscription_url_for_user(args.get('user', {{}}))\\n"
        "sys.stdout.write(json.dumps(r))\\n"
    )
    try:
        r = subprocess.run(["python3", "-c", code], input=payload, capture_output=True,
                           text=True, env=env, timeout=10)
        if r.returncode != 0:
            _log(f"linkqr helper failed ({{action}}): {{r.stderr.strip()}}")
            return None
        return json.loads(r.stdout) if r.stdout.strip() else None
    except Exception as e:
        _log(f"linkqr helper exception ({{action}}): {{e}}")
        return None

# ── Сборка всех ссылок пользователя ───────────────────────────────────────────
def _build_all_links(user):
    """
    Возвращает (links: dict, errors: list[str]).
      links  — {{proto_key: link_str}} для всех успешно построенных протоколов.
      errors — список читабельных описаний ошибок (например,
               'AWG: не удалось найти linkqr_lib'). Если errors непустой —
               вызывающий код должен показать его пользователю, чтобы тот
               понимал, что это технический сбой, а не отсутствие протокола.
    """
    if not user:
        return {{}}, []
    uuid_val = user.get("uuid", "")
    email = user.get("email", "")
    links = {{}}
    errors = []
    vless = _build_vless_link(uuid_val)
    if vless:
        links["vless"] = vless
    if email:
        # AWG: различаем «нет пира» (нормально) от «helper упал» (баг)
        awg_peer_exists = False
        try:
            awg_state_file = Path("/var/lib/xray-installer/awg_standalone_state.json")
            if awg_state_file.exists():
                awg_state = json.loads(awg_state_file.read_text())
                awg_peer_exists = any(p.get("owner_email") == email for p in awg_state.get("peers", []))
        except Exception:
            pass
        awg = _build_awg_link(email)
        if awg:
            links["awg"] = awg
        elif awg_peer_exists:
            # Пир есть, но ссылку построить не удалось — это баг linkqr_lib
            errors.append("AWG: не удалось построить ссылку (ошибка linkqr_lib на сервере)")
        # Аналогично для Mieru / NaiveProxy: проверяем есть ли пользователь
        mieru_user_exists = False
        try:
            mieru_state_file = Path("/var/lib/xray-installer/mieru.json")
            if mieru_state_file.exists():
                ms = json.loads(mieru_state_file.read_text())
                uname = (email or "").split("@")[0]
                mieru_user_exists = any(u.get("username") == uname for u in ms.get("users", []))
        except Exception:
            pass
        mieru = _build_mieru_link(email)
        if mieru:
            links["mieru"] = mieru
        elif mieru_user_exists:
            errors.append("Mieru: не удалось построить ссылку (ошибка linkqr_lib на сервере)")
        naive_user_exists = False
        try:
            naive_state_file = Path("/var/lib/xray-installer/naiveproxy.json")
            if naive_state_file.exists():
                ns = json.loads(naive_state_file.read_text())
                uname = (email or "").split("@")[0]
                naive_user_exists = any(u.get("username") == uname for u in ns.get("users", []))
        except Exception:
            pass
        naive = _build_naive_link(email)
        if naive:
            links["naive"] = naive
        elif naive_user_exists:
            errors.append("NaiveProxy: не удалось построить ссылку (ошибка linkqr_lib на сервере)")
    if uuid_val:
        # sing-box: проверяем есть ли UUID в каком-то включённом inbound
        sb_user_exists = False
        try:
            sb_state_file = Path("/var/lib/xray-installer/singbox_state.json")
            if sb_state_file.exists():
                sbs = json.loads(sb_state_file.read_text())
                for proto_name, ib in sbs.get("inbounds", {{}}).items():
                    if not ib.get("enabled"):
                        continue
                    ib_uuid = ib.get("uuid", "")
                    if ib_uuid and ib_uuid == uuid_val:
                        sb_user_exists = True
                        break
                    if any(u.get("uuid") == uuid_val for u in (ib.get("users", []) or [])):
                        sb_user_exists = True
                        break
        except Exception:
            pass
        sb = _build_singbox_links(uuid_val)
        for proto, link in sb:
            links[f"singbox_{{proto}}"] = link
        if sb_user_exists and not sb:
            errors.append("sing-box: не удалось построить ссылку (ошибка linkqr_lib на сервере)")
    h2 = _build_hysteria2_link()
    if h2:
        links["hysteria2"] = h2
    # Subscription: проверяем есть ли pepper в sub_conf
    sub_pepper_set = False
    try:
        sub_conf_file = Path("/var/lib/xray-installer/subscription.json")
        if sub_conf_file.exists():
            sc = json.loads(sub_conf_file.read_text())
            sub_pepper_set = bool(sc.get("pepper"))
    except Exception:
        pass
    sub_url = _build_subscription_url(user)
    if sub_url:
        links["subscription"] = sub_url
    elif sub_pepper_set:
        errors.append("Subscription URL: не удалось построить (ошибка linkqr_lib на сервере)")
    return links, errors

# ── Генерация QR PNG ──────────────────────────────────────────────────────────
def _generate_qr_png(text, out_path):
    if not text:
        return False
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        return False
    # qrencode CLI
    try:
        ec = "L" if len(text) > 800 else "M"
        r = subprocess.run(
            ["qrencode", "-t", "PNG", "-l", ec, "-s", "6", "-m", "4", "-o", str(out_path)],
            input=text, capture_output=True, text=True, check=False,
        )
        if r.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0:
            return True
    except Exception:
        pass
    # Fallback: python3-qrcode
    try:
        code = (
            "import qrcode, sys; "
            "text = sys.stdin.read(); "
            "qr = qrcode.QRCode(box_size=6, border=4); "
            "qr.add_data(text); qr.make(fit=True); "
            f"qr.make_image(fill_color='black', back_color='white').save('{{out_path}}');"
        )
        r = subprocess.run(["python3", "-c", code], input=text, capture_output=True, text=True, check=False)
        return r.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0
    except Exception:
        return False

# ── Telegram Bot API ─────────────────────────────────────────────────────────
def api(method, **params):
    url = f"https://api.telegram.org/bot{{TOKEN}}/{{method}}"
    data = urllib.parse.urlencode(params).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        _log(f"API error {{method}}: {{e}}")
        return {{}}

def send(chat_id, text, parse_mode="HTML", reply_markup=None):
    params = dict(chat_id=chat_id, text=text, parse_mode=parse_mode)
    if reply_markup:
        params["reply_markup"] = json.dumps(reply_markup) if isinstance(reply_markup, dict) else reply_markup
    api("sendMessage", **params)

def send_photo(chat_id, photo_path, caption=""):
    """Отправляет PNG через curl -F (multipart/form-data)."""
    import subprocess as _sp
    try:
        url = f"https://api.telegram.org/bot{{TOKEN}}/sendPhoto"
        cmd = ["curl", "-s", "-m", "30", url,
               "-F", f"chat_id={{chat_id}}",
               "-F", f"photo=@{{photo_path}};type=image/png"]
        if caption:
            cmd += ["-F", f"caption={{caption}}"]
        r = _sp.run(cmd, capture_output=True, text=True, check=False)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
        _log(f"sendPhoto curl failed: {{r.stderr.strip()}}")
        return {{}}
    except Exception as e:
        _log(f"sendPhoto error: {{e}}")
        return {{}}

def is_admin(uid):
    return str(uid) == ADMIN_ID

# ── Обработчики команд ────────────────────────────────────────────────────────
def handle_start(msg, args):
    chat_id = msg["chat"]["id"]
    uid = msg["from"]["id"]
    if not _rl_allow(uid):
        send(chat_id, "⏳ Слишком много команд. Подождите пару секунд.")
        return
    if args:
        token = args[0]
        email = _consume_invite_token(token)
        if not email:
            send(chat_id, "❌ Неверный или уже использованный invite-токен.")
            return
        user = _bind_tg_user(uid, email)
        if not user:
            send(chat_id, "❌ Не удалось привязать аккаунт. Возможно, учётка уже занята другим TG-аккаунтом.")
            return
        send(chat_id,
            f"✅ <b>Аккаунт привязан!</b>\\n\\n"
            f"Пользователь: <code>{{_safe_html(user.get('email',''))}}</code>\\n\\n"
            f"Доступные команды:\\n"
            f"/config — все ссылки подключения\\n"
            f"/qr &lt;протокол&gt; — QR-код конкретного протокола\\n"
            f"/status — трафик и срок действия\\n"
            f"/help — справка")
        return
    # Без токена — проверяем, есть ли уже привязка
    user = _lookup_user(uid)
    if user:
        send(chat_id,
            f"👋 <b>Вы уже авторизованы.</b>\\n"
            f"Пользователь: <code>{{_safe_html(user.get('email',''))}}</code>\\n\\n"
            f"Команды: /config /qr /status /help")
    else:
        send(chat_id,
            f"👋 <b>Добро пожаловать!</b>\\n\\n"
            f"Это self-service бот для доступа к вашим конфигурациям VPN.\\n\\n"
            f"Для активации используйте invite-ссылку от администратора:\\n"
            f"<code>/start &lt;token&gt;</code>\\n\\n"
            f"Ваш Telegram ID: <code>{{uid}}</code>")

def handle_config(msg):
    chat_id = msg["chat"]["id"]
    uid = msg["from"]["id"]
    if not _rl_allow(uid):
        send(chat_id, "⏳ Слишком много команд. Подождите пару секунд.")
        return
    user = _lookup_user(uid)
    if not user:
        send(chat_id, "❌ Вы не зарегистрированы. Используйте /start <token>.")
        return
    email = user.get("email", "")
    blocked, reason = _is_user_blocked(email)
    if blocked:
        send(chat_id, _format_blocked_msg(email, reason))
        return
    links, errors = _build_all_links(user)
    if not links and not errors:
        send(chat_id, "⚠️ Нет активных протоколов. Обратитесь к администратору.")
        return
    proto_labels = {{
        "vless": "VLESS / REALITY",
        "awg": "AmneziaWG",
        "hysteria2": "Hysteria2",
        "mieru": "Mieru",
        "naive": "NaiveProxy",
        "singbox_shadowtls": "SB: ShadowTLS",
        "singbox_anytls": "SB: AnyTLS",
        "singbox_tuic": "SB: TUIC",
        "singbox_trojan": "SB: Trojan",
        "singbox_vless_ws_cdn": "SB: VLESS-WS-CDN",
        "subscription": "Subscription URL",
    }}
    lines = ["📋 <b>Ваши конфигурации</b>", ""]
    keys = []
    for key in links:
        label = proto_labels.get(key, key)
        lines.append(f"🔹 <b>{{_safe_html(label)}}</b>")
        lines.append(f"   <code>{{_safe_html(links[key])}}</code>")
        lines.append("")
        keys.append(key)
    # Если есть ошибки построения ссылок — показываем их ЯВНО пользователю,
    # чтобы он понимал, что это технический сбой на сервере, а не отсутствие
    # протокола. Молчаливое пропускание в списке /config было источником
    # трудноотлаживаемых пользовательских жалоб.
    if errors:
        lines.append("⚠️ <b>Не удалось построить некоторые ссылки:</b>")
        for err in errors:
            lines.append(f"   — {{_safe_html(err)}}")
        lines.append("")
        lines.append("Обратитесь к администратору — проверьте установку linkqr_lib.")
        lines.append("")
    if keys:
        lines.append("Нажмите кнопку для QR-кода протокола:")
        # Inline-кнопки: по 2 в ряд
        inline_keyboard = []
        row = []
        for k in keys:
            label = proto_labels.get(k, k).replace("SB: ", "")[:20]
            row.append({{"text": f"QR: {{label}}", "callback_data": f"qr:{{k}}"}})
            if len(row) == 2:
                inline_keyboard.append(row)
                row = []
        if row:
            inline_keyboard.append(row)
        send(chat_id, "\\n".join(lines), reply_markup={{"inline_keyboard": inline_keyboard}})
    else:
        # Только ошибки, без успешно построенных ссылок — кнопок нет
        send(chat_id, "\\n".join(lines))

def handle_qr(msg, args):
    chat_id = msg["chat"]["id"]
    uid = msg["from"]["id"]
    if not _rl_allow(uid):
        send(chat_id, "⏳ Слишком много команд. Подождите пару секунд.")
        return
    if not args:
        send(chat_id, "Использование: <code>/qr &lt;протокол&gt;</code>\\nНапример: <code>/qr vless</code>")
        return
    protocol = args[0].lower()
    user = _lookup_user(uid)
    if not user:
        send(chat_id, "❌ Вы не зарегистрированы.")
        return
    email = user.get("email", "")
    blocked, reason = _is_user_blocked(email)
    if blocked:
        send(chat_id, _format_blocked_msg(email, reason))
        return
    links, errors = _build_all_links(user)
    link = links.get(protocol)
    if not link:
        # Если протокол в списке ошибок — показываем причину, а не «не активен»
        err_for_proto = [e for e in errors if protocol.lower() in e.lower()]
        if err_for_proto:
            send(chat_id, f"❌ Не удалось построить ссылку для <code>{{_safe_html(protocol)}}</code>:\\n"
                          f"<i>{{_safe_html(err_for_proto[0])}}</i>\\n\\n"
                          f"Обратитесь к администратору.")
        else:
            send(chat_id, f"❌ Протокол <code>{{_safe_html(protocol)}}</code> не активен.")
        return
    try:
        QR_DIR.mkdir(parents=True, exist_ok=True)
        png_path = QR_DIR / f"{{uid}}_{{protocol}}.png"
        ok = _generate_qr_png(link, png_path)
        if not ok:
            send(chat_id, f"❌ Не удалось сгенерировать QR для <code>{{_safe_html(protocol)}}</code>.")
            return
        caption = f"QR: {{_safe_html(protocol)}}\\n<code>{{_safe_html(link)}}</code>"
        send_photo(chat_id, png_path, caption)
        # Удаляем временный файл
        try:
            png_path.unlink()
        except Exception:
            pass
    except Exception as e:
        send(chat_id, f"❌ Ошибка: {{_safe_html(str(e))}}")

def handle_status(msg):
    chat_id = msg["chat"]["id"]
    uid = msg["from"]["id"]
    if not _rl_allow(uid):
        send(chat_id, "⏳ Слишком много команд. Подождите пару секунд.")
        return
    send(chat_id, _format_status_msg(uid))

def _format_blocked_msg(email, reason):
    reason_text = {{
        "disabled": "⛔ Учётная запись отключена администратором.",
        "blocked": "⛔ Учётная запись заблокирована.",
        "ttl_expired": "⏰ Срок действия подписки истёк.",
        "traffic_limit": "📦 Исчерпан лимит трафика.",
        "no_user": "❌ Учётная запись не найдена.",
    }}.get(reason, f"⛔ Заблокировано: {{reason}}")
    lines = [reason_text, ""]
    if reason == "ttl_expired":
        ttl = _read_json(TTL_FILE).get(email, {{}})
        exp = ttl.get("expires_at", "")
        if exp:
            lines.append(f"📅 Дата истечения: <code>{{_safe_html(exp)}}</code>")
        lines.append("Обратитесь к администратору для продления.")
    elif reason == "traffic_limit":
        tr = _get_user_traffic_info(email)
        lines.append(f"📦 Лимит: <code>{{tr['limit_gb']}} GiB</code>")
        lines.append("Обратитесь к администратору для увеличения лимита.")
    return "\\n".join(lines)

def _format_status_msg(uid):
    user = _lookup_user(uid)
    if not user:
        return ("❌ <b>Вы не зарегистрированы.</b>\\n\\n"
                "Обратитесь к администратору для получения invite-ссылки.\\n"
                "Команда <code>/start &lt;token&gt;</code> активирует ваш аккаунт.")
    email = user.get("email", "")
    name = user.get("name", "") or email.split("@")[0]
    blocked, reason = _is_user_blocked(email)
    lines = [f"📊 <b>Статус подписки</b> — <code>{{_safe_html(name)}}</code>", ""]
    if blocked:
        return "\\n".join([lines[0], lines[1], _format_blocked_msg(email, reason)])
    lines.append("🟢 <b>Подписка активна</b>")
    lines.append("")
    tr = _get_user_traffic_info(email)
    if tr["limit_bytes"] > 0:
        pct = tr["pct"] or 0
        bar = _progress_bar(pct)
        used_h = _format_bytes(tr["used_bytes"])
        limit_h = _format_bytes(tr["limit_bytes"])
        lines.append(f"📦 Трафик: <code>{{used_h}} / {{limit_h}}</code>")
        lines.append(f"   <code>{{bar}}</code>")
    else:
        used_h = _format_bytes(tr["used_bytes"])
        lines.append(f"📦 Трафик: <code>{{used_h}}</code> (безлимит)")
    lines.append("")
    ttl = _read_json(TTL_FILE).get(email, {{}})
    exp = ttl.get("expires_at", "")
    if exp:
        lines.append(f"📅 Срок действия: <code>{{_safe_html(exp)}}</code>")
        lines.append(f"   Осталось: <b>{{_safe_html(_ttl_expires_str(exp))}}</b>")
    else:
        lines.append("📅 Срок действия: <b>бессрочно</b>")
    return "\\n".join(lines)

def handle_protocols(msg):
    """Список доступных протоколов с описаниями."""
    chat_id = msg["chat"]["id"]
    send(chat_id,
        "🔌 <b>Доступные протоколы</b>\\n\\n"
        "<b>VLESS REALITY</b>\\n"
        "  Самый незаметный — маскируется под TLS к настоящему сайту.\\n"
        "  Используйте, если ничего другое не работает.\\n"
        "  Клиенты: NekoBox, v2rayNG, Happ, Streisand, Hiddify\\n\\n"
        "<b>VLESS xHTTP</b>\\n"
        "  REALITY через HTTP/2 — лучше работает при жёстком DPI.\\n"
        "  Рекомендуется для мобильных сетей РФ.\\n\\n"
        "<b>AWG (AmneziaWG)</b>\\n"
        "  WireGuard с обфускацией — для случаев когда VPN-протокол\\n"
        "  детектируется ТСПУ. Настройка через отдельного клиента.\\n\\n"
        "<b>Hysteria2</b>\\n"
        "  QUIC-based — для нестабильных/мобильных соединений.\\n"
        "  Быстрее при lossy networks.\\n\\n"
        "<b>Mieru</b>\\n"
        "  Mitsuka-bypass — работает в самых жёстких условиях.\\n"
        "  Используйте только если всё остальное заблокировано.\\n\\n"
        "<b>NaiveProxy</b>\\n"
        "  HTTP/2 masquerading — режется редко.\\n\\n"
        "<b>sing-box (multi)</b>\\n"
        "  Подписка со всеми протоколами в одном конфиге —\\n"
        "  клиент сам выбирает лучший.\\n\\n"
        "📖 <b>Клиенты по платформам:</b>\\n"
        "  • <b>Android</b>: NekoBox, v2rayNG, Hiddify\\n"
        "  • <b>iOS</b>: V2Box, Streisand, Hiddify\\n"
        "  • <b>Windows</b>: NekoRay, v2rayN, Hiddify\\n"
        "  • <b>macOS</b>: Hiddify, Foxray\\n"
        "  • <b>Linux</b>: NekoRay, v2rayA\\n\\n"
        f"Для своего подключения используйте /config.")

def handle_guide(msg):
    """Краткое руководство по клиентам."""
    chat_id = msg["chat"]["id"]
    send(chat_id,
        "📘 <b>Руководство по подключению</b>\\n\\n"
        "<b>1. Получите конфиг</b>\\n"
        "  /config — список всех доступных ссылок + кнопки для QR\\n\\n"
        "<b>2. Выберите протокол</b>\\n"
        "  • VLESS REALITY — для большинства случаев\\n"
        "  • VLESS xHTTP — при жёстком DPI (мобильные сети)\\n"
        "  • AWG/Hysteria2/Mieru — если REALITY заблокирован\\n\\n"
        "<b>3. Установите клиент</b>\\n"
        "  Android: <a href=\\\"https://play.google.com/store/apps/details?id=com.nekoroid.nekoray\\\">NekoBox</a> или v2rayNG\\n"
        "  iOS: V2Box или Streisand\\n"
        "  Windows: <a href=\\\"https://github.com/MatsuriDayo/nekoray\\\">NekoRay</a>\\n\\n"
        "<b>4. Импортируйте конфиг</b>\\n"
        "  Скопируйте vless:// ссылку → вставьте в клиент → Подключиться\\n\\n"
        "<b>5. Проверьте статус</b>\\n"
        "  /status — трафик + TTL + лимит\\n\\n"
        "💡 <b>Совет</b>: если соединение нестабильно — попробуйте\\n"
        "другой протокол из /config. Каждый работает по-разному в\\n"
        "зависимости от провайдера и времени суток.")

def handle_menu(msg):
    """Inline-клавиатура с кнопками для всех client-команд."""
    chat_id = msg["chat"]["id"]
    keyboard = {{
        "inline_keyboard": [
            [{{"text": "🔗 Получить конфиг", "callback_data": "menu:config"}}],
            [{{"text": "📊 Трафик и TTL", "callback_data": "menu:status"}}],
            [{{"text": "🔌 Протоколы", "callback_data": "menu:protocols"}}],
            [{{"text": "📘 Руководство", "callback_data": "menu:guide"}}],
            [{{"text": "❓ Помощь", "callback_data": "menu:help"}}],
        ]
    }}
    api("sendMessage", chat_id=str(chat_id),
        text="🎛️ <b>Меню</b>\\n\\nВыберите действие:",
        parse_mode="HTML",
        reply_markup=json.dumps(keyboard))

def handle_help(msg):
    chat_id = msg["chat"]["id"]
    send(chat_id,
        "📖 <b>Справка</b>\\n\\n"
        "<b>Доступные команды:</b>\\n"
        "/start [token] — привязка аккаунта (один раз)\\n"
        "/config — список ссылок + кнопки для QR\\n"
        "/qr &lt;протокол&gt; — QR-код конкретного протокола\\n"
        "/status — трафик, TTL, лимит\\n"
        "/protocols — описание протоколов + клиенты по платформам\\n"
        "/guide — краткое руководство по подключению\\n"
        "/menu — inline-клавиатура с кнопками\\n"
        "/help — эта справка\\n\\n"
        "<b>Протоколы</b>: vless (REALITY), vless-xhttp, awg, hysteria2, mieru, naive, singbox\\n\\n"
        "<b>Алиасы</b>: /traffic = /status\\n\\n"
        "По всем вопросам обращайтесь к администратору сервера.")

def handle_callback(update):
    """Обработка inline-кнопок."""
    cb = update.get("callback_query")
    if not cb:
        return
    msg = cb.get("message", {{}})
    chat_id = msg.get("chat", {{}}).get("id")
    uid = cb.get("from", {{}}).get("id")
    data = cb.get("data", "")
    # Answer callback (remove spinner)
    api("answerCallbackQuery", callback_query_id=cb.get("id", ""))
    # QR callback (existing)
    if data.startswith("qr:"):
        protocol = data[3:]
        handle_qr({{"chat": {{"id": chat_id}}, "from": {{"id": uid}}}}, [protocol])
        return
    # Menu callback (new)
    if data.startswith("menu:"):
        action = data[5:]
        fake_msg = {{"chat": {{"id": chat_id}}, "from": {{"id": uid}}}}
        if action == "config":      handle_config(fake_msg)
        elif action == "status":    handle_status(fake_msg)
        elif action == "protocols": handle_protocols(fake_msg)
        elif action == "guide":     handle_guide(fake_msg)
        elif action == "help":      handle_help(fake_msg)
        return

# ── Диспетчер ─────────────────────────────────────────────────────────────────
def process_update(update):
    # Callback (inline-кнопки)
    if "callback_query" in update:
        handle_callback(update)
        return
    msg = update.get("message") or update.get("edited_message")
    if not msg or "text" not in msg:
        return
    text  = msg["text"].strip()
    parts = text.split()
    cmd   = parts[0].split("@")[0].lower() if parts else ""
    args  = parts[1:]
    if cmd == "/start":       handle_start(msg, args)
    elif cmd == "/config":    handle_config(msg)
    elif cmd == "/qr":        handle_qr(msg, args)
    elif cmd == "/status" or cmd == "/traffic": handle_status(msg)
    elif cmd == "/protocols": handle_protocols(msg)
    elif cmd == "/guide":     handle_guide(msg)
    elif cmd == "/menu":      handle_menu(msg)
    elif cmd == "/help":      handle_help(msg)

def main():
    global OFFSET
    _log("Client bot started")
    fail_count = 0
    while True:
        try:
            r = api("getUpdates", offset=OFFSET, timeout=25, limit=10)
            if not r:
                fail_count += 1
                if fail_count in (1, 10) or fail_count % 60 == 0:
                    _log(f"Poll: нет ответа от API ({{fail_count}} попыток подряд)")
                time.sleep(5)
                continue
            fail_count = 0
            for upd in r.get("result", []):
                OFFSET = upd["update_id"] + 1
                try:
                    process_update(upd)
                except Exception as e:
                    _log(f"Update error: {{e}}")
        except Exception as e:
            _log(f"Poll error: {{e}}")
            time.sleep(5)

if __name__ == "__main__":
    main()
'''
    return script


# =============================================================================
#  УСТАНОВКА / ОСТАНОВКА SYSTEMD-СЕРВИСА
# =============================================================================
def install_client_bot_service(bot_cfg: dict) -> bool:
    """Генерирует inner-скрипт, пишет systemd-unit, запускает сервис."""
    script_content = _generate_client_bot_script(bot_cfg)
    _CLIENT_BOT_SCRIPT.write_text(script_content)
    _CLIENT_BOT_SCRIPT.chmod(0o700)

    svc = (
        "[Unit]\n"
        "Description=VLESS Telegram Client Self-Service Bot\n"
        "After=network.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 /usr/local/bin/xray-tg-client-bot.py\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _CLIENT_BOT_SVC.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", "xray-tg-client"], quiet=True)
    _run(["systemctl", "restart", "xray-tg-client"])
    time.sleep(2)
    return client_bot_running()


def stop_client_bot_service() -> None:
    _run(["systemctl", "stop", "xray-tg-client"], quiet=True)
    _run(["systemctl", "disable", "xray-tg-client"], quiet=True)
    _CLIENT_BOT_SCRIPT.unlink(missing_ok=True)
    _CLIENT_BOT_SVC.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)


def regenerate_client_bot() -> bool:
    """Перегенерирует inner-скрипт после смены токена/настроек."""
    cfg = client_bot_load()
    if not cfg.get("token"):
        return False
    script_content = _generate_client_bot_script(cfg)
    _CLIENT_BOT_SCRIPT.write_text(script_content)
    _CLIENT_BOT_SCRIPT.chmod(0o700)
    if client_bot_running():
        _run(["systemctl", "restart", "xray-tg-client"], quiet=True)
        time.sleep(1)
    return True


# =============================================================================
#  TUI-МЕНЮ (пункт "TC" в главном меню _core.py)
# =============================================================================
def do_tg_client_bot_menu() -> None:
    """Меню управления клиентским Telegram-ботом."""
    while True:
        os.system("clear")
        cfg = client_bot_load()
        running = client_bot_running()

        token     = cfg.get("token", "")
        admin_id  = cfg.get("admin_id", "")
        rate_s    = cfg.get("rate_limit_seconds", 2)
        invites   = cfg.get("invite_tokens", {})
        active_invites = {k: v for k, v in invites.items() if not v.get("used")}
        mapping   = client_map_load()

        configured = bool(token and admin_id)

        print()
        _box_top("🤖  TELEGRAM CLIENT BOT — self-service для пользователей")
        _box_desc(
            "Клиентский бот: пользователь пишет /start <invite> → привязывается к своей "
            "учётке → получает ссылки и QR на свои протоколы (VLESS, AWG, Hysteria2, "
            "Mieru, NaiveProxy, sing-box). READ-ONLY: не даёт admin-команд."
        )
        _box_sep()
        _box_row(f"  Статус бота:    {''+GREEN+'ЗАПУЩЕН'+NC if running else ''+DIM+'ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Конфиг:         {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:          {DIM}{token[:10]}...{NC}")
            _box_row(f"  Admin ID:       {CYAN}{admin_id}{NC}")
            _box_row(f"  Rate-limit:     {CYAN}{rate_s}{NC} сек/команда")
            _box_row(f"  Привязано TG:   {CYAN}{len(mapping)}{NC} аккаунтов")
            _box_row(f"  Активных invite:{YELLOW}{len(active_invites)}{NC}")
        _box_sep()
        if not configured:
            _box_item("1", f"Настроить бота (отдельный токен + admin ID)")
        else:
            _box_item("1", f"Изменить настройки")
            if running:
                _box_item("2", f"Перезапустить бота")
                _box_item("3", f"{RED}Остановить бота{NC}")
            else:
                _box_item("2", f"{GREEN}Запустить бота{NC}")
            _box_item("4", f"Создать invite-ссылку для пользователя")
            _box_item("5", f"Список привязанных TG-аккаунтов")
            _box_item("6", f"Отвязать TG-аккаунт")
            _box_item("7", f"Проверить статус сервиса")
        _box_sep()
        _box_info("Это ОТДЕЛЬНЫЙ бот от admin-бота (xray-tg-bot).")
        _box_info("Systemd-сервис: xray-tg-client")
        _box_info("Токен: @BotFather → /newbot (создайте НОВОГО бота)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_client_configure(cfg)
        elif ch == "2" and configured:
            if running:
                _info("Перезапускаю...")
                _run(["systemctl", "restart", "xray-tg-client"], quiet=True)
                time.sleep(2)
                _ok("Перезапущен") if client_bot_running() else _warn("Не запустился — см. journalctl -u xray-tg-client")
            else:
                _menu_client_start(cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3" and configured and running:
            _menu_client_stop()
        elif ch == "4" and configured:
            _menu_client_invite(cfg)
        elif ch == "5" and configured:
            _menu_client_list_bindings()
        elif ch == "6" and configured:
            _menu_client_unbind()
        elif ch == "7" and configured:
            _menu_client_svc_status()
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_client_configure(cfg: dict) -> None:
    """Настройка токена и admin ID для клиентского бота."""
    os.system("clear")
    print()
    _box_top("🤖  Настройка клиентского бота")
    _box_desc(
        "Создайте НОВОГО бота через @BotFather (НЕ используйте тот же токен, что "
        "у admin-бота). Это гарантирует полную изоляцию: если клиентский бот "
        "утечёт — admin-бот продолжит работать. Admin ID нужен для крайнего "
        "случая (отладка); обычным пользователям он не виден."
    )
    _box_sep()
    cur_token   = cfg.get("token", "")
    cur_admin   = cfg.get("admin_id", "")
    cur_rate    = cfg.get("rate_limit_seconds", 2)
    if cur_token:
        _box_row(f"  Текущий токен:    {DIM}{cur_token[:10]}...{NC}")
    if cur_admin:
        _box_row(f"  Текущий admin ID: {CYAN}{cur_admin}{NC}")
    _box_row(f"  Rate-limit:       {CYAN}{cur_rate}{NC} сек/команда")
    _box_bottom()
    print()

    try:
        new_token = input(f"  Bot Token [{DIM}Enter = оставить{NC}]: ").strip()
        new_admin = input(f"  Admin Chat ID [{DIM}Enter = оставить{NC}]: ").strip()
        new_rate  = input(f"  Rate-limit секунд [{DIM}Enter = {cur_rate}{NC}]: ").strip()
    except KeyboardInterrupt:
        return

    if new_token:
        cfg["token"] = new_token
    if new_admin:
        cfg["admin_id"] = new_admin
    if new_rate.isdigit():
        cfg["rate_limit_seconds"] = int(new_rate)
    elif "rate_limit_seconds" not in cfg:
        cfg["rate_limit_seconds"] = 2

    if not cfg.get("token") or not cfg.get("admin_id"):
        _warn("Токен и Admin ID обязательны")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    client_bot_save(cfg)

    print()
    _info("Устанавливаю systemd-сервис xray-tg-client...")
    if install_client_bot_service(cfg):
        _ok("Клиентский бот запущен!")
        # Проверяем токен через getMe
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{cfg['token']}/getMe"
        ], capture=True)
        try:
            data = json.loads(r.stdout)
            if data.get("ok"):
                uname = data["result"].get("username", "")
                _ok(f"Бот: @{uname}")
                _box_top("📋  Готово!")
                _box_row(f"  Ссылка на бота: {CYAN}https://t.me/{uname}{NC}")
                _box_info("Теперь создайте invite-токен (пункт 4) и отправьте пользователю.")
                _box_bottom()
            else:
                _warn("Бот запущен, но токен может быть неверным")
        except Exception:
            _ok("Бот запущен (не удалось проверить токен)")
    else:
        _err("Бот не запустился — проверьте journalctl -u xray-tg-client")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_client_start(cfg: dict) -> None:
    _info("Запускаю клиентский бот...")
    if install_client_bot_service(cfg):
        _ok("Бот запущен")
    else:
        _err("Не удалось запустить — проверьте journalctl -u xray-tg-client")


def _menu_client_stop() -> None:
    try:
        ans = input(f"  {YELLOW}Остановить клиентский бот? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans == "y":
        stop_client_bot_service()
        _ok("Бот остановлен и удалён из автозапуска")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_client_invite(cfg: dict) -> None:
    """Создаёт invite-токен для конкретного VLESS-пользователя."""
    os.system("clear")
    print()
    users = _read_users()
    if not users:
        _warn("Нет пользователей в /etc/xray/users.json")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    _box_top("👥  Выберите пользователя для invite-токена")
    for i, u in enumerate(users, 1):
        email = u.get("email", "?")
        name  = u.get("name", "") or email.split("@")[0]
        disabled = u.get("disabled", False) or u.get("blocked", False)
        flag = f" {RED}(disabled/blocked){NC}" if disabled else ""
        _box_row(f"  {i}. {CYAN}{email}{NC} — {name}{flag}")
    _box_back()
    _box_bottom()
    try:
        raw = input(f"  Номер (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
    if not raw.isdigit() or not (1 <= int(raw) <= len(users)):
        return
    target = users[int(raw) - 1]
    email = target.get("email", "")
    if not email:
        _warn("У пользователя нет email")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    tok = issue_invite_token(email, admin_id=cfg.get("admin_id", ""))

    # Пытаемся узнать username бота
    bot_username = ""
    try:
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{cfg['token']}/getMe"
        ], capture=True)
        data = json.loads(r.stdout)
        if data.get("ok"):
            bot_username = data["result"].get("username", "")
    except Exception:
        pass

    print()
    _ok(f"Invite-токен создан для {email}")
    print()
    if bot_username:
        invite_link = f"https://t.me/{bot_username}?start={tok}"
        _box_top("📋  Invite-ссылка")
        _box_row(f"  {CYAN}{invite_link}{NC}")
        _box_info("Одноразовая — после использования помечается как used.")
        _box_info("Отправьте пользователю — он нажмёт и привяжется к своей учётке.")
        _box_bottom()
    else:
        _box_top("📋  Invite-токен")
        _box_row(f"  Токен: {CYAN}{tok}{NC}")
        _box_info("Пользователь должен написать боту: /start <токен>")
        _box_bottom()

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_client_list_bindings() -> None:
    """Показывает список привязок TG user_id -> VLESS user."""
    os.system("clear")
    print()
    mapping = client_map_load()
    _box_top("👥  Привязанные TG-аккаунты")
    if not mapping:
        _box_row(f"  {DIM}(пусто){NC}")
    else:
        for tg_id, info in mapping.items():
            email = info.get("email", "?")
            bound = info.get("bound_at", "")[:19]
            _box_row(f"  TG {CYAN}{tg_id}{NC} → {email}  {DIM}({bound}){NC}")
    _box_bottom()
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_client_unbind() -> None:
    """Отвязывает TG-аккаунт от VLESS-пользователя."""
    mapping = client_map_load()
    if not mapping:
        _warn("Нет привязанных аккаунтов")
        time.sleep(1)
        return
    print()
    _box_top("Отвязать TG-аккаунт")
    keys = list(mapping.keys())
    for i, k in enumerate(keys, 1):
        email = mapping[k].get("email", "?")
        _box_row(f"  {i}. TG {k} → {email}")
    _box_back()
    _box_bottom()
    try:
        raw = input(f"  Номер (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
    if raw.isdigit() and 1 <= int(raw) <= len(keys):
        removed = keys[int(raw) - 1]
        del mapping[removed]
        client_map_save(mapping)
        _ok(f"Отвязан: {removed}")
    time.sleep(1)


def _menu_client_svc_status() -> None:
    os.system("clear")
    print()
    _box_top("🔍  Статус сервиса xray-tg-client")
    _box_bottom()
    print()
    _run(["systemctl", "status", "xray-tg-client", "--no-pager", "-l"])
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ── Псевдонимы для обратной совместимости ────────────────────────────────────
__all__ = [
    "do_tg_client_bot_menu",
    "install_client_bot_service",
    "stop_client_bot_service",
    "regenerate_client_bot",
    "client_bot_running",
    "client_bot_load",
    "client_bot_save",
    "client_map_load",
    "client_map_save",
    "issue_invite_token",
    "bind_telegram_user",
    "lookup_user_by_tg_id",
    "format_status_message",
    "format_config_message",
    "format_qr_payload",
    "_consume_invite_token",
    "_is_user_blocked",
    "_ttl_is_expired",
    "_ttl_expires_str",
    "_get_user_traffic_info",
    "_format_bytes",
    "_progress_bar",
    "_generate_client_bot_script",
]
