"""
chimera/modules/tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Telegram Bot — единая точка для всего, что связано с Telegram в проекте.

Объединяет и заменяет разрозненные TG_CONFIG_FILE / _tg_load / _tg_save /
tg_send / _tg_notify_event / _tg_install_monitor_cron из _core.py.
В _core.py оставляем тонкие обёртки-делегаты (2 строки), которые
импортируют функции отсюда — обратная совместимость полная.

════════════════════════════════════════════════════════════════════════════════
ЧАСТЬ 1: Уведомления (admin-only, одностороннее)
  Текущая функциональность: xray_down/up, cert_expire, traffic_limit,
  health_report, node_down — всё сохранено без изменений.

ЧАСТЬ 2: Пользовательский бот (раздача конфигов)
  Пользователь пишет боту → получает свою ссылку/QR/конфиг.
  Поддерживает все режимы: A, B, B-Multi, REALITY, xHTTP.
  Работает как systemd-сервис (long-polling), никаких внешних зависимостей
  кроме python3 и curl (уже есть на сервере).

Команды бота:
  /start       — приветствие, список команд
  /config      — VLESS-ссылка для этого пользователя (если авторизован)
  /status      — статус сервера (только для admin chat_id)
  /users       — список пользователей (только admin)
  /help        — справка

Авторизация пользователей:
  Белый список Telegram user_id в tg_bot.json → "allowed_users": [123, 456]
  Или открытый режим: admin выдаёт одноразовый invite-токен через меню.
  Пользователь вводит /start <token> → добавляется в allowed_users.

Хранение:
  /var/lib/xray-installer/tg_bot.json   — конфиг бота
  /var/lib/xray-installer/telegram.json — конфиг уведомлений (совместимость)

Публичное API (обратная совместимость с _core.py):
  tg_load()                    → dict  (= _tg_load)
  tg_save(cfg)                          (= _tg_save)
  tg_send(msg, token, chat_id) → bool  (= tg_send)
  tg_notify_event(event, detail)        (= _tg_notify_event)
  do_manage_telegram()                  — меню уведомлений (как раньше)
  do_tg_bot_menu()                      — меню бота (новое)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
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
_NOTIF_FILE  = Path("/var/lib/xray-installer/telegram.json")   # уведомления (совместимость)
_BOT_FILE    = Path("/var/lib/xray-installer/tg_bot.json")     # бот
_STATE_FILE  = Path("/var/lib/xray-installer/state.json")
_LOG_FILE    = Path("/var/log/chimera.log")
_BOT_SVC     = Path("/etc/systemd/system/xray-tg-bot.service")
_BOT_SCRIPT  = Path("/usr/local/bin/xray-tg-bot.py")
_MONITOR_SVC = Path("/etc/cron.d/xray-tg-monitor")

# ── box_renderer ───────────────────────────────────────────────────────────────
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
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [TG] [{level}] {clean}\n")
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

# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 1: Уведомления — публичное API (обратная совместимость с _core.py)
# ══════════════════════════════════════════════════════════════════════════════

def tg_load() -> dict:
    """Загружает конфиг уведомлений. Совместим с _tg_load() из _core.py."""
    try:
        if _NOTIF_FILE.exists():
            return json.loads(_NOTIF_FILE.read_text())
    except Exception:
        pass
    return {}


def tg_save(cfg: dict) -> None:
    """Сохраняет конфиг уведомлений. Совместим с _tg_save() из _core.py."""
    _NOTIF_FILE.parent.mkdir(parents=True, exist_ok=True)
    _NOTIF_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _NOTIF_FILE.chmod(0o600)


def tg_send(msg: str, token: str = "", chat_id: str = "") -> bool:
    """
    Отправляет сообщение в Telegram через curl.
    Если token/chat_id не переданы — берёт из _NOTIF_FILE.
    Совместим с tg_send() из _core.py.

    Прокси: необязательный ключ "proxy" в telegram.json — curl -x
    (напр. "http://127.0.0.1:25181", локальный mieru-прокси; кейс
    RU-3 — хостовый инжектор рвёт прямые TG-потоки, 2026-10-08).
    """
    cfg = tg_load()
    if not token or not chat_id:
        token   = token or cfg.get("token", "")
        chat_id = chat_id or cfg.get("chat_id", "")
    if not token or not chat_id:
        return False
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "-m", "10"]
        proxy = str(cfg.get("proxy") or "").strip()
        if proxy:
            cmd += ["-x", proxy]
        cmd += [
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ]
        r = _run(cmd, capture=True)
        return r.stdout.strip() == "200"
    except Exception:
        return False


def tg_send_code(msg: str, token: str = "", chat_id: str = "") -> str:
    """Как tg_send, но возвращает HTTP-код ("200"/"000"/"401"/...) —
    для честной диагностики в меню (тест-отправка)."""
    cfg = tg_load()
    if not token or not chat_id:
        token   = token or cfg.get("token", "")
        chat_id = chat_id or cfg.get("chat_id", "")
    if not token or not chat_id:
        return "no-config"
    try:
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "-m", "10"]
        proxy = str(cfg.get("proxy") or "").strip()
        if proxy:
            cmd += ["-x", proxy]
        cmd += [
            f"https://api.telegram.org/bot{token}/sendMessage",
            "-d", f"chat_id={chat_id}",
            "-d", f"text={msg}",
            "-d", "parse_mode=HTML",
        ]
        r = _run(cmd, capture=True)
        return (r.stdout or "").strip() or "000"
    except Exception:
        return "000"


def tg_send_diag_msg(code: str) -> str:
    """Человекочитаемая причина ошибки тест-отправки по HTTP-коду."""
    return {
        "000": "нет связи с api.telegram.org (сеть/DPI/прокси — токен ни при чём;"
               " проверьте маршрут или задайте proxy в telegram.json)",
        "401": "токен неверён (отозван в BotFather?) — обновите токен",
        "400": "chat_id неверён (бот не найдёт диалог) — проверьте Chat ID",
        "403": "бот заблокирован пользователем или не может писать в чат",
        "404": "токен неверён (бот не существует) — обновите токен",
        "429": "слишком часто (flood limit) — повторите позже",
        "no-config": "не задан token/chat_id в telegram.json",
    }.get(code, f"HTTP {code} — см. документацию Telegram Bot API")


def tg_notify_event(event: str, detail: str = "") -> None:
    """
    Отправляет уведомление если соответствующее событие включено.
    Совместим с _tg_notify_event() из _core.py.

    Формат сообщения:
      {icon} [<hostname> | <server_ip>] {detail}
      <ts>

    IP берётся из telegram.json → 'server_ip' (если задан).
    Если server_ip пустой — показывается только hostname (обратная
    совместимость со старыми конфигами).
    """
    cfg = tg_load()
    if not cfg.get("token") or not cfg.get("chat_id"):
        return
    events = cfg.get("events", {})
    if not events.get(event, True):
        return
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass
    # IP-адрес сервера — берётся из telegram.json (поле server_ip,
    # задаётся администратором при настройке). Если пусто — не показываем.
    server_ip = cfg.get("server_ip", "")
    # Заголовок сервера: [hostname] или [hostname | ip] если есть IP
    if server_ip:
        header = f"[{hostname} | {server_ip}]"
    else:
        header = f"[{hostname}]"
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    icons = {
        "xray_down":     "🔴",
        "xray_up":       "🟢",
        "cert_expire":   "🔒",
        "traffic_limit": "⚠️",
        "user_connect":  "👤",
        "health_report": "📋",
        "node_down":     "📡",
        "port_blocked":  "🚫",
        "autoban":       "🚫",  # FIX-2 (2026-09-25): было 🛡️ — пользователь просил «перечёркнутый красный кружок»
        "port_hopping":  "⚡",
    }
    icon = icons.get(event, "ℹ️")
    text = f"{icon} <b>{header}</b> {detail}\n<i>{ts}</i>"
    tg_send(text)
    _log("INFO", f"TG notify: {event} — {detail}")


def _install_monitor_cron() -> None:
    """Устанавливает cron-скрипт мониторинга Xray (xray_down/up, cert).

    v2 (2026-10-02) — фикс инцидента со спамом cert-алертами:
      • токен/chat_id/server_ip больше НЕ запекаются в скрипт — читаются
        из telegram.json при каждом запуске (смена токена в меню [5][1]
        подхватывается без переустановки cron'а);
      • каждый send() проверяет флаг events.<event> — выключение события
        в меню [5]→[3] глушит соответствующий алерт немедленно. Раньше
        «Сертификат истекает через N дн.» летело при каждом запуске cron
        (каждые 5 минут = до 288 алертов/сутки), игнорируя выключенные
        алерты — источник «знатного» спама последнего месяца;
      • анти-спам cert-алерта: максимум 1 алерт в сутки (stamp-файл),
        сброс при продлении серта (>= 30 дней).
    """
    cfg = tg_load()
    token   = cfg.get("token", "")
    chat_id = cfg.get("chat_id", "")
    if not token or not chat_id:
        _warn("Сначала настройте токен и Chat ID")
        return

    script = Path("/usr/local/bin/xray-tg-monitor.sh")
    script.write_text(
        "#!/bin/bash\n"
        "# xray-tg-monitor (Chimera) — мониторинг Xray + срока сертификата\n"
        "# v2 (2026-10-02): TG-конфиг читается из telegram.json при каждом\n"
        "# запуске; каждый алерт проверяет events.<event>; cert — 1 алерт/сутки.\n"
        "STAMP_CERT=/var/lib/xray-installer/tg-cert-alert.stamp\n"
        "\n"
        "# send <event> <message> — плейсхолдер {H} заменяется на [host | ip]\n"
        "send() {\n"
        "  python3 -c '\n"
        "import json, socket, subprocess, sys\n"
        "from pathlib import Path\n"
        "event, msg = sys.argv[1], sys.argv[2].replace(\"\\\\n\", \"\\n\")\n"
        "try:\n"
        "    cfg = json.loads(Path(\"/var/lib/xray-installer/telegram.json\").read_text())\n"
        "    token, chat = cfg.get(\"token\"), cfg.get(\"chat_id\")\n"
        "    if not token or not chat:\n"
        "        sys.exit(0)\n"
        "    if event and not cfg.get(\"events\", {}).get(event, True):\n"
        "        sys.exit(0)\n"
        "    host = socket.gethostname().split(\".\")[0]\n"
        "    ip = cfg.get(\"server_ip\", \"\")\n"
        "    header = \"[{} | {}]\".format(host, ip) if ip else \"[{}]\".format(host)\n"
        "    proxy = (cfg.get(\"proxy\") or \"\").strip()\n"
        "    cmd = [\"curl\", \"-s\", \"-o\", \"/dev/null\", \"-m\", \"10\"]\n"
        "    if proxy:\n"
        "        cmd += [\"-x\", proxy]\n"
        "    cmd += [\n"
        "        \"https://api.telegram.org/bot\" + token + \"/sendMessage\",\n"
        "        \"-d\", \"chat_id=\" + chat,\n"
        "        \"-d\", \"text=\" + msg.replace(\"{H}\", header),\n"
        "        \"-d\", \"parse_mode=HTML\"]\n"
        "    subprocess.run(cmd, capture_output=True)\n"
        "except Exception:\n"
        "    pass\n"
        "' \"$1\" \"$2\"\n"
        "}\n"
        "\n"
        "TS=$(date '+%d.%m.%Y %H:%M')\n"
        "\n"
        "if ! systemctl is-active --quiet xray 2>/dev/null; then\n"
        "  STAMP=/tmp/xray-tg-down.stamp\n"
        "  if [ ! -f \"$STAMP\" ]; then touch \"$STAMP\";\n"
        "    send \"xray_down\" \"🔴 <b>{H}</b> Xray не запущен!\\n<i>$TS</i>\"; fi\n"
        "else\n"
        "  if [ -f /tmp/xray-tg-down.stamp ]; then rm -f /tmp/xray-tg-down.stamp;\n"
        "    send \"xray_up\" \"🟢 <b>{H}</b> Xray восстановился.\\n<i>$TS</i>\"; fi\n"
        "fi\n"
        "# Проверка срока сертификата (< 30 дней; анти-спам: 1 алерт в сутки)\n"
        "CERT=$(find /etc/letsencrypt/live -name 'cert.pem' 2>/dev/null | head -1)\n"
        "if [ -n \"$CERT\" ]; then\n"
        "  EXP=$(openssl x509 -enddate -noout -in \"$CERT\" 2>/dev/null | cut -d= -f2)\n"
        "  if [ -n \"$EXP\" ]; then\n"
        "    DAYS=$(( ( $(date -d \"$EXP\" +%s) - $(date +%s) ) / 86400 ))\n"
        "    if [ \"$DAYS\" -lt 30 ]; then\n"
        "      TAG=\"$(date '+%Y-%m-%d'):$DAYS\"\n"
        "      if [ \"$(cat \"$STAMP_CERT\" 2>/dev/null)\" != \"$TAG\" ]; then\n"
        "        echo \"$TAG\" > \"$STAMP_CERT\"\n"
        "        send \"cert_expire\" \"🔒 <b>{H}</b> Сертификат истекает через $DAYS дн.\\n<i>$TS</i>\"\n"
        "      fi\n"
        "    else\n"
        "      rm -f \"$STAMP_CERT\" 2>/dev/null\n"
        "    fi\n"
        "  fi\n"
        "fi\n"
    )
    script.chmod(0o755)

    _MONITOR_SVC.parent.mkdir(parents=True, exist_ok=True)
    _MONITOR_SVC.write_text(
        "# xray-tg-monitor — installed by vless-installer\n"
        f"*/5 * * * * root {script} 2>/dev/null\n"
    )
    _ok(f"Cron-мониторинг установлен: {script}")
    _log("INFO", "TG monitor cron installed (v2: events-aware, cert anti-spam)")


# ══════════════════════════════════════════════════════════════════════════════
#  ЧАСТЬ 2: Пользовательский бот — раздача конфигов
# ══════════════════════════════════════════════════════════════════════════════

def _bot_load() -> dict:
    try:
        if _BOT_FILE.exists():
            return json.loads(_BOT_FILE.read_text())
    except Exception:
        pass
    return {}


def _bot_save(cfg: dict) -> None:
    _BOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    _BOT_FILE.chmod(0o600)


def _bot_running() -> bool:
    """Проверяет, запущен ли systemd-сервис бота."""
    r = _run(["systemctl", "is-active", "--quiet", "xray-tg-bot"], quiet=False)
    return r.returncode == 0


def _load_state() -> dict:
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text())
    except Exception:
        pass
    return {}


def _get_vless_link(user_uuid: Optional[str] = None) -> str:
    """
    Формирует VLESS-ссылку из state.json.
    Поддерживает все режимы: A, B, B-Multi, REALITY, xHTTP.
    user_uuid — если задан, подставляется вместо основного UUID (для мультипользователей).
    """
    state = _load_state()
    domain       = state.get("domain", "")
    port         = state.get("server_port", 443)
    uuid_val     = user_uuid or state.get("uuid", "")
    proto        = state.get("protocol_mode", "reality")
    pub_key      = state.get("public_key", "")
    short_id     = state.get("short_id", "")
    fp           = state.get("fingerprint", "chrome") or "chrome"
    xtls_flow    = state.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path   = state.get("xhttp_path", "/")
    xhttp_mode   = state.get("xhttp_mode", "stream-up")
    install_mode = state.get("install_mode", "A")
    awg_exit     = state.get("awg_exit_enabled", False)

    # SNI: для режима B с AWG — используем reality_dest, иначе domain.
    # xhttp_reality наследует правило REALITY (те же ключи/dest маскировки).
    sni = domain
    if proto in ("reality", "xhttp_reality") and awg_exit and install_mode == "B":
        sni = state.get("reality_dest", domain).split(":")[0]

    if not domain or not uuid_val:
        return ""

    if proto == "xhttp_reality":
        # xHTTP + REALITY: транспорт xhttp + маскировка REALITY.
        # security=reality, type=xhttp, БЕЗ flow (xhttp-транспорт не
        # поддерживает xtls-rprx-vision). pbk/sid — как у reality-ветки,
        # path/mode — как у xhttp-ветки.
        from urllib.parse import quote as _uq
        path_enc = _uq(xhttp_path, safe="/")
        link = (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?encryption=none&security=reality&sni={sni}"
            f"&fp={fp}&pbk={pub_key}&sid={short_id}"
            f"&type=xhttp&path={path_enc}&mode={xhttp_mode}#VLESS-xHTTP-REALITY"
        )
    elif proto == "xhttp":
        link = (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=xhttp&security=tls&path={xhttp_path}"
            f"&sni={sni}&fp={fp}#VLESS-xHTTP"
        )
    else:
        flow_part = f"&flow={xtls_flow}" if xtls_flow else ""
        link = (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=tcp&security=reality"
            f"&pbk={pub_key}&sid={short_id}&sni={sni}&fp={fp}"
            f"{flow_part}#VLESS-REALITY"
        )
    return link


def _get_server_status_text() -> str:
    """Формирует текст статуса сервера для отправки в бот."""
    state = _load_state()
    hostname = ""
    try:
        hostname = _run(["hostname", "-s"], capture=True).stdout.strip()
    except Exception:
        pass

    # Статус Xray
    r = _run(["systemctl", "is-active", "xray"], capture=True)
    xray_status = "🟢 запущен" if r.stdout.strip() == "active" else "🔴 не запущен"

    # Аптайм
    uptime_str = ""
    try:
        r2 = _run(["uptime", "-p"], capture=True)
        uptime_str = r2.stdout.strip()
    except Exception:
        pass

    lines = [
        f"📊 <b>Статус сервера [{hostname}]</b>",
        f"",
        f"Xray: {xray_status}",
        f"Протокол: {state.get('protocol_mode', '?').upper()}",
        f"Порт: {state.get('server_port', '?')}",
        f"Режим: {state.get('install_mode', '?')}",
    ]
    if uptime_str:
        lines.append(f"Аптайм: {uptime_str}")
    lines.append(f"\n<i>{datetime.now().strftime('%d.%m.%Y %H:%M')}</i>")
    return "\n".join(lines)


def _generate_bot_script(bot_cfg: dict, notif_cfg: dict) -> str:
    """
    Генерирует Python-скрипт бота (long-polling, без внешних зависимостей).
    Скрипт запускается как systemd-сервис.

    Опциональное поле bot_cfg['cascade_peers']: список удалённых серверов
    для multi-server /status через SSH. Формат:
        [
            {"host": "203.0.113.103", "user": "root", "port": 22,
             "name": "Server 2", "sudo": false},
            {"host": "203.0.113.102", "user": "inferno1978", "port": 22,
             "name": "Server 3", "sudo": true},
            ...
        ]
    Если cascade_peers задан и непустой — /status собирает сводку со всех
    серверов через SSH (нужен passwordless SSH-ключ на этом сервере к каждому
    peer). Если cascade_peers пустой/отсутствует — /status работает как
    раньше (только локальный статус текущего сервера).
    """
    token        = json.dumps(bot_cfg.get("token") or notif_cfg.get("token", ""), ensure_ascii=False)
    admin_id     = json.dumps(str(bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")), ensure_ascii=False)
    allowed      = json.dumps(bot_cfg.get("allowed_users", []), ensure_ascii=False)
    invite_tokens = json.dumps(bot_cfg.get("invite_tokens", {}), ensure_ascii=False)
    # NOTE: для cascade_peers используем repr() а не json.dumps(), потому что
    # в Python значения True/False (а в JSON — true/false). repr() даёт
    # валидный Python-литерал.
    cascade_peers = repr(bot_cfg.get("cascade_peers", []))
    # Локальные метаданные для primary-сервера (этот сервер). Выводятся в
    # /status перед локальным hostname, чтобы было видно какой это сервер.
    local_name = repr(bot_cfg.get("local_name", ""))
    local_ip   = repr(bot_cfg.get("local_ip", ""))
    state_file   = str(_STATE_FILE)
    bot_file     = str(_BOT_FILE)

    script = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# xray-tg-bot — auto-generated by vless-installer
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерируется из меню установщика

import json, os, sys, time, re, subprocess, urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime

# IPv4-first (инцидент 08.10.2026, RU-2): мёртвый IPv6-маршрут убивал
# urllib-поллинг (Errno 101 Network is unreachable) — urllib, в отличие
# от curl, не умеет happy-eyeballs. Принудительно предпочитаем A-записи;
# если их нет — прежний резолв (поведение не меняется).
import socket as _socket
_gai_orig = _socket.getaddrinfo
def _gai_ipv4_first(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _gai_orig(host, port, _socket.AF_INET,
                         type or _socket.SOCK_STREAM, proto, flags)
    except Exception:
        return _gai_orig(host, port, family, type, proto, flags)
_socket.getaddrinfo = _gai_ipv4_first

TOKEN    = {token}
ADMIN_ID = {admin_id}
CASCADE_PEERS = {cascade_peers}
LOCAL_NAME = {local_name}
LOCAL_IP   = {local_ip}
BOT_FILE = Path("{bot_file}")
STATE_F  = Path("{state_file}")
LOG_F    = Path("/var/log/chimera.log")
OFFSET   = 0

def _log(msg):
    try:
        with LOG_F.open("a") as f:
            f.write(f"[{{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}] [BOT] {{msg}}\\n")
    except Exception:
        pass

def _bot_load():
    try:
        return json.loads(BOT_FILE.read_text()) if BOT_FILE.exists() else {{}}
    except Exception:
        return {{}}

def _bot_save(cfg):
    BOT_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    BOT_FILE.chmod(0o600)

def _state():
    try:
        return json.loads(STATE_F.read_text()) if STATE_F.exists() else {{}}
    except Exception:
        return {{}}

def api(method, **params):
    """Вызов Telegram Bot API через urllib (нет зависимостей).

    Прокси: необязательный ключ "proxy" в telegram.json — urllib
    ProxyHandler (CONNECT для https). Ключа нет → напрямую.
    """
    url = f"https://api.telegram.org/bot{{TOKEN}}/{{method}}"
    data = urllib.parse.urlencode(params).encode()
    try:
        _tgp = Path("/var/lib/xray-installer/telegram.json")
        _pc = json.loads(_tgp.read_text()) if _tgp.exists() else {{}}
        _px = str(_pc.get("proxy") or "").strip()
    except Exception:
        _px = ""
    # Ретраи: локальный mieru-прокси транзиентно рвёт отдельные запросы
    # (замер 08.10.2026, RU-2: ~1 разрыв на 2-3 мин поллинга) — один
    # разрыв не должен стоить потерянного сообщения/команды.
    for _att in range(1, 4):
        try:
            req = urllib.request.Request(url, data=data)
            if _px:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({{"https": _px, "http": _px}}))
                resp = opener.open(req, timeout=30)
            else:
                resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except Exception as e:
            _log(f"API error {{method}} (попытка {{_att}}/3): {{e}}")
            if _att < 3:
                time.sleep(2)
    return {{}}

def send(chat_id, text, parse_mode="HTML"):
    api("sendMessage", chat_id=chat_id, text=text, parse_mode=parse_mode)

def is_admin(uid):
    return str(uid) == ADMIN_ID

def is_allowed(uid):
    cfg = _bot_load()
    allowed = cfg.get("allowed_users", [])
    return str(uid) in [str(x) for x in allowed] or is_admin(uid)

def get_vless_link(user_uuid=None):
    st = _state()
    domain    = st.get("domain", "")
    port      = st.get("server_port", 443)
    uuid_val  = user_uuid or st.get("uuid", "")
    proto     = st.get("protocol_mode", "reality")
    pub_key   = st.get("public_key", "")
    short_id  = st.get("short_id", "")
    fp        = st.get("fingerprint", "chrome") or "chrome"
    xtls_flow = st.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path = st.get("xhttp_path", "/")
    xhttp_mode = st.get("xhttp_mode", "stream-up")
    awg_exit  = st.get("awg_exit_enabled", False)
    mode      = st.get("install_mode", "A")
    # SNI: для режима B с AWG — reality_dest (xhttp_reality наследует
    # правило REALITY — те же ключи/dest маскировки), иначе domain.
    sni = domain
    if proto in ("reality", "xhttp_reality") and awg_exit and mode == "B":
        sni = st.get("reality_dest", domain).split(":")[0]
    if not domain or not uuid_val:
        return ""
    if proto == "xhttp_reality":
        # xHTTP + REALITY: security=reality + type=xhttp, БЕЗ flow
        # (xhttp-транспорт не поддерживает xtls-rprx-vision).
        path_enc = urllib.parse.quote(xhttp_path, safe="/")
        return (f"vless://{{uuid_val}}@{{domain}}:{{port}}"
                f"?encryption=none&security=reality&sni={{sni}}"
                f"&fp={{fp}}&pbk={{pub_key}}&sid={{short_id}}"
                f"&type=xhttp&path={{path_enc}}&mode={{xhttp_mode}}#VLESS-xHTTP-REALITY")
    if proto == "xhttp":
        return (f"vless://{{uuid_val}}@{{domain}}:{{port}}"
                f"?type=xhttp&security=tls&path={{xhttp_path}}"
                f"&sni={{sni}}&fp={{fp}}#VLESS-xHTTP")
    flow_part = f"&flow={{xtls_flow}}" if xtls_flow else ""
    return (f"vless://{{uuid_val}}@{{domain}}:{{port}}"
            f"?type=tcp&security=reality"
            f"&pbk={{pub_key}}&sid={{short_id}}&sni={{sni}}&fp={{fp}}"
            f"{{flow_part}}#VLESS-REALITY")

def get_status_text():
    st = _state()
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "server"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True)
        xs = "🟢 запущен" if r.stdout.strip() == "active" else "🔴 не запущен"
    except Exception:
        xs = "❓ неизвестно"
    try:
        up = subprocess.check_output(["uptime", "-p"], text=True).strip()
    except Exception:
        up = ""
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    return (f"📊 <b>Статус [{{host}}]</b>\\n\\n"
            f"Xray: {{xs}}\\n"
            f"Протокол: {{st.get('protocol_mode','?').upper()}}\\n"
            f"Порт: {{st.get('server_port','?')}}\\n"
            f"Режим: {{st.get('install_mode','?')}}\\n"
            + (f"Аптайм: {{up}}\\n" if up else "") +
            f"\\n<i>{{ts}}</i>")

def _local_status_dict():
    """Собирает локальный статус в dict (для агрегации с remote)."""
    st = _state()
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "localhost"
    try:
        r = subprocess.run(["systemctl", "is-active", "xray"],
                           capture_output=True, text=True, timeout=5)
        xray_status = r.stdout.strip()
    except Exception:
        xray_status = "unknown"
    try:
        up = subprocess.check_output(["uptime", "-p"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        up = ""
    d = {{
        "host":     host,
        # Локальные метаданные из bot_cfg — используются в выводе
        "name":     LOCAL_NAME or host,
        "ip":       LOCAL_IP,
        "xray":     xray_status,
        "proto":    st.get("protocol_mode", "?"),
        "port":     st.get("server_port", "?"),
        "mode":     st.get("install_mode", "?"),
        "uptime":   up,
        "local":    True,
    }}
    # Mieru-каскад (Entry): mita + Exit-ы + живость health-тика.
    # Поля добавляются только при настроенном каскаде (старые peers
    # без mieru-полей просто не показывают сегмент — обратная совместимость).
    try:
        mcs = json.loads(Path("/var/lib/xray-installer/mieru_cascade.json").read_text())
        exits = [e for e in mcs.get("exits", []) if e.get("enabled", True)]
        if mcs.get("role") == "entry" and exits:
            n_ok = sum(1 for e in exits if e.get("healthy"))
            try:
                r2 = subprocess.run(["systemctl", "is-active", "mita"],
                                    capture_output=True, text=True, timeout=5)
                mita = r2.stdout.strip() or "unknown"
            except Exception:
                mita = "unknown"
            newest = 0.0
            for e in exits:
                v = e.get("last_check", "")
                try:
                    import datetime as _dt
                    ts = _dt.datetime.strptime(str(v), "%Y-%m-%d %H:%M:%S").timestamp()
                    newest = max(newest, ts)
                except Exception:
                    pass
            stalled = newest and (time.time() - newest > 300)
            d["mieru"] = {{"ok": n_ok, "total": len(exits), "mita": mita,
                           "stalled": bool(stalled)}}
    except Exception:
        pass
    return d

def _remote_status_dict(peer):
    """Получает статус с удалённого сервера через SSH.

    peer = dict с ключами host, user, port, name, sudo (bool).
    Удалённый сервер должен иметь /usr/local/bin/chimera-remote-status.py
    (этот скрипт деплоится chimera-setup).

    Возвращает dict (при успехе) или dict с ключом 'error' (при ошибке).
    """
    host = peer.get("host", "")
    user = peer.get("user", "root")
    port = peer.get("port", 22)
    name = peer.get("name", host)
    use_sudo = peer.get("sudo", False)

    # SSH target (user@host or just host if root)
    ssh_target = f"{{user}}@{{host}}" if user != "root" else host

    # Build ssh argv list. We invoke /usr/local/bin/chimera-remote-status.py
    # on remote — no shell-interpolation issues, just one path argument.
    # If use_sudo (non-root SSH user with sudo NOPASSWD) — prefix with sudo -n.
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        ssh_target,
    ]
    if use_sudo:
        ssh_cmd.extend(["sudo", "-n", "/usr/local/bin/chimera-remote-status.py"])
    else:
        ssh_cmd.extend(["/usr/local/bin/chimera-remote-status.py"])

    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return {{"error": f"exit={{r.returncode}}: {{r.stderr.strip()[:80]}}"}}
        out = r.stdout.strip()
        # Output is single JSON line (chimera-remote-status.py:print(json.dumps(...)))
        try:
            data = json.loads(out.split("\\n")[-1])
            data["name"] = name
            data["ip"] = host  # IP peer (peer["host"])
            data["local"] = False
            return data
        except Exception:
            # Fallback — maybe stderr warnings pollute stdout
            for line in out.split("\\n"):
                line = line.strip()
                if line.startswith("{{"):
                    try:
                        data = json.loads(line)
                        data["name"] = name
                        data["ip"] = host
                        data["local"] = False
                        return data
                    except Exception:
                        continue
            return {{"error": f"parse fail: {{out[:80]}}"}}
    except subprocess.TimeoutExpired:
        return {{"error": "timeout (>20s)"}}
    except Exception as e:
        return {{"error": str(e)[:80]}}



def get_status_text_all():
    """Агрегированный статус: локальный + все cascade_peers через SSH.

    Возвращает HTML-сообщение со списком всех серверов.
    """
    ts = datetime.now().strftime("%d.%m.%Y %H:%M")
    lines = [f"📊 <b>Статус каскада ({{ts}})</b>\\n"]

    # Локальный статус (этот сервер)
    local = _local_status_dict()
    lines.append(_format_status_line(local, is_first=True))

    # Remote peers
    for peer in CASCADE_PEERS:
        name = peer.get("name", peer.get("host", "?"))
        r = _remote_status_dict(peer)
        if "error" in r:
            # ошибка remote: показываем peer name + peer IP + причину
            peer_ip = peer.get("host", "?")
            lines.append(f"\\n• <b>{{name}}</b> ({{peer_ip}}): ❌ {{r['error']}}")
        else:
            lines.append(_format_status_line(r, is_first=False))

    return "\\n".join(lines)

def _format_status_line(d, is_first=False):
    """Форматирует dict статуса в HTML-строку.

    Формат:  • <name> (<host>) — <ip>
                🟢 Xray=active | REALITY:443 | М=B | Апт: up X days
    """
    if "error" in d:
        ip = d.get("ip", "")
        ip_part = f" — {{ip}}" if ip else ""
        return f"• <b>{{d.get('name', '?')}}</b> ({{d.get('host', '?')}}){{ip_part}}: ❌ {{d['error']}}"
    host = d.get("host", "?")
    # name: для local используем LOCAL_NAME (или host если пусто),
    # для remote — peer["name"] (или host если пусто)
    name = d.get("name") or host
    ip = d.get("ip", "")
    ip_part = f" — <code>{{ip}}</code>" if ip else ""
    xray = d.get("xray", "?")
    xray_emoji = "🟢" if xray == "active" else "🔴" if xray in ("inactive", "failed") else "❓"
    proto = str(d.get("proto", "?")).upper()
    port = d.get("port", "?")
    mode = d.get("mode", "?")
    up = d.get("uptime", "")
    up_str = f" | Апт: {{up}}" if up else ""
    # Mieru-каскад: сегмент только если сервер отдал mieru-поля
    # (старые chimera-remote-status.py без mieru — просто нет ключа).
    mi = d.get("mieru")
    mieru_str = ""
    if isinstance(mi, dict):
        ok, total = mi.get("ok", 0), mi.get("total", 0)
        mark = "✓" if (total > 0 and ok == total) else ("⚠️" if ok > 0 else "✗")
        mieru_str = f" | 🧅 Mieru: {{ok}}/{{total}} {{mark}}"
        if mi.get("mita") not in (None, "active"):
            mieru_str += " [mita ✗]"
        if mi.get("stalled"):
            mieru_str += " [tick ✗]"
    return (f"• <b>{{name}}</b> ({{host}}){{ip_part}}\\n"
            f"   {{xray_emoji}} Xray={{xray}} | {{proto}}:{{port}} | М={{mode}}{{mieru_str}}{{up_str}}")


def get_users_text():
    """Список пользователей Xray (из config.json)."""
    cfg_paths = [
        Path("/usr/local/etc/xray/config.json"),
        Path("/etc/xray/config.json"),
    ]
    for p in cfg_paths:
        if p.exists():
            try:
                cfg = json.loads(p.read_text())
                users = []
                for ib in cfg.get("inbounds", []):
                    for client in ib.get("settings", {{}}).get("clients", []):
                        email = client.get("email", "—")
                        uid   = client.get("id", "")[:8] + "..."
                        users.append(f"  • {{email}}  <code>{{uid}}</code>")
                if users:
                    return "👥 <b>Пользователи:</b>\\n" + "\\n".join(users)
            except Exception:
                pass
    return "Список пользователей недоступен"

def handle_start(msg, args):
    uid  = msg["from"]["id"]
    uname = msg["from"].get("username", str(uid))
    cfg = _bot_load()

    # Invite-токен
    if args:
        token_val = args[0]
        invites = cfg.get("invite_tokens", {{}})
        if token_val in invites:
            allowed = cfg.get("allowed_users", [])
            if uid not in allowed:
                allowed.append(uid)
                cfg["allowed_users"] = allowed
            del invites[token_val]
            cfg["invite_tokens"] = invites
            _bot_save(cfg)
            send(uid, f"✅ Вы авторизованы! Используйте /config для получения ссылки.")
            _log(f"User @{{uname}} ({{uid}}) authorized via invite token")
            return

    if is_admin(uid):
        send(uid, (
            "👋 <b>VLESS Admin Bot</b>\\n\\n"
            "<b>Быстрый старт:</b>\\n"
            "/menu   — inline-клавиатура с кнопками\\n"
            "/help   — расширенная справка по всем командам\\n"
            "/status — статус каскада со всех серверов\\n\\n"
            "<b>Самые популярные:</b>\\n"
            "/config        — ваша VLESS-ссылка\\n"
            "/users         — список пользователей\\n"
            "/ban &lt;ip&gt;      — забанить IP вручную\\n"
            "/restart &lt;svc&gt; — перезапуск сервиса\\n"
            "/logs [svc]    — последние строки лога\\n"
            "/cert          — статус сертификатов\\n\\n"
            f"Сервер: <code>{{LOCAL_NAME or 'primary'}}</code> ({{LOCAL_IP or '?'}})"
        ))
    elif is_allowed(uid):
        send(uid, "👋 Привет! Используйте /config для получения вашей ссылки.")
    else:
        send(uid, (
            "👋 Для доступа запросите у администратора invite-ссылку.\\n"
            f"Ваш ID: <code>{{uid}}</code>"
        ))

def handle_config(msg):
    uid = msg["from"]["id"]
    if not is_allowed(uid):
        send(uid, "⛔ Нет доступа. Запросите invite-ссылку у администратора.")
        return
    link = get_vless_link()
    if not link:
        send(uid, "⚠️ Сервер ещё не настроен или конфиг недоступен.")
        return
    send(uid, (
        f"🔗 <b>Ваша VLESS-ссылка:</b>\\n\\n"
        f"<code>{{link}}</code>\\n\\n"
        f"Скопируйте и импортируйте в NekoBox / v2rayNG / Happ."
    ))
    _log(f"Config sent to user {{uid}}")

def handle_status(msg):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    # FIX: если cascade_peers задан — /status возвращает агрегированную сводку
    # со всех серверов (через SSH). Иначе — старый локальный /status.
    if CASCADE_PEERS:
        send(uid, get_status_text_all())
    else:
        send(uid, get_status_text())

def handle_status_local(msg):
    """Локальный статус текущего сервера — без агрегации."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    send(uid, get_status_text())

# ══════════════════════════════════════════════════════════════════════════════
#  НОВЫЕ ADMIN-КОМАНДЫ (v6+):
#    /restart /reload_nginx /logs /health
#    /ban /unban /banlist /whitelist /wl_add /wl_del
#    /geo /geo_toggle /f2b_status
#    /traffic /traffic_top /user /reset_user /users_active
#    /nodes /probe /cert /version /menu
# ══════════════════════════════════════════════════════════════════════════════

# Список сервисов, которые можно перезапускать через /restart
# (whitelist — безопасные. Никаких shutdown/reboot/systemctl poweroff).
ALLOWED_RESTART_SERVICES = {{
    "xray":         ("systemctl", "restart", "xray"),
    "nginx":        ("systemctl", "restart", "nginx"),
    "dnscrypt":     ("systemctl", "restart", "dnscrypt-proxy"),
    "agh":          ("systemctl", "restart", "AdGuardHome"),
    "adguardhome":  ("systemctl", "restart", "AdGuardHome"),
    "fail2ban":     ("systemctl", "restart", "fail2ban"),
    "warp":         ("systemctl", "restart", "wg-quick@wg-warp"),
}}

LOG_PATHS = {{
    "xray":     "/var/log/xray/error.log",
    "xray_acc": "/var/log/xray/access.log",
    "nginx":    "/var/log/nginx/error.log",
    "nginx_acc":"/var/log/nginx/access.log",
    "chimera":  "/var/log/chimera.log",
    "fail2ban": "/var/log/fail2ban.log",
    "dnscrypt": "/var/log/dnscrypt-proxy.log",
    "system":   "/var/log/syslog",
}}

def _validate_ip(ip_str):
    """Валидация IPv4. Возвращает True/False."""
    import re
    return bool(re.match(r"^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$", ip_str))

# ══════════════════════════════════════════════════════════════════════════════
#  CASCADE EXEC HELPERS — для каскадного выполнения команд на peer'ах
#  через SSH + chimera-remote-cmd.py
# ══════════════════════════════════════════════════════════════════════════════

# Whitelist команд которые можно выполнять каскадно (через chimera-remote-cmd.py)
# На peer'ах — единственный executor. Локально (на primary) — handle_* функции
# с той же логикой, для скорости (без subprocess overhead).
CASCADE_REMOTE_COMMANDS = {{
    "ban", "unban", "banlist", "whitelist", "wl_add", "wl_del",
    "geo", "f2b", "restart", "reload_nginx", "logs",
    "users", "users_active", "user", "traffic", "status", "version",
}}

def _parse_server_arg(args):
    """Парсит опциональный последний аргумент [server].

    Возвращает (args_without_server, server_target) где:
    - server_target: None/'local' (primary), '1'/'2'/'3' (peer), 'all' (cascade)
    - args_without_server: список аргументов без последнего server-маркера

    Примеры:
        ['1.2.3.4']             → (['1.2.3.4'], None)
        ['1.2.3.4', 'all']      → (['1.2.3.4'], 'all')
        ['1.2.3.4', '2']        → (['1.2.3.4'], '2')
        ['xray']                → (['xray'], None)
        ['xray', '3']           → (['xray'], '3')
        ['nginx', '50', 'all']  → (['nginx', '50'], 'all')
    """
    if not args:
        return args, None
    last = args[-1].lower()
    if last in ("all", "1", "2", "3", "local"):
        return args[:-1], last
    return args, None


def _exec_remote_via_ssh(peer, command, *cmd_args):
    """Выполняет chimera-remote-cmd.py на peer через SSH.

    peer: dict с host/user/port/sudo (CASCADE_PEERS)
    command: имя команды ('ban', 'unban', 'restart', etc.)
    cmd_args: tuple аргументов команды

    Возвращает: dict {{"ok": bool, "output": str}} (формат chimera-remote-cmd.py)
    или {{"ok": False, "output": "<error>"}} при ошибке SSH.
    """
    host = peer.get("host", "")
    user = peer.get("user", "root")
    port = peer.get("port", 22)
    use_sudo = peer.get("sudo", False)
    ssh_target = f"{{user}}@{{host}}" if user != "root" else host

    # Build argv for chimera-remote-cmd.py on remote
    remote_argv = ["/usr/local/bin/chimera-remote-cmd.py", command] + [str(a) for a in cmd_args]

    # Build ssh command argv (no shell-interpolation)
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
        ssh_target,
    ]
    if use_sudo:
        ssh_cmd.extend(["sudo", "-n"] + remote_argv)
    else:
        ssh_cmd.extend(remote_argv)

    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return {{"ok": False, "output": f"SSH exit={{r.returncode}}: {{r.stderr.strip()[:200]}}"}}
        out = r.stdout.strip()
        # Try to parse as JSON (chimera-remote-cmd.py returns single JSON line)
        try:
            return json.loads(out.split("\\n")[-1])
        except Exception:
            return {{"ok": False, "output": f"parse fail: {{out[:200]}}"}}
    except subprocess.TimeoutExpired:
        return {{"ok": False, "output": "timeout (>20s)"}}
    except Exception as e:
        return {{"ok": False, "output": str(e)[:100]}}


def _exec_cascade(server_target, command, *cmd_args):
    """Выполняет command с cmd_args на указанном сервере (или на всех).

    server_target: None/'local'/'1' (primary), '2'/'3' (peer), 'all' (cascade)
    command: имя команды для chimera-remote-cmd.py
    cmd_args: tuple аргументов команды

    Возвращает: список tuples [(server_name, result_dict), ...]
    """
    results = []

    # Primary (local execution через chimera-remote-cmd.py на primary)
    if server_target in (None, "local", "1", "all"):
        primary_name = LOCAL_NAME or "primary"
        # Execute locally
        try:
            local_argv = ["/usr/local/bin/chimera-remote-cmd.py", command] + [str(a) for a in cmd_args]
            r = subprocess.run(local_argv, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                try:
                    result = json.loads(r.stdout.strip().split("\\n")[-1])
                except Exception:
                    result = {{"ok": False, "output": f"parse fail: {{r.stdout.strip()[:200]}}"}}
            else:
                result = {{"ok": False, "output": f"local exit={{r.returncode}}: {{r.stderr.strip()[:200]}}"}}
        except Exception as e:
            result = {{"ok": False, "output": str(e)[:100]}}
        results.append((primary_name, result))
        if server_target in (None, "local", "1"):
            return results  # only primary

    # Remote peers
    if server_target == "all":
        for peer in CASCADE_PEERS:
            peer_name = peer.get("name", peer.get("host", "?"))
            result = _exec_remote_via_ssh(peer, command, *cmd_args)
            results.append((peer_name, result))
    elif server_target in ("2", "3"):
        # Нумерация peers в CASCADE_PEERS: '2' = peer[0], '3' = peer[1]
        peer_idx = int(server_target) - 2
        if peer_idx < 0 or peer_idx >= len(CASCADE_PEERS):
            return [(f"server{{server_target}}", {{"ok": False, "output": f"no peer with number {{server_target}}"}})]
        peer = CASCADE_PEERS[peer_idx]
        peer_name = peer.get("name", peer.get("host", "?"))
        result = _exec_remote_via_ssh(peer, command, *cmd_args)
        results.append((peer_name, result))

    return results


def _format_cascade_results(results, command_intro=""):
    """Форматирует список [(server_name, result_dict), ...] в HTML-сообщение."""
    lines = []
    if command_intro:
        lines.append(command_intro)
        lines.append("")
    for server_name, result in results:
        ok = result.get("ok", False)
        output = result.get("output", "(no output)")
        # Truncate output to keep message within Telegram 4096 limit
        if len(output) > 1000:
            output = "..." + output[-1000:]
        emoji = "✅" if ok else "❌"
        lines.append(f"{{emoji}} <b>{{server_name}}</b>")
        # Output may be multiline — wrap each line with indent
        for out_line in output.split("\\n"):
            lines.append(f"   <code>{{out_line}}</code>")
        lines.append("")
    return "\\n".join(lines)



def handle_ban(msg, args):
    """Ручной бан IP в xray_manual_ban ipset. /ban <ip> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    # Парсим [server] из args
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server or not _validate_ip(args_no_server[0]):
        send(uid, "Использование: <code>/ban &lt;ip&gt; [1|2|3|all|local]</code>\\n"
                  "Например: <code>/ban 1.2.3.4</code> (primary), <code>/ban 1.2.3.4 all</code> (cascade)")
        return
    ip = args_no_server[0]
    # Execute on target(s)
    results = _exec_cascade(server_target, "ban", ip)
    intro = f"🛡️ <b>Ban {{ip}}</b>" + (f" (cascade)" if server_target == "all" else
            (f" (server {{server_target}})" if server_target else ""))
    send(uid, _format_cascade_results(results, intro))
    # Audit log
    target_str = server_target or "local"
    _log(f"Ban {{ip}} on {{target_str}} by admin {{uid}}: result={{results[0][1].get('ok') if results else 'no_result'}}")


def handle_unban(msg, args):
    """Разбан IP. /unban <ip> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server or not _validate_ip(args_no_server[0]):
        send(uid, "Использование: <code>/unban &lt;ip&gt; [1|2|3|all|local]</code>")
        return
    ip = args_no_server[0]
    results = _exec_cascade(server_target, "unban", ip)
    intro = f"✅ <b>Unban {{ip}}</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))
    _log(f"Unban {{ip}} on {{server_target or 'local'}} by admin {{uid}}")


def handle_banlist(msg, args=None):
    """Список забаненных IP. /banlist [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "banlist")
    intro = "📋 <b>Ban list</b>" + (f" (cascade)" if server_target == "all" else
            (f" (server {{server_target}})" if server_target else " (primary)"))
    send(uid, _format_cascade_results(results, intro))


def handle_whitelist(msg, args=None):
    """Список whitelist IP. /whitelist [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "whitelist")
    intro = "📋 <b>Whitelist</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_wl_add(msg, args):
    """Добавить IP в whitelist. /wl_add <ip> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server or not _validate_ip(args_no_server[0]):
        send(uid, "Использование: <code>/wl_add &lt;ip&gt; [1|2|3|all|local]</code>")
        return
    ip = args_no_server[0]
    results = _exec_cascade(server_target, "wl_add", ip)
    intro = f"✅ <b>WL add {{ip}}</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))
    _log(f"WL add {{ip}} on {{server_target or 'local'}} by admin {{uid}}")


def handle_wl_del(msg, args):
    """Удалить IP из whitelist. /wl_del <ip> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server or not _validate_ip(args_no_server[0]):
        send(uid, "Использование: <code>/wl_del &lt;ip&gt; [1|2|3|all|local]</code>")
        return
    ip = args_no_server[0]
    results = _exec_cascade(server_target, "wl_del", ip)
    intro = f"✅ <b>WL del {{ip}}</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))
    _log(f"WL del {{ip}} on {{server_target or 'local'}} by admin {{uid}}")


def handle_geo(msg, args=None):
    """Статус ingress GeoIP-блокировки. /geo [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "geo")
    intro = "🌍 <b>GeoIP</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_geo_toggle(msg):
    """Вкл/выкл ingress GeoIP-блокировку (ОТКЛЮЧЕНО из TG)."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    send(uid, "⚠️ Toggle ingress GeoIP — это потенциально опасная операция.\\n"
              "Используйте chimera TUI на сервере: Меню → Управление GeoIP → [3] Toggle.\\n"
              "Из Telegram эта команда отключена в целях безопасности.")
    _log(f"Geo toggle requested by admin {{uid}} — denied (use TUI)")


def handle_f2b(msg, args=None):
    """Статус fail2ban + список забаненных. /f2b [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "f2b")
    intro = "🛡️ <b>fail2ban</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_traffic(msg, args):
    """Топ пользователей по трафику. /traffic [n] [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    n = "10"
    if args_no_server and args_no_server[0].isdigit():
        n = str(min(int(args_no_server[0]), 50))
    results = _exec_cascade(server_target, "traffic", n)
    intro = f"📊 <b>Traffic top {{n}}</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_traffic_top(msg):
    """Алиас к /traffic 20."""
    handle_traffic(msg, ["20"])


def handle_users(msg, args=None):
    """Список пользователей Xray. /users [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "users")
    intro = "👥 <b>Users</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_users_active(msg, args=None):
    """Активные пользователи за последний час. /users_active [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "users_active")
    intro = "👥 <b>Active users</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_user(msg, args):
    """Детальная инфа по пользователю. /user <email> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server:
        send(uid, "Использование: <code>/user &lt;email&gt; [1|2|3|all|local]</code>")
        return
    email = args_no_server[0]
    results = _exec_cascade(server_target, "user", email)
    intro = f"👤 <b>{{email}}</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_reset_user(msg, args):
    """Сброс трафик-счётчика (отключено из TG)."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    if not args:
        send(uid, "Использование: <code>/reset_user &lt;email&gt;</code>")
        return
    email = args[0]
    send(uid, f"⚠️ Сброс трафика для <code>{{email}}</code> — требует chimera TUI.\\n"
              f"Из Telegram отключено в целях безопасности. Используйте: Меню → Управление пользователями → Сброс трафика.")
    _log(f"Reset user {{email}} requested by admin {{uid}} — denied (use TUI)")


def handle_restart(msg, args):
    """Перезапуск сервиса. /restart <service> [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    if not args_no_server:
        send(uid, "Использование: <code>/restart &lt;service&gt; [1|2|3|all|local]</code>\\n"
                  f"Доступные: <code>{{', '.join(sorted(ALLOWED_RESTART_SERVICES.keys()))}}</code>")
        return
    svc = args_no_server[0].lower()
    if svc not in ALLOWED_RESTART_SERVICES:
        send(uid, f"❌ Неизвестный сервис: <code>{{svc}}</code>\\n"
                  f"Доступные: <code>{{', '.join(sorted(ALLOWED_RESTART_SERVICES.keys()))}}</code>")
        return
    results = _exec_cascade(server_target, "restart", svc)
    intro = f"🔄 <b>Restart {{svc}}</b>" + (f" (cascade)" if server_target == "all" else
            (f" (server {{server_target}})" if server_target else ""))
    send(uid, _format_cascade_results(results, intro))
    _log(f"Restart {{svc}} on {{server_target or 'local'}} by admin {{uid}}")


def handle_reload_nginx(msg, args=None):
    """Мягкий reload nginx. /reload_nginx [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args or [])
    results = _exec_cascade(server_target, "reload_nginx")
    intro = "🔄 <b>nginx reload</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))
    _log(f"Nginx reload on {{server_target or 'local'}} by admin {{uid}}")


def handle_logs(msg, args):
    """Последние строки лога. /logs [service] [n] [1|2|3|all|local]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    args_no_server, server_target = _parse_server_arg(args)
    service = args_no_server[0].lower() if args_no_server else "xray"
    n_lines = 20
    if len(args_no_server) > 1 and args_no_server[1].isdigit():
        n_lines = min(int(args_no_server[1]), 100)
    if service not in LOG_PATHS:
        send(uid, f"❌ Неизвестный лог: <code>{{service}}</code>\\n"
                  f"Доступные: <code>{{', '.join(sorted(LOG_PATHS.keys()))}}</code>")
        return
    results = _exec_cascade(server_target, "logs", service, n_lines)
    intro = f"📄 <b>Logs {{service}} {{n_lines}} lines</b>" + (f" (cascade)" if server_target == "all" else "")
    send(uid, _format_cascade_results(results, intro))


def handle_health(msg):
    """Запускает chimera diagnostics и возвращает summary (primary-only)."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    send(uid, "⏳ Запускаю диагностику... (может занять до 30 сек)")
    try:
        r = subprocess.run(
            ["python3", "-c",
             "import sys; sys.path.insert(0, '/opt/chimera'); "
             "from chimera.modules.diagnostics import run_split_tunnel_diagnostics; "
             "import io, contextlib; "
             "buf = io.StringIO(); "
             "contextlib.redirect_stdout(buf).__enter__(); "
             "run_split_tunnel_diagnostics(); "
             "print(buf.getvalue()[-3000:])"],
            capture_output=True, text=True, timeout=60
        )
        if r.returncode == 0:
            content = r.stdout.strip() or "(diagnostics returned no output)"
            if len(content) > 3800:
                content = "..." + content[-3800:]
            send(uid, f"📋 <b>Chimera Diagnostics</b>\\n\\n<code>{{content}}</code>")
        else:
            send(uid, f"❌ Diagnostics error (exit={{r.returncode}}):\\n<code>{{r.stderr.strip()[:300]}}</code>")
    except subprocess.TimeoutExpired:
        send(uid, "⚠️ Диагностика превысила 60 сек — возможно зависла")
    except Exception as e:
        send(uid, f"❌ Ошибка: {{str(e)[:100]}}")

def handle_nodes(msg):
    """Список exit-нод каскада + TCP-ping. /nodes"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    st = _state()
    nodes = st.get("chain_nodes", [])
    if not nodes and st.get("chain_exit_host"):
        nodes = [{{"host": st["chain_exit_host"], "port": st.get("chain_exit_port", 443),
                "sni": st.get("chain_exit_sni", "")}}]
    if not nodes:
        send(uid, "❌ Exit-ноды не настроены (не Режим B?)")
        return
    text_lines = [f"🔗 <b>Exit-ноды каскада</b> ({{len(nodes)}} шт)\\n"]
    for i, nd in enumerate(nodes, 1):
        host = nd.get("host", "?")
        port = nd.get("port", 443)
        sni = nd.get("sni", "")
        # TCP-ping
        try:
            r = subprocess.run(["timeout", "5", "bash", "-c",
                                f"echo > /dev/tcp/{{host}}/{{port}}"],
                               capture_output=True, text=True, timeout=6)
            status = "🟢 up" if r.returncode == 0 else "🔴 down"
        except Exception:
            status = "❓"
        text_lines.append(f"<b>Нода #{{i}}</b>: {{status}}\\n"
                          f"  Host: <code>{{host}}</code>:{{port}}\\n"
                          f"  SNI: <code>{{sni}}</code>")
    send(uid, "\\n".join(text_lines))


def handle_probe(msg, args):
    """TCP-ping до произвольного IP/port. /probe <ip> [port]"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    if not args:
        send(uid, "Использование: <code>/probe &lt;ip/host&gt; [port]</code>\\nНапример: <code>/probe 8.8.8.8 443</code>")
        return
    host = args[0]
    port = args[1] if len(args) > 1 and args[1].isdigit() else "443"
    try:
        r = subprocess.run(["timeout", "5", "bash", "-c",
                            f"echo > /dev/tcp/{{host}}/{{port}}"],
                           capture_output=True, text=True, timeout=6)
        if r.returncode == 0:
            send(uid, f"🟢 <code>{{host}}:{{port}}</code> — TCP достижим (5s timeout)")
        else:
            send(uid, f"🔴 <code>{{host}}:{{port}}</code> — недостижим (timeout или отказ)")
    except Exception as e:
        send(uid, f"❌ {{str(e)[:80]}}")


def handle_cert(msg):
    """Статус TLS-сертификатов на всех 3 серверах. /cert"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    text_lines = ["🔒 <b>Сертификаты TLS</b>\\n"]
    # Local cert
    try:
        cert_path = next(Path("/etc/letsencrypt/live").glob("*/cert.pem"), None)
        if cert_path:
            r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", str(cert_path)],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                exp_date = r.stdout.split("=")[-1].strip()
                r2 = subprocess.run(["bash", "-c",
                                     f"days=$((( $(date -d '{{exp_date}}' +%s) - $(date +%s) ) / 86400)); echo $days"],
                                    capture_output=True, text=True, timeout=10)
                days = r2.stdout.strip()
                emoji = "🟢" if int(days) > 30 else "🔴" if int(days) > 0 else "💀"
                text_lines.append(f"<b>Server 1 ({{LOCAL_NAME or 'local'}})</b>\\n  {{emoji}} истекает {{exp_date}} ({{days}} дн.)\\n")
        else:
            text_lines.append("<b>Server 1</b>\\n  ⚠️ сертификат не найден\\n")
    except Exception as e:
        text_lines.append(f"<b>Server 1</b>\\n  ❌ ошибка: {{str(e)[:60]}}\\n")
    # Remote certs via SSH
    for peer in CASCADE_PEERS:
        name = peer.get("name", peer.get("host", "?"))
        host = peer.get("host", "")
        use_sudo = peer.get("sudo", False)
        ssh_target = f"{{peer.get('user','root')}}@{{host}}" if peer.get("user","root") != "root" else host
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                   "-o", "ConnectTimeout=10", "-p", str(peer.get("port", 22)), ssh_target]
        cmd = "openssl x509 -enddate -noout -in $(ls /etc/letsencrypt/live/*/cert.pem 2>/dev/null | head -1) 2>/dev/null"
        if use_sudo:
            ssh_cmd.extend(["sudo", "-n", "bash", "-c", cmd])
        else:
            ssh_cmd.extend(["bash", "-c", cmd])
        try:
            r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                exp_date = r.stdout.split("=")[-1].strip()
                r2 = subprocess.run(["bash", "-c",
                                     f"days=$((( $(date -d '{{exp_date}}' +%s) - $(date +%s) ) / 86400)); echo $days"],
                                    capture_output=True, text=True, timeout=10)
                days = r2.stdout.strip() or "?"
                try:
                    d_int = int(days)
                    emoji = "🟢" if d_int > 30 else "🔴" if d_int > 0 else "💀"
                except Exception:
                    emoji = "❓"
                text_lines.append(f"<b>{{name}}</b> ({{host}})\\n  {{emoji}} истекает {{exp_date}} ({{days}} дн.)\\n")
            else:
                text_lines.append(f"<b>{{name}}</b> ({{host}})\\n  ⚠️ не найден\\n")
        except Exception as e:
            text_lines.append(f"<b>{{name}}</b> ({{host}})\\n  ❌ ошибка: {{str(e)[:60]}}\\n")
    send(uid, "\\n".join(text_lines))


def handle_version(msg):
    """Версия chimera + последний коммит + uptime бота. /version"""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    try:
        r = subprocess.run(["git", "-C", "/opt/chimera", "log", "--oneline", "-1"],
                           capture_output=True, text=True, timeout=10)
        commit = r.stdout.strip() if r.returncode == 0 else "??"
    except Exception:
        commit = "??"
    try:
        host = subprocess.check_output(["hostname", "-s"], text=True).strip()
    except Exception:
        host = "?"
    send(uid, f"📋 <b>Chimera version</b>\\n\\n"
              f"Git commit: <code>{{commit}}</code>\\n"
              f"Host: <code>{{host}}</code>\\n"
              f"Local: <code>{{LOCAL_NAME}}</code> ({{LOCAL_IP}})\\n"
              f"Cascade peers: <code>{{len(CASCADE_PEERS)}}</code>")


def handle_menu(msg):
    """Inline-клавиатура с кнопками для всех admin-команд."""
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    keyboard = {{
        "inline_keyboard": [
            [{{"text": "📊 Статус каскада", "callback_data": "/status"}}],
            [{{"text": "👥 Пользователи", "callback_data": "/users"}},
             {{"text": "🛡️ Бан-лист", "callback_data": "/banlist"}}],
            [{{"text": "🔒 Сертификаты", "callback_data": "/cert"}},
             {{"text": "📋 Версия", "callback_data": "/version"}}],
            [{{"text": "🌍 Geo-IP", "callback_data": "/geo"}},
             {{"text": "🛡️ fail2ban", "callback_data": "/f2b"}}],
            [{{"text": "🔗 Ноды", "callback_data": "/nodes"}},
             {{"text": "🚦 Трафик", "callback_data": "/traffic"}}],
            [{{"text": "🔄 Restart menu", "callback_data": "/restart"}}],
            [{{"text": "❓ Помощь", "callback_data": "/help"}}],
        ]
    }}
    api("sendMessage", chat_id=str(uid),
        text="🎛️ <b>Admin menu</b>\\n\\nВыберите команду:",
        parse_mode="HTML",
        reply_markup=json.dumps(keyboard))


def handle_invite(msg):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    cfg = _bot_load()
    invites = cfg.get("invite_tokens", {{}})
    import secrets as _sec
    tok = _sec.token_urlsafe(12)
    invites[tok] = {{"created": datetime.now().isoformat(), "by": uid}}
    cfg["invite_tokens"] = invites
    _bot_save(cfg)
    bot_info = api("getMe")
    bot_username = bot_info.get("result", {{}}).get("username", "YOUR_BOT")
    invite_link = f"https://t.me/{{bot_username}}?start={{tok}}"
    send(uid, (
        f"🔑 <b>Invite-ссылка создана:</b>\\n\\n"
        f"<code>{{invite_link}}</code>\\n\\n"
        f"Одноразовая. Отправьте пользователю."
    ))
    _log(f"Invite token created by admin {{uid}}: {{tok}}")

def handle_broadcast(msg, args):
    uid = msg["from"]["id"]
    if not is_admin(uid):
        send(uid, "⛔ Только для администратора.")
        return
    if not args:
        send(uid, "Использование: /broadcast текст сообщения")
        return
    text = " ".join(args)
    cfg = _bot_load()
    allowed = cfg.get("allowed_users", [])
    ok = 0
    for u in allowed:
        try:
            send(u, f"📢 <b>Сообщение от администратора:</b>\\n\\n{{text}}")
            ok += 1
            time.sleep(0.05)
        except Exception:
            pass
    send(uid, f"✅ Разослано {{ok}} из {{len(allowed)}} пользователей.")
    _log(f"Broadcast by admin {{uid}}: {{text[:50]}}")

def handle_help(msg):
    uid = msg["from"]["id"]
    # Basic help for non-admin users
    base = (
        "📖 <b>Справка</b>\\n\\n"
        "/start  — начало работы\\n"
        "/config — получить VLESS-ссылку\\n"
        "/help   — эта справка\\n"
    )
    if not is_admin(uid):
        send(uid, base)
        return
    # Extended admin help — grouped by category
    text = (
        "📖 <b>Admin Help — справка</b>\\n\\n"
        "<b>📋 Базовые команды</b>\\n"
        "/start            — приветствие + список команд\\n"
        "/config           — ваша VLESS-ссылка\\n"
        "/help             — эта справка\\n"
        "/menu             — inline-клавиатура с кнопками для всех команд\\n"
        "\\n<b>📊 Статус и мониторинг</b>\\n"
        "/status           — агрегированный статус всех серверов каскада (через SSH)\\n"
        "/status_local     — статус только текущего сервера\\n"
        "/health           — запустить chimera diagnostics (11 проверок)\\n"
        "/version          — версия chimera + последний git commit\\n"
        "/cert             — статус TLS-сертификатов на всех серверах\\n"
        "\\n<b>👥 Пользователи</b>\\n"
        "/users [N]        — список пользователей Xray (N=1|2|3|all — на каком сервере)\\n"
        "/users_active [N] — активные за последний час\\n"
        "/user &lt;email&gt; [N]   — детальная инфа (UUID, TTL, лимит)\\n"
        "/reset_user &lt;email&gt; — сброс трафик-счётчика (требует TUI)\\n"
        "/traffic [n] [N]  — топ-N по подключениям (дефолт 10)\\n"
        "/traffic_top [N]  — алиас для /traffic 20\\n"
        "/invite           — создать одноразовую invite-ссылку\\n"
        "/broadcast &lt;текст&gt; — рассылка всем привязанным пользователям\\n"
        "\\n<b>🛡️ Бан-лист и whitelist</b>\\n"
        "/ban &lt;ip&gt; [N]    — ручной бан IP (N=all → на всех серверах)\\n"
        "/unban &lt;ip&gt; [N]  — разбан IP\\n"
        "/banlist [N]      — список забаненных IP\\n"
        "/whitelist [N]    — список whitelist IP (clients_wl)\\n"
        "/wl_add &lt;ip&gt; [N] — добавить IP в whitelist (защита от autoban)\\n"
        "/wl_del &lt;ip&gt; [N] — удалить IP из whitelist\\n"
        "\\n<b>🌍 GeoIP и fail2ban</b>\\n"
        "/geo [N]          — статус ingress GeoIP-блокировки\\n"
        "/geo_toggle       — переключить (отключено из TG — используйте TUI)\\n"
        "/f2b [N]          — статус fail2ban + список banned по jail'ам\\n"
        "\\n<b>🔗 Каскад и ноды</b>\\n"
        "/nodes            — список exit-нод каскада + TCP-ping до каждой\\n"
        "/probe &lt;ip/host&gt; [port] — TCP-ping до произвольного адреса (дефолт 443)\\n"
        "\\n<b>🔄 Управление сервисами</b>\\n"
        "/restart &lt;service&gt; [N] — перезапуск (xray/nginx/dnscrypt/agh/fail2ban/warp)\\n"
        "/reload_nginx [N] — мягкий reload nginx без обрыва соединений\\n"
        "/logs [service] [n] [N] — последние N строк лога (дефолт xray, 20)\\n"
        "                     services: xray, xray_acc, nginx, nginx_acc, chimera, fail2ban, dnscrypt, system\\n"
        "\\n<b>🎯 Каскадное выполнение (опциональный последний аргумент N)</b>\\n"
        "  <code>N=1</code>     — только primary (по умолчанию)\\n"
        "  <code>N=2</code>     — server 2 (через SSH к cascade_peers[0])\\n"
        "  <code>N=3</code>     — server 3 (через SSH к cascade_peers[1])\\n"
        "  <code>N=all</code>   — на ВСЕХ серверах (cascade)\\n"
        "  <code>N=local</code> — то же что N=1\\n\\n"
        "  Примеры:\\n"
        "  <code>/ban 1.2.3.4 all</code>     — бан на всех 3 серверах\\n"
        "  <code>/restart xray 2</code>      — restart xray на server 2\\n"
        "  <code>/logs nginx 50 all</code>   — логи nginx со всех 3\\n"
        "  <code>/users 2</code>             — пользователи server 2\\n"
        "\\n<i>Команды выполняются на текущем (primary) сервере: {{LOCAL_NAME or 'localhost'}}</i>\\n"
        "<i>Если нужен статус с других серверов каскада — используйте /status</i>"
    )
    send(uid, text)

def process_update(update):
    msg = update.get("message") or update.get("edited_message")
    if not msg or "text" not in msg:
        # Check for callback_query (inline keyboard button press)
        cb = update.get("callback_query")
        if cb:
            handle_callback_query(cb)
        return
    text  = msg["text"].strip()
    parts = text.split()
    cmd   = parts[0].split("@")[0].lower() if parts else ""
    args  = parts[1:]
    # Existing commands
    if cmd == "/start":   handle_start(msg, args)
    elif cmd == "/config": handle_config(msg)
    elif cmd == "/status": handle_status(msg)
    elif cmd == "/status_local": handle_status_local(msg)
    elif cmd == "/users":  handle_users(msg)
    elif cmd == "/invite": handle_invite(msg)
    elif cmd == "/broadcast": handle_broadcast(msg, args)
    elif cmd == "/help":   handle_help(msg)
    # New: server management
    elif cmd == "/restart":      handle_restart(msg, args)
    elif cmd == "/reload_nginx": handle_reload_nginx(msg)
    elif cmd == "/logs":        handle_logs(msg, args)
    elif cmd == "/health":       handle_health(msg)
    # New: ban/whitelist
    elif cmd == "/ban":          handle_ban(msg, args)
    elif cmd == "/unban":        handle_unban(msg, args)
    elif cmd == "/banlist":      handle_banlist(msg)
    elif cmd == "/whitelist":    handle_whitelist(msg)
    elif cmd == "/wl_add":       handle_wl_add(msg, args)
    elif cmd == "/wl_del":       handle_wl_del(msg, args)
    # New: geo/f2b
    elif cmd == "/geo":          handle_geo(msg)
    elif cmd == "/geo_toggle":   handle_geo_toggle(msg)
    elif cmd == "/f2b":          handle_f2b(msg)
    elif cmd == "/f2b_status":   handle_f2b(msg)
    # New: traffic/users
    elif cmd == "/traffic":      handle_traffic(msg, args)
    elif cmd == "/traffic_top":  handle_traffic_top(msg)
    elif cmd == "/user":         handle_user(msg, args)
    elif cmd == "/reset_user":   handle_reset_user(msg, args)
    elif cmd == "/users_active": handle_users_active(msg)
    # New: cascade/nodes
    elif cmd == "/nodes":        handle_nodes(msg)
    elif cmd == "/probe":        handle_probe(msg, args)
    elif cmd == "/cert":         handle_cert(msg)
    elif cmd == "/version":      handle_version(msg)
    # New: convenience
    elif cmd == "/menu":         handle_menu(msg)

def handle_callback_query(cb):
    """Обрабатывает нажатия inline-кнопок (из /menu).

    Callback data — это имя команды (например "/status"). Нажатие кнопки
    эмулирует выполнение этой команды от имени пользователя.
    """
    cb_data = cb.get("data", "")
    cb_id   = cb.get("id", "")
    cb_from = cb.get("from", {{}})
    # Construct a fake msg with from.id = cb.from.id, so handlers see admin id
    fake_msg = {{
        "from": cb_from,
        "text": cb_data,
    }}
    # Answer the callback (removes the loading spinner)
    api("answerCallbackQuery", callback_query_id=cb_id)
    # Re-dispatch through process_update with a fake message
    # Strip leading "/" from callback_data and re-add to match the cmd format
    parts = cb_data.split()
    cmd = parts[0].split("@")[0].lower() if parts else ""
    args = parts[1:]
    if cmd == "/start":   handle_start(fake_msg, args)
    elif cmd == "/config": handle_config(fake_msg)
    elif cmd == "/status": handle_status(fake_msg)
    elif cmd == "/status_local": handle_status_local(fake_msg)
    elif cmd == "/users":  handle_users(fake_msg)
    elif cmd == "/invite": handle_invite(fake_msg)
    elif cmd == "/broadcast": handle_broadcast(fake_msg, args)
    elif cmd == "/help":   handle_help(fake_msg)
    elif cmd == "/restart":      handle_restart(fake_msg, args)
    elif cmd == "/reload_nginx": handle_reload_nginx(fake_msg)
    elif cmd == "/logs":        handle_logs(fake_msg, args)
    elif cmd == "/health":       handle_health(fake_msg)
    elif cmd == "/ban":          handle_ban(fake_msg, args)
    elif cmd == "/unban":        handle_unban(fake_msg, args)
    elif cmd == "/banlist":      handle_banlist(fake_msg)
    elif cmd == "/whitelist":    handle_whitelist(fake_msg)
    elif cmd == "/wl_add":       handle_wl_add(fake_msg, args)
    elif cmd == "/wl_del":       handle_wl_del(fake_msg, args)
    elif cmd == "/geo":          handle_geo(fake_msg)
    elif cmd == "/geo_toggle":   handle_geo_toggle(fake_msg)
    elif cmd == "/f2b":          handle_f2b(fake_msg)
    elif cmd == "/f2b_status":   handle_f2b(fake_msg)
    elif cmd == "/traffic":      handle_traffic(fake_msg, args)
    elif cmd == "/traffic_top":  handle_traffic_top(fake_msg)
    elif cmd == "/user":         handle_user(fake_msg, args)
    elif cmd == "/reset_user":   handle_reset_user(fake_msg, args)
    elif cmd == "/users_active": handle_users_active(fake_msg)
    elif cmd == "/nodes":        handle_nodes(fake_msg)
    elif cmd == "/probe":        handle_probe(fake_msg, args)
    elif cmd == "/cert":         handle_cert(fake_msg)
    elif cmd == "/version":      handle_version(fake_msg)
    elif cmd == "/menu":         handle_menu(fake_msg)

def main():
    global OFFSET
    _log("Bot started")
    fail_count = 0
    while True:
        try:
            r = api("getUpdates", offset=OFFSET, timeout=25, limit=10)
            # api() гасит исключения сама и при ошибке возвращает {{}} —
            # поэтому проверяем результат явно, а не полагаемся на except
            # ниже (иначе при недоступности сети, например блокировке
            # Telegram на РФ-адресе entry-ноды или упавшем WARP/AWG
            # туннеле, цикл крутится без задержки и заливает лог тысячами
            # одинаковых строк в минуту).
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

    # Применяем патч fingerprint-команд (/fp, /setfp)
    try:
        from chimera.modules.user_fp_manager import patch_tg_bot_script
        return patch_tg_bot_script(script)
    except Exception:
        return script


def _install_bot_service(bot_cfg: dict) -> bool:
    """Устанавливает systemd-сервис для бота."""
    notif_cfg = tg_load()
    script_content = _generate_bot_script(bot_cfg, notif_cfg)

    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)

    svc = (
        "[Unit]\n"
        "Description=VLESS Telegram Config Bot\n"
        "After=network.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/python3 /usr/local/bin/xray-tg-bot.py\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _BOT_SVC.write_text(svc)
    _run(["systemctl", "daemon-reload"], quiet=True)
    _run(["systemctl", "enable", "xray-tg-bot"], quiet=True)
    r = _run(["systemctl", "restart", "xray-tg-bot"])
    time.sleep(2)
    return _bot_running()


def _stop_bot_service() -> None:
    _run(["systemctl", "stop", "xray-tg-bot"], quiet=True)
    _run(["systemctl", "disable", "xray-tg-bot"], quiet=True)
    _BOT_SCRIPT.unlink(missing_ok=True)
    _BOT_SVC.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], quiet=True)


def _regenerate_bot() -> bool:
    """Перегенерирует скрипт бота (после смены токена/пользователей)."""
    bot_cfg  = _bot_load()
    notif_cfg = tg_load()
    if not (bot_cfg.get("token") or notif_cfg.get("token")):
        return False
    script_content = _generate_bot_script(bot_cfg, notif_cfg)
    _BOT_SCRIPT.write_text(script_content)
    _BOT_SCRIPT.chmod(0o700)
    if _bot_running():
        _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
        time.sleep(1)
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Уведомления (оригинальная функциональность, без изменений интерфейса)
# ══════════════════════════════════════════════════════════════════════════════

def do_manage_telegram() -> None:
    """Меню настройки Telegram-уведомлений. Совместим с _core.py."""
    while True:
        os.system("clear")
        cfg = tg_load()
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
        events  = cfg.get("events", {})
        configured = bool(token and chat_id)

        # event_labels определён здесь — доступен во всех ветках ch
        event_labels = {
            "xray_down":    "Xray упал / не отвечает",
            "xray_up":      "Xray восстановился",
            "cert_expire":  "Сертификат истекает (< 30 дней)",
            "traffic_limit":"Трафик пользователя превысил лимит",
            "health_report":"Ежедневный health-отчёт (08:00)",
            "node_down":    "Exit-нода недоступна",
            "port_blocked": "Порт недоступен (ТСПУ/firewall/knocking)",
            "autoban":      "AutoBan — IP забанен автоматически",
            # mieru-каскад (mieru_cascade_monitor.py; добавляются в
            # telegram.json при первом toggle, отсутствующий = ВКЛ)
            "mieru_down":     "Mieru: mita упал",
            "mieru_up":       "Mieru: mita восстановился",
            "mieru_exit_down": "Mieru: Exit недоступен (2+ фейла)",
            "mieru_exit_up":  "Mieru: Exit восстановился",
            "mieru_no_exits": "Mieru: все Exit-ы недоступны",
            "mieru_stalled":  "Mieru: health-tick не обновляется",
            # b4 ops-слой (b4_monitor.py; отсутствующий ключ = ВКЛ)
            "b4_down":        "B4: сервис упал",
            "b4_up":          "B4: сервис восстановился",
            "b4_degraded":    "B4: прямой путь деградировал",
            "b4_recovered":   "B4: прямой путь восстановился",
            "b4_stalled":     "B4: health-tick не обновляется",
            "b4_restarted":   "B4: рестарт (self-heal)",
            "b4_discovery":   "B4: запущен Discovery (ремедия)",
            "b4_preset":      "B4: ротация пресета (ремедия)",
            "b4_exempt_empty": "B4: ipset exempt пуст",
            "b4_exempt_ok":   "B4: ipset exempt заполнен",
            # CPU Steal монитор (steal_monitor.py; отсутствующий ключ = ВКЛ)
            "steal_report":   "Steal: дневной отчёт (оверселл)",
            "steal_alert":    "Steal: критический всплеск",
        }

        print()
        _box_top("🔔  Telegram-уведомления (admin)")
        _box_row(f"  Статус:  {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:   {DIM}{token[:10]}...{NC}")
            _box_row(f"  Chat ID: {CYAN}{chat_id}{NC}")
            _box_row(f"  {BOLD}Включённые события:{NC}")
            for ev, label in event_labels.items():
                en = events.get(ev, True)
                col = GREEN if en else DIM
                _box_row(f"    {col}{'✓' if en else '✗'}{NC} {label}")
        _box_sep()
        _box_item("1", f"{'Изменить' if configured else 'Настроить'} токен и Chat ID")
        _box_item("2", "Тест — отправить тестовое сообщение")
        _box_item("3", "Включить/выключить отдельные события")
        _box_item("4", "Установить cron-мониторинг Xray")
        _box_item("5", f"{RED}Отключить уведомления{NC} (удалить конфиг)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            print()
            new_token = input(f"  Bot Token (Enter = оставить): ").strip()
            if new_token:
                cfg["token"] = new_token
            new_chat = input(f"  Chat ID (Enter = оставить): ").strip()
            if new_chat:
                cfg["chat_id"] = new_chat
            if "events" not in cfg:
                cfg["events"] = {k: True for k in event_labels}
            tg_save(cfg)
            # Перегенерируем бот-скрипт если он настроен
            _regenerate_bot()
            _ok("Конфиг сохранён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if not cfg.get("token") or not cfg.get("chat_id"):
                _warn("Сначала настройте токен и Chat ID [1]")
            else:
                _info("Отправка тестового сообщения...")
                ok = tg_send(
                    "✅ <b>VLESS Installer</b>: тестовое сообщение. Уведомления работают!",
                    cfg["token"], cfg["chat_id"]
                )
                _ok("Сообщение отправлено!") if ok else _warn("Ошибка — проверьте токен и chat_id")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            ev_keys = ["xray_down","xray_up","cert_expire","traffic_limit",
                       "health_report","node_down","port_blocked","autoban",
                       "mieru_down","mieru_up","mieru_exit_down",
                       "mieru_exit_up","mieru_no_exits","mieru_stalled",
                       "b4_down","b4_up","b4_degraded","b4_recovered",
                       "b4_stalled","b4_restarted","b4_discovery",
                       "b4_preset","b4_exempt_empty","b4_exempt_ok",
                       "steal_report","steal_alert"]
            ev_labels = [
                "Xray упал","Xray восстановился","Сертификат истекает",
                "Лимит трафика","Daily health-отчёт","Exit-нода недоступна",
                "Порт недоступен (ТСПУ/firewall/knocking)","AutoBan — IP забанен",
                "Mieru: mita упал","Mieru: mita восстановился",
                "Mieru: Exit недоступен","Mieru: Exit восстановился",
                "Mieru: все Exit-ы недоступны","Mieru: health-tick не обновляется",
                "B4: сервис упал","B4: сервис восстановился",
                "B4: прямой путь деградировал","B4: прямой путь восстановился",
                "B4: health-tick не обновляется","B4: рестарт (self-heal)",
                "B4: запущен Discovery (ремедия)","B4: ротация пресета (ремедия)",
                "B4: ipset exempt пуст","B4: ipset exempt заполнен",
                "Steal: дневной отчёт (оверселл)","Steal: критический всплеск",
            ]
            events = cfg.get("events", {k: True for k in ev_keys})
            print()
            _box_top("Уведомления — вкл/выкл событий")
            for i, (k, lbl) in enumerate(zip(ev_keys, ev_labels), 1):
                en = events.get(k, True)
                _box_item(f"{i}", f"{''+GREEN+'[ВКЛ]'+NC if en else ''+DIM+'[ВЫКЛ]'+NC} {lbl}")
            _box_back()
            _box_bottom()
            raw = input("  Номер для переключения (Enter = выход): ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(ev_keys):
                k = ev_keys[int(raw)-1]
                events[k] = not events.get(k, True)
                cfg["events"] = events
                tg_save(cfg)
                _ok(f"{'Включено' if events[k] else 'Выключено'}: {ev_labels[int(raw)-1]}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            _install_monitor_cron()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "5":
            try:
                ans = input(f"  {RED}Удалить конфиг уведомлений? [y/N]:{NC} ").strip().lower()
            except KeyboardInterrupt:
                continue
            if ans == "y":
                _NOTIF_FILE.unlink(missing_ok=True)
                Path("/etc/cron.d/xray-tg-monitor").unlink(missing_ok=True)
                Path("/usr/local/bin/xray-tg-monitor.sh").unlink(missing_ok=True)
                _ok("Конфиг уведомлений удалён")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)

# ══════════════════════════════════════════════════════════════════════════════
#  МЕНЮ: Пользовательский бот
# ══════════════════════════════════════════════════════════════════════════════

def do_tg_bot_menu() -> None:
    """Меню управления Telegram Config Bot."""

    while True:
        os.system("clear")
        bot_cfg   = _bot_load()
        notif_cfg = tg_load()
        running   = _bot_running()

        # Токен может быть в bot_cfg или взят из notif_cfg
        token     = bot_cfg.get("token") or notif_cfg.get("token", "")
        admin_id  = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
        allowed   = bot_cfg.get("allowed_users", [])
        invites   = bot_cfg.get("invite_tokens", {})

        configured = bool(token and admin_id)

        print()
        _box_top("🤖  TELEGRAM CONFIG BOT — раздача конфигов пользователям")
        _box_desc(
            "Пользователь пишет боту /config → получает свою VLESS-ссылку. "
            "Администратор управляет доступом через invite-токены."
        )
        _box_sep()
        _box_row(f"  Статус бота:      {''+GREEN+'ЗАПУЩЕН'+NC if running else ''+DIM+'ОСТАНОВЛЕН'+NC}")
        _box_row(f"  Конфиг:           {''+GREEN+'НАСТРОЕН'+NC if configured else ''+YELLOW+'НЕ НАСТРОЕН'+NC}")
        if configured:
            _box_row(f"  Токен:            {DIM}{token[:10]}...{NC}")
            _box_row(f"  Admin Chat ID:    {CYAN}{admin_id}{NC}")
            _box_row(f"  Авторизовано:     {CYAN}{len(allowed)}{NC} пользователей")
            if invites:
                _box_row(f"  Активных invite:  {YELLOW}{len(invites)}{NC}")
        _box_sep()
        if not configured:
            _box_item("1", f"Настроить бота (токен + admin ID)")
        else:
            _box_item("1", f"Изменить настройки")
            if running:
                _box_item("2", f"Перезапустить бота")
                _box_item("3", f"{RED}Остановить бота{NC}")
            else:
                _box_item("2", f"{GREEN}Запустить бота{NC}")
            _box_item("4", f"Создать invite-ссылку для пользователя")
            _box_item("5", f"Список авторизованных пользователей")
            _box_item("6", f"Удалить пользователя из списка")
            _box_item("7", f"Проверить статус сервиса")
        _box_sep()
        _box_info("Бот работает как systemd-сервис xray-tg-bot")
        _box_info("Токен: @BotFather → /newbot")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_bot_configure(bot_cfg, notif_cfg)
        elif ch == "2" and configured:
            if running:
                _info("Перезапускаю...")
                _run(["systemctl", "restart", "xray-tg-bot"], quiet=True)
                time.sleep(2)
                _ok("Перезапущен") if _bot_running() else _warn("Не запустился — см. journalctl -u xray-tg-bot")
            else:
                _menu_bot_start(bot_cfg)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "3" and configured and running:
            _menu_bot_stop()
        elif ch == "4" and configured:
            _menu_bot_invite(bot_cfg, token, admin_id)
        elif ch == "5" and configured:
            _menu_bot_list_users(bot_cfg)
        elif ch == "6" and configured:
            _menu_bot_remove_user(bot_cfg)
        elif ch == "7" and configured:
            _menu_bot_svc_status()
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_bot_configure(bot_cfg: dict, notif_cfg: dict) -> None:
    """Настройка токена и admin ID."""
    os.system("clear")
    print()
    _box_top("🤖  Настройка Telegram Bot")
    _box_desc(
        "Создайте бота через @BotFather (/newbot). "
        "Если токен тот же что для уведомлений — можно использовать один бот. "
        "Admin Chat ID — ваш личный Telegram ID (узнать: @userinfobot)."
    )
    _box_sep()
    cur_token    = bot_cfg.get("token") or notif_cfg.get("token", "")
    cur_admin_id = bot_cfg.get("admin_id") or notif_cfg.get("chat_id", "")
    if cur_token:
        _box_row(f"  Текущий токен:    {DIM}{cur_token[:10]}...{NC}")
    if cur_admin_id:
        _box_row(f"  Текущий admin ID: {CYAN}{cur_admin_id}{NC}")
    _box_bottom()
    print()

    try:
        new_token = input(f"  Bot Token [{DIM}Enter = оставить{NC}]: ").strip()
        new_admin = input(f"  Admin Chat ID [{DIM}Enter = оставить{NC}]: ").strip()
    except KeyboardInterrupt:
        return

    if new_token:
        bot_cfg["token"] = new_token
    elif cur_token and not bot_cfg.get("token"):
        bot_cfg["token"] = cur_token

    if new_admin:
        bot_cfg["admin_id"] = new_admin
    elif cur_admin_id and not bot_cfg.get("admin_id"):
        bot_cfg["admin_id"] = cur_admin_id

    if not bot_cfg.get("token") or not bot_cfg.get("admin_id"):
        _warn("Токен и Admin ID обязательны")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return

    _bot_save(bot_cfg)

    # Синхронизируем токен в уведомлениях если это тот же токен
    if bot_cfg["token"] == notif_cfg.get("token") or not notif_cfg.get("token"):
        notif_cfg["token"]   = bot_cfg["token"]
        notif_cfg["chat_id"] = bot_cfg["admin_id"]
        tg_save(notif_cfg)

    print()
    _info("Устанавливаю systemd-сервис бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен!")
        print()
        # Проверяем токен через getMe
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{bot_cfg['token']}/getMe"
        ], capture=True)
        try:
            data = json.loads(r.stdout)
            if data.get("ok"):
                uname = data["result"].get("username", "")
                _ok(f"Бот: @{uname}")
                _box_top("📋  Готово!")
                _box_row(f"  Ссылка на бота: {CYAN}https://t.me/{uname}{NC}")
                _box_info(f"Напишите боту /start для проверки")
                _box_info(f"Admin Chat ID {bot_cfg['admin_id']} имеет полный доступ")
                _box_bottom()
            else:
                _warn("Бот запущен, но токен может быть неверным")
        except Exception:
            _ok("Бот запущен (не удалось проверить токен)")
    else:
        _err("Бот не запустился — проверьте journalctl -u xray-tg-bot")

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_start(bot_cfg: dict) -> None:
    _info("Запускаю бота...")
    if _install_bot_service(bot_cfg):
        _ok("Бот запущен")
    else:
        _err("Не удалось запустить — проверьте journalctl -u xray-tg-bot")


def _menu_bot_stop() -> None:
    try:
        ans = input(f"  {YELLOW}Остановить бота? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans == "y":
        _stop_bot_service()
        _ok("Бот остановлен и удалён из автозапуска")
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_invite(bot_cfg: dict, token: str, admin_id: str) -> None:
    """Создаёт одноразовый invite-токен и показывает ссылку."""
    # Получаем username бота
    bot_username = ""
    try:
        r = _run([
            "curl", "-s", "-m", "10",
            f"https://api.telegram.org/bot{token}/getMe"
        ], capture=True)
        data = json.loads(r.stdout)
        if data.get("ok"):
            bot_username = data["result"].get("username", "")
    except Exception:
        pass

    tok = secrets.token_urlsafe(12)
    invites = bot_cfg.get("invite_tokens", {})
    invites[tok] = {"created": datetime.now().isoformat(), "by": "admin_menu"}
    bot_cfg["invite_tokens"] = invites
    _bot_save(bot_cfg)
    _regenerate_bot()

    print()
    _ok(f"Invite-токен создан")
    print()
    if bot_username:
        invite_link = f"https://t.me/{bot_username}?start={tok}"
        _box_top("📋  Invite-ссылка")
        _box_row(f"  {CYAN}{invite_link}{NC}")
        _box_info("Одноразовая — после использования удаляется")
        _box_info("Отправьте пользователю — он нажмёт и получит доступ к /config")
        _box_bottom()
    else:
        _box_top("📋  Invite-токен")
        _box_row(f"  Токен: {CYAN}{tok}{NC}")
        _box_info("Пользователь должен написать боту: /start <токен>")
        _box_bottom()

    # Уведомляем себя в TG
    if bot_username:
        tg_send(
            f"🔑 <b>Новая invite-ссылка создана:</b>\n\nhttps://t.me/{bot_username}?start={tok}",
            token, admin_id
        )

    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_bot_list_users(bot_cfg: dict) -> None:
    os.system("clear")
    print()
    allowed = bot_cfg.get("allowed_users", [])
    _box_top("👥  Авторизованные пользователи")
    if not allowed:
        _box_row(f"  {DIM}(пусто){NC}")
    else:
        for i, uid in enumerate(allowed, 1):
            _box_row(f"  {i}. {CYAN}{uid}{NC}")
    _box_bottom()
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_bot_remove_user(bot_cfg: dict) -> None:
    allowed = bot_cfg.get("allowed_users", [])
    if not allowed:
        _warn("Список пользователей пуст")
        time.sleep(1)
        return
    print()
    _box_top("Удалить пользователя")
    for i, uid in enumerate(allowed, 1):
        _box_row(f"  {i}. {uid}")
    _box_back()
    _box_bottom()
    try:
        raw = input(f"  Номер (Enter = отмена): ").strip()
    except KeyboardInterrupt:
        return
    if raw.isdigit() and 1 <= int(raw) <= len(allowed):
        removed = allowed.pop(int(raw)-1)
        bot_cfg["allowed_users"] = allowed
        _bot_save(bot_cfg)
        _regenerate_bot()
        _ok(f"Удалён: {removed}")
    time.sleep(1)


def _menu_bot_svc_status() -> None:
    os.system("clear")
    print()
    _box_top("🔍  Статус сервиса xray-tg-bot")
    _box_bottom()
    print()
    _run(["systemctl", "status", "xray-tg-bot", "--no-pager", "-l"])
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


# ── Алиасы для обратной совместимости с _core.py ──────────────────────────────
# В _core.py достаточно заменить:
#   from chimera.modules.tg_bot import (
#       tg_load as _tg_load, tg_save as _tg_save,
#       tg_send, tg_notify_event as _tg_notify_event,
#       do_manage_telegram,
#   )
# И убрать дублирующиеся определения TG_CONFIG_FILE/_tg_load/_tg_save/tg_send/_tg_notify_event

TG_CONFIG_FILE = _NOTIF_FILE  # совместимость
_tg_load       = tg_load
_tg_save       = tg_save
_tg_notify_event = tg_notify_event
