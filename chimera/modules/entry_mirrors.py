"""
chimera/modules/entry_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Entry Mirrors — резервные entry-ноды для клиент-сайд авто-failover.

Проблема:
  smart_balancer.py и cluster_ops.py решают отказоустойчивость EXIT-нод
  (Режим B) — но у клиента всегда ОДИН entry-адрес/домен. Если конкретно
  его заблокируют/забанят по IP — упадёт вся связка, сколько бы exit-нод
  ни было живо позади.

Решение (уровень клиента, БЕЗ изменения серверной топологии):
  Каждый Mirror — это ОТДЕЛЬНЫЙ, независимо установленный VLESS+REALITY
  сервер (обычной установкой этого же инсталлятора, на другом VPS/ASN/
  стране), в users.json которого прописаны ТЕ ЖЕ UUID, что и на основном
  сервере. Этот модуль НЕ разворачивает и НЕ настраивает такие серверы —
  только хранит их публичные connection-параметры (host/port/pbk/sid/sni/
  fp), проверяет их доступность (TCP-probe) и генерирует по ним vless://
  ссылки для каждого пользователя.

  Собранные ссылки (основной сервер + все живые mirror) попадают в единую
  подписку (subscription.py, функция get_mirror_uris — единственная точка
  интеграции, при этом entry_mirrors.py не импортирует subscription.py,
  завязка в одну сторону). Клиентские приложения (v2rayNG / NekoBox / Happ),
  умеющие группировать несколько ссылок подписки в urltest/auto-группу,
  сами переключаются на живой mirror при недоступности одного из них —
  никакой доработки на сервере под конкретного клиента не требуется.

  ВАЖНО — честно про пределы этого подхода (см. обсуждение с автором):
  спасает от блокировки/бана КОНКРЕТНОГО IP/домена одного сервера.
  От блокировки самой техники REALITY (по паттерну, а не по адресу) —
  НЕ спасает, т.к. технология на всех mirror одна и та же. Для этого
  нужна диверсификация протоколов (Hysteria2/MTProto/Mieru/NaiveProxy/
  SlipGate — уже есть россыпью в проекте), это отдельная задача.

Хранение:
  /var/lib/xray-installer/entry_mirrors.json
  {
    "mirrors": [
      {
        "id": "a1b2c3d4", "label": "EU-2 Hetzner", "enabled": true,
        "host": "1.2.3.4", "port": 443, "sni": "www.example.com",
        "pbk": "...", "sid": "...", "fp": "chrome",
        "added_ts": 1700000000,
        "last_check": {"ok": true, "ts": 1700000100, "latency_ms": 42}
      }
    ]
  }

Публичный API для subscription.py (единственная точка интеграции):
    from chimera.modules.entry_mirrors import get_mirror_uris
    uris = get_mirror_uris(uuid_str, only_healthy=True)

Точка входа из _core.py (единственные строки, которые нужно туда добавить —
сам _core.py этим модулем не изменяется):
    1. Импорт:
         from chimera.modules.entry_mirrors import do_entry_mirrors_menu
    2. Пункт меню (например в разделе "Подписка/Продвинутое"):
         _box_row(f"  {CYAN}M{NC}  🪞 {TITLE}Entry Mirrors (резервные точки входа){NC}")
    3. Обработчик:
         elif choice.upper() == "M":
             try:
                 do_entry_mirrors_menu()
             except ImportError as _e:
                 warn(f"Модуль Entry Mirrors не найден: {_e}")
                 time.sleep(2)

Автономный запуск (cron-проверка здоровья):
    python3 -m chimera.modules.entry_mirrors probe
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import importlib
import json
import os
import secrets
import socket
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [entry_mirrors] [{level}] {msg}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg: str)      -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg: str)     -> None: print(f"{RED}[ERR]{NC}   {msg}");   _log("ERR", msg)

# ── box_renderer (UI меню, общий для всех модулей установщика) ────────────────
from chimera.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_item_exit,
    _box_back, _box_info, _box_warn, _box_ok, _box_link, _box_desc,
    _box_kv, _box_ask, _box_narrow,
)

# ── Делегирование в _core.py (без circular import, без дублирования) ──────────
def _core_call(func_name: str, *args, **kwargs):
    core = importlib.import_module("chimera._core")
    return getattr(core, func_name)(*args, **kwargs)

def _load_all_users() -> list[dict]:
    try:
        return _core_call("_unified_load_users")
    except Exception as e:
        _warn(f"Не удалось получить список пользователей из _core: {e}")
        return []

def _gen_vless_link(host: str, uuid_str: str, pbk: str, sid: str,
                     sni: str, fp: str, port: int) -> Optional[str]:
    try:
        return _core_call(
            "_gen_vless_link", host, uuid_str, pbk, sid, sni, fp,
            "reality", "/", "stream-up", port,
        )
    except Exception as e:
        _warn(f"Не удалось собрать vless-ссылку: {e}")
        return None

# ── Пути ────────────────────────────────────────────────────────────────────
_STATE_FILE  = Path("/var/lib/xray-installer/entry_mirrors.json")
_PROBE_TIMEOUT_S = 4

# ══════════════════════════════════════════════════════════════════════════
#  ХРАНЕНИЕ
# ══════════════════════════════════════════════════════════════════════════
def _load() -> dict:
    if _STATE_FILE.exists():
        try:
            data = json.loads(_STATE_FILE.read_text())
            data.setdefault("mirrors", [])
            return data
        except Exception as e:
            _warn(f"entry_mirrors.json повреждён, начинаю с пустого списка: {e}")
    return {"mirrors": []}

def _save(data: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    _STATE_FILE.chmod(0o600)

def _find(data: dict, mirror_id: str) -> Optional[dict]:
    for m in data["mirrors"]:
        if m["id"] == mirror_id:
            return m
    return None

# ══════════════════════════════════════════════════════════════════════════
#  HEALTH-ПРОБА (простой TCP-connect, без разбора REALITY-хендшейка —
#  по тому же принципу, что и TCP-проба exit-нод в smart_balancer.py)
# ══════════════════════════════════════════════════════════════════════════
def _probe(host: str, port: int) -> tuple[bool, Optional[int]]:
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=_PROBE_TIMEOUT_S):
            latency_ms = int((time.monotonic() - start) * 1000)
            return True, latency_ms
    except Exception:
        return False, None

def probe_all(quiet: bool = False, boxed: bool = False) -> None:
    """Проверяет все mirror, пишет результат в state. Вызывается из меню
    и из cron (`python3 -m chimera.modules.entry_mirrors probe`).

    boxed=True — вывод рамками box_renderer (путь из меню [4]); cron-вызов
    (quiet=True) и старые вызовы без параметров не меняются."""
    data = _load()
    if boxed:
        _box_top("🔎  ПРОВЕРКА ДОСТУПНОСТИ MIRROR")
        _box_row()
    for m in data["mirrors"]:
        ok, latency_ms = _probe(m["host"], m["port"])
        m["last_check"] = {"ok": ok, "ts": int(time.time()), "latency_ms": latency_ms}
        if not quiet:
            if boxed:
                icon = "✅" if ok else "❌"
                detail = f"{GREEN}{latency_ms}ms{NC}" if ok else f"{RED}нет TCP{NC}"
                _box_row(f"  {icon}  {WHITE}{_box_narrow(m['label'])}{NC}"
                         f"  {DIM}{_box_narrow(str(m['host']))}:{m['port']}{NC}  {detail}")
            else:
                status = f"{GREEN}✓ {latency_ms}ms{NC}" if ok else f"{RED}✗ недоступен{NC}"
                print(f"  {m['label']:<24} {m['host']}:{m['port']}  {status}")
    _save(data)
    if boxed:
        if not data["mirrors"]:
            _box_row(f"  {DIM}Mirror-нод нет - добавьте через [1].{NC}")
        _box_row()
        _box_bottom()

# ══════════════════════════════════════════════════════════════════════════
#  ПУБЛИЧНЫЙ API — единственная точка интеграции с subscription.py
# ══════════════════════════════════════════════════════════════════════════
def get_mirror_uris(uuid_str: str, only_healthy: bool = True) -> list[str]:
    """Возвращает список vless:// ссылок на этот UUID по всем включённым
    (и, если only_healthy=True, последний раз доступным) mirror-нодам.
    Ничего не проверяет заново — использует результат последнего probe_all()
    (по крону), чтобы не тормозить генерацию подписки живыми TCP-пробами
    на каждый HTTP-запрос клиента."""
    data = _load()
    uris: list[str] = []
    for m in data["mirrors"]:
        if not m.get("enabled", True):
            continue
        if only_healthy:
            lc = m.get("last_check") or {}
            if not lc.get("ok"):
                continue
        link = _gen_vless_link(
            m["host"], uuid_str, m["pbk"], m["sid"], m["sni"],
            m.get("fp", "chrome"), int(m.get("port", 443)),
        )
        if not link:
            continue
        # Подмешиваем метку mirror в fragment ссылки, чтобы в клиенте
        # было видно, какой это вход (иначе не отличить от основного).
        base, _, frag = link.partition("#")
        label = m.get("label", m["id"])
        uris.append(f"{base}#{label}" if frag == "" else f"{base}#{label} · {frag}")
    return uris

# ══════════════════════════════════════════════════════════════════════════
#  МЕНЮ
# ══════════════════════════════════════════════════════════════════════════
def _status_str(m: dict) -> str:
    if not m.get("enabled", True):
        return f"{DIM}○ выключен{NC}"
    lc = m.get("last_check")
    if not lc:
        return f"{DIM}○ не проверялся{NC}"
    if lc.get("ok"):
        return f"{GREEN}● живой{NC} {DIM}({lc.get('latency_ms')}ms){NC}"
    return f"{RED}● недоступен{NC}"

def _list_mirrors() -> None:
    data = _load()
    if not data["mirrors"]:
        _box_row(f"  {DIM}Mirror-нод нет - добавьте через [1].{NC}")
        return
    for i, m in enumerate(data["mirrors"], 1):
        _box_row(f"  {DIM}[{i}]{NC}  {WHITE}{m['label']}{NC}  {_status_str(m)}")
        _box_row(f"        {DIM}{m['host']}:{m['port']}  sni={m['sni']}{NC}")

# ══════════════════════════════════════════════════════════════════════════
#  ПАРСИНГ vless:// ССЫЛКИ (чтобы не вбивать host/pbk/sid/sni/fp руками —
#  всё это уже есть в ссылке, которую отдаёт mirror-сервер в своём меню)
# ══════════════════════════════════════════════════════════════════════════
def _parse_vless_link(link: str) -> Optional[dict]:
    """Разбирает vless://uuid@host:port?...&security=reality&pbk=...&sid=...
    &sni=...&fp=...#label на составные части. Возвращает None, если это не
    похоже на REALITY-ссылку (нет security=reality, pbk или sni) — такую
    ссылку как mirror-точку REALITY не добавить, нужны вручную введённые
    поля."""
    try:
        parsed = urllib.parse.urlparse(link.strip())
        if parsed.scheme != "vless" or not parsed.hostname:
            return None
        qs = urllib.parse.parse_qs(parsed.query)
        def _q(key: str, default: str = "") -> str:
            return (qs.get(key) or [default])[0]
        if _q("security") != "reality":
            return None
        pbk = _q("pbk")
        sni = _q("sni")
        if not pbk or not sni:
            return None
        return {
            "host":  parsed.hostname,
            "port":  parsed.port or 443,
            "pbk":   pbk,
            "sid":   _q("sid"),
            "sni":   sni,
            "fp":    _q("fp", "chrome"),
            "label": urllib.parse.unquote(parsed.fragment) if parsed.fragment else "",
        }
    except Exception:
        return None

# ── UI-хелперы (канон стилизации AWG TUI / icmp_gate) ────────────────────────
def _pause() -> None:
    """Пауза после действия; EOF/Ctrl+C безопасны (канон icmp_gate._ig_pause)."""
    try:
        input(f"{DIM}Enter - назад в меню...{NC}")
    except (EOFError, KeyboardInterrupt):
        pass

def _add_err(msg: str) -> None:
    """Компактный результат-бокс об ошибке добавления mirror."""
    _box_top("➕  ДОБАВЛЕНИЕ ENTRY MIRROR")
    _box_row()
    _box_row(f"  {RED}❌  {msg}{NC}")
    _box_bottom()

def _ask_port(default: str) -> Optional[int]:
    """Ввод порта с валидацией (число 1-65535), EOF-безопасно.
    До 5 попыток; None — ввод так и не состоялся (диалог отменяется)."""
    for _ in range(5):
        raw = _box_ask("Порт", default) or default
        try:
            port = int(raw)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        _box_top("➕  ПОРТ MIRROR")
        _box_row()
        _box_row(f"  {RED}❌  Порт должен быть числом 1-65535.{NC}")
        _box_row()
        _box_row(f"  {DIM}Повторите ввод (Enter = {default}).{NC}")
        _box_bottom()
    return None

def _add_mirror() -> None:
    _box_top("➕  ДОБАВЛЕНИЕ ENTRY MIRROR")
    _box_row()
    _box_row(f"  {DIM}Mirror - отдельно установленный этим же инсталлятором{NC}")
    _box_row(f"  {DIM}VLESS+REALITY-сервер, в users.json которого прописаны{NC}")
    _box_row(f"  {DIM}ТЕ ЖЕ UUID, что и на основном сервере.{NC}")
    _box_row()
    _box_row(f"  {DIM}Шаг 1 - вставьте vless:// ссылку с mirror-сервера (её{NC}")
    _box_row(f"  {DIM}отдаёт меню ссылок на самом mirror): все поля подставятся{NC}")
    _box_row(f"  {DIM}автоматически. Enter - ввести поля вручную.{NC}")
    _box_bottom()

    raw_link = _box_ask("Вставьте vless:// ссылку (Enter = вручную)")

    parsed = _parse_vless_link(raw_link) if raw_link else None
    if raw_link and not parsed:
        _box_top("➕  ДОБАВЛЕНИЕ ENTRY MIRROR")
        _box_row()
        _box_warn("Не похоже на REALITY-ссылку (нужны security=reality, pbk и sni в query) - переключаюсь на ввод полями.")
        _box_bottom()

    # Название (единственное обязательное поле без значения по умолчанию)
    label_hint = parsed["label"] if parsed and parsed.get("label") else ""
    label = _box_ask("Название (для себя, например 'EU-2 Hetzner')", label_hint)
    if not label:
        _add_err("Название обязательно.")
        return

    # Поля: из ссылки (подтверждение по Enter) или вручную с подсказками
    if parsed:
        _box_top("➕  ПАРАМЕТРЫ ИЗ ССЫЛКИ  (ENTER = КАК ЕСТЬ)")
        _box_row()
        _box_kv("IP или домен", _box_narrow(parsed["host"]))
        _box_kv("Порт", str(parsed["port"]))
        _box_kv("SNI", _box_narrow(parsed["sni"]))
        _box_kv("Public Key (pbk)", parsed["pbk"][:18] + "...")
        _box_kv("Short ID (sid)", _box_narrow(parsed["sid"]) or "(пусто)")
        _box_kv("Fingerprint", parsed["fp"])
        _box_bottom()
        host = _box_ask("IP или домен", parsed["host"])
        port = _ask_port(str(parsed["port"]))
        sni  = _box_ask("SNI", parsed["sni"])
        pbk  = _box_ask("Public Key (pbk)", parsed["pbk"])
        sid  = _box_ask("Short ID (sid)", parsed["sid"])
        fp   = _box_ask("Fingerprint", parsed["fp"])
    else:
        _box_top("➕  ПАРАМЕТРЫ MIRROR  (ВРУЧНУЮ)")
        _box_row()
        _box_kv("IP или домен", "адрес mirror-сервера")
        _box_kv("Порт", "порт VLESS+REALITY, обычно 443")
        _box_kv("SNI", "reality_dest / домен маскировки")
        _box_kv("Public Key (pbk)", "публичный ключ REALITY mirror")
        _box_kv("Short ID (sid)", "hex-id, можно пусто")
        _box_kv("Fingerprint", "отпечаток TLS (chrome, firefox, ...)")
        _box_row()
        _box_row(f"  {DIM}IP, SNI и Public Key обязательны.{NC}")
        _box_bottom()
        host = _box_ask("IP или домен")
        port = _ask_port("443")
        sni  = _box_ask("SNI (reality_dest / домен маскировки)")
        pbk  = _box_ask("Public Key (pbk)")
        sid  = _box_ask("Short ID (sid, можно пусто)")
        fp   = _box_ask("Fingerprint", "chrome")

    if not host:
        _add_err("Host обязателен.")
        return
    if port is None:
        _add_err("Порт не введён.")
        return
    if not (sni and pbk):
        _add_err("SNI и Public Key обязательны.")
        return

    data = _load()
    mirror = {
        "id": secrets.token_hex(4),
        "label": label, "enabled": True,
        "host": host, "port": port, "sni": sni,
        "pbk": pbk, "sid": sid, "fp": fp,
        "added_ts": int(time.time()),
        "last_check": None,
    }
    data["mirrors"].append(mirror)
    _save(data)
    _log("OK", f"Mirror '{label}' добавлен")
    ok, latency_ms = _probe(host, port)
    mirror["last_check"] = {"ok": ok, "ts": int(time.time()), "latency_ms": latency_ms}
    _save(data)

    _box_top("➕  ДОБАВЛЕНИЕ ENTRY MIRROR")
    _box_row()
    _box_ok(_box_narrow(f"Mirror «{label}» добавлен. Проверяю доступность..."))
    _box_row()
    if ok:
        _box_ok(f"Доступен по TCP, {latency_ms}ms.")
        _log("OK", f"Mirror '{label}': доступен, {latency_ms}ms")
    else:
        _box_warn("Недоступен по TCP - проверьте адрес/порт/файрвол на той стороне.")
        _log("WARN", f"Mirror '{label}': недоступен по TCP")
    _box_bottom()

def _pick_mirror(data: dict, prompt: str) -> Optional[dict]:
    """Рамочный выбор mirror из списка (канон выбора carrier в awg_diagnose).
    EOF/Ctrl+C или пустой ввод = отмена."""
    if not data["mirrors"]:
        _box_top("🪞  ВЫБОР MIRROR")
        _box_row()
        _box_row(f"  {DIM}Mirror-нод нет - добавьте через [1].{NC}")
        _box_bottom()
        return None
    _box_top("🪞  ВЫБОР MIRROR")
    _box_row()
    _box_row(f"  {DIM}{_box_narrow(prompt)} (Enter = отмена):{NC}")
    _box_row()
    for i, m in enumerate(data["mirrors"], 1):
        _box_item(str(i) if i < 10 else "0",
                  f"{_box_narrow(m['label'])}  {DIM}{_box_narrow(str(m['host']))}:{m['port']}{NC}")
    _box_item("Q", "Отмена (Enter)")
    _box_bottom()
    raw = _box_ask("Выбор")
    if not raw or raw.lower() in ("q", "й"):
        return None
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(data["mirrors"]):
            return data["mirrors"][idx]
    except ValueError:
        pass
    _box_top("🪞  ВЫБОР MIRROR")
    _box_row()
    _box_row(f"  {RED}❌  Неверный номер.{NC}")
    _box_bottom()
    return None

def _remove_mirror() -> None:
    data = _load()
    m = _pick_mirror(data, "Номер mirror для удаления")
    if not m:
        return
    _box_top("🗑️  УДАЛЕНИЕ MIRROR")
    _box_row()
    _box_kv("Mirror", _box_narrow(m["label"]))
    _box_kv("Адрес", f"{m['host']}:{m['port']}")
    _box_kv("SNI", _box_narrow(m["sni"]))
    _box_row()
    _box_row(f"  {YELLOW}Mirror пропадёт из подписки всех пользователей.{NC}")
    _box_bottom()
    confirm = _box_ask(f"Точно удалить «{_box_narrow(m['label'])}»? [y/N]").lower()
    if confirm not in ("y", "yes", "д", "да"):
        return
    data["mirrors"] = [x for x in data["mirrors"] if x["id"] != m["id"]]
    _save(data)
    _log("OK", f"Mirror '{m['label']}' удалён")
    _box_top("🗑️  УДАЛЕНИЕ MIRROR")
    _box_row()
    _box_ok(_box_narrow(f"Mirror «{m['label']}» удалён."))
    _box_bottom()

def _toggle_mirror() -> None:
    data = _load()
    m = _pick_mirror(data, "Номер mirror для вкл/выкл")
    if not m:
        return
    m["enabled"] = not m.get("enabled", True)
    _save(data)
    _log("OK", f"Mirror '{m['label']}': {'включён' if m['enabled'] else 'выключен'}")
    _box_top("🔀  ВКЛ/ВЫКЛ MIRROR")
    _box_row()
    icon = "✅" if m["enabled"] else "⭕"
    state = f"{GREEN}включён{NC}" if m["enabled"] else f"{DIM}выключен{NC}"
    _lbl = _box_narrow(f"«{m['label']}»")
    _box_row(f"  {icon}  {_lbl} - {state}.")
    _box_row()
    _box_row(f"  {DIM}Выключенные mirror не попадают в подписки пользователей.{NC}")
    _box_bottom()

def _show_links() -> None:
    users = _load_all_users()
    active_users = [u for u in users if not u.get("disabled") and u.get("uuid")]
    _box_top("🔗  MIRROR-ССЫЛКИ ПО ПОЛЬЗОВАТЕЛЯМ")
    _box_row()
    if not active_users:
        _box_row(f"  {DIM}Нет активных пользователей.{NC}")
        _box_bottom()
        return
    _box_row(f"  {DIM}Ссылки всех включённых mirror для каждого пользователя{NC}")
    _box_row(f"  {DIM}(основной сервер в подписке и так есть).{NC}")
    _box_row()
    shown = 0
    for u in active_users:
        uris = get_mirror_uris(u["uuid"], only_healthy=False)
        if not uris:
            continue
        label = u.get("email", u.get("name", "?"))
        _box_row(f"  {BOLD}{WHITE}{_box_narrow(str(label))}{NC}"
                 f"  {DIM}- {len(uris)} mirror:{NC}")
        for uri in uris:
            _box_link(uri)
        _box_row()
        shown += 1
    if not shown:
        _box_row(f"  {DIM}Ни у одного пользователя пока нет mirror-ссылок -{NC}")
        _box_row(f"  {DIM}добавьте mirror через [1].{NC}")
        _box_row()
    _box_bottom()
    from chimera.modules.box_renderer import _print_link_warning
    _print_link_warning(is_vless=True)

def do_entry_mirrors_menu() -> None:
    while True:
        os.system("clear")
        data = _load()
        n_total = len(data["mirrors"])
        n_ok = sum(1 for m in data["mirrors"] if (m.get("last_check") or {}).get("ok"))
        _box_top(f"🪞  ENTRY MIRRORS  {DIM}({NC}{n_ok}/{n_total} живых{DIM}){NC}")
        _box_row()
        _box_row(f"  {DIM}Резервные точки входа для клиент-сайд auto-failover.{NC}")
        _box_row(f"  {DIM}Основной сервер сюда не входит — он и так в подписке.{NC}")
        _box_row()
        _list_mirrors()
        _box_row()
        # Подсказка про iOS/Karing — mirror-серверы требуют ручной настройки
        # shadow-клиента на каждом отдельно. Это НЕ автоматизируется из этого
        # меню, потому что clients[] на mirror-серверах этот модуль не
        # редактирует (mirror-серверы — отдельные инстансы инсталлятора на
        # других VPS, доступны только по SSH). Без shadow на mirror'е
        # iOS-подписка исключает mirror-ссылки целиком (см. subscription.py
        # ::build_subscription_body_ios). Чтобы mirror работал и в iOS-подписке,
        # админ должен зайти на каждый mirror-сервер отдельно и выполнить
        # в инсталляторе: главное меню → 2 (Управление пользователями) →
        # 1 (Менеджер пользователей) → K (iOS/Karing-ссылка) для нужных юзеров.
        if n_total > 0:
            _box_row(f"  {YELLOW}📱 iOS/Karing:{NC} {DIM}для каждого mirror:{NC}")
            _box_row(f"     {DIM}зайдите на него по SSH и выполните в инсталляторе{NC}")
            _box_row(f"     {DIM}«2 → 1 → K» для каждого юзера с iOS-подпиской.{NC}")
            _box_row(f"     {DIM}Иначе iOS-подписка исключит этот mirror.{NC}")
            _box_row()
        _box_sep()
        _box_item("1", "➕  Добавить mirror")
        _box_item("2", "🗑️   Удалить mirror")
        _box_item("3", "🔀  Включить/выключить mirror")
        _box_item("4", "🔎  Проверить доступность всех сейчас")
        _box_item("5", "🔗  Показать ссылки по всем пользователям")
        _box_row()
        _box_back()
        _box_bottom()

        ch = _box_ask("Выбор").lower()

        if ch == "1":
            _add_mirror(); _pause()
        elif ch == "2":
            _remove_mirror(); _pause()
        elif ch == "3":
            _toggle_mirror(); _pause()
        elif ch == "4":
            probe_all(boxed=True); _pause()
        elif ch == "5":
            _show_links(); _pause()
        elif ch in ("q", "0", ""):
            return

# ══════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (cron: python3 -m chimera.modules.entry_mirrors probe)
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "probe":
        probe_all(quiet=True)
        sys.exit(0)
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    do_entry_mirrors_menu()
