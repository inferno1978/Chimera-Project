"""
chimera/modules/users_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Users Watchdog — целостность clients в config.json Xray.

Зачем (инцидент 16.10.2026, RU-3): диагностический прогон TUI на живой
entry-ноде перезаписал inbound-vless clients артефактом [u1/a@x] вместо
реального пользователя → ночной рестарт xray загрузил битый inbound →
«invalid request user id», каскад VLESS упал на часы. users.json при этом
оставался корректным — просто никто не сверял конфиг с ним.

Что делает (одна итерация, systemd-timer, интервал настраивается):
  1. Читает users.json → эталонный список клиентов для главного
     user-facing инбаунда (vless + clients + порт == state.server_port).
  2. Читает config.json → сверяет clients каждого инбаунда с эталоном:
       • пропавшие пользователи (есть в users.json, нет в конфиге);
       • неизвестные/артефактные клиенты (u1/a@x);
       • расхождение email у того же uuid;
       • БЕЗУМНЫЕ клиенты — id не является UUID (мгновенное восстановление,
         без ожидания циклов подтверждения: xray принимает такой конфиг,
         но auth всегда падает — именно сценарий инцидента);
       • пустой clients при непустом users.json.
  3. Прочие инбаунды с clients (chain-exit «entry@chain» и т.п.) защищаются
     СНАПШОТОМ последнего известного доброго состояния (не users.json —
     у них другой источник истины).
 4. При расхождении (после N циклов подтверждения, кроме «безумных»):
       backup → атомарная замена → xray run -test → restart →
       проверка active → автооткат при неудаче.
  5. Telegram-уведомление (через tg_bot, уважая фильтр событий) +
       лог /var/log/users-watchdog.log.

Кастомизация (/var/lib/xray-installer/users-watchdog.json):
       interval_minutes, action_on_mismatch (restore|notify|none),
       require_confirm_cycles, cooldown_minutes, max_restores_per_hour,
       remove_unknown_clients, protect_other_inbounds, notify, backup_keep.

Предохранители от «запинания» битым состоянием и борьба с дребезгом:
       maintenance-флаг (пауза на время диагностик/TUI-экспериментов),
       cooldown между восстановлениями, лимит восстановлений в час,
       подтверждение расхождения несколькими циклами, lock от параллельных
       запусков, отказ писать пустой clients (min-clients guard),
       источник восстановления каскадом: users.json → снапшот → свежий
       валидный *.bak.

Точки входа:
    from chimera.modules.users_watchdog import (
        users_watchdog_run, users_watchdog_install, users_watchdog_remove,
        do_manage_users_watchdog,
    )

CLI (systemd-timer):
    python3 main.py --users-watchdog-run

Модуль СТОЙК К ИЗОЛЯЦИИ: верхний уровень импортирует только stdlib —
зависимости от chimera ленивые (внутри функций). Watchdog не должен
зависеть от того, что защищает.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time as _time_mod
from datetime import datetime
from pathlib import Path

# ── Цвета ─────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m', NC='\033[0m')
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'], _C['BOLD'], _C['DIM'], _C['NC'],
)

# ── Пути (патчатся в тестах) ──────────────────────────────────────────────────
_CFG_DIR        = Path("/etc/xray")
_CFG_ALT_DIR    = Path("/usr/local/etc/xray")
_STATE_DIR      = Path("/var/lib/xray-installer")
# users.json — в CONFIG_DIR (= /etc/xray/users.json), как USERS_FILE в _core:
# это источник истины юзеров entry-ноды
_USERS_FILE     = _CFG_DIR / "users.json"
_XRAY_STATE     = _STATE_DIR / "state.json"
_WD_CONFIG      = _STATE_DIR / "users-watchdog.json"
_WD_STATE       = _STATE_DIR / "users-watchdog-state.json"
_MAINT_FLAG     = _STATE_DIR / "users-watchdog.maintenance"
_LOCK_FILE      = Path("/run/users-watchdog.lock")
_LOG            = Path("/var/log/users-watchdog.log")
_LOGROTATE      = Path("/etc/logrotate.d/users-watchdog")
_SCRIPT          = Path("/usr/local/bin/users-watchdog.sh")
_SERVICE        = Path("/etc/systemd/system/users-watchdog.service")
_TIMER          = Path("/etc/systemd/system/users-watchdog.timer")
_UNIT_NAME      = "users-watchdog.timer"

_XRAY_BIN_CANDIDATES = ("/usr/local/bin/xray", "/usr/bin/xray")
_XRAY_SERVICE        = "xray"
_RESTART_WAIT_SEC   = 15
_LOCK_STALE_SEC     = 600
_BAK_SCAN_LIMIT     = 10
_BAK_PREFIX         = ".bak-users-watchdog-"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# ── Конфиг по умолчанию ───────────────────────────────────────────────────────
DEFAULTS: dict = {
    "enabled":                  True,     # обслуживается таймером (install)
    "interval_minutes":         1,        # как часто сверять
    "action_on_mismatch":       "restore",  # restore | notify | none
    "require_confirm_cycles":   2,        # циклов подряд до restore (кроме insane)
    "cooldown_minutes":         5,        # пауза между восстановлениями
    "max_restores_per_hour":    6,        # 0 = без лимита; сверх → только notify
    "remove_unknown_clients":   True,     # вычищать артефакты (u1/a@x)
    "protect_other_inbounds":   True,     # снапшот-защита chain/exit инбаундов
    "notify":                   "tg",     # tg | none
    "backup_keep":              20,       # сколько .bak-users-watchdog-* хранить
}
_VALID_ACTIONS = ("restore", "notify", "none")


# ── Швы для тестов ────────────────────────────────────────────────────────────
def _now() -> float:
    return _time_mod.time()


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Базовые хелперы ────────────────────────────────────────────────────────────
def _ok(msg: str) -> None:   print(f'  {GREEN}✓{NC} {msg}')
def _warn(msg: str) -> None: print(f'  {YELLOW}⚠{NC}  {msg}')
def _info(msg: str) -> None: print(f'  {CYAN}•{NC} {msg}')


def _sh(cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """Запуск команды (шов для тестов)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # timeout и пр.
        return subprocess.CompletedProcess(args=cmd, returncode=124,
                                            stdout="", stderr=str(e))


def _log(level: str, msg: str) -> None:
    """Лог в файл + stdout. Уровни: INFO, WARN, ERROR, OK."""
    line = f"[{_now_iso()}] [{level}] {msg}"
    try:
        _LOG.parent.mkdir(parents=True, exist_ok=True)
        with _LOG.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    prefixes = {"INFO":  f"  {CYAN}[INFO]{NC}",
                "WARN":  f"  {YELLOW}[WARN]{NC}",
                "ERROR": f"  {RED}[ERROR]{NC}",
                "OK":    f"  {GREEN}[OK]{NC}"}
    print(f"{prefixes.get(level, '  [*]')} {msg}")


def _tg_event(event: str, detail: str = "", cfg: dict | None = None) -> None:
    """TG-уведомление: сначала через chimera (уважает фильтр событий),
    затем — автономный fallback по state.json (как nginx-watchdog)."""
    try:
        if cfg is not None and cfg.get("notify") != "tg":
            return
    except Exception:
        pass
    try:
        import importlib
        core = importlib.import_module("chimera._core")
        core._tg_notify_event(event, detail)
        return
    except Exception:
        pass
    # Автономный fallback (без chimera в импортах)
    try:
        st = json.loads(_XRAY_STATE.read_text())
        bot, cid = st.get("tg_bot_token", ""), st.get("tg_chat_id", "")
        if not bot or not cid:
            return
        px = ""
        tgj = _STATE_DIR / "telegram.json"
        if tgj.exists():
            try:
                px = (json.loads(tgj.read_text()) or {}).get("proxy", "") or ""
            except Exception:
                pass
        cmd = ["curl", "-s", "-X", "POST",
               f"https://api.telegram.org/bot{bot}/sendMessage",
               "--data-urlencode", f"chat_id={cid}",
               "--data-urlencode", f"text=[users-watchdog] {event}: {detail}",
               "--max-time", "10"]
        if px:
            cmd += ["-x", px]
        _sh(cmd, timeout=15)
    except Exception:
        pass


# ── Конфиг watchdog ───────────────────────────────────────────────────────────
def _load_wd_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        raw = json.loads(_WD_CONFIG.read_text())
        if isinstance(raw, dict):
            cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
    except Exception:
        pass
    return _validate_cfg(cfg)


def _save_wd_config(cfg: dict) -> None:
    _WD_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    _WD_CONFIG.write_text(json.dumps(_validate_cfg(cfg), indent=2, ensure_ascii=False))
    try:
        _WD_CONFIG.chmod(0o640)
    except Exception:
        pass


def _validate_cfg(cfg: dict) -> dict:
    c = dict(cfg)
    try:
        c["interval_minutes"] = max(1, int(c.get("interval_minutes", 1)))
    except Exception:
        c["interval_minutes"] = 1
    if c.get("action_on_mismatch") not in _VALID_ACTIONS:
        c["action_on_mismatch"] = "restore"
    try:
        c["require_confirm_cycles"] = min(5, max(1, int(c.get("require_confirm_cycles", 2))))
    except Exception:
        c["require_confirm_cycles"] = 2
    try:
        c["cooldown_minutes"] = max(0, int(c.get("cooldown_minutes", 5)))
    except Exception:
        c["cooldown_minutes"] = 5
    try:
        c["max_restores_per_hour"] = max(0, int(c.get("max_restores_per_hour", 6)))
    except Exception:
        c["max_restores_per_hour"] = 6
    for flag in ("remove_unknown_clients", "protect_other_inbounds"):
        c[flag] = bool(c.get(flag, DEFAULTS[flag]))
    try:
        c["backup_keep"] = max(3, int(c.get("backup_keep", 20)))
    except Exception:
        c["backup_keep"] = 20
    if c.get("notify") not in ("tg", "none"):
        c["notify"] = "tg"
    return c


# ── Состояние watchdog ────────────────────────────────────────────────────────
def _load_wd_state() -> dict:
    try:
        raw = json.loads(_WD_STATE.read_text())
        if isinstance(raw, dict):
            return raw
    except Exception:
        pass
    return {"snapshots": {}, "pending": {}, "restore_events": []}


def _save_wd_state(st: dict) -> None:
    try:
        _WD_STATE.parent.mkdir(parents=True, exist_ok=True)
        _WD_STATE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
        _WD_STATE.chmod(0o640)
    except Exception:
        pass


# ── Санитарные проверки ───────────────────────────────────────────────────────
def _uuid_valid(s) -> bool:
    return isinstance(s, str) and bool(_UUID_RE.match(s))


def _clients_sane(clients) -> bool:
    """Клиенты «здравы» = список непустой и все id — валидные UUID."""
    if not isinstance(clients, list) or not clients:
        return False
    return all(_uuid_valid(c.get("id")) for c in clients
               if isinstance(c, dict)) and all(isinstance(c, dict) for c in clients)


# ── Чтение источников истины ──────────────────────────────────────────────────
def _load_users_raw() -> list:
    """users.json как есть (без fallback в state.json — на exit-нодах это
    опасно: их inbound обслуживает entry@chain, а не users.json)."""
    try:
        raw = json.loads(_USERS_FILE.read_text())
        if isinstance(raw, list):
            return [u for u in raw if isinstance(u, dict)]
    except Exception:
        pass
    return []


def _state_server_port() -> int:
    try:
        st = json.loads(_XRAY_STATE.read_text())
        return int(st.get("server_port", 443))
    except Exception:
        return 443


def _find_config_paths() -> list:
    """Живые config.json (/etc/xray + симлинк-альтернатива, дедуп по realpath)."""
    seen, out = set(), []
    for d in (_CFG_DIR, _CFG_ALT_DIR):
        p = d / "config.json"
        if not p.exists():
            continue
        try:
            real = str(p.resolve())
        except Exception:
            real = str(p)
        if real in seen:
            continue
        seen.add(real)
        out.append(p)
    return out


def _xray_bin() -> str:
    for c in _XRAY_BIN_CANDIDATES:
        if Path(c).exists():
            return c
    w = shutil.which("xray")
    return w or "/usr/local/bin/xray"


def _systemctl(*args, timeout: int = 30) -> subprocess.CompletedProcess:
    return _sh(["systemctl", *args], timeout=timeout)


def _unit_active(unit: str) -> bool:
    return _systemctl("is-active", unit, timeout=10).stdout.strip() == "active"


def _unit_enabled(unit: str) -> bool:
    return "enabled" in _systemctl("is-enabled", unit, timeout=10).stdout


# ── Классификация инбаундов ───────────────────────────────────────────────────
def _inbound_port(inb: dict):
    try:
        return int(inb.get("port"))
    except Exception:
        return None


def _classify_inbounds(cfg: dict, users: list, server_port: int) -> list:
    """[(inbound, kind)] для всех инбаундов с settings.clients.
    kind: 'main' — обслуживается users.json (vless + порт == server_port,
    users.json непустой); 'other' — снапшот-защита (chain/exit и пр.)."""
    out = []
    users_enabled = [u for u in users if not u.get("disabled") and u.get("uuid")]
    for inb in cfg.get("inbounds", []):
        if not isinstance(inb, dict):
            continue
        settings = inb.get("settings") or {}
        if "clients" not in settings:
            continue
        if (inb.get("protocol") == "vless" and users_enabled
                and _inbound_port(inb) == server_port):
            out.append((inb, "main"))
        else:
            out.append((inb, "other"))
    return out


# ── Эталонные клиенты ────────────────────────────────────────────────────────
def _flow_for_inbound(inb: dict, current_clients: list) -> str:
    """flow надёжнее всего копировать из живого валидного клиента; иначе —
    вычислить по структуре (reality + не-xhttp → vision)."""
    for c in current_clients or []:
        if isinstance(c, dict) and _uuid_valid(c.get("id")) and c.get("flow"):
            return c["flow"]
    st = inb.get("streamSettings") or {}
    if "realitySettings" in st and st.get("network", "tcp") != "xhttp":
        return "xtls-rprx-vision"
    return ""


def _expected_from_users(users: list, inb: dict, current_clients: list) -> list:
    """Клиенты для 'main'-инбаунда из users.json (enabled, дедуп,
    перенос экзотических полей живых клиентов по uuid)."""
    st = inb.get("streamSettings") or {}
    is_xhttp = st.get("network", "tcp") == "xhttp"
    flow = "" if is_xhttp else _flow_for_inbound(inb, current_clients)
    seen_uuid, seen_email, out = set(), set(), []
    for u in users:
        if u.get("disabled"):
            continue
        uid, email = u.get("uuid", ""), (u.get("email") or "").strip()
        if not _uuid_valid(uid) or uid in seen_uuid:
            continue
        if email and email in seen_email:
            continue
        seen_uuid.add(uid)
        if email:
            seen_email.add(email)
        client = {"id": uid}
        if email:
            client["email"] = email
        if flow:
            client["flow"] = flow
        for cur in current_clients or []:
            if isinstance(cur, dict) and cur.get("id") == uid:
                for k, v in cur.items():
                    if k not in ("id", "email", "flow") and v is not None:
                        client[k] = v
                break
        out.append(client)
    return out


# ── Сверка ────────────────────────────────────────────────────────────────────
def _diff_clients(current: list, expected: list, remove_unknown: bool) -> dict:
    """Расхождение clients. Возвращает словарь с деталями и потребностью
    в восстановлении."""
    current = [c for c in (current or []) if isinstance(c, dict)]
    expected = [c for c in (expected or []) if isinstance(c, dict)]
    cur_ids = {c.get("id") for c in current}
    exp_ids = {c.get("id") for c in expected}
    exp_email = {c.get("id"): (c.get("email") or "") for c in expected}
    d = {
        "missing":   sorted(i for i in exp_ids - cur_ids if i),
        "unknown":   sorted(i for i in cur_ids - exp_ids if i),
        "mismatch":  sorted(c.get("id") for c in current
                           if c.get("id") in exp_ids
                           and (c.get("email") or "") != exp_email.get(c.get("id"))),
        "insane":    sorted(c.get("id") for c in current
                            if not _uuid_valid(c.get("id"))),
        "empty":     (not current) and bool(expected),
    }
    d["needs_restore"] = bool(
        d["missing"] or d["insane"] or d["empty"]
        or (remove_unknown and d["unknown"]) or d["mismatch"])
    return d


def _diff_fingerprint(diff: dict) -> str:
    return json.dumps({k: diff.get(k) for k in ("missing", "unknown",
                                                "mismatch", "insane", "empty")},
                      sort_keys=True)


def _shorten(items: list, n: int = 3) -> str:
    items = [str(i) for i in items]
    if len(items) <= n:
        return ", ".join(items) or "—"
    return ", ".join(items[:n]) + f" (+{len(items) - n})"


# ── Человекочитаемые TG-тексты (кейс окт.2026 №9) ─────────────────────────────
# Сырой дамп «missing=[—] unknown=[…] mismatch=[—] insane=[—] empty=False»
# в Telegram читался как абракадабра (скрин от админа RU: пользователь не
# понял, что нода нашла посторонний UUID). Технический формат остаётся в
# /var/log/users-watchdog.log (компактный, полный UUID — для grep), в TG
# уходит человекочитаемое описание.
def _client_label(cid: str, clients: list) -> str:
    """Метка клиента для TG: «email (e6d10d3d…)» или «e6d10d3d-2a41…»."""
    cid = str(cid or "?")
    email = ""
    for c in clients or []:
        if isinstance(c, dict) and c.get("id") == cid and c.get("email"):
            email = str(c["email"])
            break
    short = cid if len(cid) <= 13 else cid[:13] + "…"
    return f"{email} ({short})" if email else short


def _label_ids(ids: list, clients: list, n: int = 3) -> str:
    """Список меток клиентов (макс. n, дальше «(+N)»)."""
    items = [_client_label(i, clients) for i in ids or []]
    if len(items) <= n:
        return ", ".join(items) or "—"
    return ", ".join(items[:n]) + f" (+{len(items) - n})"


def _human_drift_note(tag: str, diff: dict, current: list,
                      expected: list, source: str) -> str:
    """Человекочитаемое описание дрейфа для TG-уведомления."""
    if source == "users.json":
        head = f"{tag}: список клиентов в конфиге Xray расходится с users.json"
    else:
        head = f"{tag}: список клиентов повреждён (расходится с сохранённым эталоном)"
    lines = []
    if diff.get("empty"):
        lines.append("• список клиентов ПУСТ — подключиться никто не сможет")
    if diff.get("insane"):
        lines.append("• битые записи (id не является UUID): "
                     + _shorten(diff["insane"]))
    if diff.get("missing"):
        lines.append("• пропали из конфига: "
                     + _label_ids(diff["missing"], expected))
    if diff.get("unknown"):
        lines.append("• посторонние клиенты (нет в эталоне): "
                     + _label_ids(diff["unknown"], current))
    if diff.get("mismatch"):
        lines.append("• email не совпадает с эталоном: "
                     + _label_ids(diff["mismatch"], current))
    return head + "\n" + "\n".join(lines)


def _tg_drift_text(tg_notes: list, suffix: str = "", limit: int = 800) -> str:
    """Склейка human-заметок для TG: обрезка целыми блоками (не посередине
    строки), суффикс-пояснение действия watchdog."""
    parts = [p for p in (tg_notes or []) if p]
    text = "\n".join(parts)
    if len(text) > limit:
        keep, total = [], 0
        for p in parts:
            if total + len(p) + 1 > limit - 120:
                break
            keep.append(p)
            total += len(p) + 1
        cut = len(parts) - len(keep)
        text = "\n".join(keep)
        if cut > 0:
            text += f"\n… (ещё по {cut} инбаунд(ам) — см. users-watchdog.log)"
    if suffix:
        text += f"\n{suffix}"
    return text[:1000]


# ── Last resort: свежий валидный .bak ─────────────────────────────────────────
def _clients_from_bak(tag: str, server_port: int) -> list:
    """Ищет clients того же инбаунда в свежих бэкапах config.json.
    Возвращает [] если ничего валидного не найдено."""
    cands = []
    try:
        cands = sorted(_CFG_DIR.glob("config.json.bak*"), key=lambda p: p.stat().st_mtime,
                       reverse=True)[:_BAK_SCAN_LIMIT]
    except Exception:
        return []
    for bak in cands:
        try:
            cfg = json.loads(bak.read_text())
        except Exception:
            continue
        for inb in cfg.get("inbounds", []):
            if not isinstance(inb, dict):
                continue
            settings = inb.get("settings") or {}
            if "clients" not in settings:
                continue
            if inb.get("tag") == tag or (
                    inb.get("protocol") == "vless"
                    and _inbound_port(inb) == server_port):
                cl = settings.get("clients")
                if _clients_sane(cl):
                    return cl
    return []


# ── Атомарная запись ──────────────────────────────────────────────────────────
def _atomic_write_text(path: Path, content: str) -> bool:
    """Запись с сохранением прав/владельца: tmp в той же папке + os.replace."""
    try:
        st = os.stat(path)
        tmp = path.parent / f".{path.name}.uwtmp-{os.getpid()}"
        tmp.write_text(content)
        try:
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        except Exception:
            pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        _log("ERROR", f"атомарная запись {path} не удалась: {e}")
        return False


def _wait_unit_active(unit: str, seconds: int) -> bool:
    for _ in range(max(1, seconds)):
        if _unit_active(unit):
            return True
        _time_mod.sleep(1)
    return _unit_active(unit)


def _prune_backups(keep: int) -> None:
    try:
        baks = sorted(_CFG_DIR.glob(f"config.json{_BAK_PREFIX}*"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        for old in baks[keep:]:
            try:
                old.unlink()
            except Exception:
                pass
    except Exception:
        pass


# ── Восстановление одного config.json ────────────────────────────────────────
def _restore_path(cfg_path: Path, patches: dict) -> bool:
    """Патчит clients указанных инбаундов (tag → новый список), с бэкапом,
    валидацией xray и автооткатом. patches = {tag: new_clients}."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = cfg_path.parent / f"config.json{_BAK_PREFIX}{ts}"
    original = cfg_path.read_text()
    try:
        shutil.copy2(cfg_path, backup)
    except Exception as e:
        _log("ERROR", f"бэкап не создан ({e}) — восстановление отменено")
        return False

    cfg = json.loads(original)
    patched = 0
    for inb in cfg.get("inbounds", []):
        if not isinstance(inb, dict):
            continue
        tag = inb.get("tag", "")
        if tag in patches and "clients" in (inb.get("settings") or {}):
            inb["settings"]["clients"] = patches[tag]
            patched += 1
    if not patched:
        _log("WARN", f"{cfg_path}: инбаунды для патча не найдены — пропуск")
        return False

    if not _atomic_write_text(cfg_path,
                              json.dumps(cfg, indent=2, ensure_ascii=False)):
        return False

    # Валидация нового конфига ДО рестарта
    r = _sh([_xray_bin(), "run", "-test", "-config", str(cfg_path)], timeout=60)
    if r.returncode != 0:
        _log("ERROR", f"xray -test провален после патча — откат: "
                      f"{(r.stderr or r.stdout or '')[-300:]}")
        _atomic_write_text(cfg_path, original)
        return False

    # Рестарт + проверка
    _systemctl("restart", _XRAY_SERVICE, timeout=60)
    if not _wait_unit_active(_XRAY_SERVICE, _RESTART_WAIT_SEC):
        _log("ERROR", "xray не поднялся после восстановления — ОТКАТ")
        _atomic_write_text(cfg_path, original)
        _systemctl("restart", _XRAY_SERVICE, timeout=60)
        _wait_unit_active(_XRAY_SERVICE, _RESTART_WAIT_SEC)
        return False

    _log("OK", f"{cfg_path.name}: clients восстановлены "
               f"(инбаундов: {patched}, бэкап: {backup.name})")
    return True


# ── Lock ──────────────────────────────────────────────────────────────────────
def _acquire_lock() -> bool:
    try:
        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(_LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if _now() - _LOCK_FILE.stat().st_mtime > _LOCK_STALE_SEC:
                _LOCK_FILE.unlink(missing_ok=True)
                return _acquire_lock()
        except Exception:
            pass
        return False
    except Exception:
        return True  # /run недоступен — работаем без lock (лучше, чем мёртвый WDG)


def _release_lock() -> None:
    try:
        _LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# ── Главная итерация ─────────────────────────────────────────────────────────
def _cycle(force: bool = False) -> int:
    """Один проход проверки. Возвращает код: 0 — ок/дрейф отслежен,
    1 — восстановлено, 2 — ошибка."""
    if not _acquire_lock():
        return 0  # предыдущий проход ещё живёт
    try:
        return _cycle_inner(force)
    finally:
        _release_lock()


def _cycle_inner(force: bool) -> int:
    cfg = _load_wd_config()
    if not force and not cfg.get("enabled"):
        return 0

    # Maintenance-пауза: админ сознательно работает с конфигом (TUI-диагностики)
    if _MAINT_FLAG.exists():
        st = _load_wd_state()
        if _now() - _ts(st.get("last_maint_log", 0)) > 3600:
            _log("INFO", "maintenance-флаг активен — проверка пропущена")
            st["last_maint_log"] = _now()
            st["last_status"] = "skipped_maintenance"
            _save_wd_state(st)
        return 0

    paths = _find_config_paths()
    if not paths:
        _log("WARN", "config.json Xray не найден — нечего проверять")
        return 0

    users = _load_users_raw()
    users_enabled = [u for u in users if not u.get("disabled") and u.get("uuid")]
    server_port = _state_server_port()
    st = _load_wd_state()
    action = cfg.get("action_on_mismatch", "restore")
    rc = 0

    # ── Сбор расхождений по всем конфигам/инбаундам ──────────────────────
    # restore_jobs: {cfg_path: {tag: (new_clients, source)}}
    restore_jobs: dict = {}
    drift_notes: list = []   # технические (лог)
    tg_notes: list = []      # человекочитаемые (TG; кейс окт.2026 №9)
    confirmed: dict = {}

    for path in paths:
        try:
            cfgj = json.loads(path.read_text())
        except Exception as e:
            _log("WARN", f"{path}: конфиг не читается ({e}) — пропущен")
            continue

        for inb, kind in _classify_inbounds(cfgj, users, server_port):
            tag = inb.get("tag", "?")
            settings = inb.get("settings") or {}
            current = settings.get("clients") or []

            if kind == "main":
                expected = _expected_from_users(users, inb, current)
                source = "users.json"
                if not expected:
                    # users.json непуст, но ни одного валидного пользователя —
                    # min-clients guard: НЕ вытирать живой конфиг пустым
                    # эталоном; только сигнал
                    _log("ERROR", f"{tag}: users.json без валидных пользователей "
                                   f"— конфиг не тронут")
                    drift_notes.append(f"{tag}: users.json не дал ни одного "
                                       f"валидного клиента")
                    tg_notes.append(f"{tag}: users.json пуст или без валидных "
                                    f"пользователей — конфиг не тронут "
                                    f"(min-clients guard)")
                    continue
            else:
                # 'other'-инбаунды (chain «entry@chain», exit и пр.):
                # снапшот-защита — их источник истины не users.json
                if not cfg.get("protect_other_inbounds"):
                    continue
                if _clients_sane(current):
                    snap = st.get("snapshots", {}).get(tag)
                    if snap != current:
                        st.setdefault("snapshots", {})[tag] = current
                    st.setdefault("pending", {}).pop(tag, None)
                    continue
                # Повреждён: снапшот → свежий валидный .bak → уведомление
                snap = st.get("snapshots", {}).get(tag)
                expected, source = [], ""
                if snap:
                    expected, source = snap, "snapshot"
                if not expected:
                    expected, source = _clients_from_bak(tag, server_port), "backup"
                if not expected:
                    _log("ERROR", f"{tag}: клиенты повреждены, источник "
                                   f"восстановления не найден — уведомление")
                    drift_notes.append(f"{tag}: повреждён, источник "
                                       f"восстановления отсутствует")
                    tg_notes.append(f"{tag}: клиенты повреждены, "
                                    f"авто-восстановление невозможно (нет "
                                    f"снапшота и свежего бэкапа) — требуется "
                                    f"вмешательство администратора")
                    continue

            diff = _diff_clients(current, expected, cfg.get("remove_unknown_clients",
                                                            True))
            if not diff["needs_restore"]:
                # Дрейфа нет: обновляем снапшот эталоном
                if st.get("snapshots", {}).get(tag) != expected:
                    st.setdefault("snapshots", {})[tag] = expected
                st.setdefault("pending", {}).pop(tag, None)
                continue

            note = (f"{tag}: missing=[{_shorten(diff['missing'])}] "
                    f"unknown=[{_shorten(diff['unknown'])}] "
                    f"mismatch=[{_shorten(diff['mismatch'])}] "
                    f"insane=[{_shorten(diff['insane'])}] empty={diff['empty']}")
            drift_notes.append(note)
            _log("WARN", note)
            tg_notes.append(_human_drift_note(tag, diff, current, expected,
                                               source))

            if action == "none":
                continue

            # Безумные клиенты / пустота → мгновенно, без подтверждения
            immediate = bool(diff["insane"] or diff["empty"])
            if not immediate:
                pend = st.setdefault("pending", {})
                fp = _diff_fingerprint(diff)
                p = pend.get(tag) or {"count": 0, "fingerprint": fp,
                                      "first_seen": _now_iso()}
                if p.get("fingerprint") != fp:
                    p = {"count": 0, "fingerprint": fp, "first_seen": _now_iso()}
                p["count"] += 1
                pend[tag] = p
                if p["count"] < cfg.get("require_confirm_cycles", 2):
                    if action == "restore":
                        _log("INFO", f"{tag}: дрейф подтверждается "
                                     f"({p['count']}/{cfg['require_confirm_cycles']})")
                    continue
            st.setdefault("pending", {}).pop(tag, None)
            confirmed[tag] = (expected, source)

        if confirmed:
            restore_jobs.setdefault(path, {}).update(confirmed)
            confirmed = {}

    # ── Уведомление о дрейфе (когда восстановление НЕ выполняется) ────────
    if drift_notes and action != "restore":
        st["last_status"] = "notify_only"
        if action == "notify":
            _tg_event("users_drift",
                      _tg_drift_text(tg_notes, "конфиг не менялся "
                                       "(режим: только уведомления)"), cfg)
        _log("WARN", f"действие={action}: дрейф не устранялся")
        st["last_check"] = _now_iso()
        _save_wd_state(st)
        return 0

    if not restore_jobs:
        # дрейф есть, но восстановление отложено (подтверждение/cooldown/
        # бюджет) — информируем одним событием
        if drift_notes:
            _tg_event("users_drift",
                      _tg_drift_text(tg_notes, "конфиг пока не менялся — дрейф "
                                       "подтверждается перед "
                                       "авто-восстановлением"), cfg)
            st["last_status"] = "drift_pending"
        else:
            st["last_status"] = "ok"
        st["last_check"] = _now_iso()
        _save_wd_state(st)
        return rc

    # ── Cooldown и бюджет ───────────────────────────────────────────────
    now = _now()
    last_restore = _ts(st.get("last_restore_ts", 0))
    cooldown_sec = int(cfg.get("cooldown_minutes", 5)) * 60
    if now - last_restore < cooldown_sec:
        _log("INFO", "cooldown: восстановление отложено "
                     f"({int((now - last_restore) // 60)} мин назад)")
        st["last_status"] = "cooldown"
        st["last_check"] = _now_iso()
        _save_wd_state(st)
        return 0

    hour_ago = now - 3600
    events = [t for t in (_ts(x) for x in st.get("restore_events", []))
              if t and t > hour_ago]
    budget = int(cfg.get("max_restores_per_hour", 6))
    if budget and len(events) >= budget:
        if not st.get("budget_alerted"):
            _log("ERROR", f"лимит восстановлений ({budget}/час) исчерпан — "
                          f"только уведомления до конца часа")
            _tg_event("users_watchdog_budget",
                      "слишком частые расхождения: авто-восстановление "
                      "приостановлено на час, проверьте ноду", cfg)
            st["budget_alerted"] = True
        st["last_status"] = "budget_exhausted"
        st["last_check"] = _now_iso()
        _save_wd_state(st)
        return 0
    if st.get("budget_alerted") and len(events) < budget:
        st["budget_alerted"] = False

    # ── Восстановление ──────────────────────────────────────────────────
    restored_any, failed_any = False, False
    for path, patches in restore_jobs.items():
        patch_plain = {tag: cl for tag, (cl, _src) in patches.items()}
        if _restore_path(path, patch_plain):
            restored_any = True
            for tag, (cl, src) in patches.items():
                st.setdefault("snapshots", {})[tag] = cl
                _tg_event("users_restored",
                          f"{tag}: список клиентов восстановлен автоматически "
                          f"(источник: {src}), Xray перезапущен", cfg)
        else:
            failed_any = True
            _tg_event("users_restore_failed",
                      f"восстановление не удалось ({path.name}), применён откат "
                      f"к исходному конфигу", cfg)

    if restored_any:
        st["last_restore_ts"] = _now()
        st["last_restore"] = _now_iso()
        st.setdefault("restore_events", []).append(_now_iso())
        st["restore_events"] = st["restore_events"][-50:]
        _prune_backups(int(cfg.get("backup_keep", 20)))
        st["last_status"] = "restored"
        rc = 1
    elif failed_any:
        st["last_status"] = "restore_failed"
        rc = 2
    st["last_check"] = _now_iso()
    _save_wd_state(st)
    return rc


def _ts(x) -> float:
    """ISO/epoch → epoch (0 при пустоте)."""
    if isinstance(x, (int, float)) and x > 0:
        return float(x)
    if isinstance(x, str) and x:
        try:
            return datetime.strptime(x[:19], "%Y-%m-%d %H:%M:%S").timestamp()
        except Exception:
            return 0.0
    return 0.0


# ── Systemd-юниты ────────────────────────────────────────────────────────────
def _installer_path() -> str:
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    return "/opt/chimera"


def _build_wrapper_script() -> str:
    """Лёгкий запуск БЕЗ main.py/_core: watchdog не должен зависеть от
    тяжёлого ядра (и от его поломок). Модуль использует только stdlib."""
    installer = _installer_path()
    return (
        "#!/bin/bash\n"
        "# users-watchdog.sh — Chimera Project\n"
        "# Автоматически создан. Управляется через меню установщика.\n"
        f"INSTALLER=\"{installer}\"\n"
        "[ -d \"$INSTALLER\" ] || INSTALLER=\"/opt/chimera\"\n"
        "PYTHONPATH=\"$INSTALLER:$PYTHONPATH\" exec /usr/bin/python3 -c '"
        "import sys; "
        "from chimera.modules.users_watchdog import users_watchdog_run; "
        "sys.exit(users_watchdog_run())'\n"
    )


def _build_service() -> str:
    return (
        "[Unit]\n"
        "Description=Users Watchdog (clients integrity vs users.json)\n"
        "After=xray.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={_SCRIPT}\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
    )


def _build_timer(interval_minutes: int) -> str:
    return (
        "[Unit]\n"
        "Description=Users Watchdog Timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=60\n"
        f"OnUnitActiveSec={interval_minutes}min\n"
        "AccuracySec=15\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def _write_logrotate() -> None:
    _LOGROTATE.write_text(
        f"{_LOG} {{\n"
        "    daily\n"
        "    rotate 7\n"
        "    compress\n"
        "    delaycompress\n"
        "    missingok\n"
        "    notifempty\n"
        "    create 0640 root root\n"
        "}\n"
    )


def users_watchdog_install(interval_minutes: int | None = None) -> None:
    """Устанавливает watchdog: сервис + таймер + logrotate, сразу делает
    первый проход (снапшот доброго состояния / немедленный фикс)."""
    cfg = _load_wd_config()
    if interval_minutes is not None:
        cfg["interval_minutes"] = interval_minutes
    cfg["enabled"] = True
    _save_wd_config(cfg)

    _SERVICE.parent.mkdir(parents=True, exist_ok=True)
    _SCRIPT.write_text(_build_wrapper_script())
    try:
        _SCRIPT.chmod(0o755)
    except Exception:
        pass
    _SERVICE.write_text(_build_service())
    _TIMER.write_text(_build_timer(cfg["interval_minutes"]))
    _write_logrotate()
    _systemctl("daemon-reload")
    _systemctl("enable", "--now", _UNIT_NAME)
    _ok(f"users-watchdog установлен (проверка каждые {cfg['interval_minutes']} мин)")
    _info(f"Лог: {_LOG}")
    # Первый проход сразу: фиксируем доброе состояние (или чиним битое)
    try:
        _cycle(force=True)
    except Exception as e:
        _warn(f"первый проход не удался: {e}")


def users_watchdog_remove() -> None:
    """Останавливает и удаляет watchdog (конфиг/состояние/логи остаются)."""
    _systemctl("disable", "--now", _UNIT_NAME)
    for f in (_TIMER, _SERVICE, _LOGROTATE, _SCRIPT):
        try:
            f.unlink(missing_ok=True)
        except Exception:
            pass
    _systemctl("daemon-reload")
    try:
        cfg = _load_wd_config()
        cfg["enabled"] = False
        _save_wd_config(cfg)
    except Exception:
        pass
    _ok("users-watchdog остановлен и удалён")


def _reapply_timer(interval_minutes: int) -> None:
    """Перезаписывает таймер с новым интервалом (если активен)."""
    if _unit_active(_UNIT_NAME):
        _TIMER.write_text(_build_timer(interval_minutes))
        _systemctl("daemon-reload")
        _systemctl("restart", _UNIT_NAME)


# ── Публичный CLI-вход ────────────────────────────────────────────────────────
def users_watchdog_run() -> int:
    """Точка входа `main.py --users-watchdog-run` (systemd-timer)."""
    try:
        return _cycle(force=False)
    except Exception as e:
        _log("ERROR", f"внутренняя ошибка цикла: {e}")
        return 2


# ── TUI-меню ─────────────────────────────────────────────────────────────────
def _choose(prompt: str, options: list, current) -> tuple:
    """Диалог выбора из списка. Возвращает (значение, изменилось)."""
    opts = {str(k): v for k, v in options}
    print()
    for k, v in options:
        mark = " ←" if (k == str(current) or str(v) == str(current)) else ""
        print(f"  {CYAN}{k}{NC} — {v}{mark}")
    try:
        ch = input(f"{CYAN}Выбор (Enter — отмена):{NC} ").strip()
    except (EOFError, KeyboardInterrupt):
        return current, False
    if ch == "" or ch not in opts:
        return current, False
    return opts[ch], True


def do_manage_users_watchdog() -> None:
    """Интерактивное меню: Безопасность и автоматизация → Users Watchdog."""
    from chimera.modules.box_renderer import (
        _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
        RED as _RED, GREEN as _GREEN, YELLOW as _YELLOW, CYAN as _CYAN, DIM as _DIM,
        NC as _NC,
    )
    while True:
        os.system("clear")
        cfg = _load_wd_config()
        st = _load_wd_state()
        active = _unit_active(_UNIT_NAME)
        enabled = _unit_enabled(_UNIT_NAME)
        status_str = f'{_GREEN}активен{_NC}' if active else f'{_YELLOW}не активен{_NC}'
        now = _now()
        events = [t for t in (_ts(x) for x in st.get("restore_events", []))
                  if t and t > now - 3600]
        snaps = st.get("snapshots", {})
        maint = _MAINT_FLAG.exists()
        snaps_str = "; ".join(f"{t}: {len(c)} кл." for t, c in snaps.items()) or "—"

        _box_top("👥  USERS WATCHDOG (ЦЕЛОСТНОСТЬ КЛИЕНТОВ)")
        _box_row(f'  Статус:   {status_str}   Таймер: {"enabled" if enabled else "disabled"}')
        _box_row(f'  Проверка: каждые {cfg["interval_minutes"]} мин; '
                 f'действие: {cfg["action_on_mismatch"]}')
        _box_row(f'  Подтверждение: {cfg["require_confirm_cycles"]} цикла; '
                 f'cooldown: {cfg["cooldown_minutes"]} мин; '
                 f'лимит: {cfg["max_restores_per_hour"] or "∞"}/час')
        _box_row(f'  Неизвестные клиенты: {"удалять" if cfg["remove_unknown_clients"] else "оставлять"}; '
                 f'прочие инбаунды: {"защищать" if cfg["protect_other_inbounds"] else "нет"}')
        _box_row(f'  Maintenance-пауза: '
                 f'{_YELLOW}ВКЛ{_NC} (проверки стоят)' if maint else
                 f'  Maintenance-пауза: выкл')
        _box_row(f'  Последняя проверка: {st.get("last_check", "—")} '
                 f'[{st.get("last_status", "—")}]')
        _box_row(f'  Восстановлений за час: {len(events)}')
        _box_row(f'  Снапшоты: {_DIM}{snaps_str[:52]}{_NC}')
        if _LOG.exists():
            lines = [l for l in _LOG.read_text(errors="replace").splitlines()[-3:]]
            if lines:
                _box_sep()
                for line in lines:
                    _box_row(f'  {_DIM}{line[:64]}{_NC}')
        _box_sep()
        _box_item("1", "Включить / Выключить watchdog")
        _box_item("2", "Проверить сейчас")
        _box_item("3", f'Интервал проверки (сейчас: {cfg["interval_minutes"]} мин)')
        _box_item("4", f'Действие при расхождении: {cfg["action_on_mismatch"]}')
        _box_item("5", f'Циклов подтверждения: {cfg["require_confirm_cycles"]}')
        _box_item("6", f'Cooldown между восстановлениями: {cfg["cooldown_minutes"]} мин')
        _box_item("7", f'Лимит восстановлений в час: {cfg["max_restores_per_hour"] or "без лимита"}')
        _box_item("8", f'Удалять неизвестных клиентов: '
                       f'{"да" if cfg["remove_unknown_clients"] else "нет"}')
        _box_item("9", f'Защита прочих инбаундов (снапшот): '
                       f'{"да" if cfg["protect_other_inbounds"] else "нет"}')
        _box_item("T", f'Уведомления Telegram: {cfg["notify"]}')
        _box_item("M", 'Maintenance-пауза '
                       f'{_DIM}(включи перед диагностиками/TUI-экспериментами){_NC}')
        _box_item("L", "Показать лог")
        _box_item("R", "Сбросить состояние (pending/снапшоты/счётчики)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{_CYAN}Выбор:{_NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if ch == "1":
            if active:
                users_watchdog_remove()
                _box_top("👥  USERS WATCHDOG — ВЫКЛЮЧЁН")
                _box_row(f"  {_YELLOW}Таймер остановлен и удалён.{_NC}")
                _box_row(f"  {_DIM}Конфиг/снапшоты/логи сохранены.{_NC}")
                _box_bottom()
            else:
                users_watchdog_install()
                _box_top("👥  USERS WATCHDOG — ВКЛЮЧЁН")
                _box_row(f"  {_GREEN}Таймер активен, первый проход выполнен.{_NC}")
                _box_bottom()
            input(f"{_CYAN}Нажмите Enter...{_NC}")

        elif ch == "2":
            _box_top("👥  РУЧНАЯ ПРОВЕРКА")
            _box_row(f"  {_CYAN}Запуск...{_NC}")
            _box_bottom()
            try:
                rc = _cycle(force=True)
                msg = {0: "расхождений нет", 1: "было восстановлено",
                       2: "ошибка — смотрите лог"}.get(rc, str(rc))
                color = _GREEN if rc == 0 else (_YELLOW if rc == 1 else _RED)
                _box_top("👥  РЕЗУЛЬТАТ ПРОВЕРКИ")
                _box_row(f"  {color}{msg}{_NC}")
                _box_bottom()
            except Exception as e:
                _box_top("👥  ОШИБКА")
                _box_row(f"  {_RED}{e}{_NC}")
                _box_bottom()
            input(f"{_CYAN}Нажмите Enter...{_NC}")

        elif ch == "3":
            val, changed = _choose("интервал",
                                   [("1", 1), ("2", 2), ("5", 5), ("10", 10),
                                    ("15", 15), ("30", 30), ("60", 60)],
                                   cfg["interval_minutes"])
            if changed:
                cfg["interval_minutes"] = val
                _save_wd_config(cfg)
                _reapply_timer(val)
                _ok(f"интервал: {val} мин")

        elif ch == "4":
            val, changed = _choose("действие",
                                   [("restore", "restore — восстанавливать"),
                                    ("notify", "notify — только уведомлять"),
                                    ("none", "none — только лог")],
                                   cfg["action_on_mismatch"])
            if changed:
                cfg["action_on_mismatch"] = val
                _save_wd_config(cfg)
                _ok(f"действие при расхождении: {val}")

        elif ch == "5":
            val, changed = _choose("циклы", [("1", 1), ("2", 2), ("3", 3)],
                                   cfg["require_confirm_cycles"])
            if changed:
                cfg["require_confirm_cycles"] = val
                _save_wd_config(cfg)
                _ok(f"подтверждение: {val} цикла")

        elif ch == "6":
            val, changed = _choose("cooldown",
                                   [("0", 0), ("2", 2), ("5", 5), ("10", 10),
                                    ("30", 30), ("60", 60)],
                                   cfg["cooldown_minutes"])
            if changed:
                cfg["cooldown_minutes"] = val
                _save_wd_config(cfg)
                _ok(f"cooldown: {val} мин")

        elif ch == "7":
            val, changed = _choose("лимит",
                                   [("0", 0), ("3", 3), ("6", 6), ("12", 12)],
                                   cfg["max_restores_per_hour"])
            if changed:
                cfg["max_restores_per_hour"] = val
                _save_wd_config(cfg)
                _ok(f"лимит: {val or 'без лимита'}/час")

        elif ch == "8":
            cfg["remove_unknown_clients"] = not cfg["remove_unknown_clients"]
            _save_wd_config(cfg)
            _ok(f"удалять неизвестных: {cfg['remove_unknown_clients']}")

        elif ch == "9":
            cfg["protect_other_inbounds"] = not cfg["protect_other_inbounds"]
            _save_wd_config(cfg)
            _ok(f"защита прочих инбаундов: {cfg['protect_other_inbounds']}")

        elif ch == "t":
            cfg["notify"] = "none" if cfg["notify"] == "tg" else "tg"
            _save_wd_config(cfg)
            _ok(f"уведомления: {cfg['notify']}")

        elif ch == "m":
            if maint:
                _MAINT_FLAG.unlink(missing_ok=True)
                _ok("maintenance-пауза снята — проверки возобновились")
            else:
                _MAINT_FLAG.parent.mkdir(parents=True, exist_ok=True)
                _MAINT_FLAG.write_text(_now_iso() + "\n")
                _warn("maintenance-пауза включена — проверки пропускаются")

        elif ch == "l":
            _box_top("👥  ЛОГ USERS WATCHDOG")
            if _LOG.exists():
                for line in _LOG.read_text(errors="replace").splitlines()[-30:]:
                    _box_row(f"  {_DIM}{line[:72]}{_NC}")
            else:
                _box_row(f"  {_YELLOW}Лог пуст или ещё не создан.{_NC}")
            _box_bottom()
            input(f"{_CYAN}Нажмите Enter...{_NC}")

        elif ch == "r":
            _save_wd_state({"snapshots": {}, "pending": {}, "restore_events": []})
            _ok("состояние сброшено (снапшоты переучатся при следующей проверке)")

        elif ch in ("q", "0", ""):
            break

