#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera/modules/v6_adaptive.py
───────────────────────────────────────────────────────────────────────────────
v6-adaptive watcher: авто-переключение dns.queryStrategy / freedom
domainStrategy по ЖИВОЙ IPv6-связности ноды (unattended, из cron).

КЕЙС (03.11.2026, 138.124.100.55 / Intezio): хостер выдаёт глобальный
IPv6-адрес + шлюз + default-маршрут (rDNS на оба семейства), но сам /64
не доводится до сегмента — egress-пакеты уходят с eth0 и молча погибают
за шлюзом, ingress 100% loss. Preflight установки честно ставит
UseIPv4. Когда хостер починит маршрутизацию, нода должна САМА перейти
на UseIPv6v4 — без ручного меню (запрос владельца 03.11: «не хочется
руками клацать»).

КОНТРАКТ:
  • Действует ТОЛЬКО при state.json["strategy"] ∈ {"", "auto"} — пустое
    значение = «адаптивно по живому v6» (родная семантика
    domain_strategy.resolve_outbound_strategy: пустой preferred →
    UseIPv6v4 при живом v6, иначе UseIPv4). Явный выбор юзера
    (UseIPv4/UseIPv6v4/UseIP/UseIPv4v6) НЕ трогается — приоритет
    установки (кейс 91.х: state-выбор важнее адаптива).
  • Патч хирургический: domain_strategy.apply_domain_strategy_to_config
    (dns.queryStrategy + все freedom-outbound'ы дуал-записью
    settings+sockopt + v4-чистка dns.servers при UseIPv4).
    routing.domainStrategy НЕ трогается (AsIs/IPOnDemand — другая
    настройка, семантика правил, не IPv4/IPv6-приоритет).
  • Безопасность: бэкап config.json с таймстампом (хранятся последние
    BACKUP_KEEP) → атомарная запись (tmp+replace, режим/владелец
    сохраняются) → `xray run -test` → safe-restart (systemctl
    reset-failed + restart + wait is-active 45с, паттерн
    _xray_safe_restart из _core). Провал валидации ИЛИ рестарта →
    откат текста конфига + повторный рестарт + TG-уведомление.
  • Идемпотентен: цель == текущему конфигу → ничего не пишет и не
    рестартит (cron каждые DEFAULT_INTERVAL мин почти бесплатен).
  • flock /var/lock — не пересекается с меню и параллельным прогоном.
  • AWG-туннель (fd66:66 ULA + NAT66 MASQUERADE) чинится САМ вместе с
    апстримом — ip6tables-правила статичны; наблюдатель их не трогает.

CLI (человек):  python3 main.py --v6-adaptive on|off|status
CLI (cron/скрипт): python3 main.py --v6-adaptive-check
  (cron-скрипт зовёт run_once() напрямую — модуль самодостаточен,
  БЕЗ exec монолита _core; паттерн exit_switch_watcher)

Событие TG: v6_strategy_switch (фильтр events в telegram.json;
неизвестные ключи по умолчанию ВКЛЮЧЕНЫ — events.get(event, True)).
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import shutil
import stat as stat_mod
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

# ── Константы (module-level: тесты патчат под tmp) ──────────────────────────
STATE_FILE       = Path("/var/lib/xray-installer/state.json")
XRAY_CONFIG      = Path("/etc/xray/config.json")
MARKER_FILE      = Path("/var/lib/xray-installer/v6_adaptive_state.json")
LOCK_FILE        = Path("/var/lock/chimera-v6-adaptive.lock")
CRON_FILE        = Path("/etc/cron.d/chimera-v6-adaptive")
CRON_SCRIPT      = Path("/usr/local/bin/chimera-v6-adaptive.sh")
LOG_FILE         = Path("/var/log/chimera-v6-adaptive.log")
TG_CFG_FILE      = Path("/var/lib/xray-installer/telegram.json")
XRAY_BIN         = "/usr/local/bin/xray"
DEFAULT_INTERVAL = 10          # минут
BACKUP_KEEP      = 5           # config.json.v6adapt-*.bak рядом с конфигом
AUTO_VALUES      = ("", "auto")   # state["strategy"]: адаптивные значения
PROBE_TARGETS    = ("2001:4860:4860::8888", "2606:4700:4700::1111")
EVENT_SWITCH     = "v6_strategy_switch"


# ── Мелкие хелперы ───────────────────────────────────────────────────────────

def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{_ts()} {msg}\n")
    except Exception:
        pass


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_text_preserving(path: Path, text: str) -> bool:
    """Атомарная запись (tmp + os.replace) с сохранением режима/владельца."""
    try:
        mode = uid = gid = None
        if path.exists():
            st = path.stat()
            mode, uid, gid = stat_mod.S_IMODE(st.st_mode), st.st_uid, st.st_gid
        tmp = path.with_name(path.name + ".v6adapt.tmp")
        tmp.write_text(text, encoding="utf-8")
        if mode is not None:
            os.chmod(tmp, mode)
            try:
                os.chown(tmp, uid, gid)
            except (PermissionError, OSError):
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        _log(f"ERROR: запись {path}: {e}")
        return False


def _mark(data: dict) -> None:
    """Маркер-наблюдаемость: последний прогон всегда виден в файле."""
    _write_text_preserving(MARKER_FILE, json.dumps(data, indent=2,
                                                   ensure_ascii=False))


# ── Пробы ────────────────────────────────────────────────────────────────────

def _probe_v6(runner: Optional[Any] = None) -> tuple[bool, str]:
    """
    Живая v6-связность ноды: (адрес → маршрут → egress-пинг).

    Зеркалит _check_ipv6_preflight() из _core (адрес и маршрут — как там),
    плюс реальная проба egress до двух anycast-целей. Ранний выход при
    успехе; при мёртвом egress — 2×2с на прогон.
    """
    run = runner or subprocess.run

    def _r(cmd: list) -> Any:
        try:
            return run(cmd, capture_output=True, text=True, timeout=10)
        except Exception:
            return None

    r = _r(["ip", "-6", "addr", "show", "scope", "global"])
    if r is None or "inet6" not in (getattr(r, "stdout", "") or ""):
        return False, "нет глобального IPv6-адреса"

    r = _r(["ip", "-6", "route", "show", "default"])
    if r is None or "default" not in (getattr(r, "stdout", "") or ""):
        return False, "нет default-маршрута IPv6"

    for t in PROBE_TARGETS:
        r = _r(["ping", "-6", "-c", "1", "-W", "2", t])
        if r is not None and getattr(r, "returncode", 1) == 0:
            return True, f"жив (ответ от {t})"
    return False, "egress мёртв (обе пробы loss)"


def _xray_test_ok(runner: Optional[Any] = None) -> bool:
    """Валидация конфига самим ядром ДО рестарта."""
    run = runner or subprocess.run
    binp = XRAY_BIN if os.path.exists(XRAY_BIN) else shutil.which("xray")
    if not binp:
        _log("WARN: xray-бинарник не найден — валидация пропущена")
        return True
    try:
        r = run([str(binp), "run", "-test", "-c", str(XRAY_CONFIG)],
                capture_output=True, text=True, timeout=30)
        return getattr(r, "returncode", 1) == 0
    except Exception as e:
        _log(f"ERROR: xray run -test: {e}")
        return False


def _safe_restart(runner: Optional[Any] = None,
                  sleep: Optional[Any] = None) -> bool:
    """
    Безопасный рестарт xray (паттерн _xray_safe_restart из _core):
    reset-failed гасит start-rate-limit (StartLimitBurst=3/60s юнита),
    затем restart и ожидание is-active до 45с.
    """
    run = runner or subprocess.run
    _sl = sleep or time.sleep
    try:
        run(["systemctl", "reset-failed", "xray"],
            capture_output=True, text=True, timeout=15)
        run(["systemctl", "restart", "xray"],
            capture_output=True, text=True, timeout=60)
    except Exception as e:
        _log(f"ERROR: systemctl restart xray: {e}")
        return False
    for _ in range(45):
        try:
            r = run(["systemctl", "is-active", "xray"],
                    capture_output=True, text=True, timeout=10)
            if (getattr(r, "stdout", "") or "").strip() == "active":
                return True
        except Exception:
            pass
        _sl(1)
    return False


def _tg_notify(detail: str) -> None:
    """TG-уведомление. Основной путь — общий tg_bot (уважает events-фильтр
    telegram.json), fallback — прямой curl (паттерн exit_switch_watcher).
    Best-effort: никогда не поднимает исключений."""
    try:
        from chimera.modules import tg_bot
        tg_bot.tg_notify_event(EVENT_SWITCH, detail)
        return
    except Exception as e:
        _log(f"WARN: tg_bot недоступен ({e}) — curl-fallback")
    try:
        cfg = _read_json(TG_CFG_FILE, {}) or {}
        token = str(cfg.get("token") or "")
        chat = str(cfg.get("chat_id") or "")
        if not token or not chat:
            return
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-m", "10",
             f"https://api.telegram.org/bot{token}/sendMessage",
             "-d", f"chat_id={chat}", "-d", f"text={detail}"],
            capture_output=True, text=True, timeout=15)
    except Exception:
        pass


# ── Бэкапы ───────────────────────────────────────────────────────────────────

def _backup_path() -> Path:
    return XRAY_CONFIG.with_name(
        f"{XRAY_CONFIG.name}.v6adapt-{time.strftime('%Y%m%d-%H%M%S')}.bak")


def _prune_backups(keep: int = BACKUP_KEEP) -> None:
    try:
        baks = sorted(XRAY_CONFIG.parent.glob(f"{XRAY_CONFIG.name}.v6adapt-*.bak"))
        for old in (baks[:-keep] if keep > 0 else baks):
            old.unlink(missing_ok=True)
    except Exception:
        pass


def _restore(bak: Path, original_text: str) -> None:
    try:
        text = bak.read_text(encoding="utf-8") if bak.exists() else original_text
    except Exception:
        text = original_text
    _write_text_preserving(XRAY_CONFIG, text)


# ── Ядро: одна итерация ──────────────────────────────────────────────────────

def run_once(apply: bool = True) -> dict:
    """
    Одна итерация наблюдателя (cron / --v6-adaptive-check / enable()).

    Возвращает отчёт-словарь: action = no-state | skip-explicit |
    no-config | bad-config | busy | noop | dry-run | switched |
    fail-write | rollback-validate | rollback-restart.
    """
    lock_fd = None
    try:
        try:
            LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = open(LOCK_FILE, "a")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"action": "busy", "ts": _ts()}
        except Exception as e:
            _log(f"WARN: lock недоступен ({e}) — продолжаю без него")

        state = _read_json(STATE_FILE, None)
        if not isinstance(state, dict):
            _mark({"action": "no-state", "ts": _ts()})
            return {"action": "no-state"}

        strategy = str(state.get("strategy", "") or "")
        if strategy not in AUTO_VALUES:
            # явный выбор установки — приоритет юзера (кейс 91.х)
            _mark({"action": "skip-explicit", "strategy": strategy,
                   "ts": _ts()})
            return {"action": "skip-explicit", "strategy": strategy}

        alive, detail = _probe_v6()

        from chimera.modules.domain_strategy import (
            apply_domain_strategy_to_config, resolve_outbound_strategy,
        )
        target = resolve_outbound_strategy("", alive)

        if not XRAY_CONFIG.exists():
            _mark({"action": "no-config", "alive": alive, "target": target,
                   "ts": _ts()})
            return {"action": "no-config", "alive": alive, "target": target}

        cfg_text = XRAY_CONFIG.read_text(encoding="utf-8")
        try:
            config = json.loads(cfg_text)
        except Exception as e:
            _log(f"ERROR: config.json не парсится ({e}) — не трогаю")
            _mark({"action": "bad-config", "ts": _ts()})
            return {"action": "bad-config"}

        changes = apply_domain_strategy_to_config(config, target)
        if not changes:
            _mark({"action": "noop", "alive": alive, "target": target,
                   "detail": detail, "ts": _ts()})
            return {"action": "noop", "alive": alive, "target": target}

        if not apply:
            _mark({"action": "dry-run", "alive": alive, "target": target,
                   "changes": changes, "ts": _ts()})
            return {"action": "dry-run", "alive": alive, "target": target,
                    "changes": changes}

        # бэкап → патч → валидация → рестарт (провал → откат)
        bak = _backup_path()
        try:
            bak.write_text(cfg_text, encoding="utf-8")
            _prune_backups()
        except Exception as e:
            _log(f"WARN: бэкап не записан ({e}) — продолжаю")

        if not _write_text_preserving(
                XRAY_CONFIG,
                json.dumps(config, indent=2, ensure_ascii=False)):
            _restore(bak, cfg_text)
            _mark({"action": "fail-write", "ts": _ts()})
            _tg_notify("v6-adaptive: ошибка записи config.json — откат")
            return {"action": "fail-write"}

        if not _xray_test_ok():
            # конфиг откачен; РАБОТАЮЩИЙ xray не трогаем — он читал
            # конфиг при старте и продолжает жить на прежнем (файл
            # восстановлен), рестарт не нужен.
            _restore(bak, cfg_text)
            _mark({"action": "rollback-validate", "target": target,
                   "ts": _ts()})
            _tg_notify(f"v6-adaptive: xray -test провален при {target} — "
                       f"конфиг откачен на прежнюю стратегию")
            return {"action": "rollback-validate", "target": target}

        if not _safe_restart():
            # рестарт не удался — вернуть прежний текст и поднять xray на нём
            _write_text_preserving(XRAY_CONFIG, cfg_text)
            _safe_restart()
            _mark({"action": "rollback-restart", "target": target,
                   "ts": _ts()})
            _tg_notify(f"v6-adaptive: рестарт xray провален ({target}) — "
                       f"откат и подъём на прежней стратегии")
            return {"action": "rollback-restart", "target": target}

        try:
            prev = json.loads(cfg_text).get("dns", {}).get(
                "queryStrategy", "")
        except Exception:
            prev = ""
        _mark({"action": "switched", "from": prev, "to": target,
               "alive": alive, "changes": changes, "ts": _ts()})
        _tg_notify(f"v6-adaptive: стратегия {prev or '?'} → {target} "
                   f"({'v6 ожил' if alive else 'v6 мёртв'}; {detail})")
        return {"action": "switched", "from": prev, "to": target,
                "alive": alive, "changes": changes}
    finally:
        try:
            if lock_fd is not None:
                lock_fd.close()
        except Exception:
            pass


# ── Cron lifecycle (паттерн exit_switch_watcher) ────────────────────────────

def _find_python() -> str:
    return shutil.which("python3") or "/usr/bin/python3"


def _installer_path() -> str:
    try:
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            return str(Path(list(spec.submodule_search_locations)[0]).parent)
    except Exception:
        pass
    return "/opt/chimera"


def install_watcher(interval_min: int = DEFAULT_INTERVAL) -> tuple[bool, str]:
    """Ставит cron-задачу наблюдателя (1–60 мин) + bash-обёртку."""
    try:
        interval = max(1, min(60, int(interval_min)))
        inst = _installer_path()
        py = _find_python()
        script = (
            "#!/bin/bash\n"
            "# chimera-v6-adaptive.sh — v6-adaptive watcher (Chimera Project)\n"
            f"export PYTHONPATH=\"{inst}:$PYTHONPATH\"\n"
            f"{py} -c \"\n"
            "import sys\n"
            f"sys.path.insert(0, '{inst}')\n"
            "from chimera.modules.v6_adaptive import run_once\n"
            "run_once()\n"
            f"\" 2>>{LOG_FILE}\n"
        )
        CRON_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        CRON_SCRIPT.write_text(script, encoding="utf-8")
        CRON_SCRIPT.chmod(0o750)
        CRON_FILE.parent.mkdir(parents=True, exist_ok=True)
        CRON_FILE.write_text(
            f"# chimera-v6-adaptive — авто domainStrategy по живому IPv6 "
            f"каждые {interval} мин (Chimera Project)\n"
            f"*/{interval} * * * * root {CRON_SCRIPT} "
            f">> {LOG_FILE} 2>&1\n",
            encoding="utf-8")
        CRON_FILE.chmod(0o644)
        return True, f"v6-adaptive cron установлен (интервал {interval} мин)"
    except Exception as e:
        return False, f"Ошибка установки cron: {e}"


def uninstall_watcher() -> tuple[bool, str]:
    """Снимает cron (state.json и маркер не трогает)."""
    try:
        CRON_FILE.unlink(missing_ok=True)
        CRON_SCRIPT.unlink(missing_ok=True)
        return True, "v6-adaptive cron снят"
    except Exception as e:
        return False, f"Ошибка снятия cron: {e}"


# ── Управление (CLI) ─────────────────────────────────────────────────────────

def enable() -> tuple[bool, str]:
    """
    Включить адаптивный режим: state["strategy"]="" (родная семантика
    «адаптивно по живому v6» у resolve_outbound_strategy) + cron + первый
    прогон сразу. Явную стратегию, прописанную установкой, затирает —
    в этом и есть смысл команды (запрос владельца 03.11).
    """
    state = _read_json(STATE_FILE, None)
    if not isinstance(state, dict):
        return False, "state.json не найден — сначала установка Xray"
    state["strategy"] = ""
    if not _write_text_preserving(
            STATE_FILE, json.dumps(state, indent=2, ensure_ascii=False)):
        return False, "не удалось записать state.json"
    ok, msg = install_watcher()
    if not ok:
        return False, msg
    rep = run_once(apply=True)
    extra = ""
    if rep.get("action") == "switched":
        extra = f" (сразу переключил: {rep.get('from')} → {rep.get('to')})"
    return True, f"Адаптивный режим включён (strategy='' + cron): {msg}{extra}"


def disable() -> tuple[bool, str]:
    """Выключить наблюдатель. state['strategy'] НЕ меняется — вернуть
    явный выбор можно меню: Настройки сети → 6 (domainStrategy)."""
    ok, msg = uninstall_watcher()
    suffix = ("; state['strategy'] не менялся — явный выбор: "
              "Настройки сети → 6")
    return ok, msg + suffix if ok else msg


def status() -> dict:
    state = _read_json(STATE_FILE, {}) or {}
    alive, detail = _probe_v6()
    cur_qs = ""
    if XRAY_CONFIG.exists():
        cfg = _read_json(XRAY_CONFIG, {}) or {}
        cur_qs = str((cfg.get("dns") or {}).get("queryStrategy", ""))
    strategy = str(state.get("strategy", "") or "")
    return {
        "strategy_state": strategy,
        "adaptive": strategy in AUTO_VALUES,
        "cron_installed": CRON_FILE.exists(),
        "v6_alive": alive,
        "v6_detail": detail,
        "target": "UseIPv6v4" if alive else "UseIPv4",
        "current_query_strategy": cur_qs,
        "last": _read_json(MARKER_FILE, {}),
    }


def main(argv: Optional[list] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--v6-adaptive-check" in args:
        rep = run_once(apply=True)
        print(json.dumps(rep, ensure_ascii=False))
        return 0
    sub = "status"
    if "--v6-adaptive" in args:
        i = args.index("--v6-adaptive")
        rest = [a for a in args[i + 1:] if not a.startswith("--")]
        if rest:
            sub = rest[0].lower()
    if sub in ("on", "enable"):
        ok, msg = enable()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    if sub in ("off", "disable"):
        ok, msg = disable()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    st = status()
    print(f"strategy state : {st['strategy_state']!r}"
          + (" (адаптив)" if st["adaptive"]
             else " (явный выбор — watcher не трогает)"))
    print(f"cron           : "
          + ("установлен" if st["cron_installed"] else "нет"))
    print(f"IPv6 жив       : " + ("да" if st["v6_alive"] else "нет")
          + f" ({st['v6_detail']})")
    print(f"цель           : {st['target']}")
    print(f"config dns.queryStrategy: {st['current_query_strategy'] or '(нет)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
