#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chimera/modules/v6_adaptive.py
───────────────────────────────────────────────────────────────────────────────
v6-adaptive watcher: авто-переключение dns.queryStrategy / freedom
domainStrategy по ЖИВОЙ IPv6-связности ноды (unattended, из cron).

КЕЙС (03.11.2026, 203.0.113.55 / хостер): хостер выдаёт глобальный
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
TUI:  Настройки сети → V — do_v6_adaptive_menu(): живой статус (проба
  при отрисовке), вкл/выкл наблюдателя, ручной прогон, подробности
  (оформление — box_renderer _core, паттерн tfo_settings: «Настройки
  сети → T»)

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
    Fallback-уведа получает заголовок «[имя · домен · IP]» (канон
    node_identity.server_header, волна-3) — как у конвейера; недоступен
    node_identity — без заголовка (прежний вид).
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
        try:
            from chimera.modules.node_identity import server_header
            _hdr = str(server_header(cfg) or "").strip()
        except Exception:
            _hdr = ""
        text = f"[{_hdr}] {detail}" if _hdr else detail
        subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-m", "10",
             f"https://api.telegram.org/bot{token}/sendMessage",
             "-d", f"chat_id={chat}", "-d", f"text={text}"],
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
    tg_cfg = _read_json(TG_CFG_FILE, {}) or {}
    tg_ready = bool(str(tg_cfg.get("token") or "")
                    and str(tg_cfg.get("chat_id") or ""))
    return {
        "strategy_state": strategy,
        "adaptive": strategy in AUTO_VALUES,
        "cron_installed": CRON_FILE.exists(),
        "v6_alive": alive,
        "v6_detail": detail,
        "target": "UseIPv6v4" if alive else "UseIPv4",
        "current_query_strategy": cur_qs,
        "last": _read_json(MARKER_FILE, {}),
        "tg_ready": tg_ready,
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
    print("TG-уведы      : "
          + ("настроены" if st.get("tg_ready")
             else "нет (Безопасность и автоматизация → S → 📬 Telegram)"))
    return 0


# ── TUI: пункт меню «Настройки сети → V» (паттерн tfo_settings) ──────────────
#
# Канон оформления: box_renderer монолита (_box_top/_box_row/_box_item/
# _box_desc/_box_sep/_box_back/_box_bottom) + ленивый _core_module()
# (tfo_settings/chain_nodes). Чистые рендеры (_status_rows/_report_text/
# _log_tail) не зависят от _core и покрыты юнит-тестами; интерактивная
# обёртка do_v6_adaptive_menu() — тонкая, тестится smoke-ом с фейковым
# chimera._core (канон tests/test_awg_ui_smoke.py). Под пайпом (EOF на
# input) меню не падает — канон entry_mirrors.

NC_FALLBACK = "\033"   # сброс цвета, если _core недоступен (паттерн tfo)

# Цветовые метки строк статуса (TUI-агностичны: в меню маппятся на ANSI
# _core, в тестах — просто идентификаторы)
C_OK, C_WARN, C_BAD, C_INFO, C_DIM = "ok", "warn", "bad", "info", "dim"


def _core_module():
    """Ленивая привязка к chimera._core (как в tfo_settings/chain_nodes)."""
    import importlib
    return importlib.import_module("chimera._core")


def _tui_error(msg: str) -> None:
    """[ERROR]-печать. В _core.py функции error НЕТ (только info/success/
    warn) — свой хелпер по паттерну tfo_settings._error (инцидент 29.08:
    AttributeError в меню T). Отказ _core (headless/тесты) → stderr,
    без падения."""
    try:
        core = _core_module()
        print(f"{core.RED}[ERROR]{NC_FALLBACK} {msg}")
        try:
            core.log_to_file("ERROR", msg)
        except Exception:
            pass
    except Exception:
        print(f"[v6-adaptive:ERROR] {msg}", file=sys.stderr)


def _status_rows(st: dict) -> list[tuple[str, str, str]]:
    """Статус → строки (label, value, метка цвета) для _box_row.

    Чистая функция (без _core/ANSI/subprocess) — тестопригодное ядро
    меню; на вход — словарь status().
    """
    rows: list[tuple[str, str, str]] = []
    if st.get("adaptive"):
        rows.append(("Режим",
                     "АДАПТИВНЫЙ — нода сама держит стратегию по живому IPv6",
                     C_OK))
    else:
        rows.append(("Режим",
                     f"явный выбор: {st.get('strategy_state') or '?'} "
                     f"(наблюдатель не трогает)",
                     C_WARN))
    rows.append(("Наблюдатель",
                 "установлен (cron)" if st.get("cron_installed")
                 else "не установлен",
                 C_OK if st.get("cron_installed") else C_DIM))
    if st.get("v6_alive"):
        rows.append(("IPv6 сейчас",
                     str(st.get("v6_detail") or "").strip() or "жив",
                     C_OK))
    else:
        rows.append(("IPv6 сейчас",
                     str(st.get("v6_detail") or "").strip() or "мёртв",
                     C_BAD))
    if st.get("adaptive"):
        rows.append(("Цель стратегии", str(st.get("target", "?")), C_INFO))
    qs = str(st.get("current_query_strategy") or "")
    rows.append(("В конфиге Xray",
                 f"dns.queryStrategy = {qs}" if qs
                 else "dns.queryStrategy не задан",
                 C_INFO))
    last = st.get("last") or {}
    if isinstance(last, dict) and last.get("action"):
        rows.append(("Последний прогон",
                     f"{last.get('ts', '?')} — {last.get('action')}",
                     C_DIM))
    # TG-уведы о переключении (v6_strategy_switch): бот не настроен на
    # свежей ноде — переключение прошло бы молча; показываем состояние
    # прямо здесь (вопрос владельца 03.11: «а уведы в ТГ будут
    # приходить?»)
    if st.get("tg_ready"):
        rows.append(("TG-уведы",
                     "настроены — переключение придёт в чат", C_OK))
    else:
        rows.append(("TG-уведы",
                     "не настроены (Безопасность и автоматизация → S)", C_WARN))
    return rows


_REPORT_LABELS = {
    "no-state":          "state.json не найден — сначала установка Xray",
    "skip-explicit":     "явный выбор стратегии в state — наблюдатель не трогает",
    "no-config":         "config.json не найден — наблюдатель ждёт установку",
    "bad-config":        "config.json не парсится — конфиг не тронут",
    "busy":              "прогон уже идёт (lock) — повторите позже",
    "noop":              "конфиг уже соответствует цели — изменений нет",
    "dry-run":           "dry-run: изменения показаны, не применялись",
    "switched":          "переключил стратегию",
    "fail-write":        "ошибка записи config.json — откат",
    "rollback-validate": "xray -test провален — конфиг откачен, xray не трогали",
    "rollback-restart":  "рестарт не удался — откат и подъём на прежней стратегии",
}


def _report_text(rep: dict) -> str:
    """Резюме прогона run_once для меню (чистая функция)."""
    act = str(rep.get("action", "?"))
    label = _REPORT_LABELS.get(act, act)
    if act == "switched":
        label += (f": {rep.get('from') or '?'} → {rep.get('to')}"
                  f" ({'v6 ожил' if rep.get('alive') else 'v6 мёртв'})")
    return label


def _log_tail(n: int = 6) -> list[str]:
    """Последние n строк журнала (best-effort, для «Подробностей»)."""
    try:
        return LOG_FILE.read_text(encoding="utf-8").splitlines()[-n:]
    except Exception:
        return []


def _pause(core) -> None:
    """«Нажмите Enter» — EOF-безопасно (канон entry_mirrors: под пайпом
    диалоги не падают)."""
    try:
        input(f"{core.BLUE}Нажмите Enter...{core.NC}")
    except (EOFError, KeyboardInterrupt):
        pass


def _show_last_details(core) -> None:
    """Пункт «Подробности»: маркер последнего прогона + хвост журнала."""
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_bottom = core._box_bottom
    DIM, NC = core.DIM, core.NC
    last = _read_json(MARKER_FILE, {}) or {}
    _box_top("V6-ADAPTIVE — ПОСЛЕДНИЙ ПРОГОН")
    _box_row()
    if not last:
        _box_row(f"  {DIM}маркер не создан — наблюдатель ещё не прогонялся{NC}")
    else:
        for k in ("ts", "action", "from", "to", "alive", "target", "detail"):
            if k in last:
                _box_row(f"  {k + ':':<10} {last[k]}")
        for c in (last.get("changes") or []):
            _box_row(f"  change:   {c}")
    _box_row()
    tail = _log_tail(6)
    if tail:
        _box_row(f"  {DIM}— журнал (хвост):{NC}")
        for line in tail:
            _box_row(f"  {DIM}{line}{NC}")
    _box_bottom()


def do_v6_adaptive_menu() -> None:
    """Меню «Настройки сети → V»: адаптивная стратегия по живому IPv6.

    Статус в реальном времени (проба v6 при отрисовке) + вкл/выкл
    наблюдателя + ручной прогон + подробности. Включение = enable()
    (state["strategy"]="" + cron + первый прогон сразу), выключение =
    disable() (снимает ТОЛЬКО cron; вернуть явный выбор — пункт 6).
    """
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_item   = core._box_item
    _box_desc   = core._box_desc
    _box_sep    = core._box_sep
    _box_back   = core._box_back
    _box_bottom = core._box_bottom
    info    = core.info
    success = core.success
    warn    = core.warn
    CYAN = core.CYAN
    NC   = core.NC
    _colors = {C_OK: core.GREEN, C_WARN: core.YELLOW, C_BAD: core.RED,
               C_INFO: CYAN, C_DIM: core.DIM}

    while True:
        os.system("clear")
        print()
        st = status()
        _box_top("🔄  V6-ADAPTIVE — АВТОМАТИКА СТРАТЕГИИ")
        _box_row()
        for label, value, c in _status_rows(st):
            _box_row(f"  {label + ':':<18} {_colors.get(c, '')}{value}{NC}")
        _box_sep()
        _box_desc("Наблюдатель (cron, 10 мин) пробует живой IPv6 ноды и")
        _box_desc("держит dns.queryStrategy + freedom-outbound'ы в соответствии:")
        _box_desc("v6 жив → UseIPv6v4, мёртв → UseIPv4. Явный выбор (пункт 6)")
        _box_desc("всегда приоритетнее — наблюдатель его не трогает.")
        _box_row()
        if st["adaptive"] and st["cron_installed"]:
            _box_item("1", f"⏹  Выключить наблюдатель  {core.DIM}(снять cron; ничего не меняется){NC}")
            _box_item("2", "↻  Проверить сейчас  (ручной прогон наблюдателя)")
        else:
            _box_item("1", f"🟢 Включить адаптивный режим  {core.DIM}(cron + первый прогон сразу){NC}")
            _box_item("2", "↻  Проверить сейчас  (одиночный прогон, без cron)")
        _box_item("3", "📋 Подробности последнего прогона")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        try:
            # Q — что рендерит _box_back(); b/B/0 — паритет с tfo_settings
            if ch in ("q", "Q", "b", "B", "0", ""):
                break
            if ch == "1":
                if st["adaptive"] and st["cron_installed"]:
                    ok, msg = disable()
                else:
                    ok, msg = enable()
                (success if ok else warn)(msg)
            elif ch == "2":
                rep = run_once(apply=True)
                info(f"Прогон: {_report_text(rep)}")
            elif ch == "3":
                _show_last_details(core)
            else:
                warn("Неверный выбор.")
        except Exception as e:   # меню не должно вылетать целиком (кейс T)
            _tui_error(f"v6-adaptive: {e}")
        _pause(core)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
