"""
vless_installer/modules/server_fragment.py
───────────────────────────────────────────────────────────────────────────────
Server-side TLS fragmentation — sockopt.fragment на INBOUND-стороне сервера.

АРХИТЕКТУРА:
  Сейчас fragment_config.py применяется только к CLIENT-конфигу (outbound),
  что бьёт по исходящему TLS ClientHello. Но ТСПУ смотрит трафик в обе
  стороны: если сервер шлёт ServerHello + Certificate одним куском, DPI
  видит асимметрию (ClientHello дроблённый, ServerHello цельный) и
  классифицирует соединение как прокси.

  Решение: включить sockopt.fragment на inbound в /etc/xray/config.json.
  Xray-core поддерживает fragment на inbound с v1.8.13+ — поле
  `streamSettings.sockopt.fragment` на inbound-блоке VLESS+REALITY.

  Работает так: ядро дробит первые N TCP-сегментов ответа сервера
  (ServerHello + Cert + ServerKeyExchange) на мелкие части с задержкой.
  DPI теряет цельную сигнатуру и не может сопоставить её с реальным
  Cloudflare-ответом (который виден в dest-домене REALITY).

ВНИМАНИЕ:
  • Применяется ТОЛЬКО к inbound VLESS+REALITY. На xHTTP inbound
    бесполезно (там TLS терминирует nginx, не Xray).
  • Совместим с mode A и mode B (Entry-нода).
  • После применения нужен restart xray.
  • При пересоздании config.json (reconfigure, switch-mode) настройки
    слетают — поэтому модуль хранит параметры в state.json и патчит
    config.json повторно через server_fragment_reapply_after_rebuild().

ТОЧКИ ВЫЗОВА:
  • do_server_fragment_menu()                 — TUI-меню
  • server_fragment_enable()                  — применить fragment на inbound
  • server_fragment_disable()                 — снять fragment с inbound
  • server_fragment_status()                  — dict состояния
  • server_fragment_reapply_after_rebuild()   — хук после пересоздания config
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

# ── Цвета (как во всех модулях проекта) ───────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ──────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [SERVER-FRAGMENT] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");    _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}");   _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}");  _log("WARN",    msg)
def error(msg: str)   -> None: print(f"{RED}[ERR]{NC}   {msg}");     _log("ERROR",   msg)


from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_item, _box_item_exit, _box_sep,
    _box_bottom, _box_back, _box_desc, _box_info, _box_warn, _box_ok,
)


# ── Константы ────────────────────────────────────────────────────────────────
_XRAY_CONFIG     = Path("/etc/xray/config.json")
_XRAY_CONFIG_ALT = Path("/usr/local/etc/xray/config.json")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")

# Пресеты server-side fragment (вдвое мягче клиентского — бьём по ответу,
# который обычно крупнее ClientHello и быстрее детектируется)
_PRESETS = {
    "aggressive": {
        "packets":  "1-3",
        "length":   "1-3",
        "interval": "5-10",
        "desc":     "Агрессивная (1–3 байта) — максимальный обход DPI на ответе",
    },
    "balanced": {
        "packets":  "1-3",
        "length":   "3-7",
        "interval": "10-20",
        "desc":     "Сбалансированная (3–7 байт) — рекомендуется",
    },
    "light": {
        "packets":  "1-2",
        "length":   "5-15",
        "interval": "20-50",
        "desc":     "Лёгкая (5–15 байт) — минимальный оверхед",
    },
    "custom": {
        "packets":  "",
        "length":   "",
        "interval": "",
        "desc":     "Пользовательская — ввести вручную",
    },
}


# ── Xray config helpers ──────────────────────────────────────────────────────

def _find_xray_config() -> Optional[Path]:
    """Возвращает канонический путь к config.json (он же используется в systemd)."""
    for p in (_XRAY_CONFIG, _XRAY_CONFIG_ALT):
        if p.exists():
            return p
    return None


def _load_xray_config() -> Optional[dict]:
    p = _find_xray_config()
    if not p:
        return None
    try:
        return json.loads(p.read_text())
    except Exception as e:
        error(f"Не удалось прочитать xray config: {e}")
        return None


def _save_xray_config(cfg: dict) -> bool:
    """Атомарная запись (с учётом symlink — пишем в target)."""
    p = _find_xray_config() or _XRAY_CONFIG
    target = p.resolve() if p.is_symlink() else p
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        tmp.replace(target)
        # Восстанавливаем владельца, если это /etc/xray/config.json
        try:
            import shutil
            shutil.chown(target, user="nobody", group="nogroup")
        except Exception:
            pass
        return True
    except Exception as e:
        error(f"Не удалось сохранить xray config: {e}")
        return False


def _xray_test_and_restart() -> bool:
    """Проверяет конфиг, перезапускает xray, возвращает True при успехе."""
    p = _find_xray_config()
    if not p:
        error("config.json не найден — нечего проверять")
        return False

    # Тест
    xray_bin = Path("/usr/local/bin/xray")
    if not xray_bin.exists():
        xray_bin = Path("/usr/bin/xray")
    r = _run([str(xray_bin), "run", "-test", "-config", str(p)],
             capture=True, quiet=True, check=False)
    if r.returncode != 0:
        error("Конфиг невалиден! Откат не выполняю, чтобы не сломать работающий.")
        error((r.stdout + r.stderr)[:400])
        return False

    # Рестарт
    for svc in ("xray", "xray-core"):
        rs = _run(["systemctl", "is-active", "--quiet", svc], quiet=True)
        if rs.returncode == 0:
            _run(["systemctl", "restart", svc], quiet=True)
            time.sleep(2)
            rs2 = _run(["systemctl", "is-active", "--quiet", svc], quiet=True)
            return rs2.returncode == 0
    warn("xray сервис не активен — конфиг сохранён, но не перезапущен")
    return True


# ── subprocess helper (локальный) ────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int = 60):
    import subprocess
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8",
                  errors="replace", timeout=timeout)
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  timeout=timeout)
    return subprocess.run(cmd, **kw)


# ── State helpers ────────────────────────────────────────────────────────────

def _load_state() -> dict:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(st: dict) -> None:
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception as e:
        error(f"Ошибка записи state.json: {e}")


def _load_server_fragment_state() -> dict:
    st = _load_state()
    return st.get("server_fragment", {})


def _save_server_fragment_state(sf: dict) -> None:
    st = _load_state()
    st["server_fragment"] = sf
    _save_state(st)


def _ensure_state() -> dict:
    st = _load_state()
    if "server_fragment" not in st:
        st["server_fragment"] = {
            "enabled":  False,
            "preset":   "balanced",
            "packets":  "1-3",
            "length":   "3-7",
            "interval": "10-20",
            "last_applied": "",
        }
        _save_state(st)
    return st["server_fragment"]


# ── Поиск подходящего inbound ────────────────────────────────────────────────

def _find_reality_inbound(cfg: dict) -> Optional[dict]:
    """
    Находит inbound VLESS+REALITY — на него имеет смысл вешать server-side
    fragment (т.к. именно там сервер шлёт ServerHello + Cert, который DPI
    может проанализировать).
    """
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") != "vless":
            continue
        ss = inb.get("streamSettings", {})
        if ss.get("security") == "reality":
            return inb
    return None


def _find_xhttp_inbound(cfg: dict) -> Optional[dict]:
    """Находит inbound VLESS+xHTTP (для информативности — фрагмент тут не нужен)."""
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") != "vless":
            continue
        ss = inb.get("streamSettings", {})
        if ss.get("network") == "xhttp":
            return inb
    return None


# ── Публичный API ────────────────────────────────────────────────────────────

def server_fragment_enable(
    preset: str = "balanced",
    packets: str = "",
    length: str = "",
    interval: str = "",
    restart: bool = True,
) -> bool:
    """
    Включает sockopt.fragment на VLESS+REALITY inbound.

    Args:
      preset:    один из _PRESETS — берёт packets/length/interval из пресета
      packets/length/interval: если заданы — переопределяют пресет
      restart:   перезапустить xray после применения

    Возвращает True при успехе.
    """
    if preset not in _PRESETS:
        error(f"Неизвестный пресет: {preset}")
        return False

    p = _PRESETS[preset]
    pkts = packets  or p["packets"]
    lng  = length   or p["length"]
    ivl  = interval or p["interval"]

    if preset == "custom" and not (pkts and lng and ivl):
        error("Custom пресет требует задания packets/length/interval")
        return False

    cfg = _load_xray_config()
    if cfg is None:
        error("config.json не найден — сначала установите VLESS-сервер")
        return False

    inb = _find_reality_inbound(cfg)
    if inb is None:
        # Проверим, может это xHTTP-режим
        xh = _find_xhttp_inbound(cfg)
        if xh is not None:
            error("Server-side fragment неприменим в xHTTP-режиме: TLS терминирует nginx,")
            error("не Xray. Включите REALITY-режим или фрагментируйте ответ в nginx (отдельная задача).")
        else:
            error("Не найден VLESS+REALITY inbound в config.json")
        return False

    # Вставляем/обновляем sockopt.fragment в streamSettings
    ss = inb.setdefault("streamSettings", {})
    sockopt = ss.setdefault("sockopt", {})
    # Сохраняем существующие настройки sockopt (tcpFastOpen и пр.)
    sockopt["fragment"] = {
        "packets":  pkts,
        "length":   lng,
        "interval": ivl,
    }

    if not _save_xray_config(cfg):
        return False

    info(f"Server-side fragment применён: preset={preset} "
         f"packets={pkts} length={lng} interval={ivl}ms")

    if restart:
        if not _xray_test_and_restart():
            # Откатываем фрагмент
            warn("Откатываю fragment из-за ошибки перезапуска xray")
            cfg2 = _load_xray_config()
            if cfg2:
                inb2 = _find_reality_inbound(cfg2)
                if inb2:
                    sockopt2 = inb2.get("streamSettings", {}).get("sockopt", {})
                    sockopt2.pop("fragment", None)
                    _save_xray_config(cfg2)
                    _xray_test_and_restart()
            return False

    # Сохраняем в state
    sf = _ensure_state()
    sf.update({
        "enabled":       True,
        "preset":        preset,
        "packets":       pkts,
        "length":        lng,
        "interval":      ivl,
        "last_applied":  time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    _save_server_fragment_state(sf)

    success("Server-side TLS fragmentation активирована")
    _log("INFO", f"Server fragment enabled: preset={preset}, "
                  f"packets={pkts} length={lng} interval={ivl}")
    return True


def server_fragment_disable(restart: bool = True) -> bool:
    """Снимает sockopt.fragment с REALITY inbound."""
    cfg = _load_xray_config()
    if cfg is None:
        return False

    inb = _find_reality_inbound(cfg)
    if inb is None:
        warn("VLESS+REALITY inbound не найден — снимать нечего")
    else:
        sockopt = inb.get("streamSettings", {}).get("sockopt", {})
        if "fragment" in sockopt:
            sockopt.pop("fragment")
            info("Удаляю sockopt.fragment из REALITY inbound")
        else:
            info("sockopt.fragment уже отсутствует — изменений не требуется")

    if not _save_xray_config(cfg):
        return False

    if restart:
        if not _xray_test_and_restart():
            return False

    sf = _ensure_state()
    sf["enabled"] = False
    sf["last_disabled"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _save_server_fragment_state(sf)

    success("Server-side TLS fragmentation отключена")
    _log("INFO", "Server fragment disabled")
    return True


def server_fragment_status() -> dict:
    """
    Возвращает dict:
      enabled (bool)            — по state.json
      preset, packets, length, interval — параметры
      in_config (bool)          — реально ли есть в config.json
      inbound_protocol (str)    — "reality" / "xhttp" / "none"
      last_applied, last_disabled
    """
    sf = _ensure_state()
    result = {
        "enabled":          sf.get("enabled", False),
        "preset":           sf.get("preset", ""),
        "packets":          sf.get("packets", ""),
        "length":           sf.get("length", ""),
        "interval":         sf.get("interval", ""),
        "last_applied":     sf.get("last_applied", ""),
        "last_disabled":    sf.get("last_disabled", ""),
        "in_config":        False,
        "inbound_protocol": "none",
    }

    cfg = _load_xray_config()
    if cfg:
        inb = _find_reality_inbound(cfg)
        if inb:
            result["inbound_protocol"] = "reality"
            sockopt = inb.get("streamSettings", {}).get("sockopt", {})
            frag = sockopt.get("fragment")
            if frag:
                result["in_config"] = True
        elif _find_xhttp_inbound(cfg):
            result["inbound_protocol"] = "xhttp"

    return result


def server_fragment_reapply_after_rebuild() -> None:
    """
    Хук для вызова после пересоздания config.json (reconfigure, switch_mode,
    migration import). Если в state включён fragment — пере-применяем его
    к свежему config.json.
    """
    sf = _load_server_fragment_state()
    if not sf.get("enabled"):
        return
    info("Server-side fragment был включён — пере-применяю после пересоздания config")
    server_fragment_enable(
        preset=sf.get("preset", "balanced"),
        packets=sf.get("packets", ""),
        length=sf.get("length", ""),
        interval=sf.get("interval", ""),
        restart=True,
    )


# ── TUI-меню ─────────────────────────────────────────────────────────────────

def _format_status_line(st: dict) -> str:
    if not st["enabled"]:
        return f"{YELLOW}отключён{NC}"
    cfg_col = GREEN if st["in_config"] else RED
    parts = [
        f"{GREEN}включён{NC}",
        f"{cfg_col}config {'✓' if st['in_config'] else '✗'}{NC}",
        f"{CYAN}{st['preset']}{NC}",
        f"{DIM}p={st['packets']} l={st['length']} i={st['interval']}{NC}",
    ]
    return "  │  ".join(parts)


def do_server_fragment_menu() -> None:
    """
    TUI-меню управления server-side TLS fragmentation.
    Вызывается из _menu_diagnostics() (пункт "SF").
    """
    _ensure_state()

    while True:
        os.system("clear")
        print()
        st = server_fragment_status()

        _box_top("🖥️   SERVER-SIDE TLS FRAGMENTATION")
        _box_row(f"  Статус: {_format_status_line(st)}")
        if st["inbound_protocol"] == "xhttp":
            _box_row(f"  Режим: {YELLOW}xHTTP{NC} {DIM}— fragment неприменим (TLS терминирует nginx){NC}")
        elif st["inbound_protocol"] == "reality":
            _box_row(f"  Режим: {GREEN}VLESS+REALITY{NC} {DIM}— fragment активен на inbound{NC}")
        else:
            _box_row(f"  Режим: {RED}не установлен{NC} {DIM}— сначала установите VLESS-сервер{NC}")
        _box_sep()
        _box_desc(
            "Server-side TLS fragmentation дробит ответ сервера "
            "(ServerHello + Certificate + ServerKeyExchange) на мелкие TCP-сегменты. "
            "Клиентский fragment бьёт по ClientHello, этот — по ServerHello. "
            "Вместе они дают симметричную картину, не детектируемую ТСПУ."
        )
        _box_sep()
        _box_row()

        if st["inbound_protocol"] == "reality":
            if st["enabled"]:
                _box_item("1", f"🔴 Выключить fragment     {DIM}(снять sockopt.fragment с inbound){NC}")
                _box_item("2", f"🔁 Сменить пресет        {DIM}(пере-применить с другими параметрами){NC}")
                _box_item("3", f"⚙️  Custom параметры      {DIM}(ввести packets/length/interval){NC}")
            else:
                _box_item("1", f"⚡ Агрессивная  {DIM}(1–3 байта, макс. обход DPI на ответе){NC}")
                _box_item("2", f"✅ Сбалансированная  {DIM}(3–7 байт, рекомендуется){NC}")
                _box_item("3", f"🔆 Лёгкая  {DIM}(5–15 байт, минимальный оверхед){NC}")
                _box_item("4", f"⚙️  Пользовательская  {DIM}(ввести вручную){NC}")
        else:
            _box_row(f"  {DIM}Действия недоступны — требуется VLESS+REALITY inbound{NC}")

        _box_sep()
        _box_item("S", f"📊 Подробный статус")
        _box_item("I", f"📖 Информация / зачем это нужно")
        _box_row()
        _box_item_exit("0", "← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().upper()
        except KeyboardInterrupt:
            break

        if ch in ("0", "Q", ""):
            break

        if st["inbound_protocol"] != "reality":
            if ch in ("S", "I"):
                pass  # эти пункты доступны всегда
            else:
                warn("Требуется VLESS+REALITY inbound")
                time.sleep(1.5)
                continue

        if st["enabled"]:
            # Меню при включённом fragment
            if ch == "1":
                print()
                warn("Отключение снимет фрагментацию с ServerHello.")
                warn("Трафик снова станет видимым ТСПУ по асимметрии.")
                try:
                    confirm = input(f"\n{YELLOW}Продолжить? (y/N):{NC} ").strip().lower()
                except KeyboardInterrupt:
                    confirm = ""
                if confirm == "y":
                    server_fragment_disable()
                else:
                    info("Отменено")
                input(f"\n{BLUE}Нажмите Enter...{NC}")

            elif ch == "2":
                # Сменить пресет
                print()
                _box_top("🔁  ВЫБОР НОВОГО ПРЕСЕТА")
                _box_item("1", f"⚡ Агрессивная  {DIM}(1–3 байта){NC}")
                _box_item("2", f"✅ Сбалансированная  {DIM}(3–7 байт){NC}")
                _box_item("3", f"🔆 Лёгкая  {DIM}(5–15 байт){NC}")
                _box_item("4", f"⚙️  Custom  {DIM}(ввести вручную){NC}")
                _box_bottom()
                try:
                    sub = input(f"{CYAN}Пресет:{NC} ").strip()
                except KeyboardInterrupt:
                    continue
                preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
                if sub in preset_map:
                    server_fragment_enable(preset=preset_map[sub])
                elif sub == "4":
                    _prompt_custom_and_apply()
                else:
                    warn("Неверный выбор")
                    time.sleep(1)
                input(f"\n{BLUE}Нажмите Enter...{NC}")

            elif ch == "3":
                _prompt_custom_and_apply()
                input(f"\n{BLUE}Нажмите Enter...{NC}")

        else:
            # Меню при выключенном fragment
            preset_map = {"1": "aggressive", "2": "balanced", "3": "light"}
            if ch in preset_map:
                server_fragment_enable(preset=preset_map[ch])
                input(f"\n{BLUE}Нажмите Enter...{NC}")
            elif ch == "4":
                _prompt_custom_and_apply()
                input(f"\n{BLUE}Нажмите Enter...{NC}")

        if ch == "S":
            _show_detailed_status(st)
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "I":
            _show_info()
            input(f"\n{BLUE}Нажмите Enter...{NC}")


def _prompt_custom_and_apply() -> None:
    """Запрашивает packets/length/interval и применяет custom-пресет."""
    print()
    info("Введите параметры фрагментации (N или N-M):")
    try:
        pkts = input(f"  {CYAN}packets {DIM}(напр. 1-3){NC}: ").strip() or "1-3"
        lng  = input(f"  {CYAN}length  {DIM}(напр. 3-7){NC}: ").strip() or "3-7"
        ivl  = input(f"  {CYAN}interval{DIM}(мс, напр. 10-20){NC}: ").strip() or "10-20"
    except KeyboardInterrupt:
        return

    # Простая валидация
    def _ok_range(v: str) -> bool:
        parts = v.split("-")
        if len(parts) not in (1, 2):
            return False
        try:
            nums = [int(p) for p in parts]
            return all(n > 0 for n in nums) and (len(nums) == 1 or nums[0] <= nums[1])
        except ValueError:
            return False

    if not (_ok_range(pkts) and _ok_range(lng) and _ok_range(ivl)):
        warn("Некорректный формат. Ожидается N или N-M с положительными числами")
        time.sleep(2)
        return

    server_fragment_enable(preset="custom", packets=pkts, length=lng, interval=ivl)


def _show_detailed_status(st: dict) -> None:
    print()
    _box_top("📊  ПОДРОБНЫЙ СТАТУС SERVER FRAGMENT")
    _box_row(f"  Глобально:    "
             f"{GREEN}включён{NC}" if st["enabled"]
             else f"  Глобально:    {YELLOW}отключён{NC}")
    _box_row(f"  В config.json: "
             f"{GREEN}есть{NC}" if st["in_config"]
             else f"{RED}отсутствует{NC}")
    _box_row(f"  Inbound:       {CYAN}{st['inbound_protocol']}{NC}")
    if st["enabled"]:
        _box_row(f"  Пресет:        {CYAN}{st['preset']}{NC}")
        _box_row(f"  packets:       {DIM}{st['packets']}{NC}")
        _box_row(f"  length:        {DIM}{st['length']} байт{NC}")
        _box_row(f"  interval:      {DIM}{st['interval']} мс{NC}")
    if st["last_applied"]:
        _box_row(f"  Посл. apply:   {DIM}{st['last_applied']}{NC}")
    if st["last_disabled"]:
        _box_row(f"  Посл. disable: {DIM}{st['last_disabled']}{NC}")
    _box_sep()
    if st["enabled"] and not st["in_config"]:
        _box_warn("ВНИМАНИЕ: в state включён, но в config отсутствует!")
        _box_warn("Возможно, config.json был пересоздан. Пере-примените через меню.")
    elif not st["enabled"] and st["in_config"]:
        _box_warn("ВНИМАНИЕ: в state выключен, но в config ещё присутствует!")
        _box_warn("Это рассинхрон — нажмите Выключить для очистки.")
    _box_bottom()


def _show_info() -> None:
    print()
    _box_top("📖  ЗАЧЕМ НУЖЕН SERVER-SIDE FRAGMENT")
    _box_row()
    _box_row(f"  {BOLD}Проблема:{NC}")
    _box_row(f"  Клиентский fragment (меню F1) бьёт только ClientHello —")
    _box_row(f"  исходящий от клиента TLS-handshake. Серверный ответ")
    _box_row(f"  (ServerHello + Certificate) уходит цельным куском.")
    _box_row()
    _box_row(f"  ТСПУ с двунаправленной DPI-аналитикой видит асимметрию:")
    _box_row(f"  входящий TLS дроблёный, ответный — цельный. Это")
    _box_row(f"  сильный маркер прокси-сервера.")
    _box_row()
    _box_row(f"  {BOLD}Решение:{NC}")
    _box_row(f"  sockopt.fragment на inbound VLESS+REALITY заставляет")
    _box_row(f"  Xray дробить первые N TCP-сегментов ответа сервера.")
    _box_row(f"  Теперь обе стороны TLS-handshake выглядят одинаково")
    _box_row(f"  фрагментированно — DPI теряет сигнатуру.")
    _box_row()
    _box_row(f"  {BOLD}Совместимость:{NC}")
    _box_row(f"  • Xray-core v1.8.13+")
    _box_row(f"  • Только VLESS+REALITY (на xHTTP TLS терминирует nginx)")
    _box_row(f"  • Mode A и Mode B (Entry-нода)")
    _box_row(f"  • Не конфликтует с клиентским fragment — это ортогональные слои")
    _box_row()
    _box_row(f"  {BOLD}Рекомендация:{NC}")
    _box_row(f"  Используйте тот же пресет, что и на клиенте, или на 1 шаг")
    _box_row(f"  мягче (серверные ответы крупнее, дробить легче).")
    _box_row()
    _box_row(f"  {BOLD}Связка:{NC}")
    _box_row(f"  Client fragment (F1) + Server fragment (SF) =")
    _box_row(f"  симметричная двунаправленная фрагментация TLS.")
    _box_bottom()
