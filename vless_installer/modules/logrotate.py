"""
vless_installer/modules/logrotate.py
───────────────────────────────────────────────────────────────────────────────
Управление ротацией логов Xray из интерактивного меню.

Позволяет:
  • Просмотреть текущие настройки logrotate для /var/log/xray/*.log
  • Включить/выключить ротацию логов
  • Настроить периодичность (daily / weekly / monthly)
  • Настроить количество хранимых файлов

Точка входа из _core.py:
    from vless_installer.modules.logrotate import do_manage_logrotate
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import time
import textwrap

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
RED    = _C['RED']
GREEN  = _C['GREEN']
YELLOW = _C['YELLOW']
CYAN   = _C['CYAN']
BLUE   = _C['BLUE']
BOLD   = _C['BOLD']
DIM    = _C['DIM']
WHITE  = _C['WHITE']
NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = msg
            import re
            clean = re.sub(r'\033\[[0-9;]*m', '', clean)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _dim(msg: str)     -> None: print(f"{DIM}{msg}{NC}")

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


from vless_installer.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item,
)

# =============================================================================
def do_manage_logrotate() -> None:
    """
    Управление ротацией логов Xray из интерактивного меню.

    Позволяет:
      - Просмотреть текущие конфиги /etc/logrotate.d/xray*
      - Изменить частоту (daily / weekly) и глубину хранения (rotate N)
      - Принудительно запустить ротацию прямо сейчас (logrotate -f)
      - Показать размер лог-файлов
    """
    _LOGROTATE_XRAY     = Path("/etc/logrotate.d/xray")
    _LOGROTATE_XRAY_AUX = Path("/etc/logrotate.d/xray-aux")
    _LOG_DIR            = Path("/var/log/xray")
    _AUX_LOGS           = [
        Path("/var/log/xray-autoupdate.log"),
        Path("/var/log/xray-geo-update.log"),
        Path("/var/log/xray-autoban.log"),
        Path("/var/log/xray-watchdog.log"),
        Path("/var/log/vless-install.log"),
    ]

    def _log_size(p: Path) -> str:
        try:
            sz = p.stat().st_size
            if sz >= 1024 * 1024:
                return f"{sz / 1024 / 1024:.1f} МБ"
            if sz >= 1024:
                return f"{sz // 1024} КБ"
            return f"{sz} Б"
        except Exception:
            return "—"

    def _config_exists(p: Path) -> str:
        return f"{GREEN}есть{NC}" if p.exists() else f"{RED}нет{NC}"

    def _parse_rotate_param(path: Path, param: str) -> str:
        """Читает значение параметра (daily/weekly/rotate N) из конфига logrotate."""
        if not path.exists():
            return "?"
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith(param):
                parts = line.split()
                return parts[1] if len(parts) > 1 else parts[0]
        return "?"

    while True:
        os.system("clear")
        print()
        _box_top("📋  УПРАВЛЕНИЕ РОТАЦИЕЙ ЛОГОВ XRAY")
        _box_row()

        # Размеры основных логов
        _box_row(f"  {CYAN}Размер лог-файлов:{NC}")
        for fname in ("access.log", "error.log"):
            lp = _LOG_DIR / fname
            sz = _log_size(lp) if lp.exists() else f"{DIM}нет файла{NC}"
            _box_row(f"    /var/log/xray/{fname:<16}  {sz}")
        for lp in _AUX_LOGS:
            if lp.exists():
                _box_row(f"    {lp}  {_log_size(lp)}")

        _box_sep()
        # Текущие параметры logrotate
        freq_main = _parse_rotate_param(_LOGROTATE_XRAY,     "daily") or \
                    _parse_rotate_param(_LOGROTATE_XRAY,     "weekly")
        rot_main  = _parse_rotate_param(_LOGROTATE_XRAY,     "rotate")
        freq_aux  = _parse_rotate_param(_LOGROTATE_XRAY_AUX, "daily") or \
                    _parse_rotate_param(_LOGROTATE_XRAY_AUX, "weekly")
        rot_aux   = _parse_rotate_param(_LOGROTATE_XRAY_AUX, "rotate")
        _box_row(f"  Конфиг xray:      {_config_exists(_LOGROTATE_XRAY)}"
                 f"  {DIM}(частота: {freq_main or '?'}, хранить: {rot_main or '?'} архивов){NC}")
        _box_row(f"  Конфиг xray-aux:  {_config_exists(_LOGROTATE_XRAY_AUX)}"
                 f"  {DIM}(частота: {freq_aux or '?'}, хранить: {rot_aux or '?'} архивов){NC}")
        _box_sep()

        _box_item("1", "Применить/обновить конфиг logrotate (настройки по умолчанию)")
        _box_item("2", "Изменить частоту и глубину хранения")
        _box_item("3", f"Запустить ротацию прямо сейчас  {DIM}(logrotate -f){NC}")
        _box_item("4", f"Показать содержимое конфигов logrotate")
        _box_item("Q", "Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        # ── [1] Применить дефолтный конфиг ──────────────────────────────────
        if ch == "1":
            setup_logrotate()
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [2] Изменить параметры ────────────────────────────────────────────
        elif ch == "2":
            print()
            _box_row("  Параметры для access.log / error.log:")
            _box_item("1", "daily   — ежедневно (рекомендуется при высоком трафике)")
            _box_item("2", "weekly  — еженедельно (стандарт)")
            _box_bottom()
            try:
                freq_ch = input("  Частота [1=daily / 2=weekly]: ").strip()
                freq = "daily" if freq_ch == "1" else "weekly"
                rot_raw = input("  Количество архивов [14]: ").strip()
                rotate = int(rot_raw) if rot_raw.isdigit() else 14
            except (KeyboardInterrupt, EOFError, ValueError):
                _warn("Отмена")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue

            _LOGROTATE_XRAY.parent.mkdir(parents=True, exist_ok=True)
            _LOGROTATE_XRAY.write_text(textwrap.dedent(f"""\
                # Ротация логов Xray-core
                # Создано VLESS Ultimate Installer v4.11.3
                /var/log/xray/access.log
                /var/log/xray/error.log {{
                    {freq}
                    rotate {rotate}
                    compress
                    delaycompress
                    missingok
                    notifempty
                    create 0640 xray xray
                    sharedscripts
                    postrotate
                        systemctl kill -s USR1 xray 2>/dev/null || true
                    endscript
                }}
            """))
            _LOGROTATE_XRAY.chmod(0o644)
            r = _run(["logrotate", "--debug", str(_LOGROTATE_XRAY)],
                     check=False, quiet=True, capture=True)
            if r.returncode == 0:
                _success(f"logrotate обновлён: {freq}, {rotate} архивов")
            else:
                _warn("logrotate --debug вернул ошибку — проверьте конфиг вручную")
            _log("INFO", f"logrotate reconfig: freq={freq}, rotate={rotate}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [3] Принудительная ротация ────────────────────────────────────────
        elif ch == "3":
            if not _LOGROTATE_XRAY.exists():
                _warn(f"Конфиг не найден: {_LOGROTATE_XRAY} — сначала выполните пункт [1]")
                input(f"{BLUE}Нажмите Enter...{NC}")
                continue
            _info("Запускаю logrotate -f ...")
            r = _run(["logrotate", "-f", str(_LOGROTATE_XRAY)], check=False, capture=True)
            if r.returncode == 0:
                _success("Ротация выполнена")
            else:
                _warn(f"Ротация завершилась с кодом {r.returncode}")
                if r.stderr:
                    _dim(r.stderr.strip())
            # Aux тоже ротируем если конфиг есть
            if _LOGROTATE_XRAY_AUX.exists():
                _run(["logrotate", "-f", str(_LOGROTATE_XRAY_AUX)], check=False, quiet=True)
            input(f"{BLUE}Нажмите Enter...{NC}")

        # ── [4] Показать конфиги ──────────────────────────────────────────────
        elif ch == "4":
            for cfg in (_LOGROTATE_XRAY, _LOGROTATE_XRAY_AUX):
                print()
                if cfg.exists():
                    print(f"  {CYAN}=== {cfg} ==={NC}")
                    for line in cfg.read_text().splitlines():
                        print(f"  {line}")
                else:
                    print(f"  {YELLOW}{cfg} — не найден{NC}")
            print()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", ""):
            break
        else:
            _warn("Неверный выбор")
            time.sleep(1)



