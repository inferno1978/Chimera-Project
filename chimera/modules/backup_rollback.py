"""
chimera/modules/backup_rollback.py
───────────────────────────────────────────────────────────────────────────────
Резервное копирование и откат конфигурации Xray + unit-тесты + проверка связи.

  • create_backup()       — создаёт резервную копию config.json/state.json и др.
                            Мутирует глобали ROLLBACK_AVAILABLE / BACKUP_TIMESTAMP
                            в _core (через setattr).
  • perform_rollback()    — откат к последнему бэкапу.
  • run_unit_tests()      — 14 тестов: Python, root, зависимости, конфиги.
  • verify_connectivity() — проверка IPv4/IPv6 и слушающих портов.

Точки входа из _core.py:
    from chimera.modules.backup_rollback import (
        create_backup, perform_rollback, run_unit_tests, verify_connectivity,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  BACKUP
# ============================================================================
def create_backup() -> None:
    """Создаёт резервную копию конфигурации. Мутирует ROLLBACK_AVAILABLE /
    BACKUP_TIMESTAMP в _core."""
    core = _core_module()
    info    = core.info
    success = core.success
    BACKUP_DIR    = core.BACKUP_DIR
    CONFIG_DIR    = core.CONFIG_DIR
    XRAY_SERVICE  = core.XRAY_SERVICE
    OPTIMIZER_CONF = core.OPTIMIZER_CONF
    STATE_FILE    = core.STATE_FILE

    backup_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = BACKUP_DIR / f"config_{backup_ts}"
    info(f"Создание резервной копии: {backup_path}")
    backup_path.mkdir(parents=True, exist_ok=True)
    for src, name in [
        (CONFIG_DIR / "config.json", "config.json"),
        (XRAY_SERVICE,               "xray.service"),
        (OPTIMIZER_CONF,             "99-vless-performance.conf"),
        (STATE_FILE,                 "state.json"),
    ]:
        if src.exists():
            shutil.copy2(src, backup_path / name)

    # Пишем в глобали ядра (через setattr, т.к. global в этом модуле
    # не ссылается на _core's namespace).
    setattr(core, "ROLLBACK_AVAILABLE", True)
    setattr(core, "BACKUP_TIMESTAMP", backup_ts)
    success(f"Резервная копия создана: {backup_path}")


# ============================================================================
#  ROLLBACK
# ============================================================================
def perform_rollback() -> None:
    """Откат к последнему бэкапу (если ROLLBACK_AVAILABLE)."""
    core = _core_module()
    warn    = core.warn
    success = core.success
    _run     = core._run
    BACKUP_DIR    = core.BACKUP_DIR
    CONFIG_DIR    = core.CONFIG_DIR
    XRAY_SERVICE  = core.XRAY_SERVICE
    ROLLBACK_AVAILABLE = getattr(core, "ROLLBACK_AVAILABLE", False)
    BACKUP_TIMESTAMP   = getattr(core, "BACKUP_TIMESTAMP", "")

    if not ROLLBACK_AVAILABLE:
        warn("Резервная копия недоступна")
        return
    backup_path = BACKUP_DIR / f"config_{BACKUP_TIMESTAMP}"
    warn(f"Выполнение отката к: {backup_path}")
    for name, dst in [
        ("config.json", CONFIG_DIR / "config.json"),
        ("xray.service", XRAY_SERVICE),
    ]:
        src = backup_path / name
        if src.exists():
            shutil.copy2(src, dst)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    # (start-limit-fix): reset-failed перед рестартом (StartLimitBurst)
    _run(["systemctl", "reset-failed", "xray"], check=False, quiet=True)
    _run(["systemctl", "restart", "xray", "nginx"], check=False, quiet=True)
    success("Откат завершён")


# ============================================================================
#  UNIT TESTS
# ============================================================================
def run_unit_tests() -> None:
    """14 unit-тестов: Python, root, зависимости, конфиги, сервисы."""
    core = _core_module()
    _box_top   = core._box_top
    _box_row   = core._box_row
    _box_info  = core._box_info
    _box_ok    = core._box_ok
    _box_warn  = core._box_warn
    _box_bottom = core._box_bottom
    _run       = core._run
    command_exists = core.command_exists
    find_nginx_bin = core.find_nginx_bin
    gen_uuid   = core.gen_uuid
    gen_hex    = core.gen_hex
    CONFIG_DIR = core.CONFIG_DIR
    STATE_FILE = core.STATE_FILE
    XRAY_BIN   = core.XRAY_BIN
    TOTAL_RAM  = core.TOTAL_RAM
    BOLD = core.BOLD
    DIM = core.DIM
    GREEN = core.GREEN
    NC = core.NC
    YELLOW = core.YELLOW
    PROTOCOL_MODE = getattr(core, "PROTOCOL_MODE", "reality")
    INSTALL_MODE  = getattr(core, "INSTALL_MODE", "A")
    GREEN, YELLOW, BOLD, DIM, NC = (
        core.GREEN, core.YELLOW, core.BOLD, core.DIM, core.NC
    )

    passed = 0
    failed = 0
    _box_top("🧪  UNIT-ТЕСТЫ")
    _box_row()
    _box_info("Запуск unit тестов...")
    _box_row()

    def _test(num: int, desc: str, ok: bool) -> None:
        nonlocal passed, failed
        if ok:
            _box_ok(f"Тест {num}: {desc} — OK")
            passed += 1
        else:
            _box_warn(f"Тест {num}: {desc} — FAIL")
            failed += 1

    _test(1, "Python 3.12+",     sys.version_info >= (3, 12))
    _test(2, "Root права",       os.geteuid() == 0)
    _test(3, "jq",               command_exists("jq"))
    _test(4, "UUID генерация",   bool(re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        gen_uuid())))
    _test(5, "ShortID генерация", (lambda s: len(s)==16 and bool(re.match(r'^[0-9a-f]+$',s)))(gen_hex(8)))
    _test(6, "Xray бинарник",    XRAY_BIN.exists() and os.access(XRAY_BIN, os.X_OK))
    _test(7, f"RAM ({TOTAL_RAM}MB)", TOTAL_RAM >= 256)
    _test(8, "openssl",          command_exists("openssl"))

    # --- Расширенные тесты ---
    _ut_state: dict = {}
    try:
        if STATE_FILE.exists():
            _ut_state = json.loads(STATE_FILE.read_text())
    except Exception:
        pass
    _ut_proto   = _ut_state.get("protocol_mode", PROTOCOL_MODE or "reality")
    _ut_awg     = _ut_state.get("awg_exit_enabled", False)
    _ut_mode    = _ut_state.get("install_mode", INSTALL_MODE or "A")

    # Тест 9: nginx -t (валидность конфига nginx)
    _nginx = find_nginx_bin()
    _nginx_optional = (_ut_proto == "reality") or _ut_awg
    _nginx_label = "nginx -t (конфиг валиден)" if not _nginx_optional else "nginx -t (опц.)"
    if _nginx:
        _r = _run([_nginx, "-t"], capture=True, check=False, quiet=True)
        _test(9, _nginx_label, _r.returncode == 0)
    else:
        if _nginx_optional:
            _box_row(f"  {DIM}Тест 9: {_nginx_label} — не установлен (не нужен в REALITY){NC}")
        else:
            _test(9, _nginx_label, False)

    # Тест 10: xray --test config.json
    _cfg_candidates = [CONFIG_DIR / "config.json", Path("/usr/local/etc/xray/config.json")]
    _cfg_test = next((str(p) for p in _cfg_candidates if p.exists()), None)
    if _cfg_test and XRAY_BIN.exists():
        _r = _run([str(XRAY_BIN), "run", "-test", "-config", _cfg_test],
                  capture=True, check=False, quiet=True)
        _test(10, "xray -test config.json", _r.returncode == 0)
    else:
        _test(10, "xray -test config.json", False)

    # Тест 11: certbot доступен
    _certbot = next((p for p in (Path("/snap/bin/certbot"), Path("/usr/bin/certbot"))
                     if p.exists()), None)
    _certbot_optional = (_ut_proto == "reality")
    if _certbot_optional:
        _certbot_label = "certbot (опц., REALITY не нужен)"
        if _certbot:
            _box_row(f"  {DIM}Тест 11: {_certbot_label} — найден{NC}")
        else:
            _box_row(f"  {DIM}Тест 11: {_certbot_label} — не установлен (норма){NC}")
    else:
        _test(11, "certbot", _certbot is not None)

    # Тест 12: Stats API в конфиге Xray
    _stats_ok = False
    if _cfg_test:
        try:
            _cfg_json = json.loads(Path(_cfg_test).read_text())
            _stats_ok = "stats" in _cfg_json and "policy" in _cfg_json
        except Exception:
            pass
    if _stats_ok:
        _test(12, "Xray Stats API в конфиге", True)
    else:
        _box_row(f"  {DIM}Тест 12: Xray Stats API — не настроен "
                 f"(статистика недоступна, VPN работает){NC}")

    # Тест 13: cron-агенты активны (watchdog timer)
    _r = _run(["systemctl", "is-active", "xray-watchdog.timer"],
              capture=True, check=False, quiet=True)
    _watchdog_ok = _r.returncode == 0 and _r.stdout.strip() == "active"
    if _watchdog_ok:
        _test(13, "xray-watchdog.timer активен", True)
    else:
        _box_row(f"  {DIM}Тест 13: xray-watchdog.timer — не активен (опц.){NC}")

    # Тест 14: xray сервис активен прямо сейчас
    _r = _run(["systemctl", "is-active", "xray"],
              capture=True, check=False, quiet=True)
    _test(14, "xray.service активен", _r.stdout.strip() == "active")

    _box_row()
    col = GREEN if failed == 0 else YELLOW
    _box_row(f"  {BOLD}Результаты:{NC} {GREEN}{passed} пройдено{NC} / {col}{failed} провалено{NC}")
    if failed == 0:
        _box_row(f"  {DIM}(опциональные тесты в счётчик не входят){NC}")
    _box_row()
    _box_bottom()


# ============================================================================
#  VERIFY CONNECTIVITY
# ============================================================================
def verify_connectivity() -> None:
    """Проверка IPv4/IPv6 connectivity и слушающих портов."""
    core = _core_module()
    _box_row   = core._box_row
    _box_ok    = core._box_ok
    _box_warn  = core._box_warn
    _box_info  = core._box_info
    _run       = core._run
    get_server_ip = core.get_server_ip
    IS_IPV6_AVAILABLE = getattr(core, "IS_IPV6_AVAILABLE", False)
    SERVER_PORT  = core.SERVER_PORT
    BOLD, NC = core.BOLD, core.NC

    _box_row()
    ipv4 = get_server_ip("4")
    ipv6 = get_server_ip("6")

    if ipv4:
        r = _run(["curl", "-s", "-4", "-m", "5", "https://api4.ipify.org"],
                 check=False, quiet=True)
        if r.returncode == 0:
            _box_ok(f"IPv4: рабочий ({ipv4})")
        else:
            _box_warn("IPv4: проблемы с соединением")
    else:
        _box_warn("IPv4: адрес не определён")

    if IS_IPV6_AVAILABLE and ipv6:
        r = _run(["curl", "-s", "-6", "-m", "5", "https://api64.ipify.org"],
                 check=False, quiet=True)
        if r.returncode == 0:
            _box_ok(f"IPv6: рабочий ({ipv6})")
        else:
            _box_info(f"{BOLD}IPv6: проблемы с соединением{NC}")
    else:
        _box_info(f"{BOLD}IPv6: не доступен{NC}")

    for port in (22, 80, SERVER_PORT):
        r = _run(["ss", "-tlnp"], capture=True, check=False)
        if f":{port} " in r.stdout:
            _box_ok(f"Порт {port}: OK")
        else:
            _box_warn(f"Порт {port}: не слушает")
    _box_row()
