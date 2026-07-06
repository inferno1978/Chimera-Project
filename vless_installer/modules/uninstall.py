"""
vless_installer/modules/uninstall.py
───────────────────────────────────────────────────────────────────────────────
Полное удаление VLESS Reality + связанных компонентов.

Одна функция:

• **do_uninstall** — интерактивное удаление Xray, Nginx, сайта, правил UFW,
  DNSCrypt-proxy и т.д. Перед удалением требует подтверждение доменом.

Точки входа из _core.py:
    from vless_installer.modules.uninstall import do_uninstall

Доступ к helpers ядра (_box_*, die, _run, CONFIG_DIR, XRAY_BIN, XRAY_SERVICE,
DNSCRYPT_BIN, DNSCRYPT_CONF_DIR, DNSCRYPT_SERVICE, PKG_MGR, цвета YELLOW/RED/NC)
— через importlib (lazy binding), как и в других извлечённых модулях
(warp.py, smart_balancer.py, failover.py, standalone_screens.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  УДАЛЕНИЕ VLESS REALITY
# =============================================================================
def do_uninstall() -> None:
    core = _core_module()
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    _box_info    = core._box_info
    die          = core.die
    _run         = core._run
    CONFIG_DIR   = core.CONFIG_DIR
    XRAY_BIN     = core.XRAY_BIN
    XRAY_SERVICE = core.XRAY_SERVICE
    DNSCRYPT_BIN      = core.DNSCRYPT_BIN
    DNSCRYPT_CONF_DIR = core.DNSCRYPT_CONF_DIR
    DNSCRYPT_SERVICE  = core.DNSCRYPT_SERVICE
    PKG_MGR      = core.PKG_MGR
    YELLOW, RED, NC = core.YELLOW, core.RED, core.NC

    _box_top("УДАЛЕНИЕ VLESS REALITY")
    _box_warn("Будет удалено: Xray, Nginx, сайт, правила UFW")
    _box_row()
    _box_bottom()
    uninst_domain = input(f"{YELLOW}Домен для подтверждения удаления:{NC} ").strip()
    if not uninst_domain:
        _box_top("УДАЛЕНИЕ VLESS REALITY")
        _box_warn("Домен не введён. Отмена.")
        _box_bottom()
        sys.exit(0)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', uninst_domain):
        die(f"Некорректный формат домена: '{uninst_domain}'")

    confirm = input(f"{RED}Удалить? [y/N]:{NC} ").strip().lower()
    if confirm != 'y':
        _box_top("УДАЛЕНИЕ VLESS REALITY")
        _box_info("Отменено.")
        _box_bottom()
        sys.exit(0)

    _box_top("УДАЛЕНИЕ VLESS REALITY")

    for svc in ("xray", "nginx", "dnscrypt-proxy"):
        _run(["systemctl", "stop",    svc], check=False, quiet=True)
    for svc in ("xray", "dnscrypt-proxy"):
        _run(["systemctl", "disable", svc], check=False, quiet=True)

    # Удаление Xray через официальный скрипт
    with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        r = _run([
            "curl", "-fsSL", "--connect-timeout", "10",
            "https://github.com/XTLS/Xray-install/raw/main/install-release.sh",
            "-o", str(tmp_path),
        ], check=False, quiet=True)
        if r.returncode == 0 and tmp_path.stat().st_size > 0:
            _run(["bash", str(tmp_path), "remove"], check=False, quiet=True)
    finally:
        tmp_path.unlink(missing_ok=True)

    for p in (XRAY_BIN, XRAY_SERVICE):
        Path(p).unlink(missing_ok=True)
    # Зачищаем drop-in директорию xray (оставляемую официальным bash-установщиком)
    shutil.rmtree("/etc/systemd/system/xray.service.d", ignore_errors=True)
    for d in (Path("/usr/local/etc/xray"), CONFIG_DIR,
              Path("/var/log/xray"), Path("/var/lib/xray")):
        shutil.rmtree(d, ignore_errors=True)

    # Удаление DNSCrypt
    _box_info("Удаление DNSCrypt-proxy...")
    DNSCRYPT_BIN.unlink(missing_ok=True)
    DNSCRYPT_SERVICE.unlink(missing_ok=True)
    shutil.rmtree(DNSCRYPT_CONF_DIR, ignore_errors=True)
    for log_f in ("/var/log/dnscrypt-proxy.log",
                  "/var/log/dnscrypt-blocked.log",
                  "/var/log/dnscrypt-proxy-blocked.log"):
        Path(log_f).unlink(missing_ok=True)

    override = Path("/etc/systemd/system/nginx.service.d/after-xray.conf")
    override.unlink(missing_ok=True)
    try:
        override.parent.rmdir()
    except Exception:
        pass
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)

    if PKG_MGR == "apt":
        _run(["apt-get", "remove", "--purge", "-y", "nginx", "nginx-common"],
             check=False, quiet=True)
        _run(["apt-get", "autoremove", "-y"], check=False, quiet=True)
    else:
        _run(["dnf", "remove", "-y", "nginx"], check=False, quiet=True)

    shutil.rmtree("/etc/nginx", ignore_errors=True)
    shutil.rmtree("/var/log/nginx", ignore_errors=True)
    if uninst_domain:
        shutil.rmtree(f"/var/www/{uninst_domain}", ignore_errors=True)
    _box_row()
    _box_bottom()
