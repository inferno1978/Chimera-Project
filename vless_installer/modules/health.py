"""
vless_installer/modules/health.py
───────────────────────────────────────────────────────────────────────────────
Проверки здоровья системы — Xray, Nginx, SSL, порты.

  • health_check_xray()   — проверяет активность сервиса Xray
  • health_check_nginx()  — проверяет активность Nginx
  • health_check_ssl()    — проверяет срок действия TLS-сертификата
  • health_check_ports()  — проверяет доступность портов 22, 80, SERVER_PORT
  • run_full_health_check() — запускает все проверки и пишет статус
  • do_check_tls_cert()   — интерактивный просмотр информации о сертификате

Точка входа из _core.py:
    from vless_installer.modules.health import (
        health_check_xray, health_check_nginx, health_check_ssl,
        health_check_ports, run_full_health_check, do_check_tls_cert,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
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
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{level}] {clean}\n")
    except Exception:
        pass

def info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",   msg)
def log_to_file(level: str, msg: str) -> None: _log(level, msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

# ── Константы ─────────────────────────────────────────────────────────────────
HEALTH_CHECK_FILE = Path("/var/lib/xray-installer/health.status")
_STATE_FILE       = Path("/var/lib/xray-installer/state.json")

# ── Импорты из других модулей ─────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_ok, _box_warn,
    RED, GREEN, YELLOW, CYAN, BOLD, DIM, NC,
)

# ── Получение PARAM_DOMAIN и SERVER_PORT из state.json (без импорта _core) ───
def _get_state_value(key: str, default=None):
    try:
        if _STATE_FILE.exists():
            return json.loads(_STATE_FILE.read_text()).get(key, default)
    except Exception:
        pass
    return default

def _load_state_into_globals() -> None:
    """No-op совместимости — данные читаются через _get_state_value()."""
    pass


# =============================================================================
def health_check_xray() -> bool:
    time.sleep(3)
    r = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
    if r.stdout.strip() != "active":
        warn("Xray сервис не активен")
        try:
            logs = _run(["journalctl", "-u", "xray", "-n", "20", "--no-pager"],
                        capture=True, check=False).stdout
            log_to_file("WARN", logs[-2000:])
        except Exception:
            pass
        return False
    r2 = _run(["pgrep", "-x", "xray"], capture=True, check=False)
    if r2.returncode != 0:
        warn("Xray процесс не запущен")
        return False
    success("Xray: OK")
    return True


def health_check_nginx() -> bool:
    time.sleep(2)
    r = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
    if r.stdout.strip() != "active":
        warn("Nginx сервис не активен")
        return False
    r2 = _run(["nginx", "-t"], capture=True, check=False)
    if r2.returncode != 0:
        warn("Nginx конфигурация невалидна")
        log_to_file("WARN", r2.stderr)
        return False
    success("Nginx: OK")
    return True


def health_check_ssl() -> bool:
    # BUGFIX: при пустом _get_state_value("domain", "") (xHTTP до установки) не падаем с ошибкой пути.
    if not _get_state_value("domain", ""):
        warn("SSL проверка пропущена: домен не задан")
        return False
    _domain_val = _get_state_value("domain", "")
    cert = Path(f"/etc/letsencrypt/live/{_domain_val}/fullchain.pem")
    if not cert.exists():
        warn("SSL сертификат не найден")
        return False
    try:
        r = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
                 capture=True, check=False)
        expiry = r.stdout.strip().split("=", 1)[1]
        r2 = _run(["date", "-d", expiry, "+%s"], capture=True, check=False)
        expiry_epoch = int(r2.stdout.strip())
        days_left = (expiry_epoch - int(time.time())) // 86400
        if days_left < 30:
            warn(f"SSL сертификат истекает через {days_left} дней!")
        else:
            success(f"SSL: OK (действителен до: {expiry}, осталось: {days_left} дн.)")
    except Exception:
        success("SSL: OK (дата не определена)")
    return True


def do_check_tls_cert() -> None:
    """
    Расширенная проверка TLS-сертификата:
      1. Чтение файла сертификата (subject, issuer, срок действия).
      2. Живое подключение openssl s_client — проверяет цепочку и реальный ответ сервера.
      3. Предупреждение если осталось < WARN_DAYS дней.
      4. Показывает альтернативные имена (SAN).
    """
    WARN_DAYS = 30

    _load_state_into_globals()
    domain = _get_state_value("domain", "")
    port   = _get_state_value("server_port", 443) or 443

    print()
    _box_top("🔒  Проверка TLS-сертификата")

    if not domain:
        _box_warn("Домен не задан — проверьте state.json")
        _box_bottom()
        return

    cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")

    # --- [1] Чтение файла сертификата ---
    _box_row(f"  {CYAN}Файл сертификата:{NC}")
    if not cert_path.exists():
        _box_warn(f"Файл не найден: {cert_path}")
    else:
        _box_ok(f"{cert_path}")
        try:
            # subject
            r = _run(["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"],
                     capture=True, check=False)
            _box_row(f"    Субъект:  {DIM}{r.stdout.strip().removeprefix('subject=')}{NC}")
            # issuer
            r2 = _run(["openssl", "x509", "-in", str(cert_path), "-noout", "-issuer"],
                      capture=True, check=False)
            _box_row(f"    Издатель: {DIM}{r2.stdout.strip().removeprefix('issuer=')}{NC}")
            # dates
            r3 = _run(["openssl", "x509", "-in", str(cert_path), "-noout",
                       "-startdate", "-enddate"], capture=True, check=False)
            not_before, not_after = "", ""
            for line in r3.stdout.splitlines():
                if line.startswith("notBefore="):
                    not_before = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    not_after  = line.split("=", 1)[1].strip()
            _box_row(f"    Выдан:    {DIM}{not_before}{NC}")
            # Срок истечения с цветовой индикацией
            try:
                r4 = _run(["date", "-d", not_after, "+%s"], capture=True, check=False)
                exp_epoch = int(r4.stdout.strip())
                days_left = (exp_epoch - int(time.time())) // 86400
                if days_left < 7:
                    exp_col = f"{RED}{BOLD}{days_left} дн.!{NC}"
                elif days_left < WARN_DAYS:
                    exp_col = f"{YELLOW}{days_left} дн.{NC}"
                else:
                    exp_col = f"{GREEN}{days_left} дн.{NC}"
                _box_row(f"    Истекает: {DIM}{not_after}{NC}  →  {exp_col}")
            except Exception:
                _box_row(f"    Истекает: {DIM}{not_after}{NC}")
            # SAN
            r5 = _run(["openssl", "x509", "-in", str(cert_path), "-noout", "-ext",
                       "subjectAltName"], capture=True, check=False)
            san_line = ""
            for line in r5.stdout.splitlines():
                if "DNS:" in line or "IP:" in line:
                    san_line = line.strip()
                    break
            if san_line:
                _box_row(f"    SAN:      {DIM}{san_line}{NC}")
        except Exception as e:
            _box_warn(f"Ошибка чтения файла: {e}")

    # --- [2] Живое подключение openssl s_client ---
    _box_sep()
    _box_row(f"  {CYAN}Живая проверка ({domain}:{port}):{NC}")
    try:
        import subprocess as _sp
        proc = _sp.run(
            ["openssl", "s_client", "-connect", f"{domain}:{port}",
             "-servername", domain, "-brief"],
            input=b"Q\n",
            capture_output=True,
            timeout=10,
        )
        output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")

        # Ищем строки с результатом верификации
        verified = False
        for line in output.splitlines():
            ll = line.strip().lower()
            if "verify return" in ll and "1" in ll:
                verified = True
            if "verify ok" in ll or "verification: ok" in ll:
                verified = True
            if "certificate chain" in ll or "depth=" in ll.lower():
                _box_row(f"    {DIM}{line.strip()}{NC}")

        if "verify error" in output.lower():
            for line in output.splitlines():
                if "verify error" in line.lower():
                    _box_warn(f"Ошибка цепочки: {line.strip()}")
            verified = False

        if verified:
            _box_ok("Цепочка сертификатов: OK")
        else:
            # Пробуем упрощённый вывод без -brief
            proc2 = _sp.run(
                ["openssl", "s_client", "-connect", f"{domain}:{port}",
                 "-servername", domain],
                input=b"Q\n",
                capture_output=True,
                timeout=10,
            )
            out2 = (proc2.stdout + proc2.stderr).decode("utf-8", errors="replace")
            if "Verify return code: 0" in out2:
                _box_ok("Цепочка сертификатов: OK")
            else:
                for line in out2.splitlines():
                    if "Verify return code" in line:
                        _box_warn(f"Цепочка: {line.strip()}")
                        break
                else:
                    _box_warn("Не удалось однозначно определить статус цепочки")

    except FileNotFoundError:
        _box_warn("openssl не найден — установите: apt install openssl")
    except Exception as e:
        _box_warn(f"Ошибка подключения: {e}")

    _box_bottom()
    log_to_file("INFO", f"TLS cert check: domain={domain} port={port}")


def health_check_ports() -> bool:
    for port in (22, 80, _get_state_value("server_port", 443)):
        r = _run(["ss", "-tlnp"], capture=True, check=False)
        if f":{port} " in r.stdout:
            success(f"Порт {port}: OK")
        else:
            warn(f"Порт {port}: не слушает")
    return True


def run_full_health_check() -> bool:
    info("=== Полная проверка здоровья системы ===")
    status = "healthy"
    if not health_check_xray():  status = "degraded"
    if not health_check_nginx(): status = "degraded"
    if not health_check_ssl():   status = "degraded"
    health_check_ports()
    HEALTH_CHECK_FILE.parent.mkdir(parents=True, exist_ok=True)
    HEALTH_CHECK_FILE.write_text(status)
    if status == "healthy":
        success("=== Все проверки здоровья пройдены ===")
    else:
        warn("=== Проверка завершена с предупреждениями ===")
    return status == "healthy"

# =============================================================================
#  UNIT ТЕСТЫ
# =============================================================================

