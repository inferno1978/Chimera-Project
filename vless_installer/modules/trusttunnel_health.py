"""
vless_installer/modules/trusttunnel_health.py
───────────────────────────────────────────────────────────────────────────────
Health check для TrustTunnel-сервиса. Вызывается из cron через
`main.py --trusttunnel-health` (каждые 5 минут, install_cron()).

Методы проверки:
  • systemctl is-active trusttunnel
  • /metrics endpoint (http://127.0.0.1:1987/health-check → HTTP 200)
  • Версия бинарника совпадает с state['version']

Если сервис упал — одна попытка рестарта + повторная проверка.
Результат пишется в /var/lib/xray-installer/trusttunnel-health.status.

Точка входа из main.py:
    from vless_installer.modules.trusttunnel_health import (
        trusttunnel_health_check, trusttunnel_health_check_cron,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from vless_installer.modules.trusttunnel import (
    trusttunnel_load_state,
    trusttunnel_service_active,
    trusttunnel_restart_service,
    _BINARY_PATH,
    _METRICS_PORT,
    _SERVICE_NAME,
    _log,
)

_STATUS_FILE = Path("/var/lib/xray-installer/trusttunnel-health.status")


def trusttunnel_health_check() -> dict:
    """Одна итерация health-check. Возвращает dict:
      {"healthy": bool, "service_active": bool, "metrics_ok": bool,
       "version_match": bool, "details": str, "checked_at": ISO}
    """
    state = trusttunnel_load_state()
    result = {
        "healthy":        False,
        "service_active": False,
        "metrics_ok":     False,
        "version_match":  False,
        "details":        "",
        "checked_at":     datetime.now(timezone.utc).isoformat(),
    }
    if not state.get("installed"):
        result["details"] = "TrustTunnel not installed"
        return result

    # 1. Сервис активен?
    result["service_active"] = trusttunnel_service_active()

    # 2. /metrics endpoint
    metrics_port = state.get("metrics_port", _METRICS_PORT)
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-m", "5", f"http://127.0.0.1:{metrics_port}/health-check"],
            capture_output=True, text=True, timeout=8,
        )
        result["metrics_ok"] = r.stdout.strip() == "200"
    except Exception:
        result["metrics_ok"] = False

    # 3. Версия бинарника
    expected_version = state.get("version", "")
    if _BINARY_PATH.exists() and expected_version:
        try:
            r = subprocess.run(
                [str(_BINARY_PATH), "--version"],
                capture_output=True, text=True, timeout=5,
            )
            actual = (r.stdout or "").strip()
            result["version_match"] = (actual == expected_version)
        except Exception:
            result["version_match"] = False

    result["healthy"] = result["service_active"] and result["metrics_ok"]
    if not result["healthy"]:
        result["details"] = (
            f"service={'up' if result['service_active'] else 'DOWN'}, "
            f"metrics={'ok' if result['metrics_ok'] else 'FAIL'}, "
            f"version={'ok' if result['version_match'] else 'MISMATCH'}"
        )
    return result


def trusttunnel_health_check_cron() -> None:
    """Cron entrypoint. Проверяет health, при падении — одна попытка
    рестарта + повторная проверка. Пишет status-файл.
    """
    _log("INFO", "health_check_cron: starting")
    check = trusttunnel_health_check()
    if not check["healthy"]:
        _log("WARN", f"health_check_cron: unhealthy — {check['details']}, attempting restart")
        if trusttunnel_restart_service():
            time.sleep(3)
            check = trusttunnel_health_check()
            _log("INFO", f"health_check_cron: after restart — healthy={check['healthy']}")
        else:
            _log("ERROR", "health_check_cron: restart failed")
    try:
        _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATUS_FILE.write_text(json.dumps(check, indent=2))
        _STATUS_FILE.chmod(0o600)
    except Exception as e:
        _log("WARN", f"health_check_cron: cannot write status file: {e}")
    _log("INFO", f"health_check_cron: done, healthy={check['healthy']}")
