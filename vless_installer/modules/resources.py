"""
vless_installer/modules/resources.py
───────────────────────────────────────────────────────────────────────────────
Фундаментальные хелперы ядра: ресурсы системы, генераторы значений,
определение IP/страны сервера, адаптивные параметры.

  • _get_total_ram_mb() / _get_total_cpu()   — аппаратные характеристики
  • gen_uuid() / gen_hex() / gen_spiderx()   — генераторы (UUID, hex, путь)
  • get_server_ip()                          — публичный IP сервера
  • country_flag_emoji()                     — emoji-флаг по ISO 3166-1 alpha-2
  • get_server_country() / _cached()         — страна по IP (ip-api.com)
  • get_adaptive_value()                     — адаптивные sysctl-параметры
  • generate_self_signed_cert()              — openssl self-signed

Не вынесены (остались в _core.py, т.к. мутируют globals):
  • _on_exit()                               — atexit trap, пишет INSTALL_STARTED
  • _check_resources()                       — sys.exit при нехватке RAM
  • _check_ipv6_preflight()                  — мутирует IS_IPV6_AVAILABLE /
                                                 IPV6_PREFLIGHT / IPV6_ROUTE_OK

Точки входа из _core.py:
    from vless_installer.modules.resources import (
        _get_total_ram_mb, _get_total_cpu,
        gen_uuid, gen_hex, gen_spiderx,
        get_server_ip, country_flag_emoji,
        get_server_country, get_server_country_cached,
        get_adaptive_value, generate_self_signed_cert,
    )

Доступ к helpers ядра (_run, info, warn, success, TOTAL_RAM) — через
_core_module() lazy binding.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

# ── Кеш страны сервера (заполняется один раз) ────────────────────────────────
_SERVER_CC:   str = ""
_SERVER_NAME: str = ""
_SERVER_FLAG: str = ""


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  АППАРАТНЫЕ РЕСУРСЫ
# ============================================================================
def _get_total_ram_mb() -> int:
    try:
        result = subprocess.run(["free", "-m"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("Mem:"):
                return int(line.split()[1])
    except Exception:
        pass
    return 1024


def _get_total_cpu() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


# ============================================================================
#  ГЕНЕРАТОРЫ
# ============================================================================
def gen_uuid() -> str:
    return str(uuid.uuid4())


def gen_hex(n: int = 8) -> str:
    core = _core_module()
    _run = core._run
    try:
        result = _run(["openssl", "rand", "-hex", str(n)], capture=True, check=False)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ''.join(random.choices('0123456789abcdef', k=n * 2))


def gen_spiderx() -> str:
    chars = string.ascii_lowercase + string.digits
    length = random.randint(6, 15)
    return '/' + ''.join(random.choices(chars, k=length))


# ============================================================================
#  IP / GEOIP СЕРВЕРА
# ============================================================================
def get_server_ip(ip_type: str = "4") -> str:
    core = _core_module()
    _run = core._run
    if ip_type == "6":
        urls = ["https://api64.ipify.org"]
        flag = "-6"
    else:
        urls = ["https://api4.ipify.org"]
        flag = "-4"
    for url in urls:
        try:
            r = _run(["curl", "-s", flag, "-m", "5", url],
                     capture=True, check=False)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except Exception:
            pass

    # ПАТЧ: fallback через 'ip route get 8.8.8.8' — работает без доступа в интернет,
    # на серверах со сложной маршрутизацией или несколькими интерфейсами.
    # Критично для awg_apply_policy_routing: без корректного локального IP
    # исключение из AWG-маршрутизации не будет добавлено → потеря SSH после ребута.
    if ip_type == "4":
        try:
            r2 = _run(["ip", "route", "get", "8.8.8.8"],
                      capture=True, check=False)
            if r2.returncode == 0:
                # Парсим строку вида: "8.8.8.8 via ... src 1.2.3.4 uid ..."
                for token in r2.stdout.split():
                    if token == "src":
                        idx = r2.stdout.split().index("src")
                        candidate = r2.stdout.split()[idx + 1]
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate):
                            return candidate
        except Exception:
            pass

    return ""


def country_flag_emoji(country_code: str) -> str:
    """
    Возвращает эмодзи флага страны по двухбуквенному коду ISO 3166-1 alpha-2.
    Принцип: буквы A-Z маппятся на региональные индикаторы Unicode (U+1F1E6..U+1F1FF).
    """
    cc = country_code.upper().strip()
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc)


def get_server_country() -> tuple[str, str, str]:
    """
    Определяет страну сервера по его публичному IPv4 через ip-api.com.
    Возвращает (country_code, country_name, flag_emoji).
    """
    core = _core_module()
    _run = core._run
    try:
        r = _run(
            ["curl", "-s", "--max-time", "8",
             "http://ip-api.com/json?fields=status,country,countryCode,city"],
            capture=True, check=False
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip())
            if data.get("status") == "success":
                cc   = data.get("countryCode", "??")
                name = data.get("country", "Unknown")
                return cc, name, country_flag_emoji(cc)
    except Exception:
        pass
    return "??", "Unknown", "🌐"


def get_server_country_cached() -> tuple[str, str, str]:
    """Возвращает (country_code, country_name, flag_emoji), кешируя результат."""
    global _SERVER_CC, _SERVER_NAME, _SERVER_FLAG
    if not _SERVER_CC:
        _SERVER_CC, _SERVER_NAME, _SERVER_FLAG = get_server_country()
    return _SERVER_CC, _SERVER_NAME, _SERVER_FLAG


# ============================================================================
#  АДАПТИВНЫЕ ПАРАМЕТРЫ (под TOTAL_RAM)
# ============================================================================
def get_adaptive_value(param: str) -> str:
    core = _core_module()
    TOTAL_RAM = core.TOTAL_RAM
    if TOTAL_RAM < 512:
        mapping: dict[str, str] = {
            "overcommit": "0", "swappiness": "1",
            "conntrack": "262144", "file_max": "524288",
        }
    elif TOTAL_RAM < 1024:
        mapping = {
            "overcommit": "0", "swappiness": "5",
            "conntrack": "524288", "file_max": "1048576",
        }
    else:
        mapping = {
            "overcommit": "1", "swappiness": "10",
            "conntrack": "2000000", "file_max": "2097152",
        }
    return mapping.get(param, "")


# ============================================================================
#  САМОПОДПИСАННЫЙ СЕРТИФИКАТ
# ============================================================================
def generate_self_signed_cert(domain: str) -> None:
    core = _core_module()
    info    = core.info
    success = core.success
    _run    = core._run

    le_path = Path(f"/etc/letsencrypt/live/{domain}")
    info(f"Генерация самоподписанного сертификата для {domain}...")
    le_path.mkdir(parents=True, exist_ok=True)
    _run([
        "openssl", "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(le_path / "privkey.pem"),
        "-out",    str(le_path / "fullchain.pem"),
        "-subj",   f"/CN={domain}/O=SelfSigned/C=US",
        "-addext", f"subjectAltName=DNS:{domain}",
    ], quiet=True, check=False)
    try:
        (le_path / "privkey.pem").chmod(0o600)
        (le_path / "fullchain.pem").chmod(0o644)
    except Exception:
        pass
    success("Самоподписанный сертификат создан")
