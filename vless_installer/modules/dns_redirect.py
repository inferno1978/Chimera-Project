"""
vless_installer/modules/dns_redirect.py
───────────────────────────────────────────────────────────────────────────────
Принудительное перенаправление DNS-трафика (порт 53, UDP+TCP) от VPN-клиентов
через iptables/ip6tables NAT REDIRECT на локальный DNSCrypt-proxy.

ЗАЧЕМ
=====
Без этого правила клиент может вручную прописать свой DNS-сервер (8.8.8.8,
1.1.1.1, провайдерский DNS) — и его DNS-запросы уйдут напрямую, минуя
DNSCrypt-proxy. Это:
  • сводит на нет защиту от DNS-leak
  • позволяет провайдеру видеть запрашиваемые домены
  • может использоваться для DPI-блокировки по DNS

Правило NAT REDIRECT в PREROUTING перехватывает ВСЕ пакеты с --dport 53,
приходящие через VPN-интерфейс (awg0), и перенаправляет их на локальный
dnscrypt-proxy (по умолчанию 127.0.0.1:5300). Клиент не может обойти это
на уровне приложения.

АРХИТЕКТУРА
===========
• State-файл: /var/lib/xray-installer/dns_redirect.json (chmod 0o600)
  Поля: enabled, target_port, iface_filter, applied_at, comment
• Правила iptables: table=nat, chain=PREROUTING, -i <iface> -p udp/tcp --dport 53
  → REDIRECT --to-ports <dnscrypt_port>
• Идемпотентность: через -C (check) перед -A (add), по образцу
  awg_net_common.iptables_ensure()
• IPv6: применяется только если dnscrypt-proxy слушает ::1 (в текущей
  конфигурации НЕ слушает — поэтому IPv6 REDIRECT пропускается с warning)
• Health-check: проверка что dnscrypt-proxy активен и слушает порт
  перед apply (чтобы не создать black-hole)
• Persist после reboot: systemd-юнит dns-redirect-restore.service
  (ExecStartPost применяет правила при старте сети)

ПРОТОКОЛ-СПЕЦИФИКА
==================
AWG standalone / cascade: интерфейс awg0
Mode A (без AWG): нет VPN-интерфейса — REDIRECT не имеет смысла
  (клиенты подключаются по VLESS TCP:443 напрямую, DNS уходит через Xray
  dns-spoofing, а не через отдельный интерфейс)

Публичное API:
  do_manage_dns_redirect()  — TUI-меню (пункт в _menu_network)
  apply_dns_redirect()      — применить правила (idempotent)
  remove_dns_redirect()     — удалить правила
  health_check_dns_redirect() — для diagnostics / health check
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Tuple


# =============================================================================
#  Константы
# =============================================================================
_STATE_FILE     = Path("/var/lib/xray-installer/dns_redirect.json")
_LOG_FILE       = Path("/var/log/vless-install.log")
_DNSCRYPT_TOML  = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
_DEFAULT_PORT   = 5300
_DEFAULT_IFACE  = "awg0"  # standalone AWG и cascade — оба используют awg0
_COMMENT        = "xray-dns-redirect"  # для идентификации правил при -D

# systemd unit для persist после reboot
_RESTORE_SVC    = Path("/etc/systemd/system/dns-redirect-restore.service")
_RESTORE_SCRIPT = Path("/usr/local/bin/xray-dns-redirect-restore.sh")


# =============================================================================
#  Цвета (как в tg_bot.py / ingress_geoip.py)
# =============================================================================
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']


# ── box_renderer ─────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item,
    _box_back, _box_info, _box_warn, _box_desc,
)


# =============================================================================
#  Логирование
# =============================================================================
def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        with _LOG_FILE.open("a") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"[DNS-REDIRECT] [{level}] {clean}\n")
    except Exception:
        pass

def _info(msg):  print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO", msg)
def _ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg):   print(f"{RED}[ERR]{NC}   {msg}");   _log("ERROR", msg)


def _run(cmd: list, capture: bool = False, quiet: bool = False,
         check: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  STATE I/O
# =============================================================================
def state_load() -> dict:
    """Загружает конфигурацию DNS-редиректа.
    Возвращает дефолт при отсутствии файла.
    """
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {
        "enabled":       False,
        "target_port":   _DEFAULT_PORT,
        "iface_filter":  _DEFAULT_IFACE,
        "applied_at":    "",
        "ipv6_enabled":  False,
    }


def state_save(data: dict) -> None:
    """Сохраняет конфигурацию (chmod 0o600)."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    try:
        _STATE_FILE.chmod(0o600)
    except Exception:
        pass


# =============================================================================
#  ОПРЕДЕЛЕНИЕ ПОРТА DNSCRYPT
# =============================================================================
def get_dnscrypt_port() -> int:
    """Определяет актуальный порт dnscrypt-proxy.
    1. Читает listen_addresses из TOML (если файл существует).
    2. Fallback на _DEFAULT_PORT (5300).

    Поддерживает форматы:
      '127.0.0.1:5300'           — IPv4
      '[::1]:5300'               — IPv6 в квадратных скобках
      '[::]:5353'                — IPv6 any
    """
    if _DNSCRYPT_TOML.exists():
        try:
            content = _DNSCRYPT_TOML.read_text()
            # Сначала ищем IPv6-формат [::xxx]:PORT
            m = re.search(
                r'listen_addresses\s*=\s*\[\s*[\'"]\[[^\]]+\]:(\d+)',
                content, re.IGNORECASE,
            )
            if m:
                port = int(m.group(1))
                if 1024 <= port <= 65535:
                    return port
            # Затем IPv4-формат xxx:PORT
            m = re.search(
                r'listen_addresses\s*=\s*\[\s*[\'"][^:]+:(\d+)',
                content, re.IGNORECASE,
            )
            if m:
                port = int(m.group(1))
                if 1024 <= port <= 65535:
                    return port
        except Exception:
            pass
    return _DEFAULT_PORT


def get_dnscrypt_listen_ipv6() -> bool:
    """True если dnscrypt-proxy слушает на ::1 (IPv6 loopback).
    Иначе False — в этом случае IPv6 REDIRECT бессмысленен (connection refused).
    """
    if not _DNSCRYPT_TOML.exists():
        return False
    try:
        content = _DNSCRYPT_TOML.read_text()
        # Ищем listen_addresses = ['[::1]:5300', ...] или ['127.0.0.1:5300', '[::1]:5300']
        m = re.search(r'listen_addresses\s*=\s*\[(.*?)\]', content, re.IGNORECASE | re.DOTALL)
        if m:
            addrs_str = m.group(1)
            return '::1' in addrs_str or '::' in addrs_str
    except Exception:
        pass
    return False


# =============================================================================
#  HEALTH CHECK
# =============================================================================
def is_dnscrypt_active() -> bool:
    """Проверяет что dnscrypt-proxy активен (systemctl is-active)."""
    r = _run(["systemctl", "is-active", "--quiet", "dnscrypt-proxy"],
             quiet=True, check=False)
    return r.returncode == 0


def is_port_listening(port: int, proto: str = "udp") -> bool:
    """Проверяет что локальный порт слушается через ss.
    proto: 'udp' или 'tcp'.
    """
    flag = "-ulnp" if proto == "udp" else "-tlnp"
    r = _run(["ss", flag], capture=True, check=False)
    if r.returncode != 0:
        return False
    # Ищем :5300 в выводе (с пробелом или концом строки)
    return bool(re.search(rf":{port}\s", r.stdout))


def health_check_dns_redirect() -> dict:
    """
    Полная проверка состояния DNS-редиректа для diagnostics.

    Возвращает dict:
      {
        "enabled": bool,           # включён ли в state
        "dnscrypt_active": bool,   # запущен ли сервис
        "port_listening_udp": bool,
        "port_listening_tcp": bool,
        "rules_applied": bool,     # есть ли правила в iptables
        "ipv6_supported": bool,    # слушает ли dnscrypt на ::1
        "issues": [str],           # список проблем
        "recommendation": str,     # человекочитаемая рекомендация
      }
    """
    state = state_load()
    port = state.get("target_port", _DEFAULT_PORT)
    result = {
        "enabled":            state.get("enabled", False),
        "dnscrypt_active":    is_dnscrypt_active(),
        "port_listening_udp": is_port_listening(port, "udp"),
        "port_listening_tcp": is_port_listening(port, "tcp"),
        "rules_applied":      _check_rules_applied(state.get("iface_filter", "")),
        "ipv6_supported":     get_dnscrypt_listen_ipv6(),
        "issues":             [],
        "recommendation":     "",
    }
    if not result["dnscrypt_active"]:
        result["issues"].append("dnscrypt-proxy сервис не активен")
    if not result["port_listening_udp"]:
        result["issues"].append(f"порт {port}/udp не слушается dnscrypt-proxy")
    if not result["port_listening_tcp"]:
        result["issues"].append(f"порт {port}/tcp не слушается dnscrypt-proxy")
    if result["enabled"] and not result["rules_applied"]:
        result["issues"].append("редирект включён в state, но правила в iptables отсутствуют")
    if result["enabled"] and result["rules_applied"] and not result["dnscrypt_active"]:
        result["issues"].append(
            "ВНИМАНИЕ: правила активны, но dnscrypt-proxy не запущен — "
            "DNS-трафик клиентов будет отбрасываться (black-hole)!"
        )

    if not result["enabled"]:
        result["recommendation"] = "DNS-редирект выключен"
    elif not result["issues"]:
        result["recommendation"] = "OK — DNS-редирект работает корректно"
    else:
        result["recommendation"] = (
            "Требуется внимание: " + "; ".join(result["issues"]) +
            ". Перезапустите dnscrypt-proxy или отключите редирект."
        )
    return result


# =============================================================================
#  Iptables helper (идемпотентное добавление/удаление)
# =============================================================================
def _ipt_rule_exists(family: str, table: str, chain: str,
                     rule_args: list) -> bool:
    """Проверяет существование правила через -C (check).
    family: 'iptables' или 'ip6tables'.
    """
    cmd = [family, "-t", table, "-C", chain] + rule_args
    r = _run(cmd, quiet=True, check=False)
    return r.returncode == 0


def _ipt_add_rule_idempotent(family: str, table: str, chain: str,
                             rule_args: list) -> bool:
    """Идемпотентно добавляет правило (через -C → -A).
    Возвращает True если правило добавлено или уже существовало.
    """
    if _ipt_rule_exists(family, table, chain, rule_args):
        return True  # уже есть
    cmd = [family, "-t", table, "-A", chain] + rule_args
    r = _run(cmd, quiet=True, check=False)
    if r.returncode != 0:
        _log("ERROR", f"failed to add rule: {' '.join(cmd)} (rc={r.returncode})")
        return False
    return True


def _ipt_delete_rule(family: str, table: str, chain: str,
                     rule_args: list) -> bool:
    """Удаляет правило через -D. Возвращает True при успехе или если правила не было."""
    cmd = [family, "-t", table, "-D", chain] + rule_args
    r = _run(cmd, quiet=True, check=False)
    # rc=0 — удалено; rc=1 — правила не было (тоже OK для идемпотентности)
    return r.returncode in (0, 1)


def _build_redirect_rule_args(iface: str, proto: str, target_port: int) -> list:
    """Строит аргументы правила REDIRECT для iptables.
    Пример: ['-i', 'awg0', '-p', 'udp', '--dport', '53',
             '-j', 'REDIRECT', '--to-ports', '5300',
             '-m', 'comment', '--comment', 'xray-dns-redirect']
    """
    return [
        "-i", iface,
        "-p", proto,
        "--dport", "53",
        "-j", "REDIRECT",
        "--to-ports", str(target_port),
        "-m", "comment", "--comment", _COMMENT,
    ]


def _check_rules_applied(iface: str) -> bool:
    """Проверяет есть ли в iptables наши правила REDIRECT для указанного интерфейса."""
    port = get_dnscrypt_port()
    for proto in ("udp", "tcp"):
        rule_args = _build_redirect_rule_args(iface, proto, port)
        if not _ipt_rule_exists("iptables", "nat", "PREROUTING", rule_args):
            return False
    return True


# =============================================================================
#  APPLY / REMOVE
# =============================================================================
def apply_dns_redirect(iface: Optional[str] = None,
                       target_port: Optional[int] = None) -> dict:
    """
    Применяет правила NAT REDIRECT для DNS-трафика от VPN-клиентов.

    Аргументы:
      iface       — VPN-интерфейс (по умолчанию 'awg0')
      target_port — порт dnscrypt-proxy (по умолчанию auto-detected из TOML)

    Возвращает dict с результатом:
      {"success": bool, "applied_v4": bool, "applied_v6": bool,
       "skipped_reason": str, "warnings": [str]}

    Идемпотентность: повторный вызов НЕ создаёт дубликаты (через -C check).

    Edge-cases:
      • Если dnscrypt-proxy не активен → НЕ применяем (black-hole prevention).
      • Если dnscrypt не слушает ::1 → IPv6 правила пропускаются с warning.
      • Если интерфейс не существует → правила всё равно добавляются
        (iptables не валидирует -i на момент добавления; правило станет
        активным когда интерфейс появится). См. remove_dns_redirect для
        cleanup при отключении интерфейса.
    """
    iface = iface or _DEFAULT_IFACE
    target_port = target_port or get_dnscrypt_port()
    result = {
        "success":         False,
        "applied_v4":      False,
        "applied_v6":      False,
        "skipped_reason":  "",
        "warnings":        [],
    }

    # 1) Health-check: dnscrypt-proxy должен быть активен
    if not is_dnscrypt_active():
        result["skipped_reason"] = (
            "dnscrypt-proxy не активен — применение правил создаст black-hole. "
            "Сначала запустите dnscrypt-proxy."
        )
        _err(result["skipped_reason"])
        return result

    if not is_port_listening(target_port, "udp"):
        result["skipped_reason"] = (
            f"dnscrypt-proxy не слушает порт {target_port}/udp — применение создаст black-hole."
        )
        _err(result["skipped_reason"])
        return result

    # 2) Применяем IPv4 правила (UDP + TCP)
    for proto in ("udp", "tcp"):
        rule_args = _build_redirect_rule_args(iface, proto, target_port)
        ok = _ipt_add_rule_idempotent("iptables", "nat", "PREROUTING", rule_args)
        if not ok:
            result["warnings"].append(
                f"не удалось добавить IPv4 {proto} правило"
            )
    # Проверяем что оба правила реально стоят
    result["applied_v4"] = _check_rules_applied(iface)

    # 3) IPv6 — только если dnscrypt слушает ::1
    ipv6_supported = get_dnscrypt_listen_ipv6()
    if ipv6_supported:
        for proto in ("udp", "tcp"):
            rule_args = _build_redirect_rule_args(iface, proto, target_port)
            _ipt_add_rule_idempotent("ip6tables", "nat", "PREROUTING", rule_args)
        # Проверяем
        v6_ok = True
        for proto in ("udp", "tcp"):
            rule_args = _build_redirect_rule_args(iface, proto, target_port)
            if not _ipt_rule_exists("ip6tables", "nat", "PREROUTING", rule_args):
                v6_ok = False
                break
        result["applied_v6"] = v6_ok
    else:
        result["warnings"].append(
            "dnscrypt-proxy не слушает ::1 — IPv6 REDIRECT пропущен "
            "(клиенты с IPv6 DNS будут получать connection refused). "
            "Добавьте '[::1]:5300' в listen_addresses TOML для IPv6 поддержки."
        )

    # 4) Сохраняем state
    state = state_load()
    state.update({
        "enabled":       True,
        "target_port":   target_port,
        "iface_filter":  iface,
        "applied_at":    datetime.now(timezone.utc).isoformat(),
        "ipv6_enabled":  ipv6_supported,
    })
    state_save(state)

    # 5) Persist после reboot
    _install_restore_service(iface, target_port)

    result["success"] = result["applied_v4"]
    _log("INFO", f"apply_dns_redirect: success={result['success']}, "
                  f"v4={result['applied_v4']}, v6={result['applied_v6']}, "
                  f"warnings={result['warnings']}")
    return result


def remove_dns_redirect() -> dict:
    """
    Удаляет все правила NAT REDIRECT для DNS (IPv4 + IPv6).
    Идемпотентно — повторный вызов безопасен.

    Edge-case: если AWG-интерфейс уже отключён, правила всё равно
    корректно удаляются (iptables -D работает независимо от существования
    интерфейса).
    """
    state = state_load()
    iface = state.get("iface_filter", _DEFAULT_IFACE)
    port = state.get("target_port", get_dnscrypt_port())
    result = {"success": True, "removed_v4": False, "removed_v6": False}

    # IPv4
    for proto in ("udp", "tcp"):
        rule_args = _build_redirect_rule_args(iface, proto, port)
        _ipt_delete_rule("iptables", "nat", "PREROUTING", rule_args)
    # Проверяем что удалили
    v4_remaining = False
    for proto in ("udp", "tcp"):
        rule_args = _build_redirect_rule_args(iface, proto, port)
        if _ipt_rule_exists("iptables", "nat", "PREROUTING", rule_args):
            v4_remaining = True
            break
    result["removed_v4"] = not v4_remaining

    # IPv6 (только если были применены)
    if state.get("ipv6_enabled"):
        for proto in ("udp", "tcp"):
            rule_args = _build_redirect_rule_args(iface, proto, port)
            _ipt_delete_rule("ip6tables", "nat", "PREROUTING", rule_args)
        v6_remaining = False
        for proto in ("udp", "tcp"):
            rule_args = _build_redirect_rule_args(iface, proto, port)
            if _ipt_rule_exists("ip6tables", "nat", "PREROUTING", rule_args):
                v6_remaining = True
                break
        result["removed_v6"] = not v6_remaining

    # Дополнительно: cleanup «висячих» правил с любым интерфейсом
    # (если admin сменил iface_filter между apply и remove)
    _cleanup_all_dns_redirect_rules()

    # Обновляем state
    state.update({
        "enabled":      False,
        "applied_at":   "",
        "ipv6_enabled": False,
    })
    state_save(state)

    # Удаляем restore-service
    _remove_restore_service()

    _log("INFO", f"remove_dns_redirect: v4={result['removed_v4']}, v6={result['removed_v6']}")
    return result


def _cleanup_all_dns_redirect_rules() -> None:
    """Удаляет ВСЕ правила с комментарием xray-dns-redirect
    (для cleanup если admin менял iface между apply).
    """
    for family in ("iptables", "ip6tables"):
        # Перечисляем правила с нашим комментарием и удаляем каждое
        for _ in range(10):  # максимум 10 итераций (защита от зацикливания)
            r = _run(
                [family, "-t", "nat", "-S", "PREROUTING"],
                capture=True, check=False,
            )
            if r.returncode != 0:
                break
            lines = r.stdout.splitlines()
            found_to_delete = None
            for line in lines:
                if _COMMENT in line and "REDIRECT" in line and "--dport 53" in line:
                    # Парсим правило: "-A PREROUTING -i awg0 -p udp --dport 53 ..."
                    # → удаляем через -D PREROUTING <args>
                    parts = line.split()
                    if len(parts) < 2 or parts[0] != "-A":
                        continue
                    chain = parts[1]
                    rule_args = parts[2:]
                    found_to_delete = (chain, rule_args)
                    break
            if not found_to_delete:
                break
            chain, rule_args = found_to_delete
            _run([family, "-t", "nat", "-D", chain] + rule_args,
                 quiet=True, check=False)


# =============================================================================
#  PERSIST после reboot (systemd unit)
# =============================================================================
def _install_restore_service(iface: str, target_port: int) -> None:
    """Устанавливает systemd unit, который восстанавливает правила после reboot."""
    script = (
        "#!/bin/bash\n"
        "# Auto-generated by vless-installer (dns_redirect.py)\n"
        "# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ\n"
        f"IFACE={iface}\n"
        f"PORT={target_port}\n"
        "sleep 3  # ждём пока поднимется сеть\n"
        "# Проверяем что dnscrypt-proxy активен\n"
        "if ! systemctl is-active --quiet dnscrypt-proxy; then\n"
        "  echo 'dnscrypt-proxy not active, skipping DNS redirect restore' >&2\n"
        "  exit 0\n"
        "fi\n"
        "# IPv4 UDP\n"
        f"iptables -t nat -C PREROUTING -i $IFACE -p udp --dport 53 -j REDIRECT "
        f"--to-ports $PORT -m comment --comment {_COMMENT} 2>/dev/null || \\\n"
        f"iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 53 -j REDIRECT "
        f"--to-ports $PORT -m comment --comment {_COMMENT}\n"
        "# IPv4 TCP\n"
        f"iptables -t nat -C PREROUTING -i $IFACE -p tcp --dport 53 -j REDIRECT "
        f"--to-ports $PORT -m comment --comment {_COMMENT} 2>/dev/null || \\\n"
        f"iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 53 -j REDIRECT "
        f"--to-ports $PORT -m comment --comment {_COMMENT}\n"
    )
    try:
        _RESTORE_SCRIPT.write_text(script)
        _RESTORE_SCRIPT.chmod(0o755)
        svc = (
            "[Unit]\n"
            "Description=Restore DNS Redirect iptables rules (VLESS Installer)\n"
            "After=network-online.target dnscrypt-proxy.service\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={_RESTORE_SCRIPT}\n"
            "RemainAfterExit=yes\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        _RESTORE_SVC.write_text(svc)
        _run(["systemctl", "daemon-reload"], quiet=True)
        _run(["systemctl", "enable", "dns-redirect-restore"], quiet=True)
    except Exception as e:
        _log("WARN", f"cannot install restore service: {e}")


def _remove_restore_service() -> None:
    """Удаляет systemd unit для restore после reboot."""
    try:
        _run(["systemctl", "stop", "dns-redirect-restore"], quiet=True)
        _run(["systemctl", "disable", "dns-redirect-restore"], quiet=True)
    except Exception:
        pass
    try:
        _RESTORE_SVC.unlink(missing_ok=True)
        _RESTORE_SCRIPT.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], quiet=True)
    except Exception:
        pass


# =============================================================================
#  TUI-МЕНЮ
# =============================================================================
def do_manage_dns_redirect() -> None:
    """Меню управления принудительным DNS-редиректом.
    Пункт в _menu_network() в _core.py.
    """
    while True:
        os.system("clear")
        state = state_load()
        port = state.get("target_port", _DEFAULT_PORT)
        iface = state.get("iface_filter", _DEFAULT_IFACE)
        enabled = state.get("enabled", False)

        # Health-check данные
        hc = health_check_dns_redirect()

        print()
        _box_top("🔒  ПРИНУДИТЕЛЬНЫЙ DNS REDIRECT")
        _box_desc(
            "Перенаправление DNS-трафика (порт 53, UDP+TCP) от VPN-клиентов "
            "на локальный DNSCrypt-proxy. Исключает DNS leak даже если клиент "
            "прописал свой DNS-сервер вручную."
        )
        _box_sep()
        status_str = (f"{GREEN}ВКЛЮЧЁН{NC}" if enabled else f"{DIM}ВЫКЛЮЧЕН{NC}")
        _box_row(f"  Статус:           {status_str}")
        _box_row(f"  Интерфейс:        {CYAN}{iface}{NC}")
        _box_row(f"  Целевой порт:     {CYAN}{port}{NC} (dnscrypt-proxy)")
        if state.get("applied_at"):
            applied = state["applied_at"][:19].replace("T", " ")
            _box_row(f"  Применён:         {DIM}{applied}{NC}")
        _box_sep()
        _box_row(f"  {BOLD}Health Check:{NC}")
        hc_str = f"{GREEN}OK{NC}" if not hc["issues"] else f"{YELLOW}проблемы{NC}"
        _box_row(f"    dnscrypt-proxy: {GREEN if hc['dnscrypt_active'] else RED}"
                 f"{'активен' if hc['dnscrypt_active'] else 'НЕ активен'}{NC}")
        _box_row(f"    Порт {port}/udp:  {GREEN if hc['port_listening_udp'] else RED}"
                 f"{'слушается' if hc['port_listening_udp'] else 'НЕ слушается'}{NC}")
        _box_row(f"    Порт {port}/tcp:  {GREEN if hc['port_listening_tcp'] else RED}"
                 f"{'слушается' if hc['port_listening_tcp'] else 'НЕ слушается'}{NC}")
        _box_row(f"    Правила iptables: {GREEN if hc['rules_applied'] else DIM}"
                 f"{'применены' if hc['rules_applied'] else 'отсутствуют'}{NC}")
        _box_row(f"    IPv6 support:    {GREEN if hc['ipv6_supported'] else YELLOW}"
                 f"{'да (::1 слушается)' if hc['ipv6_supported'] else 'нет (только IPv4)'}{NC}")
        if hc["issues"]:
            _box_sep()
            _box_warn("  " + "; ".join(hc["issues"]))
        _box_sep()
        if not enabled:
            _box_item("1", f"{GREEN}Включить DNS REDIRECT{NC} (перенаправление на dnscrypt-proxy)")
        else:
            _box_item("1", f"Переприменить правила{NC} (после рестарта dnscrypt-proxy)")
            _box_item("2", f"{RED}Отключить DNS REDIRECT{NC} (удалить правила")
        _box_item("3", "Изменить интерфейс (по умолчанию awg0)")
        _box_item("4", "Изменить целевой порт (по умолчанию auto-detected)")
        _box_item("5", "Показать текущие правила iptables")
        _box_item("6", "Тест: dig через VPN-интерфейс (если возможно)")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            return

        if ch == "1":
            _menu_apply(iface, port)
        elif ch == "2" and enabled:
            _menu_remove()
        elif ch == "3":
            _menu_change_iface()
        elif ch == "4":
            _menu_change_port()
        elif ch == "5":
            _menu_show_rules()
        elif ch == "6":
            _menu_dig_test(iface, port)
        elif ch in ("q", "Q", "0", ""):
            return
        else:
            _warn("Неверный выбор")
            time.sleep(1)


def _menu_apply(iface: str, port: int) -> None:
    """Применение правил с подтверждением."""
    os.system("clear")
    print()
    _box_top("🔒  Применение DNS REDIRECT")
    _box_desc(
        f"Будут добавлены правила в iptables nat PREROUTING для интерфейса "
        f"{CYAN}{iface}{NC}, перенаправляющие DNS-трафик (UDP+TCP, порт 53) "
        f"на dnscrypt-proxy (порт {CYAN}{port}{NC})."
    )
    _box_sep()
    _box_warn("  ⚠ Это сделает невозможным использование кастомных DNS-серверов")
    _box_warn("    клиентами VPN — все DNS-запросы будут идти через dnscrypt-proxy.")
    _box_warn("  ⚠ Убедитесь что dnscrypt-proxy запущен и слушает порт.")
    _box_bottom()
    print()
    try:
        ans = input(f"  {YELLOW}Применить? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans != "y":
        return
    print()
    _info("Применяю правила...")
    result = apply_dns_redirect(iface, port)
    if result["success"]:
        _ok("DNS REDIRECT применён успешно!")
        if result["warnings"]:
            for w in result["warnings"]:
                _warn(w)
    else:
        _err(f"Не удалось применить: {result['skipped_reason']}")
        for w in result["warnings"]:
            _warn(w)
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_remove() -> None:
    """Отключение с подтверждением."""
    try:
        ans = input(f"  {YELLOW}Отключить DNS REDIRECT? [y/N]:{NC} ").strip().lower()
    except KeyboardInterrupt:
        return
    if ans != "y":
        return
    _info("Удаляю правила...")
    result = remove_dns_redirect()
    if result["success"]:
        _ok("DNS REDIRECT отключён, правила удалены")
    else:
        _err("Не удалось удалить некоторые правила — проверьте iptables -t nat -S")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


def _menu_change_iface() -> None:
    """Смена интерфейса."""
    state = state_load()
    cur = state.get("iface_filter", _DEFAULT_IFACE)
    print()
    _box_top("Смена интерфейса")
    _box_row(f"  Текущий: {CYAN}{cur}{NC}")
    _box_info("Обычные варианты: awg0 (AWG standalone/cascade), tun0, wg0")
    _box_info("Оставьте пустым для отмены.")
    _box_bottom()
    try:
        new = input(f"  Новый интерфейс: ").strip()
    except KeyboardInterrupt:
        return
    if not new:
        return
    state["iface_filter"] = new
    state_save(state)
    _ok(f"Интерфейс изменён на {new}")
    _info("Перепримените правила (пункт 1) для активации.")
    time.sleep(1)


def _menu_change_port() -> None:
    """Смена целевого порта."""
    state = state_load()
    auto = get_dnscrypt_port()
    cur = state.get("target_port", auto)
    print()
    _box_top("Смена целевого порта")
    _box_row(f"  Текущий:           {CYAN}{cur}{NC}")
    _box_row(f"  Auto-detected:     {CYAN}{auto}{NC} (из dnscrypt-proxy.toml)")
    _box_info("Оставьте пустым для auto-detect.")
    _box_bottom()
    try:
        new = input(f"  Новый порт [Enter=auto]: ").strip()
    except KeyboardInterrupt:
        return
    if not new:
        state["target_port"] = auto
    elif new.isdigit() and 1 <= int(new) <= 65535:
        state["target_port"] = int(new)
    else:
        _warn("Неверный порт")
        time.sleep(1)
        return
    state_save(state)
    _ok(f"Порт изменён на {state['target_port']}")
    time.sleep(1)


def _menu_show_rules() -> None:
    """Показывает текущие правила iptables nat PREROUTING."""
    os.system("clear")
    print()
    _box_top("🔍  Текущие правила iptables nat PREROUTING")
    _box_bottom()
    print()
    print(f"{BOLD}IPv4 (iptables):{NC}")
    _run(["iptables", "-t", "nat", "-S", "PREROUTING"])
    print()
    print(f"{BOLD}IPv6 (ip6tables):{NC}")
    _run(["ip6tables", "-t", "nat", "-S", "PREROUTING"])
    print()
    # Фильтр по нашему комментарию
    print(f"{BOLD}Только DNS REDIRECT правила:{NC}")
    for family in ("iptables", "ip6tables"):
        r = _run([family, "-t", "nat", "-S", "PREROUTING"], capture=True, check=False)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if _COMMENT in line:
                    print(f"  {CYAN}{family}{NC}: {line}")
    print()
    input(f"{BLUE}Нажмите Enter...{NC}")


def _menu_dig_test(iface: str, port: int) -> None:
    """Тестовый DNS-запрос через dnscrypt-proxy."""
    os.system("clear")
    print()
    _box_top("🧪  Тест DNS через dnscrypt-proxy")
    _box_desc(
        f"Отправляет тестовые DNS-запросы на 127.0.0.1:{port} и проверяет, "
        f"что dnscrypt-proxy отвечает. Для полноценной проверки редиректа "
        f"нужно с клиентского устройства сделать dig через VPN-туннель "
        f"с явным указанием стороннего DNS (например 8.8.8.8) — если "
        f"редирект работает, ответ придёт от dnscrypt-proxy (Cloudflare), "
        f"а не от Google."
    )
    _box_bottom()
    print()
    if not shutil.which("dig"):
        _warn("dig не установлен — установить: apt install dnsutils")
        input(f"{BLUE}Нажмите Enter...{NC}")
        return
    for domain in ("google.com", "cloudflare.com", "youtube.com"):
        try:
            r = subprocess.run(
                ["dig", "@127.0.0.1", f"-p{port}", domain,
                 "+time=3", "+tries=1", "+noall", "+answer"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                # Извлекаем IP из ответа
                lines = [l for l in r.stdout.splitlines() if domain in l]
                _ok(f"{domain:<22} → {lines[0].split()[-1] if lines else 'нет ответа'}")
            else:
                _warn(f"{domain:<22} нет ответа")
        except Exception as e:
            _err(f"{domain:<22} ошибка: {e}")
    print()
    _info("Для проверки редиректа с клиента:")
    _info("  dig @8.8.8.8 google.com  # должно прийти от Cloudflare, не Google")
    input(f"\n{BLUE}Нажмите Enter...{NC}")


# =============================================================================
#  Публичный экспорт
# =============================================================================
__all__ = [
    "do_manage_dns_redirect",
    "apply_dns_redirect",
    "remove_dns_redirect",
    "health_check_dns_redirect",
    "is_dnscrypt_active",
    "is_port_listening",
    "get_dnscrypt_port",
    "get_dnscrypt_listen_ipv6",
    "state_load",
    "state_save",
    # Константы (для тестов)
    "_DEFAULT_PORT",
    "_DEFAULT_IFACE",
    "_COMMENT",
    "_STATE_FILE",
    # Внутренние (для unit-тестов)
    "_ipt_rule_exists",
    "_ipt_add_rule_idempotent",
    "_ipt_delete_rule",
    "_build_redirect_rule_args",
    "_check_rules_applied",
    "_cleanup_all_dns_redirect_rules",
]
