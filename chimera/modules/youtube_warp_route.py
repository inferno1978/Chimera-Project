#!/usr/bin/env python3
"""
YouTube → WARP routing module for Chimera.
Implements domain-based routing of YouTube traffic through Cloudflare WARP
using Xray's `freedom` outbound with `sendThrough` (source IP binding).

Architecture (Option D):
  1. WARP must be installed and wg-warp interface up (warp.py).
  2. `ip rule add from <warp_ip> table 301` + `ip route add default dev wg-warp table 301`
     -> kernel routes any packet with source IP = warp_ip through wg-warp.
  3. Xray outbound: {"protocol":"freedom","tag":"warp","settings":{"sendThrough":"<warp_ip>"}}
  4. Xray routing rule: domain:[youtube.com,...] -> outboundTag:"warp"
  5. Xray calls freedom -> connect() with source IP = warp_ip -> kernel table 301 -> wg-warp -> Cloudflare -> YouTube.

For sing-box (Hysteria2/TUIC): same principle, using `bind_interface` instead of `sendThrough`.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Optional

# ── Constants ──────────────────────────────────────────────────────────────
_YOUTUBE_WARP_RULE_COMMENT = "youtube_via_warp"
_WARP_ROUTE_TABLE = 301
_WARP_RULE_PRIORITY = 151  # 1 above telemt-warp (150)

# YouTube domains — same list as youtube_route.py, kept in sync
_YOUTUBE_DOMAINS = [
    "domain:youtube.com",
    "domain:youtu.be",
    "domain:youtube-nocookie.com",
    "domain:youtubeeducation.com",
    "domain:youtubei.googleapis.com",
    "domain:ytimg.com",
    "domain:googlevideo.com",
    "domain:manifest.googlevideo.com",
    "domain:ggpht.com",
    "domain:youtube-googletag.com",
    "domain:accounts.google.com",
    "domain:apis.google.com",
]

# sing-box uses domain_suffix, not domain: prefix
_YOUTUBE_DOMAINS_SINGBOX = [
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubeeducation.com",
    "googleapis.com",
    "ytimg.com",
    "googlevideo.com",
    "ggpht.com",
    "youtube-googletag.com",
    "accounts.google.com",
    "apis.google.com",
]


def _core_module():
    """Lazy import of chimera._core to avoid circular imports."""
    import chimera._core as core
    return core


def _run(cmd, capture=False, quiet=False, check=False):
    """Wrapper for subprocess.run matching Chimera's _run signature."""
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    return r


# ── WARP Interface Helpers ─────────────────────────────────────────────────

def _get_warp_ipv4() -> str:
    """Get the IPv4 address of the wg-warp interface."""
    try:
        r = _run(["ip", "-4", "addr", "show", "wg-warp"], capture=True)
        if r.returncode == 0:
            m = re.search(r'inet\s+([\d.]+)', r.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    try:
        conf = Path("/etc/wireguard/wg-warp.conf").read_text()
        m = re.search(r'^Address\s*=\s*([\d.]+)', conf, re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "172.16.0.2"


def _get_warp_ipv6() -> str:
    """Get the IPv6 address of the wg-warp interface."""
    try:
        r = _run(["ip", "-6", "addr", "show", "wg-warp"], capture=True)
        if r.returncode == 0:
            m = re.search(r'inet6\s+([0-9a-fA-F:]+)', r.stdout)
            if m:
                ip = m.group(1)
                if not ip.startswith("fe80"):
                    return ip
    except Exception:
        pass
    try:
        conf = Path("/etc/wireguard/wg-warp.conf").read_text()
        m = re.search(r'^Address\s*=\s*[\d.]+/\d+,\s*([0-9a-fA-F:]+)', conf, re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _warp_iface_up() -> bool:
    """True if wg-warp interface exists."""
    r = _run(["ip", "link", "show", "wg-warp"])
    return r.returncode == 0


# ── Kernel Routing ─────────────────────────────────────────────────────────

def _kernel_routes_apply():
    """Add ip rule + ip route for source-based routing through wg-warp."""
    warp_ip = _get_warp_ipv4()

    r = _run(["ip", "rule", "show"], capture=True)
    rule_str = f"from {warp_ip} lookup {_WARP_ROUTE_TABLE}"
    if rule_str not in r.stdout and f"from {warp_ip} table {_WARP_ROUTE_TABLE}" not in r.stdout:
        _run(["ip", "rule", "add", "from", warp_ip, "table", str(_WARP_ROUTE_TABLE)], check=True)

    r = _run(["ip", "route", "show", "table", str(_WARP_ROUTE_TABLE)], capture=True)
    if "default" not in r.stdout or "wg-warp" not in r.stdout:
        _run(["ip", "route", "add", "default", "dev", "wg-warp", "table", str(_WARP_ROUTE_TABLE)], check=True)

    warp_ipv6 = _get_warp_ipv6()
    if warp_ipv6:
        r = _run(["ip", "-6", "rule", "show"], capture=True)
        rule6 = f"from {warp_ipv6} lookup {_WARP_ROUTE_TABLE}"
        if rule6 not in r.stdout:
            try:
                _run(["ip", "-6", "rule", "add", "from", warp_ipv6, "table", str(_WARP_ROUTE_TABLE)], check=True)
            except Exception:
                pass
        r = _run(["ip", "-6", "route", "show", "table", str(_WARP_ROUTE_TABLE)], capture=True)
        if "default" not in r.stdout or "wg-warp" not in r.stdout:
            try:
                _run(["ip", "-6", "route", "add", "default", "dev", "wg-warp", "table", str(_WARP_ROUTE_TABLE)], check=True)
            except Exception:
                pass


def _kernel_routes_remove():
    """Remove ip rule + ip route."""
    warp_ip = _get_warp_ipv4()
    _run(["ip", "rule", "del", "from", warp_ip, "table", str(_WARP_ROUTE_TABLE)])
    _run(["ip", "route", "del", "default", "dev", "wg-warp", "table", str(_WARP_ROUTE_TABLE)])

    warp_ipv6 = _get_warp_ipv6()
    if warp_ipv6:
        _run(["ip", "-6", "rule", "del", "from", warp_ipv6, "table", str(_WARP_ROUTE_TABLE)])
        _run(["ip", "-6", "route", "del", "default", "dev", "wg-warp", "table", str(_WARP_ROUTE_TABLE)])


# ── Xray Config ────────────────────────────────────────────────────────────

def _detect_warp_ip_version() -> tuple:
    """Определяет, какая IP-версия через WARP работает.

    Возвращает (version, debug_dict):
      version: "ipv4"/"ipv6"/"both"/"none"
      debug_dict: {"ipv4": str, "ipv6": str} — отладка для каждой проверки
    """
    v4, dbg4 = _warp_ipv4_connectivity()
    v6, dbg6 = _warp_ipv6_connectivity()
    if v4 and v6:
        ver = "both"
    elif v4:
        ver = "ipv4"
    elif v6:
        ver = "ipv6"
    else:
        ver = "none"
    return ver, {"ipv4": dbg4, "ipv6": dbg6}


def _xray_apply_warp_outbound(ip_version: str = "auto"):
    """Add WARP outbound + YouTube->WARP rule to Xray config.

    Args:
      ip_version: "auto" (default) — detect which IP version works through WARP
                  "ipv4"          — force IPv4 (sendThrough=warp_ipv4, UseIPv4)
                  "ipv6"          — force IPv6 (sendThrough=warp_ipv6, UseIPv6)
                  "both"          — try IPv4 first, fallback to IPv6 (UseIPv4v6)

    v5.0.3: при ip_version="auto" вызывает _detect_warp_ip_version() и
    выбирает стратегию. Если IPv4 не работает но IPv6 работает —
    использует IPv6 (sendThrough=warp_ipv6, domainStrategy=UseIPv6).
    Это решает проблему ТСПУ-блокировки IPv4 внутри WireGuard туннеля.
    """
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _set_config_owner = core._set_config_owner
    _run = core._run
    info = core.info
    warn = core.warn

    # Определяем стратегию IP-версии
    if ip_version == "auto":
        ip_version = _detect_warp_ip_version()
        info(f"Авто-определение: через WARP работает {ip_version}")

    warp_ipv4 = _get_warp_ipv4()
    warp_ipv6 = _get_warp_ipv6()

    # Выбираем sendThrough и domainStrategy на основе ip_version
    if ip_version == "ipv6":
        if not warp_ipv6:
            warn("IPv6 адрес WARP не найден — нельзя использовать IPv6 стратегию")
            return False
        send_through = warp_ipv6
        domain_strategy = "UseIPv6"
        strategy_desc = f"IPv6 (sendThrough={warp_ipv6}, UseIPv6)"
    elif ip_version == "both":
        if not warp_ipv4 and not warp_ipv6:
            warn("Нет ни IPv4, ни IPv6 адреса WARP")
            return False
        # UseIPv4v6: try IPv4 first, fallback IPv6. sendThrough должен
        # быть IPv4 (основной), IPv6 пакеты пойдут с IPv6-адреса интерфейса.
        send_through = warp_ipv4 or warp_ipv6
        domain_strategy = "UseIPv4v6"
        strategy_desc = f"IPv4+IPv6 (sendThrough={send_through}, UseIPv4v6)"
    else:
        # "ipv4" (default)
        if not warp_ipv4:
            warn("IPv4 адрес WARP не найден — нельзя использовать IPv4 стратегию")
            return False
        send_through = warp_ipv4
        domain_strategy = "UseIPv4"
        strategy_desc = f"IPv4 (sendThrough={warp_ipv4}, UseIPv4)"

    written = set()
    ok = False

    for cfg_path in (CONFIG_DIR / "config.json", Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.setdefault("routing", {})
            outbounds = cfg.setdefault("outbounds", [])

            rules = [r for r in routing.setdefault("rules", [])
                     if r.get("comment") not in (_YOUTUBE_WARP_RULE_COMMENT, "youtube_via_ru")]

            # Удаляем старый outbound warp (если есть) — перезаписываем с
            # актуальным sendThrough и domainStrategy.
            outbounds = [ob for ob in outbounds if ob.get("tag") != "warp"]
            outbounds.append({
                "protocol": "freedom",
                "tag": "warp",
                "settings": {
                    "domainStrategy": domain_strategy,
                    "sendThrough": send_through,
                },
            })
            cfg["outbounds"] = outbounds
            info(f"Outbound 'warp' настроен: {strategy_desc}")

            new_rule = {
                "type": "field",
                "domain": list(_YOUTUBE_DOMAINS),
                "outboundTag": "warp",
                "comment": _YOUTUBE_WARP_RULE_COMMENT,
            }
            routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info(f"Конфиг: {cfg_path} (YouTube->WARP, {strategy_desc})")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if ok:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        core.success(f"YouTube->WARP применено в Xray ({strategy_desc})")
    return ok


def _xray_remove_warp_outbound():
    """Remove WARP outbound + rule from Xray config."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _set_config_owner = core._set_config_owner
    _run = core._run

    written = set()
    for cfg_path in (CONFIG_DIR / "config.json", Path("/usr/local/etc/xray/config.json")):
        if not cfg_path.exists():
            continue
        try:
            real = str(cfg_path.resolve())
        except Exception:
            real = str(cfg_path)
        if real in written:
            continue
        written.add(real)
        try:
            cfg = json.loads(cfg_path.read_text())
            routing = cfg.setdefault("routing", {})
            routing["rules"] = [r for r in routing.setdefault("rules", [])
                                if r.get("comment") != _YOUTUBE_WARP_RULE_COMMENT]
            rules_ref_warp = any(r.get("outboundTag") == "warp" for r in routing.get("rules", []))
            if not rules_ref_warp:
                cfg["outbounds"] = [ob for ob in cfg.get("outbounds", []) if ob.get("tag") != "warp"]
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
        except Exception:
            pass
    _run(["systemctl", "restart", "xray"], check=False, quiet=True)


# ── sing-box Config ───────────────────────────────────────────────────────

def _singbox_apply_warp_outbound():
    """Add WARP outbound + YouTube->WARP rule to sing-box config."""
    core = _core_module()
    SINGBOX_CONFIG = Path("/etc/sing-box/config.json")
    if not SINGBOX_CONFIG.exists():
        return False

    try:
        cfg = json.loads(SINGBOX_CONFIG.read_text())
        outbounds = cfg.setdefault("outbounds", [])
        route = cfg.setdefault("route", {})
        rules = route.setdefault("rules", [])

        rules = [r for r in rules if r.get("comment") != _YOUTUBE_WARP_RULE_COMMENT]

        if not any(ob.get("tag") == "warp" for ob in outbounds):
            outbounds.append({"type": "direct", "tag": "warp", "bind_interface": "wg-warp"})

        new_rule = {
            "domain_suffix": list(_YOUTUBE_DOMAINS_SINGBOX),
            "outbound": "warp",
            "comment": _YOUTUBE_WARP_RULE_COMMENT,
        }
        route["rules"] = [new_rule] + rules

        SINGBOX_CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        SINGBOX_CONFIG.chmod(0o644)
        _run(["systemctl", "restart", "sing-box"], check=False, quiet=True)
        core.success("YouTube->WARP применено в sing-box (bind_interface=wg-warp)")
        return True
    except Exception as e:
        core.warn(f"Ошибка патча sing-box: {e}")
        return False


def _singbox_remove_warp_outbound():
    """Remove WARP outbound + rule from sing-box config."""
    SINGBOX_CONFIG = Path("/etc/sing-box/config.json")
    if not SINGBOX_CONFIG.exists():
        return
    try:
        cfg = json.loads(SINGBOX_CONFIG.read_text())
        route = cfg.setdefault("route", {})
        route["rules"] = [r for r in route.setdefault("rules", [])
                          if r.get("comment") != _YOUTUBE_WARP_RULE_COMMENT]
        rules_ref_warp = any(r.get("outbound") == "warp" for r in route.get("rules", []))
        if not rules_ref_warp:
            cfg["outbounds"] = [ob for ob in cfg.get("outbounds", []) if ob.get("tag") != "warp"]
        SINGBOX_CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        SINGBOX_CONFIG.chmod(0o644)
        _run(["systemctl", "restart", "sing-box"], check=False, quiet=True)
    except Exception:
        pass


# ── Persistence ────────────────────────────────────────────────────────────

_SYSTEMD_SERVICE = """[Unit]
Description=Restore YouTube->WARP kernel routes
After=network-online.target wg-quick@wg-warp.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -c "from chimera.modules.youtube_warp_route import restore_kernel_routes; restore_kernel_routes()"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""

_SERVICE_PATH = Path("/etc/systemd/system/youtube-warp-restore.service")


def _install_persistence():
    try:
        _SERVICE_PATH.write_text(_SYSTEMD_SERVICE)
        _run(["systemctl", "daemon-reload"], quiet=True)
        _run(["systemctl", "enable", "youtube-warp-restore.service"], quiet=True)
    except Exception:
        pass


def _remove_persistence():
    try:
        _run(["systemctl", "disable", "youtube-warp-restore.service"], quiet=True)
        _SERVICE_PATH.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], quiet=True)
    except Exception:
        pass


def restore_kernel_routes():
    """Called by systemd on boot. Only if state says warp mode."""
    try:
        core = _core_module()
        if not core.STATE_FILE.exists():
            return
        state = json.loads(core.STATE_FILE.read_text())
        if state.get("youtube_route_target") != "warp":
            return
    except Exception:
        return
    if not _warp_iface_up():
        return
    _kernel_routes_apply()


# ── Public API ─────────────────────────────────────────────────────────────

def apply_youtube_warp_routing(enable: bool, ip_version: str = "auto") -> tuple:
    """Enable or disable YouTube->WARP routing.

    Args:
      enable: True — включить, False — выключить.
      ip_version: "auto" — определить автоматически (по умолчанию)
                  "ipv4"  — принудительно IPv4
                  "ipv6"  — принудительно IPv6 (для ТСПУ-блокировки IPv4)
                  "both"  — IPv4+IPv6 (UseIPv4v6)
    """
    core = _core_module()

    if enable:
        if not _warp_iface_up():
            return False, ("WARP не установлен или интерфейс wg-warp не найден. "
                           "Сначала установите WARP: меню -> Cloudflare WARP")

        warp_ipv4 = _get_warp_ipv4()
        warp_ipv6 = _get_warp_ipv6()
        core.info(f"WARP интерфейс: wg-warp, IPv4: {warp_ipv4}, IPv6: {warp_ipv6}")

        try:
            _kernel_routes_apply()
            core.success("Kernel: table 301 -> wg-warp (source-based routing)")
        except Exception as e:
            return False, f"Ошибка kernel маршрутизации: {e}"

        # Передаём ip_version в _xray_apply_warp_outbound — оно выберет
        # правильный sendThrough и domainStrategy.
        _xray_apply_warp_outbound(ip_version=ip_version)
        _singbox_apply_warp_outbound()
        _install_persistence()

        # Remove conflicting youtube_via_ru rule
        try:
            from chimera.modules.youtube_route import _youtube_remove_from_xray
            _youtube_remove_from_xray()
        except Exception:
            pass

        # Описываем что применили
        if ip_version == "ipv6":
            desc = f"sendThrough={warp_ipv6} (IPv6), table 301"
        elif ip_version == "both":
            desc = f"sendThrough={warp_ipv4} (IPv4+IPv6), table 301"
        else:
            desc = f"sendThrough={warp_ipv4} (IPv4), table 301"
        return True, f"YouTube->WARP включён ({desc})"
    else:
        _xray_remove_warp_outbound()
        _singbox_remove_warp_outbound()
        _kernel_routes_remove()
        _remove_persistence()
        return True, "YouTube->WARP отключён"


# ── Interactive flow (auto-install / activate WARP) ───────────────────────
#
# v5.0.0 FIX: раньше нажатие [W] в меню YouTube при отсутствии WARP просто
# показывало warn и возвращало пользователя в основное меню. Это плохо для
# UX — пользователь не понимает что делать дальше. Теперь [W] автоматически
# предлагает установить/активировать WARP прямо здесь, не выходя из меню
# YouTube-маршрутизации.
#
# Сценарии:
#   1. WARP не установлен (нет /etc/wireguard/wg-warp.conf)
#      → Предлагаем запустить install wizard прямо здесь.
#      → После успешной установки автоматически применяем YouTube->WARP.
#
#   2. WARP установлен, но сервис остановлен (systemctl is-active != active)
#      → Предлагаем запустить сервис.
#      → После успешного старта применяем YouTube->WARP.
#
#   3. WARP установлен и активен, но интерфейс wg-warp почему-то не поднят
#      → Сообщаем об ошибке, предлагаем открыть полное меню WARP.
#
#   4. WARP полностью готов
#      → Просто применяем YouTube->WARP routing.
#
# Возвращает (ok: bool, message: str) — совместимо с apply_youtube_warp_routing.

def _warp_status_check() -> dict:
    """Возвращает статус WARP для интерактивного flow.

    Keys:
      installed: bool  — /etc/wireguard/wg-warp.conf существует
      service_active: bool — systemctl is-active wg-quick@wg-warp == active
      iface_up: bool — `ip link show wg-warp` успешен
    """
    out = {"installed": False, "service_active": False, "iface_up": False}
    try:
        out["installed"] = Path("/etc/wireguard/wg-warp.conf").exists()
    except Exception:
        pass
    try:
        r = _run(["systemctl", "is-active", "wg-quick@wg-warp"], capture=True, check=False)
        out["service_active"] = (r.stdout or "").strip() == "active"
    except Exception:
        pass
    out["iface_up"] = _warp_iface_up()
    return out


def _warp_connectivity_test(timeout: int = 10) -> tuple:
    """Проверяет связность через wg-warp используя plain curl (без -4/-6).

    v5.0.5: КРИТИЧНО — раньше проверяли IPv4 и IPv6 отдельно через
    curl -4 и curl -6. Но это даёт ложные негативы:
      - curl -4: ТСПУ дропает IPv4-пакеты внутри WireGuard -> timeout (rc=28)
      - curl -6: DNS может вернуть Cloudflare IPv6, который ТСПУ
        блокирует -> couldn't connect (rc=7). При этом plain curl с
        Happy Eyeballs пробует НЕСКОЛЬКО адресов и находит рабочий.

    ТЕПЕРЬ: запускаем plain `curl --interface wg-warp` (без -4/-6).
    Curl сам выберет работающий IP через Happy Eyeballs algorithm.
    Если получил ответ с warp=on — WARP работает. IP-версию
    определяем по формату ip= в ответе (IPv4 содержит точку, IPv6
    содержит двоеточие).

    Возвращает (ok: bool, ip_version: str, debug: str):
      ip_version: "ipv4"/"ipv6"/"unknown"
    """
    try:
        r = _run(
            ["curl", "--interface", "wg-warp",
             "--max-time", str(timeout), "-sS",
             "https://www.cloudflare.com/cdn-cgi/trace"],
            capture=True, check=False,
        )
        out = (r.stdout or "").strip()
        _err = (r.stderr or "").strip()[:300]
        debug = f"rc={r.returncode}, stdout_len={len(out)}, stderr={_err}"

        if r.returncode != 0 or not out:
            return False, "none", debug

        if "warp=" not in out and "ip=" not in out:
            return False, "none", debug + f" | unexpected output: {out[:100]}"

        # Определяем IP-версию из ответа
        ip_ver = "unknown"
        for line in out.splitlines():
            if line.startswith("ip="):
                ip_addr = line.split("=", 1)[1].strip()
                if ":" in ip_addr:
                    ip_ver = "ipv6"
                elif "." in ip_addr:
                    ip_ver = "ipv4"
                break

        return True, ip_ver, debug + f" | detected: {ip_ver}"
    except Exception as e:
        return False, "none", f"exception: {e}"


def _warp_ipv4_connectivity(timeout: int = 8) -> tuple:
    """Проверяет IPv4-связность через wg-warp. Возвращает (ok, debug).
    Используется только для отладки — основной тест в _warp_connectivity_test."""
    try:
        r = _run(
            ["curl", "-4", "--interface", "wg-warp",
             "--max-time", str(timeout), "-sS",
             "https://www.cloudflare.com/cdn-cgi/trace"],
            capture=True, check=False,
        )
        out = (r.stdout or "").strip()
        _err = (r.stderr or "").strip()[:200]
        debug = f"rc={r.returncode}, stdout_len={len(out)}, stderr={_err}"
        if r.returncode != 0 or not out:
            return False, debug
        return (("ip=" in out) or ("warp=" in out)), debug
    except Exception as e:
        return False, f"exception: {e}"


def _warp_ipv6_connectivity(timeout: int = 8) -> tuple:
    """Проверяет IPv6-связность через wg-warp. Возвращает (ok, debug).
    Используется только для отладки — основной тест в _warp_connectivity_test."""
    try:
        r = _run(
            ["curl", "-6", "--interface", "wg-warp",
             "--max-time", str(timeout), "-sS",
             "https://www.cloudflare.com/cdn-cgi/trace"],
            capture=True, check=False,
        )
        out = (r.stdout or "").strip()
        _err = (r.stderr or "").strip()[:200]
        debug = f"rc={r.returncode}, stdout_len={len(out)}, stderr={_err}"
        if r.returncode != 0 or not out:
            return False, debug
        return ("ip=" in out), debug
    except Exception as e:
        return False, f"exception: {e}"


def _detect_warp_ip_version() -> tuple:
    """Определяет, какая IP-версия через WARP работает.

    v5.0.5: использует plain curl (без -4/-6) как основной тест.
    Curl с Happy Eyeballs сам выбирает работающий IP. Если plain curl
    работает — парсим ip= из ответа для определения версии.

    Возвращает (version, debug_dict):
      version: "ipv4"/"ipv6"/"both"/"none"
      debug_dict: {"plain": str, "ipv4": str, "ipv6": str}
    """
    # Основной тест: plain curl (без -4/-6)
    ok, ver, dbg_plain = _warp_connectivity_test()

    # Дополнительная отладка: -4 и -6 отдельно (для диагностики)
    v4, dbg4 = _warp_ipv4_connectivity()
    v6, dbg6 = _warp_ipv6_connectivity()

    if not ok:
        return "none", {"plain": dbg_plain, "ipv4": dbg4, "ipv6": dbg6}

    # Plain curl работает — возвращаем определённую версию.
    if ver == "ipv6":
        return "ipv6", {"plain": dbg_plain, "ipv4": dbg4, "ipv6": dbg6}
    elif ver == "ipv4":
        if v6:
            return "both", {"plain": dbg_plain, "ipv4": dbg4, "ipv6": dbg6}
        return "ipv4", {"plain": dbg_plain, "ipv4": dbg4, "ipv6": dbg6}
    else:
        return "ipv4", {"plain": dbg_plain, "ipv4": dbg4, "ipv6": dbg6}


def _warp_allowed_ips_check() -> dict:
    """Парсит wg-warp.conf и проверяет AllowedIPs.

    Возвращает {ipv4: bool, ipv6: bool} — содержит ли AllowedIPs
    соответствующие диапазоны. Если AllowedIPs только ::/0 без
    0.0.0.0/0 — WireGuard будет дропать IPv4 пакеты, даже если
    маршрут в table 301 добавлен. Это типичная причина "WARP
    поднят, handshake есть, но IPv4 не работает".
    """
    out = {"ipv4": False, "ipv6": False, "raw": ""}
    try:
        conf = Path("/etc/wireguard/wg-warp.conf").read_text()
        out["raw"] = conf
        m = re.search(r'^AllowedIPs\s*=\s*(.+)$', conf, re.MULTILINE)
        if m:
            ips = m.group(1).strip()
            # 0.0.0.0/0 покрывает весь IPv4
            if "0.0.0.0/0" in ips:
                out["ipv4"] = True
            # ::/0 покрывает весь IPv6
            if "::/0" in ips:
                out["ipv6"] = True
    except Exception:
        pass
    return out


def do_youtube_warp_interactive(core) -> tuple:
    """Интерактивный flow включения YouTube->WARP с авто-установкой.

    Вызывается из меню YouTube-маршрутизации (youtube_route.py) при нажатии [W].
    Не требует предварительной установки WARP — предложит установить
    прямо здесь, без выхода в основное меню.

    Args:
      core: модуль chimera._core (передаётся извне для согласованности
            с остальным кодом youtube_route).

    Returns:
      (ok: bool, message: str) — совместимо с apply_youtube_warp_routing.
      ok=True только если YouTube->WARP реально применён.
    """
    info = core.info
    warn = core.warn
    success = core.success
    CYAN = core.CYAN
    YELLOW = core.YELLOW
    GREEN = core.GREEN
    RED = core.RED
    BLUE = core.BLUE
    NC = core.NC
    BOLD = core.BOLD
    DIM = core.DIM  # FIX: DIM использовался в print() ниже, но не был извлечён из core

    st = _warp_status_check()

    # ── Сценарий 1: WARP полностью готов ──────────────────────────────────
    if st["iface_up"]:
        # v5.0.3: перед применением правила проверяем, КАКАЯ IP-версия
        # через wg-warp реально работает. ТСПУ может дропать IPv4-пакеты
        # внутри WireGuard туннеля (DPI по заголовку), пропуская IPv6.
        # Handshake проходит (маленькие пакеты), IPv6 работает, IPv4 — нет.
        # Xray нужно настроить на работающую IP-версию.
        info("Проверка IP-связности через wg-warp (IPv4 + IPv6)...")
        ip_ver, dbg = _detect_warp_ip_version()

        if ip_ver == "none":
            # Ни IPv4, ни IPv6 через WARP не работают.
            print()
            warn("⚠ WARP поднят, но НИ IPv4, НИ IPv6 через wg-warp не работают.")
            print(f"{DIM}  Handshake может проходить, но данные не идут.{NC}")
            print()
            # v5.0.4: показываем отладку curl — чтобы понять ПОЧЕМУ падает.
            print(f"{YELLOW}  Отладка curl:{NC}")
            print(f"  {DIM}plain (auto): {dbg.get('plain', '?')}{NC}")
            print(f"  {DIM}IPv4 (-4):    {dbg.get('ipv4', '?')}{NC}")
            print(f"  {DIM}IPv6 (-6):    {dbg.get('ipv6', '?')}{NC}")
            print()
            allowed = _warp_allowed_ips_check()
            if not allowed["ipv4"] and not allowed["ipv6"]:
                print(f"{YELLOW}  Причина: AllowedIPs в wg-warp.conf некорректный{NC}")
                print(f"{DIM}  Должно быть: AllowedIPs = 0.0.0.0/0, ::/0{NC}")
            else:
                print(f"{YELLOW}  Возможные причины:{NC}")
                print(f"  {DIM}• ТСПУ блокирует WireGuard трафик (DPI){NC}")
                print(f"  {DIM}• Endpoint Cloudflare недоступен (попробуйте сменить){NC}")
                print(f"  {DIM}• Firewall блокирует исходящий трафик через wg-warp{NC}")
            print()
            print(f"{CYAN}  Откройте меню WARP → 6 (Изменить Endpoint) или 4 (диагностика){NC}")
            try:
                _ans = input(f"{CYAN}  Открыть полное меню WARP? [Y/n]:{NC} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _ans = "n"
            if _ans in ("", "y", "yes", "д", "да"):
                try:
                    from chimera.modules.warp import do_manage_warp
                    do_manage_warp()
                    # После выхода из меню перепроверяем.
                    new_ver, _ = _detect_warp_ip_version()
                    if new_ver != "none":
                        success(f"Через WARP заработал: {new_ver}")
                        return apply_youtube_warp_routing(True, ip_version=new_ver)
                except Exception as e:
                    warn(f"Ошибка: {e}")
            return (False, "Через WARP не работает ни IPv4, ни IPv6 — нужно починить WARP.")

        elif ip_ver == "ipv6":
            # IPv4 не работает, но IPv6 работает! Это типичная картина
            # ТСПУ-блокировки IPv4 в WireGuard. Предлагаем использовать IPv6.
            print()
            success("IPv6 через WARP РАБОТАЕТ (IPv4 заблокирован ТСПУ).")
            print(f"{DIM}  ТСПУ делает DPI на WireGuard и дропает IPv4-пакеты внутри{NC}")
            print(f"{DIM}  туннеля, пропуская IPv6. YouTube имеет полную IPv6-поддержку.{NC}")
            print()
            print(f"{CYAN}  Будем использовать IPv6 стратегию:{NC}")
            print(f"  {DIM}• sendThrough = <WARP IPv6 адрес>{NC}")
            print(f"  {DIM}• domainStrategy = UseIPv6{NC}")
            print(f"  {DIM}• Все YouTube-домены имеют IPv6 (youtube.com, googlevideo.com, ...){NC}")
            print()
            try:
                _ans = input(f"{CYAN}  Применить YouTube->WARP через IPv6? [Y/n]:{NC} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _ans = "n"
            if _ans in ("", "y", "yes", "д", "да"):
                return apply_youtube_warp_routing(True, ip_version="ipv6")
            return (False, "Пользователь отменил IPv6 стратегию.")

        elif ip_ver == "ipv4":
            # Только IPv4 работает (IPv6 не работает — например, сервер без IPv6).
            success("IPv4 через WARP работает (IPv6 недоступен на сервере).")
            info("Применяем YouTube->WARP маршрутизацию (IPv4)...")
            return apply_youtube_warp_routing(True, ip_version="ipv4")

        else:
            # both — IPv4 и IPv6 оба работают. Используем UseIPv4v6 (IPv4 first).
            success("IPv4 и IPv6 через WARP оба работают.")
            info("Применяем YouTube->WARP маршрутизацию (IPv4+IPv6)...")
            return apply_youtube_warp_routing(True, ip_version="both")

    # ── Сценарий 2: установлен, но сервис остановлен ──────────────────────
    if st["installed"] and not st["service_active"]:
        print()
        warn("WARP установлен, но сервис wg-quick@wg-warp остановлен.")
        try:
            _ans = input(f"{CYAN}  Запустить WARP сейчас? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            _ans = "n"
        if _ans in ("", "y", "yes", "д", "да"):
            r = _run(["systemctl", "start", "wg-quick@wg-warp"], capture=True, check=False)
            if r.returncode != 0:
                print(f"{RED}  Ошибка запуска:{NC} {(r.stderr or '').strip()[:200]}")
                return (False, "Не удалось запустить wg-quick@wg-warp — "
                               "откройте меню WARP для диагностики.")
            # Ждём подъёма интерфейса (до 5 сек).
            import time as _t
            for _ in range(10):
                if _warp_iface_up():
                    break
                _t.sleep(0.5)
            if not _warp_iface_up():
                return (False, "Сервис wg-quick@wg-warp запущен, но интерфейс "
                               "wg-warp не появился — проверьте конфиг.")
            success("WARP запущен.")
            return apply_youtube_warp_routing(True)
        else:
            return (False, "Пользователь отменил запуск WARP.")

    # ── Сценарий 3: WARP не установлен (или битая установка) ──────────────
    if not st["installed"]:
        print()
        print(f"{YELLOW}  ⚠ WARP не установлен.{NC}")
        print(f"{DIM}  YouTube->WARP требует установленный Cloudflare WARP (wg-warp).{NC}")
        print(f"{DIM}  Можно установить прямо сейчас — откроется мастер установки.{NC}")
        print()
        try:
            _ans = input(f"{CYAN}  Установить WARP сейчас? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            _ans = "n"
        if _ans not in ("", "y", "yes", "д", "да"):
            return (False, "WARP не установлен — установка отменена пользователем.")

        # Запускаем мастер установки WARP прямо здесь.
        try:
            from chimera.modules.warp import (
                _menu_install_wizard as _warp_wizard,
                _warp_service_active, _warp_is_installed,
            )
        except Exception as e:
            return (False, f"Не удалось импортировать модуль WARP: {e}")

        info("Запуск мастера установки WARP...")
        try:
            _warp_wizard()
        except KeyboardInterrupt:
            print()
            return (False, "Мастер WARP прерван пользователем.")
        except Exception as e:
            return (False, f"Ошибка в мастере WARP: {e}")

        # Проверяем результат.
        if not _warp_is_installed() or not _warp_service_active():
            # Мастер либо не завершился успешно, либо пользователь отменил.
            print()
            warn("WARP не установлен или не активен после мастера.")
            print(f"{DIM}  Возможно, мастер был отменён или упал. Откройте полное{NC}")
            print(f"{DIM}  меню WARP (Настройки сети → C → Cloudflare WARP) для диагностики.{NC}")
            try:
                _ans2 = input(f"{CYAN}  Открыть полное меню WARP? [Y/n]:{NC} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _ans2 = "n"
            if _ans2 in ("", "y", "yes", "д", "да"):
                try:
                    from chimera.modules.warp import do_manage_warp
                    do_manage_warp()
                except Exception as e:
                    warn(f"Ошибка открытия меню WARP: {e}")
                # Перепроверяем после выхода из меню.
                if not _warp_iface_up():
                    return (False, "WARP всё ещё не поднят — YouTube->WARP не применён.")
            else:
                return (False, "WARP не готов — YouTube->WARP не применён.")

        # WARP должен быть готов — применяем routing.
        if not _warp_iface_up():
            return (False, "WARP установлен, но интерфейс wg-warp не поднят — "
                           "проверьте: systemctl status wg-quick@wg-warp")
        success("WARP готов.")
        return apply_youtube_warp_routing(True)

    # ── Сценарий 4: установлен и сервис активен, но интерфейса нет ────────
    # (битая установка или упавший wg-quick)
    print()
    warn(f"WARP установлен и сервис помечен active, но интерфейс wg-warp "
         f"отсутствует. Это признак битой установки.")
    print(f"{DIM}  Откройте меню WARP для диагностики:{NC}")
    print(f"{DIM}  Настройки сети → C → Cloudflare WARP → 4 (Статус/диагностика){NC}")
    try:
        _ans = input(f"{CYAN}  Открыть полное меню WARP? [Y/n]:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        _ans = "n"
    if _ans in ("", "y", "yes", "д", "да"):
        try:
            from chimera.modules.warp import do_manage_warp
            do_manage_warp()
        except Exception as e:
            warn(f"Ошибка: {e}")
        if _warp_iface_up():
            return apply_youtube_warp_routing(True)
    return (False, "WARP не готов — YouTube->WARP не применён.")


def restore_if_needed(silent: bool = False) -> bool:
    """Re-apply after regenerate xray/singbox config."""
    try:
        core = _core_module()
        if not core.STATE_FILE.exists():
            return False
        state = json.loads(core.STATE_FILE.read_text())
        if state.get("youtube_route_target") != "warp":
            return False
    except Exception:
        return False

    if not _warp_iface_up():
        return False

    r = _run(["ip", "route", "show", "table", str(_WARP_ROUTE_TABLE)], capture=True)
    if "wg-warp" in r.stdout:
        if not silent:
            try:
                core.info("Пере-применяем YouTube->WARP правило после regenerate...")
            except Exception:
                pass
        # v5.0.3: используем auto-detection IP-версии — после regenerate
        # конфиг мог потерять актуальный sendThrough.
        _xray_apply_warp_outbound(ip_version="auto")
        _singbox_apply_warp_outbound()
        return True
    else:
        if not silent:
            try:
                core.info("Пере-применяем YouTube->WARP маршрутизацию...")
            except Exception:
                pass
        apply_youtube_warp_routing(True, ip_version="auto")
        return True
