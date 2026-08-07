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

def _xray_apply_warp_outbound():
    """Add WARP outbound + YouTube->WARP rule to Xray config."""
    core = _core_module()
    CONFIG_DIR = core.CONFIG_DIR
    _set_config_owner = core._set_config_owner
    _run = core._run
    info = core.info
    warn = core.warn

    warp_ip = _get_warp_ipv4()
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

            if not any(ob.get("tag") == "warp" for ob in outbounds):
                outbounds.append({
                    "protocol": "freedom",
                    "tag": "warp",
                    "settings": {
                        "domainStrategy": "UseIPv4",
                        "sendThrough": warp_ip,
                    },
                })
                info(f"Добавлен outbound 'warp' (sendThrough={warp_ip})")

            new_rule = {
                "type": "field",
                "domain": list(_YOUTUBE_DOMAINS),
                "outboundTag": "warp",
                "comment": _YOUTUBE_WARP_RULE_COMMENT,
            }
            routing["rules"] = [new_rule] + rules
            cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            _set_config_owner(cfg_path)
            info(f"Конфиг: {cfg_path} (YouTube->WARP sendThrough={warp_ip})")
            ok = True
        except Exception as e:
            warn(f"Ошибка патча {cfg_path}: {e}")

    if ok:
        _run(["systemctl", "restart", "xray"], check=False, quiet=True)
        core.success("YouTube->WARP применено в Xray")
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

def apply_youtube_warp_routing(enable: bool) -> tuple:
    """Enable or disable YouTube->WARP routing."""
    core = _core_module()

    if enable:
        if not _warp_iface_up():
            return False, ("WARP не установлен или интерфейс wg-warp не найден. "
                           "Сначала установите WARP: меню -> Cloudflare WARP")

        warp_ip = _get_warp_ipv4()
        core.info(f"WARP интерфейс: wg-warp, IPv4: {warp_ip}")

        try:
            _kernel_routes_apply()
            core.success("Kernel: table 301 -> wg-warp (source-based routing)")
        except Exception as e:
            return False, f"Ошибка kernel маршрутизации: {e}"

        _xray_apply_warp_outbound()
        _singbox_apply_warp_outbound()
        _install_persistence()

        # Remove conflicting youtube_via_ru rule
        try:
            from chimera.modules.youtube_route import _youtube_remove_from_xray
            _youtube_remove_from_xray()
        except Exception:
            pass

        return True, f"YouTube->WARP включён (sendThrough={warp_ip}, table 301)"
    else:
        _xray_remove_warp_outbound()
        _singbox_remove_warp_outbound()
        _kernel_routes_remove()
        _remove_persistence()
        return True, "YouTube->WARP отключён"


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
        _xray_apply_warp_outbound()
        _singbox_apply_warp_outbound()
        return True
    else:
        if not silent:
            try:
                core.info("Пере-применяем YouTube->WARP маршрутизацию...")
            except Exception:
                pass
        apply_youtube_warp_routing(True)
        return True
