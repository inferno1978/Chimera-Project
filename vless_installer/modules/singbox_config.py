"""
vless_installer/modules/singbox_config.py
───────────────────────────────────────────────────────────────────────────────
Генерация /etc/sing-box/config.json из state.

По образцу xray_install.py::generate_xray_config():
  • Python dict-литералы + json.dumps
  • Без Jinja2, без YAML
  • Читает singbox_state.json, собирает config.json

Архитектура config.json:
{
  "log": {...},
  "inbounds": [
    // ShadowTLS v3 — принимает TLS-handshake к маскировочному домену,
    // после handshake передаёт трафик на trojan-in через "detour"
    {
      "type": "shadowtls",
      "tag": "shadowtls-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "version": 3,
      "users": [{"password": "...", "name": "..."}],
      "handshake": {"server": "www.cloudflare.com", "server_port": 443},
      "detour": "trojan-in",
      "tls": {
        "certificate": ["/etc/letsencrypt/live/example.com/fullchain.pem"],
        "key": ["/etc/letsencrypt/live/example.com/privkey.pem"]
      }
    },
    // Trojan — внутренний inbound, слушает только на loopback (или вообще
    // ни на чём — sing-box направляет через detour). Принимает трафик от ShadowTLS.
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "127.0.0.1",
      "listen_port": 0,  // 0 = только через detour
      "users": [{"password": "...", "name": "..."}]
    },
    // AnyTLS — отдельный inbound, слушает на loopback:8444
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "127.0.0.1",
      "listen_port": 8444,
      "users": [{"password": "...", "name": "..."}],
      "tls": {
        "certificate": ["/etc/sing-box/certs/anytls.crt"],
        "key": ["/etc/sing-box/certs/anytls.key"]
      }
    },
    // TUIC v5 — QUIC, слушает на UDP:443 (параллельно с TCP:443)
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{"uuid": "...", "password": "..."}],
      "congestion_control": "bbr",
      "tls": {
        "certificate": ["/etc/sing-box/certs/tuic.crt"],
        "key": ["/etc/sing-box/certs/tuic.key"]
      }
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "final": "direct"
  }
}
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from vless_installer.modules.singbox_common import (
    RED, GREEN, YELLOW, CYAN, BLUE, BOLD, DIM, NC,
    info, success, warn, error, log_to_file,
    SINGBOX_CONFIG_FILE, SINGBOX_CONFIG_DIR,
)
from vless_installer.modules.singbox_state import (
    singbox_state_load, singbox_state_save, singbox_state_get_enabled_protocols,
)


# ============================================================================
#  Builders для каждого inbound-типа
# ============================================================================
def _build_shadowtls_inbound(state_ib: dict) -> dict:
    """Строит ShadowTLS inbound из state.

    state_ib fields:
      listen, listen_port, version, users, handshake, detour, cert_path, key_path
    """
    handshake = state_ib.get("handshake", {})
    users = state_ib.get("users", [])
    # ShadowTLS users format: [{"password": "...", "name": "..."}]
    sb_users = [{"password": u["password"], "name": u.get("name", u.get("uuid", "")[:8])}
                for u in users if u.get("password")]

    inbound = {
        "type":         "shadowtls",
        "tag":          "shadowtls-in",
        "listen":       state_ib.get("listen", "127.0.0.1"),
        "listen_port":  state_ib.get("listen_port", 8443),
        "version":      state_ib.get("version", 3),
        "users":        sb_users,
        "handshake": {
            "server":      handshake.get("server", "www.cloudflare.com"),
            "server_port": handshake.get("server_port", 443),
        },
        "detour":       state_ib.get("detour", "trojan-in"),
    }

    # TLS — только если есть сертификаты (LE для честного TLS-handshake)
    cert_path = state_ib.get("cert_path", "")
    key_path = state_ib.get("key_path", "")
    if cert_path and key_path and Path(cert_path).exists() and Path(key_path).exists():
        inbound["tls"] = {
            "certificate": [cert_path],
            "key":         [key_path],
        }

    return inbound


def _build_trojan_inbound(state_ib: dict) -> dict:
    """Строит Trojan inbound (внутренний, под ShadowTLS)."""
    users = state_ib.get("users", [])
    sb_users = [{"password": u["password"], "name": u.get("name", u.get("uuid", "")[:8])}
                for u in users if u.get("password")]

    return {
        "type":         "trojan",
        "tag":          "trojan-in",
        "listen":       state_ib.get("listen", "127.0.0.1"),
        "listen_port":  state_ib.get("listen_port", 0),  # 0 = только через detour
        "users":        sb_users,
    }


def _build_anytls_inbound(state_ib: dict) -> dict:
    """Строит AnyTLS inbound."""
    users = state_ib.get("users", [])
    sb_users = [{"password": u["password"], "name": u.get("name", u.get("uuid", "")[:8])}
                for u in users if u.get("password")]

    inbound = {
        "type":         "anytls",
        "tag":          "anytls-in",
        "listen":       state_ib.get("listen", "127.0.0.1"),
        "listen_port":  state_ib.get("listen_port", 8444),
        "users":        sb_users,
    }

    cert_path = state_ib.get("cert_path", "")
    key_path = state_ib.get("key_path", "")
    if cert_path and key_path and Path(cert_path).exists() and Path(key_path).exists():
        inbound["tls"] = {
            "certificate": [cert_path],
            "key":         [key_path],
        }

    return inbound


def _build_tuic_inbound(state_ib: dict) -> dict:
    """Строит TUIC v5 inbound.

    TUIC users format: [{"uuid": "...", "password": "..."}]
    """
    users = state_ib.get("users", [])
    sb_users = [{"uuid": u["uuid"], "password": u["password"]}
                for u in users if u.get("uuid") and u.get("password")]

    inbound = {
        "type":               "tuic",
        "tag":                 "tuic-in",
        "listen":              state_ib.get("listen", "::"),
        "listen_port":         state_ib.get("listen_port", 443),
        "users":               sb_users,
        "congestion_control":  state_ib.get("congestion_control", "bbr"),
        "auth_timeout":        "3s",
        "zero_rtt_handshake":  False,
        "heartbeat":           "10s",
    }

    cert_path = state_ib.get("cert_path", "")
    key_path = state_ib.get("key_path", "")
    if cert_path and key_path and Path(cert_path).exists() and Path(key_path).exists():
        inbound["tls"] = {
            "certificate": [cert_path],
            "key":         [key_path],
        }

    return inbound


# ============================================================================
#  Главная функция — генерация полного config.json
# ============================================================================
def singbox_generate_config() -> bool:
    """
    Читает singbox_state.json и генерирует /etc/sing-box/config.json.

    Returns:
      True при успехе, False при ошибке.
    """
    state = singbox_state_load()
    if not state.get("installed"):
        error("sing-box не установлен — нельзя генерировать конфиг")
        return False

    inbounds_state = state.get("inbounds", {})
    inbounds: list[dict] = []

    # ShadowTLS + Trojan (всегда парой)
    if inbounds_state.get("shadowtls", {}).get("enabled"):
        inbounds.append(_build_shadowtls_inbound(inbounds_state["shadowtls"]))
        if inbounds_state.get("trojan", {}).get("enabled"):
            inbounds.append(_build_trojan_inbound(inbounds_state["trojan"]))

    # AnyTLS
    if inbounds_state.get("anytls", {}).get("enabled"):
        inbounds.append(_build_anytls_inbound(inbounds_state["anytls"]))

    # TUIC
    if inbounds_state.get("tuic", {}).get("enabled"):
        inbounds.append(_build_tuic_inbound(inbounds_state["tuic"]))

    if not inbounds:
        warn("Нет включённых inbound'ов — конфиг будет пустым (только direct outbound)")

    config = {
        "log": {
            "level":     "info",
            "timestamp": True,
            "output":    str(SINGBOX_CONFIG_FILE.parent / "singbox.log"),
        },
        "inbounds": inbounds,
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block",  "tag": "block"},
        ],
        "route": {
            "final":     "direct",
            "auto_detect_interface": False,
        },
    }

    # Атомарная запись
    try:
        SINGBOX_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SINGBOX_CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False))
        tmp.replace(SINGBOX_CONFIG_FILE)
        # Права 0o644 — sing-box читает от имени root, но логи могут писать и юзеры
        SINGBOX_CONFIG_FILE.chmod(0o644)
    except Exception as e:
        error(f"Не удалось записать {SINGBOX_CONFIG_FILE}: {e}")
        return False

    # Обновляем last_applied в state
    from datetime import datetime, timezone
    state["last_applied"] = datetime.now(timezone.utc).isoformat()
    singbox_state_save(state)

    success(f"Конфиг sing-box сгенерирован: {len(inbounds)} inbound(s)")
    log_to_file("INFO", f"config.json generated with {len(inbounds)} inbounds")
    return True


# ============================================================================
#  Валидация конфига
# ============================================================================
def singbox_validate_config() -> bool:
    """Запускает sing-box check -c /etc/sing-box/config.json."""
    from vless_installer.modules.singbox_common import _singbox_binary_exists, _run, SINGBOX_BINARY
    if not _singbox_binary_exists():
        error("Бинарник sing-box не установлен")
        return False
    if not SINGBOX_CONFIG_FILE.exists():
        error(f"Конфиг не найден: {SINGBOX_CONFIG_FILE}")
        return False

    r = _run([str(SINGBOX_BINARY), "check", "-c", str(SINGBOX_CONFIG_FILE)],
             capture=True, quiet=True)
    if r.returncode != 0:
        error("Конфиг sing-box невалиден:")
        error((r.stdout + r.stderr)[:500])
        return False
    return True


# ============================================================================
#  Отдельная генерация для каждого протокола (для меню)
# ============================================================================
def singbox_enable_shadowtls(
    password: str = "",
    handshake_server: str = "",
    handshake_port: int = 0,
    listen_port: int = 0,
    cert_path: str = "",
    key_path: str = "",
    cert_source: str = "",
) -> bool:
    """Включает ShadowTLS v3 inbound."""
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    from vless_installer.modules.singbox_users import singbox_gen_password

    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("shadowtls", {})

    new_ib = dict(ib)
    new_ib["enabled"] = True
    new_ib["version"] = 3
    if listen_port:
        new_ib["listen_port"] = listen_port
    if handshake_server:
        new_ib.setdefault("handshake", {})["server"] = handshake_server
    if handshake_port:
        new_ib.setdefault("handshake", {})["server_port"] = handshake_port
    if cert_path:
        new_ib["cert_path"] = cert_path
    if key_path:
        new_ib["key_path"] = key_path
    if cert_source:
        new_ib["cert_source"] = cert_source

    # Если ещё нет пароля — генерируем
    if not new_ib.get("password"):
        new_ib["password"] = singbox_gen_password()

    # Список users берём из существующего (если есть) или генерируем пустой
    if not new_ib.get("users"):
        new_ib["users"] = []

    singbox_state_update_inbound("shadowtls", **new_ib)

    # Trojan-внутренний тоже включаем
    trojan_ib = state.get("inbounds", {}).get("trojan", {})
    trojan_ib["enabled"] = True
    if not trojan_ib.get("users"):
        trojan_ib["users"] = []
    trojan_ib["password"] = new_ib["password"]  # тот же пароль что у shadowtls
    singbox_state_update_inbound("trojan", **trojan_ib)

    return True


def singbox_disable_shadowtls() -> bool:
    """Выключает ShadowTLS (и Trojan)."""
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    singbox_state_update_inbound("shadowtls", enabled=False)
    singbox_state_update_inbound("trojan", enabled=False)
    return True


def singbox_enable_anytls(
    password: str = "",
    listen_port: int = 0,
    cert_path: str = "",
    key_path: str = "",
    cert_source: str = "",
) -> bool:
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    from vless_installer.modules.singbox_users import singbox_gen_password

    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("anytls", {})

    new_ib = dict(ib)
    new_ib["enabled"] = True
    if listen_port:
        new_ib["listen_port"] = listen_port
    if cert_path:
        new_ib["cert_path"] = cert_path
    if key_path:
        new_ib["key_path"] = key_path
    if cert_source:
        new_ib["cert_source"] = cert_source
    if not new_ib.get("password"):
        new_ib["password"] = singbox_gen_password()
    if not new_ib.get("users"):
        new_ib["users"] = []

    singbox_state_update_inbound("anytls", **new_ib)
    return True


def singbox_disable_anytls() -> bool:
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    singbox_state_update_inbound("anytls", enabled=False)
    return True


def singbox_enable_tuic(
    listen_port: int = 0,
    cert_path: str = "",
    key_path: str = "",
    cert_source: str = "",
) -> bool:
    from vless_installer.modules.singbox_state import singbox_state_update_inbound

    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("tuic", {})

    new_ib = dict(ib)
    new_ib["enabled"] = True
    if listen_port:
        new_ib["listen_port"] = listen_port
    if cert_path:
        new_ib["cert_path"] = cert_path
    if key_path:
        new_ib["key_path"] = key_path
    if cert_source:
        new_ib["cert_source"] = cert_source
    if not new_ib.get("users"):
        new_ib["users"] = []

    singbox_state_update_inbound("tuic", **new_ib)
    return True


def singbox_disable_tuic() -> bool:
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    singbox_state_update_inbound("tuic", enabled=False)
    return True
