"""
chimera/modules/singbox_state.py
───────────────────────────────────────────────────────────────────────────────
State management для sing-box backend.

Полностью автономный state-файл /var/lib/xray-installer/singbox_state.json
НЕ смешивается с основным state.json (который относится к VLESS-установке).

В основном state.json только регистрируется путь (singbox_state_file) —
аналогично awg_standalone_state.json.

Структура state:
{
  "installed": true,
  "version": "1.11.4",
  "installed_at": "2026-07-12T12:00:00Z",
  "binary_path": "/usr/local/bin/sing-box",
  "config_path": "/etc/sing-box/config.json",
  "inbounds": {
    "shadowtls": {
      "enabled": true,
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "version": 3,
      "password": "...",
      "handshake": {
        "server": "www.cloudflare.com",
        "server_port": 443
      },
      "detour": "trojan-in"
      // v4.22.3: cert_path/key_path/cert_source больше НЕ создаются для
      // shadowtls — протокол проксирует TLS-handshake на handshake.server,
      // локальный сертификат не нужен и не поддерживается схемой inbound.
      // Старые state-файлы с этими полями (созданные в v4.22.0-v4.22.2)
      // обратно совместимы — генератор их игнорирует безусловно.
    },
    "anytls": {
      "enabled": true,
      "listen": "127.0.0.1",
      "listen_port": 8444,
      "password": "...",
      "cert_source": "self-signed",
      "cert_path": "/etc/sing-box/certs/anytls.crt",
      "key_path":  "/etc/sing-box/certs/anytls.key",
      "cert_sha256": "abcdef..."
    },
    "tuic": {
      "enabled": true,
      "listen": "::",
      "listen_port": 443,            // UDP
      "users": [                     // UUID + пароль
        {"uuid": "...", "password": "..."}
      ],
      "congestion_control": "bbr",
      "cert_source": "self-signed",
      "cert_path": "/etc/sing-box/certs/tuic.crt",
      "key_path":  "/etc/sing-box/certs/tuic.key",
      "cert_sha256": "abcdef..."
    },
    "trojan": {
      "enabled": true,                // внутренний, под ShadowTLS
      "listen": "127.0.0.1",
      "listen_port": 0,               // sing-box внутренний pipe через detour
      "users": [{"password": "...", "name": "default"}]
    },
    "vless_ws_cdn": {                 // v4.23 — VLESS+WS за CDN (Cloudflare/Gcore/Bunny)
      "enabled": false,
      "listen": "0.0.0.0",            // bound externally — CDN подключается к этому порту
      "listen_port": 8443,            // DEFAULT_PORT_VLESS_WS_CDN — поддержан всеми 3 CDN
      "uuid": "...",                  // VLESS UUID клиента
      "ws_path": "/a3f4b2c1",         // случайный hex path, генерируется при enable
      "host": "vless.example.com",    // real Host header (домен через CDN)
      "cdn_provider": "cloudflare"    // "cloudflare" | "gcore" | "bunny"
      // cert_path/key_path/cert_source НЕ создаются — CDN терминирует TLS своим
      // cert, origin слушает plain WS. Это тот же принцип что в shadowtls v4.22.3:
      // поле не нужно — не создаём, не тащим мёртвые ключи в state.
    }
  },
  "sni_dispatch": {
    "enabled": false,
    "nginx_stream_conf": "/etc/nginx/streams-enabled/singbox-dispatch.conf",
    "shadowtls_sni": "shadowtls.example.com",
    "anytls_sni": "anytls.example.com",
    "default_backend": "unix:/dev/shm/vless-reality.socket"
  },
  "last_applied": "2026-07-12T12:00:00Z"
}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .singbox_common import (
    SINGBOX_STATE_FILE, SINGBOX_BINARY, SINGBOX_CONFIG_FILE,
    DEFAULT_PORT_SHADOWTLS, DEFAULT_PORT_ANYTLS, DEFAULT_PORT_TUIC,
    DEFAULT_PORT_TUIC_ALTERNATIVE,
    DEFAULT_PORT_VLESS_WS_CDN,
    DEFAULT_SHADOWTLS_HANDSHAKE_HOST, DEFAULT_SHADOWTLS_HANDSHAKE_PORT,
    register_singbox_in_main_state, unregister_singbox_from_main_state,
)


def _core_module():
    """Ленивый импорт _core (как во всех модулях проекта)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── State load/save ──────────────────────────────────────────────────────────

def singbox_state_load() -> dict:
    """Загружает state. Возвращает {} если файл не существует, corrupt или
    содержит не-dict (например JSON-массив или скаляр).

    ВАЖНО: возвращает dict ВСЕГДА. Если в файле лежит JSON-массив [1,2,3] или
    скаляр "string" — это невалидный state, возвращаем {} и логируем WARN
    с реальным типом (list/str/int/etc), не молчать.
    """
    try:
        if not SINGBOX_STATE_FILE.exists():
            return {}
        result = json.loads(SINGBOX_STATE_FILE.read_text())
        # Валидация типа — state обязан быть dict. JSON-массив/скаляр невалиден.
        if not isinstance(result, dict):
            actual_type = type(result).__name__
            try:
                core = _core_module()
                core.log_to_file(
                    "WARN",
                    f"singbox_state_load: state file contains {actual_type}, "
                    f"expected dict — treating as empty"
                )
            except Exception:
                pass
            return {}
        return result
    except Exception as e:
        try:
            core = _core_module()
            core.log_to_file("WARN", f"singbox_state_load: {e}")
        except Exception:
            pass
        return {}


def singbox_state_save(state: dict) -> bool:
    """Атомарно сохраняет state. Возвращает True при успехе.

    ВАЖНО: возвращает True даже если регистрация в main_state.json провалилась —
    сам singbox_state.json записан OK, это первичная цель. Но в лог уходит
    ERROR-запись о рассинхроне, чтобы админ видел проблему.
    """
    try:
        SINGBOX_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SINGBOX_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False))
        tmp.replace(SINGBOX_STATE_FILE)
        # Права 0600 — внутри state есть пароли и сертификаты
        SINGBOX_STATE_FILE.chmod(0o600)
        # Регистрируем в основном state.json
        register_ok = register_singbox_in_main_state()
        if not register_ok:
            # state сохранён, но регистрация в main state.json провалилась.
            # Не проглатываем молча — логируем ERROR явно.
            try:
                core = _core_module()
                core.log_to_file(
                    "ERROR",
                    "singbox_state_save: state сохранён, но регистрация в "
                    "main state.json провалилась — singbox_state_file не "
                    "зарегистрирован, возможен рассинхрон при diagnostic/backup"
                )
            except Exception:
                pass
        return True
    except Exception as e:
        try:
            core = _core_module()
            core.log_to_file("ERROR", f"singbox_state_save: {e}")
        except Exception:
            pass
        return False


def singbox_state_update(**kwargs: Any) -> dict:
    """Частичное обновление state (merge top-level keys). Возвращает обновлённый state."""
    state = singbox_state_load()
    state.update(kwargs)
    singbox_state_save(state)
    return state


def singbox_state_delete() -> bool:
    """Полностью удаляет state-файл (при uninstall)."""
    try:
        if SINGBOX_STATE_FILE.exists():
            SINGBOX_STATE_FILE.unlink()
        unregister_singbox_from_main_state()
        return True
    except Exception:
        return False


# ── State initialization ────────────────────────────────────────────────────

def singbox_state_init(version: str = "") -> dict:
    """Создаёт начальный state при первой установке бинарника.

    Все inbound'ы по умолчанию disabled — пользователь включает через меню.
    """
    state = {
        "installed":         True,
        "version":           version,
        "installed_at":      datetime.now(timezone.utc).isoformat(),
        "binary_path":       str(SINGBOX_BINARY),
        "config_path":       str(SINGBOX_CONFIG_FILE),
        "inbounds": {
            "shadowtls": {
                "enabled":      False,
                "listen":       "127.0.0.1",
                "listen_port":  DEFAULT_PORT_SHADOWTLS,
                "version":      3,
                "password":     "",
                "handshake": {
                    "server":      DEFAULT_SHADOWTLS_HANDSHAKE_HOST,
                    "server_port": DEFAULT_SHADOWTLS_HANDSHAKE_PORT,
                },
                "detour":       "trojan-in",
                # v4.22.3: cert_path/key_path/cert_source НЕ создаются для
                # shadowtls — протокол не поддерживает локальный TLS-сертификат
                # (см. _build_shadowtls_inbound docstring).
            },
            "anytls": {
                "enabled":      False,
                "listen":       "127.0.0.1",
                "listen_port":  DEFAULT_PORT_ANYTLS,
                "password":     "",
                "cert_source":  "",
                "cert_path":    "",
                "key_path":     "",
                "cert_sha256":  "",
            },
            "tuic": {
                "enabled":            False,
                "listen":             "::",
                "listen_port":        DEFAULT_PORT_TUIC_ALTERNATIVE,
                "users":              [],
                "congestion_control": "bbr",
                "cert_source":        "",
                "cert_path":          "",
                "key_path":           "",
                "cert_sha256":        "",
            },
            "trojan": {
                "enabled":      False,
                "listen":       "127.0.0.1",
                "listen_port":  0,
                "users":         [],
            },
            # v4.23 — VLESS-WS-CDN: VLESS+WebSocket за CDN (Cloudflare/Gcore/Bunny).
            # CDN терминирует TLS своим cert, origin (sing-box) слушает plain WS.
            # cert_path/key_path НЕ создаются — см. _build_vless_ws_cdn_inbound docstring.
            "vless_ws_cdn": {
                "enabled":      False,
                "listen":       "0.0.0.0",     # bound externally — CDN подключается
                "listen_port":  DEFAULT_PORT_VLESS_WS_CDN,
                "uuid":         "",            # генерируется при enable
                "ws_path":      "",            # генерируется при enable (случайный hex)
                "host":         "",            # real Host header (домен через CDN)
                "cdn_provider": "",            # "cloudflare" | "gcore" | "bunny"
            },
        },
        "sni_dispatch": {
            "enabled":            False,
            "nginx_stream_conf":  "/etc/nginx/streams-enabled/singbox-dispatch.conf",
            "shadowtls_sni":      "",
            "anytls_sni":         "",
            "default_backend":    "",
        },
        "last_applied": "",
    }
    singbox_state_save(state)
    return state


# ── Inbound management ──────────────────────────────────────────────────────

def singbox_state_get_inbound(protocol: str) -> dict:
    """Возвращает подсекцию inbound'а по имени протокола."""
    state = singbox_state_load()
    return state.get("inbounds", {}).get(protocol, {})


def singbox_state_set_inbound(protocol: str, inbound: dict) -> bool:
    """Полностью заменяет подсекцию inbound'а."""
    state = singbox_state_load()
    inbounds = state.setdefault("inbounds", {})
    inbounds[protocol] = inbound
    return singbox_state_save(state)


def singbox_state_update_inbound(protocol: str, **fields) -> bool:
    """Частичное обновление inbound'а (merge)."""
    state = singbox_state_load()
    inbounds = state.setdefault("inbounds", {})
    ib = inbounds.setdefault(protocol, {})
    ib.update(fields)
    return singbox_state_save(state)


def singbox_state_is_protocol_enabled(protocol: str) -> bool:
    return bool(singbox_state_get_inbound(protocol).get("enabled", False))


def singbox_state_get_enabled_protocols() -> list[str]:
    """Возвращает список включённых протоколов."""
    state = singbox_state_load()
    inbounds = state.get("inbounds", {})
    return [p for p, ib in inbounds.items() if ib.get("enabled", False)]


# ── SNI-dispatch ────────────────────────────────────────────────────────────

def singbox_state_get_sni_dispatch() -> dict:
    return singbox_state_load().get("sni_dispatch", {})


def singbox_state_set_sni_dispatch(sni_state: dict) -> bool:
    state = singbox_state_load()
    state["sni_dispatch"] = sni_state
    return singbox_state_save(state)


def singbox_state_update_sni_dispatch(**fields) -> bool:
    state = singbox_state_load()
    sd = state.setdefault("sni_dispatch", {})
    sd.update(fields)
    return singbox_state_save(state)


# ── Helpers ──────────────────────────────────────────────────────────────────

def singbox_state_is_installed() -> bool:
    """Была ли установка sing-box."""
    return bool(singbox_state_load().get("installed", False))


def singbox_state_get_version() -> str:
    return singbox_state_load().get("version", "")


def singbox_state_get_binary_path() -> str:
    return singbox_state_load().get("binary_path", str(SINGBOX_BINARY))


def singbox_state_get_config_path() -> str:
    return singbox_state_load().get("config_path", str(SINGBOX_CONFIG_FILE))
