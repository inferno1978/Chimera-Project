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
      listen, listen_port, version, users, handshake, detour

    ВАЖНО (v4.22.3): ShadowTLS v3 в sing-box НЕ поддерживает локальный TLS-сертификат
    на inbound — протокол проксирует TLS-handshake целиком на реальный внешний сервер
    (handshake.server), наблюдатель видит настоящий сертификат реального сайта.
    Поэтому поле "tls" здесь НЕ генерируется НИ ПРИ КАКИХ УСЛОВИЯХ.

    Поля cert_path/key_path в state_ib (если есть) игнорируются безусловно —
    они могли остаться от старых конфигов v4.22.0-v4.22.2, когда ShadowTLS
    ошибочно генерировал TLS-блок. Это backcompat-носитель, генератор их не читает.
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

    # НЕ добавляем "tls" — ShadowTLS проксирует handshake на внешний сервер,
    # локальный сертификат не нужен и не поддерживается схемой протокола.
    # cert_path/key_path в state_ib игнорируются (см. docstring выше).

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

    initial_packet_size (v4.22.4): общее поле из "QUIC Fields" применимо к
    TUIC (и Hysteria/Hysteria2). Регулирует размер начального QUIC-пакета —
    это единственный доступный рычаг против DPI, классифицирующего по длине
    initial-packet.

    ВАЖНО: obfs (salamander/gecko) в схеме sing-box существует ТОЛЬКО для
    Hysteria/Hysteria2-inbound. У TUIC такого поля НЕТ ВООБЩЕ — добавление
    "obfs" в TUIC-конфиг было бы мёртвым JSON-полем (класс ошибки v4.22.3
    с ShadowTLS TLS-блоком). initial_packet_size — НЕ полная замена обфускации,
    а частичный митигейт: меняет размер пакета, но не шифрует содержимое.
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

    # initial_packet_size — передаём в конфиг ТОЛЬКО если явно задано в state.
    # НЕ подставляем дефолт sing-box насильно — существующие установки не должны
    # менять поведение без явного действия пользователя.
    initial_packet_size = state_ib.get("initial_packet_size")
    if initial_packet_size is not None:
        # Принимаем int или строку — sing-box ожидает int, но строка тоже
        # парсится (например "1200"). Приводим к int для надёжности.
        try:
            inbound["initial_packet_size"] = int(initial_packet_size)
        except (ValueError, TypeError):
            pass  # некорректное значение — игнорируем, не ломаем генерацию

    return inbound


def _build_vless_ws_cdn_inbound(state_ib: dict) -> dict:
    """Строит VLESS-WS-CDN inbound (v4.23).

    VLESS+WebSocket за CDN (Cloudflare/Gcore/Bunny). CDN терминирует TLS своим
    сертификатом и форвардит plain WebSocket на origin (sing-box).

    state_ib fields:
      listen, listen_port, uuid, ws_path, host

    ВАЖНО (аналог регрессии v4.22.3 с ShadowTLS TLS-блоком): inbound НЕ содержит
    поля "tls" НИ ПРИ КАКИХ УСЛОВИЯХ. TLS живёт только на грани CDN — sing-box
    слушает plain WS. Добавление "tls" сюда было бы мёртвым JSON-полем.
    cert_path/key_path/cert_source в state (если есть от старых конфигов) —
    игнорируются безусловно.

    Архитектура:
      Клиент → TLS к CDN (CDN cert) → CDN форвардит plain WS → sing-box inbound
              ↓
              sing-box VLESS-inbound (type="vless", transport ws, NO tls{})
              ↓
              direct outbound → интернет
    """
    uuid_val = state_ib.get("uuid", "")
    ws_path = state_ib.get("ws_path", "/")
    host = state_ib.get("host", "")

    inbound = {
        "type":         "vless",
        "tag":          "vless-ws-cdn-in",
        "listen":       state_ib.get("listen", "0.0.0.0"),
        "listen_port":  state_ib.get("listen_port", 8443),
        "users":        [{"uuid": uuid_val}] if uuid_val else [],
        "transport": {
            "type":    "ws",
            "path":    ws_path,
        },
    }

    # Host header — только если задан (передаётся в ws-connection)
    if host:
        inbound["transport"]["headers"] = {"Host": host}

    # НЕ добавляем "tls" — CDN терминирует TLS, origin слушает plain WS.
    # cert_path/key_path в state_ib игнорируются (см. docstring выше).

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

    # VLESS-WS-CDN (v4.23)
    if inbounds_state.get("vless_ws_cdn", {}).get("enabled"):
        inbounds.append(_build_vless_ws_cdn_inbound(inbounds_state["vless_ws_cdn"]))

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
    # cert_path/key_path/cert_source НЕ принимаются — ShadowTLS v3 не поддерживает
    # локальный TLS-сертификат на inbound (см. _build_shadowtls_inbound docstring).
    # Параметры убраны в v4.22.3; вызовы, передающие их, получат TypeError
    # (намеренно — скрытый ignore привёл бы к тихому накоплению мусора в state).
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
    # cert_path/key_path/cert_source НЕ записываем в state для shadowtls —
    # протокол их не использует (см. _build_shadowtls_inbound). Старые поля,
    # оставшиеся от v4.22.0-v4.22.2, НЕ чистим принудительно (backcompat).

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


# ============================================================================
#  VLESS-WS-CDN enable/disable (v4.23)
# ============================================================================
def singbox_enable_vless_ws_cdn(
    cdn_provider: str = "cloudflare",
    host: str = "",
    ws_path: str = "",
    listen_port: int = 0,
    uuid_val: str = "",
) -> bool:
    """Включает VLESS-WS-CDN inbound.

    Args:
      cdn_provider: "cloudflare" | "gcore" | "bunny"
      host: real Host header (домен, проксируемый через CDN)
      ws_path: WS path (если пусто — генерируется случайный hex)
      listen_port: TCP-порт для прослушивания (default 8443 — DEFAULT_PORT_VLESS_WS_CDN)
      uuid_val: VLESS UUID клиента (если пусто — генерируется)

    ВАЖНО: cert_path/key_path/cert_source НЕ принимаются — CDN терминирует TLS,
    origin слушает plain WS. Это аналог fixed-логики shadowtls v4.22.3: поле не
    нужно — не принимаем (передача cert_path вызовет TypeError).
    """
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    from vless_installer.modules.singbox_common import CDN_PROVIDERS

    # Валидация cdn_provider
    if cdn_provider not in CDN_PROVIDERS:
        error(f"Неизвестный CDN-провайдер: {cdn_provider}")
        warn(f"Доступные: {', '.join(CDN_PROVIDERS.keys())}")
        return False

    state = singbox_state_load()
    ib = state.get("inbounds", {}).get("vless_ws_cdn", {})

    new_ib = dict(ib)
    new_ib["enabled"] = True
    new_ib["cdn_provider"] = cdn_provider
    if listen_port:
        new_ib["listen_port"] = listen_port
    if host:
        new_ib["host"] = host

    # ws_path: НЕ регенерируем молча при повторных enable/regen.
    # Только если явно передан или поле пустое.
    if ws_path:
        new_ib["ws_path"] = ws_path
    elif not new_ib.get("ws_path"):
        new_ib["ws_path"] = _gen_random_ws_path()

    # uuid: аналогично — не перегенерируем если уже есть.
    if uuid_val:
        new_ib["uuid"] = uuid_val
    elif not new_ib.get("uuid"):
        new_ib["uuid"] = _gen_vless_uuid()

    # cert_path/key_path/cert_source НЕ записываем — CDN терминирует TLS.
    # Старые поля (если остались от экспериментов) НЕ чистим принудительно (backcompat).

    singbox_state_update_inbound("vless_ws_cdn", **new_ib)
    return True


def singbox_disable_vless_ws_cdn() -> bool:
    from vless_installer.modules.singbox_state import singbox_state_update_inbound
    singbox_state_update_inbound("vless_ws_cdn", enabled=False)
    return True


# ── Генераторы случайных значений для VLESS-WS-CDN ───────────────────────────

def _gen_random_ws_path(length: int = 16) -> str:
    """Генерирует случайный WS path вида /a3f4b2c1d5e6f7a8 (hex)."""
    import secrets
    return "/" + secrets.token_hex(length // 2)


def _gen_vless_uuid() -> str:
    """Генерирует VLESS UUID v4."""
    import uuid as _uuid
    return str(_uuid.uuid4())
