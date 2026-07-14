"""
vless_installer/modules/linkqr_lib.py
───────────────────────────────────────────────────────────────────────────────
Общая библиотека генерации ссылок и QR-кодов для клиентов.

Эта библиотека — ЕДИНАЯ точка входа для построения ссылок/QR любого протокола
(VLESS/REALITY/xHTTP, AWG, Hysteria2, Mieru, NaiveProxy, sing-box variants,
FPTN, subscription-URL). Используется ОБИМИ ботами:
  • admin-ботом (vless_installer/modules/tg_bot.py)
  • клиентским self-service ботом (vless_installer/modules/tg_client_bot.py)

Принципы:
  • НИКОГДА не отдаёт приватные ключи / PSK / пароли в открытом виде в ссылках
    (ссылки строятся из публичных параметров: uuid, public_key, sni, port, ...).
  • Только чтение state-файлов — никаких writes.
  • Lazy binding к _core.py через importlib (как и в других извлечённых модулях).
  • QR-генерация: сначала qrencode CLI, fallback на python3-qrcode.

Публичное API:
    generate_qr_png(text, out_path) -> bool
    build_vless_link_for_user(user_uuid=None, state=None) -> str
    build_awg_link_for_user(email, awg_state=None) -> str
    build_mieru_link_for_user(email_or_name, mieru_state=None) -> str
    build_naive_link_for_user(email_or_name, naive_state=None) -> str
    build_singbox_links_for_user(uuid, singbox_state=None) -> list[tuple[str, str]]
    build_hysteria2_link(state=None) -> Optional[str]
    build_all_links_for_user(user_dict) -> dict[str, str]
    build_subscription_url_for_user(user_dict, sub_conf=None) -> Optional[str]
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from typing import Optional, List, Tuple, Dict


# ── Константы путей к state-файлам (читаются, не пишутся) ────────────────────
_MAIN_STATE_FILE     = Path("/var/lib/xray-installer/state.json")
_AWG_STATE_FILE      = Path("/var/lib/xray-installer/awg_standalone_state.json")
_SINGBOX_STATE_FILE  = Path("/var/lib/xray-installer/singbox_state.json")
_MIERU_STATE_FILE    = Path("/var/lib/xray-installer/mieru.json")
_NAIVE_STATE_FILE    = Path("/var/lib/xray-installer/naiveproxy.json")
_FPTN_STATE_FILE     = Path("/var/lib/xray-installer/fptn.json")
_TRUSTTUNNEL_STATE_FILE = Path("/var/lib/xray-installer/trusttunnel.json")
_SUB_CONF_FILE       = Path("/var/lib/xray-installer/subscription.json")
_USERS_FILE          = Path("/etc/xray/users.json")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py) — как в других извлечённых модулях
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core (lazy import)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ── Универсальные helpers чтения JSON ────────────────────────────────────────
def _read_json(path: Path) -> dict:
    """Безопасное чтение JSON-файла. Возвращает {} при любой ошибке."""
    try:
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _read_users() -> list:
    """Чтение /etc/xray/users.json. Возвращает [] при ошибке."""
    try:
        if _USERS_FILE.exists():
            data = json.loads(_USERS_FILE.read_text())
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def _find_user_by_uuid(uuid_str: str, users: Optional[list] = None) -> Optional[dict]:
    """Линейный поиск пользователя по UUID."""
    if users is None:
        users = _read_users()
    for u in users:
        if u.get("uuid", "") == uuid_str:
            return u
    return None


def _find_user_by_email(email: str, users: Optional[list] = None) -> Optional[dict]:
    """Линейный поиск пользователя по email."""
    if users is None:
        users = _read_users()
    for u in users:
        if u.get("email", "") == email:
            return u
    return None


# =============================================================================
#  QR-КОД — единая функция генерации PNG
# =============================================================================
def generate_qr_png(text: str, out_path: Path) -> bool:
    """
    Сохраняет QR-код (PNG) для строки `text` по пути `out_path`.

    Алгоритм:
      1. Пробует `qrencode -t PNG` (быстро, нет Python-зависимостей).
      2. Fallback на python3-qrcode (медленнее, но работает без qrencode).

    Возвращает True при успехе. Файл НЕ chmod'ится как 0o600 здесь —
    вызывающий код должен сам решать, нужны ли строгие права (например
    QR с приватным ключом AWG требует 0o600, а QR с публичной vless://
    ссылкой — нет).

    Для длинных строк (>800 символов, например vpn:// URI Amnezia) используется
    флаг -l L (низший уровень error correction) — иначе QR не помещается.
    """
    if not text:
        return False
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        return False

    # 1) qrencode CLI
    qrencode = shutil.which("qrencode")
    if qrencode:
        # -l L для длинных данных, -s 6 размер модуля, -m 4 margin
        ec_level = "L" if len(text) > 800 else "M"
        try:
            r = subprocess.run(
                [qrencode, "-t", "PNG", "-l", ec_level, "-s", "6", "-m", "4",
                 "-o", str(out_path)],
                input=text, capture_output=True, text=True, check=False,
            )
            if r.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0:
                return True
        except Exception:
            pass

    # 2) Fallback: python3-qrcode
    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L if len(text) > 800
                              else qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(str(out_path))
        return out_path.exists() and out_path.stat().st_size > 0
    except ImportError:
        return False
    except Exception:
        return False


# =============================================================================
#  VLESS / REALITY / xHTTP
# =============================================================================
def build_vless_link_for_user(user_uuid: Optional[str] = None,
                              state: Optional[dict] = None) -> str:
    """
    Строит vless:// ссылку для конкретного пользователя.

    Если user_uuid=None — использует primary UUID из state.json (для совместимости
    с admin-ботом, который раздаёт один общий конфиг).

    Поддерживает все режимы установки: A, B, B-Multi, REALITY, xHTTP.
    Возвращает "" если домен или UUID отсутствуют.

    Ссылка содержит ТОЛЬКО публичные параметры (public_key, short_id, sni, fp).
    Приватный ключ сервера НИКОГДА не попадает в ссылку.
    """
    if state is None:
        state = _read_json(_MAIN_STATE_FILE)

    domain       = state.get("domain", "")
    port         = state.get("server_port", 443)
    uuid_val     = user_uuid or state.get("uuid", "")
    proto        = state.get("protocol_mode", "reality")
    pub_key      = state.get("public_key", "")
    short_id     = state.get("short_id", "")
    fp           = state.get("fingerprint", "chrome") or "chrome"
    xtls_flow    = state.get("xtls_flow", "xtls-rprx-vision") or ""
    xhttp_path   = state.get("xhttp_path", "/")
    install_mode = state.get("install_mode", "A")
    awg_exit     = state.get("awg_exit_enabled", False)

    # SNI: для режима B с AWG-exit — берём из reality_dest, иначе domain
    sni = domain
    if proto == "reality" and awg_exit and install_mode == "B":
        sni = (state.get("reality_dest", domain) or domain).split(":")[0]

    if not domain or not uuid_val:
        return ""

    if proto == "xhttp":
        return (
            f"vless://{uuid_val}@{domain}:{port}"
            f"?type=xhttp&security=tls&path={xhttp_path}"
            f"&sni={sni}&fp={fp}#VLESS-xHTTP"
        )
    flow_part = f"&flow={xtls_flow}" if xtls_flow else ""
    return (
        f"vless://{uuid_val}@{domain}:{port}"
        f"?type=tcp&security=reality"
        f"&pbk={pub_key}&sid={short_id}&sni={sni}&fp={fp}"
        f"{flow_part}#VLESS-REALITY"
    )


# =============================================================================
#  AWG (AmneziaWG standalone)
# =============================================================================
def build_awg_link_for_user(email: str,
                            awg_state: Optional[dict] = None) -> str:
    """
    Строит vpn:// URI для пира AWG, привязанного к VLESS-пользователю по email.

    Возвращает "" если:
      • AWG не установлен
      • у пользователя нет пира (owner_email не сопоставлен)
      • пир истёк по TTL

    URI содержит приватный ключ клиента + PSK — это НЕБОЕВОЙ секрет для
    пользователя (его собственный ключ), поэтому отдаётся владельцу.
    СЕКРЕТ СЕРВЕРА (server_privkey) в URI НЕ попадает — только server_pubkey.
    """
    if awg_state is None:
        awg_state = _read_json(_AWG_STATE_FILE)
    if not awg_state.get("installed"):
        return ""

    # Ленивый импорт awg_qr чтобы не тянуть зависимости на старте
    try:
        from vless_installer.modules.awg_qr import awgs_qr_build_vpn_uri
        from vless_installer.modules.awg_state import awgs_state_find_peer_by_owner
    except Exception:
        return ""

    peer = awgs_state_find_peer_by_owner(email)
    if not peer:
        return ""

    # Проверка TTL пира
    expires_at = peer.get("expires_at", "")
    if expires_at:
        try:
            from vless_installer.modules.awg_expires import awgs_expires_is_expired
            if awgs_expires_is_expired(expires_at):
                return ""
        except Exception:
            pass

    try:
        return awgs_qr_build_vpn_uri(peer, awg_state)
    except Exception:
        return ""


# =============================================================================
#  Mieru
# =============================================================================
def build_mieru_link_for_user(email_or_name: str,
                              mieru_state: Optional[dict] = None) -> str:
    """
    Строит mierus:// ссылку (формат Karing) для пользователя Mieru.

    Mieru не привязан к VLESS-пользователям напрямую — сопоставление идёт
    по username = email.split('@')[0] (или по полному email_or_name).

    Возвращает "" если Mieru не установлен или пользователь не найден.
    """
    if mieru_state is None:
        mieru_state = _read_json(_MIERU_STATE_FILE)
    if not mieru_state.get("installed"):
        return ""

    # Извлекаем username: если передан email — берём часть до @
    username = (email_or_name or "").split("@")[0].strip()
    if not username:
        return ""

    users = mieru_state.get("users", [])
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return ""

    try:
        from vless_installer.modules.mieru import _gen_client_share_link
        return _gen_client_share_link(
            server_ip=mieru_state.get("_server_ip", "") or _get_public_ip(),
            port_start=mieru_state.get("port_start", 2012),
            port_end=mieru_state.get("port_end", 2022),
            protocol=mieru_state.get("protocol", "TCP"),
            username=user.get("username", ""),
            password=user.get("password", ""),
            traffic_preset=mieru_state.get("traffic_preset", "basic"),
        )
    except Exception:
        return ""


# =============================================================================
#  NaiveProxy
# =============================================================================
def build_naive_link_for_user(email_or_name: str,
                              naive_state: Optional[dict] = None) -> str:
    """
    Строит naive+https:// ссылку для пользователя NaiveProxy.

    Сопоставление: username = email.split('@')[0].
    Возвращает "" если NaiveProxy не установлен или пользователь не найден.
    """
    if naive_state is None:
        naive_state = _read_json(_NAIVE_STATE_FILE)
    if not naive_state.get("installed"):
        return ""

    username = (email_or_name or "").split("@")[0].strip()
    if not username:
        return ""

    users = naive_state.get("users", [])
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return ""

    try:
        from vless_installer.modules.naiveproxy import _build_naive_link
        return _build_naive_link(
            domain=naive_state.get("domain", ""),
            port=naive_state.get("port", 443),
            username=user.get("username", ""),
            password=user.get("password", ""),
            tag="NaiveProxy",
        )
    except Exception:
        return ""


# =============================================================================
#  Sing-box variants (ShadowTLS / AnyTLS / TUIC / VLESS-WS-CDN)
# =============================================================================
def build_singbox_links_for_user(uuid: str,
                                 singbox_state: Optional[dict] = None
                                 ) -> List[Tuple[str, str]]:
    """
    Строит список (protocol_name, link) для всех включённых sing-box inbound,
    в которых присутствует данный UUID пользователя.

    Возвращает [] если sing-box не установлен или UUID не найден ни в одном
    inbound. Возможные имена протоколов: shadowtls, anytls, tuic, trojan,
    vless_ws_cdn.
    """
    if singbox_state is None:
        singbox_state = _read_json(_SINGBOX_STATE_FILE)
    if not singbox_state.get("installed"):
        return []

    inbounds = singbox_state.get("inbounds", {})
    public_ip = _get_public_ip()
    result: List[Tuple[str, str]] = []

    try:
        from vless_installer.modules.singbox_menu import (
            _gen_shadowtls_client_uri,
            _gen_anytls_client_uri,
            _gen_tuic_client_uri,
            _gen_vless_ws_cdn_client_uri,
            _get_public_endpoint,
        )
    except Exception:
        return []

    for proto_name, ib in inbounds.items():
        if not ib.get("enabled"):
            continue
        users = ib.get("users", []) or []
        # TUIC / VLESS-WS-CDN могут использовать единый uuid на уровне inbound
        ib_uuid = ib.get("uuid", "")
        if ib_uuid:
            # Inbound с единым UUID — проверяем прямое совпадение
            user_match = (ib_uuid == uuid)
        else:
            user_match = any((u.get("uuid", "") == uuid for u in users))
        if not user_match:
            continue

        try:
            host, port, _loop = _get_public_endpoint(ib, public_ip)
            if proto_name == "shadowtls":
                # Найти password пользователя
                pwd = next((u.get("password", "") for u in users if u.get("uuid") == uuid), "")
                link = _gen_shadowtls_client_uri(ib, host or public_ip, port, pwd)
            elif proto_name == "anytls":
                pwd = next((u.get("password", "") for u in users if u.get("uuid") == uuid), "")
                link = _gen_anytls_client_uri(ib, host or public_ip, port, pwd)
            elif proto_name == "tuic":
                link = _gen_tuic_client_uri(ib, host or public_ip, port)
            elif proto_name == "vless_ws_cdn":
                link = _gen_vless_ws_cdn_client_uri(ib)
            elif proto_name == "trojan":
                pwd = next((u.get("password", "") for u in users if u.get("uuid") == uuid), "")
                # Trojan: trojan://pass@host:port?sni=...#tag
                # singbox_menu не имеет отдельного _gen_trojan_client_uri —
                # строим минимальную ссылку здесь
                sni = ib.get("handshake", {}).get("server", "") or host
                link = f"trojan://{pwd}@{host or public_ip}:{port}?sni={sni}#Trojan"
            else:
                continue
            if link:
                result.append((proto_name, link))
        except Exception:
            continue

    return result


# =============================================================================
#  Hysteria2 (общий пароль на exit-ноду — без per-user)
# =============================================================================
def build_hysteria2_link(state: Optional[dict] = None) -> Optional[str]:
    """
    Строит hysteria2:// ссылку для общего доступа.

    Hysteria2 в текущей архитектуре НЕ имеет per-user аккаунтов — один пароль
    на exit-ноду. Поэтому ссылка одинакова для всех. Бот может её показывать
    только если h2_exit_enabled=True и hysteria-сервер активен.
    """
    if state is None:
        state = _read_json(_MAIN_STATE_FILE)
    h2 = state.get("hysteria2", {})
    if not h2.get("enabled"):
        return None

    exit_nodes = h2.get("exit_nodes", []) or []
    active_node = next((n for n in exit_nodes if n.get("status") == "active"), None)
    if not active_node:
        return None

    host = h2.get("_active_node_ip") or active_node.get("ip", "")
    if not host:
        return None
    port = (active_node.get("ports", [443]) or [443])[0]
    password = active_node.get("auth", "")
    sni = state.get("domain", "") or host
    if not password:
        return None
    return f"hysteria2://{urllib.parse.quote(password, safe='')}@{host}:{port}?insecure=1&sni={sni}#Hysteria2"


# =============================================================================
#  Subscription URL (агрегатор всех протоколов одной ссылкой)
# =============================================================================
def build_subscription_url_for_user(user_dict: dict,
                                    sub_conf: Optional[dict] = None
                                    ) -> Optional[str]:
    """
    Строит HTTPS URL подписки вида https://{domain}:{port}/sub/{token}.

    Токен = HMAC-SHA256(pepper, uuid)[:24]. Subscription-сервер (модуль
    subscription.py) раздаёт base64-агрегат всех URI пользователя по этому URL.

    Возвращает None если:
      • subscription не настроен (нет pepper/port)
      • у пользователя нет UUID
      • нет domain
    """
    if sub_conf is None:
        sub_conf = _read_json(_SUB_CONF_FILE)
    pepper = sub_conf.get("pepper", "")
    if not pepper:
        return None
    uuid_str = (user_dict or {}).get("uuid", "")
    if not uuid_str:
        return None

    state = _read_json(_MAIN_STATE_FILE)
    domain = state.get("domain", "")
    if not domain:
        return None
    port = sub_conf.get("listen_port", sub_conf.get("port", 8443))

    try:
        from vless_installer.modules.subscription import _token_for
        token = _token_for(uuid_str, pepper)
    except Exception:
        # Резервный способ: HMAC-SHA256(pepper, uuid)[:24]
        import hmac
        import hashlib
        token = hmac.new(
            pepper.encode("utf-8"),
            uuid_str.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:24]

    return f"https://{domain}:{port}/sub/{token}"


# =============================================================================
#  Высокоуровневый агрегатор: все ссылки пользователя одним вызовом
# =============================================================================
def build_trusttunnel_link_for_user(user_dict: dict,
                                    state: Optional[dict] = None) -> str:
    """Build a tt://?<base64url> deep-link for a TrustTunnel user.

    Returns "" if TrustTunnel not installed or the user is not in
    credentials.toml. Uses the pure-Python TLV codec from
    trusttunnel.trusttunnel_deeplink_for_user (no subprocess spawn —
    safe for high-frequency bot /config and /qr requests).

    The URI contains the user's own username + password (deterministic
    SHA-256 of uuid), the server's hostname + address, and the upstream
    protocol. It does NOT contain the server's TLS private key — only
    public parameters. For Let's Encrypt certs (system-verifiable), the
    certificate field is omitted, keeping the URI compact.
    """
    if not user_dict:
        return ""
    email = user_dict.get("email", "")
    uuid_str = user_dict.get("uuid", "")
    if not email or not uuid_str:
        return ""
    try:
        from vless_installer.modules.trusttunnel import trusttunnel_deeplink_for_user
        return trusttunnel_deeplink_for_user(email, uuid_str, state=state)
    except Exception:
        return ""


def build_all_links_for_user(user_dict: dict) -> Dict[str, str]:
    """
    Строит dict всех активных ссылок пользователя:
      {"vless": "vless://...",
       "awg":   "vpn://...",
       "hysteria2": "hysteria2://...",
       "singbox_shadowtls": "trojan://...",
       "singbox_tuic": "tuic://...",
       "mieru": "mierus://...",
       "naive": "naive+https://...",
       "trusttunnel": "tt://?...",
       "subscription": "https://..."}

    Только активные протоколы (где пользователь реально присутствует).
    Пустые значения опускаются.

    НЕ включаем приватные ключи сервера, PSK — только то, что пользователь
    должен видеть для подключения.
    """
    if not user_dict:
        return {}

    uuid_str = user_dict.get("uuid", "")
    email    = user_dict.get("email", "")
    links: Dict[str, str] = {}

    # VLESS
    vless = build_vless_link_for_user(uuid_str)
    if vless:
        links["vless"] = vless

    # AWG
    if email:
        awg = build_awg_link_for_user(email)
        if awg:
            links["awg"] = awg

    # Sing-box
    if uuid_str:
        for proto, link in build_singbox_links_for_user(uuid_str):
            links[f"singbox_{proto}"] = link

    # Hysteria2 (общий, без per-user)
    h2 = build_hysteria2_link()
    if h2:
        links["hysteria2"] = h2

    # Mieru / NaiveProxy (сопоставление по username из email)
    if email:
        mieru = build_mieru_link_for_user(email)
        if mieru:
            links["mieru"] = mieru
        naive = build_naive_link_for_user(email)
        if naive:
            links["naive"] = naive

    # TrustTunnel (deep-link tt://?<base64url>)
    if email and uuid_str:
        tt = build_trusttunnel_link_for_user(user_dict)
        if tt:
            links["trusttunnel"] = tt

    # Subscription
    sub_url = build_subscription_url_for_user(user_dict)
    if sub_url:
        links["subscription"] = sub_url

    return links


# =============================================================================
#  Helpers
# =============================================================================
def _get_public_ip() -> str:
    """Возвращает публичный IPv4 сервера. Кешируется в _core.PARAM_PUBLIC_IP."""
    try:
        core = _core_module()
        # _core хранит публичный IP в глобальной переменной после детекта
        for attr in ("PARAM_PUBLIC_IP", "PUBLIC_IP", "SERVER_IP"):
            v = getattr(core, attr, "")
            if v:
                return str(v)
    except Exception:
        pass
    # Fallback: попробуем определить через curl
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", "5", "https://api.ipify.org"],
            capture_output=True, text=True, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return ""


# ── Псевдонимы для удобного импорта ──────────────────────────────────────────
__all__ = [
    "generate_qr_png",
    "build_vless_link_for_user",
    "build_awg_link_for_user",
    "build_mieru_link_for_user",
    "build_naive_link_for_user",
    "build_singbox_links_for_user",
    "build_hysteria2_link",
    "build_subscription_url_for_user",
    "build_trusttunnel_link_for_user",
    "build_all_links_for_user",
    "_read_json",
    "_read_users",
    "_find_user_by_uuid",
    "_find_user_by_email",
]
