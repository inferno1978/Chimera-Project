"""
chimera/modules/nginx_front_portal.py
───────────────────────────────────────────────────────────────────────────────
nginx reverse-proxy с TLS для User Portal (rest_api.py).

Проблема:
  rest_api.py по умолчанию слушает на 127.0.0.1:8443 — доступ только через
  SSH-туннель. expose=True открывает 0.0.0.0:8443 без TLS — Basic Auth = base64,
  НЕ шифрование, креды видны любому снифферу.

Решение:
  nginx vhost с TLS на настраиваемом порту (default 9443), проксирует на
  127.0.0.1:<web_panel_port>. rest_api остаётся на loopback — НЕ открывается
  в UFW. UFW открывается ТОЛЬКО для nginx front port.

  TLS сертификат — переиспользуется существующий Let's Encrypt для PARAM_DOMAIN
  (если уже получен при установке VLESS). Если нет — certbot ставит новый.

  Lifecycle:
    install:  регистрируем порт → получаем сертификат → генерируем vhost →
              enable site → reload nginx → UFW open
    remove:   disable site → удаляем vhost → UFW close → разрегистрируем порт
              (сертификат НЕ трогаем — он может использоваться VLESS/nginx)

  Конфликт-детекшн через port_registry:
    перед установкой проверяем что порт свободен (registry + ss + UFW + /etc/services).
    если занят — отказываем с описанием конфликта.

Точка входа из TUI:
    from chimera.modules.nginx_front_portal import (
        nginx_front_install, nginx_front_remove, nginx_front_status,
        do_manage_nginx_front,
    )

Точка входа из rest_api.py install_web_service():
    nginx_front_install(port=9443)  # опционально
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


# ── Константы ────────────────────────────────────────────────────────────────
# Порт по умолчанию для nginx front. 9443 — выбран чтобы НЕ конфликтовать с:
#   - 443 (VLESS / nginx основной сайт)
#   - 8443 (rest_api web_panel, loopback)
#   - 51820 (AWG)
#   - 2012-2022 (Mieru)
# Если 9443 занят (например sing-box ShadowTLS) — пользователь может выбрать
# другой порт через TUI.
DEFAULT_NGINX_FRONT_PORT = 9443

# Файлы nginx vhost.
NGINX_SITE_NAME = "chimera-portal-nginx"
NGINX_SITE_AVAILABLE = Path("/etc/nginx/sites-available") / NGINX_SITE_NAME
NGINX_SITE_ENABLED = Path("/etc/nginx/sites-enabled") / NGINX_SITE_NAME

# Файл состояния — хранит выбранный порт, домен, время установки.
NGINX_FRONT_STATE_FILE = Path("/var/lib/xray-installer/nginx_front_portal.json")


# ── Чтение/запись state ──────────────────────────────────────────────────────

def _state_load() -> dict:
    if not NGINX_FRONT_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(NGINX_FRONT_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}


def _state_save(state: dict) -> None:
    NGINX_FRONT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    NGINX_FRONT_STATE_FILE.write_text(
        json.dumps(state, indent=2, ensure_ascii=False)
    )
    try:
        NGINX_FRONT_STATE_FILE.chmod(0o600)
    except Exception:
        pass


# ── Валидация порта ──────────────────────────────────────────────────────────

def _validate_port(port: int) -> "tuple[bool, str]":
    """Базовая валидация: 1-65535, не привилегированный если < 1024."""
    if not isinstance(port, int):
        return False, "Порт должен быть числом"
    if port < 1 or port > 65535:
        return False, f"Порт {port} вне диапазона 1-65535"
    if port < 1024:
        return False, (f"Привилегированный порт {port} (< 1024) — nginx может "
                       "не иметь прав. Используйте порт >= 1024.")
    # Зарезервированные порты Chimera.
    reserved = {
        443:   "VLESS / основной nginx сайт",
        80:    "HTTP / certbot ACME",
        22:    "SSH",
        8443:  "rest_api web_panel (loopback) — конфликт с backend",
    }
    if port in reserved:
        return False, f"Порт {port} зарезервирован для: {reserved[port]}"
    return True, ""


# ── Поиск SSL сертификата ────────────────────────────────────────────────────

def _find_ssl_cert(domain: "Optional[str]" = None) -> "tuple[Optional[Path], Optional[Path]]":
    """Ищет SSL-сертификат для domain (или PARAM_DOMAIN).

    Возвращает (cert_path, key_path) или (None, None) если не найден.
    Сертификат мог быть получен при установке VLESS (certbot) — лежит в
    /etc/letsencrypt/live/<domain>/{fullchain,privkey}.pem.
    """
    if domain is None:
        try:
            core = _core_module()
            domain = core.PARAM_DOMAIN
        except Exception:
            domain = ""
    if not domain:
        return None, None
    cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if cert.exists() and key.exists():
        return cert, key
    return None, None


# ── Генерация nginx vhost ────────────────────────────────────────────────────

def _generate_vhost(port: int, backend_port: int,
                    cert_path: Path, key_path: Path,
                    domain: str) -> str:
    """Генерирует nginx vhost config.

    listener <port> ssl → proxy_pass http://127.0.0.1:<backend_port>
    backend_port — это rest_api web_panel port (8443 по умолчанию).
    """
    return f"""# Chimera — nginx front для User Portal с TLS.
# Сгенерировано nginx_front_portal.py. НЕ редактировать вручную —
# изменения будут потеряны при следующем apply.
# Управление: TUI → Настройки сети → nginx front для User Portal.

# HTTP → HTTPS redirect (если пришёл на 80 — но мы слушаем отдельный порт,
# поэтому redirect не нужен; оставляем заглушку для будущего ACME).
server {{
    listen 80;
    server_name {domain};
    # Заглушка — реально трафик идёт на 443-порт основного сайта.
    # Этот блок нужен только если certbot захочет проверить домен через HTTP-01
    # на этом vhost. Но обычно сертификат уже получен для основного сайта.
    location /.well-known/acme-challenge/ {{
        root /var/www/{domain};
    }}
    location / {{
        return 404;
    }}
}}

# HTTPS — основной vhost для User Portal.
server {{
    listen {port} ssl http2;
    server_name {domain};

    # TLS — переиспользуем сертификат основного домена.
    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};

    # Современные шифры (Mozilla Intermediate 2024).
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS (2 года).
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Security headers.
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Логи.
    access_log /var/log/nginx/chimera-portal-nginx-access.log;
    error_log  /var/log/nginx/chimera-portal-nginx-error.log;

    # Проксирование на rest_api.py (loopback).
    location / {{
        proxy_pass http://127.0.0.1:{backend_port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # WebSocket support (для будущих live-обновлений портала).
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Таймауты — portal быстрые запросы, но Backup может быть долгим.
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Не буферизовать (для streaming downloads — clash/singbox configs).
        proxy_buffering off;
        proxy_request_buffering off;
    }}

    # ACME challenge — для certbot renewal через webroot.
    location /.well-known/acme-challenge/ {{
        root /var/www/{domain};
    }}
}}
"""


# ── Установка / удаление ─────────────────────────────────────────────────────

def _generate_self_signed_tls(public_ip: str) -> "tuple[Optional[Path], Optional[Path]]":
    """Генерирует self-signed TLS сертификат (как в olcRTC).

    Возвращает (cert_path, key_path) или (None, None) при ошибке.
    Сертификат сохраняется в /etc/olcrtc-manager/ (переиспользуем директорию).
    Нет — используем отдельную: /etc/nginx/ssl/chimera-portal-self-signed.{crt,key}
    """
    ssl_dir = Path("/etc/nginx/ssl")
    ssl_dir.mkdir(parents=True, exist_ok=True)
    cert = ssl_dir / "chimera-portal-self-signed.crt"
    key  = ssl_dir / "chimera-portal-self-signed.key"
    r = subprocess.run([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-sha256", "-days", "825",
        "-keyout", str(key),
        "-out", str(cert),
        "-subj", "/CN=chimera-portal",
        "-addext", f"subjectAltName=IP:{public_ip or '127.0.0.1'},DNS:localhost",
    ], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return None, None
    try:
        key.chmod(0o600)
        cert.chmod(0o644)
    except Exception:
        pass
    return cert, key


def nginx_front_install(port: int = DEFAULT_NGINX_FRONT_PORT,
                        domain: "Optional[str]" = None,
                        backend_port: "Optional[int]" = None,
                        use_self_signed: bool = False) -> "tuple[bool, str]":
    """Устанавливает nginx front с TLS для User Portal.

    Делегирует в chimera.modules.panel_nginx_front — единая точка логики
    для всех панелей Chimera (User Portal, Telemt Panel, будущие).

    Args:
      port: внешний порт nginx (default 9443).
      domain: домен для TLS-сертификата (default = PARAM_DOMAIN).
      backend_port: порт rest_api web_panel (default = из web_config.json или 8443).
      use_self_signed: если True — генерирует self-signed TLS (без домена).

    Returns:
      (success, message)
    """
    from chimera.modules.panel_nginx_front import panel_nginx_front_install
    from chimera.modules.port_registry import SERVICE_WEB_PANEL_NGINX

    # Определяем backend_port (порт rest_api web_panel).
    if backend_port is None:
        try:
            from chimera.modules.rest_api import _web_config_load, DEFAULT_WEB_PORT
            backend_port = _web_config_load().get("port", DEFAULT_WEB_PORT)
        except Exception:
            backend_port = 8443

    ok, msg = panel_nginx_front_install(
        service_tag=SERVICE_WEB_PANEL_NGINX,
        port=port,
        backend_port=backend_port,
        site_name=NGINX_SITE_NAME,
        state_file=NGINX_FRONT_STATE_FILE,
        title="User Portal",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,  # User Portal не требует CheckOrigin rewrite
        backend_http_scheme="http",
        cert_name_slug="chimera-portal",
    )

    # Дополнительно сохраняем расширенный state (для обратной совместимости
    # с существующим кодом, который читает backend_port, cert_path и т.д.)
    if ok:
        try:
            core = _core_module()
            state = {
                "enabled":      True,
                "port":         port,
                "domain":       domain or core.PARAM_DOMAIN,
                "backend_port": backend_port,
                "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }
            _state_save(state)
            core.log_to_file("INFO",
                f"nginx_front_portal: installed port={port} "
                f"domain={domain} backend=127.0.0.1:{backend_port}")
        except Exception:
            pass

    return ok, msg


def nginx_front_remove() -> "tuple[bool, str]":
    """Удаляет nginx front для User Portal.

    Делегирует в chimera.modules.panel_nginx_front — единая точка логики.

    Возвращает (success, message).
    Сертификат НЕ трогаем — он может использоваться VLESS/nginx основным сайтом.
    """
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove
    from chimera.modules.port_registry import SERVICE_WEB_PANEL_NGINX

    state = _state_load()
    if not state.get("enabled"):
        return True, "nginx front не был установлен"

    port = state.get("port")

    ok, msg = panel_nginx_front_remove(
        service_tag=SERVICE_WEB_PANEL_NGINX,
        site_name=NGINX_SITE_NAME,
        state_file=NGINX_FRONT_STATE_FILE,
        title="User Portal",
    )

    # Сохраняем расширенный state (для обратной совместимости с nginx_front_status).
    _state_save({"enabled": False, "port": 0, "domain": "",
                 "backend_port": 0, "installed_at": ""})

    try:
        core = _core_module()
        core.log_to_file("INFO", f"nginx_front_portal: removed (was port={port})")
    except Exception:
        pass

    return ok, msg


def nginx_front_status() -> dict:
    """Возвращает статус nginx front.

    Returns:
      {
        "enabled": bool,
        "port": int,
        "domain": str,
        "backend_port": int,
        "cert_path": str,
        "vhost_exists": bool,
        "vhost_enabled": bool,
        "nginx_active": bool,
      }
    """
    state = _state_load()
    return {
        "enabled":         state.get("enabled", False),
        "port":            state.get("port", 0),
        "domain":          state.get("domain", ""),
        "backend_port":    state.get("backend_port", 0),
        "cert_path":       state.get("cert_path", ""),
        "vhost_exists":    NGINX_SITE_AVAILABLE.exists(),
        "vhost_enabled":   NGINX_SITE_ENABLED.exists() or NGINX_SITE_ENABLED.is_symlink(),
        "nginx_active":    _is_nginx_active(),
    }


def _is_nginx_active() -> bool:
    """Проверяет, активен ли nginx (systemctl is-active)."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "nginx"],
            capture_output=True, text=True, check=False,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


# ── TUI ──────────────────────────────────────────────────────────────────────

def do_manage_nginx_front() -> None:
    """TUI-меню управления nginx front для User Portal."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_bottom = core._box_bottom
    _box_item   = core._box_item
    _box_info   = core._box_info
    _box_warn   = core._box_warn
    _box_back   = core._box_back
    CYAN   = core.CYAN
    NC     = core.NC
    GREEN  = core.GREEN
    YELLOW = core.YELLOW
    RED    = core.RED
    DIM    = core.DIM
    BLUE   = core.BLUE
    info    = core.info
    warn    = core.warn
    success = core.success

    while True:
        status = nginx_front_status()
        print()
        _box_top("🌐  nginx front для User Portal (TLS)")
        _box_row()
        if status["enabled"]:
            _box_row(f"  Статус: {GREEN}включён{NC}")
            _box_row(f"  URL: {CYAN}https://{status['domain']}:{status['port']}{NC}")
            _box_row(f"  Backend: {DIM}127.0.0.1:{status['backend_port']}{NC}")
            _box_row(f"  Сертификат: {DIM}{status['cert_path']}{NC}")
            _box_row(f"  nginx: {GREEN+'активен' if status['nginx_active'] else RED+'неактивен'}{NC}")
        else:
            _box_row(f"  Статус: {DIM}выключен{NC}")
            _box_row(f"  {DIM}nginx front ставит TLS перед User Portal.{NC}")
            _box_row(f"  {DIM}rest_api слушает 127.0.0.1:8443 (loopback, не открыт).{NC}")
            _box_row(f"  {DIM}nginx fronts на выбранном порту (default {DEFAULT_NGINX_FRONT_PORT}).{NC}")
        _box_sep()

        # Проверяем конфликты для default port (если выключен).
        if not status["enabled"]:
            from chimera.modules.port_registry import port_is_free
            is_free, descs = port_is_free(DEFAULT_NGINX_FRONT_PORT, "tcp",
                                          exclude_service="web_panel_nginx")
            if is_free:
                _box_row(f"  Порт по умолчанию {DEFAULT_NGINX_FRONT_PORT}: {GREEN}свободен{NC}")
            else:
                _box_row(f"  Порт по умолчанию {DEFAULT_NGINX_FRONT_PORT}: {YELLOW}занят{NC}")
                for d in descs[:2]:
                    _box_row(f"    {DIM}• {d}{NC}")
            _box_sep()

        if status["enabled"]:
            _box_item("1", f"{RED}Выключить nginx front{NC}")
            _box_item("2", "Изменить порт (переустановить)")
        else:
            _box_item("1", f"{GREEN}Включить nginx front (порт {DEFAULT_NGINX_FRONT_PORT}){NC}")
            _box_item("2", "Включить с другим портом")
        _box_item("3", "Проверить конфликты портов")
        _box_row()
        _box_row(f"  {DIM}User Portal после включения: https://<domain>:<port>/portal/{NC}")
        _box_row(f"  {DIM}Admin Panel:                  https://<domain>:<port>/admin/{NC}")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            return

        if ch == "q" or ch == "":
            return

        if ch == "1":
            if status["enabled"]:
                # Выключить.
                print()
                if _confirm("Выключить nginx front?", default=False):
                    ok, msg = nginx_front_remove()
                    if ok:
                        success(f"  {msg}")
                    else:
                        warn(f"  {msg}")
                    input(f"\n{BLUE}  Нажмите Enter...{NC}")
            else:
                # Включить с default port — спросить про сертификат.
                print()
                use_ss = _ask_self_signed(core)
                info(f"Устанавливаю nginx front на порту {DEFAULT_NGINX_FRONT_PORT}...")
                ok, msg = nginx_front_install(port=DEFAULT_NGINX_FRONT_PORT,
                                               use_self_signed=use_ss)
                if ok:
                    success(f"  {msg}")
                else:
                    warn(f"  {msg}")
                input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch == "2":
            # Изменить порт / включить с другим портом.
            print()
            try:
                port_str = input(f"{CYAN}  Порт (1-65535, Enter={DEFAULT_NGINX_FRONT_PORT}):{NC} ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not port_str:
                port = DEFAULT_NGINX_FRONT_PORT
            else:
                try:
                    port = int(port_str)
                except ValueError:
                    warn("  Некорректный порт")
                    input(f"\n{BLUE}  Нажмите Enter...{NC}")
                    continue
            # Спросить про сертификат.
            use_ss = _ask_self_signed(core)
            # Если уже включён — сначала удаляем.
            if status["enabled"]:
                info("  Сначала удаляем старую конфигурацию...")
                nginx_front_remove()
            ok, msg = nginx_front_install(port=port, use_self_signed=use_ss)
            if ok:
                success(f"  {msg}")
            else:
                warn(f"  {msg}")
            input(f"\n{BLUE}  Нажмите Enter...{NC}")

        elif ch == "3":
            print()
            from chimera.modules.port_registry import do_manage_port_registry
            do_manage_port_registry()


def _confirm(prompt: str, default: bool = False) -> bool:
    """Простой y/N prompt."""
    core = _core_module()
    CYAN = core.CYAN
    NC   = core.NC
    hint = "Y/n" if default else "y/N"
    try:
        ans = input(f"{CYAN}  {prompt} [{hint}]:{NC} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not ans:
        return default
    return ans in ("y", "yes", "д", "да")


def _ask_self_signed(core) -> bool:
    """Спрашивает пользователя: Let's Encrypt (домен) или self-signed (IP).

    Возвращает True если self-signed, False если Let's Encrypt.
    """
    CYAN = core.CYAN
    NC   = core.NC
    DIM  = core.DIM
    YELLOW = core.YELLOW
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item

    print()
    _box_top("🔒  TLS сертификат")
    _box_row()
    _box_row(f"  {DIM}Для доступа к User Portal/Admin Panel по HTTPS нужен TLS.{NC}")
    _box_sep()
    _box_item("1", f"Let's Encrypt {DIM}(нужен домен, доверенный сертификат){NC}")
    _box_item("2", f"Self-signed {DIM}(без домена, по IP — браузер предупредит){NC}")
    _box_bottom()
    try:
        ch = input(f"{CYAN}  Выбор [2 — self-signed]:{NC} ").strip() or "2"
    except (EOFError, KeyboardInterrupt):
        return True
    return ch == "2"
