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

def nginx_front_install(port: int = DEFAULT_NGINX_FRONT_PORT,
                        domain: "Optional[str]" = None,
                        backend_port: "Optional[int]" = None) -> "tuple[bool, str]":
    """Устанавливает nginx front с TLS для User Portal.

    Args:
      port: внешний порт nginx (default 9443).
      domain: домен для TLS-сертификата (default = PARAM_DOMAIN).
      backend_port: порт rest_api web_panel (default = из web_config.json или 8443).

    Returns:
      (success, message)
    """
    core = _core_module()
    info    = core.info
    success = core.success
    warn    = core.warn
    _run    = core._run
    log_to_file = core.log_to_file

    # 1. Валидация порта.
    ok, err = _validate_port(port)
    if not ok:
        return False, err

    # 2. Проверяем что nginx установлен.
    nginx_bin = core.find_nginx_bin()
    if not nginx_bin:
        return False, "nginx не установлен. Установите через основное меню."

    # 3. Определяем домен.
    if domain is None:
        domain = core.PARAM_DOMAIN
    if not domain:
        return False, ("PARAM_DOMAIN не задан. Сначала установите VLESS с доменом "
                       "— сертификат будет получен автоматически.")

    # 4. Ищем SSL-сертификат.
    cert_path, key_path = _find_ssl_cert(domain)
    if cert_path is None:
        # Пробуем получить через ssl_certbot.
        info(f"SSL-сертификат для {domain} не найден, получаем через certbot...")
        try:
            from chimera.modules.ssl_certbot import obtain_ssl_cert
            obtain_ssl_cert(domain)
            cert_path, key_path = _find_ssl_cert(domain)
        except Exception as e:
            return False, f"Не удалось получить SSL-сертификат: {e}"
    if cert_path is None or key_path is None:
        return False, f"SSL-сертификат для {domain} не найден и не получен"

    # 5. Определяем backend_port.
    if backend_port is None:
        try:
            from chimera.modules.rest_api import _web_config_load, DEFAULT_WEB_PORT
            backend_port = _web_config_load().get("port", DEFAULT_WEB_PORT)
        except Exception:
            backend_port = 8443

    # 6. Регистрируем порт в port_registry + проверка конфликтов.
    from chimera.modules.port_registry import (
        port_register, ufw_open_port, SERVICE_WEB_PANEL_NGINX,
    )
    ok, msg = port_register(SERVICE_WEB_PANEL_NGINX, port, "tcp",
                            comment=f"nginx front для User Portal (TLS, →127.0.0.1:{backend_port})")
    if not ok:
        return False, msg

    # 7. Генерируем vhost config.
    vhost = _generate_vhost(port, backend_port, cert_path, key_path, domain)
    try:
        NGINX_SITE_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
        NGINX_SITE_AVAILABLE.write_text(vhost)
    except Exception as e:
        return False, f"Не удалось записать vhost: {e}"

    # 8. Enable site (symlink).
    try:
        if NGINX_SITE_ENABLED.exists() or NGINX_SITE_ENABLED.is_symlink():
            NGINX_SITE_ENABLED.unlink()
        NGINX_SITE_ENABLED.symlink_to(NGINX_SITE_AVAILABLE)
    except Exception as e:
        return False, f"Не удалось enable site: {e}"

    # 9. nginx -t (проверка конфигурации).
    r = _run([nginx_bin, "-t"], capture=True, check=False)
    if r.returncode != 0:
        # Откат: удаляем vhost.
        try:
            NGINX_SITE_ENABLED.unlink(missing_ok=True)
            NGINX_SITE_AVAILABLE.unlink(missing_ok=True)
        except Exception:
            pass
        from chimera.modules.port_registry import port_unregister
        port_unregister(SERVICE_WEB_PANEL_NGINX, port, "tcp")
        return False, f"nginx -t failed: {r.stderr.strip()[:300]}"

    # 10. Reload nginx.
    r = _run(["systemctl", "reload", "nginx"], capture=True, check=False)
    if r.returncode != 0:
        # Откат.
        try:
            NGINX_SITE_ENABLED.unlink(missing_ok=True)
            NGINX_SITE_AVAILABLE.unlink(missing_ok=True)
        except Exception:
            pass
        from chimera.modules.port_registry import port_unregister
        port_unregister(SERVICE_WEB_PANEL_NGINX, port, "tcp")
        return False, f"nginx reload failed: {r.stderr.strip()[:300]}"

    # 11. UFW open (опционально — если UFW активен).
    if shutil.which("ufw"):
        ok, msg = ufw_open_port(port, "tcp", SERVICE_WEB_PANEL_NGINX,
                               comment="nginx front для User Portal (TLS)")
        if ok:
            info(f"UFW: {msg}")
        else:
            warn(f"UFW: {msg}")

    # 12. Сохраняем state.
    _state_save({
        "enabled":      True,
        "port":         port,
        "domain":       domain,
        "backend_port": backend_port,
        "cert_path":    str(cert_path),
        "key_path":     str(key_path),
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    })

    success(f"nginx front для User Portal установлен: https://{domain}:{port}")
    log_to_file("INFO", f"nginx_front_portal: installed port={port} domain={domain} backend=127.0.0.1:{backend_port}")
    return True, f"nginx front установлен на порту {port} (https://{domain}:{port})"


def nginx_front_remove() -> "tuple[bool, str]":
    """Удаляет nginx front для User Portal.

    Возвращает (success, message).
    Сертификат НЕ трогаем — он может использоваться VLESS/nginx основным сайтом.
    """
    core = _core_module()
    info    = core.info
    success = core.success
    warn    = core.warn
    _run    = core._run
    log_to_file = core.log_to_file

    state = _state_load()
    if not state.get("enabled"):
        return True, "nginx front не был установлен"

    port = state.get("port")

    # 1. Disable site (удаляем symlink).
    try:
        NGINX_SITE_ENABLED.unlink(missing_ok=True)
    except Exception as e:
        warn(f"Не удалось удалить symlink: {e}")

    # 2. Удаляем vhost config.
    try:
        NGINX_SITE_AVAILABLE.unlink(missing_ok=True)
    except Exception as e:
        warn(f"Не удалось удалить vhost: {e}")

    # 3. nginx -t + reload.
    nginx_bin = core.find_nginx_bin()
    if nginx_bin:
        r = _run([nginx_bin, "-t"], capture=True, check=False)
        if r.returncode == 0:
            _run(["systemctl", "reload", "nginx"], capture=True, check=False)
        else:
            warn(f"nginx -t failed after remove: {r.stderr.strip()[:200]}")

    # 4. UFW close.
    if port and shutil.which("ufw"):
        from chimera.modules.port_registry import (
            ufw_close_port, SERVICE_WEB_PANEL_NGINX,
        )
        ok, msg = ufw_close_port(port, "tcp", SERVICE_WEB_PANEL_NGINX)
        if ok:
            info(f"UFW: {msg}")

    # 5. Разрегистрируем порт.
    from chimera.modules.port_registry import port_unregister, SERVICE_WEB_PANEL_NGINX
    port_unregister(SERVICE_WEB_PANEL_NGINX)

    # 6. Сохраняем state.
    _state_save({"enabled": False, "port": 0, "domain": "",
                 "backend_port": 0, "installed_at": ""})

    success("nginx front для User Portal удалён")
    log_to_file("INFO", f"nginx_front_portal: removed (was port={port})")
    return True, "nginx front удалён"


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
                # Включить с default port.
                print()
                info(f"Устанавливаю nginx front на порту {DEFAULT_NGINX_FRONT_PORT}...")
                ok, msg = nginx_front_install(port=DEFAULT_NGINX_FRONT_PORT)
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
            # Если уже включён — сначала удаляем.
            if status["enabled"]:
                info("  Сначала удаляем старую конфигурацию...")
                nginx_front_remove()
            ok, msg = nginx_front_install(port=port)
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
