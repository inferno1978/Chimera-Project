"""
chimera/modules/panel_nginx_front.py
───────────────────────────────────────────────────────────────────────────────
Универсальный helper для установки nginx front с TLS для любых панелей Chimera.

Поддерживает 2 режима TLS:
  1. Let's Encrypt — для домена (PARAM_DOMAIN или свой)
  2. Self-signed — для доступа по IP (когда домена нет)

Используется:
  - chimera.modules.nginx_front_portal (User Portal / rest_api)
  - chimera.modules.telemt_panel (_telemt_setup_direct_access)
  - Любой будущей панелью, которой нужен nginx front с TLS

Все порты регистрируются через port_registry с проверкой конфликтов
(registry + system + ufw). Это гарантирует, что две панели не займут
один и тот же порт.

API:
  panel_nginx_front_install(
      service_tag: str,           # из port_registry (SERVICE_*)
      port: int,                  # внешний порт nginx (TLS)
      backend_port: int,          # порт backend-сервиса на 127.0.0.1
      site_name: str,             # имя nginx vhost (sites-enabled/<name>)
      state_file: Path,           # JSON-файл состояния (для toggle/status)
      title: str = "Panel",       # для логов/сообщений
      use_self_signed: bool = False,
      domain: Optional[str] = None,
      websocket_origin_rewrite: bool = False,
      backend_http_scheme: str = "http",  # http or https backend
  ) -> tuple[bool, str]

  panel_nginx_front_remove(
      service_tag: str,
      site_name: str,
      state_file: Path,
  ) -> tuple[bool, str]

  ask_tls_mode() -> bool  # True = self-signed, False = Let's Encrypt
  ask_domain(default: Optional[str] = None) -> Optional[str]
  check_port_via_registry(port: int, service_tag: str) -> tuple[bool, list[str]]
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════

NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_SITES_ENABLED  = Path("/etc/nginx/sites-enabled")
NGINX_SSL_DIR        = Path("/etc/nginx/ssl")


# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════

def _core_module():
    """Lazy import chimera._core для избежания циклической зависимости."""
    from chimera import _core
    return _core


def _find_ssl_cert(domain: str) -> "tuple[Optional[Path], Optional[Path]]":
    """Ищет SSL-сертификат Let's Encrypt для домена.

    Возвращает (cert_path, key_path) или (None, None).
    """
    if not domain:
        return None, None
    cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if cert.exists() and key.exists():
        return cert, key
    return None, None


def _generate_self_signed_tls(public_ip: str,
                               cert_name: str = "panel"
                               ) -> "tuple[Optional[Path], Optional[Path]]":
    """Генерирует self-signed TLS сертификат.

    Args:
      public_ip: публичный IP для subjectAltName (или '127.0.0.1').
      cert_name: имя файла (без расширения) — например 'telemt-panel'.

    Returns:
      (cert_path, key_path) или (None, None) при ошибке.
    """
    NGINX_SSL_DIR.mkdir(parents=True, exist_ok=True)
    cert = NGINX_SSL_DIR / f"{cert_name}-self-signed.crt"
    key  = NGINX_SSL_DIR / f"{cert_name}-self-signed.key"
    r = subprocess.run([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-sha256", "-days", "825",
        "-keyout", str(key), "-out", str(cert),
        "-subj", f"/CN={cert_name}",
        "-addext", f"subjectAltName=IP:{public_ip or '127.0.0.1'},DNS:localhost",
    ], capture_output=True, check=False)
    if r.returncode != 0:
        return None, None
    try:
        key.chmod(0o600)
        cert.chmod(0o644)
    except Exception:
        pass
    return cert, key


# ══════════════════════════════════════════════════════════════════════════════
#  PORT REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

def check_port_via_registry(port: int, service_tag: str) -> "tuple[bool, list[str]]":
    """Проверяет порт через port_registry (registry + system + ufw).

    Returns:
      (is_free, conflict_descriptions)
    """
    try:
        from chimera.modules.port_registry import port_is_free
        return port_is_free(port, "tcp", exclude_service=service_tag)
    except Exception:
        # port_registry недоступен — не блокируем.
        return True, []


def _register_port(service_tag: str, port: int, comment: str) -> None:
    """Регистрирует порт в port_registry (с проверкой конфликтов)."""
    try:
        from chimera.modules.port_registry import port_register
        port_register(service_tag, port, "tcp", comment=comment)
    except Exception:
        pass


def _unregister_port(service_tag: str, port: int) -> None:
    """Снимает регистрацию порта."""
    try:
        from chimera.modules.port_registry import port_unregister
        port_unregister(service_tag, port=port, proto="tcp")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  UI: ВЫБОР TLS-РЕЖИМА И ДОМЕНА
# ══════════════════════════════════════════════════════════════════════════════

def ask_tls_mode(panel_name: str = "панель") -> "tuple[bool, Optional[str]]":
    """Спрашивает пользователя: Let's Encrypt (домен) или self-signed (IP).

    Returns:
      (use_self_signed, domain_hint)
      - use_self_signed=True → self-signed режим
      - use_self_signed=False → Let's Encrypt, domain_hint=None (спросим отдельно)
    """
    core = _core_module()
    CYAN, NC, DIM, YELLOW = core.CYAN, core.NC, core.DIM, core.YELLOW
    _box_top, _box_row, _box_sep, _box_bottom, _box_item = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom, core._box_item
    )

    # Подсказка: есть ли PARAM_DOMAIN?
    param_domain = getattr(core, "PARAM_DOMAIN", "") or ""

    print()
    _box_top(f"🔒  TLS сертификат для {panel_name}")
    _box_row()
    _box_row(f"  {DIM}Для доступа по HTTPS нужен TLS сертификат.{NC}")
    if param_domain:
        _box_row(f"  {DIM}Текущий домен сервера: {YELLOW}{param_domain}{NC}")
    _box_sep()
    _box_item("1", f"Let's Encrypt {DIM}(нужен домен, доверенный сертификат){NC}")
    _box_item("2", f"Self-signed {DIM}(по IP — браузер предупредит){NC}")
    _box_bottom()
    try:
        ch = input(f"{CYAN}  Выбор [1 — Let's Encrypt]: {NC}").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return True, None
    return (ch == "2"), None


def ask_domain(default: "Optional[str]" = None) -> "Optional[str]":
    """Спрашивает домен у пользователя.

    Args:
      default: домен по умолчанию (если Enter — используется он).
                Если None — предлагается PARAM_DOMAIN.
    """
    core = _core_module()
    CYAN, NC, DIM, YELLOW, GREEN = core.CYAN, core.NC, core.DIM, core.YELLOW, core.GREEN

    if default is None:
        default = getattr(core, "PARAM_DOMAIN", "") or ""

    print()
    if default:
        try:
            ans = input(f"{CYAN}  Домен (Enter={default}): {NC}").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        return ans or default
    else:
        try:
            ans = input(f"{CYAN}  Домен: {NC}").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        return ans or None


# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ NGINX VHOST
# ══════════════════════════════════════════════════════════════════════════════

def _generate_vhost(port: int,
                    backend_port: int,
                    cert_path: Path,
                    key_path: Path,
                    domain: str,
                    backend_http_scheme: str = "http",
                    websocket_origin_rewrite: bool = False,
                    panel_name_slug: str = "panel",
                    ) -> str:
    """Генерирует nginx vhost config.

    Args:
      port: внешний порт nginx (TLS).
      backend_port: порт backend-сервиса (на 127.0.0.1).
      cert_path, key_path: пути к TLS сертификату.
      domain: домен для server_name (или '_' для self-signed).
      backend_http_scheme: 'http' или 'https' backend.
      websocket_origin_rewrite: если True — подменять Host/Origin/Referer
        на 127.0.0.1:backend_port (нужно для Telemt Panel CheckOrigin).
      panel_name_slug: slug панели для логов/файлов (например 'telemt-panel').
    """
    # WebSocket origin rewrite block
    if websocket_origin_rewrite:
        ws_headers = f"""        # ВАЖНО: Panel использует WebSocket с CheckOrigin. Когда nginx
        # проксирует запросы с публичного IP:порта — Origin и Host не
        # совпадают с тем, что Panel ожидает (127.0.0.1:{backend_port}).
        # CheckOrigin отклоняет WebSocket → 'Telemt is unreachable'.
        # Подменяем Origin, Host, и Referer на ожидаемые значения.
        proxy_set_header Host 127.0.0.1:{backend_port};
        proxy_set_header Origin {backend_http_scheme}://127.0.0.1:{backend_port};
        proxy_set_header Referer {backend_http_scheme}://127.0.0.1:{backend_port}/;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 30s;
        # WebSocket long-lived: 1 час вместо 60 сек.
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;"""
    else:
        ws_headers = f"""        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_buffering off;
        proxy_request_buffering off;"""

    # SSL verification для HTTPS backend (self-signed cert).
    ssl_verify_block = ""
    if backend_http_scheme == "https":
        ssl_verify_block = """        proxy_ssl_verify off;
        proxy_ssl_session_reuse on;"""

    # ACME challenge block — только для Let's Encrypt (когда есть domain)
    acme_block = ""
    if domain and domain != "_":
        acme_block = f"""
    # ACME challenge — для certbot renewal через webroot.
    location /.well-known/acme-challenge/ {{
        root /var/www/{domain};
    }}"""

    return f"""# Chimera — nginx front для {panel_name_slug} с TLS.
# Сгенерировано panel_nginx_front.py. НЕ редактировать вручную.
# Управление: TUI → соответствующее меню панели.

server {{
    listen {port} ssl http2;
    server_name {domain};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};

    # Современные шифры (Mozilla Intermediate 2024).
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS (2 года) — только для Let's Encrypt (домен доверенный).
    {f'add_header Strict-Transport-Security "max-age=63072000" always;' if domain and domain != "_" else ""}

    # Security headers.
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Логи.
    access_log /var/log/nginx/{panel_name_slug}-nginx-access.log;
    error_log  /var/log/nginx/{panel_name_slug}-nginx-error.log;

    # Проксирование на backend (loopback).
    location / {{
        proxy_pass {backend_http_scheme}://127.0.0.1:{backend_port};
        proxy_http_version 1.1;
{ssl_verify_block}
{ws_headers}
    }}{acme_block}
}}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА / УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════

def panel_nginx_front_install(
    service_tag: str,
    port: int,
    backend_port: int,
    site_name: str,
    state_file: Path,
    title: str = "Panel",
    use_self_signed: bool = False,
    domain: "Optional[str]" = None,
    websocket_origin_rewrite: bool = False,
    backend_http_scheme: str = "http",
    cert_name_slug: "Optional[str]" = None,
) -> "tuple[bool, str]":
    """Устанавливает nginx front с TLS для панели.

    Args:
      service_tag: тег из port_registry (например SERVICE_WEB_PANEL_NGINX).
      port: внешний порт nginx (TLS).
      backend_port: порт backend-сервиса (на 127.0.0.1).
      site_name: имя nginx vhost (sites-enabled/<site_name>).
      state_file: путь к JSON-файлу состояния.
      title: человекочитаемое имя для логов.
      use_self_signed: True → self-signed, False → Let's Encrypt.
      domain: домен для Let's Encrypt (если None и не self_signed — спросить).
      websocket_origin_rewrite: подменять Host/Origin/Referer для WebSocket CheckOrigin.
      backend_http_scheme: 'http' или 'https'.
      cert_name_slug: slug для имени self-signed сертификата.

    Returns:
      (success, message)
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    # В _core.py нет функции err/_err — используем warn для некритичных ошибок.
    # (die() exits, не подходит — нам нужно показать сообщение и вернуть False.)
    CYAN, NC, GREEN, RED, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.RED, core.YELLOW, core.DIM

    # ── Подгрузка state.json в глобали, если ещё не сделано ──────────
    # do_manage_web_panel() / do_subscription_menu() вызывают этот модуль
    # БЕЗ _load_state_into_globals() — поэтому PARAM_DOMAIN пустой, и nginx
    # front падает с "DOMAIN не задан". Подгружаем явно (идемпотентно).
    try:
        if not getattr(core, "PARAM_DOMAIN", ""):
            if hasattr(core, "_load_state_into_globals"):
                core._load_state_into_globals()
    except Exception:
        # _load_state_into_globals может не существовать в старых версиях —
        # fallback ниже: читаем state.json напрямую.
        pass

    if cert_name_slug is None:
        cert_name_slug = site_name.replace(".", "-").replace("_", "-")

    # 1. Проверка конфликтов порта через port_registry.
    is_free, conflicts = check_port_via_registry(port, service_tag)
    if not is_free:
        warn(f"Порт {port} занят:")
        for c in conflicts[:3]:
            print(f"    {DIM}• {c}{NC}")
        return False, f"Порт {port} занят"

    # 2. Определение сертификата.
    public_ip = ""
    if use_self_signed:
        info("Генерация self-signed TLS сертификата...")
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "5", "ifconfig.me"],
                capture_output=True, text=True, check=False, timeout=10,
            )
            public_ip = r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            pass
        cert_path, key_path = _generate_self_signed_tls(public_ip, cert_name_slug)
        if cert_path is None:
            return False, "Не удалось сгенерировать self-signed TLS сертификат"
        domain = public_ip or "localhost"
    else:
        # Let's Encrypt.
        if domain is None:
            domain = getattr(core, "PARAM_DOMAIN", "") or ""
        # Fallback: если PARAM_DOMAIN всё ещё пустой — читаем state.json
        # напрямую (на случай если _load_state_into_globals не вызвалась
        # или в старой версии проекта).
        if not domain:
            try:
                import json as _json
                _state_path = Path("/var/lib/xray-installer/state.json")
                if _state_path.exists():
                    _state = _json.loads(_state_path.read_text())
                    domain = _state.get("domain", "") or ""
            except Exception:
                pass
        if not domain:
            return False, ("DOMAIN не задан. Либо установите VLESS с доменом, "
                           "либо используйте self-signed режим (без домена).")
        # Ищем существующий сертификат.
        cert_path, key_path = _find_ssl_cert(domain)
        if cert_path is None:
            info(f"SSL-сертификат для {domain} не найден, получаем через certbot...")
            try:
                from chimera.modules.ssl_certbot import obtain_ssl_cert
                obtain_ssl_cert(domain)
                cert_path, key_path = _find_ssl_cert(domain)
            except Exception as e:
                return False, f"Не удалось получить SSL-сертификат: {e}"
        if cert_path is None or key_path is None:
            return False, f"SSL-сертификат для {domain} не найден и не получен"

    # 3. Генерация vhost.
    vhost = _generate_vhost(
        port=port,
        backend_port=backend_port,
        cert_path=cert_path,
        key_path=key_path,
        domain=domain if not use_self_signed else "_",
        backend_http_scheme=backend_http_scheme,
        websocket_origin_rewrite=websocket_origin_rewrite,
        panel_name_slug=cert_name_slug,
    )

    # 4. Запись vhost + symlink.
    NGINX_SITES_AVAILABLE.mkdir(parents=True, exist_ok=True)
    available = NGINX_SITES_AVAILABLE / site_name
    enabled   = NGINX_SITES_ENABLED / site_name
    try:
        available.write_text(vhost)
        if enabled.exists() or enabled.is_symlink():
            enabled.unlink()
        enabled.symlink_to(available)
    except Exception as e:
        return False, f"Не удалось записать vhost: {e}"

    # 5. nginx -t + reload.
    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        return False, "nginx не установлен"
    r = subprocess.run([nginx_bin, "-t"], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        # Откат.
        enabled.unlink(missing_ok=True)
        available.unlink(missing_ok=True)
        return False, f"nginx -t failed: {r.stderr.strip()[:300]}"
    subprocess.run(["systemctl", "reload", "nginx"], check=False)

    # 6. Регистрация в port_registry + открытие порта в фаерволе.
    # ВАЖНО: ufw_open_port() работает только если UFW активен.
    # Если UFW не установлен или inactive — fallback на iptables.
    # Иначе юзер видит 'nginx слушает порт, но извне недоступен' (как
    # было в баг-репорте SpecteR 22.08.2026 — порт 45443 назначен,
    # nginx слушал, но фаервол блокировал).
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register,
        )
        port_register(service_tag, port, "tcp",
                      comment=f"{title} (nginx front, TLS, →127.0.0.1:{backend_port})")
        ufw_ok, ufw_msg = ufw_open_port(port, "tcp", service_tag,
                                        comment=f"{title} (nginx front, TLS)")
        if ufw_ok:
            info(f"  {CYAN}Порт {port}/tcp открыт в UFW: {ufw_msg}{NC}")
        else:
            # UFW не установлен или inactive — fallback на iptables.
            info(f"  {YELLOW}UFW недоступен ({ufw_msg}) — открываю порт через iptables...{NC}")
            import shutil as _sh
            ipt = _sh.which("iptables")
            if ipt:
                # Проверяем существующее правило (идемпотентность).
                r_check = subprocess.run(
                    [ipt, "-C", "INPUT", "-p", "tcp", "--dport", str(port),
                     "-j", "ACCEPT"],
                    capture_output=True, check=False,
                )
                if r_check.returncode != 0:
                    # Правила нет — добавляем.
                    r_add = subprocess.run(
                        [ipt, "-I", "INPUT", "1", "-p", "tcp",
                         "--dport", str(port), "-j", "ACCEPT"],
                        capture_output=True, text=True, check=False,
                    )
                    if r_add.returncode == 0:
                        info(f"  {CYAN}Порт {port}/tcp открыт в iptables{NC}")
                        # Persist rules (iptables-persistent / netfilter-persistent).
                        np = _sh.which("netfilter-persistent")
                        if np:
                            subprocess.run([np, "save"], capture_output=True, check=False)
                    else:
                        warn(f"  {RED}Не удалось открыть порт {port} в iptables: "
                             f"{r_add.stderr.strip()[:200]}{NC}")
                        warn(f"  {YELLOW}Откройте вручную: iptables -I INPUT 1 "
                             f"-p tcp --dport {port} -j ACCEPT{NC}")
                else:
                    info(f"  {DIM}Порт {port}/tcp уже открыт в iptables{NC}")
            else:
                warn(f"  {RED}Ни UFW, ни iptables не найдены — порт {port} "
                     f"НЕ открыт в фаерволе!{NC}")
                warn(f"  {YELLOW}Откройте вручную или проверьте security group "
                     f"хостинг-провайдера.{NC}")
    except Exception as _e:
        warn(f"  {RED}Ошибка открытия порта {port} в фаерволе: {_e}{NC}")
        warn(f"  {YELLOW}Откройте вручную: iptables -I INPUT 1 -p tcp "
             f"--dport {port} -j ACCEPT{NC}")

    # 7. State file.
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({
        "enabled": True,
        "port": port,
        "domain": domain if not use_self_signed else None,
        "self_signed": use_self_signed,
        "url": f"https://{domain if not use_self_signed else (public_ip or 'SERVER_IP')}:{port}",
    }, indent=2))

    url = f"https://{domain if not use_self_signed else (public_ip or 'SERVER_IP')}:{port}"
    success(f"{title}: nginx front включён — {url}")
    if use_self_signed:
        warn("Браузер предупредит о self-signed TLS — это нормально.")
    return True, url


def panel_nginx_front_remove(
    service_tag: str,
    site_name: str,
    state_file: Path,
    title: str = "Panel",
) -> "tuple[bool, str]":
    """Удаляет nginx front + закрывает порт.

    Returns:
      (success, message)
    """
    core = _core_module()
    info, success = core.info, core.success

    available = NGINX_SITES_AVAILABLE / site_name
    enabled   = NGINX_SITES_ENABLED / site_name

    # 1. Read state (для порта).
    port = None
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
            port = state.get("port")
        except Exception:
            pass

    # 2. Удаляем vhost.
    enabled.unlink(missing_ok=True)
    available.unlink(missing_ok=True)

    # 3. nginx reload.
    nginx_bin = shutil.which("nginx")
    if nginx_bin:
        r = subprocess.run([nginx_bin, "-t"], capture_output=True, text=True, check=False)
        if r.returncode == 0:
            subprocess.run(["systemctl", "reload", "nginx"], check=False)

    # 4. Закрываем порт в фаерволе + снимаем регистрацию.
    # Симметрично panel_nginx_front_install: UFW → iptables fallback.
    if port is not None:
        try:
            from chimera.modules.port_registry import (
                ufw_close_port, port_unregister,
            )
            ufw_close_port(port, "tcp", service_tag)
            port_unregister(service_tag, port=port, proto="tcp")
            info(f"  {CYAN}Порт {port}/tcp закрыт в UFW + снят с регистрации{NC}")
        except Exception as _e:
            warn(f"  {YELLOW}port_registry/UFW error: {_e} — fallback на iptables...{NC}")
        # Fallback: убираем orphaned iptables правила (если port_registry
        # не нашёл их, или UFW inactive при install).
        import shutil as _sh
        ipt = _sh.which("iptables")
        if ipt:
            args = ["-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
            for _ in range(5):
                r_check = subprocess.run(
                    [ipt, "-C", "INPUT"] + args,
                    capture_output=True, check=False,
                )
                if r_check.returncode != 0:
                    break  # правила нет — выходим
                subprocess.run(
                    [ipt, "-D", "INPUT"] + args,
                    capture_output=True, check=False,
                )
            # Persist после удаления.
            np = _sh.which("netfilter-persistent")
            if np:
                subprocess.run([np, "save"], capture_output=True, check=False)
        # Также снимаем orphaned UFW правило (если осталось).
        if _sh.which("ufw"):
            subprocess.run(["ufw", "delete", "allow", f"{port}/tcp"],
                           capture_output=True, input="y\n", check=False)

    # 5. Очищаем state.
    state_file.unlink(missing_ok=True)

    success(f"{title}: nginx front выключен, порт {port or '?'} освобождён.")
    return True, f"{title}: nginx front удалён"


# ══════════════════════════════════════════════════════════════════════════════
#  STATUS
# ══════════════════════════════════════════════════════════════════════════════

def panel_nginx_front_status(state_file: Path) -> dict:
    """Возвращает статус nginx front для панели.

    Returns:
      dict с ключами:
        enabled: bool
        port: int | None
        domain: str | None
        self_signed: bool
        url: str | None
    """
    if not state_file.exists():
        return {"enabled": False}
    try:
        return json.loads(state_file.read_text())
    except Exception:
        return {"enabled": False}
