"""
vless_installer/modules/nginx_setup.py
───────────────────────────────────────────────────────────────────────────────
Настройка Nginx для VLESS-инсталлятора: rate-limit, сайты-заглушки, временный
конфиг для certbot, финальный конфиг (xHTTP TLS / AWG 2.0 / REALITY+Unix-socket),
systemd override (Nginx → Xray).

Содержит 9 функций, извлечённых из _core.py (Tier-3 рефакторинг):

  • setup_nginx_rate_limit()              — rate-limit.conf (limit_req/limit_conn zones)
  • create_website()                      — генерация HTML-шаблона сайта-заглушки
  • _create_techhub(web_root)             — шаблон «TechHub» (template #1)
  • _create_nexcloud(web_root)            — шаблон «NexCloud» (template #2/7+)
  • _create_simple_site(...)              — универсальный 1-страничный шаблон
  • _ensure_nginx_sites_enabled_include() — include sites-enabled в nginx.conf
                                             (для nginx.org-репо, где conf.d only)
  • setup_nginx_temp()                    — временный HTTP-only конфиг для certbot
                                             (мутирует STAGE_NGINX_DONE в _core)
  • setup_nginx_final()                   — финальный конфиг: xHTTP TLS / AWG 2.0 /
                                             REALITY+Unix-socket с proxy_protocol
  • setup_nginx_systemd_override()        — systemd override (After/Wants xray.service)

Все константы (NGINX_CONF_DIR, NGINX_ENABLED_DIR, NGINX_RATE_LIMIT_CONF,
PARAM_DOMAIN, PARAM_SOCKET_PATH, PARAM_SITE_TEMPLATE, PROTOCOL_MODE, SERVER_PORT,
AWG_EXIT_ENABLED, PARAM_USE_DNSCRYPT) читаются из _core через _core_module().
STAGE_NGINX_DONE мутируется через setattr(core, ...) — это эквивалент
`global STAGE_NGINX_DONE; STAGE_NGINX_DONE = True` в старом _core.py.

Точки входа из _core.py:
    from vless_installer.modules.nginx_setup import (
        setup_nginx_rate_limit, create_website,
        _create_techhub, _create_nexcloud, _create_simple_site,
        _ensure_nginx_sites_enabled_include,
        setup_nginx_temp, setup_nginx_final, setup_nginx_systemd_override,
    )

Доступ к helpers ядра (info/warn/success/_run/log_to_file/find_nginx_bin) —
через importlib (lazy binding), как и в других извлечённых модулях.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import socket
import textwrap
from pathlib import Path
from typing import Optional


# ── Sentinel для различения "не передан" от "передан None" ───────────────────
# Нужно для параметров port/socket_path в setup_nginx_final():
#   • VLESS install flow вызывает без аргументов → должны inherit из core
#   • Telemt own-site вызывает socket_path=None явно → должны использовать TCP
# Обычный default=None не различает эти два случая — sentinel решает.
_UNSET = object()


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль vless_installer._core (импорт лениво)."""
    import importlib
    return importlib.import_module("vless_installer._core")


# ============================================================================
#  NGINX RATE LIMIT
# ============================================================================
def setup_nginx_rate_limit() -> None:
    core = _core_module()
    info = core.info
    success = core.success
    _run = core._run
    find_nginx_bin = core.find_nginx_bin
    NGINX_RATE_LIMIT_CONF = core.NGINX_RATE_LIMIT_CONF
    info("Настройка Nginx rate limiting...")
    NGINX_RATE_LIMIT_CONF.parent.mkdir(parents=True, exist_ok=True)
    NGINX_RATE_LIMIT_CONF.write_text(textwrap.dedent("""\
        limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
        limit_req_zone $binary_remote_addr zone=api:10m rate=5r/s;
        limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    """))
    _run([find_nginx_bin() or "/usr/sbin/nginx", "-t"], check=False, quiet=True)
    _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
    success("Nginx rate limiting настроен")

# =============================================================================
#  ШАГ 9: САЙТЫ-ЗАГЛУШКИ
# =============================================================================
def create_website(domain: Optional[str] = None,
                   site_template: Optional[str] = None) -> None:
    """Создаёт сайт-заглушку в /var/www/<domain>/.

    Параметры domain/site_template, переданные явно, ПЕРЕКРЫВАЮТ значения
    из core.PARAM_DOMAIN / core.PARAM_SITE_TEMPLATE. Если не переданы —
    поведение идентично предыдущему (VLESS install flow не меняется ни
    в одном байте вывода).

    Это позволяет параллельно поднимать сайт для VLESS-домена и отдельный
    сайт для Telemt-домена на одном сервере — без мутации глобального state
    в _core.py (см. задачу Telemt nginx-fallback в CHANGELOG).
    """
    core = _core_module()
    info = core.info
    success = core.success
    _run = core._run
    PARAM_DOMAIN = domain if domain is not None else core.PARAM_DOMAIN
    PARAM_SITE_TEMPLATE = (
        site_template if site_template is not None else core.PARAM_SITE_TEMPLATE
    )
    web_root = Path(f"/var/www/{PARAM_DOMAIN}")
    web_root.mkdir(parents=True, exist_ok=True)
    info(f"Создание шаблона сайта #{PARAM_SITE_TEMPLATE}...")
    tmpl = int(PARAM_SITE_TEMPLATE or "0")
    if tmpl == 1:
        _create_techhub(web_root)
    elif tmpl == 2:
        _create_nexcloud(web_root)
    elif tmpl == 3:
        _create_simple_site(web_root, "Holm & Oak",    "Curated Homeware",         "#faf9f7", "#44403c", "#78716c")
    elif tmpl == 4:
        _create_simple_site(web_root, "Ember & Grain", "Wood-Fired Bistro",         "#1a1208", "#e8a832", "#a89070")
    elif tmpl == 5:
        _create_simple_site(web_root, "NexHub",        "Community & Cloud Storage", "#0e1117", "#2f81f7", "#8b949e")
    elif tmpl == 6:
        _create_simple_site(web_root, "ByteForge",     "Tech Community Forum",      "#080c10", "#58a6ff", "#768390")
    else:
        _create_nexcloud(web_root)

    (web_root / "robots.txt").write_text("User-agent: *\n")
    try:
        _run(["chown", "-R", "www-data:www-data", str(web_root)], check=False, quiet=True)
    except Exception:
        pass
    success(f"Сайт создан в {web_root}")


def _create_techhub(web_root: Path) -> None:
    (web_root / "index.html").write_text(
        '<!DOCTYPE html>\n<html lang="ru">\n<head>\n'
        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
        '<title>TechHub - Компьютерные технологии</title>\n'
        '<style>\n'
        '*{margin:0;padding:0;box-sizing:border-box}\n'
        'body{font-family:\'Segoe UI\',Tahoma,sans-serif;line-height:1.6;color:#333;background:#f5f5f5}\n'
        'header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:2rem;text-align:center}\n'
        'nav{background:#333;padding:1rem;display:flex;justify-content:center;flex-wrap:wrap}\n'
        'nav a{color:#fff;text-decoration:none;padding:.5rem 1rem;margin:.25rem;border-radius:4px;transition:background .3s}\n'
        'nav a:hover{background:#667eea}\n'
        'section{padding:3rem 2rem;max-width:1200px;margin:2rem auto;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}\n'
        'h2{color:#667eea;margin-bottom:1.5rem;border-bottom:3px solid #667eea;padding-bottom:.5rem;display:inline-block}\n'
        '.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:2rem}\n'
        '.card{background:#f9f9f9;padding:1.5rem;border-radius:8px;border-left:4px solid #667eea;transition:transform .3s}\n'
        '.card:hover{transform:translateY(-5px)}\n'
        '.card h3{color:#764ba2;margin-bottom:1rem}\n'
        'footer{background:#333;color:#fff;text-align:center;padding:2rem;margin-top:3rem}\n'
        '.btn{display:inline-block;background:#667eea;color:#fff;padding:.75rem 1.5rem;text-decoration:none;border-radius:4px;margin-top:1rem}\n'
        '</style>\n</head>\n<body>\n'
        '<header><h1>🖥️ TechHub</h1><p>Ваш портал в мир компьютерных технологий</p></header>\n'
        '<nav>\n'
        '<a href="#about">О нас</a><a href="#hardware">Железо</a><a href="#software">Софт</a>\n'
        '<a href="#network">Сети</a><a href="#security">Безопасность</a><a href="#cloud">Облака</a>\n'
        '<a href="#dev">Разработка</a><a href="#ai">ИИ</a><a href="#iot">IoT</a>\n'
        '<a href="#gaming">Гейминг</a><a href="#mobile">Мобильные</a><a href="#contact">Контакты</a>\n'
        '</nav>\n'
        '<section id="about"><h2>📌 О проекте</h2><p>TechHub — современный информационный портал о компьютерных технологиях.</p>'
        '<a href="#" class="btn">Узнать больше</a></section>\n'
        '<section id="hardware"><h2>🔧 Железо</h2><div class="grid">'
        '<div class="card"><h3>Процессоры</h3><p>Обзоры CPU от Intel и AMD</p></div>'
        '<div class="card"><h3>Видеокарты</h3><p>Тесты GPU для игр и работы</p></div>'
        '<div class="card"><h3>Память</h3><p>RAM и накопители SSD/NVMe</p></div></div></section>\n'
        '<section id="software"><h2>💻 Софт</h2><div class="grid">'
        '<div class="card"><h3>ОС</h3><p>Windows, Linux, macOS</p></div>'
        '<div class="card"><h3>Утилиты</h3><p>Полезные программы</p></div>'
        '<div class="card"><h3>Офис</h3><p>Альтернативы Microsoft Office</p></div></div></section>\n'
        '<section id="contact"><h2>📧 Контакты</h2><p>Email: info@techhub.example | Tel: +1-234-567-8900</p>'
        '<a href="#" class="btn">Написать нам</a></section>\n'
        '<footer><p>&copy; 2025 TechHub. Все права защищены.</p></footer>\n'
        '</body></html>\n'
    )


def _create_nexcloud(web_root: Path) -> None:
    for sub in ("images", "pricing", "about", "blog", "contact"):
        (web_root / sub).mkdir(exist_ok=True)

    (web_root / "style.css").write_text(
        '*{margin:0;padding:0;box-sizing:border-box}\n'
        ':root{--bg:#0f172a;--accent:#6366f1;--text:#e2e8f0;--muted:#94a3b8;--card:#1e293b;--border:#334155}\n'
        'body{font-family:"Inter",system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}\n'
        'a{color:inherit;text-decoration:none}\n'
        'header{padding:1.25rem 5%;display:flex;justify-content:space-between;align-items:center;'
        'border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:100}\n'
        '.logo{font-size:1.3rem;font-weight:800;letter-spacing:-.5px}.logo span{color:var(--accent)}\n'
        '.btn{display:inline-block;padding:.6rem 1.4rem;border-radius:7px;font-size:.875rem;font-weight:600}\n'
        '.btn-p{background:var(--accent);color:#fff}\n'
        '.page{max-width:1100px;margin:0 auto;padding:4rem 5%}\n'
        'h1{font-size:clamp(2rem,5vw,3.5rem);font-weight:800;line-height:1.15;margin-bottom:1.25rem}\n'
        '.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.5rem;margin-top:2.5rem}\n'
        '.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:2rem}\n'
        'footer{border-top:1px solid var(--border);padding:3rem 5%;display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:2rem}\n'
        '.ft-bottom{border-top:1px solid var(--border);padding:1.25rem 5%;font-size:.8rem;color:var(--muted)}\n'
    )

    (web_root / "index.html").write_text(
        '<!DOCTYPE html><html lang="en"><head>\n'
        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>NexCloud — Serverless Cloud Platform</title>\n'
        '<link rel="stylesheet" href="/style.css"></head><body>\n'
        '<header><a href="/" class="logo">Nex<span>Cloud</span></a>\n'
        '<nav><a href="/">Home</a><a href="/pricing/">Pricing</a>'
        '<a href="/about/">About</a><a href="/blog/">Blog</a><a href="/contact/">Contact</a></nav>\n'
        '<a href="/pricing/" class="btn btn-p">Get Started</a></header>\n'
        '<div class="page" style="text-align:center">\n'
        '<h1>Deploy faster with NexCloud</h1>\n'
        '<p>Serverless infrastructure that scales with your business. Zero config, full power.</p>\n'
        '</div>\n'
        '<div class="page"><div class="grid3">\n'
        '<div class="card"><h3>⚡ Edge Functions</h3><p>Run your code at the edge, 50ms cold starts.</p></div>\n'
        '<div class="card"><h3>🗄️ Managed Databases</h3><p>Postgres, Redis, and object storage.</p></div>\n'
        '<div class="card"><h3>🔒 Zero-Trust Security</h3><p>OIDC, mTLS, and WAF baked in.</p></div>\n'
        '</div></div>\n'
        '<footer>\n'
        '<div class="ft-brand"><div class="logo">Nex<span>Cloud</span></div></div>\n'
        '<div><h4>Product</h4><a href="/pricing/">Pricing</a><a href="/about/">About</a></div>\n'
        '<div><h4>Resources</h4><a href="/contact/">Support</a></div>\n'
        '<div><h4>Company</h4><a href="/about/">Team</a></div>\n'
        '</footer>\n'
        '<div class="ft-bottom"><span>&copy; 2025 NexCloud Inc.</span></div>\n'
        '</body></html>\n'
    )

    for page_dir in ("pricing", "about", "blog", "contact"):
        title = page_dir.capitalize()
        (web_root / page_dir / "index.html").write_text(
            f'<!DOCTYPE html><html lang="en"><head>\n'
            f'<meta charset="UTF-8"><title>{title} — NexCloud</title>'
            f'<link rel="stylesheet" href="/style.css"></head><body>\n'
            f'<header><a href="/" class="logo">Nex<span>Cloud</span></a></header>\n'
            f'<div class="page"><h1>{title}</h1>'
            f'<p style="margin-top:1rem;color:var(--muted)">Content for the {title} page.</p>\n'
            f'<a href="/" style="display:inline-block;margin-top:2rem;color:var(--accent)">'
            f'&larr; Back to Home</a></div>\n'
            f'<div class="ft-bottom"><span>&copy; 2025 NexCloud Inc.</span></div>\n'
            f'</body></html>\n'
        )


def _create_simple_site(
    web_root: Path, site_name: str, tagline: str,
    bg: str, accent: str, muted: str,
) -> None:
    (web_root / "index.html").write_text(
        f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        f'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'<title>{site_name}</title>\n'
        f'<style>\n'
        f'*{{margin:0;padding:0;box-sizing:border-box}}\n'
        f'body{{font-family:system-ui,sans-serif;background:{bg};color:#fff;min-height:100vh;display:flex;flex-direction:column}}\n'
        f'header{{padding:1.5rem 5%;border-bottom:1px solid rgba(255,255,255,.1);display:flex;justify-content:space-between;align-items:center}}\n'
        f'.logo{{font-size:1.25rem;font-weight:700;color:#fff}}\n'
        f'nav a{{color:{muted};margin-left:1.5rem;font-size:.875rem;text-decoration:none}}\n'
        f'.hero{{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:4rem 2rem}}\n'
        f'h1{{font-size:clamp(2rem,5vw,4rem);font-weight:700;margin-bottom:1rem}}\n'
        f'h1 span{{color:{accent}}}\n'
        f'p{{color:{muted};font-size:1.05rem;max-width:500px;margin:0 auto 2rem;line-height:1.7}}\n'
        f'.btn{{display:inline-block;background:{accent};color:#000;padding:.875rem 2.5rem;border-radius:8px;font-weight:700;text-decoration:none;margin:.5rem}}\n'
        f'footer{{padding:2rem 5%;border-top:1px solid rgba(255,255,255,.1);text-align:center;color:{muted};font-size:.8rem}}\n'
        f'</style>\n</head>\n<body>\n'
        f'<header><div class="logo">{site_name}</div>\n'
        f'<nav><a href="/">Home</a><a href="#">About</a><a href="#">Features</a><a href="#">Contact</a></nav></header>\n'
        f'<div class="hero">\n'
        f'<h1>{site_name}<br><span>{tagline}</span></h1>\n'
        f'<p>A modern, professional platform built for people who demand quality and reliability.</p>\n'
        f'<a href="#" class="btn">Get Started</a>\n'
        f'</div>\n'
        f'<footer><p>&copy; 2025 {site_name}. All rights reserved.</p></footer>\n'
        f'</body></html>\n'
    )

# =============================================================================
#  ШАГ 10: NGINX ВРЕМЕННЫЙ КОНФИГ
# =============================================================================
def _ensure_nginx_sites_enabled_include() -> None:
    """
    nginx из официального репо (nginx.org) использует conf.d/ и не включает
    sites-enabled/ по умолчанию. Эта функция добавляет:
        include /etc/nginx/sites-enabled/*;
    после строки include conf.d в блоке http {} если отсутствует.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    nginx_conf = Path("/etc/nginx/nginx.conf")
    if not nginx_conf.exists():
        return
    text = nginx_conf.read_text()
    if "sites-enabled" in text:
        return  # уже есть
    # Вставляем после строки include conf.d/*.conf
    new_lines = []
    inserted = False
    for line in text.splitlines(keepends=True):
        new_lines.append(line)
        if not inserted and "include" in line and "conf.d" in line:
            new_lines.append("    include /etc/nginx/sites-enabled/*;\n")
            inserted = True
    if not inserted:
        warn("nginx.conf: строка include conf.d не найдена — include sites-enabled не добавлен")
        return
    nginx_conf.write_text("".join(new_lines))
    info("nginx.conf: добавлен include /etc/nginx/sites-enabled/* (nginx.org репо)")


def setup_nginx_temp(domain: Optional[str] = None) -> None:
    """Создаёт временный HTTP:80 vhost для certbot ACME-челленджа.

    Используется ПЕРЕД obtain_ssl_cert() — certbot'у нужен отвечающий
    HTTP:80 endpoint с location /.well-known/acme-challenge/ чтобы выпустить
    сертификат через webroot-метод. Без этого vhost'а challenge уходит в
    дефолтный server и certbot получает 404.

    Параметр domain (v4.20.3), переданный явно, перекрывает core.PARAM_DOMAIN —
    по той же схеме, что в create_website()/setup_nginx_final()/
    obtain_ssl_cert(). Если не передан — поведение идентично предыдущему
    (VLESS install flow не меняется ни в одном байте вывода).

    Telemt own-site вызывает с domain=<домен Telemt> — certbot выпускает
    сертификат для Telemt-домена, а не для VLESS-домена сервера.
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    _run = core._run
    find_nginx_bin = core.find_nginx_bin
    log_to_file = core.log_to_file
    PARAM_DOMAIN = domain if domain is not None else core.PARAM_DOMAIN
    NGINX_CONF_DIR = core.NGINX_CONF_DIR
    NGINX_ENABLED_DIR = core.NGINX_ENABLED_DIR
    info("Настройка Nginx для certbot (временный конфиг)...")

    # Гарантируем что nginx установлен перед настройкой
    _nginx_bin = find_nginx_bin()
    if not _nginx_bin:
        info("  nginx не найден — устанавливаю...")
        _run(["apt-get", "install", "-y", "-q", "nginx"],
             env={"DEBIAN_FRONTEND": "noninteractive"},
             check=False, quiet=True)
        _nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"

    # Чиним битый симлинк если есть
    nginx_lbin = Path("/usr/local/bin/nginx")
    if nginx_lbin.is_symlink() and not nginx_lbin.exists():
        nginx_lbin.unlink()
    if _nginx_bin and not nginx_lbin.exists():
        try:
            nginx_lbin.symlink_to(_nginx_bin)
        except Exception:
            pass
    web_root = Path(f"/var/www/{PARAM_DOMAIN}")
    web_root.mkdir(parents=True, exist_ok=True)
    NGINX_CONF_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_ENABLED_DIR.mkdir(parents=True, exist_ok=True)

    # nginx из официального репо (nginx.org) не включает sites-enabled по умолчанию.
    # Проверяем nginx.conf и добавляем include если отсутствует.
    _ensure_nginx_sites_enabled_include()

    cfg = NGINX_CONF_DIR / PARAM_DOMAIN
    cfg.write_text(textwrap.dedent(f"""\
        server {{
            listen 80;
            listen [::]:80;
            server_name {PARAM_DOMAIN};
            root {web_root};
            index index.html;
            location /.well-known/acme-challenge/ {{ root {web_root}; }}
            location / {{ return 301 https://$host$request_uri; }}
        }}
    """))

    link = NGINX_ENABLED_DIR / PARAM_DOMAIN
    link.unlink(missing_ok=True)
    link.symlink_to(cfg)
    (NGINX_ENABLED_DIR / "default").unlink(missing_ok=True)

    r = _run([_nginx_bin, "-t"], capture=True, check=False)
    if "successful" in r.stderr:
        _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
        setattr(core, "STAGE_NGINX_DONE", True)
        success("Nginx запущен для certbot")
    else:
        # Hardening (v4.20.3): при провале nginx -t сначала откатываем just-created
        # симлинк, и ТОЛЬКО ПОТОМ restart/reload. Иначе restart выполняется с
        # уже подключённым битым конфигом — если процесс не поднимется, ляжет
        # весь nginx, включая рабочие VLESS-сайты, даже если ошибка локальна
        # для одного нового vhost.
        try:
            link.unlink()
        except Exception:
            pass
        log_to_file("WARN", r.stderr)
        _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
        setattr(core, "STAGE_NGINX_DONE", True)
        warn(f"Nginx -t упал для временного vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен")

# =============================================================================
#  ШАГ 11: SSL СЕРТИФИКАТ
# =============================================================================
# (obtain_ssl_cert, fix_letsencrypt_permissions вынесены в
#  vless_installer.modules.ssl_certbot; импорт — в верхней секции _core.py.)

def setup_nginx_final(domain: Optional[str] = None,
                      port=_UNSET,
                      socket_path=_UNSET,
                      protocol_mode: Optional[str] = None,
                      awg_exit_enabled: Optional[bool] = None,
                      site_template: Optional[str] = None) -> None:
    """Финальная настройка Nginx: HTTPS-сайт + reverse-proxy на Xray backend.

    Параметры domain/port/socket_path/protocol_mode/awg_exit_enabled/site_template,
    переданные явно, ПЕРЕКРЫВАЮТ значения из core.* Если не переданы — поведение
    идентично предыдущему (VLESS install flow не меняется ни в одном байте вывода).

    Telemt nginx-fallback (own-site режим) вызывает эту функцию с:
        domain=<домен Telemt>, port=<mask_port>, socket_path=None,
        protocol_mode="reality", awg_exit_enabled=False
    — это форсирует простую статическую HTTPS-сайт-заглушку на TCP-порту
    127.0.0.1:{port}, независимо от того, в каком режиме установлен VLESS
    на этом сервере (xhttp/reality/awg). Никакого проксирования на Xray,
    никакого reuse unix-сокета, никакого proxy_protocol.

    Sentinel _UNSET для port/socket_path позволяет различить "не передан"
    (→ inherit из core) от "передан None" (→ own-site TCP режим).
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    _run = core._run
    find_nginx_bin = core.find_nginx_bin
    log_to_file = core.log_to_file
    NGINX_CONF_DIR = core.NGINX_CONF_DIR
    NGINX_ENABLED_DIR = core.NGINX_ENABLED_DIR
    NGINX_RATE_LIMIT_CONF = core.NGINX_RATE_LIMIT_CONF
    PARAM_DOMAIN = domain if domain is not None else core.PARAM_DOMAIN

    # Sentinel-разрешение: _UNSET → inherit из core; явный None → own-site TCP.
    if socket_path is _UNSET:
        PARAM_SOCKET_PATH = core.PARAM_SOCKET_PATH
        _socket_explicit = False
    else:
        PARAM_SOCKET_PATH = socket_path  # может быть None или str
        _socket_explicit = True
    if port is _UNSET:
        SERVER_PORT = core.SERVER_PORT
        _port_explicit = False
    else:
        SERVER_PORT = port if port is not None else 0
        _port_explicit = True
    PROTOCOL_MODE = protocol_mode if protocol_mode is not None else core.PROTOCOL_MODE
    AWG_EXIT_ENABLED = awg_exit_enabled if awg_exit_enabled is not None else core.AWG_EXIT_ENABLED
    XHTTP_PATH = core.XHTTP_PATH
    XHTTP_BACKEND_PORT = core.XHTTP_BACKEND_PORT

    # ── Detect own-site TCP mode ────────────────────────────────────────────
    # Telemt own-site: socket_path явно None + port явно задан → TCP listen на
    # 127.0.0.1:{port}, без proxy_protocol, без real_ip_header, без Xray proxy.
    _own_site_tcp = (
        _socket_explicit and PARAM_SOCKET_PATH is None
        and _port_explicit and SERVER_PORT
    )

    # ── Domain collision check ─────────────────────────────────────────────
    # Own-site домен Telemt НЕ должен совпадать с VLESS-доменом (core.PARAM_DOMAIN)
    # — иначе два server{} блока с одинаковым server_name конфликтуют.
    if _own_site_tcp and core.PARAM_DOMAIN and PARAM_DOMAIN == core.PARAM_DOMAIN:
        raise RuntimeError(
            f"setup_nginx_final: own-site domain {PARAM_DOMAIN!r} совпадает с "
            f"core.PARAM_DOMAIN (VLESS-домен этого сервера). Own-site домен "
            f"Telemt должен быть ОТЛИЧЕН от VLESS-домена — иначе nginx-конфиги "
            f"конфликтуют (duplicate server_name / duplicate default_server)."
        )

    info("Настройка финального конфига Nginx...")
    web_root = Path(f"/var/www/{PARAM_DOMAIN}")

    create_website(domain=PARAM_DOMAIN, site_template=site_template)
    NGINX_CONF_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_ENABLED_DIR.mkdir(parents=True, exist_ok=True)

    # === OWN-SITE TCP: простой статический HTTPS-сайт на 127.0.0.1:{port} ===
    # Telemt own-site режим — генерируется ВСЕГДА как простая статическая
    # заглушка на TCP-порту, независимо от PROTOCOL_MODE/AWG_EXIT_ENABLED
    # сервера. proxy_protocol НЕ используется (Telemt подключается напрямую
    # по TCP, не через Xray xver=1). real_ip_header/set_real_ip_from тоже
    # не нужны — источник соединения сам Telemt на loopback.
    if _own_site_tcp:
        _os_nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"
        try:
            r_ver = _run([_os_nginx_bin, "-v"], capture=True, check=False)
            m_ver = re.search(r'(\d+)\.(\d+)\.(\d+)', r_ver.stderr or r_ver.stdout or "")
            _os_major = int(m_ver.group(1)) if m_ver else 1
            _os_minor = int(m_ver.group(2)) if m_ver else 18
        except Exception:
            _os_major, _os_minor = 1, 18

        if _os_major > 1 or (_os_major == 1 and _os_minor >= 25):
            _os_listen_main = f"listen 127.0.0.1:{SERVER_PORT} ssl;"
            _os_listen_default = f"listen 127.0.0.1:{SERVER_PORT} ssl default_server;"
            _os_http2_line = "    http2 on;"
        else:
            _os_listen_main = f"listen 127.0.0.1:{SERVER_PORT} ssl http2;"
            _os_listen_default = f"listen 127.0.0.1:{SERVER_PORT} ssl http2 default_server;"
            _os_http2_line = ""

        # ssl_reject_handshake для default_server (старые nginx → fallback)
        if _os_major > 1 or (_os_major == 1 and _os_minor >= 19):
            _os_default_ssl = "ssl_reject_handshake on;"
        else:
            _os_default_ssl = (
                f"ssl_certificate     /etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem;\n"
                f"            ssl_certificate_key /etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem;\n"
                f"            return 444;"
            )

        _os_rate_limit = ""
        if NGINX_RATE_LIMIT_CONF.exists():
            _os_rate_limit = ("    limit_req zone=general burst=20 nodelay;\n"
                              "    limit_conn conn_limit 10;")

        info(f"Own-site TCP: nginx слушает 127.0.0.1:{SERVER_PORT} "
             f"(статический HTTPS, без proxy_protocol)")

        cfg = NGINX_CONF_DIR / PARAM_DOMAIN
        cfg.write_text(textwrap.dedent(f"""\
            # =============================================================================
            # Own-site HTTPS-сайт для Telemt mask (свой домен + свой сайт)
            # Nginx слушает 127.0.0.1:{SERVER_PORT} — Telemt сплайсит failed
            # handshakes сюда. PROXY protocol НЕ используется.
            # =============================================================================

            # HTTP:80 — только для ACME-челленджей (certbot renew).
            # Без HTTPS-редиректа: редирект на https://$host/ ушёл бы на порт 443
            # (Telemt), а не на mask_port.
            server {{
                listen 80;
                listen [::]:80;
                server_name {PARAM_DOMAIN};
                location /.well-known/acme-challenge/ {{ root {web_root}; }}
                location / {{ return 404; }}
            }}

            # HTTPS на 127.0.0.1:{SERVER_PORT} — статический сайт-заглушка
            server {{
                {_os_listen_main}
            {_os_http2_line}
                server_name {PARAM_DOMAIN};

                ssl_certificate     /etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem;
                ssl_certificate_key /etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
                ssl_prefer_server_ciphers on;

                root {web_root};
                index index.html;

                add_header X-Robots-Tag "noindex, nofollow" always;
            {_os_rate_limit}

                location / {{
                    try_files $uri $uri/ =404;
                }}
            }}

            # Default server: reject all other SNI на этом порту
            server {{
                {_os_listen_default}
                server_name _;
                {_os_default_ssl}
            }}
        """))
        link = NGINX_ENABLED_DIR / PARAM_DOMAIN
        link.unlink(missing_ok=True)
        link.symlink_to(cfg)
        r = _run([_os_nginx_bin, "-t"], capture=True, check=False, quiet=True)
        if r.returncode == 0:
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            success(f"Own-site nginx настроен: 127.0.0.1:{SERVER_PORT} (статический HTTPS)")
        else:
            # Hardening (v4.20.3): unlink symlink ДО restart — иначе restart с
            # битым конфигом кладёт весь nginx (включая рабочие VLESS-сайты).
            try:
                link.unlink()
            except Exception:
                pass
            log_to_file("WARN", r.stderr or "")
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            warn(f"nginx -t упал для own-site vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен. Проверьте: {_os_nginx_bin} -t")
        return

    # === xHTTP TLS: Nginx терминирует TLS на :SERVER_PORT и проксирует ===
    # xHTTP path на Xray (127.0.0.1:XHTTP_BACKEND_PORT, security: none).
    # Заглушка сайта отдаётся для всех остальных путей (location /).
    # Это решает проблему отсутствия fallbacks для xHTTP в Xray-core
    # (https://github.com/XTLS/Xray-core/discussions/4113).
    #
    # Применимо ко всем xHTTP-режимам: Mode A, Mode B + AWG, Mode B + H2,
    # Mode B + exit-ноды — везде Xray слушает loopback, Nginx владеет :443.
    if PROTOCOL_MODE == "xhttp":
        # Определяем версию nginx для выбора синтаксиса http2
        _xhttp_nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"
        try:
            r_ver = _run([_xhttp_nginx_bin, "-v"], capture=True, check=False)
            m_ver = re.search(r'(\d+)\.(\d+)\.(\d+)', r_ver.stderr or r_ver.stdout or "")
            _nx_major = int(m_ver.group(1)) if m_ver else 1
            _nx_minor = int(m_ver.group(2)) if m_ver else 18
        except Exception:
            _nx_major, _nx_minor = 1, 18

        if _nx_major > 1 or (_nx_major == 1 and _nx_minor >= 25):
            # nginx ≥ 1.25: новая директива http2 on;
            _http2_line = "    http2 on;"
            _listen_tls = f"listen {SERVER_PORT} ssl;"
            _listen_tls_v6 = f"listen [::]:{SERVER_PORT} ssl;" if core.IS_IPV6_AVAILABLE else ""
        else:
            # nginx < 1.25: http2 указывается в строке listen
            _http2_line = ""
            _listen_tls = f"listen {SERVER_PORT} ssl http2;"
            _listen_tls_v6 = f"listen [::]:{SERVER_PORT} ssl http2;" if core.IS_IPV6_AVAILABLE else ""

        # Нормализуем path: ведущий слэш обязателен, без trailing slash (кроме корня).
        _xhttp_path = (XHTTP_PATH or "/").strip()
        if not _xhttp_path.startswith("/"):
            _xhttp_path = "/" + _xhttp_path
        _xhttp_path = _xhttp_path.rstrip("/") or "/"

        # Nginx location для xHTTP path. Используем префиксный матч (без знака =),
        # чтобы Nginx передавал upstream оригинальный URI с query-string.
        # proxy_pass без URI → Nginx передаёт запрос как есть (нужно для xHTTP).
        _backend = f"127.0.0.1:{XHTTP_BACKEND_PORT}"

        info(f"xHTTP TLS: Nginx терминирует TLS на :{SERVER_PORT}, "
             f"заглушка для /, проксирование {_xhttp_path} → http://{_backend}")

        cfg = NGINX_CONF_DIR / PARAM_DOMAIN
        cfg.write_text(textwrap.dedent(f"""\
            # =============================================================================
            # VLESS + xHTTP + TLS — Nginx → Xray (loopback backend)
            #
            # Xray-core НЕ поддерживает fallbacks для xHTTP (задокументированное
            # ограничение). Поэтому:
            #   • Nginx терминирует TLS на :{SERVER_PORT}, отдаёт сайт-заглушку для /
            #   • xHTTP path ({_xhttp_path}) проксируется на Xray 127.0.0.1:{XHTTP_BACKEND_PORT}
            #     (security: none — TLS уже расшифрован Nginx)
            # =============================================================================

            # HTTP → HTTPS redirect
            server {{
                listen 80;
                listen [::]:80;
                server_name {PARAM_DOMAIN};
                location /.well-known/acme-challenge/ {{ root {web_root}; }}
                location / {{ return 301 https://$host$request_uri; }}
            }}

            # Main HTTPS server: сайт-заглушка + reverse-proxy на Xray для xHTTP path
            server {{
                {_listen_tls}
                {_listen_tls_v6}
            {_http2_line}
                server_name {PARAM_DOMAIN};

                ssl_certificate     /etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem;
                ssl_certificate_key /etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
                ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
                ssl_prefer_server_ciphers on;
                ssl_session_cache shared:SSL:10m;
                ssl_session_timeout 1h;

                root {web_root};
                index index.html;

                add_header X-Robots-Tag "noindex, nofollow" always;

                # ── xHTTP path → Xray backend (loopback) ─────────────────────────
                # ВАЖНО для stream-up / packet-up режимов xHTTP:
                #   • proxy_http_version 1.1 + Connection "" — keep-alive к upstream
                #   • proxy_request_buffering off — НЕ буферизовать тело POST
                #     (иначе стриминг ломается и CDN/middlebox рвёт соединение)
                #   • proxy_buffering off — отдавать ответ клиенту сразу
                #   • proxy_read_timeout / send_timeout = 1h — длинные стримы
                #   • proxy_max_temp_file_size 0 — без буферизации на диск
                location {_xhttp_path} {{
                    proxy_pass http://{_backend};
                    proxy_http_version 1.1;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_set_header Connection "";
                    proxy_request_buffering off;
                    proxy_buffering off;
                    proxy_max_temp_file_size 0;
                    proxy_read_timeout 3600s;
                    proxy_send_timeout 3600s;
                    proxy_connect_timeout 60s;
                }}

                # ── Заглушка: сайт отдаётся для всех прочих путей ─────────────────
                location / {{
                    try_files $uri $uri/ =404;
                }}
            }}

            # Default server: reject all other SNI (аналог REALITY-режима)
            server {{
                listen {SERVER_PORT} ssl default_server;
                {"listen [::]:" + str(SERVER_PORT) + " ssl default_server;" if core.IS_IPV6_AVAILABLE else ""}
                server_name _;
                ssl_reject_handshake on;
            }}
        """))
        link = NGINX_ENABLED_DIR / PARAM_DOMAIN
        link.unlink(missing_ok=True)
        link.symlink_to(cfg)
        r = _run([_xhttp_nginx_bin, "-t"], capture=True, check=False)
        if r.returncode == 0:
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            success(f"Nginx настроен (xHTTP TLS: заглушка + proxy / → http://{_backend})")
        else:
            log_to_file("WARN", r.stderr or "")
            _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
            success("Nginx перезапущен (xHTTP TLS режим)")
        return

    # === AWG 2.0 + REALITY: Xray слушает на PORT напрямую, Nginx только HTTP→HTTPS ===
    if AWG_EXIT_ENABLED:
        info(f"AWG 2.0: Xray слушает на :{SERVER_PORT} напрямую, Nginx — только HTTP→HTTPS редирект")
        web_root = Path(f"/var/www/{PARAM_DOMAIN}")
        cfg = NGINX_CONF_DIR / PARAM_DOMAIN
        cfg.write_text(textwrap.dedent(f"""\
            # HTTP → HTTPS redirect (AWG 2.0 — Xray слушает :{SERVER_PORT} напрямую)
            server {{
                listen 80;
                listen [::]:80;
                server_name {PARAM_DOMAIN};
                root {web_root};
                index index.html;
                location /.well-known/acme-challenge/ {{ root {web_root}; }}
                location / {{ return 301 https://$host$request_uri; }}
            }}
        """))
        link = NGINX_ENABLED_DIR / PARAM_DOMAIN
        link.unlink(missing_ok=True)
        link.symlink_to(cfg)
        _nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"
        r = _run([_nginx_bin, "-t"], capture=True, check=False)
        if r.returncode == 0:
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
        else:
            # Hardening (v4.20.3): unlink symlink ДО restart — иначе restart с
            # битым конфигом кладёт весь nginx (включая рабочие VLESS-сайты).
            try:
                link.unlink()
            except Exception:
                pass
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            warn(f"nginx -t упал для AWG vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен")
        success(f"Nginx настроен (только HTTP→HTTPS редирект для AWG, Xray владеет :{SERVER_PORT})")
        return

    # === REALITY: стандартный конфиг через Unix-сокет (VLESS) ===
    # Эта ветка выполняется только для VLESS install flow (без явных port/
    # socket_path). Own-site TCP-режим обработан и return-ут выше.
    _nginx_bin = find_nginx_bin() or "/usr/sbin/nginx"
    try:
        r = _run([_nginx_bin, "-v"], capture=True, check=False)
        m = re.search(r'(\d+)\.(\d+)\.(\d+)', r.stderr)
        nginx_major = int(m.group(1)) if m else 1
        nginx_minor = int(m.group(2)) if m else 18
        nginx_ver   = f"{nginx_major}.{nginx_minor}.{m.group(3) if m else 0}"
    except Exception:
        nginx_major, nginx_minor, nginx_ver = 1, 18, "1.18.0"

    # === FIX ROOT: xver=1 в классическом REALITY → Xray посылает Proxy Protocol header.
    # Nginx должен иметь proxy_protocol в listen — это согласовано с xver=1.
    # В AWG-режиме xver=0 и Nginx вообще не проксирует на socket (только HTTP→HTTPS),
    # поэтому этот блок выполняется только для классического режима. ===
    if nginx_major > 1 or (nginx_major == 1 and nginx_minor >= 25):
        listen_main    = f"listen unix:{PARAM_SOCKET_PATH} ssl proxy_protocol;"
        listen_default = f"listen unix:{PARAM_SOCKET_PATH} ssl proxy_protocol default_server;"
        http2_line     = "    http2 on;"
        info(f"Nginx {nginx_ver}: директива 'http2 on' (proxy_protocol согласован с xver=1)")
    else:
        listen_main    = f"listen unix:{PARAM_SOCKET_PATH} ssl http2 proxy_protocol;"
        listen_default = f"listen unix:{PARAM_SOCKET_PATH} ssl http2 proxy_protocol default_server;"
        http2_line     = ""
        info(f"Nginx {nginx_ver}: http2 в строке listen (proxy_protocol согласован с xver=1)")
    # === END FIX ROOT ===

    rate_limit = ""
    if NGINX_RATE_LIMIT_CONF.exists():
        rate_limit = ("    limit_req zone=general burst=20 nodelay;\n"
                      "    limit_conn conn_limit 10;")

    # ssl_reject_handshake поддерживается только начиная с nginx 1.19.4.
    # На более старых версиях используем fallback: явный сертификат + return 444.
    # ВАЖНО: вычисляем строку ЗАРАНЕЕ, отдельной переменной — нельзя класть
    # f-string внутрь другого f-string (тернарник на {PARAM_DOMAIN} ломает
    # парсер на вложенных фигурных скобках, см. CHANGELOG).
    if nginx_major > 1 or (nginx_major == 1 and nginx_minor >= 19):
        default_server_ssl = "ssl_reject_handshake on;"
    else:
        default_server_ssl = (
            f"ssl_certificate     /etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem;\n"
            f"            ssl_certificate_key /etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem;\n"
            f"            return 444;"
        )

    cfg = NGINX_CONF_DIR / PARAM_DOMAIN
    cfg.write_text(textwrap.dedent(f"""\
        # HTTP → HTTPS redirect
        server {{
            listen 80;
            listen [::]:80;
            server_name {PARAM_DOMAIN};
            return 301 https://$host$request_uri;
        }}

        # Main server: VLESS fallback via Unix socket
        server {{
            server_name {PARAM_DOMAIN};

            {listen_main}
        {http2_line}

            ssl_certificate     /etc/letsencrypt/live/{PARAM_DOMAIN}/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/{PARAM_DOMAIN}/privkey.pem;
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
            ssl_prefer_server_ciphers on;

            real_ip_header proxy_protocol;
            set_real_ip_from unix:;

            root {web_root};
            index index.html;

            add_header X-Robots-Tag "noindex, nofollow" always;
        {rate_limit}

            location / {{
                try_files $uri $uri/ =404;
            }}
        }}

        # Default server: reject all other SNI
        # ssl_reject_handshake поддерживается только начиная с nginx 1.19.4
        server {{
            {listen_default}
            server_name _;
            {default_server_ssl}
        }}
    """))

    # Создаём временный unix-сокет если нет
    sock_path = Path(PARAM_SOCKET_PATH)
    sock_parent = sock_path.parent
    sock_parent.mkdir(parents=True, exist_ok=True)
    if not sock_path.exists():
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(str(sock_path))
            s.close()
            info("Создан временный unix-сокет для nginx -t")
        except Exception:
            pass

    link = NGINX_ENABLED_DIR / PARAM_DOMAIN
    link.unlink(missing_ok=True)
    link.symlink_to(cfg)

    r = _run([_nginx_bin, "-t"], capture=True, check=False)
    log_to_file("INFO", r.stderr)

    if r.returncode == 0:
        r_active = _run(["systemctl", "is-active", "nginx"], capture=True, check=False)
        if r_active.stdout.strip() == "active":
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
        success(f"Nginx финально настроен (Nginx {nginx_ver})")
    else:
        # Hardening (v4.20.3): unlink symlink ДО restart/reload — иначе restart
        # с битым конфигом кладёт весь nginx. Для REALITY-ветки это особенно
        # критично: unix-сокет создаётся искусственно выше, и при ошибке
        # сокет-пути restart может уронить уже работавший VLESS REALITY fallback.
        try:
            link.unlink()
        except Exception:
            pass
        _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
        warn("nginx -t: проверка с временным сокетом (предупреждение ожидаемо):")
        for line in r.stderr.splitlines()[-5:]:
            warn(f"  {line}")
        info(f"Симлинк {PARAM_DOMAIN} удалён. Nginx будет запущен до Xray (финальный шаг установки)")

    # Удаляем временный сокет; финальный старт nginx — до xray
    sock_path.unlink(missing_ok=True)
    _run(["systemctl", "stop", "nginx"], check=False, quiet=True)

# =============================================================================
#  ШАГ 12.1: NGINX SYSTEMD OVERRIDE
# =============================================================================
def setup_nginx_systemd_override() -> None:
    core = _core_module()
    info = core.info
    success = core.success
    _run = core._run
    PROTOCOL_MODE = core.PROTOCOL_MODE
    PARAM_USE_DNSCRYPT = core.PARAM_USE_DNSCRYPT
    info("Настройка зависимости Nginx → Xray в systemd...")
    override_dir = Path("/etc/systemd/system/nginx.service.d")
    override_dir.mkdir(parents=True, exist_ok=True)

    # При xHTTP (любой режим — A, B+AWG, B+H2, B+exit-ноды) Nginx проксирует
    # xhttp path на 127.0.0.1:XHTTP_BACKEND_PORT. Стартуем после Xray, чтобы
    # 502 не появлялся при одновременном старте.
    if PROTOCOL_MODE == "xhttp":
        content = textwrap.dedent("""\
            [Unit]
            After=network.target xray.service
            Wants=xray.service
        """)
        msg = "Nginx: запуск после Xray (xHTTP TLS — Nginx проксирует на loopback backend)"
    elif PARAM_USE_DNSCRYPT:
        # REALITY: xray создаёт сокет, nginx к нему подключается.
        # Nginx стартует ПОСЛЕ xray и dnscrypt.
        content = textwrap.dedent("""\
            [Unit]
            After=xray.service dnscrypt-proxy.service
            Wants=xray.service dnscrypt-proxy.service
        """)
        msg = "Nginx будет запускаться после Xray и DNSCrypt-proxy (systemd override)"
    else:
        # REALITY: xray создаёт unix-сокет, nginx к нему подключается.
        content = textwrap.dedent("""\
            [Unit]
            After=xray.service
            Wants=xray.service
        """)
        msg = "Nginx будет запускаться после Xray (systemd override)"

    (override_dir / "after-xray.conf").write_text(content)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    success(msg)
