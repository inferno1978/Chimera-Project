"""
chimera/modules/nginx_setup.py
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
    from chimera.modules.nginx_setup import (
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

# 15 анимированных многостраничных шаблонов сайтов-заглушек.
# См. chimera/modules/nginx_setup_templates.py для полного списка.
from chimera.modules.nginx_setup_templates import (
    build_template as _build_template,
    get_template_names as _get_template_names,
    create_techhub as _tmpl_create_techhub,
    create_nexcloud as _tmpl_create_nexcloud,
)


# ── Sentinel для различения "не передан" от "передан None" ───────────────────
# Нужно для параметров port/socket_path в setup_nginx_final():
#   • VLESS install flow вызывает без аргументов → должны inherit из core
#   • Telemt own-site вызывает socket_path=None явно → должны использовать TCP
# Обычный default=None не различает эти два случая — sentinel решает.
_UNSET = object()


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


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
    # 0 (или любое невалидное значение) → fallback на NexCloud (template #2),
    # как и в предыдущей версии. Иначе — один из 15 шаблонов.
    if tmpl < 1 or tmpl > 15:
        tmpl = 2
    _build_template(tmpl, web_root)

    (web_root / "robots.txt").write_text("User-agent: *\n")
    try:
        _run(["chown", "-R", "www-data:www-data", str(web_root)], check=False, quiet=True)
    except Exception:
        pass
    success(f"Сайт создан в {web_root}")


# ── Backward-compat shims ────────────────────────────────────────────────────
# Старые имена _create_techhub / _create_nexcloud / _create_simple_site
# импортируются в _core.py (строка ~268). Делегируем в новый модуль шаблонов,
# чтобы не ломать существующие импорты и тесты.
#
# Полная реализация 15 шаблонов живёт в
# chimera/modules/nginx_setup_templates.py — каждая функция пишет
# style.css + index.html + 4 подстраницы с рабочей навигацией между ними.
def _create_techhub(web_root: Path) -> None:
    """Шаблон #1 — TechHub (IT-портал, RU). Делегирует в nginx_setup_templates."""
    _tmpl_create_techhub(web_root)


def _create_nexcloud(web_root: Path) -> None:
    """Шаблон #2 — NexCloud (SaaS). Делегирует в nginx_setup_templates."""
    _tmpl_create_nexcloud(web_root)


def _create_simple_site(
    web_root: Path, site_name: str, tagline: str,
    bg: str, accent: str, muted: str,
) -> None:
    """Старая сигнатура (web_root, site_name, tagline, bg, accent, muted).

    Сохранена для обратной совместимости со старым кодом, который мог вызывать
    эту функцию напрямую. Цвета/таглайн игнорируются — вместо этого выбирается
    один из 15 новых анимированных шаблонов по имени site_name:
        "Holm & Oak"     → шаблон #3
        "Ember & Grain"  → шаблон #4
        "NexHub"         → шаблон #5
        "ByteForge"      → шаблон #6
        прочее           → шаблон #2 (NexCloud) как fallback
    """
    _name_to_idx = {
        "Holm & Oak":    3,
        "Ember & Grain": 4,
        "NexHub":        5,
        "ByteForge":     6,
    }
    idx = _name_to_idx.get(site_name, 2)
    _build_template(idx, web_root)

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


# =============================================================================
#  _cleanup_stale_chimera_vhosts — удаление старых Chimera vhost при смене домена
# =============================================================================
#  ВАЖНАЯ ИСТОРИЯ ФИКСА:
#  Раньше setup_nginx_temp/final создавали новый vhost-файл для нового домена,
#  но НЕ удаляли старый. При установке поверх (смене домена) в sites-enabled/
#  оставались два vhost-а с одинаковым listen 443 → nginx падал с
#  «duplicate listen options for 0.0.0.0:443» либо один из vhost-ов тихо
#  игнорировался.
#
#  ФИКС: перед созданием нового vhost сканируем sites-available/ и sites-enabled/,
#  находим все Chimera-конфиги (по маркерам proxy_protocol/xver/realpath//dev/shm/),
#  и удаляем те, что не совпадают с новым доменом.
#
#  ВАЖНО: не трогаем:
#    • sites-available/default (это стандартный vhost Ubuntu/Debian, не наш)
#    • sites-available/chimera-portal-nginx (Portal front — отдельная фича)
#    • sites-available/chimera-telemt-panel-nginx (Telemt front — отдельная фича)
#    • Любые чужие vhost-ы без Chimera-маркеров
# =============================================================================
def _cleanup_stale_chimera_vhosts(new_domain: str) -> int:
    """Удаляет старые Chimera VLESS vhost-файлы при смене домена.

    Возвращает количество удалённых файлов (для логирования).
    Безопасна: не трогает default, chimera-portal-nginx, chimera-telemt-panel-nginx,
    и любые vhost-ы без явных Chimera-маркеров (proxy_protocol, /dev/shm/, xver).
    """
    core = _core_module()
    info = core.info
    NGINX_CONF_DIR = core.NGINX_CONF_DIR
    NGINX_ENABLED_DIR = core.NGINX_ENABLED_DIR

    # Список имён, которые НИКОГДА не удаляем (это другие фичи Chimera или default).
    PROTECTED_NAMES = {
        "default",
        "chimera-portal-nginx",
        "chimera-telemt-panel-nginx",
    }

    # Маркеры, по которым отличаем Chimera VLESS vhost от чужого.
    # proxy_protocol — используется в REALITY (xver=1).
    # /dev/shm/ — путь unix-сокета, который Chimera генерирует автоматически.
    # xver — директива Proxy Protocol, используется в REALITY inbound.
    # realpath — нестандартная директива, может встретиться в старых конфигах.
    CHIMERA_MARKERS = ("proxy_protocol", "/dev/shm/", "xver", "realpath")

    removed = 0
    for site_dir in (NGINX_CONF_DIR, NGINX_ENABLED_DIR):
        if not site_dir.exists():
            continue
        for f in site_dir.iterdir():
            # Пропускаем скрытые файлы (.swp, .bak) и директории.
            if f.name.startswith(".") or f.is_dir():
                continue
            # Пропускаем защищённые имена (default, portal, telemt).
            if f.name in PROTECTED_NAMES:
                continue
            # Пропускаем новый домен (его только что создали / создадим).
            if f.name == new_domain:
                continue
            # Для симлинка — resolve() к target. Если target уже удалён
            # (предыдущей итерацией по sites-available), это висячий symlink —
            # удаляем безусловно, это мусор от предыдущей установки.
            target = f
            if f.is_symlink():
                try:
                    target = f.resolve()
                except Exception:
                    target = f
                if not target.exists():
                    try:
                        f.unlink()
                        removed += 1
                        info(f"  Удалён висячий симлинк Chimera: {f}")
                    except Exception:
                        pass
                    continue
            # Читаем содержимое файла (или target'а симлинка).
            try:
                content = target.read_text() if target.is_file() else ""
            except Exception:
                continue
            # Если нет ни одного Chimera-маркера — это чужой vhost, не трогаем.
            if not any(m in content for m in CHIMERA_MARKERS):
                continue
            # Это Chimera vhost от старого домена — удаляем.
            try:
                f.unlink()
                removed += 1
                info(f"  Удалён старый Chimera vhost: {f}")
            except Exception:
                pass
    return removed


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

    # FIX: удаляем старые Chimera vhost-файлы от предыдущих установок.
    # Без этого при установке поверх (смена домена) в sites-enabled остаются
    # два vhost-а с одинаковым listen 443 → nginx падает с duplicate listen.
    # Безопасно: не трогает default, portal-nginx, telemt-nginx, чужие сайты.
    try:
        _removed_count = _cleanup_stale_chimera_vhosts(PARAM_DOMAIN)
        if _removed_count > 0:
            success(f"  Удалено {_removed_count} старых Chimera vhost-ов "
                    f"(не {PARAM_DOMAIN})")
    except Exception as _e:
        warn(f"  Очистка старых vhost-ов пропущена: {_e}")

    cfg = NGINX_CONF_DIR / PARAM_DOMAIN
    cfg.write_text(textwrap.dedent(f"""\
        server {{
            listen 80;
            {f"listen [::]:80;" if core.IS_IPV6_AVAILABLE else ""}
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
        # v4.20.6: явный вывод stderr — раньше просто info("Nginx перезапущен")
        # без указания что nginx -t упал. Для certbot ACME это критично: если
        # временный vhost не валиден, certbot не сможет выпустить сертификат.
        warn(f"Nginx -t упал для временного vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен:")
        for _err_line in (r.stderr or "").splitlines()[-10:]:
            warn(f"  {_err_line}")

# =============================================================================
#  ШАГ 11: SSL СЕРТИФИКАТ
# =============================================================================
# (obtain_ssl_cert, fix_letsencrypt_permissions вынесены в
#  chimera.modules.ssl_certbot; импорт — в верхней секции _core.py.)

def setup_nginx_final(domain: Optional[str] = None,
                      port=_UNSET,
                      socket_path=_UNSET,
                      protocol_mode: Optional[str] = None,
                      awg_exit_enabled: Optional[bool] = None,
                      site_template: Optional[str] = None,
                      cdn_masking_mode: bool = False) -> None:
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

    cdn_masking_mode=True (новый параметр, по умолч. False) — активирует
    профиль «CDN masking» для XHTTP. В этом режиме:
      • path берётся из xhttp_path_gen.generate_decoy_path() (через
        core.XHTTP_PATH, который выставляет скрытое меню);
      • вместо create_website() вызывается create_fake_login() —
        одностраничная заглушка «Доступ к серверу» с капчей (шаблон #16);
      • reverse-proxy направляется на 127.0.0.1:CDN_MASKING_INBOUND_PORT
        (7443, отдельный от стандартного 8443);
      • Nginx-конфиг содержит доп. настройки для безбуферного стриминга
        и долгих таймаутов, критичные для CDN edge.
    Профиль НЕ затрагивает текущий простой XHTTP-режим — только ветка
    `if cdn_masking_mode and PROTOCOL_MODE == "xhttp"`. Дефолтное поведение
    (без параметра) полностью сохранено.
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

    # ── CDN masking: если профиль активен, берём port из CDN_MASKING_INBOUND_PORT
    #    и используем create_fake_login вместо create_website. Не затрагивает
    #    простой XHTTP-режим — только ветка cdn_masking_mode=True.
    if cdn_masking_mode:
        try:
            from chimera.modules.xhttp_cdn_masking import CDN_MASKING_INBOUND_PORT
            XHTTP_BACKEND_PORT = CDN_MASKING_INBOUND_PORT   # 7443
        except ImportError:
            pass  # fallback на стандартный 8443 если модуль недоступен

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

    # ── CDN masking: используем fake-login заглушку вместо обычного сайта ──
    # Профиль CDN masking требует одностраничную заглушку «Доступ к серверу»
    # с капчей (create_fake_login, шаблон #16). Не затрагивает стандартный
    # выбор шаблонов 1..15 — только ветка cdn_masking_mode=True.
    if cdn_masking_mode:
        try:
            from chimera.modules.nginx_setup_templates import create_fake_login
            web_root.mkdir(parents=True, exist_ok=True)
            create_fake_login(web_root)
            info(f"CDN masking: установлена fake-login заглушка → {web_root}/index.html")
        except ImportError as _e:
            warn(f"CDN masking: не удалось импортировать create_fake_login: {_e}")
            create_website(domain=PARAM_DOMAIN, site_template=site_template)
    else:
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
                {f"listen [::]:80;" if core.IS_IPV6_AVAILABLE else ""}
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
            # v4.20.7: reload — async операция. systemd отправляет SIGHUP и сразу
            # возвращает управление, nginx пере-читает конфиг и поднимает новый
            # worker с новым listener за 1-3 сек. Если _check_mask_backend_ready
            # вызывается сразу после reload — TCP-connect падает (listener ещё
            # не готов) → guard откатывает в donor-режим. sleep(2) даёт nginx
            # время поднять listener.
            _run(["systemctl", "reload", "nginx"], check=False, quiet=True)
            import time as _time
            _time.sleep(2)
            # Проверяем что listener реально поднялся. Если нет — reload мог
            # молча провалиться (например nginx в degraded state). Пробуем restart.
            _listener_check = _run(["ss", "-tlnH"], capture=True, check=False, quiet=True)
            if f"127.0.0.1:{SERVER_PORT}" not in (_listener_check.stdout or ""):
                info(f"reload не поднял listener на 127.0.0.1:{SERVER_PORT}, пробую restart...")
                _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
                _time.sleep(3)
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
            # v4.20.6: явный вывод stderr в warn — раньше quiet=True глотал ошибку,
            # пользователь не видел почему nginx -t упал (например unknown directive
            # "http2" на nginx < 1.25). Теперь stderr выводится полностью.
            warn(f"nginx -t упал для own-site vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен.")
            for _err_line in (r.stderr or "").splitlines()[-10:]:
                warn(f"  {_err_line}")
            warn(f"Проверьте вручную: {_os_nginx_bin} -t")
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

        # ── CDN masking: доп. настройки для корректной работы через CDN edge ─
        # ВАЖНО: nginx-директивы имеют разные допустимые контексты.
        # Согласно документации nginx:
        #   • large_client_header_buffers — context: http (НЕ location!)
        #   • underscores_in_headers       — context: http, server (НЕ location!)
        #   • proxy_send_timeout          — context: http, server, location
        #   • proxy_read_timeout          — context: http, server, location
        #   • proxy_next_upstream          — context: http, server, location
        #   • proxy_next_upstream_tries    — context: http, server, location
        # Поэтому large_client_header_buffers и underscores_in_headers кладём
        # в server {} блок, остальное — в location {} блок.
        #
        # large_client_header_buffers — для больших padding-заголовков XHTTP.
        # underscores_in_headers on — XHTTP использует кастомные заголовки вида
        #   X-Api-Key, и без этой директивы nginx их молча dropped бы.
        #
        # ИСТОРИЯ ФИКСОВ (честная, не переписываем):
        # • Коммит 1b434e3 перенёс large_client_header_buffers из location в
        #   server, но использовал textwrap.dedent() который при вставке в
        #   f-string с отступами ломал indentation — директива оказывалась
        #   в column 0, и nginx терял контекст server{}.
        # • Коммит fcb0cab объяснил падение "unknown directive underscores_in_headers"
        #   тем, что "этой директивы нет на кастомных сборках". Это объяснение
        #   было НЕВЕРНЫМ — underscores_in_headers часть ngx_http_core_module,
        #   всегда есть в stock nginx.
        # • Коммит 648aebc вернул underscores_in_headers и исправил отступы
        #   (убрал textwrap.dedent, использовал явные строки). Но ВЫЯСНИЛОСЬ,
        #   что настоящая причина "unknown directive" была не в отступах —
        #   а в ОПЕЧАТКЕ: директива называется underscores_in_headers (с "s"
        #   после "underscore", множественное число), а в коде была опечатка
        #   "underscores_in_headers" (без "s"). nginx не знает директивы
        #   "underscores_in_headers" вообще ни в каком контексте — отсюда
        #   "unknown directive", а не "not allowed here".
        # • Этот коммит исправляет опечатку: underscores_in_headers →
        #   underscores_in_headers во всём коде, тестах, скриптах.
        #   Проверено на реальном nginx/1.24.0: underscores_in_headers on;
        #   → syntax is ok. underscores_in_headers on; → unknown directive.
        #   Урок: 20 "зелёных" тестов не поймали опечатку, потому что ни
        #   один не сверялся с реальным поведением nginx — тесты искали ту
        #   же опечатку, что и код.
        #
        # proxy_*_timeout — для CDN masking ставим 86400s (24 часа), т.к.
        #   CDN edge может держать long-polling соединение очень долго.
        #   Для обычного XHTTP — 3600s (1 час, как было раньше).
        #   Раньше proxy_*_timeout дублировался: один раз в безусловной части
        #   location-блока (3600s), второй раз в _cdn_location_extras (86400s).
        #   Теперь — единая _proxy_timeout переменная, дублирования нет.
        _proxy_timeout = "86400s" if cdn_masking_mode else "3600s"
        _cdn_server_extras = ""   # для server {} блока
        _cdn_location_extras = ""  # для location {} блока
        if cdn_masking_mode:
            # Явные строки с правильными отступами (16 пробелов = уровень server).
            # НЕ используем textwrap.dedent() — он ломает отступы при вставке
            # в f-string. Каждая строка явно имеет 16-пробельный отступ.
            _cdn_server_extras = (
                "                # ── CDN masking: server-level настройки для Beeline/CF CDN edge ──\n"
                "                large_client_header_buffers 8 32k;\n"
                "                underscores_in_headers on;\n"
            )
            # 20 пробелов = уровень location (location на 16, содержимое на 20).
            _cdn_location_extras = (
                "                    # ── CDN masking: location-level настройки ───────────────────\n"
                "                    proxy_next_upstream off;\n"
                    "                    proxy_next_upstream_tries 1;\n"
            )

        info(f"xHTTP TLS: Nginx терминирует TLS на :{SERVER_PORT}, "
             f"заглушка для /, проксирование {_xhttp_path} → http://{_backend}"
             + (f" (CDN masking)" if cdn_masking_mode else ""))

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
                {f"listen [::]:80;" if core.IS_IPV6_AVAILABLE else ""}
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
{_cdn_server_extras}
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
                    proxy_read_timeout {_proxy_timeout};
                    proxy_send_timeout {_proxy_timeout};
                    proxy_connect_timeout 60s;
{_cdn_location_extras}                }}

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
            # v4.20.6: явный вывод stderr — раньше просто success("Nginx перезапущен")
            # без указания что nginx -t упал, пользователь не видел ошибку.
            warn(f"nginx -t упал для xHTTP vhost {PARAM_DOMAIN}:")
            for _err_line in (r.stderr or "").splitlines()[-10:]:
                warn(f"  {_err_line}")
            _run(["systemctl", "restart", "nginx"], check=False, quiet=True)
            warn("nginx перезапущен в xHTTP TLS режиме (проверьте конфиг вручную)")
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
                {f"listen [::]:80;" if core.IS_IPV6_AVAILABLE else ""}
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
            # v4.20.6: явный вывод stderr — раньше warn без деталей.
            warn(f"nginx -t упал для AWG vhost {PARAM_DOMAIN}; симлинк удалён, nginx не перезапущен:")
            for _err_line in (r.stderr or "").splitlines()[-10:]:
                warn(f"  {_err_line}")
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
        # HTTP → HTTPS redirect (+ ACME-челлендж для certbot renew)
        # ВАЖНО: return 301 обязан быть ВНУТРИ location /, а не на уровне
        # server: server-level return выполняется ДО выбора location и
        # редиректит и /.well-known/acme-challenge/ → renew падает с
        # "Some challenges have failed" (инцидент 02.10.2026, нода 138.х).
        server {{
            listen 80;
            {f"listen [::]:80;" if core.IS_IPV6_AVAILABLE else ""}
            server_name {PARAM_DOMAIN};
            location /.well-known/acme-challenge/ {{ root {web_root}; }}
            location / {{ return 301 https://$host$request_uri; }}
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
        # ВНИМАНИЕ: этот else-блок НЕ подлежит hardening "unlink symlink при
        # nginx -t failure" (который применяется в 3 других местах nginx_setup.py).
        # Здесь провал nginx -t — это ЗАПЛАНИРОВАННОЕ состояние на каждой
        # свежей VLESS REALITY-установке: конфиг тестируется через ВРЕМЕННЫЙ
        # unix-сокет (socket.bind()+close() выше, строка ~878), который НИЧЕГО
        # не слушает — Xray, который реально принимает соединения на этом сокете,
        # ещё не запущен. Реальный сокет появится позже, nginx стартует "до Xray"
        # на финальном шаге установки, за пределами этой функции.
        # Если здесь удалить symlink (как делает hardening v4.20.3 в других
        # ветках), то при финальном старте nginx VLESS-сайта уже не будет в
        # sites-enabled — ломается каждая свежая REALITY-установка.
        # Симлинк ДОЛЖЕН остаться, nginx стартует позже на финальном шаге.
        warn("nginx -t: проверка с временным сокетом (предупреждение ожидаемо):")
        for line in r.stderr.splitlines()[-5:]:
            warn(f"  {line}")
        info("Nginx будет запущен до Xray (финальный шаг установки)")

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
