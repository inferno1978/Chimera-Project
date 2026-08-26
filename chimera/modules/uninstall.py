"""
chimera/modules/uninstall.py
───────────────────────────────────────────────────────────────────────────────
Полное удаление VLESS Reality + связанных компонентов.

Одна функция:

• **do_uninstall** — интерактивное удаление Xray, Nginx, сайта, правил UFW,
  DNSCrypt-proxy и т.д. Перед удалением требует подтверждение доменом.

Точки входа из _core.py:
    from chimera.modules.uninstall import do_uninstall

Доступ к helpers ядра (_box_*, die, _run, CONFIG_DIR, XRAY_BIN, XRAY_SERVICE,
DNSCRYPT_BIN, DNSCRYPT_CONF_DIR, DNSCRYPT_SERVICE, PKG_MGR, цвета YELLOW/RED/NC)
— через importlib (lazy binding), как и в других извлечённых модулях
(warp.py, smart_balancer.py, failover.py, standalone_screens.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


# =============================================================================
#  ЗАКРЫТИЕ ПОРТОВ УДАЛЯЕМЫХ СЕРВИСОВ (UFW + port_registry, v49)
# =============================================================================
def _close_chimera_ports() -> list:
    """Закрывает UFW-правила и снимает регистрацию портов удаляемых сервисов.

    v49: do_uninstall обещал «правила UFW» в баннере, но не закрывал ничего —
    orphaned allow-правила и записи port_registry оставались жить после
    полного удаления стека.

    Закрывает: SERVICE_VLESS (КРОМЕ 22/tcp — SSH, иначе lockout),
    SERVICE_DNSCRYPT (dnscrypt удаляется), SERVICE_AGHOME* (если AGH стоит —
    его upstream dnscrypt удаляется, стек мёртв).
    Возвращает список строк для вывода пользователю.
    """
    lines: list = []
    try:
        from chimera.modules.port_registry import (
            port_unregister, ufw_close_port, port_list_for_service,
            SERVICE_VLESS, SERVICE_DNSCRYPT, SERVICE_AGHOME,
            SERVICE_AGHOME_WEB, SERVICE_AGHOME_DOH, SERVICE_AGHOME_DOT,
            SERVICE_AGHOME_DOQ,
        )
    except Exception as e:
        return [f"port_registry недоступен: {e} — порты закрыты не были"]

    def _close_tag(tag: str, keep_ports: frozenset = frozenset()) -> int:
        closed = 0
        try:
            entries = port_list_for_service(tag)
        except Exception:
            entries = []
        for e in entries:
            try:
                port = int(e.get("port", 0))
                proto = str(e.get("proto", "tcp"))
            except Exception:
                continue
            if not port:
                continue
            if port in keep_ports:
                # правило UFW НЕ трогаем (SSH!), запись реестра снимаем
                port_unregister(tag, port=port, proto=proto)
                lines.append(f"  {tag}: {port}/{proto} — правило UFW оставлено (SSH)")
                continue
            try:
                ufw_close_port(port, proto, tag,
                               legacy_comments=["VLESS", "SSH",
                                                "HTTP (certbot ACME)",
                                                "VLESS reconfigure"])
                port_unregister(tag, port=port, proto=proto)
                closed += 1
            except Exception:
                pass
        if closed:
            lines.append(f"  {tag}: закрыто портов — {closed}")
        return closed

    _close_tag(SERVICE_VLESS, keep_ports=frozenset({22}))
    _close_tag(SERVICE_DNSCRYPT)

    # AGH стоит? его upstream (dnscrypt) удаляется — останавливаем и его
    try:
        if Path("/opt/AdGuardHome/AdGuardHome").exists():
            import subprocess as _sp
            _sp.run(["systemctl", "stop", "AdGuardHome"],
                    capture_output=True, check=False)
            _sp.run(["systemctl", "disable", "AdGuardHome"],
                    capture_output=True, check=False)
            for tag in (SERVICE_AGHOME, SERVICE_AGHOME_WEB,
                        SERVICE_AGHOME_DOH, SERVICE_AGHOME_DOT,
                        SERVICE_AGHOME_DOQ):
                _close_tag(tag)
            lines.append("  AdGuardHome остановлен и отключён "
                         "(upstream dnscrypt удалён)")
    except Exception:
        pass

    # Дефицит записей: чистим всё, что могло остаться под этими тегами
    for tag in (SERVICE_VLESS, SERVICE_DNSCRYPT, SERVICE_AGHOME,
                SERVICE_AGHOME_WEB, SERVICE_AGHOME_DOH, SERVICE_AGHOME_DOT,
                SERVICE_AGHOME_DOQ):
        try:
            port_unregister(tag)
        except Exception:
            pass
    return lines


def _restore_dns_after_full_uninstall() -> list:
    """DNS-ALIVE при полном удалении: resolv.conf → внешний DNS из бэкапа.

    do_uninstall удаляет dnscrypt (и, возможно, останавливает AGH) —
    системный DNS (127.0.0.1) умирает. Восстанавливаем бэкап resolv.conf
    и гасим chimera-dns-fix/watchdog (иначе watchdog каждую минуту будет
    пытаться оживить удалённый dnscrypt и переоткрывать redirect).
    """
    lines: list = []
    try:
        from chimera.modules import resolv_conf_fix as rcf
        # 1. watchdog + persist OFF (реанимация мёртвого стека недопустима)
        try:
            rcf._remove_dns_watchdog()
            lines.append("  chimera-dns-watchdog остановлен и удалён")
        except Exception:
            pass
        try:
            rcf._disable_persist_service()
            lines.append("  chimera-dns-fix.service остановлен и удалён")
        except Exception:
            pass
        # 2. resolv.conf → бэкап (внешний DNS)
        result = rcf.rollback_resolv_conf()
        if result.get("ok"):
            lines.append("  /etc/resolv.conf восстановлен из бэкапа (внешний DNS)")
        else:
            err = str(result.get("error") or "")
            if "backup" not in err.lower():
                lines.append(f"  восстановление resolv.conf: {err}")
    except Exception as e:
        lines.append(f"  DNS-восстановление пропущено: {e}")
    return lines


# =============================================================================
#  УДАЛЕНИЕ VLESS REALITY
# =============================================================================
def do_uninstall() -> None:
    core = _core_module()
    _box_top     = core._box_top
    _box_row     = core._box_row
    _box_bottom  = core._box_bottom
    _box_warn    = core._box_warn
    _box_info    = core._box_info
    die          = core.die
    _run         = core._run
    CONFIG_DIR   = core.CONFIG_DIR
    XRAY_BIN     = core.XRAY_BIN
    XRAY_SERVICE = core.XRAY_SERVICE
    DNSCRYPT_BIN      = core.DNSCRYPT_BIN
    DNSCRYPT_CONF_DIR = core.DNSCRYPT_CONF_DIR
    DNSCRYPT_SERVICE  = core.DNSCRYPT_SERVICE
    PKG_MGR      = core.PKG_MGR
    YELLOW, RED, NC = core.YELLOW, core.RED, core.NC

    _box_top("УДАЛЕНИЕ VLESS REALITY")
    _box_warn("Будет удалено: Xray, Nginx, сайт, правила UFW, DNSCrypt")
    _box_row()
    _box_bottom()
    uninst_domain = input(f"{YELLOW}Домен для подтверждения удаления:{NC} ").strip()
    if not uninst_domain:
        _box_top("УДАЛЕНИЕ VLESS REALITY")
        _box_warn("Домен не введён. Отмена.")
        _box_bottom()
        sys.exit(0)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$', uninst_domain):
        die(f"Некорректный формат домена: '{uninst_domain}'")

    confirm = input(f"{RED}Удалить? [y/N]:{NC} ").strip().lower()
    if confirm != 'y':
        _box_top("УДАЛЕНИЕ VLESS REALITY")
        _box_info("Отменено.")
        _box_bottom()
        sys.exit(0)

    _box_top("УДАЛЕНИЕ VLESS REALITY")

    for svc in ("xray", "nginx", "dnscrypt-proxy"):
        _run(["systemctl", "stop",    svc], check=False, quiet=True)
    for svc in ("xray", "dnscrypt-proxy"):
        _run(["systemctl", "disable", svc], check=False, quiet=True)

    # Удаление Xray через официальный скрипт
    with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        r = _run([
            "curl", "-fsSL", "--connect-timeout", "10",
            "https://github.com/XTLS/Xray-install/raw/main/install-release.sh",
            "-o", str(tmp_path),
        ], check=False, quiet=True)
        if r.returncode == 0 and tmp_path.stat().st_size > 0:
            _run(["bash", str(tmp_path), "remove"], check=False, quiet=True)
    finally:
        tmp_path.unlink(missing_ok=True)

    for p in (XRAY_BIN, XRAY_SERVICE):
        Path(p).unlink(missing_ok=True)
    # Зачищаем drop-in директорию xray (оставляемую официальным bash-установщиком)
    shutil.rmtree("/etc/systemd/system/xray.service.d", ignore_errors=True)
    for d in (Path("/usr/local/etc/xray"), CONFIG_DIR,
              Path("/var/log/xray"), Path("/var/lib/xray")):
        shutil.rmtree(d, ignore_errors=True)

    # Удаление DNSCrypt
    _box_info("Удаление DNSCrypt-proxy...")
    DNSCRYPT_BIN.unlink(missing_ok=True)
    DNSCRYPT_SERVICE.unlink(missing_ok=True)
    shutil.rmtree(DNSCRYPT_CONF_DIR, ignore_errors=True)
    for log_f in ("/var/log/dnscrypt-proxy.log",
                  "/var/log/dnscrypt-blocked.log",
                  "/var/log/dnscrypt-proxy-blocked.log"):
        Path(log_f).unlink(missing_ok=True)

    override = Path("/etc/systemd/system/nginx.service.d/after-xray.conf")
    override.unlink(missing_ok=True)
    # Drop-in директорию НЕ удаляем — там могут быть чужие drop-in'ы.
    # rmdir() удалит только если директория пуста (не упадёт если нет).
    try:
        override.parent.rmdir()
    except Exception:
        pass
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)

    # ────────────────────────────────────────────────────────────────────────
    #  NGINX: удаляем ТОЛЬКО конфиги Chimera, НЕ трогаем чужие сайты!
    # ────────────────────────────────────────────────────────────────────────
    # БЫЛО (КРИТИЧЕСКИЙ БАГ):
    #   apt-get remove --purge nginx nginx-common  ← удаляет ВСЕ конфиги
    #   shutil.rmtree("/etc/nginx")                ← удаляет ВСЮ папку
    #   Это уничтожало все сайты пользователя!
    #
    # СТАЛО:
    #   Удаляем только конкретные vhost-файлы Chimera:
    #     /etc/nginx/sites-available/<domain>          (основной сайт VLESS)
    #     /etc/nginx/sites-enabled/<domain>            (symlink)
    #     /etc/nginx/sites-available/chimera-portal-nginx     (User Portal front)
    #     /etc/nginx/sites-enabled/chimera-portal-nginx       (symlink)
    #     /etc/nginx/sites-available/chimera-telemt-panel-nginx  (Telemt Panel)
    #     /etc/nginx/sites-enabled/chimera-telemt-panel-nginx    (symlink)
    #   nginx НЕ удаляем через apt-get — он может обслуживать другие сайты.
    # ────────────────────────────────────────────────────────────────────────

    _box_info("Удаление nginx-конфигов Chimera (не трогаем чужие сайты)...")

    # Список vhost-файлов, которые Chimera могла создать.
    nginx_sites_to_remove = [
        # Основной сайт VLESS (domain).
        f"/etc/nginx/sites-available/{uninst_domain}",
        f"/etc/nginx/sites-enabled/{uninst_domain}",
        # User Portal front (nginx_front_portal.py).
        "/etc/nginx/sites-available/chimera-portal-nginx",
        "/etc/nginx/sites-enabled/chimera-portal-nginx",
        # Telemt Panel front (telemt_panel.py).
        "/etc/nginx/sites-available/chimera-telemt-panel-nginx",
        "/etc/nginx/sites-enabled/chimera-telemt-panel-nginx",
    ]

    # Также проверяем старые имена (могли остаться от предыдущих версий).
    try:
        param_domain = core.PARAM_DOMAIN
        if param_domain and param_domain != uninst_domain:
            nginx_sites_to_remove.extend([
                f"/etc/nginx/sites-available/{param_domain}",
                f"/etc/nginx/sites-enabled/{param_domain}",
            ])
    except Exception:
        pass

    removed_count = 0
    for site_path in nginx_sites_to_remove:
        p = Path(site_path)
        if p.exists() or p.is_symlink():
            try:
                p.unlink()
                removed_count += 1
                _box_info(f"  Удалён: {site_path}")
            except Exception as e:
                _box_warn(f"  Не удалось удалить {site_path}: {e}")

    # Также удаляем default vhost если Chimera его создавала.
    # (nginx_setup.py иногда создаёт default для редиректа 80→443)
    # Но только если в нём есть маркер Chimera — чтобы не удалить чужой default.
    default_vhost = Path("/etc/nginx/sites-available/default")
    if default_vhost.exists():
        try:
            content = default_vhost.read_text()
            if "chimera" in content.lower() or uninst_domain in content:
                default_vhost.unlink()
                Path("/etc/nginx/sites-enabled/default").unlink(missing_ok=True)
                _box_info("  Удалён: sites-available/default (Chimera-generated)")
        except Exception:
            pass

    if removed_count == 0:
        _box_info("  nginx-конфиги Chimera не найдены — возможно уже удалены")
    else:
        _box_info(f"  Удалено {removed_count} nginx-конфиг(ов) Chimera")

    # Проверяем — остались ли другие сайты в sites-enabled/.
    # Если нет — предлагаем пользователю удалить nginx полностью.
    sites_enabled = Path("/etc/nginx/sites-enabled")
    other_sites = []
    if sites_enabled.exists():
        # FIX: 'default' добавлен в список исключений. Раньше стандартный
        # vhost Ubuntu/Debian считался «другим сайтом», и пользователю
        # предлагали полностью снести nginx — даже если кроме default'а
        # ничего нет. Теперь default не считается «другим сайтом».
        other_sites = [f for f in sites_enabled.iterdir()
                       if f.name not in ("chimera-portal-nginx",
                                          "chimera-telemt-panel-nginx",
                                          "default",
                                          uninst_domain)
                       and not f.name.startswith(".")]

    if not other_sites:
        # Нет других сайтов — спрашиваем, удалить ли nginx полностью.
        _box_row()
        _box_warn("Других сайтов в /etc/nginx/sites-enabled/ не найдено.")
        _box_warn("Можно полностью удалить nginx пакет.")
        try:
            remove_nginx = input(
                f"{YELLOW}Полностью удалить nginx? [y/N]:{NC} "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            remove_nginx = "n"

        if remove_nginx in ("y", "yes", "д", "да"):
            _box_info("Полное удаление nginx...")
            if PKG_MGR == "apt":
                _run(["apt-get", "remove", "--purge", "-y", "nginx", "nginx-common"],
                     check=False, quiet=True)
                _run(["apt-get", "autoremove", "-y"], check=False, quiet=True)
            else:
                _run(["dnf", "remove", "-y", "nginx"], check=False, quiet=True)
            # Теперь можно удалить /etc/nginx и /var/log/nginx.
            shutil.rmtree("/etc/nginx", ignore_errors=True)
            shutil.rmtree("/var/log/nginx", ignore_errors=True)
        else:
            _box_info("nginx оставлен — конфиги Chimera удалены")
            # Перезапускаем nginx чтобы он подхватил отсутствие vhost'ов.
            nginx_bin = shutil.which("nginx")
            if nginx_bin:
                _run([nginx_bin, "-t"], check=False, quiet=True)
                _run(["systemctl", "reload", "nginx"],
                     check=False, quiet=True)
    else:
        # Есть другие сайты — НЕ удаляем nginx, только reload.
        _box_info(f"Найдены другие сайты ({len(other_sites)} шт.) — nginx не удаляется")
        nginx_bin = shutil.which("nginx")
        if nginx_bin:
            _run([nginx_bin, "-t"], check=False, quiet=True)
            _run(["systemctl", "reload", "nginx"],
                 check=False, quiet=True)
            _box_info("nginx перезагружен — конфиги Chimera деактивированы")

    # Удаление веб-директории сайта (если есть).
    if uninst_domain:
        www_dir = Path(f"/var/www/{uninst_domain}")
        if www_dir.exists():
            try:
                remove_www = input(
                    f"{YELLOW}Удалить /var/www/{uninst_domain}? [y/N]:{NC} "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                remove_www = "n"
            if remove_www in ("y", "yes", "д", "да"):
                shutil.rmtree(www_dir, ignore_errors=True)
                _box_info(f"Удалено: /var/www/{uninst_domain}")
            else:
                _box_info(f"Оставлено: /var/www/{uninst_domain}")

    # ────────────────────────────────────────────────────────────────────────
    #  UFW + port_registry: закрыть порты удалённых сервисов (v49)
    # ────────────────────────────────────────────────────────────────────────
    _box_info("Закрытие портов UFW и снятие регистрации (port_registry)...")
    for line in _close_chimera_ports():
        _box_info(line)

    # DNS-ALIVE: системный DNS не должен умереть вместе со стеком (v49)
    _box_info("Восстановление системного DNS (внешний резолвер)...")
    for line in _restore_dns_after_full_uninstall():
        _box_info(line)

    _box_row()
    _box_bottom()
