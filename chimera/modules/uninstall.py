"""
chimera/modules/uninstall.py
───────────────────────────────────────────────────────────────────────────────
Полное удаление VLESS Reality + связанных компонентов.

Одна функция:

• **do_uninstall** — интерактивное удаление Xray, Nginx, сайта, правил UFW,
  DNSCrypt-proxy и AdGuard Home (v59 — полностью, с бэкапом данных).
  DNS откатывается к состоянию чистой системы: безусловно (v59 — без
  зависимости от state-файла), с живой пробой резолва и fallback на
  публичный DNS, чтобы сервер никогда не оставался с мёртвым DNS.

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
    """DNS-ALIVE при полном удалении: откат к состоянию ЧИСТОЙ системы (v59).

    Инцидент v59 (bright-lynx): удаление Chimera с AGH убивало DNS —
    SERVFAIL от 127.0.0.53. Причины: rollback_resolv_conf() требовал
    state.fixed=True (state утерян → откат тихо пропускался, а drop-in
    chimera-dns.conf продолжал гнать ВСЕ запросы systemd-resolved в
    мёртвый 127.0.0.1:53); resolv.conf восстанавливался только из бэкапа;
    никто не проверял, что DNS реально ожил.

    Теперь — hard_restore_clean_dns(): БЕЗУСЛОВНАЯ зачистка всех
    артефактов DNS-фикса (drop-in + iptables + persist + watchdog +
    resolv.conf/nsswitch) + живая проба + fallback на публичный DNS.
    """
    lines: list = []
    dns_ok = False
    try:
        from chimera.modules import resolv_conf_fix as rcf
        result = rcf.hard_restore_clean_dns()
        dns_ok = bool(result.get("probe_ok"))
        for a in result.get("actions", []):
            lines.append(f"  {a}")
        for w in result.get("warnings", []):
            lines.append(f"  ⚠ {w}")
    except Exception as e:
        lines.append(f"  DNS-восстановление пропущено: {e}")

    if dns_ok:
        lines.append("  ✓ Системный DNS жив (проверено живой пробой)")
    else:
        lines.append("  ✗ DNS всё ещё мёртв — выполните вручную:")
        lines.append("    rm -f /etc/systemd/resolved.conf.d/chimera-dns.conf")
        lines.append("    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")
        lines.append("    systemctl restart systemd-resolved")
        lines.append("    # если не помогло:")
        lines.append("    printf 'nameserver 77.88.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf")
    return lines


# =============================================================================
#  v59: ПОЛНОЕ УДАЛЕНИЕ ADGUARD HOME
# =============================================================================
# Пути AGH вынесены в модульные константы — для unit-тестов
# (tests/test_v59_uninstall_dns_alive.py патчит их на tmpdir).
_AGH_DIR          = Path("/opt/AdGuardHome")
_AGH_UNIT         = Path("/etc/systemd/system/AdGuardHome.service")
_AGH_BIN          = Path("/usr/local/bin/AdGuardHome")
_AGH_USER         = "adguard"
_AGH_BACKUP_DIR   = Path("/root/aghome-backups")
_AGH_CERTBOT_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/chimera-aghome.sh")


def _remove_aghome_full() -> list:
    """v59: полное удаление AdGuard Home при удалении всего стека.

    Раньше do_uninstall только stop/disable AGH («upstream dnscrypt
    удаляется, стек мёртв») — бинарник, /opt/AdGuardHome, юзер adguard,
    unit и certbot-hook оставались балластом. Теперь — чистое удаление:
      1. stop/disable + удаление unit-файла;
      2. бэкап /opt/AdGuardHome → /root/aghome-backups/aghome-*.tar.gz
         (данные пользователя не теряются);
      3. rm -rf /opt/AdGuardHome + /usr/local/bin/AdGuardHome;
      4. userdel/groupdel adguard;
      5. снятие certbot deploy-hook;
      6. снятие wizard-temp UFW-правил.
    Порты UFW/port_registry закрываются отдельно (_close_chimera_ports).
    """
    import subprocess as _sp
    from datetime import datetime as _dt

    lines: list = []

    if not (_AGH_DIR.exists() or _AGH_UNIT.exists() or _AGH_BIN.exists()):
        return ["  AdGuardHome не установлен — пропускаю"]

    # 1. Служба
    _sp.run(["systemctl", "stop", "AdGuardHome"],
            capture_output=True, check=False)
    _sp.run(["systemctl", "disable", "AdGuardHome"],
            capture_output=True, check=False)
    try:
        _AGH_UNIT.unlink(missing_ok=True)
        _sp.run(["systemctl", "daemon-reload"],
                capture_output=True, check=False)
        lines.append("  служба AdGuardHome остановлена и удалена")
    except Exception:
        pass

    # 2. Бэкап рабочей директории (данные пользователя!)
    if _AGH_DIR.exists():
        try:
            _AGH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            tgz = _AGH_BACKUP_DIR / ("aghome-"
                                     + _dt.now().strftime("%Y%m%d%H%M%S")
                                     + ".tar.gz")
            _sp.run(["tar", "-czf", str(tgz), "-C", "/opt", "AdGuardHome"],
                    capture_output=True, check=False, timeout=120)
            if tgz.exists() and tgz.stat().st_size > 0:
                lines.append(f"  бэкап AGH → {tgz}")
        except Exception as e:
            lines.append(f"  ⚠ бэкап AGH не создан: {e}")

    # 3. Файлы
    shutil.rmtree(_AGH_DIR, ignore_errors=True)
    _AGH_BIN.unlink(missing_ok=True)

    # 4. Пользователь и группа
    _sp.run(["userdel", _AGH_USER], capture_output=True, check=False)
    _sp.run(["groupdel", _AGH_USER], capture_output=True, check=False)

    # 5. Certbot deploy-hook
    _AGH_CERTBOT_HOOK.unlink(missing_ok=True)

    # 6. Wizard-temp UFW-правила (висящие allow от мастера первого запуска)
    try:
        from chimera.modules.aghome_setup import _ufw_clean_wizard_rules
        removed = _ufw_clean_wizard_rules()
        if removed:
            lines.append(f"  UFW: сняты wizard-правила AGH ({len(removed)} шт.)")
    except Exception:
        pass

    lines.append("  AdGuard Home полностью удалён (файлы, юзер, unit, hook)")
    return lines


# =============================================================================
#  v59: АРТЕФАКТЫ МОДУЛЯ dns_redirect
# =============================================================================
def _remove_dns_redirect_artifacts() -> list:
    """v59: PREROUTING-редиректы 53→5300 для VPN-клиентов + restore-сервис.

    Модуль dns_redirect (меню «DNS-redirect для VPN-клиентов») оставляет
    после себя iptables PREROUTING-правила (comment xray-dns-redirect) и
    systemd-юнит dns-redirect-restore.service, который восстанавливает
    правила после ребута. При полном удалении стека — вычищаем всё.
    """
    lines: list = []
    try:
        from chimera.modules import dns_redirect as dr
        result = dr.remove_dns_redirect()
        if result.get("success"):
            lines.append("  dns_redirect: PREROUTING-правила (xray-dns-redirect) "
                         "вычищены, restore-сервис удалён")
        else:
            lines.append("  ⚠ dns_redirect: часть правил могла остаться — "
                         "проверьте: iptables -t nat -S PREROUTING")
    except Exception as e:
        # Модуль недоступен — ручная зачистка по известным путям
        lines.append(f"  dns_redirect: модуль недоступен ({e}) — ручная зачистка")
        try:
            import subprocess as _sp
            _sp.run(["systemctl", "disable", "--now", "dns-redirect-restore"],
                    capture_output=True, check=False)
            Path("/etc/systemd/system/dns-redirect-restore.service").unlink(
                missing_ok=True)
            Path("/usr/local/bin/xray-dns-redirect-restore.sh").unlink(
                missing_ok=True)
            lines.append("  dns_redirect: restore-сервис удалён вручную")
        except Exception:
            pass
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
    _box_warn("Будет удалено: Xray, Nginx, сайт, правила UFW, DNSCrypt, AdGuard Home")
    _box_warn("DNS будет откачен к состоянию чистой системы (resolv.conf/nsswitch)")
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

    # ────────────────────────────────────────────────────────────────────────
    #  v59: ПОЛНОЕ удаление AdGuard Home (файлы, юзер, unit, certbot-hook)
    # ────────────────────────────────────────────────────────────────────────
    _box_info("Полное удаление AdGuard Home (с бэкапом данных)...")
    for line in _remove_aghome_full():
        _box_info(line)

    # ────────────────────────────────────────────────────────────────────────
    #  v59: артефакты dns_redirect (PREROUTING-редиректы + restore-сервис)
    # ────────────────────────────────────────────────────────────────────────
    _box_info("Очистка DNS-redirect артефактов (PREROUTING, restore-сервис)...")
    for line in _remove_dns_redirect_artifacts():
        _box_info(line)

    # ────────────────────────────────────────────────────────────────────────
    #  DNS-ALIVE v59: откат к состоянию ЧИСТОЙ системы — безусловно,
    #  с живой пробой и fallback на публичный DNS (инцидент bright-lynx:
    #  после удаления стека с AGH systemd-resolved отдавал SERVFAIL)
    # ────────────────────────────────────────────────────────────────────────
    _box_info("Восстановление системного DNS (откат к чистой системе)...")
    for line in _restore_dns_after_full_uninstall():
        _box_info(line)

    # ────────────────────────────────────────────────────────────────────────
    #  v59: финальная зачистка state-каталога установки
    # ────────────────────────────────────────────────────────────────────────
    _box_info("Финальная зачистка state-файлов Chimera...")
    state_dir = Path("/var/lib/xray-installer")
    if state_dir.exists():
        shutil.rmtree(state_dir, ignore_errors=True)
        _box_info("  удалён /var/lib/xray-installer (state всех модулей)")
    Path("/var/log/chimera.log").unlink(missing_ok=True)

    _box_row()
    _box_bottom()
