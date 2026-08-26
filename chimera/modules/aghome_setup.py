"""
chimera/modules/aghome_setup.py
───────────────────────────────────────────────────────────────────────────────
AdGuard Home — DNS-сервер с фильтрацией рекламных доменов.

АРХИТЕКТУРА DNS-СТЕКА CHIMERA (AGH-слой поверх DNSCrypt):

    Приложения (glibc) ──► 127.0.0.1:53 (AdGuard Home)
                              │  кеш 4MB + фильтры (AdGuard/AdAway/OISD)
                              ▼
                           127.0.0.1:5300 (DNSCrypt-proxy — шифрование)
                              │  DoH/DNSCrypt → Cloudflare/Google
                              ▼
                           Интернет

    Xray DNS ──► 127.0.0.1:53 (AGH) — через кеш и фильтры.
    Публичный DoH/DoT/DoQ: :30443/tcp, :853/tcp, :853/udp (TLS).

ОТЛИЧИЯ ОТ РОУТЕРНОГО СКРИПТА install-dnscrypt-v7.23-usb.sh (сделано лучше):
  • Bootstrap AGH = 127.0.0.1:5300 (dnscrypt) вместо 9.9.9.9 — нет
    plain-DNS утечки при резолве имён DoH-upstream'ов.
  • OISD Big URL: https://big.oisd.nl/ — роутерный /basic отдаёт 404
    (мёртвый фильтр), корневой URL проверен (267k записей).
  • Пароль админа НЕ предгенерируется (роутер: admin/admin bcrypt).
    AGH стартует БЕЗ конфига → нативный wizard в браузере задаёт логин/
    пароль (detectFirstRun: конфига нет → firstRun → wizard).
  • Параллельный HTTP-интерфейс :3000 защищён: временный UFW-доступ
    только с IP SSH-клиента (мастер без пароля — не выставляем наружу).
  • Служба работает от отдельного пользователя `adguard` с
    CAP_NET_BIND_SERVICE (а не от root, как на роутере).

СЕМАНТИКА ПЕРВОГО ЗАПУСКА AGH (проверено по исходникам v0.107.62,
internal/home/home.go::detectFirstRun):
  • Конфиг-файл ОТСУТСТВУЕТ → firstRun → поднимается ТОЛЬКО web-интерфейс
    (0.0.0.0:3000) с мастером; DNS-сервер НЕ запускается до завершения
    мастера (POST /control/install/configure пишет users + адреса и
    стартует DNS).
  • Конфиг-файл СУЩЕСТВУЕТ → AGH парсит и работает; пустой users при
    существующем конфиге = LOCKOUT (любой логин отклонён) — поэтому
    пароль задаётся мастером, а НЕ пустым users.
  • ИЗ ЭТОГО СЛЕДУЕТ: пока мастер не завершён, :53 никто не слушает.
    Системный DNS живёт через chimera-dns-fix redirect 53→5300
    (dnscrypt) — миграция с нулевым даунтаймом.

MIGRATION (нулевый даунтайм на живых серверах):
  1. Снять :53 у dnscrypt (ручной фикс v33 слушал 127.0.0.1:53),
     оставить только 127.0.0.1:5300 → restart dnscrypt.
  2. Redirect 53→5300 (chimera-dns-fix) ОСТАЁТСЯ активным — DNS жив.
  3. AGH стартует в wizard-режиме (конфига нет) — только web :3000.
  4. Мастер в браузере пишет конфиг (users + адреса).
  5. finalize_aghome_config() хирургически заменяет секции
     dns/tls/http/filters/querylog/statistics на канонические Chimera
     (upstream=dnscrypt:5300, фильтры, DoH/DoT, bind_hosts), рестарт AGH.
  6. Redirect 53→5300 УДАЛЯЕТСЯ (AGH теперь владеет :53) — вызовом
     fix_resolv_conf_to_localhost(force=True) с AGH-aware веткой
     (она же регенерирует persist-скрипт AGH-aware — на ребуте redirect
     не вернётся).
  7. Конфиг Xray перегенерируется (DNS → 127.0.0.1:53 через AGH).

ПОРТЫ (все через port_registry, авто-открытие/закрытие):
  :53/udp+tcp   aghome       — DNS (loopback+public bind; публичный :53
                               в UFW НЕ открывается — нет open resolver)
  :3000/tcp     aghome_web   — Web UI (loopback или public по выбору)
  :30443/tcp    aghome_doh   — DoH + Web UI HTTPS (native TLS AGH)
  :853/tcp      aghome_dot   — DoT
  :853/udp      aghome_doq   — DoQ
  :5300         dnscrypt     — upstream (loopback, force=True)

ТОЧКИ ВХОДА:
    install_aghome()                — установка + wizard + финализация
    finalize_aghome_config()        — финализация после wizard (идемпотентна)
    aghome_reset_admin_password()   — сброс пароля (wizard restart + finalize)
    uninstall_aghome()              — удаление с полным откатом
    is_aghome_active() / is_aghome_installed() / aghome_dns_ready()
    do_aghome_menu()                — TUI-меню (Сеть → A)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# ============================================================================
#  Ленивый доступ к ядру
# ============================================================================
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================
AGH_SERVICE_NAME = "AdGuardHome"
AGH_SERVICE_UNIT = Path("/etc/systemd/system/AdGuardHome.service")
AGH_BIN          = Path("/usr/local/bin/AdGuardHome")
AGH_WORK_DIR     = Path("/opt/AdGuardHome")
AGH_CONF         = AGH_WORK_DIR / "AdGuardHome.yaml"
AGH_CERTS_DIR    = AGH_WORK_DIR / "certs"
AGH_CERT_PATH    = AGH_CERTS_DIR / "agh-tls.crt"
AGH_KEY_PATH     = AGH_CERTS_DIR / "agh-tls.key"
AGH_USER         = "adguard"
AGH_GROUP        = "adguard"

AGH_STATE_FILE   = Path("/var/lib/xray-installer/aghome_state.json")
AGH_BACKUP_DIR   = Path("/root/aghome-backups")

# Порты (канонические значения Chimera; web/DoH/DoT/DoQ — публичные,
# DNS :53 — loopback+public bind, в UFW снаружи НЕ открывается).
AGH_DNS_PORT     = 53
AGH_WEB_PORT     = 3000
AGH_DOH_PORT     = 30443   # DoH + Web UI HTTPS (native TLS AGH)
AGH_DOT_PORT     = 853     # DoT (tcp)
AGH_DOQ_PORT     = 853     # DoQ (udp)

# Веб-режимы Web UI.
AGH_WEB_HTTPS_LE   = "https_le"      # домен + Let's Encrypt (рекомендуется)
AGH_WEB_HTTPS_SELF = "https_self"    # self-signed сертификат
AGH_WEB_HTTP_PUB   = "http_public"   # plain HTTP 0.0.0.0:3000
AGH_WEB_LOOPBACK   = "loopback"      # только 127.0.0.1:3000 (SSH-туннель)

# Списки фильтров (все 3 — по решению пользователя; URL проверены:
# big.oisd.nl/basic из роутерного скрипта отдаёт 404, корневой URL жив).
AGH_FILTERS: list[tuple[str, str]] = [
    ("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
     "AdGuard DNS filter"),
    ("https://adaway.org/hosts.txt",
     "AdAway Default Blocklist"),
    ("https://big.oisd.nl/",
     "OISD Big"),
]

# Fallback-резолверы — как на роутере (НЕ strict; решение пользователя).
AGH_FALLBACK_DNS: list[str] = ["9.9.9.9:53", "1.1.1.1:53"]

# Время ожидания мастера в браузере (сек) при интерактивной установке.
AGH_WIZARD_WAIT_SEC = 300

# Certbot deploy-hook для синка LE-сертификата в AGH при renew.
AGH_CERTBOT_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/chimera-aghome.sh")

# Конфиг dnscrypt-proxy (для миграции :53 → :5300).
AGH_DNSCRYPT_TOML = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")


# ============================================================================
#  СОСТОЯНИЕ (aghome_state.json)
# ============================================================================
def aghome_state_load() -> dict:
    """Читает состояние AGH. Поля: enabled, phase ('wizard'|'finalized'),
    web_mode, web_port, domain, self_signed, doh/dot/doq порты, tls_enabled,
    wizard_ssh_ip (временный UFW-доступ), installed_at."""
    try:
        if AGH_STATE_FILE.exists():
            data = json.loads(AGH_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def aghome_state_save(data: dict) -> None:
    try:
        AGH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        AGH_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        AGH_STATE_FILE.chmod(0o600)
    except Exception as e:
        try:
            core = _core_module()
            core.warn(f"AGH: не удалось сохранить state: {e}")
        except Exception:
            pass


# ============================================================================
#  ХЕЛПЕРЫ СОСТОЯНИЯ СЛУЖБЫ
# ============================================================================
def _svc_is_active(svc: str = AGH_SERVICE_NAME) -> bool:
    r = subprocess.run(["systemctl", "is-active", svc],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "active"


def _svc_is_enabled(svc: str = AGH_SERVICE_NAME) -> bool:
    r = subprocess.run(["systemctl", "is-enabled", svc],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == "enabled"


def is_aghome_installed() -> bool:
    """AGH установлен: бинарник существует (служба может быть неактивна)."""
    return AGH_BIN.exists()


def is_aghome_active() -> bool:
    """Служба AdGuardHome активна."""
    return _svc_is_active()


def aghome_wizard_pending() -> bool:
    """AGH в режиме мастера первого запуска: служба активна, конфига нет.
    В этом режиме DNS на :53 ещё не слушается — системный DNS живёт
    через redirect 53→5300 (dnscrypt)."""
    return is_aghome_active() and not AGH_CONF.exists()


def _port_listening(port: int, proto: str = "udp") -> bool:
    """Проверяет что порт слушается (ss)."""
    flag = "-ulnp" if proto == "udp" else "-tlnp"
    try:
        r = subprocess.run(["ss", flag], capture_output=True, text=True,
                           check=False, timeout=10)
        return bool(re.search(rf":{port}\s", r.stdout))
    except Exception:
        return False


def aghome_dns_ready() -> bool:
    """AGH полностью готов: служба активна И слушает :53 (udp).
    Именно это условие используют resolv_conf_fix и xray_install —
    «AGH владеет :53»."""
    return is_aghome_active() and _port_listening(AGH_DNS_PORT, "udp")


def _get_dnscrypt_port() -> int:
    """Реальный порт dnscrypt-proxy (из TOML; default 5300)."""
    try:
        from chimera.modules.dnscrypt_setup import _get_dnscrypt_port as _gdp
        return _gdp()
    except Exception:
        toml = Path("/etc/dnscrypt-proxy/dnscrypt-proxy.toml")
        if toml.exists():
            m = re.search(
                r'listen_addresses\s*=\s*\[\s*[\'"]([^\'"]+)[\'"]',
                toml.read_text(errors="replace"), re.IGNORECASE)
            if m:
                parts = m.group(1).rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    return int(parts[1])
        return 5300


def _get_public_ip() -> str:
    """Публичный IPv4 сервера: сначала state.json (domain не нужен — IP),
    затем curl, затем ip addr."""
    # 1. ip addr (самый быстрый, без сети)
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "scope", "global"],
                           capture_output=True, text=True, check=False, timeout=10)
        m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    # 2. внешние сервисы
    for url in ("https://api.ipify.org", "http://ifconfig.me"):
        try:
            r = subprocess.run(["curl", "-fsS", "--max-time", "6", url],
                               capture_output=True, text=True, check=False, timeout=10)
            ip = r.stdout.strip()
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                return ip
        except Exception:
            pass
    return ""


def _get_ssh_client_ip() -> str:
    """IP SSH-клиента (для временного доступа к мастеру :3000)."""
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        val = os.environ.get(var, "")
        if val:
            ip = val.split()[0]
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                return ip
    # fallback: who
    try:
        r = subprocess.run(["who", "-m"], capture_output=True, text=True,
                           check=False, timeout=5)
        m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _wait_service(svc: str, max_sec: int = 30) -> bool:
    """Ждёт пока служба станет active. Возвращает True при успехе."""
    for _ in range(max_sec):
        if _svc_is_active(svc):
            return True
        r = subprocess.run(["systemctl", "is-failed", svc],
                           capture_output=True, text=True, check=False)
        if r.stdout.strip() == "failed":
            return False
        time.sleep(1)
    return False


# ============================================================================
#  МИГРАЦИЯ: СНЯТЬ :53 У DNSCRYPT
# ============================================================================
def _ensure_dns_redirect_safety(port: int, remove: bool = False) -> bool:
    """Страховка DNS на время wizard-фазы: redirect 53→port (или снятие).

    v41: на живых серверах с ручным фиксом v33 redirect НИКОГДА не
    ставился (dnscrypt слушал :53 напрямую, redirect был не нужен).
    Миграция снимала :53 — и DNS попадал в black-hole: resolv.conf →
    127.0.0.1:53, где больше никого нет (AGH в wizard-режиме :53 не
    слушает). Ставим redirect ДО правки TOML: пока dnscrypt ещё на
    :53+{port} — redirect не мешает, после снятия :53 — единственный
    путь. Использует канонические правила resolv_conf_fix (comment
    «chimera-dns-fix» — персист-скрипт узнаёт их на ребуте).

    Возвращает True при успехе (или если port == 53 — redirect не нужен).
    """
    if port == 53:
        return True
    try:
        from chimera.modules.resolv_conf_fix import (
            _apply_dns_redirect, _remove_dns_redirect,
        )
        if remove:
            ok, _err = _remove_dns_redirect(port)
        else:
            ok, _err = _apply_dns_redirect(port)
        return ok
    except Exception:
        return False


def migrate_dnscrypt_off_53() -> bool:
    """Снимает :53 у dnscrypt-proxy (ручной фикс v33 на живых серверах
    слушал 127.0.0.1:53).

    Порядок (v41 — с защитой от DNS black-hole):
      1. Если dnscrypt держит :53 — СНАЧАЛА ставим redirect-страховку
         53→{port} (DNS жив на протяжении всей миграции), только потом
         правим TOML и рестартим.
      2. Если dnscrypt :53 уже не держит (повторная установка) — тоже
         гарантируем redirect: wizard-фаза живёт на нём.
      3. Провал рестарта — откат TOML + снятие redirect.

    Идемпотентно: повторный вызов безопасен.

    Возвращает True если dnscrypt слушает ТОЛЬКО :{port} И redirect
    (или сам :53) обслуживает системный DNS.
    """
    core = _core_module()
    warn = core.warn
    info = core.info
    success = core.success

    toml_path = AGH_DNSCRYPT_TOML
    if not toml_path.exists():
        warn("AGH: конфиг dnscrypt-proxy не найден — миграция пропущена")
        return False

    try:
        content = toml_path.read_text(errors="replace")
    except Exception as e:
        warn(f"AGH: не удалось прочитать dnscrypt TOML: {e}")
        return False

    # Текущие listen_addresses
    m = re.search(r'^(listen_addresses\s*=\s*\[)([^\]]*)(\])',
                  content, re.MULTILINE)
    if not m:
        warn("AGH: listen_addresses не найден в dnscrypt TOML")
        return False

    listens = re.findall(r'[\'"]([^\'"]+)[\'"]', m.group(2))
    # Порт dnscrypt = первый адрес с портом НЕ 53 (если dnscrypt слушал и :53,
    # и :5300 — берём 5300; :53 уходим освобождать AGH).
    port = 5300
    for entry in listens:
        parts = entry.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) != 53:
            port = int(parts[1])
            break

    # Кто-то держит :53 на loopback?
    dns53_taken = False
    try:
        r = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True,
                           check=False, timeout=10)
        # Ищем слушателей :53, КРОМЕ systemd-resolved stub (127.0.0.53/::1)
        for line in r.stdout.splitlines():
            if re.search(r':53\s', line) and "resolved" not in line:
                if "127.0.0.53" in line or "127.0.0.54" in line:
                    continue  # systemd-resolved stub — не мешает bind 127.0.0.1:53
                if "dnscrypt" in line.lower():
                    dns53_taken = True
                else:
                    # Чужой слушатель :53 — AGH не сможет забиндиться
                    warn(f"AGH: порт 53 занят другим процессом: {line.strip()[:100]}")
    except Exception:
        pass

    if not dns53_taken:
        info("AGH: dnscrypt не держит :53 — миграция не требуется")
        # v41: повторная установка на сервере в битом состоянии (миграция
        # прошлой версии уже сняла :53, но redirect никто не поставил) —
        # самовосстановление: ставим страховку, DNS оживает через dnscrypt.
        if _port_listening(port, "udp") or port == 53:
            if port != 53 and _ensure_dns_redirect_safety(port):
                info(f"AGH: redirect-страховка 53→{port} установлена "
                     "(wizard-фаза: DNS живёт через dnscrypt)")
            elif port != 53:
                warn("AGH: не удалось поставить redirect 53→" + str(port)
                     + " — если DNS не резолвит, Сеть → диагностика DNS")
        return True

    # v41: СНАЧАЛА страховка — потом правка TOML. Пока dnscrypt слушает
    # и :53, и {port}, redirect 53→{port} ничего не ломает; после снятия
    # :53 он становится единственным путём DNS. На серверах с ручным
    # фиксом v33 redirect никогда не ставился — без него миграция
    # создавала DNS black-hole («Could not resolve host»). БЕЗ страховки
    # TOML не трогаем.
    if not _ensure_dns_redirect_safety(port):
        warn(f"AGH: не удалось поставить redirect-страховку 53→{port} "
             "(iptables недоступен?)")
        warn("AGH: миграция прервана ДО правки TOML — системный DNS не тронут")
        return False
    info(f"AGH: redirect-страховка 53→{port} установлена — DNS жив при миграции")

    # Бэкап + перезапись listen_addresses → только 127.0.0.1:{port}
    bak = toml_path.with_name(
        toml_path.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".preAGH.bak")
    try:
        shutil.copy2(toml_path, bak)
    except Exception as e:
        warn(f"AGH: не удалось сделать бэкап dnscrypt TOML: {e}")
        return False

    new_listen = f"{m.group(1)}'127.0.0.1:{port}'{m.group(3)}"
    content = content[:m.start()] + new_listen + content[m.end():]
    try:
        toml_path.write_text(content)
    except Exception as e:
        warn(f"AGH: не удалось записать dnscrypt TOML: {e}")
        return False

    subprocess.run(["systemctl", "restart", "dnscrypt-proxy"],
                   capture_output=True, check=False)
    if not _wait_service("dnscrypt-proxy", 30):
        # откат: TOML + снятие страховки (возврат к исходному состоянию)
        warn("AGH: dnscrypt не поднялся после миграции — откат TOML")
        try:
            shutil.copy2(bak, toml_path)
            subprocess.run(["systemctl", "restart", "dnscrypt-proxy"],
                           capture_output=True, check=False)
            _wait_service("dnscrypt-proxy", 20)
        except Exception:
            pass
        _ensure_dns_redirect_safety(port, remove=True)
        return False

    # dnscrypt может слушать :53 несколько секунд (SS backlog) — проверяем
    # что 127.0.0.1:53 больше не в ss (кроме resolved stub).
    ok = False
    for _ in range(10):
        try:
            r = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True,
                               check=False, timeout=10)
            taken = any(
                re.search(r'127\.0\.0\.1:53\s', ln) and "dnscrypt" in ln.lower()
                for ln in r.stdout.splitlines())
            if not taken:
                ok = True
                break
        except Exception:
            ok = True
            break
        time.sleep(1)

    if ok and _port_listening(port, "udp"):
        success(f"AGH: dnscrypt migrated → 127.0.0.1:{port} (:53 освобождён)")
        return True
    warn(f"AGH: dnscrypt не слушает :{port} после миграции — проверьте journalctl")
    return False


# ============================================================================
#  SYSTEMD UNIT
# ============================================================================
def _write_aghome_unit() -> bool:
    """Пишет systemd-unit AdGuardHome.service (user=adguard, :53/:853 caps).

    Порядок: после dnscrypt-proxy (upstream), до xray/nginx (клиенты).
    """
    unit = f"""# Chimera Project — AdGuard Home service
# Сгенерировано chimera/modules/aghome_setup.py. НЕ редактировать вручную.
# Управление: TUI → Сеть → AdGuard Home (меню A).

[Unit]
Description=AdGuard Home — DNS-сервер с фильтрацией (upstream: dnscrypt-proxy)
Documentation=https://github.com/AdguardTeam/AdGuardHome
Wants=dnscrypt-proxy.service
After=network.target network-online.target dnscrypt-proxy.service
Before=xray.service nginx.service chimera-dns-fix.service

[Service]
Type=simple
User={AGH_USER}
Group={AGH_GROUP}
WorkingDirectory={AGH_WORK_DIR}
ExecStart={AGH_BIN} -w {AGH_WORK_DIR}
Restart=on-failure
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=30s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""
    try:
        AGH_SERVICE_UNIT.parent.mkdir(parents=True, exist_ok=True)
        AGH_SERVICE_UNIT.write_text(unit)
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, check=False)
        return True
    except Exception as e:
        try:
            core = _core_module()
            core.warn(f"AGH: не удалось записать systemd-unit: {e}")
        except Exception:
            pass
        return False


def _create_aghome_user() -> bool:
    """Создаёт системного пользователя adguard (аналогично dnscrypt)."""
    subprocess.run(
        ["useradd", "-r", "-s", "/usr/sbin/nologin",
         "-d", str(AGH_WORK_DIR), "-M", AGH_USER],
        capture_output=True, check=False)
    subprocess.run(["chown", "-R", f"{AGH_USER}:{AGH_GROUP}", str(AGH_WORK_DIR)],
                   capture_output=True, check=False)
    return True


# ============================================================================
#  TLS-СЕРТИФИКАТЫ
# ============================================================================
def _prepare_tls_cert(mode: str, domain: str) -> "tuple[Optional[Path], Optional[Path]]":
    """Готовит TLS-сертификат для DoH/DoT/DoQ + HTTPS Web UI.

    mode=AGH_WEB_HTTPS_LE:   копирует LE-сертификат домена в
                             /opt/AdGuardHome/certs/ (chown adguard) +
                             ставит certbot deploy-hook на renewal.
                             Если LE-сертификата нет — получает через
                             ssl_certbot.obtain_ssl_cert() (паттерн панелей).
    mode=AGH_WEB_HTTPS_SELF: генерирует self-signed (openssl, 10 лет).

    Возвращает (cert_path, key_path) или (None, None) при ошибке.
    """
    core = _core_module()
    info, warn = core.info, core.warn

    AGH_CERTS_DIR.mkdir(parents=True, exist_ok=True)

    if mode == AGH_WEB_HTTPS_LE:
        if not domain:
            warn("AGH: домен не задан — LE-сертификат недоступен")
            return None, None
        le_cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        le_key  = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
        if not (le_cert.exists() and le_key.exists()):
            info(f"AGH: LE-сертификат для {domain} не найден — получаем через certbot...")
            try:
                from chimera.modules.ssl_certbot import obtain_ssl_cert
                obtain_ssl_cert(domain)
            except Exception as e:
                warn(f"AGH: не удалось получить LE-сертификат: {e}")
                warn("AGH: fallback → self-signed (заменить можно позже через меню)")
                return _generate_self_signed_tls(domain)
        if not (le_cert.exists() and le_key.exists()):
            warn("AGH: LE-сертификат по-прежнему отсутствует — self-signed fallback")
            return _generate_self_signed_tls(domain)
        # Копируем (AGH-юзер не может читать /etc/letsencrypt напрямую)
        try:
            shutil.copy2(le_cert, AGH_CERT_PATH)
            shutil.copy2(le_key, AGH_KEY_PATH)
            _own_certs()
            _install_certbot_deploy_hook(domain)
            info(f"AGH: LE-сертификат {domain} → {AGH_CERT_PATH}")
            return AGH_CERT_PATH, AGH_KEY_PATH
        except Exception as e:
            warn(f"AGH: не удалось скопировать LE-сертификат: {e}")
            return None, None

    # self-signed
    return _generate_self_signed_tls(domain)


def _own_certs() -> None:
    """Владелец сертификатов — adguard, права 600/644."""
    try:
        subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}",
                        str(AGH_CERT_PATH), str(AGH_KEY_PATH)],
                       capture_output=True, check=False)
        AGH_KEY_PATH.chmod(0o600)
        AGH_CERT_PATH.chmod(0o644)
    except Exception:
        pass


def _generate_self_signed_tls(cn: str = "") -> "tuple[Optional[Path], Optional[Path]]":
    """Генерирует self-signed TLS-сертификат (openssl, RSA-2048, 10 лет).

    CN/SAN: домен если задан, иначе публичный IP (fallback 127.0.0.1).
    Паттерн panel_nginx_front._generate_self_signed_tls.
    """
    core = _core_module()
    info = core.info
    info("AGH: генерация self-signed TLS сертификата...")

    subject_cn = cn or _get_public_ip() or "127.0.0.1"
    san = f"DNS:{subject_cn}" if not re.match(r'^\d+\.\d+\.\d+\.\d+$', subject_cn) \
        else f"IP:{subject_cn}"

    try:
        AGH_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "3650",
             "-subj", f"/CN={subject_cn}",
             "-addext", f"subjectAltName={san},DNS:localhost,IP:127.0.0.1",
             "-keyout", str(AGH_KEY_PATH),
             "-out", str(AGH_CERT_PATH)],
            capture_output=True, text=True, check=False, timeout=60)
        if r.returncode != 0:
            core.warn(f"AGH: openssl упал: {r.stderr.strip()[:200]}")
            return None, None
        _own_certs()
        return AGH_CERT_PATH, AGH_KEY_PATH
    except Exception as e:
        core.warn(f"AGH: не удалось сгенерировать self-signed: {e}")
        return None, None


def _install_certbot_deploy_hook(domain: str) -> None:
    """Ставит certbot deploy-hook: при renew LE-сертификата копирует его
    в AGH и рестартует службу (иначе AGH будет служить просроченным)."""
    if not domain:
        return
    hook = f"""#!/bin/bash
# Chimera Project — sync LE-сертификат в AdGuard Home при renew.
# Сгенерировано chimera/modules/aghome_setup.py.
LE_DOMAIN="{domain}"
AGH_CERT="{AGH_CERT_PATH}"
AGH_KEY="{AGH_KEY_PATH}"
[ -f "/etc/letsencrypt/live/$LE_DOMAIN/fullchain.pem" ] || exit 0
cp "/etc/letsencrypt/live/$LE_DOMAIN/fullchain.pem" "$AGH_CERT"
cp "/etc/letsencrypt/live/$LE_DOMAIN/privkey.pem" "$AGH_KEY"
chown {AGH_USER}:{AGH_GROUP} "$AGH_CERT" "$AGH_KEY"
chmod 600 "$AGH_KEY"
systemctl restart AdGuardHome || true
"""
    try:
        AGH_CERTBOT_HOOK.parent.mkdir(parents=True, exist_ok=True)
        AGH_CERTBOT_HOOK.write_text(hook)
        AGH_CERTBOT_HOOK.chmod(0o755)
    except Exception as e:
        try:
            _core_module().warn(f"AGH: не удалось поставить certbot hook: {e}")
        except Exception:
            pass


def _remove_certbot_deploy_hook() -> None:
    try:
        AGH_CERTBOT_HOOK.unlink(missing_ok=True)
    except Exception:
        pass


# ============================================================================
#  YAML: СБОРКА СЕКЦИЙ
# ============================================================================
def _yaml_quote(s: str) -> str:
    """YAML-безопасное строковое значение в двойных кавычках."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaml_list(items: list, indent: int = 2) -> str:
    """YAML-список (пустой → [], непустой → элементы с отступом)."""
    if not items:
        return "[]"
    pad = " " * indent
    return "\n" + "\n".join(f"{pad}- {_yaml_quote(str(i))}" for i in items)


def build_dns_section(dc_port: int, public_ip: str, tls_enabled: bool) -> str:
    """Секция dns: — канонический конфиг Chimera (по мотивам роутерного,
    с VPS-адаптацией: bind_hosts = loopback + public IP для DoT/DoQ,
    приватные PTR выключены — нет LAN).

    Публичный :53 НЕ открывается в UFW — open resolver исключён;
    public IP в bind_hosts нужен только для DoT(:853)/DoQ(:853)/DoH(:30443).
    """
    bind_hosts = ["127.0.0.1"]
    if public_ip:
        bind_hosts.append(public_ip)
    bind_lines = "\n".join(f"    - {_yaml_quote(h)}" for h in bind_hosts)

    return f"""dns:
  bind_hosts:
{bind_lines}
  port: {AGH_DNS_PORT}
  anonymize_client_ip: false
  ratelimit: 20
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
    - 127.0.0.1:{dc_port}
  upstream_dns_file: ""
  bootstrap_dns:
    - 127.0.0.1:{dc_port}
    - 9.9.9.9:53
    - 1.1.1.1:53
  fallback_dns:
{chr(10).join(f"    - {f}" for f in AGH_FALLBACK_DNS)}
  upstream_mode: parallel
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
    - version.bind
    - id.server
    - hostname.bind
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0
  cache_optimistic: true
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: true
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: false
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: true
  use_http3_upstreams: false
  serve_plain_dns: true
  hostsfile_enabled: true
"""


def build_tls_section(tls_enabled: bool, server_name: str,
                      cert_path: Optional[Path], key_path: Optional[Path]) -> str:
    """Секция tls: — DoH(:30443) + DoT(:853) + DoQ(:853) + HTTPS Web UI.

    port_https обслуживает И DoH, И Web UI (AGH мультиплексирует их на
    одном HTTPS-порту). allow_unencrypted_doh: false — DoH только через TLS.
    """
    if not tls_enabled:
        return """tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 0
  port_dns_over_tls: 0
  port_dns_over_quic: 0
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
"""
    cert = str(cert_path) if cert_path else ""
    key = str(key_path) if key_path else ""
    return f"""tls:
  enabled: true
  server_name: {_yaml_quote(server_name)}
  force_https: false
  port_https: {AGH_DOH_PORT}
  port_dns_over_tls: {AGH_DOT_PORT}
  port_dns_over_quic: {AGH_DOQ_PORT}
  certificate_chain: ""
  private_key: ""
  certificate_path: {_yaml_quote(cert)}
  private_key_path: {_yaml_quote(key)}
  strict_sni_check: false
"""


def build_http_section(web_mode: str) -> str:
    """Секция http: — адрес Web UI по выбранному режиму.

    https_le/https_self: plain HTTP на loopback (SSH-туннель), публичный
    доступ — через native TLS на :30443.
    http_public: 0.0.0.0:{port} (plain, на выбор пользователя).
    loopback: 127.0.0.1:{port}.
    """
    if web_mode == AGH_WEB_HTTP_PUB:
        addr = f"0.0.0.0:{AGH_WEB_PORT}"
    else:
        addr = f"127.0.0.1:{AGH_WEB_PORT}"
    return f"""http:
  pprof:
    port: 6060
    enabled: false
  address: {addr}
  session_ttl: 720h
"""


def build_filters_section() -> str:
    """Секция filters: — все 3 списка (AdGuard DNS + AdAway + OISD Big)."""
    entries = []
    for i, (url, name) in enumerate(AGH_FILTERS, start=1):
        entries.append(
            f"  - enabled: true\n    url: {_yaml_quote(url)}\n"
            f"    name: {_yaml_quote(name)}\n    id: {i}")
    body = "\n".join(entries)
    return f"filters:\n{body}\nwhitelist_filters: []\nuser_rules: []\n"


def build_querylog_section() -> str:
    """Секция querylog: — включён (решение пользователя: логи И статистика).
    Ретенция 90 дней (2160h), ротация файлов."""
    return """querylog:
  enabled: true
  file_enabled: true
  interval: 2160h
  size_memory: 1000
  ignored: []
"""


def build_statistics_section() -> str:
    """Секция statistics: — включена (решение пользователя). Ретенция 90 дней."""
    return """statistics:
  enabled: true
  interval: 2160h
  ignored: []
"""


# ============================================================================
#  YAML: ХИРУРГИЧЕСКАЯ ЗАМЕНА СЕКЦИЙ
# ============================================================================
def yaml_replace_sections(text: str, sections: "dict[str, Optional[str]]",
                          scalars: "dict[str, str]" = {}) -> str:
    """Заменяет top-level секции YAML не разбирая остальное.

    Конфиг пишет сам AGH (машинный YAML, 2-space indent, стабильная
    структура). Мы заменяем только секции, которыми управляем:
      dns / tls / http / filters / whitelist_filters / user_rules /
      querylog / statistics / dhcp
    Всё остальное (users, schema_version, clients, auth_*, theme, ...)
    остаётся КАК ЕСТЬ — включая users с bcrypt-паролем, который задал
    мастер в браузере.

    Секции со значением None — УДАЛЯЮТСЯ из конфига (AGH допишет дефолты).

    scalars: замена top-level скаляров (например language: ru) —
    построчная замена/добавление.
    """
    lines = text.splitlines(keepends=True)

    # Разметка: диапазоны строк каждой top-level секции.
    # Top-level key: строка без отступа, вида "key:" или "key: value".
    section_starts: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*):(\s|$)', ln)
        if m:
            section_starts.append((i, m.group(1)))

    result: list[str] = []
    replaced: set[str] = set()
    idx = 0
    n = len(lines)
    while idx < n:
        # Находим секцию, начинающуюся на idx (если есть)
        cur_key = None
        for (si, key) in section_starts:
            if si == idx:
                cur_key = key
                break
        if cur_key is None:
            result.append(lines[idx])
            idx += 1
            continue

        # Конец секции: начало следующей top-level секции или EOF
        end = n
        for (si, key) in section_starts:
            if si > idx:
                end = si
                break

        if cur_key in sections:
            new_block = sections[cur_key]
            replaced.add(cur_key)
            if new_block is not None:
                # Нормализуем: блок заканчивается ровно одним \n
                block = new_block.rstrip("\n") + "\n"
                result.append(block)
            # None → секция удаляется целиком
        else:
            result.extend(lines[idx:end])
        idx = end

    # Секции, которых не было в конфиге → дописываем в конец
    for key, new_block in sections.items():
        if key not in replaced and new_block is not None:
            block = new_block.rstrip("\n") + "\n"
            if result and not result[-1].endswith("\n"):
                result[-1] += "\n"
            result.append(block)

    out = "".join(result)

    # Скаляры (language и т.п.)
    for key, val in scalars.items():
        pattern = re.compile(rf'^{re.escape(key)}:.*$', re.MULTILINE)
        if pattern.search(out):
            out = pattern.sub(f"{key}: {val}", out)
        else:
            if not out.endswith("\n"):
                out += "\n"
            out += f"{key}: {val}\n"

    return out


def _yaml_has_users(text: str) -> bool:
    """Есть ли непустая секция users: (мастер завершён)."""
    m = re.search(r'^users:\s*$', text, re.MULTILINE)
    if not m:
        # однострочный формат users: []
        m2 = re.search(r'^users:\s*\[?\s*\]?\s*$', text, re.MULTILINE)
        if m2 and "[]" in m2.group(0):
            return False
        return False
    # Смотрим следующие строки-элементы списка
    rest = text[m.end():]
    for ln in rest.splitlines():
        if re.match(r'^[A-Za-z_]', ln):
            break  # следующая top-level секция
        if re.match(r'^\s*-\s*\S', ln):
            return True
    return False


# ============================================================================
#  UFW / PORT_REGISTRY
# ============================================================================
def _ufw_allow(port: int, proto: str, comment: str) -> bool:
    """Открывает порт в UFW (fallback iptables — паттерн panel_nginx_front)."""
    try:
        if shutil.which("ufw"):
            r = subprocess.run(
                ["ufw", "allow", f"{port}/{proto}", "comment", comment],
                capture_output=True, text=True, check=False, input="y\n", timeout=30)
            if r.returncode == 0:
                return True
        ipt = shutil.which("iptables")
        if ipt:
            r = subprocess.run(
                [ipt, "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                capture_output=True, check=False)
            if r.returncode == 0:
                return True
            r = subprocess.run(
                [ipt, "-I", "INPUT", "1", "-p", proto, "--dport", str(port),
                 "-j", "ACCEPT"],
                capture_output=True, check=False)
            return r.returncode == 0
    except Exception:
        pass
    return False


def _ufw_allow_from_ip(ip: str, port: int) -> bool:
    """Временный доступ к порту только с одного IP (для мастера :3000)."""
    if not ip:
        return False
    try:
        if not shutil.which("ufw"):
            return False
        r = subprocess.run(
            ["ufw", "allow", "from", ip, "to", "any", "port", str(port),
             "proto", "tcp", "comment", "chimera-aghome-wizard-temp"],
            capture_output=True, text=True, check=False, input="y\n", timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _ufw_delete_rule(*args: str) -> None:
    """Удаляет UFW-правило (quiet, идемпотентно)."""
    try:
        if shutil.which("ufw"):
            subprocess.run(["ufw", "delete"] + list(args),
                           capture_output=True, text=True, check=False,
                           input="y\n", timeout=30)
    except Exception:
        pass


def _ufw_clean_wizard_rules(port: int = AGH_WEB_PORT) -> list:
    """Удаляет ВСЕ старые временные wizard-правила (по comment).

    Покрывает переустановки и крэши между добавлением правила и
    сохранением state (правило без clean-up оставалось в UFW навсегда).
    """
    removed = []
    try:
        if not shutil.which("ufw"):
            return removed
        r = subprocess.run(["ufw", "status"], capture_output=True,
                           text=True, check=False, timeout=30)
        for line in r.stdout.splitlines():
            if "chimera-aghome-wizard-temp" not in line:
                continue
            # ufw status: "3000/tcp  ALLOW  <IP>  # comment" — IP стоит
            # в колонке From, слова «from» в строке НЕТ. Ищем первый IPv4
            # до комментария (комментарий наших правил IP не содержит).
            m = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', line.split("#")[0])
            if not m:
                continue
            ip = m.group(1)
            _ufw_delete_rule("allow", "from", ip, "to", "any",
                             "port", str(port), "proto", "tcp")
            removed.append(ip)
    except Exception:
        pass
    return removed


def _is_public_ipv4(ip: str) -> bool:
    """IPv4 и глобальный (не RFC1918/CGNAT/loopback/TEST-NET) — годится
    как хост в URL для пользователя."""
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        # is_global строже is_private: CGNAT 100.64/10 и TEST-NET
        # не являются private, но и не global
        return a.version == 4 and a.is_global
    except Exception:
        return False


def _open_wizard_access(ssh_ip: str) -> list:
    """Временный доступ к мастеру :3000 — с IP SSH-клиента И с public
    IP VPS.

    Public IP обязателен: браузер через VLESS/xray-туннель НА ЭТОЙ ЖЕ
    VPS приходит на :3000 с source-IP сервера (hairpin) — без правила
    для pub_ip мастер недоступен через туннель. Чистит старые
    wizard-правила, возвращает список реально открытых IP.
    """
    pub_ip = _get_public_ip()
    want = []
    if ssh_ip:
        want.append(ssh_ip)
    if pub_ip and pub_ip not in want:
        want.append(pub_ip)
    _ufw_clean_wizard_rules()
    opened = []
    for ip in want:
        if _ufw_allow_from_ip(ip, AGH_WEB_PORT):
            opened.append(ip)
    return opened


def _register_aghome_ports(dc_port: int, tls_enabled: bool,
                           web_public_plain: bool) -> None:
    """Регистрирует все порты DNS-стека в port_registry + открывает публичные
    в UFW. Вызывается при установке/финализации (идемпотентно)."""
    try:
        from chimera.modules.port_registry import (
            port_register, ufw_open_port,
            SERVICE_DNSCRYPT, SERVICE_AGHOME, SERVICE_AGHOME_WEB,
            SERVICE_AGHOME_DOH, SERVICE_AGHOME_DOT, SERVICE_AGHOME_DOQ,
        )
    except Exception as e:
        try:
            _core_module().warn(f"AGH: port_registry недоступен: {e}")
        except Exception:
            pass
        return

    core = _core_module()
    info = core.info

    # dnscrypt :5300 — внутренний loopback-слушатель (force, паттерн b4_dns)
    port_register(SERVICE_DNSCRYPT, dc_port, "udp",
                  comment="dnscrypt-proxy upstream для AGH (loopback)", force=True)
    port_register(SERVICE_DNSCRYPT, dc_port, "tcp",
                  comment="dnscrypt-proxy upstream для AGH (loopback)", force=True)

    # AGH DNS :53 — наш слушатель (force: /etc/services "domain" + ss конфликт
    # с собственным слушателем). Публично НЕ открываем — нет open resolver.
    port_register(SERVICE_AGHOME, AGH_DNS_PORT, "udp",
                  comment="AdGuard Home DNS (loopback+public bind, UFW закрыт снаружи)",
                  force=True)
    port_register(SERVICE_AGHOME, AGH_DNS_PORT, "tcp",
                  comment="AdGuard Home DNS (loopback+public bind, UFW закрыт снаружи)",
                  force=True)

    # Web UI :3000
    port_register(SERVICE_AGHOME_WEB, AGH_WEB_PORT, "tcp",
                  comment="AdGuard Home Web UI", force=True)
    if web_public_plain:
        ok, msg = ufw_open_port(AGH_WEB_PORT, "tcp", SERVICE_AGHOME_WEB,
                                comment="AdGuard Home Web UI (HTTP)")
        if ok:
            info(f"AGH: порт {AGH_WEB_PORT}/tcp открыт в UFW (Web UI)")
    else:
        # loopback-режим — публичный доступ закрыт
        ufw_close_quiet(AGH_WEB_PORT, "tcp", SERVICE_AGHOME_WEB)

    # DoH/DoT/DoQ — только при TLS
    if tls_enabled:
        for tag, port, proto, label in (
            (SERVICE_AGHOME_DOH, AGH_DOH_PORT, "tcp", "DoH + Web UI HTTPS"),
            (SERVICE_AGHOME_DOT, AGH_DOT_PORT, "tcp", "DoT"),
            (SERVICE_AGHOME_DOQ, AGH_DOQ_PORT, "udp", "DoQ"),
        ):
            ok_r, _ = port_register(tag, port, proto,
                                    comment=f"AdGuard Home {label}", force=True)
            ok, msg = ufw_open_port(port, proto, tag,
                                    comment=f"AdGuard Home {label}")
            if ok:
                info(f"AGH: порт {port}/{proto} открыт в UFW ({label})")
            else:
                core.warn(f"AGH: не удалось открыть {port}/{proto} в UFW: {msg}")


def ufw_close_quiet(port: int, proto: str, service_tag: str) -> None:
    """Закрывает порт в UFW тихо (без исключений)."""
    try:
        from chimera.modules.port_registry import ufw_close_port
        ufw_close_port(port, proto, service_tag)
    except Exception:
        pass


def _unregister_aghome_ports() -> None:
    """Снимает регистрацию и закрывает ВСЕ порты DNS-стека AGH
    (кроме dnscrypt :5300 — он остаётся жить)."""
    try:
        from chimera.modules.port_registry import (
            port_unregister, ufw_close_port,
            SERVICE_AGHOME, SERVICE_AGHOME_WEB, SERVICE_AGHOME_DOH,
            SERVICE_AGHOME_DOT, SERVICE_AGHOME_DOQ,
        )
        for tag, port, proto in (
            (SERVICE_AGHOME,         AGH_DNS_PORT, "udp"),
            (SERVICE_AGHOME,         AGH_DNS_PORT, "tcp"),
            (SERVICE_AGHOME_WEB,     AGH_WEB_PORT, "tcp"),
            (SERVICE_AGHOME_DOH,     AGH_DOH_PORT, "tcp"),
            (SERVICE_AGHOME_DOT,     AGH_DOT_PORT, "tcp"),
            (SERVICE_AGHOME_DOQ,     AGH_DOQ_PORT, "udp"),
        ):
            ufw_close_port(port, proto, tag)
            port_unregister(tag, port=port, proto=proto)
    except Exception:
        pass


# ============================================================================
#  УСТАНОВКА
# ============================================================================
def _get_latest_agh_tag() -> str:
    """Последний release-tag AGH из GitHub API (3 попытки)."""
    for attempt in range(3):
        try:
            r = subprocess.run(
                ["curl", "-fsSL", "--connect-timeout", "10",
                 "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest"],
                capture_output=True, text=True, check=False, timeout=30)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                tag = data.get("tag_name", "")
                if tag:
                    return tag
        except Exception:
            pass
        time.sleep(3)
    return ""


def _ask_web_mode() -> "tuple[str, str]":
    """Спрашивает режим Web UI. Возвращает (web_mode, domain).

    Режимы:
      1. https_le     — домен + Let's Encrypt, https://{domain}:30443 (рекоменд.)
      2. https_self   — self-signed, https://IP:30443
      3. http_public  — plain HTTP 0.0.0.0:3000
      4. loopback     — 127.0.0.1:3000 (SSH-туннель)
    """
    core = _core_module()
    CYAN, NC, DIM, GREEN, YELLOW = core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW
    _box_top, _box_row, _box_sep, _box_bottom, _box_item = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom, core._box_item)

    param_domain = getattr(core, "PARAM_DOMAIN", "") or ""

    print()
    _box_top("🛡️  AdGuard Home — доступ к Web UI")
    _box_row()
    _box_row(f"  {DIM}Web UI + DoH/DoT/DoQ обслуживаются одним TLS-портом{NC}")
    _box_row(f"  {DIM}AGH ({AGH_DOH_PORT}) — сертификат домена или self-signed.{NC}")
    _box_sep()
    if param_domain:
        _box_row(f"  {DIM}Домен сервера: {YELLOW}{param_domain}{NC}")
        _box_sep()
    _box_item("1", f"HTTPS + Let's Encrypt {GREEN}(домен — рекомендуется){NC}")
    _box_item("2", f"HTTPS + self-signed {DIM}(по IP, браузер предупредит){NC}")
    _box_item("3", f"HTTP публично :{AGH_WEB_PORT} {DIM}(без TLS — пароль открытым текстом){NC}")
    _box_item("4", f"Только локально 127.0.0.1:{AGH_WEB_PORT} {DIM}(SSH-туннель){NC}")
    _box_bottom()
    try:
        ch = input(f"{CYAN}  Выбор [1]: {NC}").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return AGH_WEB_LOOPBACK, ""
    if ch == "2":
        return AGH_WEB_HTTPS_SELF, ""
    if ch == "3":
        return AGH_WEB_HTTP_PUB, ""
    if ch == "4":
        return AGH_WEB_LOOPBACK, ""

    # HTTPS + Let's Encrypt → домен
    domain = param_domain
    try:
        if domain:
            ans = input(f"{CYAN}  Домен (Enter={domain}): {NC}").strip()
            domain = ans or domain
        else:
            domain = input(f"{CYAN}  Домен: {NC}").strip()
    except (EOFError, KeyboardInterrupt):
        domain = ""
    if not domain:
        try:
            core.warn("Домен не задан — переключаю на self-signed режим")
        except Exception:
            pass
        return AGH_WEB_HTTPS_SELF, ""
    return AGH_WEB_HTTPS_LE, domain


def install_aghome(interactive: bool = True) -> bool:
    """Установка AdGuard Home поверх DNSCrypt.

    Шаги:
      1. Проверка: dnscrypt-proxy активен (upstream-требование).
      2. Скачивание бинарника (fetch_package + зеркала).
      3. Пользователь adguard + рабочие директории.
      4. МИГРАЦИЯ: снять :53 у dnscrypt (redirect 53→5300 страхует DNS).
      5. systemd-unit + старт БЕЗ конфига → нативный wizard (:3000).
      6. Временный доступ к :3000 (IP SSH-клиента) + порт_registry.
      7. interactive: ожидание завершения мастера → финализация.

    Возвращает True если AGH установлен и (interactive) финализирован.
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    _run = core._run

    # ── 1. dnscrypt обязателен (upstream) ─────────────────────────────
    if not _svc_is_active("dnscrypt-proxy"):
        warn("AGH: dnscrypt-proxy не активен — AdGuard Home не будет установлен")
        warn("AGH: сначала установите DNSCrypt (Сеть → установка / wizard)")
        return False

    info("Установка AdGuard Home...")

    # ── 2. Бинарник ───────────────────────────────────────────────────
    arch_raw = subprocess.run(["uname", "-m"], capture_output=True, text=True,
                              check=False).stdout.strip()
    arch_map = {
        "x86_64": "amd64", "aarch64": "arm64",
        "armv7l": "armv7", "armv6l": "armv6", "armv5tel": "armv5",
        "i386": "386", "i686": "386",
    }
    agh_arch = arch_map.get(arch_raw)
    if not agh_arch:
        warn(f"AGH: неподдерживаемая архитектура {arch_raw} — пропускаем")
        return False

    # Уже установленная версия?
    if AGH_BIN.exists():
        r = subprocess.run([str(AGH_BIN), "--version"], capture_output=True,
                           text=True, check=False)
        ver = (r.stdout or "").splitlines()[0] if r.stdout else "?"
        info(f"AGH: бинарник уже установлен ({ver}) — пропускаем скачивание")
    else:
        from chimera.modules.aghome_mirrors import AGHOME_FALLBACK_TAG
        latest = _get_latest_agh_tag()
        tag = latest or AGHOME_FALLBACK_TAG
        if not latest:
            info(f"AGH: GitHub API недоступен — pinned {tag} + зеркала adtidy.org")
        info(f"AGH: {tag} (linux_{agh_arch})")
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.aghome_packages import AGHOME_SPEC
        if not fetch_package(AGHOME_SPEC, tag=tag, arch=agh_arch):
            warn("AGH: не удалось скачать AdGuardHome — установка прервана")
            warn("AGH: скачайте tar.gz вручную в /root/ и повторите (Сеть → A)")
            return False
        success(f"AGH: бинарник установлен: {AGH_BIN}")

    # ── 3. Пользователь + директории ─────────────────────────────────
    AGH_WORK_DIR.mkdir(parents=True, exist_ok=True)
    AGH_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    (AGH_WORK_DIR / "data").mkdir(parents=True, exist_ok=True)
    _create_aghome_user()

    # ── 4. Миграция dnscrypt с :53 ────────────────────────────────────
    if not migrate_dnscrypt_off_53():
        warn("AGH: не удалось освободить :53 у dnscrypt — установка прервана")
        return False

    # ── 5. systemd unit + wizard-старт ────────────────────────────────
    if not _write_aghome_unit():
        return False

    # Режим мастера: конфиг НЕ создаём (detectFirstRun: файла нет → wizard)
    wizard_restart = False
    if AGH_CONF.exists():
        # Существующий конфиг (переустановка) — сохраняем, финализация
        # обновит секции на месте.
        info("AGH: существующий конфиг найден — переустановка без мастера")
    else:
        wizard_restart = True

    _run(["systemctl", "enable", AGH_SERVICE_NAME], check=False, quiet=True)
    _run(["systemctl", "restart", AGH_SERVICE_NAME], check=False, quiet=True)

    if not _wait_service(AGH_SERVICE_NAME, 30):
        warn("AGH: служба не запустилась — journalctl -u AdGuardHome -n 30")
        return False
    success(f"AGH: служба активна ( {'мастер первого запуска' if wizard_restart else 'существующий конфиг'} )")

    # ── 6. Доступ к мастеру + state ───────────────────────────────────
    web_mode, domain = AGH_WEB_LOOPBACK, ""
    if wizard_restart:
        ssh_ip = _get_ssh_client_ip()
        web_mode, domain = _ask_web_mode()

        # Доступ: IP SSH-клиента + public IP VPS (hairpin через VLESS-
        # туннель на этой же VPS: браузер через прокси = запрос с IP VPS)
        wizard_ips = _open_wizard_access(ssh_ip)
        if wizard_ips:
            info("AGH: мастер открыт в UFW для IP: "
                 + ", ".join(wizard_ips) + " (временно)")
        elif ssh_ip:
            info("AGH: UFW недоступен — используйте SSH-туннель")
        else:
            info("AGH: IP SSH-клиента не определён — используйте SSH-туннель")

        aghome_state_save({
            "enabled": True,
            "phase": "wizard",
            "web_mode": web_mode,
            "web_port": AGH_WEB_PORT,
            "domain": domain,
            "self_signed": web_mode == AGH_WEB_HTTPS_SELF,
            "tls_enabled": web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF),
            "doh_port": AGH_DOH_PORT,
            "dot_port": AGH_DOT_PORT,
            "doq_port": AGH_DOQ_PORT,
            "wizard_ips": wizard_ips,
            "wizard_ssh_ip": ssh_ip,
            "installed_at": datetime.now().isoformat(),
        })

        # Инструкция по мастеру: URL — ВСЕГДА адрес СЕРВЕРА
        # (никогда IP SSH-клиента: на нём ничего не слушает).
        pub_ip = _get_public_ip()
        wizard_host = pub_ip if _is_public_ipv4(pub_ip) else "IP-СЕРВЕРА"
        _CYAN = getattr(core, "CYAN", "")
        _NC = getattr(core, "NC", "")
        _DIM = getattr(core, "DIM", "")
        print()
        core._box_top("🛡️  AdGuard Home — мастер первого запуска")
        core._box_row()
        core._box_row(f"  Откройте в браузере {_CYAN}http://{wizard_host}:{AGH_WEB_PORT}{_NC}")
        if domain:
            core._box_row(f"  {_DIM}(или http://{domain}:{AGH_WEB_PORT}){_NC}")
        core._box_sep()
        core._box_row(f"  {_DIM}Через VLESS-туннель — тот же URL (доступ с IP сервера открыт){_NC}")
        core._box_row(f"  {_DIM}Напрямую не открывается: ssh -L {AGH_WEB_PORT}:127.0.0.1:{AGH_WEB_PORT} root@{wizard_host}{_NC}")
        core._box_sep()
        core._box_row(f"  1. Веб-интерфейс: {_CYAN}Все интерфейсы / 0.0.0.0 :{AGH_WEB_PORT}{_NC}")
        core._box_row(f"  2. DNS-сервер:    {_CYAN}Только 127.0.0.1 (Loopback){_NC}")
        core._box_row(f"     {_DIM}(Chimera перенастроит адреса автоматически){_NC}")
        core._box_row(f"  3. Логин/пароль:  {_CYAN}придумайте (admin + ваш пароль){_NC}")
        core._box_sep()
        core._box_row(f"  {_DIM}Пока мастер не завершён, :53 держит redirect → dnscrypt.{_NC}")
        core._box_bottom()

        # ── 7. Ожидание мастера ───────────────────────────────────────
        if interactive:
            info("Ожидание завершения мастера в браузере "
                 f"(до {AGH_WIZARD_WAIT_SEC // 60} мин, Ctrl+C — пропустить)...")
            if _wait_wizard_completed(AGH_WIZARD_WAIT_SEC):
                return finalize_aghome_config()
            warn("AGH: мастер не завершён — установка продолжается")
            info("AGH: завершите мастер позже и выберите: Сеть → A → 2 (Завершить настройку)")
            return True
        # неинтерактивно (do_full_install продолжит своё)
        return True

    # Существующий конфиг → сразу финализируем (идемпотентно)
    if interactive:
        st = aghome_state_load()
        web_mode = st.get("web_mode", AGH_WEB_HTTPS_LE)
        domain = st.get("domain", "")
        return finalize_aghome_config(web_mode=web_mode, domain=domain)
    return True


def _wait_wizard_completed(timeout_sec: int, poll_sec: float = 5.0) -> bool:
    """Ждёт пока мастер первого запуска запишет конфиг с users."""
    core = _core_module()
    deadline = time.monotonic() + timeout_sec
    last_dot = 0
    while time.monotonic() < deadline:
        if AGH_CONF.exists():
            try:
                text = AGH_CONF.read_text(errors="replace")
            except Exception:
                text = ""
            if _yaml_has_users(text):
                print()
                return True
        # активность службы могла упасть — мастер требует живой web
        if not _svc_is_active():
            try:
                core.warn("AGH: служба не активна во время ожидания мастера")
            except Exception:
                pass
            return False
        n = int((time.monotonic() - (deadline - timeout_sec)) // 10)
        if n > last_dot:
            print(".", end="", flush=True)
            last_dot = n
        time.sleep(poll_sec)
    print()
    return False


# ============================================================================
#  ФИНАЛИЗАЦИЯ (после мастера; идемпотентна)
# ============================================================================
def finalize_aghome_config(web_mode: str = "", domain: str = "",
                           interactive: bool = True) -> bool:
    """Применяет канонический конфиг Chimera к yaml, написанному мастером.

    Шаги:
      1. Читает yaml (требуется непустой users — мастер завершён).
      2. Готовит TLS-сертификат (LE-копия / self-signed) при TLS-режиме.
      3. Хирургически заменяет секции dns/tls/http/filters/querylog/
         statistics (+ language: ru), бэкапит оригинал.
      4. chown adguard, restart, ожидание active, проверка :53/:853/:30443.
      5. Self-heal: при провале bind на public IP → loopback-only bind.
      6. Снимает redirect 53→5300 (AGH владеет :53) через
         fix_resolv_conf_to_localhost(force=True) с AGH-aware веткой.
      7. Закрывает временный wizard-доступ, финальные порты в UFW/реестре.
      8. Перегенерирует конфиг Xray (DNS → 127.0.0.1:53 → AGH).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success

    if not AGH_CONF.exists():
        warn("AGH: конфиг не найден — мастер первого запуска не завершён")
        if interactive:
            info("AGH: откройте Web UI, задайте логин/пароль, затем повторите")
        return False
    try:
        original = AGH_CONF.read_text(errors="replace")
    except Exception as e:
        warn(f"AGH: не удалось прочитать конфиг: {e}")
        return False
    if not _yaml_has_users(original):
        warn("AGH: в конфиге нет users — мастер не завершён (lockout-риск)")
        return False

    st = aghome_state_load()
    if not web_mode:
        web_mode = st.get("web_mode", AGH_WEB_HTTPS_LE)
    if not domain:
        domain = st.get("domain", "") or (getattr(core, "PARAM_DOMAIN", "") or "")
    tls_enabled = web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF)

    # ── TLS-сертификат ────────────────────────────────────────────────
    cert_path = key_path = None
    server_name = domain
    if tls_enabled:
        cert_path, key_path = _prepare_tls_cert(web_mode, domain)
        if cert_path is None:
            warn("AGH: TLS-сертификат недоступен — DoH/DoT/DoQ отключаются")
            tls_enabled = False
            web_mode = AGH_WEB_HTTP_PUB if web_mode != AGH_WEB_LOOPBACK else web_mode
        if not server_name:
            server_name = _get_public_ip() or "localhost"

    # ── Сборка секций ─────────────────────────────────────────────────
    dc_port = _get_dnscrypt_port()
    public_ip = _get_public_ip()
    if not public_ip:
        warn("AGH: публичный IP не определён — DoT/DoQ/DoH будут loopback-only")
    if not public_ip and tls_enabled:
        # без public IP TLS-порты бессмысленны публично, но оставляем —
        # loopback DoH/DoT тоже валидны (тесты, локальные клиенты).
        pass

    sections: dict = {
        "http":          build_http_section(web_mode),
        "dns":           build_dns_section(dc_port, public_ip, tls_enabled),
        "tls":           build_tls_section(tls_enabled, server_name, cert_path, key_path),
        "filters":       build_filters_section(),
        "querylog":      build_querylog_section(),
        "statistics":    build_statistics_section(),
        "dhcp":          "dhcp:\n  enabled: false\n",
    }
    new_text = yaml_replace_sections(
        original, sections, scalars={"language": "ru"})

    # ── Бэкап + запись ────────────────────────────────────────────────
    AGH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    bak = AGH_BACKUP_DIR / (
        "AdGuardHome.yaml." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
    try:
        shutil.copy2(AGH_CONF, bak)
    except Exception:
        pass
    try:
        AGH_CONF.write_text(new_text)
        subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                       capture_output=True, check=False)
        AGH_CONF.chmod(0o640)
    except Exception as e:
        warn(f"AGH: не удалось записать конфиг: {e}")
        return False

    # ── Restart + верификация ─────────────────────────────────────────
    subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    ok = _wait_service(AGH_SERVICE_NAME, 30)

    if not ok:
        # Self-heal #1: без public IP в bind_hosts (типовая причина падения —
        # IP изменился/недоступен)
        warn("AGH: не запустилась с полным bind_hosts — пробую loopback-only...")
        healed = build_dns_section(dc_port, "", tls_enabled)
        new_text2 = yaml_replace_sections(new_text, {"dns": healed})
        try:
            AGH_CONF.write_text(new_text2)
            subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                           capture_output=True, check=False)
        except Exception:
            pass
        subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
        ok = _wait_service(AGH_SERVICE_NAME, 20)
        public_ip = ""

    if not ok:
        # Self-heal #2: откат к yaml мастера (DNS работает, секции дефолтные)
        warn("AGH: не запустилась после финализации — откат к конфигу мастера")
        try:
            shutil.copy2(bak, AGH_CONF)
            subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                           capture_output=True, check=False)
        except Exception:
            pass
        subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
        if _wait_service(AGH_SERVICE_NAME, 20):
            warn("AGH: работает на конфиге мастера (без канонических секций)")
            warn("AGH: смотрите journalctl -u AdGuardHome -n 30 и повторите финализацию")
        else:
            # Self-heal #3: DNS black-hole недопустим — вернуть redirect
            warn("AGH: критично — возвращаю системный DNS на dnscrypt redirect")
            _emergency_restore_dnscrypt_redirect()
        return False

    # ── Верификация портов ────────────────────────────────────────────
    dns_udp = _port_listening(AGH_DNS_PORT, "udp")
    dns_tcp = _port_listening(AGH_DNS_PORT, "tcp")
    if dns_udp:
        success(f"AGH: DNS слушает :{AGH_DNS_PORT} (udp{'+' + 'tcp' if dns_tcp else ''})")
    else:
        warn(f"AGH: активна, но :{AGH_DNS_PORT}/udp не слушается — journalctl")

    if tls_enabled:
        for port, proto, label in (
            (AGH_DOH_PORT, "tcp", "DoH+HTTPS"),
            (AGH_DOT_PORT, "tcp", "DoT"),
            (AGH_DOQ_PORT, "udp", "DoQ"),
        ):
            if _port_listening(port, proto):
                success(f"AGH: {label} слушает :{port}/{proto}")
            else:
                warn(f"AGH: {label} :{port}/{proto} не слушается")

    # ── Снятие redirect 53→5300 (AGH владеет :53) ─────────────────────
    if dns_udp:
        try:
            from chimera.modules.resolv_conf_fix import (
                fix_resolv_conf_to_localhost,
            )
            result = fix_resolv_conf_to_localhost(force=True)
            if result.get("ok"):
                info("AGH: redirect 53→5300 снят, системный DNS → AGH :53")
                info("AGH: persist-скрипт обновлён (AGH-aware)")
            else:
                warn(f"AGH: resolv-фикс вернул ошибку: {result.get('error')}")
        except Exception as e:
            warn(f"AGH: не удалось вызвать resolv-фикс: {e}")
            # Прямое снятие правил как fallback
            _remove_dns_redirect_direct()

    # ── Временный wizard-доступ → финальные порты ─────────────────────
    # Удаляем ВСЕ временные правила: wizard_ips (список), legacy
    # wizard_ssh_ip (одиночный) + подчистка по comment (крэши/переустановки)
    legacy_ips = list(st.get("wizard_ips", []))
    if st.get("wizard_ssh_ip"):
        legacy_ips.append(st["wizard_ssh_ip"])
    for wip in dict.fromkeys(legacy_ips):  # уникальные, порядок сохранён
        _ufw_delete_rule("allow", "from", str(wip), "to", "any",
                         "port", str(AGH_WEB_PORT), "proto", "tcp")
    _ufw_clean_wizard_rules()
    _register_aghome_ports(dc_port, tls_enabled,
                           web_public_plain=(web_mode == AGH_WEB_HTTP_PUB))

    # ── Перегенерация конфига Xray ────────────────────────────────────
    if dns_udp:
        _regenerate_xray_config(interactive=interactive)

    # ── State ─────────────────────────────────────────────────────────
    aghome_state_save({
        **st,
        "enabled": True,
        "phase": "finalized",
        "web_mode": web_mode,
        "web_port": AGH_WEB_PORT,
        "domain": domain,
        "self_signed": web_mode == AGH_WEB_HTTPS_SELF,
        "tls_enabled": tls_enabled,
        "public_bind": bool(public_ip),
        "doh_port": AGH_DOH_PORT,
        "dot_port": AGH_DOT_PORT,
        "doq_port": AGH_DOQ_PORT,
        "wizard_ips": [],
        "wizard_ssh_ip": "",
        "finalized_at": datetime.now().isoformat(),
    })
    success("AGH: финализация завершена — DNS: AGH:53 → dnscrypt:" + str(dc_port))
    if tls_enabled and domain:
        info(f"AGH: DoH: https://{domain}:{AGH_DOH_PORT}/dns-query")
        info(f"AGH: DoT: {domain}:{AGH_DOT_PORT} | DoQ: {domain}:{AGH_DOQ_PORT}/udp")
    return True


def _remove_dns_redirect_direct() -> None:
    """Прямое снятие iptables-правил redirect 53→5300 (fallback, если
    resolv_conf_fix недоступен). Совпадает с chimera-dns-fix комментарием."""
    for proto in ("udp", "tcp"):
        for port in (5300, 5353, 6000, 6053):
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "OUTPUT",
                 "-p", proto, "-d", "127.0.0.1", "--dport", "53",
                 "-j", "REDIRECT", "--to-ports", str(port),
                 "-m", "comment", "--comment", "chimera-dns-fix"],
                capture_output=True, check=False)


def _emergency_restore_dnscrypt_redirect() -> None:
    """Восстанавливает redirect 53→5300 (DNS black-hole недопустим)."""
    try:
        from chimera.modules.resolv_conf_fix import (
            fix_resolv_conf_to_localhost,
        )
        fix_resolv_conf_to_localhost(force=True)
    except Exception:
        _remove_dns_redirect_direct()
        for proto in ("udp", "tcp"):
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "OUTPUT",
                 "-p", proto, "-d", "127.0.0.1", "--dport", "53",
                 "-j", "REDIRECT", "--to-ports", "5300",
                 "-m", "comment", "--comment", "chimera-dns-fix"],
                capture_output=True, check=False)


def _regenerate_xray_config(interactive: bool = True) -> bool:
    """Перегенерирует конфиг Xray с DNS через AGH (127.0.0.1:53).

    Выбирает генератор по state.json (protocol_mode/install_mode),
    подгружает глобали, рестартит xray. При провале — warn (конфиг можно
    пересоздать через меню: Установка → Пересоздать конфиг Xray).
    """
    core = _core_module()
    info, warn = core.info, core.warn
    try:
        state_path = Path("/var/lib/xray-installer/state.json")
        if not state_path.exists():
            warn("AGH: state.json не найден — конфиг Xray не перегенерирован")
            return False
        state = json.loads(state_path.read_text())
        protocol = state.get("protocol_mode", "reality")
        mode = state.get("install_mode", "A")

        if hasattr(core, "_load_state_into_globals"):
            core._load_state_into_globals()

        from chimera.modules import xray_install
        if mode == "B":
            xray_install.generate_xray_config_chain_entry_multi()
        elif protocol == "xhttp":
            xray_install.generate_xray_config_xhttp()
        else:
            xray_install.generate_xray_config()

        subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, check=False)
        time.sleep(2)
        if _svc_is_active("xray"):
            info("AGH: конфиг Xray обновлён (DNS → 127.0.0.1:53 через AGH)")
            return True
        warn("AGH: xray не перезапустился — journalctl -u xray -n 20")
        return False
    except Exception as e:
        warn(f"AGH: не удалось перегенерировать конфиг Xray: {e}")
        return False


# ============================================================================
#  УДАЛЕНИЕ
# ============================================================================
def uninstall_aghome() -> bool:
    """Полное удаление AGH с откатом DNS-стека к dnscrypt.

    Шаги:
      1. Останов/отключение службы, удаление unit + бинарника.
      2. Бэкап /opt/AdGuardHome → /root/aghome-backups/aghome-*.tar.gz.
      3. Удаление пользователя adguard.
      4. Снятие certbot deploy-hook.
      5. Закрытие портов: UFW + port_registry (все AGH-теги).
      6. Восстановление redirect 53→5300 (fix_resolv_conf force) —
         системный DNS снова через dnscrypt.
      7. Перегенерация конфига Xray (DNS → dnscrypt:5300).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success

    if not is_aghome_installed() and not AGH_SERVICE_UNIT.exists():
        warn("AGH: не установлен — нечего удалять")
        return False

    # ── 1. Служба ─────────────────────────────────────────────────────
    subprocess.run(["systemctl", "stop", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    subprocess.run(["systemctl", "disable", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    try:
        AGH_SERVICE_UNIT.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, check=False)
    except Exception:
        pass

    # ── 2. Бэкап рабочей директории ───────────────────────────────────
    if AGH_WORK_DIR.exists():
        AGH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        tgz = AGH_BACKUP_DIR / (
            "aghome-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".tar.gz")
        try:
            subprocess.run(
                ["tar", "-czf", str(tgz), "-C", str(AGH_WORK_DIR.parent),
                 AGH_WORK_DIR.name],
                capture_output=True, check=False, timeout=120)
            info(f"AGH: бэкап → {tgz}")
        except Exception as e:
            warn(f"AGH: не удалось создать бэкап: {e}")
        try:
            shutil.rmtree(AGH_WORK_DIR, ignore_errors=True)
        except Exception:
            pass

    # ── 3. Бинарник + пользователь ────────────────────────────────────
    try:
        AGH_BIN.unlink(missing_ok=True)
    except Exception:
        pass
    subprocess.run(["userdel", AGH_USER], capture_output=True, check=False)

    # ── 4. Certbot hook ───────────────────────────────────────────────
    _remove_certbot_deploy_hook()

    # ── 5. Порты ──────────────────────────────────────────────────────
    _ufw_clean_wizard_rules()  # висящие wizard-temp правила
    _unregister_aghome_ports()

    # ── 6. DNS обратно на dnscrypt redirect ───────────────────────────
    try:
        from chimera.modules.resolv_conf_fix import (
            fix_resolv_conf_to_localhost,
        )
        result = fix_resolv_conf_to_localhost(force=True)
        if result.get("ok"):
            info("AGH: системный DNS → dnscrypt (redirect 53→5300 восстановлен)")
        else:
            warn(f"AGH: resolv-фикс: {result.get('error')}")
    except Exception as e:
        warn(f"AGH: resolv-фикс недоступен: {e}")

    # ── 7. Xray ───────────────────────────────────────────────────────
    _regenerate_xray_config(interactive=False)

    aghome_state_save({"enabled": False, "phase": "removed",
                       "removed_at": datetime.now().isoformat()})
    try:
        AGH_STATE_FILE.unlink(missing_ok=True)
    except Exception:
        pass

    success("AGH: AdGuard Home удалён, DNS-стек: dnscrypt:5300 (как до установки)")
    return True


# ============================================================================
#  СБРОС ПАРОЛЯ АДМИНА
# ============================================================================
def aghome_reset_admin_password() -> bool:
    """Сброс пароля через повторный запуск мастера.

    Механика (единственный способ без bcrypt в окружении Python):
      1. Стоп AGH, yaml → бэкап, yaml удаляется.
      2. Старт AGH → detectFirstRun: конфига нет → мастер в браузере.
      3. Пользователь задаёт новый логин/пароль.
      4. _wait_wizard_completed → финализация (секции восстанавливаются
         из aghome_state.json — режим Web UI/домен/TLS сохраняются).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success

    if not is_aghome_installed():
        warn("AGH: не установлен")
        return False

    st = aghome_state_load()
    subprocess.run(["systemctl", "stop", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    time.sleep(2)

    if AGH_CONF.exists():
        AGH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        bak = AGH_BACKUP_DIR / (
            "AdGuardHome.yaml." + datetime.now().strftime("%Y%m%d%H%M%S")
            + ".pre-reset.bak")
        try:
            shutil.copy2(AGH_CONF, bak)
        except Exception:
            pass
        AGH_CONF.unlink(missing_ok=True)

    subprocess.run(["systemctl", "start", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    if not _wait_service(AGH_SERVICE_NAME, 30):
        warn("AGH: служба не запустилась в режиме мастера")
        return False

    ssh_ip = _get_ssh_client_ip()
    wizard_ips = _open_wizard_access(ssh_ip)
    if wizard_ips:
        info("AGH: мастер открыт в UFW для IP: "
             + ", ".join(wizard_ips) + " (временно)")
    wizard_host = _get_public_ip()
    if not _is_public_ipv4(wizard_host):
        wizard_host = "IP-СЕРВЕРА"
    info(f"AGH: откройте http://{wizard_host}:{AGH_WEB_PORT} "
         f"и задайте НОВЫЙ логин/пароль администратора")

    aghome_state_save({**st, "phase": "wizard",
                       "wizard_ips": wizard_ips, "wizard_ssh_ip": ssh_ip})

    if _wait_wizard_completed(AGH_WIZARD_WAIT_SEC):
        ok = finalize_aghome_config(web_mode=st.get("web_mode", AGH_WEB_HTTPS_LE),
                                    domain=st.get("domain", ""))
        if ok:
            success("AGH: пароль администратора обновлён, конфиг восстановлен")
        return ok
    warn("AGH: мастер не завершён — пароль не изменён, конфиг не тронут")
    info("AGH: повторите позже: Сеть → A → 3 (Сброс пароля)")
    return False


# ============================================================================
#  СТАТУС
# ============================================================================
def aghome_status() -> dict:
    """Сводное состояние AGH для TUI/диагностики."""
    st = aghome_state_load()
    r_ver = subprocess.run([str(AGH_BIN), "--version"], capture_output=True,
                           text=True, check=False) if AGH_BIN.exists() else None
    version = ""
    if r_ver and r_ver.stdout:
        m = re.search(r'v?(\d+\.\d+\.\d+)', r_ver.stdout)
        version = m.group(1) if m else r_ver.stdout.splitlines()[0][:40]

    web_port = st.get("web_port", AGH_WEB_PORT)
    tls_enabled = st.get("tls_enabled", False)
    domain = st.get("domain", "")

    return {
        "installed":        is_aghome_installed(),
        "active":           is_aghome_active(),
        "enabled":          _svc_is_enabled(),
        "dns_ready":        aghome_dns_ready(),
        "wizard_pending":   aghome_wizard_pending(),
        "phase":            st.get("phase", "unknown"),
        "version":          version,
        "web_mode":         st.get("web_mode", ""),
        "web_port":         web_port,
        "web_listening":    _port_listening(web_port, "tcp"),
        "domain":           domain,
        "self_signed":      st.get("self_signed", False),
        "tls_enabled":      tls_enabled,
        "doh_port":         st.get("doh_port", AGH_DOH_PORT),
        "doh_listening":    _port_listening(st.get("doh_port", AGH_DOH_PORT), "tcp"),
        "dot_port":         st.get("dot_port", AGH_DOT_PORT),
        "dot_listening":    _port_listening(st.get("dot_port", AGH_DOT_PORT), "tcp"),
        "doq_port":         st.get("doq_port", AGH_DOQ_PORT),
        "doq_listening":    _port_listening(st.get("doq_port", AGH_DOQ_PORT), "udp"),
        "dns_port":         AGH_DNS_PORT,
        "dns_udp":          _port_listening(AGH_DNS_PORT, "udp"),
        "dns_tcp":          _port_listening(AGH_DNS_PORT, "tcp"),
        "upstream_port":    _get_dnscrypt_port(),
        "upstream_active":  _svc_is_active("dnscrypt-proxy"),
        "filters":          len(AGH_FILTERS),
        "conf_exists":      AGH_CONF.exists(),
        "state":            st,
    }


def print_aghome_status() -> None:
    """Рисует бокс статуса AGH."""
    core = _core_module()
    GREEN, RED, YELLOW, CYAN, DIM, NC = (
        core.GREEN, core.RED, core.YELLOW, core.CYAN, core.DIM, core.NC)
    _box_top, _box_row, _box_sep, _box_bottom = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom)

    s = aghome_status()
    print()
    _box_top("🛡️  AdGuard Home — статус")

    def _mark(flag: bool) -> str:
        return f"{GREEN}✓{NC}" if flag else f"{RED}✗{NC}"

    if not s["installed"]:
        _box_row(f"  Установлен:        {_mark(False)} (нет бинарника)")
        _box_bottom()
        return

    _box_row(f"  Версия:            {CYAN}{s['version'] or '?'}{NC}")
    _box_row(f"  Служба:            {_mark(s['active'])} "
             f"({'active' if s['active'] else 'stopped'})"
             f"  {'enabled' if s['enabled'] else 'disabled'}")
    _box_row(f"  DNS :{s['dns_port']}:          {_mark(s['dns_udp'] and s['dns_tcp'])} "
             f"(udp {s['dns_udp']}, tcp {s['dns_tcp']})")
    _box_row(f"  Upstream:          dnscrypt:{s['upstream_port']} "
             f"{_mark(s['upstream_active'])}")
    _box_row(f"  Web UI:            :{s['web_port']} {_mark(s['web_listening'])} "
             f"({s['web_mode'] or '?'})")
    if s["tls_enabled"]:
        _box_row(f"  TLS:               {CYAN}{s['domain'] or 'self-signed'}{NC}"
                 f"{' (self-signed)' if s['self_signed'] else ''}")
        _box_row(f"  DoH :{s['doh_port']}:          {_mark(s['doh_listening'])} "
                 f"(https + /dns-query)")
        _box_row(f"  DoT :{s['dot_port']}/tcp:       {_mark(s['dot_listening'])}")
        _box_row(f"  DoQ :{s['doq_port']}/udp:       {_mark(s['doq_listening'])}")
    else:
        _box_row(f"  TLS:               {DIM}выключен (DoH/DoT/DoQ недоступны){NC}")
    _box_sep()
    if s["wizard_pending"]:
        _box_row(f"  {YELLOW}⚠ Мастер первого запуска НЕ завершён — DNS :53 "
                 f"держит dnscrypt redirect{NC}")
        _box_row(f"  {DIM}Завершите: Сеть → A → 2{NC}")
    else:
        _box_row(f"  Фильтры:           {s['filters']} (AdGuard DNS + AdAway + OISD Big)")
        _box_row(f"  Query log/stats:   {GREEN}включены (ретенция 90 дней){NC}")
    _box_sep()
    _box_row(f"  {DIM}Конфиг: {AGH_CONF}{NC}")
    _box_row(f"  {DIM}Бэкапы: {AGH_BACKUP_DIR}/{NC}")
    _box_bottom()


# ============================================================================
#  TUI-МЕНЮ
# ============================================================================
def do_aghome_menu() -> None:
    """Меню AdGuard Home (Сеть → A)."""
    core = _core_module()
    CYAN, NC, DIM, GREEN, YELLOW, RED = (
        core.CYAN, core.NC, core.DIM, core.GREEN, core.YELLOW, core.RED)
    _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom,
        core._box_item, core._box_back)

    while True:
        import os as _os
        _os.system("clear")
        print()
        st = aghome_state_load()
        phase = st.get("phase", "")
        badge = ""
        if phase == "wizard":
            badge = f"  {YELLOW}[МАСТЕР НЕ ЗАВЕРШЁН]{NC}"
        elif phase == "finalized":
            badge = f"  {GREEN}[OK]{NC}"
        _box_top(f"🛡️  ADGUARD HOME{badge}")
        _box_row()
        _box_row(f"  {DIM}DNS: AGH :{AGH_DNS_PORT} (кеш+фильтры) → dnscrypt :5300 "
                 f"(шифрование){NC}")
        _box_row()
        _box_item("1", f"📦 Установить / переустановить{DIM}(wizard + финализация){NC}")
        _box_item("2", f"📊 Статус + завершить настройку{DIM}(если мастер не завершён){NC}")
        _box_item("3", f"🔑 Сброс пароля админа{DIM}(мастер заново){NC}")
        _box_item("4", f"🔒 Сменить режим Web UI / TLS{DIM}(домен, self-signed, публичность){NC}")
        _box_item("5", f"🔄 Переприменить конфиг{DIM}(фильтры/DoH/DoT/DoQ по канону){NC}")
        _box_sep()
        _box_item("9", f"🗑️  Удалить AdGuard Home{DIM}(откат к dnscrypt:5300){NC}")
        _box_row()
        _box_back()
        _box_bottom()
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            try:
                install_aghome(interactive=True)
            except Exception as e:
                core.warn(f"AGH: ошибка установки: {e}")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            print_aghome_status()
            if aghome_wizard_pending():
                try:
                    ans = input("Мастер не завершён. Ждать завершения сейчас? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = "n"
                if ans in ("", "y", "yes"):
                    if _wait_wizard_completed(AGH_WIZARD_WAIT_SEC):
                        finalize_aghome_config()
                    else:
                        core.warn("AGH: мастер по-прежнему не завершён")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            try:
                ans = input("Сбросить пароль через повторный мастер? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if ans in ("y", "yes"):
                aghome_reset_admin_password()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "4":
            try:
                web_mode, domain = _ask_web_mode()
                st2 = aghome_state_load()
                aghome_state_save({**st2, "web_mode": web_mode, "domain": domain,
                                   "self_signed": web_mode == AGH_WEB_HTTPS_SELF,
                                   "tls_enabled": web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF)})
                core.info("AGH: режим сохранён — применяю конфиг...")
                if AGH_CONF.exists() and not aghome_wizard_pending():
                    finalize_aghome_config(web_mode=web_mode, domain=domain)
                else:
                    core.info("AGH: применится автоматически после завершения мастера")
            except Exception as e:
                core.warn(f"AGH: ошибка смены режима: {e}")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            try:
                if AGH_CONF.exists() and not aghome_wizard_pending():
                    st2 = aghome_state_load()
                    finalize_aghome_config(
                        web_mode=st2.get("web_mode", AGH_WEB_HTTPS_LE),
                        domain=st2.get("domain", ""))
                else:
                    core.warn("AGH: конфига нет (мастер не завершён) — сначала пункт 1/2")
            except Exception as e:
                core.warn(f"AGH: ошибка переприменения: {e}")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "9":
            try:
                ans = input(f"{RED}Удалить AdGuard Home полностью? [y/N]: {NC}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if ans in ("y", "yes"):
                uninstall_aghome()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", "", "0"):
            break
        else:
            core.warn("Неверный выбор.")
            time.sleep(1)


# ============================================================================
#  ПУБЛИЧНЫЙ ЭКСПОРТ
# ============================================================================
__all__ = [
    "install_aghome",
    "finalize_aghome_config",
    "uninstall_aghome",
    "aghome_reset_admin_password",
    "is_aghome_installed",
    "is_aghome_active",
    "aghome_dns_ready",
    "aghome_wizard_pending",
    "aghome_status",
    "print_aghome_status",
    "do_aghome_menu",
    "migrate_dnscrypt_off_53",
    "yaml_replace_sections",
    "AGH_CONF", "AGH_BIN", "AGH_WORK_DIR", "AGH_STATE_FILE",
    "AGH_WEB_PORT", "AGH_DOH_PORT", "AGH_DOT_PORT", "AGH_DOQ_PORT",
    "AGH_WEB_HTTPS_LE", "AGH_WEB_HTTPS_SELF", "AGH_WEB_HTTP_PUB",
    "AGH_WEB_LOOPBACK",
]
