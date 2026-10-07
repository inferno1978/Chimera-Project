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
    AGH стартует БЕЗ конфига → wizard; по умолчанию завершается
    HEADLESS — POST /control/install/configure на loopback :3000
    (логин/пароль вводятся в TUI, yaml с bcrypt пишет сам AGH).
    Веб-мастер в браузере — fallback (v44: браузерный POST падал
    «Failed to fetch» из-за сетевого пути браузер→VPS).
  • HTTP-интерфейс :3000: на время веб-мастера порт открыт в UFW
    для ВСЕХ (v44: доступ только с IP SSH-клиента ломался при
    CGNAT/смене IP/прокси — мастер нельзя было пройти без туннелей);
    финализация закрывает. Headless-пути UFW не нужен вовсе.
  • DNS-ALIVE гарантия (v44): перед/после КАЖДОЙ фазы AGH (скачивание,
    wizard, удаление, сброс пароля) системный DNS проверяется
    ФАКТИЧЕСКИМ запросом к 127.0.0.1:53 (dig/getent); при отказе —
    авто-восстановление redirect 53→5300 (оба протокола) + красный
    бокс с ручными командами. ok:true фикса ≠ живой DNS.
  • TLS-SELF-HEAL (<node-2>): AGH при ошибке загрузки сертификата
    НЕ падает — home.go (newTLSManager err → лог) молча ставит
    tls.enabled=false, пишет это в yaml и служит plain DNS :53.
    Симптом: «DNS слушает :53, а :30443/:853 — нет». Финализация теперь
    поллит TLS-порты, при отказе берёт точную причину из journalctl,
    проверяет пару cert/key (openssl pubkey) и права пользователя
    adguard, чинит (chown / self-signed fallback / рестарт) и
    перезаписывает tls-секцию в live-конфиге.
  • ЛОЖНЫЙ :53: _port_listening больше не считает systemd-resolved
    stub (127.0.0.53:53) слушателем :53 — проверка «AGH владеет :53»
    идёт по ИМЕНИ ПРОЦЕССА AdGuardHome в ss (aghome_dns_ready —
    критично для resolv_conf_fix/xray_install).
  • XRAY MODE-B: перегенерация конфига Xray в режиме B вызывает
    chain_nodes.generate_xray_config_chain_entry_multi (жил в
    xray_install → AttributeError, конфиг не пересоздавался).
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
XRAY_STATE_FILE  = Path("/var/lib/xray-installer/state.json")

# Порты (канонические значения Chimera; web/DoH/DoT/DoQ — публичные,
# DNS :53 — loopback+public bind, в UFW снаружи НЕ открывается).
AGH_DNS_PORT     = 53
AGH_WEB_PORT     = 3000
# Порты, которые Web UI занять не может (служебные DNS-стека и системы).
AGH_WEB_PORT_RESERVED = {22, 53, 80, 443, 853, 5300, 30443}
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

# Fallback-резолверы — DoH (DNS over HTTPS, RFC 8484), полностью зашифрованы.
# Раньше тут был plaintext 9.9.9.9:53 / 149.112.112.112:53 — это означало,
# что при падении dnscrypt-proxy AGH уходил в plaintext-режим, и провайдер/
# хостер видел все DNS-запросы. DoH-фолбэки решают эту проблему: даже при
# падении dnscrypt upstream остаётся зашифрованным (TLS через :443).
#
# DoH-серверы выбраны по критериям:
#   1. Доступность с RU-хостингов (проверено на 3 серверах: 203.0.113.101,
#      203.0.113.103, 203.0.113.102 — все DoH отвечают < 1s)
#   2. Поддержка HTTP/2 (некоторые DoH требуют HTTP/2 — AdGuard Home умеет)
#   3. No-log policy (большинство публичных DoH не логируют)
#   4. Разная юрисдикция (США/Китай/Германия — нет единого места для давления)
#   5. Не входят в реестр РКН-блокировок на момент написания
#
# DoH-серверы не логируют (по их заявлениям):
#   - dns.cloudflare.com   (Cloudflare, USA)  — privacy-first, audited
#   - dns.google           (Google, USA)        — Audited by PWC, no PII logging
#   - dns.adguard-dns.com  (AdGuard, Cyprus)   — No-logs, audited
#   - dnsforge.de          (Germany, private)   — No-logs
#   - doh.pub              (AdGuard China, DNSPod/Tencent) — fallback geo
#     diversity; важно: НЕ для RU-клиентов, но как fallback на RU-серверах
#     работает (провайдер видит только TLS на 13.224.1.0/24)
#
# Bootstrap_dns по-прежнему содержит plaintext 9.9.9.9:53 — это плата за
# стабильность: AGH нужен IP-bootstrap при холодном старте (чтобы
# зарезолвить hostname DoH-сервера). Это catch-22 — без plaintext-bootstrap
# AGH не сможет достучаться до DoH при первом старте. Однако bootstrap
# срабатывает ТОЛЬКО при холодном старте AGH и больше никогда в штатной
# работе. Если dnscrypt жив (а он жив 99.9% времени), bootstrap идёт через
# 127.0.0.1:5300 (зашифровано через DNSCrypt). Plaintext 9.9.9.9 — лишь
# страховка для самого первого запроса при загрузке сервера.
AGH_FALLBACK_DNS: list[str] = [
    "https://dns.cloudflare.com/dns-query",    # Cloudflare DoH (HTTP/2)
    "https://dns.adguard-dns.com/dns-query",  # AdGuard DoH
    "https://dnsforge.de/dns-query",          # dnsforge.de (Germany)
    "https://doh.pub/dns-query",              # DNSPod/Tencent (China geo-diversity)
    "https://dns.google/dns-query",            # Google DoH (HTTP/2)
]

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


def _port_listening(port: int, proto: str = "udp", proc: str = "") -> bool:
    """Проверяет что порт слушается (ss).

     (<node-2>): регресс-фикс «ложный :53».
      1. port=53 — строки systemd-resolved stub (127.0.0.53/127.0.0.54:53,
         процесс systemd-resolved) ИСКЛЮЧАЮТСЯ: они дают ложное
         «:53 слушается», хотя AGH порт не занял (мастер/упал TLS).
      2. proc — требовать имя процесса-владельца в строке ss, напр.
         proc="AdGuardHome". Единственный надёжный способ отличить
         владельца :53 от resolved stub.
    """
    flag = "-ulnp" if proto == "udp" else "-tlnp"
    try:
        r = subprocess.run(["ss", flag], capture_output=True, text=True,
                           check=False, timeout=10)
        for ln in r.stdout.splitlines():
            if not re.search(rf":{port}\s", ln):
                continue
            if port == 53 and ("127.0.0.53" in ln or "127.0.0.54" in ln
                               or "resolved" in ln):
                continue  # systemd-resolved stub — НЕ владелец :53
            if proc and proc not in ln:
                continue
            return True
        return False
    except Exception:
        return False


def aghome_dns_ready() -> bool:
    """AGH полностью готов: служба активна И :53/udp слушает ИМЕННО AGH.

    proc-фильтр обязателен — без него systemd-resolved stub
    (127.0.0.53:53) давал ложный positive, resolv_conf_fix считал
    «AGH владеет :53» и снимал redirect → DNS black-hole.
    Именно это условие используют resolv_conf_fix и xray_install."""
    return is_aghome_active() and _port_listening(
        AGH_DNS_PORT, "udp", proc="AdGuardHome")


def aghome_fix_ratelimit_if_needed(log_info=None, log_warn=None) -> "tuple[bool, str]":
    """санация ratelimit/upstream_timeout ЖИВОГО AdGuardHome.yaml.

    Эмпирика на живом AGH v0.107.79 (инцидент: «клиент сыпал EOFами,
    убрал AGH — всё заработало»): ratelimit: 20 при subnet_len 24 =
    ОДИН бакет 20 rps на весь DNS Xray; сверх лимита запросы ТИХО
    дропаются (без REFUSED и без записи в лог), ratelimit_whitelist —
    мёртвое поле. Xray за каждый дроп платит 4 секунды до fallback.
    Единственный рабочий фикс — ratelimit: 0 (Ratelimit==0 → PassThrough).
    upstream_timeout 10s → 3s: SERVFAIL успевает до 4с-таймаута Xray.

    Идемпотентно: правит ТОЛЬКО строки ratelimit:/upstream_timeout:
    ВНУТРИ dns:-секции (users, фильтры, upstream, tls не трогает),
    бэкап .pre-ratelimit-fix.bak перед записью, рестарт + ожидание
    active и :53. iptables НЕ трогает (вызывается из agh_probe).

    Возвращает (True, note) — фикс не нужен или применён успешно;
    (False, причина) — патч записан, но AGH не поднялся (вызывающий
    обязан откатиться на DNSCrypt:5300).
    """
    log_info = log_info or (lambda m: None)
    log_warn = log_warn or (lambda m: None)

    if not AGH_CONF.exists():
        return True, "нет конфига AGH — no-op"
    try:
        text = AGH_CONF.read_text(errors="replace")
    except Exception as e:
        return True, f"yaml не читается ({e}) — no-op"

    # Правки только ВНУТРИ dns:-секции (до следующей top-level колонки)
    m_dns = re.search(r'^dns:\s*$', text, re.MULTILINE)
    if not m_dns:
        return True, "секции dns: нет — no-op"
    sec_start = m_dns.end()
    m_next = re.search(r'^[A-Za-z_][A-Za-z0-9_]*:', text[sec_start:],
                       re.MULTILINE)
    sec_end = sec_start + (m_next.start() if m_next
                           else len(text[sec_start:]))
    section = text[sec_start:sec_end]

    patched: list[str] = []
    new_section = section
    m_rl = re.search(r'^  ratelimit:\s*(\d+)\s*$', section, re.MULTILINE)
    if m_rl and int(m_rl.group(1)) != 0:
        new_section = (new_section[:m_rl.start()] + "  ratelimit: 0"
                       + new_section[m_rl.end():])
        patched.append(f"ratelimit {m_rl.group(1)} → 0")
    m_ut = re.search(r'^  upstream_timeout:\s*(\d+)s\s*$', new_section,
                     re.MULTILINE)
    if m_ut and int(m_ut.group(1)) > 3:
        new_section = (new_section[:m_ut.start()] + "  upstream_timeout: 3s"
                       + new_section[m_ut.end():])
        patched.append(f"upstream_timeout {m_ut.group(1)}s → 3s")

    if not patched:
        return True, "конфиг уже санитарен (ratelimit=0, timeout<=3s)"

    log_warn(f"AGH: конфиг угрожает DNS Xray ({'; '.join(patched)}) — "
             "патчу и перезапускаю (тихие дропы = EOF у клиентов)")

    # Бэкап + запись (права как у finalize)
    try:
        AGH_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        bak = AGH_BACKUP_DIR / ("AdGuardHome.yaml."
                                + datetime.now().strftime("%Y%m%d%H%M%S")
                                + ".pre-ratelimit-fix.bak")
        shutil.copy2(AGH_CONF, bak)
        AGH_CONF.write_text(text[:sec_start] + new_section + text[sec_end:])
        subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                       capture_output=True, check=False)
        AGH_CONF.chmod(0o640)
    except Exception as e:
        log_warn(f"AGH: не удалось записать патч: {e}")
        return True, f"патч не записан ({e}) — конфиг не тронут"

    # Рестарт + ожидание живого :53
    subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    if not _wait_service(AGH_SERVICE_NAME, 30):
        return False, f"AGH не поднялся после патча ({'; '.join(patched)})"
    ready = False
    for _ in range(5):
        if aghome_dns_ready():
            ready = True
            break
        time.sleep(2)
    if not ready:
        return False, "AGH active, но :53 не слушается после патча"
    log_info(f"AGH: санация применена ({'; '.join(patched)}), :53 слушает")
    return True, "патч применён: " + ", ".join(patched)


def _agh_core_port_conflicts(extra_ports: "tuple[int, ...]" = ()) -> "dict[int, list[str]]":
    """конфликтуют ли порты AGH с портами ядра Chimera (Xray/AWG).

    AGH биндит фиксированные порты (DNS :53, DoT/DoQ :853, DoH+WebUI
    :30443) и стартует ДО xray (unit: Before=xray.service): коллизия =
    AGH отбирает порт → xray не может забиндиться → EOF у ВСЕХ клиентов.
    Источники проверки:
      1. глобали текущей установки (do_full_install: AGH ставится ДО
         Xray — порт из SERVER_PORT);
      2. state.json (живая установка / установка из меню):
         server_port, awg_client_listen_port;
      3. живые чужие слушатели (ss -tulnp) на портах AGH.
    systemd-resolved stub (127.0.0.53:53) НЕ конфликт — другой адрес;
    сам AGH (рефинализация) исключается по имени процесса.

    Возвращает {порт AGH: [причины]} — только пересечения с портами
    AGH (53/853/30443 + extra_ports), шум отсеивается.
    """
    conflicts: "dict[int, list[str]]" = {}

    def _note(port: int, reason: str) -> None:
        conflicts.setdefault(int(port), []).append(reason)

    # 1) Глобали текущей установки
    try:
        _core = _core_module()
        _sp = int(getattr(_core, "SERVER_PORT", 0) or 0)
        if _sp:
            _note(_sp, "Xray (SERVER_PORT текущей установки)")
    except Exception:
        pass

    # 2) state.json (живая установка / меню)
    try:
        if XRAY_STATE_FILE.exists():
            _st = json.loads(XRAY_STATE_FILE.read_text())
            _sp = int(_st.get("server_port", 0) or 0)
            if _sp:
                _note(_sp, "Xray (state.json server_port)")
            _awg = int(_st.get("awg_client_listen_port", 0) or 0)
            if _awg:
                _note(_awg, "AWG (state.json awg_client_listen_port)")
    except Exception:
        pass

    # 3) Живые чужие слушатели (ss), кроме AGH и resolved stub
    ports_to_check = {AGH_DNS_PORT, AGH_DOT_PORT, AGH_DOH_PORT}
    ports_to_check.update(int(p) for p in extra_ports if p)
    try:
        r = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True,
                           check=False, timeout=10)
        for ln in (r.stdout or "").splitlines():
            if "adguardhome" in ln.lower():
                continue  # сам AGH (финализация/перезапуск)
            if "resolved" in ln or "127.0.0.53" in ln or "127.0.0.54" in ln:
                continue  # systemd-resolved stub — не конфликт
            for port in ports_to_check:
                if re.search(rf':{port}\s', ln):
                    m = re.search(r'users:\(\("([^"]+)"', ln)
                    proc = m.group(1) if m else "unknown"
                    _note(port, f"порт слушает {proc}")
    except Exception:
        pass

    return {p: reasons for p, reasons in conflicts.items()
            if p in ports_to_check}


def _find_free_web_port(preferred: int) -> int:
    """первый свободный порт для Web UI, начиная с preferred+1.

    Занятый web-порт = FATAL для AGH (bind http → crash-loop → мёртвый
    DNS :53). При коллизии сдвигаем порт и предупреждаем.
    """
    for cand in list(range(preferred + 1, 3100)) + list(range(3101, 3200)):
        if cand in AGH_WEB_PORT_RESERVED:
            continue
        if _port_listening(cand, "tcp"):
            continue
        try:
            from chimera.modules.port_registry import port_is_free
            free, _ = port_is_free(cand, "tcp")
            if not free:
                continue
        except Exception:
            pass
        return cand
    return 0


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


# ── IPv6 в DNS-стеке ───────────────────────────────────────────────────
def _get_public_ipv6() -> str:
    """Публичный глобальный IPv6 сервера (для bind_hosts AGH).

    Порядок: `ip -6 addr scope global` (без сети, мгновенно) → curl -6.
    Пропускаем deprecated/temporary (приватность-адреса ротируются —
    bind на них переломается при ротации), fe80:: (link-local).
    Возвращаем адрес БЕЗ префиксной длины; пустая строка = IPv6 нет.
    """
    def _pick(candidates: list) -> str:
        # сначала стабильные (без temporary/deprecated), иначе любой
        stable = [a for a, flags in candidates if not flags]
        pool = stable or [a for a, _ in candidates]
        return pool[0] if pool else ""

    try:
        r = subprocess.run(["ip", "-6", "addr", "show", "scope", "global"],
                           capture_output=True, text=True, check=False, timeout=10)
        candidates: list = []
        for line in r.stdout.splitlines():
            m = re.match(r"\s*inet6\s+([0-9a-fA-F:]+)/(\d+)\s+scope\s+global\s*(.*)", line)
            if not m:
                continue
            addr, flags = m.group(1), m.group(3) or ""
            if addr.startswith("fe80") or "." in addr:   # link-local / v4-mapped
                continue
            candidates.append((addr.lower(), "temporary" in flags or "deprecated" in flags))
        v6 = _pick(candidates)
        if v6:
            return v6
    except Exception:
        pass
    # fallback: внешний сервис
    try:
        r = subprocess.run(["curl", "-6", "-fsS", "--max-time", "6",
                            "https://api6.ipify.org"],
                           capture_output=True, text=True, check=False, timeout=10)
        v6 = r.stdout.strip().lower()
        if re.fullmatch(r"[0-9a-f:]+", v6) and ":" in v6 and not v6.startswith("fe80"):
            return v6
    except Exception:
        pass
    return ""


def _rewrite_dnscrypt_listen(content: str, port: int, ipv6: bool) -> str:
    """Перезаписывает строку listen_addresses в TOML dnscrypt.

    Брекет-безопасно: IPv6-элементы вида '[::1]:5300' содержат ']' внутри
    списка — поэтому матчу ВСЮ строку до конца (жадный [^\n]*), а не до
    первого ']'. При ipv6 добавляем [::1]:{port} вторым слушателем,
    127.0.0.1 всегда первый (на него ориентируются остальные модули).
    Конфиг без listen_addresses возвращается как есть.
    """
    m = re.search(r"^listen_addresses\s*=\s*\[[^\n]*\][^\n]*$",
                  content, re.MULTILINE)
    if not m:
        return content
    entries = [f"'127.0.0.1:{port}'"]
    if ipv6:
        entries.append(f"'[::1]:{port}'")
    new_line = "listen_addresses = [" + ", ".join(entries) + "]"
    return content[:m.start()] + new_line + content[m.end():]


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
    """Ждёт пока служба станет СТАБИЛЬНО active. True при успехе.

    одиночного is-active мало. Crash-looping служба (невалидный
    конфиг): systemd помечает active → процесс умирает через ~0.5с →
    failed → автозапуск через 5с. Старая логика ловила миг «active» и
    возвращала True — self-heal откат конфига НЕ срабатывал, crash-loop
    оставался жить (инцидент <node-2>, рестарт-каунтер 390+).
    Требуем 3 ПОДРЯД активные проверки (1с интервал).
    """
    streak = 0
    for _ in range(max_sec + 4):  # +4с запас на подтверждение стабильности
        if _svc_is_active(svc):
            streak += 1
            if streak >= 3:
                return True
        else:
            streak = 0
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

    # Текущие listen_addresses (брекет-безопасно — IPv6-элементы
    # '[::1]:5300' содержат ']' внутри списка, поэтому матчу всю строку)
    m = re.search(r"^listen_addresses\s*=\s*\[[^\n]*\][^\n]*$",
                  content, re.MULTILINE)
    if not m:
        warn("AGH: listen_addresses не найден в dnscrypt TOML")
        return False

    listens = re.findall(r'[\'"]([^\'"]+)[\'"]', m.group(0))
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

    # Бэкап + перезапись listen_addresses → 127.0.0.1:{port}
    # (+ '[::1]:{port}' вторым слушателем при IPv6 на сервере —)
    bak = toml_path.with_name(
        toml_path.name + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".preAGH.bak")
    try:
        shutil.copy2(toml_path, bak)
    except Exception as e:
        warn(f"AGH: не удалось сделать бэкап dnscrypt TOML: {e}")
        return False

    ipv6 = bool(getattr(core, "IS_IPV6_AVAILABLE", False))
    content = _rewrite_dnscrypt_listen(content, port, ipv6)
    if ipv6:
        info(f"AGH: dnscrypt мигрирован на 127.0.0.1:{port} + [::1]:{port} (IPv6)")
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
def _ensure_acme_http80(domain: str) -> None:
    """Гарантирует отвечающий HTTP:80 endpoint ДО запуска certbot.

    certbot --webroot НЕ слушает :80 сам — ему нужен веб-сервер, который
    отдаёт /.well-known/acme-challenge/ из webroot-а ЭТОГО домена.
    В момент выпуска AGH-сертификата этого может не быть:
      • do_full_install: install_aghome() идёт РАНЬШЕ setup_nginx_temp()
        (главный флоу) и раньше configure_firewall() → challenge уходит
        в дефолтный vhost nginx (404) или в закрытый UFW → LE-выпуск
        ВСЕГДА падал в self-signed (инцидент: server.example);
      • standalone-установка (Сеть → A): nginx/certbot могут отсутствовать
        вовсе, PARAM_EMAIL — пустой (certbot требует --email).

    Паттерн mtproto/telemt (v4.20.3): setup_nginx_temp(domain) ставит
    nginx при необходимости и создаёт vhost с ACME-location. Дополнительно:
      • certbot ставится при отсутствии (паттерн hysteria2_cert_mgr);
      • UFW пропускает :80 (правило и комментарий идентичны
        network_setup.configure_firewall — ufw не дублирует);
      • PARAM_EMAIL при пустом значении → admin@<domain> (тот же дефолт,
        что в install_prompts). Право :80 остаётся открытым навсегда —
        оно нужно certbot renew (deploy-hook синкает сертификат в AGH).
    """
    core = _core_module()
    info, warn = core.info, core.warn

    # 0) certbot обязан существовать (fresh-сервер без VLESS-стека).
    if not shutil.which("certbot"):
        info("AGH: certbot не найден — устанавливаю...")
        r = subprocess.run(
            ["apt-get", "install", "-y", "-q", "certbot"],
            env={"DEBIAN_FRONTEND": "noninteractive"},
            capture_output=True, check=False)
        if r.returncode != 0 and not shutil.which("certbot"):
            warn("AGH: не удалось установить certbot — выпуск LE невозможен")

    # 1) Email для LE-регистрации (certbot падает на --email "").
    if domain and not (getattr(core, "PARAM_EMAIL", "") or "").strip():
        setattr(core, "PARAM_EMAIL", f"admin@{domain}")

    # 2) ACME-vhost на :80 (nginx ставится при необходимости).
    try:
        from chimera.modules.nginx_setup import setup_nginx_temp
        setup_nginx_temp(domain=domain)
    except Exception as e:
        warn(f"AGH: не удалось поднять ACME-vhost для {domain}: {e}")
        warn("AGH: без него certbot, скорее всего, не выпустит сертификат")

    # 3) :80 в UFW (не дублируется — совпадает с configure_firewall).
    try:
        if shutil.which("ufw"):
            subprocess.run(
                ["ufw", "allow", "80/tcp", "comment", "HTTP (certbot ACME)"],
                capture_output=True, check=False)
    except Exception:
        pass


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
            # ДО certbot — отвечающий HTTP:80 (ACME-vhost + UFW + email).
            # Раньше webroot-челлендж уходил в дефолтный vhost nginx (404)
            # или в ещё не настроенный UFW → LE всегда падал в self-signed.
            _ensure_acme_http80(domain)
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
            _own_certs_dir()
            _install_certbot_deploy_hook(domain)
            # превентивная проверка ДО записи yaml — иначе AGH молча
            # выключит tls (enabled=false) и DoH/DoT/DoQ не поднимутся.
            pair_ok, pair_why = _cert_pair_matches(AGH_CERT_PATH, AGH_KEY_PATH)
            if not pair_ok:
                warn(f"AGH: LE-пара битая ({pair_why}) — fallback self-signed")
                return _generate_self_signed_tls(domain)
            readable, rwhy = _certs_readable_by_user(
                AGH_USER, AGH_CERT_PATH, AGH_KEY_PATH)
            if not readable:
                warn(f"AGH: сертификат не читается пользователем {AGH_USER} "
                     f"({rwhy}) — чиню права")
                _own_certs()
                _own_certs_dir()
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
    _own_certs_dir()


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
        # пара должна совпадать (иначе AGH молча выключит TLS)
        pair_ok, pair_why = _cert_pair_matches(AGH_CERT_PATH, AGH_KEY_PATH)
        if not pair_ok:
            core.warn(f"AGH: self-signed пара битая: {pair_why}")
            return None, None
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


def build_dns_section(dc_port: int, public_ip: str, tls_enabled: bool,
                      public_ipv6: str = "") -> str:
    """Секция dns: — канонический конфиг Chimera (по мотивам роутерного,
    с VPS-адаптацией: bind_hosts = loopback + public IP для DoT/DoQ,
    приватные PTR выключены — нет LAN).

    Публичный :53 НЕ открывается в UFW — open resolver исключён;
    public IP в bind_hosts нужен только для DoT(:853)/DoQ(:853)/DoH(:30443).

    public_ipv6 — публичный IPv6 сервера, добавляется в bind_hosts:
    AGH биндит :53/DoT/DoH/Web и на IPv6 (IPv6-клиенты видны в статистике,
    DoT/DoH доступны по v6). Пустая строка (нет IPv6 / self-heal
    loopback-only) — прежнее поведение байт-в-байт.

     (ratelimit: 0 — КРИТИЧНО, эмпирика на живом AGH v0.107.79):
      • ratelimit>0 = ТИХИЙ DROP сверх лимита: ни REFUSED, ни записи в
        лог/querylog — клиент видит чистый таймаут;
      • ratelimit_whitelist — МЁРТВОЕ ПОЛЕ (парсится, но не подключено
        к ratelimit-мидлвари — баг AGH), вайтлистить 127.0.0.1 нельзя;
      • ratelimit_subnet_len_ipv4: 24 → весь DNS-трафик Xray (единственный
        клиент 127.0.0.1) делил ОДИН бакет 20 rps: страница браузера =
        20-60 запросов → бо́льшая часть дропается молча → Xray платит 4с
        за каждый lookup до fallback → EOF-шторм у клиентов.
    Публичный :53 закрыт в UFW (нет open resolver) → лимит не нужен.
    upstream_timeout: 3s (< 4с-таймаута Xray): SERVFAIL от AGH приходит
    ДО таймаута Xray → мгновенный fallback на DNSCrypt вместо
    4-секундного black-hole пенальти за каждый запрос.
    """
    bind_hosts = ["127.0.0.1"]
    if public_ip:
        bind_hosts.append(public_ip)
    if public_ipv6:
        # конкретный адрес (не '::' — wildcard-бинд конфликтует с
        # уже забинженным 127.0.0.1/public IPv4 в Go dual-stack)
        bind_hosts.append(public_ipv6)
    bind_lines = "\n".join(f"    - {_yaml_quote(h)}" for h in bind_hosts)

    return f"""dns:
  bind_hosts:
{bind_lines}
  port: {AGH_DNS_PORT}
  anonymize_client_ip: false
  # 0 = без лимита (тихие дропы лимита убивали DNS Xray; whitelist мёртв).
  # Публичный :53 закрыт в UFW — open resolver исключён.
  ratelimit: 0
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
    - 149.112.112.112:53
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
  # 3s < 4с-таймаута DNS-клиента Xray → SERVFAIL успевает до
  # таймаута, Xray мгновенно уходит в fallback (не 4с black-hole).
  upstream_timeout: 3s
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


def build_http_section(web_mode: str, web_port: int = AGH_WEB_PORT) -> str:
    """Секция http: — адрес Web UI по выбранному режиму.

    web_port — кастомный порт Web UI (по умолчанию AGH_WEB_PORT);
    применяется ко всем режимам (wizard-фаза всегда на :3000 — порт
    меняется при финализации).

    AGH биндит HTTPS-порт (:30443) на ТОТ ЖЕ хост, что и
    http.address (исходники AGH: netip.AddrPortFrom(web.conf.BindAddr,
    portHTTPS)) — отдельных bind-настроек у TLS-порта нет. Поэтому в
    TLS-режимах (https_le/https_self) bind 0.0.0.0:3000: иначе :30443
    оставался loopback, UFW-порт 30443 висел бесполезно, а Web UI снаружи
    требовал SSH-туннель (запрещён требованием «без туннелей»).
    Публичный доступ к plain-порту закрыт UFW
    (_register_aghome_ports: web_public_plain=False → close), снаружи —
    только TLS :30443 (Web UI + DoH мультиплексированы).
    http_public: 0.0.0.0:{port} + UFW открыт (plain, на выбор пользователя).
    loopback: 127.0.0.1:{port} (полностью локальный режим).
    """
    if web_mode == AGH_WEB_LOOPBACK:
        addr = f"127.0.0.1:{web_port}"
    else:
        # http_public, https_le, https_self — см. docstring 
        addr = f"0.0.0.0:{web_port}"
    return f"""http:
  pprof:
    port: 6060
    enabled: false
  address: {addr}
  session_ttl: 720h
"""


def build_filters_section() -> str:
    """Секция filters: — все 3 списка (AdGuard DNS + AdAway + OISD Big).

    ТОЛЬКО filters:. Раньше блок тащил внутри себя ещё и
    whitelist_filters/user_rules — а мастерские копии этих секций
    оставались в конфиге → duplicate mapping keys → строгий YAML-парсер
    AGH отказывался стартовать → crash-loop → DNS down (инцидент
    <node-2>: «mapping key whitelist_filters already defined»).
    """
    entries = []
    for i, (url, name) in enumerate(AGH_FILTERS, start=1):
        entries.append(
            f"  - enabled: true\n    url: {_yaml_quote(url)}\n"
            f"    name: {_yaml_quote(name)}\n    id: {i}")
    body = "\n".join(entries)
    return f"filters:\n{body}\n"


def build_whitelist_filters_section() -> str:
    """Секция whitelist_filters: — ОТДЕЛЬНО (см. build_filters_section)."""
    return "whitelist_filters: []\n"


def build_user_rules_section() -> str:
    """Секция user_rules: — ОТДЕЛЬНО (см. build_filters_section)."""
    return "user_rules: []\n"


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
_TOP_KEY_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*):(\s|$)')


def _duplicate_top_keys(text: str) -> "list[str]":
    """Top-level ключи YAML, встречающиеся более одного раза.

    AGH v0.107 строго валидирует конфиг: duplicate mapping key =
    «Couldn't get logging settings ... already defined» + отказ
    стартовать → crash-loop → DNS down.
    """
    counts: dict[str, int] = {}
    for ln in text.splitlines():
        m = _TOP_KEY_RE.match(ln)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return [k for k, n in counts.items() if n > 1]


def _dedup_top_level_sections(text: str) -> str:
    """Убирает дубли top-level секций YAML — остаётся ПЕРВОЕ вхождение.

    Safety-net для текстовой хирургии конфига: генераторы секций не
    должны плодить дубли, но цена пропуска — crash-loop AGH и мёртвый
    DNS. Первое вхождение = наша каноническая секция (пишется на место
    исходной), остальные копии — вырезаются целиком до следующего
    top-level ключа.
    """
    lines = text.splitlines(keepends=True)
    starts: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        m = _TOP_KEY_RE.match(ln)
        if m:
            starts.append((i, m.group(1)))
    if not starts:
        return text
    seen: set[str] = set()
    drop: set[int] = set()
    for k, (si, key) in enumerate(starts):
        if key in seen:
            end = starts[k + 1][0] if k + 1 < len(starts) else len(lines)
            drop.update(range(si, end))
        else:
            seen.add(key)
    if not drop:
        return text
    return "".join(ln for i, ln in enumerate(lines) if i not in drop)


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

    # SAFETY-NET: дедупликация top-level ключей (первое вхождение
    # побеждает). Скаляры ниже делаем ПОСЛЕ — их подстановка тоже не
    # должна встретить дублей.
    out = _dedup_top_level_sections(out)

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
            if m:
                ip = m.group(1)
                _ufw_delete_rule("allow", "from", ip, "to", "any",
                                 "port", str(port), "proto", "tcp")
                removed.append(ip)
            else:
                # v44: правило «для всех» (Anywhere) — удаляем по порту
                mp = re.match(r'\s*(\d+)/tcp\s+ALLOW\s+Anywhere', line)
                if mp:
                    _ufw_delete_rule("allow", f"{mp.group(1)}/tcp")
                    removed.append("0.0.0.0/0")
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


def _ufw_allow_port_all(port: int) -> bool:
    """Открывает TCP-порт для всех (временно, на время wizard-фазы)."""
    try:
        if not shutil.which("ufw"):
            return False
        r = subprocess.run(
            ["ufw", "allow", f"{port}/tcp", "comment",
             "chimera-aghome-wizard-temp"],
            capture_output=True, text=True, check=False,
            input="y\n", timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _open_wizard_access(ssh_ip: str) -> list:
    """Временный доступ к мастеру :3000 — ДЛЯ ВСЕХ, без туннелей.

    Регресс v44 (<node-2>): доступ только с IP SSH-клиента + public IP
    VPS ломался (CGNAT, смена IP клиента, прокси-цепочки браузера) —
    мастер нельзя было пройти без SSH-туннеля. Wizard-фаза короткая,
    панель требует пароль: :3000 открывается для всех, финализация
    закрывает (_ufw_clean_wizard_rules по comment).

    ssh_ip сохраняется вызывающим кодом в state для совместимости;
    per-IP правила больше не ставятся (но старые чистятся).
    """
    _ufw_clean_wizard_rules()
    if _ufw_allow_port_all(AGH_WEB_PORT):
        return ["0.0.0.0/0"]
    return []


def _register_aghome_ports(dc_port: int, tls_enabled: bool,
                           web_public_plain: bool,
                           web_port: int = AGH_WEB_PORT) -> None:
    """Регистрирует все порты DNS-стека в port_registry + открывает публичные
    в UFW. Вызывается при установке/финализации (идемпотентно).

    web_port — кастомный порт Web UI. При смене порта закрывает UFW и
    снимает регистрацию СТАРОГО порта (порт не должен течь).
    """
    try:
        from chimera.modules.port_registry import (
            port_register, ufw_open_port, port_unregister,
            port_list_for_service,
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

    # Web UI: кастомный порт. Сначала — уборка СТАРЫХ записей тега
    # с другим портом (смена порта при переустановке/финализации).
    try:
        for e in port_list_for_service(SERVICE_AGHOME_WEB):
            try:
                old_port = int(e.get("port", 0))
            except Exception:
                old_port = 0
            if old_port and old_port != web_port:
                ufw_close_quiet(old_port, "tcp", SERVICE_AGHOME_WEB)
                port_unregister(SERVICE_AGHOME_WEB, port=old_port, proto="tcp")
                info(f"AGH: порт Web UI {old_port} → {web_port} "
                     f"(UFW/реестр обновлены)")
    except Exception:
        pass
    port_register(SERVICE_AGHOME_WEB, web_port, "tcp",
                  comment="AdGuard Home Web UI", force=True)
    if web_public_plain:
        ok, msg = ufw_open_port(web_port, "tcp", SERVICE_AGHOME_WEB,
                                comment="AdGuard Home Web UI (HTTP)")
        if ok:
            info(f"AGH: порт {web_port}/tcp открыт в UFW (Web UI)")
    else:
        # loopback/TLS-режим — публичный доступ закрыт
        ufw_close_quiet(web_port, "tcp", SERVICE_AGHOME_WEB)

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
    (кроме dnscrypt :5300 — он остаётся жить).

    Web UI-порт может быть кастомным — закрываем ВСЕ записи тега
    SERVICE_AGHOME_WEB из реестра (+ дефолт 3000 страховочно).
    """
    try:
        from chimera.modules.port_registry import (
            port_unregister, ufw_close_port, port_list_for_service,
            SERVICE_AGHOME, SERVICE_AGHOME_WEB, SERVICE_AGHOME_DOH,
            SERVICE_AGHOME_DOT, SERVICE_AGHOME_DOQ,
        )
        for tag, port, proto in (
            (SERVICE_AGHOME,         AGH_DNS_PORT, "udp"),
            (SERVICE_AGHOME,         AGH_DNS_PORT, "tcp"),
            (SERVICE_AGHOME_DOH,     AGH_DOH_PORT, "tcp"),
            (SERVICE_AGHOME_DOT,     AGH_DOT_PORT, "tcp"),
            (SERVICE_AGHOME_DOQ,     AGH_DOQ_PORT, "udp"),
        ):
            ufw_close_port(port, proto, tag)
            port_unregister(tag, port=port, proto=proto)
        # Web UI — все кастомные порты тега + дефолт
        web_ports = set()
        try:
            for e in port_list_for_service(SERVICE_AGHOME_WEB):
                try:
                    web_ports.add(int(e.get("port", 0)))
                except Exception:
                    pass
        except Exception:
            pass
        web_ports.add(AGH_WEB_PORT)
        # прошлые версии могли знать порт только из state — добавим его
        try:
            web_ports.add(int(aghome_state_load().get("web_port", 0) or 0))
        except Exception:
            pass
        for p in sorted(x for x in web_ports if x):
            ufw_close_port(p, "tcp", SERVICE_AGHOME_WEB)
            port_unregister(SERVICE_AGHOME_WEB, port=p, proto="tcp")
    except Exception:
        pass


# ============================================================================
#  УСТАНОВКА
# ============================================================================
def _get_latest_agh_tag() -> str:
    """Последний release-tag AGH из GitHub API (3 раунда × 2 зеркала).

    api.github.com с РФ-сетей флапает с первого раза (инцидент
    переустановки <ip>: «GitHub API недоступен» при живой
    сети) — зеркалируем запрос через gh-прокси. Полный провал всех
    попыток → вызывающий код использует pinned AGHOME_FALLBACK_TAG +
    канал static.adtidy.org (не зависит от GitHub вообще).
    """
    _api_urls = [
        "https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest",
        "https://gh-proxy.com/https://api.github.com/repos/AdguardTeam/"
        "AdGuardHome/releases/latest",
    ]
    for _attempt in range(3):
        for api_url in _api_urls:
            try:
                r = subprocess.run(
                    ["curl", "-fsSL", "--connect-timeout", "10", api_url],
                    capture_output=True, text=True, check=False, timeout=30)
                if r.returncode == 0:
                    data = json.loads(r.stdout)
                    tag = data.get("tag_name", "")
                    if tag:
                        return tag
            except Exception:
                pass
        time.sleep(2)
    return ""


def _validate_web_port(port: int) -> "tuple[bool, str]":
    """Кастомный порт Web UI: диапазон + не служебный + свободен."""
    if not (1024 <= port <= 65535):
        return False, "порт должен быть в диапазоне 1024–65535"
    if port in AGH_WEB_PORT_RESERVED:
        return False, (f"порт {port} служебный (SSH/DNS/DoT/DoQ/DoH/dnscrypt) "
                       "— выберите другой")
    try:
        from chimera.modules.port_registry import (
            port_is_free, SERVICE_AGHOME_WEB,
        )
        free, conflicts = port_is_free(port, "tcp",
                                       exclude_service=SERVICE_AGHOME_WEB)
        if not free:
            return False, "порт занят: " + "; ".join(conflicts[:3])
    except Exception:
        # port_registry недоступен — не блокируем, проверим хотя бы ss
        if _port_listening(port, "tcp"):
            return False, f"порт {port}/tcp уже слушается"
    return True, ""


def _ask_web_port() -> int:
    """Спрашивает порт Web UI (plain HTTP/локальный вход;).

    Основной вход в Web UI — TLS :30443 (не меняется). Кастомный порт
    управляет plain-доступом: режим «HTTP публично» и локальный вход.
    Wizard-фаза всегда на :3000 — порт применяется при финализации.
    """
    core = _core_module()
    CYAN, NC, DIM, YELLOW = core.CYAN, core.NC, core.DIM, core.YELLOW
    _box_top, _box_row, _box_sep, _box_bottom = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom)
    print()
    _box_top("🛡️  AdGuard Home — порт Web UI (plain HTTP)")
    _box_row()
    _box_row(f"  {DIM}Основной вход — TLS :{AGH_DOH_PORT} (Web UI + DoH).{NC}")
    _box_row(f"  {DIM}Этот порт — для plain-режима «HTTP публично» и локального входа.{NC}")
    _box_sep()
    try:
        raw = input(f"{CYAN}  Порт Web UI [{AGH_WEB_PORT}]: {NC}").strip()
    except (EOFError, KeyboardInterrupt):
        return AGH_WEB_PORT
    while True:
        if not raw:
            return AGH_WEB_PORT
        try:
            port = int(raw)
        except ValueError:
            try:
                print(f"{YELLOW}  Нужно число (Enter = {AGH_WEB_PORT}){NC}")
                raw = input(f"{CYAN}  Порт Web UI [{AGH_WEB_PORT}]: {NC}").strip()
            except (EOFError, KeyboardInterrupt):
                return AGH_WEB_PORT
            continue
        if port == AGH_WEB_PORT:
            return AGH_WEB_PORT
        ok, why = _validate_web_port(port)
        if ok:
            return port
        try:
            print(f"{YELLOW}  {why}{NC}")
            raw = input(f"{CYAN}  Порт Web UI [{AGH_WEB_PORT}]: {NC}").strip()
        except (EOFError, KeyboardInterrupt):
            return AGH_WEB_PORT


def _ask_web_mode() -> "tuple[str, str]":
    """Спрашивает режим Web UI. Возвращает (web_mode, domain).

    Режимы:
      1. https_le     — домен + Let's Encrypt, https://{domain}:30443 (рекоменд.)
      2. https_self   — self-signed, https://IP:30443
      3. http_public  — plain HTTP 0.0.0.0:3000
      4. loopback     — 127.0.0.1:3000 (SSH-туннель)

    https_le/https_self биндят http на 0.0.0.0:3000 (UFW снаружи
    закрыт) — HTTPS :30443 в AGH следует хосту http.address, иначе
    Web UI доступен только с туннелем.
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
    _box_row()
    _box_row(f" {DIM}Порт plain-доступа можно поменять следующим вопросом.{NC}")
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


# ============================================================================
#  DNS-ALIVE ГАРАНТИЯ (анти black-hole в любой фазе AGH)
# ============================================================================
def _dns_probe_ok(timeout: int = 2) -> bool:
    """Отвечает ли системный DNS на 127.0.0.1:53 — фактический запрос.

    Любой DNS-ответ (NOERROR/NXDOMAIN) = путь жив; таймаут/refused =
    мёртв. dig при наличии, иначе getent hosts (rc != 0 = не
    разрезолвился). Проверка «правила на месте» недостаточна —
    ok:true от фикса ≠ работающий DNS (инцидент v44).

    ВНИМАНИЕ: это проба КОНКРЕТНОГО адреса 127.0.0.1:53. Критерий
    «система вообще резолвит» — _system_dns_ok(): на чистой
    установке :53 свободен до старта AGH, и это НОРМА, а не авария.
    """
    if shutil.which("dig"):
        try:
            r = subprocess.run(
                ["dig", "@127.0.0.1", "github.com",
                 f"+time={timeout}", "+tries=1"],
                capture_output=True, text=True,
                timeout=timeout + 3, check=False)
            return r.returncode == 0
        except Exception:
            return False
    try:
        r = subprocess.run(["getent", "hosts", "github.com"],
                           capture_output=True, text=True,
                           timeout=timeout + 3, check=False)
        return r.returncode == 0
    except Exception:
        return False


def _system_dns_ok(timeout: int = 4) -> bool:
    """Резолвит ли СИСТЕМА имена — фактический запрос через nsswitch.

    Путь системного разрешения: nsswitch.conf → resolv.conf. Это может
    быть DNS провайдера (чистая установка), stub 127.0.0.53, AGH на
    127.0.0.1:53 или 127.0.0.1 + redirect на dnscrypt — ЛЮБОЙ рабочий
    путь проходит проверку.

     (инцидент переустановки <ip>): старый критерий
    «127.0.0.1:53 обязан отвечать» на чистой системе (AGH ещё не
    ставился, dnscrypt на :5300) давал ложный «DNS мёртв», а
    «восстановление» ЛОМАЛО рабочий DNS провайдера, направляя
    resolv.conf на ещё не готовый dnscrypt — все зеркала AGH
    «падали» из-за мёртвого резолва.

    getent hosts — честный системный путь (nsswitch + resolv.conf);
    dig github.com без @server — fallback при отсутствии getent.
    """
    try:
        r = subprocess.run(["getent", "hosts", "github.com"],
                           capture_output=True, text=True,
                           timeout=timeout + 2, check=False)
        return r.returncode == 0
    except Exception:
        pass
    if shutil.which("dig"):
        try:
            r = subprocess.run(
                ["dig", "github.com", f"+time={timeout}", "+tries=1"],
                capture_output=True, text=True,
                timeout=timeout + 3, check=False)
            return r.returncode == 0
        except Exception:
            return False
    return False


def _probe_dns_with_settle(attempts: int = 3, interval: float = 2.0) -> bool:
    """Системная DNS-проба с ожиданием готовности резолвера.

    dnscrypt-proxy и AGH после (ре)старта нуждаются в секундах на
    bootstrap (DoH/TLS handshake, prefetch сертификатов) — мгновенная
    одиночная проба после изменений даёт ложный «мёртв» (инцидент
    переустановки <ip>: redirect был поставлен верно, но
    dnscrypt ещё поднимался, dig с +time=2 не дождался).
    """
    for i in range(attempts):
        if i:
            time.sleep(interval)
        if _system_dns_ok():
            return True
    return False


def _emergency_public_dns_fallback() -> bool:
    """Последняя ступень: публичный DNS напрямую в resolv.conf.

    Локальные резолверы (AGH / dnscrypt / redirect) не поднялись —
    живой системный DNS через публичные серверы лучше мёртвого
    127.0.0.1: установка продолжится, а resolv-фикс / финализация
    AGH позже вернут системный DNS на локальный резолвер.
    """
    try:
        resolv = Path("/etc/resolv.conf")
        if resolv.is_symlink():
            resolv.unlink()
        elif resolv.exists():
            bak = resolv.parent / "resolv.conf.pre-public-fallback.bak"
            if not bak.exists():
                shutil.copy2(str(resolv), str(bak))
        resolv.write_text(
            "# Chimera: аварийный DNS-fallback — локальные резолверы "
            "недоступны\n"
            "# Восстановление локального пути: Сеть → A (resolv-фикс)\n"
            "nameserver 1.1.1.1\n"
            "nameserver 8.8.8.8\n"
            "options timeout:2 attempts:2\n"
        )
        return True
    except Exception:
        return False


def _dns_blackhole_help_box() -> None:
    """Красный бокс с ручными командами — DNS мёртв даже после авто-фикса.

    два независимых пути оживления — публичный DNS напрямую
    (быстрее всего, не зависит от локального стека) и локальный
    redirect на dnscrypt:5300.
    """
    core = _core_module()
    RED, CYAN, DIM, NC = core.RED, core.CYAN, core.DIM, core.NC
    _box_top, _box_row, _box_bottom = (
        core._box_top, core._box_row, core._box_bottom)
    print()
    _box_top(f"{RED}⚠ DNS НЕ ОТВЕЧАЕТ — ручное восстановление{NC}")
    _box_row()
    _box_row(f"  {DIM}Вариант 1 — публичный DNS напрямую (не зависит от{NC}")
    _box_row(f"  {DIM}локального стека, glibc шлёт UDP):{NC}")
    _box_row()
    _box_row(f"  {CYAN}printf 'nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n' "
             f"> /etc/resolv.conf{NC}")
    _box_row(f"  {CYAN}getent hosts github.com{NC}")
    _box_row()
    _box_row(f"  {DIM}Вариант 2 — локальный DNSCrypt (слушает 127.0.0.1:5300),{NC}")
    _box_row(f"  {DIM}перенаправьте локальный :53 на него (оба протокола):{NC}")
    _box_row()
    _box_row(f"  {CYAN}iptables -t nat -A OUTPUT -p udp -d 127.0.0.1 \\{NC}")
    _box_row(f"  {CYAN}  --dport 53 -j REDIRECT --to-ports 5300{NC}")
    _box_row(f"  {CYAN}iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 \\{NC}")
    _box_row(f"  {CYAN}  --dport 53 -j REDIRECT --to-ports 5300{NC}")
    _box_row(f"  {CYAN}dig @127.0.0.1 github.com +time=2 +tries=1{NC}")
    _box_row()
    _box_row(f"  {DIM}Затем повторите операцию (Сеть → A).{NC}")
    _box_bottom()


def _ensure_system_dns_alive(reason: str = "") -> bool:
    """Гарантия живого СИСТЕМНОГО DNS в ЛЮБОЙ фазе AGH.

    критерий живости — СИСТЕМА резолвит имена (getent через
    nsswitch → resolv.conf), а НЕ «127.0.0.1:53 отвечает». Системный
    DNS может идти через DNS провайдера (чистая установка — :53
    свободен до старта AGH), через AGH на :53 или через redirect на
    dnscrypt — ЛЮБОЙ рабочий путь проходит проверку МОЛЧА. Старая
    проверка только 127.0.0.1:53 на чистой системе давала ложный
    «DNS мёртв», а «восстановление» ломало рабочий DNS провайдера,
    направляя resolv.conf на ещё не готовый dnscrypt (инцидент
    переустановки <ip>: все зеркала AGH «упали» из-за
    мёртвого резолва, [WARN] AGH: КРИТИЧНО на полностью рабочей
    системе).

    Инцидент v44 (<node-2>) остаётся покрыт: если система НЕ
    резолвит (resolv.conf → мёртвый 127.0.0.1 без слушателя после
    удаления AGH), поднимается лестница:
      1. Полный resolv-фикс (resolv.conf + nsswitch + redirect обоих
         протоколов + persist-сервис; AGH-aware — не мешает живому AGH).
      2. Рестарт AdGuardHome, если он держит :53 (AGH мог подвиснуть).
      3. Рестарт dnscrypt-proxy + прямые iptables redirect 53→порт
         dnscrypt (оба протокола).
      4. Публичный DNS напрямую в resolv.conf (последний рубеж,
         локальный стек не поднимается вообще).
    После каждой ступени — системная проба с settle-задержкой
    (dnscrypt/AGH поднимаются не мгновенно).
    Возвращает True только если система реально резолвит.
    """
    core = _core_module()
    info, warn = core.info, core.warn
    why = f" ({reason})" if reason else ""

    # ── Фаза 0: система резолвит — молча выходим ──────────────────────
    # Чистая установка: DNS провайдера жив, :53 пуст — это НОРМА.
    if _system_dns_ok():
        return True
    time.sleep(1)
    if _system_dns_ok():
        # флап-защита: единичный таймаут ≠ мёртвый DNS
        return True

    warn(f"AGH: системный DNS не резолвит{why} — восстанавливаю")

    # ── Ступень 1: полный resolv-фикс ──────────────────────────────────
    try:
        from chimera.modules.resolv_conf_fix import (
            fix_resolv_conf_to_localhost,
        )
        result = fix_resolv_conf_to_localhost(force=True)
        if not result.get("ok"):
            warn(f"AGH: resolv-фикс: {result.get('error')}")
    except Exception as e:
        warn(f"AGH: resolv-фикс недоступен: {e}")
    if _probe_dns_with_settle():
        info("AGH: DNS восстановлен (resolv-фикс)")
        return True

    # ── Ступень 2: рестарт AGH, если он владеет :53 ────────────────────
    try:
        if _svc_is_active() and _port_listening(AGH_DNS_PORT, "udp",
                                               proc="AdGuardHome"):
            subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                           capture_output=True, check=False)
            if _wait_service(AGH_SERVICE_NAME, 20) and _probe_dns_with_settle():
                info("AGH: DNS восстановлен (рестарт AdGuardHome)")
                return True
    except Exception:
        pass

    # ── Ступень 3: dnscrypt + прямые iptables (обо протокола) ──────────
    try:
        if not _svc_is_active("dnscrypt-proxy"):
            subprocess.run(["systemctl", "restart", "dnscrypt-proxy"],
                           capture_output=True, check=False)
            _wait_service("dnscrypt-proxy", 20)
        port = _get_dnscrypt_port()
        if port and port != AGH_DNS_PORT:
            for proto in ("udp", "tcp"):
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "OUTPUT",
                     "-p", proto, "-d", "127.0.0.1", "--dport", "53",
                     "-j", "REDIRECT", "--to-ports", str(port),
                     "-m", "comment", "--comment", "chimera-dns-fix"],
                    capture_output=True, check=False)
    except Exception as e:
        warn(f"AGH: прямое восстановление: {e}")
    if _probe_dns_with_settle():
        info("AGH: DNS восстановлен (прямой iptables redirect)")
        return True

    # ── Ступень 4: публичный DNS напрямую ────────────────────────
    # Локальный стек не поднимается — живой публичный DNS лучше
    # мёртвого 127.0.0.1: установка продолжится (AGH скачается),
    # локальный резолвер вернёт resolv-фикс/финализация.
    if _emergency_public_dns_fallback() and _probe_dns_with_settle():
        info("AGH: DNS восстановлен (публичный DNS напрямую — локальные "
             "резолверы недоступны)")
        return True

    warn("AGH: КРИТИЧНО — DNS по-прежнему мёртв после авто-восстановления")
    _dns_blackhole_help_box()
    return False


# ============================================================================
#  HEADLESS-МАСТЕР (без браузера и туннелей — API на loopback)
# ============================================================================
def _agh_install_api_post(path: str, payload: dict, timeout: int = 15) -> tuple:
    """POST к API мастера первого запуска AGH (127.0.0.1:3000).

    Те же endpoints, что дергает веб-мастер (v44: браузерный POST
    /control/install/check_config падал «Failed to fetch» из-за
    сетевого пути браузер→VPS; loopback-путь не зависит ни от UFW,
    ни от туннелей, ни от прокси клиента). Возвращает (ok, error).
    """
    import urllib.error
    import urllib.request
    url = f"http://127.0.0.1:{AGH_WEB_PORT}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status in (200, 204):
                return True, None
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="replace")[:200]
        except Exception:
            body = ""
        return False, f"HTTP {e.code}" + (f": {body}" if body else "")
    except Exception as e:
        return False, str(e)[:200]


def _wizard_configure_headless(username: str, password: str,
                               web_port: int = AGH_WEB_PORT,
                               timeout_sec: int = 20) -> bool:
    """Завершает мастер первого запуска БЕЗ браузера и туннелей.

    POST /control/install/configure на loopback — ровно то, что делает
    веб-мастер на шаге 5: AGH сам пишет yaml (users + bcrypt-пароль,
    корректный schema_version) и стартует DNS на 127.0.0.1:53.
    Пока redirect 53→5300 активен, системный DNS продолжает работать
    через dnscrypt; финализация затем переключит его на AGH.

    web_port — кастомный порт Web UI в payload мастера (API живёт
    на дефолтном :3000, а конфиг пишет уже с нужным портом).
    """
    core = _core_module()
    info, warn = core.info, core.warn

    web_conf = {"ip": "0.0.0.0", "port": web_port}
    dns_conf = {"ip": "127.0.0.1", "port": AGH_DNS_PORT}

    # Пре-валидация (не фатальна: в старых сборках endpoint отсутствует)
    ok, err = _agh_install_api_post(
        "/control/install/check_config", {"web": web_conf, "dns": dns_conf})
    if not ok:
        info(f"AGH: check_config: {err or 'ок'} (продолжаю)")

    payload = {"web": web_conf, "dns": dns_conf,
               "username": username, "password": password}
    ok, err = _agh_install_api_post("/control/install/configure", payload)
    if not ok:
        warn(f"AGH: configure не прошёл: {err}")
        return False

    # AGH пишет конфиг мгновенно; ждём появления секции users.
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if AGH_CONF.exists():
            try:
                if _yaml_has_users(AGH_CONF.read_text(errors="replace")):
                    return True
            except Exception:
                pass
        time.sleep(1)
    warn("AGH: configure прошёл, но конфиг с users не появился")
    return False


def _ask_admin_credentials() -> "tuple[str, str] | None":
    """Логин + пароль администратора AGH в TUI (пароль дважды, без эха)."""
    core = _core_module()
    CYAN, NC, YELLOW = core.CYAN, core.NC, core.YELLOW
    import getpass
    try:
        username = input(
            f"{CYAN}Логин администратора [admin]: {NC}").strip() or "admin"
        while True:
            pw1 = getpass.getpass(f"{CYAN}Пароль: {NC}")
            if len(pw1) < 6:
                print(f"{YELLOW}  Минимум 6 символов — ещё раз{NC}")
                continue
            pw2 = getpass.getpass(f"{CYAN}Повтор пароля: {NC}")
            if pw1 != pw2:
                print(f"{YELLOW}  Пароли не совпадают — ещё раз{NC}")
                continue
            return username, pw1
    except (EOFError, KeyboardInterrupt):
        return None


def _ask_headless_wizard() -> bool:
    """Способ завершения мастера: headless-API (рекомендуется) или веб."""
    core = _core_module()
    CYAN, NC, DIM, GREEN = core.CYAN, core.NC, core.DIM, core.GREEN
    _box_top, _box_row, _box_sep, _box_bottom, _box_item = (
        core._box_top, core._box_row, core._box_sep, core._box_bottom,
        core._box_item)
    print()
    _box_top("🛡️  AdGuard Home — создание администратора")
    _box_row()
    _box_row(f"  {DIM}Мастер можно завершить прямо здесь — без браузера,{NC}")
    _box_row(f"  {DIM}туннелей и UFW (API на loopback).{NC}")
    _box_sep()
    _box_item("1", f"Без браузера {GREEN}(рекомендуется){NC}")
    _box_item("2", f"Веб-мастер http://<IP-сервера>:{AGH_WEB_PORT} "
                   f"{DIM}(порт временно открыт){NC}")
    _box_bottom()
    try:
        ch = input(f"{CYAN}Выбор [1]: {NC}").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return True
    return ch != "2"


def _print_wizard_instructions(domain: str = "") -> None:
    """Инструкция по веб-мастеру: URL — ВСЕГДА адрес СЕРВЕРА (v40),
    порт открыт для всех — туннели НЕ нужны (v44)."""
    core = _core_module()
    _CYAN = getattr(core, "CYAN", "")
    _NC = getattr(core, "NC", "")
    _DIM = getattr(core, "DIM", "")
    pub_ip = _get_public_ip()
    wizard_host = pub_ip if _is_public_ipv4(pub_ip) else "IP-СЕРВЕРА"
    print()
    core._box_top("🛡️  AdGuard Home — мастер первого запуска")
    core._box_row()
    core._box_row(f"  Откройте в браузере {_CYAN}http://{wizard_host}:{AGH_WEB_PORT}{_NC}")
    if domain:
        core._box_row(f"  {_DIM}(или http://{domain}:{AGH_WEB_PORT}){_NC}")
    core._box_sep()
    core._box_row(f"  {_DIM}Порт {AGH_WEB_PORT} открыт для всех — SSH-туннели НЕ нужны{_NC}")
    core._box_sep()
    core._box_row(f"  1. Веб-интерфейс: {_CYAN}Все интерфейсы / 0.0.0.0 :{AGH_WEB_PORT}{_NC}")
    core._box_row(f"  2. DNS-сервер:    {_CYAN}Только 127.0.0.1 (Loopback){_NC}")
    core._box_row(f"     {_DIM}(Chimera перенастроит адреса автоматически){_NC}")
    core._box_row(f"  3. Логин/пароль:  {_CYAN}придумайте (admin + ваш пароль){_NC}")
    core._box_sep()
    core._box_row(f"  {_DIM}Пока мастер не завершён, :53 держит redirect → dnscrypt.{_NC}")
    core._box_bottom()


def _complete_first_run_wizard(web_mode: str, domain: str,
                               interactive: bool = True,
                               state_extra: "dict | None" = None,
                               web_port: int = AGH_WEB_PORT) -> bool:
    """Мастер первого запуска: headless-API (по умолчанию) или браузер.

    Headless (v44): логин/пароль в TUI → POST /control/install/configure
    на loopback → конфиг с users пишет сам AGH. Не нужен ни браузер,
    ни SSH-туннель, ни UFW. Веб-мастер — fallback: :3000 временно
    открыт для всех, инструкция с URL сервера.

    web_port — финальный порт Web UI (wizard-фаза слушает дефолт
    :3000; кастомный порт применит финализация).

    Возвращает True, если конфиг с users создан (мастер завершён).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    ssh_ip = _get_ssh_client_ip()

    aghome_state_save({
        **(state_extra or {}),
        "enabled": True,
        "phase": "wizard",
        "web_mode": web_mode,
        "web_port": web_port,
        "domain": domain,
        "self_signed": web_mode == AGH_WEB_HTTPS_SELF,
        "tls_enabled": web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF),
        "doh_port": AGH_DOH_PORT,
        "dot_port": AGH_DOT_PORT,
        "doq_port": AGH_DOQ_PORT,
        "wizard_ips": ["0.0.0.0/0"],
        "wizard_ssh_ip": ssh_ip,
        "installed_at": datetime.now().isoformat(),
    })

    # ── Путь 1: headless — без браузера, без туннелей ──────────────────
    if interactive and _ask_headless_wizard():
        creds = _ask_admin_credentials()
        if creds:
            info("AGH: завершаю мастер локально (API loopback)...")
            if _wizard_configure_headless(*creds, web_port=web_port):
                success("AGH: администратор создан — мастер завершён "
                        "без браузера")
                return True
            warn("AGH: headless-настройка не удалась — перехожу к веб-мастеру")
        else:
            info("AGH: пароль не задан — перехожу к веб-мастеру")

    # ── Путь 2: веб-мастер (fallback) ──────────────────────────────────
    wizard_ips = _open_wizard_access(ssh_ip)
    if wizard_ips:
        info(f"AGH: порт {AGH_WEB_PORT} временно открыт в UFW "
             f"(для всех, до завершения мастера)")
    else:
        info(f"AGH: UFW недоступен — мастер на :{AGH_WEB_PORT}, "
             f"если порт не закрыт снаружи")

    _print_wizard_instructions(domain)

    if not interactive:
        # do_full_install продолжит своё; мастер завершат позже (A → 2)
        return False

    info("Ожидание завершения мастера "
         f"(до {AGH_WIZARD_WAIT_SEC // 60} мин, Ctrl+C — пропустить)...")
    return _wait_wizard_completed(AGH_WIZARD_WAIT_SEC)


def install_aghome(interactive: bool = True) -> bool:
    """Установка AdGuard Home поверх DNSCrypt.

    Шаги:
      0. DNS-alive: системный DNS жив ДО всего (иначе GitHub недоступен).
      1. Проверка: dnscrypt-proxy активен (upstream-требование).
      2. Скачивание бинарника (fetch_package + зеркала).
      3. Пользователь adguard + рабочие директории.
      4. МИГРАЦИЯ: снять :53 у dnscrypt (redirect 53→5300 страхует DNS).
      5. systemd-unit + старт БЕЗ конфига → wizard (:3000).
      6. Мастер: headless-API (по умолчанию — без браузера и туннелей)
         или веб (:3000 временно открыт для всех).
      7. interactive: финализация после завершения мастера.

    Возвращает True если AGH установлен и (interactive) финализирован.
    В КАЖДОЙ точке выхода (в т.ч. провальной) DNS остаётся живым —
    _ensure_system_dns_alive (v44).
    """
    core = _core_module()
    info, warn, success = core.info, core.warn, core.success
    _run = core._run

    # ── 0. DNS-alive: системный DNS жив ДО всего остального ───────────
    # v44 (<node-2>): установка запускалась уже с мёртвым DNS → GitHub
    # «недоступен», скачивание проваливалось, а система оставалась без
    # DNS. Чиним ДО: redirect 53→5300 (оба протокола) + resolv.conf.
    _ensure_system_dns_alive("перед установкой AGH")

    # ── 1. dnscrypt обязателен (upstream) ─────────────────────────────
    if not _svc_is_active("dnscrypt-proxy"):
        warn("AGH: dnscrypt-proxy не активен — AdGuard Home не будет установлен")
        warn("AGH: сначала установите DNSCrypt (Сеть → установка / wizard)")
        return False

    # ── 1b. конфликт портов AGH с Xray/AWG ──────────────────────
    # Xray/AWG на :53 — AGH не сможет владеть DNS-портом (ломает xray);
    # :853/:30443 — AGH отберёт порт у Xray на буте (Before=xray.service).
    _pc = _agh_core_port_conflicts()
    if AGH_DNS_PORT in _pc:
        warn(f"AGH: порт 53 занят ({'; '.join(_pc[AGH_DNS_PORT])}) — "
             "AGH обязан владеть 127.0.0.1:53, установка отменена")
        warn("AGH: смените порт Xray (меню 5 → R) или откажитесь от AGH")
        return False
    for _p in (AGH_DOT_PORT, AGH_DOH_PORT, AGH_DOQ_PORT):
        if _p in _pc:
            warn(f"AGH: порт {_p} занят ({'; '.join(_pc[_p])}) — "
                 "TLS-порты (DoH/DoT/DoQ) будут отключены при финализации")

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
        # progress_label: попытки зеркал видны пользователю (раньше все
        # 6 URL молча перебирались — «Не удалось скачать» без диагноза).
        if not fetch_package(AGHOME_SPEC, tag=tag, arch=agh_arch,
                             progress_label="AGH"):
            warn("AGH: не удалось скачать AdGuardHome — установка прервана")
            warn("AGH: скачайте tar.gz вручную в /root/ и повторите (Сеть → A)")
            # Ручное скачивание тоже требует DNS — гарантируем живой
            # резолв после провала (v44).
            _ensure_system_dns_alive("после провала скачивания")
            return False
        success(f"AGH: бинарник установлен: {AGH_BIN}")

    # ── 3. Пользователь + директории ─────────────────────────────────
    AGH_WORK_DIR.mkdir(parents=True, exist_ok=True)
    AGH_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    (AGH_WORK_DIR / "data").mkdir(parents=True, exist_ok=True)
    _create_aghome_user()

    # ── 4. Миграция dnscrypt с :53 ────────────────────────────────────────
    if not migrate_dnscrypt_off_53():
        warn("AGH: не удалось освободить :53 у dnscrypt — установка прервана")
        _ensure_system_dns_alive("после провала миграции dnscrypt")
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
        _ensure_system_dns_alive("после провала старта AGH")
        return False
    success(f"AGH: служба активна ( {'мастер первого запуска' if wizard_restart else 'существующий конфиг'} )")

    # ── 6+7. Мастер: headless-API (по умолчанию) или веб ─────────────
    web_mode, domain, web_port = AGH_WEB_LOOPBACK, "", AGH_WEB_PORT
    if wizard_restart:
        web_mode, domain = _ask_web_mode()
        web_port = _ask_web_port() # кастомный порт Web UI
        if _complete_first_run_wizard(web_mode, domain, interactive,
                                      web_port=web_port):
            return finalize_aghome_config(web_mode=web_mode,
                                          domain=domain,
                                          web_port=web_port,
                                          interactive=interactive)
        # Мастер не завершён (таймаут/неинтерактивно/headless-провал
        # и таймаут веб-пути) — DNS обязан остаться живым (v44).
        _ensure_system_dns_alive("wizard-фаза (мастер не завершён)")
        if interactive:
            warn("AGH: мастер не завершён — установка продолжается")
            info("AGH: завершите позже: Сеть → A → 2 (Завершить настройку)")
        return True

    # Существующий конфиг → сразу финализируем (идемпотентно)
    if interactive:
        st = aghome_state_load()
        web_mode = st.get("web_mode", AGH_WEB_HTTPS_LE)
        domain = st.get("domain", "")
        return finalize_aghome_config(web_mode=web_mode, domain=domain)
    return True


def _wait_wizard_completed(timeout_sec: int, poll_sec: float = 5.0) -> bool:
    """Ждёт пока мастер первого запуска запишет конфиг с users.

    В цикле поддерживает DNS-alive (v44): redirect 53→5300 мог
    слететь во время ожидания — пробим фактическим запросом и чиним.
    """
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
        # DNS black-hole недопустим даже во время ожидания мастера.
        # системная проба (nsswitch-путь), а не только 127.0.0.1:53
        # wizard-фаза может идти и на DNS провайдера (чистая установка).
        if not _system_dns_ok():
            try:
                core.warn("AGH: DNS не отвечает во время мастера — чиню")
            except Exception:
                pass
            _ensure_system_dns_alive("ожидание мастера")
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
# ── TLS-диагностика/self-heal ──────────────────────────────────────────
# AGH при ошибке загрузки сертификата НЕ падает (home.go: newTLSManager →
# err → лог + onConfigModified): молча ставит tls.enabled=false, пишет это
# в yaml и продолжает на plain DNS. Симптом: служба активна, :53 слушает,
# а :30443/:853 — нет. Хелперы ниже диагностируют причину по journalctl,
# чинят права/пару сертификата и перезапускают TLS-секцию на live-конфиге.


def _tls_ports_status() -> "dict[tuple[int, str], bool]":
    """Состояние TLS-портов AGH: DoH(:30443/tcp), DoT(:853/tcp), DoQ(:853/udp)."""
    return {
        (AGH_DOH_PORT, "tcp"): _port_listening(AGH_DOH_PORT, "tcp",
                                               proc="AdGuardHome"),
        (AGH_DOT_PORT, "tcp"): _port_listening(AGH_DOT_PORT, "tcp",
                                               proc="AdGuardHome"),
        (AGH_DOQ_PORT, "udp"): _port_listening(AGH_DOQ_PORT, "udp",
                                               proc="AdGuardHome"),
    }


def _tls_live_enabled(text: str) -> "bool | None":
    """tls.enabled из ЖИВОГО yaml (AGH мог сам переписать на false).

    None — секции tls нет (не смогли определить).
    """
    m = re.search(r'^tls:\s*$', text, re.MULTILINE)
    if not m:
        return None
    for ln in text[m.end():].splitlines():
        if re.match(r'^[A-Za-z_]', ln):        # следующая top-level секция
            break
        em = re.match(r'^\s*enabled:\s*(\w+)', ln)
        if em:
            return em.group(1).lower() == "true"
    return None


def _agh_tls_journal_errors(tail: int = 120) -> str:
    """Строки об ошибках TLS из journalctl AdGuardHome (для точного WARN)."""
    try:
        r = subprocess.run(
            ["journalctl", "-u", AGH_SERVICE_NAME, "-n", str(tail),
             "--no-pager", "--no-hostname"],
            capture_output=True, text=True, check=False, timeout=15)
        hits = [ln.strip() for ln in r.stdout.splitlines()
                if re.search(r'(?i)tls|certificate|private.?key', ln)
                and re.search(r'(?i)error|warn|fatal|fail|couldn', ln)]
        return " | ".join(hits[-3:]) if hits else ""
    except Exception:
        return ""


def _cert_pair_matches(cert: Path, key: Path) -> "tuple[bool, str]":
    """Сертификат и приватный ключ — одна пара? (openssl pubkey compare).

    Возвращает (ok, причина). ok=True также когда openssl недоступен —
    блокируем ТОЛЬКО при доказанном рассинхроне (оба pubkey получены и
    различаются).
    """
    try:
        c = subprocess.run(["openssl", "x509", "-in", str(cert),
                            "-noout", "-pubkey"],
                           capture_output=True, text=True, check=False,
                           timeout=15)
        k = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout"],
                           capture_output=True, text=True, check=False,
                           timeout=15)
        if c.returncode != 0 or k.returncode != 0:
            return True, "openssl не смог прочитать пару (пропускаю проверку)"
        cpub = c.stdout.strip()
        kpub = k.stdout.strip()
        if not cpub or not kpub:
            return True, "пустой pubkey (пропускаю проверку)"
        if cpub == kpub:
            return True, ""
        return False, "публичные ключи сертификата и private key различаются"
    except Exception as e:
        return True, f"проверка недоступна ({e})"


def _certs_readable_by_user(user: str, cert: Path, key: Path) -> "tuple[bool, str]":
    """Читаемы ли cert/key от имени пользователя службы (runuser/sudo)."""
    test_cmd = f"test -r {cert} && test -r {key}"
    for prefix in (["runuser", "-u", user, "--", "sh", "-c"],
                   ["sudo", "-n", "-u", user, "--", "sh", "-c"]):
        try:
            r = subprocess.run(prefix + [test_cmd],
                               capture_output=True, text=True, check=False,
                               timeout=15)
            if r.returncode == 0:
                return True, ""
            return False, (f"{Path(prefix[0]).name} rc={r.returncode}: "
                           f"{(r.stderr or '').strip()[:120]}")
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return True, "runuser/sudo недоступны — проверка пропущена"


def _own_certs_dir() -> None:
    """Владелец каталога certs — adguard (право на обход каталога)."""
    try:
        subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CERTS_DIR)],
                       capture_output=True, check=False)
        AGH_CERTS_DIR.chmod(0o755)
    except Exception:
        pass


def _heal_tls_listeners(server_name: str, domain: str,
                        cert_path: "Path | None",
                        key_path: "Path | None") -> "tuple[bool, Path, Path, str]":
    """Диагностика + починка TLS-портов AGH.

    Порядок:
      1. journalctl — точная причина от самого AGH.
      2. Локальная проверка пары: файлы есть? пара совпадает? читаемы
         пользователем adguard?
      3. Починка: права (chown) / self-signed fallback (пара битая) /
         простой рестарт (локально всё ок — транзиент).
      4. Перезапись tls-секции в ЖИВОМ конфиге (AGH мог сам выставить
         enabled:false) + restart + ожидание портов.

    Возвращает (tls_ok, cert_path, key_path, итоговое_сообщение).
    """
    core = _core_module()
    info, warn = core.info, core.warn

    # ── 1. Причина от AGH ─────────────────────────────────────────────
    jerr = _agh_tls_journal_errors()
    if jerr:
        warn(f"AGH: журнал AGH: {jerr[:300]}")
    try:
        live_text = AGH_CONF.read_text(errors="replace")
    except Exception as e:
        return False, cert_path, key_path, f"не читается конфиг: {e}"
    if _tls_live_enabled(live_text) is False:
        info("AGH: AGH сам выключил TLS (сертификат не загрузился) — чиню")

    # ── 2. Локальная диагностика ──────────────────────────────────────
    problems: list[str] = []
    only_perms = False
    if not (cert_path and key_path
            and Path(cert_path).exists() and Path(key_path).exists()):
        problems.append("файлы сертификата отсутствуют")
    else:
        pair_ok, pair_why = _cert_pair_matches(Path(cert_path), Path(key_path))
        if not pair_ok:
            problems.append(f"пара рассинхронена: {pair_why}")
        readable, rwhy = _certs_readable_by_user(AGH_USER, Path(cert_path),
                                                 Path(key_path))
        if not readable:
            problems.append(f"файлы не читаются пользователем {AGH_USER}: {rwhy}")
            only_perms = len(problems) == 1

    # ── 3. Починка ────────────────────────────────────────────────────
    if problems:
        for p in problems:
            warn(f"AGH: TLS: {p}")
        if only_perms:
            info("AGH: чиню права на сертификаты (chown adguard)")
            _own_certs()
            _own_certs_dir()
        else:
            info("AGH: переключаю TLS на self-signed сертификат "
                 "(LE-пару можно вернуть позже через меню)")
            cert_path, key_path = _generate_self_signed_tls(
                domain or server_name or _get_public_ip() or "localhost")
            if cert_path is None:
                return (False, cert_path, key_path,
                        "self-signed создать не удалось — TLS отключён, "
                        "plain DNS :53 продолжает работать")
    else:
        info("AGH: сертификат локально корректен — перезапускаю AGH "
             "(повторная попытка поднятия TLS)")

    if not (cert_path and key_path):
        return False, cert_path, key_path, "нет валидного сертификата"

    # ── 4. Перезапись tls-секции в live-конфиге + рестарт ─────────────
    try:
        live_text = AGH_CONF.read_text(errors="replace")
        new_tls = build_tls_section(True, server_name,
                                    Path(cert_path), Path(key_path))
        AGH_CONF.write_text(
            yaml_replace_sections(live_text, {"tls": new_tls}))
        subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                       capture_output=True, check=False)
    except Exception as e:
        return False, cert_path, key_path, f"не удалось обновить конфиг: {e}"

    subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    if not _wait_service(AGH_SERVICE_NAME, 30):
        return (False, cert_path, key_path,
                "AGH не поднялся после TLS-лечения — journalctl -u "
                f"{AGH_SERVICE_NAME} -n 30")
    # TLS-порты могут подняться на 1-3 с позже службы — поллим
    for _ in range(8):
        if all(_tls_ports_status().values()):
            return True, cert_path, key_path, "TLS-порты подняты"
        time.sleep(2)
    return (False, cert_path, key_path,
            "TLS-порты не поднялись и после лечения — см. журнал выше")


def finalize_aghome_config(web_mode: str = "", domain: str = "",
                           interactive: bool = True,
                           web_port: int = 0) -> bool:
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

    web_port — кастомный порт Web UI (0/None → из state, иначе
    AGH_WEB_PORT). При смене порта старый закрывается в UFW/реестре.
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
    # кастомный порт Web UI (state → дефолт)
    try:
        web_port = int(web_port) if web_port else 0
    except (TypeError, ValueError):
        web_port = 0
    if not web_port:
        try:
            web_port = int(st.get("web_port", 0) or 0)
        except (TypeError, ValueError):
            web_port = 0
    if not web_port or not (1 <= web_port <= 65535):
        web_port = AGH_WEB_PORT
    tls_enabled = web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF)

    # ── защита от портов-коллизий AGH ↔ Xray/AWG/чужие сервисы ────
    # AGH биндит фиксированные 53/853/30443 ДО старта xray — коллизия
    # отдаёт порт AGH и роняет xray (EOF у всех клиентов). Xray на :53 —
    # финализация невозможна в принципе (AGH обязан владеть :53).
    _port_conf = _agh_core_port_conflicts(extra_ports=(web_port,))
    if AGH_DNS_PORT in _port_conf:
        warn(f"AGH: порт {AGH_DNS_PORT} занят "
             f"({'; '.join(_port_conf[AGH_DNS_PORT])}) — AGH обязан "
             f"владеть DNS :53; финализация отменена, конфиг не тронут")
        return False
    if tls_enabled:
        _tls_hit = [p for p in (AGH_DOH_PORT, AGH_DOT_PORT, AGH_DOQ_PORT)
                    if p in _port_conf]
        if _tls_hit:
            for _p in _tls_hit:
                warn(f"AGH: порт {_p} занят ({'; '.join(_port_conf[_p])}) — "
                     f"TLS-порты DoH/DoT/DoQ отключены")
            tls_enabled = False
            web_mode = AGH_WEB_HTTP_PUB if web_mode != AGH_WEB_LOOPBACK else web_mode
    if web_port in _port_conf:
        # Web-порт занят → AGH crash-loop (bind web = fatal) — сдвигаем.
        _new_wp = _find_free_web_port(web_port)
        if _new_wp:
            warn(f"AGH: порт Web UI {web_port} занят "
                 f"({'; '.join(_port_conf[web_port])}) → порт {_new_wp}")
            web_port = _new_wp

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
    public_ipv6 = _get_public_ipv6() # bind_hosts += IPv6
    if public_ipv6:
        info(f"AGH: IPv6 bind: {public_ipv6} — DoT/DoH/Web доступны и по v6")

    sections: dict = {
        "http":             build_http_section(web_mode, web_port),
        "dns":              build_dns_section(dc_port, public_ip, tls_enabled,
                                           public_ipv6=public_ipv6),
        "tls":              build_tls_section(tls_enabled, server_name, cert_path, key_path),
        "filters":          build_filters_section(),
        "whitelist_filters": build_whitelist_filters_section(),
        "user_rules":       build_user_rules_section(),
        "querylog":         build_querylog_section(),
        "statistics":       build_statistics_section(),
        "dhcp":             "dhcp:\n  enabled: false\n",
    }
    new_text = yaml_replace_sections(
        original, sections, scalars={"language": "ru"})

    # ── GATE: дубли top-level ключей = crash-loop AGH ────────────
    # Строгий YAML-парсер AGH падает на «mapping key already defined».
    # Safety-net в yaml_replace_sections вычищает дубли, сюда попасть
    # нельзя — но если всё же попали, живой конфиг НЕ трогаем (DNS
    # важнее финализации).
    dups = _duplicate_top_keys(new_text)
    if dups:
        warn(f"AGH: BUG — дубли top-level ключей {sorted(dups)}; "
             "конфиг НЕ записан, живой конфиг не тронут")
        return False

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
    # reset-failed перед рестартом (паттерн start-limit)
    subprocess.run(["systemctl", "reset-failed", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                   capture_output=True, check=False)
    ok = _wait_service(AGH_SERVICE_NAME, 30)

    if not ok and public_ipv6:
        # Self-heal #0 (инцидент <node-2> 30.08): AGH не стартовал
        # с IPv6 в bind_hosts — сначала снимаем ТОЛЬКО IPv6: публичный IPv4
        # (DoT/DoH/Web) и loopback остаются жить. Прежний путь сразу ронял
        # всё до loopback-only, теряя ещё и TLS-порты.
        warn("AGH: не запустилась с IPv6 в bind_hosts — "
             "пробую без IPv6 (публичный IPv4 остаётся)")
        healed = build_dns_section(dc_port, public_ip, tls_enabled,
                                   public_ipv6="")
        new_text2 = yaml_replace_sections(new_text, {"dns": healed})
        try:
            AGH_CONF.write_text(new_text2)
            subprocess.run(["chown", f"{AGH_USER}:{AGH_GROUP}", str(AGH_CONF)],
                           capture_output=True, check=False)
        except Exception:
            pass
        subprocess.run(["systemctl", "reset-failed", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "restart", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
        ok = _wait_service(AGH_SERVICE_NAME, 20)
        if ok:
            public_ipv6 = ""
            warn("AGH: работает без IPv6-bind (IPv4+loopback); причина в "
                 "journalctl -u AdGuardHome -n 20")

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
        subprocess.run(["systemctl", "reset-failed", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
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
        subprocess.run(["systemctl", "reset-failed", AGH_SERVICE_NAME],
                       capture_output=True, check=False)
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
    # только по процессу AdGuardHome (127.0.0.53:53 systemd-resolved
    # давал ложное «DNS слушает») + retry: AGH биндит порты на 1-3 с
    # позже, чем systemd помечает службу active.
    dns_udp = _port_listening(AGH_DNS_PORT, "udp", proc="AdGuardHome")
    if not dns_udp:
        for _ in range(6):
            time.sleep(2)
            dns_udp = _port_listening(AGH_DNS_PORT, "udp", proc="AdGuardHome")
            if dns_udp:
                break
    dns_tcp = _port_listening(AGH_DNS_PORT, "tcp", proc="AdGuardHome")
    if dns_udp:
        success(f"AGH: DNS слушает :{AGH_DNS_PORT} (udp{'+' + 'tcp' if dns_tcp else ''})")
    else:
        warn(f"AGH: активна, но :{AGH_DNS_PORT}/udp не слушается — journalctl")

    if tls_enabled:
        # AGH при ошибке сертификата молча ставит tls.enabled=false
        # и продолжает на plain DNS → порты не поднимутся сами. Даём
        # время, затем диагностируем и чиним (_heal_tls_listeners).
        ports = _tls_ports_status()
        if not all(ports.values()):
            for _ in range(6):
                time.sleep(2)
                ports = _tls_ports_status()
                if all(ports.values()):
                    break
        if not all(ports.values()):
            warn("AGH: TLS-порты не поднялись — диагностирую причину...")
            healed, cert_path, key_path, msg = _heal_tls_listeners(
                server_name, domain, cert_path, key_path)
            if not healed:
                warn(f"AGH: TLS не восстановлен: {msg}")
                warn("AGH: DNS :53 работает; DoH/DoT/DoQ выключены "
                     "до починки сертификата")
            else:
                success("AGH: TLS восстановлен (self-heal)")
            ports = _tls_ports_status()
        for (port, proto), up in ports.items():
            label = {(AGH_DOH_PORT, "tcp"): "DoH+HTTPS",
                     (AGH_DOT_PORT, "tcp"): "DoT",
                     (AGH_DOQ_PORT, "udp"): "DoQ"}[(port, proto)]
            if up:
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
                           web_public_plain=(web_mode == AGH_WEB_HTTP_PUB),
                           web_port=web_port)

    # ── Перегенерация конфига Xray ────────────────────────────────────
    if dns_udp:
        _regenerate_xray_config(interactive=interactive)

    # ── State ─────────────────────────────────────────────────────────
    aghome_state_save({
        **st,
        "enabled": True,
        "phase": "finalized",
        "web_mode": web_mode,
        "web_port": web_port,
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
    if web_mode == AGH_WEB_HTTP_PUB:
        info(f"AGH: Web UI: http://{domain or (_get_public_ip() or 'IP-СЕРВЕРА')}:{web_port}")
    elif web_port != AGH_WEB_PORT:
        info(f"AGH: Web UI (локально): http://127.0.0.1:{web_port}")
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

     (install-order): НЕ перегенерирует, когда идёт do_full_install
    (INSTALL_STARTED=True, INSTALL_COMPLETED=False — AGH ставится ДО
    Xray) или state.json отсутствует (чистая установка). В обоих случаях
    конфиг Xray ещё не существует или будет (пере)создан ниже по потоку
    AGH-aware генератором из СВЕЖИХ параметров (живая проба
    agh_dns_available() → DNS 127.0.0.1:53), а регенерация здесь по
    СТАРОМУ state.json затёрла бы только что введённые UUID/ключи/режим
    через _load_state_into_globals(). Итоговый DNS-путь верифицируется
    по фактическому config.json функцией _verify_xray_dns_via_agh()
    (_core.py, конец установки). Вызов актуален из меню (AGH включают
    поверх живой установки) и при удалении AGH.
    """
    core = _core_module()
    info, warn = core.info, core.warn
    try:
        # (install-order): идёт do_full_install (AGH ставится ДО
        # Xray)? Перегенерировать НЕЛЬЗЯ: конфиг Xray будет создан ниже
        # по потоку AGH-aware генератором из СВЕЖИХ параметров, а вызов
        # _load_state_into_globals() здесь затёр бы только что введённые
        # параметры (UUID/ключи/режим) СТАРЫМ state.json при переустановке
        # поверх живой установки. Маркер: INSTALL_STARTED=True и
        # INSTALL_COMPLETED=False (устанавливается в конце do_full_install).
        mid_install = (getattr(core, "INSTALL_STARTED", False)
                       and not getattr(core, "INSTALL_COMPLETED", True))
        state_path = XRAY_STATE_FILE
        if mid_install:
            info("AGH: установка в процессе — конфиг Xray будет создан "
                 "этапом установки Xray из свежих параметров "
                 "(DNS сразу через AGH:53)")
            return True
        if not state_path.exists():
            info("AGH: Xray ещё не установлен — его конфиг будет создан "
                 "на этапе установки Xray (DNS сразу через AGH:53)")
            return True
        state = json.loads(state_path.read_text())
        protocol = state.get("protocol_mode", "reality")
        mode = state.get("install_mode", "A")

        if hasattr(core, "_load_state_into_globals"):
            core._load_state_into_globals()

        # (<node-2>): generate_xray_config_chain_entry_multi живёт в
        # chain_nodes (не в xray_install — AttributeError «no attribute»
        # ломал перегенерацию конфига Xray в режиме B).
        from chimera.modules import chain_nodes
        from chimera.modules import xray_install
        if mode == "B":
            gen = getattr(chain_nodes, "generate_xray_config_chain_entry_multi",
                          None)
            if gen is None:
                warn("AGH: chain_nodes.generate_xray_config_chain_entry_multi "
                     "недоступен — конфиг Xray не перегенерирован")
                return False
            gen()
        elif (protocol == "xhttp"
              and hasattr(xray_install, "generate_xray_config_xhttp")):
            xray_install.generate_xray_config_xhttp()
        else:
            xray_install.generate_xray_config()

        # (start-limit-fix): reset-failed перед рестартом — перегенерация
        # конфига xray (финализация/удаление AGH) идёт в цепочке с другими
        # рестартами (dnscrypt, AGH, ru_subnets restore)
        subprocess.run(["systemctl", "reset-failed", "xray"],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, check=False)
        time.sleep(2)
        if _svc_is_active("xray"):
            info("AGH: конфиг Xray обновлён (DNS → 127.0.0.1:53 через AGH)")
            return True
        # Повторная попытка после reset-failed (start-limit мог сработать
        # на рестартах соседних сервисов миграции)
        subprocess.run(["systemctl", "reset-failed", "xray"],
                       capture_output=True, check=False)
        subprocess.run(["systemctl", "restart", "xray"],
                       capture_output=True, check=False)
        if _wait_service("xray", 15):
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

    # v44: ok:true фикса ≠ живой DNS — проверяем ФАКТИЧЕСКИМ запросом
    # и чиним при отказе (resolv-фикс → рестарт AGH → прямые iptables).
    if _ensure_system_dns_alive("после удаления AGH"):
        info("AGH: системный DNS жив")
    else:
        warn("AGH: DNS НЕ восстановлен автоматически — команды в боксе выше")

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
      2. Старт AGH → detectFirstRun: конфига нет → мастер.
      3. Новый логин/пароль: headless-API (v44, по умолчанию — без
         браузера и туннелей) или веб-мастер.
      4. Финализация (секции восстанавливаются из aghome_state.json —
         режим Web UI/домен/TLS сохраняются).
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
        _ensure_system_dns_alive("сброс пароля (служба не стартовала)")
        return False

    web_port = int(st.get("web_port", AGH_WEB_PORT) or AGH_WEB_PORT)
    if _complete_first_run_wizard(
            st.get("web_mode", AGH_WEB_HTTPS_LE), st.get("domain", ""),
            interactive=True, state_extra=st, web_port=web_port):
        ok = finalize_aghome_config(web_mode=st.get("web_mode", AGH_WEB_HTTPS_LE),
                                    domain=st.get("domain", ""),
                                    web_port=web_port)
        if ok:
            success("AGH: пароль администратора обновлён, конфиг восстановлен")
        return ok

    _ensure_system_dns_alive("сброс пароля (мастер не завершён)")
    warn("AGH: мастер не завершён — пароль не изменён, конфиг не тронут")
    info("AGH: повторите позже: Сеть → A → 3 (Сброс пароля)")
    return False


# ============================================================================
#  СТАТУС
# ============================================================================

def _client_dns_links(s: dict) -> "list[tuple[str, str]]":
    """Готовые ссылки DoH/DoT/DoQ для вставки в клиент (браузер/ОС/приложение).

    Хост = домен TLS (LE-режим); если домена нет — публичный IPv4
    (self-signed-сеть). Пустой список, если TLS выключен или хост
    определить не удалось (нет домена и IP приватный — ссылка была бы
    бесполезна за пределами сервера).
    """
    if not s.get("tls_enabled"):
        return []
    host = str(s.get("domain") or "").strip()
    if not host:
        ip = str(_get_public_ip() or "").strip()
        host = ip if _is_public_ipv4(ip) else ""
    if not host:
        return []
    return [
        ("DoH", f"https://{host}:{s.get('doh_port', AGH_DOH_PORT)}/dns-query"),
        ("DoT", f"tls://{host}:{s.get('dot_port', AGH_DOT_PORT)}"),
        ("DoQ", f"quic://{host}:{s.get('doq_port', AGH_DOQ_PORT)}"),
    ]


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
        "web_listening":    _port_listening(web_port, "tcp",
                                             proc="AdGuardHome"),
        "domain":           domain,
        "self_signed":      st.get("self_signed", False),
        "tls_enabled":      tls_enabled,
        "doh_port":         st.get("doh_port", AGH_DOH_PORT),
        "doh_listening":    _port_listening(st.get("doh_port", AGH_DOH_PORT), "tcp",
                                             proc="AdGuardHome"),
        "dot_port":         st.get("dot_port", AGH_DOT_PORT),
        "dot_listening":    _port_listening(st.get("dot_port", AGH_DOT_PORT), "tcp",
                                             proc="AdGuardHome"),
        "doq_port":         st.get("doq_port", AGH_DOQ_PORT),
        "doq_listening":    _port_listening(st.get("doq_port", AGH_DOQ_PORT), "udp",
                                             proc="AdGuardHome"),
        "dns_port":         AGH_DNS_PORT,
        "dns_udp":          _port_listening(AGH_DNS_PORT, "udp",
                                             proc="AdGuardHome"),
        "dns_tcp":          _port_listening(AGH_DNS_PORT, "tcp",
                                             proc="AdGuardHome"),
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
        # готовые ссылки для вставки в клиент — прямо в статус-боксе.
        # _box_row сам переносит длинные URL внутри рамки (жёсткая резка
        # по видимой ширине), правая граница ║ не ломается.
        links = _client_dns_links(s)
        if links:
            _box_sep()
            _box_row(f"  {CYAN}Готовые ссылки для клиентов (настройки DNS):{NC}")
            for label, url in links:
                _box_row(f"  {label}:  {url}")
            if s.get("self_signed"):
                _box_row(f"  {DIM}⚠ self-signed: клиент должен разрешить "
                         f"недоверенный сертификат{NC}")
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
        try:
            from chimera.modules.dnscrypt_update import (
                get_version_status_line, get_pool_status_line)
            _box_row(f"  {DIM}dnscrypt: {get_version_status_line()}{NC}")
            _box_row(f"  {DIM}пул: {get_pool_status_line()}{NC}")
        except Exception:
            pass
        _box_row()
        _box_item("1", f"📦 Установить / переустановить{DIM}(wizard + финализация){NC}")
        _box_item("2", f"📊 Статус + завершить настройку{DIM}(если мастер не завершён){NC}")
        _box_item("3", f"🔑 Сброс пароля админа{DIM}(мастер заново){NC}")
        _box_item("4", f"🔒 Сменить режим Web UI / TLS{DIM}(домен, self-signed, публичность){NC}")
        _box_item("5", f"🔄 Переприменить конфиг{DIM}(фильтры/DoH/DoT/DoQ по канону){NC}")
        _box_item("6", f"⬆️  Обновление/синк dnscrypt{DIM}(версия/пул/цепочка — общее меню){NC}")
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
                web_port = _ask_web_port() # кастомный порт
                st2 = aghome_state_load()
                aghome_state_save({**st2, "web_mode": web_mode, "domain": domain,
                                   "web_port": web_port,
                                   "self_signed": web_mode == AGH_WEB_HTTPS_SELF,
                                   "tls_enabled": web_mode in (AGH_WEB_HTTPS_LE, AGH_WEB_HTTPS_SELF)})
                core.info("AGH: режим сохранён — применяю конфиг...")
                if AGH_CONF.exists() and not aghome_wizard_pending():
                    finalize_aghome_config(web_mode=web_mode, domain=domain,
                                           web_port=web_port)
                else:
                    core.info("AGH: применится автоматически после завершения мастера")
            except Exception as e:
                core.warn(f"AGH: ошибка смены режима: {e}")
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "6":
            # единое меню dnscrypt (state-файл синхронизирует все меню)
            try:
                from chimera.modules.dnscrypt_update import do_dnscrypt_update_menu
                do_dnscrypt_update_menu()
            except Exception as e:
                core.warn(f"dnscrypt_update недоступен: {e}")
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
