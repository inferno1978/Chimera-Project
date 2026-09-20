"""
chimera/modules/dnscrypt_setup.py
───────────────────────────────────────────────────────────────────────────────
Установка и настройка DNSCrypt-proxy — зашифрованный DNS-резолвер.

  • _get_dnscrypt_port()      — надёжное определение порта из конфига.
  • install_dnscrypt()        — скачивает бинарник, пишет конфиг + systemd-юнит,
                                 запускает. Мутирует глобали DNSCRYPT_INSTALLED
                                 в _core (через setattr).
  • apply_dnscrypt_tuning()   — применяет оптимизированный конфиг (кеш/TTL/lb).

Константы DNSCRYPT_BIN/CONF_DIR/CONF/SERVICE/LISTEN_ADDR/LISTEN_PORT/INSTALLED
остаются в _core.py как каноническое хранилище (много других групп их читают).

Точки входа из _core.py:
    from chimera.modules.dnscrypt_setup import (
        _get_dnscrypt_port, install_dnscrypt, apply_dnscrypt_tuning,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  ОПРЕДЕЛЕНИЕ ПОРТА
# ============================================================================
def _get_dnscrypt_port() -> int:
    """Надёжное определение реального порта DNSCrypt-proxy"""
    core = _core_module()
    DNSCRYPT_CONF        = core.DNSCRYPT_CONF
    DNSCRYPT_LISTEN_PORT = core.DNSCRYPT_LISTEN_PORT

    if not DNSCRYPT_CONF.exists():
        return DNSCRYPT_LISTEN_PORT
    try:
        content = DNSCRYPT_CONF.read_text()
        m = re.search(r'listen_addresses\s*=\s*\[\s*[\'"][^:]+:(\d+)', content, re.IGNORECASE)
        if m:
            port = int(m.group(1))
            if 1024 <= port <= 65535:
                return port
    except Exception:
        pass
    return DNSCRYPT_LISTEN_PORT


# ============================================================================
# LISTEN-ADDRESSES (IPv6-aware)
# ============================================================================
def _toml_listen_addresses(addr: str, port: int, ipv6: bool) -> str:
    """Строка listen_addresses для dnscrypt-proxy.toml.

    IPv4-loopback всегда первый (DNSCRYPT_LISTEN_ADDR — канон из _core,
    его же ждут регэкспы остальных модулей: _get_dnscrypt_port,
    resolv_conf_fix, dns_redirect). При ipv6 добавляется [::1] вторым
    элементом — dns_redirect.get_dnscrypt_listen_ipv6() видит ::1 и
    включает ip6tables-редирект 53→port в redirect-режиме.
    """
    if ipv6:
        return f"['{addr}:{port}', '[::1]:{port}']"
    return f"['{addr}:{port}']"


# ============================================================================
#  УСТАНОВКА
# ============================================================================
def install_dnscrypt() -> None:
    """Установка DNSCrypt-proxy. Мутирует DNSCRYPT_INSTALLED / DNSCRYPT_LISTEN_PORT в _core."""
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    dim     = core.dim
    _run    = core._run
    PROGRESS = core.PROGRESS
    PARAM_USE_DNSCRYPT   = getattr(core, "PARAM_USE_DNSCRYPT", False)
    IS_IPV6_AVAILABLE    = getattr(core, "IS_IPV6_AVAILABLE", False)
    DNSCRYPT_BIN         = core.DNSCRYPT_BIN
    DNSCRYPT_CONF_DIR    = core.DNSCRYPT_CONF_DIR
    DNSCRYPT_CONF        = core.DNSCRYPT_CONF
    DNSCRYPT_SERVICE     = core.DNSCRYPT_SERVICE
    DNSCRYPT_LISTEN_ADDR = core.DNSCRYPT_LISTEN_ADDR
    DNSCRYPT_LISTEN_PORT = core.DNSCRYPT_LISTEN_PORT

    if not PARAM_USE_DNSCRYPT:
        info("DNSCrypt-proxy: пропускаем по выбору пользователя")
        setattr(core, "DNSCRYPT_INSTALLED", False)
        return

    info("Установка DNSCrypt-proxy...")
    PROGRESS.update(2, "DNSCrypt")

    arch = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    arch_map = {
        "x86_64": "linux_x86_64", "aarch64": "linux_arm64",
        "armv7l": "linux_arm",    "i386": "linux_386", "i686": "linux_386",
    }
    dc_arch = arch_map.get(arch)
    if not dc_arch:
        warn(f"Неподдерживаемая архитектура для DNSCrypt: {arch} — пропускаем")
        return

    r_active = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                    capture=True, check=False)
    if r_active.stdout.strip() == "active" and DNSCRYPT_BIN.exists():
        info("DNSCrypt-proxy уже установлен и запущен — пропускаем")
        setattr(core, "DNSCRYPT_INSTALLED", True)
        PROGRESS.update(3, "DNSCrypt")
        return

    dc_tag = ""
    for attempt in range(1, 4):
        try:
            r = _run(["curl", "-fsSL", "--connect-timeout", "10",
                      "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"],
                     capture=True, check=False)
            data = json.loads(r.stdout)
            dc_tag = data.get("tag_name", "")
            if dc_tag:
                break
        except Exception:
            pass
        warn(f"Попытка {attempt}: не удалось получить тег DNSCrypt, повтор...")
        time.sleep(3)

    if not dc_tag:
        warn("Не удалось получить версию DNSCrypt-proxy — пропускаем")
        warn("Xray будет использовать публичные DNS (1.1.1.1 / 8.8.8.8)")
        return

    info(f"DNSCrypt-proxy: {dc_tag} ({dc_arch})")

    # МИГРАЦИЯ: раньше использовался subprocess curl с ОДНИМ прямым URL
    # (https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/{tag}/
    # dnscrypt-proxy-{arch}-{tag}.tar.gz) БЕЗ зеркал, БЕЗ fallback, БЕЗ
    # проверки ручного размещения. Только curl с --retry 3 (повтор того
    # же URL).
    #
    # Теперь используется fetch_package(DNSCRYPT_SPEC, tag=..., arch=...)
    # из download_manager.py. fetch_package сам:
    #   1. Проверяет /root/dnscrypt-proxy-{arch}-{tag}.tar.gz
    #      (manual_incoming_dir из spec) — если найден, использует без сети.
    #   2. Иначе — перебирает 10 зеркал по очереди через urllib.
    #   3. При успехе — post_install распаковывает tar.gz, находит
    #      dnscrypt-proxy бинарник через rglob, копирует в
    #      /usr/local/bin/dnscrypt-proxy (chmod 0o755).
    #   4. При провале — print_manual_hint() с инструкцией.
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.dnscrypt_packages import DNSCRYPT_SPEC

    ok = fetch_package(DNSCRYPT_SPEC, tag=dc_tag, arch=dc_arch)
    if not ok:
        warn("Не удалось скачать DNSCrypt-proxy — пропускаем")
        warn("Xray будет использовать публичные DNS (1.1.1.1 / 8.8.8.8)")
        return

    success(f"Бинарник DNSCrypt-proxy установлен: {DNSCRYPT_BIN}")
    DNSCRYPT_CONF_DIR.mkdir(parents=True, exist_ok=True)

    # гео-резистентный набор резолверов. Режим B подразумевает Entry-ноду
    # В РФ — а оттуда cloudflare (1.1.1.1) душится, google DoH (dns.google)
    # заблокирован. DNSCrypt-протокол Quad9 (порт 8443, БЕЗ SNI) переживает
    # DPI-фильтрацию и не фильтруется РКН → lb_estimator сам выбирает живой
    # сервер: за рубежом выигрывают cloudflare/google, из РФ — quad9.
    # Имена сверены со свежим v3/public-resolvers.md (DNSCrypt/dnscrypt-resolvers).
    _dnscrypt_server_names = (
        'server_names = ["cloudflare", "cloudflare-ipv6", "google", "google-ipv6", '
        '"quad9-dnscrypt-ip4-nofilter-pri", "quad9-dnscrypt-ip6-nofilter-pri"]'
        if IS_IPV6_AVAILABLE else
        'server_names = ["cloudflare", "google", "quad9-dnscrypt-ip4-nofilter-pri"]'
    )
    DNSCRYPT_CONF.write_text(textwrap.dedent(f"""\
        ## dnscrypt-proxy.toml — сгенерирован Chimera Project v4.12.10
        ## Слушает на {DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}
        ## при IPv6 на сервере дополнительно слушаем [::1] — DNS-путь
        ## IPv6-готов (redirect 53→{DNSCRYPT_LISTEN_PORT} в dns_redirect включается автоматически).

        listen_addresses = {_toml_listen_addresses(DNSCRYPT_LISTEN_ADDR, DNSCRYPT_LISTEN_PORT, IS_IPV6_AVAILABLE)}

        max_clients = 250

        ipv4_servers = true
        ipv6_servers = {'true' if IS_IPV6_AVAILABLE else 'false'}
        dnscrypt_servers = true
        doh_servers = true
        odoh_servers = false

        require_dnssec = false
        require_nolog = true
        require_nofilter = false

        force_tcp = false
        ## Фиксируем быстрые резолверы. Для смены: Сеть → DNSCrypt → Выбор резолверов.
        {_dnscrypt_server_names}
        lb_strategy = 'p2'
        lb_estimator = true
        timeout = 5000
        keepalive = 30

        log_level = 1
        use_syslog = true

        cert_refresh_delay = 240

        ## bootstrap/fallback обязаны быть достижимы И с зарубежных, И с
        ## РФ-хостингов. 8.8.8.8:53 заблокирован в РФ (РКН, 2024), 1.1.1.1:53
        ## душится TSPU. Quad9 + Яндекс-резолвер работают отовсюду (используются
        ## ТОЛЬКО для резолва имён DoH-серверов, не для клиентских запросов).
        bootstrap_resolvers = ['9.9.9.9:53', '77.88.8.8:53']
        ignore_system_dns = true

        fallback_resolvers = ['9.9.9.9:53', '77.88.8.8:53']

        netprobe_timeout = 5
        netprobe_address = '9.9.9.9:53'

        offline_mode = false
        reject_ttl = 10

        cache = true
        cache_size = 32768
        cache_min_ttl = 300
        cache_max_ttl = 86400
        cache_neg_min_ttl = 60
        cache_neg_max_ttl = 600

        [blocked_names]
          blocked_names_file = '/etc/dnscrypt-proxy/blocked-names.txt'
          log_file = '/var/log/dnscrypt-proxy-blocked.log'
          log_format = 'tsv'

        [blocked_ips]
          blocked_ips_file = '/etc/dnscrypt-proxy/blocked-ips.txt'

        [sources]
          [sources.public-resolvers]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
              'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''

          [sources.relays]
            urls = [
              'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
              'https://download.dnscrypt.info/resolvers-list/v3/relays.md'
            ]
            cache_file = '/etc/dnscrypt-proxy/relays.md'
            minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
            refresh_delay = 72
            prefix = ''
    """))

    for f in ("blocked-names.txt", "blocked-ips.txt"):
        fp = DNSCRYPT_CONF_DIR / f
        fp.touch()
        fp.chmod(0o644)
    DNSCRYPT_CONF.chmod(0o644)

    # ИСПРАВЛЕНИЕ: создаём отдельного пользователя dnscrypt.
    # При AWG iptables mangle маркирует трафик по --uid-owner.
    # Если dnscrypt-proxy работает от root (uid=0), его исходящие соединения
    # к DNS upstream-серверам (203.0.113.105:443 и т.п.) НЕ получают AWG fwmark
    # и уходят через дефолтный маршрут провайдера, где DoT/DNSCrypt блокируется.
    # Запуск от отдельного uid позволяет добавить его в AWG mark-правила.
    _run(["useradd", "-r", "-s", "/usr/sbin/nologin", "-d", "/var/lib/dnscrypt-proxy",
          "-m", "dnscrypt"], check=False, quiet=True)
    _run(["chown", "-R", "dnscrypt:dnscrypt", str(DNSCRYPT_CONF_DIR)],
         check=False, quiet=True)

    DNSCRYPT_SERVICE.write_text(textwrap.dedent("""\
        [Unit]
        Description=DNSCrypt-proxy — зашифрованный DNS-резолвер
        Documentation=https://github.com/DNSCrypt/dnscrypt-proxy
        After=network.target network-online.target
        Wants=network-online.target
        Before=xray.service nginx.service

        [Service]
        Type=simple
        NonBlocking=true
        ExecStart=/usr/local/bin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
        Restart=on-failure
        RestartSec=5s
        TimeoutStartSec=60s
        TimeoutStopSec=10s
        User=dnscrypt
        Group=dnscrypt
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        NoNewPrivileges=yes

        [Install]
        WantedBy=multi-user.target
    """))

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "dnscrypt-proxy"], check=False, quiet=True)
    _run(["systemctl", "start",  "dnscrypt-proxy"], check=False, quiet=True)

    dc_ok = False
    for _ in range(30):
        time.sleep(1)
        r = _run(["systemctl", "is-active", "dnscrypt-proxy"],
                 capture=True, check=False)
        if r.stdout.strip() == "active":
            dc_ok = True
            break
        r2 = _run(["systemctl", "is-failed", "dnscrypt-proxy"],
                  capture=True, check=False)
        if r2.stdout.strip() == "failed":
            warn("DNSCrypt-proxy перешёл в состояние failed")
            break

    if dc_ok:
        port_ok = False
        for _ in range(3):
            r = _run(["ss", "-ulnp"], capture=True, check=False)
            if f":{DNSCRYPT_LISTEN_PORT} " in r.stdout:
                port_ok = True
                break
            time.sleep(1)
        if port_ok:
            setattr(core, "DNSCRYPT_INSTALLED", True)
            success(f"DNSCrypt-proxy {dc_tag} запущен на "
                    f"{DNSCRYPT_LISTEN_ADDR}:{DNSCRYPT_LISTEN_PORT}")
            # port_registry (v37): внутренний loopback-слушатель — force=True
            # (паттерн b4_dns 5453). Публично порт не открывается.
            try:
                from chimera.modules.port_registry import (
                    port_register, SERVICE_DNSCRYPT,
                )
                port_register(SERVICE_DNSCRYPT, DNSCRYPT_LISTEN_PORT, "udp",
                              comment="dnscrypt-proxy (loopback, upstream для AGH)",
                              force=True)
                port_register(SERVICE_DNSCRYPT, DNSCRYPT_LISTEN_PORT, "tcp",
                              comment="dnscrypt-proxy (loopback, upstream для AGH)",
                              force=True)
            except Exception:
                pass
        else:
            warn(f"DNSCrypt-proxy активен, но порт {DNSCRYPT_LISTEN_PORT} не слушает")
    else:
        warn("DNSCrypt-proxy не запустился — Xray будет использовать публичные DNS")
        warn("Проверьте вручную: journalctl -u dnscrypt-proxy -n 30")

    PROGRESS.update(3, "DNSCrypt")


# ============================================================================
#  ТЮНИНГ КОНФИГА
# ============================================================================
def apply_dnscrypt_tuning() -> None:
    """Применяет оптимизированный конфиг DNSCrypt-proxy (кеш/TTL/lb/timeout)."""
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    dim     = core.dim
    _run    = core._run
    DNSCRYPT_BIN  = core.DNSCRYPT_BIN
    DNSCRYPT_CONF = core.DNSCRYPT_CONF

    if not DNSCRYPT_BIN.exists():
        warn("DNSCrypt-proxy не установлен")
        return
    info("Применение оптимизированного конфига DNSCrypt-proxy...")

    if not DNSCRYPT_CONF.exists():
        warn(f"Конфиг не найден: {DNSCRYPT_CONF}")
        return

    bak = DNSCRYPT_CONF.parent / (
        DNSCRYPT_CONF.name + "." +
        datetime.now().strftime("%Y%m%d%H%M%S") + ".bak"
    )
    shutil.copy2(DNSCRYPT_CONF, bak)

    TOP_PARAMS: dict[str, str] = {
        "doh_servers":        "true",
        "force_tcp":          "false",
        "odoh_servers":       "false",
        "timeout":            "1500",
        "netprobe_timeout":   "5",
        "reject_ttl":         "10",
        # = канон (шаблон install_dnscrypt): 1.1.1.1/8.8.8.8 в РФ
        # отравлены (DNAT→НСДИ, NXDomain-spoof) — тюнинг [T] не должен
        # возвращать отраву в уже вычищенный конфиг.
        "fallback_resolvers": "['9.9.9.9:53', '77.88.8.8:53']",
        "cache":              "true",
        "cache_size":         "32768",
        "cache_min_ttl":      "300",
        "lb_strategy":        "'p2'",
        "lb_estimator":       "true",
        "use_syslog":         "true",
    }

    lines = DNSCRYPT_CONF.read_text().splitlines(keepends=True)

    # ── Границы зон ────────────────────────────────────────────────────────
    # top-zone  = строки ДО первого [section] (там живут глобальные ключи).
    # tail-zone = строки ПОСЛЕ последнего [section] (pool-sync/advanced
    #             генераторы заканчивают файл пустой секцией [local_doh]).
    # БАГ (кейс vds14808, 2026-09-20): недостающие TOP_PARAMS дописывались
    # В КОНЕЦ файла, т.е. ПОСЛЕ [local_doh] → ключи становились
    # local_doh.use_syslog → [FATAL] dnscrypt-proxy, повторный тюнинг
    # дописывал ещё раз → toml: Key 'local_doh.use_syslog' has already
    # been defined. Теперь: недостающие ключи вставляются в top-zone
    # (перед первой секцией), а застрявший в tail-zone мусор от старых
    # прогонов вычищается — повторный [T] чинит битый конфиг сам.
    section_idx: list[int] = [
        i for i, line in enumerate(lines)
        if re.match(r'^\[', line.strip())
    ]
    first_section_idx = section_idx[0] if section_idx else None
    last_section_idx = section_idx[-1] if section_idx else None

    _TUNING_MARKER = "## Добавлено apply_dnscrypt_tuning"

    result: list[str] = []
    applied_top: set[str] = set()

    for i, line in enumerate(lines):
        stripped = line.strip()
        in_top = first_section_idx is None or i < first_section_idx
        in_tail = last_section_idx is not None and i > last_section_idx

        if in_top:
            if re.match(r'^log_file\s*=', stripped):
                result.append("## log_file удалён apply_dnscrypt_tuning — используем journald\n")
                continue
            m = re.match(r'^(\w+)\s*=\s*.*$', stripped)
            if m and m.group(1) in TOP_PARAMS:
                key = m.group(1)
                indent = line[: len(line) - len(line.lstrip())]
                line = f"{indent}{key} = {TOP_PARAMS[key]}\n"
                applied_top.add(key)
        elif in_tail:
            # чистка мусора старого бага: TOP_PARAMS-ключи и маркер, попавшие
            # в хвостовую секцию (например local_doh.use_syslog)
            m = re.match(r'^(\w+)\s*=\s*.*$', stripped)
            if m and m.group(1) in TOP_PARAMS:
                continue
            if stripped.startswith(_TUNING_MARKER):
                continue
        result.append(line)

        # вставка недостающих ключей — строго в top-zone,
        # последней строкой ПЕРЕД первым заголовком секции
        if first_section_idx is not None and i + 1 == first_section_idx:
            missing_top = [k for k in TOP_PARAMS if k not in applied_top]
            if missing_top:
                result.append("\n" + _TUNING_MARKER + "\n")
                for k in missing_top:
                    result.append(f"{k} = {TOP_PARAMS[k]}\n")

    # вырожденные случаи без вставки в цикле:
    #   а) нет ни одной секции — весь файл top-level, дозапись в конец;
    #   б) файл начинается сразу секцией — top-zone пуста, ключи в начало.
    if first_section_idx is None:
        missing_top = [k for k in TOP_PARAMS if k not in applied_top]
        if missing_top:
            result.append("\n" + _TUNING_MARKER + "\n")
            for k in missing_top:
                result.append(f"{k} = {TOP_PARAMS[k]}\n")
    elif first_section_idx == 0:
        missing_top = [k for k in TOP_PARAMS if k not in applied_top]
        if missing_top:
            head = [_TUNING_MARKER + "\n"]
            for k in missing_top:
                head.append(f"{k} = {TOP_PARAMS[k]}\n")
            head.append("\n")
            result = head + list(result)

    DNSCRYPT_CONF.write_text("".join(result))
    success(f"Конфиг обновлён: {DNSCRYPT_CONF}")

    _run(["systemctl", "restart", "dnscrypt-proxy"], check=False, quiet=True)
    time.sleep(2)
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"], capture=True, check=False)
    if r.stdout.strip() == "active":
        success("DNSCrypt-proxy перезапущен с оптимизированным конфигом")
        info("Активные параметры:")
        content = DNSCRYPT_CONF.read_text()
        for key in ("doh_servers", "timeout", "cache_size", "cache_min_ttl", "server_names"):
            m = re.search(rf'^{key}\s*=\s*(.+)$', content, re.MULTILINE)
            val = m.group(1).strip() if m else "?"
            dim(f"  {key} = {val}")
    else:
        warn("DNSCrypt-proxy не запустился: journalctl -u dnscrypt-proxy -n 20")
