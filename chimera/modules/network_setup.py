"""
chimera/modules/network_setup.py
───────────────────────────────────────────────────────────────────────────────
Настройка файрволла (ufw/nftables) + оптимизация сетевого стека (sysctl,
limits, BBR, conntrack, THP) + применение sysctl из меню.

  • configure_firewall()         — ufw или nftables.
                                    Открывает 22/80/SERVER_PORT.
                                    Мутирует STAGE_UFW_DONE в _core (через setattr).
  • apply_network_optimizations() — пишет /etc/sysctl.d/99-vless-performance.conf
                                    + limits.conf + systemd override.
                                    Адаптивно под TOTAL_RAM/TOTAL_CPU.
                                    BBR+fq если ядро ≥ 4.9.
  • apply_sysctl_and_limits()    — применяется из меню (sysctl --system).

МИГРАЦИЯ (этап 1.8):
- iptables/ip6tables fallback path заменён на nftables напрямую через nft_common
- UFW primary path сохранён (UFW 0.36+ уже использует nftables backend по умолчанию)
- Если UFW не установлен — fallback на прямой nft (раньше на iptables)
- /etc/iptables/rules.v4 + rules.v6 + rc.local fallback → /etc/nftables.conf +
  встроенный nftables.service (Debian/Ubuntu package)

Никаких других state.json мутаций. Все константы (OPTIMIZER_CONF, LIMITS_CONF,
SYSTEMD_CONF, UFW_MARK_FILE) читаются из _core.

Точки входа из _core.py:
    from chimera.modules.network_setup import (
        configure_firewall, apply_network_optimizations, apply_sysctl_and_limits,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path
from typing import Optional

# nftables — централизованная обёртка над `nft` CLI (этап 1.8 миграции)
from .nft_common import (
    nft_open_port, nft_rule_insert, nft_rule_add, nft_rule_exists,
    nft_persist, nft_persist_enable_systemd, _nft_available,
)
from .nft_constants import (
    NFT_TABLE_NAME, NFT_TABLE_FAMILY, NFT_CHAIN_INPUT,
    NFT_PERSIST_FILE, COMMENT_OPEN_PORT_PREFIX,
)


# ── Ленивый доступ к ядру ────────────────────────────────────────────────────
def _core_module():
    """Возвращает модуль chimera._core (импорт лениво)."""
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  ФАЙРВОЛЛ (ufw / iptables)
# ============================================================================
def configure_firewall() -> None:
    """Настраивает ufw или iptables. Открывает 22, 80, SERVER_PORT."""
    core = _core_module()
    info    = core.info
    warn    = core.warn
    success = core.success
    _run    = core._run
    PROGRESS = core.PROGRESS
    command_exists = core.command_exists
    _pkg_install   = core._pkg_install
    SERVER_PORT    = core.SERVER_PORT
    PROTOCOL_MODE  = getattr(core, "PROTOCOL_MODE", "reality")
    PKG_MGR        = getattr(core, "PKG_MGR", "apt")
    UFW_MARK_FILE  = core.UFW_MARK_FILE

    setattr(core, "STAGE_UFW_DONE", False)  # сбрасываем перед настройкой
    info("Настройка файрволла...")
    PROGRESS.update(2, "Файрволл")

    # Проверяем INPUT policy DROP (через nft list chain inet chimera input)
    # ЭТАП 1.8: мигрировано с `iptables -L INPUT -n` → `nft list chain inet chimera input`
    try:
        if _nft_available():
            _r = subprocess.run(["nft", "list", "chain", "inet", "chimera", "input"],
                                capture_output=True, text=True, check=False)
            # Если в выводе есть "policy drop" для base chain
            if _r.returncode == 0 and "policy drop" in (_r.stdout or ""):
                warn("Обнаружен файрвол с политикой INPUT DROP.")
                warn("Скрипт откроет нужные порты автоматически.")
                warn("Если после установки порты недоступны — откройте их вручную")
                warn("в панели управления вашего провайдера.")
    except Exception:
        pass

    fw_tool = ""
    if command_exists("ufw"):
        fw_tool = "ufw"
    elif _nft_available():
        fw_tool = "nft"

    if fw_tool == "ufw":
        UFW_MARK_FILE.parent.mkdir(parents=True, exist_ok=True)

        def _ufw_allow_if_missing(port: int, proto: str, comment: str) -> None:
            r = _run(["ufw", "status"], capture=True, check=False)
            if re.search(rf'^{port}/{proto}.*ALLOW', r.stdout, re.MULTILINE):
                return
            #  миграция на port_registry (с backward compat fallback).
            # SSH (22) и HTTP (80) — критичные порты, регистрируем под SERVICE_VLESS
            # с указанием в comment. VLESS port — основной.
            try:
                from chimera.modules.port_registry import (
                    ufw_open_port, port_register, SERVICE_VLESS,
                )
                port_register(SERVICE_VLESS, port, proto,
                              comment=comment, force=True)
                ok, msg = ufw_open_port(port, proto, SERVICE_VLESS,
                                        comment=comment)
                if ok:
                    try:
                        with UFW_MARK_FILE.open('a') as f:
                            f.write(f"allow {port}/{proto}\n")
                    except Exception:
                        pass
                    info(f"UFW: открыт {port}/{proto} ({comment})")
                    return
                # ufw_open_port вернул False (например, чужое правило) —
                # fallback на прямой ufw allow ниже.
            except Exception:
                pass
            _run(["ufw", "allow", f"{port}/{proto}", "comment", comment],
                 check=False, quiet=True)
            try:
                with UFW_MARK_FILE.open('a') as f:
                    f.write(f"allow {port}/{proto}\n")
            except Exception:
                pass
            info(f"UFW: открыт {port}/{proto} ({comment})")

        _ufw_allow_if_missing(22, "tcp", "SSH")

        r = _run(["ufw", "status"], capture=True, check=False)
        if "Status: active" not in r.stdout:
            # Гарантируем наличие /var/log/ufw.log до включения логирования ufw
            ufw_log = Path("/var/log/ufw.log")
            if not ufw_log.exists():
                ufw_log.touch(exist_ok=True)
                _run(["chown", "syslog:adm", str(ufw_log)], check=False, quiet=True)
                ufw_log.chmod(0o640)

            _run(["ufw", "default", "deny",  "incoming"], check=False, quiet=True)
            _run(["ufw", "default", "allow", "outgoing"], check=False, quiet=True)
            _run(["ufw", "--force", "enable"], check=False, quiet=True)
            success("UFW включён")

        _ufw_allow_if_missing(80,          "tcp", "HTTP (certbot ACME)")
        _ufw_allow_if_missing(SERVER_PORT, "tcp", f"VLESS {PROTOCOL_MODE.upper()} :{SERVER_PORT}")

        ufw_def = Path("/etc/default/ufw")
        if ufw_def.exists():
            content = ufw_def.read_text()
            if "IPV6=no" in content:
                ufw_def.write_text(content.replace("IPV6=no", "IPV6=yes"))
                _run(["ufw", "--force", "reload"], check=False, quiet=True)
                info("UFW IPv6 включён")

        setattr(core, "STAGE_UFW_DONE", True)
        success(f"UFW настроен (22, 80, {SERVER_PORT} — IPv4+IPv6)")

    elif fw_tool == "nft":
        # ЭТАП 1.8: fallback path через nftables (замена iptables/ip6tables).
        # Семантика идентична: открываем 22/80/SERVER_PORT + lo + ESTABLISHED + ICMPv6.
        # В nft всё в одной таблице inet chimera — покрывает и v4, и v6 одновременно.

        # 1. Lo interface ACCEPT (insert position=1, перед другими правилами)
        nft_rule_insert(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec='iifname "lo" accept',
            family=NFT_TABLE_FAMILY,
            comment=f"{COMMENT_OPEN_PORT_PREFIX}lo",
            idempotent=True,
        )

        # 2. ESTABLISHED,RELATED ACCEPT (insert position=2)
        # В nft: 'ct state established,related accept'
        nft_rule_insert(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec="ct state established,related accept",
            family=NFT_TABLE_FAMILY,
            comment=f"{COMMENT_OPEN_PORT_PREFIX}established",
            idempotent=True,
        )

        # 3. ICMPv6 для IPv6邻居 discovery (critical для IPv6 connectivity)
        # В nft: 'ip6 nexthdr ipv6-icmp accept' (или 'meta l4proto ipv6-icmp accept')
        nft_rule_add(
            table=NFT_TABLE_NAME, chain=NFT_CHAIN_INPUT,
            rule_spec="ip6 nexthdr icmpv6 accept",
            family=NFT_TABLE_FAMILY,
            comment=f"{COMMENT_OPEN_PORT_PREFIX}icmpv6",
            idempotent=True,
        )

        # 4. Открываем 22/80/SERVER_PORT с conntrack --ctstate NEW
        # В nft: 'tcp dport <port> ct state new accept'
        for port in (22, 80, SERVER_PORT):
            nft_open_port(
                port=port, proto="tcp",
                comment=f"{COMMENT_OPEN_PORT_PREFIX}tcp-{port}",
            )

        # 5. Persist — единый /etc/nftables.conf + встроенный nftables.service
        nft_persist(NFT_PERSIST_FILE)
        nft_persist_enable_systemd()
        success("nftables настроен (22, 80, SERVER_PORT — IPv4+IPv6 в одной таблице inet chimera)")
    else:
        warn("Файрволл не найден — пропускаем")

    PROGRESS.update(3, "Файрволл")


# ============================================================================
#  ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА
# ============================================================================
def apply_network_optimizations() -> None:
    """Пишет sysctl/limits/systemd конфиги, активирует BBR+fq, conntrack, THP."""
    core = _core_module()
    info    = core.info
    success = core.success
    _run    = core._run
    PROGRESS = core.PROGRESS
    get_adaptive_value = core.get_adaptive_value
    command_exists     = core.command_exists
    TOTAL_RAM   = core.TOTAL_RAM
    TOTAL_CPU   = core.TOTAL_CPU
    INSTALL_MODE = getattr(core, "INSTALL_MODE", "A")
    OPTIMIZER_CONF = core.OPTIMIZER_CONF
    LIMITS_CONF    = core.LIMITS_CONF
    SYSTEMD_CONF   = core.SYSTEMD_CONF

    info(f"Оптимизация сетевого стека (RAM: {TOTAL_RAM}MB)...")
    PROGRESS.update(2, "Оптимизация")

    overcommit = get_adaptive_value("overcommit") or "1"
    swappiness  = get_adaptive_value("swappiness") or "10"
    conntrack   = get_adaptive_value("conntrack")  or "1048576"
    file_max    = get_adaptive_value("file_max")   or "2097152"

    # BBR detection
    try:
        kernel_ver = _run(["uname", "-r"], capture=True, check=False).stdout.strip()
        parts = kernel_ver.split(".")
        k_major = int(re.match(r'^(\d+)', parts[0]).group(1)) if parts else 4
        k_minor = int(re.match(r'^(\d+)', parts[1]).group(1)) if len(parts) > 1 else 0
    except Exception:
        k_major, k_minor = 4, 0

    bbr_available = False
    if k_major > 4 or (k_major == 4 and k_minor >= 9):
        _run(["modprobe", "tcp_bbr"], check=False, quiet=True)
        r = _run(["sysctl", "net.ipv4.tcp_available_congestion_control"],
                 capture=True, check=False)
        if "bbr" in r.stdout:
            bbr_available = True

    congestion_lines = (
        "net.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n"
        if bbr_available else
        "net.ipv4.tcp_congestion_control = cubic\n"
    )

    sysctl_content = textwrap.dedent(f"""\
        # =============================================================
        #  Сетевые оптимизации для VLESS REALITY
        #  Адаптировано под: {TOTAL_RAM}MB RAM, {TOTAL_CPU} CPU
        # =============================================================
        {congestion_lines}net.ipv4.tcp_fastopen = 3
        net.core.rmem_max = 134217728
        net.core.wmem_max = 134217728
        net.core.rmem_default = 1048576
        net.core.wmem_default = 1048576
        net.ipv4.tcp_rmem = 4096 1048576 134217728
        net.ipv4.tcp_wmem = 4096 1048576 134217728
        net.ipv4.tcp_mem = 786432 1048576 26777216
        net.core.optmem_max = 65536
        net.ipv4.tcp_moderate_rcvbuf = 1
        net.core.netdev_budget = 600
        net.core.somaxconn = 65535
        net.ipv4.tcp_max_syn_backlog = 65535
        net.core.netdev_max_backlog = 250000
        net.netfilter.nf_conntrack_max = {conntrack}
        net.ipv4.ip_local_port_range = 1024 65535
        net.ipv4.tcp_tw_reuse = 1
        net.ipv4.tcp_max_tw_buckets = 2000000
        net.ipv4.tcp_slow_start_after_idle = 0
        net.ipv4.tcp_sack = 1
        net.ipv4.tcp_ecn = 1
        net.ipv4.tcp_mtu_probing = 1
        net.ipv4.tcp_keepalive_time = 600
        net.ipv4.tcp_keepalive_intvl = 60
        net.ipv4.tcp_keepalive_probes = 6
        net.ipv4.tcp_fin_timeout = 30
        # BUGFIX: Режим B (каскадный прокси) требует ip_forward=1 для маршрутизации.
        # Значение подставляется динамически в зависимости от режима установки.
        net.ipv4.ip_forward = {1 if INSTALL_MODE == "B" else 0}
        net.ipv6.conf.all.disable_ipv6 = 0
        net.ipv6.conf.default.disable_ipv6 = 0
        net.ipv6.conf.lo.disable_ipv6 = 0
        net.ipv6.conf.all.accept_ra = 2
        net.ipv6.conf.default.accept_ra = 2
        # BUGFIX: должен совпадать с ip_forward — иначе диагностика (--check) сообщает ошибку
        net.ipv6.conf.all.forwarding = {1 if INSTALL_MODE == "B" else 0}
        net.ipv6.conf.all.use_tempaddr = 2
        net.ipv6.conf.default.use_tempaddr = 2
        net.ipv6.conf.all.temp_prefered_lft = 86400
        net.ipv6.conf.all.temp_valid_lft = 604800
        net.ipv6.conf.all.hop_limit = 128
        net.ipv6.neigh.default.gc_thresh1 = 512
        net.ipv6.neigh.default.gc_thresh2 = 2048
        net.ipv6.neigh.default.gc_thresh3 = 4096
        net.ipv6.flowlabel_consistency = 1
        net.ipv6.flowlabel_state_ranges = 1
        net.ipv6.conf.all.accept_redirects = 0
        net.ipv6.conf.default.accept_redirects = 0
        net.ipv6.conf.all.drop_unsolicited_na = 1
        net.ipv6.conf.default.drop_unsolicited_na = 1
        net.ipv6.conf.all.accept_dad = 1
        net.ipv6.conf.default.accept_dad = 1
        net.ipv6.conf.all.accept_source_route = 0
        net.ipv6.conf.default.accept_source_route = 0
        net.ipv4.udp_mem = 786432 1048576 26214400
        net.ipv4.udp_rmem_min = 16384
        net.ipv4.udp_wmem_min = 16384
        net.ipv4.tcp_syncookies = 1
        net.ipv4.tcp_window_scaling = 1
        net.ipv4.tcp_timestamps = 1
        net.ipv4.tcp_syn_retries = 3
        net.ipv4.tcp_synack_retries = 3
        fs.file-max = {file_max}
        fs.nr_open = 2097152
        vm.overcommit_memory = {overcommit}
        vm.swappiness = {swappiness}
        vm.dirty_ratio = 15
        vm.dirty_background_ratio = 5
        kernel.numa_balancing = 1
        kernel.sched_min_granularity_ns = 10000000
        kernel.sched_wakeup_granularity_ns = 15000000
        kernel.panic = 10
        kernel.panic_on_oops = 1
    """)

    OPTIMIZER_CONF.parent.mkdir(parents=True, exist_ok=True)
    OPTIMIZER_CONF.write_text(sysctl_content)
    _run(["sysctl", "-p", str(OPTIMIZER_CONF)], check=False, quiet=True)

    LIMITS_CONF.parent.mkdir(parents=True, exist_ok=True)
    LIMITS_CONF.write_text(textwrap.dedent("""\
        * soft nofile 1048576
        * hard nofile 1048576
        * soft nproc  unlimited
        * hard nproc  unlimited
        root soft nofile 1048576
        root hard nofile 1048576
        root soft nproc  unlimited
        root hard nproc  unlimited
    """))

    SYSTEMD_CONF.parent.mkdir(parents=True, exist_ok=True)
    SYSTEMD_CONF.write_text(textwrap.dedent("""\
        [Manager]
        DefaultLimitNOFILE=1048576
        DefaultLimitNPROC=infinity
    """))
    _run(["systemctl", "daemon-reexec"], check=False, quiet=True)

    thp = Path("/sys/kernel/mm/transparent_hugepage/enabled")
    if thp.exists():
        try:
            thp.write_text("madvise")
        except Exception:
            pass

    if command_exists("irqbalance"):
        _run(["systemctl", "enable", "--now", "irqbalance"], check=False, quiet=True)
        success("irqbalance запущен")

    if bbr_available:
        r = _run(["ip", "-o", "link", "show"], capture=True, check=False)
        ifaces = [
            m.group(1) for line in r.stdout.splitlines()
            if (m := re.match(r'\d+:\s+(\S+):', line)) and m.group(1) != "lo"
        ]
        for iface in ifaces:
            _run(["tc", "qdisc", "replace", "dev", iface, "root", "fq"],
                 check=False, quiet=True)
        try:
            with open("/etc/modules-load.d/bbr.conf", "a") as f:
                f.write("tcp_bbr\n")
        except Exception:
            pass
        success("BBR активирован + fq планировщик")
    else:
        info(f"BBR недоступен на ядре {k_major}.{k_minor}, используется cubic")

    _run(["modprobe", "nf_conntrack"], check=False, quiet=True)
    hashsize = Path("/sys/module/nf_conntrack/parameters/hashsize")
    if hashsize.exists():
        try:
            hashsize.write_text("131072")
        except Exception:
            pass

    PROGRESS.update(3, "Оптимизация")
    success(f"Сетевой стек оптимизирован (адаптивно под {TOTAL_RAM}MB RAM)")


# ============================================================================
#  ПРИМЕНЕНИЕ SYSCTL ИЗ МЕНЮ
# ============================================================================
def apply_sysctl_and_limits() -> None:
    """Применяет настройки sysctl и limits.conf для оптимизации производительности.
    Вызывается из меню (применение уже созданных файлов)."""
    core = _core_module()
    success = core.success
    warn    = core.warn
    _run    = core._run
    OPTIMIZER_CONF = core.OPTIMIZER_CONF
    LIMITS_CONF    = core.LIMITS_CONF

    sysctl_conf = OPTIMIZER_CONF
    limits_conf = LIMITS_CONF
    applied = False
    if sysctl_conf.exists():
        r = _run(["sysctl", "--system"], check=False, quiet=False)
        if r.returncode == 0:
            success(f"sysctl применён из {sysctl_conf}")
            applied = True
        else:
            warn("Ошибка применения sysctl")
    else:
        warn(f"Файл {sysctl_conf} не найден — запустите установку (п.1)")
    if limits_conf.exists():
        success(f"limits.conf готов: {limits_conf}")
        applied = True
    if not applied:
        warn("Файлы оптимизации не найдены. Сначала выполните установку (п.1).")
