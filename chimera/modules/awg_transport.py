"""
chimera/modules/awg_transport.py
───────────────────────────────────────────────────────────────────────────────
AmneziaWG (AWG) 2.0 transport — Режим B (exit-нода через AWG-туннель).

Содержит 45 функций, вынесенных из chimera._core.py:
  • Установка amneziawg-tools локально и на exit-VPS (через SSH)
  • Генерация ключей и обфускационных параметров (Jc/Jmin/Jmax/S1/S2/H1-H4)
  • Формирование серверных/клиентских конфигов и systemd-юнитов
  • Policy routing (fwmark + ip rule + ip route + iptables mangle)
  • Watchdog (одиночный + мультинодовый) через cron
  • Меню управления (do_manage_awg_watchdog, do_manage_awg_nodes)
  • Аварийное восстановление, диагностика, ручное переключение нод

Точки входа из _core.py:
    from chimera.modules.awg_transport import (
        awg_check_tool, awg_generate_keys, awg_install_local,
        _awg_install_go_version_binary_only, _awg_install_go_version,
        _awg_detect_implementation, _awg_create_userspace_stubs,
        _awg_server_conf_text, _awg_client_conf_text, _awg_systemd_unit_text,
        ensure_amneziawg_ready, awg_setup_local_client, awg_apply_policy_routing,
        _awg_ensure_sshpass, awg_setup_remote_server,
        _awg_print_manual_guide, awg_rollback, awg_verify_tunnel,
        _awg_cleanup_stale_interfaces, awg_full_setup,
        awg_watchdog_install, awg_watchdog_remove, _awg_watchdog_set_flag,
        do_manage_awg_watchdog,
        _awg_node_subnets, _awg_persist_ssh_exclusion, _awg_node_from_globals,
        _awg_load_nodes_from_state, _awg_save_nodes_to_state,
        _awg_client_conf_for_node, _awg_server_conf_for_node,
        _awg_systemd_unit_for_node, awg_setup_all_nodes,
        _awg_bring_up_all_tunnels, _awg_apply_policy_routing_all_nodes,
        _awg_verify_all_tunnels, awg_multinode_watchdog_install,
        do_manage_awg_nodes, _awg_manual_switch, _awg_ping_all_nodes,
        _awg_show_failover_log, _awg_show_ssh_protection_status,
        _awg_diagnostic_all_nodes, _prompt_awg_additional_nodes,
        _awg_emergency_restore_all_nodes,
    )

Все AWG_* / _AWG_* глобали (параметры, ключи, состояние, Path-константы
_AWG_CONF_DIR, _AWG_MULTINODE_WATCHDOG_*, _AWG_WATCHDOG_*) ОСТАЮТСЯ в
_core.py — модуль читает их через `getattr(core, "...", <default>)` и
пишет через `setattr(core, "...", value)` (dual-form), что сохраняет
семантику `global X` деклараций оригинала.

Доступ к helpers ядра (info/warn/success/_run/log_to_file/_box_*/command_exists/
get_server_ip/_ensure_ssh_protection/_start_services_sequentially/STATE_FILE/
CONFIG_DIR/PARAM_USE_DNSCRYPT/_BOX_W/_wcslen/...) — через importlib
(см. _core_module()), как и в других извлечённых модулях
(asn_cache.py, warp.py, smart_balancer.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from datetime import datetime, timezone
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


def _awg_build_i_lines(i1: str, i2: str, i3: str, i4: str, i5: str) -> str:
    """Строит строки I1-I5 для .conf в зависимости от поддержки локальным
    awg-quick.

    v5.2: коммит 3e1fa70 ("всегда писать I1-I5") ломает старые сборки
    amneziawg-tools (AWG 1.5-эра), которые падают с
    'Line unrecognized: I2=' и сервис не стартует ВООБЩЕ. Решение —
    определять возможности локального awg-quick ПЕРЕД записью конфига
    (через awg-quick strip без поднятия интерфейса).

    Логика:
      - I1 пишется ВСЕГДА (поддерживается везде, включая старые сборки).
      - I2-I5: если awgs_supports_i2_i5() — пишем все 5 ключей (как в
        3e1fa70, для Keenetic native AWG 2.0). Если False — пишем только
        непустые (старое поведение до 3e1fa70, для старых amneziawg-tools).

    См. chimera/modules/awg_compat.py::awgs_supports_i2_i5().
    """
    # I1 — всегда безусловно
    lines = f"I1 = {i1}\n"
    try:
        from .awg_compat import awgs_supports_i2_i5, awgs_warn_old_tools_once
        if awgs_supports_i2_i5():
            # Современный awg-quick — пишем все 4 оставшихся ключа
            lines += f"I2 = {i2}\n"
            lines += f"I3 = {i3}\n"
            lines += f"I4 = {i4}\n"
            lines += f"I5 = {i5}\n"
        else:
            # Старый awg-quick — пишем только непустые
            awgs_warn_old_tools_once()
            for key, val in (("I2", i2), ("I3", i3), ("I4", i4), ("I5", i5)):
                if val:
                    lines += f"{key} = {val}\n"
    except Exception:
        # Fallback: пишем все 5 ключей (поведение 3e1fa70)
        lines += f"I2 = {i2}\n"
        lines += f"I3 = {i3}\n"
        lines += f"I4 = {i4}\n"
        lines += f"I5 = {i5}\n"
    return lines




def awg_check_tool(binary: str) -> bool:
    """Проверяет наличие бинарника AWG в PATH."""
    core = _core_module()
    return shutil.which(binary) is not None


def awg_generate_keys() -> bool:
    """
    Генерирует пары ключей сервера и клиента + pre-shared key.
    Заполняет глобальные AWG_*_PRIVKEY, AWG_*_PUBKEY, AWG_PRESHARED_KEY.
    Возвращает True при успехе.
    """
    core = _core_module()
    _run = core._run
    info = core.info
    log_to_file = core.log_to_file
    success = core.success
    warn = core.warn
    AWG_BIN = getattr(core, "AWG_BIN", "awg")
    AWG_CLIENT_PRIVKEY = getattr(core, "AWG_CLIENT_PRIVKEY", "")
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_SERVER_PRIVKEY = getattr(core, "AWG_SERVER_PRIVKEY", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")

    info("AWG: генерация ключей...")

    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)
    if not awg_bin:
        warn("AWG: бинарник awg/wg не найден — генерация ключей невозможна")
        return False

    def _genkey() -> tuple[str, str]:
        priv_r = _run([awg_bin, "genkey"], capture=True, check=False)
        if priv_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} genkey: {priv_r.stderr}")
        priv = priv_r.stdout.strip()
        pub_r = subprocess.run(
            [awg_bin, "pubkey"],
            input=priv, capture_output=True, text=True
        )
        if pub_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} pubkey: {pub_r.stderr}")
        return priv, pub_r.stdout.strip()

    try:
        AWG_SERVER_PRIVKEY, AWG_SERVER_PUBKEY = _genkey()
        setattr(core, "AWG_SERVER_PRIVKEY", AWG_SERVER_PRIVKEY)
        setattr(core, "AWG_SERVER_PUBKEY", AWG_SERVER_PUBKEY)
        AWG_CLIENT_PRIVKEY, AWG_CLIENT_PUBKEY = _genkey()
        setattr(core, "AWG_CLIENT_PRIVKEY", AWG_CLIENT_PRIVKEY)
        setattr(core, "AWG_CLIENT_PUBKEY", AWG_CLIENT_PUBKEY)
        psk_r = _run([awg_bin, "genpsk"], capture=True, check=False)
        if psk_r.returncode != 0:
            raise RuntimeError(f"{awg_bin} genpsk: {psk_r.stderr}")
        AWG_PRESHARED_KEY = psk_r.stdout.strip()
        setattr(core, "AWG_PRESHARED_KEY", AWG_PRESHARED_KEY)
        success(f"AWG: server pubkey = {AWG_SERVER_PUBKEY[:20]}...")
        success(f"AWG: client pubkey = {AWG_CLIENT_PUBKEY[:20]}...")
        return True
    except Exception as exc:
        warn(f"AWG: ошибка генерации ключей: {exc}")
        log_to_file("ERROR", f"awg_generate_keys: {exc}")
        return False


def awg_install_local() -> bool:
    """
    Устанавливает amneziawg-tools на локальный (RU) VPS.
    ПАТЧ: На Ubuntu 24.04 / ядро 6.x PPA недоступен с RU-серверов и DKMS не работает.
    Используем: 1) zip с GitHub releases, 2) сборка amneziawg-go из исходников.
    """
    core = _core_module()
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn
    AWG_BIN = getattr(core, "AWG_BIN", "awg")
    AWG_QUICK_BIN = getattr(core, "AWG_QUICK_BIN", "awg-quick")
    info("AWG: установка amneziawg-tools на RU-VPS...")

    if awg_check_tool(AWG_BIN) and awg_check_tool(AWG_QUICK_BIN):
        success("AWG: инструменты уже установлены")
        return True

    # Шаг 1: пробуем скачать готовые бинарники с GitHub releases
    # ПАТЧ: определяем архитектуру — ubuntu-22.04 совместимы с 24.04 для amd64;
    # для arm64 используем отдельный asset. Захардкоженный amd64 ломает ARM VPS.
    info("AWG: загрузка amneziawg-tools с GitHub releases...")
    _run(["apt-get", "install", "-y", "-q", "curl", "unzip"], check=False, quiet=True)
    _awg_arch_raw = _run(["uname", "-m"], capture=True, check=False).stdout.strip()
    if _awg_arch_raw == "x86_64":
        _awg_zip_suffix = "ubuntu-22.04-amneziawg-tools.zip"
    elif _awg_arch_raw == "aarch64":
        _awg_zip_suffix = "ubuntu-22.04-arm64-amneziawg-tools.zip"
    else:
        warn(f"AWG: неподдерживаемая архитектура {_awg_arch_raw} — переходим к сборке из исходников")
        _awg_zip_suffix = ""
    try:
        r_tag = _run(
            ["curl", "-fsSL", "--connect-timeout", "15",
             "https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest"],
            capture=True, check=False
        )
        import json as _json
        tag = _json.loads(r_tag.stdout).get("tag_name", "")
        if tag and _awg_zip_suffix:
            # МИГРАЦИЯ: раньше один прямой URL через curl, без зеркал.
            # Теперь fetch_package(AWG_TOOLS_SPEC, tag=..., arch=...) — 14
            # зеркал через urllib (jsDelivr + raw + release + 7 gh-proxy +
            # Statically), проверка /root/ для ручного размещения.
            from chimera.modules.download_manager import fetch_package
            from chimera.modules.awg_transport_packages import AWG_TOOLS_SPEC
            # arch нужен для mirror_urls_builder
            _awg_arch_for_spec = "arm64" if "arm64" in _awg_zip_suffix else "amd64"
            ok = fetch_package(
                AWG_TOOLS_SPEC, tag=tag, arch=_awg_arch_for_spec,
                print_hint_on_failure=False,
            )
            if ok:
                success(f"AWG: amneziawg-tools установлены из GitHub releases ({tag})")
    except Exception as exc:
        warn(f"AWG: не удалось загрузить из GitHub releases: {exc}")

    if awg_check_tool(AWG_BIN) and awg_check_tool(AWG_QUICK_BIN):
        # Бинарники есть — теперь нужен amneziawg-go для userspace режима
        return _awg_install_go_version_binary_only()

    # Шаг 2: полная сборка amneziawg-go (включает awg и awg-quick как stubs)
    warn("AWG: GitHub releases недоступны — собираем amneziawg-go из исходников...")
    return _awg_install_go_version()


def _awg_install_go_version_binary_only() -> bool:
    """Устанавливает только amneziawg-go (userspace бинарник) без stub-обёрток awg/awg-quick."""
    core = _core_module()
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn
    AWG_BIN = getattr(core, "AWG_BIN", "awg")
    info("AWG: сборка amneziawg-go (userspace модуль ядра)...")
    _run(["apt-get", "install", "-y", "-q", "git", "make", "golang-go"],
         check=False, quiet=True)
    if not shutil.which("go"):
        warn("AWG: Go не доступен — userspace режим недоступен")
        return awg_check_tool(AWG_BIN)  # бинарники уже есть, продолжаем

    awg_go_bin = Path("/usr/local/bin/amneziawg-go")
    if awg_go_bin.exists():
        success("AWG: amneziawg-go уже установлен")
        return True

    # МИГРАЦИЯ (Wave 6, Variant A): раньше `git clone --depth=1` без зеркал.
    # Теперь fetch_package(AWG_GO_SOURCE_SPEC) — HTTP tarball через
    # codeload.github.com (Variant A согласно анализу: Makefile tolerates
    # missing .git/, submodules отсутствуют). 9 зеркал (прямой GitHub +
    # codeload + 7 gh-proxy), проверка /root/ для ручного размещения.
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC

    ok = fetch_package(AWG_GO_SOURCE_SPEC, print_hint_on_failure=False)
    if ok:
        success("AWG: amneziawg-go установлен (userspace)")
        return True
    warn("AWG: не удалось скачать/собрать amneziawg-go")
    return awg_check_tool(AWG_BIN)


def _awg_install_go_version() -> bool:
    """Fallback: устанавливает userspace amneziawg-go через go build + stub-обёртки awg/awg-quick."""
    core = _core_module()
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn
    info("AWG: попытка установки userspace amneziawg-go...")
    _run(["apt-get", "install", "-y", "-q", "git", "make", "golang-go"],
         check=False, quiet=True)

    if not shutil.which("go"):
        warn("AWG: Go не доступен — невозможно собрать amneziawg-go")
        return False

    # Используем постоянную директорию вместо tempdir — make падает в /tmp с некоторыми настройками
    # МИГРАЦИЯ (Wave 6, Variant A): раньше `git clone --depth=1` без зеркал.
    # Теперь fetch_package(AWG_GO_SOURCE_SPEC) — HTTP tarball (Variant A).
    # post_install сам делает extract + make + copy в /usr/local/bin/.
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.awg_transport_packages import AWG_GO_SOURCE_SPEC

    try:
        ok = fetch_package(AWG_GO_SOURCE_SPEC, print_hint_on_failure=False)
        if ok:
            _awg_create_userspace_stubs()
            success("AWG: amneziawg-go установлен (userspace режим)")
            return True
        warn("AWG: не удалось скачать/собрать amneziawg-go")
        return False
    except Exception as exc:
        warn(f"AWG: ошибка сборки amneziawg-go: {exc}")
        return False


def _awg_detect_implementation() -> str:
    """
    Автоматически определяет доступность модуля ядра amnezia-wg/amneziawg
    и возвращает путь к userspace-реализации (amneziawg-go) или пустую
    строку если модуль ядра загружен и работает.

    Логика выбора:
      1. Если модуль amneziawg/amnezia-wg загружен (lsmod) → ядро, возврат ""
      2. Если можно создать тестовый интерфейс type amneziawg → ядро, возврат ""
      3. Если amneziawg-go доступен → userspace, возврат пути к бинарю
      4. Иначе → userspace как fallback (пустая строка, awg-quick сам разберётся)

    Возвращает строку для подстановки в:
      WG_QUICK_USERSPACE_IMPLEMENTATION=<result>
    Если возвращает "" — переменную не нужно выставлять (ядро само обработает).
    """
    core = _core_module()
    _run = core._run
    log_to_file = core.log_to_file
    # Шаг 1: проверяем lsmod
    _r_lsmod = _run(["lsmod"], capture=True, check=False)
    _lsmod_out = (_r_lsmod.stdout or "").lower()
    if "amneziawg" in _lsmod_out or "amnezia_wg" in _lsmod_out or "amnezia-wg" in _lsmod_out:
        log_to_file("INFO", "AWG impl: kernel module loaded (lsmod)")
        return ""

    # Шаг 2: пробуем создать тестовый интерфейс
    _test_iface = "awg_probe_tmp0"
    _r_add = _run(
        ["ip", "link", "add", _test_iface, "type", "amneziawg"],
        capture=True, check=False
    )
    if _r_add.returncode == 0:
        _run(["ip", "link", "delete", _test_iface], check=False, quiet=True)
        log_to_file("INFO", "AWG impl: kernel module available (ip link probe)")
        return ""

    # Шаг 3: модуля нет — ищем amneziawg-go
    _go_candidates = [
        "/usr/local/bin/amneziawg-go",
        "/usr/bin/amneziawg-go",
    ]
    for _gc in _go_candidates:
        if Path(_gc).exists() and os.access(_gc, os.X_OK):
            log_to_file("INFO", f"AWG impl: userspace amneziawg-go at {_gc}")
            return _gc

    # Шаг 4: пробуем загрузить модуль принудительно
    for _mod in ("amneziawg", "amnezia-wg", "wireguard"):
        _r_mp = _run(["modprobe", _mod], capture=True, check=False)
        if _r_mp.returncode == 0:
            log_to_file("INFO", f"AWG impl: kernel module loaded via modprobe {_mod}")
            return ""

    # Ничего не найдено — возвращаем путь по умолчанию как fallback
    log_to_file("WARN", "AWG impl: neither kernel module nor amneziawg-go found, using default path")
    return "/usr/local/bin/amneziawg-go"


def _awg_create_userspace_stubs() -> None:
    """Создаёт stub-обёртки awg и awg-quick для userspace режима."""
    core = _core_module()
    stub_awg = (
        "#!/bin/bash\n"
        "exec /usr/local/bin/amneziawg-go \"$@\"\n"
    )
    stub_quick = (
        "#!/bin/bash\n"
        "set -e\n"
        "IFACE=\"$2\"\n"
        "CONF=\"/etc/amnezia/amneziawg/${IFACE}.conf\"\n"
        "case \"$1\" in\n"
        "  up)\n"
        "    /usr/local/bin/amneziawg-go \"$IFACE\" &\n"
        "    sleep 1\n"
        "    ip link set \"$IFACE\" up\n"
        "    awg setconf \"$IFACE\" \"$CONF\"\n"
        "    ;;\n"
        "  down)\n"
        "    ip link delete \"$IFACE\" 2>/dev/null || true\n"
        "    ;;\n"
        "esac\n"
    )
    for path, body in [
        ("/usr/local/bin/awg",       stub_awg),
        ("/usr/local/bin/awg-quick", stub_quick),
    ]:
        Path(path).write_text(body.replace("\\n", "\n").replace('\"', '"'))
        os.chmod(path, 0o755)


def _awg_server_conf_text() -> str:
    """
    Формирует текст конфига AWG-сервера (для exit-VPS). Dual-Stack IPv4+IPv6.

    Структура PostUp/PostDown (полностью идемпотентная, через общий слой
    chimera.modules.awg_net_common):

      IPv4 (iptables):
        - build_nat_idempotent_shell(scope_source=False) — blanket MASQUERADE
          через $WAN + FORWARD -i awg0 + FORWARD -o awg0 ESTABLISHED,RELATED,
          каждое с `iptables -C || iptables -A` идиомой (безопасно при
          повторных `awg-quick up awg0` без промежуточного `down`).

      IPv6 (ip6tables):
        - build_nat6_idempotent_shell(scope_source=False) — аналогично IPv4,
          через ip6tables с тем же blanket MASQUERADE + FORWARD -i/-o.
          До этого фикса ip6tables-правила добавлялись через -A без -C-проверки
          (тот же баг №1 из ревью, только для IPv6 — забыт при первичном рефакторинге).

    MASQUERADE scope (scope_source=False = blanket, без -s):
      Сознательное сохранение поведения до коммита 47f56d3. На exit-VPS в Mode B
      chain кроме AWG-трафика (от RU-VPS, src=10.66.66.2) могут быть другие
      исходящие потоки (системные обновления, monitoring-агенты, туннели других
      сервисов), которые тоже должны маскарадиться через WAN. Сужение до
      `-s {awg_subnet}` сломало бы их. Если в будущем потребуется ограничить
      MASQUERADE только AWG-подсетью — передать scope_source=True в вызовы
      build_nat_idempotent_shell / build_nat_cleanup_shell ниже.

    WAN-интерфейс определяется в runtime через `ip route | awk '/default/'`
    (не хардкодим — после ребута udev может переименовать eth0 → ens3 и т.п.).
    Для IPv6 WAN-интерфейс определяется через `ip -6 route | awk '/default/'`.
    """
    core = _core_module()
    AWG_CLIENT_IP = getattr(core, "AWG_CLIENT_IP", "10.66.66.2/32")
    AWG_CLIENT_IPv6 = getattr(core, "AWG_CLIENT_IPv6", "fd66:66:66::2/128")
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_H1 = getattr(core, "AWG_H1", 1)
    AWG_H2 = getattr(core, "AWG_H2", 2)
    AWG_H3 = getattr(core, "AWG_H3", 3)
    AWG_H4 = getattr(core, "AWG_H4", 4)
    AWG_JC = getattr(core, "AWG_JC", 4)
    AWG_JMAX = getattr(core, "AWG_JMAX", 70)
    AWG_JMIN = getattr(core, "AWG_JMIN", 40)
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_S1 = getattr(core, "AWG_S1", 0)
    AWG_S2 = getattr(core, "AWG_S2", 0)
    # v5.0.0: S3/S4 — добавлены для полного набора AWG 2.0
    AWG_S3 = getattr(core, "AWG_S3", 0)
    AWG_S4 = getattr(core, "AWG_S4", 0)
    # v5.0.0: I1-I5 — опциональные decoy CPS-пакеты
    AWG_I1 = getattr(core, "AWG_I1", "")
    AWG_I2 = getattr(core, "AWG_I2", "")
    AWG_I3 = getattr(core, "AWG_I3", "")
    AWG_I4 = getattr(core, "AWG_I4", "")
    AWG_I5 = getattr(core, "AWG_I5", "")
    AWG_SERVER_IP = getattr(core, "AWG_SERVER_IP", "10.66.66.1/32")
    AWG_SERVER_IPv6 = getattr(core, "AWG_SERVER_IPv6", "fd66:66:66::1/128")
    AWG_SERVER_PRIVKEY = getattr(core, "AWG_SERVER_PRIVKEY", "")
    # NAT/MASQUERADE/FORWARD правила — через общий awg_net_common, тот же
    # слой что использует awg_standalone.awgs_setup_nat_and_routing.
    # scope_source=False → blanket MASQUERADE (поведение до 47f56d3, см. docstring).
    from .awg_net_common import (
        build_nat_idempotent_shell as _build_nat_up,
        build_nat_cleanup_shell as _build_nat_down,
        build_nat6_idempotent_shell as _build_nat6_up,
        build_nat6_cleanup_shell as _build_nat6_down,
    )
    _awg_subnet = "10.66.66.0/24"  # AWG_SUBNET из _core.py globals
    try:
        _awg_subnet = getattr(core, "AWG_SUBNET", "10.66.66.0/24")
    except Exception:
        pass
    _awg_subnet_v6 = "fd66:66:66::/64"  # AWG_SUBNET_V6 из _core.py globals
    try:
        _awg_subnet_v6 = getattr(core, "AWG_SUBNET_V6", "fd66:66:66::/64")
    except Exception:
        pass
    # IPv4: WAN через `ip route` (default route IPv4)
    _postup_v4 = (
        "WAN=$(ip route | awk '/default/ {print $5; exit}'); "
        + _build_nat_up(_awg_subnet, "awg0", "$WAN", scope_source=False)
    )
    _postdown_v4 = (
        "WAN=$(ip route | awk '/default/ {print $5; exit}'); "
        + _build_nat_down(_awg_subnet, "awg0", "$WAN", scope_source=False)
    )
    # IPv6: WAN через `ip -6 route` (default route IPv6).
    # Используем ту же $WAN переменную — обычно IPv4 и IPv6 default route
    # идут через один и тот же физический интерфейс, но если IPv6 отсутствует,
    # `ip -6 route | awk ...` вернёт пустую строку и правило MASQUERADE будет
    # с `-o ''` — безвредно (ip6tables его просто не сматчит, || true в -D
    # и `-C` в -A предотвращают падение).
    _postup_v6 = (
        "WAN6=$(ip -6 route | awk '/default/ {print $5; exit}'); "
        "[ -n \"$WAN6\" ] && "
        + _build_nat6_up(_awg_subnet_v6, "awg0", "$WAN6", scope_source=False)
        + " || true"
    )
    _postdown_v6 = (
        "WAN6=$(ip -6 route | awk '/default/ {print $5; exit}'); "
        "[ -n \"$WAN6\" ] && "
        + _build_nat6_down(_awg_subnet_v6, "awg0", "$WAN6", scope_source=False)
        + " || true"
    )
    # v5.2: I1-I5 пишутся через _awg_build_i_lines() — условная запись
    # в зависимости от поддержки локальным awg-quick (см. awg_compat.py).
    # Раньше (3e1fa70) писались ВСЕГДА — это ломало старые amneziawg-tools.
    _i_lines = _awg_build_i_lines(AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5)
    return (
        f"[Interface]\n"
        f"PrivateKey = {AWG_SERVER_PRIVKEY}\n"
        f"Address = {AWG_SERVER_IP}, {AWG_SERVER_IPv6}\n"
        f"ListenPort = {AWG_EXIT_PORT}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"S3 = {AWG_S3}\n"
        f"S4 = {AWG_S4}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"{_i_lines}"
        # PostUp: только IPv4 + IPv6 блоки через awg_net_common — без ручных
        # дублирующих iptables FORWARD строк (они целиком генерируются билдерами).
        f"PostUp = {_postup_v4}; "
        f"{_postup_v6}\n"
        # PostDown: аналогично, cleanup через билдеры.
        f"PostDown = {_postdown_v4}; "
        f"{_postdown_v6}\n"
        f"\n"
        f"[Peer]\n"
        f"# RU-VPS (Xray client)\n"
        f"PublicKey = {AWG_CLIENT_PUBKEY}\n"
        f"PresharedKey = {AWG_PRESHARED_KEY}\n"
        f"AllowedIPs = {AWG_CLIENT_IP}, {AWG_CLIENT_IPv6}\n"
    )


def _awg_client_conf_text() -> str:
    """Формирует текст конфига AWG-клиента (для RU-VPS). Dual-Stack IPv4+IPv6."""
    core = _core_module()
    AWG_CLIENT_IP = getattr(core, "AWG_CLIENT_IP", "10.66.66.2/32")
    AWG_CLIENT_IPv6 = getattr(core, "AWG_CLIENT_IPv6", "fd66:66:66::2/128")
    AWG_CLIENT_LISTEN_PORT = getattr(core, "AWG_CLIENT_LISTEN_PORT", 11100)
    AWG_CLIENT_PRIVKEY = getattr(core, "AWG_CLIENT_PRIVKEY", "")
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_H1 = getattr(core, "AWG_H1", 1)
    AWG_H2 = getattr(core, "AWG_H2", 2)
    AWG_H3 = getattr(core, "AWG_H3", 3)
    AWG_H4 = getattr(core, "AWG_H4", 4)
    AWG_JC = getattr(core, "AWG_JC", 4)
    AWG_JMAX = getattr(core, "AWG_JMAX", 70)
    AWG_JMIN = getattr(core, "AWG_JMIN", 40)
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_S1 = getattr(core, "AWG_S1", 0)
    AWG_S2 = getattr(core, "AWG_S2", 0)
    # v5.0.0: S3/S4 — добавлены для полного набора AWG 2.0
    AWG_S3 = getattr(core, "AWG_S3", 0)
    AWG_S4 = getattr(core, "AWG_S4", 0)
    # v5.0.0: I1-I5 — опциональные decoy CPS-пакеты
    AWG_I1 = getattr(core, "AWG_I1", "")
    AWG_I2 = getattr(core, "AWG_I2", "")
    AWG_I3 = getattr(core, "AWG_I3", "")
    AWG_I4 = getattr(core, "AWG_I4", "")
    AWG_I5 = getattr(core, "AWG_I5", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    # v5.2: I1-I5 через _awg_build_i_lines() (см. выше в _awg_server_conf_text)
    _i_lines = _awg_build_i_lines(AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5)
    return (
        f"[Interface]\n"
        f"PrivateKey = {AWG_CLIENT_PRIVKEY}\n"
        f"Address = {AWG_CLIENT_IP}, {AWG_CLIENT_IPv6}\n"
        f"ListenPort = {AWG_CLIENT_LISTEN_PORT}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"S3 = {AWG_S3}\n"
        f"S4 = {AWG_S4}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"{_i_lines}"
        f"DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111\n"
        f"Table = off\n"
        f"\n"
        f"[Peer]\n"
        f"# Зарубежный VPS (AWG-сервер)\n"
        f"PublicKey = {AWG_SERVER_PUBKEY}\n"
        f"PresharedKey = {AWG_PRESHARED_KEY}\n"
        f"Endpoint = {AWG_EXIT_HOST}:{AWG_EXIT_PORT}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )


def _awg_systemd_unit_text(xray_uid: int) -> str:
    """Формирует текст systemd unit для AWG-клиента."""
    core = _core_module()
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    pr_up = (
        # ── IPv4 policy routing ────────────────────────────────────────────────
        # ip rule — policy routing fwmark (idempotent)
        f"ip rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null || true; "
        # ip route в таблице AWG (idempotent)
        f"ip route show table {AWG_ROUTE_TABLE} | grep -q default || "
        f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        # iptables OUTPUT mark (idempotent через -C)
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        # ИСПРАВЛЕНИЕ: маркируем трафик dnscrypt-proxy (uid dnscrypt) тем же fwmark.
        # dnscrypt-proxy делает исходящие соединения к DNS upstream — они должны
        # идти через AWG, иначе провайдер блокирует DoT/DNSCrypt на порту 443.
        f"DC_UID=$(id -u dnscrypt 2>/dev/null); "
        f"[ -n \"$DC_UID\" ] && ("
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true"
        f") || true; "
        # iptables FORWARD MSS clamp (idempotent через -C)
        f"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || "
        f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # sysctl rp_filter
        f"sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1; "
        f"sysctl -w net.ipv4.conf.{AWG_INTERFACE}.rp_filter=0 >/dev/null 2>&1; "
        # ── IPv6 policy routing (применяем если IPv6-стек доступен) ───────────
        f"ip -6 route show 2>/dev/null | grep -q . && ("
        # ip6 rule fwmark (idempotent)
        f"ip -6 rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip -6 rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null || true; "
        # ip6 route default через awg0 (idempotent)
        f"ip -6 route show table {AWG_ROUTE_TABLE} 2>/dev/null | grep -q default || "
        f"ip -6 route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        # ip6tables OUTPUT mangle mark (idempotent через -C)
        f"ip6tables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || "
        f"ip6tables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        # ip6tables FORWARD MSS clamp (idempotent через -C)
        f"ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || "
        f"ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # ip6tables FORWARD ACCEPT (idempotent через -C)
        f"ip6tables -C FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || "
        f"ip6tables -A FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"ip6tables -C FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || "
        f"ip6tables -A FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        # ip6tables NAT MASQUERADE (idempotent через проверку)
        f"IFACE6=$(ip -6 route | awk '/default/ {{print $5; exit}}'); "
        f"[ -n \"$IFACE6\" ] && ("
        f"ip6tables -t nat -C POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || "
        f"ip6tables -t nat -A POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || true"
        f") || true"
        f") || true"
    )
    pr_down = (
        # ── IPv4 cleanup ───────────────────────────────────────────────────────
        f"ip route del default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"iptables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        # ── IPv6 cleanup (идемпотентно — ошибки игнорируем) ───────────────────
        f"ip -6 route del default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip -6 rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} 2>/dev/null || true; "
        f"ip6tables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {AWG_FWMARK} 2>/dev/null || true; "
        f"ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN "
        f"-j TCPMSS --set-mss {AWG_MTU - 40} 2>/dev/null || true; "
        f"ip6tables -D FORWARD -i {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"ip6tables -D FORWARD -o {AWG_INTERFACE} -j ACCEPT 2>/dev/null || true; "
        f"IFACE6=$(ip -6 route | awk '/default/ {{print $5; exit}}'); "
        f"[ -n \"$IFACE6\" ] && ip6tables -t nat -D POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || true"
    )
    # АВТООПРЕДЕЛЕНИЕ реализации: если модуль ядра amneziawg доступен —
    # WG_QUICK_USERSPACE_IMPLEMENTATION не нужен (ядро само всё сделает).
    # Если ядра нет — используем amneziawg-go (userspace).
    _awg_impl = _awg_detect_implementation()
    # Строка для Environment= (пустая если ядро)
    _env_line  = f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl}\n" if _awg_impl else ""
    # Префикс для ExecStart/ExecStop inline env
    _impl_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl} " if _awg_impl else ""
    # ExecStartPre: пробуем загрузить модуль ядра; если не выйдет — userspace подхватит
    _pre_modprobe = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    return (
        f"[Unit]\n"
        f"Description=AmneziaWG 2.0 client (awg0) + policy routing for Xray\n"
        f"After=network-online.target\n"
        f"Wants=network-online.target\n"
        f"\n"
        f"[Service]\n"
        f"Type=oneshot\n"
        f"RemainAfterExit=yes\n"
        f"{_env_line}"
        f"ExecStartPre=/bin/bash -c '{_pre_modprobe}'\n"
        f"ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf'\n"
        f"ExecStartPost=/bin/bash -c '{pr_up}'\n"
        f"ExecStop=/bin/bash -c '{pr_down}'\n"
        f"ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN down /etc/amnezia/amneziawg/awg0.conf'\n"
        f"\n"
        f"[Install]\n"
        f"WantedBy=multi-user.target\n"
    )


def ensure_amneziawg_ready(remote_host: str = None, ssh_fn=None) -> None:
    """
    Подготавливает систему к работе с AmneziaWG:
      - Очищает зависшие интерфейсы и сервисы (ЭТАП 0)
      - Проверяет, загружен ли уже модуль ядра (ЭТАП 1)
      - Устанавливает модуль через официальный PPA (ЭТАП 2)
      - Если PPA недоступен — добавляет репозиторий вручную (ЭТАП 3)
      - Финальный fallback: DKMS-сборка из исходников (ЭТАП 4)

    Аргументы:
      remote_host — IP удалённого сервера (str) или None для локального режима.
      ssh_fn      — callable(cmd, capture, check) для удалённых команд.
                    Обязателен если remote_host указан. Передавать _ssh из
                    awg_setup_remote_server() явно, чтобы избежать NameError.

    При неустранимой ошибке бросает Exception, останавливая установку.
    """
    core = _core_module()
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn

    # Метка для логов: показываем, где работаем
    _where = f"[{remote_host}]" if remote_host else "[local]"

    # -------------------------------------------------------------------------
    # Вспомогательная функция: выполнить команду локально или удалённо.
    # Возвращает subprocess.CompletedProcess. capture=True наполняет .stdout.
    # -------------------------------------------------------------------------
    def _exec(cmd: str, check: bool = False, capture: bool = False):
        if remote_host:
            # ssh_fn передаётся явно из awg_setup_remote_server() — нет NameError
            if ssh_fn is None:
                raise RuntimeError(
                    "ensure_amneziawg_ready: remote_host указан, но ssh_fn не передан!"
                )
            return ssh_fn(cmd, capture=capture, check=check)
        else:
            return _run(["bash", "-c", cmd], check=check, capture=capture)

    # =========================================================================
    # ЭТАП 0: ОЧИСТКА — удаляем все следы предыдущих неудачных попыток.
    # Выполняется ВСЕГДА, независимо от состояния модуля.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 0: очистка зависших интерфейсов и сервисов...")

    # Останавливаем все связанные сервисы (ошибки игнорируем — сервиса может не быть)
    _exec(
        "systemctl stop amneziawg-awg0 2>/dev/null || true; "
        "systemctl stop wg-quick@awg0 2>/dev/null || true; "
        "systemctl stop amneziawg-tools 2>/dev/null || true",
        check=False,
    )

    # Удаляем основной интерфейс awg0, если существует
    _exec(
        "ip link show awg0 >/dev/null 2>&1 && ip link delete dev awg0 2>/dev/null || true",
        check=False,
    )

    # Удаляем тестовый интерфейс, если завис с прошлой попытки
    _exec(
        "ip link show test_awg0 >/dev/null 2>&1 && ip link delete dev test_awg0 2>/dev/null || true",
        check=False,
    )

    # Принудительная очистка всех интерфейсов типа amneziawg
    # (может не поддерживаться на старых ядрах — игнорируем ошибку)
    _exec("ip -s link flush type amneziawg 2>/dev/null || true", check=False)

    info(f"AWG {_where}: сетевые интерфейсы очищены")

    # =========================================================================
    # ЭТАП 1: ПРОВЕРКА — может, модуль уже загружен?
    # Сначала lsmod, затем реальный функциональный тест через ip link.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 1: проверка наличия модуля amneziawg в ядре...")

    # Проверка 1а: lsmod
    r_lsmod = _exec(
        "lsmod | grep -q amneziawg && echo LOADED || echo NOT_LOADED",
        capture=True, check=False,
    )
    _lsmod_ok = "LOADED" in (r_lsmod.stdout or "")

    # Проверка 1б: функциональный тест — создаём и сразу удаляем тестовый интерфейс
    r_iftest = _exec(
        "ip link add test_awg0 type amneziawg 2>/dev/null && "
        "ip link delete dev test_awg0 2>/dev/null && echo TYPE_OK || echo TYPE_FAIL",
        capture=True, check=False,
    )
    _type_ok = "TYPE_OK" in (r_iftest.stdout or "")

    if _lsmod_ok and _type_ok:
        success(f"AWG {_where} ЭТАП 1: модуль уже загружен и готов — пропускаем установку")
        return  # Всё хорошо, выходим немедленно

    warn(f"AWG {_where} ЭТАП 1: модуль не обнаружен (lsmod={_lsmod_ok}, iftest={_type_ok})")

    # =========================================================================
    # ЭТАП 2: УСТАНОВКА ЧЕРЕЗ ОФИЦИАЛЬНЫЙ PPA (приоритетная попытка)
    # Использует add-apt-repository ppa:amnezia/ppa
    # =========================================================================
    info(f"AWG {_where} ЭТАП 2: установка через официальный PPA amnezia/ppa...")

    # Устанавливаем зависимости для работы с PPA и сборки модуля ядра
    _exec(
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -q 2>/dev/null && "
        "apt-get install -y -q "
        "  software-properties-common "
        "  python3-launchpadlib "
        "  gnupg2 "
        "  linux-headers-$(uname -r) "
        "  build-essential "
        "2>/dev/null",
        check=False,
    )

    # Добавляем PPA и проверяем результат
    r_ppa = _exec(
        "add-apt-repository ppa:amnezia/ppa -y 2>/dev/null && echo PPA_ADDED || echo PPA_FAILED",
        capture=True, check=False,
    )
    _ppa_added = "PPA_ADDED" in (r_ppa.stdout or "")

    if _ppa_added:
        # Обновляем индексы и устанавливаем пакет amneziawg
        r_inst = _exec(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -q 2>/dev/null && "
            "apt-get install -y -q amneziawg 2>/dev/null && "
            "echo AWG_PKG_OK || echo AWG_PKG_FAIL",
            capture=True, check=False,
        )
        if "AWG_PKG_OK" in (r_inst.stdout or ""):
            # Загружаем модуль в ядро и проверяем функционально
            _exec("modprobe amneziawg 2>/dev/null || true", check=False)
            r_v = _exec(
                "ip link add test_awg0 type amneziawg 2>/dev/null && "
                "ip link delete dev test_awg0 2>/dev/null && echo OK || echo FAIL",
                capture=True, check=False,
            )
            if "OK" in (r_v.stdout or ""):
                success(f"AWG {_where} ЭТАП 2: модуль установлен через PPA — готово!")
                success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
                return
            else:
                warn(f"AWG {_where} ЭТАП 2: пакет установлен, но интерфейс не создаётся — продолжаем")
        else:
            warn(f"AWG {_where} ЭТАП 2: пакет amneziawg не найден в PPA")
    else:
        warn(f"AWG {_where} ЭТАП 2: add-apt-repository не сработал")

    # =========================================================================
    # ЭТАП 3: РУЧНОЕ ДОБАВЛЕНИЕ PPA
    # Fallback для серверов без launchpadlib или с заблокированным launchpad.
    # Прямая запись в sources.list.d + импорт GPG-ключа.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 3: ручное добавление репозитория PPA в sources.list...")

    r_mppa = _exec(
        # Импортируем GPG-ключ репозитория
        "gpg --no-default-keyring "
        "  --keyring /usr/share/keyrings/amnezia-ppa.gpg "
        "  --keyserver keyserver.ubuntu.com "
        "  --recv-keys 57290828 2>/dev/null && "
        # Прописываем репозиторий с привязкой к keyring
        "echo 'deb [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] "
        "  https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main' "
        "  > /etc/apt/sources.list.d/amnezia-ppa.list && "
        "echo MANUAL_PPA_OK || echo MANUAL_PPA_FAIL",
        capture=True, check=False,
    )

    if "MANUAL_PPA_OK" in (r_mppa.stdout or ""):
        r_inst2 = _exec(
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -q 2>/dev/null && "
            "apt-get install -y -q amneziawg 2>/dev/null && "
            "echo AWG_PKG2_OK || echo AWG_PKG2_FAIL",
            capture=True, check=False,
        )
        if "AWG_PKG2_OK" in (r_inst2.stdout or ""):
            _exec("modprobe amneziawg 2>/dev/null || true", check=False)
            r_v2 = _exec(
                "ip link add test_awg0 type amneziawg 2>/dev/null && "
                "ip link delete dev test_awg0 2>/dev/null && echo OK || echo FAIL",
                capture=True, check=False,
            )
            if "OK" in (r_v2.stdout or ""):
                success(f"AWG {_where} ЭТАП 3: модуль установлен через ручной PPA — готово!")
                success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
                return
            else:
                warn(f"AWG {_where} ЭТАП 3: пакет установлен, но интерфейс не создаётся — продолжаем")
        else:
            warn(f"AWG {_where} ЭТАП 3: пакет amneziawg не найден и через ручной PPA")
    else:
        warn(f"AWG {_where} ЭТАП 3: не удалось добавить репозиторий вручную")

    # =========================================================================
    # ЭТАП 4: DKMS-СБОРКА ИЗ ИСХОДНИКОВ (финальный fallback)
    # Клонируем официальный репозиторий и собираем модуль через DKMS.
    # =========================================================================
    info(f"AWG {_where} ЭТАП 4: сборка модуля из исходников через DKMS...")

    # Устанавливаем зависимости для сборки: dkms, заголовки ядра, git
    r_dkms_deps = _exec(
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get install -y -q dkms linux-headers-$(uname -r) build-essential git 2>/dev/null && "
        "echo DKMS_DEPS_OK || echo DKMS_DEPS_FAIL",
        capture=True, check=False,
    )

    if "DKMS_DEPS_FAIL" in (r_dkms_deps.stdout or ""):
        warn(f"AWG {_where} ЭТАП 4: не удалось установить зависимости для DKMS")
    else:
        # МИГРАЦИЯ (Wave 6, Variant A): раньше `git clone --depth=1` внутри
        # bash one-liner, без зеркал. Теперь fetch_package(AWG_KMOD_SOURCE_SPEC)
        # — HTTP tarball (Variant A согласно анализу: Makefile в src/ не
        # использует git, версия hardcoded 1.0.0, submodules отсутствуют).
        # 9 зеркал (прямой GitHub + codeload + 7 gh-proxy).
        #
        # post_install AWG_KMOD_SOURCE_SPEC делает:
        #   1. extract tarball → amneziawg-linux-kernel-module-master/
        #   2. cd src/ (ИСПРАВЛЕНО: раньше cd в root, но Makefile в src/)
        #   3. make dkms-install (fallback: make && make install)
        #   4. modprobe amneziawg
        #   5. verify: ip link add test_awg0 type amneziawg && delete
        from chimera.modules.download_manager import fetch_package
        from chimera.modules.awg_transport_packages import AWG_KMOD_SOURCE_SPEC

        try:
            ok = fetch_package(AWG_KMOD_SOURCE_SPEC, print_hint_on_failure=False)
        except Exception:
            ok = False

        if ok:
            success(f"AWG {_where} ЭТАП 4: модуль собран через DKMS — готово!")
            success(f"AWG {_where}: [OK] Модуль AmneziaWG установлен и готов")
            return
        else:
            warn(f"AWG {_where} ЭТАП 4: DKMS-сборка не удалась")

    # =========================================================================
    # ЭТАП 5: ВСЕ СПОСОБЫ ИСЧЕРПАНЫ — останавливаем установку
    # =========================================================================
    raise Exception(
        f"AWG {_where}: не удалось установить модуль ядра AmneziaWG ни одним из методов.\n"
        f"  Попробуйте вручную:\n"
        f"    1) add-apt-repository ppa:amnezia/ppa -y && apt-get update && apt-get install -y amneziawg\n"
        f"    2) или DKMS: git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module "
        f"&& cd amneziawg-linux-kernel-module && bash dkms-install.sh\n"
        f"  После ручной установки перезапустите скрипт."
    )


def awg_setup_local_client() -> bool:
    """
    Настраивает AWG-клиент на RU-VPS:
    1. Устанавливает amneziawg-tools
    2. Генерирует ключи
    3. Записывает конфиги клиента и шаблон сервера
    4. Создаёт systemd unit с policy routing
    Возвращает True при успехе.
    """
    core = _core_module()
    _run = core._run
    info = core.info
    log_to_file = core.log_to_file
    success = core.success
    warn = core.warn
    AWG_CLIENT_LISTEN_PORT = getattr(core, "AWG_CLIENT_LISTEN_PORT", 11100)
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_INSTALLED = getattr(core, "AWG_INSTALLED", False)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    _AWG_ACTIVE_CONF = getattr(core, "_AWG_ACTIVE_CONF", Path("/etc/amnezia/amneziawg/awg0.conf"))
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))

    info("AWG: настройка клиента на RU-VPS...")

    # 1. Подготовка модуля ядра AmneziaWG (очистка + установка при необходимости)
    try:
        ensure_amneziawg_ready()  # None = работаем локально на RU-VPS
    except Exception as _e:
        warn(f"AWG: модуль ядра недоступен: {_e}")
        return False

    # 2. Установка инструментов (awg, awg-quick, amneziawg-go)
    if not awg_install_local():
        warn("AWG: не удалось установить amneziawg-tools")
        return False

    # 2. Генерация ключей
    if not awg_generate_keys():
        warn("AWG: не удалось сгенерировать ключи")
        return False

    # 3. Директории
    _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_AWG_CONF_DIR), 0o700)

    # 4. Конфиги — ВАЖНО: клиентский конфиг = awg0.conf (используется awg-quick)
    client_conf = _awg_client_conf_text()
    _AWG_ACTIVE_CONF.write_text(client_conf)
    os.chmod(str(_AWG_ACTIVE_CONF), 0o600)
    success(f"AWG: клиентский конфиг → {_AWG_ACTIVE_CONF}")

    # --- БАГ-FIX 1: симлинк для awg-quick -----------------------------------
    # awg-quick (как wg-quick) по умолчанию ищет конфиги в /etc/wireguard/.
    # Без симлинка сервис падает: "Cannot find device 'awg0'".
    # Создаём: /etc/wireguard/awg0.conf → /etc/amnezia/amneziawg/awg0.conf
    _wg_dir = Path("/etc/wireguard")
    _wg_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_wg_dir), 0o700)
    _wg_link = _wg_dir / "awg0.conf"
    try:
        if _wg_link.exists() or _wg_link.is_symlink():
            _wg_link.unlink()
        _wg_link.symlink_to(_AWG_ACTIVE_CONF)
        success(f"AWG: симлинк создан: {_wg_link} → {_AWG_ACTIVE_CONF}")
    except Exception as _sym_err:
        warn(f"AWG: не удалось создать симлинк {_wg_link}: {_sym_err}")
        warn("AWG: awg-quick будет вызываться с полным путём к конфигу")
    # -------------------------------------------------------------------------

    # Сохраняем серверный конфиг рядом (для scp на exit-VPS)
    log_to_file("DEBUG", f"AWG template: generating server conf text "
                         f"(server_pubkey={AWG_SERVER_PUBKEY[:16] if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                         f"client_pubkey={AWG_CLIENT_PUBKEY[:16] if AWG_CLIENT_PUBKEY else 'EMPTY'}, "
                         f"psk={'SET' if AWG_PRESHARED_KEY else 'EMPTY'})")
    server_conf = _awg_server_conf_text()
    _server_conf_save = _AWG_CONF_DIR / "awg0-server-template.conf"
    log_to_file("DEBUG", f"AWG template: writing to {_server_conf_save} ({len(server_conf)} bytes)")
    _server_conf_save.write_text(server_conf)
    os.chmod(str(_server_conf_save), 0o600)
    log_to_file("DEBUG", f"AWG template: written OK, exists={_server_conf_save.exists()}, "
                         f"size={_server_conf_save.stat().st_size}")
    success(f"AWG: серверный конфиг (шаблон для exit-VPS) → {_server_conf_save}")

    # 5. UID пользователя xray
    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: пользователь xray не найден — policy routing будет по uid=0")

    # 6. Systemd unit
    unit_path = Path("/etc/systemd/system/amneziawg-awg0.service")
    unit_path.write_text(_awg_systemd_unit_text(xray_uid))
    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    _run(["systemctl", "enable", "amneziawg-awg0.service"], check=False, quiet=True)
    success("AWG: systemd unit amneziawg-awg0.service создан и включён")

    # BUGFIX: открываем входящий UDP порт AWG на entry-ноде.
    # Некоторые провайдеры (например AEZA) ставят INPUT policy DROP по умолчанию,
    # и без этого правила ответные пакеты от exit-ноды не проходят —
    # туннель односторонний (sent > 0, received = 0).
    import subprocess as _sp2
    _lport = str(AWG_CLIENT_LISTEN_PORT)
    _chk2 = _sp2.run(
        ["iptables", "-C", "INPUT", "-p", "udp", "--dport", _lport, "-j", "ACCEPT"],
        capture_output=True
    )
    if _chk2.returncode != 0:
        _sp2.run(
            ["iptables", "-A", "INPUT", "-p", "udp", "--dport", _lport, "-j", "ACCEPT"],
            capture_output=True
        )
        success(f"AWG: открыт входящий UDP/{_lport} на entry-ноде")
    # Сохраняем правило если доступен iptables-persistent
    _sp2.run(
        ["bash", "-c",
         "which netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save 2>/dev/null || "
         "mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"],
        capture_output=True
    )

    return True


def awg_apply_policy_routing() -> None:
    """
    Немедленно применяет policy routing (без перезагрузки):
    пакеты процесса xray помечаются → роутятся через awg0.
    """
    core = _core_module()
    _run = core._run
    command_exists = core.command_exists
    get_server_ip = core.get_server_ip
    info = core.info
    log_to_file = core.log_to_file
    success = core.success
    warn = core.warn
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    AWG_SUBNET_V6 = getattr(core, "AWG_SUBNET_V6", "fd66:66:66::/64")
    info("AWG: применение policy routing...")

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: xray uid не найден, используем 0")

    # ── Проверяем наличие IPv6-стека на сервере (graceful fallback) ───────────
    _ipv6_available = False
    try:
        r_v6 = _run(["ip", "-6", "route", "show"], capture=True, check=False, quiet=True)
        _ipv6_available = r_v6.returncode == 0
        if not _ipv6_available:
            warn("AWG: IPv6-стек недоступен на RU-сервере — пропускаем IPv6-правила (IPv4-only режим)")
        else:
            info("AWG: IPv6-стек обнаружен — применяем Dual-Stack policy routing")
    except Exception:
        warn("AWG: не удалось проверить IPv6-стек — пропускаем IPv6 (IPv4-only режим)")

    sysctl_cmds = [
        ["sysctl", "-w", "net.ipv4.ip_forward=1"],
        ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"],
        ["sysctl", "-w", f"net.ipv4.conf.{AWG_INTERFACE}.rp_filter=0"],
    ]
    routing_cmds = [
        ["ip", "route", "add", "default", "dev", AWG_INTERFACE,
         "table", str(AWG_ROUTE_TABLE)],
        ["ip", "rule", "add", "fwmark", str(AWG_FWMARK),
         "table", str(AWG_ROUTE_TABLE), "priority", "100"],
        ["iptables", "-t", "mangle", "-A", "OUTPUT",
         "-m", "owner", "--uid-owner", str(xray_uid),
         "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
        # ИСПРАВЛЕНИЕ: dnscrypt-proxy тоже должен идти через AWG.
        # Получаем uid пользователя dnscrypt динамически.
    ]
    try:
        import pwd as _pwd_dc
        _dc_uid = _pwd_dc.getpwnam("dnscrypt").pw_uid
        routing_cmds.append(
            ["iptables", "-t", "mangle", "-A", "OUTPUT",
             "-m", "owner", "--uid-owner", str(_dc_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)]
        )
    except KeyError:
        pass  # dnscrypt не установлен — ничего не добавляем
    routing_cmds += [
        # MSS clamping — убираем фрагментацию под MTU AWG
        ["iptables", "-t", "mangle", "-A", "FORWARD",
         "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--set-mss", str(AWG_MTU - 40)],
    ]

    # ── IPv6 policy routing (только если стек доступен) ───────────────────────
    if _ipv6_available:
        routing_cmds += [
            # ip6 rule: трафик Xray по fwmark → таблица AWG
            ["ip", "-6", "rule", "add", "fwmark", str(AWG_FWMARK),
             "table", str(AWG_ROUTE_TABLE), "priority", "100"],
            # ip6 route: дефолтный маршрут через awg0 в таблице AWG
            ["ip", "-6", "route", "add", "default", "dev", AWG_INTERFACE,
             "table", str(AWG_ROUTE_TABLE)],
            # ip6tables OUTPUT: маркируем трафик xray
            ["ip6tables", "-t", "mangle", "-A", "OUTPUT",
             "-m", "owner", "--uid-owner", str(xray_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
            # ip6tables MSS clamping
            ["ip6tables", "-t", "mangle", "-A", "FORWARD",
             "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
             "-j", "TCPMSS", "--set-mss", str(AWG_MTU - 40)],
            # ip6tables FORWARD ACCEPT: разрешаем форвардинг IPv6 через туннель
            ["ip6tables", "-A", "FORWARD", "-i", AWG_INTERFACE, "-j", "ACCEPT"],
            ["ip6tables", "-A", "FORWARD", "-o", AWG_INTERFACE, "-j", "ACCEPT"],
        ]
        # ip6tables NAT MASQUERADE: IPv6-пакеты из туннеля выходят с адресом RU-сервера.
        # Используем bash-обёртку т.к. нужна shell-подстановка для определения интерфейса.
        _run(
            ["bash", "-c",
             "IFACE6=$(ip -6 route | awk '/default/ {print $5; exit}'); "
             "[ -n \"$IFACE6\" ] && ip6tables -t nat -A POSTROUTING -o \"$IFACE6\" -j MASQUERADE 2>/dev/null || "
             f"ip6tables -t nat -A POSTROUTING -s {AWG_SUBNET_V6} -j MASQUERADE 2>/dev/null || true"],
            check=False, quiet=True
        )

    # ПАТЧ: добавляем исключения из AWG маршрутизации для exit-VPS и самого сервера.
    # Без этих правил SSH к exit-VPS и исходящий трафик сервера попадают в AWG петлю.
    _server_ip  = get_server_ip("4") or ""
    _server_ip6 = (get_server_ip("6") or "") if _ipv6_available else ""
    _exit_ip    = AWG_EXIT_HOST if AWG_EXIT_HOST else ""

    if _server_ip:
        _run(["ip", "rule", "add", "from", f"{_server_ip}/32",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
        info(f"AWG: исключение из AWG маршрутизации для сервера {_server_ip}")
    if _server_ip6 and _ipv6_available:
        _run(["ip", "-6", "rule", "add", "from", f"{_server_ip6}/128",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
        info(f"AWG: IPv6 исключение для сервера {_server_ip6}")
    if _exit_ip:
        _run(["ip", "rule", "add", "to", f"{_exit_ip}/32",
              "lookup", "main", "priority", "50"], check=False, quiet=True)
        # Маршрут к exit-VPS через физический интерфейс (не через AWG)
        _run(["bash", "-c",
              f"ip route add {_exit_ip}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null || true"],
             check=False, quiet=True)
        info(f"AWG: исключение из AWG маршрутизации для exit-VPS {_exit_ip}")
        # Если exit-IP сам является IPv6 — добавляем и ip6 rule
        if _ipv6_available and ":" in _exit_ip:
            _run(["ip", "-6", "rule", "add", "to", f"{_exit_ip}/128",
                  "lookup", "main", "priority", "50"], check=False, quiet=True)

    for cmd in sysctl_cmds + routing_cmds:
        r = _run(cmd, check=False, quiet=True)
        if r.returncode not in (0, 2):  # 2 = правило уже существует
            log_to_file("WARN", f"AWG routing cmd failed: {' '.join(cmd)} → {r.stderr.strip()}")

    # ── Сохраняем правила iptables (с гарантией восстановления после ребута) ─
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r_save = _run(["iptables-save"], capture=True, check=False)
    if r_save.returncode == 0:
        rules_v4 = rules_dir / "rules.v4"
        rules_v4.write_text(r_save.stdout)
        os.chmod(str(rules_v4), 0o600)
        success("AWG: iptables сохранены → /etc/iptables/rules.v4")

    # ── Сохраняем ip6tables (только если IPv6 применялся) ────────────────────
    if _ipv6_available:
        r_save6 = _run(["ip6tables-save"], capture=True, check=False)
        if r_save6.returncode == 0:
            rules_v6 = rules_dir / "rules.v6"
            rules_v6.write_text(r_save6.stdout)
            os.chmod(str(rules_v6), 0o600)
            success("AWG: ip6tables сохранены → /etc/iptables/rules.v6")
        else:
            warn("AWG: ip6tables-save не удался — IPv6 правила не сохранены на диск")

    # ── БАГ-FIX 2: установка и включение netfilter-persistent ────────────────
    # Без netfilter-persistent правила iptables НЕ восстанавливаются после ребута.
    # Просто сохранить в rules.v4 недостаточно — нужен сервис который их грузит.
    _nfp_installed = False
    if command_exists("netfilter-persistent") or command_exists("iptables-restore"):
        # Попробуем сохранить через netfilter-persistent
        r_nfp = _run(["netfilter-persistent", "save"], check=False, quiet=True)
        if r_nfp.returncode == 0:
            success("AWG: netfilter-persistent save — OK")
            _nfp_installed = True
    if not _nfp_installed:
        info("AWG: устанавливаем netfilter-persistent для сохранения iptables...")
        # БАГ-FIX: iptables-persistent задаёт интерактивные вопросы через debconf
        # ("Save current IPv4/IPv6 rules?"), что вешает скрипт навсегда.
        # Решение: предварительно выставляем пресиды debconf + DEBIAN_FRONTEND=noninteractive.
        _run(
            ["bash", "-c",
             "export DEBIAN_FRONTEND=noninteractive && "
             "echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' "
             "  | debconf-set-selections 2>/dev/null; "
             "echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' "
             "  | debconf-set-selections 2>/dev/null; "
             "apt-get install -y -q netfilter-persistent iptables-persistent 2>/dev/null"],
            check=False, quiet=True
        )
        r_nfp2 = _run(["netfilter-persistent", "save"], check=False, quiet=True)
        if r_nfp2.returncode == 0:
            success("AWG: netfilter-persistent установлен и правила сохранены")
            _nfp_installed = True
        else:
            warn("AWG: netfilter-persistent недоступен — будет использован fallback через cron")

    # Включаем netfilter-persistent в systemd (автозапуск)
    _run(["systemctl", "enable", "netfilter-persistent"], check=False, quiet=True)

    # ── Сохраняем sysctl постоянно ────────────────────────────────────────────
    sysctl_conf = Path("/etc/sysctl.d/99-awg.conf")
    _sysctl_content = (
        "net.ipv4.ip_forward=1\n"
        "net.ipv4.conf.all.rp_filter=0\n"
    )
    if _ipv6_available:
        # forwarding=1 нужен на RU-сервере для маршрутизации через awg0
        _sysctl_content += "net.ipv6.conf.all.forwarding=1\n"
    sysctl_conf.write_text(_sysctl_content)
    _run(["sysctl", "--system"], check=False, quiet=True)

    # ── БАГ-FIX 2 (продолжение): cron @reboot — полное восстановление ────────
    # Восстанавливаем И ip rule/route, И iptables (fallback если netfilter-persistent
    # по какой-то причине не отработал — двойная защита).
    _v6_reboot = ""
    if _ipv6_available:
        _v6_reboot = (
            f"test -f /etc/iptables/rules.v6 && ip6tables-restore < /etc/iptables/rules.v6 2>/dev/null; "
            f"ip -6 rule show | grep -q 'fwmark {AWG_FWMARK}' || "
            f"ip -6 rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null; "
            f"ip -6 route show table {AWG_ROUTE_TABLE} | grep -q default || "
            f"ip -6 route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null; "
        )
        if _server_ip6:
            _v6_reboot += (
                f"ip -6 rule show | grep -q 'from {_server_ip6}' || "
                f"ip -6 rule add from {_server_ip6}/128 lookup main priority 49 2>/dev/null; "
            )

    reboot_script = (
        "# AWG policy routing + iptables restore — автогенерировано vless-installer\n"
        f"@reboot root "
        # 1. iptables из сохранённого дампа (жёсткий fallback)
        f"test -f /etc/iptables/rules.v4 && iptables-restore < /etc/iptables/rules.v4 2>/dev/null; "
        # 2. ip6tables restore (Dual-Stack, если был применён)
        + _v6_reboot +
        # 3. ip rule исключение для самого сервера (приоритет 49)
        f"ip rule show | grep -q 'from {_server_ip}' || "
        f"ip rule add from {_server_ip}/32 lookup main priority 49 2>/dev/null; "
        # 4. ip rule исключение для exit-VPS (приоритет 50)
        f"ip rule show | grep -q 'to {_exit_ip}' || "
        f"ip rule add to {_exit_ip}/32 lookup main priority 50 2>/dev/null; "
        # 5. маршрут к exit-VPS через физический интерфейс
        f"ip route show | grep -q '{_exit_ip}' || "
        f"ip route add {_exit_ip}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null; "
        # 6. ip rule (policy routing fwmark)
        f"ip rule show | grep -q 'fwmark {AWG_FWMARK}' || "
        f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 2>/dev/null; "
        # 7. ip route в таблице AWG
        f"ip route show table {AWG_ROUTE_TABLE} | grep -q default || "
        f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE} 2>/dev/null"
    )
    cron_path = Path("/etc/cron.d/awg-routing")
    cron_path.write_text(reboot_script + "\n")
    os.chmod(str(cron_path), 0o644)
    _v6_status = "Dual-Stack (IPv4+IPv6)" if _ipv6_available else "IPv4-only"
    success(f"AWG: policy routing применён и сохранён ({_v6_status}, iptables + ip rule/route при ребуте)")


def _awg_ensure_sshpass() -> bool:
    """
    Проверяет наличие sshpass. При отсутствии предлагает установить через apt.
    Возвращает True если sshpass доступен после вызова, иначе False.
    """
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_row = core._box_row
    _box_top = core._box_top
    _run = core._run
    command_exists = core.command_exists
    info = core.info
    success = core.success
    warn = core.warn
    CYAN, NC, YELLOW = core.CYAN, core.NC, core.YELLOW
    if command_exists("sshpass"):
        return True
    warn("AWG: sshpass не найден — он нужен для SSH-аутентификации по паролю.")
    print()
    _box_top("Установка sshpass")
    _box_row(f"  {YELLOW}sshpass не установлен. Установить автоматически?{NC}")
    _box_item("Y", "Да — apt install sshpass")
    _box_item("N", "Нет — показать инструкцию ручной настройки")
    _box_bottom()
    try:
        _ans = input(f"  {CYAN}Установить sshpass? [Y/N, Enter=Y]:{NC} ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        _ans = "n"
    if _ans in ("", "y"):
        info("AWG: установка sshpass...")
        _r = _run(["apt-get", "install", "-y", "-q", "sshpass"],
                  check=False, quiet=True)
        if _r.returncode == 0 and command_exists("sshpass"):
            success("AWG: sshpass установлен")
            return True
        warn("AWG: не удалось установить sshpass автоматически")
    return False


def awg_setup_remote_server(
    auth_method: str = "",
    ssh_password: str = "",
) -> bool:
    """
    Устанавливает AWG-сервер на exit-VPS по SSH.

    Методы аутентификации:
      auth_method="key"      — SSH-ключ (~/.ssh/id_*), BatchMode=yes.
      auth_method="password" — пароль через sshpass; передаётся только через
                               переменную окружения SSHPASS (env=), никогда
                               не попадает в cmdline, лог или stdout.

    Если параметры не переданы — берутся из глобальных
    AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD (заполняются prompt_awg_exit_mode).

    Логика fallback:
      ключ не сработал  → предлагает ввести пароль интерактивно.
      пароль тоже нет   → _awg_print_manual_guide() + return False.

    Пароль очищается из памяти сразу после использования.
    Возвращает True при успехе, False при недоступности SSH.
    """
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_row = core._box_row
    _box_top = core._box_top
    _box_wrap_msg = core._box_wrap_msg
    info = core.info
    log_to_file = core.log_to_file
    success = core.success
    warn = core.warn
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    AWG_SSH_AUTH_METHOD = getattr(core, "AWG_SSH_AUTH_METHOD", "key")
    AWG_SSH_PASSWORD = getattr(core, "AWG_SSH_PASSWORD", "")
    AWG_SUBNET = getattr(core, "AWG_SUBNET", "10.66.66.0/24")
    AWG_SUBNET_V6 = getattr(core, "AWG_SUBNET_V6", "fd66:66:66::/64")
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))
    _AWG_REMOTE_CONF_PATH = getattr(core, "_AWG_REMOTE_CONF_PATH", "/etc/amnezia/amneziawg/awg0.conf")
    CYAN, DIM, GREEN, NC, YELLOW = core.CYAN, core.DIM, core.GREEN, core.NC, core.YELLOW
    _auth   = auth_method  if auth_method  else AWG_SSH_AUTH_METHOD
    _passwd = ssh_password if ssh_password else AWG_SSH_PASSWORD

    info(f"AWG: установка сервера на exit-VPS {AWG_EXIT_HOST} (auth={_auth})...")
    log_to_file("INFO", f"awg_setup_remote_server host={AWG_EXIT_HOST} auth={_auth}")

    # === FIX EXTRA: сброс зависших интерфейсов на exit-VPS перед установкой ===
    _awg_cleanup_stale_interfaces(target="remote", remote_host=AWG_EXIT_HOST)
    # === END FIX EXTRA ===

    # ── Ищем SSH-ключ ─────────────────────────────────────────────────────────
    ssh_key = None
    for _cand in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa",
                  "~/.ssh/id_ecdsa",   "~/.ssh/id_dsa"]:
        _kp = Path(_cand).expanduser()
        if _kp.exists():
            ssh_key = str(_kp)
            break

    # ── Общие SSH-опции ────────────────────────────────────────────────────────
    _common = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=15",
        "-o", "LogLevel=ERROR",
        "-o", "UserKnownHostsFile=/dev/null",
    ]

    # ── Готовим sshpass если нужен ────────────────────────────────────────────
    if _auth == "password" and _passwd and not _awg_ensure_sshpass():
        warn("AWG: sshpass недоступен — откат к SSH-ключу")
        _auth   = "key"
        _passwd = ""

    # ── Строим ssh/scp команды ────────────────────────────────────────────────
    if _auth == "password" and _passwd:
        # Пароль только через env SSHPASS — не в аргументах процесса
        _env      = {**os.environ, "SSHPASS": _passwd}
        _pw_extra = ["-o", "PasswordAuthentication=yes", "-o", "BatchMode=no"]
        _ssh_base = ["sshpass", "-e", "ssh", *_common, *_pw_extra]
        _scp_base = ["sshpass", "-e", "scp", *_common, *_pw_extra]
    else:
        _env      = None
        _k_extra  = (["-i", ssh_key] if ssh_key else []) + ["-o", "BatchMode=yes"]
        _ssh_base = ["ssh", *_common, *_k_extra]
        _scp_base = ["scp", *_common, *_k_extra]

    def _ssh(cmd: str, capture: bool = False, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
        """SSH к exit-VPS. Логирует только rc, не содержимое команды."""
        # timeout=120: защита от зависания при firewall-дропе пакетов.
        # ConnectTimeout=15 покрывает только фазу соединения — без общего timeout
        # subprocess может висеть бесконечно при зависшей сессии.
        try:
            _res = subprocess.run(
                [*_ssh_base, f"root@{AWG_EXIT_HOST}", cmd],
                capture_output=True, text=True, env=_env,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log_to_file("WARN", f"AWG ssh timeout (120s) для команды на {AWG_EXIT_HOST}")
            return subprocess.CompletedProcess([], 124, stdout="", stderr="timeout")
        log_to_file("DEBUG", f"AWG ssh rc={_res.returncode}")
        return _res

    def _scp(local: str, remote: str) -> subprocess.CompletedProcess:
        """SCP файла на exit-VPS."""
        _res = subprocess.run(
            [*_scp_base, local, f"root@{AWG_EXIT_HOST}:{remote}"],
            capture_output=True, text=True, env=_env,
        )
        log_to_file("DEBUG", f"AWG scp rc={_res.returncode} src={local}")
        return _res

    # ── Проверка SSH-доступа ──────────────────────────────────────────────────
    info(f"AWG: проверка SSH-соединения с {AWG_EXIT_HOST} (auth={_auth})...")
    r_test = _ssh("echo AWG_SSH_TEST_OK")
    if "AWG_SSH_TEST_OK" not in (r_test.stdout or ""):
        # Выводим причину отказа — помогает пользователю понять проблему
        _ssh_err = (r_test.stderr or "").strip()
        _ssh_rc  = r_test.returncode
        if _ssh_err:
            warn(f"AWG: SSH ошибка (rc={_ssh_rc}): {_ssh_err[:200]}")
        else:
            warn(f"AWG: SSH не ответил (rc={_ssh_rc}, stdout пуст)")
        log_to_file("WARN", f"AWG ssh test failed rc={_ssh_rc} stderr={_ssh_err[:500]!r}")

        # Единый диалог fallback для обоих методов (key и password)
        _fail_reason = "по SSH-ключу" if _auth == "key" else "по паролю"
        warn(f"AWG: SSH-подключение к {AWG_EXIT_HOST} не удалось ({_fail_reason})")
        _box_top("AWG: SSH-подключение не удалось")
        _box_row()
        _box_wrap_msg(f"  {YELLOW}", 2,
            f"Не удалось подключиться к {AWG_EXIT_HOST} {_fail_reason}.{NC}")
        if _ssh_err:
            _box_row(f"  {DIM}Причина: {_ssh_err[:120]}{NC}")
        _box_row()
        _box_item("K", f"Попробовать SSH-{GREEN}ключ{NC} (BatchMode=yes, ~/.ssh/id_*)")
        _box_item("P", f"Ввести {CYAN}пароль{NC} root и попробовать через sshpass")
        _box_item("M", "Показать инструкцию ручной настройки и продолжить")
        _box_bottom()
        try:
            _fb = input(f"  {CYAN}Выбор [K/P/M, Enter=M]:{NC} ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            _fb = "M"

        if _fb == "K":
            # Повторяем с явным ключом — сбрасываем пароль
            return awg_setup_remote_server("key", "")

        if _fb == "P":
            if not _awg_ensure_sshpass():
                warn("AWG: sshpass недоступен — установите вручную: apt-get install sshpass")
            else:
                try:
                    _tp = getpass.getpass(f"  Пароль для root@{AWG_EXIT_HOST}: ")
                except (KeyboardInterrupt, EOFError):
                    _tp = ""
                if _tp:
                    _ok = awg_setup_remote_server("password", _tp)
                    _tp = ""   # очищаем сразу
                    return _ok

        # M или любой другой ввод — показываем ручную инструкцию
        warn(f"AWG: нет SSH-доступа к {AWG_EXIT_HOST}")
        _awg_print_manual_guide()
        _passwd = ""
        return False

    info(f"AWG: SSH к {AWG_EXIT_HOST} — OK (auth={_auth})")

    # ── Подготовка модуля ядра AmneziaWG на exit-VPS ─────────────────────────
    # ВАЖНО: _ssh передаётся явным параметром ssh_fn — ensure_amneziawg_ready()
    # является глобальной функцией и не видит _ssh из closure напрямую.
    info(f"AWG: подготовка модуля ядра на exit-VPS {AWG_EXIT_HOST}...")
    try:
        ensure_amneziawg_ready(remote_host=AWG_EXIT_HOST, ssh_fn=_ssh)
    except Exception as _e:
        warn(f"AWG Remote: модуль ядра недоступен на {AWG_EXIT_HOST}: {_e}")
        _awg_print_manual_guide()
        _passwd = ""
        return False

    info("AWG: установка пакетов на exit-VPS (1-2 мин)...")
    # _remote_setup включает git clone + make amneziawg-go — может занять до 5 минут.
    # _ssh() имеет timeout=120; для сборки Go выполняем в два этапа чтобы не упасть по таймауту.
    _remote_setup_pkg = (
        "export DEBIAN_FRONTEND=noninteractive && "
        "apt-get update -q 2>/dev/null && "
        "apt-get install -y -q curl git make golang-go unzip 2>/dev/null && "
        "ARCH=$(uname -m) && "
        "if [ \"$ARCH\" = 'x86_64' ]; then AWG_ARCH_SUFFIX='ubuntu-22.04-amneziawg-tools.zip'; "
        "elif [ \"$ARCH\" = 'aarch64' ]; then AWG_ARCH_SUFFIX='ubuntu-22.04-arm64-amneziawg-tools.zip'; "
        "else echo \"[AWG] WARN: unknown arch $ARCH, trying amd64 asset\"; AWG_ARCH_SUFFIX='ubuntu-22.04-amneziawg-tools.zip'; fi && "
        "AWG_TAG=$(curl -fsSL --connect-timeout 15 https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest 2>/dev/null | grep tag_name | cut -d'\"' -f4) && "
        "if [ -n \"$AWG_TAG\" ]; then "
        "  curl -fsSL --connect-timeout 30 --retry 3 "
        "  https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${AWG_TAG}/${AWG_ARCH_SUFFIX} "
        "  -o /tmp/awg-tools.zip && "
        "  unzip -o /tmp/awg-tools.zip -d /tmp/awg-tools-ex && "
        "  find /tmp/awg-tools-ex -name 'awg' -exec cp {} /usr/local/bin/awg \\; && "
        "  find /tmp/awg-tools-ex -name 'awg-quick' -exec cp {} /usr/local/bin/awg-quick \\; && "
        "  chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick && "
        "  rm -rf /tmp/awg-tools.zip /tmp/awg-tools-ex; "
        "fi && "
        "sysctl -w net.ipv4.ip_forward=1 && "
        "sysctl -w net.ipv6.conf.all.forwarding=1 && "
        "echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-awg.conf && "
        "echo net.ipv6.conf.all.forwarding=1 >> /etc/sysctl.d/99-awg.conf && "
        "mkdir -p /etc/amnezia/amneziawg && chmod 700 /etc/amnezia/amneziawg"
    )
    _remote_setup_go = (
        # Сборка amneziawg-go вынесена отдельно — может занять до 3-4 минут
        "if [ ! -f /usr/local/bin/amneziawg-go ]; then "
        "  mkdir -p /tmp/awg-go-build && "
        "  git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go-build/src && "
        "  cd /tmp/awg-go-build/src && make && "
        "  cp /tmp/awg-go-build/src/amneziawg-go /usr/local/bin/amneziawg-go && "
        "  chmod +x /usr/local/bin/amneziawg-go && "
        "  rm -rf /tmp/awg-go-build; "
        "fi"
    )
    _ssh(_remote_setup_pkg)
    info("AWG: сборка amneziawg-go на exit-VPS (может занять 3-4 мин)...")
    # Для сборки Go увеличиваем таймаут до 360 секунд через отдельный subprocess
    try:
        subprocess.run(
            [*_ssh_base, f"root@{AWG_EXIT_HOST}", _remote_setup_go],
            capture_output=True, text=True, env=_env, timeout=360,
        )
    except subprocess.TimeoutExpired:
        warn("AWG: сборка amneziawg-go превысила 6 мин — продолжаем (может не работать userspace)")

    # ── Копируем серверный конфиг (scp → base64 fallback) ────────────────────
    import base64 as _b64
    _srv_tmpl = _AWG_CONF_DIR / "awg0-server-template.conf"

    # FIX: файл мог быть удалён awg_rollback() при предыдущей неудачной попытке.
    # Если шаблона нет — пересоздаём его через генератор (те же ключи уже в globals).
    log_to_file("DEBUG", f"AWG remote: checking template {_srv_tmpl}: "
                         f"exists={_srv_tmpl.exists()}, "
                         f"server_pubkey={AWG_SERVER_PUBKEY[:16] + '...' if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                         f"client_pubkey={AWG_CLIENT_PUBKEY[:16] + '...' if AWG_CLIENT_PUBKEY else 'EMPTY'}, "
                         f"psk={'SET' if AWG_PRESHARED_KEY else 'EMPTY'}")
    if not _srv_tmpl.exists():
        warn("AWG: awg0-server-template.conf не найден — пересоздаём из текущих параметров...")
        log_to_file("WARN", f"AWG remote: template missing, regenerating "
                            f"(pubkeys: server={AWG_SERVER_PUBKEY[:16] + '...' if AWG_SERVER_PUBKEY else 'EMPTY'}, "
                            f"client={AWG_CLIENT_PUBKEY[:16] + '...' if AWG_CLIENT_PUBKEY else 'EMPTY'})")
        try:
            _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(str(_AWG_CONF_DIR), 0o700)
            _srv_tmpl.write_text(_awg_server_conf_text())
            os.chmod(str(_srv_tmpl), 0o600)
            log_to_file("DEBUG", f"AWG remote: template regenerated OK, size={_srv_tmpl.stat().st_size}")
            success(f"AWG: серверный конфиг пересоздан → {_srv_tmpl}")
        except Exception as _regen_err:
            log_to_file("ERROR", f"AWG remote: template regen failed: {_regen_err}")
            warn(f"AWG: не удалось пересоздать серверный конфиг: {_regen_err}")
            _awg_print_manual_guide()
            _passwd = ""
            return False
    else:
        log_to_file("DEBUG", f"AWG remote: template OK, size={_srv_tmpl.stat().st_size}")

    log_to_file("DEBUG", f"AWG remote: starting scp {_srv_tmpl} → root@{AWG_EXIT_HOST}:{_AWG_REMOTE_CONF_PATH}")
    r_scp = _scp(str(_srv_tmpl), _AWG_REMOTE_CONF_PATH)
    log_to_file("DEBUG", f"AWG remote: scp rc={r_scp.returncode}, "
                         f"stderr={r_scp.stderr[:300] if r_scp.stderr else ''}")
    if r_scp.returncode != 0:
        info("AWG: scp не удался — передаём через base64/stdin...")
        log_to_file("WARN", f"AWG remote: scp failed (rc={r_scp.returncode}), falling back to base64. "
                            f"scp stderr: {r_scp.stderr[:500] if r_scp.stderr else '(empty)'}")
        try:
            _cfg_b64 = _b64.b64encode(_srv_tmpl.read_bytes()).decode()
            log_to_file("DEBUG", f"AWG remote: base64 payload ready ({len(_cfg_b64)} chars)")
        except FileNotFoundError:
            log_to_file("ERROR", f"AWG remote: template vanished between exists-check and read_bytes: {_srv_tmpl}")
            warn("AWG: серверный конфиг недоступен для передачи через base64")
            _awg_print_manual_guide()
            _passwd = ""
            return False
        r_hd = _ssh(
            f"printf '%s' '{_cfg_b64}' | base64 -d > {_AWG_REMOTE_CONF_PATH}"
            f" && chmod 600 {_AWG_REMOTE_CONF_PATH}"
        )
        log_to_file("DEBUG", f"AWG remote: base64 transfer rc={r_hd.returncode}, "
                             f"stderr={r_hd.stderr[:300] if r_hd.stderr else ''}")
        if r_hd.returncode != 0:
            log_to_file("ERROR", f"AWG remote: base64 transfer failed: {r_hd.stderr[:500]}")
            warn("AWG: не удалось передать конфиг ни через scp, ни через base64")
            _awg_print_manual_guide()
            _passwd = ""
            return False
        success("AWG: конфиг передан через base64")
    else:
        _ssh(f"chmod 600 {_AWG_REMOTE_CONF_PATH}")
        log_to_file("DEBUG", "AWG remote: scp succeeded")
        success(f"AWG: серверный конфиг скопирован → {_AWG_REMOTE_CONF_PATH}")

    # ── Systemd unit на exit-VPS (передаём через base64) ─────────────────────
    # АВТООПРЕДЕЛЕНИЕ: проверяем доступность модуля ядра на exit-VPS через SSH.
    # Если модуль загружен — WG_QUICK_USERSPACE_IMPLEMENTATION не нужен.
    _r_remote_kmod = _ssh(
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' && echo KMOD_OK || "
        "ip link add awg_probe type amneziawg 2>/dev/null && "
        "ip link delete awg_probe 2>/dev/null && echo KMOD_OK || echo KMOD_NO",
        capture=True, check=False
    )
    _remote_has_kmod = "KMOD_OK" in (_r_remote_kmod.stdout or "")
    _remote_impl = "" if _remote_has_kmod else "amneziawg-go"
    _remote_env_line = (
        f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl}"
        if _remote_impl else ""
    )
    _remote_impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl} " if _remote_impl else ""
    _remote_pre = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    if _remote_has_kmod:
        success("AWG remote: модуль ядра доступен на exit-VPS — используем kernel mode")
    else:
        info("AWG remote: модуль ядра недоступен на exit-VPS — используем userspace (amneziawg-go)")
    _unit_lines_base = [
        "[Unit]",
        "Description=AmneziaWG 2.0 server (awg0)",
        "After=network.target",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
    ]
    if _remote_env_line:
        _unit_lines_base.append(_remote_env_line)
    _unit_lines = _unit_lines_base + [
        f"ExecStartPre=/bin/bash -c '{_remote_pre}'",
        "ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_remote_impl_pfx}$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf'",
        "ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_remote_impl_pfx}$AWG_BIN down /etc/amnezia/amneziawg/awg0.conf'",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    _unit_b64 = _b64.b64encode("\n".join(_unit_lines).encode()).decode()
    r_unit = _ssh(
        f"printf '%s' '{_unit_b64}' | base64 -d"
        f" > /etc/systemd/system/amneziawg-awg0.service"
        f" && chmod 644 /etc/systemd/system/amneziawg-awg0.service"
    )
    if r_unit.returncode != 0:
        warn("AWG: не удалось создать systemd unit на exit-VPS (продолжаем)")
    else:
        success("AWG: systemd unit создан на exit-VPS")

    # ── Открываем UDP-порт ────────────────────────────────────────────────────
    _ssh(f"ufw allow {AWG_EXIT_PORT}/udp 2>/dev/null || true")
    _ssh(
        f"iptables -C INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT 2>/dev/null ||"
        f" iptables -A INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT 2>/dev/null || true"
    )
    success(f"AWG: UDP/{AWG_EXIT_PORT} открыт на exit-VPS")

    # ── Запуск AWG-сервера ────────────────────────────────────────────────────
    # BUGFIX: отключаем стандартный awg-quick@awg0.service если он есть —
    # он конкурирует с amneziawg-awg0.service за интерфейс awg0 и при старте
    # выдаёт "awg0 already exists", после чего awg show пуст (обычный wg
    # вместо amneziawg поднимает интерфейс без Jc/Jmin/Jmax параметров).
    _ssh(
        "systemctl stop awg-quick@awg0.service 2>/dev/null || true; "
        "systemctl disable awg-quick@awg0.service 2>/dev/null || true; "
        "ip link delete awg0 2>/dev/null || true"
    )
    r_start = _ssh(
        "systemctl daemon-reload && "
        "systemctl enable amneziawg-awg0.service && "
        "systemctl start amneziawg-awg0.service"
    )
    if r_start.returncode != 0:
        warn("AWG: systemd старт не удался — пробуем awg-quick напрямую...")
        r_alt = _ssh(
            "AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
            + (f"WG_QUICK_USERSPACE_IMPLEMENTATION={_remote_impl} " if _remote_impl else "")
            + "$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf 2>&1"
        )
        if r_alt.returncode != 0:
            warn(f"AWG: сервер не запустился: {(r_alt.stdout or '')[:300]}")
            log_to_file("ERROR", f"AWG remote start: {(r_alt.stdout or '')[:500]}")
            _passwd = ""
            return False

    # =============================================================================
    # ПАТЧ: Включение NAT (Masquerade) на Exit-Node (КРИТИЧНО!)
    # Без этого интернет через туннель работать не будет.
    # =============================================================================
    info("AWG Remote: включение NAT (Masquerade) для выхода в интернет...")
    
    try:
        # 1. Определяем внешний интерфейс на удаленном сервере
        get_iface_cmd = "ip -4 route | grep default | awk '{print $5}'"
        r_iface = _ssh(get_iface_cmd, capture=True, check=False)
        
        exit_iface = ""
        if r_iface.returncode == 0 and r_iface.stdout.strip():
            exit_iface = r_iface.stdout.strip()
            info(f"AWG Remote: обнаружен внешний интерфейс: {exit_iface}")
        else:
            exit_iface = "eth0" # Стандартный fallback
            warn(f"AWG Remote: не удалось определить интерфейс автоматически, используем стандартный: {exit_iface}")

        # 2. Включаем IP Forwarding (пересылку пакетов IPv4 + IPv6)
        fwd_cmd = "sysctl -w net.ipv4.ip_forward=1 && sysctl -w net.ipv6.conf.all.forwarding=1"
        _ssh(fwd_cmd, check=False, quiet=True)
        info("AWG Remote: IP Forwarding (IPv4+IPv6) включен")

        # 3. Добавляем правило IPv4 NAT (Masquerade)
        nat_cmd = f"iptables -t nat -A POSTROUTING -o {exit_iface} -j MASQUERADE"
        r_nat = _ssh(nat_cmd, check=False)

        if r_nat.returncode == 0:
            success(f"AWG Remote: IPv4 NAT успешно включен на интерфейсе {exit_iface}")
        else:
            warn(f"AWG Remote: Не удалось включить IPv4 NAT через iptables (код {r_nat.returncode}). Пробуем альтернативу...")
            # Альтернативный вариант: маскировать конкретно подсеть туннеля
            alt_nat_cmd = f"iptables -t nat -A POSTROUTING -s {AWG_SUBNET} -j MASQUERADE"
            r_alt = _ssh(alt_nat_cmd, check=False)
            if r_alt.returncode == 0:
                success("AWG Remote: IPv4 NAT включен через подсеть туннеля.")
            else:
                warn("AWG Remote: КРИТИЧЕСКАЯ ОШИБКА! IPv4 NAT не включен ни одним способом. Интернет работать не будет!")
                warn("Рекомендуется вручную выполнить команду iptables на exit-VPS.")

        # 3b. IPv6 NAT (Masquerade) — graceful: не ломаем установку при недоступности
        r_ip6check = _ssh("ip -6 route show default 2>/dev/null | head -1", capture=True, check=False, quiet=True)
        _exit_has_ipv6 = r_ip6check.returncode == 0 and bool((r_ip6check.stdout or "").strip())
        if _exit_has_ipv6:
            # Определяем IPv6 внешний интерфейс (может отличаться от IPv4)
            r_iface6 = _ssh("ip -6 route | awk '/default/ {print $5; exit}'", capture=True, check=False, quiet=True)
            exit_iface6 = (r_iface6.stdout or "").strip() or exit_iface
            nat6_cmd = f"ip6tables -t nat -A POSTROUTING -o {exit_iface6} -j MASQUERADE"
            r_nat6 = _ssh(nat6_cmd, check=False, quiet=True)
            if r_nat6.returncode == 0:
                success(f"AWG Remote: IPv6 NAT включен на интерфейсе {exit_iface6}")
            else:
                # Fallback: по ULA-подсети туннеля
                alt_nat6_cmd = f"ip6tables -t nat -A POSTROUTING -s {AWG_SUBNET_V6} -j MASQUERADE"
                r_alt6 = _ssh(alt_nat6_cmd, check=False, quiet=True)
                if r_alt6.returncode == 0:
                    success("AWG Remote: IPv6 NAT включен через подсеть туннеля.")
                else:
                    warn("AWG Remote: IPv6 NAT не включён — туннель будет работать в IPv4-only режиме")
        else:
            warn("AWG Remote: IPv6 недоступен на exit-VPS — пропускаем ip6tables NAT (IPv4-only)")

        # 4. Сохраняем правила iptables + ip6tables, чтобы они пережили перезагрузку
        _save_v6 = " && ip6tables-save > /etc/iptables/rules.v6" if _exit_has_ipv6 else ""
        save_commands = [
            "command -v netfilter-persistent >/dev/null && netfilter-persistent save",
            f"mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4{_save_v6}",
        ]
        
        saved = False
        for cmd in save_commands:
            r_save = _ssh(cmd, check=False, quiet=True)
            if r_save.returncode == 0:
                info(f"AWG Remote: правила iptables сохранены ({cmd.split()[0]})")
                saved = True
                break
        
        if not saved:
            warn("AWG Remote: не удалось сохранить правила iptables автоматически. Они могут сброситься после ребута.")

    except Exception as e:
        warn(f"AWG Remote: Ошибка при настройке NAT: {e}")
        warn("Проверьте работу NAT вручную на exit-VPS.")
    
    # =============================================================================
    # Конец патча NAT
    # =============================================================================

    # ── Верификация ───────────────────────────────────────────────────────────
    r_ver = _ssh(
        "ip link show awg0 2>/dev/null && echo IFACE_OK || echo IFACE_MISSING"
    )
    _iface_ok = "IFACE_OK" in (r_ver.stdout or "")
    if _iface_ok:
        success(f"AWG: сервер активен на {AWG_EXIT_HOST}:{AWG_EXIT_PORT}/udp")
    else:
        warn("AWG: интерфейс awg0 не обнаружен на exit-VPS после запуска")
        log_to_file("WARN", f"AWG remote iface check: {r_ver.stdout!r}")

    _passwd = ""   # очищаем пароль из памяти независимо от результата
    return _iface_ok


def _awg_print_manual_guide() -> None:
    """Выводит инструкцию по ручной настройке AWG на exit-VPS."""
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_row_auto = core._box_row_auto
    _box_top = core._box_top
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))
    CYAN, NC, YELLOW = core.CYAN, core.NC, core.YELLOW
    srv_tmpl = _AWG_CONF_DIR / "awg0-server-template.conf"
    print()
    _box_top("AWG: Ручная настройка exit-VPS")
    _box_row()
    _box_row(f"  {YELLOW}Выполните на зарубежном VPS ({AWG_EXIT_HOST}):{NC}")
    _box_row()
    _box_row(f"  {CYAN}1. Установите AmneziaWG (без PPA — через GitHub releases):{NC}")
    _box_row_auto("     apt-get install -y curl unzip git make golang-go", cont_indent="       ")
    _box_row_auto('     TAG=$(curl -fsSL https://api.github.com/repos/amnezia-vpn/amneziawg-tools/releases/latest | grep tag_name | cut -d\'"\' -f4)', cont_indent="       ")
    _box_row_auto('     curl -fsSL https://github.com/amnezia-vpn/amneziawg-tools/releases/download/${TAG}/ubuntu-22.04-amneziawg-tools.zip -o /tmp/awg.zip', cont_indent="       ")
    _box_row_auto("     unzip -o /tmp/awg.zip -d /tmp/awg-ex && find /tmp/awg-ex -name 'awg' -exec cp {} /usr/local/bin/awg \\;", cont_indent="       ")
    _box_row_auto("     find /tmp/awg-ex -name 'awg-quick' -exec cp {} /usr/local/bin/awg-quick \\; && chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick", cont_indent="       ")
    _box_row_auto("     git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git /tmp/awg-go && cd /tmp/awg-go && make", cont_indent="       ")
    _box_row_auto("     cp /tmp/awg-go/amneziawg-go /usr/local/bin/amneziawg-go && chmod +x /usr/local/bin/amneziawg-go", cont_indent="       ")
    _box_row()
    _box_row(f"  {CYAN}2. Скопируйте серверный конфиг с RU-VPS:{NC}")
    _box_row_auto(f"     scp root@<RU-VPS-IP>:{srv_tmpl} /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row()
    _box_row(f"  {CYAN}3. Откройте порт и запустите AWG:{NC}")
    _box_row(f"     ufw allow {AWG_EXIT_PORT}/udp")
    _box_row_auto("     # Если модуль ядра amneziawg загружен:", cont_indent="       ")
    _box_row_auto("     awg-quick up /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row_auto("     # Если модуль ядра недоступен (userspace):", cont_indent="       ")
    _box_row_auto("     WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /etc/amnezia/amneziawg/awg0.conf", cont_indent="       ")
    _box_row("     systemctl enable --now amneziawg-awg0.service")
    _box_row()
    _box_row(f"  {CYAN}4. Включите IP forwarding:{NC}")
    _box_row("     sysctl -w net.ipv4.ip_forward=1")
    _box_row("     echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/99-awg.conf")
    _box_bottom()


def awg_rollback() -> None:
    """Откат всех изменений AWG при ошибке установки."""
    core = _core_module()
    _run = core._run
    log_to_file = core.log_to_file
    warn = core.warn
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    _AWG_ACTIVE_CONF = getattr(core, "_AWG_ACTIVE_CONF", Path("/etc/amnezia/amneziawg/awg0.conf"))
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))
    warn("AWG: rollback — удаляем правила и конфиги...")

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    for cmd in [
        ["systemctl", "stop",    "amneziawg-awg0.service"],
        ["systemctl", "disable", "amneziawg-awg0.service"],
        ["ip", "link", "delete", AWG_INTERFACE],
        ["ip", "rule", "del", "fwmark", str(AWG_FWMARK),
         "table", str(AWG_ROUTE_TABLE)],
        ["ip", "route", "flush", "table", str(AWG_ROUTE_TABLE)],
        ["iptables", "-t", "mangle", "-D", "OUTPUT",
         "-m", "owner", "--uid-owner", str(xray_uid),
         "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
    ]:
        _run(cmd, check=False, quiet=True)

    for p in [
        _AWG_ACTIVE_CONF,
        _AWG_CONF_DIR / "awg0-server-template.conf",
        Path("/etc/systemd/system/amneziawg-awg0.service"),
        Path("/etc/cron.d/awg-routing"),
        Path("/etc/sysctl.d/99-awg.conf"),
    ]:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

    _run(["systemctl", "daemon-reload"], check=False, quiet=True)
    warn("AWG: rollback завершён")
    log_to_file("WARN", "AWG rollback completed")


def awg_verify_tunnel() -> bool:
    """
    Проверяет работоспособность AWG-туннеля послойно:
      1. Интерфейс существует (ip link show)
      2. Handshake (awg show latest-handshakes)
      3. Трафик двусторонний (awg show transfer: sent > 0 и received > 0)
      4. Ping через интерфейс до внутреннего IP exit-VPS
      5. Policy routing: ip rule fwmark + маршрут в таблице + iptables mangle
    Выводит итоговый бокс с диагнозом по каждому слою.
    Возвращает True если туннель функционален (интерфейс + routing),
    False если интерфейс не поднят.
    """
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_ok = core._box_ok
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_top = core._box_top
    _box_warn = core._box_warn
    _run = core._run
    info = core.info
    log_to_file = core.log_to_file
    AWG_BIN = getattr(core, "AWG_BIN", "awg")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    AWG_SERVER_IP = getattr(core, "AWG_SERVER_IP", "10.66.66.1/32")
    _AWG_ACTIVE_CONF = getattr(core, "_AWG_ACTIVE_CONF", Path("/etc/amnezia/amneziawg/awg0.conf"))
    DIM, GREEN, NC, RED, YELLOW = core.DIM, core.GREEN, core.NC, core.RED, core.YELLOW
    info("AWG: верификация туннеля...")
    log_to_file("DEBUG", f"awg_verify_tunnel: iface={AWG_INTERFACE} fwmark={AWG_FWMARK} "
                         f"table={AWG_ROUTE_TABLE} server_ip={AWG_SERVER_IP}")

    _ok   = f"{GREEN}✓{NC}"
    _warn = f"{YELLOW}✗{NC}"
    _skip = f"{DIM}−{NC}"

    results: list[str] = []   # строки для итогового бокса

    # ── 1. Интерфейс ─────────────────────────────────────────────────────────
    r_link = _run(["ip", "link", "show", AWG_INTERFACE], capture=True, check=False)
    iface_ok = r_link.returncode == 0
    if iface_ok:
        results.append(f"  {_ok}  Интерфейс {AWG_INTERFACE} поднят")
        log_to_file("DEBUG", f"awg_verify: iface OK")
    else:
        results.append(f"  {_warn}  Интерфейс {AWG_INTERFACE} НЕ существует")
        log_to_file("WARN", f"awg_verify: iface {AWG_INTERFACE} missing")

    # ── 2. Handshake ─────────────────────────────────────────────────────────
    handshake_ok   = False
    handshake_str  = ""
    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)

    if iface_ok and awg_bin:
        try:
            r_hs = _run([awg_bin, "show", AWG_INTERFACE, "latest-handshakes"],
                        capture=True, check=False)
            if r_hs.returncode == 0 and r_hs.stdout.strip():
                for _line in r_hs.stdout.strip().splitlines():
                    _parts = _line.split()
                    if len(_parts) >= 2:
                        try:
                            _ts = int(_parts[-1])
                        except ValueError:
                            continue
                        if _ts > 0:
                            _ago = int(time.time()) - _ts
                            _ago_str = f"{_ago}с" if _ago < 120 else f"{_ago // 60}м {_ago % 60}с"
                            handshake_ok  = True
                            handshake_str = _ago_str
                            break
                if handshake_ok:
                    _hc = GREEN if int(time.time()) - _ts < 180 else YELLOW
                    results.append(f"  {_ok}  Handshake: {_hc}{handshake_str} назад{NC}")
                    log_to_file("DEBUG", f"awg_verify: handshake OK, {handshake_str} ago")
                else:
                    results.append(f"  {_warn}  Handshake: не установлен "
                                   f"{DIM}(peer подключён?){NC}")
                    log_to_file("WARN", "awg_verify: no handshake yet")
            else:
                results.append(f"  {_warn}  Handshake: нет данных от awg show")
                log_to_file("WARN", f"awg_verify: awg show rc={r_hs.returncode}")
        except Exception as _e:
            results.append(f"  {_skip}  Handshake: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: handshake check error: {_e}")
    elif not awg_bin:
        results.append(f"  {_skip}  Handshake: awg/wg бинарник не найден")
        log_to_file("WARN", "awg_verify: no awg/wg binary for handshake check")
    else:
        results.append(f"  {_skip}  Handshake: пропущен (интерфейс не поднят)")

    # ── 3. Transfer (sent > 0 и received > 0) ────────────────────────────────
    transfer_sent = transfer_recv = 0
    if iface_ok and awg_bin:
        try:
            r_tr = _run([awg_bin, "show", AWG_INTERFACE, "transfer"],
                        capture=True, check=False)
            if r_tr.returncode == 0 and r_tr.stdout.strip():
                for _line in r_tr.stdout.strip().splitlines():
                    _parts = _line.split()
                    # формат: <pubkey> <received_bytes> <sent_bytes>
                    if len(_parts) >= 3:
                        try:
                            transfer_recv += int(_parts[1])
                            transfer_sent += int(_parts[2])
                        except ValueError:
                            pass
                def _fmt_bytes(b: int) -> str:
                    if b >= 1024 * 1024:
                        return f"{b / (1024*1024):.1f} МБ"
                    if b >= 1024:
                        return f"{b / 1024:.1f} КБ"
                    return f"{b} Б"
                if transfer_sent > 0 and transfer_recv > 0:
                    results.append(f"  {_ok}  Трафик: ↑{_fmt_bytes(transfer_sent)} "
                                   f"↓{_fmt_bytes(transfer_recv)} {DIM}(двусторонний){NC}")
                    log_to_file("DEBUG", f"awg_verify: transfer OK sent={transfer_sent} recv={transfer_recv}")
                elif transfer_sent > 0 and transfer_recv == 0:
                    results.append(f"  {_warn}  Трафик: ↑{_fmt_bytes(transfer_sent)} ↓0 "
                                   f"{YELLOW}(односторонний — закрыт входящий UDP?){NC}")
                    log_to_file("WARN", f"awg_verify: one-way tunnel sent={transfer_sent} recv=0")
                else:
                    results.append(f"  {_skip}  Трафик: нет данных "
                                   f"{DIM}(handshake ещё не прошёл){NC}")
                    log_to_file("DEBUG", "awg_verify: no transfer data yet")
        except Exception as _e:
            results.append(f"  {_skip}  Трафик: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: transfer check error: {_e}")
    else:
        results.append(f"  {_skip}  Трафик: пропущен")

    # ── 4. Ping до внутреннего IP exit-VPS через awg0 ────────────────────────
    _server_ip_raw = AWG_SERVER_IP.split("/")[0] if AWG_SERVER_IP else ""
    if iface_ok and _server_ip_raw:
        try:
            r_ping = _run(
                ["ping", "-c", "2", "-W", "3", "-I", AWG_INTERFACE, _server_ip_raw],
                capture=True, check=False
            )
            if r_ping.returncode == 0:
                _m = re.search(r"time=([\d.]+)", r_ping.stdout)
                _lat = f"{int(float(_m.group(1)))} мс" if _m else "OK"
                _lc  = GREEN if _m and float(_m.group(1)) < 150 else                        YELLOW if _m and float(_m.group(1)) < 300 else RED
                results.append(f"  {_ok}  Ping → {_server_ip_raw}: {_lc}{_lat}{NC}")
                log_to_file("DEBUG", f"awg_verify: ping {_server_ip_raw} OK lat={_lat}")
            else:
                results.append(f"  {_warn}  Ping → {_server_ip_raw}: нет ответа "
                               f"{DIM}(туннель не двусторонний?){NC}")
                log_to_file("WARN", f"awg_verify: ping {_server_ip_raw} failed rc={r_ping.returncode}")
        except Exception as _e:
            results.append(f"  {_skip}  Ping: ошибка ({_e})")
            log_to_file("WARN", f"awg_verify: ping error: {_e}")
    elif _server_ip_raw:
        results.append(f"  {_skip}  Ping: пропущен (интерфейс не поднят)")
    else:
        results.append(f"  {_skip}  Ping: AWG_SERVER_IP не задан")

    # ── 5. Policy routing ─────────────────────────────────────────────────────
    # 5a. ip rule fwmark
    r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
    _rule_txt = r_rule.stdout or ""
    fwmark_rule_ok = str(AWG_FWMARK) in _rule_txt
    if fwmark_rule_ok:
        results.append(f"  {_ok}  ip rule fwmark {AWG_FWMARK} → table {AWG_ROUTE_TABLE}")
        log_to_file("DEBUG", f"awg_verify: fwmark rule OK")
    else:
        results.append(f"  {_warn}  ip rule: fwmark {AWG_FWMARK} не найдено")
        log_to_file("WARN", f"awg_verify: fwmark {AWG_FWMARK} missing from ip rule show")

    # 5b. Маршрут в таблице
    r_rt = _run(["ip", "route", "show", "table", str(AWG_ROUTE_TABLE)],
                capture=True, check=False)
    route_ok = r_rt.returncode == 0 and bool((r_rt.stdout or "").strip())
    if route_ok:
        results.append(f"  {_ok}  Маршрут в таблице {AWG_ROUTE_TABLE}: "
                       f"{DIM}{(r_rt.stdout or '').strip()[:40]}{NC}")
        log_to_file("DEBUG", f"awg_verify: route table {AWG_ROUTE_TABLE} OK")
    else:
        results.append(f"  {_warn}  Маршрут в таблице {AWG_ROUTE_TABLE}: отсутствует")
        log_to_file("WARN", f"awg_verify: no route in table {AWG_ROUTE_TABLE}")

    # 5c. iptables mangle OUTPUT (uid xray)
    try:
        _xray_uid = pwd.getpwnam("xray").pw_uid
        r_ipt = _run(
            ["iptables", "-t", "mangle", "-C", "OUTPUT",
             "-m", "owner", "--uid-owner", str(_xray_uid),
             "-j", "MARK", "--set-mark", str(AWG_FWMARK)],
            capture=True, check=False
        )
        if r_ipt.returncode == 0:
            results.append(f"  {_ok}  iptables mangle: uid(xray={_xray_uid}) → "
                           f"mark {AWG_FWMARK}")
            log_to_file("DEBUG", "awg_verify: iptables mangle rule OK")
        else:
            results.append(f"  {_warn}  iptables mangle: правило для uid(xray) не найдено")
            log_to_file("WARN", "awg_verify: iptables mangle rule missing")
    except KeyError:
        results.append(f"  {_skip}  iptables mangle: пользователь xray не найден")
        log_to_file("WARN", "awg_verify: xray user not found for iptables check")
    except Exception as _e:
        results.append(f"  {_skip}  iptables mangle: ошибка проверки ({_e})")
        log_to_file("WARN", f"awg_verify: iptables check error: {_e}")

    # ── Итоговый бокс ─────────────────────────────────────────────────────────
    print()
    _box_top("AWG: результаты верификации")
    for _line in results:
        _box_row(_line)
    _box_sep()

    # Диагностические подсказки при проблемах
    _hints: list[str] = []
    if not iface_ok:
        _hints.append(f"journalctl -u amneziawg-awg0 -n 30")
        _hints.append(f"awg-quick up {_AWG_ACTIVE_CONF}")
    if iface_ok and not fwmark_rule_ok:
        _hints.append(f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100")
    if iface_ok and not route_ok:
        _hints.append(f"ip route add default dev {AWG_INTERFACE} table {AWG_ROUTE_TABLE}")
    if transfer_sent > 0 and transfer_recv == 0:
        _hints.append(f"# На exit-VPS: проверьте входящий UDP/{AWG_EXIT_PORT}")
        _hints.append(f"iptables -A INPUT -p udp --dport {AWG_EXIT_PORT} -j ACCEPT")

    if _hints:
        _box_warn("Команды для ручного исправления:")
        for _h in _hints:
            _box_row(f"  {DIM}{_h}{NC}")
    else:
        _box_ok("Все слои верификации пройдены")

    _box_bottom()

    if not iface_ok:
        log_to_file("WARN", "awg_verify_tunnel: FAILED — interface not up")
        return False

    log_to_file("DEBUG", "awg_verify_tunnel: OK")
    return True


def _awg_cleanup_stale_interfaces(target: str = "local", remote_host: str = None) -> None:
    """
    Принудительно удаляет все зависшие AWG-интерфейсы и очищает связанные
    ip rule/route, чтобы избежать "Interface already exists" / "File exists"
    при повторных установках.

    target="local"  — выполняется локально.
    target="remote" — выполняется на remote_host через встроенную SSH-обёртку
                      (использует AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD, как
                      в awg_setup_remote_server).
    Абсолютно идемпотентна: все команды с 2>/dev/null || true.
    """
    core = _core_module()
    _run = core._run
    info = core.info
    log_to_file = core.log_to_file
    success = core.success
    AWG_SSH_AUTH_METHOD = getattr(core, "AWG_SSH_AUTH_METHOD", "key")
    AWG_SSH_PASSWORD = getattr(core, "AWG_SSH_PASSWORD", "")
    _cleanup_bash = (
        # 1. Останавливаем сервисы
        "for i in $(seq 0 9); do "
        "systemctl stop amneziawg-awg${i}.service wg-quick@awg${i}.service 2>/dev/null || true; "
        "done; "
        # 2. Удаляем интерфейсы
        "for i in $(seq 0 9); do "
        "ip link delete dev awg${i} 2>/dev/null || true; "
        "done; "
        # 3. Flush через тип (fallback-safe)
        "ip -s link flush type amneziawg 2>/dev/null || true; "
        # 4. Удаляем конфиги и симлинки
        "rm -f /etc/amnezia/amneziawg/awg*.conf /etc/wireguard/awg*.conf 2>/dev/null || true; "
        # 5. Чистим ip rule / ip route для таблиц 1000-1009
        "for i in $(seq 0 9); do "
        "ip rule del fwmark $((1000 + i)) 2>/dev/null || true; "
        "ip -6 rule del fwmark $((1000 + i)) 2>/dev/null || true; "
        "ip route flush table $((1000 + i)) 2>/dev/null || true; "
        "ip -6 route flush table $((1000 + i)) 2>/dev/null || true; "
        "done"
    )

    if target == "remote":
        if not remote_host:
            log_to_file("WARN", "_awg_cleanup_stale_interfaces: remote_host не задан — пропуск")
            return
        info(f"AWG: очистка зависших интерфейсов на {remote_host}...")
        # Используем ту же SSH-логику что и awg_setup_remote_server:
        # строим _ssh_base из глобальных AWG_SSH_AUTH_METHOD / AWG_SSH_PASSWORD
        _auth   = AWG_SSH_AUTH_METHOD
        _passwd = AWG_SSH_PASSWORD
        _common = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15",
            "-o", "LogLevel=ERROR",
            "-o", "UserKnownHostsFile=/dev/null",
        ]
        _env = None
        if _auth == "password" and _passwd and _awg_ensure_sshpass():
            _env      = {**os.environ, "SSHPASS": _passwd}
            _ssh_base = ["sshpass", "-e", "ssh", *_common,
                         "-o", "PasswordAuthentication=yes", "-o", "BatchMode=no"]
        else:
            ssh_key = None
            for _cand in ["~/.ssh/id_ed25519", "~/.ssh/id_rsa",
                          "~/.ssh/id_ecdsa",   "~/.ssh/id_dsa"]:
                _kp = Path(_cand).expanduser()
                if _kp.exists():
                    ssh_key = str(_kp)
                    break
            _k_extra  = (["-i", ssh_key] if ssh_key else []) + ["-o", "BatchMode=yes"]
            _ssh_base = ["ssh", *_common, *_k_extra]

        try:
            r = subprocess.run(
                [*_ssh_base, f"root@{remote_host}", f"bash -c '{_cleanup_bash}'"],
                capture_output=True, text=True, env=_env, timeout=60,
            )
            if r.returncode == 0:
                success(f"AWG: remote cleanup на {remote_host} — OK")
            else:
                log_to_file("WARN",
                    f"_awg_cleanup_stale_interfaces remote rc={r.returncode}: {r.stderr[:200]}")
        except subprocess.TimeoutExpired:
            log_to_file("WARN", f"_awg_cleanup_stale_interfaces remote timeout на {remote_host}")
        except Exception as e:
            log_to_file("WARN", f"_awg_cleanup_stale_interfaces remote error: {e}")
    else:
        info("AWG: очистка зависших интерфейсов (local)...")
        r = _run(["bash", "-c", _cleanup_bash], check=False, quiet=True)
        if r.returncode == 0:
            success("AWG: local cleanup — OK")
        else:
            log_to_file("WARN",
                f"_awg_cleanup_stale_interfaces local rc={r.returncode}: {r.stderr[:200]}")


def awg_full_setup() -> None:
    """
    Точка входа — полная установка AWG в Режиме B.
    Вызывается из do_full_install() при AWG_EXIT_ENABLED == True.

    Порядок действий:
    1. Настройка клиента на RU-VPS (установка + генерация ключей + конфиги)
    2. Установка и запуск AWG-сервера на exit-VPS по SSH
    3. Поднятие AWG-туннеля (awg-quick up awg0)
    4. Применение policy routing (Xray uid → fwmark → awg0)
    5. Перезапуск Xray
    6. Верификация туннеля
    """
    core = _core_module()
    CONFIG_DIR = getattr(core, "CONFIG_DIR", None)
    PARAM_USE_DNSCRYPT = getattr(core, "PARAM_USE_DNSCRYPT", None)
    _BOX_W = getattr(core, "_BOX_W", None)
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_row_auto = core._box_row_auto
    _box_sep = core._box_sep
    _box_warn = core._box_warn
    _box_wrap_msg = core._box_wrap_msg
    _run = core._run
    _start_services_sequentially = core._start_services_sequentially
    _wcslen = getattr(core, "_wcslen", None)
    log_to_file = core.log_to_file
    success = core.success
    warn = core.warn
    AWG_EXIT_ENABLED = getattr(core, "AWG_EXIT_ENABLED", False)
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INSTALLED = getattr(core, "AWG_INSTALLED", False)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_NODES = getattr(core, "AWG_NODES", [])
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    _AWG_ACTIVE_CONF = getattr(core, "_AWG_ACTIVE_CONF", Path("/etc/amnezia/amneziawg/awg0.conf"))
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))
    BOLD, CYAN, GREEN, NC, YELLOW = core.BOLD, core.CYAN, core.GREEN, core.NC, core.YELLOW

    if not AWG_EXIT_ENABLED:
        return

    # === FIX EXTRA: сброс зависших интерфейсов перед установкой ===
    _awg_cleanup_stale_interfaces(target="local")
    # === END FIX EXTRA ===

    # ── Заголовочный бокс: голубая рамка, жёлтый жирный заголовок ────────
    print()
    _AWG_TITLE       = "AmneziaWG 2.0 — Установка"
    _AWG_TITLE_COLOR = '\033[1;33m'   # жёлтый + жирный
    _title_lpad = (_BOX_W - _wcslen(_AWG_TITLE)) // 2
    _title_rpad = _BOX_W - _wcslen(_AWG_TITLE) - _title_lpad
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    print(f"{CYAN}║{NC}{' ' * _title_lpad}{_AWG_TITLE_COLOR}{_AWG_TITLE}{NC}{' ' * _title_rpad}{CYAN}║{NC}")
    _scheme_text = f"  Схема: Клиент → Xray(RU) → awg0 → {AWG_EXIT_HOST} → Интернет"
    _scheme_pad  = max(0, _BOX_W - _wcslen(_scheme_text))
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
    print(f"{CYAN}║{NC}{_scheme_text}{' ' * _scheme_pad}{CYAN}║{NC}")
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")
    print()

    try:
        # === PATCH v2 п.6: мульти-нодовый путь (реальный код вместо заглушки) ===
        if len(AWG_NODES) > 1:
            print(f"  {YELLOW}[1/6]{NC} Установка {len(AWG_NODES)} AWG-нод (Multi-Node)...")
            if not awg_setup_all_nodes():
                warn("AWG Multi-Node: ни одна нода не настроена — прерываем")
                return

            print(f"  {YELLOW}[3/6]{NC} Поднятие всех туннелей...")
            _awg_bring_up_all_tunnels()

            print(f"  {YELLOW}[4/6]{NC} Настройка policy routing для всех нод...")
            _awg_apply_policy_routing_all_nodes()

            print(f"  {YELLOW}[4.5/6]{NC} Установка Multi-Node Watchdog...")
            try:
                awg_multinode_watchdog_install()
            except Exception as _wde:
                warn(f"AWG Multi-Node Watchdog: {_wde}")

            # === PATCH v2 п.7: строгий порядок запуска сервисов ===
            print(f"  {YELLOW}[5/6]{NC} Последовательный запуск сервисов...")
            _awg_ifaces = [n["interface"] for n in AWG_NODES]
            _start_services_sequentially(
                dnscrypt_enabled=PARAM_USE_DNSCRYPT,
                awg_interfaces=_awg_ifaces,
                xray_restart=True,
            )

            print(f"  {YELLOW}[6/6]{NC} Верификация туннелей...")
            _awg_verify_all_tunnels()
            AWG_INSTALLED = True
            setattr(core, "AWG_INSTALLED", AWG_INSTALLED)
            return   # выходим: финальный бокс single-node не нужен

        # ── SINGLE-NODE PATH (оригинальный код) ───────────────────────────────
        # ── Шаг 1: клиент на RU-VPS ───────────────────────────────────────
        print(f"  {YELLOW}[1/6]{NC} Установка AWG-клиента на RU-VPS...")
        if not awg_setup_local_client():
            warn("AWG: не удалось настроить клиент — AWG пропускается")
            return

        # ── Шаг 2: сервер на exit-VPS ─────────────────────────────────────
        print(f"  {YELLOW}[2/6]{NC} Установка AWG-сервера на {AWG_EXIT_HOST}...")
        remote_ok = awg_setup_remote_server()

        # ── Шаг 3: поднимаем туннель ──────────────────────────────────────
        print(f"  {YELLOW}[3/6]{NC} Поднятие туннеля awg0...")
        _up_impl = _awg_detect_implementation()
        _up_impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        r_up = _run(
            ["bash", "-c",
             "AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_impl_pfx}"
             "$AWG_BIN up /etc/amnezia/amneziawg/awg0.conf"],
            check=False, quiet=True
        )
        if r_up.returncode == 0:
            success("AWG: туннель awg0 поднят")
        else:
            r_chk = _run(["ip", "link", "show", "awg0"], capture=True, check=False)
            if r_chk.returncode == 0:
                success("AWG: туннель awg0 уже активен")
            else:
                warn(f"AWG: awg-quick up → rc={r_up.returncode}: {r_up.stderr[:150]}")
                log_to_file("WARN", f"awg-quick up awg0: {r_up.stderr}")

        # ── Шаг 4: policy routing ─────────────────────────────────────────
        print(f"  {YELLOW}[4/6]{NC} Настройка policy routing...")
        awg_apply_policy_routing()

        # ── Шаг 4.5: AWG Tunnel Watchdog ──────────────────────────────────
        print(f"  {YELLOW}[4.5/6]{NC} Установка watchdog мониторинга туннеля awg0...")
        try:
            awg_watchdog_install()
        except Exception as _wde:
            warn(f"AWG Watchdog: установка не критична, пропуск: {_wde}")

        # ── Шаг 5: перезапуск Xray ────────────────────────────────────────
        print(f"  {YELLOW}[5/6]{NC} Перезапуск Xray...")
        _xray_cfg_exists = (
            (CONFIG_DIR / "config.json").exists()
            or Path("/usr/local/etc/xray/config.json").exists()
        )
        if _xray_cfg_exists:
            _run(["systemctl", "restart", "xray"], check=False, quiet=True)
            time.sleep(2)
            r_xray = _run(["systemctl", "is-active", "xray"], capture=True, check=False)
            if r_xray.stdout.strip() == "active":
                success("AWG: Xray активен")
            else:
                warn("AWG: Xray не запустился — проверьте: journalctl -u xray -n 30")
        else:
            warn(
                f"AWG: конфиг Xray не найден ({CONFIG_DIR / 'config.json'}) — "
                "пропускаем перезапуск. Выполните установку Xray (пункт 1 меню) "
                "и затем перезапустите: systemctl restart xray"
            )

        # ── Шаг 6: верификация ────────────────────────────────────────────
        print(f"  {YELLOW}[6/6]{NC} Верификация...")
        awg_verify_tunnel()

        AWG_INSTALLED = True
        setattr(core, "AWG_INSTALLED", AWG_INSTALLED)

        # ── Финальный бокс — полностью зелёный ───────────────────────────
        print()
        _AWG_DONE     = "AmneziaWG 2.0 установлен и настроен"
        _done_lpad    = (_BOX_W - _wcslen(_AWG_DONE)) // 2
        _done_rpad    = _BOX_W - _wcslen(_AWG_DONE) - _done_lpad
        print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
        print(f"{CYAN}║{NC}{' ' * _done_lpad}{GREEN}{BOLD}{_AWG_DONE}{NC}{' ' * _done_rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
        # детали — через _box_row (голубые ║)
        _box_row_auto(f"  Клиентский конфиг RU-VPS:  {_AWG_ACTIVE_CONF}", cont_indent="    ")
        _box_row_auto(f"  Серверный шаблон exit-VPS: {_AWG_CONF_DIR}/awg0-server-template.conf", cont_indent="    ")
        _box_row(f"  Интерфейс:   {AWG_INTERFACE}")
        _box_row_auto(f"  Policy:      uid(xray) → mark {AWG_FWMARK} → table {AWG_ROUTE_TABLE} → {AWG_INTERFACE}", cont_indent="               ")
        if not remote_ok:
            _box_sep()
            _box_warn("Exit-VPS требует РУЧНОЙ НАСТРОЙКИ (SSH недоступен)!")
            _box_wrap_msg(
                f"  {YELLOW}", 2,
                f"Следуйте инструкции выше или запустите скрипт снова после настройки SSH.{NC}"
            )
        _box_bottom()

    except Exception as exc:
        warn(f"AWG: критическая ошибка: {exc}")
        log_to_file("ERROR", f"awg_full_setup exception: {exc}")
        try:
            awg_rollback()
        except Exception as rb:
            warn(f"AWG: ошибка rollback: {rb}")


def awg_watchdog_install(check_host: str = "1.1.1.1") -> None:
    """
    Создаёт Bash-скрипт мониторинга туннеля awg0 и cron-задачу (каждую минуту).

    Логика watchdog:
      - Туннель UP:   убеждается, что ip rule fwmark AWG_FWMARK table AWG_ROUTE_TABLE существует.
      - Туннель DOWN: удаляет это правило → трафик Xray идёт напрямую (Direct Mode).
      - Восстановление: добавляет правило обратно, логирует событие.

    Не затрагивает конфиг Xray, не перезапускает сервисы, не меняет install_mode.
    Не конфликтует с существующим xray-auto-fallback (нодовый фолбэк).
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    _AWG_WATCHDOG_CRON = getattr(core, "_AWG_WATCHDOG_CRON", Path("/etc/cron.d/awg-watchdog"))
    _AWG_WATCHDOG_LOG = getattr(core, "_AWG_WATCHDOG_LOG", Path("/var/log/awg-watchdog.log"))
    _AWG_WATCHDOG_SCRIPT = getattr(core, "_AWG_WATCHDOG_SCRIPT", Path("/usr/local/bin/awg-watchdog.sh"))
    _AWG_WATCHDOG_STATE = getattr(core, "_AWG_WATCHDOG_STATE", Path("/var/lib/xray-installer/awg-watchdog.state"))
    info("AWG Watchdog: генерация скрипта мониторинга туннеля awg0...")

    script_content = textwrap.dedent(f"""\
        #!/bin/bash
        # =============================================================================
        # AWG Tunnel Fallback Watchdog
        # Автосгенерирован Chimera Project (install_final.py)
        #
        # Проверяет ping через {AWG_INTERFACE} каждую минуту (из cron).
        # Туннель UP   → гарантирует наличие: ip rule fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE}
        # Туннель DOWN → удаляет это правило → Xray выходит напрямую (Direct Mode)
        # Восстановление → возвращает правило обратно.
        # =============================================================================

        AWG_IFACE="{AWG_INTERFACE}"
        AWG_FWMARK={AWG_FWMARK}
        AWG_ROUTE_TABLE={AWG_ROUTE_TABLE}
        RULE_PRIORITY=100
        CHECK_HOST="{check_host}"
        CHECK_TIMEOUT=3
        LOG="{_AWG_WATCHDOG_LOG}"
        STATE_FILE="{_AWG_WATCHDOG_STATE}"
        PING_COUNT=2

        ts()  {{ date '+%Y-%m-%d %H:%M:%S'; }}
        log() {{ echo "[$(ts)] $*" >> "$LOG"; }}

        # Проверка наличия ip rule (совместимо с разными версиями iproute2)
        rule_exists() {{
            ip rule show 2>/dev/null | grep -qE "fwmark (0x)?${{AWG_FWMARK}}(/0x[0-9a-f]+)? +lookup ${{AWG_ROUTE_TABLE}}"
        }}

        rule_add() {{
            if ! rule_exists; then
                ip rule add fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} priority ${{RULE_PRIORITY}} 2>/dev/null
                log "RULE ADDED: ip rule add fwmark=${{AWG_FWMARK}} table=${{AWG_ROUTE_TABLE}} priority=${{RULE_PRIORITY}}"
            fi
        }}

        rule_del() {{
            if rule_exists; then
                ip rule del fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} priority ${{RULE_PRIORITY}} 2>/dev/null || \\
                ip rule del fwmark ${{AWG_FWMARK}} table ${{AWG_ROUTE_TABLE}} 2>/dev/null
                log "RULE DELETED: ip rule del fwmark=${{AWG_FWMARK}} table=${{AWG_ROUTE_TABLE}}"
            fi
        }}

        current_state() {{
            [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "unknown"
        }}

        set_state() {{ echo "$1" > "$STATE_FILE"; }}

        # Проверка: интерфейс существует + ping проходит строго через него
        tunnel_ok() {{
            ip link show "${{AWG_IFACE}}" &>/dev/null || return 1
            ping -I "${{AWG_IFACE}}" -c ${{PING_COUNT}} -W ${{CHECK_TIMEOUT}} -q "${{CHECK_HOST}}" &>/dev/null
        }}

        # ── Основная логика ──────────────────────────────────────────────────

        PREV_STATE=$(current_state)

        if tunnel_ok; then
            # Туннель работает
            if [ "$PREV_STATE" != "up" ]; then
                log "TUNNEL UP — восстановление (предыдущее состояние: ${{PREV_STATE}})"
                rule_add
                set_state "up"
                log "DIRECT MODE OFF — трафик Xray снова маршрутизируется через ${{AWG_IFACE}}"
            else
                # Уже был up — idempotent-проверка правила
                if ! rule_exists; then
                    rule_add
                    log "RULE RESTORED (state=up, но правило отсутствовало)"
                fi
            fi
        else
            # Туннель недоступен
            if [ "$PREV_STATE" != "down" ]; then
                log "TUNNEL DOWN — ${{AWG_IFACE}} не отвечает, переключение в Direct Mode"
                rule_del
                set_state "down"
                log "DIRECT MODE ON — правило fwmark ${{AWG_FWMARK}} удалено, Xray идёт напрямую"
            fi
            # Уже был down — правило и так отсутствует, ничего не делаем
        fi
    """)

    try:
        _AWG_WATCHDOG_SCRIPT.write_text(script_content)
        _AWG_WATCHDOG_SCRIPT.chmod(0o750)
        success(f"AWG Watchdog: скрипт → {_AWG_WATCHDOG_SCRIPT}")
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи скрипта: {e}")
        return

    # Cron: каждую минуту, от root, stderr в /dev/null
    cron_line = (
        f"# AWG Tunnel Fallback Watchdog — Chimera Project\n"
        f"* * * * * root {_AWG_WATCHDOG_SCRIPT} 2>/dev/null\n"
    )
    try:
        _AWG_WATCHDOG_CRON.write_text(cron_line)
        _AWG_WATCHDOG_CRON.chmod(0o644)
        success(f"AWG Watchdog: cron → {_AWG_WATCHDOG_CRON} (каждую минуту)")
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи cron: {e}")
        return

    # Инициализируем лог
    try:
        _AWG_WATCHDOG_LOG.touch(exist_ok=True)
        _AWG_WATCHDOG_LOG.chmod(0o640)
    except Exception:
        pass

    # Сохраняем флаг в state.json
    _awg_watchdog_set_flag(True)

    info(f"AWG Watchdog: лог    → {_AWG_WATCHDOG_LOG}")
    info(f"AWG Watchdog: state  → {_AWG_WATCHDOG_STATE}")
    info(f"AWG Watchdog: ping IP  → {check_host}")


def awg_watchdog_remove() -> None:
    """Удаляет AWG Tunnel Watchdog (скрипт + cron + state-файл)."""
    core = _core_module()
    success = core.success
    _AWG_WATCHDOG_CRON = getattr(core, "_AWG_WATCHDOG_CRON", Path("/etc/cron.d/awg-watchdog"))
    _AWG_WATCHDOG_SCRIPT = getattr(core, "_AWG_WATCHDOG_SCRIPT", Path("/usr/local/bin/awg-watchdog.sh"))
    _AWG_WATCHDOG_STATE = getattr(core, "_AWG_WATCHDOG_STATE", Path("/var/lib/xray-installer/awg-watchdog.state"))
    for p in (_AWG_WATCHDOG_CRON, _AWG_WATCHDOG_SCRIPT, _AWG_WATCHDOG_STATE):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    _awg_watchdog_set_flag(False)
    success("AWG Tunnel Watchdog отключён и удалён.")


def _awg_watchdog_set_flag(enabled: bool) -> None:
    """Записывает флаг awg_tunnel_watchdog_enabled в state.json."""
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    warn = core.warn
    if not STATE_FILE.exists():
        return
    try:
        state = json.loads(STATE_FILE.read_text())
        state["awg_tunnel_watchdog_enabled"] = enabled
        STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"AWG Watchdog: ошибка записи state.json: {e}")


def do_manage_awg_watchdog() -> None:
    """
    Меню управления AWG Tunnel Watchdog.
    Доступно из _menu_security() → пункт 'W'.
    """
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    _box_back = core._box_back
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_row = core._box_row
    _box_row_auto = core._box_row_auto
    _box_sep = core._box_sep
    _box_top = core._box_top
    info = core.info
    success = core.success
    warn = core.warn
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    _AWG_WATCHDOG_CRON = getattr(core, "_AWG_WATCHDOG_CRON", Path("/etc/cron.d/awg-watchdog"))
    _AWG_WATCHDOG_LOG = getattr(core, "_AWG_WATCHDOG_LOG", Path("/var/log/awg-watchdog.log"))
    _AWG_WATCHDOG_SCRIPT = getattr(core, "_AWG_WATCHDOG_SCRIPT", Path("/usr/local/bin/awg-watchdog.sh"))
    _AWG_WATCHDOG_STATE = getattr(core, "_AWG_WATCHDOG_STATE", Path("/var/lib/xray-installer/awg-watchdog.state"))
    BLUE, CYAN, DIM, GREEN, NC, RED, YELLOW = core.BLUE, core.CYAN, core.DIM, core.GREEN, core.NC, core.RED, core.YELLOW
    while True:
        os.system("clear")
        print()
        _box_top("🔌 AWG Tunnel Watchdog — мониторинг туннеля awg0")
        _box_row()

        cron_active   = _AWG_WATCHDOG_CRON.exists()
        script_exists = _AWG_WATCHDOG_SCRIPT.exists()
        flag_enabled  = False
        cur_state     = "нет данных"

        try:
            cur_state = _AWG_WATCHDOG_STATE.read_text().strip() \
                if _AWG_WATCHDOG_STATE.exists() else "нет данных"
        except Exception:
            pass

        try:
            st = json.loads(STATE_FILE.read_text())
            flag_enabled  = st.get("awg_tunnel_watchdog_enabled", False)
            install_mode  = st.get("install_mode", "?")
        except Exception:
            install_mode  = "?"

        # Текущее состояние ip rule
        rule_present = False
        try:
            r = subprocess.run(
                ["ip", "rule", "show"], capture_output=True, text=True, check=False
            )
            rule_present = (
                str(AWG_FWMARK) in r.stdout and str(AWG_ROUTE_TABLE) in r.stdout
            )
        except Exception:
            pass

        state_color = GREEN if cur_state == "up" else (RED if cur_state == "down" else DIM)
        rule_color  = GREEN if rule_present else RED

        _box_row_auto(f"  Watchdog cron:       "
                 f"{GREEN+'активен'+NC if cron_active else YELLOW+'отключён'+NC}")
        _box_row_auto(f"  Туннель (last check):{state_color} {cur_state}{NC}")
        _box_row_auto(f"  ip rule fwmark {AWG_FWMARK}:  "
                 f"{rule_color}{'присутствует' if rule_present else 'ОТСУТСТВУЕТ (Direct Mode)'}{NC}")
        _box_row(f"  Режим Xray:          {CYAN}{install_mode}{NC}")
        _box_row_auto(f"  Флаг state.json:     "
                 f"{GREEN+'ВКЛ'+NC if flag_enabled else YELLOW+'ВЫКЛ'+NC}")
        _box_row()
        _box_row_auto(f"  {DIM}Лог: {_AWG_WATCHDOG_LOG}{NC}")
        _box_sep()

        _box_item("1", f"{'Отключить и удалить' if cron_active else 'Установить'} AWG Tunnel Watchdog")
        _box_item("2", f"Восстановить ip rule вручную  {GREEN}(включить туннельный маршрут){NC}")
        _box_item("3", f"Удалить ip rule вручную  {YELLOW}(перейти в Direct Mode){NC}")
        _box_item("T", "Запустить проверку вручную прямо сейчас")
        _box_item("L", f"Показать последние 40 строк лога")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "1":
            if cron_active:
                awg_watchdog_remove()
            else:
                if install_mode != "B":
                    warn("AWG Tunnel Watchdog актуален только при Режиме B (awg0 активен).")
                else:
                    awg_watchdog_install()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            info("Восстанавливаем ip rule вручную...")
            r = subprocess.run(
                ["ip", "rule", "add", "fwmark", str(AWG_FWMARK),
                 "table", str(AWG_ROUTE_TABLE), "priority", "100"],
                capture_output=True, text=True, check=False
            )
            try:
                _AWG_WATCHDOG_STATE.write_text("up")
            except Exception:
                pass
            if r.returncode == 0 or "File exists" in r.stderr:
                success(f"ip rule add fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} priority 100 — OK")
            else:
                warn(f"ip rule add: {r.stderr.strip()}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            warn(f"Удаляем ip rule fwmark {AWG_FWMARK} — Xray перейдёт в Direct Mode!")
            subprocess.run(
                ["ip", "rule", "del", "fwmark", str(AWG_FWMARK),
                 "table", str(AWG_ROUTE_TABLE)],
                check=False
            )
            try:
                _AWG_WATCHDOG_STATE.write_text("down")
            except Exception:
                pass
            success(f"ip rule del fwmark {AWG_FWMARK} table {AWG_ROUTE_TABLE} — OK")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "t":
            if script_exists:
                info("Запускаю watchdog вручную (bash)...")
                subprocess.run(["bash", str(_AWG_WATCHDOG_SCRIPT)], check=False)
                time.sleep(0.5)
                # Показываем последние 5 строк лога
                if _AWG_WATCHDOG_LOG.exists():
                    lines = _AWG_WATCHDOG_LOG.read_text().splitlines()[-5:]
                    print()
                    for ln in lines:
                        print(f"  {DIM}{ln}{NC}")
            else:
                warn("Скрипт watchdog не установлен. Сначала установите (пункт 1).")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "l":
            if _AWG_WATCHDOG_LOG.exists():
                lines = _AWG_WATCHDOG_LOG.read_text().splitlines()[-40:]
                print()
                print("\n".join(f"  {DIM}{ln}{NC}" for ln in lines) or "  (лог пуст)")
            else:
                print("  Лог-файл не найден.")
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор.")
            time.sleep(1)


def _awg_node_subnets(node_index: int) -> dict:
    """Уникальные сетевые параметры для ноды node_index (0-based)."""
    core = _core_module()
    n = node_index
    return {
        "interface":    f"awg{n}",
        "subnet_v4":    f"10.66.{n}.0/24",
        "client_ip":    f"10.66.{n}.2/32",
        "server_ip":    f"10.66.{n}.1/32",
        "subnet_v6":    f"fd66:{n}::/48",
        "client_ip_v6": f"fd66:{n}::2/128",
        "server_ip_v6": f"fd66:{n}::1/128",
        "fwmark":       1000 + n,
        "route_table":  1000 + n,
    }


def _awg_persist_ssh_exclusion(ssh_ip: str) -> None:
    """Сохраняет SSH-исключение в /etc/cron.d/awg-ssh-protection (переживёт ребут)."""
    core = _core_module()
    log_to_file = core.log_to_file
    if not ssh_ip:
        return
    cron_path = Path("/etc/cron.d/awg-ssh-protection")
    line = (
        f"# AWG SSH client protection — vless-installer\n"
        f"@reboot root "
        f"ip rule show | grep -q 'from {ssh_ip}' || "
        f"ip rule add from {ssh_ip}/32 lookup main priority 49 2>/dev/null\n"
    )
    try:
        cron_path.write_text(line)
        cron_path.chmod(0o644)
    except Exception as e:
        log_to_file("WARN", f"_awg_persist_ssh_exclusion: {e}")


def _awg_node_from_globals(index: int = 0) -> dict:
    """Создаёт запись ноды из текущих глобальных AWG_* переменных (fallback)."""
    core = _core_module()
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    AWG_SSH_AUTH_METHOD = getattr(core, "AWG_SSH_AUTH_METHOD", "key")
    return {
        "host":             AWG_EXIT_HOST,
        "port":             AWG_EXIT_PORT,
        "pubkey":           AWG_SERVER_PUBKEY,
        "preshared_key":    AWG_PRESHARED_KEY,
        "interface":        f"awg{index}",
        "client_ip":        f"10.66.{index}.2/32",
        "server_ip":        f"10.66.{index}.1/32",
        "client_ip_v6":     f"fd66:{index}::2/128",
        "server_ip_v6":     f"fd66:{index}::1/128",
        "subnet_v4":        f"10.66.{index}.0/24",
        "subnet_v6":        f"fd66:{index}::/48",
        "fwmark":           1000 + index,
        "route_table":      1000 + index,
        "status":           "unknown",
        "last_check":       "",
        "ssh_auth_method":  AWG_SSH_AUTH_METHOD,
    }


def _awg_load_nodes_from_state() -> list:
    """Загружает AWG_NODES из state.json."""
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    if not STATE_FILE.exists():
        return []
    try:
        st = json.loads(STATE_FILE.read_text())
        return st.get("awg_nodes", [])
    except Exception:
        return []


def _awg_save_nodes_to_state(nodes: list) -> None:
    """
    Записывает AWG_NODES в state.json через merge.
    PATCH v2: использует json.loads → dict.update → json.dumps
    чтобы не затирать другие поля state.json.
    """
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    warn = core.warn
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    _AWG_SSH_CLIENT_IP = getattr(core, "_AWG_SSH_CLIENT_IP", "")
    if not STATE_FILE.exists():
        return
    try:
        st = json.loads(STATE_FILE.read_text())
        safe = [{k: v for k, v in n.items() if k != "ssh_password"} for n in nodes]
        st.update({
            "awg_nodes":             safe,
            "awg_active_node_index": AWG_ACTIVE_NODE_INDEX,
            "awg_ssh_client_ip":     _AWG_SSH_CLIENT_IP,
        })
        STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    except Exception as e:
        warn(f"AWG: ошибка сохранения нод в state.json: {e}")


def _awg_client_conf_for_node(node: dict) -> str:
    """Генерирует текст клиентского конфига AWG для конкретной ноды.

    v5.0.0: добавлены S3, S4, I1-I5 — полный набор параметров AWG 2.0,
    как в _awg_client_conf_text() и awg_standalone.awgs_build_server_conf().
    """
    core = _core_module()
    AWG_CLIENT_PRIVKEY = getattr(core, "AWG_CLIENT_PRIVKEY", "")
    AWG_H1 = getattr(core, "AWG_H1", 1)
    AWG_H2 = getattr(core, "AWG_H2", 2)
    AWG_H3 = getattr(core, "AWG_H3", 3)
    AWG_H4 = getattr(core, "AWG_H4", 4)
    AWG_JC = getattr(core, "AWG_JC", 4)
    AWG_JMAX = getattr(core, "AWG_JMAX", 70)
    AWG_JMIN = getattr(core, "AWG_JMIN", 40)
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_S1 = getattr(core, "AWG_S1", 0)
    AWG_S2 = getattr(core, "AWG_S2", 0)
    # v5.0.0: S3/S4
    AWG_S3 = getattr(core, "AWG_S3", 0)
    AWG_S4 = getattr(core, "AWG_S4", 0)
    # v5.0.0: I1-I5
    AWG_I1 = getattr(core, "AWG_I1", "")
    AWG_I2 = getattr(core, "AWG_I2", "")
    AWG_I3 = getattr(core, "AWG_I3", "")
    AWG_I4 = getattr(core, "AWG_I4", "")
    AWG_I5 = getattr(core, "AWG_I5", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    cli_ip   = node["client_ip"]
    cli_ip6  = node["client_ip_v6"]
    srv_pub  = node.get("pubkey", AWG_SERVER_PUBKEY)
    psk      = node.get("preshared_key", AWG_PRESHARED_KEY)
    cli_priv = node.get("client_privkey", AWG_CLIENT_PRIVKEY)
    endpoint = f"{node['host']}:{node['port']}"
    # v5.2: I1-I5 через _awg_build_i_lines() (см. _awg_server_conf_text)
    _i_lines = _awg_build_i_lines(AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5)
    return (
        f"[Interface]\n"
        f"PrivateKey = {cli_priv}\n"
        f"Address = {cli_ip}, {cli_ip6}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"S3 = {AWG_S3}\n"
        f"S4 = {AWG_S4}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        f"{_i_lines}"
        f"DNS = 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111\n"
        f"Table = off\n\n"
        f"[Peer]\n"
        f"# Зарубежный VPS — AWG-сервер ({node['host']})\n"
        f"PublicKey = {srv_pub}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )


def _awg_server_conf_for_node(node: dict) -> str:
    """Генерирует текст серверного конфига AWG (для exit-VPS).

    v5.0.0: добавлены S3, S4, I1-I5 — полный набор параметров AWG 2.0.
    """
    core = _core_module()
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_H1 = getattr(core, "AWG_H1", 1)
    AWG_H2 = getattr(core, "AWG_H2", 2)
    AWG_H3 = getattr(core, "AWG_H3", 3)
    AWG_H4 = getattr(core, "AWG_H4", 4)
    AWG_JC = getattr(core, "AWG_JC", 4)
    AWG_JMAX = getattr(core, "AWG_JMAX", 70)
    AWG_JMIN = getattr(core, "AWG_JMIN", 40)
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_S1 = getattr(core, "AWG_S1", 0)
    AWG_S2 = getattr(core, "AWG_S2", 0)
    # v5.0.0: S3/S4
    AWG_S3 = getattr(core, "AWG_S3", 0)
    AWG_S4 = getattr(core, "AWG_S4", 0)
    # v5.0.0: I1-I5
    AWG_I1 = getattr(core, "AWG_I1", "")
    AWG_I2 = getattr(core, "AWG_I2", "")
    AWG_I3 = getattr(core, "AWG_I3", "")
    AWG_I4 = getattr(core, "AWG_I4", "")
    AWG_I5 = getattr(core, "AWG_I5", "")
    AWG_SERVER_PRIVKEY = getattr(core, "AWG_SERVER_PRIVKEY", "")
    iface    = node["interface"]
    srv_ip   = node["server_ip"]
    srv_ip6  = node["server_ip_v6"]
    srv_priv = node.get("server_privkey", AWG_SERVER_PRIVKEY)
    cli_pub  = node.get("client_pubkey", AWG_CLIENT_PUBKEY)
    psk      = node.get("preshared_key", AWG_PRESHARED_KEY)
    cli_ip   = node["client_ip"]
    cli_ip6  = node["client_ip_v6"]
    lport    = node["port"]
    dif = "$(ip route | awk '/default/ {print $5; exit}')"
    # v5.2: I1-I5 через _awg_build_i_lines() (см. _awg_server_conf_text)
    _i_lines = _awg_build_i_lines(AWG_I1, AWG_I2, AWG_I3, AWG_I4, AWG_I5)
    return (
        f"[Interface]\n"
        f"PrivateKey = {srv_priv}\n"
        f"Address = {srv_ip}, {srv_ip6}\n"
        f"ListenPort = {lport}\n"
        f"MTU = {AWG_MTU}\n"
        f"Jc = {AWG_JC}\nJmin = {AWG_JMIN}\nJmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\nS2 = {AWG_S2}\n"
        f"S3 = {AWG_S3}\nS4 = {AWG_S4}\n"
        f"H1 = {AWG_H1}\nH2 = {AWG_H2}\nH3 = {AWG_H3}\nH4 = {AWG_H4}\n"
        f"{_i_lines}"
        f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT; "
        f"iptables -A FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -o {dif} -j MASQUERADE; "
        f"ip6tables -A FORWARD -i {iface} -j ACCEPT; "
        f"ip6tables -A FORWARD -o {iface} -j ACCEPT; "
        f"ip6tables -t nat -A POSTROUTING -o {dif} -j MASQUERADE\n"
        f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT; "
        f"iptables -D FORWARD -o {iface} -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -o {dif} -j MASQUERADE; "
        f"ip6tables -D FORWARD -i {iface} -j ACCEPT; "
        f"ip6tables -D FORWARD -o {iface} -j ACCEPT; "
        f"ip6tables -t nat -D POSTROUTING -o {dif} -j MASQUERADE\n\n"
        f"[Peer]\n# RU-VPS (Xray client)\n"
        f"PublicKey = {cli_pub}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {cli_ip}, {cli_ip6}\n"
    )


def _awg_systemd_unit_for_node(node: dict, xray_uid: int) -> str:
    """Генерирует systemd unit для конкретной AWG-ноды с policy routing и SSH-защитой."""
    core = _core_module()
    AWG_MTU = getattr(core, "AWG_MTU", 1280)
    _AWG_SSH_CLIENT_IP = getattr(core, "_AWG_SSH_CLIENT_IP", "")
    iface   = node["interface"]
    fwmark  = node["fwmark"]
    rtable  = node["route_table"]
    mss     = AWG_MTU - 40
    conf    = f"/etc/amnezia/amneziawg/{iface}.conf"
    ssh_excl = ""
    if _AWG_SSH_CLIENT_IP:
        ssh_excl = (
            f"ip rule show | grep -q 'from {_AWG_SSH_CLIENT_IP}' || "
            f"ip rule add from {_AWG_SSH_CLIENT_IP}/32 lookup main priority 49 2>/dev/null || true; "
        )
    pr_up = (
        f"{ssh_excl}"
        f"ip rule show | grep -q 'fwmark {fwmark}' || "
        f"ip rule add fwmark {fwmark} table {rtable} priority 100 2>/dev/null || true; "
        f"ip route show table {rtable} | grep -q default || "
        f"ip route add default dev {iface} table {rtable} 2>/dev/null || true; "
        f"iptables -t mangle -C OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true; "
        f"DC_UID=$(id -u dnscrypt 2>/dev/null); "
        f"[ -n \"$DC_UID\" ] && (iptables -t mangle -C OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || "
        f"iptables -t mangle -A OUTPUT -m owner --uid-owner \"$DC_UID\" "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true) || true; "
        f"sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1; "
        f"sysctl -w net.ipv4.conf.{iface}.rp_filter=0 >/dev/null 2>&1"
    )
    pr_down = (
        f"ip route del default dev {iface} table {rtable} 2>/dev/null || true; "
        f"ip rule del fwmark {fwmark} table {rtable} 2>/dev/null || true; "
        f"iptables -t mangle -D OUTPUT -m owner --uid-owner {xray_uid} "
        f"-j MARK --set-mark {fwmark} 2>/dev/null || true"
    )
    _awg_impl = _awg_detect_implementation()
    _env_line = f"Environment=WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl}\n" if _awg_impl else ""
    _impl_pfx = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_awg_impl} " if _awg_impl else ""
    _pre = (
        "lsmod | grep -qiE 'amneziawg|amnezia.wg' || "
        "/sbin/modprobe amneziawg 2>/dev/null || "
        "/sbin/modprobe amnezia-wg 2>/dev/null || "
        "/sbin/modprobe wireguard 2>/dev/null || true"
    )
    return (
        f"[Unit]\n"
        f"Description=AmneziaWG 2.0 client ({iface}) + policy routing\n"
        f"After=network-online.target\nWants=network-online.target\n\n"
        f"[Service]\nType=oneshot\nRemainAfterExit=yes\n{_env_line}"
        f"ExecStartPre=/bin/bash -c '{_pre}'\n"
        f"ExecStart=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN up {conf}'\n"
        f"ExecStartPost=/bin/bash -c '{pr_up}'\n"
        f"ExecStop=/bin/bash -c '{pr_down}'\n"
        f"ExecStop=/bin/bash -c 'AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
        f"{_impl_pfx}$AWG_BIN down {conf}'\n\n"
        f"[Install]\nWantedBy=multi-user.target\n"
    )


def awg_setup_all_nodes() -> bool:
    """
    Настраивает все AWG-ноды из AWG_NODES.
    PATCH v2: _ensure_ssh_protection() вызывается ПЕРВОЙ.
    """
    core = _core_module()
    _ensure_ssh_protection = core._ensure_ssh_protection
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    AWG_CLIENT_IP = getattr(core, "AWG_CLIENT_IP", "10.66.66.2/32")
    AWG_CLIENT_IPv6 = getattr(core, "AWG_CLIENT_IPv6", "fd66:66:66::2/128")
    AWG_CLIENT_PRIVKEY = getattr(core, "AWG_CLIENT_PRIVKEY", "")
    AWG_CLIENT_PUBKEY = getattr(core, "AWG_CLIENT_PUBKEY", "")
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_INTERFACE = getattr(core, "AWG_INTERFACE", "awg0")
    AWG_NODES = getattr(core, "AWG_NODES", [])
    AWG_PRESHARED_KEY = getattr(core, "AWG_PRESHARED_KEY", "")
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    AWG_SERVER_IP = getattr(core, "AWG_SERVER_IP", "10.66.66.1/32")
    AWG_SERVER_IPv6 = getattr(core, "AWG_SERVER_IPv6", "fd66:66:66::1/128")
    AWG_SERVER_PRIVKEY = getattr(core, "AWG_SERVER_PRIVKEY", "")
    AWG_SERVER_PUBKEY = getattr(core, "AWG_SERVER_PUBKEY", "")
    AWG_SUBNET = getattr(core, "AWG_SUBNET", "10.66.66.0/24")
    AWG_SUBNET_V6 = getattr(core, "AWG_SUBNET_V6", "fd66:66:66::/64")
    _AWG_CONF_DIR = getattr(core, "_AWG_CONF_DIR", Path("/etc/amnezia/amneziawg"))

    if not AWG_NODES:
        AWG_NODES = [_awg_node_from_globals(0)]
        setattr(core, "AWG_NODES", AWG_NODES)

    def _sync_globals_from_node(n: dict) -> None:
        AWG_EXIT_HOST   = n["host"]
        setattr(core, "AWG_EXIT_HOST", AWG_EXIT_HOST)
        AWG_EXIT_PORT   = n["port"]
        setattr(core, "AWG_EXIT_PORT", AWG_EXIT_PORT)
        AWG_INTERFACE   = n["interface"]
        setattr(core, "AWG_INTERFACE", AWG_INTERFACE)
        AWG_SUBNET      = n["subnet_v4"]
        setattr(core, "AWG_SUBNET", AWG_SUBNET)
        AWG_CLIENT_IP   = n["client_ip"]
        setattr(core, "AWG_CLIENT_IP", AWG_CLIENT_IP)
        AWG_SERVER_IP   = n["server_ip"]
        setattr(core, "AWG_SERVER_IP", AWG_SERVER_IP)
        AWG_SUBNET_V6   = n["subnet_v6"]
        setattr(core, "AWG_SUBNET_V6", AWG_SUBNET_V6)
        AWG_CLIENT_IPv6 = n["client_ip_v6"]
        setattr(core, "AWG_CLIENT_IPv6", AWG_CLIENT_IPv6)
        AWG_SERVER_IPv6 = n["server_ip_v6"]
        setattr(core, "AWG_SERVER_IPv6", AWG_SERVER_IPv6)
        AWG_FWMARK      = n["fwmark"]
        setattr(core, "AWG_FWMARK", AWG_FWMARK)
        AWG_ROUTE_TABLE = n["route_table"]
        setattr(core, "AWG_ROUTE_TABLE", AWG_ROUTE_TABLE)

    # PATCH v2 п.3: SSH-защита ДО любых изменений маршрутов
    _ensure_ssh_protection()

    try:
        ensure_amneziawg_ready()
    except Exception as e:
        warn(f"AWG: модуль ядра недоступен: {e}")
        return False

    if not awg_install_local():
        warn("AWG: не удалось установить amneziawg-tools")
        return False

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
        warn("AWG: пользователь xray не найден — uid=0")

    _AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_AWG_CONF_DIR), 0o700)
    _wg_dir = Path("/etc/wireguard")
    _wg_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(_wg_dir), 0o700)

    any_ok = False
    for idx, node in enumerate(AWG_NODES):
        iface = node["interface"]
        info(f"AWG: настройка ноды {idx} ({iface} → {node['host']}:{node['port']})...")

        if not awg_generate_keys():
            warn(f"AWG: нода {idx}: ключи не сгенерированы — пропуск")
            continue

        node.update({
            "server_privkey": AWG_SERVER_PRIVKEY,
            "server_pubkey":  AWG_SERVER_PUBKEY,
            "client_privkey": AWG_CLIENT_PRIVKEY,
            "client_pubkey":  AWG_CLIENT_PUBKEY,
            "preshared_key":  AWG_PRESHARED_KEY,
            "pubkey":         AWG_SERVER_PUBKEY,
        })

        cli_conf_path = _AWG_CONF_DIR / f"{iface}.conf"
        cli_conf_path.write_text(_awg_client_conf_for_node(node))
        os.chmod(str(cli_conf_path), 0o600)
        success(f"AWG: клиентский конфиг → {cli_conf_path}")

        _wg_link = _wg_dir / f"{iface}.conf"
        try:
            if _wg_link.exists() or _wg_link.is_symlink():
                _wg_link.unlink()
            _wg_link.symlink_to(cli_conf_path)
        except Exception as sym_err:
            warn(f"AWG: симлинк {_wg_link}: {sym_err}")

        srv_conf_path = _AWG_CONF_DIR / f"{iface}-server-template.conf"
        srv_conf_path.write_text(_awg_server_conf_for_node(node))
        os.chmod(str(srv_conf_path), 0o600)

        svc_name = f"amneziawg-{iface}.service"
        unit_path = Path(f"/etc/systemd/system/{svc_name}")
        unit_path.write_text(_awg_systemd_unit_for_node(node, xray_uid))
        _run(["systemctl", "daemon-reload"], check=False, quiet=True)
        _run(["systemctl", "enable", svc_name], check=False, quiet=True)
        success(f"AWG: systemd unit {svc_name} создан и включён")

        _sync_globals_from_node(node)
        AWG_CLIENT_PUBKEY   = node["client_pubkey"]
        setattr(core, "AWG_CLIENT_PUBKEY", AWG_CLIENT_PUBKEY)
        AWG_SERVER_PRIVKEY  = node["server_privkey"]
        setattr(core, "AWG_SERVER_PRIVKEY", AWG_SERVER_PRIVKEY)
        AWG_PRESHARED_KEY   = node["preshared_key"]
        setattr(core, "AWG_PRESHARED_KEY", AWG_PRESHARED_KEY)
        AWG_SSH_AUTH_METHOD = node.get("ssh_auth_method", "key")
        AWG_SSH_PASSWORD    = node.get("ssh_password", "")

        info(f"AWG: нода {idx}: установка сервера на {node['host']} по SSH...")
        node["remote_ok"] = awg_setup_remote_server()
        any_ok = True

    _awg_save_nodes_to_state(AWG_NODES)

    # === FIX 4: защита от IndexError при обращении к AWG_NODES[AWG_ACTIVE_NODE_INDEX] ===
    if AWG_NODES and 0 <= AWG_ACTIVE_NODE_INDEX < len(AWG_NODES):
        _sync_globals_from_node(AWG_NODES[AWG_ACTIVE_NODE_INDEX])
    else:
        AWG_ACTIVE_NODE_INDEX = 0
        setattr(core, "AWG_ACTIVE_NODE_INDEX", AWG_ACTIVE_NODE_INDEX)
        if AWG_NODES:
            _sync_globals_from_node(AWG_NODES[0])
    # === END FIX 4 ===

    return any_ok


def _awg_bring_up_all_tunnels() -> None:
    """Поднимает все AWG-туннели."""
    core = _core_module()
    _run = core._run
    success = core.success
    warn = core.warn
    AWG_NODES = getattr(core, "AWG_NODES", [])
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    for node in nodes:
        iface = node["interface"]
        conf  = f"/etc/amnezia/amneziawg/{iface}.conf"
        _up_impl = _awg_detect_implementation()
        _up_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        r = _run(
            ["bash", "-c",
             f"AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_pfx}$AWG_BIN up {conf}"],
            check=False, quiet=True
        )
        if r.returncode == 0:
            success(f"AWG: туннель {iface} поднят")
        else:
            r_chk = _run(["ip", "link", "show", iface], capture=True, check=False)
            if r_chk.returncode == 0:
                success(f"AWG: туннель {iface} уже активен")
            else:
                warn(f"AWG: awg-quick up {iface} → rc={r.returncode}: {r.stderr[:120]}")


def _awg_apply_policy_routing_all_nodes() -> None:
    """
    Применяет policy routing для ВСЕХ нод.
    PATCH v2 п.3: _ensure_ssh_protection() вызывается первой.
    """
    core = _core_module()
    _ensure_ssh_protection = core._ensure_ssh_protection
    _run = core._run
    get_server_ip = core.get_server_ip
    success = core.success
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    AWG_NODES = getattr(core, "AWG_NODES", [])
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    active_idx = AWG_ACTIVE_NODE_INDEX

    # PATCH v2 п.3: SSH-защита ДО изменений маршрутов
    _ensure_ssh_protection()

    _server_ip  = get_server_ip("4") or ""
    _server_ip6 = get_server_ip("6") or ""
    if _server_ip:
        _run(["ip", "rule", "add", "from", f"{_server_ip}/32",
              "lookup", "main", "priority", "49"], check=False, quiet=True)
    if _server_ip6:
        _run(["ip", "-6", "rule", "add", "from", f"{_server_ip6}/128",
              "lookup", "main", "priority", "49"], check=False, quiet=True)

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    _ipv6_ok = _run(["ip", "-6", "route", "show"], capture=True, check=False, quiet=True).returncode == 0

    for idx, node in enumerate(nodes):
        iface  = node["interface"]
        fwmark = node["fwmark"]
        rtable = node["route_table"]
        host   = node["host"]

        _run(["ip", "rule", "add", "fwmark", str(fwmark),
              "table", str(rtable), "priority", "100"], check=False, quiet=True)
        _run(["ip", "route", "add", "default", "dev", iface,
              "table", str(rtable)], check=False, quiet=True)
        if _ipv6_ok:
            _run(["ip", "-6", "rule", "add", "fwmark", str(fwmark),
                  "table", str(rtable), "priority", "100"], check=False, quiet=True)
            _run(["ip", "-6", "route", "add", "default", "dev", iface,
                  "table", str(rtable)], check=False, quiet=True)
        if host:
            _run(["ip", "rule", "add", "to", f"{host}/32",
                  "lookup", "main", "priority", "50"], check=False, quiet=True)
            _run(["bash", "-c",
                  f"ip route add {host}/32 dev $(ip route | awk '/default/ {{print $5; exit}}') 2>/dev/null || true"],
                 check=False, quiet=True)

        # iptables mangle mark — только для АКТИВНОЙ ноды
        if idx == active_idx:
            _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                  "-m", "owner", "--uid-owner", str(xray_uid),
                  "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            if _ipv6_ok:
                _run(["ip6tables", "-t", "mangle", "-A", "OUTPUT",
                      "-m", "owner", "--uid-owner", str(xray_uid),
                      "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            try:
                dc_uid = pwd.getpwnam("dnscrypt").pw_uid
                _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
                      "-m", "owner", "--uid-owner", str(dc_uid),
                      "-j", "MARK", "--set-mark", str(fwmark)], check=False, quiet=True)
            except KeyError:
                pass

        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, quiet=True)
        _run(["sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0"], check=False, quiet=True)

    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r4 = _run(["iptables-save"], capture=True, check=False)
    if r4.returncode == 0:
        (rules_dir / "rules.v4").write_text(r4.stdout)
    if _ipv6_ok:
        r6 = _run(["ip6tables-save"], capture=True, check=False)
        if r6.returncode == 0:
            (rules_dir / "rules.v6").write_text(r6.stdout)
    _run(["netfilter-persistent", "save"], check=False, quiet=True)
    success(f"AWG Multi-Node: policy routing применён для {len(nodes)} нод(ы)")


def _awg_verify_all_tunnels() -> None:
    """
    Проверяет статус всех AWG-туннелей (multi-node).
    Для каждой ноды: интерфейс + handshake + ping до внутреннего IP.
    Обновляет node["status"] и сохраняет в state.
    """
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_top = core._box_top
    _run = core._run
    log_to_file = core.log_to_file
    AWG_BIN = getattr(core, "AWG_BIN", "awg")
    AWG_FWMARK = getattr(core, "AWG_FWMARK", 1000)
    AWG_NODES = getattr(core, "AWG_NODES", [])
    AWG_ROUTE_TABLE = getattr(core, "AWG_ROUTE_TABLE", 1000)
    DIM, GREEN, NC, RED, YELLOW = core.DIM, core.GREEN, core.NC, core.RED, core.YELLOW
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]
    awg_bin = AWG_BIN if awg_check_tool(AWG_BIN) else ("wg" if awg_check_tool("wg") else None)

    _ok   = f"{GREEN}✓{NC}"
    _warn = f"{YELLOW}✗{NC}"
    _skip = f"{DIM}−{NC}"

    print()
    _box_top("AWG Multi-Node: результаты верификации")

    for node in nodes:
        iface      = node["interface"]
        server_ip  = node.get("server_ip", "").split("/")[0]
        exit_host  = node.get("host", "")
        fwmark     = node.get("fwmark", AWG_FWMARK)
        route_tbl  = node.get("route_table", AWG_ROUTE_TABLE)

        _box_row(f"  {DIM}Нода: {iface} → {exit_host}{NC}")

        # Интерфейс
        r_link = _run(["ip", "link", "show", iface], capture=True, check=False)
        iface_ok = r_link.returncode == 0
        if iface_ok:
            _box_row(f"    {_ok}  Интерфейс {iface} активен")
            node["status"] = "up"
            log_to_file("DEBUG", f"_awg_verify_all: {iface} up")
        else:
            _box_row(f"    {_warn}  Интерфейс {iface} НЕ поднят")
            node["status"] = "down"
            log_to_file("WARN", f"_awg_verify_all: {iface} not found")

        # Handshake
        if iface_ok and awg_bin:
            try:
                r_hs = _run([awg_bin, "show", iface, "latest-handshakes"],
                            capture=True, check=False)
                if r_hs.returncode == 0 and r_hs.stdout.strip():
                    _hs_ok = False
                    for _line in r_hs.stdout.strip().splitlines():
                        _parts = _line.split()
                        if len(_parts) >= 2:
                            try:
                                _ts = int(_parts[-1])
                            except ValueError:
                                continue
                            if _ts > 0:
                                _ago = int(time.time()) - _ts
                                _ago_str = (f"{_ago}с" if _ago < 120
                                            else f"{_ago // 60}м {_ago % 60}с")
                                _hc = GREEN if _ago < 180 else YELLOW
                                _box_row(f"    {_ok}  Handshake: "
                                         f"{_hc}{_ago_str} назад{NC}")
                                log_to_file("DEBUG",
                                    f"_awg_verify_all: {iface} handshake {_ago_str} ago")
                                _hs_ok = True
                                break
                    if not _hs_ok:
                        _box_row(f"    {_warn}  Handshake: не установлен")
                        log_to_file("WARN", f"_awg_verify_all: {iface} no handshake")
                else:
                    _box_row(f"    {_skip}  Handshake: нет данных")
            except Exception as _e:
                _box_row(f"    {_skip}  Handshake: ошибка ({_e})")
                log_to_file("WARN", f"_awg_verify_all: {iface} handshake error: {_e}")

        # Ping до внутреннего IP exit-VPS
        if iface_ok and server_ip:
            try:
                r_ping = _run(
                    ["ping", "-c", "2", "-W", "3", "-I", iface, server_ip],
                    capture=True, check=False
                )
                if r_ping.returncode == 0:
                    _m = re.search(r"time=([\d.]+)", r_ping.stdout)
                    _lat = f"{int(float(_m.group(1)))} мс" if _m else "OK"
                    _lc  = GREEN if _m and float(_m.group(1)) < 150 else                            YELLOW if _m and float(_m.group(1)) < 300 else RED
                    _box_row(f"    {_ok}  Ping → {server_ip}: {_lc}{_lat}{NC}")
                    log_to_file("DEBUG", f"_awg_verify_all: {iface} ping {server_ip} OK")
                else:
                    _box_row(f"    {_warn}  Ping → {server_ip}: нет ответа")
                    log_to_file("WARN",
                        f"_awg_verify_all: {iface} ping {server_ip} failed")
            except Exception as _e:
                _box_row(f"    {_skip}  Ping: ошибка ({_e})")
                log_to_file("WARN", f"_awg_verify_all: {iface} ping error: {_e}")
        elif iface_ok:
            _box_row(f"    {_skip}  Ping: server_ip не задан")

        # Policy routing
        r_rule = _run(["ip", "rule", "show"], capture=True, check=False)
        if str(fwmark) in (r_rule.stdout or ""):
            _box_row(f"    {_ok}  ip rule fwmark {fwmark} → table {route_tbl}")
        else:
            _box_row(f"    {_warn}  ip rule: fwmark {fwmark} не найдено")
            log_to_file("WARN", f"_awg_verify_all: {iface} fwmark {fwmark} missing")

        node["last_check"] = datetime.now(timezone.utc).isoformat()
        _box_sep()

    _box_bottom()
    _awg_save_nodes_to_state(nodes)


def awg_multinode_watchdog_install() -> None:
    """
    Создаёт bash-скрипт мультинодового watchdog и cron-задачу.
    PATCH v2 п.2: при 1 ноде вызывает оригинальный awg_watchdog_install() — не дублирует.
    PATCH v2 п.4: switch_active_node() обновляет fwmark Xray в iptables mangle.
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    AWG_NODES = getattr(core, "AWG_NODES", [])
    _AWG_MULTINODE_FAILOVER_LOG = getattr(core, "_AWG_MULTINODE_FAILOVER_LOG", Path("/var/log/awg-failover-history.log"))
    _AWG_MULTINODE_WATCHDOG_CRON = getattr(core, "_AWG_MULTINODE_WATCHDOG_CRON", Path("/etc/cron.d/awg-multinode-watchdog"))
    _AWG_MULTINODE_WATCHDOG_LOG = getattr(core, "_AWG_MULTINODE_WATCHDOG_LOG", Path("/var/log/awg-multinode-watchdog.log"))
    _AWG_MULTINODE_WATCHDOG_SCRIPT = getattr(core, "_AWG_MULTINODE_WATCHDOG_SCRIPT", Path("/usr/local/bin/awg-multinode-watchdog.sh"))
    nodes = AWG_NODES if AWG_NODES else [_awg_node_from_globals(0)]

    # PATCH v2: при одной ноде — оригинальный watchdog, без дублирования
    if len(nodes) <= 1:
        awg_watchdog_install()
        return

    info(f"AWG Multi-Node Watchdog: генерация скрипта для {len(nodes)} нод...")

    hosts_arr   = " ".join(f'"{n["host"]}"'       for n in nodes)
    ifaces_arr  = " ".join(f'"{n["interface"]}"'  for n in nodes)
    fwmarks_arr = " ".join(str(n["fwmark"])        for n in nodes)
    rtables_arr = " ".join(str(n["route_table"])   for n in nodes)

    tg_cmd = (
        "TG_TOKEN=$(python3 -c \"import json; s=json.load(open('/etc/xray/state.json')); "
        "print(s.get('tg_bot_token',''))\" 2>/dev/null); "
        "TG_CHAT=$(python3 -c \"import json; s=json.load(open('/etc/xray/state.json')); "
        "print(s.get('tg_chat_id',''))\" 2>/dev/null); "
        "[ -n \"$TG_TOKEN\" ] && [ -n \"$TG_CHAT\" ] && "
        "curl -sS \"https://api.telegram.org/bot${TG_TOKEN}/sendMessage\" "
        "--data-urlencode \"chat_id=${TG_CHAT}\" "
        "--data-urlencode \"text=${TG_MSG}\" >/dev/null 2>&1 || true"
    )

    script = textwrap.dedent(f"""\
        #!/bin/bash
        # AWG Multi-Node Failover Watchdog — Chimera Project (patch v2)
        set -euo pipefail

        HOSTS=({hosts_arr})
        IFACES=({ifaces_arr})
        FWMARKS=({fwmarks_arr})
        RTABLES=({rtables_arr})
        NODE_COUNT=${{#HOSTS[@]}}

        ACTIVE_IDX_FILE="/var/run/awg-active-node"
        FAIL_COUNT_DIR="/var/run/awg-fail-counts"
        LOG="{_AWG_MULTINODE_WATCHDOG_LOG}"
        FAILOVER_LOG="{_AWG_MULTINODE_FAILOVER_LOG}"
        FAIL_THRESHOLD=2
        PING_COUNT=2
        PING_TIMEOUT=3

        mkdir -p "$FAIL_COUNT_DIR"
        ts()    {{ date '+%Y-%m-%d %H:%M:%S'; }}
        log()   {{ echo "[$(ts)] $*" | tee -a "$LOG"; }}
        flog()  {{ echo "[$(ts)] $*" | tee -a "$FAILOVER_LOG" >> "$LOG"; }}

        get_active() {{ [ -f "$ACTIVE_IDX_FILE" ] && cat "$ACTIVE_IDX_FILE" || echo "0"; }}
        set_active() {{ echo "$1" > "$ACTIVE_IDX_FILE"; }}

        get_fail() {{ [ -f "$FAIL_COUNT_DIR/$1" ] && cat "$FAIL_COUNT_DIR/$1" || echo "0"; }}
        set_fail() {{ echo "$2" > "$FAIL_COUNT_DIR/$1"; }}
        inc_fail() {{ local c; c=$(get_fail "$1"); set_fail "$1" $(( c + 1 )); echo $(( c + 1 )); }}
        reset_fail() {{ set_fail "$1" 0; }}

        tunnel_ok() {{
            local idx=$1
            ip link show "${{IFACES[$idx]}}" &>/dev/null || return 1
            ping -I "${{IFACES[$idx]}}" -c $PING_COUNT -W $PING_TIMEOUT -q "${{HOSTS[$idx]}}" &>/dev/null 2>&1 || \
            ping -I "${{IFACES[$idx]}}" -c $PING_COUNT -W $PING_TIMEOUT -q "1.1.1.1" &>/dev/null 2>&1
        }}

        # PATCH v2 п.4: switch_active_node обновляет fwmark Xray
        switch_active_node() {{
            local old_idx=$1 new_idx=$2
            local old_fwmark="${{FWMARKS[$old_idx]}}"
            local new_fwmark="${{FWMARKS[$new_idx]}}"
            local new_iface="${{IFACES[$new_idx]}}"
            local new_rtable="${{RTABLES[$new_idx]}}"

            flog "FAILOVER: нода $old_idx (fwmark=$old_fwmark) → нода $new_idx (fwmark=$new_fwmark)"

            # === FIX 3: идемпотентный ip rule replace вместо add (не даёт RTNETLINK: File exists) ===
            ip rule show | grep -q "fwmark ${{new_fwmark}}" || \
                ip rule replace fwmark "$new_fwmark" table "$new_rtable" priority 100 2>/dev/null || true
            ip route show table "$new_rtable" 2>/dev/null | grep -q default || \
                ip route add default dev "$new_iface" table "$new_rtable" 2>/dev/null || true
            ip -6 rule show 2>/dev/null | grep -q "fwmark ${{new_fwmark}}" || \
                ip -6 rule replace fwmark "$new_fwmark" table "$new_rtable" priority 100 2>/dev/null || true
            # === END FIX 3 ===

            XRAY_UID=$(id -u xray 2>/dev/null || echo 0)
            DC_UID=$(id -u dnscrypt 2>/dev/null || echo "")

            # Удаляем старый fwmark для xray
            iptables -t mangle -D OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            ip6tables -t mangle -D OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            [ -n "$DC_UID" ] && {{
                iptables -t mangle -D OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$old_fwmark" 2>/dev/null || true
            }} || true

            # Добавляем новый fwmark для xray
            iptables -t mangle -C OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
            iptables -t mangle -A OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            ip6tables -t mangle -C OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
            ip6tables -t mangle -A OUTPUT -m owner --uid-owner "$XRAY_UID" \
                -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            [ -n "$DC_UID" ] && {{
                iptables -t mangle -C OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$new_fwmark" 2>/dev/null || \
                iptables -t mangle -A OUTPUT -m owner --uid-owner "$DC_UID" \
                    -j MARK --set-mark "$new_fwmark" 2>/dev/null || true
            }} || true

            set_active "$new_idx"

            # Обновляем state.json через merge
            python3 -c "
import json, sys
try:
    with open('/etc/xray/state.json') as f: s = json.load(f)
    s['awg_active_node_index'] = $new_idx
    with open('/etc/xray/state.json', 'w') as f: json.dump(s, f, indent=2)
except Exception as e: sys.stderr.write(str(e))
" 2>/dev/null || true

            TG_MSG="AWG Failover: нода $old_idx (${{HOSTS[$old_idx]}}) → нода $new_idx (${{HOSTS[$new_idx]}})"
            {tg_cmd}
            flog "FAILOVER DONE → активна нода $new_idx ($new_iface)"
        }}

        ACTIVE=$(get_active)
        declare -a NODE_STATUS

        for (( i=0; i<NODE_COUNT; i++ )); do
            if tunnel_ok "$i"; then
                NODE_STATUS[$i]="up"; reset_fail "$i"
            else
                fails=$(inc_fail "$i")
                if [ "$fails" -ge "$FAIL_THRESHOLD" ]; then
                    NODE_STATUS[$i]="down"
                    log "WARN: нода $i (${{HOSTS[$i]}}) провал $fails/$FAIL_THRESHOLD"
                else
                    NODE_STATUS[$i]="warn"
                fi
            fi
        done

        if [ "${{NODE_STATUS[$ACTIVE]}}" = "down" ]; then
            log "FAILOVER TRIGGER: активная нода $ACTIVE упала"
            for (( i=0; i<NODE_COUNT; i++ )); do
                if [ "$i" -ne "$ACTIVE" ] && [ "${{NODE_STATUS[$i]}}" = "up" ]; then
                    switch_active_node "$ACTIVE" "$i"
                    ACTIVE="$i"
                    break
                fi
            done
        fi

        if [ "${{NODE_STATUS[$ACTIVE]}}" = "up" ]; then
            FWMARK="${{FWMARKS[$ACTIVE]}}"
            RTABLE="${{RTABLES[$ACTIVE]}}"
            # === FIX 3: идемпотентный replace вместо add ===
            ip rule show | grep -qE "fwmark (0x)?${{FWMARK}}.*lookup ${{RTABLE}}" || {{
                ip rule replace fwmark "$FWMARK" table "$RTABLE" priority 100 2>/dev/null || true
                log "RULE RESTORED: fwmark=$FWMARK table=$RTABLE"
            }}
            # === END FIX 3 ===
        fi
    """)

    try:
        _AWG_MULTINODE_WATCHDOG_SCRIPT.write_text(script)
        _AWG_MULTINODE_WATCHDOG_SCRIPT.chmod(0o750)
        success(f"AWG Multi-Node Watchdog: скрипт → {_AWG_MULTINODE_WATCHDOG_SCRIPT}")
    except Exception as e:
        warn(f"AWG Multi-Node Watchdog: ошибка записи скрипта: {e}")
        return

    cron_line = (
        f"# AWG Multi-Node Failover Watchdog — Chimera Project\n"
        f"* * * * * root {_AWG_MULTINODE_WATCHDOG_SCRIPT} 2>/dev/null\n"
    )
    try:
        _AWG_MULTINODE_WATCHDOG_CRON.write_text(cron_line)
        _AWG_MULTINODE_WATCHDOG_CRON.chmod(0o644)
        success(f"AWG Multi-Node Watchdog: cron → {_AWG_MULTINODE_WATCHDOG_CRON}")
    except Exception as e:
        warn(f"AWG Multi-Node Watchdog: ошибка cron: {e}")
        return

    _AWG_MULTINODE_WATCHDOG_LOG.touch(exist_ok=True)
    _AWG_MULTINODE_FAILOVER_LOG.touch(exist_ok=True)
    _awg_watchdog_set_flag(True)
    success("AWG Multi-Node Watchdog установлен")


def do_manage_awg_nodes() -> None:
    """TUI: управление пулом AWG exit-нод. Вход из _menu_security() → [N]."""
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    _box_back = core._box_back
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_top = core._box_top
    _box_warn = core._box_warn
    info = core.info
    success = core.success
    warn = core.warn
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    AWG_NODES = getattr(core, "AWG_NODES", [])
    BLUE, CYAN, GREEN, NC, RED = core.BLUE, core.CYAN, core.GREEN, core.NC, core.RED
    while True:
        os.system("clear")
        print()
        _box_top("🌐 AWG Multi-Node — Управление нодами и Failover")
        _box_row()

        nodes = _awg_load_nodes_from_state() or AWG_NODES or []
        active_idx = AWG_ACTIVE_NODE_INDEX
        try:
            st = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
            active_idx = st.get("awg_active_node_index", 0)
        except Exception:
            pass

        watchdog_data = {}
        try:
            wp = Path("/var/run/awg-multinode-state.json")
            if wp.exists():
                watchdog_data = json.loads(wp.read_text())
        except Exception:
            pass

        if not nodes:
            _box_warn("AWG-ноды не настроены. Запустите установку (Режим B + AWG).")
        else:
            _box_row(f"  Всего нод: {CYAN}{len(nodes)}{NC}   Активная: {GREEN}нода {active_idx}{NC}")
            _box_sep()
            for idx, node in enumerate(nodes):
                iface  = node.get("interface", f"awg{idx}")
                host   = node.get("host", "?")
                port   = node.get("port", 51820)
                fwmark = node.get("fwmark", 1000 + idx)
                rtable = node.get("route_table", 1000 + idx)
                r_link = subprocess.run(
                    ["ip", "link", "show", iface], capture_output=True, text=True, check=False
                )
                iface_up = r_link.returncode == 0
                wd_status = "—"
                for wn in watchdog_data.get("nodes", []):
                    if wn.get("index") == idx:
                        wd_status = wn.get("status", "—")
                        break
                is_active = (idx == active_idx)
                active_mark = f" {GREEN}[АКТИВНАЯ]{NC}" if is_active else ""
                link_col = GREEN if iface_up else RED
                link_lbl = "UP" if iface_up else "DOWN"
                _box_row(
                    f"  {CYAN}[{idx}]{NC} {iface} → {host}:{port}"
                    f"  {link_col}{link_lbl}{NC}  watchdog:{wd_status}{active_mark}"
                )
                _box_row(f"      fwmark={fwmark}  table={rtable}  {node.get('subnet_v4','?')}")

        _box_sep()
        _box_item("S", "Переключить активную ноду вручную")
        _box_item("P", "Пинг / проверка связи через каждую ноду")
        _box_item("F", "Показать историю failover")
        _box_item("W", "Управление Multi-Node Watchdog")
        _box_item("R", "Восстановить ip rule/route для всех нод")
        _box_item("I", "SSH-защита: статус и IP SSH-клиента")
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("b", "0", "q", ""):
            break
        elif ch == "s":
            if not nodes:
                warn("Нет нод."); input(f"{BLUE}Enter...{NC}"); continue
            _box_top("Переключение активной ноды")
            for idx, n in enumerate(nodes):
                mark = " ← активная" if idx == active_idx else ""
                _box_row(f"  [{idx}] {n.get('interface','?')} → {n.get('host','?')}{mark}")
            _box_bottom()
            try:
                raw = input(f"  {CYAN}Номер ноды [0-{len(nodes)-1}]:{NC} ").strip()
                new_idx = int(raw)
                if 0 <= new_idx < len(nodes):
                    _awg_manual_switch(active_idx, new_idx, nodes)
                    success(f"Переключено на ноду {new_idx}")
                else:
                    warn("Неверный номер ноды")
            except (ValueError, KeyboardInterrupt):
                warn("Отмена")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "p":
            _awg_ping_all_nodes(nodes); input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "f":
            _awg_show_failover_log(); input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "w":
            do_manage_awg_watchdog()
        elif ch == "r":
            info("Восстановление ip rule/route...")
            _awg_apply_policy_routing_all_nodes()
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "i":
            _awg_show_ssh_protection_status(); input(f"{BLUE}Нажмите Enter...{NC}")


def _awg_manual_switch(old_idx: int, new_idx: int, nodes: list) -> None:
    """Ручное переключение активной ноды: обновляет iptables mangle + state.json."""
    core = _core_module()
    _run = core._run
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    if old_idx == new_idx or new_idx >= len(nodes):
        return
    old_fwmark = nodes[old_idx]["fwmark"]
    new_fwmark = nodes[new_idx]["fwmark"]
    new_rtable = nodes[new_idx]["route_table"]
    new_iface  = nodes[new_idx]["interface"]
    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0
    _run(["iptables", "-t", "mangle", "-D", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(old_fwmark)], check=False, quiet=True)
    _run(["ip6tables", "-t", "mangle", "-D", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(old_fwmark)], check=False, quiet=True)
    _run(["iptables", "-t", "mangle", "-A", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(new_fwmark)], check=False, quiet=True)
    _run(["ip6tables", "-t", "mangle", "-A", "OUTPUT",
          "-m", "owner", "--uid-owner", str(xray_uid),
          "-j", "MARK", "--set-mark", str(new_fwmark)], check=False, quiet=True)
    _run(["ip", "rule", "add", "fwmark", str(new_fwmark),
          "table", str(new_rtable), "priority", "100"], check=False, quiet=True)
    _run(["ip", "route", "add", "default", "dev", new_iface,
          "table", str(new_rtable)], check=False, quiet=True)
    AWG_ACTIVE_NODE_INDEX = new_idx
    setattr(core, "AWG_ACTIVE_NODE_INDEX", AWG_ACTIVE_NODE_INDEX)
    _awg_save_nodes_to_state(nodes)
    try:
        Path("/var/run/awg-active-node").write_text(str(new_idx))
    except Exception:
        pass


def _awg_ping_all_nodes(nodes: list) -> None:
    """Пингует каждую ноду через её интерфейс, выводит latency."""
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_top = core._box_top
    GREEN, NC, RED = core.GREEN, core.NC, core.RED
    print()
    _box_top("AWG: проверка связи через все туннели")
    for idx, node in enumerate(nodes):
        iface = node.get("interface", f"awg{idx}")
        host  = node.get("host", "")
        if not host:
            continue
        _box_row(f"  Нода {idx} ({iface} → {host}):")
        r4 = subprocess.run(
            ["ping", "-I", iface, "-c", "3", "-W", "3", "-q", host],
            capture_output=True, text=True, check=False
        )
        if r4.returncode == 0:
            for line in r4.stdout.splitlines():
                if "rtt" in line or "avg" in line:
                    _box_row(f"    {GREEN}IPv4 OK{NC}  {line.strip()}")
                    break
        else:
            _box_row(f"    {RED}IPv4 FAIL{NC}")
    _box_bottom()


def _awg_show_failover_log() -> None:
    """Последние 50 строк лога failover."""
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_top = core._box_top
    _AWG_MULTINODE_FAILOVER_LOG = getattr(core, "_AWG_MULTINODE_FAILOVER_LOG", Path("/var/log/awg-failover-history.log"))
    print()
    _box_top(f"История Failover — {_AWG_MULTINODE_FAILOVER_LOG}")
    try:
        if _AWG_MULTINODE_FAILOVER_LOG.exists():
            for line in _AWG_MULTINODE_FAILOVER_LOG.read_text().splitlines()[-50:]:
                _box_row(f"  {line}")
        else:
            _box_row("  Лог пуст или отсутствует.")
    except Exception as e:
        _box_row(f"  Ошибка чтения лога: {e}")
    _box_bottom()


def _awg_show_ssh_protection_status() -> None:
    """Статус SSH-защиты."""
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_top = core._box_top
    _box_warn = core._box_warn
    _AWG_SSH_CLIENT_IP = getattr(core, "_AWG_SSH_CLIENT_IP", "")
    GREEN, NC, RED, YELLOW = core.GREEN, core.NC, core.RED, core.YELLOW
    print()
    _box_top("🔒 AWG SSH-защита — статус")
    ssh_ip = _AWG_SSH_CLIENT_IP
    cron_p = Path("/etc/cron.d/awg-ssh-protection")
    if not ssh_ip and cron_p.exists():
        try:
            m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", cron_p.read_text())
            if m:
                ssh_ip = m.group(1)
        except Exception:
            pass
    if ssh_ip:
        _box_row(f"  SSH-клиент IP: {GREEN}{ssh_ip}{NC}")
        r = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        rule_ok = f"from {ssh_ip}" in r.stdout
        col = GREEN if rule_ok else RED
        lbl = "ПРИСУТСТВУЕТ (priority 49)" if rule_ok else "ОТСУТСТВУЕТ — SSH может разорваться!"
        _box_row(f"  ip rule: {col}{lbl}{NC}")
    else:
        _box_warn("SSH-клиент IP не определён — защита не применена.")
    _box_row(f"  Cron (@reboot): {(GREEN+'активен'+NC) if cron_p.exists() else (YELLOW+'отсутствует'+NC)}")
    _box_bottom()


def _awg_diagnostic_all_nodes(state: dict) -> None:
    """Диагностика всех AWG-нод. Вызывается из do_full_diagnostic()."""
    core = _core_module()
    _box_row = core._box_row
    _box_sep = core._box_sep
    _AWG_SSH_CLIENT_IP = getattr(core, "_AWG_SSH_CLIENT_IP", "")
    CYAN, GREEN, NC, RED, YELLOW = core.CYAN, core.GREEN, core.NC, core.RED, core.YELLOW
    nodes = state.get("awg_nodes", [])
    active_idx = state.get("awg_active_node_index", 0)
    if not nodes:
        nodes = [{
            "interface":   state.get("awg_interface", "awg0"),
            "host":        state.get("awg_exit_host", ""),
            "fwmark":      state.get("awg_fwmark", 1000),
            "route_table": state.get("awg_route_table", 1000),
        }]
    _box_sep()
    _box_row(f"  {CYAN}AWG Multi-Node Диагностика ({len(nodes)} нод){NC}")
    for idx, node in enumerate(nodes):
        iface  = node.get("interface", f"awg{idx}")
        host   = node.get("host", "")
        fwmark = node.get("fwmark", 1000 + idx)
        rtable = node.get("route_table", 1000 + idx)
        mark = f" {GREEN}[ACT]{NC}" if idx == active_idx else ""
        r_link = subprocess.run(
            ["ip", "link", "show", iface], capture_output=True, text=True, check=False
        )
        iface_ok = r_link.returncode == 0
        iface_col = GREEN if iface_ok else RED
        _box_row(f"  Нода {idx} ({iface}){mark}: {iface_col}{'UP' if iface_ok else 'DOWN'}{NC}")
        r_rule = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        rule_ok = str(fwmark) in r_rule.stdout and str(rtable) in r_rule.stdout
        _box_row(f"    ip rule fwmark {fwmark}→table {rtable}: {(GREEN+'OK'+NC) if rule_ok else (RED+'MISSING'+NC)}")
        r_route = subprocess.run(
            ["ip", "route", "show", "table", str(rtable)],
            capture_output=True, text=True, check=False
        )
        _box_row(f"    ip route table {rtable}: {(GREEN+'OK'+NC) if 'default' in r_route.stdout else (RED+'MISSING'+NC)}")
        if host and iface_ok:
            r_ping = subprocess.run(
                ["ping", "-I", iface, "-c", "2", "-W", "3", "-q", host],
                capture_output=True, text=True, check=False
            )
            if r_ping.returncode == 0:
                for line in r_ping.stdout.splitlines():
                    if "rtt" in line or "avg" in line:
                        _box_row(f"    latency: {GREEN}{line.strip()}{NC}")
                        break
            else:
                _box_row(f"    latency: {RED}нет ответа{NC}")
    r_dc = subprocess.run(
        ["systemctl", "is-active", "dnscrypt-proxy"],
        capture_output=True, text=True, check=False
    )
    _box_row(
        f"  DNSCrypt-proxy: "
        f"{(GREEN+'активен'+NC) if r_dc.stdout.strip() == 'active' else (YELLOW+'не активен'+NC)}"
    )
    ssh_ip = state.get("awg_ssh_client_ip", "") or _AWG_SSH_CLIENT_IP
    if ssh_ip:
        r_ssh = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        ssh_ok = f"from {ssh_ip}" in r_ssh.stdout
        _box_row(f"  SSH-защита ({ssh_ip}): {(GREEN+'OK'+NC) if ssh_ok else (RED+'ОТСУТСТВУЕТ'+NC)}")


def _prompt_awg_additional_nodes() -> None:
    """
    Задаёт вопрос о добавлении дополнительных AWG-нод.
    Вызывается из prompt_awg_exit_mode() после success("Параметры AWG сохранены").
    """
    core = _core_module()
    _box_bottom = core._box_bottom
    _box_row = core._box_row
    _box_top = core._box_top
    info = core.info
    success = core.success
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    AWG_EXIT_HOST = getattr(core, "AWG_EXIT_HOST", "")
    AWG_EXIT_PORT = getattr(core, "AWG_EXIT_PORT", 51820)
    AWG_NODES = getattr(core, "AWG_NODES", [])
    AWG_SSH_AUTH_METHOD = getattr(core, "AWG_SSH_AUTH_METHOD", "key")
    CYAN, DIM, NC = core.CYAN, core.DIM, core.NC

    node0: dict = {
        "host":            AWG_EXIT_HOST,
        "port":            AWG_EXIT_PORT,
        "pubkey":          "",
        "preshared_key":   "",
        "interface":       "awg0",
        "client_ip":       "10.66.0.2/32",
        "server_ip":       "10.66.0.1/32",
        "client_ip_v6":    "fd66:0::2/128",
        "server_ip_v6":    "fd66:0::1/128",
        "subnet_v4":       "10.66.0.0/24",
        "subnet_v6":       "fd66:0::/48",
        "fwmark":          1000,
        "route_table":     1000,
        "status":          "unknown",
        "last_check":      "",
        "ssh_auth_method": AWG_SSH_AUTH_METHOD,
    }
    AWG_NODES = [node0]
    setattr(core, "AWG_NODES", AWG_NODES)

    print()
    _box_top("Дополнительные AWG exit-ноды (Multi-Node Failover)")
    _box_row(f"  {DIM}Нода 0 уже добавлена: {AWG_EXIT_HOST}:{AWG_EXIT_PORT}{NC}")
    _box_row()
    _box_row(f"  {CYAN}Хотите добавить ещё одну или несколько exit-нод?{NC}")
    _box_row(f"  {DIM}При падении активной ноды watchdog автоматически переключится.{NC}")
    _box_bottom()

    while True:
        try:
            ans = input(f"  {CYAN}Добавить ещё одну AWG exit-ноду? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break
        if ans not in ("y", "yes", "д", "да"):
            break

        n = len(AWG_NODES)
        subnets = _awg_node_subnets(n)
        print()
        _box_top(f"AWG Exit-нода №{n} (awg{n})")
        _box_row(f"  {DIM}IPv4: {subnets['subnet_v4']}  IPv6: {subnets['subnet_v6']}{NC}")
        _box_row(f"  {DIM}fwmark/table: {subnets['fwmark']}/{subnets['route_table']}{NC}")
        _box_bottom()

        new_host = ""
        while not new_host:
            try:
                new_host = input(f"  {CYAN}[N{n}-1] IP зарубежного VPS для ноды {n}:{NC} ").strip()
            except KeyboardInterrupt:
                break
        if not new_host:
            break

        raw_port = ""
        try:
            raw_port = input(f"  {CYAN}[N{n}-2] UDP-порт [{AWG_EXIT_PORT}]:{NC} ").strip()
        except KeyboardInterrupt:
            pass
        new_port = int(raw_port) if raw_port.isdigit() else AWG_EXIT_PORT

        new_ssh_method = AWG_SSH_AUTH_METHOD
        new_ssh_password = ""
        try:
            ssh_ans = input(
                f"  {CYAN}[N{n}-3] SSH-аутентификация (1=ключ, 2=пароль):{NC} "
            ).strip()
            if ssh_ans == "2":
                new_ssh_method = "password"
                new_ssh_password = getpass.getpass(f"  Пароль для root@{new_host}: ")
        except KeyboardInterrupt:
            pass

        AWG_NODES.append({
            **subnets,
            "host":            new_host,
            "port":            new_port,
            "pubkey":          "",
            "preshared_key":   "",
            "status":          "unknown",
            "last_check":      "",
            "ssh_auth_method": new_ssh_method,
            "ssh_password":    new_ssh_password,
        })
        success(f"   Нода {n} добавлена: {new_host}:{new_port}/udp  ({subnets['interface']})")

        try:
            more = input(f"  {CYAN}Добавить ещё одну ноду? [y/N]:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break
        if more not in ("y", "yes", "д", "да"):
            break

    AWG_ACTIVE_NODE_INDEX = 0
    setattr(core, "AWG_ACTIVE_NODE_INDEX", AWG_ACTIVE_NODE_INDEX)
    total = len(AWG_NODES)
    if total > 1:
        success(f"AWG Multi-Node: {total} нод(ы) настроено (failover включён)")
    else:
        info("AWG: одна нода (стандартный режим)")


def _awg_emergency_restore_all_nodes() -> None:
    """Аварийное восстановление всех AWG-нод из state.json."""
    core = _core_module()
    STATE_FILE = getattr(core, "STATE_FILE", None)
    _ensure_ssh_protection = core._ensure_ssh_protection
    _run = core._run
    info = core.info
    success = core.success
    warn = core.warn
    AWG_ACTIVE_NODE_INDEX = getattr(core, "AWG_ACTIVE_NODE_INDEX", 0)
    AWG_NODES = getattr(core, "AWG_NODES", [])
    _AWG_SSH_CLIENT_IP = getattr(core, "_AWG_SSH_CLIENT_IP", "")

    if not STATE_FILE.exists():
        warn("AWG Emergency: state.json не найден")
        return
    try:
        st = json.loads(STATE_FILE.read_text())
    except Exception as e:
        warn(f"AWG Emergency: ошибка чтения state.json: {e}")
        return

    nodes = st.get("awg_nodes", [])
    if not nodes:
        warn("AWG Emergency: awg_nodes пустой — одиночный режим")
        return

    AWG_NODES = nodes
    setattr(core, "AWG_NODES", AWG_NODES)
    AWG_ACTIVE_NODE_INDEX = st.get("awg_active_node_index", 0)
    setattr(core, "AWG_ACTIVE_NODE_INDEX", AWG_ACTIVE_NODE_INDEX)
    _AWG_SSH_CLIENT_IP = st.get("awg_ssh_client_ip", "")
    setattr(core, "_AWG_SSH_CLIENT_IP", _AWG_SSH_CLIENT_IP)

    info(f"AWG Emergency: восстанавливаем {len(nodes)} нод(ы)...")
    _ensure_ssh_protection()

    try:
        xray_uid = pwd.getpwnam("xray").pw_uid
    except KeyError:
        xray_uid = 0

    for idx, node in enumerate(nodes):
        iface = node.get("interface", f"awg{idx}")
        conf  = f"/etc/amnezia/amneziawg/{iface}.conf"

        if node.get("client_privkey") and node.get("server_pubkey"):
            try:
                Path(conf).write_text(_awg_client_conf_for_node(node))
                Path(conf).chmod(0o600)
                success(f"AWG Emergency: конфиг {conf} восстановлен")
            except Exception as e:
                warn(f"AWG Emergency: {conf}: {e}")
        else:
            warn(f"AWG Emergency: нода {idx} — ключи не найдены")

        svc = f"amneziawg-{iface}.service"
        unit_path = Path(f"/etc/systemd/system/{svc}")
        if not unit_path.exists():
            unit_path.write_text(_awg_systemd_unit_for_node(node, xray_uid))
            _run(["systemctl", "daemon-reload"], check=False, quiet=True)
            _run(["systemctl", "enable", svc], check=False, quiet=True)
            success(f"AWG Emergency: unit {svc} восстановлен")

        _up_impl = _awg_detect_implementation()
        _up_pfx  = f"WG_QUICK_USERSPACE_IMPLEMENTATION={_up_impl} " if _up_impl else ""
        _run(
            ["bash", "-c",
             f"AWG_BIN=$(command -v awg-quick || echo /usr/local/bin/awg-quick); "
             f"{_up_pfx}$AWG_BIN up {conf}"],
            check=False, quiet=True
        )

    _awg_apply_policy_routing_all_nodes()
    success(f"AWG Emergency: завершено ({len(nodes)} нод)")
