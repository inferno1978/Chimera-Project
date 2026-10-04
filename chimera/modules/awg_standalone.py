"""
chimera/modules/awg_standalone.py
───────────────────────────────────────────────────────────────────────────────
Главный модуль AmneziaWG 2.0 standalone-режима.

Полный цикл:
  • Конфликт-чек (chain Mode B, занятость awg0, порта, конфига)
  • Установка DKMS-модуля + awg-tools (PPA для Ubuntu / DKMS для Debian)
  • Генерация ключей сервера + первичного клиента
  • Генерация awg0.conf с выбранным carrier-пресетом
  • Idempotent sysctl + swap + NIC tuning (через awg_hw_tuning)
  • Firewall: открыть только UDP-порт AWG (без переделки deny-all)
  • Systemd-юнит awg-quick@awg0.service
  • TUI-меню управления

Это АВТОНОМНЫЙ модуль — НЕ переиспользует globals AWG_* из _core.py.
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from .awg_constants import (
    AWGS_INTERFACE, AWGS_DEFAULT_PORT, AWGS_DEFAULT_SUBNET,
    AWGS_DEFAULT_SUBNET_V6, AWGS_DEFAULT_MTU,
    AWGS_CONF_DIR, AWGS_SERVER_CONF, AWGS_AWG_DIR, AWGS_KEYS_DIR,
    AWGS_INIT_FILE, AWGS_LOG_FILE, AWGS_BACKUP_DIR,
    AWGS_BIN, AWGS_QUICK_BIN, AWGS_SYSTEMD_AWG_QUICK,
    AWGS_DEFAULT_PARAMS,
    AWGS_PORT_MIN, AWGS_PORT_MAX,
    AWGS_DEFAULT_PROTOCOL_VERSION,
)
from .awg_state import (
    awgs_state_load, awgs_state_save, awgs_state_init,
    awgs_state_is_installed, awgs_state_update,
)
from .awg_presets import (
    awgs_presets_list, awgs_presets_get, awgs_presets_generate,
    awgs_presets_validate_params,
)
from .awg_hw_tuning import awgs_hw_tune_all
from .awg_apply import awgs_apply, awgs_service_status
from .awg_net_common import (
    iptables_ensure,
    build_nat_rule_args,
    build_nat_idempotent_shell,
    build_nat_cleanup_shell,
    build_sysctl_lines,
    apply_rp_filter_per_iface,
    apply_ip_forward,
    write_sysctl_conf,
    detect_wan_iface as _awg_net_detect_wan_iface,
    RP_FILTER_DEFAULT,
)


def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


# ============================================================================
#  КОНФЛИКТ-ЧЕК
# ============================================================================

def awgs_check_conflicts(port: int = AWGS_DEFAULT_PORT) -> list:
    """
    Проверяет конфликты перед установкой standalone AWG.
    Возвращает список строк-конфликтов (пустой = установка безопаса).
    """
    core = _core_module()
    conflicts = []

    # 1. Конфликт с chain Mode B (Chimera Project)
    vless_state = Path("/var/lib/xray-installer/state.json")
    if vless_state.exists():
        try:
            import json
            st = json.loads(vless_state.read_text())
            if st.get("awg_exit_enabled") and st.get("install_mode") == "B":
                conflicts.append(
                    "На этом сервере уже настроен AWG-транспорт для Mode B "
                    "(chain RU→зарубеж). Standalone AWG нельзя ставить сюда — "
                    "будет конфликт интерфейса awg0 и конфига /etc/amnezia/amneziawg/awg0.conf."
                )
        except Exception:
            pass

    # 2. Конфликт интерфейса awg0
    r = core._run(["ip", "link", "show", AWGS_INTERFACE], capture=True, check=False)
    if r.returncode == 0:
        conflicts.append(
            f"Интерфейс {AWGS_INTERFACE} уже существует. Это может быть chain Mode B "
            f"или ручная установка AWG. Standalone AWG требует чистый awg0."
        )

    # 3. Конфликт порта — общесистемная проверка через ss
    r = core._run(["ss", "-ulnp"], capture=True, check=False)
    if r.returncode == 0 and f":{port} " in r.stdout:
        conflicts.append(
            f"UDP-порт {port} уже занят. Укажите другой --port "
            f"(доступные: 51820-51830, 11100 не использовать — занят chain)."
        )

    # 3.1 Конфликт порта — кросс-модульная проверка через state-файлы.
    # Проверяет, не занят ли этот порт другим автономным протокол-модулем
    # проекта (Hysteria2, Mieru, NaiveProxy, WDTT, TurnTunnel, Turnable,
    # OLCrtc, SlipGate, FPTN, VLESS Mode B). ss не видит будущих портов
    # (если модуль установлен но сервис остановлен), поэтому state.json —
    # единственный надёжный источник для preemptive-конфликта.
    try:
        other_proto_conflict = core.check_port_used_by_other_protocol(
            port, exclude_module="vless_state"
        )
        # exclude_module="vless_state" — потому что конфликт с Mode B chain
        # уже проверен в шаге 1 выше (через awg_exit_enabled + install_mode == "B"),
        # и он выдаёт более информативное сообщение. Если Mode B не активен
        # (awg_exit_enabled=False), но в state.json остались awg_exit_port
        # записи — формальный конфликт по порту возможен, но это не блокирует
        # standalone (старый AWG chain удалён). Поэтому пропускаем.
        if other_proto_conflict:
            conflicts.append(other_proto_conflict)
    except AttributeError:
        # core.check_port_used_by_other_protocol может отсутствовать в
        # старых версиях _core.py при работе из cron — silently skip.
        pass
    except Exception:
        pass

    # 4. Конфликт конфига
    if AWGS_SERVER_CONF.exists():
        conflicts.append(
            f"Конфиг {AWGS_SERVER_CONF} уже существует. "
            f"Удалите его (awg_uninstall) или используйте --force для перезаписи."
        )

    # 5. Уже установлен standalone
    if awgs_state_is_installed():
        conflicts.append(
            "Standalone AWG уже установлен (state.json существует). "
            "Используйте 'Удалить' перед повторной установкой."
        )

    return conflicts


# ============================================================================
#  УСТАНОВКА DKMS-МОДУЛЯ
# ============================================================================

def awgs_detect_os() -> dict:
    """Возвращает {distro, version, codename}."""
    core = _core_module()
    info = {"distro": "", "version": "", "codename": ""}
    try:
        r = core._run(["cat", "/etc/os-release"], capture=True, check=False)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.startswith("ID="):
                    info["distro"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    info["version"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_CODENAME="):
                    info["codename"] = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return info


def awgs_kmod_already_ready() -> bool:
    """v5.4.5: бинарники awg/awg-quick + рабочий kmod уже в системе?

    Реальный кейс (E2E 2026-10-03, 138x): пакеты amneziawg-tools/-dkms
    установлены ранее, но PPA/keyserver недоступны (падение DNS) —
    инсталлер падал, хотя ВСЁ уже стоит. Идемпотентная установка
    обязана замечать готовую систему и не требовать сети.
    """
    core = _core_module()
    awg_bin = core._run(["which", AWGS_BIN], capture=True, check=False).stdout.strip()
    awg_quick = core._run(["which", AWGS_QUICK_BIN], capture=True, check=False).stdout.strip()
    if not (awg_bin and awg_quick):
        return False
    core._run(["modprobe", "amnezia"], check=False, quiet=True)
    probe = core._run(
        ["bash", "-c",
         "ip link add test_awg0 type amneziawg 2>/dev/null && "
         "ip link del test_awg0 && echo KMOD_OK"],
        capture=True, check=False)
    return "KMOD_OK" in (probe.stdout or "")


def _awgs_apt_repair() -> bool:
    """
    Автовосстановление сломанного состояния apt (dpkg/зависимости).

    Кейс из продакшена (host1889848, Ubuntu 24.04, 2026-10-04): установка
    падает с
      'E: Unmet dependencies. Try "apt --fix-broken install" with no
       packages (or specify a solution).'
    из-за полусобранных пакетов от прерванной ранее установки. Не путать с
    _awgs_apt_lock_heal() (висячие ЛОКИ — там kill процессов, здесь —
    чиним dpkg-состояние).
    apt сам подсказывает решение — выполняем его автоматически:
      0. _awgs_apt_lock_heal() — снять висячий лок, иначе dpkg молча упадёт
      1. dpkg --configure -a   (безопасно: донастраивает полусобранные)
      2. apt-get -f install -y (чинит зависимости; ставит недостающее)
    Возвращает True, если apt-get check после ремонта проходит.
    """
    core = _core_module()
    core.warn("Сломанные зависимости apt — запускаю авто-восстановление "
              "(dpkg --configure -a + apt --fix-broken)...")
    _awgs_apt_lock_heal()  # лок может держать полусобранный dpkg-процесс
    core._run(["dpkg", "--configure", "-a"],
              capture=True, check=False, quiet=True)
    r = core._run(["apt-get", "--fix-broken", "install", "-y"],
                  capture=True, check=False, quiet=True)
    if r.returncode != 0:
        core.log_to_file("WARN",
                         f"apt --fix-broken rc={r.returncode}: "
                         f"{((r.stderr or '') + (r.stdout or ''))[-400:]}")
    # Верификация: apt-get check должен пройти
    r = core._run(["apt-get", "check"], capture=True, check=False, quiet=True)
    ok = r.returncode == 0
    if ok:
        core.success("Зависимости apt восстановлены")
    else:
        core.warn("Авто-восстановление apt не помогло — продолжаем с fallback'ами")
    return ok


def _awgs_apt_install(pkg: str) -> bool:
    """
    apt-get install с авто-восстановлением broken-зависимостей и ретраем.
    Возвращает True, если пакет реально установлен (which-проверка не входит —
    проверяется код возврата apt).
    """
    core = _core_module()
    r = core._run(["apt-get", "install", "-y", pkg],
                  capture=True, check=False, quiet=True)
    if r.returncode == 0:
        return True
    err = (r.stderr or "") + (r.stdout or "")
    core.log_to_file("WARN", f"apt install {pkg}: {err[-300:]}")
    # Ретрай после ремонта: чинит 'E: Unmet dependencies' на VPS
    # с полусобранными пакетами (типовой кейс на свежих VPS-шаблонах)
    if ("Unmet dependencies" in err or "fix-broken" in err
            or "unmet dependencies" in err.lower()):
        _awgs_apt_repair()
        r2 = core._run(["apt-get", "install", "-y", pkg],
                       capture=True, check=False, quiet=True)
        if r2.returncode == 0:
            core.success(f"Пакет {pkg} установлен после авто-восстановления apt")
            return True
        core.log_to_file("WARN", f"apt install {pkg} retry: {(r2.stderr or '')[-300:]}")
    return False


def awgs_install_dkms() -> bool:
    """
    Устанавливает amneziawg-tools + DKMS kernel module через PPA amnezia/ppa.
    Перенесено из bivlked install_amneziawg.sh (steps 1-2).

    Правильный PPA: amnezia/ppa (НЕ amnezia/awg)
    GPG fingerprint: 75C9DD72C799870E310542E24166F2C257290828
    DEB822 формат для Ubuntu 24.04+ и Debian 13+, legacy .list для Debian 12.
    """
    core = _core_module()

    # v5.4.5: быстрый путь — всё уже установлено (идемпотентность +
    # устойчивость к недоступному PPA/keyserver при готовых пакетах)
    if awgs_kmod_already_ready():
        # v5.5.2 (E2E fi1): даже при готовых пакетах userspace-стабы
        # от Mode B эпохи затемняют which awg → syncconf уходит в
        # amneziawg-go (не умеет show/syncconf) → пиры применяются в
        # conf, но НЕ к живому интерфейсу — handshake молча не сходится
        _awgs_remove_shadowing_stubs()
        core.success("AmneziaWG уже установлен (awg/awg-quick + kmod найдены) — "
                     "переустановка пакетов не требуется")
        return True

    info = awgs_detect_os()
    distro = info["distro"].lower()
    codename = info["codename"].lower() or info["version"]

    core.info(f"ОС: {distro} {info['version']} ({codename})")

    # ── Шаг 1: зависимости для DKMS-сборки ──────────────────────────────────
    # ВАЖНО: wireguard-tools ставим первым, гарантированно и отдельно —
    # он даёт бинарник `wg`, который используется для генерации ключей
    # (awg genkey не существует в userspace-режиме amneziawg-go).
    core.info("Установка базовых зависимостей (wireguard-tools, curl, qrencode)...")
    core._run(["apt-get", "update", "-y"], check=False, quiet=True)

    # Профилактический ремонт apt: на VPS с полусобранными пакетами ЛЮБАЯ
    # установка падает с 'E: Unmet dependencies' (кейс продакшена).
    # Лечим ДО установки: dpkg --configure -a + apt --fix-broken install.
    r = core._run(["apt-get", "check"], capture=True, check=False, quiet=True)
    if r.returncode != 0:
        _awgs_apt_repair()

    # Ставим по одному пакету — если один упадёт, остальные всё равно установятся.
    # _awgs_apt_install сам чинит зависимости и ретраит при Unmet dependencies
    for pkg in ("curl", "qrencode", "wireguard-tools", "gpg", "dkms", "build-essential"):
        _awgs_apt_install(pkg)

    # linux-headers — отдельно, зависит от архитектуры и дистрибутива
    arch = core._run(["uname", "-m"], capture=True, check=False).stdout.strip()
    if distro == "debian":
        if arch == "aarch64":
            headers_pkg = "linux-headers-arm64"
        elif arch == "armv7l":
            headers_pkg = "linux-headers-armmp"
        else:
            headers_pkg = "linux-headers-amd64"
    else:
        # Ubuntu — linux-headers-generic работает на всех arch
        headers_pkg = "linux-headers-generic"
    r = core._run(["apt-get", "install", "-y", headers_pkg],
                  capture=True, check=False, quiet=True)
    if r.returncode != 0:
        core.log_to_file("WARN", f"apt install {headers_pkg}: {r.stderr[-300:]}")

    # Проверяем, что wg реально установлен
    wg_check = core._run(["which", "wg"], capture=True, check=False)
    if wg_check.returncode != 0:
        core.warn("wireguard-tools НЕ установлен — генерация ключей будет невозможна!")
        core.log_to_file("ERROR", f"wg not found after install. which wg: {wg_check.stderr}")
    else:
        core.info(f"wg доступен: {wg_check.stdout.strip()}")

    # ── Шаг 2: PPA amnezia/ppa (правильный!) ────────────────────────────────
    # Маппинг codename на поддерживаемый PPA (как в bivlked)
    ppa_mapping = {
        # Debian
        "bookworm": "focal",
        "trixie":   "noble",
        # Ubuntu LTS
        "focal":    "focal",
        "jammy":    "jammy",
        "noble":    "noble",
        # Ubuntu non-LTS → fallback на noble (DKMS соберётся под текущее ядро)
        "oracular": "noble",
        "plucky":   "noble",
        "questing": "noble",
    }
    ppa_codename = ppa_mapping.get(codename, "noble")

    # Для non-LTS Ubuntu проверяем доступность PPA, fallback на noble
    if codename not in ("focal", "jammy", "noble", "bookworm", "trixie"):
        core.info(f"Проверка доступности PPA Amnezia для '{ppa_codename}'...")
        r = core._run(
            ["curl", "-fsI", "--max-time", "15", "--retry", "2", "--retry-delay", "5",
             f"https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/{ppa_codename}/Release"],
            capture=True, check=False,
        )
        if r.returncode != 0:
            core.warn(f"PPA Amnezia не публикует пакеты для '{ppa_codename}' — переключаюсь на 'noble'")
            ppa_codename = "noble"

    core.info(f"PPA codename: {ppa_codename} (маппинг из {codename})")

    # GPG keyring с проверкой fingerprint (как в bivlked)
    keyring_dir = Path("/etc/apt/keyrings")
    keyring_file = keyring_dir / "amnezia-ppa.gpg"
    ppa_sources = Path("/etc/apt/sources.list.d/amnezia-ppa.sources")
    ppa_list = Path("/etc/apt/sources.list.d/amnezia-ppa.list")

    # Полный fingerprint GPG-ключа Amnezia PPA (40 символов)
    PPA_KEY_FINGERPRINT = "75C9DD72C799870E310542E24166F2C257290828"

    try:
        keyring_dir.mkdir(parents=True, exist_ok=True)

        # Скачиваем GPG-ключ с keyserver.ubuntu.com по полному fingerprint
        if not keyring_file.exists():
            core.info("Импорт GPG-ключа Amnezia PPA...")
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".gpg", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            try:
                r = core._run(
                    ["bash", "-c",
                     f"curl -fsSL 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{PPA_KEY_FINGERPRINT}' "
                     f"| gpg --batch --no-tty --yes --dearmor -o {tmp_path}"],
                    capture=True, check=False,
                )
                if r.returncode != 0:
                    core.warn(f"Не удалось импортировать GPG-ключ: {r.stderr}")
                    return _awgs_install_dkms_fallback()

                # Проверка fingerprint (pin)
                r = core._run(
                    ["bash", "-c",
                     f"gpg --batch --no-tty --show-keys --with-colons {tmp_path} 2>/dev/null "
                     f"| awk -F: '/^fpr:/{{print $10; exit}}'"],
                    capture=True, check=False,
                )
                got_fpr = r.stdout.strip()
                if got_fpr != PPA_KEY_FINGERPRINT:
                    core.warn(f"GPG fingerprint mismatch: получен '{got_fpr}', ожидается '{PPA_KEY_FINGERPRINT}'")
                    tmp_path.unlink(missing_ok=True)
                    return _awgs_install_dkms_fallback()

                tmp_path.chmod(0o644)
                tmp_path.replace(keyring_file)
                core.info("GPG-ключ импортирован и проверен")
            finally:
                tmp_path.unlink(missing_ok=True)

        # Удаляем старые legacy-файлы (могли остаться от предыдущих версий)
        for legacy in (
            f"/etc/apt/sources.list.d/amnezia-ubuntu-ppa-{codename}.list",
            f"/etc/apt/sources.list.d/amnezia-ubuntu-ppa-{codename}.sources",
            "/etc/apt/sources.list.d/amneziawg.list",
            "/etc/apt/sources.list.d/amneziawg.sources",
        ):
            Path(legacy).unlink(missing_ok=True)

        # Создаём sources-файл в правильном формате
        # Debian 12 → legacy .list; Debian 13+ и Ubuntu 24.04+ → DEB822 .sources
        use_deb822 = not (distro == "debian" and info["version"].startswith("12"))

        if use_deb822:
            # Проверяем, не пересоздать ли существующий .sources (suite может быть устаревшим)
            existing_suite = ""
            if ppa_sources.exists():
                r = core._run(
                    ["bash", "-c",
                     f"awk '/^Suites:/{{print $2; exit}}' {ppa_sources} 2>/dev/null"],
                    capture=True, check=False,
                )
                existing_suite = r.stdout.strip()
            if not ppa_sources.exists() or existing_suite != ppa_codename:
                deb822_content = (
                    "Types: deb\n"
                    "URIs: https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu\n"
                    f"Suites: {ppa_codename}\n"
                    "Components: main\n"
                    f"Signed-By: {keyring_file}\n"
                )
                ppa_sources.write_text(deb822_content)
                ppa_sources.chmod(0o644)
            ppa_list.unlink(missing_ok=True)
        else:
            # Debian 12 — legacy .list формат
            list_content = (
                f"deb [signed-by={keyring_file}] "
                f"https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu {ppa_codename} main\n"
            )
            ppa_list.write_text(list_content)
            ppa_list.chmod(0o644)
            ppa_sources.unlink(missing_ok=True)

        core.info("PPA amnezia/ppa добавлен")

        # apt update (толерантный к кратковременному outage PPA)
        r = core._run(["apt-get", "update", "-y"], capture=True, check=False)
        if r.returncode != 0:
            # v5.5.2 (E2E fi1): висячий apt.systemd.daily держит lock →
            # update молча проваливается, PPA-индексы не обновляются.
            # Лечим (TERM→KILL зависших системных apt) и ретраим.
            stderr = r.stderr or ""
            if ("could not get lock" in stderr.lower()
                    or "held by process" in stderr.lower()):
                if _awgs_apt_lock_heal():
                    time.sleep(1)
                    r = core._run(["apt-get", "update", "-y"],
                                  capture=True, check=False)
        if r.returncode != 0:
            # Если ошибка только на PPA Amnezia — продолжаем (issue #68 bivlked)
            stderr = r.stderr or ""
            if "amnezia" in stderr.lower():
                core.warn("PPA Amnezia временно недоступен — retry через 30 сек...")
                time.sleep(30)
                core._run(["apt-get", "update", "-y"], check=False, quiet=True)
            else:
                core.log_to_file("WARN", f"apt update: {stderr[-500:]}")

        # Проверяем, что пакет amneziawg-dkms появился в apt-cache
        def _cache_has_dkms() -> bool:
            rr = core._run(["apt-cache", "show", "amneziawg-dkms"],
                           capture=True, check=False)
            return rr.returncode == 0 and bool(rr.stdout.strip())

        if not _cache_has_dkms():
            # v5.5.2 (E2E fi1): вторая попытка после лечения лока —
            # индексы PPA могли не обновиться из-за apt-lock.
            if _awgs_apt_lock_heal():
                core._run(["apt-get", "update", "-y"],
                          check=False, quiet=True)
            if _cache_has_dkms():
                core.success("amneziawg-dkms найден в apt-cache после ретрая")
        if not _cache_has_dkms():
            core.warn("Пакет amneziawg-dkms не найден в apt-cache после обновления PPA")
            core.warn("Возможно PPA amnezia/ppa временно недоступен или GPG-ключ не подошёл")
            return _awgs_install_dkms_fallback()

        # Устанавливаем amneziawg-tools + amneziawg-dkms + wireguard-tools
        core.info("Установка пакетов amneziawg-tools + amneziawg-dkms...")
        r = core._run(
            ["apt-get", "install", "-y",
             "amneziawg-tools", "amneziawg-dkms", "wireguard-tools", "qrencode"],
            capture=True, check=False,  # 10 мин на DKMS-сборку
        )
        if r.returncode != 0:
            err_tail = (r.stderr or "")[-800:]
            core.log_to_file("ERROR", f"apt install amneziawg: {err_tail}")
            core.warn("Установка пакетов amneziawg из PPA не удалась:")
            # Покажем последние 5 строк stderr для диагностики
            for line in err_tail.splitlines()[-5:]:
                if line.strip():
                    core.warn(f"  {line.strip()}")
            # Ретрай после авто-восстановления apt: типовая причина падения —
            # 'E: Unmet dependencies' из-за полусобранных пакетов на VPS
            # (инцидент host1889848, 2026-10-04). apt сам советует
            # 'apt --fix-broken install' — делаем это и ретраим.
            retried_ok = False
            full_err = (r.stderr or "") + (r.stdout or "")
            if ("Unmet dependencies" in full_err or "fix-broken" in full_err
                    or "unmet dependencies" in full_err.lower()):
                if _awgs_apt_repair():
                    core.info("Ретраим установку amneziawg после ремонта apt...")
                    r2 = core._run(
                        ["apt-get", "install", "-y",
                         "amneziawg-tools", "amneziawg-dkms",
                         "wireguard-tools", "qrencode"],
                        capture=True, check=False,
                    )
                    if r2.returncode == 0:
                        core.success("Пакеты amneziawg установлены после "
                                     "авто-восстановления apt")
                        retried_ok = True
                    else:
                        core.log_to_file(
                            "ERROR",
                            f"apt install amneziawg retry: {(r2.stderr or '')[-500:]}",
                        )
            if not retried_ok:
                core.warn("→ Пробуем Go-версию (userspace) как fallback")
                return _awgs_install_dkms_fallback()

        # v5.5.2 (E2E fi1): пакеты установлены — убрать userspace-стабы,
        # затемняющие пакетные awg/awg-quick (наследие Mode B эпохи)
        _awgs_remove_shadowing_stubs()
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_install_dkms exception: {e}")
        core.warn(f"Исключение при установке DKMS: {e}")
        return _awgs_install_dkms_fallback()

    # ── Шаг 3: проверка модуля ─────────────────────────────────────────────
    # v5.4.5: функциональная проба вместо мгновенного lsmod: dkms-раскатка
    # для нескольких ядер асинхронна, modprobe+lsmod сразу после apt давали
    # ложный WARN «не загрузился» при реально работающем модуле (E2E de1:
    # WARN вылез, при этом awg0 поднялся и туннель работал). Проба
    # `ip link add test_awg0 type amneziawg` — единственный надёжный тест.
    kmod_ok = False
    for attempt in range(3):
        core._run(["modprobe", "amnezia"], check=False, quiet=True)
        probe = core._run(
            ["bash", "-c",
             "ip link add test_awg0 type amneziawg 2>/dev/null && "
             "ip link del test_awg0 && echo KMOD_OK"],
            capture=True, check=False)
        if "KMOD_OK" in (probe.stdout or ""):
            kmod_ok = True
            break
        core.log_to_file("WARN", f"awgs_install_dkms: kmod probe attempt "
                                  f"{attempt + 1}/3 failed")
        time.sleep(3)
    if not kmod_ok:
        # Возможно, нужен reboot (DKMS собрал модуль, но ядро его не подгрузило)
        core.warn("DKMS-модуль amnezia не загрузился в runtime — может потребоваться reboot")
        # Не возвращаем False — бинарники awg/awg-quick всё равно должны работать

    # Проверяем бинарники
    awg_bin = core._run(["which", AWGS_BIN], capture=True, check=False).stdout.strip()
    awg_quick_bin = core._run(["which", AWGS_QUICK_BIN], capture=True, check=False).stdout.strip()
    if not awg_bin or not awg_quick_bin:
        core.warn(f"Бинарники {AWGS_BIN}/{AWGS_QUICK_BIN} не найдены после установки")
        return _awgs_install_dkms_fallback()

    core.success("AmneziaWG DKMS-модуль установлен")
    return True


def _awgs_install_dkms_fallback() -> bool:
    """
    Fallback: устанавливаем через Go-версию (userspace), как в моём awg_transport.py.
    Это не kernel-module, но работает если DKMS не собирается.
    """
    core = _core_module()
    core.info("Fallback: установка Go-версии amneziawg (userspace)...")
    try:
        from .awg_transport import _awg_install_go_version
        if _awg_install_go_version():
            core.success("amneziawg Go-версия установлена (userspace)")
            # v5.5.2 (E2E fi1): без пакетного amneziawg-tools юнита
            # awg-quick@.service не существует → сервис not-found,
            # туннель не поднимается. Ставим userspace-юнит.
            if not _awgs_install_userspace_unit():
                core.warn("userspace: юнит awg-quick@.service создать "
                          "не удалось — сервис не поднимется")
            core.warn("userspace-режим (amneziawg-go): производительность "
                      "ниже kernel-модуля. При возможности установите "
                      "amneziawg-dkms из PPA amnezia/ppa")
            return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_install_dkms_fallback: {e}")
    return False


def _awgs_install_userspace_unit() -> bool:
    """v5.5.2: юнит awg-quick@.service для userspace (go) standalone.

    Пакет amneziawg-tools приносит /lib/systemd/system/awg-quick@.service;
    в userspace-режиме (go-fallback) пакет не ставится — создаём
    /etc/systemd/system-юнит на стаб-обёртку awg-quick. Юнит создаём
    ТОЛЬКО если юнита ещё нигде нет (иначе перекрыли бы пакетный).
    """
    core = _core_module()
    for unit_path in (
        "/lib/systemd/system/awg-quick@.service",
        "/usr/lib/systemd/system/awg-quick@.service",
        "/etc/systemd/system/awg-quick@.service",
    ):
        if Path(unit_path).exists():
            core.info(f"Юнит awg-quick@.service уже существует: {unit_path}")
            return True
    content = (
        "[Unit]\n"
        "Description=AmneziaWG userspace (amneziawg-go) for %i\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=/usr/local/bin/awg-quick up %i\n"
        "ExecStop=/usr/local/bin/awg-quick down %i\n"
        "TimeoutStartSec=30\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    try:
        Path("/etc/systemd/system/awg-quick@.service").write_text(content)
        core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
        core.success("Юнит awg-quick@.service создан (userspace-режим)")
        return True
    except Exception as e:
        core.log_to_file("ERROR", f"_awgs_install_userspace_unit: {e}")
        return False


def _awgs_remove_shadowing_stubs(paths: dict | None = None) -> None:
    """v5.5.2 (E2E fi1): убрать userspace-стабы, затемняющие пакетный AWG.

    Наследие userspace-эпохи Mode B: /usr/local/bin/awg и awg-quick
    (обёртки над amneziawg-go) стоят ВЫШЕ /usr/bin в PATH. При
    установленных пакетах amneziawg-tools все вызовы which awg → стаб
    → amneziawg-go, который не умеет show/syncconf: пиры применяются
    в .conf и state, но НЕ к живому kernel-интерфейсу — handshake
    молча не сходится (E2E fi1 2026-10-03: cascade_entry в conf,
    latest-handshakes = 0).

    Удаляем ТОЛЬКО при наличии пакетного аналога (чистый userspace-режим
    без пакетов не трогаем). Также убираем /etc/systemd/system/
    awg-quick@.service (userspace-юнит), если есть пакетный юнит —
    иначе /etc перекрывает /lib.

    paths — DI для тестов (словарь путей); по умолчанию системные пути.
    """
    core = _core_module()
    P = paths or {
        "stub_awg": "/usr/local/bin/awg",
        "pkg_awg": "/usr/bin/awg",
        "stub_quick": "/usr/local/bin/awg-quick",
        "pkg_quick": "/usr/bin/awg-quick",
        "etc_unit": "/etc/systemd/system/awg-quick@.service",
        "lib_unit": "/lib/systemd/system/awg-quick@.service",
        "usr_unit": "/usr/lib/systemd/system/awg-quick@.service",
    }
    removed = []
    for stub_key, pkg_key in (("stub_awg", "pkg_awg"),
                              ("stub_quick", "pkg_quick")):
        stub, pkg = Path(P[stub_key]), Path(P[pkg_key])
        if stub.exists() and pkg.exists():
            try:
                stub.unlink()
                removed.append(str(stub))
            except OSError as e:
                core.log_to_file("WARN", f"unlink {stub}: {e}")
    etc_unit = Path(P["etc_unit"])
    pkg_unit = any(Path(P[k]).exists() for k in ("lib_unit", "usr_unit"))
    if etc_unit.exists() and pkg_unit:
        try:
            etc_unit.unlink()
            removed.append(str(etc_unit))
        except OSError as e:
            core.log_to_file("WARN", f"unlink {etc_unit}: {e}")
    if removed:
        core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
        core.warn("Удалены userspace-остатки, затемнявшие пакетный "
                  f"AmneziaWG: {', '.join(removed)}")


def _awgs_apt_lock_heal() -> bool:
    """v5.5.2: лечение висячих apt-локов перед установкой пакетов.

    Реальный кейс (E2E fi1 2026-10-03): apt.systemd.daily update завис
    (недоступный репозиторий, http-метод без таймаута) и держит
    /var/lib/apt/lists/lock сутками → apt-get update инсталлера молча
    проваливается → PPA-индексы не обновляются → ложный fallback на
    userspace-go. Держателя локa определяем через fuser; если это
    системное apt-обслуживание (apt.systemd.daily) или apt-get,
    висящий дольше 30 минут — завершаем (TERM, затем KILL) и логируем.
    Чужие/свежие apt-процессы НЕ трогаем.
    Возвращает True, если что-то было завершено.
    """
    core = _core_module()
    r = core._run(
        ["bash", "-c",
         "fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend "
         "/var/lib/dpkg/lock /var/cache/apt/archives/lock 2>/dev/null"],
        capture=True, check=False)
    pids = set()
    for tok in (r.stdout or "").split():
        tok = tok.strip().strip(":")
        if tok.isdigit():
            pids.add(tok)
    killed = []
    for pid in sorted(pids):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = (f.read().decode("utf-8", "replace")
                       .replace("\0", " ").strip())
            et = core._run(["ps", "-o", "etimes=", "-p", pid],
                           capture=True, check=False).stdout.strip()
            etime = int(et) if et.isdigit() else 0
        except (OSError, ValueError):
            continue
        is_daily = "apt.systemd.daily" in cmd
        is_stale_aptget = "apt-get" in cmd and etime > 1800
        if not (is_daily or is_stale_aptget):
            continue
        core.warn(f"Зависший apt-процесс (pid {pid}, {etime}s): "
                  f"{cmd[:80]}")
        core._run(
            ["bash", "-c",
             f"pkill -TERM -P {pid} 2>/dev/null; kill -TERM {pid} 2>/dev/null; "
             f"sleep 2; "
             f"pkill -KILL -P {pid} 2>/dev/null; kill -KILL {pid} 2>/dev/null; "
             f"true"],
            check=False, quiet=True)
        killed.append(pid)
    if killed:
        core.warn(f"Зависшие apt-процессы завершены: {', '.join(killed)} "
                  "(системное apt-обслуживание блокировало установку)")
        time.sleep(1)
    return bool(killed)


# ============================================================================
#  ГЕНЕРАЦИЯ КЛЮЧЕЙ
# ============================================================================

def _awgs_x25519(scalar: bytes, u: bytes) -> bytes:
    """
    X25519 (RFC 7748) на чистом Python — без внешних зависимостей
    (ни wg/awg-бинарников, ни пакета cryptography).

    Нужна как последний fallback генерации ключей: на VPS со сломанным apt
    (E: Unmet dependencies) может отсутствовать и wg, и рабочий awg
    (stub-обёртка после Go-fallback проксирует в amneziawg-go, который
    НЕ поддерживает genkey/pubkey/genpsk). Ключи WireGuard/AWG — это
    clamped X25519, поэтому pure-Python реализация байт-в-байт совместима
    с `wg genkey`/`awg genkey` (проверена тестами против cryptography).
    """
    P = 2**255 - 19
    A24 = 121665

    k = int.from_bytes(scalar, "little")
    k &= (1 << 254) - 8          # k[0] &= 248; k[31] &= 127 (сброс бита 255)
    k |= 1 << 254                # k[31] |= 64
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = ((DA - CB) ** 2 % P) * x1 % P
        x2 = AA * BB % P
        z2 = E * (AA + A24 * E) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


def _awgs_py_keygen_pair() -> tuple:
    """
    Pure-Python генерация пары ключей (priv+pub), формат идентичен wg genkey.
    Возвращает (privkey_b64, pubkey_b64).
    """
    import base64
    priv = bytearray(os.urandom(32))
    priv[0] &= 248                # RFC 7748 clamp
    priv[31] &= 127
    priv[31] |= 64
    priv_raw = bytes(priv)
    pub_raw = _awgs_x25519(priv_raw, b"\x09" + b"\x00" * 31)
    return (
        base64.b64encode(priv_raw).decode(),
        base64.b64encode(pub_raw).decode(),
    )


def _awgs_py_genpsk() -> str:
    """Pure-Python PresharedKey: 32 случайных байта в base64 (как wg genpsk)."""
    import base64
    return base64.b64encode(os.urandom(32)).decode()


def awgs_generate_keys() -> tuple:
    """
    Генерирует пару ключей сервера (priv+pub).
    Цепочка (каждый следующий шаг — если предыдущий недоступен):
      1. `wg genkey`/`wg pubkey` — нативный бинарник из wireguard-tools
      2. `awg genkey`/`awg pubkey` — из amneziawg-tools (kernel-режим)
      3. Pure-Python X25519 (RFC 7748) — работает ВСЕГДА, даже при сломанном
         apt и userspace-заглушке awg (amneziawg-go не умеет genkey)
    Ключи Curve25519 полностью совместимы между WG и AWG.
    Возвращает (privkey, pubkey) или ("", "") при ошибке.
    """
    core = _core_module()

    # Определяем, какой бинарник доступен
    awg_path = core._run(["which", AWGS_BIN], capture=True, check=False).stdout.strip()
    wg_path = core._run(["which", "wg"], capture=True, check=False).stdout.strip()

    # Если ни одного нет — пробуем установить wireguard-tools
    if not awg_path and not wg_path:
        core.warn("Ни awg, ни wg не найдены — устанавливаем wireguard-tools...")
        core._run(["apt-get", "update", "-y"], check=False, quiet=True)
        core._run(["apt-get", "install", "-y", "wireguard-tools"],
                  check=False, quiet=True)
        wg_path = core._run(["which", "wg"], capture=True, check=False).stdout.strip()

    # prefer wg over awg: stub-обёртка awg (после fallback на amneziawg-go)
    # проксирует вызовы на amneziawg-go, который НЕ поддерживает genkey/pubkey.
    # wg (из wireguard-tools) — нативный бинарник, всегда работает.
    bin_for_genkey = wg_path or awg_path

    privkey, pubkey = "", ""
    if bin_for_genkey:
        if wg_path:
            core.info(f"Генерация ключей через wg ({wg_path})")
        else:
            core.info(f"Генерация ключей через awg ({awg_path}) — wg недоступен")

        # Приватный ключ (genkey читает /dev/urandom, не требует stdin, но подаём пустой)
        r = core._run([bin_for_genkey, "genkey"],
                      capture=True, check=False, input_text="")
        if r.returncode == 0:
            privkey = r.stdout.strip()

        # Публичный из приватного (pubkey читает privkey из stdin)
        if privkey:
            r = core._run([bin_for_genkey, "pubkey"],
                          capture=True, check=False, input_text=privkey + "\n")
            if r.returncode == 0:
                pubkey = r.stdout.strip()

    # Last-resort: pure-Python X25519 — не зависит ни от apt, ни от бинарников.
    # Покрывает кейс: wg не установлен (broken apt), awg — userspace-заглушка.
    if not privkey or not pubkey:
        core.warn("Бинарники wg/awg недоступны или не поддерживают genkey — "
                  "включаю pure-Python генерацию ключей (X25519, RFC 7748)")
        try:
            privkey, pubkey = _awgs_py_keygen_pair()
            core.success("Ключи сгенерированы pure-Python X25519 "
                         "(формат идентичен wg genkey)")
        except Exception as e:
            core.log_to_file("ERROR", f"awgs_generate_keys pure-python: {e}")
            return "", ""

    return privkey, pubkey


def awgs_generate_preshared_key() -> str:
    """
    Генерирует PresharedKey (опциональный, для per-client PSK).
    Prefer wg (нативный), fallback на awg, last-resort — pure-Python
    (32 случайных байта base64, как wg genpsk; работает даже когда
    оба бинарника недоступны/нерабочие).
    """
    core = _core_module()
    wg_path = core._run(["which", "wg"], capture=True, check=False).stdout.strip()
    awg_path = core._run(["which", AWGS_BIN], capture=True, check=False).stdout.strip()
    bin_for_genpsk = wg_path or awg_path
    if bin_for_genpsk:
        r = core._run([bin_for_genpsk, "genpsk"],
                      capture=True, check=False, input_text="")
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        core.log_to_file(
            "WARN",
            f"awgs_generate_preshared_key: {bin_for_genpsk} genpsk failed "
            f"(rc={r.returncode}) — использую pure-Python fallback",
        )
    return _awgs_py_genpsk()


# ============================================================================
#  РУЧНОЙ ВВОД ПАРАМЕТРОВ ОБФУСКАЦИИ
# ============================================================================

# Полный список параметров AWG 2.0 с описанием, диапазонами и рекомендациями.
# Перенесено из upstream AmneziaWG + bivlked validation + real-world reports.
AWGS_PARAMS_SPEC = [
    # (key, label, min, max, recommended, description)
    ("jc", "Jc (Junk packet count)",
     1, 128, 4,
     "Количество junk-пакетов перед реальным handshake. "
     "Больше = сильнее обфускация, но больше overhead. "
     "Mobile DPI (Tele2/Yota): фиксируйте 3."),
    ("jmin", "Jmin (Junk packet min size)",
     0, 1280, 40,
     "Минимальный размер junk-пакета в байтах. "
     "Default: 40-89. Mobile: 30-50."),
    ("jmax", "Jmax (Junk packet max size)",
     0, 1280, 70,
     "Максимальный размер junk-пакета. Должен быть >= Jmin. "
     "ВАЖНО для mobile: узкий Jmax (≤150) — Yota блокирует при Jmax>300. "
     "Default: Jmin+50..250. Mobile: Jmin+20..80."),
    ("s1", "S1 (Init packet junk size)",
     0, 1280, 0,
     "Доп. junk в init-пакете. 0 = выключено. "
     "Рекомендуется 0 — S-параметры редко нужны и могут ломать handshake."),
    ("s2", "S2 (Response packet junk size)",
     0, 1280, 0,
     "Доп. junk в response-пакете. 0 = выключено. Рекомендуется 0."),
    ("s3", "S3 (Under-load packet junk size)",
     0, 64, 0,
     "Доп. junk в under-load пакетах (при загрузке сервера). 0 = выключено."),
    ("s4", "S4 (Transport packet junk size)",
     0, 32, 0,
     "Доп. junk в transport-пакетах. 0 = выключено. Протокольный лимит — 32 байта."),
]

# H1-H4 — отдельный блок ввода (v5.5.1): официальный формат AWG 2.0+ —
# «N» ИЛИ диапазон «N-M» в 0..INT32_MAX (wiki.amnezia.host: одиночные
# числа — формат legacy 1.0; amneziawg-tools config.c →
# u32_range_from_string). Диапазоны НЕ должны пересекаться — пакеты из
# зоны перекрытия не классифицируются и молча дропаются
# (device/receive.go DeterminePacketTypeAndPadding).
AWGS_H_UPPER_LIMIT = 2147483647  # INT32_MAX

# I1-I5 — опциональные CPS-цепочки (мини-язык тегов amneziawg-go).
AWGS_PARAMS_SPEC_HEX = [
    # (key, label, recommended, description)
    ("i1", "I1 (Init packet junk — CPS-цепочка)",
     "random",
     "CPS-цепочка из кросс-движковых тегов (kernel + go-клиенты): "
     "<b 0xHEX>, <t>, <r N>, <rc N>, <rd N>. Шорткаты профилей: "
     "auto, quic, quic0rtt, burst (QUIC-всплеск I1-I5), dns, tls, "
     "altsvc, dtls12, dtls13, noise, http3, sip, binary. "
     "Tele2 Красноярск/Мегафон: ОСТАВИТЬ ПУСТЫМ (иначе блокировка). "
     "Голый hex — формат AWG 1.5, принимается, но НЕ рекомендуется."),
    ("i2", "I2 (decoy-пакет №2 — CPS-цепочка)",
     "",
     "Опционально. Пусто = без пакета; 'fill' — нейтральная цепочка "
     "автоматически (как автозаполнение I2-I5 в генераторах 3.1)."),
    ("i3", "I3 (decoy-пакет №3 — CPS-цепочка)",
     "",
     "Опционально. Пусто = без пакета; 'fill' — нейтральная цепочка."),
    ("i4", "I4 (decoy-пакет №4 — CPS-цепочка)",
     "",
     "Опционально. Пусто = без пакета; 'fill' — нейтральная цепочка."),
    ("i5", "I5 (decoy-пакет №5 — CPS-цепочка)",
     "",
     "Опционально. Пусто = без пакета; 'fill' — нейтральная цепочка."),
]

# v5.5.5: шорткаты профилей мимикрии для интерактивного ввода (полный
# реестр — AWG_I1_MIMICRY_PROFILES в awg_presets, 13 профилей).
AWGS_MIMICRY_SHORTCUTS: dict = {
    "auto":     "random",
    "random":   "random",
    "quic":     "quic_mimicry",
    "quic0rtt": "quic_0rtt",
    "0rtt":     "quic_0rtt",
    "burst":    "quic_burst",
    "dns":      "dns_mimicry",
    "tls":      "tls_mimicry",
    "altsvc":   "tls_altsvc",
    "h3alt":    "tls_altsvc",
    "dtls":     "dtls12",
    "dtls12":   "dtls12",
    "dtls13":   "dtls13",
    "noise":    "noise_ik",
    "noiseik":  "noise_ik",
    "http3":    "http3_host",
    "h3":       "http3_host",
    "sip":      "sip",
    "binary":   "binary",
}

# Рекомендованный порт под маскировку (подсказка после генерации).
AWGS_MIMICRY_PORT_HINTS: dict = {
    "quic_mimicry": "443 (QUIC)",
    "quic_0rtt":    "443 (QUIC)",
    "quic_burst":   "443 (QUIC)",
    "http3_host":   "443 (HTTP/3)",
    "dns_mimicry":  "53 (DNS)",
    "tls_mimicry":  "443 (TLS)",
    "tls_altsvc":   "443 (TLS + Alt-Svc)",
    "dtls12":       "443 (DTLS)",
    "dtls13":       "443 (DTLS)",
    "sip":          "5060 (SIP)",
}


def awgs_prompt_custom_params(protocol_version: str = "2.0") -> dict:
    """
    Интерактивный ввод ВСЕХ параметров обфускации AWG (2.0 или 3.1).
    Для каждого параметра показывает: описание, диапазон, рекомендуемое значение.
    Пользователь может Enter (значение по умолчанию) или ввести своё.

    v5.5.1 — полная поддержка официального синтаксиса:
      • H1-H4 — «N» или диапазон «N-M» (0..INT32_MAX, без пересечений);
      • I1-I5 — CPS-цепочки кросс-движковых тегов + шорткаты ВСЕХ 13
        профилей мимикрии (auto/quic/quic0rtt/burst/dns/tls/altsvc/
        dtls12/dtls13/noise/http3/sip/binary) + 'fill' для I2-I5;
      • 3.1 — ручной ввод и 9 транспортных директив (HeaderProtectionKey,
        ContentPaddingAddition «N»/«N-M», таймеры, RandomTrailers/
        DisableCookies «on»/«off»).

    v5.5.5 — защита от несовместимых параметров (kernel-сервер +
    go-клиенты): теги <c> (kernel-only) и <d>/<ds>/<dz N> (go-only,
    no-op) БЛОКИРУЮТСЯ на этапе ввода с переспросом; финальная
    валидация — strict_cross_engine=True. Ввести конфиг, который
    заведомо не заработает, невозможно.

    Возвращает dict с ключами jc/jmin/jmax/s1-s4/h1-h4/i1-i5 (+ 9 ключей
    3.1 при protocol_version="3.1"), либо None при провале валидации.
    """
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC, GREEN, YELLOW, DIM, BOLD = (
        core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM, core.BOLD
    )
    import random
    from .awg_protocol import (
        awg_is_31, awg_protocol_label, awg31_generate_extra_params,
        AWG31_DIRECTIVE_NAMES,
    )
    from .awg_presets import (
        _generate_non_overlapping_h_values, _generate_non_overlapping_h_values_31,
        awg_i1_mimicry_generate, awg_i_chain_mimicry_generate,
        _generate_neutral_i_chain, _is_valid_cps_or_legacy_hex,
        _cps_has_kernel_only_tags, _cps_has_go_only_tags,
    )

    is_31 = awg_is_31(protocol_version)

    print()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom

    _box_top(f"Ручная настройка параметров обфускации {awg_protocol_label(protocol_version)}")
    _box_row()
    _box_row(f"  {DIM}Для каждого параметра укажите значение или Enter для рекомендуемого.{NC}")
    _box_row(f"  {DIM}Рекомендации основаны на тестах bivlked/amneziawg-installer{NC}")
    if is_31:
        _box_row(f"  {DIM}и констрейнтах официальной AWG 3.1 (wiki.amnezia.host).{NC}")
    _box_row()
    _box_bottom()
    print()

    params = {}

    # Числовые параметры (Jc/Jmin/Jmax/S1-S4)
    # v5.5.5: для 3.1 рекомендации/диапазоны S1-S4 — из констрейнтов
    # GenerateObfuscation31. Прежние «рекомендуется 0» (2.0-специфика)
    # проваливали финальную валидацию 3.1 при вводе «всё по Enter»
    # (S1=0 < 15) — кастомный 3.1-конфиг было невозможно собрать с
    # дефолтами.
    _S_RANGES_31 = {"s1": (15, 150), "s2": (15, 150),
                    "s3": (12, 55), "s4": (12, 27)}
    for key, label, vmin, vmax, recommended, desc in AWGS_PARAMS_SPEC:
        if is_31 and key in _S_RANGES_31:
            vmin, vmax = _S_RANGES_31[key]
            recommended = (vmin + vmax) // 2
        print(f"{BOLD}{label}{NC}")
        print(f"  {DIM}{desc}{NC}")
        print(f"  {GREEN}Рекомендуется:{NC} {recommended}  {DIM}(диапазон: {vmin}-{vmax}){NC}")
        while True:
            val_str = input(f"  {CYAN}Значение [{recommended}]: {NC}").strip()
            if not val_str:
                val = recommended
                break
            if not val_str.isdigit():
                print(f"  {YELLOW}Нужно целое число{NC}")
                continue
            val = int(val_str)
            if val < vmin or val > vmax:
                print(f"  {YELLOW}Вне диапазона ({vmin}-{vmax}){NC}")
                continue
            # Спец-проверка: Jmax >= Jmin
            if key == "jmax" and val < params.get("jmin", 0):
                print(f"  {YELLOW}Jmax ({val}) не может быть меньше Jmin ({params['jmin']}){NC}")
                continue
            break
        params[key] = val
        print()

    # H1-H4 — официальный формат «N» / «N-M» (v5.5.1)
    print(f"{BOLD}H1-H4 — magic headers (официальный формат AWG 2.0+: «N» или «N-M» до {AWGS_H_UPPER_LIMIT}){NC}")
    print(f"  {DIM}Диапазоны скрывают заголовок от DPI; не должны пересекаться между собой.{NC}")
    print(f"  {DIM}Значения 1-4 не используйте — это узнаваемые vanilla-WireGuard типы сообщений.{NC}")
    print(f"  {GREEN}Рекомендуется:{NC} auto — непересекающиеся диапазоны" +
          (f" (узкие ~20k, фикс бага amneziawg-go в 3.1)" if is_31 else ""))
    _h_vals = None
    while True:
        _h_auto = input(f"  {CYAN}H1-H4 ['auto' или четыре значения через пробел, напр. "
                        f"'2135087609-2135093954 2147225277 2147461177 2147478893-2147482205']: {NC}").strip()
        if not _h_auto or _h_auto.lower() == "auto":
            _h_gen = (_generate_non_overlapping_h_values_31() if is_31
                      else _generate_non_overlapping_h_values())
            _h_vals = [str(v) for v in _h_gen]
            info(f"  Сгенерированы H1-H4: {' '.join(_h_vals)}")
            break
        parts = _h_auto.split()
        if len(parts) != 4:
            print(f"  {YELLOW}Нужно 4 значения (H1 H2 H3 H4) или 'auto'{NC}")
            continue
        ok_h = True
        for p in parts:
            if not (p.isdigit() or ("-" in p and p.split("-", 1)[0].isdigit()
                                    and p.split("-", 1)[1].isdigit())):
                print(f"  {YELLOW}'{p}' не «N» и не «N-M»{NC}")
                ok_h = False
                break
            _lo = int(p.split("-")[0])
            _hi = int(p.split("-")[-1])
            if _lo > _hi or _hi > AWGS_H_UPPER_LIMIT:
                print(f"  {YELLOW}'{p}': lo>hi или превышает INT32_MAX{NC}")
                ok_h = False
                break
            if 1 <= _lo <= 4 or 1 <= _hi <= 4:
                warn(f"  '{p}' содержит значения 1-4 — узнаваемые vanilla-WireGuard "
                     f"типы сообщений; рекомендуется диапазон от 5")
        if not ok_h:
            continue
        # Проверка пересечений
        _h_parsed = []
        for p in parts:
            if "-" in p:
                _lo, _hi = p.split("-", 1)
                _h_parsed.append((int(_lo), int(_hi)))
            else:
                _iv = int(p)
                _h_parsed.append((_iv, _iv))
        _overlap = False
        for _i in range(4):
            for _j in range(_i + 1, 4):
                if _h_parsed[_i][0] <= _h_parsed[_j][1] and _h_parsed[_j][0] <= _h_parsed[_i][1]:
                    print(f"  {YELLOW}H{_i+1} и H{_j+1} пересекаются — пакеты из зоны "
                          f"перекрытия не классифицируются и дропаются{NC}")
                    _overlap = True
        if _overlap:
            continue
        _h_vals = parts
        break
    params["h1"], params["h2"], params["h3"], params["h4"] = _h_vals
    print()

    # CPS-параметры (I1-I5)
    print(f"{BOLD}Опциональные параметры (I1-I5) — CPS-цепочки:{NC}")
    print(f"  {DIM}Оставьте пустым (Enter) если не уверены — большинство операторов не требуют.{NC}")
    print(f"  {DIM}Профили мимикрии: auto quic quic0rtt burst dns tls altsvc dtls12 dtls13 noise http3 sip binary{NC}")
    print()
    _burst_filled = False
    for key, label, recommended, desc in AWGS_PARAMS_SPEC_HEX:
        if _burst_filled:
            break
        print(f"{BOLD}{label}{NC}")
        print(f"  {DIM}{desc}{NC}")
        if recommended == "random":
            print(f"  {GREEN}Рекомендуется:{NC} auto — нейтральный <r N> (безопасен для всех клиентов)")
        elif recommended:
            print(f"  {GREEN}Рекомендуется:{NC} {recommended}")
        else:
            print(f"  {GREEN}Рекомендуется:{NC} пусто")
        while True:
            val = input(f"  {CYAN}Значение (Enter=пусто, профиль, fill, CPS-цепочка): {NC}").strip()
            if not val:
                val = ""
                break
            _low = val.lower()
            # v5.5.5: 'fill' — нейтральная цепочка (та же форма, что
            # автозаполнение I2-I5 в генераторах 3.1)
            if _low == "fill":
                val = _generate_neutral_i_chain()
                info(f"  Сгенерирована нейтральная цепочка {key}: {val}")
                break
            if _low in AWGS_MIMICRY_SHORTCUTS:
                _profile = AWGS_MIMICRY_SHORTCUTS[_low]
                if _profile == "quic_burst":
                    # full-chain профиль: I1-I5 заполняются «всплеском»
                    # QUIC-пакетов разного типа (Initial/0-RTT/Handshake/1-RTT)
                    _chain = awg_i_chain_mimicry_generate("quic_burst")
                    params["i1"], params["i2"], params["i3"], \
                        params["i4"], params["i5"] = _chain
                    info("  Сгенерирован QUIC-всплеск (I1-I5):")
                    for _ik in ("i1", "i2", "i3", "i4", "i5"):
                        info(f"    {_ik.upper()} = {params[_ik]}")
                    _burst_filled = True
                    break
                val = awg_i1_mimicry_generate(_profile)
                info(f"  Сгенерирован {key} (профиль {_profile}): {val}")
                _port_hint = AWGS_MIMICRY_PORT_HINTS.get(_profile)
                if _port_hint:
                    info(f"  Под маскировку желательно значение AWG-порта: {_port_hint}")
                break
            if not _is_valid_cps_or_legacy_hex(val):
                warn(f"  Не похоже на CPS-цепочку (<b 0x...>, <t>, <r N>, <rc N>, "
                     f"<rd N>) и не hex — попробуйте ещё раз")
                continue
            # v5.5.5: наш стандартный деплой — kernel-сервер + go-клиенты;
            # теги одного движка БЛОКИРУЮТСЯ с переспросом (раньше <c>
            # только предупреждал — можно было собрать конфиг, который
            # не подключится ни на одном клиенте-приложении)
            if _cps_has_kernel_only_tags(val):
                warn(f"  <c> — тег ТОЛЬКО модуля ядра Linux; клиентские "
                     f"приложения Amnezia (Windows/Android/iOS/macOS) "
                     f"отвергнут весь junk-пакет — подключение не "
                     f"состоялось бы. Используйте кросс-движковые теги: "
                     f"<b 0x...>/<t>/<r N>/<rc N>/<rd N>")
                continue
            if _cps_has_go_only_tags(val):
                warn(f"  <d>/<ds>/<dz N> — теги ТОЛЬКО amneziawg-go (и no-op); "
                     f"серверный модуль ядра amneziawg-tools такой конфиг "
                     f"не загрузит. Используйте кросс-движковые теги: "
                     f"<b 0x...>/<t>/<r N>/<rc N>/<rd N>")
                continue
            if all(c in "0123456789abcdefABCDEF" for c in val) and "<" not in val:
                warn(f"  Голый hex — формат AWG 1.5; на Keenetic/amneziawg-go "
                     f"может не работать. Рекомендуется CPS-формат, напр. "
                     f"'<r {len(val)//2}>'")
            break
        if not _burst_filled:
            params[key] = val
        print()

    # AWG 3.1: 9 транспортных директив (v5.5.1 — полный ручной контроль)
    if is_31:
        _defaults_31 = awg31_generate_extra_params()
        _short = {
            "header_protection_key":
                "base64 32 байта (44 символа). Общий для сервера и клиента — "
                "шифрование заголовков ChaCha20; nonce берётся из S-паддинга "
                "(поэтому S1-S4 >= 12).",
            "content_padding_addition":
                "Число или «N-M» (0-64). Случайный паддинг транспортных "
                "пакетов; 0 = выкл; 2-10 при низкой скорости.",
            "rekey_after_time":
                "Число или «N-M» секунд (100-200) — рандомизация rekey.",
            "rekey_timeout":
                "Число или «N-M» секунд (3-10) — таймаут handshake-попытки.",
            "reject_after_time":
                "Число или «N-M» секунд (130-300); должен быть больше "
                "KeepaliveTimeout + RekeyTimeout и больше RekeyAfterTime.",
            "keepalive_timeout":
                "Число или «N-M» секунд (8-20) — keepalive-интервал.",
            "max_handshake_attempts":
                "Число или «N-M» (15-50) — попыток handshake до отказа.",
            "random_trailers":
                "on/off — дописывать пакеты до MTU случайными байтами (3.1).",
            "disable_cookies":
                "on/off — не отвечать cookiereply на порту WireGuard (3.1; "
                "ломает keepalive за NAT под нагрузкой — включать осознанно).",
        }
        print(f"{BOLD}Транспортная защита AWG 3.1 (9 директив):{NC}")
        print(f"  {DIM}Enter — рекомендованное значение (генерация по констрейнтам 3.1).{NC}")
        print()
        for _k31 in _defaults_31:
            _dir = AWG31_DIRECTIVE_NAMES[_k31]
            _def = _defaults_31[_k31]
            print(f"{BOLD}{_dir}{NC}")
            print(f"  {DIM}{_short.get(_k31, '')}{NC}")
            while True:
                v31 = input(f"  {CYAN}Значение [{_def}]: {NC}").strip()
                if not v31:
                    v31 = _def
                    break
                if _k31 in ("random_trailers", "disable_cookies"):
                    if v31.lower() not in ("on", "off", "0", "1"):
                        print(f"  {YELLOW}Допустимо: on / off / 0 / 1{NC}")
                        continue
                    break
                # диапазонные: «N» или «N-M» — проверка ниже общей валидацией
                if _k31 == "header_protection_key":
                    import base64 as _b64
                    try:
                        if len(_b64.b64decode(v31, validate=True)) < 30:
                            raise ValueError
                    except Exception:
                        print(f"  {YELLOW}Нужен base64-ключ 32 байта (44 символа, как wg genkey){NC}")
                        continue
                    break
                if not (v31.isdigit() or ("-" in v31 and
                                          v31.split("-", 1)[0].isdigit() and
                                          v31.split("-", 1)[1].isdigit())):
                    print(f"  {YELLOW}Формат: число «N» или диапазон «N-M»{NC}")
                    continue
                break
            params[_k31] = v31
            print()

    # Итоговая сводка
    _box_top(f"Итоговые параметры")
    _box_row()
    for key, label, _, _, _, _ in AWGS_PARAMS_SPEC:
        _box_row(f"  {CYAN}{key.upper():<6}{NC} = {params[key]}")
    for _i, key in enumerate(("h1", "h2", "h3", "h4")):
        _box_row(f"  {CYAN}{key.upper():<6}{NC} = {params[key]}")
    for key, label, _, _ in AWGS_PARAMS_SPEC_HEX:
        val = params[key]
        if val:
            _box_row(f"  {CYAN}{key.upper():<6}{NC} = {val[:40]}{'...' if len(val) > 40 else ''}")
        else:
            _box_row(f"  {CYAN}{key.upper():<6}{NC} = {DIM}(пусто){NC}")
    if is_31:
        for _k31 in _defaults_31:
            _box_row(f"  {CYAN}{AWG31_DIRECTIVE_NAMES[_k31]:<24}{NC} = "
                     f"{params.get(_k31, '')}")
    _box_bottom()

    # Валидация (v5.5.5: strict_cross_engine — конфиг пойдёт и на
    # kernel-сервер, и на go-клиентов; одно-движковые теги уже
    # заблокированы на вводе — здесь защита остальным правилам:
    # S1+56≠S2, пересечения H, таймерная иерархия 3.1 и т.д.)
    ok, err = awgs_presets_validate_params(params, protocol_version=protocol_version,
                                           strict_cross_engine=True)
    if not ok:
        warn(f"Валидация: {err}")
        return None

    return params


# ============================================================================
#  ГЕНЕРАЦИЯ КОНФИГОВ
# ============================================================================

def awgs_build_server_conf(
    server_privkey: str,
    port: int,
    subnet: str,
    subnet_v6: str,
    mtu: int,
    params: dict,
    peers: list = None,
    endpoint_host: str = "",
    cascade_role: str = "",
    cascade_peer: dict = None,
    protocol_version: str = "",
) -> str:
    """
    Генерирует содержимое awg0.conf (серверная сторона).

    protocol_version (v5.5): "" | "2.0" — формат AWG 2.0 (обратная
    совместимость, байт-в-байт как раньше); "3.1" — после I1-I5
    добавляются 9 директив AWG 3.1 (HeaderProtectionKey/
    ContentPaddingAddition/Rekey*/RejectAfterTime/KeepaliveTimeout/
    MaxHandshakeAttempts/RandomTrailers/DisableCookies — см.
    awg_protocol.awg_render_31_lines; пустые комментируются по правилу
    v5.4.5). Все существующие вызовы без версии получают 2.0-конфиг
    без изменений.
    """
    peers = peers or []

    from .awg_protocol import awg_is_31, awg_render_31_lines

    # Серверный IP в подсети (первый адрес).
    # ВАЖНО: используем префикс подсети из аргумента (например /24), НЕ /32.
    # При /32 ядро не добавляет маршрут "10.66.66.0/24 dev awg0" →
    # ответный трафик к клиентам не идёт через туннель → "подключение есть,
    # но интернета нет" (баг зафиксирован в тестировании v4.15.0).
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    prefix = subnet.split("/")[1] if "/" in subnet else "24"
    server_ip = f"{base}.1/{prefix}"
    # IPv6 сервера (префикс из подсети, не /128 — иначе та же проблема с маршрутом)
    v6_base = subnet_v6.split("::")[0]
    v6_prefix = subnet_v6.split("/")[1] if "/" in subnet_v6 else "64"
    server_ipv6 = f"{v6_base}::1/{v6_prefix}"

    lines = []
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {server_privkey}")
    lines.append(f"Address = {server_ip}")
    if subnet_v6:
        lines.append(f"Address = {server_ipv6}")
    lines.append(f"ListenPort = {port}")
    lines.append(f"MTU = {mtu}")
    # Параметры обфускации AWG 2.0
    lines.append(f"Jc = {params.get('jc', 4)}")
    lines.append(f"Jmin = {params.get('jmin', 40)}")
    lines.append(f"Jmax = {params.get('jmax', 70)}")
    lines.append(f"S1 = {params.get('s1', 0)}")
    lines.append(f"S2 = {params.get('s2', 0)}")
    lines.append(f"S3 = {params.get('s3', 0)}")
    lines.append(f"S4 = {params.get('s4', 0)}")
    lines.append(f"H1 = {params.get('h1', 1)}")
    lines.append(f"H2 = {params.get('h2', 2)}")
    lines.append(f"H3 = {params.get('h3', 3)}")
    lines.append(f"H4 = {params.get('h4', 4)}")
    # v5.4.2: I1-I5 для СЕРВЕРНОГО конфига — комментируем пустые (как в эталоне Amnezia).
    # Старые amneziawg-tools на сервере падают на 'I2 = ' (пустая), но игнорируют '# I2 = '.
    # Клиентский конфиг (awg_qr.py) пишет I1-I5 без комментария — это работает
    # (подтверждено zvshka: рабочая конфигурация Amnezia имеет # I на сервере
    # и I без # на клиенте).
    for key in ("i1", "i2", "i3", "i4", "i5"):
        val = params.get(key, "")
        if val:
            lines.append(f"{key.upper()} = {val}")
        else:
            lines.append(f"# {key.upper()} = ")

    # AWG 3.1 (v5.5): 9 транспортных директив сразу после I1-I5 —
    # HeaderProtectionKey, ContentPaddingAddition, таймеры, RandomTrailers,
    # DisableCookies. Единое правило v5.4.5: непустые — «Key = value»,
    # пустые — «# Key = » (голое «Key = » валит awg setconf).
    if awg_is_31(protocol_version):
        lines.append(awg_render_31_lines(params))

    # Cascade: если это AWG0 (entry), добавляем peer к AWG1
    if cascade_role == "entry" and cascade_peer:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# cascade exit peer")
        lines.append(f"PublicKey = {cascade_peer.get('pubkey', '')}")
        lines.append(f"AllowedIPs = {cascade_peer.get('subnet', '0.0.0.0/0')}")
        if cascade_peer.get("endpoint"):
            lines.append(f"Endpoint = {cascade_peer['endpoint']}")
        if cascade_peer.get("preshared_key"):
            lines.append(f"PresharedKey = {cascade_peer['preshared_key']}")
        lines.append("PersistentKeepalive = 25")

    # Обычные пиры (клиенты)
    for peer in peers:
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"# {peer.get('name', 'peer')}")
        lines.append(f"PublicKey = {peer.get('client_pubkey', '')}")
        # AllowedIPs — IP клиента
        client_ip = peer.get("client_ip", "")
        if client_ip:
            # Без префикса в конфиге — добавляем /32
            if "/" not in client_ip:
                client_ip = f"{client_ip}/32"
            lines.append(f"AllowedIPs = {client_ip}")
        client_ipv6 = peer.get("client_ipv6", "")
        if client_ipv6:
            if "/" not in client_ipv6:
                client_ipv6 = f"{client_ipv6}/128"
            lines.append(f"AllowedIPs = {client_ipv6}")
        if peer.get("preshared_key"):
            lines.append(f"PresharedKey = {peer['preshared_key']}")

    return "\n".join(lines) + "\n"


def awgs_write_server_conf(content: str) -> bool:
    """Записывает awg0.conf с правильными правами."""
    try:
        AWGS_CONF_DIR.mkdir(parents=True, exist_ok=True)
        AWGS_SERVER_CONF.write_text(content)
        AWGS_SERVER_CONF.chmod(0o600)
        return True
    except Exception as e:
        core = _core_module()
        core.log_to_file("ERROR", f"awgs_write_server_conf: {e}")
        return False


# ============================================================================
#  FIREWALL
# ============================================================================

def awgs_setup_firewall(port: int) -> bool:
    """
    Открывает UDP-порт AWG в UFW.
    НЕ переделывает deny-all, НЕ трогает Fail2Ban (как договорились в Q4=b).

     миграция на port_registry (с backward compat fallback).
    """
    core = _core_module()
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register, SERVICE_AWG_STANDALONE,
        )
        port_register(SERVICE_AWG_STANDALONE, port, "udp",
                      comment="AWG standalone", force=True)
        ok, msg = ufw_open_port(port, "udp", SERVICE_AWG_STANDALONE,
                                comment="AWG standalone")
        if ok:
            core.success(f"UFW: открыт UDP-порт {port} для AWG ({msg})")
            return True
        # ufw_open_port вернул False — fallback на прямой ufw allow ниже.
    except Exception:
        pass
    # Проверяем, активен ли UFW
    r = core._run(["ufw", "status"], capture=True, check=False)
    if r.returncode != 0:
        core.info("UFW не установлен/неактивен — пропуск firewall-настройки")
        return True
    if "inactive" in r.stdout.lower():
        core.info("UFW неактивен — пропуск (не включаем, чтобы не сломать SSH)")
        return True
    # Добавляем правило
    r = core._run(["ufw", "allow", f"{port}/udp", "comment", "AWG standalone"],
                  capture=True, check=False)
    if r.returncode == 0:
        core.success(f"UFW: открыт UDP-порт {port} для AWG")
        return True
    core.warn(f"UFW: не удалось открыть порт {port}/udp: {r.stderr}")
    return False


# ============================================================================
#  NAT / МАРШРУТИЗАЦИЯ — критично для standalone AWG
# ============================================================================

def awgs_detect_wan_interface() -> str:
    """Возвращает имя WAN-интерфейса (через который идёт default route).

    Делегирует в общий awg_net_common.detect_wan_iface (используется также
    Mode B exit-VPS для подстановки $WAN в PostUp).
    """
    core = _core_module()
    return _awg_net_detect_wan_iface(core)


def awgs_build_nat_helper_body(awg_subnet: str,
                               awg_iface: str = AWGS_INTERFACE) -> str:
    """v5.4.5: тело helper-скрипта /usr/local/sbin/awg-nat-rules.sh.

    Вынесено в отдельную функцию для юнит-тестирования (см.
    tests/test_awg_standalone.py::TestAwgsNatHelper).
    """
    return (
        "#!/bin/bash\n"
        "# AWG standalone NAT + FORWARD — сгенерировано chimera (awg_standalone.py)\n"
        "# up|down — идемпотентно применить/убрать правила для " + awg_subnet + "\n"
        "# Удаляется awgs_uninstall_full().\n"
        "set -u\n"
        "CMD=\"${1:-up}\"\n"
        "WAN=$(ip route show default | awk '{print $5; exit}')\n"
        "if [ -z \"$WAN\" ]; then echo \"awg-nat-rules: WAN interface not found\" >&2; exit 1; fi\n"
        "case \"$CMD\" in\n"
        "  up)   " + build_nat_idempotent_shell(awg_subnet, awg_iface, "$WAN") + " ;;\n"
        "  down) " + build_nat_cleanup_shell(awg_subnet, awg_iface, "$WAN") + " ;;\n"
        "  *) echo \"usage: $0 up|down\" >&2; exit 1 ;;\n"
        "esac\n"
    )


def awgs_build_nat_unit_content() -> str:
    """v5.4.5: содержимое awg-nat.service — ExecStart/ExecStop вызывают
    helper-скрипт БЕЗ shell-кавычек (инлайн `bash -c '...awk '{...}'...'`
    разрывался systemd-токенизатором — NAT умирал после каждой перезагрузки).

    v5.5.3 FIX-F: WantedBy+=awg-quick@awg0.service — старт туннеля тянет
    за собой NAT-юнит (wants-симлинк). Раньше было только multi-user.target:
    `systemctl stop awg-quick@awg0 && start` (и даже restart!) гасил awg-nat
    через Requires (ExecStop удалял MASQUERADE), а повторный старт туннеля
    NAT НЕ поднимал → exit-нода после рестарта awg0 = живой handshake при
    чёрной дыре каскадного трафика (E2E 2026-10-03: failover-тест fi1,
    probe FAIL после stop/start). Теперь: stop awg0 → NAT down (Requires),
    start/restart awg0 → NAT up (WantedBy-симлинк).
    """
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    return f"""[Unit]
Description=AWG standalone NAT + FORWARD rules (idempotent)
After={AWGS_SYSTEMD_AWG_QUICK}
Requires={AWGS_SYSTEMD_AWG_QUICK}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/awg-nat-rules.sh up
ExecStop=/usr/local/sbin/awg-nat-rules.sh down

[Install]
WantedBy=multi-user.target {AWGS_SYSTEMD_AWG_QUICK}
"""


def awgs_setup_nat_and_routing(subnet: str, wan_iface: str = "") -> bool:
    """
    Настраивает NAT/MASQUERADE + FORWARD + sysctl для standalone AWG.

    КРИТИЧНО: без этого "подключение есть, но интернета нет" —
    пакеты от клиента (10.66.66.x) уходят в интернет через awg0,
    но без MASQUERADE они имеют source=10.66.66.x (приватный IP),
    который не маршрутизируется в интернете → ответы не приходят.

    Также включает:
    • net.ipv4.ip_forward=1 (если ещё не включён)
    • rp_filter=2 (loose mode) ТОЛЬКО на awg0 и WAN — точечно, не глобально.
      Loose mode сохраняет anti-spoofing защиту (в отличие от 0=off) и
      достаточно для корректной работы NAT. Раньше сбрасывался global
      all/default rp_filter=0 — это ослабляло защиту всей системы.
    • iptables MASQUERADE для подсети awg0 → WAN (idempotent через -C check)
    • iptables FORWARD: awg0 → anywhere (ACCEPT), idempotent
    • iptables FORWARD: anywhere → awg0 (ESTABLISHED,RELATED ACCEPT), idempotent
    • systemd-юнит awg-nat.service для перманентности (After=awg-quick@awg0)

    Идемпотентность: при повторных вызовах (переустановка, --force, повторный
    запуск после сбоя) правила НЕ дублируются — каждое добавляется через
    _iptables_ensure (iptables -C → iptables -A только если -C не нашёл).
    То же касается systemd-юнита: его ExecStart использует bash-idiому
    `iptables -C ... || iptables -A ...`, безопасную при многократных
    `systemctl restart awg-nat`.

    Общий сетевой слой: NAT-правила и sysctl-конфиг генерируются через
    chimera.modules.awg_net_common — тот же слой использует
    awg_transport._awg_server_conf_text для генерации PostUp/PostDown строк
    в awg0.conf на exit-VPS (Mode B chain). Это устраняет дублирование
    NAT/MASQUERADE/sysctl логики между standalone и Mode B exit-VPS.

    Уникально для standalone-режима (а также для exit-VPS стороны Mode B):
    тут нужен NAT/MASQUERADE, потому что клиенты подключаются к этому серверу
    через awg0 и их трафик должен выйти в интернет через WAN-интерфейс сервера.
    Для RU-VPS стороны Mode B NAT не нужен — там применяется policy routing
    по fwmark (xray-процесс маркируется, ip rule отправляет marked-трафик
    через таблицу AWG → awg0 → exit-VPS, где уже exit-VPS делает MASQUERADE).
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    if not wan_iface:
        wan_iface = awgs_detect_wan_interface()
    if not wan_iface:
        warn("Не удалось определить WAN-интерфейс — NAT не настроен")
        return False

    info(f"WAN-интерфейс: {wan_iface}")

    # 1. sysctl: ip_forward=1 (idempotent)
    info("Настройка sysctl (ip_forward, per-interface rp_filter=2 loose mode)...")
    apply_ip_forward(core)

    # rp_filter=2 (loose mode) ТОЛЬКО на awg0 и WAN — точечно, не глобально.
    # Раньше сбрасывались all/default rp_filter=0 — ослабляло anti-spoofing
    # на всей системе. Loose mode (2) достаточен для NAT и сохраняет защиту.
    apply_rp_filter_per_iface(core, AWGS_INTERFACE, wan_iface,
                              value=RP_FILTER_DEFAULT)

    # Перманентим sysctl — через общий хелпер (вычищает старые global all/default
    # записи, оставляет только per-interface)
    sysctl_conf = Path("/etc/sysctl.d/99-awg-standalone.conf")
    try:
        if write_sysctl_conf(sysctl_conf, AWGS_INTERFACE, wan_iface,
                             rp_filter_value=RP_FILTER_DEFAULT):
            info(f"  sysctl-конфиг: {sysctl_conf} (per-interface rp_filter=2)")
        else:
            warn(f"  Не удалось записать {sysctl_conf}")
    except Exception as e:
        core.log_to_file("WARN", f"awgs_setup_nat sysctl persist: {e}")

    # 2. iptables: MASQUERADE + FORWARD (idempotent через _iptables_ensure)
    info("Настройка iptables (MASQUERADE + FORWARD, idempotent)...")
    awg_subnet = subnet  # уже в формате CIDR (например 10.66.66.0/24)

    # Получаем список правил из общего билдера — тот же самый, что использует
    # Mode B exit-VPS через PostUp (см. awg_transport._awg_server_conf_text).
    nat_rules = build_nat_rule_args(awg_subnet, AWGS_INTERFACE, wan_iface)
    for rule_args in nat_rules:
        # rule_args[0] == "iptables" — iptables_ensure ожидает args без "iptables"
        # (он сам добавляет "iptables" префикс). Передаём args[1:].
        iptables_ensure(core, rule_args[1:])
    success(f"iptables: MASQUERADE {awg_subnet} → {wan_iface} + FORWARD правила")

    # 3. systemd-юнит awg-nat.service — для перманентности после reboot.
    # ExecStart использует bash-идиому `iptables -C || iptables -A` (через
    # build_nat_idempotent_shell) — безопасен при многократных restart.
    # WAN определяется в runtime через `ip route show default` (не хардкодим
    # wan_iface, т.к. после ребута интерфейс может переименовать — udev).
    #
    # v5.4.5: КРИТИЧЕСКИЙ фикс — раньше ExecStart был инлайном:
    #   ExecStart=/bin/bash -c 'WAN=$(... awk '{print $5}') ...'
    # systemd-токенизатор разрывал аргумент на вложенной одинарной кавычке
    # awk, а $WAN разворачивал сам systemd (пусто). Юнит молча падал
    # после КАЖДОЙ перезагрузки → NAT не восстанавливался → «подключено,
    # но нет интернета» (подтверждено E2E 2026-10-03, юнит на de1).
    # Теперь правила вынесены в helper-скрипт (как awg-expires-check.sh),
    # юнит вызывает его без shell-кавычек.
    info("Создание systemd-юнита awg-nat.service (idempotent ExecStart)...")
    nat_helper = Path("/usr/local/sbin/awg-nat-rules.sh")
    helper_body = awgs_build_nat_helper_body(awg_subnet, AWGS_INTERFACE)
    try:
        nat_helper.write_text(helper_body)
        nat_helper.chmod(0o755)
    except Exception as e:
        warn(f"Не удалось создать {nat_helper}: {e}")
        warn("NAT правила применены в runtime, но не переживут reboot")
        return True
    nat_unit = Path("/etc/systemd/system/awg-nat.service")
    nat_unit_content = awgs_build_nat_unit_content()
    try:
        nat_unit.write_text(nat_unit_content)
        core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
        core._run(["systemctl", "enable", "awg-nat.service"],
                  check=False, quiet=True)
        # v5.4.5: restart обязателен — если юнит остался в failed от
        # предыдущей установки/бута (E2E 138x: failed-статус висел от
        # старого юнита юзера при живых runtime-правилах), без restart
        # он не поднимется до следующего ребута
        core._run(["systemctl", "restart", "awg-nat.service"],
                  check=False, quiet=True)
        success("awg-nat.service создан и включен (NAT после reboot, idempotent)")
    except Exception as e:
        warn(f"Не удалось создать awg-nat.service: {e}")
        warn("NAT правила применены в runtime, но не переживут reboot")

    return True


# ============================================================================
#  SYSTEMD-СЕРВИС
# ============================================================================

def awgs_setup_systemd() -> bool:
    """
    Включает и запускает awg-quick@awg0.service.
    Юнит предоставляется пакетом amneziawg-tools — отдельный юнит не нужен.
    """
    core = _core_module()
    core._run(["systemctl", "daemon-reload"], check=False, quiet=True)
    core._run(["systemctl", "enable", AWGS_SYSTEMD_AWG_QUICK],
              check=False, quiet=True)
    r = core._run(["systemctl", "start", AWGS_SYSTEMD_AWG_QUICK],
                  capture=True, check=False)
    if r.returncode != 0:
        core.log_to_file("ERROR", f"awgs_setup_systemd start: {r.stderr}")
        return False
    time.sleep(2)
    status = awgs_service_status()
    if not status["active"]:
        core.warn(f"awg-quick@awg0 не активен — проверьте лог: journalctl -u {AWGS_SYSTEMD_AWG_QUICK}")
        return False
    core.success("awg-quick@awg0.service запущен")
    return True


def awgs_stop_systemd() -> bool:
    """Останавливает и выключает awg-quick@awg0.service."""
    core = _core_module()
    core._run(["systemctl", "stop", AWGS_SYSTEMD_AWG_QUICK],
              check=False, quiet=True)
    core._run(["systemctl", "disable", AWGS_SYSTEMD_AWG_QUICK],
              check=False, quiet=True)
    return True


# ============================================================================
#  ПОЛНАЯ УСТАНОВКА
# ============================================================================

def awgs_install(
    port: int = AWGS_DEFAULT_PORT,
    subnet: str = AWGS_DEFAULT_SUBNET,
    subnet_v6: str = AWGS_DEFAULT_SUBNET_V6,
    mtu: int = AWGS_DEFAULT_MTU,
    carrier_preset: str = "default",
    endpoint_host: str = "",
    allow_ipv6_tunnel: bool = False,
    skip_hw_tuning: bool = False,
    force: bool = False,
    custom_params: dict = None,
    protocol_version: str = AWGS_DEFAULT_PROTOCOL_VERSION,
) -> bool:
    """
    Полный цикл установки standalone AWG (2.0 или 3.1).
    Возвращает True при успехе.

    protocol_version="3.1" (v5.5): генерация параметров по констрейнтам
    GenerateObfuscation31 (S1-S4 ≥ 12, Jmax ≤ 339, I1 = <r 32-256> + 9
    транспортных параметров), awg0.conf с 3.1-директивами, state с
    protocol_version="3.1". Перед установкой предупреждает о поддержке
    клиентами (AmneziaVPN 5.0.1.5+; роутеры 3.1 НЕ поддерживают).
    """
    from .awg_protocol import (
        awg_is_31, awg_protocol_label, awg_vpn_uri_protocol_version,
    )
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    GREEN, NC, CYAN, BOLD, YELLOW, DIM = (
        core.GREEN, core.NC, core.CYAN, core.BOLD, core.YELLOW, core.DIM,
    )

    is_31 = awg_is_31(protocol_version)
    _version_label = awg_protocol_label(protocol_version)

    _box_top(f"Установка {_version_label} (standalone)")
    _box_row()
    if is_31:
        _box_row(f"  {YELLOW}AWG 3.1: transport protection — шифрование заголовков,"
                 f" паддинг, рандомизация таймеров.{NC}")
        _box_row(f"  {DIM}Клиенты: AmneziaVPN 5.0.1.5+ (Windows/macOS/Linux/"
                 f"Android/iOS). Роутеры (Keenetic/GL-INet) 3.1 НЕ "
                 f"поддерживают — им выдавайте 2.0-конфиг с другого "
                 f"сервера.{NC}")
        _box_row(f"  {DIM}При проблемах с большими пакетами снизьте MTU "
                 f"до 1100 (WPP-профили используют именно его).{NC}")
    _box_bottom()

    # 1. Валидация
    if port < AWGS_PORT_MIN or port > AWGS_PORT_MAX:
        warn(f"Порт {port} вне диапазона ({AWGS_PORT_MIN}-{AWGS_PORT_MAX})")
        return False
    # Если переданы custom_params — валидируем их, иначе проверяем пресет
    if custom_params:
        ok, err = awgs_presets_validate_params(custom_params,
                                               protocol_version=protocol_version)
        if not ok:
            warn(f"Пользовательские параметры: {err}")
            return False
    else:
        ok, err = awgs_presets_validate_params(
            awgs_presets_generate(carrier_preset,
                                   protocol_version=protocol_version),
            protocol_version=protocol_version)
        if not ok:
            warn(f"Пресет '{carrier_preset}': {err}")
            return False

    # 2. Конфликт-чек
    info("Проверка конфликтов...")
    conflicts = awgs_check_conflicts(port)
    if conflicts and not force:
        for c in conflicts:
            warn(f"  • {c}")
        warn("Установка отменена. Устраните конфликты или запустите с --force.")
        return False
    if conflicts and force:
        warn("--force: игнорируем конфликты (продолжаем на свой риск)")
        for c in conflicts:
            warn(f"  • {c}")

    # 3. Подготовка директорий
    info("Создание директорий...")
    for d in (AWGS_CONF_DIR, AWGS_AWG_DIR, AWGS_KEYS_DIR, AWGS_BACKUP_DIR):
        d.mkdir(parents=True, exist_ok=True)
    AWGS_LOG_FILE.touch(exist_ok=True)

    # 4. Установка DKMS
    info("Установка AmneziaWG DKMS-модуля...")
    if not awgs_install_dkms():
        warn("Установка DKMS не удалась")
        return False

    # 5. Hardware-tuning (idempotent)
    if not skip_hw_tuning:
        info("Hardware-tuning (sysctl + swap + NIC)...")
        awgs_hw_tune_all()

    # 6. Генерация ключей сервера
    info("Генерация ключей сервера...")
    server_priv, server_pub = awgs_generate_keys()
    if not server_priv or not server_pub:
        warn("Не удалось сгенерировать ключи сервера")
        return False

    # 7. Публичный endpoint
    endpoint = endpoint_host
    if not endpoint:
        try:
            endpoint = core.get_server_ip("4") or ""
        except Exception:
            endpoint = ""
    if not endpoint:
        warn("Не удалось определить публичный IP — клиентские конфиги будут без endpoint")

    # 8. Параметры обфускации (по версии протокола)
    if custom_params:
        info("Используются пользовательские параметры обфускации...")
        params = custom_params
        info(f"  Jc={params['jc']}, Jmin={params['jmin']}, Jmax={params['jmax']}, "
             f"S1={params['s1']}, S2={params['s2']}, S3={params['s3']}, S4={params['s4']}, "
             f"H1={params['h1']}, H2={params['h2']}, H3={params['h3']}, H4={params['h4']}")
        if params.get("i1"):
            info(f"  I1={'задан' if params['i1'] else 'отсутствует'}")
        if is_31:
            info(f"  HeaderProtectionKey={'задан' if params.get('header_protection_key') else 'ОТСУТСТВУЕТ'}"
                 f", RandomTrailers={params.get('random_trailers', '?')}")
    else:
        info(f"Генерация параметров обфускации (preset: {carrier_preset}, "
             f"протокол: {_version_label})...")
        params = awgs_presets_generate(carrier_preset,
                                        protocol_version=protocol_version)
        preset_info = awgs_presets_get(carrier_preset)
        if preset_info:
            info(f"  Пресет: {preset_info['label']}")
        info(f"  Jc={params['jc']}, Jmin={params['jmin']}, Jmax={params['jmax']}, "
             f"I1={'задан' if params['i1'] else 'отсутствует'}")
        if is_31:
            info("  + HeaderProtectionKey, ContentPaddingAddition, "
                 "Rekey*/RejectAfterTime/KeepaliveTimeout/MaxHandshakeAttempts, "
                 "RandomTrailers, DisableCookies")

    # 9. Генерация awg0.conf
    info("Генерация awg0.conf...")
    conf_content = awgs_build_server_conf(
        server_privkey=server_priv,
        port=port,
        subnet=subnet,
        subnet_v6=subnet_v6 if allow_ipv6_tunnel else "",
        mtu=mtu,
        params=params,
        peers=[],
        endpoint_host=endpoint,
        protocol_version=protocol_version,
    )
    if not awgs_write_server_conf(conf_content):
        warn("Не удалось записать awg0.conf")
        return False

    # 10. Firewall
    info("Настройка firewall (только UDP-порт AWG)...")
    awgs_setup_firewall(port)

    # 11. Systemd
    info("Запуск awg-quick@awg0.service...")
    if not awgs_setup_systemd():
        # v5.5.2 (E2E fi1 2026-10-03): честный контракт установки —
        # успех = поднятый туннель. Раньше здесь был только warn:
        # userspace-go без юнита давал «Установка завершена» при
        # мёртвом awg0 (systemctl not-found), каскад получал бокс
        # данных от неработающего exit. Конфиг сохранён в
        # /etc/amnezia/amneziawg/awg0.conf — дебаг: journalctl -u awg-quick@awg0.
        warn("Не удалось запустить awg-quick@awg0 — установка НЕ завершена. "
             "Конфиг сохранён для дебага: journalctl -u awg-quick@awg0")
        return False

    # 11.1 NAT / маршрутизация — КРИТИЧНО для standalone AWG
    # Без MASQUERADE + ip_forward + FORWARD правил клиенты подключаются,
    # но не получают интернет (ответный трафик не доходит).
    info("Настройка NAT/MASQUERADE + ip_forward (для интернета у клиентов)...")
    awgs_setup_nat_and_routing(subnet=subnet)

    # 12. Сохранение state
    info("Сохранение state...")
    awgs_state_init(
        server_privkey=server_priv,
        server_pubkey=server_pub,
        port=port,
        subnet=subnet,
        subnet_v6=subnet_v6,
        mtu=mtu,
        endpoint=endpoint,
        endpoint_host=endpoint_host,
        params=params,
        carrier_preset=carrier_preset,
        allow_ipv6_tunnel=allow_ipv6_tunnel,
        protocol_version=protocol_version,
    )

    # v4.25: bulk-provisioning всех существующих VLESS-пользователей в AWG.
    # Каждый VLESS-юзер получает peer (привязка через owner_email).
    # Лимит 253 пира (по числу IP в /24 подсети).
    try:
        from chimera.modules.rest_api import _sync_all_from_vless
        from chimera.modules.users_manager import _unified_load_users
        _vless_users = _unified_load_users()
        if _vless_users:
            info(f"Синхронизирую {len(_vless_users)} VLESS-юзеров в AWG...")
            _stats = _sync_all_from_vless(_vless_users)
            _awg_stats = _stats.get("awg_peers", {})
            if _awg_stats.get("created", 0) > 0:
                success(f"Добавлено AWG peers: {_awg_stats['created']}")
    except Exception as _e:
        try:
            warn(f"Sync VLESS-юзеров не удался: {_e}")
        except Exception:
            print(f"Sync VLESS-юзеров не удался: {_e}")

    # 13. Создание cron для --expires (если ещё нет)
    awgs_setup_expires_cron()

    success(f"Установка {_version_label} завершена!")
    print()
    _box_top(f"Готово")
    _box_row(f"  {GREEN}Протокол:{NC}         {_version_label}")
    _box_row(f"  {GREEN}Интерфейс:{NC}        {AWGS_INTERFACE}")
    _box_row(f"  {GREEN}UDP-порт:{NC}         {port}")
    _box_row(f"  {GREEN}Подсеть:{NC}           {subnet}")
    if allow_ipv6_tunnel:
        _box_row(f"  {GREEN}IPv6 подсеть:{NC}     {subnet_v6}")
    _box_row(f"  {GREEN}Пресет:{NC}            {carrier_preset}")
    if is_31:
        _box_row(f"  {GREEN}VPN URI version:{NC}   {awg_vpn_uri_protocol_version(protocol_version)} "
                 f"(AmneziaVPN 5.0.1.5+)")
    _box_row(f"  {GREEN}Endpoint:{NC}          {endpoint or '(не определён)'}")
    _box_row(f"  {GREEN}Server pubkey:{NC}     {server_pub[:32]}...")
    _box_row(f"  {GREEN}Конфиг:{NC}            {AWGS_SERVER_CONF}")
    _box_row(f"  {GREEN}State:{NC}             /var/lib/xray-installer/awg_standalone_state.json")
    _box_row(f"  {GREEN}Лог:{NC}               {AWGS_LOG_FILE}")
    _box_bottom()
    print()
    info("Добавьте первого клиента: меню → Управление клиентами AWG → Add")
    return True


def awgs_setup_expires_cron() -> bool:
    """Создаёт cron-задачу для автоудаления истёкших клиентов.

    v5.1: bare ``python3 -c "from chimera.modules.awg_expires import ..."`` в
    cron НЕ работает — cron запускается с произвольной cwd и без PYTHONPATH,
    поэтому ``from chimera...`` падает с ``ModuleNotFoundError: No module
    named 'chimera'``. Реальный трейсбек с сервера пользователя zvshka
    подтвердил, что фича автоудаления истёкших AWG-клиентов НИКОГДА не
    срабатывала с момента появления.

    Паттерн исправления — wrapper bash-скрипт (как в
    ``node_health_monitor.py::install_health_monitor`` и
    ``geo_files.py::setup_geo_autoupdate``):
      1. Находим путь установки chimera через ``importlib.util.find_spec``
         (fallback ``/opt/chimera``).
      2. Пишем ``/usr/local/sbin/awg-expires-check.sh`` с ``export PYTHONPATH``
         и ``sys.path.insert(0, ...)`` внутри python -c.
      3. Cron-файл просто вызывает wrapper-скрипт.
    """
    from .awg_constants import AWGS_CRON_EXPIRES, AWGS_CRON_EXPIRES_SCRIPT

    # Находим путь установки chimera (тот же способ, что в
    # node_health_monitor.py::install_health_monitor).
    try:
        import importlib.util
        spec = importlib.util.find_spec("chimera")
        if spec and spec.submodule_search_locations:
            installer_path = str(
                Path(list(spec.submodule_search_locations)[0]).parent
            )
        else:
            installer_path = "/opt/chimera"
    except Exception:
        installer_path = "/opt/chimera"

    try:
        # Wrapper bash-скрипт: export PYTHONPATH + sys.path.insert + python -c
        script_content = (
            "#!/bin/bash\n"
            f"# AWG standalone: автоудаление истёкших клиентов "
            f"(wrapper для cron; v5.1: PYTHONPATH-safe).\n"
            f"export PYTHONPATH=\"{installer_path}:$PYTHONPATH\"\n"
            f"/usr/bin/python3 -c \"\n"
            f"import sys\n"
            f"sys.path.insert(0, '{installer_path}')\n"
            f"from chimera.modules.awg_expires import awgs_expires_check\n"
            f"awgs_expires_check()\n"
            f"\" >> {AWGS_LOG_FILE} 2>&1\n"
        )
        AWGS_CRON_EXPIRES_SCRIPT.write_text(script_content)
        AWGS_CRON_EXPIRES_SCRIPT.chmod(0o755)

        # Cron-файл — вызывает wrapper-скрипт.
        cron_content = (
            "# AWG standalone: автоудаление истёкших клиентов\n"
            f"*/5 * * * * root {AWGS_CRON_EXPIRES_SCRIPT}\n"
        )
        AWGS_CRON_EXPIRES.write_text(cron_content)
        AWGS_CRON_EXPIRES.chmod(0o644)
        return True
    except Exception as e:
        core = _core_module()
        core.log_to_file("WARN", f"awgs_setup_expires_cron: {e}")
        return False


# ============================================================================
#  TUI-МЕНЮ
# ============================================================================

def do_manage_awg_standalone() -> None:
    """Главное TUI-меню управления AmneziaWG standalone."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_wrap_msg = core._box_wrap_msg
    warn = core.warn
    info = core.info
    CYAN, NC, GREEN, YELLOW, DIM, BOLD = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM, core.BOLD

    while True:
        import os
        os.system("clear")
        print()
        # v5.5: заголовок показывает ФАКТИЧЕСКУЮ версию установленного
        # протокола (2.0/3.1) из state — «AmneziaWG (standalone VPN)» до
        # установки, когда версия ещё не определена.
        from .awg_protocol import awg_protocol_label
        from .awg_state import awgs_state_get_protocol_version
        _installed_version = awgs_state_get_protocol_version() if awgs_state_is_installed() else ""
        _menu_title = (awg_protocol_label(_installed_version)
                       if _installed_version else "AmneziaWG 2.0/3.1") + " (standalone VPN)"
        _box_top(f"{_menu_title}")
        _box_row()

        # Статус установки
        installed = awgs_state_is_installed()
        if installed:
            st = awgs_state_load()
            _box_row(f"  {GREEN}● Установлен{NC}  ({awg_protocol_label(_installed_version)}, "
                     f"порт {st.get('port', '?')}, "
                     f"пиры: {len(st.get('peers', []))})")
        else:
            _box_row(f"  {YELLOW}○ Не установлен{NC}")
        _box_row()
        _box_item("1", f"Установить standalone AWG (выбор протокола: 2.0 / 3.1)")
        _box_item("2", f"Управление клиентами (пиры)")
        _box_item("3", f"Каскад из 2 серверов (RU→зарубеж)")
        _box_item("4", f"Диагностика (kernel/sysctl/UFW + carrier-compare)")
        _box_item("5", f"Backup / Restore")
        _box_item("6", f"Полное удаление")
        _box_item("7", f"Ротация обфускации (Jc/Jmin/Jmax/I1 без разрыва)")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "1":
            _awgs_menu_install()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            from .awg_peers import do_manage_awg_peers
            do_manage_awg_peers()
        elif ch == "3":
            from .awg_cascade import do_manage_awg_cascade
            do_manage_awg_cascade()
        elif ch == "4":
            from .awg_diagnose import do_awg_diagnose_menu
            do_awg_diagnose_menu()
            input(f"{core.BLUE}Нажмите Enter...{NC}")
        elif ch == "5":
            from .awg_backup import do_manage_awg_backup
            do_manage_awg_backup()
        elif ch == "6":
            from .awg_uninstall import do_awg_uninstall_menu
            do_awg_uninstall_menu()
        elif ch == "7":
            do_awgs_rotate_menu()
        elif ch in ("q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)


def _awgs_prompt_protocol_version() -> str:
    """v5.5: выбор версии протокола AWG перед установкой (TUI).

    Возвращает "2.0" или "3.1" (нормализовано через awg_protocol).
    """
    from .awg_protocol import AWG_VERSION_20, AWG_VERSION_31, awg_normalize_version
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_item = core._box_item
    _box_desc = core._box_desc
    _box_bottom = core._box_bottom
    CYAN, NC, GREEN, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM

    print()
    _box_top(f"Версия протокола AmneziaWG")
    _box_row()
    _box_item("1", f"AmneziaWG 2.0 {GREEN}(Enter — по умолчанию){NC}")
    _box_desc("Максимальная совместимость: роутеры Keenetic/GL-INet, все клиенты.")
    _box_item("2", f"AmneziaWG 3.1 {YELLOW}(новое, transport protection){NC}")
    _box_desc("Шифрование заголовков + паддинг + рандомизация таймеров — ответ "
              "на поведенческий AI-анализ трафика (лето 2026). Клиенты: "
              "AmneziaVPN 5.0.1.5+. Роутеры 3.1 НЕ поддерживают.")
    _box_row()
    _box_bottom()
    while True:
        ch = input(f"{CYAN}Версия протокола [1/2, Enter=1]:{NC} ").strip()
        if ch in ("", "1"):
            return AWG_VERSION_20
        if ch == "2":
            return AWG_VERSION_31
        core.warn("Введите 1 или 2")


def _awgs_menu_install() -> None:
    """Подменю установки standalone AWG (2.0 / 3.1)."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    CYAN, NC, GREEN, DIM = core.CYAN, core.NC, core.GREEN, core.DIM

    # v5.5: сначала — выбор версии протокола (2.0 / 3.1), она пробрасывается
    # во ВСЕ пути установки ниже (пресеты, advanced, custom params).
    protocol_version = _awgs_prompt_protocol_version()

    print()
    _box_top(f"Установка {awg_protocol_label_static(protocol_version)}")
    _box_row()
    _box_item("1", f"Default preset (проводной интернет) {GREEN}(рекомендуется){NC}")
    _box_desc("Универсальный пресет, работает в большинстве сетей.")
    _box_item("2", f"Mobile preset (мобильные DPI: Yota/Tele2/Мегафон)")
    _box_desc("Jc=3, узкий Jmax — для ТСПУ и мобильных операторов.")
    _box_item("3", f"Выбрать оператора вручную (9 пресетов)")
    _box_desc("Yota MSK, Tele2 MSK/Krasnoyarsk, Таттелеком, Мегафон, Билайн, T-Mobile US")
    _box_item("4", f"Расширенные параметры (порт, подсеть, MTU, IPv6, endpoint)")
    _box_desc("Тонкая настройка под конкретный сервер.")
    _box_item("5", f"Ручная настройка ВСЕХ параметров обфускации {GREEN}(эксперт){NC}")
    _box_desc("Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5 — каждый параметр вручную с рекомендациями. "
              "Для 3.1 транспортные параметры генерируются автоматически.")
    _box_item("Q", f"Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch == "1":
        awgs_install(carrier_preset="default", protocol_version=protocol_version)
    elif ch == "2":
        awgs_install(carrier_preset="mobile", protocol_version=protocol_version)
    elif ch == "3":
        _awgs_menu_carrier(protocol_version=protocol_version)
    elif ch == "4":
        _awgs_menu_advanced(protocol_version=protocol_version)
    elif ch == "5":
        _awgs_menu_custom_params(protocol_version=protocol_version)
    elif ch in ("q", ""):
        return


def awg_protocol_label_static(version: str) -> str:
    """Локальный хелпер-обёртка (без циклического импорта в TUI-пути)."""
    from .awg_protocol import awg_protocol_label
    return awg_protocol_label(version)


def _awgs_menu_custom_params(protocol_version: str = "2.0") -> None:
    """Подменю ручной настройки параметров обфускации (2.0 или 3.1)."""
    from .awg_protocol import awg31_merge_into_params, awg_is_31
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC = core.CYAN, core.NC

    # Сначала спрашиваем базовые параметры (порт/подсеть/MTU/IPv6/endpoint)
    print()
    info("Ручная настройка параметров обфускации.")
    info("Сначала базовые параметры, затем — параметры обфускации.")
    print()

    port_str = input(f"{CYAN}UDP-порт [51820]: {NC}").strip()
    port = int(port_str) if port_str.isdigit() else AWGS_DEFAULT_PORT

    subnet = input(f"{CYAN}Подсеть IPv4 [10.66.66.0/24]: {NC}").strip() or AWGS_DEFAULT_SUBNET

    ipv6_ch = input(f"{CYAN}Включить IPv6 в туннеле? [y/N]: {NC}").strip().lower()
    allow_ipv6 = ipv6_ch in ("y", "yes", "д", "да")
    subnet_v6 = AWGS_DEFAULT_SUBNET_V6 if allow_ipv6 else ""

    mtu_str = input(f"{CYAN}MTU [1280]: {NC}").strip()
    mtu = int(mtu_str) if mtu_str.isdigit() else AWGS_DEFAULT_MTU

    endpoint = input(f"{CYAN}Endpoint (если за NAT, иначе пусто) []: {NC}").strip()

    # Теперь — параметры обфускации (v5.5.1: с версией протокола — для 3.1
    # промпт охватывает и 9 транспортных директив)
    custom_params = awgs_prompt_custom_params(protocol_version=protocol_version)
    if custom_params is None:
        warn("Параметры не валидны — отмена")
        return

    # AWG 3.1: ручной ввод охватывает базовый 2.0-набор; 9 транспортных
    # параметров 3.1 генерируются автоматически (GenerateObfuscation31-
    # констрейнты, см. awg_protocol.awg31_generate_extra_params).
    if awg_is_31(protocol_version):
        custom_params = awg31_merge_into_params(custom_params)
        info("AWG 3.1: транспортные параметры (HeaderProtectionKey, "
             "ContentPaddingAddition, таймеры, RandomTrailers, "
             "DisableCookies) сгенерированы автоматически")

    print()
    confirm = input(f"{CYAN}Начать установку с этими параметрами? [Y/n]: {NC}").strip().lower()
    if confirm in ("n", "no", "н", "нет"):
        return

    print()
    awgs_install(
        port=port,
        subnet=subnet,
        subnet_v6=subnet_v6,
        mtu=mtu,
        endpoint_host=endpoint,
        allow_ipv6_tunnel=allow_ipv6,
        custom_params=custom_params,
        protocol_version=protocol_version,
    )


def _awgs_menu_carrier(protocol_version: str = "2.0") -> None:
    """Подменю выбора оператора."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    CYAN, NC = core.CYAN, core.NC

    print()
    _box_top(f"Выбор оператора (carrier preset)")
    _box_row()
    presets = awgs_presets_list()
    for i, name in enumerate(presets, 1):
        p = awgs_presets_get(name)
        _box_item(str(i) if i < 10 else "0", f"{name} — {p['label']}")
        _box_desc(p["description"])
    _box_item("Q", "Назад")
    _box_bottom()
    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch in ("q", ""):
        return
    try:
        idx = int(ch) - 1
        if 0 <= idx < len(presets):
            awgs_install(carrier_preset=presets[idx],
                         protocol_version=protocol_version)
    except ValueError:
        pass


def _awgs_menu_advanced(protocol_version: str = "2.0") -> None:
    """Подменю расширенных параметров."""
    core = _core_module()
    info = core.info
    warn = core.warn
    CYAN, NC = core.CYAN, core.NC

    print()
    info("Расширенные параметры (Enter = значение по умолчанию)")
    print()

    # Порт
    port_str = input(f"{CYAN}UDP-порт [51820]: {NC}").strip()
    port = int(port_str) if port_str.isdigit() else AWGS_DEFAULT_PORT

    # Подсеть
    subnet = input(f"{CYAN}Подсеть IPv4 [10.66.66.0/24]: {NC}").strip() or AWGS_DEFAULT_SUBNET

    # IPv6
    ipv6_ch = input(f"{CYAN}Включить IPv6 в туннеле? [y/N]: {NC}").strip().lower()
    allow_ipv6 = ipv6_ch in ("y", "yes", "д", "да")
    subnet_v6 = AWGS_DEFAULT_SUBNET_V6 if allow_ipv6 else ""

    # MTU
    mtu_str = input(f"{CYAN}MTU [1280]: {NC}").strip()
    mtu = int(mtu_str) if mtu_str.isdigit() else AWGS_DEFAULT_MTU

    # Endpoint (для NAT)
    endpoint = input(f"{CYAN}Endpoint (если за NAT, иначе пусто) []: {NC}").strip()

    # Пресет
    carrier = input(f"{CYAN}Carrier preset [default]: {NC}").strip() or "default"
    if carrier not in awgs_presets_list():
        warn(f"Пресет '{carrier}' не найден, используется 'default'")
        carrier = "default"

    print()
    awgs_install(
        port=port,
        subnet=subnet,
        subnet_v6=subnet_v6,
        mtu=mtu,
        carrier_preset=carrier,
        endpoint_host=endpoint,
        allow_ipv6_tunnel=allow_ipv6,
        protocol_version=protocol_version,
    )


# ============================================================================
#  РОТАЦИЯ ПАРАМЕТРОВ ОБФУСКАЦИИ (без разрыва туннеля)
# ============================================================================

def awgs_rotate_obfuscation(preset_name: str = "") -> tuple[bool, str]:
    """
    Ротация параметров обфускации Jc/Jmin/Jmax/S1-S4/H1-H4/I1
    без разрыва туннеля (через awg syncconf).

    Алгоритм:
      1. Генерируем новые параметры через awgs_presets_generate(preset)
         (использует текущий carrier-пресет из state, или заданный)
      2. Перестраиваем awg0.conf через awg_peer_rebuild_conf(apply=True,
         params_override=new_params) — конфиг строится с NEW_PARAMS,
         но state на диске пока НЕ меняется
      3. При успехе apply — коммитим state["params"]=new_params
         При неудаче — state не трогаем, туннель продолжает работать
         на старых параметрах

    Параметры:
      preset_name: имя carrier-пресета для генерации
                   (пусто = использовать текущий из state)

    Возвращает:
      (True, "Параметры обновлены: Jc=X Jmin=Y Jmax=Z I1=...") при успехе
      (False, "сообщение об ошибке") при неудаче
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    from .awg_state import awgs_state_load, awgs_state_update
    from .awg_presets import awgs_presets_generate, awgs_presets_list
    from .awg_peers import awg_peer_rebuild_conf
    from .awg_protocol import awg_is_31

    # Проверяем что AWG установлен
    if not awgs_state_is_installed():
        return False, "Standalone AWG не установлен"

    state = awgs_state_load()
    # v5.5: ротация соблюдает версию протокола из state (3.1 → полный
    # 3.1-набор, включая новые HeaderProtectionKey и таймеры)
    protocol_version = state.get("protocol_version", "2.0")

    # Определяем пресет для генерации
    if not preset_name:
        preset_name = state.get("carrier_preset", "default")
    if preset_name not in awgs_presets_list():
        return False, f"Неизвестный пресет: {preset_name}"

    info(f"Ротация параметров обфускации (пресет: {preset_name})...")

    # Генерируем новые параметры (по версии протокола из state)
    try:
        new_params = awgs_presets_generate(preset_name,
                                            protocol_version=protocol_version)
    except ValueError as e:
        return False, str(e)

    # Перестраиваем конфиг и применяем через syncconf (без даунтайма).
    # ВАЖНО: передаём new_params через params_override, чтобы конфиг строился
    # с НОВЫМИ параметрами (а не со старыми из state на диске).
    # State на диске коммитим ТОЛЬКО при подтверждённом успехе apply —
    # иначе state будет противоречить реальности на интерфейсе
    # (регрессия 225c2ba: state коммитился после rebuild_conf, который
    #  читал СТАРЫЕ params с диска → ротация молча не работала).
    info("Применение через awg syncconf (без разрыва туннеля)...")
    if awg_peer_rebuild_conf(apply=True, params_override=new_params):
        # Apply успешен — теперь безопасно коммитить state
        awgs_state_update(params=new_params)

        # v5.4.1: Перегенерируем клиентские .conf файлы для всех пиров —
        # после ротации параметры обфускации изменились, и клиенты должны
        # получить новые параметры, иначе handshake не завершится
        # (подтверждено жалобой zvshka: "handshake did not complete after
        # 2842297815 seconds" — сервер и клиент с разными параметрами).
        try:
            from .awg_qr import awgs_qr_export_peer
            updated_state = awgs_state_load()
            for peer in updated_state.get("peers", []):
                try:
                    awgs_qr_export_peer(peer)
                except Exception as e:
                    core.log_to_file("WARN",
                        f"awgs_rotate_obfuscation: не удалось обновить "
                        f"клиентский конфиг для пира '{peer.get('name', '?')}': {e}")
            if updated_state.get("peers"):
                info(f"Клиентские конфиги обновлены для "
                     f"{len(updated_state['peers'])} пира(ов) — "
                     f"передайте новые .conf файлы клиентам")
        except Exception as e:
            core.log_to_file("WARN",
                f"awgs_rotate_obfuscation: ошибка обновления клиентских "
                f"конфигов: {e}")

        # v5.1: I1 теперь CPS tag (например "<r 24>") — обычно короткий,
        # не нужно обрезать. Для legacy hex (длинный) оставляем обрезку.
        _i1_val = new_params.get("i1", "")
        if not _i1_val:
            i1_display = "отсутствует"
        elif len(_i1_val) > 16:
            i1_display = _i1_val[:16] + "..."
        else:
            i1_display = _i1_val
        # v5.5.5: сколько I-цепочек заполнено (3.1 — все 5 по умолчанию)
        _i_filled = sum(1 for _k in ("i1", "i2", "i3", "i4", "i5")
                        if new_params.get(_k))
        msg = (f"Параметры обновлены: Jc={new_params['jc']} "
               f"Jmin={new_params['jmin']} Jmax={new_params['jmax']} "
               f"I1={i1_display} I-цепочек: {_i_filled}/5")
        if awg_is_31(protocol_version):
            msg += " (+ новые HeaderProtectionKey/таймеры AWG 3.1)"
        success(msg)
        core.log_to_file("INFO", f"awgs_rotate_obfuscation: {msg}")
        return True, msg
    else:
        # awgs_apply() уже пробовала syncconf → fallback restart → оба провалились.
        # Туннель работает на старых параметрах (state не изменён).
        warn("Не удалось применить конфиг ни через syncconf, ни через restart — "
             "туннель работает на старых параметрах, требуется ручное вмешательство")
        return False, ("Не удалось применить конфиг ни через syncconf, ни через restart. "
                       "Туннель работает на старых параметрах, требуется ручное вмешательство")


def do_awgs_rotate_menu() -> None:
    """TUI-меню ротации параметров обфускации."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_sep = core._box_sep
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    _box_desc = core._box_desc
    info = core.info
    warn = core.warn
    success = core.success
    CYAN, NC, GREEN, YELLOW, DIM = core.CYAN, core.NC, core.GREEN, core.YELLOW, core.DIM

    from .awg_state import awgs_state_load, awgs_state_is_installed
    from .awg_presets import awgs_presets_list, awgs_presets_get

    if not awgs_state_is_installed():
        print()
        warn("Standalone AWG не установлен")
        input(f"\n{CYAN}Нажмите Enter...{NC}")
        return

    state = awgs_state_load()
    current_preset = state.get("carrier_preset", "default")
    current_params = state.get("params", {})

    import os
    os.system("clear")
    print()
    _box_top(f"Ротация параметров обфускации")
    _box_row()
    _box_row(f"  Текущий пресет: {CYAN}{current_preset}{NC}")
    if current_params:
        _box_row(f"  Текущие параметры:")
        _box_row(f"    Jc={current_params.get('jc', '?')} "
                 f"Jmin={current_params.get('jmin', '?')} "
                 f"Jmax={current_params.get('jmax', '?')}")
        i1 = current_params.get("i1", "")
        # v5.1: I1 теперь CPS tag — обычно короткий, не нужно обрезать.
        if not i1:
            i1_display = "отсутствует"
        elif len(i1) > 16:
            i1_display = i1[:16] + "..."
        else:
            i1_display = i1
        _box_row(f"    I1={i1_display}")
    _box_row()
    _box_sep()
    _box_row(f"  {DIM}Ротация генерирует новые случайные значения{NC}")
    _box_row(f"  {DIM}в рамках текущего carrier-пресета.{NC}")
    _box_row(f"  {DIM}Применяется через awg syncconf — без разрыва.{NC}")
    _box_row()
    _box_sep()
    _box_row()
    _box_item("1", f"Ротировать ({current_preset})")
    _box_desc("Новые Jc/Jmin/Jmax/I1 в рамках того же пресета")
    _box_item("2", f"Сменить пресет + ротировать")
    _box_desc("Выбрать другой carrier-пресет, затем ротировать")
    _box_item("Q", f"Назад")
    _box_bottom()

    ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

    if ch == "1":
        ok, msg = awgs_rotate_obfuscation(current_preset)
        if ok:
            success(msg)
        else:
            warn(msg)
        input(f"\n{CYAN}Нажмите Enter...{NC}")
    elif ch == "2":
        # Показать список пресетов
        print()
        presets = awgs_presets_list()
        for i, p in enumerate(presets, 1):
            preset = awgs_presets_get(p)
            marker = f" {GREEN}← текущий{NC}" if p == current_preset else ""
            print(f"  [{i}] {p} — {preset.get('label', '')}{marker}")
        print()
        choice = input(f"{CYAN}Выберите пресет [1-{len(presets)}]: {NC}").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(presets):
                selected = presets[idx]
                ok, msg = awgs_rotate_obfuscation(selected)
                if ok:
                    awgs_state_update(carrier_preset=selected)
                    success(msg)
                else:
                    warn(msg)
            else:
                warn("Неверный выбор")
        except ValueError:
            warn("Неверный ввод")
        input(f"\n{CYAN}Нажмите Enter...{NC}")


# ══════════════════════════════════════════════════════════════════════════════
#  УЧАСТИЕ В ОБЩЕМ БЭКАПЕ (единая автообнаружаемая система chimera.modules.backup_registry)
# ══════════════════════════════════════════════════════════════════════════════
# У AWG Standalone уже есть собственный полнофункциональный бэкап-модуль
# (awg_backup.py с awgs_backup_create/awgs_backup_restore), который вызывается
# из отдельного меню AWG. Здесь — ТОЛЬКО список путей для ЕДИНОГО бэкапа всего
# проекта, чтобы пользователь по привычке нажавший "Экспорт всего" в главном
# меню получил AWG-конфиги в общем архиве тоже. Дублирования логики нет —
# только пути.
def get_backup_paths() -> list[tuple[Path, str]]:
    """Возвращает [(реальный_путь, имя_в_архиве), ...] — всё необходимое для
    восстановления AWG Standalone БЕЗ переиздания клиентских ключей.

    Файлы:
      • /etc/amnezia/amneziawg/awg0.conf — серверный конфиг (PrivateKey
        сервера + параметры обфускации — без них клиенты не смогут
        подключиться; клиентские ключи НЕ входят в серверный конфиг,
        они лежат в /root/awg/keys/ и не бэкапятся здесь намеренно).
      • /root/awg/awgsetup_cfg.init — init-файл (параметры установки).
      • /var/lib/xray-installer/awg_standalone_state.json — module state.
      • /etc/systemd/system/awg-cascade-routing.service — systemd-unit
        каскада (опционально, только если установлен каскад).

    Клиентские конфиги (/root/awg/keys/*) НЕ включаем — это пользовательские
    секреты, их переиздают после восстановления через меню AWG Standalone.

    Пустой список если AWG Standalone не установлен. Никогда не бросает
    исключение.
    """
    try:
        from .awg_constants import (
            AWGS_SERVER_CONF, AWGS_INIT_FILE, AWGS_STATE_FILE,
            AWGS_SYSTEMD_CASCADE,
        )
        candidates = [
            (AWGS_SERVER_CONF,        "amnezia/amneziawg/awg0.conf"),
            (AWGS_INIT_FILE,          "awg/awgsetup_cfg.init"),
            (AWGS_STATE_FILE,         "awg/awg_standalone_state.json"),
            (AWGS_SYSTEMD_CASCADE,    "etc/systemd/system/awg-cascade-routing.service"),
        ]
        return [(p, arcname) for p, arcname in candidates if p.exists()]
    except Exception:
        return []
